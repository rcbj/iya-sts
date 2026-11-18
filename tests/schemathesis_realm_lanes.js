// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: schemathesis_realm_lanes.js
//
// ===========================================================================
// THE FUZZ MODE RUNS ITS REALMS IN PARALLEL, AND NO WIDER THAN IT WAS ASKED
// (#1502). The driving is the job's own; this holds the scheduling.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const kit = require('./protocol/schemathesis_kit');

const log = require('bunyan').createLogger({
  name: 'schemathesis_realm_lanes',
  level: process.env.LOG_LEVEL || 'info' });

async function widest(items, width) {
  log.debug("Entering widest().");
  let running = 0;
  let most = 0;
  const seen = [];
  await kit.boundedMap(items, width, async function (item) {
    running += 1;
    most = Math.max(most, running);
    seen.push(item);
    await new Promise(function (resolve) {
      setTimeout(resolve, 15);
    });
    running -= 1;
  });
  log.debug("Leaving widest().");
  return { most: most, seen: seen };
}

async function run(t) {
  log.debug("Entering run().");
  const three = await widest(['a', 'b', 'c'], 3);
  t.equal(three.most, 3, 'three realms overlap at a width of three');
  t.equal(three.seen.slice().sort().join(), 'a,b,c', 'and each runs once');
  const one = await widest(['a', 'b', 'c'], 1);
  t.equal(one.most, 1, 'a width of one never overlaps');
  t.equal(one.seen.join(), 'a,b,c', 'and keeps the order');
  const two = await widest(['a', 'b', 'c', 'd'], 2);
  t.equal(two.most, 2, 'a width is never exceeded');
  const saved = process.env.STS_SCHEMATHESIS_REALMS;
  try {
    delete process.env.STS_SCHEMATHESIS_REALMS;
    t.equal(kit.realmConcurrency(), kit.PROFILES.length,
            'every realm at once by default');
    process.env.STS_SCHEMATHESIS_REALMS = '1';
    t.equal(kit.realmConcurrency(), 1, 'one restores the old order');
    process.env.STS_SCHEMATHESIS_REALMS = 'many';
    t.equal(kit.realmConcurrency(), kit.PROFILES.length,
            'a value that is no number is the default');
  } finally {
    if (saved === undefined) {
      delete process.env.STS_SCHEMATHESIS_REALMS;
    } else {
      process.env.STS_SCHEMATHESIS_REALMS = saved;
    }
  }
  await budget(t);
  await gates(t);
  await heavyProxies(t);
  sources(t);
  log.debug("Leaving run().");
}

// STS_SCHEMATHESIS_PROCESSES, and the cores less one by default (2026-11-18).
async function budget(t) {
  log.debug("Entering budget().");
  const saved = process.env.STS_SCHEMATHESIS_PROCESSES;
  try {
    delete process.env.STS_SCHEMATHESIS_PROCESSES;
    t.equal(kit.processBudget(), Math.max(1, os.cpus().length - 1),
            'the cells at once are the cores less one by default');
    process.env.STS_SCHEMATHESIS_PROCESSES = '2';
    t.equal(kit.processBudget(), 2, 'STS_SCHEMATHESIS_PROCESSES overrides');
    process.env.STS_SCHEMATHESIS_PROCESSES = '0';
    t.equal(kit.processBudget(), Math.max(1, os.cpus().length - 1),
            'and zero is the default, never no cells at all');
  } finally {
    if (saved === undefined) {
      delete process.env.STS_SCHEMATHESIS_PROCESSES;
    } else {
      process.env.STS_SCHEMATHESIS_PROCESSES = saved;
    }
  }
  log.debug("Leaving budget().");
}

// The gate itself: never wider than asked, first come first served, and a
// withdrawn ticket is never granted.
async function gates(t) {
  log.debug("Entering gates().");
  const one = kit.makeGate(1);
  let inside = 0;
  let most = 0;
  const order = [];
  await Promise.all(['a', 'b', 'c', 'd'].map(function (name) {
    return kit.inGate(one, async function () {
      inside += 1;
      most = Math.max(most, inside);
      order.push(name);
      await new Promise(function (resolve) {
        setTimeout(resolve, 10);
      });
      inside -= 1;
    });
  }));
  t.equal(most, 1, 'a gate of one never holds two at once');
  t.equal(order.join(), 'a,b,c,d', 'and grants in the order asked');
  t.equal(one.stats().most, 1, 'and says so');
  const two = kit.makeGate(2);
  const granted = [];
  const first = two.request(function () {
    granted.push('first');
  });
  two.request(function () {
    granted.push('second');
  });
  const third = two.request(function () {
    granted.push('third');
  });
  const fourth = two.request(function () {
    granted.push('fourth');
  });
  third.release();
  first.release();
  first.release();
  t.equal(granted.join(), 'first,second,fourth',
          'a withdrawn ticket is never granted, and a second release ' +
          'frees nothing twice');
  t.equal(two.stats().running, 2, 'the gate is still full');
  fourth.release();
  t.equal(two.stats().running, 1, 'and frees as its tickets are released');
  let thrown = false;
  try {
    await kit.inGate(one, async function () {
      throw new Error('the cell threw');
    });
  } catch (e) {
    log.debug("Caught in gates(): " + ((e && e.message) || e));
    thrown = true;
  }
  t.check(thrown && one.stats().running === 0,
          'a cell that throws gives its slot back');
  log.debug("Leaving gates().");
}

// Children that ask for the heavy gate exactly as a cell's proxy does
// (auth_proxy.js heavyGate()), over a real IPC channel, against the kit's
// half (serveHeavyGate()): never two inside at once, and a wait past the
// cap goes ahead, counted.
const CHILD = [
  "'use strict';",
  "const proxy = require(process.env.STS_TEST_PROXY);",
  "proxy.listenForGrants();",
  "process.on('message', async function (m) {",
  "  if (!m || m.go === undefined) { return; }",
  "  const giveBack = await proxy.heavyGate('POST /admin-api/pki/build');",
  "  process.send({ probe: 'in', at: Date.now() });",
  "  await new Promise(function (r) { setTimeout(r, m.go); });",
  "  process.send({ probe: 'out', at: Date.now() });",
  "  giveBack();",
  "  if (m.last) { setTimeout(function () { process.exit(0); }, 50); }",
  "});"
].join("\n");

function forkHolder(file, waitSeconds) {
  log.debug("Entering forkHolder().");
  const child = childProcess.fork(file, [], {
    env: Object.assign({}, process.env, {
      STS_TEST_PROXY: path.join(__dirname, 'schemathesis', 'auth_proxy.js'),
      STS_SCHEMA_SERVICE_BASE: 'https://sts:8081',
      STS_SCHEMA_HEAVY_WAIT_S: String(waitSeconds),
      LOG_LEVEL: 'warn', STS_LOG_LEVEL: 'warn' }),
    stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  log.debug("Leaving forkHolder().");
  return child;
}

async function heavyProxies(t) {
  log.debug("Entering heavyProxies().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'heavy-gate-'));
  const file = path.join(dir, 'holder.js');
  fs.writeFileSync(file, CHILD);
  const gate = kit.makeGate(1);
  let inside = 0;
  let most = 0;
  function watch(child, counts) {
    log.debug("Entering watch().");
    const done = new Promise(function (resolve) {
      child.on('exit', resolve);
    });
    child.on('message', function (m) {
      if (m && m.probe === 'in') {
        inside += 1;
        most = Math.max(most, inside);
      } else if (m && m.probe === 'out') {
        inside -= 1;
      }
    });
    log.debug("Leaving watch().");
    return { child: child, counts: counts, done: done };
  }
  const holders = [0, 1, 2].map(function () {
    const child = forkHolder(file, 60);
    return watch(child, kit.serveHeavyGate(child, gate));
  });
  holders.forEach(function (one) {
    one.child.send({ go: 0, last: false });
    one.child.send({ go: 40, last: true });
  });
  await Promise.all(holders.map(function (one) {
    return one.done;
  }));
  t.equal(most, 1, 'three proxies asking at once are inside one at a time');
  t.equal(gate.stats().granted, 6, 'and every request was let through');
  t.equal(gate.stats().running, 0, 'and the gate is free when they are done');
  t.check(holders.every(function (one) {
    return one.counts.held === 2 && one.counts.pastCap === 0;
  }), 'each cell counts what the gate held for it');
  // A ticket held by a child that never gives it back, and a second child
  // whose cap is one second: it goes ahead, and says so.
  inside = 0;
  most = 0;
  const stuck = forkHolder(file, 60);
  const stuckOne = watch(stuck, kit.serveHeavyGate(stuck, gate));
  const patient = forkHolder(file, 1);
  const patientOne = watch(patient, kit.serveHeavyGate(patient, gate));
  stuck.send({ go: 5000, last: true });
  await new Promise(function (resolve) {
    setTimeout(resolve, 300);
  });
  const asked = Date.now();
  patient.send({ go: 0, last: true });
  await patientOne.done;
  const took = Date.now() - asked;
  t.check(took >= 900 && took < 4000,
          'a wait past the cap goes ahead after the cap (' + took + ' ms)');
  t.equal(patientOne.counts.pastCap, 1, 'and is counted as past the cap');
  stuck.kill();
  await stuckOne.done;
  await new Promise(function (resolve) {
    setImmediate(resolve);
  });
  t.equal(gate.stats().running, 0,
          'a proxy that exits gives back what it held');
  t.equal(gate.stats().queued, 0, 'and nothing is left waiting');
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving heavyProxies().");
}

// What the rule stands on in the kit's source: every cell runs inside the
// slots, and the CA rebuilds that timed out are heavy.
function sources(t) {
  log.debug("Entering sources().");
  const source = fs.readFileSync(path.join(__dirname, 'protocol',
    'schemathesis_kit.js'), 'utf8');
  const body = source.slice(source.indexOf('async function run('));
  t.equal((body.match(/runSurface\(/g) || []).length, 1,
          'run() reaches runSurface() in one place');
  t.check(/return inGate\(slots, function \(\) \{\s*return runSurface\(/
    .test(body), 'and that place holds a slot and passes the heavy gate');
  t.check(/runSurface\(serviceBase, cellProvisioned, cell, workDir, say,\s*heavyGate\)/
    .test(body), 'every cell is given the one heavy gate');
  ['POST /admin-api/pki/build', 'POST /admin-api/pki/build-scope']
    .forEach(function (one) {
      t.check(kit.HEAVY_OPERATIONS.indexOf(one) >= 0, one + ' is heavy');
    });
  if (!process.env.STS_SCHEMA_SERVICE_BASE) {
    process.env.STS_SCHEMA_SERVICE_BASE = 'https://sts:8081';
  }
  const proxy = require('./schemathesis/auth_proxy.js');
  const heavy = new Set(kit.HEAVY_OPERATIONS);
  t.check(proxy.isHeavy('POST', '/admin-api/pki/build?x=1', heavy) &&
          proxy.isHeavy('post', '/admin-api/pki/build/', heavy),
          'the proxy holds a heavy operation whatever its query or slash');
  t.check(!proxy.isHeavy('GET', '/admin-api/pki/build', heavy) &&
          !proxy.isHeavy('POST', '/admin-api/pki/clear', heavy),
          'and nothing else');
  t.check(kit.HEAVY_WAIT_CAP_SECONDS < kit.REQUEST_TIMEOUT_SECONDS / 1.5,
          'the cap leaves an operation most of the request timeout');
  log.debug("Leaving sources().");
}

module.exports = {
  name: 'schemathesis_realm_lanes',
  describe: 'the fuzz mode runs its realms in parallel, within its width, ' +
            'its cells within the cores and one heavy operation at a time',
  run: run
};
