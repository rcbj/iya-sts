#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ONE NODE.JS CLUSTER NODE, AND NOTHING ELSE (#444, phase 3): the Node
// service's own postgres driver (`persistence/persistence_postgres.js`) joins
// the cluster, heartbeats and contends for the scheduler's lease every
// quarter second, and prints one JSON line whenever what it sees changes.
// `rust/crates/sts-cluster/tests/node_interop.rs` runs it beside a Rust node
// on the same store, to show that the two read and write the cluster tables'
// rows alike — the compatible-upgrade decision (D11) needs the row format
// shared even though the two never run together in production.
//
//   node tests/tools/cluster-interop-node.js <database url> <node id>
//
// Runs until it is killed. Not a test by itself; run where the compiled tree
// is (the tests image).
'use strict';

const path = require('path');
const ROOT = path.join(__dirname, '..', '..');
const bunyan = require('bunyan');
const log = bunyan.createLogger({ name: 'cluster-interop', level: 'fatal' });

const LEASE = 'ops.scheduler';
const HEARTBEAT_MS = 250;
const TTL_MS = 1500;

async function main() {
  log.debug("Entering main().");
  const url = process.argv[2];
  const nodeId = process.argv[3];
  const pg = require(path.join(ROOT, 'persistence', 'persistence_postgres.js'));
  const driver = pg.create({ url: url, log: log, verifyTls: false,
                             poolMax: 2 });
  await driver.open();
  const joined = await driver.joinCluster({ nodeId: nodeId, name: nodeId,
                                            mode: 'active-active',
                                            ttlMs: TTL_MS, info: {} });
  let last = '';
  const say = function (what) {
    const line = JSON.stringify(what);
    if (line !== last) {
      last = line;
      process.stdout.write(line + '\n');
    }
  };
  say({ joined: joined.joined, differing: joined.differing });
  // A LOOP OF ONE PROCESS'S HEARTBEATS, not a service timer: this file is
  // a test tool that does nothing else and is killed when it is done.
  for (;;) {
    try {
      const beat = await driver.heartbeat(nodeId, TTL_MS, null);
      const lease = await driver.acquireLease(LEASE, nodeId, TTL_MS);
      say({ alive: !!Number(beat.alive), held: !!lease.held,
            holder: lease.holder || (lease.held ? nodeId : ''),
            token: Number(lease.token) || 0 });
    } catch (e) {
      say({ error: String((e && e.message) || e) });
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, HEARTBEAT_MS);
    });
  }
}

main().catch(function (e) {
  process.stdout.write(JSON.stringify({ fatal: String((e && e.message) ||
                                                      e) }) + '\n');
  process.exit(1);
});
