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
  log.debug("Leaving run().");
}

module.exports = {
  name: 'schemathesis_realm_lanes',
  describe: 'the fuzz mode runs its realms in parallel, within its width',
  run: run
};
