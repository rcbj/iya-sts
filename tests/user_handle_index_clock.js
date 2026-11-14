// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: user_handle_index_clock.js
//
// ===========================================================================
// THE USER-HANDLE INDEX MOVES ONLY WITH A HANDLE (#909, 2026-10-23).
//
// `ldap/ldap_server.js`'s usernameless owner index was rebuilt on a miss
// whenever `directoryVersion` had moved, and every write in the process
// moves that — so under ordinary traffic nearly every unknown handle, which
// an unauthenticated client can post at will, rebuilt the whole index. It
// has a clock of its own now, as the group index does (#618). Held here, in
// the default realm of the run's own process:
//
//   1. the first lookup builds the index and finds the holder;
//   2. unknown handles asked between writes that touch no handle do NOT
//      rebuild it;
//   3. a handle minted afterwards is found at once — its write moves the
//      clock, so the miss rebuilds exactly once.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'user_handle_index_clock',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  const ldap = require('../ldap/ldap_server');
  const credentials = require('../common/credentials');
  const stamp = String(process.pid);
  const builds = function () {
    log.debug("Entering builds().");
    log.debug("Leaving builds().");
    return ldap.userHandleIndexState().builds;
  };
  const randomHandle = function () {
    log.debug("Entering randomHandle().");
    log.debug("Leaving randomHandle().");
    return nodeCrypto.randomBytes(64).toString('base64url');
  };
  const ANN = 'uhc-ann-' + stamp;
  ldap.createUser(ANN, { invent: false });
  const annHandle = credentials.userHandleOf(ANN, { mint: true });
  const before = builds();
  t.check(!!annHandle && credentials.ownerOfUserHandle(annHandle) === ANN,
          '1. the first lookup finds the holder', String(annHandle));
  const afterFirst = builds();
  t.check(afterFirst <= before + 1,
          '1b. and builds the index at most once', before + ' -> ' +
            afterFirst);

  for (let i = 0; i < 5; i++) {
    ldap.createUser('uhc-other-' + stamp + '-' + i, { invent: false });
    credentials.ownerOfUserHandle(randomHandle());
  }
  t.equal(builds(), afterFirst,
          '2. five unknown handles between five unrelated writes rebuild ' +
          'nothing (#909)');

  const BOB = 'uhc-bob-' + stamp;
  ldap.createUser(BOB, { invent: false });
  const bobHandle = credentials.userHandleOf(BOB, { mint: true });
  t.check(credentials.ownerOfUserHandle(bobHandle) === BOB,
          '3. a handle minted afterwards is found at once', String(bobHandle));
  t.equal(builds(), afterFirst + 1, '3b. by exactly one rebuild');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'user_handle_index_clock',
  describe: 'the usernameless user-handle index is rebuilt only when a ' +
            'handle may have changed (#909), not for every unknown handle ' +
            'after any write',
  run: run
};
