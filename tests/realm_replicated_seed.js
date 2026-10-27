// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_replicated_seed.js
//
// ===========================================================================
// A REALM THAT REPLICATED FROM ANOTHER PROCESS IS NOT SEEDED HERE (2026-10-27).
//
// `ldap/ldap_server.js`'s builder seeds a realm's subtree the moment the realm
// is created — the containers, the internal applications, the native roles.
// A realm learnt through the change log already HAS that subtree, written by
// the process that built it and on its way in the same log; since the realm
// row is applied ahead of its directory rows, a seed here raced them: one
// STS-STORE-0052 per seeded entry on every replica, and a write made on the
// replica's losing copy before the merge was lost (run #4, sts_worker_pools).
// So `realms.create()` tells its builders where a realm came from, and the
// directory's builder stands aside for a replicated one.
//
// Three claims:
//   1. a realm created here is seeded, as it always was;
//   2. a realm restored from the store at startup (restored, not replicated)
//      is seeded too — the store may predate the subtree;
//   3. a realm that REPLICATED is not: its ou=roles is empty until the rows
//      arrive.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'realm_replicated_seed',
  level: process.env.LOG_LEVEL || 'info' });

module.exports = {
  name: 'realm_replicated_seed',
  describe: 'a realm that replicated from another process is not seeded ' +
            'by the directory\'s builder; one made or restored here is',
  run: function (t) {
    log.debug("Entering run().");
    const realms = require('../common/realms');
    require('../ldap/ldap_server');
    const roles = require('../common/roles');
    const stamp = Date.now().toString(36);

    function nativeRolesIn(id) {
      log.debug("Entering nativeRolesIn(). id=" + id);
      let names = [];
      try {
        names = realms.run(realms.get(id), function () {
          return roles.all().filter(function (r) {
            return r.native === true;
          }).map(function (r) {
            return r.name;
          });
        });
      } catch (e) {
        // An unseeded subtree has no ou=roles to list; that is the answer
        // claim 3 is after, so it counts as "none" rather than failing.
        log.debug("Caught in nativeRolesIn(): " + ((e && e.message) || e));
        names = [];
      }
      log.debug("Leaving nativeRolesIn(). " + names.length);
      return names;
    }

    const made = 'seedhere' + stamp;
    const created = realms.create({ id: made, name: 'Made here' });
    t.check(!!(created && created.ok !== false),
            'A1. a realm created here is created');
    t.check(nativeRolesIn(made).indexOf('REPORT_ADMIN') >= 0,
            'A2. and its subtree is seeded: the native roles are there');

    const restored = 'seedrest' + stamp;
    const back = realms.create({ id: restored, name: 'Restored',
                                 restored: true });
    t.check(!!(back && back.ok !== false),
            'B1. a realm restored from the store at startup is created');
    t.check(nativeRolesIn(restored).indexOf('REPORT_ADMIN') >= 0,
            'B2. and seeded as well — the store may predate its subtree');

    const replicated = 'seedrepl' + stamp;
    const learnt = realms.create({ id: replicated, name: 'Replicated',
                                   restored: true, replicated: true });
    t.check(!!(learnt && learnt.ok !== false),
            'C1. a realm that replicated from another process is created');
    t.equal(nativeRolesIn(replicated).length, 0,
            'C2. and NOT seeded: its rows are on their way in the change ' +
            'log, and a seed here raced them');

    [made, restored, replicated].forEach(function (id) {
      realms.remove(id);
    });
    log.debug("Leaving run().");
  }
};
