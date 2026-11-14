// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_kinds.js
//
// ===========================================================================
// THE MANAGEMENT API AND THE CONSOLE'S OWN OPERATIONS ARE TWO KINDS (#454).
//
// Since #446 the admin console is a static application whose one data source
// is `/admin-api`, and to draw itself it added operations that exist only for
// it: its frame, its drawings, its form helpers. They answer in the shape a
// renderer wants, which changes whenever a page does, so they are not part of
// the contract an external client relies on. `mgmt-api/admin_api.ts` marks
// every row of its route table `management` or `console`, and everything
// else follows from that one field: where the operation is, which document
// describes it, which list names it, and what the gate asks for it.
//
// **WHAT THIS FILE HOLDS, AND WHY EACH IS A RULE RATHER THAN A HABIT.**
//
//   1. Every row has a kind, and the PATH is the kind: a console row is under
//      `/admin-api/console` and a management row is not. The gate decides on
//      the path of a request it has not routed yet, so a console row outside
//      the prefix would be gated as a management one.
//   2. A console POST writes nothing. That is rule 7's guard: every console
//      CONTROL keeps a management operation, and a control cannot hide on the
//      console side when the console side has only reads and form helpers.
//      A write is allowed only where ARGUED_CONSOLE_WRITES names it and the
//      management operation doing the same write, which must be registered.
//   3. The two documents and the two lists do not overlap, and the explorer
//      (Server configuration → Management API) is built from the management
//      document alone.
//   4. The console's set is the one written here. A row moving across is a
//      decision, and this list is where it is seen being made.
//   5. A management operation with a console twin names the twin, and the
//      twin is registered.
//   6. ADMIN_CONSOLE is a native role, conferred by the console's client, and
//      `admin:console` is one of the management API's protected scopes.
//
// In process: each claim is about the table and the modules as built, which
// is what every request reads, and none of them needs a request to see.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'admin_api_kinds',
  level: process.env.LOG_LEVEL || 'info' });

delete process.env.CONFIG_FILE;

// THE CONSOLE'S OPERATIONS, BY operationId. Written out on purpose — see 4.
const CONSOLE_OPERATIONS = [
  'getConsoleShell', 'getConsoleOperations', 'getConsoleOpenApi',
  'getConsoleDashboard', 'getApiExplorer', 'getDelegationSettings',
  'getDelegationMap', 'getDelegationCluster', 'getDelegationAllowed',
  'getDelegationChain', 'getFederationMap', 'getConsoleNewApplicationForm',
  'getConsoleDelegationUser', 'getConsoleDelegationApplication',
  'applyPkiProfile', 'generatePkiKeyPair', 'generatePkiAltKeyPair',
  'usePkiStoredKey', 'generateClientSecret', 'setConsoleLanguage'
];

// THE CONSOLE WRITES THAT ARE ARGUED, by operationId, each with the
// management operation that does the same write — so rule 7 still holds:
// the control is not hidden on the console side. One, and it is the reader's
// own preference rather than an administrative control.
//   setConsoleLanguage (#539): the signed-in person's own preferredLanguage,
//     the console's language chooser; the same attribute of any person is
//     setUserAttribute (POST /admin-api/users/set-attribute).
const ARGUED_CONSOLE_WRITES = {
  setConsoleLanguage: 'setUserAttribute'
};

const CONSOLE_PREFIX = /^\/admin-api\/console(\/|$)/;

function pathOf(entry) {
  log.debug("Entering pathOf().");
  log.debug("Leaving pathOf().");
  return String(entry.path || entry.route || '');
}

function run(t) {
  log.debug("Entering run().");
  const adminApi = require('../mgmt-api/admin_api');
  const spec = require('../mgmt-api/admin_api_spec');
  const roles = require('../common/roles');
  const scopePolicy = require('../common/scope_policy');
  const routes = adminApi.ROUTES;
  t.check(Array.isArray(routes) && routes.length >= 100,
          'the route table was built', String(routes && routes.length));

  // --- 1. every row has a kind, and the path is the kind -------------------
  t.log.info('=== 1. every row has a kind, and its path says which ===');
  const unkinded = routes.filter(function (entry) {
    return entry.kind !== 'management' && entry.kind !== 'console';
  });
  t.check(unkinded.length === 0, '1a. every row is management or console',
          unkinded.map(pathOf).join(', ') || 'none without');
  const misplaced = routes.filter(function (entry) {
    return (entry.kind === 'console') !== CONSOLE_PREFIX.test(pathOf(entry));
  });
  t.check(misplaced.length === 0,
          '1b. a console row is under /admin-api/console and a management ' +
          'row is not',
          misplaced.map(function (entry) {
            return entry.kind + ' ' + pathOf(entry);
          }).join(', ') || 'none misplaced');

  // --- 2. a console POST writes nothing --------------------------------------
  t.log.info('=== 2. the console side has reads and form helpers only ===');
  const writing = [];
  const managementIds = [];
  routes.filter(function (entry) {
    return entry.kind === 'management';
  }).forEach(function (entry) {
    managementIds.push(entry.operationId);
    (entry.actions || []).forEach(function (action) {
      managementIds.push(action.operationId);
    });
  });
  routes.filter(function (entry) {
    return entry.kind === 'console' && entry.method !== 'GET';
  }).forEach(function (entry) {
    const twin = ARGUED_CONSOLE_WRITES[entry.operationId];
    if (twin) {
      if (managementIds.indexOf(twin) < 0) {
        writing.push(pathOf(entry) + ' (its management twin ' + twin +
                     ' is not registered)');
      }
      return;
    }
    if (!Array.isArray(entry.actions) || !entry.actions.length) {
      writing.push(pathOf(entry) + ' (no declared actions)');
      return;
    }
    entry.actions.forEach(function (action) {
      if (action.writesNothing !== true) {
        writing.push(pathOf(entry).replace(':action', action.action));
      }
    });
  });
  t.check(writing.length === 0,
          '2. every console POST is a form helper that writes nothing, so ' +
          'no console control lacks a management operation (rule 7)',
          writing.join(', ') || 'none');

  // --- 3. two documents, two lists, no overlap -------------------------------
  t.log.info('=== 3. the documents and the lists ===');
  const options = { baseUrl: 'https://sts.example', version: '0',
                    authRequired: true };
  const managementDoc = spec.buildSpec(routes.filter(function (entry) {
    return entry.kind === 'management';
  }), options);
  const consoleDoc = spec.buildSpec(routes.filter(function (entry) {
    return entry.kind === 'console';
  }), Object.assign({}, options, { console: true }));
  const managementPaths = Object.keys(managementDoc.paths || {});
  const consolePaths = Object.keys(consoleDoc.paths || {});
  t.check(managementPaths.length > 100 && !managementPaths.some(function (p) {
    return CONSOLE_PREFIX.test(p);
  }), '3a. the management document describes no console operation',
          managementPaths.length + ' path(s)');
  t.check(consolePaths.length > 0 && consolePaths.every(function (p) {
    return CONSOLE_PREFIX.test(p);
  }), '3b. the console\'s document describes console operations alone',
          consolePaths.join(', '));
  t.check(/admin console's own operations/.test(consoleDoc.info.description) &&
          consoleDoc.info.title !== managementDoc.info.title,
          '3c. and says so before anything else');
  const index = adminApi.operationSummaries();
  const all = adminApi.operationSummaries('all');
  t.check(index.every(function (row) {
    return row.kind === 'management' && !CONSOLE_PREFIX.test(row.path);
  }), '3d. the index lists the management operations alone',
          index.length + ' operation(s)');
  t.check(all.length > index.length && all.some(function (row) {
    return row.kind === 'console';
  }), '3e. and the console\'s operation list both kinds',
          all.length + ' operation(s)');
  const fs = require('fs');
  const path = require('path');
  const explorer = fs.readFileSync(path.join(__dirname, '..', 'admin-ui',
                                             'api_explorer.ts'), 'utf8');
  t.check(/buildSpec\(adminApi\.ROUTES\.filter\(function \(entry\) \{\s*return \(entry\.kind \|\| 'management'\) === 'management';/
            .test(explorer),
          '3f. Server configuration → Management API (the API explorer) is ' +
          'built from the management operations alone');

  // --- 4. the console's set is the one written here --------------------------
  t.log.info('=== 4. which operations are the console\'s ===');
  const consoleIds = all.filter(function (row) {
    return row.kind === 'console';
  }).map(function (row) {
    return row.operationId;
  }).sort();
  const expected = CONSOLE_OPERATIONS.slice(0).sort();
  t.equal(JSON.stringify(consoleIds), JSON.stringify(expected),
          '4. the console\'s operations are exactly the list in this file');

  // --- 5. twins -------------------------------------------------------------
  t.log.info('=== 5. a management answer with a console twin ===');
  const twinned = routes.filter(function (entry) {
    return entry.consoleTwin;
  });
  t.check(twinned.length >= 4 && twinned.every(function (entry) {
    return entry.kind === 'management' &&
           Array.isArray(entry.consoleMembers) &&
           entry.consoleMembers.length > 0 &&
           routes.some(function (other) {
             return other.kind === 'console' &&
                    other.path === entry.consoleTwin;
           });
  }), '5a. each names the console members it leaves out and a twin that ' +
      'is registered', twinned.map(pathOf).join(', '));
  const helpersLeft = routes.filter(function (entry) {
    return entry.kind === 'management' && Array.isArray(entry.actions) &&
           entry.actions.some(function (action) {
             return (entry.consoleActions || [])
               .indexOf(action.action) >= 0;
           });
  });
  t.check(helpersLeft.length === 0,
          '5b. a form helper that moved is no longer an action of its old ' +
          'route', helpersLeft.map(pathOf).join(', ') || 'none left behind');

  // --- 5c. rule 7 for a page whose own operation moved ----------------------
  // Every page a console GET draws is still mirrored by a management
  // operation: by its `mirrors`, or — for a drawing — by the operation its
  // data comes from, which names the page in `drawnOn`.
  const mirroredByManagement = {};
  index.forEach(function (row) {
    mirroredByManagement[String(row.mirrors || '')
      .replace(/^GET\s+/, '')] = true;
    (row.drawnOn || []).forEach(function (page) {
      mirroredByManagement[page] = true;
    });
  });
  const orphaned = all.filter(function (row) {
    const page = /^GET (\/admin\S*)$/.exec(String(row.mirrors || ''));
    return row.kind === 'console' && row.method === 'GET' && page &&
           !mirroredByManagement[page[1]];
  }).map(function (row) {
    return row.path + ' (' + row.mirrors + ')';
  });
  t.check(orphaned.length === 0,
          '5c. every page a console operation draws is still mirrored by a ' +
          'management operation, through `mirrors` or `drawnOn` (rule 7)',
          orphaned.join(', ') || 'none orphaned');

  // --- 6. the role and the scope --------------------------------------------
  t.log.info('=== 6. ADMIN_CONSOLE and admin:console ===');
  const row = roles.NATIVE_ROLES.filter(function (one) {
    return one.name === 'ADMIN_CONSOLE';
  })[0];
  t.check(!!row && row.permission === 'admin:console' &&
          (row.seedConferredBy || []).indexOf('sts-admin-console') >= 0 &&
          !(row.seedApplications || []).length,
          '6a. ADMIN_CONSOLE is a native role authorizing admin:console, ' +
          'conferred by the console\'s client and held by no member',
          JSON.stringify(row || null));
  t.check(scopePolicy.ADMIN_SCOPES.indexOf('admin:console') >= 0,
          '6b. admin:console is one of the management API\'s protected ' +
          'scopes, so only a client declaring it is issued it');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_api_kinds',
  describe: 'the management API and the admin console\'s own operations are ' +
            'two kinds: the path, the documents, the lists and the role ' +
            'follow from one field (#454)',
  run: run
};
