#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: export-admin-api-tables.js
//
// ---------------------------------------------------------------------------
// THE ROUTING ROWS `/admin-api` KEEPS IN CODE, FOR `sts-mgmt-api` (#444,
// phase 4, the `mgmtapi` slice).
//
// The model (`models/api/management.tsp`, `console.tsp`) is the document:
// every operation, its parameters, its body and its answers, which the Rust
// crate reads as generated (`rust/crates/sts-mgmt-api/src/generated/`). What
// the model does not hold is what `mgmt-api/admin_api.ts`'s route table and
// the console beside it hold in code: which console control an operation
// mirrors, the pages a drawing is drawn on, the tag it is filed under, the
// actions a `:action` route carries and the form helpers that left it, the
// members a console twin answers alone, the document's frame (its prose, its
// tags, its security schemes) and the console's settings homes. They are
// exported here, as JSON, the way `export-rust-tables.js` exports the
// settings table, and the Rust crate's build refuses an operation the model
// has and these rows do not, or the other way round.
//
// It loads the whole stack, so it runs where TypeScript is compiled: the
// tests image.
//
//   node tests/tools/export-admin-api-tables.js           write the file
//   node tests/tools/export-admin-api-tables.js --check   exit 1 when stale
//
// The vector builder `mgmtApiVectors()` in `crypto-vectors.js` carries the
// same object, so `sts-mgmt-api`'s vector test fails when the committed file
// has drifted from the Node table.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'export-admin-api-tables',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..', '..');
const FILE = path.join(ROOT, 'rust', 'crates', 'sts-mgmt-api', 'tables',
                       'admin_api.json');

// What the frame's two request-dependent values are written as.
const BASE_MARK = '@@BASE@@';
const VERSION_MARK = '@@VERSION@@';

/**
 * The document `buildSpec()` makes for one kind, less what the model holds.
 *
 * @param {any} api - mgmt-api/admin_api
 * @param {any} spec - mgmt-api/admin_api_spec
 * @param {string} kind - `management` or `console`
 * @param {boolean} authRequired - whether the gate is on
 * @returns {any} the frame
 */
function frameOf(api, spec, kind, authRequired) {
  log.debug("Entering frameOf().");
  const routes = api.ROUTES.filter(function (entry) {
    return (entry.kind || 'management') === kind;
  });
  const built = spec.buildSpec(routes, { baseUrl: BASE_MARK,
    version: VERSION_MARK, authRequired: authRequired,
    console: kind === 'console' });
  const frame = JSON.parse(JSON.stringify(built));
  frame.paths = Object.keys(built.paths).map(function (p) {
    return { path: p, methods: Object.keys(built.paths[p]) };
  });
  frame.components = Object.assign({}, frame.components);
  delete frame.components.schemas;
  log.debug("Leaving frameOf().");
  return frame;
}

/**
 * The tables, as the Rust crate reads them.
 *
 * @returns {any} the export
 */
function tables() {
  log.debug("Entering tables().");
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const api = require(path.join(ROOT, 'mgmt-api', 'admin_api'));
  const spec = require(path.join(ROOT, 'mgmt-api', 'admin_api_spec'));
  const admin = require(path.join(ROOT, 'admin-ui', 'admin'));
  const realms = require(path.join(ROOT, 'common', 'realms'));
  const rows = [];
  api.ROUTES.forEach(function (entry) {
    const shared = {
      method: entry.method,
      kind: entry.kind || 'management',
      tag: entry.tag || ''
    };
    if (entry.consoleMembers) {
      shared.consoleMembers = entry.consoleMembers.slice(0);
      shared.consoleTwin = entry.consoleTwin;
    }
    if (entry.handlerOwnsBody) {
      shared.handlerOwnsBody = true;
    }
    if (entry.drawnOn) {
      shared.drawnOn = entry.drawnOn.slice(0);
    }
    if (!entry.actions) {
      rows.push(Object.assign({ path: entry.path,
        operationId: entry.operationId, mirrors: entry.mirrors || '' },
      shared));
      return;
    }
    entry.actions.forEach(function (action) {
      const row = Object.assign({
        path: entry.route.replace(':action', action.action),
        operationId: action.operationId,
        mirrors: action.mirrors || entry.mirrors || '',
        route: entry.route, action: action.action }, shared);
      if (action.writesNothing) {
        row.writesNothing = true;
      }
      rows.push(row);
    });
  });
  // The `:action` routes, each with the actions it carries and the form
  // helpers that moved to the console (#454).
  const routes = api.ROUTES.filter(function (entry) {
    return !!entry.actions;
  }).map(function (entry) {
    const out = { method: entry.method, route: entry.route,
                  kind: entry.kind || 'management',
                  actions: entry.actions.map(function (one) {
                    return one.action;
                  }) };
    if (entry.consoleActions) {
      out.consoleActions = entry.consoleActions.slice(0);
    }
    return out;
  });
  const config = admin.configJson();
  const pageSettings = {};
  ['/admin/config', '/admin/realms'].forEach(function (page) {
    const block = admin.configSettingsJson(page);
    pageSettings[page] = {
      groups: block.groups.map(function (group) {
        return group.group;
      }),
      sharedWith: block.sharedWith
    };
  });
  // The frame drawn for nobody in particular: every section.
  const frame = admin.shellJson(null, null, null);
  const out = {
    rows: rows,
    routes: routes,
    frames: {
      management: { on: frameOf(api, spec, 'management', true),
                    off: frameOf(api, spec, 'management', false) },
      console: { on: frameOf(api, spec, 'console', true),
                 off: frameOf(api, spec, 'console', false) }
    },
    homes: config.homes,
    homeProblems: config.homeProblems,
    pageSettings: pageSettings,
    consolePages: admin.consolePages(),
    realmSupport: realms.realmSupport(),
    // THE CONSOLE'S FRAME (#444, the `apis` slice): `SECTIONS` as the
    // sidebar draws them for a service administrator, every page's nav
    // label, and the pages a realm administrator may not reach
    // (`admin_scope.ts`'s `SERVICE_PAGES`) — what `GET /admin-api/console`
    // and the dashboard filter `sections` by.
    consoleSections: frame.sections,
    navLabels: frame.navLabels,
    servicePages: require(path.join(ROOT, 'admin-ui',
                                    'admin_scope')).SERVICE_PAGES
  };
  log.debug("Leaving tables(). " + rows.length + " row(s).");
  return out;
}

/**
 * The text the file should hold.
 *
 * @returns {string} the text
 */
function rendered() {
  log.debug("Entering rendered().");
  const text = JSON.stringify(tables(), null, 1) + '\n';
  log.debug("Leaving rendered().");
  return text;
}

if (require.main === module) {
  const text = rendered();
  if (process.argv.indexOf('--check') >= 0) {
    let current = null;
    try {
      current = fs.readFileSync(FILE, 'utf8');
    } catch (e) {
      log.debug("Caught in export-admin-api-tables.js: " +
                ((e && e.message) || e));
      current = null;
    }
    if (current !== text) {
      console.error('stale: ' + path.relative(ROOT, FILE) +
                    ' — run node tests/tools/export-admin-api-tables.js');
      process.exit(1);
    }
    console.log('the admin API tables are current');
    process.exit(0);
  }
  const out = process.argv[2] || FILE;
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, text);
  console.log('wrote ' + out);
  process.exit(0);
}

module.exports = { tables: tables, rendered: rendered, BASE_MARK: BASE_MARK,
                   VERSION_MARK: VERSION_MARK };
