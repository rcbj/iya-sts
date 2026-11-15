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
 * `GET /admin-api/pki`'s `revocationNote` as a product-mode process writes
 * it under the default revocation policy.
 *
 * @returns {string} the sentence
 */
function productRevocationNote() {
  log.debug("Entering productRevocationNote().");
  const program = [
    'require(' + JSON.stringify(path.join(ROOT, 'common',
                                          'protocol_stack')) + ');',
    'const v = require(' + JSON.stringify(path.join(ROOT, 'admin-ui',
      'pki_admin')) + ').pkiView({ query: {} });',
    'process.stdout.write("\\n@@NOTE@@" + JSON.stringify(v.revocationNote));',
    'process.exit(0);'
  ].join('\n');
  const out = require('child_process').execFileSync(process.execPath,
    ['-e', program], { env: Object.assign({}, process.env,
      { STS_MODE: 'product', STS_LOG_LEVEL: 'fatal' }),
    maxBuffer: 64 * 1024 * 1024 }).toString('utf8');
  const at = out.lastIndexOf('@@NOTE@@');
  log.debug("Leaving productRevocationNote().");
  return JSON.parse(out.slice(at + '@@NOTE@@'.length));
}

/**
 * The constant tables `GET /admin-api/acme`, `/est`, `/scep` and their
 * monitors draw (#444, phase 5, the `apis2` slice), read off the modules
 * that hold them so the Rust views carry Node's words rather than a copy.
 *
 * @returns {any} the tables
 */
function familyViewTables() {
  log.debug("Entering familyViewTables().");
  const mod = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const core = mod('common/cert_enrollment');
  const acme = mod('acme/acme');
  const acmeConsole = mod('acme/acme_console');
  const estConsole = mod('est/est_console');
  const scep = mod('scep/scep');
  const scepConsole = mod('scep/scep_console');
  const cms = mod('scep/scep_cms');
  const requirement = mod('common/mode').REQUIREMENTS.filter(function (one) {
    return one.id === 'certificate-enrollment';
  })[0] || null;
  const out = {
    profileIds: core.PROFILE_IDS.slice(),
    deviceProfile: core.DEVICE_PROFILE,
    profileNeeds: core.PROFILE_NEEDS,
    refusedProfiles: core.REFUSED_PROFILES,
    requirement: requirement,
    revocationReasonIds: mod('common/pki_revocation').REASONS.map(
      function (one) {
        return one.id;
      }),
    acme: {
      challengeType: acme.CHALLENGE_TYPE,
      identifierTypes: acme.IDENTIFIER_TYPES,
      profileDescriptions: acme.PROFILE_DESCRIPTIONS,
      actions: acmeConsole.ACME_ACTIONS.slice()
    },
    est: {
      operations: estConsole.OPERATIONS,
      revocationReasons: estConsole.REVOCATION_REASONS,
      actions: estConsole.EST_ACTIONS.slice(),
      keyAlgorithms: mod('common/crypto_impl/key_material').keyAlgIds(),
      signatureAlgorithms: mod('est/est_codec').SIGNATURE_ALGORITHMS
    },
    scep: {
      capabilities: scep.CAPABILITIES.slice(),
      operations: scep.OPERATIONS.slice(),
      messageTypes: cms.MESSAGE_TYPES,
      algorithms: cms.algorithms(),
      exceptions: scepConsole.EXCEPTIONS.slice(),
      revokeReasons: scepConsole.REVOKE_REASONS.slice(),
      actions: scepConsole.SCEP_ACTIONS.slice()
    }
  };
  // `GET /admin-api/pki`'s constant members, taken from Node's own answer
  // in a realm with nothing built: the vocabularies, the tiers, the
  // report's sentences and the published action list. What varies with
  // the hierarchy, the entries or the settings is computed in Rust.
  const view = mod('admin-ui/pki_admin').pkiView({ query: {} });
  out.pki = {
    keyAlgorithms: view.keyAlgorithms,
    signatureAlgorithms: view.signatureAlgorithms,
    tiers: view.tiers,
    revocationNote: view.revocationNote,
    // The same sentence in product mode, whose default revocation policy
    // hard-fails (`revocation_status.describePolicy()`), from a child
    // started in that mode: the mode is read once, at start.
    revocationNoteProduct: productRevocationNote(),
    residency: view.residency,
    encoder: view.encoder,
    actions: view.actions,
    personSigningKeyMax: view.personSigningKeyMax,
    personRevocationReasons: view.personRevocationReasons,
    personAttributes: view.personAttributes,
    personIssuerAttribute: view.personIssuerAttribute,
    subjectKinds: view.subjectKinds,
    purposes: view.purposes,
    tierLabels: view.tierLabels,
    serviceScope: view.serviceScope,
    reasons: view.revocation.reasons,
    crlLifetimeMinutes: view.revocation.crlLifetimeMinutes
  };
  // `protocolEndpoints` (`admin-core/protocol_endpoints.ts`'s `forPage()`),
  // which the management API appends to a GET mirroring a Protocols page:
  // each family view's HTTP rows, built against a marker base the Rust view
  // replaces with the request's realm base. A socket row reports a live
  // listener and is not a table, so none is kept here.
  const endpoints = mod('admin-core/protocol_endpoints');
  const api = mod('mgmt-api/admin_api');
  const marker = { headers: { host: 'marker.invalid' }, protocol: 'https',
                   secure: true, socket: {}, connection: {},
                   get: function (name) {
                     return this.headers[String(name).toLowerCase()];
                   } };
  out.protocolEndpoints = {};
  ['getPki', 'getAcme', 'getEst', 'getScep'].forEach(function (id) {
    const row = api.ROUTES.filter(function (one) {
      return one.operationId === id;
    })[0];
    const page = /^GET (\/admin\S*)$/.exec(String(row.mirrors || ''));
    out.protocolEndpoints[id] = (endpoints.forPage(marker, page[1]) || [])
      .filter(function (one) {
        return !one.transport;
      }).map(function (one) {
        return Object.assign({}, one, {
          url: String(one.url).replace('https://marker.invalid', '') });
      });
  });
  log.debug("Leaving familyViewTables().");
  return out;
}

/**
 * `GET /admin-api/users/new`'s constant members (#444, phase 5, the `apis5`
 * slice), in a realm with no custom attribute: the credential catalogue
 * (`vcClaims.personFields()`, as `newUserJson()` maps it), the field grid's
 * groups and attributes (`personEditor`), the credential choices, the
 * attributes one box holds whole, and the form's own rows BEFORE
 * `newUserFieldRows()` applies the attribute policy — each with the base
 * `simple` the policy widens and the claim it reaches — so the Rust view
 * marks what the realm's policy requires as Node does.
 *
 * @returns {any} the tables
 */
function newUserFormTables() {
  log.debug("Entering newUserFormTables().");
  const mod = function (name) {
    return require(path.join(ROOT, name));
  };
  const vcClaims = mod('oid4vc/vc_claims');
  const personEditor = mod('ldap/person_editor');
  const views = mod('admin-core/admin_views');
  const catalogue = vcClaims.personFields();
  const claimOf = {};
  catalogue.forEach(function (row) {
    claimOf[row.ldap.toLowerCase()] = row.claim.join('.');
  });
  // `newUserFieldRows()`'s rows, as it builds them before the policy.
  const rows = personEditor.editableAttributes().filter(function (row) {
    return row.group !== 'policies';
  }).map(function (row) {
    return { name: row.name, label: row.label, schema: row.schema,
             multi: row.multi, note: row.note, group: row.group,
             example: row.example, simple: !!row.simple };
  });
  catalogue.forEach(function (row) {
    const known = rows.some(function (one) {
      return one.name.toLowerCase() === row.ldap.toLowerCase();
    });
    if (!known) {
      rows.push({ name: row.ldap, label: row.label, schema: row.schema,
                  multi: false, note: '',
                  group: personEditor.groupOf(row.ldap) === 'other' &&
                    row.ldap.toLowerCase() === 'mail'
                    ? 'contact' : personEditor.groupOf(row.ldap),
                  example: personEditor.FIELD_EXAMPLES[
                    row.ldap.toLowerCase()] || '',
                  simple: row.ldap.toLowerCase() === 'mail' });
    }
  });
  const out = {
    fields: catalogue.map(function (row) {
      return { attribute: row.ldap, label: row.label, schema: row.schema,
               claim: row.claim.slice(0), invented: !!row.from };
    }),
    fieldGroups: personEditor.FIELD_GROUPS.map(function (group) {
      return { id: group.id, label: group.label, what: group.what };
    }),
    gridFields: personEditor.editableAttributes().map(function (row) {
      return { attribute: row.name, label: row.label, group: row.group,
               multi: row.multi, example: row.example,
               simple: row.simple, takes: row.note || 'text',
               custom: !!row.custom };
    }),
    credentials: views.CREDENTIAL_CHOICES.map(function (one) {
      return { id: one.id, label: one.label, what: one.what };
    }),
    rows: rows.map(function (row) {
      return Object.assign({}, row,
        { claim: claimOf[row.name.toLowerCase()] || '' });
    }),
    longTextAttributes: mod('common/applications').LONG_TEXT_ATTRIBUTES || [],
    defaultCredential: mod('admin-core/admin_actions').DEFAULT_CREDENTIAL,
    passwordSentences: mod('common/password_policy').SENTENCES
  };
  log.debug("Leaving newUserFormTables().");
  return out;
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
  // The certificate enrollment tab's settings blocks (#444, phase 5, the
  // `apis2` slice): one page, each family's group alone.
  // And the groups page's (#444, phase 5, the `apis3` slice).
  // And the role roster's and the new-user form's (the `apis5` slice).
  const blockPages = ['/admin/cert-issuance', '/admin/pki', '/admin/groups',
                      '/admin/rbac'];
  blockPages.forEach(function (page) {
    const block = admin.configSettingsJson(page);
    pageSettings[page] = {
      groups: block.groups.map(function (group) {
        return group.group;
      }),
      sharedWith: block.sharedWith
    };
  });
  // THE PROTOCOL SETTINGS PAGES (#444, the `apis5` slice): each
  // `get…Settings` operation's answer less its settings block (computed in
  // Rust from `pageSettings`, added here for each page) and its `status`
  // (the mechanism's live state, not a table).
  const settingsOperations = {};
  api.ROUTES.forEach(function (entry) {
    const m = /^GET (\/admin\/\S+)$/.exec(String(entry.mirrors || ''));
    if (!m || !/^get\w+Settings$/.test(entry.operationId || '')) {
      return;
    }
    // The two VC operations draw a page of their own under /admin/vc
    // (`settingsPage` in admin_api.ts's SETTINGS_PAGES).
    const asked = entry.operationId === 'getOid4vciSettings'
      ? '/admin/oid4vci'
      : (entry.operationId === 'getOid4vpSettings' ? '/admin/oid4vp' : m[1]);
    let page = null;
    try {
      page = admin.protocolSettingsJsonFor(asked);
    } catch (e) {
      log.debug("Caught in tables(): " + ((e && e.message) || e));
      page = null;
    }
    if (!page) {
      return;
    }
    const out = Object.assign({}, page);
    const block = out.settings || {};
    delete out.settings;
    delete out.status;
    out.settingsPage = block.page;
    out.settingsGroups = (block.groups || []).map(function (group) {
      return group.group;
    });
    settingsOperations[entry.operationId] = out;
    if (block.page && !pageSettings[block.page]) {
      const whole = admin.configSettingsJson(block.page);
      pageSettings[block.page] = {
        groups: whole.groups.map(function (group) {
          return group.group;
        }),
        sharedWith: whole.sharedWith
      };
    }
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
                                    'admin_scope')).SERVICE_PAGES,
    // The settings a realm administrator may not write (#444, the `apis2`
    // slice): `admin_scope.ts`'s two lists, beside the per-process keys.
    serviceSettingKeys: require(path.join(ROOT, 'admin-ui',
                                          'admin_scope')).SERVICE_SETTING_KEYS,
    serviceSettingPrefixes: require(path.join(ROOT, 'admin-ui',
      'admin_scope')).SERVICE_SETTING_PREFIXES,
    // The Account API's Overview draws a person's entry against the
    // inetOrgPerson schema's fixed list (`common/inetorgperson.ts`, 3z).
    inetOrgPersonClasses: require(path.join(ROOT, 'common',
                                            'inetorgperson')).CLASSES,
    familyViews: familyViewTables(),
    newUserForm: newUserFormTables(),
    settingsOperations: settingsOperations,
    // `GET /admin-api/tokens`' constant members (the `apis5` slice): the
    // issued families and the kinds the console offers to revoke.
    issued: {
      families: require(path.join(ROOT, 'common',
                                  'admin_stats')).ISSUED_FAMILIES,
      revocableKinds: require(path.join(ROOT, 'common',
                                        'admin_stats')).REVOCABLE_KINDS
    }
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
