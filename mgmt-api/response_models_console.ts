// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_console.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): the console-only operations (`kind: console`,
// `/admin-api/console/*`).
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
//
// **THE DRAWINGS SHARE ONE GRAPH.** A node or an edge here came from one of
// three builders: `common/delegation.js`'s `graph()`, `common/app_permissions`'
// `graph()` (which reuses the shape and adds what a grant knows) and
// `common/user_graph.ts`'s `graphFor()` (which adds what an issuance knows). A
// page reads them through one renderer, so they are one model, closed, with
// every member any of the three can write and none of them required.
//
// **A DRAWING'S `format=svg` IS A SECOND MEDIA TYPE ON THE SAME 200**, so those
// five operations are `Kit.media('image/svg+xml')` with the JSON model under
// `schema`.
//
// **EVERY TOP LEVEL HERE IS A `closed()` OBJECT, NEVER A UNION.**
// `ResponseModels.apply()` adds `protocolEndpoints` to a model's `properties`
// for a GET mirroring a Protocols page, and a union has none to add it to.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

const STR = Kit.str();
const INT = Kit.int();
// A number where the source does not promise a whole one: a time read back out
// of a store, a count summed from a register row.
const NUM = Kit.num();
const BOOL = Kit.bool();
const STRS = Kit.listOf(STR);
const NSTR = Kit.nullable(STR);

const PAGING: Json = Kit.closed({
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  total: INT, param: NSTR, noun: NSTR
});

const ROLE_COUNTS: Json = Kit.closed({
  initial: INT, intermediary: INT, target: INT
});

// `delegation.js`'s `party()`.
const PARTY: Json = Kit.closed({
  key: STR, presented: STR, application: STR, what: STR
});

// `delegation.js`'s `credential()`, one kind's worth on an act.
const ACT_CREDENTIAL: Json = Kit.closed({
  kind: STR, identifier: STR, note: STR
});

// `recordUnguarded()`, and what another process's replicated row carries. An
// act written before a member existed lacks it, so nothing here is required.
const ACT: Json = Kit.closed({
  seq: NUM, origin: NSTR, at: NUM, protocol: STR, type: STR, typeLabel: STR,
  mode: STR, spec: STR, policed: BOOL, outcome: STR, initial: PARTY,
  intermediary: PARTY, target: PARTY, authorizedBy: STR, reason: STR,
  consumed: Kit.listOf(ACT_CREDENTIAL), produced: Kit.listOf(ACT_CREDENTIAL),
  sessionId: STR, note: STR, chainKey: STR
});

// `chainList()`, one row per relationship.
const CHAIN: Json = Kit.closed({
  chainKey: STR, protocol: STR, type: STR, typeLabel: STR, mode: STR,
  initial: PARTY, intermediary: PARTY, target: PARTY, acts: INT, issued: INT,
  refused: INT, firstAt: NUM, lastAt: NUM, authorizedBy: STR, reason: STR
});

// `foldCredentials()`'s row: every credential of one kind on one line.
const FOLDED: Json = Kit.closed({
  kind: STR, count: INT, identifiers: STRS, moreIdentifiers: INT, notes: STRS
});

const REALM_NAMED: Json = Kit.closed({ id: STR, name: STR, isDefault: BOOL });

const NODE: Json = Kit.closed({
  id: STR, kind: STR, realm: REALM_NAMED, issuer: STR, roles: ROLE_COUNTS,
  acts: INT, issued: INT, refused: INT, key: STR, presented: STR,
  application: STR, aliases: STRS, what: STR, protocols: STRS, firstAt: NUM,
  lastAt: NUM, selfTarget: BOOL, chiefRole: STR,
  // The grants' picture (`app_permissions.ts`).
  grants: INT, exposes: INT, dangling: INT,
  // The person's picture (`user_graph.ts`, `normaliseNode()`).
  credentials: INT, flows: STRS, authentications: INT, isSubject: BOOL,
  isClient: BOOL, kinds: STRS
});

// One family of sign-ins on the person's `signed-in` line.
const EDGE_AUTHENTICATION: Json = Kit.closed({
  protocol: STR, method: STR, count: INT, at: NUM, lastAt: NUM
});

const EDGE: Json = Kit.closed({
  id: STR, from: STR, to: STR, fromRole: STR, toRole: STR, relation: STR,
  skipped: STRS, chainKey: STR, protocol: STR, protocols: STRS, type: STR,
  typeLabel: STR, mode: STR, spec: STR, policed: BOOL, subject: STR,
  actor: STR, acts: INT, issued: INT, refused: INT, firstAt: NUM, lastAt: NUM,
  authorizedBy: STR, reason: STR, consumed: Kit.listOf(FOLDED),
  produced: Kit.listOf(FOLDED),
  // A configured pair beside the acts (#186).
  attribute: STR, mechanism: STR, setOn: STR, used: BOOL,
  // A grant's line. `app_permissions.ts` seeds the two folds and nothing
  // empties them, so they are always `{}` there.
  consumedFold: Kit.mapOf(FOLDED), producedFold: Kit.mapOf(FOLDED),
  permissionId: STR, permissionName: STR, baseUri: STR, description: STR,
  asked: BOOL,
  // The person's picture.
  credentials: INT, authentications: Kit.listOf(EDGE_AUTHENTICATION),
  audience: STR, audienceRegistered: BOOL, permissions: STRS, scopes: STRS
});

const TOKEN_ROW: Json = Kit.closed({
  seq: NUM, at: NUM, kind: STR, identifier: STR, note: STR, protocol: STR,
  type: STR, typeLabel: STR, mode: STR, chainKey: STR, subject: STR,
  actor: STR, target: STR
});

// `user_graph.ts`'s `credentialsFor()`.
const CREDENTIAL_ROW: Json = Kit.closed({
  at: NUM, family: STR, kind: STR, identifier: STR, flow: STR, flowLabel: STR,
  flowProtocol: STR, flowSpec: STR, flowOidc: STR, flowStated: BOOL,
  holder: STR, audience: STR, scope: STR, issuer: STR, state: NSTR,
  sessionId: STR, revocable: BOOL, revoked: BOOL, detail: STR,
  expiresAtMs: NUM
});

const GRAPH: Json = Kit.closed({
  realm: REALM_NAMED, issuer: STR, nodes: Kit.listOf(NODE),
  edges: Kit.listOf(EDGE), tokens: Kit.listOf(TOKEN_ROW), tokensLeftOff: INT,
  maxTokenRows: INT, acts: INT, chains: INT,
  // `app_permissions.ts`.
  counts: Kit.closed({ nodes: INT, edges: INT, grants: INT }),
  // `user_graph.ts`.
  credentials: Kit.listOf(CREDENTIAL_ROW), credentialsOnDelegationLines: INT,
  subject: STR
});

// `delegationNodeLook()`.
const LOOK: Json = Kit.closed({
  shape: STR, label: STR, sublabel: NSTR, identifier: NSTR, title: STR,
  href: NSTR, dashed: BOOL
});

const DRAWING: Json = Kit.closed({
  width: NUM, height: NUM, failed: NSTR
});

// `delegationFacts()`: the strings in an answer that name somebody. The keys
// are those strings, whatever the answer held.
const FACTS: Json = Kit.closed({
  users: Kit.mapOf(BOOL, 'Each name in the answer that is a known person.'),
  apps: Kit.mapOf(Kit.closed({ name: STR, dnLabel: STR }),
                  'Each name in the answer the registry holds.')
});

const APP_ROW: Json = Kit.closed({
  key: STR, identifier: STR, spellings: STRS, roles: ROLE_COUNTS,
  protocols: STRS, acts: INT, issued: INT, refused: INT, credentials: INT,
  firstAt: NUM, lastAt: NUM, identityKey: STR, chains: INT
});

const TOKEN_COUNTS: Json = Kit.closed({
  issued: INT, valid: INT, expired: INT, revoked: INT, other: INT
});

// `userGraph`'s `rowFromStats()` and `foldDelegation()`.
const USER_ROW: Json = Kit.closed({
  key: STR, name: STR, presented: STR, forms: STRS, authenticated: BOOL,
  isClient: BOOL, authentications: INT, protocols: STRS, tokens: TOKEN_COUNTS,
  artifacts: INT, lastAt: NUM, delegated: BOOL, acts: INT, issued: INT,
  refused: INT, chains: INT, roles: ROLE_COUNTS
});

// `delegationChooser()`.
const CHOOSER: Json = Kit.closed({
  total: INT,
  entries: Kit.listOf(Kit.closed({
    key: STR, names: STRS, label: STR, detail: STR, href: STR
  })),
  slice: Kit.closed({ matched: INT, from: INT }),
  search: Kit.strEnum(['contains', 'exact']),
  complete: BOOL
});

const GRANTED_TO: Json = Kit.closed({
  identifier: STR, name: STR, asked: BOOL
});

const GRANT: Json = Kit.closed({
  client: STR, clientName: STR, permissionId: STR, resource: STR,
  resourceName: STR, baseUri: STR, permissionName: STR, description: STR,
  dangling: BOOL, asked: BOOL
});

const PERMISSION: Json = Kit.closed({
  resource: STR, resourceName: STR, baseUri: STR, name: STR, description: STR,
  id: NSTR, raw: STR, grantedTo: Kit.listOf(GRANTED_TO)
});

const RESOURCE: Json = Kit.closed({
  identifier: STR, name: STR, baseUri: STR, rawBaseUri: STR,
  permissions: Kit.listOf(Kit.closed({
    name: STR, description: STR, id: NSTR, raw: STR,
    grantedTo: Kit.listOf(GRANTED_TO)
  })),
  grantsHeld: INT
});

const REGISTER_COUNTS: Json = Kit.closed({
  resources: INT, permissions: INT, unidentified: INT, grants: INT,
  dangling: INT, unused: INT, ungranted: INT, clients: INT
});

const REGISTER: Json = Kit.closed({
  resources: Kit.listOf(RESOURCE), permissions: Kit.listOf(PERMISSION),
  grants: Kit.listOf(GRANT), counts: REGISTER_COUNTS
});

const CLUSTER_COUNTS: Json = Kit.closed({
  applications: INT, grants: INT, lines: INT, permissions: INT, dangling: INT,
  selfGrants: INT, asked: INT, unused: INT
});

const CLUSTER: Json = Kit.closed({
  key: STR, members: STRS, grants: Kit.listOf(GRANT),
  permissions: Kit.listOf(PERMISSION), counts: CLUSTER_COUNTS
});

const CLUSTER_SUMMARY: Json = Kit.closed({
  key: STR, members: STRS, counts: CLUSTER_COUNTS
});

const GROUP_COUNTS: Json = Kit.closed({
  clusters: INT, applications: INT, largest: INT, alone: INT, joined: INT
});

const CLUSTERS: Json = Kit.closed({
  clusters: Kit.listOf(CLUSTER),
  memberOf: Kit.mapOf(STR, 'Each application, to its group\'s key.'),
  counts: GROUP_COUNTS
});

const PAGE_OF_GRANTS: Json = Kit.closed({
  shown: Kit.listOf(GRANT), paging: PAGING
});

const PAGE_OF_PERMISSIONS: Json = Kit.closed({
  shown: Kit.listOf(PERMISSION), paging: PAGING
});

// A setting's value is what its row's type says: a scalar, or a `csv` row's
// list. `dflt` may be a function's answer, of the same kinds.
const SETTING_VALUE: Json = {
  type: ['string', 'number', 'boolean', 'array', 'null'],
  items: { type: ['string', 'number', 'boolean'] }
};

const SELECT_ALL_RULE: Json = Kit.listOf(Kit.closed({
  setting: STR, values: STRS, on: BOOL, canBeOn: BOOL
}));

// `common/config.js`'s `describe()`.
const SETTING: Json = Kit.closed({
  key: STR, group: STR, label: STR, description: STR, type: STR,
  enumValues: STRS, csvValues: STRS, ordered: BOOL,
  csvValueNotes: Kit.mapOf(STR, 'A sentence per value of the row.'),
  selectAll: Kit.closed({ onlyWhileOn: SELECT_ALL_RULE,
                          aloneWhileOn: SELECT_ALL_RULE }),
  min: NUM, max: NUM, step: NUM, value: SETTING_VALUE, text: NSTR,
  source: STR, editable: BOOL, restartReason: NSTR, editRefusal: NSTR,
  env: NSTR, legacyEnv: Kit.nullable(Kit.oneOrMany(STR)), appconfigPath: STR,
  default: SETTING_VALUE, realmSettable: BOOL, overridden: BOOL
});

// `admin.ts`'s `configSettingsJson()`, or null with no filler installed.
const SETTINGS_BLOCK: Json = Kit.nullable(Kit.closed({
  page: STR,
  groups: Kit.listOf(Kit.closed({ group: STR,
                                  settings: Kit.listOf(SETTING) })),
  settingCount: INT, editableCount: INT, overridden: STRS, setWith: STR,
  context: Kit.closed({
    configFile: NSTR, defaultsFile: NSTR, persistsAppconfig: BOOL,
    persistsRealms: BOOL, persistenceMode: STR, inRealm: BOOL, realmId: STR
  }),
  sharedWith: Kit.mapOf(Kit.listOf(Kit.closed({ path: STR, label: STR })),
                        'The other pages a settings group is drawn on.')
}));

// `Negotiated` in `common/i18n.ts`.
const NEGOTIATED: Json = Kit.closed({
  locale: STR, chain: STRS, catalog: STR,
  direction: Kit.strEnum(['ltr', 'rtl']), matched: BOOL
});

// `PageLocale.consoleData()`, or `consoleLanguage()` with `catalogs=files`.
const CONSOLE_LOCALE: Json = Kit.closed({
  negotiated: NEGOTIATED,
  offered: Kit.listOf(Kit.closed({ tag: STR, name: STR })),
  catalogs: Kit.mapOf(Kit.mapOf(STR, 'A translated message by its key.'),
                      'Each catalog along the chain, by language tag.'),
  catalogFiles: Kit.mapOf(STR, 'Each static catalog, by language tag.')
});

// The sidebar's row: a page, or a group of them that `isNavGroup()` recurses
// into. SECTIONS nests no deeper than a group inside a section, and a group
// inside a group is written out once more rather than left unstated.
const NAV_LEAF: Json = {
  path: STR, label: STR, blurb: STR, hidden: BOOL, title: STR, what: STR
};
const NAV_ITEM: Json = Kit.closed(Object.assign({}, NAV_LEAF, {
  items: Kit.listOf(Kit.closed(Object.assign({}, NAV_LEAF, {
    items: Kit.listOf(Kit.closed(NAV_LEAF))
  })))
}));
const SECTION: Json = Kit.closed({
  title: STR, what: STR, items: Kit.listOf(NAV_ITEM)
});

const PERSISTENCE: Json = Kit.closed({ enabled: BOOL, mode: STR });

// `AdminApi.consoleGateOf()`.
const GATE: Json = Kit.closed({
  enforced: BOOL, available: BOOL, session: BOOL, username: STR,
  authority: NSTR, identityRealm: NSTR, readGroup: NSTR, writeGroup: NSTR,
  read: BOOL, write: BOOL, security: BOOL, roles: STRS, open: BOOL,
  closed: BOOL, windowOpens: BOOL, empty: BOOL,
  bootstrapPasswordRequired: BOOL,
  bootstrap: Kit.nullable(Kit.closed({
    username: NSTR, seeded: BOOL, claimedAt: STR
  }))
});

const SHELL: Json = Kit.closed({
  gate: Kit.nullable(GATE), navAuthority: STR,
  roleLabels: Kit.mapOf(STR, 'Each role the gate names, by its id.'),
  realm: Kit.closed({ id: STR, name: STR }), wsTrustIssuer: NSTR,
  realms: Kit.nullable(Kit.listOf(Kit.closed({
    id: STR, name: STR, prefix: STR
  }))),
  realmRoot: STR, portalHref: STR, sections: Kit.listOf(SECTION),
  navLabels: Kit.mapOf(STR, 'Every console page\'s label, by its path.'),
  // `realms.js`'s `retiringState()`.
  retiring: Kit.nullable(Kit.closed({
    since: NUM, sinceIso: STR, inProgress: BOOL, interrupted: BOOL,
    finishesBy: NUM, refusing: STR, why: STR, finish: STR
  })),
  // `shellRuntimeFacts()`: all of these, the mode alone, or none.
  runtime: Kit.closed({
    process: STR, mode: STR, database: STR, keyEncryptionKey: STR,
    databasePassword: STR
  }),
  persistence: PERSISTENCE,
  version: Kit.closed({ version: STR, stamped: BOOL, buildInfo: STR }),
  locale: CONSOLE_LOCALE
});

const LANGUAGE: Json = Kit.closed({
  ok: BOOL, errors: STRS, locale: CONSOLE_LOCALE
}, { required: ['ok'] });

const EXPLORER: Json = Kit.closed({
  page: STR, api: STR, document: STR, version: STR, paths: INT,
  operations: INT, scope: STR, audience: NSTR, tokenInReply: BOOL, who: STR,
  realmPrefix: STR, script: STR
});

// The graph's fields, spread at the top of the map's answer by
// `Object.assign({}, graph, ...)`.
const DELEGATION_FILTER: Json = Kit.closed({
  type: NSTR, mode: NSTR, outcome: NSTR, protocol: NSTR, q: NSTR
});

const SUMMARY: Json = Kit.closed({
  held: INT, heldHere: INT, processes: INT, recorded: INT, dropped: INT,
  maxRecords: INT, chains: INT, oldestSeq: NUM, newestSeq: NUM,
  byType: Kit.mapOf(INT, 'Acts per mechanism.'),
  byMode: Kit.mapOf(INT, 'Acts per mode.'),
  byOutcome: Kit.mapOf(INT, 'Acts per outcome.'),
  byProtocol: Kit.mapOf(INT, 'Acts per protocol.')
});

const TYPE_ROW: Json = Kit.closed({
  type: STR, protocol: STR, mode: STR, label: STR, spec: STR, policed: BOOL,
  what: STR
});

const MODE_ROW: Json = Kit.closed({ mode: STR, label: STR, what: STR });

const ROLE_ROW: Json = Kit.closed({ role: STR, label: STR, what: STR });

const DRAWN = {
  drawing: DRAWING, looks: Kit.mapOf(LOOK, 'Each node\'s look, by node id.'),
  label: STR, svg: STR
};

const DELEGATION_MAP: Json = Kit.closed(Object.assign({}, DRAWN, {
  realm: REALM_NAMED, issuer: STR, nodes: Kit.listOf(NODE),
  edges: Kit.listOf(EDGE), tokens: Kit.listOf(TOKEN_ROW), tokensLeftOff: INT,
  maxTokenRows: INT, acts: INT, chains: INT, filter: DELEGATION_FILTER,
  matched: INT, held: INT, summary: SUMMARY, all: INT,
  types: Kit.listOf(TYPE_ROW), modes: Kit.listOf(MODE_ROW), outcomes: STRS,
  applicationChooser: CHOOSER, userChooser: CHOOSER, mapKey: STR,
  directoryLoaded: BOOL, facts: FACTS
}));

const DELEGATION_CHAIN: Json = Kit.closed(Object.assign({}, DRAWN, {
  chain: Kit.nullable(CHAIN), chainKey: STR, found: BOOL,
  acts: Kit.listOf(ACT), graph: GRAPH, held: INT, maxRecords: INT, mapKey: STR,
  facts: FACTS
}));

const DELEGATION_APPLICATION: Json = Kit.closed(Object.assign({}, DRAWN, {
  application: Kit.nullable(APP_ROW), asked: NSTR, key: STR, registered: BOOL,
  registeredName: STR, acts: Kit.listOf(ACT), graph: GRAPH,
  rolesBySeq: Kit.mapOf(STRS, 'The roles played, by the act\'s `seq`.'),
  applications: Kit.listOf(APP_ROW), held: INT, maxRecords: INT,
  roles: Kit.listOf(ROLE_ROW), chooser: CHOOSER, mapKey: STR, facts: FACTS
}));

// `user_graph.ts`'s FLOWS, or `flowRow()` naming one it has no row for.
const FLOW_ROW: Json = Kit.closed({
  flow: STR, protocol: STR, label: STR, oidc: STR, spec: STR, browser: BOOL,
  what: STR, unknown: BOOL
});

const DELEGATION_USER: Json = Kit.closed(Object.assign({}, DRAWN, {
  user: Kit.nullable(USER_ROW), asked: NSTR, key: STR,
  credentials: Kit.listOf(CREDENTIAL_ROW), flows: Kit.listOf(FLOW_ROW),
  onDelegationLines: INT, acts: Kit.listOf(ACT), graph: GRAPH,
  counts: Kit.nullable(Kit.closed({
    credentials: INT, acts: INT, chains: INT, authentications: INT,
    applications: INT
  })),
  users: Kit.listOf(USER_ROW), usersComplete: BOOL, chooser: CHOOSER,
  mapKey: STR, facts: FACTS
}));

const DELEGATION_ALLOWED: Json = Kit.closed(Object.assign({}, DRAWN, {
  graph: GRAPH, counts: REGISTER_COUNTS, grants: Kit.listOf(GRANT),
  groups: Kit.listOf(CLUSTER_SUMMARY), groupCounts: GROUP_COUNTS,
  groupsPaging: PAGING, register: REGISTER, clusters: CLUSTERS,
  shownGroups: Kit.listOf(CLUSTER), facts: FACTS,
  apps: FACTS.properties.apps
}));

// `permissionGroupsView()`'s two branches and what the drawing adds to either.
const DELEGATION_CLUSTER: Json = Kit.closed(Object.assign({}, DRAWN, {
  application: NSTR, group: Kit.nullable(CLUSTER_SUMMARY),
  grants: Kit.listOf(GRANT), grantsPaging: PAGING,
  permissions: Kit.listOf(PERMISSION), permissionsPaging: PAGING,
  groups: Kit.listOf(CLUSTER_SUMMARY), counts: GROUP_COUNTS, paging: PAGING,
  asked: STR, graph: GRAPH, cluster: Kit.nullable(CLUSTER), register: REGISTER,
  clusters: CLUSTERS, grantPage: PAGE_OF_GRANTS,
  permissionPage: PAGE_OF_PERMISSIONS,
  groupPage: Kit.closed({ shown: Kit.listOf(CLUSTER), paging: PAGING }),
  facts: FACTS, apps: FACTS.properties.apps
}));

const DELEGATION_SETTINGS: Json = Kit.closed({
  allowed: Kit.closed({
    resources: Kit.listOf(RESOURCE), permissions: Kit.listOf(PERMISSION),
    grants: Kit.listOf(GRANT), counts: REGISTER_COUNTS,
    filter: Kit.closed({ permissions: NSTR, grants: NSTR }),
    paging: Kit.closed({ permissions: PAGING, grants: PAGING })
  }),
  settings: SETTINGS_BLOCK, register: REGISTER,
  listState: Kit.closed({
    permWanted: STR, grantWanted: STR, permPage: PAGE_OF_PERMISSIONS,
    grantPage: PAGE_OF_GRANTS
  }),
  allApplications: Kit.listOf(Kit.closed({ identifier: STR, name: STR }))
});

// FEDERATION_GRAPH's `applicationRows()`.
const FEDERATION_USE: Json = Kit.closed({
  application: STR, source: STR, via: STR, configured: BOOL,
  authentications: INT, users: INT, lastUser: STR, lastSeen: STR
});

// `describe()` and what `graph()` adds to each row.
const FEDERATION_ROW: Json = Kit.closed({
  id: STR, name: STR, role: STR, roleLabel: STR, protocol: STR,
  protocolLabel: STR, peer: STR, application: STR, enabled: BOOL, ready: BOOL,
  missing: STRS, usable: BOOL, signsIn: BOOL, signalsEnabled: BOOL,
  authentications: INT, users: INT, lastUser: STR, lastSeen: STR,
  lastError: STR, lastErrorAt: STR, mechanism: STR, mechanismLabel: STR,
  mechanismKnown: BOOL, mechanismConfigured: BOOL, brokersTo: STR,
  brokerUsable: BOOL, brokerProblem: STR,
  brokeredUse: Kit.nullable(FEDERATION_USE), releases: STRS, dn: STR,
  applications: Kit.listOf(FEDERATION_USE), applicationCount: INT,
  attributed: INT, unattributed: INT
});

const FEDERATION_MAP: Json = Kit.closed({
  realm: REALM_NAMED,
  counts: Kit.closed({
    relationships: INT, serviceProvider: INT, identityProvider: INT,
    usable: INT, applications: INT, partners: INT, authentications: INT
  }),
  filter: Kit.closed({ role: STR, protocol: STR, q: STR }),
  empty: BOOL, filtered: BOOL, relationships: Kit.listOf(FEDERATION_ROW),
  nodes: Kit.listOf(Kit.closed({
    id: STR, kind: STR, label: STR, relationships: STRS
  })),
  edges: Kit.listOf(Kit.closed({
    id: STR, from: STR, to: STR, relation: STR, relationship: STR,
    brokeredTo: STR, use: Kit.nullable(FEDERATION_USE)
  })),
  drawing: DRAWING, label: STR, svg: STR,
  roles: Kit.listOf(Kit.closed({
    role: STR, label: STR, short: STR, what: STR
  })),
  protocols: Kit.listOf(Kit.closed({
    protocol: STR, label: STR, family: STR, what: STR, needs: STRS, spec: STR,
    signalsOnly: BOOL
  })),
  mapKey: STR
});

const DASHBOARD: Json = Kit.closed({
  issuer: NSTR, startedAt: STR, uptimeMs: NUM, calls: NUM, tokensHeld: NUM,
  tokensHeldOnly: BOOL, tokensRevoked: NUM, artifactsHeld: NUM,
  signOnSessions: NUM, usersKnown: NUM, usersAuthenticatedHere: NUM,
  pages: STRS, base: STR, persistence: PERSISTENCE, testDouble: BOOL,
  sections: Kit.listOf(SECTION)
});

// An attribute's `editable`: the schema row's word, or false for one that is
// not (`declarationAttributes()` copies the row as it stands).
const EDITABLE_WORD: Json = { type: ['string', 'boolean', 'null'] };

const FAMILY_NAMED: Json = Kit.closed({ id: STR, label: STR });

// `applications.js`'s `applicationFields()` through `typedField()`.
const APPLICATION_FIELD: Json = Kit.closed({
  attribute: STR, type: STR, long: BOOL, editable: EDITABLE_WORD,
  sensitive: BOOL, overrides: STR, choices: Kit.nullable(STRS), example: NSTR,
  what: STR, families: STRS, everyFamily: BOOL, declaration: BOOL,
  primaryName: BOOL, simple: BOOL, group: STR, section: STR,
  sectionLabel: STR, inSimple: BOOL, described: SETTING
});

const NEW_APPLICATION_FORM: Json = Kit.closed({
  directory: BOOL, container: NSTR, max: Kit.nullable(NUM),
  applicationCount: INT, realm: Kit.closed({ id: STR, name: STR }),
  kinds: Kit.listOf(Kit.closed({ kind: STR, label: STR, what: STR })),
  protocols: Kit.listOf(Kit.closed({
    id: STR, label: STR, what: STR, kind: STR, kinds: STRS,
    identifierAttribute: STR, redirectAttribute: STR, logoutAttribute: STR,
    deliveryAttribute: STR, eventsAttribute: STR, secretAttribute: STR
  })),
  declarations: Kit.listOf(Kit.closed({
    attribute: STR, role: STR, kind: STR, editable: EDITABLE_WORD,
    sensitive: BOOL, what: STR, families: Kit.listOf(FAMILY_NAMED),
    everyFamily: BOOL
  })),
  fields: Kit.listOf(APPLICATION_FIELD),
  fieldGroups: Kit.listOf(Kit.closed({
    id: STR, label: STR, families: STRS
  })),
  familyChoices: Kit.listOf(Kit.closed({
    id: STR, label: STR, families: STRS, kind: STR, what: STR
  })),
  longTextAttributes: STRS, defaultSecretLifetimeDays: NUM,
  persistence: Kit.closed({ persistsDirectory: BOOL, mode: NSTR }),
  resourceMetadataImport: Kit.closed({
    wellKnown: STR, acceptsNonconforming: BOOL, dialsInternalAddresses: BOOL
  }),
  editable: Kit.listOf(Kit.closed({
    name: STR, mode: EDITABLE_WORD, sensitive: BOOL, families: STRS
  }))
});

const KEY_ALGORITHM: Json = Kit.closed({
  id: STR, label: STR, family: STR, kind: STR, signs: BOOL, slow: BOOL
});

// `pki_authoring.ts`'s `view()`. What the form holds is under `draft`.
//
// A draft is a map because its keys are the form's own field list, which this
// same answer publishes as `fields` (115 names, `FIELDS` in that file, three of
// them written by name beside it and a family of `pki_ku_*` by a loop over
// x509's bits): `apply-profile` rewrites them and a client echoes them back, so
// the service's vocabulary here is data the document reads from the service.
const DRAFT: Json = Kit.mapOf({ type: ['string', 'boolean', 'number', 'null'] },
                              'The certificate form, by field name.');

const WORKBENCH: Json = Kit.closed({
  fields: STRS,
  profiles: Kit.listOf(Kit.closed({
    id: STR, label: STR, ca: BOOL, selfSigned: BOOL, years: NUM,
    keyUsage: STRS, extKeyUsage: STRS, pathLen: Kit.nullable(NUM), note: STR
  })),
  pqModes: Kit.listOf(Kit.closed({
    id: STR, label: STR, classical: BOOL, families: STRS, note: STR
  })),
  pqMode: STR, keyAlgorithms: Kit.listOf(KEY_ALGORITHM),
  alternativeKeyAlgorithms: Kit.listOf(KEY_ALGORITHM),
  signatureAlgorithms: Kit.listOf(Kit.closed({
    id: STR, label: STR, weak: BOOL, kind: STR
  })),
  signerLabel: STR, keystoreFormats: STRS,
  keyUsageBits: Kit.listOf(Kit.closed({ name: STR, what: STR })),
  extendedKeyUsages: Kit.listOf(Kit.closed({ name: STR, oid: STR })),
  netscapeTypes: Kit.listOf(Kit.closed({ name: STR })),
  accessMethods: STRS,
  dnFields: Kit.listOf(Kit.closed({ attr: STR, field: STR })),
  issuers: Kit.listOf(Kit.closed({
    id: STR, label: STR, subject: STR, keyAlg: STR, notAfter: STR,
    hasAlternativeKey: BOOL
  })),
  objects: Kit.listOf(Kit.closed({
    id: STR, ca: BOOL, profile: NSTR, profileLabel: NSTR, subject: STR,
    issuerSubject: NSTR, issuerId: NSTR, selfSigned: BOOL, serialHex: NSTR,
    keyAlg: STR, keyAlgLabel: NSTR, signatureAlg: NSTR,
    signatureAlgLabel: NSTR, pqMode: NSTR, altKeyAlg: NSTR, altSigned: BOOL,
    notBefore: NSTR, notAfter: NSTR, expired: BOOL, thumbprint: NSTR,
    createdAt: Kit.nullable(Kit.oneOf(STR, NUM)), hasPrivateKey: BOOL,
    hasCsr: BOOL, certificatePem: NSTR, csrPem: STR
  })),
  maxObjects: INT, slowFamilies: STRS, draft: DRAFT
});

// The pane's four helpers: the form and how to draw it, or `refuse()`'s pair
// and a schema's or the catch's `{ ok, errors }`.
const PKI_HELPER: Json = Kit.closed({
  ok: BOOL, errors: STRS, why: STR, draft: DRAFT, algorithm: STR,
  workbench: WORKBENCH
}, { required: ['ok'] });

const CLIENT_SECRET: Json = Kit.closed({
  ok: BOOL, changed: BOOL, clientSecret: STR, message: STR, errors: STRS
}, { required: ['ok'] });

const OPERATION_ROW: Json = Kit.closed({
  method: STR, path: STR, operationId: STR, summary: STR, mirrors: STR,
  kind: STR, drawnOn: STRS, query: STRS
});

const CONSOLE_OPERATIONS: Json = Kit.closed({
  operations: Kit.listOf(OPERATION_ROW)
});

// `admin_api_spec.ts`'s `buildSpec()`: closed at the top, and free below it.
const OPENAPI_INNER: Json = Kit.freeForm(
  'The inside of an OpenAPI document (its paths and components): a statement ' +
  'about this API in OpenAPI\'s own vocabulary, whose every model is stated ' +
  'at the operation it describes.');

const OPENAPI_DOCUMENT: Json = Kit.closed({
  openapi: STR,
  info: Kit.closed({
    title: STR, version: STR, description: STR,
    license: Kit.closed({ name: STR })
  }),
  servers: Kit.listOf(Kit.closed({ url: STR, description: STR })),
  tags: Kit.listOf(Kit.closed({ name: STR, description: STR })),
  security: Kit.listOf(Kit.mapOf(STRS, 'The scopes a security scheme needs, ' +
                                       'by the scheme\'s name.')),
  paths: OPENAPI_INNER,
  components: OPENAPI_INNER
}, { required: ['openapi', 'info', 'paths'] });

/**
 * A 200 that is the JSON model, or the drawing alone with `format=svg`.
 *
 * @param model - the JSON answer's model
 * @returns the status's model
 */
function drawn(model: Json): Json {
  return Object.assign(Kit.media('image/svg+xml'), { schema: model });
}

export = {
  components: {} as Record<string, unknown>,
  operations: {
    getApiExplorer: { '200': EXPLORER },
    getConsoleShell: { '200': SHELL },
    setConsoleLanguage: { '200': LANGUAGE, '400': LANGUAGE },
    getDelegationMap: { '200': drawn(DELEGATION_MAP) },
    getFederationMap: { '200': drawn(FEDERATION_MAP) },
    getDelegationCluster: { '200': drawn(DELEGATION_CLUSTER) },
    getDelegationAllowed: { '200': drawn(DELEGATION_ALLOWED) },
    getDelegationSettings: { '200': DELEGATION_SETTINGS },
    getDelegationChain: { '200': drawn(DELEGATION_CHAIN) },
    getConsoleDashboard: { '200': DASHBOARD },
    getConsoleNewApplicationForm: { '200': NEW_APPLICATION_FORM },
    getConsoleDelegationUser: { '200': drawn(DELEGATION_USER) },
    getConsoleDelegationApplication: { '200': drawn(DELEGATION_APPLICATION) },
    applyPkiProfile: { '200': PKI_HELPER, '400': PKI_HELPER },
    generatePkiKeyPair: { '200': PKI_HELPER, '400': PKI_HELPER },
    generatePkiAltKeyPair: { '200': PKI_HELPER, '400': PKI_HELPER },
    usePkiStoredKey: { '200': PKI_HELPER, '400': PKI_HELPER },
    generateClientSecret: { '200': CLIENT_SECRET, '400': CLIENT_SECRET },
    getConsoleOperations: { '200': CONSOLE_OPERATIONS },
    getConsoleOpenApi: { '200': OPENAPI_DOCUMENT }
  } as Record<string, Record<string, unknown>>
};
