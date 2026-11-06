// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_service.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): Service, Monitoring, Configuration, Trust realms,
// Persistence, Cluster, Metrics, Audit log, Risk, Devices.
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
//
// **EVERY MEMBER HERE WAS READ OFF THE CODE THAT BUILDS IT**, every branch, and
// an answer that fails its model is not sent. So where a member's type depends
// on a store, a mode or a provider, the union is written out; a time that is a
// number in one view and a string in another is each in its own place, not one
// shared `TIME`, because which one it is is what a client has to know.
//
// **NO `enum` ON A MEMBER WHOSE VALUES ARE ANOTHER MODULE'S TABLE**, unless the
// values were counted here: a value added to that table would otherwise turn
// every answer carrying it into a 500. `SETTING.source` is the one written out,
// and it is the case for the rule: the old schema's list had no `realm`, which
// is `config.js`'s first answer inside a realm.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

const str = Kit.str;
const int = Kit.int;
const num = Kit.num;
const bool = Kit.bool;
const closed = Kit.closed;
const listOf = Kit.listOf;
const mapOf = Kit.mapOf;
const nullable = Kit.nullable;
const oneOf = Kit.oneOf;
const action = Kit.action;

const STRINGS: Json = listOf(str());
const OPT_STR: Json = nullable(str());
const OPT_INT: Json = nullable(int());
const OPT_NUM: Json = nullable(num());
const OPT_BOOL: Json = nullable(bool());

// What a setting can hold once `config.js`'s `TYPES` has parsed it: a number for
// int and port, a boolean for bool, a list for csv, otherwise a string. A
// `dflt` is the table's own literal, or what its function answers, so it is the
// same set and null.
const SCALAR: Json = oneOf(str(), num(), bool(), { type: 'null' });
const SETTING_VALUE: Json = oneOf(str(), num(), bool(), { type: 'null' },
                                  listOf(oneOf(str(), num(), bool())));

// `admin_views.ts`'s `pagingJson()`.
const PAGING: Json = closed({
  page: int(), pages: int(), perPage: int(), firstRow: int(), lastRow: int(),
  total: int(), param: str(), noun: str()
}, { description: 'Which page of how many, and the query parameter that ' +
                  'moves it.' });

// ---------------------------------------------------------------------------
// A SETTING AS `config.js`'s `describe()` SENDS IT.
//
// **`legacyEnv` IS NOT DECLARED, ON PURPOSE**: `describe()` still sends it for
// a row that has one, and no row has had one since #523, so it never reaches
// JSON. `tests/protocol/admin_api.js` holds that every documented member appears
// on a row, so declaring it fails that test; the next row carrying one must put
// the member back here, in the same change, or every settings answer 500s.
// ---------------------------------------------------------------------------
const SELECT_ALL_RULE: Json = closed({
  setting: str(),
  values: STRINGS,
  on: bool(),
  canBeOn: bool()
});

const SETTING: Json = closed({
  key: str('The dot path, which is BOTH the name every operation here takes ' +
           'and the path in the appconfig file. `oid4vci.batchSize` is ' +
           '`appconfig.oid4vci.batchSize`.'),
  group: str('The protocol it belongs to, and the console\'s section heading.'),
  label: str(),
  description: str('What it does and why the default is the default.'),
  type: str('How a value posted for it is coerced and checked: one of ' +
            '`config.js`\'s types (string, int, port, bool, csv, enum, ' +
            'color).'),
  enumValues: listOf(str(), 'Present on `enum` settings only.'),
  csvValues: listOf(str(), 'Present on a `csv` setting whose entries must ' +
                           'each be one of these; absent on an open list.'),
  ordered: bool('Present, true, on a `csv` setting whose order is a ' +
                'preference: the first value is the most preferred.'),
  csvValueNotes: mapOf(str(), 'Present beside `csvValues` where the setting ' +
                              'describes each value: the value mapped to one ' +
                              'sentence.'),
  selectAll: closed({
    onlyWhileOn: listOf(SELECT_ALL_RULE),
    aloneWhileOn: listOf(SELECT_ALL_RULE)
  }, { description: 'Present on an `ordered` setting whose select-all is ' +
                    'narrowed by other settings. `onlyWhileOn`: the values ' +
                    'are selected only while that setting is on. ' +
                    '`aloneWhileOn`: while that setting is on, only the ' +
                    'values are selected. `canBeOn` is false where this mode ' +
                    'never lets that setting be on.' }),
  min: num('The lowest value POST /config/set will take, on an int setting ' +
           'that declares one.'),
  max: num('The highest value it will take.'),
  step: num('The value must be a MULTIPLE of this, counted from `min`. The ' +
            'four token lifetimes use 30.'),
  value: Object.assign({}, SETTING_VALUE, {
    description: 'The effective value, coerced to its type: a number for ' +
                 'int/port, a boolean for bool, an array of strings for csv.'
  }),
  text: str('The same value on one line: what the console shows in its input ' +
            'and what the environment variable would carry.'),
  source: Kit.strEnum(['realm', 'override', 'env', 'env-legacy', 'appconfig',
                       'defaults', 'default'],
    'Where the effective value came from, highest first: this trust realm\'s ' +
    'own value; a runtime override set through this API or the console; the ' +
    'setting\'s own environment variable; a legacy variable (no row has one ' +
    'since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, ' +
    'the DEFAULT appconfig file that one is unioned on top of. `default` is ' +
    'reachable only for the DERIVED settings, whose value is a function of ' +
    'a neighbouring setting: for every other setting, no value anywhere ' +
    'stops this service from STARTING.'),
  editable: bool('Whether POST /config/set will take it from the realm this ' +
                 'answer was read in. False means either the value was ' +
                 'consumed at startup or `editRefusal` is set. It is refused ' +
                 'rather than accepted, because an accepted change that does ' +
                 'nothing reads as having worked.'),
  restartReason: str('Why it is not editable, when the value was consumed at ' +
                     'startup.'),
  editRefusal: str('Why this row cannot be edited from the realm the reader ' +
                   'is in: `realms.maxCount` while a realm other than the ' +
                   'default is ambient. Absent on every row of the default ' +
                   'realm\'s answer.'),
  env: str('Its environment variable.'),
  appconfigPath: str(),
  default: Object.assign({}, SETTING_VALUE, {
    description: 'The built-in default: the `dflt` column of `config.js`\'s ' +
                 'table, which `env/defaults.js` is GENERATED from. It is ' +
                 'what the value WOULD be with nothing set anywhere.'
  }),
  realmSettable: bool('Whether a trust realm may hold its own value for it.'),
  overridden: bool('Whether a runtime override is in force. Equal to `source ' +
                   '=== "override"`, and reported separately so a caller can ' +
                   'filter without matching a string.')
}, { description: 'One setting: what it is, what it is set to, and where ' +
                  'that came from.' });

const SETTING_GROUP: Json = closed({
  group: str(),
  settings: listOf(SETTING)
}, { description: 'One group\'s settings.' });

// `admin.ts`'s `settingsContext()`.
const SETTINGS_CONTEXT: Json = closed({
  configFile: OPT_STR,
  defaultsFile: str(),
  persistsAppconfig: bool(),
  persistsRealms: bool(),
  persistenceMode: str(),
  inRealm: bool(),
  realmId: str()
});

// `admin.ts`'s `configSettingsJson()`: the `settings` member of every page that
// owns settings.
const SETTINGS_BLOCK: Json = closed({
  page: str(),
  groups: listOf(SETTING_GROUP, 'In the order `config.js` declares them.'),
  settingCount: int(),
  editableCount: int('How many of them can be changed while the service ' +
                     'runs.'),
  overridden: listOf(str(), 'The keys on this page with a runtime override ' +
                            'in force.'),
  setWith: str('The operation that writes them.'),
  context: SETTINGS_CONTEXT,
  sharedWith: mapOf(STRINGS, 'A group drawn on another page as well, and ' +
                             'those pages.')
}, { description: 'The settings this page draws, described: the same rows ' +
                  'GET /config returns, filtered to the ones this page owns.'
});

// ---------------------------------------------------------------------------
// A SECRET'S SOURCE, `common/secrets.js`'s `describeSecret()`. The KEK and the
// database password are both one. `where` is what the nine providers'
// `describe()` say between them; a value is never in it.
// ---------------------------------------------------------------------------
const SECRET_WHERE: Json = closed({
  from: str(),
  shared: bool(),
  region: str(),
  vault: str(),
  endpoint: str(),
  field: str(),
  authenticates: str(),
  wraps: str()
});

const SECRET_PROVIDER: Json = closed({ id: str(), label: str() });

const SECRET_SOURCE: Json = closed({
  secret: str(),
  configured: bool(),
  provider: str(),
  label: str(),
  known: bool(),
  where: SECRET_WHERE,
  shared: bool(),
  field: str(),
  providers: listOf(SECRET_PROVIDER)
});

// ---------------------------------------------------------------------------
// `GET /persistence`'s `status`: `persistence.js`'s `status()` and what it asks
// each part of the store.
// ---------------------------------------------------------------------------

// `persistence_replication.js`'s `status()`: the store's, and a tiered store's
// global database's beside it. `lastTrim` carries what the store's
// `purgeChangeLog()` answered, or `error`.
const REPLICATION: Json = closed({
  coordinating: bool(),
  supported: bool(),
  startedAt: OPT_STR,
  appliedSeq: num(),
  highestSeq: num(),
  holes: int(),
  holeRanges: int(),
  holesAbandoned: int(),
  pollIntervalMs: int(),
  pulls: int(),
  nudges: int(),
  failures: int(),
  rowsApplied: int(),
  byKind: mapOf(int(), 'Rows applied, per kind of change.'),
  lastPullAt: OPT_STR,
  lastError: OPT_STR,
  otherProcesses: int(),
  originsDropped: int(),
  retention: closed({
    retentionS: int(),
    readerTtlS: int(),
    reportedAt: OPT_STR,
    reportError: OPT_STR,
    declaredGoneAt: OPT_STR,
    fanInGraceS: int(),
    trimming: bool(),
    lastTrim: nullable(closed({
      at: str(),
      error: OPT_STR,
      readersGone: int(),
      readers: int(),
      bound: nullable(oneOf(num(), str())),
      trimmed: int()
    }))
  }),
  note: str()
});

const LAG_SAMPLE: Json = closed({
  maxMs: num(), p99Ms: num(), meanMs: num(), at: str()
});

const CELL_ROUTING: Json = closed({
  indexed: int(),
  conflicts: int(),
  lastConflict: OPT_STR,
  projectionWrites: int()
});

const PERSISTENCE_STATUS: Json = closed({
  mode: str(),
  configuredMode: str(),
  enabled: bool(),
  healthy: OPT_BOOL,
  dataDir: OPT_STR,
  database: nullable(closed({
    host: OPT_STR,
    port: OPT_STR,
    database: OPT_STR,
    user: OPT_STR,
    passwordFrom: str(),
    passwordProvider: str(),
    passwordSecret: SECRET_SOURCE,
    sslmode: str(),
    encrypted: bool(),
    verifyCertificate: bool(),
    caFile: OPT_STR,
    tls: str(),
    note: str()
  }, { description: 'Parsed out of the connection string, which is never ' +
                    'returned.' })),
  engine: OPT_STR,
  writeDelayMs: int(),
  persistsDirectory: bool(),
  persistsRealms: bool(),
  persistsAppconfig: bool(),
  pending: bool(),
  writes: int(),
  failures: int(),
  lastWriteAt: OPT_STR,
  lastError: OPT_STR,
  restoredAt: OPT_STR,
  restored: closed({ realms: int(), entries: int(), overrides: int() }),
  entriesTracked: int(),
  realmsTracked: int(),
  coordinates: bool(),
  minted: closed({
    persisting: bool(),
    supported: bool(),
    unsupportedReason: str(),
    sealed: bool(),
    mode: str(),
    setting: bool(),
    retentionMs: num(),
    stores: int(),
    shared: int(),
    handles: listOf(closed({ handle: str(), shape: str(), scope: str() })),
    pending: int(),
    writes: int(),
    failures: int(),
    rowsWritten: int(),
    rowsDeleted: int(),
    lastWriteAt: OPT_STR,
    lastError: str(),
    restoredAt: OPT_STR,
    restored: int(),
    droppedUnreadable: int(),
    droppedUnknown: int()
  }),
  usedAssertions: closed({
    store: str(),
    kind: str(),
    persistent: bool(),
    atomicAcrossProcesses: bool(),
    why: str(),
    cap: num(),
    live: OPT_INT,
    liveIsCurrent: bool()
  }),
  replication: REPLICATION,
  cells: nullable(closed({
    cell: str(),
    jurisdiction: OPT_STR,
    globalReplication: nullable(REPLICATION),
    routing: CELL_ROUTING
  })),
  origin: nullable(closed({ origin: str(), adopted: bool(), why: str() })),
  answersAfterCommit: bool(),
  commitBacklog: bool(),
  retryArmed: bool(),
  liveness: nullable(closed({
    open: bool(), queries: int(), connects: int(), drops: int(), viaPool: int()
  })),
  eventLoop: nullable(closed({
    lastReport: nullable(LAG_SAMPLE),
    sinceReport: nullable(LAG_SAMPLE),
    warnAboveMs: num()
  })),
  note: str()
}, { description: 'What the store is actually doing, which is a different ' +
                  'fact from what `persistence.*` says it should.' });

// ---------------------------------------------------------------------------
// `GET /cluster`'s `status`: `admin.ts`'s `clusterStatusBlock()`.
// ---------------------------------------------------------------------------

// The cluster's own view of a node's caches is `cache_registry.js`'s packed row
// (`snapshotRowOf()`), an array because it travels on every heartbeat.
const NODE_INFO: Json = closed({
  pid: int(),
  host: str(),
  port: SCALAR,
  uptimeMs: num(),
  workers: int(),
  lastStallMs: num(),
  caches: nullable(closed({
    at: num(),
    pid: str(),
    caches: listOf(listOf(oneOf(str(), num(), { type: 'null' })),
                   'name, size, largest realm, valid, bound, hits, misses, ' +
                   'evictions, refusals.')
  })),
  listenerCertificates: listOf(str(), 'Base64, the PEM\'s body.')
}, { description: 'What only that node can say about itself.' });

const CLUSTER_NODE: Json = closed({
  nodeId: str(),
  name: OPT_STR,
  mode: OPT_STR,
  version: OPT_STR,
  startedAt: num(),
  heartbeatAt: num(),
  expiresAt: num(),
  leftAt: num(),
  info: NODE_INFO,
  agrees: nullable(bool('Whether its settings fingerprint agrees with the ' +
                        'node answering; the fingerprint is never returned.'))
});

const CLUSTER_LEASE: Json = closed({
  name: str(),
  holder: str(),
  token: num(),
  acquiredAt: num(),
  expiresAt: num()
});

const RESTARTS: Json = mapOf(closed({ count: int(), lastEndedAt: num() }),
                             'Per running name.');

const CAPABILITY_ROW: Json = closed({
  id: str(),
  section: str(),
  by: str(),
  what: str(),
  provided: bool(),
  note: str(),
  accepted: bool()
});

// `cluster.js`'s `status()`.
const CLUSTER_SELF: Json = closed({
  mode: str(),
  why: str(),
  refused: OPT_STR,
  configured: str(),
  nodeId: OPT_STR,
  name: OPT_STR,
  role: OPT_STR,
  joinedAt: OPT_STR,
  heartbeatMs: num(),
  ttlMs: num(),
  lastStallMs: num(),
  msSinceRenewal: OPT_NUM,
  heartbeatFailures: int(),
  lastHeartbeatError: OPT_STR,
  leases: listOf(closed({ name: str(), token: oneOf(num(), str()) })),
  fingerprintSet: bool(),
  agreementSettings: STRINGS,
  capabilities: closed({
    rows: listOf(CAPABILITY_ROW),
    missing: STRINGS,
    acceptedMissing: STRINGS,
    unknownAccepted: STRINGS,
    ready: bool()
  })
});

// `cells_admin.ts`'s `clusterSummaryHere()`, as another cell answers it.
const PEER_CLUSTER_SUMMARY: Json = closed({
  cell: str(),
  jurisdiction: OPT_STR,
  at: num(),
  clustered: bool(),
  mode: str(),
  members: closed({
    live: listOf(closed({
      name: str(),
      mode: str(),
      version: str(),
      startedAt: num(),
      heartbeatAt: num(),
      expiresAt: num(),
      uptimeMs: num(),
      workers: int(),
      lastStallMs: num(),
      agrees: OPT_BOOL,
      leases: STRINGS
    })),
    restarts: RESTARTS,
    gone: listOf(closed({
      name: str(),
      version: str(),
      endedAt: num(),
      how: str(),
      earlierLives: int()
    }))
  }),
  leases: listOf(closed({ name: str(), holder: str(), expiresAt: num() })),
  pools: listOf(closed({
    name: OPT_STR,
    state: OPT_STR,
    pools: listOf(closed({
      id: str(),
      title: OPT_STR,
      state: OPT_STR,
      currentWorkers: int(),
      busyWorkers: int(),
      freeWorkers: int(),
      crashed: int(),
      failedStarts: int()
    }))
  })),
  poolsError: str()
});

const CLUSTER_STATUS: Json = closed({
  self: CLUSTER_SELF,
  snapshotAgeMs: OPT_NUM,
  nodes: listOf(CLUSTER_NODE),
  members: nullable(closed({
    running: STRINGS,
    restarts: RESTARTS,
    leftOrExpired: listOf(closed({
      nodeId: str(),
      name: OPT_STR,
      earlierLives: int()
    }))
  })),
  leases: listOf(CLUSTER_LEASE),
  databaseNow: OPT_NUM,
  otherCells: nullable(closed({
    askedAt: num(),
    cells: listOf(closed({
      cell: str(),
      jurisdiction: OPT_STR,
      reachable: bool(),
      answeredMs: num(),
      summary: PEER_CLUSTER_SUMMARY,
      error: str()
    })),
    error: OPT_STR
  })),
  secrets: closed({
    started: bool(),
    secrets: listOf(closed({ name: str(), what: str(), source: str() }))
  }, { description: 'Where each shared secret\'s value came from, never the ' +
                    'value.' }),
  barrier: closed({
    active: bool(),
    holds: bool(),
    requests: int(),
    caughtUp: int(),
    gaveUp: int(),
    heldForCommit: int(),
    answeredUnheld: int(),
    commitFailures: int(),
    totalWaitMs: num(),
    totalHoldMs: num(),
    refusedForCommit: int(),
    heldForBacklog: int(),
    ldapHeldForCommit: int(),
    ldapRefusedForCommit: int(),
    meanWaitMs: num(),
    meanHoldMs: num()
  })
}, { description: 'Whether a cluster is WORKING, which `cluster.mode` being ' +
                  'set does not say.' });

// ---------------------------------------------------------------------------
// `PageSettings` is what `admin.ts`'s `protocolSettingsJson()` answers for every
// page in its table, across families. Only the two rows that have a status
// block carry `status`, and it is one of those two.
// ---------------------------------------------------------------------------
const PAGE_SETTINGS: Json = closed({
  page: str('The console path this mirrors.'),
  title: str(),
  what: str('What the page says the family is, as plain text.'),
  notes: listOf(str(), 'The caveats the page carries, in order. On these ' +
                       'pages the caveats are most of the content: what a ' +
                       'family does NOT check is the half a client author ' +
                       'cannot read off a protocol trace.'),
  links: listOf(closed({ href: str(), what: str() },
                       { description: 'One link the page offers.' })),
  settings: SETTINGS_BLOCK,
  leadHtml: str('The page\'s first paragraph, as the console draws it.'),
  alsoHtml: listOf(str(), 'The caveats, as the console draws them.'),
  status: oneOf(PERSISTENCE_STATUS, CLUSTER_STATUS)
}, { description: 'One console page, and the settings it draws: the same ' +
                  'described rows GET /config returns, filtered to the ones ' +
                  'that page owns.' });

// ---------------------------------------------------------------------------
// `GET /config`: `admin.ts`'s `configJson()` over `config.js`'s `snapshot()`.
// Every member below is on every answer: `tests/protocol/admin_api.js` holds
// that, and reads `groups.items.properties.settings.items` directly, so the
// row stays inline here rather than behind a `$ref`.
// ---------------------------------------------------------------------------
const CONFIG: Json = closed({
  realm: str('The realm this was read in.'),
  realmSettings: listOf(str(), 'The keys that realm holds a value of its own ' +
                               'for.'),
  configFile: nullable(str('The CONFIG_FILE this process was started with, ' +
                           'which is the file to edit to make a change ' +
                           'survive a restart. Nothing here ever writes to ' +
                           'it.')),
  defaultsFile: str('The DEFAULT appconfig file, which `configFile` is ' +
                    'unioned on top of key by key with the operator\'s value ' +
                    'winning. A setting whose `source` is `defaults` came ' +
                    'from here.'),
  settingCount: int(),
  editableCount: int('How many of them POST /config/set will take. The rest ' +
                     'are restart-only and say why in `restartReason`.'),
  overridden: listOf(str(), 'The keys with a runtime override in force. Empty ' +
                            'on a freshly started service, and emptied again ' +
                            'by POST /config/reset-all.'),
  groups: listOf(SETTING_GROUP, 'In the order `config.js` declares them, ' +
                                'which is the order the console renders its ' +
                                'sections.'),
  homes: listOf(closed({
    group: str(),
    pages: STRINGS,
    labels: listOf(str(), 'The pages\' console labels, in the same order.')
  }, { description: 'One group, and the page or pages that draw it.' }),
  'WHERE EACH GROUP IS EDITED: every group is drawn on the console page for ' +
  'the protocol it configures, so a caller can send a person to the right ' +
  'page. Every one of those forms posts to the same four actions.'),
  homeProblems: listOf(str(), 'Empty, and reported rather than left implicit. ' +
                              'A sentence here means a setting group exists ' +
                              'that no console page draws.'),
  settings: SETTINGS_BLOCK
}, { description: 'Every setting this service has, grouped by the protocol ' +
                  'it belongs to. The same table the /admin/config page ' +
                  'renders and the same call it makes, so the console and ' +
                  'this API cannot come to describe different sets of ' +
                  'settings.' });

// The four actions of `admin_actions.ts`'s `configAction()`, and what a refusal
// from `config.js` adds to them.
const SET_SETTING: Json = action({
  key: str(),
  setting: SETTING,
  realm: OPT_STR
});

const SET_SETTINGS: Json = action({
  applied: STRINGS,
  changed: STRINGS,
  settings: listOf(SETTING)
});

const RESET_ALL: Json = action({
  cleared: STRINGS,
  realm: OPT_STR
});

// ---------------------------------------------------------------------------
// `GET /realms`: `admin_views.ts`'s `realmsJson()` and `realmJson()`.
// ---------------------------------------------------------------------------
const LISTENER_CERTIFICATE: Json = closed({
  source: str(), notBefore: str(), notAfter: str(), serialHex: str()
});

// `tls/listeners.js`'s `status()`.
const LISTENER_BOUND: Json = closed({
  id: str(),
  owner: str(),
  port: int(),
  publicBaseUrl: OPT_STR,
  hostnames: STRINGS,
  state: str(),
  why: OPT_STR,
  code: OPT_STR,
  boundAt: nullable(oneOf(str(), num())),
  certificate: nullable(LISTENER_CERTIFICATE)
});

// `realms.js`'s `retiringState()`.
const RETIRING: Json = closed({
  since: num(),
  sinceIso: str(),
  inProgress: bool(),
  interrupted: bool(),
  finishesBy: num(),
  refusing: str(),
  why: str(),
  finish: str()
});

const REALM: Json = closed({
  id: str(),
  name: str(),
  description: OPT_STR,
  domain: str(),
  baseDn: str(),
  builtin: bool(),
  retiring: nullable(RETIRING),
  pathPrefix: str(),
  baseUrl: str(),
  listeners: listOf(closed({
    id: str(),
    port: int(),
    publicBaseUrl: OPT_STR,
    hostnames: STRINGS,
    clientAuth: OPT_STR,
    certificateSource: str(),
    here: nullable(LISTENER_BOUND)
  })),
  kid: str(),
  settings: listOf(closed({
    key: str(), value: str(), label: str(), group: str()
  })),
  endpoints: closed({
    openidConfiguration: str(),
    authorizationServerMetadata: str(),
    jwks: str(),
    samlMetadata: str()
  })
});

const REALMS: Json = closed({
  enabled: bool(),
  active: bool(),
  pathSegment: str(),
  current: str(),
  reserved: STRINGS,
  realms: listOf(REALM),
  support: listOf(closed({
    family: str(),
    state: str(),
    by: str(),
    cards: STRINGS,
    note: str()
  })),
  settings: SETTINGS_BLOCK,
  defaultDomain: str(),
  count: int(),
  currentName: str(),
  persistence: closed({ persistsRealms: bool(), mode: str() }),
  paging: nullable(PAGING)
});

// One model per action would say the same thing five times: what any of them
// adds, including what a refusal from `realms.js` carries. `retiring` is the
// refusal of a removal already under way; `bootstrap`, `password` and `username`
// are a created realm's, and the last two only in product mode.
const REALM_ACTION: Json = action({
  realm: str(),
  key: str(),
  prefix: str(),
  bootstrap: nullable(closed({
    username: str(),
    created: bool(),
    passwordResetRequired: bool()
  })),
  password: str('The bootstrap administrator\'s generated password, in ' +
                'product mode, once.'),
  username: str(),
  retiring: RETIRING,
  retirement: closed({
    late: STRINGS,
    failed: STRINGS,
    undelivered: listOf(closed({ count: num(), what: str() })),
    boundSeconds: num()
  })
});

// ---------------------------------------------------------------------------
// `GET /listeners`: `listeners_admin.ts`'s `listenersView()`.
// ---------------------------------------------------------------------------
const TLS_POLICY: Json = closed({
  minVersion: OPT_STR,
  tls12: bool(),
  tls13Suites: listOf(closed({ name: str(), postQuantum: bool() })),
  tls12Ciphers: STRINGS,
  pqcOnly: bool(),
  groups: str(),
  signatureAlgorithms: str(),
  sessionTimeoutS: num(),
  sessionCacheSize: num(),
  truststore: str(),
  clientAuth: OPT_STR
});

const HTTP_POLICY: Json = closed({
  keepAliveTimeoutS: num(),
  headersTimeoutS: num(),
  maxRequestsPerSocket: num(),
  maxConnections: num(),
  http2: bool(),
  http2MaxConcurrentStreams: num()
});

const LISTENERS: Json = closed({
  realm: str(),
  listeners: listOf(closed({
    id: str(),
    name: str(),
    setting: str(),
    port: SCALAR,
    tls: bool(),
    what: str(),
    group: OPT_STR,
    policy: nullable(TLS_POLICY),
    http: nullable(HTTP_POLICY)
  })),
  custom: listOf(closed({
    id: str(),
    label: OPT_STR,
    owner: str(),
    port: int(),
    publicBaseUrl: OPT_STR,
    hostnames: STRINGS,
    clientAuth: OPT_STR,
    certificateSource: str(),
    // A listener's own TLS values, which `listener_map.js` keeps as given after
    // checking each against its base setting: the names are `config.js`'s
    // `PER_LISTENER_SETTINGS`, so they are data here.
    tls: mapOf(SETTING_VALUE, 'A listener\'s own TLS values, per setting.'),
    state: str(),
    why: OPT_STR,
    code: OPT_STR,
    certificate: nullable(LISTENER_CERTIFICATE),
    policy: TLS_POLICY,
    http: HTTP_POLICY
  })),
  applications: listOf(closed({
    application: str(),
    label: str(),
    what: str(),
    session: bool(),
    listeners: STRINGS,
    advertised: OPT_STR,
    decidedBy: str()
  })),
  definitions: closed({
    listeners: str(),
    applications: str(),
    serviceApplications: str(),
    cookieDomain: str()
  }),
  rescue: bool(),
  problem: OPT_STR,
  warnings: STRINGS,
  process: TLS_POLICY,
  live: listOf(closed({ label: str(), kind: str(), realm: OPT_STR })),
  settings: SETTINGS_BLOCK
});

// What `config.js`'s `setOverride()` and `realms.js`'s answer, both.
const LISTENERS_ACTION: Json = action({
  key: str(),
  realm: OPT_STR
});

// ---------------------------------------------------------------------------
// `GET /mode`: `common/mode.js`'s `report()`. A requirement's columns are
// written in that table as the sentences they are.
// ---------------------------------------------------------------------------
const MODE: Json = closed({
  mode: str(),
  isProduct: bool(),
  requirements: listOf(closed({
    id: str(),
    inForce: str(),
    what: str(),
    development: str(),
    product: str(),
    where: str(),
    waived: listOf(closed({
      requirement: str(),
      section: str(),
      level: str(),
      setting: str(),
      perApplication: bool(),
      attribute: str(),
      dynamicRegistration: closed({ setting: str(), value: SETTING_VALUE })
    }))
  })),
  developmentOnlySettings: listOf(closed({
    key: str(),
    group: str(),
    predicate: str(),
    developmentOnlyValues: nullable(STRINGS),
    default: SETTING_VALUE,
    value: SETTING_VALUE,
    inForce: SETTING_VALUE,
    ignored: bool(),
    why: str()
  })),
  notYet: listOf(closed({ id: str(), what: str() }))
});

// ---------------------------------------------------------------------------
// `GET /encryption`: `encryption_admin.ts`'s `encryptionJson()`.
// ---------------------------------------------------------------------------
const KEK_LABEL: Json = closed({
  label: str(),
  encryptions: int(),
  decryptions: int(),
  failures: int(),
  plaintextBytes: num(),
  ciphertextBytes: num(),
  firstAt: num('Milliseconds, 0 when never.'),
  lastAt: num('Milliseconds, 0 when never.')
});

const ENCRYPTION: Json = closed({
  what: str(),
  mode: str(),
  key: closed({
    present: bool(),
    persists: bool(),
    ephemeral: bool(),
    provider: str(),
    providerLabel: str(),
    inKms: bool(),
    kmsKey: OPT_STR,
    providerKnown: bool(),
    where: SECRET_WHERE,
    providers: listOf(SECRET_PROVIDER),
    note: str()
  }),
  algorithm: closed({
    envelope: str(),
    version: oneOf(str(), num()),
    cipher: str(),
    keyBits: int(),
    ivBits: int(),
    tagBits: int(),
    dataKeys: str(),
    dataCiphers: STRINGS,
    dekWrap: str(),
    aad: str(),
    perRecordSubkey: bool()
  }),
  dataKeys: closed({
    lifecycle: nullable(closed({
      on: bool(),
      offReason: str(),
      scheduled: bool(),
      scheduleOffReason: str(),
      rotationDays: num(),
      activationLeadSeconds: num(),
      retireAfterDays: num(),
      directoryCipher: str(),
      counting: bool(),
      countOffReason: str(),
      kekRotation: bool(),
      kekRotationOffReason: str(),
      jobs: STRINGS
    })),
    counts: closed({
      current: int(),
      pending: int(),
      superseded: int(),
      destroyed: int(),
      derived: int()
    }),
    total: int(),
    lastCounted: OPT_STR,
    keys: listOf(closed({
      id: str(),
      realm: OPT_STR,
      cls: OPT_STR,
      scope: OPT_STR,
      alg: str(),
      state: str(),
      createdAt: OPT_STR,
      activateAt: OPT_STR,
      ageDays: OPT_INT,
      values: OPT_NUM,
      countedAt: OPT_STR
    })),
    paging: PAGING,
    note: str()
  }),
  algorithmNote: str(),
  boundaries: closed({
    perRealmKey: bool(),
    perRealmDataKey: bool(),
    realms: str(),
    storage: str(),
    keyResidency: str()
  }),
  store: closed({
    mode: str(),
    configuredMode: str(),
    fellBack: bool(),
    persistsMinted: bool(),
    note: str()
  }),
  classes: listOf(closed({
    what: str(),
    where: str(),
    sealed: bool(),
    label: OPT_STR,
    why: str(),
    encryptions: OPT_INT,
    decryptions: OPT_INT,
    failures: OPT_INT,
    lastAt: OPT_STR
  })),
  unclassified: listOf(KEK_LABEL),
  accounting: closed({
    operations: int(),
    encryptions: int(),
    decryptions: int(),
    failures: int(),
    plaintextBytes: num(),
    ciphertextBytes: num(),
    since: str(),
    firstAt: OPT_STR,
    lastAt: OPT_STR,
    labels: listOf(KEK_LABEL)
  }),
  accountingNote: str(),
  failuresNote: str(),
  noSamples: str()
});

// The handler's 202, or its refusal.
const DATA_KEYS_ACTION: Json = action({
  accepted: bool(),
  runId: str(),
  run: str('The address to follow the run at.')
});

// ---------------------------------------------------------------------------
// `GET /cells`: `cells_admin.ts`.
// ---------------------------------------------------------------------------
const CELL_PEOPLE: Json = closed({
  cell: str(),
  refused: str('Why the other cell did not list them.'),
  people: listOf(closed({
    name: str(), uuid: str(), displayName: str()
  })),
  next: str('The `after` of the next page, empty on the last.')
});

const CELLS: Json = closed({
  multi: bool(),
  cell: str(),
  jurisdiction: OPT_STR,
  consoleUrl: OPT_STR,
  peers: listOf(closed({
    id: str(),
    jurisdiction: OPT_STR,
    consoleUrl: str(),
    reachable: bool(),
    answeredMs: num(),
    reportedJurisdiction: OPT_STR,
    error: str()
  })),
  store: closed({
    tiered: bool(),
    globalReplicaLagMs: OPT_NUM,
    globalReplication: nullable(REPLICATION),
    routing: nullable(CELL_ROUTING),
    peoplePerCell: listOf(closed({
      realm: str(), cell: str(), people: int()
    }))
  }),
  channel: closed({
    listening: bool(),
    port: OPT_INT,
    listenError: OPT_STR,
    certificateUntil: OPT_STR,
    operations: STRINGS,
    counters: closed({
      relayedOut: int(),
      relayedIn: int(),
      opsOut: int(),
      opsIn: int(),
      refusedPeers: int(),
      failures: int()
    }),
    lastFailure: OPT_STR
  }),
  placement: closed({ relayed: int(), placedHere: int(), rows: int() }),
  sessions: closed({ projections: int(), exports: int() }),
  settings: SETTINGS_BLOCK,
  people: CELL_PEOPLE
});

// `code` is what `cell_rehome.ts` refused with, and it is in the body: the rule
// is that an error code is never sent, and this is reported on #1353 rather
// than changed here.
const REHOME_ACTION: Json = action({
  target: str(),
  code: str()
});

// ---------------------------------------------------------------------------
// `GET /caches`: `caches_admin.ts`'s `cachesJson()`, without `paging`, which
// `publicJson()` removes.
// ---------------------------------------------------------------------------
const CACHE_SUMMARY: Json = closed({
  name: str(),
  title: str(),
  description: str(),
  owner: str(),
  scope: str(),
  kind: str(),
  persisted: bool(),
  size: int(),
  largestRealm: int(),
  valid: int(),
  expired: int(),
  maxEntries: OPT_NUM,
  bound: str(),
  atBound: bool(),
  lifetime: str(),
  settings: STRINGS,
  counted: bool(),
  notCountedWhy: str(),
  hitMeaning: str(),
  hits: OPT_INT,
  misses: OPT_INT,
  hitRatio: OPT_NUM,
  evictions: int(),
  refusals: int(),
  problem: OPT_STR
});

const CACHES: Json = closed({
  generatedAt: str(),
  pid: str(),
  caches: listOf(CACHE_SUMMARY),
  totals: closed({ caches: int(), entries: int(), expired: int() }),
  notListed: listOf(closed({ what: str(), where: str(), why: str() })),
  otherProcesses: listOf(closed({
    nodeId: str(),
    name: str(),
    host: str(),
    pid: str(),
    thisNode: bool(),
    takenAt: str(),
    ageSeconds: num(),
    caches: listOf(closed({
      name: str(),
      title: str(),
      scope: str(),
      size: int(),
      largestRealm: int(),
      valid: int(),
      maxEntries: OPT_NUM,
      hits: OPT_INT,
      misses: OPT_INT,
      evictions: int(),
      refusals: int()
    })),
    totals: closed({ entries: int(), evictions: int(), refusals: int() })
  })),
  cache: str('The one asked for by `?cache=`.'),
  found: bool(),
  known: listOf(str(), 'The caches there are, when the one asked for is not.'),
  summary: CACHE_SUMMARY,
  entries: listOf(closed({
    realm: OPT_STR,
    key: str(),
    valid: bool(),
    validUntil: OPT_STR,
    remainingSeconds: OPT_INT,
    basis: str(),
    remaining: str()
  })),
  entriesPaging: PAGING
});

// ---------------------------------------------------------------------------
// `GET /sts-metadata`: `sts_metadata.ts`'s `pageJson()`. An `ENDPOINTS` row may
// carry `coverage`, and a `specs` row `what`.
// ---------------------------------------------------------------------------
const STS_METADATA: Json = closed({
  service: str(),
  version: str(),
  build: closed({
    number: str(),
    release: bool(),
    commit: str(),
    at: str(),
    stamped: bool()
  }),
  issuer: str(),
  wsTrustIssuer: str(),
  port: SCALAR,
  testDouble: bool(),
  endpoints: listOf(closed({
    path: str(),
    methods: STRINGS,
    name: str(),
    group: str(),
    specs: STRINGS,
    description: str(),
    documented: bool(),
    linkable: bool(),
    notLinkableBecause: str(),
    url: str(),
    effect: str()
  })),
  specifications: listOf(closed({
    id: str(),
    name: str(),
    where: str(),
    url: str(),
    coverage: str(),
    what: str()
  })),
  protocols: listOf(closed({
    name: str(),
    what: str(),
    sockets: str(),
    groups: STRINGS,
    specs: STRINGS,
    notAProtocol: bool(),
    endpoints: int()
  })),
  undocumentedPaths: STRINGS,
  stalePaths: STRINGS,
  unknownSpecIds: STRINGS,
  unknownProtocolGroups: STRINGS,
  unknownProtocolSpecIds: STRINGS,
  unclaimedGroups: STRINGS,
  rows: listOf(closed({
    path: str(),
    group: str(),
    name: str(),
    specs: STRINGS,
    what: str(),
    effect: str(),
    coverage: str(),
    methods: STRINGS,
    documented: bool()
  })),
  https: bool(),
  rfc9700: bool(),
  namedServers: listOf(closed({
    id: str(),
    label: OPT_STR,
    description: OPT_STR,
    overrides: mapOf(SETTING_VALUE, 'The settings this server overrides.'),
    removed: STRINGS,
    changedAt: str(),
    memberCount: int(),
    autoCreated: bool(),
    seen: int(),
    seenAt: str(),
    createdAt: str(),
    urls: closed({
      oauth: str(), oidc: str(), authorize: str(), token: str()
    })
  })),
  defaultServerId: str(),
  groupOrder: STRINGS
});

// ---------------------------------------------------------------------------
// `GET /openapi.json`, and the account API's through `GET /account-api`. The
// inside of an OpenAPI document is OpenAPI's vocabulary rather than this
// service's, and what the operations in it say is the very table this file is
// applied to, so its members are the one honest free-form.
// ---------------------------------------------------------------------------
const OPENAPI_INNER =
  'An OpenAPI 3.1 document\'s own contents: their shape is OpenAPI\'s, not ' +
  'this service\'s, and they are generated from the route table.';

const OPENAPI_DOCUMENT: Json = closed({
  openapi: str(),
  info: Kit.freeForm(OPENAPI_INNER),
  servers: Kit.freeForm(OPENAPI_INNER),
  tags: Kit.freeForm(OPENAPI_INNER),
  security: Kit.freeForm(OPENAPI_INNER),
  paths: Kit.freeForm(OPENAPI_INNER),
  components: Kit.freeForm(OPENAPI_INNER)
}, { description: 'An OpenAPI 3.1.0 document.' });

const ACCOUNT_API: Json = closed({
  url: str('Where the account API publishes the document itself.'),
  paths: int('Paths in the document.'),
  operations: int('Operations in the document.'),
  document: OPENAPI_DOCUMENT
});

// ---------------------------------------------------------------------------
// `GET /admin-api`: the handler's own, `admin_api.ts`.
// ---------------------------------------------------------------------------
const API_INDEX: Json = closed({
  name: str(),
  version: str('M.N.O.<build>: the release the repo-root VERSION file ' +
               'declares, followed by the build number. A stamp written ' +
               'before build numbers returned (#1317) reports the bare M.N.O.'),
  build: str('The build number on its own: the UTC build instant as ' +
             'YYYYMMDDHHMMSS, or the BUILD_NUMBER a release build named. ' +
             'Absent on a stamp that carries none.'),
  release: bool('True when this build was flagged as a release ' +
                '(STS_RELEASE=true) and named its build number.'),
  commit: str('The first twelve characters of the commit this was built ' +
              'from. Absent when the build could not know it.'),
  builtAt: str('When this build was made. Read it with `stamped`.'),
  stamped: bool('True when this version came off a record written at image ' +
                'build time. False means the process computed its own record ' +
                'at startup, so `builtAt` and the build number are the moment ' +
                'it started.'),
  openapi: str('Where the document is.'),
  docs: str('Where the explorer is.'),
  console: str('Where the console every operation mirrors is.'),
  protected: bool('Whether this API requires an access token ' +
                  '(`adminApi.authRequired`, on by default).'),
  operations: listOf(closed({
    method: str(),
    path: str(),
    operationId: str(),
    summary: str(),
    mirrors: str('The /admin control this operation is the API form of.'),
    kind: Kit.strEnum(['management', 'console'],
                      'Which of the two kinds the operation is (#454).'),
    drawnOn: listOf(str(), 'The console pages drawn from this operation\'s ' +
                           'data by one of the console\'s own operations ' +
                           '(#454); present only where there are any.')
  }, { description: 'One operation.' }),
  'Every management operation, with the console page it mirrors. The ' +
  'console\'s own operations are listed by GET /admin-api/console/operations ' +
  '(#454).')
}, { description: 'What this API is, where its document is, and every ' +
                  'operation it offers.' });

// ---------------------------------------------------------------------------
// RISK: `risk_admin.ts`, over `risk_datasets.ts`, `risk_terms.ts`,
// `risk_engine.ts` and `risk_store.ts`.
//
// **AN ASSESSMENT COMES IN TWO SHAPES**: the memory store hands back what the
// engine wrote, and the database hands back its columns, so the row's model is
// their union and neither is required. `datasets` on it is a map of dataset id
// to the version read, with `stale` and `attributions` beside them in the same
// object, as the engine writes it.
// ---------------------------------------------------------------------------
const ATTRIBUTION: Json = closed({
  provider: str(),
  text: str(),
  url: OPT_STR,
  licence: OPT_STR,
  licenceUrl: OPT_STR,
  modified: str()
});

const ACCEPTANCE: Json = closed({
  id: oneOf(str(), num()),
  provider: str(),
  termsDigest: str(),
  termsText: str(),
  acceptedBy: str(),
  acceptedVia: str(),
  deployment: str(),
  pageDigest: str(),
  acceptedAt: num()
});

// `store.listVersions()`: the memory row, or `riskVersionFrom()`'s columns.
// **`parameters` IS A BAG THIS SERVICE WRITES AS A VERSION PROGRESSES AND KEEPS
// IN THE DATABASE** (`attributionUrl`, `termsDigest`, `progressRows`, `mdsNo`,
// `signatureOverride`...), so a row an older build wrote may carry a member this
// one does not: a map, its values typed, rather than a closed list.
const DATASET_VERSION: Json = closed({
  realm: str(),
  dataset: str(),
  version: str(),
  format: str(),
  provider: str(),
  licence: OPT_STR,
  attribution: OPT_STR,
  source: str(),
  sourceUri: OPT_STR,
  sha256: OPT_STR,
  byteCount: num(),
  rowCount: num(),
  parameters: mapOf(SCALAR, 'What was recorded of this version as it loaded.'),
  verification: OPT_STR,
  publishedAt: num(),
  nextUpdateAt: num(),
  fetchedAt: num(),
  loadedAt: num(),
  activatedAt: num(),
  supersededAt: num(),
  rowsDeletedAt: num(),
  state: str(),
  refusal: OPT_STR,
  errorCode: OPT_STR,
  origin: OPT_STR,
  reloadable: bool()
});

const RISK_DATASET: Json = closed({
  dataset: str(),
  realm: str(),
  kind: str(),
  title: str(),
  what: str(),
  formats: STRINGS,
  perRealm: bool(),
  staleAfterMs: OPT_NUM,
  state: str(),
  activeVersion: str(),
  previousVersion: OPT_STR,
  publishedAt: num(),
  rows: num(),
  provider: OPT_STR,
  attribution: OPT_STR,
  attributionUrl: OPT_STR,
  versions: listOf(DATASET_VERSION)
});

// `risk_terms.ts`'s `status()`: the provider's row of `PROVIDERS` and what was
// said of it.
const RISK_PROVIDER: Json = closed({
  provider: str(),
  title: str(),
  url: OPT_STR,
  licence: OPT_STR,
  licenceName: OPT_STR,
  licenceUrl: OPT_STR,
  attribution: OPT_STR,
  terms: OPT_STR,
  termsUrl: OPT_STR,
  supported: bool(),
  noAcceptance: bool(),
  termsDigest: OPT_STR,
  needsAcceptance: bool(),
  accepted: nullable(ACCEPTANCE),
  changed: bool()
});

// A hit in a range table: `riskRangeFrom()`'s columns, or what `parseRow()` made
// of the file's line in the memory store, with `dataset` added.
const RANGE_HIT: Json = closed({
  dataset: str(),
  start: str(),
  end: str(),
  locationId: num(),
  continent: OPT_STR,
  country: OPT_STR,
  subdivision: OPT_STR,
  city: OPT_STR,
  registeredCountry: OPT_STR,
  latitude: OPT_NUM,
  longitude: OPT_NUM,
  accuracyKm: num(),
  anonymousProxy: bool(),
  satellite: bool(),
  asn: num(),
  asOrg: OPT_STR,
  asDomain: OPT_STR,
  category: OPT_STR,
  note: OPT_STR
});

const ADDRESS_LOOKUP: Json = closed({
  address: str(),
  prefix: OPT_STR,
  geo: nullable(RANGE_HIT),
  asn: nullable(RANGE_HIT),
  lists: listOf(closed({ dataset: str(), category: OPT_STR })),
  datasets: mapOf(str(), 'The version of each dataset this was read from.'),
  stale: STRINGS,
  attributions: listOf(ATTRIBUTION)
});

const FIDO_STATEMENT =
  'The FIDO Alliance\'s MDS3 metadata statement, kept as the BLOB carried it: ' +
  'its shape is the FIDO Metadata Statement specification\'s, and which of its ' +
  'optional members a statement has is the vendor\'s.';

const AUTHENTICATOR_LOOKUP: Json = closed({
  input: str(),
  keyKind: str(),
  key: str(),
  listed: bool(),
  why: str(),
  detail: str(),
  version: str(),
  stale: bool(),
  model: nullable(closed({
    keyKind: str(),
    key: str(),
    description: OPT_STR,
    protocolFamily: OPT_STR,
    certificationLevel: OPT_STR,
    latestStatus: OPT_STR,
    latestStatusAt: num(),
    compromised: bool(),
    statusReports: listOf(closed({
      status: str(),
      effectiveDate: str(),
      reason: str(),
      expires: str(),
      comment: str()
    })),
    metadataStatement: Kit.freeForm(FIDO_STATEMENT)
  })),
  attributions: listOf(ATTRIBUTION)
});

// One line of an assessment's `signals`. The first is always `model`, the rest
// each one thing that moved the score.
const RISK_SIGNAL: Json = closed({
  signal: str(),
  score: OPT_NUM,
  factor: num(),
  factors: nullable(mapOf(num(), 'Per level of the model.')),
  terms: nullable(closed({
    users: num(), signIns: num(), userSignIns: num()
  })),
  why: str(),
  what: str(),
  evidence: OPT_STR,
  knownContext: bool(),
  unknown: STRINGS,
  capped: str(),
  listsSetAside: STRINGS,
  device: nullable(closed({
    id: str(),
    via: str(),
    own: bool(),
    compliance: str(),
    attestation: str(),
    status: str()
  }))
});

const RISK_ASSESSMENT: Json = closed({
  realm: str(),
  id: str(),
  at: num(),
  phase: str(),
  door: str(),
  subject: OPT_STR,
  username: OPT_STR,
  userHref: str(),
  sessionId: OPT_STR,
  clientId: OPT_STR,
  addressPrefix: OPT_STR,
  asn: num(),
  asOrg: OPT_STR,
  country: OPT_STR,
  subdivision: OPT_STR,
  city: OPT_STR,
  latitude: OPT_NUM,
  longitude: OPT_NUM,
  accuracyKm: num(),
  ipLists: STRINGS,
  uaHash: OPT_STR,
  uaFamily: OPT_STR,
  uaOs: OPT_STR,
  uaPlatform: OPT_STR,
  bot: OPT_BOOL,
  ja4: OPT_STR,
  credentialKind: OPT_STR,
  credentialHash: OPT_STR,
  aaguid: OPT_STR,
  authenticatorCert: OPT_STR,
  backupEligible: OPT_BOOL,
  backupState: OPT_BOOL,
  datasets: mapOf(oneOf(str(), listOf(oneOf(str(), ATTRIBUTION))),
                  'The version of each dataset read, and `stale` and ' +
                  '`attributions` beside them.'),
  signals: listOf(RISK_SIGNAL),
  score: OPT_NUM,
  level: str(),
  decision: OPT_STR,
  policyId: OPT_STR,
  errorCode: OPT_STR,
  feedback: OPT_STR,
  feedbackAt: num()
});

const RISK_SUBJECT: Json = closed({
  subject: str(),
  username: OPT_STR,
  userHref: str(),
  score: OPT_NUM,
  level: str(),
  previousLevel: OPT_STR,
  reason: OPT_STR,
  lastAssessment: OPT_STR,
  crossedAt: num(),
  updatedAt: num(),
  actions: mapOf(str(), 'Each reaction taken, and the assessment that took it.'),
  feedback: OPT_STR
});

const RISK: Json = closed({
  realm: str(),
  realmOnly: bool(),
  store: closed({ mode: str(), database: bool(), why: str() }),
  directory: str(),
  datasets: listOf(RISK_DATASET),
  formats: listOf(closed({ format: str(), provider: str(), what: str() })),
  providers: listOf(RISK_PROVIDER),
  acceptances: listOf(ACCEPTANCE),
  attributions: listOf(ATTRIBUTION),
  redistribution: str(),
  lookup: nullable(ADDRESS_LOOKUP),
  authenticatorLookup: nullable(AUTHENTICATOR_LOOKUP),
  assessments: closed({ total: int(), rows: listOf(RISK_ASSESSMENT) }),
  assessmentsPaging: PAGING,
  subjects: listOf(RISK_SUBJECT),
  subjectsPaging: PAGING,
  signals: listOf(closed({ signal: str(), factor: num(), what: str() })),
  assessmentsInDatabase: bool(),
  failures: closed({
    store: closed({ recording: bool(), database: bool(), why: str() }),
    windowDays: num(),
    total: int(),
    offset: int(),
    limit: int(),
    rows: listOf(closed({
      id: oneOf(str(), num()),
      at: num(),
      door: str(),
      subject: OPT_STR,
      username: OPT_STR,
      userHref: str(),
      name: str(),
      prefix: OPT_STR,
      asn: num(),
      errorCode: OPT_STR
    }))
  }),
  failuresPaging: PAGING,
  settings: SETTINGS_BLOCK
});

// `RiskStore.metricsOf()`. Every `by*` is a count per value that a row held, and
// a series point a count per level, so they are maps.
const COUNTS: Json = mapOf(num());

const RISK_THRESHOLD: Json = closed({
  current: num(), share: num(), target: num(), suggested: OPT_NUM
});

const RISK_METRICS: Json = closed({
  window: str(),
  windows: STRINGS,
  realmOnly: bool(),
  bands: STRINGS,
  realm: str(),
  windowMs: num(),
  since: num(),
  bucketMs: num(),
  database: bool(),
  enforced: bool(),
  thresholds: closed({ medium: num(), high: num() }),
  assessments: closed({
    total: num(),
    subjects: num(),
    bots: num(),
    meanScore: num(),
    maxScore: num(),
    byLevel: COUNTS,
    byDoor: COUNTS,
    byDecision: COUNTS,
    byPhase: COUNTS,
    byCountry: COUNTS,
    byBand: COUNTS,
    bySignal: COUNTS,
    bySignalLevel: mapOf(COUNTS),
    bySignalFeedback: mapOf(COUNTS),
    scoreQuantiles: COUNTS,
    feedback: closed({ confirmed: num(), denied: num() }),
    series: listOf(COUNTS)
  }),
  calibration: closed({
    assessments: num(),
    answered: num(),
    notMeRate: num(),
    minimums: closed({ assessments: num(), answersPerSignal: num() }),
    thresholds: closed({ medium: RISK_THRESHOLD, high: RISK_THRESHOLD }),
    signals: listOf(closed({
      signal: str(),
      factor: num(),
      builtIn: num(),
      fired: num(),
      high: num(),
      answered: num(),
      notMe: num(),
      suggested: OPT_NUM,
      advice: str()
    })),
    invalidFactors: STRINGS
  }),
  standings: COUNTS,
  signals: listOf(closed({
    signal: str(), factor: num(), builtIn: num(), what: str(), fired: num()
  })),
  process: closed({
    since: num(),
    assessed: num(),
    failed: num(),
    durationMs: closed({
      samples: num(), mean: num(), p50: num(), p95: num(), p99: num(), max: num()
    }),
    reactions: closed({ taken: COUNTS, observed: COUNTS, failed: COUNTS }),
    rescore: closed({ runs: num(), sessions: num(), raised: num() }),
    breachedPasswords: nullable(closed({
      enabled: bool(),
      since: num(),
      screened: num(),
      breached: num(),
      unanswered: num(),
      fromCache: num()
    }))
  })
});

// What any of the risk actions answers, including a refused import's `dataset`
// and `version`, and an upload's. `duplicate` is a version already recorded;
// `serial` and `overridden` are a FIDO BLOB's.
const RISK_ACTION: Json = action({
  dataset: OPT_STR,
  version: OPT_STR,
  realm: OPT_STR,
  state: str(),
  rows: num(),
  skipped: num(),
  activated: bool(),
  sha256: str(),
  duplicate: bool(),
  serial: num(),
  overridden: str(),
  previous: str(),
  unloaded: bool(),
  acceptance: ACCEPTANCE,
  bytes: num(),
  kind: str()
});

// ---------------------------------------------------------------------------
// GEOLOCATION: `geolocation_admin.ts`'s `geoView()`. `shown()` withholds a count
// below `risk.geoMinimumCount`, so a count is nullable everywhere.
// ---------------------------------------------------------------------------
const GEO_COUNT: Json = closed({
  people: OPT_NUM,
  signIns: OPT_NUM,
  suppressed: bool(),
  lastAt: num()
});

const GEOLOCATION: Json = closed({
  ok: bool(),
  realm: str(),
  window: str(),
  windows: STRINGS,
  level: str(),
  continent: nullable(closed({ continent: str(), name: str() })),
  country: nullable(closed({ iso: str(), name: str() })),
  minimumCount: num(),
  database: bool(),
  since: num(),
  liveSessions: OPT_NUM,
  total: GEO_COUNT,
  world: GEO_COUNT,
  continents: listOf(closed(Object.assign({
    continent: str(), name: str()
  }, GEO_COUNT.properties))),
  countries: listOf(closed(Object.assign({
    iso: str(), onMap: bool(), name: str(), continent: OPT_STR
  }, GEO_COUNT.properties))),
  unknown: GEO_COUNT,
  cities: listOf(closed({
    city: str(),
    subdivision: OPT_STR,
    latitude: OPT_NUM,
    longitude: OPT_NUM,
    people: num(),
    signIns: num(),
    lastAt: num()
  })),
  countryOnly: nullable(GEO_COUNT),
  hidden: closed({ cities: num(), signIns: num() }),
  datasets: listOf(closed({
    dataset: str(), title: str(), state: str(), version: str()
  })),
  attributions: listOf(ATTRIBUTION),
  outlines: closed({
    source: str(),
    url: str(),
    upstream: str(),
    generatedBy: str(),
    inputSha256: str(),
    license: str()
  }),
  drawing: closed({
    picture: closed({ svg: str(), width: num(), height: num() }),
    legend: listOf(closed({ colour: str(), from: num(), to: num() }))
  }),
  noDataColour: str()
});

// ---------------------------------------------------------------------------
// MAIL: `mail_admin.ts` over `common/mail.ts`.
// ---------------------------------------------------------------------------
const MAIL_COUNTS: Json = closed({
  pending: int(), sent: int(), captured: int(), dead: int()
});

// `mail.ts`'s `view()`. A captured message's `text` and `html` only when one
// message is asked for.
const MAIL_ROW: Json = closed({
  id: str(),
  realm: OPT_STR,
  username: OPT_STR,
  to: OPT_STR,
  category: OPT_STR,
  template: OPT_STR,
  lang: OPT_STR,
  subject: OPT_STR,
  from: OPT_STR,
  messageId: OPT_STR,
  via: OPT_STR,
  actor: OPT_STR,
  state: str(),
  transport: OPT_STR,
  generation: num(),
  attempts: num(),
  inFlight: bool(),
  holder: str(),
  errorCode: OPT_STR,
  why: OPT_STR,
  providerId: str(),
  bodyKept: bool(),
  queuedAt: str(),
  nextAttemptAt: str(),
  lastAttemptAt: str(),
  finishedAt: str(),
  text: OPT_STR,
  html: OPT_STR
});

const MAIL: Json = closed({
  realm: str(),
  mode: str(),
  setting: OPT_STR,
  transport: OPT_STR,
  available: bool(),
  from: OPT_STR,
  linkBase: OPT_STR,
  linkBasePinned: bool(),
  relay: nullable(closed({
    host: OPT_STR,
    port: SCALAR,
    tls: SCALAR,
    auth: SCALAR,
    dkim: str()
  })),
  buildProblem: nullable(closed({ code: str(), why: str(), at: str() })),
  counts: MAIL_COUNTS,
  categories: listOf(closed({
    id: str(), label: str(), what: str(), optional: bool(), reason: str()
  })),
  selfServiceReset: bool(),
  securityNotices: bool(),
  templates: listOf(closed({
    id: str(),
    title: str(),
    category: str(),
    values: STRINGS,
    links: STRINGS,
    languages: STRINGS,
    builtInLanguages: STRINGS
  })),
  settings: SETTINGS_BLOCK,
  template: closed({
    id: str(),
    title: str(),
    category: str(),
    lang: str(),
    own: bool(),
    values: STRINGS,
    links: STRINGS,
    subject: str(),
    text: str(),
    html: str()
  })
});

const MAIL_OUTBOX: Json = closed({
  realm: str(),
  transport: OPT_STR,
  counts: MAIL_COUNTS,
  state: str(),
  q: str(),
  rows: listOf(MAIL_ROW),
  rowsPaging: PAGING,
  message: nullable(MAIL_ROW)
});

// `verified` is `startVerification()`'s answer for an address already verified.
const MAIL_ACTION: Json = action({
  message_id: str(),
  verified: bool(),
  row: MAIL_ROW
});
// ---------------------------------------------------------------------------
// A REFUSAL OF A READ. A GET's row declares only its 200, so what its door says
// to a query parameter outside a closed set is `default`; this names the same
// words for the ones that are refused that way.
// ---------------------------------------------------------------------------
const REFUSAL: Json = closed({
  ok: bool(),
  errors: STRINGS,
  error: str(),
  error_description: str(),
  message: str()
});

// ---------------------------------------------------------------------------
// DEVICES: `devices_admin.ts` over `common/devices.ts`. A key's values are stored
// on its entry as JSON and read back with `JSON.parse`, so `DEVICE_KEY` is what
// `prepareKey()` writes; `revocation` is `attestation_revocation.ts`'s verdict.
// ---------------------------------------------------------------------------
const DEVICE_CHANGE: Json = closed({
  status: str(),
  previous: OPT_STR,
  at: str(),
  source: str(),
  actor: str(),
  reason: str()
});

const DEVICE_KEY: Json = closed({
  id: str(),
  kind: str(),
  thumbprint: str(),
  label: str(),
  added: str(),
  addedBy: str(),
  proof: str(),
  attestation: closed({
    level: str(),
    format: str(),
    summary: str(),
    verifiedAt: str(),
    chainSerials: STRINGS,
    revocation: closed({
      status: str(),
      reason: str(),
      serial: str(),
      listVersion: str(),
      checkedAt: oneOf(str(), num()),
      chainSerials: STRINGS,
      why: str()
    }),
    freshness: closed({ status: str(), detail: str() })
  }),
  material: closed({
    certificate: str(),
    subject: OPT_STR,
    issuer: OPT_STR,
    serial: OPT_STR,
    notAfter: oneOf(str(), num(), { type: 'null' }),
    // The public members of whichever key type it is, which are JOSE's.
    jwk: mapOf(oneOf(str(), listOf(str()), bool(), num()),
               'A public JWK\'s members.'),
    credentialId: str(),
    aaguid: str(),
    attachment: str()
  })
});

const DEVICE: Json = closed({
  id: str(),
  dn: str(),
  owner: str(),
  ownerKind: str(),
  label: str(),
  applications: STRINGS,
  keys: listOf(DEVICE_KEY),
  keyKinds: STRINGS,
  attestation: closed({
    level: str(), format: str(), summary: str(), keyId: str()
  }),
  compliance: str(),
  complianceChange: nullable(DEVICE_CHANGE),
  status: str(),
  statusChange: nullable(DEVICE_CHANGE),
  riskLevel: str(),
  riskChange: nullable(closed({
    level: str(),
    previous: OPT_STR,
    at: str(),
    source: str(),
    actor: str(),
    reason: str(),
    beforeCompromise: str()
  })),
  platform: str(),
  model: str(),
  os: str(),
  enrolment: closed({ method: str(), at: str(), actor: str() }),
  nativeSso: bool(),
  rememberedBrowser: nullable(closed({
    generation: num(),
    issuedAt: str(),
    browser: str(),
    secondFactorAt: str()
  })),
  sessionLive: bool(),
  lastUsed: str(),
  created: str(),
  ownerName: str(),
  ownerFound: bool(),
  applicationNames: STRINGS
});

const DEVICE_VOCABULARY: Json = closed({
  ownerKinds: STRINGS,
  keyKinds: STRINGS,
  compliance: STRINGS,
  attestation: STRINGS,
  statuses: STRINGS,
  platforms: STRINGS
});

const DEVICES: Json = closed({
  found: bool(),
  id: str(),
  device: nullable(DEVICE),
  vocabulary: DEVICE_VOCABULARY,
  total: int(),
  matched: int(),
  filter: mapOf(str(), 'What the list was narrowed by.'),
  devices: listOf(DEVICE),
  page: int(),
  pages: int(),
  perPage: int(),
  devicesPaging: PAGING
});

const DEVICE_ACTION: Json = action({
  id: str(),
  device: DEVICE,
  key: str('The key\'s id.'),
  previous: str(),
  status: str(),
  sessionsEnded: num(),
  certificatesRevoked: num()
});

// `mdmFeed()`. A row's refusal is `setCompliance()`'s.
const DEVICE_COMPLIANCE: Json = action({
  applied: int(),
  refused: int(),
  results: listOf(closed({
    index: int(),
    id: str(),
    ok: bool(),
    errors: STRINGS,
    previous: str(),
    status: str(),
    changed: bool(),
    signalled: bool()
  }))
});

const DEVICE_COMPLIANCE_COUNTS: Json = mapOf(num());

const DEVICES_MONITOR: Json = closed({
  counts: closed({
    total: num(),
    byOwnerKind: COUNTS,
    byCompliance: COUNTS,
    byAttestation: COUNTS,
    byKeyKind: COUNTS,
    byEnrolment: COUNTS,
    byStatus: COUNTS,
    byRiskLevel: COUNTS,
    byKeyAttestationFormat: COUNTS,
    keys: num(),
    nativeSso: closed({ live: num(), ended: num(), none: num() }),
    windowed: bool(),
    counted: num(),
    complete: bool()
  }),
  timeline: closed({
    days: int(),
    rows: listOf(closed({
      day: str(),
      created: num(),
      removed: num(),
      evicted: num(),
      compliance: DEVICE_COMPLIANCE_COUNTS
    })),
    totals: closed({
      created: num(),
      removed: num(),
      evicted: num(),
      compliance: DEVICE_COMPLIANCE_COUNTS
    }),
    since: str()
  }),
  activity: closed({
    scope: str(),
    recognitions: COUNTS,
    enrolments: COUNTS,
    attestationLevels: COUNTS,
    attestationFormats: COUNTS,
    attestationRefusals: COUNTS
  }),
  complianceSources: STRINGS
});

const DEVICE_REGISTRATION: Json = closed({
  enrolment: listOf(closed({ method: str(), built: bool(), what: str() })),
  recognition: listOf(closed({ kind: str(), built: bool(), what: str() })),
  ownerKinds: STRINGS,
  keyKinds: STRINGS,
  keyProofs: STRINGS,
  attestationLevels: STRINGS,
  attestationFormats: STRINGS,
  complianceStates: STRINGS,
  complianceSources: STRINGS,
  mdmFeed: closed({
    built: bool(),
    path: str(),
    scope: str(),
    role: str(),
    maxReports: num(),
    identifiedBy: STRINGS,
    source: str()
  }),
  receivedCaep: closed({ built: bool(), source: str(), via: str() }),
  signals: closed({ caep: STRINGS, risc: STRINGS, subject: str() }),
  recordedAt: closed({ signIn: str(), tokenEndpoint: str() }),
  decisions: closed({
    riskSignals: STRINGS,
    expectRegistered: bool(),
    refuseCompromised: bool(),
    requireCompliantDevice: bool(),
    compliantDeviceAttested: bool(),
    policy: str(),
    acr: str(),
    claim: str()
  }),
  unattestedKeys: closed({
    accepted: bool(), predicate: str(), adminKeys: str()
  }),
  freshKeyAttestation: closed({
    required: bool(), predicate: str(), nonce: str(), scep: str()
  }),
  trustAnchors: listOf(closed({
    kind: str(),
    setting: str(),
    source: str(),
    count: OPT_INT,
    shipped: listOf(closed({
      subject: str(), notAfter: str(), sha256: str(), used: bool()
    }))
  })),
  challenges: closed({
    store: str(),
    perRealm: bool(),
    persisted: bool(),
    live: int(),
    ttlSeconds: num(),
    max: num(),
    purposes: STRINGS
  }),
  settings: SETTINGS_BLOCK,
  androidStatus: closed({
    active: str(),
    loadedAt: num(),
    rows: num(),
    stale: bool(),
    staleAfterHours: num(),
    url: str(),
    required: bool(),
    job: str(),
    error: str()
  })
});

// ---------------------------------------------------------------------------
// THE SCHEDULER: `scheduler_admin.ts` over `cluster/scheduler.ts`. `runView()` is
// the one shape of a run; a run's `params` is what the person who asked for it
// sent, which is whatever that job reads.
// ---------------------------------------------------------------------------
const SCHEDULER_RUN: Json = closed({
  runId: str(),
  jobId: OPT_STR,
  realm: OPT_STR,
  trigger: str(),
  state: str(),
  attempt: int(),
  fenceAt: num(),
  node: str(),
  nodeName: str(),
  host: str(),
  pid: OPT_INT,
  worker: bool(),
  dueAt: OPT_STR,
  queuedAt: OPT_STR,
  queuedAtMs: OPT_NUM,
  startedAt: OPT_STR,
  endedAt: OPT_STR,
  durationMs: OPT_NUM,
  requestedBy: str(),
  requestedVia: str(),
  params: Kit.freeForm('A manual run\'s `params`: the JSON its requester sent, ' +
                       'whose members are the job\'s own to read, or null.'),
  takenOver: bool(),
  abandonedOf: OPT_STR,
  ranIn: OPT_STR,
  deferredMs: num(),
  errorCode: str(),
  why: str(),
  result: nullable(str('`summaryOf()`: the job\'s answer as text, 500 ' +
                       'characters at most.')),
  nextRunAt: OPT_STR,
  nextRunInMs: OPT_NUM,
  stale: bool()
});

const SCHEDULER_LEADER: Json = closed({
  clustered: bool(),
  known: bool(),
  node: OPT_STR,
  nodeName: OPT_STR,
  host: OPT_STR,
  pid: OPT_INT,
  since: OPT_STR,
  token: OPT_NUM,
  leaseHolder: OPT_STR,
  leaseAcquiredAt: OPT_STR,
  leaseExpiresAt: OPT_STR,
  lastTickAt: OPT_STR,
  lastTickAgoMs: OPT_NUM,
  thisProcess: OPT_BOOL,
  live: OPT_BOOL
});

const SCHEDULER_JOB: Json = closed({
  id: str(),
  title: str(),
  describe: str(),
  owner: str(),
  kind: str(),
  scope: str(),
  realm: str(),
  readOnly: bool(),
  schedule: closed({
    text: str(),
    everyMs: OPT_NUM,
    setting: OPT_STR,
    cron: OPT_STR,
    manualOnly: bool()
  }),
  state: str(),
  offReason: OPT_STR,
  manual: bool(),
  timeoutMs: num(),
  runsOn: str(),
  onFront: OPT_STR,
  nice: num(),
  processes: listOf(SCHEDULER_RUN),
  lastRun: nullable(SCHEDULER_RUN),
  running: nullable(SCHEDULER_RUN),
  queued: listOf(SCHEDULER_RUN),
  nextRunAt: OPT_STR,
  nextRunInMs: OPT_NUM,
  nextRunState: str(),
  overdueSince: OPT_STR,
  overdueWhy: OPT_STR
});

const LEADER_AT_REQUEST: Json = closed({
  node: OPT_STR, pid: OPT_INT, token: OPT_NUM
});

const SCHEDULER: Json = closed({
  generatedAt: str(),
  nowMs: num(),
  clock: str(),
  answeredBy: closed({
    node: str(), nodeName: str(), host: str(), pid: int()
  }),
  leader: SCHEDULER_LEADER,
  tickS: num(),
  enabled: bool(),
  unknownDisabledIds: STRINGS,
  jobs: listOf(SCHEDULER_JOB),
  runs: listOf(SCHEDULER_RUN),
  commands: listOf(closed({
    id: str(),
    command: str(),
    state: str(),
    requestedBy: str(),
    queuedAt: OPT_STR,
    endedAt: OPT_STR,
    leaderAtRequest: nullable(LEADER_AT_REQUEST),
    obeyedBy: Kit.nullable(oneOf(str(), closed({
      node: OPT_STR, pid: OPT_INT, nodeName: OPT_STR, host: OPT_STR
    })))
  })),
  confinedToRealm: OPT_STR,
  filters: closed({ job: OPT_STR, outcome: OPT_STR }),
  runsPaging: PAGING,
  jobsPaging: PAGING,
  jobIds: STRINGS,
  settings: SETTINGS_BLOCK,
  run: str('The run asked for by `?run=`.'),
  found: bool(),
  detail: nullable(SCHEDULER_RUN)
});

const SCHEDULER_ACTION: Json = action({
  accepted: bool(),
  runId: str(),
  alreadyQueued: bool(),
  run: SCHEDULER_RUN,
  href: str(),
  command: str(),
  leaderAtRequest: nullable(LEADER_AT_REQUEST)
});

// ---------------------------------------------------------------------------
// WHAT EVERY NODE SNAPSHOT SAYS: `node_snapshots.ts`'s `read()`, under both the
// worker pools and node health.
// ---------------------------------------------------------------------------
const SNAPSHOT_CLUSTER: Json = closed({
  clustered: bool(),
  text: str(),
  intervalSeconds: num(),
  staleAfterSeconds: num(),
  goneRemovedAfterHours: num(),
  readError: OPT_STR
});

const NO_NODE: Json = closed({
  ok: bool(),
  errors: STRINGS,
  nodes: listOf(str(), 'The nodes there are.')
});

const WORKER_POOL: Json = closed({
  id: str(),
  title: str(),
  module: str(),
  setting: str(),
  state: str(),
  stateText: str(),
  maxWorkers: num(),
  initialWorkers: num(),
  currentWorkers: num(),
  readyWorkers: num(),
  startingWorkers: num(),
  busyWorkers: num(),
  freeWorkers: num(),
  restarts: closed({
    forked: num(),
    replaced: num(),
    crashed: num(),
    failedStarts: num(),
    stopped: num()
  }),
  responseTime: closed({
    answered: num(),
    averageMs: OPT_NUM,
    recentAverageMs: OPT_NUM,
    maxMs: OPT_NUM
  }),
  startedAt: OPT_STR,
  prefixes: STRINGS,
  workers: listOf(closed({
    threadId: oneOf(int(), str()),
    slot: nullable(oneOf(int(), str())),
    ready: bool(),
    busy: bool(),
    inFlight: num(),
    served: num(),
    retiring: bool(),
    upSeconds: OPT_NUM
  }))
});

const POOLS_VIEW_MEMBERS: Json = {
  generatedAt: str(),
  node: OPT_STR,
  pid: OPT_INT,
  mainThread: bool(),
  scope: str(),
  scopeText: str(),
  pools: listOf(WORKER_POOL)
};

const WORKER_POOLS: Json = closed(Object.assign({}, POOLS_VIEW_MEMBERS, {
  answeredBy: closed({ node: OPT_STR, pid: int() }),
  state: str(),
  cluster: SNAPSHOT_CLUSTER,
  nodes: listOf(closed({
    name: str(),
    self: bool(),
    state: str(),
    stateText: str(),
    ageSeconds: OPT_NUM,
    takenAt: OPT_STR,
    view: nullable(closed(POOLS_VIEW_MEMBERS))
  })),
  totals: closed({
    nodes: int(),
    nodesCounted: int(),
    pools: listOf(closed({
      id: str(),
      title: str(),
      currentWorkers: num(),
      busyWorkers: num(),
      freeWorkers: num(),
      forked: num(),
      crashed: num(),
      failedStarts: num(),
      nodesOn: num()
    })),
    text: str()
  })
}));
//@@MORE-CONSTANTS@@

export = {
  components: {
    ApiIndex: API_INDEX,
    Config: CONFIG,
    PageSettings: PAGE_SETTINGS
    //@@MORE-COMPONENTS@@
  } as Record<string, unknown>,
  operations: {
    getStsMetadata: { '200': STS_METADATA },
    getOpenApi: { '200': OPENAPI_DOCUMENT },
    getEncryption: { '200': ENCRYPTION },
    rotateDataKeys: { '200': DATA_KEYS_ACTION, '202': DATA_KEYS_ACTION },
    reencryptDataKeys: { '200': DATA_KEYS_ACTION, '202': DATA_KEYS_ACTION },
    countDataKeys: { '200': DATA_KEYS_ACTION, '202': DATA_KEYS_ACTION },
    rotateKek: { '200': DATA_KEYS_ACTION, '202': DATA_KEYS_ACTION },
    getCells: { '200': CELLS },
    getCellPeople: { '200': CELL_PEOPLE },
    rehomePerson: { '200': REHOME_ACTION },
    getMode: { '200': MODE },
    getAccountApi: { '200': ACCOUNT_API },
    getListeners: { '200': LISTENERS },
    setListeners: { '200': LISTENERS_ACTION },
    setListenerApplications: { '200': LISTENERS_ACTION },
    getCaches: { '200': CACHES },
    getRealms: { '200': REALMS },
    createRealm: { '200': REALM_ACTION },
    updateRealm: { '200': REALM_ACTION },
    setRealmSetting: { '200': REALM_ACTION },
    unsetRealmSetting: { '200': REALM_ACTION },
    removeRealm: { '200': REALM_ACTION },
    setSetting: { '200': SET_SETTING },
    setSettings: { '200': SET_SETTINGS },
    resetSetting: { '200': SET_SETTING },
    resetAllSettings: { '200': RESET_ALL },
    getRisk: { '200': RISK },
    getRiskMetrics: { '200': RISK_METRICS, '400': REFUSAL },
    getGeolocation: { '200': GEOLOCATION, '400': REFUSAL },
    uploadRiskDataset: { '200': RISK_ACTION, '202': RISK_ACTION },
    importRiskDataset: { '200': RISK_ACTION },
    activateRiskDataset: { '200': RISK_ACTION },
    reloadRiskDatasetVersion: { '200': RISK_ACTION },
    rollbackRiskDataset: { '200': RISK_ACTION },
    acceptRiskProviderTerms: { '200': RISK_ACTION },
    deleteRiskDatasetVersion: { '200': RISK_ACTION },
    getMail: { '200': MAIL, '400': REFUSAL },
    sendMailTestMessage: { '200': MAIL_ACTION },
    sendMailVerificationLink: { '200': MAIL_ACTION },
    saveMailTemplate: { '200': MAIL_ACTION },
    resetMailTemplate: { '200': MAIL_ACTION },
    getMailOutbox: { '200': MAIL_OUTBOX, '400': REFUSAL },
    retryMailDeadLetter: { '200': MAIL_ACTION },
    getDevices: { '200': DEVICES, '400': REFUSAL },
    createDevice: { '200': DEVICE_ACTION },
    updateDevice: { '200': DEVICE_ACTION },
    removeDevice: { '200': DEVICE_ACTION },
    addDeviceKey: { '200': DEVICE_ACTION },
    removeDeviceKey: { '200': DEVICE_ACTION },
    setDeviceCompliance: { '200': DEVICE_ACTION },
    setDeviceStatus: { '200': DEVICE_ACTION },
    reportDeviceCompliance: { '200': DEVICE_COMPLIANCE },
    getDevicesMonitor: { '200': DEVICES_MONITOR },
    getDeviceRegistration: { '200': DEVICE_REGISTRATION },
    getScheduler: { '200': SCHEDULER, '400': REFUSAL },
    runSchedulerJob: { '200': SCHEDULER_ACTION, '202': SCHEDULER_ACTION },
    stepDownScheduler: { '200': SCHEDULER_ACTION, '202': SCHEDULER_ACTION },
    getWorkerPools: { '200': WORKER_POOLS, '404': NO_NODE },
    //@@MORE-OPERATIONS@@
  } as Record<string, Record<string, unknown>>
};
