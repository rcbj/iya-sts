// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_directory.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): Kerberos, LDAP, Directory, TLS, WS-Trust,
// WS-Federation, SCIM, SAML 2.0, SAML 1.1, SAML assertions, Custom SAML
// attributes, Custom claims, UserInfo claims.
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
//
// **AN ANSWER THAT FAILS ITS MODEL IS NOT SENT**, so each model below is the
// union of every member any branch of its builder can send, read from the
// builder; recorded traffic only ever checked it. Three things this family
// has that are easy to get wrong:
//
//   * **A DIRECTORY ENTRY'S ATTRIBUTE NAMES ARE DATA** (`mapOf`, `ATTRIBUTES`),
//     because this directory is schemaless on purpose: an `ldapadd` can write
//     any name. The record a registry derives from an entry is the opposite,
//     its members are this service's own, and it is `closed`.
//   * **A GET MIRRORING A PROTOCOLS PAGE GETS `protocolEndpoints` ADDED**, by
//     `ResponseModels.apply()`, and only to a model with top-level
//     `properties`. So those models are one closed object and never a `oneOf`,
//     and a read with two shapes (the directory pages' "no directory is
//     loaded", a list and its drill-down) is the same object with both sets of
//     members optional.
//   * **`FEDERATION_RELATIONSHIP` REPEATS `federation/federation.js`'s SCHEMA
//     BY NAME**: `ldapFederationsView()` copies a record whose members are that
//     table's attributes, so a new attribute there owes a line here or
//     `GET /admin-api/ldap/federations` stops answering once a relationship
//     exists.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

const STR: Json = Kit.str();
const INT: Json = Kit.int();
const NUM: Json = Kit.num();
const BOOL: Json = Kit.bool();
const STR_LIST: Json = Kit.listOf(STR);
const INT_LIST: Json = Kit.listOf(INT);
const NULL_STR: Json = Kit.nullable(STR);
const NULL_INT: Json = Kit.nullable(INT);
const NULL_BOOL: Json = Kit.nullable(BOOL);
const COUNTS: Json = Kit.mapOf(NUM, 'A count per name.');

// A moment some module keeps in milliseconds and another as text; null until
// it happened.
const MOMENT: Json = Kit.oneOf(NUM, STR, { type: 'null' });

// `protocolEndpoints` on a GET mirroring a Protocols page. `apply()` adds it to
// a model whose page has endpoints; it is written out here as well on the ones
// recorded carrying it, so that the model read alone is the whole answer.
const ENDPOINT_ROWS: Json = Kit.listOf(Kit.closed({
  name: STR,
  methods: Kit.oneOrMany(STR),
  url: STR,
  route: STR,
  transport: STR,
  registered: BOOL
}));

// One attribute of a directory entry, or one recorded field of a registry:
// its name is data. A value is a list as the entry holds it, or one string
// where a registry keeps a single-valued field, and `withoutSecrets()` hands
// a null it was given straight back.
const ATTRIBUTES: Json = Kit.mapOf(Kit.nullable(Kit.oneOrMany(STR)),
  'Attribute names, which are data in a schemaless directory, and values.');

// `AdminViews.pagingJson()`.
const PAGING: Json = Kit.closed({
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  total: INT, param: NULL_STR, noun: NULL_STR
});

// What `directoryPageJson()` answers in a process with no directory loaded.
const NO_DIRECTORY: Json = {
  directory: BOOL,
  message: STR
};

// The `SCHEMA` every directory container publishes. One model for all of them:
// the columns differ per module (applications.js has the most, roles.js two)
// and all of them are optional, and `editable` is a boolean on some rows and
// 'single' or 'multi' on others.
const SCHEMA_TABLE: Json = Kit.closed({
  objectClasses: Kit.listOf(Kit.closed({
    name: STR, what: STR, where: STR, standard: BOOL
  })),
  attributes: Kit.listOf(Kit.closed({
    name: STR, what: STR, kind: STR, from: STR, role: STR,
    standard: BOOL, sensitive: BOOL, secret: BOOL,
    identifier: BOOL, identifierName: STR,
    editable: Kit.oneOf(BOOL, STR),
    enum: STR_LIST,
    families: STR_LIST, familyWhy: STR,
    overrides: STR, strictOverride: BOOL
  }))
});

// `pagedRows()` at the top of a directory page.
const PAGE_FIGURES: Json = {
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  paging: PAGING
};

const Q_FILTER: Json = Kit.closed({ q: NULL_STR });

// `entryObject()`: a directory entry as the registries read it.
const ENTRY_OBJECT: Json = {
  dn: STR,
  origin: NULL_STR,
  createdAt: NULL_STR,
  modifiedAt: NULL_STR,
  operational: STR_LIST,
  attributes: ATTRIBUTES
};

const NAMED_ENTRY: Json = Kit.closed(Object.assign({ name: STR },
                                                   ENTRY_OBJECT));

// The bounded look inside a windowed process (#616); null otherwise.
const WINDOWED_SEARCH: Json = Kit.nullable(Kit.closed({
  complete: BOOL, scanned: INT, scanLimit: INT
}));

// `common/applications.js`'s `view()`, masked by `withoutSecrets()`.
const APPLICATION_VIEW: Json = Kit.closed({
  identifier: STR,
  dnLabel: NULL_STR,
  dn: NULL_STR,
  name: NULL_STR,
  kinds: STR_LIST,
  protocols: STR_LIST,
  allowedProtocols: STR_LIST,
  recordedProtocols: STR_LIST,
  declaredKinds: STR_LIST,
  registeredBy: STR,
  returnAddressesObserved: Kit.listOf(Kit.closed({
    attribute: STR, value: STR, held: BOOL, trusted: BOOL
  })),
  registered: BOOL,
  firstSeen: STR,
  lastSeen: STR,
  authentications: NUM,
  sessions: NUM,
  users: NUM,
  description: NULL_STR,
  origin: NULL_STR,
  createdAt: NULL_STR,
  modifiedAt: NULL_STR,
  operational: STR_LIST,
  attributes: ATTRIBUTES,
  fields: ATTRIBUTES
});

// `recordFromAttributes()` gives every row of federation.js's SCHEMA a member:
// the single-valued as a string, the multi-valued as a list.
const FEDERATION_SINGLE: string[] = [
  'fedId', 'cn', 'fedName', 'fedRole', 'fedProtocol', 'fedProvider',
  'fedPeer', 'fedLocalEntityId', 'fedEnabled', 'fedSsoUrl', 'fedTokenUrl',
  'fedUserinfoUrl', 'fedJwksUri', 'fedEmailsUrl', 'fedJwks',
  'fedTrustAnchor', 'fedSigningCertificate', 'fedClientId',
  'fedClientSecret', 'fedResponseMode', 'fedTeamId', 'fedKeyId',
  'fedClientSigningKey', 'fedTokenAuth', 'fedScope', 'fedResponseType',
  'fedIdTokenSignedResponseAlg', 'fedUserinfoSignedResponseAlg',
  'fedRefreshTokens', 'fedRefreshEverySeconds', 'fedRegister',
  'fedRegisteredIssuer', 'fedRequestObject', 'fedRequestObjectSigningAlg',
  'fedWebFinger', 'fedDiscovery', 'fedInitiateLogin', 'fedBinding',
  'fedSignRequest', 'fedUsernameSource', 'fedSubjectClaim',
  'fedAutocreateUsers', 'fedUpdateUserAttributes', 'fedProvisionGroups',
  'fedProvisionCap', 'fedProvisionIdleMinutes', 'fedSubjectPolicy',
  'fedSubjectPattern', 'fedMayAssertAdministrators', 'fedSignalEmailMatch',
  'fedSignalsEnabled', 'fedSignalsIssuer', 'fedSignalsDelivery',
  'fedSignalsTokenUrl', 'fedSignalsClientId', 'fedSignalsClientSecret',
  'fedSignalsScope', 'fedSignalsBearer', 'fedSloUrl', 'fedSloBinding',
  'fedEndSessionUrl', 'fedAcceptSignout', 'fedRequireSignedLogout',
  'fedEncryptionKeyType', 'fedKeyManagementAlgorithm',
  'fedContentEncryptionAlgorithm', 'fedAllowUnencrypted',
  'fedAllowUnsolicited', 'fedApplication', 'fedAuthnMechanism',
  'fedAuthnRelationship', 'fedFirstSeen', 'fedLastSeen',
  'fedAuthentications', 'fedUsers', 'fedLastUser', 'fedLastError',
  'fedLastErrorAt'
];

const FEDERATION_MULTI: string[] = [
  'description', 'fedAllowedTenants', 'fedAuthorizeParams',
  'fedAttributeMap', 'fedSubjectGroup', 'fedSubjectDomain',
  'fedHomeRealmDomain', 'fedSignalsEvents', 'fedEncryptionKey',
  'fedRelease', 'fedApplicationUse'
];

const FEDERATION_RELATIONSHIP: Json = (function (): Json {
  const members: Json = {
    dn: STR, createdAt: STR, modifiedAt: STR,
    ready: BOOL, missing: STR_LIST,
    entryAttributes: ATTRIBUTES,
    roleShort: STR, protocolLabel: STR, enabled: BOOL
  };
  FEDERATION_SINGLE.forEach(function (name) {
    members[name] = STR;
  });
  FEDERATION_MULTI.forEach(function (name) {
    members[name] = STR_LIST;
  });
  return Kit.closed(members);
}());

const SPIFFE_SELECTOR: Json = Kit.closed({ type: STR, value: STR });

// `SpiffeRegistry.recordFromEntry()`, with `selectorTexts` from the view.
const SPIFFE_ENTRY: Json = Kit.closed({
  id: STR, dn: STR, spiffeId: STR, parentId: STR,
  selectors: Kit.listOf(SPIFFE_SELECTOR), selectorTexts: STR_LIST,
  x509SvidTtl: NUM, jwtSvidTtl: NUM,
  dnsNames: STR_LIST, federatesWith: STR_LIST, hint: STR,
  admin: BOOL, downstream: BOOL, storeSvid: BOOL,
  expiresAt: NUM, expired: BOOL, revisionNumber: NUM,
  origin: STR, svidsIssued: NUM, lastSvidAt: STR,
  createdAt: STR, modifiedAt: STR,
  attributes: ATTRIBUTES
});

// `SpiffeRegistry.agentFromEntry()`.
const SPIFFE_AGENT: Json = Kit.closed({
  id: STR, dn: STR, attestationType: STR,
  selectors: Kit.listOf(SPIFFE_SELECTOR),
  banned: BOOL, canReattest: BOOL, svidHash: STR, expiresAt: NUM,
  firstSeen: STR, lastSeen: STR, attestations: NUM,
  attributes: ATTRIBUTES
});

// ---------------------------------------------------------------------------
// `persistence.status()`, whole, on `GET /ldap/service`. Its nested reports are
// each module's own: `persistence_minted.js`, `used_assertions.js`,
// `persistence_replication.js`, `persistence_tiered.js`, `secrets.js`.
// ---------------------------------------------------------------------------
const SECRET_WHERE: Json = Kit.closed({
  from: STR, shared: BOOL, region: STR, vault: STR, endpoint: STR,
  field: STR, wraps: STR, authenticates: STR
});

const DATABASE_PASSWORD_SECRET: Json = Kit.closed({
  secret: STR, configured: BOOL, provider: STR, label: STR, known: BOOL,
  where: SECRET_WHERE, shared: BOOL, field: STR,
  providers: Kit.listOf(Kit.closed({ id: STR, label: STR }))
});

const DATABASE_DESCRIPTION: Json = Kit.nullable(Kit.closed({
  host: NULL_STR, port: NULL_STR, database: NULL_STR, user: NULL_STR,
  passwordFrom: STR, passwordProvider: STR,
  passwordSecret: DATABASE_PASSWORD_SECRET,
  sslmode: STR, encrypted: BOOL, verifyCertificate: BOOL, caFile: NULL_STR,
  tls: STR, note: STR
}));

const LAG_SAMPLE: Json = Kit.nullable(Kit.closed({
  maxMs: NUM, p99Ms: NUM, meanMs: NUM, at: STR
}));

const REPLICATION_STATUS: Json = Kit.closed({
  coordinating: BOOL, supported: BOOL, startedAt: MOMENT,
  appliedSeq: NUM, highestSeq: NUM, holes: NUM, holeRanges: NUM,
  holesAbandoned: NUM, pollIntervalMs: NUM, pulls: NUM, nudges: NUM,
  failures: NUM, rowsApplied: NUM, byKind: COUNTS,
  lastPullAt: MOMENT, lastError: NULL_STR,
  otherProcesses: NUM, originsDropped: NUM,
  retention: Kit.closed({
    retentionS: NUM, readerTtlS: NUM, reportedAt: NULL_STR,
    reportError: NULL_STR, declaredGoneAt: MOMENT, fanInGraceS: NUM,
    trimming: BOOL,
    lastTrim: Kit.nullable(Kit.closed({
      at: STR, error: NULL_STR, trimmed: NUM, bound: Kit.nullable(NUM),
      readers: NUM, readersGone: NUM
    }))
  }),
  note: STR
});

const PERSISTENCE_STATUS: Json = Kit.closed({
  mode: STR, configuredMode: STR, enabled: BOOL, healthy: NULL_BOOL,
  dataDir: NULL_STR, database: DATABASE_DESCRIPTION, engine: NULL_STR,
  writeDelayMs: NUM, persistsDirectory: BOOL, persistsRealms: BOOL,
  persistsAppconfig: BOOL, pending: BOOL, writes: NUM, failures: NUM,
  lastWriteAt: MOMENT, lastError: NULL_STR, restoredAt: MOMENT,
  restored: Kit.closed({ realms: NUM, entries: NUM, overrides: NUM }),
  entriesTracked: NUM, realmsTracked: NUM, coordinates: BOOL,
  minted: Kit.closed({
    persisting: BOOL, supported: BOOL, unsupportedReason: STR, sealed: BOOL,
    mode: STR, setting: BOOL, retentionMs: NUM, stores: NUM, shared: NUM,
    handles: Kit.listOf(Kit.closed({ handle: STR, shape: STR, scope: STR })),
    pending: NUM, writes: NUM, failures: NUM, rowsWritten: NUM,
    rowsDeleted: NUM, lastWriteAt: MOMENT, lastError: NULL_STR,
    restoredAt: MOMENT, restored: NUM, droppedUnreadable: NUM,
    droppedUnknown: NUM, droppedPoison: NUM,
    poisonDrops: Kit.listOf(Kit.closed({
      at: STR, code: STR, message: STR, rows: NUM,
      handles: Kit.listOf(STR), realms: Kit.listOf(STR)
    }))
  }),
  usedAssertions: Kit.closed({
    store: NULL_STR, kind: NULL_STR, persistent: BOOL,
    atomicAcrossProcesses: BOOL, why: NULL_STR, cap: NUM,
    live: Kit.nullable(NUM), liveIsCurrent: BOOL
  }),
  replication: REPLICATION_STATUS,
  cells: Kit.nullable(Kit.closed({
    cell: NULL_STR, jurisdiction: NULL_STR,
    globalReplication: Kit.nullable(REPLICATION_STATUS),
    routing: Kit.closed({
      indexed: NUM, conflicts: NUM, lastConflict: NULL_STR,
      projectionWrites: NUM
    })
  })),
  origin: Kit.nullable(Kit.closed({
    origin: NULL_STR, adopted: BOOL, why: STR
  })),
  answersAfterCommit: BOOL, commitBacklog: BOOL, retryArmed: BOOL,
  liveness: Kit.nullable(Kit.closed({
    open: BOOL, queries: NUM, connects: NUM, drops: NUM, viaPool: NUM
  })),
  eventLoop: Kit.nullable(Kit.closed({
    lastReport: LAG_SAMPLE, sinceReport: LAG_SAMPLE, warnAboveMs: NUM
  })),
  note: STR
});

// The nine `/admin-api/ldap/*` pages, `ldap/ldap_server.js`'s views.
const DIRECTORY_ENTRY_LIST: Json = Kit.closed(Object.assign({
  baseDn: STR, count: INT, matched: INT, shown: INT,
  filter: Kit.closed({ q: NULL_STR, origin: NULL_STR }),
  origins: STR_LIST, originCounts: COUNTS, order: STR,
  search: WINDOWED_SEARCH,
  entries: Kit.listOf(Kit.closed({
    dn: STR, origin: STR, attributes: ATTRIBUTES
  }))
}, PAGE_FIGURES, NO_DIRECTORY));

const DIRECTORY_APPLICATION_LIST: Json = Kit.closed(Object.assign({
  baseDn: STR, container: STR, count: INT, matched: INT, shown: INT, max: INT,
  filter: Q_FILTER, sourceOfTruth: STR,
  kinds: Kit.listOf(Kit.closed({ kind: STR, label: STR, what: STR })),
  schema: SCHEMA_TABLE,
  applications: Kit.listOf(APPLICATION_VIEW)
}, PAGE_FIGURES, NO_DIRECTORY));

const DIRECTORY_FEDERATION_LIST: Json = Kit.closed(Object.assign({
  baseDn: STR, container: STR, count: INT, matched: INT, shown: INT, max: INT,
  filter: Q_FILTER, sourceOfTruth: STR,
  roles: Kit.listOf(Kit.closed({
    role: STR, label: STR, short: STR, what: STR
  })),
  protocols: Kit.listOf(Kit.closed({
    protocol: STR, label: STR, family: STR, what: STR, needs: STR_LIST,
    spec: STR, signalsOnly: BOOL
  })),
  schema: SCHEMA_TABLE,
  relationships: Kit.listOf(FEDERATION_RELATIONSHIP),
  enabledCount: INT
}, PAGE_FIGURES, NO_DIRECTORY));

const DIRECTORY_SPIFFE: Json = Kit.closed(Object.assign({
  baseDn: STR, container: STR, entriesContainer: STR, agentsContainer: STR,
  entries: INT, agents: INT, maxEntries: INT, maxAgents: INT,
  sourceOfTruth: STR, editable: STR_LIST, schema: SCHEMA_TABLE,
  filter: Kit.closed({ entryq: NULL_STR, agentq: NULL_STR }),
  entriesPaging: PAGING, agentsPaging: PAGING,
  registrationEntries: Kit.listOf(SPIFFE_ENTRY),
  attestedAgents: Kit.listOf(SPIFFE_AGENT)
}, NO_DIRECTORY));

const DIRECTORY_ROLE_LIST: Json = Kit.closed(Object.assign({
  baseDn: STR, container: STR, count: INT, matched: INT, shown: INT, max: INT,
  filter: Q_FILTER, sourceOfTruth: STR, builtIn: STR_LIST,
  schema: SCHEMA_TABLE, roles: Kit.listOf(NAMED_ENTRY),
  builtInCatalogue: Kit.listOf(Kit.closed({ name: STR, what: STR }))
}, PAGE_FIGURES, NO_DIRECTORY));

const DIRECTORY_POLICY_LIST: Json = Kit.closed(Object.assign({
  baseDn: STR, container: STR, count: INT, matched: INT, shown: INT, max: INT,
  ownCount: INT, applicationCount: INT, applicationMax: INT,
  filter: Q_FILTER, sourceOfTruth: STR, schema: SCHEMA_TABLE,
  policies: Kit.listOf(NAMED_ENTRY), enabledCount: INT
}, PAGE_FIGURES, NO_DIRECTORY));

const DIRECTORY_PEP_LIST: Json = Kit.closed(Object.assign({
  baseDn: STR, container: STR, count: INT, matched: INT, shown: INT, max: INT,
  filter: Q_FILTER, sourceOfTruth: STR, schema: SCHEMA_TABLE,
  peps: Kit.listOf(NAMED_ENTRY), enabledCount: INT
}, PAGE_FIGURES, NO_DIRECTORY));

const DIRECTORY_DEVICE_LIST: Json = Kit.closed(Object.assign({
  baseDn: STR, container: STR, count: INT, matched: INT, shown: INT,
  filter: Q_FILTER, sourceOfTruth: STR, schema: SCHEMA_TABLE,
  entries: Kit.listOf(Kit.closed({ dn: STR, attributes: ATTRIBUTES })),
  search: WINDOWED_SEARCH, pageCap: INT
}, PAGE_FIGURES, NO_DIRECTORY));

const DIRECTORY_SERVICE: Json = Kit.closed(Object.assign({
  url: STR, port: NULL_INT, listening: BOOL, listenError: NULL_STR,
  baseDn: STR, usersDn: STR, groupsDn: STR, namingContexts: STR_LIST,
  searchScope: STR, ldapVersion: INT, bindPolicy: STR, refusedPassword: STR,
  schema: STR, referentialIntegrity: BOOL,
  persistence: PERSISTENCE_STATUS,
  tls: Kit.closed({
    ldaps: BOOL, port: NULL_INT, url: STR, listening: BOOL, error: NULL_STR,
    startTls: BOOL, clientCertificateMode: STR,
    saslExternal: Kit.closed({
      available: BOOL, mechanisms: STR_LIST,
      outsideCertificateAuthorities: BOOL, rule: STR
    }),
    clientCertificates: STR,
    certificate: Kit.closed({
      subject: NULL_STR, names: Kit.nullable(STR_LIST),
      fingerprint256: NULL_STR, notAfter: NULL_STR, source: STR
    })
  }),
  autoCreateUsers: BOOL, autoCreateRule: STR, authenticationFacts: STR,
  enforcedRules: STR_LIST,
  limits: Kit.closed({
    maxEntries: NUM, maxSearchResults: NUM, currentEntries: NUM,
    currentEntriesEverywhere: NUM
  }),
  operations: STR_LIST, specifications: STR_LIST, implementation: STR,
  ldapPort: NULL_INT, ldapsPort: NULL_INT, certificateProvenance: NULL_STR
}, NO_DIRECTORY));

// ---------------------------------------------------------------------------
// A PROTOCOL SETTINGS PAGE: `AdminConsole.protocolSettingsJson()`.
// ---------------------------------------------------------------------------
const SETTING_VALUE: Json = Kit.oneOf(BOOL, NUM, STR, STR_LIST,
                                      { type: 'null' });

// `config.js`'s `describe()`.
const SETTING_ROW: Json = Kit.closed({
  key: STR, group: STR, label: STR, description: STR, type: STR,
  enumValues: STR_LIST, csvValues: STR_LIST, ordered: BOOL,
  csvValueNotes: Kit.mapOf(STR, 'The sentence beside each value.'),
  selectAll: Kit.mapOf(Kit.listOf(Kit.closed({
    setting: STR, values: STR_LIST, on: BOOL, canBeOn: BOOL
  })), 'The rules by kind: onlyWhileOn and aloneWhileOn.'),
  min: NUM, max: NUM, step: NUM,
  value: SETTING_VALUE, text: NULL_STR, source: STR,
  editable: BOOL, restartReason: STR, editRefusal: STR,
  env: NULL_STR, legacyEnv: NULL_STR, appconfigPath: STR,
  default: SETTING_VALUE, masked: BOOL, realmSettable: BOOL, overridden: BOOL
});

// `AdminConsole.configSettingsJson()`.
const SETTINGS_BLOCK: Json = Kit.closed({
  page: STR,
  groups: Kit.listOf(Kit.closed({
    group: STR, settings: Kit.listOf(SETTING_ROW)
  })),
  settingCount: INT, editableCount: INT, overridden: STR_LIST, setWith: STR,
  context: Kit.closed({
    configFile: NULL_STR, defaultsFile: NULL_STR, persistsAppconfig: BOOL,
    persistsRealms: BOOL, persistenceMode: STR, inRealm: BOOL,
    realmId: NULL_STR
  }),
  sharedWith: Kit.mapOf(Kit.listOf(Kit.closed({ path: STR, label: STR })),
                        'The other pages, by settings group.')
});

const SETTINGS_PAGE_MEMBERS: Json = {
  page: STR, title: STR, what: STR, notes: STR_LIST,
  links: Kit.listOf(Kit.closed({ href: STR, what: STR })),
  settings: SETTINGS_BLOCK, leadHtml: STR, alsoHtml: STR_LIST,
  protocolEndpoints: ENDPOINT_ROWS
};

const SETTINGS_PAGE: Json = Kit.closed(SETTINGS_PAGE_MEMBERS);

// ---------------------------------------------------------------------------
// KERBEROS.
// ---------------------------------------------------------------------------
const ETYPE: Json = Kit.closed({ etype: INT, name: NULL_STR });

const RETAINED_KEY: Json = Kit.closed({
  kvno: NUM, etypes: Kit.listOf(ETYPE), retiredAt: STR, expiresAt: STR
});

// `principals.kerberosRealmOf()`.
const KERBEROS_REALM: Json = Kit.closed({
  trustRealm: NULL_STR, kerberosRealm: NULL_STR, enabled: BOOL, active: BOOL,
  reason: NULL_STR, served: STR_LIST
});

// `krbtgtState()`, and `rotationView()` over it.
const KRBTGT_VIEW: Json = Kit.nullable(Kit.closed({
  principal: STR, source: STR, kvno: Kit.nullable(NUM),
  etypes: Kit.listOf(ETYPE), sealed: BOOL, createdAt: STR, keyCreatedAt: STR,
  rotatedAt: STR, invalidatedAt: STR, retained: Kit.listOf(RETAINED_KEY),
  windowOpenUntil: STR, retainedTtlSeconds: NUM, why: STR,
  trustRealm: STR, scheduled: BOOL, offReason: STR, intervalDays: NUM,
  lastRotatedAt: NULL_STR, nextDueAt: NULL_STR,
  jobs: Kit.closed({ scheduled: STR, byHand: STR }), confirmWord: STR
}));

// The Kerberos page's `status`: `kerberosPreauthStatusBlock()`, which is
// `Krb5Fast.policy()` (or its stand-in with `note`) plus the krbtgt and
// `Krb5Pkinit.policy()`.
const KERBEROS_STATUS: Json = Kit.closed({
  passwordAloneRefused: BOOL, fast: BOOL, armorTypes: STR_LIST,
  fastFactors: STR_LIST, passwordAloneForSecondFactorAccounts: STR,
  refusal: NULL_STR, otpIndicator: STR, notImplemented: STR_LIST, note: STR,
  krbtgt: KRBTGT_VIEW,
  pkinit: Kit.nullable(Kit.closed({
    pkinit: BOOL, anonymousPkinit: BOOL, anonymousTickets: STR,
    freshnessRequired: BOOL, legacyKdf: BOOL, kdfs: STR_LIST,
    keyAgreement: STR_LIST, rsaKeyTransport: STR, cmsDigests: STR_LIST,
    clientCertificates: STR, indicators: STR_LIST, kdcKeyAlgorithm: STR,
    kdcCertificate: Kit.nullable(Kit.closed({
      serialHex: STR, keyAlg: STR, notAfter: STR
    })),
    postQuantum: STR
  }))
});

const KERBEROS_PRINCIPALS: Json = Kit.closed({
  protocolEndpoints: ENDPOINT_ROWS,
  installed: BOOL, realm: NULL_STR, trustRealm: NULL_STR,
  kerberos: KERBEROS_REALM, productKdc: BOOL, personKeys: BOOL,
  enctypes: INT_LIST, startingKvno: NUM,
  retention: Kit.closed({ versions: NUM, ttlSeconds: NUM, ttlSetting: NUM }),
  acceptor: Kit.closed({ spn: NULL_STR, available: BOOL, storedKey: BOOL }),
  accountPolicy: Kit.closed({
    anyUsernameAuthenticates: BOOL, neverCreated: STR_LIST,
    serviceHosts: STR_LIST
  }),
  krbtgt: KRBTGT_VIEW,
  actions: STR_LIST,
  people: Kit.listOf(Kit.closed({
    retained: Kit.listOf(RETAINED_KEY), username: STR, principal: STR,
    kvno: Kit.nullable(NUM), etypes: Kit.listOf(ETYPE), derivedAt: STR,
    derivedOn: STR, sealed: BOOL, current: BOOL
  })),
  peopleTotal: INT, peoplePaging: PAGING,
  services: Kit.listOf(Kit.closed({
    retained: Kit.listOf(RETAINED_KEY), principal: STR, spn: STR,
    kvno: Kit.nullable(NUM), etypes: Kit.listOf(ETYPE), createdAt: STR,
    rotatedAt: STR, sealed: BOOL, held: BOOL
  })),
  servicesTotal: INT, servicesPaging: PAGING,
  fixtureAccounts: BOOL, realmsServed: STR_LIST,
  database: Kit.listOf(Kit.closed({
    principal: STR, nameType: NUM, salt: NULL_STR,
    etypes: Kit.listOf(ETYPE), requiresPreAuth: BOOL, revoked: BOOL,
    passwordExpired: BOOL, okAsDelegate: BOOL, kvno: NUM, autoCreated: BOOL,
    directoryKeys: BOOL, description: STR
  })),
  databaseTotal: INT, databasePaging: PAGING,
  notes: Kit.closed({
    keys: STR, mode: STR, realm: STR, window: STR, previous: STR
  })
});

// `mintServiceKeys()`, what `create-service` and `rotate-service` hand over.
const KERBEROS_MINTED: Json = {
  act: STR, spn: STR, principal: STR, kvno: NUM, etypes: INT_LIST, sealed: BOOL,
  retained: Kit.listOf(RETAINED_KEY), keytabKvnos: INT_LIST,
  keytabFilename: STR, keytab: STR, trustRealm: NULL_STR
};

// `dropPrevious()`, what the two `drop-previous-*` actions answer.
const KERBEROS_DROPPED: Json = {
  dropped: INT, kvnos: INT_LIST, principal: STR, currentKvno: NUM,
  username: STR, spn: STR, trustRealm: NULL_STR
};

// `resetPersonKeytab()`: `personKeytab()`'s answer and what the reset adds.
const KERBEROS_PERSON_KEYTAB: Json = {
  username: STR, principal: STR, realm: NULL_STR, trustRealm: NULL_STR,
  kvno: NUM, etypes: INT_LIST, keytabKvnos: INT_LIST, source: STR,
  keytabFilename: STR, keytab: STR,
  passwordSet: BOOL, generated: BOOL,
  signedOut: Kit.closed({ ended: BOOL, terminated: NUM, message: NULL_STR }),
  // A refused password, `credentials.preparePassword()`'s words for why.
  reason: STR, problems: STR_LIST
};

const NAMED_ENCTYPE: Json = Kit.closed({ id: INT, name: NULL_STR });

const TRUST_KEY: Json = {
  held: BOOL, kvno: NUM, source: STR, setAt: NULL_STR, principal: STR
};

// `Krb5Trusts.viewOf()`, and `decorate()`'s three on the page's rows.
const KERBEROS_TRUST: Json = Kit.closed({
  partnerRealm: STR, netbiosName: NULL_STR, partnerSid: STR, type: STR,
  partnerTrustRealm: STR, direction: STR, trustDirection: INT,
  trustAttributes: INT, attributes: STR_LIST, suffixes: STR_LIST,
  enctypes: INT_LIST,
  forestTrustInfo: Kit.nullable(Kit.closed({
    domains: Kit.listOf(Kit.closed({
      sid: STR, dnsName: STR, netbiosName: STR, sidEnabled: BOOL
    })),
    topLevelNames: Kit.listOf(Kit.closed({ name: STR, enabled: BOOL }))
  })),
  claimsTransformation: STR, boundary: STR,
  incoming: Kit.closed(Object.assign({
    previous: Kit.nullable(Kit.closed({
      kvno: NUM, source: STR, retiredAt: NULL_STR, acceptedUntil: STR
    }))
  }, TRUST_KEY)),
  outgoing: Kit.closed(TRUST_KEY),
  enabled: BOOL, createdAt: NULL_STR, updatedAt: NULL_STR,
  enctypeNames: Kit.listOf(NAMED_ENCTYPE), lastKeyChangeAt: NULL_STR,
  health: Kit.listOf(Kit.closed({
    kind: STR, level: STR, text: STR,
    params: Kit.mapOf(STR, 'What the sentence is filled from.')
  }))
});

const NULL_TRUST: Json = Kit.nullable(KERBEROS_TRUST);

const KERBEROS_TRUSTS: Json = Kit.closed({
  protocolEndpoints: ENDPOINT_ROWS,
  realm: NULL_STR, trustRealm: NULL_STR, kerberos: KERBEROS_REALM,
  trusts: Kit.listOf(KERBEROS_TRUST), total: INT, trustsPaging: PAGING,
  trust: NULL_TRUST, unknownTrust: STR, product: BOOL,
  form: Kit.closed({
    attributes: STR_LIST, defaultAttributes: STR_LIST,
    contradictions: Kit.listOf(Kit.closed({ a: STR, b: STR, why: STR })),
    requires: Kit.listOf(Kit.closed({ attribute: STR, needs: STR, why: STR })),
    types: STR_LIST, directions: STR_LIST, keySources: STR_LIST,
    enctypes: Kit.listOf(NAMED_ENCTYPE), defaultEnctypes: INT_LIST,
    claimsTransformations: STR_LIST, minPasswordLength: INT,
    trustRealms: Kit.listOf(Kit.closed({ id: STR, kerberosRealm: STR }))
  }),
  settings: Kit.closed({
    crossRealmClassicDelegation: BOOL, requireSidFilteringInProduct: BOOL,
    maxReferralHops: NUM, trustKeyGraceSeconds: NUM, graceSeconds: NUM
  }),
  actions: STR_LIST
});

// The keys a generated trust key shows once, base64 by enctype number; each
// side is absent where its key was not generated.
const SHOWN_KEYS: Json = Kit.mapOf(STR, 'Base64 keys, by enctype number.');
const SHOWN_SIDES: Json = Kit.nullable(Kit.closed({
  incoming: SHOWN_KEYS, outgoing: SHOWN_KEYS
}));

// `kerberosTrustsAction()`: `{ ok, trustRealm, action }` over the library's.
const KERBEROS_TRUST_ACTION: Json = Kit.action({
  trustRealm: NULL_STR, action: STR, trust: NULL_TRUST, shown: SHOWN_SIDES,
  here: NULL_TRUST, there: NULL_TRUST, created: BOOL, otherRealm: STR,
  rotated: STR_LIST
});

// ---------------------------------------------------------------------------
// TLS: the truststore and the connection.
// ---------------------------------------------------------------------------
const TRUST_ANCHOR: Json = Kit.closed({
  subject: NULL_STR, issuer: NULL_STR, serial: NULL_STR, notBefore: NULL_STR,
  notAfter: NULL_STR, fingerprint256: STR, ca: BOOL, readable: BOOL,
  source: STR, persisted: BOOL, addedAt: STR, pem: STR, unadmittable: STR
});

const TRUSTSTORE: Json = Kit.closed({
  protocolEndpoints: ENDPOINT_ROWS,
  installed: BOOL, anchors: Kit.listOf(TRUST_ANCHOR), total: INT, fromFile: INT,
  atRuntime: INT, max: INT, anchorsFile: STR,
  loadedFromFile: Kit.nullable(NUM), persisted: BOOL, actions: STR_LIST,
  doors: Kit.closed({ console: STR, api: STR }),
  notes: Kit.closed({
    persisted: STR, scope: STR, effect: STR, revocation: STR
  }),
  note: STR, page: INT, pages: INT, perPage: INT, paging: PAGING
});

const ANCHOR_BRIEF: Json = Kit.closed({
  subject: NULL_STR, fingerprint256: NULL_STR, source: NULL_STR
});

const SEEN_HEADER: Json = Kit.closed({
  header: STR, present: BOOL, value: NULL_STR, what: STR
});

// `describeCertificate()`.
const PEER_CERTIFICATE: Json = Kit.nullable(Kit.closed({
  depth: INT, subject: NULL_STR, issuer: NULL_STR, serialNumber: NULL_STR,
  validFrom: NULL_STR, validTo: NULL_STR, subjectAltName: NULL_STR,
  extendedKeyUsage: Kit.nullable(STR_LIST), keySize: Kit.nullable(NUM),
  curve: NULL_STR, fingerprint256: NULL_STR, pem: NULL_STR
}));

// `common/revocation_status.js`'s `summarise()` and `decide()`. A link is one
// certificate of the chain, with the route that answered about it copied on by
// `applyRouteResult()`.
const REVOCATION_LINK: Json = Kit.closed({
  depth: INT, subject: NULL_STR, serialHex: NULL_STR, issuer: NULL_STR,
  status: STR, source: STR, why: STR,
  authority: Kit.closed({ scope: NULL_STR, ca: NULL_STR, label: STR }),
  reason: NULL_STR, reasonCode: Kit.nullable(NUM), revokedAt: NULL_STR,
  unknownKind: STR, refusable: BOOL, invalid: BOOL, noRevAvail: BOOL,
  notDialled: STR_LIST, distributionPoints: STR_LIST, ocspOrder: STR,
  answeredBy: STR, crlUrl: STR, crlNextUpdate: NULL_STR, crlFromCache: BOOL,
  deltaUrl: STR, indirect: BOOL, ocspUrl: STR, ocspFromCache: BOOL,
  ocspResponder: NULL_STR, ocspNonce: Kit.oneOf(BOOL, STR, { type: 'null' }),
  ocspNextUpdate: NULL_STR, ocspResponderStatus: STR
});

const REVOCATION_VERDICT: Json = Kit.nullable(Kit.closed({
  status: STR, checked: BOOL, notDialled: STR_LIST, noRevAvail: STR_LIST,
  revoked: Kit.nullable(Kit.closed({
    depth: INT, subject: NULL_STR, serialHex: NULL_STR, reason: NULL_STR,
    reasonCode: Kit.nullable(NUM), revokedAt: NULL_STR, source: STR,
    answeredBy: STR
  })),
  unknown: Kit.listOf(Kit.closed({
    depth: INT, subject: NULL_STR, kind: STR, refusable: BOOL, why: STR,
    invalid: BOOL, notDialled: STR_LIST
  })),
  links: Kit.listOf(REVOCATION_LINK),
  policy: STR, policyConfigured: STR, refused: BOOL, why: STR
}));

// `tls_server.js`'s `connectionView()`.
const TLS_CONNECTION: Json = Kit.closed({
  generatedAt: STR,
  connection: Kit.closed({
    https: BOOL, encrypted: BOOL, protocol: NULL_STR, cipher: NULL_STR,
    peerAddress: NULL_STR, clientAddress: NULL_STR
  }),
  clientCertificate: Kit.closed({
    presented: BOOL, verified: BOOL, authorizationError: NULL_STR,
    certificate: PEER_CERTIFICATE, thumbprint: NULL_STR,
    identity: Kit.nullable(Kit.closed({
      issuedHere: BOOL, accepted: BOOL, kind: NULL_STR, username: NULL_STR,
      realm: NULL_STR, why: NULL_STR
    })),
    revocation: REVOCATION_VERDICT, signIn: STR, note: STR
  }),
  forwarded: Kit.closed({
    trustProxy: BOOL, trustedProxies: STR_LIST, rangesConfigured: NUM,
    rangesUsable: NUM, peerIsTrustedProxy: BOOL, believed: BOOL,
    socket: Kit.closed({ scheme: STR, host: STR, encrypted: BOOL }),
    effectiveBaseUrl: STR, whatItMeans: STR,
    forwarding: Kit.listOf(SEEN_HEADER),
    clientCertificateHeaders: Kit.closed({
      readByThisService: BOOL, seen: STR_LIST, note: STR,
      headers: Kit.listOf(SEEN_HEADER)
    }),
    proxyMustSanitize: STR
  })
});

// ---------------------------------------------------------------------------
// THE FOUR CLAIM SETS: `AdminViews.claimSetsJson()` and `claimsAction()`.
//
// **`ClaimSets`'s members are all sent on every healthy read**, because
// `tests/protocol/admin_api.js` asserts each documented member of that schema
// is in a live reply; the `ClaimEntry` component stays `admin_api_spec.ts`'s,
// because the replace action's request body refers to it.
// ---------------------------------------------------------------------------
const CLAIM_VALUE: Json = Kit.freeForm(
  'A claim value as it would be issued. Its JSON type is the catalogue ' +
  'row\'s and the person\'s own data, and a row may nest under a dotted path.');

// `checkClaimEntries()`: a typed claim, or an attribute claim (#94), with what
// its kind of set adds, and `claimId` on the Kerberos page's rows.
const CLAIM_ROW: Json = Kit.closed({
  name: STR, value: STR, attribute: STR, multi: BOOL, type: STR,
  nameFormat: STR, namespace: STR, claimId: STR
});

// `ClaimAttributes.catalogueRows()`, with `pacClaimId` on the Kerberos page.
const CATALOGUE_ROW: Json = Kit.closed({
  ldap: STR, claim: STR, label: NULL_STR, schema: NULL_STR,
  sets: Kit.mapOf(BOOL, 'Whether it is ticked, by claim set.'),
  generated: BOOL, custom: BOOL, syntax: NULL_STR, pacClaimId: STR
});

const ATTRIBUTE_CHOICE: Json = Kit.closed({ attribute: STR, from: STR_LIST });

// One value of `subjectClaimsFor()`'s report, or of
// `kerberosPacAttributeValues()`.
const VALUE_REPORT: Json = Kit.closed({
  ldap: STR, claim: STR, value: CLAIM_VALUE, source: STR, ldpTerm: NULL_STR,
  claimId: STR, values: Kit.listOf(CLAIM_VALUE)
});

const BY_LDAP: Json = Kit.mapOf(VALUE_REPORT, 'By directory attribute.');

// `GroupClaims.groupsOf()`.
const GROUPS_PREVIEW: Json = Kit.closed({
  user: STR, key: NULL_STR, application: STR, enabled: BOOL, loaded: BOOL,
  claim: NULL_STR, valueForm: NULL_STR, memberOfCounts: BOOL, reason: STR,
  dn: NULL_STR, entryFound: BOOL,
  groups: Kit.listOf(Kit.closed({
    cn: NULL_STR, dn: STR, rule: NULL_STR, via: STR_LIST, viaMemberOf: BOOL
  })),
  values: STR_LIST
});

const CLAIM_SET_MEMBERS: Json = {
  placeholders: STR_LIST,
  attributeCatalogue: Kit.listOf(CATALOGUE_ROW),
  precedence: STR,
  sets: Kit.listOf(Kit.closed({
    id: STR, label: STR, claims: Kit.listOf(CLAIM_ROW), attributes: STR_LIST,
    attributeClaims: Kit.freeForm(
      'The claims one person would be issued, keyed and nested by the claim ' +
      'names the catalogue and an administrator chose.'),
    attributeReport: Kit.listOf(VALUE_REPORT),
    attributeClaimPreview: Kit.listOf(Kit.closed({
      name: STR, attribute: STR, carried: BOOL, value: CLAIM_VALUE
    })),
    withheldFrom: Kit.mapOf(STR_LIST, 'Partners withholding it, by claim.')
  })),
  attributeChoices: Kit.listOf(ATTRIBUTE_CHOICE),
  preview: Kit.closed({ user: STR, byLdap: BY_LDAP, entryFound: BOOL }),
  groups: Kit.closed({
    enabled: BOOL, loaded: BOOL, claim: NULL_STR, valueForm: NULL_STR,
    memberOfCounts: BOOL, sets: STR_LIST, problem: STR, grants: STR,
    precedence: STR, settings: STR_LIST, preview: GROUPS_PREVIEW
  }),
  withholding: Kit.listOf(Kit.closed({ id: STR, names: STR_LIST }))
};

const CLAIM_SETS: Json = Kit.closed(Object.assign({
  reservedJwtClaims: STR_LIST
}, CLAIM_SET_MEMBERS));

// `claimsRequestJson()`, what `userinfoClaimsJson()` adds: OIDC Core 5.5.
const CLAIMS_REQUEST: Json = Kit.closed({
  supported: BOOL, members: STR_LIST, maxClaims: NUM,
  requestable: Kit.listOf(Kit.closed({
    claim: STR, ldap: STR, label: NULL_STR, grouped: BOOL
  })),
  fromTheSignIn: STR_LIST, precedence: STR_LIST, notEnforced: STR_LIST,
  directParameter: Kit.closed({
    note: STR, spellings: STR_LIST, malformedIsRefused: STR
  }),
  preview: Kit.closed({
    asked: BOOL, ok: BOOL, error: STR, request: STR,
    parsed: Kit.freeForm('The claims request as a caller typed it, parsed: ' +
                         'OIDC Core 5.5 keys it by the claims they ask for.'),
    ignoredMembers: STR_LIST, idTokenNames: STR_LIST,
    claims: Kit.freeForm('The claims one person would be issued for that ' +
                         'request, keyed by the names it asked for.'),
    report: Kit.listOf(Kit.closed({
      requested: STR, claim: STR, ldap: STR, value: CLAIM_VALUE, source: STR
    })),
    unresolvable: STR_LIST,
    essentialAndAbsent: STR_LIST,
    valueMismatches: STR_LIST,
    entryFound: BOOL
  })
});

const USERINFO_CLAIM_SETS: Json = Kit.closed(Object.assign({
  protocolEndpoints: ENDPOINT_ROWS, reservedJwtClaims: STR_LIST,
  claimsRequest: CLAIMS_REQUEST, request: STR, inventedEmail: NULL_STR
}, CLAIM_SET_MEMBERS));

const SAML_ATTRIBUTE_SETS: Json = Kit.closed(Object.assign({
  protocolEndpoints: ENDPOINT_ROWS, defaultSaml11Namespace: STR
}, CLAIM_SET_MEMBERS));

const KERBEROS_PAC_CLAIMS: Json = Kit.closed({
  protocolEndpoints: ENDPOINT_ROWS,
  enabled: BOOL, setting: STR, types: STR_LIST, placeholders: STR_LIST,
  idFormat: STR, precedence: STR,
  sets: Kit.listOf(Kit.closed({
    id: STR, label: STR, claims: Kit.listOf(CLAIM_ROW), attributes: STR_LIST
  })),
  attributeCatalogue: Kit.listOf(CATALOGUE_ROW),
  attributeChoices: Kit.listOf(ATTRIBUTE_CHOICE),
  preview: Kit.closed({
    user: STR, entryFound: BOOL, byLdap: BY_LDAP,
    claims: Kit.listOf(Kit.closed({
      name: STR, id: STR, type: STR, values: Kit.listOf(CLAIM_VALUE),
      from: STR, dropped: BOOL
    }))
  })
});

// Every action of the claims, UserInfo, SAML attributes and PAC resources:
// `claimsAction()`.
const CLAIM_ACTION: Json = Kit.action({
  set: STR, claims: Kit.listOf(CLAIM_ROW), attributes: STR_LIST,
  added: STR_LIST, removed: STR_LIST
});

// ---------------------------------------------------------------------------
// SAML: the assertion settings, and the two profiles' registers.
// ---------------------------------------------------------------------------
const SAML_ASSERTIONS: Json = Kit.closed({
  protocolEndpoints: ENDPOINT_ROWS,
  assertions: Kit.closed({
    saml2LifetimeMin: NUM, saml11LifetimeMin: NUM, clockSkewS: NUM,
    saml2WindowS: NUM, saml11WindowS: NUM
  }),
  perApplication: Kit.listOf(Kit.closed({
    setting: STR, attribute: STR, profile: STR
  })),
  settings: Kit.listOf(SETTING_ROW),
  assertionsIssued: Kit.closed({
    held: NUM, forgotten: NUM, cap: NUM,
    byKind: Kit.listOf(Kit.closed({
      kind: STR, issued: NUM, valid: NUM, expired: NUM, noExpiry: NUM
    }))
  }),
  now: NUM,
  context: Kit.nullable(Kit.closed({
    configFile: NULL_STR, defaultsFile: NULL_STR, persistsAppconfig: BOOL,
    persistsRealms: BOOL, persistenceMode: STR, inRealm: BOOL,
    realmId: NULL_STR
  })),
  rows: Kit.listOf(Kit.closed({
    key: STR, unit: STR, kind: NULL_STR, profile: STR, field: STR
  })),
  seconds: Kit.mapOf(Kit.nullable(NUM), 'Each setting in seconds, by key.')
});

const SAML_ASSERTIONS_ACTION: Json = Kit.action({
  applied: STR_LIST, changed: STR_LIST, cleared: STR_LIST,
  settings: Kit.listOf(SETTING_ROW)
});

// `pagedRows()`'s own paging object, which these two pages send as it is
// rather than through `pagingJson()`, and so with `offset`.
const RAW_PAGING: Json = Kit.closed({
  page: INT, pages: INT, perPage: INT, offset: INT, total: INT, firstRow: INT,
  lastRow: INT, param: NULL_STR, noun: NULL_STR
});

// `consumedMetadataOf()`.
const CONSUMED_METADATA: Json = Kit.closed({
  state: STR, stateWhy: STR, expiresAt: STR, staleAt: STR, refreshable: BOOL,
  refresh: Kit.nullable(Kit.closed({
    ok: BOOL, lastAttemptAt: STR, lastSuccessAt: STR, failingSince: STR,
    failures: NUM, why: STR
  })),
  refresherEnabled: BOOL, refresherRunning: BOOL, trustAnchors: NUM,
  trustAnchorProblems: STR_LIST, mdqUrl: STR, consumed: BOOL, consumedAt: STR,
  how: STR, url: STR, signature: STR, signingCertificateConfigured: BOOL,
  validUntil: STR, expired: BOOL, cacheDuration: STR,
  authnRequestsSigned: BOOL, wantAssertionsSigned: BOOL,
  wantAssertionsEncrypted: BOOL, nameIdFormats: STR_LIST,
  assertionConsumerServices: Kit.listOf(Kit.closed({
    index: STR, isDefault: NULL_BOOL, binding: STR, location: STR
  })),
  singleLogoutServices: Kit.listOf(Kit.closed({
    binding: STR, location: STR, responseLocation: STR
  })),
  encryptionCertificate: BOOL
});

const SAML2_FACTS: Json = {
  identifier: STR, slug: NULL_STR, idpEntityId: NULL_STR, metadataUrl: STR,
  ssoUrl: STR, sloUrl: STR, arsUrl: STR
};

const SAML11_FACTS: Json = {
  identifier: STR, slug: NULL_STR, idpProviderId: NULL_STR, metadataUrl: STR,
  ssoUrl: STR, responderUrl: STR
};

// One answer for the list and for `?sp=`: the two share no required member,
// and a model with top-level members is what `protocolEndpoints` is added to.
const SAML2_SERVICE_PROVIDERS: Json = Kit.closed(Object.assign({
  protocolEndpoints: ENDPOINT_ROWS,
  serviceProviders: Kit.listOf(Kit.closed(Object.assign({
    name: NULL_STR, authentications: NUM, sessions: NUM, users: NUM,
    firstSeen: STR, lastSeen: STR, assertionConsumerServices: STR_LIST,
    singleLogoutServices: STR_LIST, nameIdFormats: STR_LIST,
    responseBindings: STR_LIST, lastRequestSigned: BOOL,
    lastRequestVerification: STR
  }, SAML2_FACTS))),
  paging: RAW_PAGING,
  unscopedMetadata: STR,
  settings: SETTINGS_BLOCK,
  artifactsAwaitingResolution: NUM,
  requestsHeldForSignIn: NUM,
  mdqRefused: Kit.listOf(Kit.closed({
    entityId: STR, why: STR, firstAt: NULL_STR,
    lastAt: NULL_STR, count: NUM
  })),
  mdqRefusedPaging: RAW_PAGING,
  kind: STR,
  // The drill-down.
  found: BOOL,
  name: STR,
  authentications: NUM,
  assertionConsumerServices: STR_LIST,
  singleLogoutServices: STR_LIST,
  nameIdFormats: STR_LIST,
  responseBindings: STR_LIST,
  lastRequestSigned: BOOL,
  lastRequestVerification: Kit.closed({
    outcome: STR, binding: STR, signatureMethod: STR, weak: BOOL
  }),
  signingCertificate: STR,
  signingCertificates: STR_LIST,
  observedSigningCertificate: STR,
  signedRequestsRequired: Kit.closed({ required: BOOL, why: STR }),
  metadata: CONSUMED_METADATA
}, SAML2_FACTS));

const SAML11_RELYING_PARTIES: Json = Kit.closed(Object.assign({
  protocolEndpoints: ENDPOINT_ROWS,
  relyingParties: Kit.listOf(Kit.closed(Object.assign({
    name: NULL_STR, authentications: NUM, sessions: NUM, users: NUM,
    firstSeen: STR, lastSeen: STR, assertionConsumerServices: STR_LIST,
    nameIdFormats: STR_LIST, profiles: STR_LIST
  }, SAML11_FACTS))),
  paging: RAW_PAGING,
  unscopedMetadata: STR,
  settings: SETTINGS_BLOCK,
  artifactsAwaitingResolution: NUM,
  assertionsHeldByReference: NUM,
  flowsHeldForSignIn: NUM,
  kind: STR,
  // The drill-down.
  registered: BOOL,
  identifierLooksGuessed: BOOL,
  name: STR,
  authentications: NUM,
  assertionConsumerServices: STR_LIST,
  nameIdFormats: STR_LIST,
  profiles: STR_LIST
}, SAML11_FACTS));

const SAML_IDP_INITIATED: Json = Kit.closed({
  protocolEndpoints: ENDPOINT_ROWS,
  idpInitiated: Kit.listOf(Kit.closed({
    identifier: STR, name: STR, entityId: STR, protocol: STR, label: STR,
    attribute: STR, launchUrl: STR, endpoint: NULL_STR, missing: STR_LIST
  })),
  idpInitiatedPaging: PAGING,
  realmSwitches: Kit.listOf(Kit.closed({
    protocol: STR, label: STR, setting: STR, attribute: STR, enabled: BOOL
  }))
});

const NULL_APPLICATION: Json = Kit.nullable(APPLICATION_VIEW);

// `applications.updateApplication()` and its neighbours, which hand back the
// whole `view()`, and `saml2Action()`'s register.
const SAML_APPLICATION_ACTION: Json = Kit.action({
  application: NULL_APPLICATION, changed: BOOL
});

// `SpMetadata.consume()`, what uploading, refreshing and importing metadata
// answer; here `application` is the identifier rather than the view.
const SAML_METADATA_ACTION: Json = Kit.action({
  application: STR, how: STR, entityId: STR, signature: STR,
  certificateUse: STR, signingCertificates: NUM,
  assertionConsumerServices: STR_LIST, singleLogoutServices: STR_LIST,
  nameIdFormats: STR_LIST, authnRequestsSigned: BOOL,
  wantAssertionsSigned: BOOL, validUntil: NULL_STR, cacheDuration: NULL_STR,
  skipped: STR_LIST, url: STR, created: BOOL, warnings: STR_LIST, why: STR
});

// ---------------------------------------------------------------------------
// SCIM: the surface, the monitor and the outbound clients (#552).
// ---------------------------------------------------------------------------
const HTTP_STATUS: Json = Kit.oneOf(NUM, STR, { type: 'null' });

const SCIM_STORE: Json = Kit.nullable(Kit.closed({
  what: STR, users: STR, groups: STR, baseDn: STR, userCount: NUM,
  groupCount: NUM, entryCount: NUM, maxEntries: NUM
}));

// `ScimAuth.describe()`'s schemes.
const SCIM_SCHEME: Json = Kit.closed({
  id: STR, type: STR, canonical: BOOL, name: STR, enabled: BOOL,
  refusedByMode: STR, setting: STR, primary: BOOL, scoped: BOOL,
  applicationScoped: BOOL, recorded: BOOL, challenged: BOOL, spec: STR,
  specUri: STR, description: STR
});

const SCIM_AUTHENTICATION: Json = Kit.nullable(Kit.closed({
  required: BOOL, discoveryOpen: BOOL, realm: STR,
  scopes: Kit.closed({ read: STR, write: STR }),
  hobaRegistration: STR, digestAlgorithms: STR_LIST,
  schemes: Kit.listOf(SCIM_SCHEME), policy: STR_LIST
}));

const SCIM_MAPPING_ROW: Json = Kit.closed({
  scim: STR, ldap: NULL_STR, kind: NULL_STR, type: NULL_STR, parent: NULL_STR,
  extension: BOOL, readOnly: BOOL, required: BOOL, schema: STR, note: STR
});

const RESOURCE_COUNT: Json = Kit.closed({ resourceType: NULL_STR, count: NUM });

// `admin_stats.js`'s `scimSnapshot()`.
const SCIM_COUNTERS: Json = Kit.closed({
  total: NUM, ok: NUM, failed: NUM, firstAt: MOMENT, lastAt: MOMENT,
  operations: Kit.listOf(Kit.closed({
    operation: STR, label: STR, method: STR, what: STR, count: NUM
  })),
  resourceTypes: Kit.listOf(RESOURCE_COUNT),
  byStatus: COUNTS, byScimType: COUNTS, byAuthScheme: COUNTS
});

// `scimMonitorSnapshot()`.
const SCIM_MONITOR_COUNTERS: Json = Kit.closed({
  calls: NUM, ok: NUM, failed: NUM, successRate: Kit.nullable(NUM),
  firstAt: MOMENT, lastAt: MOMENT, since: MOMENT,
  latency: Kit.closed({
    totalMs: NUM, averageMs: Kit.nullable(NUM), maxMs: NUM
  }),
  bytesOut: NUM,
  authentication: Kit.closed({
    distinct: NUM, applications: NUM, identities: NUM, anonymous: NUM,
    refused: NUM, capped: BOOL, cap: NUM, byScheme: COUNTS
  }),
  operations: Kit.listOf(Kit.closed({
    operation: STR, label: STR, method: STR, what: STR, count: NUM, ok: NUM,
    failed: NUM, averageMs: Kit.nullable(NUM), maxMs: Kit.nullable(NUM),
    bytes: NUM
  })),
  resourceTypes: Kit.listOf(RESOURCE_COUNT),
  byStatus: COUNTS, byStatusClass: COUNTS, byScimType: COUNTS,
  clients: Kit.listOf(Kit.closed({
    principal: NULL_STR, kind: NULL_STR, calls: NUM, ok: NUM, failed: NUM,
    schemes: STR_LIST, resourceTypes: STR_LIST, firstAt: MOMENT,
    lastAt: MOMENT, lastOperation: NULL_STR, lastStatus: HTTP_STATUS
  })),
  recent: Kit.listOf(Kit.closed({
    at: MOMENT, operation: NULL_STR, resourceType: NULL_STR,
    status: HTTP_STATUS, ok: BOOL, scimType: NULL_STR, scheme: NULL_STR,
    principal: NULL_STR, ms: Kit.nullable(NUM), bytes: Kit.nullable(NUM),
    method: NULL_STR, path: NULL_STR
  })),
  recentCap: NUM,
  realm: Kit.closed({ id: NULL_STR, name: NULL_STR })
});

// `outbound_delivery.ts`'s `view()` and the SCIM client's `viewExtra`.
const SCIM_DELIVERY: Json = Kit.closed({
  id: STR, realm: NULL_STR, clientId: STR, uri: NULL_STR, state: STR,
  generation: Kit.nullable(NUM), attempts: Kit.nullable(NUM), inFlight: BOOL,
  holder: STR, status: HTTP_STATUS, errorCode: NULL_STR, why: NULL_STR,
  queuedAt: STR, nextAttemptAt: STR, lastAttemptAt: STR, finishedAt: STR,
  client: STR, type: STR, uuid: STR, name: STR, pendingChange: BOOL
});

const SCIM_QUEUE_COUNTS: Json = Kit.closed({
  queued: NUM, retrying: NUM, dead: NUM, sent: NUM
});

const SCIM_RECONCILE: Json = {
  users: NUM, groups: NUM, deprovisioned: NUM, why: STR, notPushedHere: BOOL
};

const SCIM_DISCOVERY: Json = {
  ok: BOOL, patch: BOOL, filter: BOOL, etag: BOOL,
  endpoints: Kit.mapOf(STR, 'The path of each resource type, by its name.'),
  why: STR
};

// `ScimClients.rowOf()`: an application's fields as the client's own members,
// never a credential, and what `view()` lays over it.
const SCIM_CLIENT_MEMBERS: Json = {
  id: STR, identifier: STR, dn: STR, name: STR,
  baseUrl: STR, authMethod: STR, username: STR, tokenEndpoint: STR,
  oauthClientId: STR, oauthClientAuth: STR, oauthScope: STR,
  oauthResource: STR, tlsSource: STR, tlsCertificate: STR, caCertificates: STR,
  scopeMode: STR, scopeFilter: STR, groupMode: STR, deprovision: STR,
  reconcileMinutes: STR, jurisdiction: STR, maxRequestsPerSecond: STR,
  scopeGroups: STR_LIST, groups: STR_LIST, cells: STR_LIST,
  enabled: BOOL, passwordSet: BOOL, oauthClientSecretSet: BOOL,
  tlsPrivateKeySet: BOOL,
  certificate: Kit.nullable(Kit.closed({
    subject: STR, issuer: STR, notAfter: NULL_STR, serial: NULL_STR, error: STR
  })),
  problems: STR_LIST, usable: BOOL
};

// `acrossCells()`'s row per cell.
const SCIM_CELL_ROW: Json = Kit.closed({
  cell: STR, here: BOOL, reachable: BOOL, error: STR, withheld: STR,
  identifier: STR, pushes: BOOL, counts: SCIM_QUEUE_COUNTS, pausedUntil: STR,
  failures: NUM, lastReconcileAt: STR,
  queued: Kit.listOf(SCIM_DELIVERY), retrying: Kit.listOf(SCIM_DELIVERY),
  dead: Kit.listOf(SCIM_DELIVERY)
});

const SCIM_CLIENT_LIVE: Json = {
  counts: SCIM_QUEUE_COUNTS, pausedUntil: STR, failures: NUM,
  lastReconcileAt: STR,
  lastReconcile: Kit.nullable(Kit.closed(Object.assign({ ok: BOOL },
                                                       SCIM_RECONCILE))),
  byCell: Kit.listOf(SCIM_CELL_ROW)
};

const SCIM_CLIENT_ROW: Json = Kit.closed(Object.assign({}, SCIM_CLIENT_MEMBERS,
                                                       SCIM_CLIENT_LIVE));

const SCIM_CLIENT_PAGE: Json = Kit.nullable(Kit.closed(Object.assign({},
  SCIM_CLIENT_MEMBERS, SCIM_CLIENT_LIVE, {
    queues: Kit.closed({
      queued: Kit.listOf(SCIM_DELIVERY), retrying: Kit.listOf(SCIM_DELIVERY),
      dead: Kit.listOf(SCIM_DELIVERY), counts: SCIM_QUEUE_COUNTS
    }),
    linked: NUM,
    discovery: Kit.nullable(Kit.closed(Object.assign({}, SCIM_DISCOVERY, {
      maxResults: NUM, bulk: BOOL, authenticationSchemes: STR_LIST, at: STR
    })))
  })));

// `ScimClients.view()`, and `acrossCells()`'s `cellId`.
const SCIM_CLIENTS: Json = Kit.closed({
  family: STR, clients: Kit.listOf(SCIM_CLIENT_ROW),
  choices: Kit.closed({
    authMethods: STR_LIST, oauthClientAuth: STR_LIST, tlsSources: STR_LIST,
    scopeModes: STR_LIST, groupModes: STR_LIST, deprovision: STR_LIST
  }),
  httpAllowed: BOOL, client: SCIM_CLIENT_PAGE, missing: STR, cellId: NULL_STR
});

const SCIM: Json = Kit.closed({
  protocolEndpoints: ENDPOINT_ROWS,
  installed: BOOL, enabled: BOOL, baseUrl: NULL_STR, specifications: STR_LIST,
  store: SCIM_STORE,
  identifiers: Kit.nullable(Kit.closed({ id: STR, why: STR, example: STR })),
  authentication: SCIM_AUTHENTICATION,
  endpoints: Kit.listOf(Kit.closed({ method: STR, path: STR, what: STR })),
  doesNotDo: STR_LIST,
  reachableNegatives: Kit.listOf(Kit.closed({ what: STR, answer: STR })),
  mapping: Kit.closed({
    user: Kit.listOf(SCIM_MAPPING_ROW), group: Kit.listOf(SCIM_MAPPING_ROW)
  }),
  counters: SCIM_COUNTERS,
  settings: Kit.nullable(SETTINGS_BLOCK),
  scimClients: Kit.nullable(SCIM_CLIENTS)
});

const SCIM_MONITOR: Json = Kit.closed({
  installed: BOOL, enabled: BOOL, baseUrl: NULL_STR,
  schemes: Kit.listOf(SCIM_SCHEME), authRequired: BOOL, store: SCIM_STORE,
  counters: SCIM_MONITOR_COUNTERS
});

// `ScimClients.act()`: `actHere()`'s answer; with `cell` and `reachable` over
// it for an act that named a cell; and one row per cell for an act that named
// none.
const SCIM_CLIENT_ACTION: Json = Kit.action(Object.assign({
  client: Kit.withoutCodes(Kit.nullable(SCIM_CLIENT_ROW)),
  certificate: Kit.closed({
    subject: NULL_STR, serial: NULL_STR, notAfter: NULL_STR, rootPem: NULL_STR
  }),
  discovery: Kit.closed(SCIM_DISCOVERY),
  totalResults: Kit.nullable(NUM),
  count: NUM,
  cells: Kit.listOf(Kit.closed({
    cell: STR, reachable: BOOL, ok: BOOL, message: STR, count: NUM
  })),
  cell: STR, reachable: BOOL
}, SCIM_RECONCILE));

// ---------------------------------------------------------------------------
// THE DIRECTORY TAG'S THREE REGISTERS: attribute sources (#94), secret
// destinations (#221 P3) and post-login activities (#1111).
// ---------------------------------------------------------------------------
// `AttributeSources.normalise()`, as `recordOf()` parses it back.
const ATTRIBUTE_SOURCE_MEMBERS: Json = {
  id: STR, dialect: STR, host: STR, port: NUM, database: STR, user: STR,
  passwordProvider: STR, passwordRef: STR, passwordField: STR, caFile: STR,
  caCertificates: STR, trustPublicRoots: BOOL, serverName: STR, table: STR,
  keyColumn: STR, keyAttribute: STR,
  columns: Kit.mapOf(STR, 'The attribute each column of the operator\'s ' +
                          'table is written onto.'),
  refresh: STR_LIST, scheduleS: NUM, timeoutMs: NUM, onFailure: STR,
  enabled: BOOL
};

const ATTRIBUTE_SOURCE_ROW: Json = Kit.closed(Object.assign({
  status: Kit.closed({
    cursor: STR, cursorKind: STR, cursorOpen: BOOL,
    cycleEndedAt: MOMENT, lastRunAt: STR, lastRunPeople: NUM,
    lastError: STR, lastCode: STR, lastErrorAt: STR, failures: NUM,
    lastOkAt: STR
  }),
  trust: Kit.closed({
    certificates: Kit.listOf(Kit.closed({
      subject: STR, issuer: STR, notBefore: STR, notAfter: STR, expired: BOOL,
      notYetValid: BOOL, ca: BOOL, selfSigned: BOOL, sha256: STR
    })),
    unreadable: NUM, caFile: STR, publicRoots: BOOL
  })
}, ATTRIBUTE_SOURCE_MEMBERS));

const ATTRIBUTE_SOURCES: Json = Kit.closed({
  sources: Kit.listOf(ATTRIBUTE_SOURCE_ROW), sourcesPaging: PAGING,
  dialects: STR_LIST, modes: STR_LIST, onFailure: STR_LIST,
  passwordProviders: STR_LIST, hostPatterns: STR,
  refused: Kit.closed({ names: STR_LIST, prefixes: STR_LIST }),
  job: STR, settings: Kit.nullable(SETTINGS_BLOCK)
});

const ATTRIBUTE_SOURCE_ACTION: Json = Kit.action({
  source: Kit.closed(ATTRIBUTE_SOURCE_MEMBERS),
  key: STR, found: BOOL, why: STR,
  row: Kit.nullable(Kit.mapOf(Kit.freeForm(
    'A value of the operator\'s own SQL table, as its driver read it.'),
                              'The row, by the operator\'s column names.')),
  runId: Kit.oneOf(NUM, STR),
  changed: STR_LIST,
  failures: Kit.listOf(Kit.closed({ source: STR, why: STR }))
});

// `SecretDestinations.rowOf()`.
const SECRET_DESTINATION: Json = Kit.closed({
  id: STR, identifier: STR, name: STR, provider: STR, payload: STR,
  usable: BOOL, problems: STR_LIST,
  location: Kit.closed({
    provider: STR, payload: STR, region: STR, project: STR, endpoint: STR,
    mount: STR, field: STR, directory: STR, caCertificates: STR
  }),
  credentialSet: BOOL, credentialShape: STR
});

const SECRET_DESTINATIONS: Json = Kit.closed({
  destinations: Kit.listOf(SECRET_DESTINATION), destinationsPaging: PAGING,
  matched: INT, providers: STR_LIST, payloads: STR_LIST,
  credentialShapes: Kit.mapOf(STR, 'What each provider\'s credential is.'),
  fileAllowed: BOOL, family: STR
});

const SECRET_DESTINATION_ACTION: Json = Kit.action({
  destination: Kit.nullable(SECRET_DESTINATION),
  version: Kit.oneOf(NUM, STR, { type: 'null' })
});

const BOUNDED_NUMBER: Json = Kit.closed({ min: NUM, max: NUM, dflt: NUM });

// A started activity. `started` on an action is the record as it is kept, its
// moments in milliseconds; on the page they are ISO strings, or null.
const STARTED_ACTIVITY_MEMBERS: Json = {
  id: STR, activity: STR, groups: STR_LIST, intervalDays: NUM, maxMails: NUM,
  perRun: NUM, state: STR, startedAt: MOMENT, startedBy: NULL_STR,
  changedAt: MOMENT, changedBy: NULL_STR, endedAt: MOMENT
};

const POST_LOGIN_ACTIVITIES: Json = Kit.closed({
  realm: STR, job: STR, everyMinutes: NUM, activities: STR_LIST,
  limits: Kit.closed({
    intervalDays: BOUNDED_NUMBER, maxMails: BOUNDED_NUMBER,
    perRun: BOUNDED_NUMBER, groups: Kit.closed({ max: NUM })
  }),
  mailAvailable: BOOL, activityEnabled: BOOL,
  groupChooser: Kit.closed({
    search: STR,
    chosen: Kit.listOf(Kit.closed({
      asked: STR, cn: NULL_STR, dn: NULL_STR, found: BOOL
    })),
    pane: Kit.closed({
      total: NUM, matched: NUM, from: NUM,
      shown: Kit.listOf(Kit.closed({ cn: NULL_STR, dn: STR }))
    })
  }),
  started: Kit.listOf(Kit.closed(Object.assign({
    run: Kit.closed({
      cursor: STR, passes: NUM, read: NUM, mailed: NUM, notDue: NUM,
      heldBack: NUM, refused: NUM, lastRunAt: NULL_STR, lastSummary: STR
    })
  }, STARTED_ACTIVITY_MEMBERS)))
});

const POST_LOGIN_ACTION: Json = Kit.action({
  started: Kit.closed(STARTED_ACTIVITY_MEMBERS)
});

// ---------------------------------------------------------------------------
// The models, by operation.
// ---------------------------------------------------------------------------
const ACTION_MODELS: Json = {};

// Runs once per operation while this table is built, as the kit's helpers do,
// so no Entering/Leaving pair: a line per model would drown that log.
function actions(model: Json, ids: string[]): void {
  ids.forEach(function (id) {
    ACTION_MODELS[id] = { '200': model };
  });
}

['Claim', 'UserInfoClaim', 'KerberosPacClaim'].forEach(function (one) {
  actions(CLAIM_ACTION, ['add' + one, 'remove' + one,
                         'replace' + one + 's', 'clear' + one + 's',
                         'set' + one + 'Attributes',
                         'selectAll' + one + 'Attributes',
                         'clear' + one + 'Attributes']);
});

actions(CLAIM_ACTION, [
  'addAttributeClaim', 'addUserInfoAttributeClaim',
  'addKerberosPacAttributeClaim', 'addSamlAttribute',
  'addSamlDirectoryAttributeClaim', 'removeSamlAttribute',
  'clearSamlAttributes', 'replaceSamlAttributes',
  'setSamlDirectoryAttributes', 'selectAllSamlDirectoryAttributes',
  'clearSamlDirectoryAttributes'
]);

actions(SAML_ASSERTIONS_ACTION, ['setSamlAssertions', 'resetSamlAssertions']);

actions(SAML_APPLICATION_ACTION, [
  'registerSaml2ServiceProvider', 'addSaml2LogoutService',
  'removeSaml2LogoutService', 'setSaml2SigningCertificate',
  'removeSaml2SigningCertificate', 'confirmSaml2SigningCertificate',
  'discardSaml2SigningCertificate', 'setSaml2MetadataSigningCertificate',
  'registerSaml11RelyingParty'
]);

actions(SAML_METADATA_ACTION, [
  'refreshSaml2Metadata', 'importSaml2MetadataFromMdq', 'uploadSaml2Metadata'
]);

actions(Kit.action({
  added: NUM, duplicates: NUM, anchors: NUM,
  addedAnchors: Kit.listOf(ANCHOR_BRIEF), persisted: BOOL, warning: STR
}), ['addTrustAnchors']);

actions(Kit.action({
  removed: NUM, anchors: NUM, persisted: BOOL, removedAnchor: ANCHOR_BRIEF
}), ['removeTrustAnchor']);

actions(Kit.action(KERBEROS_MINTED), ['createKerberosServicePrincipal',
                                      'rotateKerberosServicePrincipal']);

actions(Kit.action({
  spn: STR, principal: STR, trustRealm: NULL_STR
}), ['deleteKerberosServicePrincipal']);

actions(Kit.action({
  cleared: BOOL, username: STR, trustRealm: NULL_STR
}), ['clearKerberosPersonKeys']);

actions(Kit.action(KERBEROS_DROPPED), ['dropKerberosServicePreviousKeys',
                                       'dropKerberosPersonPreviousKeys']);

actions(Kit.action(KERBEROS_PERSON_KEYTAB), ['resetKerberosPersonKeytab']);

actions(Kit.action({
  queued: BOOL, runId: Kit.oneOf(NUM, STR), alreadyQueued: BOOL,
  invalidate: BOOL, trustRealm: NULL_STR
}), ['rotateKerberosKrbtgt', 'rotateKerberosKrbtgtInvalidate']);

actions(KERBEROS_TRUST_ACTION, [
  'addKerberosTrust', 'updateKerberosTrust', 'enableKerberosTrust',
  'disableKerberosTrust', 'rotateKerberosTrustKey', 'removeKerberosTrust',
  'pairKerberosTrust'
]);

actions(ATTRIBUTE_SOURCE_ACTION, [
  'addAttributeSource', 'updateAttributeSource', 'removeAttributeSource',
  'testAttributeSource', 'refreshAttributeSource',
  'refreshAttributeSourcePerson'
]);

actions(SECRET_DESTINATION_ACTION, [
  'addSecretDestination', 'updateSecretDestination',
  'removeSecretDestination', 'testSecretDestination'
]);

actions(POST_LOGIN_ACTION, [
  'startPostLoginActivity', 'pausePostLoginActivity',
  'resumePostLoginActivity', 'endPostLoginActivity'
]);

actions(SCIM_CLIENT_ACTION, [
  'addScimClient', 'updateScimClient', 'removeScimClient',
  'issueScimClientCertificate', 'testScimClient', 'reconcileScimClient',
  'deliverScimClientNow', 'retryScimDelivery', 'retryScimDeadLetters',
  'purgeScimDeadLetters'
]);

export = {
  // The operations whose row names a schema keep that name, because a test or
  // a reader of the document may read it. `PageSettings` is not among them:
  // other families' pages name it too, and the Kerberos page's differs by
  // `status`, so those five are operations below.
  components: {
    DirectoryEntryList: DIRECTORY_ENTRY_LIST,
    DirectoryApplicationList: DIRECTORY_APPLICATION_LIST,
    DirectoryFederationList: DIRECTORY_FEDERATION_LIST,
    DirectorySpiffe: DIRECTORY_SPIFFE,
    DirectoryRoleList: DIRECTORY_ROLE_LIST,
    DirectoryPolicyList: DIRECTORY_POLICY_LIST,
    DirectoryPepList: DIRECTORY_PEP_LIST,
    DirectoryService: DIRECTORY_SERVICE,
    SamlAssertions: SAML_ASSERTIONS,
    ClaimSets: CLAIM_SETS,
    UserInfoClaimSets: USERINFO_CLAIM_SETS,
    SamlAttributeSets: SAML_ATTRIBUTE_SETS,
    KerberosPacClaims: KERBEROS_PAC_CLAIMS,
    Saml2ServiceProviderList: SAML2_SERVICE_PROVIDERS,
    Saml11RelyingPartyList: SAML11_RELYING_PARTIES,
    SamlIdpInitiatedList: SAML_IDP_INITIATED,
    Scim: SCIM,
    ScimMonitor: SCIM_MONITOR
  } as Record<string, unknown>,
  operations: Object.assign({
    getDirectoryDevices: { '200': DIRECTORY_DEVICE_LIST },
    getKerberosSettings: { '200': Kit.closed(Object.assign({
      status: KERBEROS_STATUS
    }, SETTINGS_PAGE_MEMBERS)) },
    getLdapSettings: { '200': SETTINGS_PAGE },
    getWsTrustSettings: { '200': SETTINGS_PAGE },
    getWsFedSettings: { '200': SETTINGS_PAGE },
    getTlsSettings: { '200': SETTINGS_PAGE },
    getTruststore: { '200': TRUSTSTORE, '503': TRUSTSTORE },
    getTlsConnection: { '200': TLS_CONNECTION },
    getKerberosPrincipals: { '200': KERBEROS_PRINCIPALS },
    getKerberosTrusts: { '200': KERBEROS_TRUSTS },
    getAttributeSources: { '200': ATTRIBUTE_SOURCES },
    getSecretDestinations: { '200': SECRET_DESTINATIONS },
    getPostLoginActivities: { '200': POST_LOGIN_ACTIVITIES },
    getScimClients: { '200': SCIM_CLIENTS }
  }, ACTION_MODELS) as Record<string, Record<string, unknown>>
};
