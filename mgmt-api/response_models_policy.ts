// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_policy.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): XACML, Policies, Delegation, UMA.
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
//
// **WRITTEN FROM THE CODE THAT BUILDS EACH ANSWER, NOT FROM WHAT WAS SEEN.** An
// answer these refuse is not sent, so a member a rare branch sends has to be
// here: a refused act's `holders`, the windowed consent page's `search`, a PDP
// status's `detail`, a person's picture's `signed-in` line. The comment above
// each group names the function whose return it states; a member added there
// owes a line here, or that answer becomes a 500.
//
// **THREE THINGS THAT LOOK WRONG AND ARE NOT.**
//
//   * A timestamp in the delegation pictures is a nullable number because
//     `user_graph.ts` folds with `Math.max(edge.lastAt, family.lastAt)`, and a
//     family with no `lastAt` is NaN, which JSON.stringify writes as null.
//   * A policy profile lists its fields by name, and its `defaults` and
//     `sources` are maps. Each kind's `FIELDS` table is its vocabulary, so the
//     profile is closed over it; `defaults` and `sources` are the same table
//     read as key and value, where a second copy of the list says nothing
//     more. **A new row in a kind's `FIELDS` owes a name in the list below.**
//     A new KIND of policy owes a member of `POLICIES` and a save and reset
//     row in `operations`.
//   * The console-only members and the owner's projection take members away
//     from these after the view built them, so nothing here but an action's
//     `ok` is `required`.
//
// THE FIVE FREE-FORM MEMBERS: an AuthZEN access request's `subject`,
// `resource`, `action` and `context` (the caller's own JSON, bound at the
// denial), and UMA's `endpoints` (RFC 8414 metadata). Each states why.
//
// No function here logs, as `response_model_kit.ts` says of its own: each runs
// only while a document's tables are built, and a line per schema would drown
// that log.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

// ---------------------------------------------------------------------------
// WORDS USED THROUGHOUT.
// ---------------------------------------------------------------------------
const STR: Json = Kit.str();
const NSTR: Json = Kit.nullable(Kit.str());
const INT: Json = Kit.int();
const NINT: Json = Kit.nullable(Kit.int());
const NUM: Json = Kit.num();
const NNUM: Json = Kit.nullable(Kit.num());
const BOOL: Json = Kit.bool();
const NBOOL: Json = Kit.nullable(Kit.bool());
const STRS: Json = Kit.listOf(STR);
const NULL: Json = { type: 'null' };

// One value of a setting or of a policy's field. A row's type decides which,
// and a `csv` row is parsed into a list.
const SCALAR: Json = Kit.oneOf(STR, NUM, BOOL, NULL);
const VALUE: Json = Kit.oneOf(STR, NUM, BOOL, NULL, Kit.listOf(SCALAR));

// `pagingJson()` in `admin-core/admin_views.ts`.
const PAGING: Json = Kit.closed({
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT, total: INT,
  param: NSTR, noun: NSTR
});

// `sendJson()` adds this to the answer of a GET mirroring a Protocols page;
// `protocol_endpoints.ts`'s `EndpointRow`. `apply()` writes it over a model
// with `properties`; it is declared as well so a model read alone is true.
const PROTOCOL_ENDPOINTS: Json = Kit.listOf(Kit.closed({
  name: STR, methods: STRS, url: STR, route: STR, transport: STR,
  registered: BOOL, listening: BOOL
}));

// A refusal of a GET, the words `mgmt-api/response_models.ts`'s ERROR uses:
// the registration loop's own paging and filter checks answer
// `{ ok: false, errors }`.
const GET_REFUSAL: Json = Kit.closed({
  ok: BOOL, errors: STRS, error: STR, error_description: STR, message: STR
});

// ---------------------------------------------------------------------------
// A PAGE'S SETTINGS BLOCK: `configSettingsJson()` in `admin-ui/admin.ts`, whose
// rows are `describe()` in `common/config.js` and whose `context` is
// `settingsContext()`.
// ---------------------------------------------------------------------------
const SELECT_ALL_RULE: Json = Kit.listOf(Kit.closed({
  setting: STR, values: STRS, on: BOOL, canBeOn: BOOL
}));

const SETTING: Json = Kit.closed({
  key: STR, group: STR, label: STR, description: STR, type: STR,
  enumValues: STRS, csvValues: STRS, ordered: BOOL,
  csvValueNotes: Kit.mapOf(STR),
  selectAll: Kit.closed({ onlyWhileOn: SELECT_ALL_RULE,
                          aloneWhileOn: SELECT_ALL_RULE }),
  min: NUM, max: NUM, step: NUM,
  value: VALUE, text: SCALAR, source: STR, editable: BOOL,
  restartReason: NSTR, editRefusal: NSTR,
  env: Kit.nullable(Kit.oneOrMany(STR)),
  legacyEnv: Kit.nullable(Kit.oneOrMany(STR)),
  appconfigPath: STR, default: VALUE, realmSettable: BOOL, overridden: BOOL
});

const SETTINGS: Json = Kit.nullable(Kit.closed({
  page: STR,
  groups: Kit.listOf(Kit.closed({ group: STR, settings: Kit.listOf(SETTING) })),
  settingCount: INT, editableCount: INT, overridden: STRS, setWith: STR,
  context: Kit.closed({
    configFile: NSTR, defaultsFile: NSTR, persistsAppconfig: BOOL,
    persistsRealms: BOOL, persistenceMode: STR, inRealm: BOOL, realmId: STR
  }),
  sharedWith: Kit.mapOf(Kit.listOf(Kit.closed({ path: STR, label: NSTR })))
}));

// ---------------------------------------------------------------------------
// XACML: `xacml/xacml_admin.ts`. Every view answers `noXacml()`'s two members
// in a process without that module, so each carries them.
// ---------------------------------------------------------------------------
const NO_XACML: Json = { xacml: BOOL, message: STR };

const ELSEWHERE: Json = Kit.listOf(Kit.closed({
  id: STR, name: NSTR, count: INT
}));

// `serviceOwnPolicies()`: the two states and what that function adds to them.
const SERVICE_OWN: Json = Kit.listOf(Kit.closed({
  key: STR, label: STR, decides: STR, asked: STR, remote: BOOL,
  name: STR, ok: BOOL, builtIn: BOOL, why: STR, setting: STR, template: STR,
  entry: BOOL, enabled: NBOOL, effect: STR, readsRisk: BOOL
}));

// A field of the model's nodes as `editDataFor()` copies it: the primitives of
// whichever node a tree row names, every kind `xacml_xml.js` reads, and the
// three sub-objects it copies whole. `value` and `reference` are a Match's, and
// their own members are the expression's.
const XACML_EXPRESSION: Json = Kit.closed({
  kind: STR, type: STR, lexical: STR, namespaces: Kit.mapOf(NSTR),
  xpathCategory: NSTR, category: NSTR, attributeId: STR, dataType: STR,
  issuer: NSTR, mustBePresent: BOOL, path: STR, contextSelectorId: NSTR,
  functionId: STR, description: NSTR, variableId: STR
});

const XACML_NODE: Json = Kit.closed({
  kind: STR, id: STR, description: NSTR, version: NSTR, combiningAlgId: STR,
  xpathVersion: NSTR, target: NULL, condition: NULL,
  maxDelegationDepth: Kit.oneOf(STR, NUM, NULL),
  effect: STR, ref: STR, matchId: STR,
  value: XACML_EXPRESSION, reference: XACML_EXPRESSION,
  namespaces: Kit.mapOf(NSTR),
  type: STR, lexical: STR, xpathCategory: NSTR, category: NSTR,
  attributeId: STR, dataType: STR, issuer: NSTR, mustBePresent: BOOL,
  path: STR, contextSelectorId: NSTR, functionId: STR, variableId: STR,
  on: STR, name: STR
});

const XACML_MENU: Json = Kit.listOf(Kit.closed({ value: STR, label: STR }));

const XACML_TREE_ROW: Json = Kit.closed({
  path: STR, depth: INT, kind: STR, label: STR, detail: STR,
  options: Kit.closed({
    kind: STR, removable: BOOL,
    additions: Kit.listOf(Kit.closed({ action: STR, label: STR, help: STR }))
  }),
  edit: Kit.nullable(Kit.closed({
    node: XACML_NODE,
    algorithms: Kit.listOf(Kit.closed({ uri: STR, label: STR, what: STR })),
    scope: Kit.listOf(Kit.closed({ id: STR, detail: STR })),
    valueShortType: NSTR
  }))
});

// `xacml.enforce()`'s three members, as `decideJson()` copies them.
const XACML_ENFORCEMENT: Json = Kit.closed({
  allowed: BOOL, bias: STR, why: NSTR
});

// `{ code, message, detail }`: `detail` is what the throw named, and these are
// every second argument of `model.syntaxError()`, `processingError()` and
// `missingAttribute()` in `xacml/`.
const XACML_STATUS: Json = Kit.nullable(Kit.closed({
  code: STR, message: NSTR,
  detail: Kit.nullable(Kit.closed({
    attributeId: STR, category: STR, dataType: STR, problems: STRS,
    errors: STRS, type: STR, lexical: STR
  }))
}));

// `xacml_monitor.ts`'s `snapshot()`: a row of `rows`, of `remoteRows` (which
// has `remote` and nulls for the four decisions), and UMA's own row.
const MONITOR_ROW: Json = Kit.closed({
  id: STR, label: STR, kind: STR, where: STR, module: STR, guards: STR,
  enforces: BOOL, bias: NSTR, dischargesObligations: BOOL,
  decisions: INT, allowed: NINT, refused: NINT,
  permit: NINT, deny: NINT, notApplicable: NINT, indeterminate: NINT,
  other: NINT, undischargeable: INT,
  lastAt: Kit.oneOf(STR, NUM, NULL), lastDecision: NSTR, lastAllowed: NBOOL,
  remote: Kit.closed({
    authenticated: BOOL, certificateSubject: STR, current: BOOL, stale: BOOL,
    enabled: BOOL, registeredAt: NSTR, lastSeen: NSTR, syncToken: STR,
    policyCount: NINT, version: STR, lastNotify: STR
  })
});

const MONITOR_TOTALS: Json = Kit.closed({
  decisions: INT, allowed: INT, refused: INT, unenforced: INT,
  undischargeable: INT
});

// `PepRegistry.all()`'s row, with what `pepsJson()` adds.
const PEP_ROW: Json = Kit.closed({
  name: STR, dn: STR, identity: STR, certificateSubject: STR, thumbprint: STR,
  authenticated: BOOL, notifyUrl: STR, bias: STR, resource: STR,
  description: STR, version: STR, enabled: BOOL, registeredAt: STR,
  lastSeen: STR, syncToken: STR, policyCount: NNUM, decisions: NNUM,
  allowed: NNUM, refused: NNUM, undischargeable: NNUM, lastNotify: STR,
  current: BOOL, stale: BOOL, notifyProblem: NSTR,
  // `PepTls.certificateOf()`, with `chainPem` taken off by `pepsJson()`.
  listenerCertificate: Kit.nullable(Kit.closed({
    subject: STR, serialHex: STR, notBefore: STR, notAfter: STR, expired: BOOL,
    thumbprint: STR, keyAlg: STR, signatureAlg: STR, dnsNames: STRS,
    ipAddresses: STRS, issuedAt: STR, certificatePem: STR
  }))
});

const XACML: Json = Kit.closed(Object.assign({}, NO_XACML, {
  enabled: BOOL, policies: INT, enabledPolicies: INT, root: NSTR,
  pipAvailable: BOOL, settings: SETTINGS,
  protocolEndpoints: PROTOCOL_ENDPOINTS
}));

const XACML_POLICIES: Json = Kit.closed(Object.assign({}, NO_XACML, {
  root: NSTR,
  policies: Kit.listOf(Kit.closed({
    name: STR, policyId: NSTR, kind: STR, version: STR, enabled: BOOL,
    isRoot: BOOL, combiningAlgId: STR, description: STR, application: NSTR,
    orphanedAt: NSTR, problems: STRS
  })),
  // `FgaPolicies.ownedPolicies()`.
  applicationPolicies: Kit.listOf(Kit.closed({
    application: STR, known: BOOL, enforced: BOOL,
    policies: Kit.listOf(Kit.closed({
      name: STR, policyId: NSTR, version: STR, enabled: BOOL,
      orphanedAt: NSTR, referenced: BOOL
    }))
  })),
  // `XacmlTemplates.catalogue()`.
  templates: Kit.listOf(Kit.closed({
    id: STR, label: STR, blurb: STR, what: STR,
    parameters: Kit.listOf(Kit.closed({
      name: STR, label: STR, help: NSTR, type: STR, dflt: SCALAR
    }))
  })),
  serviceOwn: SERVICE_OWN,
  protocolEndpoints: PROTOCOL_ENDPOINTS
}));

// `editorJson()`: both branches, the second being "nothing to edit".
const XACML_EDITOR: Json = Kit.closed(Object.assign({}, NO_XACML, {
  policies: STRS, serviceOwn: SERVICE_OWN,
  policy: Kit.nullable(Kit.closed({
    name: STR, enabled: BOOL, isRoot: BOOL, policyId: NSTR, kind: NSTR,
    version: NSTR, combiningAlgId: NSTR, description: NSTR
  })),
  problem: NSTR, tree: Kit.listOf(XACML_TREE_ROW),
  menus: Kit.nullable(Kit.closed({
    types: XACML_MENU, categories: XACML_MENU, functions: XACML_MENU,
    matchFunctions: XACML_MENU, xpathType: STR, resourceCategory: STR
  })),
  // `[problem]` where the document does not load, and `problem` may be null.
  problems: Kit.listOf(NSTR),
  xpathVersionGaps: Kit.listOf(NSTR), document: STR, alfa: NSTR,
  protocolEndpoints: PROTOCOL_ENDPOINTS
}));

const XACML_DECISION: Json = Kit.closed(Object.assign({}, NO_XACML, {
  asked: BOOL, subject: STR, action: STR, resource: NSTR, decision: STR,
  status: XACML_STATUS, obligations: STRS, advice: STRS,
  // XACML's PolicyIdentifierList, each policy named with its version.
  applicablePolicies: Kit.listOf(Kit.oneOf(Kit.str(), Kit.closed({
    kind: Kit.str(), id: Kit.str(), version: Kit.str()
  }))),
  enforcement: XACML_ENFORCEMENT,
  enforcements: Kit.listOf(XACML_ENFORCEMENT),
  protocolEndpoints: PROTOCOL_ENDPOINTS
}));

const XACML_MONITOR: Json = Kit.closed(Object.assign({}, NO_XACML, {
  policies: Kit.closed({ total: INT, enabled: INT, root: NSTR }),
  peps: Kit.closed({ embedded: INT, remote: INT, total: INT }),
  decisions: Kit.closed({ here: MONITOR_TOTALS, remote: MONITOR_TOTALS,
                          combined: MONITOR_TOTALS }),
  since: STR, enabled: BOOL, remotePepsEnabled: BOOL,
  realm: Kit.closed({ id: STR, name: NSTR }),
  rows: Kit.listOf(MONITOR_ROW), remoteRows: Kit.listOf(MONITOR_ROW),
  elsewhere: ELSEWHERE,
  protocolEndpoints: PROTOCOL_ENDPOINTS
}));

const XACML_PEPS: Json = Kit.closed(Object.assign({}, NO_XACML, {
  enabled: BOOL, syncToken: NSTR, staleAfterS: NUM, requiresCertificate: BOOL,
  notify: Kit.closed({
    on: BOOL, allowedHosts: STRS, timeoutMs: NUM,
    // `OutboundTls.describe()`.
    transport: Kit.closed({ allowHttp: BOOL, skipTlsVerificationSet: BOOL,
                            skipTlsVerification: BOOL, caFile: STR })
  }),
  peps: Kit.listOf(PEP_ROW), elsewhere: ELSEWHERE,
  listenerCertificates: Kit.closed({ useCase: STR, keyAlgorithms: STRS,
                                     defaultKeyAlg: STR }),
  current: INT, stale: INT,
  protocolEndpoints: PROTOCOL_ENDPOINTS
}));

// `xacmlAction()` turns `{ ok, why }` into `{ ok, why, errors }` and passes the
// rest. `store.write()`'s refusal reaches a caller whole, so `problems`, which
// is null where the throw named none; `editorAction()` answers `what`.
const XACML_ACTION_MEMBERS: Json = {
  why: STR, what: STR, problems: Kit.nullable(STRS)
};

const XACML_ACTION: Json = Kit.action(XACML_ACTION_MEMBERS);

// `PepTls.issue()`: the one answer holding a private key, handed over once.
const XACML_ISSUE: Json = Kit.action(Object.assign({}, XACML_ACTION_MEMBERS, {
  pep: STR, realm: STR, serialHex: STR, subject: STR, notBefore: STR,
  notAfter: STR, thumbprint: STR, dnsNames: STRS, ipAddresses: STRS,
  replacedSerialHex: NSTR, certificatePem: STR, chainPem: STRS,
  fullChainPem: STR, anchorPem: STR, privateKeyPem: STR
}));

// ---------------------------------------------------------------------------
// ONE APPLICATION AS `applications.js`'s `view()` DRAWS IT, which is what
// `updateApplication()` answers and so what a delegated permission grant and a
// global consent answer. An entry's attribute names are data.
// ---------------------------------------------------------------------------
const APPLICATION: Json = Kit.closed({
  identifier: STR, dnLabel: NSTR, dn: NSTR, name: NSTR, kinds: STRS,
  protocols: STRS, allowedProtocols: STRS, recordedProtocols: STRS,
  declaredKinds: STRS, registeredBy: STR,
  returnAddressesObserved: Kit.listOf(Kit.closed({
    attribute: STR, value: STR, held: BOOL, trusted: BOOL
  })),
  registered: BOOL, firstSeen: STR, lastSeen: STR, authentications: NUM,
  sessions: NUM, users: NUM, description: NSTR, origin: NSTR, createdAt: NSTR,
  modifiedAt: NSTR, operational: STRS,
  attributes: Kit.mapOf(Kit.oneOrMany(SCALAR)),
  fields: Kit.mapOf(Kit.oneOrMany(SCALAR))
});

// `updateApplication()`, what `AppPermissions` adds (only a message), and what
// `Consent` adds. The `revoke*` and `forget` answers carry no application.
const PERMISSION_ACTION: Json = Kit.action({
  changed: BOOL, application: APPLICATION
});

const CONSENT_ACTION: Json = Kit.action({
  changed: BOOL, application: APPLICATION, revoked: INT, withdrawnAt: NSTR,
  removed: INT, dn: NSTR
});

// ---------------------------------------------------------------------------
// DELEGATION: `common/delegation.js`, and `common/user_graph.ts` on top of it
// for one person's picture. One node and one edge model for both those and
// `app_permissions.ts`'s `graph()`, because a picture of any of them is drawn
// by the same layout, which is why that function keeps these shapes.
// ---------------------------------------------------------------------------
const WHEN: Json = NNUM;

const ROLES_COUNT: Json = Kit.closed({
  initial: NUM, intermediary: NUM, target: NUM
});

// `party()`.
const PARTY: Json = Kit.closed({
  key: STR, presented: STR, application: STR, what: STR
});

// `credential()`.
const CREDENTIAL: Json = Kit.closed({ kind: STR, identifier: STR, note: STR });

// `foldCredentials()`, and `user_graph.ts`'s `foldOnto()`.
const FOLDED: Json = Kit.closed({
  kind: STR, count: INT, identifiers: STRS, moreIdentifiers: INT, notes: STRS
});

// `recordUnguarded()`.
const DELEGATION_ACT: Json = Kit.closed({
  seq: NUM, origin: STR, at: WHEN, protocol: STR, type: STR, typeLabel: STR,
  mode: STR, spec: STR, policed: BOOL, outcome: STR, initial: PARTY,
  intermediary: PARTY, target: PARTY, authorizedBy: STR, reason: STR,
  consumed: Kit.listOf(CREDENTIAL), produced: Kit.listOf(CREDENTIAL),
  sessionId: STR, note: STR, chainKey: STR
});

// `chainList()`.
const DELEGATION_CHAIN: Json = Kit.closed({
  chainKey: STR, protocol: STR, type: STR, typeLabel: STR, mode: STR,
  initial: PARTY, intermediary: PARTY, target: PARTY, acts: INT, issued: INT,
  refused: INT, firstAt: WHEN, lastAt: WHEN, authorizedBy: STR, reason: STR
});

// `applicationList()`.
const DELEGATION_APPLICATION: Json = Kit.closed({
  key: STR, identifier: STR, spellings: STRS, roles: ROLES_COUNT,
  protocols: STRS, acts: INT, issued: INT, refused: INT, credentials: INT,
  firstAt: WHEN, lastAt: WHEN, identityKey: STR, chains: INT
});

// `graph()`'s `nodeFor()` and its issuer box, what `user_graph.ts`'s
// `normaliseNode()` and `nodeFor()` add, and `app_permissions.ts`'s three.
const GRAPH_NODE: Json = Kit.closed({
  id: STR, kind: STR, key: STR, presented: STR, application: STR,
  aliases: STRS, what: STR, roles: ROLES_COUNT, protocols: STRS, acts: INT,
  issued: INT, refused: INT, firstAt: WHEN, lastAt: WHEN, selfTarget: BOOL,
  chiefRole: STR,
  realm: Kit.closed({ id: STR, name: NSTR, isDefault: BOOL }),
  issuer: STR,
  credentials: INT, flows: STRS, authentications: INT, isSubject: BOOL,
  isClient: BOOL, kinds: STRS,
  grants: INT, exposes: INT, dangling: INT
});

// `graph()`'s three edge seeds (an act's, the issuer's, a configured pair's),
// `user_graph.ts`'s four (signed in, issued for, reaches, issued), and
// `app_permissions.ts`'s, which keeps its two empty folds.
const GRAPH_EDGE: Json = Kit.closed({
  id: STR, from: STR, to: STR, fromRole: STR, toRole: STR, relation: STR,
  skipped: STRS, chainKey: STR, protocol: NSTR, protocols: STRS, type: NSTR,
  typeLabel: NSTR, mode: STR, spec: NSTR, policed: BOOL, subject: NSTR,
  actor: NSTR, acts: INT, issued: INT, refused: INT, credentials: INT,
  firstAt: WHEN, lastAt: WHEN, authorizedBy: STR, reason: STR,
  consumed: Kit.listOf(FOLDED), produced: Kit.listOf(FOLDED),
  consumedFold: Kit.mapOf(FOLDED), producedFold: Kit.mapOf(FOLDED),
  attribute: STR, mechanism: STR, setOn: STR, used: BOOL,
  authentications: Kit.listOf(Kit.closed({
    protocol: STR, method: STR, count: INT, at: WHEN, lastAt: WHEN
  })),
  audience: STR, audienceRegistered: BOOL, permissions: STRS, scopes: STRS,
  permissionId: STR, permissionName: STR, baseUri: NSTR, description: NSTR,
  asked: BOOL
});

// `user_graph.ts`'s `credentialsFor()`, both of its rows.
const PERSON_CREDENTIAL: Json = Kit.closed({
  at: WHEN, family: STR, kind: STR, identifier: STR, flow: STR, flowLabel: NSTR,
  flowProtocol: NSTR, flowSpec: NSTR, flowOidc: NSTR, flowStated: BOOL,
  holder: STR, audience: STR, scope: STR, issuer: STR, state: NSTR,
  sessionId: STR, revocable: BOOL, revoked: BOOL, detail: STR, expiresAtMs: WHEN
});

// `graph()`, with the three `graphFor()` adds, and `app_permissions.ts`'s
// `counts`.
const GRAPH: Json = Kit.closed({
  realm: Kit.closed({ id: STR, name: NSTR, isDefault: BOOL }),
  issuer: STR, nodes: Kit.listOf(GRAPH_NODE), edges: Kit.listOf(GRAPH_EDGE),
  tokens: Kit.listOf(Kit.closed({
    seq: NUM, at: WHEN, kind: STR, identifier: STR, note: STR, protocol: STR,
    type: STR, typeLabel: STR, mode: STR, chainKey: STR, subject: NSTR,
    actor: NSTR, target: NSTR
  })),
  tokensLeftOff: INT, maxTokenRows: INT, acts: INT, chains: INT,
  credentials: Kit.listOf(PERSON_CREDENTIAL),
  credentialsOnDelegationLines: INT, subject: STR,
  counts: Kit.closed({ nodes: INT, edges: INT, grants: INT })
});

// `delegationNodeLook()`, the issuer's box and everybody else's.
const LOOK: Json = Kit.closed({
  shape: STR, label: STR, sublabel: STR, identifier: NSTR, title: STR,
  href: STR, dashed: BOOL
});

// `delegationChooser()`. A person's `names` may hold an undefined `presented`,
// which an array writes as null.
const CHOOSER: Json = Kit.closed({
  total: INT,
  entries: Kit.listOf(Kit.closed({
    key: STR, names: Kit.listOf(NSTR), label: STR, detail: STR, href: STR
  })),
  slice: Kit.closed({ matched: INT, from: INT }),
  search: STR, complete: BOOL
});

// `delegationFacts()`.
const FACTS: Json = Kit.closed({
  users: Kit.mapOf(BOOL),
  apps: Kit.mapOf(Kit.closed({ name: STR, dnLabel: STR }))
});

const DRAWING: Json = Kit.closed({ width: NUM, height: NUM, failed: NSTR });

const VOCABULARY_ROLE: Json = Kit.closed({ role: STR, label: STR, what: STR });

// `user_graph.ts`'s `userList()`, `rowFromStats()` and `foldDelegation()`.
const IDENTITY: Json = Kit.closed({
  key: STR, name: NSTR, presented: STR, forms: Kit.listOf(NSTR),
  authenticated: BOOL, isClient: BOOL, authentications: INT, protocols: STRS,
  tokens: Kit.closed({ issued: INT, valid: INT, expired: INT, revoked: INT,
                       other: INT }),
  artifacts: INT, lastAt: WHEN, delegated: BOOL, acts: INT, issued: INT,
  refused: INT, chains: INT, roles: ROLES_COUNT
});

// `delegationUserModel()`.
const DELEGATION_USER: Json = Kit.closed({
  user: Kit.nullable(IDENTITY), asked: NSTR, key: NSTR,
  credentials: Kit.listOf(PERSON_CREDENTIAL),
  // `FLOWS` in `user_graph.ts`, and `flowRow()`'s row for one it does not know.
  flows: Kit.listOf(Kit.closed({
    flow: STR, protocol: STR, label: STR, oidc: STR, spec: STR, browser: BOOL,
    unknown: BOOL, what: STR
  })),
  onDelegationLines: INT, acts: Kit.listOf(DELEGATION_ACT), graph: GRAPH,
  counts: Kit.nullable(Kit.closed({
    credentials: INT, acts: INT, chains: INT, authentications: INT,
    applications: INT
  })),
  users: Kit.listOf(IDENTITY), usersComplete: BOOL, drawing: DRAWING,
  looks: Kit.mapOf(LOOK), label: STR, svg: STR, chooser: CHOOSER,
  mapKey: STR, facts: FACTS
});

// `delegationApplicationModel()`.
const DELEGATION_APPLICATION_PAGE: Json = Kit.closed({
  application: Kit.nullable(DELEGATION_APPLICATION), asked: NSTR, key: NSTR,
  registered: BOOL, registeredName: STR, acts: Kit.listOf(DELEGATION_ACT),
  graph: GRAPH, rolesBySeq: Kit.mapOf(STRS),
  applications: Kit.listOf(DELEGATION_APPLICATION), held: INT, maxRecords: INT,
  roles: Kit.listOf(VOCABULARY_ROLE), drawing: DRAWING, looks: Kit.mapOf(LOOK),
  label: STR, svg: STR, chooser: CHOOSER, mapKey: STR, facts: FACTS
});

// `common/delegation_policy.ts`'s `list()`, both pair rows.
const EXCHANGE_PAIR: Json = Kit.closed({
  mechanism: STR, intermediary: STR, target: STR, targetApplication: NSTR,
  attribute: STR, setOn: STR, setOnRole: STR, impersonates: BOOL,
  subjectGroups: STRS, targetKnown: BOOL, warning: STR
});

const EXCHANGE_INTERMEDIARY: Json = Kit.closed({
  application: STR, impersonates: BOOL, semantics: STRS, defaultSemantics: STR,
  notDelegated: BOOL, subjectGroups: STRS
});

// `delegationFlaggedPersons()` in `ldap/ldap_server.js`.
const EXCHANGE_PERSON: Json = Kit.closed({
  username: STR, dn: STR, notDelegated: BOOL, mayAct: STR, semantics: STRS,
  defaultSemantics: STR
});

const EXCHANGE_POLICY: Json = Kit.closed({
  enforced: BOOL, attributes: Kit.mapOf(STR), protectedGroups: STRS,
  pairs: Kit.listOf(EXCHANGE_PAIR), pairsPaging: PAGING,
  intermediaries: Kit.listOf(EXCHANGE_INTERMEDIARY),
  intermediariesPaging: PAGING, people: Kit.listOf(EXCHANGE_PERSON),
  peoplePaging: PAGING
});

function pageOf(row: Json): Json {
  return Kit.closed({ shown: Kit.listOf(row), paging: PAGING });
}

// `krb5_principals.js`'s `delegationPolicy()`.
const KERBEROS_PAIR: Json = Kit.closed({
  mechanism: STR, type: STR, frontEnd: STR, target: STR, realm: STR,
  attribute: STR, setOn: STR, setOnRole: STR, requires: STR, targetKnown: BOOL,
  warning: STR, note: STR
});

const KERBEROS_ACCOUNT: Json = Kit.closed({
  principal: STR, realm: STR, notDelegated: BOOL,
  trustedToAuthenticateForDelegation: BOOL, okAsDelegate: BOOL,
  autoCreated: BOOL, description: STR, effects: STRS
});

// `TYPES` in `common/delegation.js`.
const MECHANISM: Json = Kit.closed({
  type: STR, protocol: STR, mode: STR, label: STR, spec: STR, policed: BOOL,
  what: STR
});

// ---------------------------------------------------------------------------
// THE DELEGATED PERMISSION REGISTER: `app_permissions.ts`'s `register()`.
// ---------------------------------------------------------------------------
const GRANTED_TO: Json = Kit.listOf(Kit.closed({
  identifier: STR, name: STR, asked: BOOL
}));

const PERMISSION: Json = Kit.closed({
  resource: STR, resourceName: STR, baseUri: NSTR, name: NSTR,
  description: NSTR, id: NSTR, raw: NSTR, grantedTo: GRANTED_TO
});

const GRANT: Json = Kit.closed({
  client: STR, clientName: STR, permissionId: STR, resource: STR,
  resourceName: STR, baseUri: NSTR, permissionName: NSTR, description: NSTR,
  dangling: BOOL, asked: BOOL
});

const PERMISSION_RESOURCE: Json = Kit.closed({
  identifier: STR, name: STR, baseUri: NSTR, rawBaseUri: STR,
  permissions: Kit.listOf(Kit.closed({
    name: NSTR, description: NSTR, id: NSTR, raw: NSTR, grantedTo: GRANTED_TO
  })),
  grantsHeld: INT
});

const REGISTER_COUNTS: Json = Kit.closed({
  resources: INT, permissions: INT, unidentified: INT, grants: INT,
  dangling: INT, unused: INT, ungranted: INT, clients: INT
});

// The handler answers the register with `graph` beside it.
const PERMISSIONS: Json = Kit.closed({
  resources: Kit.listOf(PERMISSION_RESOURCE),
  permissions: Kit.listOf(PERMISSION), grants: Kit.listOf(GRANT),
  counts: REGISTER_COUNTS, graph: GRAPH
});

// `permissionGroupsView()`: `application` decides the shape, and a name nobody
// holds is `group: null` and a 200. One model and not `oneOf`: the two answers
// share `application` and `counts`, and a union would report a refused member
// once per branch, naming the wrong branch half the time.
const CLUSTER_COUNTS: Json = Kit.closed({
  clusters: INT, applications: INT, largest: INT, alone: INT, joined: INT
});

const CLUSTER: Json = Kit.closed({
  key: STR, members: STRS,
  counts: Kit.closed({
    applications: INT, grants: INT, lines: INT, permissions: INT, dangling: INT,
    selfGrants: INT, asked: INT, unused: INT
  })
});

const PERMISSION_GROUPS: Json = Kit.closed({
  application: NSTR, counts: CLUSTER_COUNTS,
  // Every group, with no `application`.
  groups: Kit.listOf(CLUSTER), paging: PAGING,
  // The one group an `application` is in.
  group: Kit.nullable(CLUSTER), grants: Kit.listOf(GRANT), grantsPaging: PAGING,
  permissions: Kit.listOf(PERMISSION), permissionsPaging: PAGING, graph: GRAPH
});

const DELEGATION_LIST: Json = Kit.closed({
  // `delegationView()`'s `json`, whose counts are `summary()`'s. The four `by`
  // maps are keyed by a mechanism, a mode, an outcome and a protocol, and an
  // act recorded under an unknown type is counted under it.
  held: INT, heldHere: INT, processes: INT, recorded: INT, dropped: INT,
  maxRecords: INT, matched: INT, shown: INT, oldestSeq: NUM, newestSeq: NUM,
  byType: Kit.mapOf(INT), byMode: Kit.mapOf(INT), byOutcome: Kit.mapOf(INT),
  byProtocol: Kit.mapOf(INT),
  filter: Kit.closed({ type: NSTR, mode: NSTR, outcome: NSTR, protocol: NSTR,
                       q: NSTR }),
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  types: Kit.listOf(MECHANISM),
  modes: Kit.listOf(Kit.closed({ mode: STR, label: STR, what: STR })),
  outcomes: STRS, roles: Kit.listOf(VOCABULARY_ROLE),
  acts: Kit.listOf(DELEGATION_ACT), chains: Kit.listOf(DELEGATION_CHAIN),
  applications: Kit.listOf(DELEGATION_APPLICATION), graph: GRAPH,
  policy: Kit.closed({ pairs: Kit.listOf(KERBEROS_PAIR),
                       accounts: Kit.listOf(KERBEROS_ACCOUNT) }),
  // What `delegationPageModel()` adds.
  allowed: Kit.closed({
    resources: Kit.listOf(PERMISSION_RESOURCE),
    permissions: Kit.listOf(PERMISSION), grants: Kit.listOf(GRANT),
    counts: REGISTER_COUNTS, graph: GRAPH,
    filter: Kit.closed({ permissions: NSTR, grants: NSTR }),
    paging: Kit.closed({ permissions: PAGING, grants: PAGING })
  }),
  delegationPolicy: EXCHANGE_POLICY, all: INT, paging: PAGING,
  delegationPerPage: INT,
  chainPage: pageOf(DELEGATION_CHAIN), pairPage: pageOf(KERBEROS_PAIR),
  flagPage: pageOf(KERBEROS_ACCOUNT), mechanismPage: pageOf(MECHANISM),
  applicationChooser: CHOOSER, userChooser: CHOOSER,
  permissionsView: Kit.closed({
    register: Kit.closed({
      resources: Kit.listOf(PERMISSION_RESOURCE),
      permissions: Kit.listOf(PERMISSION), grants: Kit.listOf(GRANT),
      counts: REGISTER_COUNTS
    }),
    // `permissionsListStateOf()`.
    listState: Kit.closed({
      permWanted: STR, grantWanted: STR, permPage: pageOf(PERMISSION),
      grantPage: pageOf(GRANT)
    }),
    allApplications: Kit.listOf(Kit.closed({ identifier: STR, name: STR }))
  }),
  exchangePolicyView: Kit.closed({
    register: Kit.closed({
      pairs: Kit.listOf(EXCHANGE_PAIR),
      intermediaries: Kit.listOf(EXCHANGE_INTERMEDIARY),
      people: Kit.listOf(EXCHANGE_PERSON), protectedGroups: STRS,
      enforced: BOOL, attributes: Kit.mapOf(STR)
    }),
    pairs: pageOf(EXCHANGE_PAIR),
    intermediaries: pageOf(EXCHANGE_INTERMEDIARY),
    people: pageOf(EXCHANGE_PERSON)
  }),
  facts: FACTS
});

// ---------------------------------------------------------------------------
// THE POLICIES: `policiesView()` and `policyKindMember()` in
// `admin-core/admin_views.ts`, over the seven modules `admin-core/
// policy_kinds.ts` registers. Each kind's profile is `read()` in its module:
// these members, and that module's `FIELDS` by key.
// ---------------------------------------------------------------------------
const PROFILE_BASE: Json = {
  name: STR, precedence: INT, stored: BOOL, inherited: BOOL, from: STR, dn: STR,
  description: STR, sources: Kit.mapOf(STR), problems: STRS, enforced: BOOL
};

function profileOf(keys: string[], extra?: Json): Json {
  const members: Json = Object.assign({}, PROFILE_BASE, extra || {});
  keys.forEach(function (key) {
    members[key] = VALUE;
  });
  return Kit.closed(members);
}

const PASSWORD_PROFILE: Json = profileOf([
  'minLength', 'history', 'minSymbols', 'requireUppercase', 'requireDigit',
  'generatedLength', 'hashAlgorithm', 'argon2Memory', 'argon2Iterations',
  'argon2Parallelism', 'scryptLogN', 'scryptBlockSize', 'scryptParallelism'
]);

const AUTHN_PROFILE: Json = profileOf([
  'requireSecondFactor', 'requireSecondFactorForAdministrators',
  'rememberedBrowserDays', 'rememberedBrowserSkipsSecondFactor',
  'emailCodeTtlS', 'emailCodeAttempts', 'emailResendS', 'emailFailureLimit',
  'passwordPrimary', 'passwordSecondFactor', 'passkeyPrimary',
  'securityKeySecondFactor', 'totpSecondFactor', 'recoveryCodeSecondFactor',
  'emailCodePrimary', 'emailCodeSecondFactor', 'emailLinkPrimary',
  'emailLinkSecondFactor', 'certificatePrimary', 'kerberosPrimary',
  'walletPrimary', 'walletSecondFactor', 'federationPrimary'
]);

const SERVICE_ACCOUNT_PROFILE: Json = profileOf([
  'exemptFromSecondFactor', 'allowBrowserSignIn', 'allowLdapBind',
  'allowWsTrust', 'allowScim', 'allowSsf', 'allowEst', 'allowKerberos',
  'allowPasswordGrant', 'rotationEnabled', 'rotationIntervalDays',
  'rotationOverlapMinutes', 'generatedLength', 'requireOwner',
  'rotationAlarmFailures'
]);

const PASSKEY_PROFILE: Json = profileOf([
  'allowUsernameless', 'requireUsernameless', 'securityKeyResidentKey',
  'backupEligibility', 'enforcePinLength', 'minPinLength',
  'pinLengthOnlyIfSupported', 'enforceAttestationAtSignIn',
  'postQuantumRequired', 'postQuantumAllowCredentials',
  'registrationAlgorithms', 'registrationMode', 'lanes', 'clientRules',
  'passkeyHints', 'securityKeyHints', 'signInHints',
  'enterpriseSerialAttribute', 'userDisplayName', 'rpNameExtras',
  'credentialLabel', 'aggregateDevices', 'recoveryAssurance',
  'attestationAlgorithms', 'adminEnrolment', 'deviceBoundRequired'
]);

const LOCALE_PROFILE: Json = profileOf(['defaultLocale',
                                        'populatePreferredLanguage']);

const ATTRIBUTES_PROFILE: Json = profileOf(['requiredAttributes'],
                                           { required: STRS });

const POST_LOGIN_PROFILE: Json = profileOf([
  'enabled', 'activity', 'snoozeDays', 'graceDays', 'noPasskey', 'method',
  'attestation', 'noPasskeyFallback'
]);

// A `FIELDS` row with what the view reads beside it. The two that say why a
// row cannot be used are `authnPolicyExtras()`'s.
const POLICY_FIELD: Json = Kit.closed({
  key: STR, attribute: STR, label: STR, type: STR, min: NUM, max: NUM,
  values: Kit.listOf(SCALAR), unit: STR, empty: STR, default: VALUE,
  value: VALUE, source: NSTR, mechanism: STR, role: STR, email: BOOL, what: STR,
  disabled: BOOL, disabledWhy: STR
});

const SCHEMA_ROW: Json = Kit.listOf(Kit.closed({ name: STR, what: STR }));

const POLICY_SCHEMA: Json = Kit.closed({
  container: STR, definitionContainer: STR, objectClasses: SCHEMA_ROW,
  attributes: SCHEMA_ROW, personAttributes: SCHEMA_ROW
});

// `namedBy()` in each module; `policiesViewAsync()` adds `peopleComplete`.
const NAMED_BY: Json = Kit.closed({
  applications: STRS, groups: STRS, people: STRS, peopleComplete: BOOL
});

// `policyKindMember()`'s row, and the authentication policy's, which
// `authnPolicyExtras()` writes over it from `AuthnPolicy.named()`.
const NAMED_PROFILE: Json = Kit.closed({
  name: STR, dn: STR, description: STR, precedence: INT,
  selectApplications: STRS, selectGroups: STRS, namedBy: NAMED_BY, rules: STRS,
  fields: Kit.listOf(POLICY_FIELD), registrationAlgorithms: STRS,
  registrationMode: STR, mechanisms: STRS, secondFactors: STRS
});

function kindMember(profile: Json, extra?: Json): Json {
  return Kit.closed(Object.assign({
    profile: profile, rules: STRS, defaults: Kit.mapOf(VALUE),
    fields: Kit.listOf(POLICY_FIELD), schema: POLICY_SCHEMA, selectors: STRS,
    references: Kit.mapOf(STR), named: Kit.listOf(NAMED_PROFILE)
  }, extra || {}));
}

// `AuthnPolicy.named()`, as one act answers it.
const NAMED_AUTHN: Json = Kit.nullable(Kit.closed({
  name: STR, dn: STR, description: STR, precedence: INT, mechanisms: STRS,
  secondFactors: STRS
}));

// `AttributePolicy.definitions()`.
const ATTRIBUTE_DEFINITION: Json = Kit.closed({
  name: STR, label: STR, syntax: STR, multi: BOOL, description: STR,
  portalVisible: BOOL, portalEditable: BOOL, dn: STR
});

const POLICIES: Json = Kit.closed({
  mode: STR,
  kinds: Kit.listOf(Kit.closed({
    id: STR, label: STR, container: STR, governs: STR, tabbed: BOOL,
    profiles: INT, actions: STRS
  })),
  profiles: Kit.listOf(Kit.closed({
    kind: STR, name: STR, stored: BOOL, inherited: BOOL, dn: STR, problems: STRS
  })),
  paging: PAGING, actions: STRS, enforced: BOOL, enforcement: STR,
  password: kindMember(PASSWORD_PROFILE, {
    // `passwordPolicyExtras()`.
    generator: Kit.closed({
      module: STR, version: STR, source: STR, pools: STRS, excluded: STRS,
      drawsUntil: STR
    }),
    doors: Kit.listOf(Kit.closed({ door: STR, via: STR })),
    notDoors: STR
  }),
  authn: kindMember(AUTHN_PROFILE, {
    // `authnPolicyExtras()`.
    from: STR, inherited: BOOL, mail: Kit.closed({ usable: BOOL, why: STR }),
    nistWarning: STR,
    mechanisms: Kit.listOf(Kit.closed({
      id: STR, label: STR, email: BOOL, primary: NBOOL, secondFactor: NBOOL,
      active: BOOL, what: STR
    })),
    vocabulary: Kit.closed({ mechanisms: STRS, secondFactors: STRS })
  }),
  serviceAccount: kindMember(SERVICE_ACCOUNT_PROFILE),
  passkey: kindMember(PASSKEY_PROFILE, {
    // `PasskeyClients.view()`.
    clients: Kit.closed({
      learning: BOOL, threshold: INT, windowHours: NUM, bound: INT,
      learnedCount: INT,
      rows: Kit.listOf(Kit.closed({
        client: STR, learned: BOOL, learnedAt: STR, learnedFailures: INT,
        failures: INT, firstAt: STR, lastAt: STR
      })),
      paging: Kit.closed({ page: INT, per: INT, pages: INT, total: INT }),
      actions: Kit.closed({ clear: STR, clearAll: STR })
    })
  }),
  locale: kindMember(LOCALE_PROFILE),
  attributes: kindMember(ATTRIBUTES_PROFILE, {
    // `attributePolicyExtras()`.
    enforced: BOOL, alwaysRequired: STRS, required: STRS,
    catalogue: Kit.listOf(Kit.closed({
      name: STR, label: STR, schema: STR, custom: BOOL, locked: BOOL,
      required: BOOL
    })),
    custom: Kit.listOf(ATTRIBUTE_DEFINITION), maxCustom: INT,
    syntaxes: Kit.listOf(Kit.closed({ id: STR, what: STR })),
    missingFilter: STR, missingAsked: BOOL, missing: NINT,
    actions: Kit.closed({ define: STR, update: STR, remove: STR })
  }),
  postLogin: kindMember(POST_LOGIN_PROFILE)
});

// What `policiesAction()` answers for a save and for a reset, of one kind.
function saveOrReset(profile: Json): Json {
  return Kit.action({
    kind: STR, profile: profile, rules: STRS, enforced: BOOL, removed: BOOL
  });
}

// A refused act keeps everything the module's refusal carried
// (`Object.assign({}, result, ...)`), which is `holders` on a custom attribute
// somebody still holds.
const AUTHN_ACT: Json = Kit.action({
  kind: STR, policy: NAMED_AUTHN, dn: STR, removed: BOOL, name: STR
});

const PASSKEY_CLIENT_ACT: Json = Kit.action({
  kind: STR, action: STR, client: STR, removed: INT, dn: STR
});

const ATTRIBUTE_ACT: Json = Kit.action({
  kind: STR, definition: Kit.nullable(ATTRIBUTE_DEFINITION), name: STR, dn: STR,
  removed: BOOL, holders: INT
});

// ---------------------------------------------------------------------------
// CONSENT: `consentPageViewAsync()` and `consentPageView()` over
// `common/consent.ts`'s `register()`. The two differ in `search` and in what
// `counts` says.
// ---------------------------------------------------------------------------
const CONSENT: Json = Kit.closed({
  required: BOOL, storable: BOOL, attribute: STR, globalAttribute: STR,
  globals: Kit.listOf(Kit.closed({
    client: STR, clientName: STR, scope: STR, permission: STR, resource: STR,
    granted: BOOL
  })),
  users: Kit.listOf(Kit.closed({
    username: STR, dn: STR, scope: STR, client: STR, at: STR, raw: STR,
    unreadable: BOOL
  })),
  counts: Kit.closed({ globals: INT, consents: INT, people: INT,
                       unreadable: INT, countsOf: STR }),
  matched: INT, windowed: BOOL,
  // `recordedPageAsync()`: null, or the exact search over the holders.
  search: Kit.nullable(Kit.closed({
    exact: BOOL, q: STR, scanned: INT, scanLimit: INT, holders: INT,
    complete: BOOL
  })),
  globalsPaging: PAGING, usersPaging: PAGING, query: Kit.closed({ q: STR }),
  withdrawnAttribute: STR,
  applicationChoices: Kit.listOf(Kit.closed({ identifier: STR, name: STR }))
});

// ---------------------------------------------------------------------------
// AUTHZEN: `authzen/authzen_admin.ts`'s `view()` and `act()`, and
// `AccessRequests.viewOf()`.
// ---------------------------------------------------------------------------
const AUTHZEN_ROW: Json = Kit.closed({
  key: STR, object: STR, property: STR, attributeId: STR, category: STR,
  dataType: STR, multiplicity: STR, description: STR
});

// `callerOf()`, and `view()`'s two rows for a name it could not locate.
const AUTHZEN_CALLER: Json = Kit.closed({
  dn: STR, name: STR, kind: STR, applications: STRS, callbacks: STRS,
  member: BOOL
});

const AUTHZEN_BOUND: Json = Kit.freeForm(
  'What the AuthZEN caller sent at the denial, bound and relayed: the ' +
  'subject, resource and action objects carry properties of the caller\'s ' +
  'own naming, and this service states only that it kept them.');

const AUTHZEN_CONTEXT: Json = Kit.freeForm(
  'The members of the caller\'s AuthZEN context that the policy\'s advice ' +
  'named, each as the request carried it: a policy names them and a caller ' +
  'fills them, so neither key nor value is this service\'s vocabulary.');

const ACCESS_REQUEST: Json = Kit.closed({
  id: STR, status: STR, requester: STR,
  client: Kit.nullable(Kit.closed({ id: STR, name: STR })),
  application: NSTR, subject: AUTHZEN_BOUND, action: AUTHZEN_BOUND,
  resource: AUTHZEN_BOUND, context: AUTHZEN_CONTEXT, emergency: BOOL,
  justification: STR, createdAt: NUM, expiresAt: NUM, finishedAt: NUM,
  decidedBy: STR,
  approval: Kit.nullable(Kit.closed({
    id: STR, approvedAt: NUM, approvedUntil: NUM, approver: STR, revoked: BOOL
  })),
  approvers: Kit.closed({ roles: STRS, groups: STRS, owners: BOOL })
});

const AUTHZEN: Json = Kit.closed({
  realm: STR, enabled: BOOL, xacmlEnabled: BOOL, apiObject: BOOL,
  audience: STRS, callerAuthentication: STR, doors: STRS, role: STR, scope: STR,
  group: STR, settings: SETTINGS,
  catalogue: Kit.closed({
    rows: Kit.listOf(AUTHZEN_ROW), problems: STRS, objects: STRS,
    categories: STRS, dataTypes: STRS, multiplicities: STRS,
    reservedPrefix: STR, reservedContext: STRS
  }),
  callers: Kit.listOf(AUTHZEN_CALLER), callersTotal: INT,
  looked: Kit.nullable(AUTHZEN_CALLER),
  accessRequests: Kit.closed({
    enabled: BOOL, rows: Kit.listOf(ACCESS_REQUEST), maxCallbacks: INT
  }),
  protocolEndpoints: PROTOCOL_ENDPOINTS
});

// A write the registry refuses is passed up as it is, so an application's
// `updateApplication()` refusal is `{ ok, errors }` and is covered already.
const AUTHZEN_CATALOGUE_ACT: Json = Kit.action({
  changed: BOOL, replaced: BOOL, row: AUTHZEN_ROW, removed: STR
});

const AUTHZEN_CALLER_ACT: Json = Kit.action({
  changed: BOOL, caller: AUTHZEN_CALLER
});

const AUTHZEN_REQUEST_ACT: Json = Kit.action({
  changed: BOOL, task: ACCESS_REQUEST
});

// ---------------------------------------------------------------------------
// UMA: `uma/uma_console.ts`.
// ---------------------------------------------------------------------------
const UMA_PERMISSION_TEXT: Json = Kit.listOf(Kit.closed({
  resource: STR, name: STR, scopes: STRS
}));

const UMA_RESOURCE_SERVER: Json = Kit.closed({
  identifier: STR, name: STR, ownsResources: BOOL, protectionGranted: BOOL,
  resources: INT, rpts: INT, tickets: INT, pending: INT
});

function umaPaged(row: Json): Json {
  return Kit.closed({ total: INT, rows: Kit.listOf(row), paging: PAGING });
}

const UMA_RESOURCE_ROW: Json = Kit.closed({
  id: STR, name: STR, type: STR, scopes: STRS, resourceServer: STR, owner: STR,
  ownerKind: STR, createdAt: NUM
});

const UMA_PENDING_ROW: Json = Kit.closed({
  id: STR, state: STR, owner: STR, ownerKind: STR, requester: NSTR, client: STR,
  resourceServer: STR, permissions: UMA_PERMISSION_TEXT, createdAt: NUM,
  expiresAt: NUM
});

// `UmaOwnerPolicy.specOf()` and `withLabel()`.
const UMA_SHARE: Json = Kit.closed({
  id: STR, resourceId: STR, scopes: STRS,
  recipient: Kit.closed({ kind: STR, value: STR, claim: STR, label: STR }),
  expires: STR, acr: STR, askMe: BOOL
});

const UMA: Json = Kit.closed({
  page: STR, title: STR, enabled: BOOL, specifications: STRS,
  endpoints: Kit.freeForm(
    'The realm\'s RFC 8414 authorization server metadata with UMA\'s members ' +
    'added (`oauth2.asMetadata()`), or nothing when UMA is off. Its members ' +
    'are an IANA registry\'s and each is conditional on a setting, and ' +
    'GET /.well-known/uma2-configuration is where it is specified.'),
  resourceServers: Kit.listOf(UMA_RESOURCE_SERVER),
  filter: Kit.closed({ resourceServer: STR, owner: STR }),
  resources: umaPaged(UMA_RESOURCE_ROW),
  tickets: umaPaged(Kit.closed({
    key: STR, state: STR, resourceServer: STR, owner: STR,
    permissions: UMA_PERMISSION_TEXT, pending: STR, issuedAt: NUM,
    expiresAt: NUM
  })),
  rpts: umaPaged(Kit.closed({
    jti: STR, requestingParty: STR, client: STR, resourceServer: STR,
    permissions: UMA_PERMISSION_TEXT, upgradedFrom: STR, createdAt: NUM,
    exp: NUM
  })),
  pending: umaPaged(UMA_PENDING_ROW),
  // `ownerView()`: `{ found: false, asked }`, or the owner.
  owner: Kit.nullable(Kit.closed({
    found: BOOL, asked: STR, kind: STR, owner: STR, ownsResources: BOOL,
    editable: BOOL, resources: Kit.listOf(UMA_RESOURCE_ROW),
    // `UmaOwnerPolicy.view()`, both branches.
    document: Kit.closed({
      ok: BOOL, why: STR, stored: BOOL,
      version: Kit.oneOf(STR, NUM), rules: INT, shares: Kit.listOf(UMA_SHARE),
      custom: Kit.listOf(Kit.closed({ id: STR, description: STR, alfa: STR })),
      alfaEditing: BOOL, alfa: STR
    }),
    documentXml: STR, pending: Kit.listOf(UMA_PENDING_ROW)
  })),
  // `whatIf()`, all three of its answers.
  whatIf: Kit.nullable(Kit.closed({
    asked: Kit.closed({ resource: STR, scope: STR, party: STR, client: STR }),
    problem: STR, outcome: STR, code: STR,
    layers: Kit.listOf(Kit.closed({
      layer: STR, outcome: STR, policy: STR, decision: STR,
      missing: STRS, approval: BOOL, why: STR
    }))
  })),
  monitor: Kit.nullable(MONITOR_ROW), actions: STRS, settings: SETTINGS,
  protocolEndpoints: PROTOCOL_ENDPOINTS
});

const UMA_MONITOR: Json = Kit.closed({
  pep: Kit.nullable(MONITOR_ROW),
  resourceServers: Kit.listOf(UMA_RESOURCE_SERVER),
  totals: Kit.closed({ resources: INT, tickets: INT, rpts: INT, pending: INT })
});

// `act()`. `application` here is the identifier, not `APPLICATION`.
const UMA_APPLICATION_ACT: Json = Kit.action({
  application: STR, changed: BOOL, revoked: INT, ownsResources: BOOL
});

const UMA_RESOURCE_ACT: Json = Kit.action({ resource: STR, revoked: INT });

const UMA_RPT_ACT: Json = Kit.action({ rpt: STR, revoked: INT });

const UMA_SHARE_ACT: Json = Kit.action({
  owner: STR, share: UMA_SHARE, revoked: INT
});

// `UmaClaims.answer()` hands back the stored row as it is: `savePending()`'s
// members, whose `permissions` are the protocol's own two names.
const UMA_ANSWER_ACT: Json = Kit.action({
  owner: STR,
  pending: Kit.closed({
    id: STR, owner: STR, ownerKind: STR, requestingParty: STR, requester: NSTR,
    client: STR, resourceServer: STR, ticketKey: STR,
    permissions: Kit.listOf(Kit.closed({ resource_id: STR,
                                         resource_scopes: STRS })),
    state: STR, createdAt: NUM, updatedAt: NUM, expiresAt: NUM
  })
});

// ---------------------------------------------------------------------------
// THE OPERATIONS.
// ---------------------------------------------------------------------------
// The same model on several operations. Each action's `'200'` also serves its
// `'400'`: `Kit.applyModels()` says so, and each answers `ok` and `errors`.
function each(names: string[], model: Json): Json {
  const out: Json = {};
  names.forEach(function (name) {
    out[name] = { '200': model };
  });
  return out;
}

const XACML_ACTIONS: string[] = [
  'createXacmlPolicy', 'importXacmlAlfa', 'enableXacmlPolicy',
  'disableXacmlPolicy', 'setXacmlRootPolicy', 'deleteXacmlPolicy',
  'editXacmlPolicy', 'addXacmlRule', 'editXacmlMatch', 'removeXacmlNode',
  'addXacmlTargetClause', 'addXacmlAlternative', 'addXacmlMatch',
  'editXacmlRule', 'addXacmlCondition', 'setXacmlApply', 'setXacmlValue',
  'setXacmlDesignator', 'setXacmlVariable', 'addXacmlArgument',
  'editXacmlApply', 'editXacmlValue', 'editXacmlDesignator',
  'addXacmlRuleObligation', 'addXacmlPolicyObligation', 'addXacmlRuleAdvice',
  'addXacmlPolicyAdvice', 'editXacmlObligation', 'addXacmlAssignment',
  'addXacmlPolicyToSet', 'addXacmlPolicySetToSet', 'addXacmlPolicyReference',
  'addXacmlPolicySetReference', 'editXacmlReference', 'addXacmlVariable',
  'renameXacmlVariable', 'setXacmlExpressionSelector', 'editXacmlSelector',
  'setXacmlExpressionFunction', 'editXacmlFunctionReference',
  'editXacmlAssignment', 'disableXacmlPep', 'enableXacmlPep', 'forgetXacmlPep'
];

export = {
  // Named because `admin_api.ts`'s rows name them. None is a request body.
  components: {
    Xacml: XACML,
    XacmlPolicies: XACML_POLICIES,
    XacmlEditor: XACML_EDITOR,
    XacmlDecision: XACML_DECISION,
    XacmlMonitor: XACML_MONITOR,
    XacmlPeps: XACML_PEPS,
    DelegationList: DELEGATION_LIST
  } as Record<string, unknown>,
  operations: Object.assign(
    each(XACML_ACTIONS, XACML_ACTION),
    each(['setPermissionBase', 'definePermission', 'removePermission',
          'grantPermission', 'revokePermission'], PERMISSION_ACTION),
    each(['grantGlobalConsent', 'revokeGlobalConsent', 'revokeConsent',
          'revokeApplicationConsent', 'forgetUserConsent'], CONSENT_ACTION),
    each(['savePasswordPolicy', 'resetPasswordPolicy'],
         saveOrReset(PASSWORD_PROFILE)),
    each(['saveAuthnPolicy', 'resetAuthnPolicy'],
         saveOrReset(AUTHN_PROFILE)),
    each(['saveServiceAccountPolicy', 'resetServiceAccountPolicy'],
         saveOrReset(SERVICE_ACCOUNT_PROFILE)),
    each(['savePasskeyPolicy', 'resetPasskeyPolicy'],
         saveOrReset(PASSKEY_PROFILE)),
    each(['saveLocalePolicy', 'resetLocalePolicy'],
         saveOrReset(LOCALE_PROFILE)),
    each(['saveAttributesPolicy', 'resetAttributesPolicy'],
         saveOrReset(ATTRIBUTES_PROFILE)),
    each(['savePostLoginPolicy', 'resetPostLoginPolicy'],
         saveOrReset(POST_LOGIN_PROFILE)),
    each(['saveNamedAuthnPolicy', 'deleteNamedAuthnPolicy'], AUTHN_ACT),
    each(['clearPasskeyClient', 'clearPasskeyClients'], PASSKEY_CLIENT_ACT),
    each(['definePersonAttribute', 'updatePersonAttribute',
          'removePersonAttribute'], ATTRIBUTE_ACT),
    each(['setAuthzenAttribute', 'removeAuthzenAttribute'],
         AUTHZEN_CATALOGUE_ACT),
    each(['setAuthzenScope', 'setAuthzenCallbacks'], AUTHZEN_CALLER_ACT),
    each(['approveAuthzenAccessRequest', 'denyAuthzenAccessRequest',
          'revokeAuthzenAccessRequest', 'cancelAuthzenAccessRequest'],
         AUTHZEN_REQUEST_ACT),
    each(['enableUmaResourceServer', 'disableUmaResourceServer',
          'setUmaOwnsResources'], UMA_APPLICATION_ACT),
    each(['shareUmaResource', 'unshareUmaResource'], UMA_SHARE_ACT),
    each(['approveUmaRequest', 'refuseUmaRequest'], UMA_ANSWER_ACT),
    {
      issueXacmlPepCertificate: { '200': XACML_ISSUE },
      deleteUmaResource: { '200': UMA_RESOURCE_ACT },
      revokeUmaRpt: { '200': UMA_RPT_ACT },
      // The view is `DelegationList`; the gate may refuse a read 400.
      getDelegation: { '400': GET_REFUSAL },
      getDelegationUser: {
        '200': Object.assign(Kit.media('image/svg+xml'),
                             { schema: DELEGATION_USER })
      },
      getDelegationApplication: {
        '200': Object.assign(Kit.media('image/svg+xml'),
                             { schema: DELEGATION_APPLICATION_PAGE })
      },
      getDelegationPolicy: { '200': EXCHANGE_POLICY },
      getPermissions: { '200': PERMISSIONS },
      getPermissionGroups: { '200': PERMISSION_GROUPS },
      getPolicies: { '200': POLICIES, '400': GET_REFUSAL },
      getConsent: { '200': CONSENT },
      getXacmlAuthzen: { '200': AUTHZEN },
      getUma: { '200': UMA },
      getUmaMonitor: { '200': UMA_MONITOR }
    }
  ) as Record<string, Record<string, unknown>>
};
