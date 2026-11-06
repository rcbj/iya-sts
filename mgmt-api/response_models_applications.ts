// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_applications.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): Applications, OAuth 2.0 / OIDC, Tokens,
// Authorization servers, OpenID4VCI, OpenID4VP, Verifier request, Credential
// claims, Credential status, Token lifetimes.
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
//
// **EVERY MODEL HERE IS THE UNION OF WHAT THE BRANCHES BEHIND ITS OPERATION CAN
// SEND, READ FROM THE CODE**, because an answer that fails its model is not
// sent. Traffic is a lower bound and was used only to check the reading.
//
// **A VALUE THAT COMES OUT OF A TOKEN'S CLAIMS IS NOT THIS SERVICE'S TO TYPE.**
// `recordJwt()` copies `client_id || azp || aud` and an `aud` may be an array
// (RFC 7519 section 4.1.3), and a configured custom claim may carry a number or
// a list under a name the record reads. Those members are `CLAIM_VALUE`.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

const STR = Kit.str();
const INT = Kit.int();
const NUM = Kit.num();
const BOOL = Kit.bool();
const STRS = Kit.listOf(STR);
const NULL_STR = Kit.nullable(STR);
const NULL_NUM = Kit.nullable(NUM);
const NULL_BOOL = Kit.nullable(BOOL);

// A value of one of a person's or a token's claims: never an object here,
// because every reader of these records treats it as a name.
const CLAIM_VALUE = Kit.oneOf(STR, NUM, BOOL, { type: 'null' }, Kit.listOf(
  Kit.oneOf(STR, NUM, BOOL)));

// What a page's JSON says about its paging, `pagingJson()`.
const PAGING = Kit.closed({
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT, total: INT,
  param: STR, noun: STR
});

// The same members flattened into an answer beside its rows.
const FLAT_PAGING = {
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT
};

// `protocolEndpoints`: `sendJson()` adds it to a GET mirroring a Protocols page
// outside the view (`admin_api_spec.ts` says it too, for the models it can
// read).
const PROTOCOL_ENDPOINTS = Kit.listOf(Kit.closed({
  name: STR, methods: Kit.oneOrMany(STR), url: STR, route: STR, transport: STR,
  registered: BOOL
}));

// ---------------------------------------------------------------------------
// ONE SETTING, `common/config.js`'s `describe()`. A setting's value is what its
// row's type parses to: bool, int, string, or a `csv`'s list. `default` is the
// row's `dflt`, which a function may compute and which may be null.
// ---------------------------------------------------------------------------
const SETTING_VALUE = Kit.oneOf(STR, NUM, BOOL, { type: 'null' }, STRS);

const SELECT_ALL_RULE = Kit.listOf(Kit.closed({
  setting: STR, values: STRS, on: BOOL, canBeOn: BOOL
}));

const SETTING = Kit.closed({
  key: STR, group: STR, label: STR, description: STR, type: STR,
  enumValues: STRS, csvValues: STRS, ordered: BOOL,
  csvValueNotes: Kit.mapOf(STR,
  'The sentence beside each of a list\'s values.'),
  selectAll: Kit.closed({
    onlyWhileOn: SELECT_ALL_RULE, aloneWhileOn: SELECT_ALL_RULE
  }),
  min: NUM, max: NUM, step: NUM,
  value: SETTING_VALUE, text: STR, source: STR, editable: BOOL,
  restartReason: STR, editRefusal: STR, env: NULL_STR, legacyEnv: NULL_STR,
  appconfigPath: STR, default: SETTING_VALUE, realmSettable: BOOL,
  overridden: BOOL
});

const SETTINGS_CONTEXT = Kit.closed({
  configFile: NULL_STR, defaultsFile: NULL_STR, persistsAppconfig: BOOL,
  persistsRealms: BOOL, persistenceMode: STR, inRealm: BOOL, realmId: STR
});

// `configSettingsJson()`: what every page that owns settings answers.
const SETTINGS_BLOCK = Kit.closed({
  page: STR,
  groups: Kit.listOf(Kit.closed({ group: STR, settings: Kit.listOf(SETTING) })),
  settingCount: INT, editableCount: INT, overridden: STRS, setWith: STR,
  context: SETTINGS_CONTEXT,
  sharedWith: Kit.mapOf(Kit.listOf(Kit.closed({ path: STR, label: STR })),
                        'The other pages each settings group is drawn on.')
});

// `protocolSettingsJson()`, for the three protocol settings pages in this
// family. None of those three rows has a `status` block. A model of their own
// rather than `PageSettings`, whose other pages carry other status blocks.
const PROTOCOL_SETTINGS_PAGE = Kit.closed({
  page: STR, title: STR, what: STR, notes: STRS,
  links: Kit.listOf(Kit.closed({ href: STR, what: STR })),
  settings: SETTINGS_BLOCK, leadHtml: STR, alsoHtml: STRS,
  protocolEndpoints: PROTOCOL_ENDPOINTS
});

// ---------------------------------------------------------------------------
// WHAT WAS ISSUED: `issuedList()` in `common/admin_stats.js`.
//
// THE MEMBERS OF A ROW DEPEND ON ITS FAMILY: a token row is `recordJwt()`'s and
// an artifact's is `recordArtifact()`'s, and they share few. `IssuedRecord` is
// read by `tests/protocol/admin_api.js`, which holds that every name in
// `properties` is on a live row of the list (a token row, the kind that job has
// just minted). So `properties` keeps what every token row carries, and what
// only some rows carry is `patternProperties`, one exact name each: as closed
// to `additionalProperties: false` as a declared member, and honest about being
// conditional.
// ---------------------------------------------------------------------------
const exactly = function (members: Json): Json {
  const out: Json = {};
  Object.keys(members).forEach(function (name) {
    out['^' + name + '$'] = members[name];
  });
  return out;
};

const ISSUED_RECORD: Json = Object.assign(Kit.closed({
  family: Kit.str('token, assertion, ticket or svid: what the `family` ' +
                  'filter takes.'),
  kind: Kit.str('access_token, id_token, refresh_token, a SAML assertion ' +
                'version, a Kerberos ticket type or an SVID type.'),
  state: Kit.str('valid, expired, revoked, "not yet valid" or "no expiry ' +
                 'stated".'),
  jti: CLAIM_VALUE,
  sub: CLAIM_VALUE,
  username: CLAIM_VALUE,
  typ: CLAIM_VALUE,
  issuedAt: NUM,
  expiresAtMs: NULL_NUM,
  revocable: BOOL,
  revoked: BOOL,
  revokedAt: NULL_NUM,
  revokedVia: STR,
  sessionId: STR,
  setId: STR,
  jkt: STR,
  grant: STR,
  client_id: CLAIM_VALUE,
  scope: CLAIM_VALUE,
  identifier: CLAIM_VALUE,
  length: INT,
  key: STR,
  iat: NUM,
  nbf: NUM,
  exp: NUM
}, { description: 'One thing this service issued and still remembers. Claims ' +
                  'and facts only: the signed token, the assertion XML and ' +
                  'the ticket are deliberately not kept.' }), {
  patternProperties: exactly({
    // On every token row, and on no artifact's unless it says so below.
    iss: CLAIM_VALUE, audience: STR, x5t: STR, x5tSpki: STR,
    sessionAuthenticated: BOOL, grantId: STR, grantRefresh: BOOL, order: INT,
    revocationReach: STR,
    // `recordArtifact()`, and each of its four families' own.
    expiresAt: NUM, subject: STR, id: STR, signed: BOOL, realm: STR,
    service: STR, etype: Kit.oneOf(STR, NUM), claimSet: STR, pacClaims: NUM,
    entryId: STR, serial: STR, hint: STR, person: STR, configId: STR
  })
});

const REF_ISSUED_RECORD = { $ref: '#/components/schemas/IssuedRecord' };

const ISSUED_SET: Json = Kit.closed({
  setKey: STR, setId: STR, grouped: BOOL, size: INT, kinds: STRS,
  families: STRS, family: STR, state: STR,
  states: Kit.mapOf(INT, 'How many members are in each state.'),
  issuedAt: NUM, expiresAtMs: NUM, lastExpiresAtMs: NUM,
  username: CLAIM_VALUE, sub: CLAIM_VALUE, client_id: CLAIM_VALUE,
  audience: STR, scope: CLAIM_VALUE, sessionId: STR,
  sessionAuthenticated: BOOL, grant: STR, revocableCount: INT,
  revokedCount: INT, members: Kit.listOf(REF_ISSUED_RECORD)
}, { description: 'One issuance: everything that came back in a single reply.'
});

const REF_ISSUED_SET = { $ref: '#/components/schemas/IssuedSet' };

const ISSUED_LIST: Json = Kit.closed(Object.assign({
  held: INT, heldSets: INT,
  coverage: Kit.closed({
    source: STR, complete: BOOL, newest: NULL_NUM, session: NULL_STR,
    unread: BOOL, countEstimated: BOOL
  }),
  matched: INT, matchedCredentials: INT, shown: INT, shownCredentials: INT,
  heldByFamily: Kit.mapOf(INT, 'Credentials held in each family.'),
  filter: Kit.closed({
    family: NULL_STR, kind: NULL_STR, state: NULL_STR, session: NULL_STR
  }),
  families: Kit.listOf(Kit.closed({
    family: STR, label: STR, kinds: STRS, what: STR
  })),
  revocableKinds: STRS, revokedCount: INT,
  sets: Kit.listOf(REF_ISSUED_SET),
  issued: Kit.listOf(REF_ISSUED_RECORD),
  paging: PAGING
}, FLAT_PAGING));

const ISSUED_SET_DETAIL: Json = Kit.closed({
  setKey: NULL_STR, set: Kit.nullable(REF_ISSUED_SET), found: BOOL,
  why: NULL_STR
});

// ---------------------------------------------------------------------------
// A CREDENTIAL'S LINEAGE: `credentialLineageModel()`, over the delegation
// store's acts (`common/delegation.js`) and `common/credential_graph.ts`, whose
// graph is `delegation.graph()`'s with its own nodes and edges added.
// ---------------------------------------------------------------------------
const PARTY = Kit.closed({
  key: STR, presented: STR, application: STR, what: STR
});

const ACT_CREDENTIAL = Kit.closed({ kind: STR, identifier: STR, note: STR });

const DELEGATION_ACT = Kit.closed({
  seq: NUM, origin: Kit.oneOf(STR, NUM, { type: 'null' }), at: NUM,
  protocol: STR, type: STR, typeLabel: STR, mode: STR, spec: STR, policed: BOOL,
  outcome: STR, initial: PARTY, intermediary: PARTY, target: PARTY,
  authorizedBy: STR, reason: STR, consumed: Kit.listOf(ACT_CREDENTIAL),
  produced: Kit.listOf(ACT_CREDENTIAL), sessionId: STR, note: STR, chainKey: STR
});

const GRAPH_REALM = Kit.closed({ id: STR, name: STR, isDefault: BOOL });

const GRAPH_NODE = Kit.closed({
  id: STR, kind: STR, realm: GRAPH_REALM, issuer: STR,
  roles: Kit.closed({ initial: INT, intermediary: INT, target: INT }),
  acts: INT, issued: INT, refused: INT, credentials: INT, flows: STRS,
  kinds: STRS, authentications: INT, key: STR, presented: STR,
  application: STR, aliases: STRS, what: STR, protocols: STRS, firstAt: NUM,
  lastAt: NUM, selfTarget: BOOL, chiefRole: STR
});

const FOLDED_CREDENTIAL = Kit.closed({
  kind: STR, count: INT, identifiers: STRS, moreIdentifiers: INT, notes: STRS
});

const GRAPH_EDGE = Kit.closed({
  id: STR, acts: INT, issued: INT, refused: INT, credentials: INT,
  firstAt: NUM, lastAt: NUM, authorizedBy: STR, reason: STR,
  consumed: Kit.listOf(FOLDED_CREDENTIAL),
  produced: Kit.listOf(FOLDED_CREDENTIAL),
  skipped: STRS, chainKey: STR, protocols: STRS, protocol: STR, type: STR,
  typeLabel: STR, mode: STR, spec: STR, policed: BOOL, subject: STR, actor: STR,
  from: STR, to: STR, fromRole: STR, toRole: STR, relation: STR,
  audience: STR, audienceRegistered: BOOL, permissions: STRS, scopes: STRS,
  attribute: STR, mechanism: STR, setOn: STR, used: BOOL
});

const GRAPH_TOKEN = Kit.closed({
  seq: NUM, at: NUM, kind: STR, identifier: STR, note: STR, protocol: STR,
  type: STR, typeLabel: STR, mode: STR, chainKey: STR, subject: STR, actor: STR,
  target: STR
});

const GRAPH = Kit.closed({
  realm: GRAPH_REALM, issuer: STR, nodes: Kit.listOf(GRAPH_NODE),
  edges: Kit.listOf(GRAPH_EDGE), tokens: Kit.listOf(GRAPH_TOKEN),
  tokensLeftOff: INT, maxTokenRows: INT, acts: INT, chains: INT
});

const NODE_LOOK = Kit.closed({
  shape: STR, label: STR, sublabel: STR, identifier: STR, title: STR, href: STR,
  dashed: BOOL
});

// `userGraph.flowRow()` or `artifactFlowRow()`: their rows and placeholders.
const FLOW_ROW = Kit.closed({
  flow: STR, match: STR, protocol: STR, label: STR, oidc: STR, spec: STR,
  browser: BOOL, unknown: BOOL, what: STR
});

const AUDIENCE_PARTY = Kit.closed({
  identifier: STR, audience: STR, registered: BOOL
});

const CREDENTIAL_LINEAGE = Kit.closed({
  identifier: NULL_STR, held: NULL_BOOL,
  credential: Kit.nullable(REF_ISSUED_RECORD),
  counts: Kit.nullable(Kit.closed({
    generations: INT, acts: INT, exchanges: INT, parties: INT
  })),
  generations: Kit.listOf(Kit.closed({
    identifier: STR, generation: INT,
    credential: Kit.nullable(REF_ISSUED_RECORD),
    act: Kit.nullable(DELEGATION_ACT), producedByExchange: BOOL,
    consumed: Kit.listOf(ACT_CREDENTIAL), opaque: Kit.listOf(ACT_CREDENTIAL),
    holder: STR, originLabel: STR
  })),
  origins: STRS,
  issuances: Kit.listOf(Kit.closed({
    identifier: STR, credential: REF_ISSUED_RECORD, flow: FLOW_ROW,
    subject: STR, holder: STR, audience: AUDIENCE_PARTY,
    audiences: Kit.listOf(AUDIENCE_PARTY)
  })),
  walls: Kit.listOf(Kit.closed({
    identifier: STR, act: DELEGATION_ACT, credential: ACT_CREDENTIAL
  })),
  truncated: BOOL, acts: Kit.listOf(DELEGATION_ACT), graph: GRAPH,
  maxGenerations: INT,
  drawing: Kit.closed({ width: NUM, height: NUM, failed: NULL_STR }),
  looks: Kit.mapOf(NODE_LOOK, 'How each node of the graph is drawn.'),
  label: STR, svg: STR, subjectKey: STR,
  facts: Kit.closed({
    users: Kit.mapOf(BOOL, 'Who in the answer has a user page.'),
    apps: Kit.mapOf(Kit.closed({ name: STR, dnLabel: STR }),
                    'Which values in the answer are applications.')
  })
});

// ---------------------------------------------------------------------------
// THE TEN TOKEN ACTIONS, `tokenAction()`. One action's `revoked` is a count;
// the
// `set` member of the set actions is the key that was asked for.
// ---------------------------------------------------------------------------
const TOKEN_SET_ACTION = Kit.action({
  setKey: STR, set: STR, revocable: INT, revoked: INT, restored: INT,
  reachedProtocol: INT, recordOnly: INT, kinds: STRS
});

const TOKEN_ARTIFACT_ACTION = Kit.action({
  artifact: STR, kind: STR, revocationReach: STR
});

const TOKEN_COUNT_ACTION = Kit.action({ revoked: INT, user: STR });

// ---------------------------------------------------------------------------
// USED ASSERTIONS, `usedAssertionsView()` over `common/used_assertions.js`.
// ---------------------------------------------------------------------------
const USED_ASSERTIONS = Kit.closed(Object.assign({
  store: STR, persistent: BOOL, atomicAcrossProcesses: BOOL, storeNote: STR,
  cap: NUM, live: NUM, matched: INT, shown: INT, searchNote: STR,
  filter: Kit.closed({ q: STR, format: STR, use: STR, state: STR }),
  formats: Kit.mapOf(STR, 'Each format and what it is called.'),
  uses: Kit.mapOf(STR, 'Each use and what it is called.'),
  states: Kit.mapOf(STR, 'Each state and what it means.'),
  rows: Kit.listOf(Kit.closed({
    format: STR, formatLabel: STR, use: STR, useLabel: STR, issuer: STR,
    identifier: STR, clientId: STR, subject: STR, state: STR, usedAt: NUM,
    spentAt: NUM, expiresAt: NUM, origin: STR
  })),
  paging: PAGING, total: INT, param: STR, noun: STR
}, FLAT_PAGING));

// ---------------------------------------------------------------------------
// CREDENTIAL STATUS, `vcStatus.summary()` and `statusAction()`.
// ---------------------------------------------------------------------------
const CREDENTIAL_STATUS = Kit.closed({
  size: INT, bits: INT, tokenStatusList: STR, aggregation: STR,
  bitstring: STRS, ttlS: NUM, lifetimeS: NUM, allocated: INT, valid: INT,
  invalid: INT, suspended: INT,
  rows: Kit.listOf(Kit.closed({
    idx: INT, format: STR, configId: STR, artifactKey: NULL_STR, status: STR,
    explicit: STR, expiresAt: NULL_NUM, allocatedAt: NUM,
    changedAt: NULL_NUM, via: NULL_STR
  })),
  rowsPaging: PAGING
});

const STATUS_CHANGE = Kit.action({ idx: INT, status: STR });

// ---------------------------------------------------------------------------
// TOKEN LIFETIMES.
// ---------------------------------------------------------------------------
const TOKEN_LIFETIMES: Json = Kit.closed({
  lifetimes: Kit.closed({
    accessTokenTtlS: NUM, idTokenTtlS: NUM, refreshTokenTtlS: NUM,
    clockSkewS: NUM
  }),
  settings: Kit.listOf(SETTING),
  tokens: Kit.closed({
    held: INT, forgotten: INT, cap: NUM, revoked: INT,
    byKind: Kit.listOf(Kit.closed({
      kind: STR, issued: INT, valid: INT, expired: INT, revoked: INT,
      notYetValid: INT, noExpiry: INT, bound: INT
    }))
  }),
  now: NUM,
  context: Kit.nullable(SETTINGS_CONTEXT),
  overridable: Kit.listOf(Kit.closed({ setting: STR, attribute: STR }))
});

// ---------------------------------------------------------------------------
// WHAT A CREDENTIAL CARRIES: `vcJson()` and `vcAction()`.
//
// A subject's claims are the catalogue's (`VC_ATTRIBUTES`), one level of
// nesting
// at most (`address`, `place_of_birth`), and each value a directory value or a
// generated one: never deeper.
// ---------------------------------------------------------------------------
const NESTED_CLAIM = Kit.oneOf(CLAIM_VALUE, Kit.mapOf(CLAIM_VALUE,
  'A claim\'s members, as `address` has.'));

const CREDENTIAL_CLAIMS: Json = Kit.closed({
  selected: STRS, defaults: STRS, ldpOmitted: STRS,
  attributes: Kit.listOf(Kit.closed({
    ldap: STR, claim: STR, label: STR, schema: STR, ldpTerm: STR,
    selected: BOOL,
    example: Kit.closed({ value: CLAIM_VALUE, source: STR })
  })),
  protocolEndpoints: PROTOCOL_ENDPOINTS,
  preview: Kit.closed({
    user: STR,
    claims: Kit.closed({
      claims: Kit.mapOf(NESTED_CLAIM, 'The credential subject\'s claims.'),
      report: Kit.listOf(Kit.closed({
        ldap: STR, claim: STR, value: CLAIM_VALUE, source: STR,
        ldpTerm: NULL_STR
      })),
      entryFound: BOOL
    })
  })
});

// `populateDirectory()`.
const SWEEP = Kit.closed({
  ok: BOOL, loaded: BOOL, examined: INT, changed: INT, values: INT,
  attributes: STRS, skipped: Kit.oneOf(BOOL, STR), errors: STRS
});

const CLAIM_SELECTION = Kit.action({
  selected: STRS, added: STRS, removed: STRS, sweep: SWEEP
});

// ---------------------------------------------------------------------------
// WHAT THE VERIFIER ASKS FOR: `vpConfigJson()`, `vpConfigAction()`, and what
// `vc_verifier.ts` keeps of each presentation.
//
// A DCQL query here is always one this service built (`dcqlQuery()`,
// `signInDcqlQuery()`): no caller supplies one. `type_values` holds a list per
// entry for a JWT VC, whose identifier is itself a list.
// ---------------------------------------------------------------------------
const DCQL_QUERY = Kit.closed({
  credentials: Kit.listOf(Kit.closed({
    id: STR, format: STR,
    meta: Kit.closed({
      vct_values: Kit.listOf(STR), doctype_value: STR,
      type_values: Kit.listOf(Kit.oneOrMany(STR))
    }),
    require_cryptographic_holder_binding: BOOL,
    claims: Kit.listOf(Kit.closed({ path: STRS }))
  })),
  credential_sets: Kit.listOf(Kit.closed({
    options: Kit.listOf(STRS), required: BOOL
  }))
});

const RECENT_VERIFICATIONS = {
  verifications: Kit.listOf(Kit.closed({
    state: STR, format: STR, responseType: STR, responseMode: STR,
    byReference: BOOL, clientId: STR, requested: STRS, expiresAt: STR,
    received: BOOL, ok: NULL_BOOL, decidedAt: NULL_STR, claims: STRS,
    failedChecks: STRS, error: STR
  })),
  total: INT, limit: INT
};

const VERIFIER_REQUEST: Json = Kit.closed({
  protocolEndpoints: PROTOCOL_ENDPOINTS,
  requested: STRS, defaults: STRS, format: STR,
  formats: Kit.listOf(Kit.closed({
    id: STR, label: STR, identifiedBy: STR, identifier: Kit.oneOrMany(STR),
    selectiveDisclosure: STR, holderBinding: STR, configurations: STRS,
    identifierText: STR, what: STR
  })),
  ldpOmitted: STRS,
  catalogue: Kit.listOf(Kit.closed({
    claim: STR, label: STR, nested: BOOL,
    attributes: Kit.listOf(Kit.closed({ ldap: STR, schema: STR })),
    ldpTerms: STRS, paths: Kit.listOf(STRS), requested: BOOL,
    issued: Kit.closed({ known: BOOL, carried: STRS, missing: STRS })
  })),
  dcqlQuery: DCQL_QUERY,
  extras: Kit.listOf(Kit.closed({ claim: STR, paths: Kit.listOf(STRS) })),
  recentVerifications: Kit.closed(RECENT_VERIFICATIONS),
  startChoices: Kit.closed({
    format: STRS, by: STRS, mode: STRS, response_type: STRS,
    response_mode: STRS, client_id_prefix: STRS
  })
});

const REQUESTED_CLAIMS = Kit.action({
  requested: STRS, added: STRS, removed: STRS, format: STR
});

const PRESENTED_CLAIMS = Kit.freeForm(
  'What a holder\'s wallet disclosed from a credential, which may be another ' +
  'issuer\'s: its names and values are the presentation\'s, not this ' +
  'service\'s.');

const VERDICT_CHECK = Kit.closed({
  name: STR, ok: BOOL, detail: CLAIM_VALUE
});

// `record.verdict`: a declined answer, a malformed one, a verified one, or a
// self-issued ID Token's, at the four places `vc_verifier.ts` writes it.
const VERDICT = Kit.closed({
  ok: BOOL, refused: BOOL, error: STR, errorDescription: STR,
  checks: Kit.listOf(VERDICT_CHECK), at: STR, claims: PRESENTED_CLAIMS,
  disclosed: Kit.listOf(CLAIM_VALUE), extraDisclosed: Kit.listOf(CLAIM_VALUE),
  requested: STRS, vct: CLAIM_VALUE, sub: CLAIM_VALUE, format: STR,
  presentationDigest: CLAIM_VALUE,
  selfIssued: Kit.closed({ subject: CLAIM_VALUE, claims: PRESENTED_CLAIMS })
});

// The open list, or one presentation by its `state`.
const VERIFICATIONS: Json = Kit.closed(Object.assign({}, RECENT_VERIFICATIONS, {
  protocolEndpoints: PROTOCOL_ENDPOINTS,
  found: BOOL, state: STR, nonce: STR, client_id: STR, requested: STRS,
  dcql_query: DCQL_QUERY, received: BOOL, verdict: Kit.nullable(VERDICT)
}));

const VERIFICATION_NOT_FOUND = Kit.closed({
  ok: BOOL, found: BOOL, state: STR, errors: STRS
});

const VERIFICATION_STARTED = Kit.action({
  state: STR, nonce: STR, mode: STR, format: STR, responseType: STR,
  responseMode: STR, byReference: BOOL, clientId: STR, requested: STRS,
  dcql_query: DCQL_QUERY, expiresAt: STR, wallet: STR, walletUrl: STR,
  requestUri: STR, query: STR, redirectUri: NULL_STR, request_uri: STR
});

// ---------------------------------------------------------------------------
// OPENID4VCI: what the credential issuer saw. `event_description` is the
// wallet's own word, kept as it arrived.
// ---------------------------------------------------------------------------
const LAST_CREDENTIAL_REQUEST = Kit.closed({
  seen: BOOL, encrypted: BOOL, path: STR, contentType: NULL_STR, kid: NULL_STR,
  alg: NULL_STR, enc: NULL_STR, at: STR
}, { required: ['seen'] });

const CREDENTIAL_NOTIFICATION = Kit.closed({
  notification_id: STR, event: NULL_STR, event_description: CLAIM_VALUE,
  notified_at: Kit.oneOf(STR, NUM, { type: 'null' })
});

// ---------------------------------------------------------------------------
// AUTHORIZATION SERVERS, `oauth-oidc/authorization_servers.ts`.
//
// `overrides`, a drift row's `published` and `actual`, and `capabilities` are
// free-form for the reason that module's catalogue is "help, not schema": any
// member name may be set to any JSON value (`setMember()` parses what it is
// given), so that a document a client did not expect can be published.
// ---------------------------------------------------------------------------
const PUBLISHED_VALUE = Kit.freeForm(
  'An RFC 8414 metadata member\'s value as the operator chose to publish it: ' +
  'any JSON, deliberately, including what no specification defines.');

const AS_MEMBER = Kit.closed({
  name: STR, group: STR, kind: STR, what: STR, enforces: STR, document: STR
});

const AS_PROFILE_MEMBERS = {
  id: STR, label: STR, description: STR,
  overrides: Kit.mapOf(PUBLISHED_VALUE, 'The members this server overrides.'),
  removed: STRS, changedAt: STR, memberCount: INT, autoCreated: BOOL,
  seen: NUM, seenAt: STR, createdAt: STR,
  urls: Kit.closed({ oauth: STR, oidc: STR, authorize: STR, token: STR })
};

const AS_PROFILE = Kit.closed(AS_PROFILE_MEMBERS);

const AS_DRIFT = Kit.listOf(Kit.closed({
  member: STR, published: PUBLISHED_VALUE, actual: PUBLISHED_VALUE, kind: STR,
  what: STR
}));

const AS_LIST = Kit.closed(Object.assign({
  profileCount: INT, shown: INT, members: Kit.listOf(AS_MEMBER), paging: PAGING,
  overrideTotal: INT, driftTotal: INT,
  authorizationServers: Kit.listOf(Kit.closed(Object.assign({},
  AS_PROFILE_MEMBERS,
    { drift: AS_DRIFT })))
}, FLAT_PAGING));

const AS_DETAIL = Kit.closed(Object.assign({}, AS_PROFILE_MEMBERS, {
  found: BOOL, drift: AS_DRIFT,
  capabilities: Kit.freeForm(
    'The RFC 8414 document this server would publish: what this service ' +
    'builds, with the operator\'s overrides, whose values are any JSON.'),
  members: Kit.listOf(AS_MEMBER), memberGroups: STRS
}));

// The list, or one profile: one closed object, as `APPLICATION_LIST` says
// below.
const AUTHORIZATION_SERVER_LIST: Json = Kit.closed(Object.assign({},
  AS_LIST.properties, AS_DETAIL.properties));

const AS_ACTION = Kit.action({ profile: Kit.nullable(AS_PROFILE) });

// ---------------------------------------------------------------------------
// THE OAUTH 2.0 / OIDC MONITOR, `oauth2_monitor_console.ts` over `par.ts`.
//
// A pushed request's `parameters` are what the client pushed, a request
// object's
// claims among them: its names and values are the client's.
// ---------------------------------------------------------------------------
const ERROR_COUNT = Kit.listOf(Kit.closed({ name: STR, count: INT }));

const PUSHED_REQUEST = Kit.closed({
  request_uri_digest: STR, request_uri_shown: STR, client_id: CLAIM_VALUE,
  authorization_server: CLAIM_VALUE, state: STR, created_at: STR,
  expires_at: STR,
  expires_in: INT, spent_at: NULL_STR, reads: INT, client_authenticated: BOOL,
  authentication_method: STR, source: CLAIM_VALUE,
  request_object_alg: CLAIM_VALUE, request_object_encrypted: CLAIM_VALUE,
  dpop_jkt: STR, attested_jkt: STR, redirect_uri: STR,
  redirect_uri_unregistered: BOOL, response_type: STR, scope: STR,
  parameters: Kit.freeForm(
    'The authorization request a client pushed (RFC 9126), which may carry ' +
    'any parameter and a request object\'s claims of any JSON type.')
});

const MONITOR_SECTION = Kit.closed({
  id: STR, title: STR,
  events: Kit.listOf(Kit.closed({
    event: STR, counter: STR, label: STR, count: INT
  })),
  totals: Kit.mapOf(INT, 'Each counter this section shows.'),
  lastAt: NULL_STR, lastEvent: NULL_STR, errors: ERROR_COUNT,
  clientsPaging: PAGING, clientsParam: STR,
  clients: Kit.listOf(Kit.closed({
    client_id: STR, counters: Kit.mapOf(INT, 'Each counter, for this client.'),
    errors: ERROR_COUNT, lastAt: NULL_STR, lastEvent: NULL_STR
  })),
  pushedRequests: Kit.closed({
    filter: Kit.closed({ state: STR, client_id: STR }),
    total: INT, offset: INT, limit: INT, capacity: NUM, lifetime_s: NUM,
    paging: Kit.closed({
      page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
      total: INT
    }),
    items: Kit.listOf(PUSHED_REQUEST)
  }),
  ownResourceRequirement: Kit.closed({
    acr_values: NULL_STR, max_age: NULL_NUM
  }),
  acrValuesSupported: STRS
});

const OAUTH2_MONITOR = Kit.closed({
  page: STR, title: STR, since: STR, sections: Kit.listOf(MONITOR_SECTION),
  actions: STRS
});

// ---------------------------------------------------------------------------
// GRANT MANAGEMENT, `grant_management.ts`. A row is `decorate()`d, or is
// `list()`'s
// bare row where the grant went between the two reads. `authorization_details`
// is what the client asked for (RFC 9396): each type's fields are its own.
// ---------------------------------------------------------------------------
const GRANTS = Kit.closed({
  grants: Kit.listOf(Kit.closed({
    grantId: STR, clientId: CLAIM_VALUE, subject: CLAIM_VALUE,
    generation: NUM, tokens: INT,
    scopes: Kit.listOf(Kit.closed({ scope: STR, resource: STRS })),
    claims: STRS,
    authorization_details: Kit.listOf(Kit.freeForm(
      'An RFC 9396 authorization detail as the client asked for it: a ' +
      'type\'s fields are that type\'s definition\'s, written by an ' +
      'operator.')),
    created_at: NUM, last_updated: NUM, expires_at: NUM, updated_by: CLAIM_VALUE
  })),
  total: INT, matched: INT,
  filter: Kit.closed({ q: NULL_STR, clientId: NULL_STR }),
  paging: Kit.closed({ grants: PAGING })
});

// ---------------------------------------------------------------------------
// CLAIMS PROVIDERS, `claims_providers.ts`.
// ---------------------------------------------------------------------------
const CLAIM_PROVIDERS = Kit.closed({
  protocolEndpoints: PROTOCOL_ENDPOINTS,
  redirectUri: STR, callbackPath: STR,
  providers: Kit.listOf(Kit.closed({
    id: STR, name: STR, issuer: STR, authorizationEndpoint: STR,
    tokenEndpoint: STR, claimsEndpoint: STR, jwksUri: STR, clientId: STR,
    authMethod: STR, scope: STR, claims: STRS, delivery: STR, createdAt: NUM,
    updatedAt: NUM, hasSecret: BOOL
  })),
  links: Kit.listOf(Kit.closed({
    username: STR, provider: STR, sub: STR, linkedAt: NUM, expiresAt: NUM,
    refreshable: BOOL, stale: BOOL
  })),
  counts: Kit.closed({ providers: INT, links: INT }),
  matched: Kit.closed({ links: INT }),
  filter: Kit.closed({ links: NULL_STR }),
  paging: Kit.closed({ providers: PAGING, links: PAGING })
});

// ---------------------------------------------------------------------------
// OPENID PROVIDER COMMANDS, `provider_commands.ts` over `outbound_delivery.ts`.
// `roles` and `last_access` are what a relying party said of itself, each held
// to its shape where it arrives (`rolesFrom()`, `lastAccessFrom()`).
// ---------------------------------------------------------------------------
const COMMAND_DELIVERY = Kit.closed({
  id: STR, realm: STR, clientId: STR, uri: STR, state: STR, generation: NUM,
  attempts: NUM, inFlight: BOOL, holder: STR, status: Kit.oneOf(NUM, STR),
  errorCode: STR, why: STR, queuedAt: STR, nextAttemptAt: STR,
  lastAttemptAt: STR, finishedAt: STR, command: STR, username: STR, sub: STR,
  trigger: STR, accountState: STR, awaitingCallback: BOOL
});

const COMMAND_RUN = Kit.closed({
  id: STR, clientId: STR, command: STR, uri: STR, state: STR, events: NUM,
  accounts: NUM, totalAccounts: NULL_NUM, resumes: NUM, lastEventId: STR,
  errors: STRS, why: STR, errorCode: STR, actor: STR, startedAt: STR,
  finishedAt: STR
});

const PROVIDER_COMMANDS = Kit.closed({
  protocolEndpoints: PROTOCOL_ENDPOINTS,
  enabled: BOOL, automatic: BOOL, issuer: STR,
  clients: Kit.listOf(Kit.closed({
    clientId: STR, name: STR, endpoint: STR,
    learned: Kit.nullable(Kit.closed({
      commandsSupported: STRS, audSubRequired: BOOL,
      // Section 2.2's role object, which `ProviderCommands.rolesFrom()` holds a
      // relying party's answer to.
      roles: Kit.listOf(Kit.closed({ id: STR, display: STR, description: STR })),
      learnedAt: STR
    }))
  })),
  accounts: Kit.listOf(Kit.closed({
    clientId: STR, sub: STR, username: STR, state: STR, lastCommand: STR,
    updatedAt: STR, audSub: STR, lastAccess: Kit.oneOf(STR, NUM)
  })),
  deliveries: Kit.listOf(COMMAND_DELIVERY),
  counts: Kit.closed({ pending: INT, sent: INT, dead: INT }),
  runs: Kit.listOf(COMMAND_RUN),
  accountCommands: STRS, tenantCommands: STRS, clientIds: STRS,
  listCounts: Kit.closed({
    clients: INT, accounts: INT, runs: INT, deliveries: INT
  }),
  paging: Kit.closed({
    clients: PAGING, accounts: PAGING, runs: PAGING, deliveries: PAGING
  })
});

const COMMAND_ACTION = Kit.action({ row: COMMAND_DELIVERY, run: COMMAND_RUN });

// ---------------------------------------------------------------------------
// ONE APPLICATION: `view()` in `common/applications.js`. An entry's attribute
// names are data, the directory being schemaless on purpose, and a value is one
// string or a list, or a typed value a write left there.
// ---------------------------------------------------------------------------
const ENTRY_VALUES = Kit.mapOf(CLAIM_VALUE, 'By attribute name.');

const APP_VIEW_MEMBERS = {
  identifier: STR, dnLabel: NULL_STR, dn: NULL_STR, name: NULL_STR,
  kinds: STRS, protocols: STRS, allowedProtocols: STRS,
  recordedProtocols: STRS, declaredKinds: STRS, registeredBy: STR,
  returnAddressesObserved: Kit.listOf(Kit.closed({
    attribute: STR, value: STR, held: BOOL, trusted: BOOL
  })),
  registered: BOOL, firstSeen: STR, lastSeen: STR, authentications: NUM,
  sessions: NUM, users: NUM, description: NULL_STR, origin: NULL_STR,
  createdAt: NULL_STR, modifiedAt: NULL_STR, operational: STRS,
  attributes: ENTRY_VALUES, fields: ENTRY_VALUES
};

const APP_VIEW = Kit.closed(APP_VIEW_MEMBERS);

// Each list row of `GET /applications` is masked, with its secret's expiry.
const APP_ROW = Kit.closed(Object.assign({}, APP_VIEW_MEMBERS, {
  secretExpiry: Kit.closed({ state: STR, at: STR })
}));

const KIND_ROW = Kit.closed({ kind: STR, label: STR, what: STR });

const PROTOCOL_ROW = Kit.closed({
  id: STR, label: STR, kind: STR, kinds: STRS, identifierAttribute: STR,
  redirectAttribute: STR, logoutAttribute: STR, deliveryAttribute: STR,
  eventsAttribute: STR, secretAttribute: STR, what: STR
});

const FAMILY_CHOICE = Kit.closed({
  id: STR, label: STR, families: STRS, kind: STR, what: STR
});

const FIELD_GROUP = Kit.closed({ id: STR, label: STR, families: STRS });

// `applicationFields()` through `typedField()`. An override carries the setting
// it overrides, `described`, and the form's `inSimple` is the new-form page's.
const FIELD_ROW = Kit.closed({
  attribute: STR, type: STR, long: BOOL, editable: Kit.oneOf(STR, BOOL),
  sensitive: BOOL, overrides: STR, choices: Kit.nullable(STRS),
  example: NULL_STR, what: STR, families: STRS, everyFamily: BOOL,
  declaration: BOOL, primaryName: BOOL, simple: BOOL, group: STR, section: STR,
  sectionLabel: STR, described: SETTING, inSimple: BOOL
});

const DECLARATION_ROW = Kit.closed({
  attribute: STR, role: STR, kind: STR, editable: Kit.oneOf(STR, BOOL),
  sensitive: BOOL, what: STR,
  families: Kit.listOf(Kit.closed({ id: STR, label: STR })), everyFamily: BOOL
});

const NEW_APPLICATION_FORM: Json = Kit.closed({
  directory: BOOL, container: NULL_STR, max: NULL_NUM, applicationCount: INT,
  realm: Kit.closed({ id: STR, name: STR }),
  kinds: Kit.listOf(KIND_ROW), protocols: Kit.listOf(PROTOCOL_ROW),
  declarations: Kit.listOf(DECLARATION_ROW), fields: Kit.listOf(FIELD_ROW),
  fieldGroups: Kit.listOf(FIELD_GROUP),
  familyChoices: Kit.listOf(FAMILY_CHOICE),
  longTextAttributes: STRS, defaultSecretLifetimeDays: NUM,
  persistence: Kit.closed({ persistsDirectory: BOOL, mode: STR }),
  resourceMetadataImport: Kit.closed({
    wellKnown: STR, acceptsNonconforming: BOOL, dialsInternalAddresses: BOOL
  }),
  editable: Kit.listOf(Kit.closed({
    name: STR, mode: Kit.oneOf(STR, BOOL), sensitive: BOOL, families: STRS
  }))
});

// `applicationsListJson()`.
const APPLICATIONS_LIST = Kit.closed(Object.assign({
  applicationCount: INT, matched: INT, shown: INT, registered: INT,
  filter: Kit.closed({ q: NULL_STR, kind: NULL_STR,
  exclude: Kit.nullable(STRS) }),
  container: NULL_STR, max: NULL_NUM, kinds: Kit.listOf(KIND_ROW),
  settings: Kit.nullable(SETTINGS_BLOCK), paging: PAGING,
  kindCounts: Kit.mapOf(INT, 'How many applications are of each kind.'),
  authentications: NUM, protocols: Kit.listOf(PROTOCOL_ROW),
  applications: Kit.listOf(APP_ROW)
}, FLAT_PAGING));

// ---------------------------------------------------------------------------
// ONE APPLICATION'S PAGE, `applicationDetailJson()`.
// ---------------------------------------------------------------------------
// `pagedRows()`'s paging, which `pagingJson()` narrows: this one has `offset`.
const RAW_PAGING = Kit.closed({
  page: INT, perPage: INT, pages: INT, offset: INT, total: INT, firstRow: INT,
  lastRow: INT, param: STR, noun: STR
});

const SCOPE_WARNING = Kit.closed({
  attribute: STR, value: STR, reason: STR, dropped: BOOL, text: STR
});

// `certificateSummary()`, which answers `{ unreadable }` for what will not
// parse.
const CERTIFICATE_SUMMARY = Kit.closed({
  subject: STR, issuer: STR, serialHex: STR, notBefore: STR, notAfter: STR,
  expired: BOOL, selfSigned: BOOL, keyType: NULL_STR, thumbprint: STR,
  unreadable: STR
});

// `KEY_PAIR_ATTRIBUTES` in `common/applications.js`.
const KEY_PAIR_NAMES = Kit.closed({
  issuer: STR, certificate: STR, chain: STR, privateKey: STR, handle: STR,
  handleLabel: STR, expires: STR, source: STR, jwks: STR, registered: STR
});

// The registered half: a JWKS's keys for `jwt`, certificates for `saml`.
const REGISTERED_KEYS = Kit.closed({
  attribute: STR, problem: STR,
  keys: Kit.listOf(Kit.closed({
    kid: STR, kty: STR, alg: STR, use: STR,
    certificate: Kit.nullable(CERTIFICATE_SUMMARY)
  })),
  certificates: Kit.listOf(CERTIFICATE_SUMMARY)
});

const KEY_PAIR_MEMBERS = {
  label: STR, held: BOOL, source: STR, privateKeyHeld: BOOL,
  certificate: Kit.nullable(CERTIFICATE_SUMMARY),
  chain: Kit.listOf(CERTIFICATE_SUMMARY), handle: STR, handleLabel: STR,
  issuers: STRS, attributes: KEY_PAIR_NAMES, registered: REGISTERED_KEYS
};

// A row of `tlsClientCertificates.listFor()`, narrowed by its two callers.
const HELD_CERTIFICATE_MEMBERS = {
  serialHex: STR, label: NULL_STR, subject: NULL_STR, keyAlg: NULL_STR,
  notBefore: Kit.oneOf(STR, NUM, { type: 'null' }),
  notAfter: Kit.oneOf(STR, NUM, { type: 'null' }), thumbprint: NULL_STR,
  state: STR, reason: NULL_STR,
  revokedAt: Kit.oneOf(STR, NUM, { type: 'null' }), certificatePem: NULL_STR
};

const HELD_CERTIFICATE = Kit.closed(HELD_CERTIFICATE_MEMBERS);

// The revoked row itself, which `revoke()` answers as `listFor()` built it.
const REVOKED_CERTIFICATE = Kit.closed(Object.assign({},
HELD_CERTIFICATE_MEMBERS, {
  slot: Kit.oneOf(STR, NUM, { type: 'null' }),
  createdAt: Kit.oneOf(STR, NUM, { type: 'null' })
}));

const CERTIFICATE_HOLDING = {
  certificates: Kit.listOf(HELD_CERTIFICATE), active: INT, max: NUM,
  keyAlgorithms: STRS, defaultKeyAlg: STR, revocationReasons: STRS,
  passwordMin: NUM, implicitName: STR, caAvailable: BOOL
};

const MTLS_STATE = Kit.closed(Object.assign({}, CERTIFICATE_HOLDING, {
  authMethod: STR, certificateMethod: BOOL,
  subjects: Kit.listOf(Kit.closed({
    member: STR, attribute: STR, label: STR, value: STR
  })),
  registeredSubject: STRS, boundTokensAttribute: STR, boundTokens: BOOL,
  adminApiBound: BOOL, selfSignedThumbprint: STR, bindingAvailable: BOOL
}));

const SIGNING_STATE = Kit.closed(Object.assign({}, CERTIFICATE_HOLDING, {
  ok: BOOL, kind: STR, holder: STR, wstrustDeclared: BOOL
}));

// `applicationStoredCertificatesOf()`, whose refusal has `errors`.
const STORED_CERTIFICATE = Kit.closed({
  sha256: STR, subject: STR, issuer: STR, serialNumber: STR, notBefore: STR,
  notAfter: STR, expired: BOOL, readable: BOOL
});

const STORED_CERTIFICATES = Kit.closed({
  ok: BOOL, errors: STRS, application: STR, dn: NULL_STR,
  certificates: Kit.listOf(STORED_CERTIFICATE), rule: STR
});

const CLIENT_SECRET_SUMMARY = Kit.closed({
  id: STR, createdAt: NUM, expiresAt: NUM, description: NULL_STR, expired: BOOL,
  primary: BOOL
});

const CLIENT_SECRET_MEMBERS = {
  held: BOOL, authMethod: STR, registered: BOOL,
  registrationAccessTokenHeld: BOOL, expiresAt: NUM,
  secrets: Kit.listOf(CLIENT_SECRET_SUMMARY), max: NUM
};

// `applicationCredentialsState().json`.
const CREDENTIALS_JSON = Kit.closed({
  clientSecret: Kit.closed(CLIENT_SECRET_MEMBERS),
  keyPairs: Kit.listOf(Kit.closed(Object.assign({}, KEY_PAIR_MEMBERS,
                                                { purpose: STR }))),
  caAvailable: BOOL, oauthDeclared: BOOL, sources: STRS, mtls: MTLS_STATE,
  signing: SIGNING_STATE, stored: STORED_CERTIFICATES
});

// The same state as the page has it: `applicationPageData()` takes `json` and
// two
// secrets off, and keeps the rest.
const CREDENTIALS_PAGE = Kit.closed({
  oauthDeclared: BOOL,
  clientSecret: Kit.closed(Object.assign({}, CLIENT_SECRET_MEMBERS, {
    defaultLifetimeDays: NUM, overlapS: NUM
  })),
  purposes: Kit.listOf(Kit.closed(Object.assign({}, KEY_PAIR_MEMBERS, {
    id: STR, sealedAtRest: BOOL, certificatePem: STR
  }))),
  ca: Kit.closed({
    available: BOOL, keyAlg: STR,
    keyAlgorithms: Kit.listOf(Kit.closed({ id: STR, label: STR, kind: STR })),
    leafLifetimeDays: NUM
  }),
  sources: STRS, mtls: MTLS_STATE, signing: SIGNING_STATE,
  stored: STORED_CERTIFICATES
});

const SSF_SETTING = Kit.closed({
  setting: STR, attribute: STR, value: SETTING_VALUE, source: STR
});

const SSF_STREAM = Kit.closed({
  stream_id: STR, status: STR, statusReason: NULL_STR, aud: CLAIM_VALUE,
  delivery: Kit.closed({ method: STR, endpoint_url: NULL_STR }),
  events_requested: STRS, events_delivered: STRS, format: STR, description: STR,
  createdBy: STR, createdAt: Kit.oneOf(STR, NUM), updatedAt: Kit.oneOf(STR,
  NUM),
  lastPushAt: Kit.oneOf(STR, NUM), lastPushError: STR
});

const SIGNALS_MEMBERS = {
  installed: BOOL, streams: Kit.listOf(SSF_STREAM),
  settings: Kit.listOf(SSF_SETTING)
};

const SIGNALS_JSON = Kit.closed(SIGNALS_MEMBERS);

// A software statement's `metadata` is RFC 7591 client metadata, the client's.
const STATEMENT_DESCRIBED_MEMBERS = {
  readable: BOOL, why: STR, verifies: BOOL, typed: BOOL, issuer: STR,
  issuedAt: NUM, expiresAt: NUM,
  metadata: Kit.freeForm(
    'RFC 7591 client metadata fixed by a software statement: any member a ' +
    'publisher chose, including extensions no specification defines.'),
  thumbprint: STR
};

const STATEMENT_SETTINGS = Kit.closed({
  requireTrustedIssuer: BOOL, opensRegistration: BOOL, required: BOOL,
  lifetimeSeconds: NUM
});

const STATEMENT_REGISTERED = Kit.nullable(Kit.closed({
  issuer: STR, trusted: BOOL, publisher: STR
}));

const STATEMENT_JSON = Kit.closed({
  declaredIssuers: STRS, usableKeys: INT,
  issued: Kit.nullable(Kit.closed(Object.assign({}, STATEMENT_DESCRIBED_MEMBERS,
                                                { statement: STR }))),
  registeredWith: STATEMENT_REGISTERED, settings: STATEMENT_SETTINGS
});

const STATEMENT_PAGE = Kit.closed({
  issuers: STRS, usableKeys: INT, keyProblems: Kit.listOf(CLAIM_VALUE),
  issuedToken: STR,
  issued: Kit.nullable(Kit.closed(STATEMENT_DESCRIBED_MEMBERS)),
  registeredWith: STATEMENT_REGISTERED, settings: STATEMENT_SETTINGS,
  json: STATEMENT_JSON
});

const ROLES_STATE = Kit.closed({
  held: Kit.listOf(Kit.closed({
    name: STR, id: STR, displayName: STR, application: STR, carriedAs: STR,
    permissions: STRS
  })),
  offerable: STRS,
  required: Kit.listOf(Kit.closed({
    name: STR, resolves: STR, displayName: STR, role: STR
  })),
  requirable: STRS
});

const LIFETIME_ROW = Kit.closed({
  setting: STR, attribute: STR, label: STR, value: NUM, realmValue: NUM,
  source: STR
});

// A claim row, `checkClaimEntries()`, as a realm's set and an application's
// hold
// it; `effective` adds where each came from.
const CLAIM_ROW_MEMBERS = {
  name: STR, value: CLAIM_VALUE, nameFormat: STR, namespace: STR,
  attribute: STR,
  multi: BOOL, type: STR
};

const CLAIM_ROW = Kit.closed(CLAIM_ROW_MEMBERS);

const CLAIM_SET_ROW = Kit.closed({
  id: STR, label: STR, attribute: STR, realm: Kit.listOf(CLAIM_ROW),
  own: Kit.listOf(CLAIM_ROW),
  effective: Kit.listOf(Kit.closed(Object.assign({}, CLAIM_ROW_MEMBERS, {
    source: STR, replacesRealm: BOOL
  })))
});

const CLAIM_REPORT_ROW = Kit.closed({
  ldap: STR, claim: STR, value: CLAIM_VALUE, source: STR, ldpTerm: NULL_STR
});

const CLAIMS_MAP = Kit.mapOf(NESTED_CLAIM, 'The claims, by name.');

const CLAIM_SELECTIONS = Kit.closed({
  catalogue: Kit.listOf(Kit.closed({
    ldap: STR, claim: STR, label: STR, schema: STR, ldpTerm: STR,
    generated: BOOL
  })),
  preview: Kit.closed({
    user: STR,
    byLdap: Kit.mapOf(CLAIM_REPORT_ROW, 'By lower-cased attribute name.'),
    entryFound: BOOL
  }),
  sets: Kit.listOf(Kit.closed({
    id: STR, label: STR, attribute: STR, realm: STRS, own: Kit.nullable(STRS),
    inherited: BOOL, effective: STRS, claims: CLAIMS_MAP,
    report: Kit.listOf(CLAIM_REPORT_ROW)
  })),
  credential: Kit.nullable(Kit.closed({
    attribute: STR, realm: STRS, own: Kit.nullable(STRS), inherited: BOOL,
    effective: STRS, claims: CLAIMS_MAP, report: Kit.listOf(CLAIM_REPORT_ROW),
    ldpOmitted: STRS
  }))
});

// `applicationEnrollmentState()`. A certificate record is what the core stored,
// less its private key: `publicRecord()`. `device` and `attestation` are a
// device's; `revoked` appears once it is.
const ENROLLED_CERTIFICATE = Kit.closed({
  serialHex: STR, family: STR, profile: STR, subject: STR, names: STRS,
  thumbprint: STR, keyAlg: STR, notBefore: Kit.oneOf(STR, NUM),
  notAfter: Kit.oneOf(STR, NUM), issuedAt: STR,
  requestedBy: Kit.nullable(Kit.closed({ kind: STR, id: STR, admin: BOOL })),
  via: STR, keySource: STR, replaces: NULL_STR, certificatePem: STR,
  chainPem: STRS, device: STR, attestation: CLAIM_VALUE,
  revoked: Kit.closed({ at: Kit.oneOf(STR, NUM), reason: STR, by: STR }),
  expired: BOOL, status: STR
});

const ENROLLMENT_RULE = Kit.closed({
  family: STR, label: STR, allowedProfiles: STRS, allowedProfilesSource: STR,
  defaultProfile: NULL_STR, defaultProfileSource: STR,
  certificateLifetimeDays: NUM, certificateLifetimeSource: STR
});

const VALUE_SOURCE = Kit.closed({ value: NUM, source: STR });

const EST_SWITCH = Kit.closed({ on: BOOL, source: STR });

const EST_STATE = Kit.nullable(Kit.closed({
  basicAuthentication: EST_SWITCH, certificateAuthentication: EST_SWITCH,
  serverKeyGeneration: EST_SWITCH
}));

const EAB_KEY = Kit.closed({
  kid: STR, createdAt: Kit.oneOf(STR, NUM), expiresAt: Kit.oneOf(STR, NUM),
  createdBy: NULL_STR, boundAccount: NULL_STR,
  boundAt: Kit.oneOf(STR, NUM, { type: 'null' }), status: STR
});

const SCEP_CHALLENGE = Kit.closed({
  id: STR, profile: NULL_STR, createdAt: Kit.oneOf(STR, NUM),
  expiresAt: Kit.oneOf(STR, NUM), createdBy: NULL_STR,
  usedAt: Kit.oneOf(STR, NUM, { type: 'null' }), status: STR
});

const ENROLLMENT_JSON = Kit.closed({
  families: STRS, rules: Kit.listOf(ENROLLMENT_RULE),
  certificateCap: VALUE_SOURCE, est: EST_STATE,
  certificates: Kit.listOf(ENROLLED_CERTIFICATE), certificatesPaging: PAGING,
  certificatesTotal: INT, eabKeys: Kit.listOf(EAB_KEY),
  scepChallenges: Kit.listOf(SCEP_CHALLENGE), hostNames: STRS
});

const ENROLLMENT_PAGE = Kit.closed({
  families: STRS, rules: Kit.listOf(ENROLLMENT_RULE), cap: VALUE_SOURCE,
  est: EST_STATE, certificates: Kit.listOf(ENROLLED_CERTIFICATE),
  paged: Kit.closed({
    paging: RAW_PAGING, shown: Kit.listOf(ENROLLED_CERTIFICATE)
  }),
  eabKeys: Kit.listOf(EAB_KEY), challenges: Kit.listOf(SCEP_CHALLENGE),
  hostNames: STRS, keyAlgorithms: STRS, json: ENROLLMENT_JSON
});

// `appPermissions.register()`.
const PERMISSION_GRANT = Kit.closed({
  client: STR, clientName: STR, permissionId: STR, resource: STR,
  resourceName: STR, baseUri: NULL_STR, permissionName: STR,
  description: NULL_STR, dangling: BOOL, asked: BOOL
});

const PERMISSION_EXPOSED = Kit.closed({
  resource: STR, resourceName: STR, baseUri: NULL_STR, name: STR,
  description: NULL_STR, id: NULL_STR, raw: NULL_STR,
  grantedTo: Kit.listOf(Kit.closed({ identifier: STR, name: STR, asked: BOOL }))
});

const pageOf = function (row: Json): Json {
  return Kit.closed({ paging: RAW_PAGING, shown: Kit.listOf(row) });
};

// One audit row, `common/audit.js`'s `record()`. `detailOf()` keeps a number, a
// boolean or a trimmed string under any name its caller gave.
const AUDIT_EVENT = Kit.closed({
  seq: NUM, origin: Kit.oneOf(STR, NUM, { type: 'null' }), at: NUM,
  category: STR,
  action: STR, outcome: STR, errorCode: STR, actor: STR, actorForm: STR,
  target: STR, protocol: STR, channel: STR, address: STR, summary: STR,
  detail: Kit.mapOf(Kit.oneOf(STR, NUM, BOOL), 'What the event recorded.')
});

// An access type, `authorizationDetailsTypeOf()` (#432, #564). `schema`,
// `limits`
// and `source` are the JSON an operator wrote; a compiled `validate` is a
// function, which JSON leaves out, so only its null is ever sent.
const OPERATOR_JSON = Kit.freeForm(
  'The JSON an operator wrote into an access type\'s definition: a JSON ' +
  'Schema ' +
  '(RFC 9396 leaves a type\'s fields to its definition), or the definition.');

const FGA_ROW = Kit.closed({
  path: STR, attributeId: STR, category: STR, dataType: STR, multiplicity: STR,
  description: STR
});

const ACCESS_TYPE = Kit.closed({
  stored: STR, type: STR, description: STR, locations: STRS,
  schema: OPERATOR_JSON,
  validate: { type: 'null' }, problem: STR, actions: Kit.nullable(STRS),
  datatypes: Kit.nullable(STRS), privileges: Kit.nullable(STRS), required: STRS,
  interaction: STR, consentActions: STRS, bearer: CLAIM_VALUE,
  maxLifetimeS: NULL_NUM, acr: STR, derivableFrom: STRS,
  introspectionClaims: STRS, limits: OPERATOR_JSON,
  validateLimits: { type: 'null' },
  xacml: Kit.listOf(FGA_ROW), notForPolicy: STRS, source: OPERATOR_JSON
});

const PEP_HOLDER = Kit.closed({
  name: STR, kind: STR, dn: STR, member: BOOL, scoped: BOOL, scope: BOOL,
  why: STR, code: STR
});

// `xacml/fga_policies.ts`'s `state()`, with the page's three lists of choices.
const FGA_STATE = Kit.nullable(Kit.closed({
  known: BOOL, enforced: BOOL, reference: NULL_STR,
  policy: Kit.nullable(Kit.closed({
    name: STR, policyId: NULL_STR, version: NULL_STR, enabled: BOOL,
    application: NULL_STR, orphanedAt: NULL_STR, own: BOOL, editor: STR
  })),
  usable: BOOL, failure: STR, code: STR, why: STR,
  types: Kit.listOf(Kit.closed({
    type: STR, covered: BOOL, uncovered: STRS, rows: INT, notForPolicy: STRS
  })),
  unreadable: Kit.listOf(Kit.closed({ stored: STR, problem: STR })),
  template: STR,
  peps: Kit.nullable(Kit.closed({
    group: STR, authzenGroup: STR, total: INT, truncated: BOOL, unlocated: INT,
    holders: Kit.listOf(PEP_HOLDER)
  })),
  applicationPolicies: Kit.closed({ count: INT, max: NUM }),
  choices: Kit.closed({
    categories: STRS, dataTypes: STRS, multiplicities: STRS
  })
}));

// What `krb5_trusts.ts`'s `applicationAcross()` draws for an application.
const KRB5_PROBLEM = Kit.closed({
  kind: STR, params: Kit.mapOf(STR, 'What the sentence names.'), text: STR
});

const KRB5_TRUST_STATE_MEMBERS = {
  realm: STR, via: STR, path: STRS, ok: BOOL, problems: Kit.listOf(KRB5_PROBLEM)
};

const KRB5_ACROSS = Kit.nullable(Kit.closed({
  realm: STR,
  frontEnds: Kit.listOf(Kit.closed(Object.assign({}, KRB5_TRUST_STATE_MEMBERS,
                                                 { actor: STR }))),
  targets: Kit.listOf(Kit.closed(Object.assign({}, KRB5_TRUST_STATE_MEMBERS, {
    target: STR, classicRefused: BOOL, classicProblems: Kit.listOf(KRB5_PROBLEM)
  }))),
  selfRealms: Kit.listOf(Kit.closed(Object.assign({}, KRB5_TRUST_STATE_MEMBERS,
                                                  { accepted: BOOL }))),
  tgtDelegation: Kit.closed({
    unconstrained: BOOL, foreignTgtDelegation: STR,
    trusts: Kit.listOf(Kit.closed({
      partner: STR, allowed: BOOL, attributes: STRS, delivered: BOOL
    }))
  }),
  choices: Kit.closed({
    krb5S4uSelfRealm: STRS, krb5ForeignTgtDelegation: STRS
  })
}));

const MARKED_VALUES = Kit.listOf(Kit.closed({ value: STR, declared: BOOL }));

// `applicationObservedState()`.
const OBSERVED_STATE = Kit.closed({
  oauthGrantTypeObserved: MARKED_VALUES,
  oauthResponseTypeObserved: MARKED_VALUES,
  appRedirectUriObserved: MARKED_VALUES, oauthScope: MARKED_VALUES,
  appAuthorizationServer: MARKED_VALUES, samlNameIdFormat: MARKED_VALUES,
  samlResponseBinding: MARKED_VALUES,
  samlLastRequest: Kit.nullable(Kit.closed({
    signed: BOOL, outcome: STR, binding: STR, signatureMethod: STR, weak: BOOL
  })),
  samlObservedSigningCertificate: Kit.nullable(Kit.closed({
    subject: STR, sha256: STR, unreadable: BOOL
  })),
  oauthAllowedTokenResponseTypes: Kit.closed({
    enabled: STRS, enforced: BOOL, waived: BOOL
  })
});

const ATTRIBUTE_NOTE = Kit.closed({ text: STR, sensitive: BOOL });

const OBSERVED_ADDRESS = Kit.closed({
  attribute: STR, value: STR, held: BOOL, trusted: BOOL
});

const OWNER_ROW = Kit.closed({ dn: STR, kind: STR, name: STR, present: BOOL });

const EDITABLE_NAME = Kit.listOf(Kit.closed({ name: STR, sensitive: BOOL }));

// `applicationPageData()`: what the console's page is drawn from. The name
// `page`
// cannot collide with an attribute, and is a number on the list reply.
const APPLICATION_PAGE = Kit.closed({
  notes: Kit.mapOf(ATTRIBUTE_NOTE, 'What each attribute of the entry is.'),
  config: Kit.closed({
    fields: Kit.listOf(FIELD_ROW),
    values: Kit.mapOf(STRS, 'Each field\'s values, by attribute.'),
    groups: Kit.listOf(FIELD_GROUP), familyChoices: Kit.listOf(FAMILY_CHOICE),
    protocols: Kit.listOf(PROTOCOL_ROW), longTextAttributes: STRS,
    fieldSearches: Kit.mapOf(STR,
    'What each attribute\'s search looks through.'),
    observed: OBSERVED_STATE,
    derived: Kit.closed({
      oauthAllowedScope: Kit.listOf(Kit.closed({
        value: STR, permission: STR, api: STR, apiName: STR
      }))
    }),
    fieldWarnings: Kit.mapOf(Kit.listOf(SCOPE_WARNING), 'By attribute.')
  }),
  passkeyPolicies: Kit.closed({
    named: STR, missing: BOOL, applies: STR, precedence: NUM,
    groupPolicies: INT,
    link: STR
  }),
  launchUrls: Kit.mapOf(Kit.closed({
    protocol: STR, label: STR, url: STR, enabled: BOOL, setting: STR,
    attribute: STR, missing: STRS, endpoint: NULL_STR
  }), 'By protocol.'),
  cors: Kit.listOf(Kit.closed({ stored: STR, canonical: STR })),
  accessTypes: Kit.listOf(ACCESS_TYPE), fga: FGA_STATE,
  permissionClaims: Kit.closed({
    permissions: Kit.listOf(Kit.closed({
      name: STR, description: NULL_STR, id: NULL_STR, attributes: STRS
    })),
    stale: STRS,
    catalogue: Kit.listOf(Kit.closed({ ldap: STR, claim: STR, label: STR }))
  }),
  grantsUncataloguedAccess: BOOL, acceptsUnregisteredAddresses: BOOL,
  protocolRows: Kit.listOf(Kit.closed({
    id: STR, label: STR, kinds: STRS, kind: STR
  })),
  editable: Kit.closed({
    set: EDITABLE_NAME, multi: EDITABLE_NAME, multiAll: EDITABLE_NAME
  }),
  did: Kit.closed({
    did: NULL_STR, url: STR, ok: BOOL, why: STR,
    methods: Kit.listOf(Kit.closed({
      kid: STR, kty: STR, crv: STR, alg: STR, kept: BOOL
    })),
    origins: STRS
  }),
  credentials: CREDENTIALS_PAGE,
  signals: Kit.closed(Object.assign({}, SIGNALS_MEMBERS,
  { json: SIGNALS_JSON })),
  softwareStatement: STATEMENT_PAGE,
  roles: ROLES_STATE,
  permissions: Kit.closed({
    held: Kit.listOf(PERMISSION_GRANT), exposes: Kit.listOf(PERMISSION_EXPOSED),
    offerable: Kit.listOf(PERMISSION_EXPOSED),
    clients: Kit.listOf(Kit.closed({ identifier: STR, name: STR })),
    heldPage: pageOf(PERMISSION_GRANT), exposedPage: pageOf(PERMISSION_EXPOSED),
    grantedOutPage: pageOf(PERMISSION_GRANT), registerPermissions: INT
  }),
  lifetimes: Kit.closed({ rows: Kit.listOf(LIFETIME_ROW), skew: NUM }),
  claims: Kit.listOf(CLAIM_SET_ROW), claimSelections: CLAIM_SELECTIONS,
  enrollment: Kit.closed({ credentials: ENROLLMENT_PAGE,
  config: ENROLLMENT_PAGE }),
  observed: pageOf(OBSERVED_ADDRESS),
  warnings: Kit.listOf(SCOPE_WARNING),
  owners: Kit.listOf(OWNER_ROW), maxOwners: NUM,
  ownership: Kit.closed({
    kind: STR, name: STR, marked: BOOL, protected: BOOL, reasons: STRS
  }),
  krb5Across: KRB5_ACROSS
});

// `applicationDetailJson()`, `{ found: false, identifier }` for one nobody
// holds,
// and an owner's narrowing of it (#607), whose `owners` and `maxOwners` are the
// page's lifted out. So every member is optional.
const APPLICATION_DETAIL = Kit.closed(Object.assign({}, APP_VIEW_MEMBERS, {
  found: BOOL, page: APPLICATION_PAGE, warnings: Kit.listOf(SCOPE_WARNING),
  attributesShown: Kit.listOf(Kit.closed({
    name: STR, values: Kit.listOf(CLAIM_VALUE), sealedAtRest: BOOL,
    operational: BOOL
  })),
  attributesPaging: PAGING, authenticationEvents: Kit.listOf(AUDIT_EVENT),
  authenticationEventsPaging: PAGING, authenticationEventsMatched: INT,
  authenticationEventsKnownActors: Kit.mapOf(BOOL,
  'Which actors have a user page.'),
  authenticationEventsLog: Kit.closed({
    held: NUM, recorded: NUM, dropped: NUM, maxEvents: NUM
  }),
  returnAddressesObservedShown: Kit.listOf(OBSERVED_ADDRESS),
  returnAddressesObservedPaging: PAGING, credentials: CREDENTIALS_JSON,
  sharedSignals: SIGNALS_JSON, certificateEnrollment: ENROLLMENT_JSON,
  customClaims: Kit.listOf(CLAIM_SET_ROW), claimSelections: CLAIM_SELECTIONS,
  tokenLifetimes: Kit.closed({
    lifetimes: Kit.listOf(LIFETIME_ROW), clockSkewS: NUM
  }),
  softwareStatements: STATEMENT_JSON, applicationRoles: ROLES_STATE,
  delegatedPermissions: Kit.closed({
    held: Kit.listOf(PERMISSION_GRANT), exposes: Kit.listOf(PERMISSION_EXPOSED),
    offerable: Kit.listOf(NULL_STR), grantedOut: Kit.listOf(PERMISSION_GRANT),
    paging: Kit.closed({ held: PAGING, exposes: PAGING, grantedOut: PAGING })
  }),
  owners: Kit.listOf(OWNER_ROW), maxOwners: NUM
}));

// ---------------------------------------------------------------------------
// THE APPLICATION ACTIONS, `applicationsAction()`. `application` is the view
// after
// a write, or the identifier where the action answers only its name. `changed`
// is
// a boolean, and the list of attributes on `update-fields`.
// ---------------------------------------------------------------------------
const APP_ACTION_MEMBERS = {
  application: Kit.oneOf(STR, APP_VIEW, { type: 'null' }),
  changed: Kit.oneOf(BOOL, STRS)
};

const appAction = function (extra?: Json): Json {
  return Kit.action(Object.assign({}, APP_ACTION_MEMBERS, extra || {}));
};

const APP_WRITE = appAction({ warnings: Kit.listOf(SCOPE_WARNING) });

const CERTIFICATE_ISSUED = Kit.closed({
  serialHex: STR, subject: STR, keyAlg: STR, label: NULL_STR, notBefore: STR,
  notAfter: STR, thumbprint: STR, certificatePem: STR,
  chainPem: Kit.oneOrMany(STR), implicitName: STR
});

// `tlsClientCertificates.bundle()`. Each file travels as `text` or as `base64`.
const BUNDLE_FILE = Kit.closed({ name: STR, mime: STR, text: STR,
base64: STR });

const CERTIFICATE_BUNDLE = Kit.closed({
  pkcs12: BUNDLE_FILE, key: BUNDLE_FILE, chain: BUNDLE_FILE
});

const CERTIFICATE_ISSUE = appAction({
  purpose: STR, certificate: CERTIFICATE_ISSUED, files: CERTIFICATE_BUNDLE
});

const REVOCATION_ENTRY = Kit.nullable(Kit.closed({
  serialHex: STR, revokedAt: Kit.oneOf(STR, NUM), reason: STR, reasonCode: NUM,
  reasonWhat: STR, subject: STR, note: STR
}));

const CERTIFICATE_REVOKE = appAction({
  certificate: REVOKED_CERTIFICATE, reason: STR, entry: REVOCATION_ENTRY,
  why: STR
});

const STORED_CERTIFICATE_ACTION = appAction({
  dn: NULL_STR, certificates: Kit.listOf(STORED_CERTIFICATE), rule: STR,
  sha256: STR
});

const CLIENT_SECRET_ACTION = appAction({
  clientSecret: STR, secretId: STR, expiresAt: NUM, replaced: BOOL,
  overlapUntil: NUM, left: INT
});

const ACCESS_TYPE_ACTION = appAction({
  type: STR, definition: OPERATOR_JSON
});

const FGA_ACTION = appAction({
  policy: STR, enforced: BOOL, created: BOOL, failure: STR,
  peps: Kit.closed({
    group: STR, authzenGroup: STR, total: INT, truncated: BOOL, unlocated: INT,
    holders: Kit.listOf(PEP_HOLDER),
    granted: Kit.listOf(PEP_HOLDER), held: Kit.listOf(PEP_HOLDER),
    failed: Kit.listOf(PEP_HOLDER)
  })
});

// What `sp_metadata.ts`'s `consume()` says of a document it read, with its
// refusal.
const SP_METADATA_ACTION = appAction({
  how: STR, entityId: STR, signature: STR, certificateUse: STR,
  signingCertificates: INT, assertionConsumerServices: Kit.listOf(CLAIM_VALUE),
  singleLogoutServices: Kit.listOf(CLAIM_VALUE), nameIdFormats: STRS,
  authnRequestsSigned: BOOL, wantAssertionsSigned: BOOL, validUntil: NULL_STR,
  cacheDuration: NULL_STR, skipped: STRS, url: STR, why: STR
});

// `protected_resource_metadata.ts`'s `analyse()` or a refusal. The document is
// the
// resource's own (RFC 9728), and a refusal may name a status or the members
// read.
const THIRD_PARTY_METADATA = Kit.freeForm(
  'An RFC 9728 document as the resource published it, which may carry ' +
  'extensions and a signed form: the document\'s, not this service\'s.');

const RESOURCE_METADATA_ACTION = appAction({
  source: STR, url: STR, filename: STR, contentType: STR,
  document: THIRD_PARTY_METADATA, compact: STR, pretty: STR,
  members: Kit.listOf(Kit.closed({
    member: STR, value: THIRD_PARTY_METADATA, known: BOOL, type: STR, what: STR,
    maps: STR, problem: Kit.oneOf(STR, { type: 'null' })
  })),
  extensions: STRS, signedMetadata: THIRD_PARTY_METADATA,
  resourceCheck: Kit.closed({
    checked: BOOL, matches: NULL_BOOL, expected: STRS, wellKnownUrl: NULL_STR,
    why: STR
  }),
  authorizationServers: Kit.closed({
    listed: INT, matched: INT, allMatched: BOOL, anyUnmatched: BOOL,
    rows: Kit.listOf(Kit.closed({
      issuer: CLAIM_VALUE, matched: BOOL, authorizationServer: STR
    })),
    realm: THIRD_PARTY_METADATA
  }),
  plan: Kit.closed({
    detailsTypeLines: STRS, name: STR, identifier: STR, clientId: STR,
    baseUri: STR, audience: STR, protocols: STRS,
    permissions: Kit.listOf(THIRD_PARTY_METADATA), permissionLines: STRS,
    warnings: STRS
  }),
  warnings: STRS, status: NUM
});

// A list row's `$ref` keeps the operation's name; `getApplications` is a list
// or
// one application, whose `page` is a number on one and an object on the other.
//
// ONE CLOSED OBJECT, NOT `oneOf`: a validator's refusal of a union names every
// branch's members, and STS-API-0139 is read by a person. Nothing is opened by
// it, since each member is still declared and typed.
const APPLICATION_LIST: Json = Kit.closed(Object.assign({},
  APPLICATIONS_LIST.properties, APPLICATION_DETAIL.properties, {
    page: Kit.oneOf(INT, APPLICATION_PAGE),
    kinds: Kit.listOf(Kit.oneOf(STR, KIND_ROW)),
    protocols: Kit.listOf(Kit.oneOf(STR, PROTOCOL_ROW)),
    registered: Kit.oneOf(BOOL, NUM)
  }));

export = {
  components: {
    IssuedRecord: ISSUED_RECORD,
    IssuedSet: ISSUED_SET,
    IssuedSetDetail: ISSUED_SET_DETAIL,
    IssuedList: ISSUED_LIST,
    TokenLifetimes: TOKEN_LIFETIMES,
    CredentialClaims: CREDENTIAL_CLAIMS,
    VerifierRequest: VERIFIER_REQUEST,
    AuthorizationServerList: AUTHORIZATION_SERVER_LIST,
    ApplicationList: APPLICATION_LIST,
    NewApplicationForm: NEW_APPLICATION_FORM
  } as Record<string, unknown>,
  operations: {
    getCredentialStatus: { '200': CREDENTIAL_STATUS },
    suspendCredential: { '200': STATUS_CHANGE },
    reinstateCredential: { '200': STATUS_CHANGE },
    revokeCredential: { '200': STATUS_CHANGE },
    publishStatusList: {
      '200': Kit.action({ purpose: STR, published: BOOL })
    },
    getCredentialLineage: {
      '200': Object.assign(Kit.media('image/svg+xml'),
                           { schema: CREDENTIAL_LINEAGE })
    },
    revokeToken: { '200': Kit.action({ jti: STR }) },
    restoreToken: { '200': Kit.action({ jti: STR }) },
    revokeIssuedArtifact: { '200': TOKEN_ARTIFACT_ACTION },
    restoreIssuedArtifact: { '200': TOKEN_ARTIFACT_ACTION },
    revokeIssuedSet: { '200': TOKEN_SET_ACTION },
    restoreIssuedSet: { '200': TOKEN_SET_ACTION },
    revokeTokensByKind: { '200': TOKEN_COUNT_ACTION },
    revokeTokensBySubject: { '200': TOKEN_COUNT_ACTION },
    revokeTokensByUser: { '200': TOKEN_COUNT_ACTION },
    revokeAllTokens: { '200': TOKEN_COUNT_ACTION },
    getIssued: { '400': Kit.action() },
    getApplications: { '400': Kit.action() },
    getUsedAssertions: { '200': USED_ASSERTIONS, '400': Kit.action() },
    getOauth2Settings: { '200': PROTOCOL_SETTINGS_PAGE },
    getOid4vciSettings: { '200': PROTOCOL_SETTINGS_PAGE },
    getOid4vpSettings: { '200': PROTOCOL_SETTINGS_PAGE },
    setTokenLifetimes: {
      '200': Kit.action({
        applied: STRS, changed: STRS, settings: Kit.listOf(SETTING)
      })
    },
    resetTokenLifetimes: {
      '200': Kit.action({ cleared: STRS, settings: Kit.listOf(SETTING) })
    },
    selectCredentialClaims: { '200': CLAIM_SELECTION },
    addCredentialClaim: { '200': CLAIM_SELECTION },
    removeCredentialClaim: { '200': CLAIM_SELECTION },
    resetCredentialClaims: { '200': CLAIM_SELECTION },
    populateDirectory: { '200': CLAIM_SELECTION },
    selectRequestedClaims: { '200': REQUESTED_CLAIMS },
    addRequestedClaim: { '200': REQUESTED_CLAIMS },
    removeRequestedClaim: { '200': REQUESTED_CLAIMS },
    resetRequestedClaims: { '200': REQUESTED_CLAIMS },
    setRequestFormat: { '200': REQUESTED_CLAIMS },
    startVerification: { '200': VERIFICATION_STARTED },
    getVerifications: { '200': VERIFICATIONS, '404': VERIFICATION_NOT_FOUND },
    getLastCredentialRequest: { '200': LAST_CREDENTIAL_REQUEST },
    getCredentialNotification: { '200': CREDENTIAL_NOTIFICATION },
    createAuthorizationServer: { '200': AS_ACTION },
    setAuthorizationServerMember: { '200': AS_ACTION },
    removeAuthorizationServerMember: { '200': AS_ACTION },
    resetAuthorizationServerMember: { '200': AS_ACTION },
    deleteAuthorizationServer: { '200': AS_ACTION },
    createApplication: { '200': appAction() },
    setApplicationAttribute: { '200': APP_WRITE },
    addApplicationValue: { '200': APP_WRITE },
    removeApplicationValue: { '200': APP_WRITE },
    updateApplicationFields: { '200': APP_WRITE },
    confirmApplicationReturnAddress: { '200': appAction() },
    discardApplicationReturnAddress: { '200': appAction() },
    addApplicationOwner: {
      '200': appAction({ owner: STR, owners: Kit.listOf(OWNER_ROW) })
    },
    removeApplicationOwner: {
      '200': appAction({ owner: STR, owners: Kit.listOf(OWNER_ROW) })
    },
    regenerateApplicationClientSecret: { '200': CLIENT_SECRET_ACTION },
    rotateApplicationClientSecret: { '200': CLIENT_SECRET_ACTION },
    addApplicationClientSecret: { '200': CLIENT_SECRET_ACTION },
    removeApplicationClientSecret: { '200': CLIENT_SECRET_ACTION },
    revealApplicationSecret: {
      '200': appAction({ secret: STR, value: STR })
    },
    generateApplicationDidKey: {
      '200': appAction({
        did: NULL_STR, kid: STR, algorithm: STR, verificationMethod: STR,
        documentUrl: STR,
        publicJwk: Kit.mapOf(Kit.oneOf(STR, NUM, STRS),
                             'A JWK\'s members, which its algorithm decides.'),
        privateJwk: Kit.mapOf(Kit.oneOf(STR, NUM, STRS),
                              'A JWK\'s members, which its algorithm decides.'),
        privateKeyPem: NULL_STR, replaced: BOOL, why: STR
      })
    },
    signApplicationDomainLinkage: {
      '200': appAction({
        why: STR, did: NULL_STR, origin: STR, kid: STR,
        didConfiguration: Kit.closed({
          '@context': CLAIM_VALUE, linked_dids: STRS
        }),
        filename: STR, hostAt: STR
      })
    },
    setApplicationCustomClaim: {
      '200': appAction({ set: STR, claims: Kit.listOf(CLAIM_ROW) })
    },
    removeApplicationCustomClaim: {
      '200': appAction({ set: STR, claims: Kit.listOf(CLAIM_ROW) })
    },
    setApplicationClaimAttributes: {
      '200': appAction({
        set: STR, inherited: BOOL, attributes: Kit.nullable(STRS)
      })
    },
    setApplicationClaimSelections: {
      '200': appAction({
        sets: Kit.listOf(Kit.closed({
          set: STR, changed: BOOL, inherited: BOOL, attributes: STRS
        }))
      })
    },
    inheritApplicationClaimAttributes: {
      '200': appAction({
        set: STR, inherited: BOOL, attributes: Kit.nullable(STRS)
      })
    },
    setApplicationPermissionClaims: {
      '200': appAction({
        permission: STR, attributes: Kit.nullable(STRS),
        mappings: Kit.mapOf(STRS, 'Each permission\'s claims.')
      })
    },
    clearApplicationPermissionClaims: {
      '200': appAction({
        permission: STR, attributes: Kit.nullable(STRS),
        mappings: Kit.mapOf(STRS, 'Each permission\'s claims.')
      })
    },
    setApplicationAccessType: { '200': ACCESS_TYPE_ACTION },
    removeApplicationAccessType: { '200': ACCESS_TYPE_ACTION },
    setApplicationAccessTypeRow: { '200': ACCESS_TYPE_ACTION },
    removeApplicationAccessTypeRow: { '200': ACCESS_TYPE_ACTION },
    setApplicationAccessTypeNotForPolicy: { '200': ACCESS_TYPE_ACTION },
    enableApplicationFga: { '200': FGA_ACTION },
    disableApplicationFga: { '200': FGA_ACTION },
    createApplicationFgaPolicy: { '200': FGA_ACTION },
    resetApplicationFgaPolicy: { '200': FGA_ACTION },
    issueApplicationTlsClientCertificate: { '200': CERTIFICATE_ISSUE },
    revokeApplicationTlsClientCertificate: { '200': CERTIFICATE_REVOKE },
    issueApplicationSigningCertificate: { '200': CERTIFICATE_ISSUE },
    revokeApplicationSigningCertificate: { '200': CERTIFICATE_REVOKE },
    addApplicationCertificate: { '200': STORED_CERTIFICATE_ACTION },
    removeApplicationCertificate: { '200': STORED_CERTIFICATE_ACTION },
    issueApplicationSoftwareStatement: {
      '200': appAction({
        softwareStatement: STR,
        claims: Kit.freeForm(
          'A software statement\'s claims: RFC 7591 client metadata the ' +
          'operator asked it to fix, beside its registered claims.')
      })
    },
    revokeApplicationRegistration: { '200': appAction() },
    refreshApplicationMetadata: { '200': SP_METADATA_ACTION },
    loadProtectedResourceMetadata: { '200': RESOURCE_METADATA_ACTION },
    exportApplicationLdif: {
      '200': appAction({
        credentials: BOOL, attributes: STRS, leftOut: STRS, ldif: STR,
        files: Kit.listOf(BUNDLE_FILE)
      })
    },
    importApplicationLdif: { '200': appAction() },
    deleteApplication: { '200': appAction() },
    getOauth2Monitor: { '200': OAUTH2_MONITOR, '400': Kit.action() },
    deletePushedRequest: {
      '200': Kit.action({
        request_uri_digest: STR, client_id: CLAIM_VALUE, state: STR
      })
    },
    getGrants: { '200': GRANTS },
    revokeGrant: { '200': Kit.action({ revoked: INT }) },
    getClaimProviders: { '200': CLAIM_PROVIDERS },
    addClaimProvider: { '200': Kit.action() },
    updateClaimProvider: { '200': Kit.action() },
    removeClaimProvider: { '200': Kit.action() },
    revokeClaimSourceLink: { '200': Kit.action() },
    getProviderCommands: { '200': PROVIDER_COMMANDS },
    sendAccountCommand: { '200': COMMAND_ACTION },
    sendTenantCommand: { '200': COMMAND_ACTION },
    retryCommandDelivery: { '200': COMMAND_ACTION }
  } as Record<string, Record<string, unknown>>
};
