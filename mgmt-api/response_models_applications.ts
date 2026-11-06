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
  csvValueNotes: Kit.mapOf(STR, 'The sentence beside each of a list\'s values.'),
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
  settings: SETTINGS_BLOCK, leadHtml: STR, alsoHtml: STRS
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
  looks: Kit.mapOf(NODE_LOOK, 'How each node of the graph is drawn, by its id.'),
  label: STR, svg: STR, subjectKey: STR,
  facts: Kit.closed({
    users: Kit.mapOf(BOOL, 'Who in the answer has a user page.'),
    apps: Kit.mapOf(Kit.closed({ name: STR, dnLabel: STR }),
                    'Which values in the answer are applications.')
  })
});

// ---------------------------------------------------------------------------
// THE TEN TOKEN ACTIONS, `tokenAction()`. One action's `revoked` is a count; the
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
// A subject's claims are the catalogue's (`VC_ATTRIBUTES`), one level of nesting
// at most (`address`, `place_of_birth`), and each value a directory value or a
// generated one: never deeper.
// ---------------------------------------------------------------------------
const NESTED_CLAIM = Kit.oneOf(CLAIM_VALUE, Kit.mapOf(CLAIM_VALUE,
  'A claim\'s members, as `address` has.'));

const CREDENTIAL_CLAIMS: Json = Kit.closed({
  selected: STRS, defaults: STRS, ldpOmitted: STRS,
  attributes: Kit.listOf(Kit.closed({
    ldap: STR, claim: STR, label: STR, schema: STR, ldpTerm: STR, selected: BOOL,
    example: Kit.closed({ value: CLAIM_VALUE, source: STR })
  })),
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
  'issuer\'s: its names and values are the presentation\'s, not this service\'s.');

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
  authorizationServers: Kit.listOf(Kit.closed(Object.assign({}, AS_PROFILE_MEMBERS,
    { drift: AS_DRIFT })))
}, FLAT_PAGING));

const AS_DETAIL = Kit.closed(Object.assign({}, AS_PROFILE_MEMBERS, {
  found: BOOL, drift: AS_DRIFT,
  capabilities: Kit.freeForm(
    'The RFC 8414 document this server would publish: what this service ' +
    'builds, with the operator\'s overrides, whose values are any JSON.'),
  members: Kit.listOf(AS_MEMBER), memberGroups: STRS
}));

const AS_ACTION = Kit.action({ profile: Kit.nullable(AS_PROFILE) });

export = {
  components: {
    IssuedRecord: ISSUED_RECORD,
    IssuedSet: ISSUED_SET,
    IssuedSetDetail: ISSUED_SET_DETAIL,
    IssuedList: ISSUED_LIST,
    TokenLifetimes: TOKEN_LIFETIMES,
    CredentialClaims: CREDENTIAL_CLAIMS,
    VerifierRequest: VERIFIER_REQUEST,
    AuthorizationServerList: Kit.oneOf(AS_LIST, AS_DETAIL)
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
    getUsedAssertions: { '200': USED_ASSERTIONS },
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
    deleteAuthorizationServer: { '200': AS_ACTION }
  } as Record<string, Record<string, unknown>>
};
