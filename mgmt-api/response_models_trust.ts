// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_trust.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): Federation, OpenID Federation, PKI, ACME, SCEP, EST,
// SPIFFE, Shared Signals, CAEP, RISC, GNAP.
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
//
// **A VIEW THAT MIRRORS A PROTOCOLS PAGE IS ONE `closed()`, NEVER A
// `oneOf()`.** `ResponseModels.apply()` adds `protocolEndpoints` to a model
// that has `properties`, and a union has none: a list and a detail written as
// a union would refuse the member `sendJson()` adds. So those views' models are
// the union of their members in one object, and only `required` is left out.
//
// **WHAT A PARTNER SENT IS NOT THIS SERVICE'S TO TYPE.** `PARTNER_VALUE` and
// the other free-form uses below are each a value a foreign document carried
// and this service keeps or relays as it arrived, and a strict type there would
// turn one partner's odd document into a 500 on an operator's own page.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

const STR = Kit.str();
const INT = Kit.int();
const NUM = Kit.num();
const BOOL = Kit.bool();
const STRS = Kit.listOf(STR);
const NSTR = Kit.nullable(STR);
const NINT = Kit.nullable(INT);
const NBOOL = Kit.nullable(BOOL);
const COUNTS = Kit.mapOf(NUM);
// A moment some rows hold as an ISO string and others as milliseconds.
const WHEN = Kit.nullable(Kit.oneOf(STR, NUM));
// A value that is any scalar a setting or a counter may hold.
const SCALAR = Kit.oneOf(STR, NUM, BOOL, { type: 'null' });

// The paging object `AdminViews.pagingJson()` writes.
const PAGING = Kit.closed({
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT, total: INT,
  param: STR, noun: STR
});

// One row `common/config.js`'s `describe()` writes. `default` and `value` take
// the type of the setting, a list included.
const SETTING_VALUE = Kit.oneOf(STR, NUM, BOOL, { type: 'null' },
                                Kit.listOf(SCALAR));
const SELECT_RULE = Kit.listOf(Kit.closed({
  setting: STR, values: STRS, on: BOOL, canBeOn: BOOL
}));
const SETTING_ROW = Kit.closed({
  key: STR, group: STR, label: STR, description: STR, type: STR,
  enumValues: Kit.listOf(SCALAR), csvValues: Kit.listOf(SCALAR), ordered: BOOL,
  csvValueNotes: Kit.mapOf(STR),
  selectAll: Kit.closed({ onlyWhileOn: SELECT_RULE,
                          aloneWhileOn: SELECT_RULE }),
  min: NUM, max: NUM, step: NUM,
  value: SETTING_VALUE, text: NSTR, source: STR, editable: BOOL,
  restartReason: STR, editRefusal: STR, env: Kit.oneOrMany(STR),
  legacyEnv: Kit.oneOrMany(STR), appconfigPath: STR, default: SETTING_VALUE,
  realmSettable: BOOL, overridden: BOOL
});
// `AdminConsole.configSettingsJson()`: a page's settings, or null where the
// console has not filled the slot.
const SETTINGS = Kit.nullable(Kit.closed({
  page: STR,
  groups: Kit.listOf(Kit.closed({ group: STR,
                                  settings: Kit.listOf(SETTING_ROW) })),
  settingCount: INT, editableCount: INT, overridden: STRS, setWith: STR,
  context: Kit.closed({
    configFile: NSTR, defaultsFile: NSTR, persistsAppconfig: BOOL,
    persistsRealms: BOOL, persistenceMode: STR, inRealm: BOOL, realmId: STR
  }),
  sharedWith: Kit.mapOf(STRS)
}));

// A row of `protocolEndpoints`, which `sendJson()` adds to a GET mirroring a
// Protocols page. `apply()` writes `admin_api_spec.ts`'s copy over this one,
// and only the SPIFFE sockets' rows carry `listening`: see SPIFFE, below.
const ENDPOINT_ROW = Kit.closed({
  name: STR, methods: Kit.oneOrMany(STR), url: STR, route: STR, transport: STR,
  registered: BOOL, listening: BOOL
});

const PARTNER_VALUE = Kit.freeForm(
  'A value of a document a partner published or answered, kept and relayed ' +
  'as it arrived: nothing here narrows it, and a partner\'s odd value must ' +
  'not turn an operator\'s own page into a failure.');

// ---------------------------------------------------------------------------
// FEDERATION. A relationship's attributes are `federation.js`'s SCHEMA, which
// is why the record is closed over the names rather than a map of them: they
// are this service's own schema, and a new one owes a row here beside its row
// there. `recordFromAttributes()` gives every single-valued one a string and
// every multi-valued one a list.
// ---------------------------------------------------------------------------
const FED_SINGLE = ['fedId', 'cn', 'fedName', 'fedRole', 'fedProtocol',
  'fedProvider', 'fedPeer', 'fedLocalEntityId', 'fedEnabled', 'fedSsoUrl',
  'fedTokenUrl', 'fedUserinfoUrl', 'fedJwksUri', 'fedEmailsUrl', 'fedJwks',
  'fedTrustAnchor', 'fedSigningCertificate', 'fedClientId', 'fedClientSecret',
  'fedResponseMode', 'fedTeamId', 'fedKeyId', 'fedClientSigningKey',
  'fedTokenAuth', 'fedScope', 'fedResponseType', 'fedIdTokenSignedResponseAlg',
  'fedUserinfoSignedResponseAlg', 'fedRefreshTokens', 'fedRefreshEverySeconds',
  'fedRegister', 'fedRegisteredIssuer', 'fedRequestObject',
  'fedRequestObjectSigningAlg', 'fedWebFinger', 'fedDiscovery',
  'fedInitiateLogin', 'fedBinding', 'fedSignRequest', 'fedUsernameSource',
  'fedSubjectClaim', 'fedAutocreateUsers', 'fedUpdateUserAttributes',
  'fedProvisionGroups', 'fedProvisionCap', 'fedProvisionIdleMinutes',
  'fedSubjectPolicy', 'fedSubjectPattern', 'fedMayAssertAdministrators',
  'fedSignalEmailMatch', 'fedSignalsEnabled', 'fedSignalsIssuer',
  'fedSignalsDelivery', 'fedSignalsTokenUrl', 'fedSignalsClientId',
  'fedSignalsClientSecret', 'fedSignalsScope', 'fedSignalsBearer', 'fedSloUrl',
  'fedSloBinding', 'fedEndSessionUrl', 'fedAcceptSignout',
  'fedRequireSignedLogout', 'fedEncryptionKeyType', 'fedKeyManagementAlgorithm',
  'fedContentEncryptionAlgorithm', 'fedAllowUnencrypted', 'fedAllowUnsolicited',
  'fedApplication', 'fedAuthnMechanism', 'fedAuthnRelationship', 'fedFirstSeen',
  'fedLastSeen', 'fedAuthentications', 'fedUsers', 'fedLastUser',
  'fedLastError', 'fedLastErrorAt'];
const FED_MULTI = ['description', 'fedAllowedTenants', 'fedAuthorizeParams',
  'fedAttributeMap', 'fedSubjectGroup', 'fedSubjectDomain',
  'fedHomeRealmDomain', 'fedSignalsEvents', 'fedEncryptionKey', 'fedRelease',
  'fedApplicationUse'];
const FED_ATTRIBUTES: Json = {};
FED_SINGLE.forEach(function (name) {
  FED_ATTRIBUTES[name] = STR;
});
FED_MULTI.forEach(function (name) {
  FED_ATTRIBUTES[name] = STRS;
});
// A directory entry as `ldap_server.js`'s `entryObject()` hands it over. Its
// attribute names are data: an entry carries what an `ldapmodify` gave it.
const DIRECTORY_ENTRY = Kit.closed({
  dn: STR, origin: STR, createdAt: WHEN, modifiedAt: WHEN,
  operational: STRS, attributes: Kit.mapOf(STRS)
});
// `federation.get()`: the attributes, where the entry is, and the entry. See
// the report on #1353: `entry` carries the sealed credentials.
const FED_RECORD = Kit.closed(Object.assign({}, FED_ATTRIBUTES, {
  dn: STR, createdAt: WHEN, modifiedAt: WHEN, entry: DIRECTORY_ENTRY
}));
const FED_READINESS = Kit.closed({ ready: BOOL, missing: STRS });
const FED_ACTION = Kit.action({
  relationship: Kit.nullable(FED_RECORD), readiness: FED_READINESS, kid: STR
});
const FED_SCHEMA_ROW = Kit.closed({
  name: STR, kind: STR, role: STR, from: STR, what: STR, standard: BOOL,
  sensitive: BOOL, enum: STRS,
  editable: Kit.oneOf(BOOL, STR)
});
const FED_ROW = Kit.closed({
  id: STR, name: STR, role: STR, roleLabel: STR, protocol: STR,
  protocolLabel: STR, peer: STR, application: STR, category: STR, provider: STR,
  providerLabel: STR, enabled: BOOL, ready: BOOL, missing: STRS, usable: BOOL,
  signsIn: BOOL, signalsEnabled: BOOL, releases: STRS, mappings: STRS,
  authentications: INT, users: INT, lastUser: STR, lastSeen: STR,
  lastError: STR, lastErrorAt: STR, dn: STR
});
const FED_SIGN_OUT = {
  singleLogout: STR, signOutCleanup: STR, backchannelLogout: STR,
  frontchannelLogout: STR, postLogoutRedirect: STR
};
const FED_PATHS = Kit.closed({
  base: STR, login: STR, acs: STR, metadata: STR, link: STR,
  notifications: STR, stepup: STR, profile: STR, slo: STR,
  backchannelLogout: STR, frontchannelLogout: STR, jwks: STR,
  atprotoClient: STR, initiateLogin: STR, fragmentScript: STR,
  requestObject: STR, webfinger: STR, signals: STR
});
// A public JWK of an encryption key, or a partner-facing key row. A JWK's
// members depend on its key type (RFC 7517 section 4) and the AKP ones are
// post-quantum, so they are listed and a member the crypto engine adds is a
// model change.
const JWK = Kit.closed({
  kty: STR, use: STR, alg: STR, kid: STR, key_ops: STRS, ext: BOOL,
  crv: STR, x: STR, y: STR, n: STR, e: STR, pub: STR, ek: STR,
  x5c: STRS, x5t: STR, 'x5t#S256': STR, x5u: STR
});
const FED_ENCRYPTION = Kit.nullable(Kit.closed({
  policy: Kit.closed({ family: STR, keyType: STR, management: STR,
                       content: STR }),
  required: BOOL, allowUnencrypted: BOOL, graceS: NUM, current: STR,
  certificatePem: STR, jwk: Kit.nullable(JWK),
  keys: Kit.listOf(Kit.closed({
    kid: STR, keyType: STR, state: STR, notAfter: WHEN, createdAt: WHEN,
    retiresAt: WHEN, decrypts: BOOL, sealed: BOOL
  }))
}));
const FED_BLOCK = Kit.closed({
  relationship: STR, username: STR, at: STR, event: STR, jti: STR, by: STR
});
// `SsfTransmitters.view()`: what this service holds of a partner's stream. The
// members are this service's; `config` and `stream` hold what the partner
// answered, so their values are `PARTNER_VALUE`.
const FED_SIGNALS = Kit.closed({
  relationship: STR, name: STR, kind: STR, enabled: BOOL, signalsEnabled: BOOL,
  receiving: BOOL, issuer: STR, delivery: STR, eventsRequested: STRS,
  credential: Kit.closed({ method: STR, tokenEndpoint: STR, clientId: STR,
                           scope: STR, secretHeld: BOOL }),
  ready: BOOL, missing: STRS,
  config: Kit.nullable(Kit.closed({
    issuer: PARTNER_VALUE, jwks_uri: PARTNER_VALUE,
    configuration_endpoint: PARTNER_VALUE, status_endpoint: PARTNER_VALUE,
    add_subject_endpoint: PARTNER_VALUE, remove_subject_endpoint: PARTNER_VALUE,
    verification_endpoint: PARTNER_VALUE,
    delivery_methods_supported: Kit.listOf(PARTNER_VALUE)
  })),
  discoveryUrl: STR, discoveredAt: STR, streamId: STR,
  stream: Kit.nullable(Kit.closed({
    stream_id: PARTNER_VALUE, aud: PARTNER_VALUE,
    events_supported: PARTNER_VALUE, events_requested: PARTNER_VALUE,
    events_delivered: PARTNER_VALUE,
    delivery: Kit.closed({ method: PARTNER_VALUE, endpoint_url: PARTNER_VALUE })
  })),
  streamDelivery: STR, streamAud: STRS, pollEndpoint: STR, pushEndpoint: STR,
  pushEndpointSet: BOOL, state: STR, streamStatus: STR, verifiedAt: STR,
  lastPollAt: STR, lastPollResult: STR, lastError: STR,
  counts: Kit.closed({ received: INT, verified: INT, refused: INT,
                       acted: INT }),
  blocks: Kit.listOf(FED_BLOCK)
});
const FED_REACTION = Kit.closed({
  event: STR, reaction: STR, done: BOOL, skipped: STR, observed: BOOL, why: STR,
  ended: INT, revoked: INT, gnapGrants: INT, oauthGrants: INT, tokens: INT,
  codes: INT
});
const FED_ARRIVAL = Kit.closed({
  relationship: STR, jti: STR, via: STR, receivedAt: STR, verified: BOOL,
  refusal: STR, why: STR, events: STRS,
  subject: Kit.freeForm('An RFC 9493 subject identifier as a partner\'s SET ' +
                        'carried it, in whatever format that partner chose.'),
  person: STR, mapping: STR, reactions: Kit.listOf(FED_REACTION), iat: NUM
});
const FED_OUTBOUND = Kit.nullable(Kit.closed({
  application: STR,
  streams: Kit.listOf(Kit.closed({
    streamId: STR, delivery: STR, status: STR, eventsDelivered: STRS,
    createdBy: STR, lastActivityAt: STR, dead: BOOL, deadLetters: INT
  }))
}));
const FED_SIGNALS_ACTION = Kit.action({
  signals: FED_SIGNALS,
  answer: Kit.freeForm('The partner\'s own answer to an SSF stream ' +
                       'management call (SSF 1.0 section 8), relayed as it ' +
                       'arrived; null when it sent none.'),
  polled: Kit.closed({ received: INT, acted: INT, refused: INT, rounds: INT,
                       why: STR })
});
const FEDERATION_RELATIONSHIP_LIST = Kit.closed({
  // The list.
  relationshipCount: INT, matched: INT, shown: INT, ready: Kit.oneOf(INT, BOOL),
  filter: Kit.closed({ q: NSTR, role: NSTR, category: NSTR }),
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  container: NSTR, max: NUM, settings: SETTINGS,
  roles: Kit.listOf(Kit.closed({ role: STR, label: STR, short: STR,
                                 what: STR })),
  protocols: Kit.listOf(Kit.closed({
    protocol: STR, label: STR, family: STR, what: STR, needs: STRS, spec: STR,
    signalsOnly: BOOL
  })),
  paths: FED_PATHS, paging: PAGING, roleCounts: COUNTS, categoryCounts: COUNTS,
  consumerProviders: Kit.closed({
    on: BOOL,
    catalogue: Kit.listOf(Kit.closed({
      id: STR, label: STR, protocol: STR, generic: BOOL, docs: STR, note: STR,
      defaults: Kit.mapOf(STR), needs: STRS, adapters: STRS, subject: STR,
      emailVerified: STR, claims: STRS
    }))
  }),
  enabledNotConfigured: INT, authentications: INT,
  relationships: Kit.listOf(FED_ROW),
  // One of them: `found`, then `federationRow()`'s members (`ready`, above, is
  // the list's count there and this row's boolean here), then the rest.
  found: BOOL,
  id: STR, name: STR, role: STR, roleLabel: STR, protocol: STR,
  protocolLabel: STR, peer: STR, application: STR, category: STR,
  provider: Kit.oneOf(STR, { type: 'null' }, Kit.closed({
    id: STR, label: STR, note: STR, docs: STR, realmOn: BOOL
  })),
  providerLabel: STR, enabled: BOOL, missing: STRS, usable: BOOL, signsIn: BOOL,
  signalsEnabled: BOOL, releases: STRS, mappings: STRS, users: INT,
  lastUser: STR, lastSeen: STR, lastError: STR, lastErrorAt: STR, dn: STR,
  endpoints: Kit.closed(Object.assign({
    assertionConsumerService: STR, login: STR, metadata: NSTR, jwks: NSTR,
    initiateLogin: NSTR
  }, FED_SIGN_OUT)),
  // The sensitive attributes read `(set — not returned)` or empty, the one
  // multi-valued one among them (`fedEncryptionKey`) included.
  fields: Kit.closed(Object.assign({}, FED_ATTRIBUTES,
                                   { fedEncryptionKey: STR })),
  editable: Kit.listOf(FED_SCHEMA_ROW),
  unmappedAttributes: Kit.listOf(Kit.closed({ name: STR, refused: STR,
                                              first: STR, last: STR })),
  signals: Kit.nullable(FED_SIGNALS),
  signalArrivals: Kit.listOf(FED_ARRIVAL),
  outboundSignals: FED_OUTBOUND,
  encryption: FED_ENCRYPTION,
  links: Kit.listOf(Kit.closed({ username: STR, dn: STR, link: STR, issuer: STR,
                                 subject: STR })),
  linksPaging: PAGING,
  setFields: Kit.listOf(FED_SCHEMA_ROW),
  multiFields: Kit.listOf(FED_SCHEMA_ROW),
  signalSetFields: Kit.listOf(FED_SCHEMA_ROW),
  schema: Kit.listOf(FED_SCHEMA_ROW),
  enumLabels: Kit.mapOf(STR),
  defaultSubjectPolicy: STR, autocreateDefault: BOOL, subjectPolicy: STR,
  encrypts: BOOL, base: STR, loginHref: STR, metadataUrl: STR,
  signOut: Kit.closed(FED_SIGN_OUT),
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});

const FED_CHECK_PARTNER = Kit.action({
  errorCode: STR, why: STR, issuer: STR,
  endpoints: Kit.closed({ authorization_endpoint: STR, token_endpoint: STR,
                          userinfo_endpoint: STR, jwks_uri: STR }),
  discovered: BOOL, keys: INT, readable: INT
});

// What a GET answers when  refuses a parameter.
const REFUSED = Kit.action();

const operations: Record<string, Record<string, unknown>> = {
  getFederationRelationships: { '400': REFUSED },
  createFederationRelationship: { '200': FED_ACTION },
  setFederationField: { '200': FED_ACTION },
  addFederationValue: { '200': FED_ACTION },
  removeFederationValue: { '200': FED_ACTION },
  enableFederationRelationship: { '200': FED_ACTION },
  disableFederationRelationship: { '200': FED_ACTION },
  checkFederationPartner: { '200': FED_CHECK_PARTNER },
  registerAtFederationPartner: { '200': Kit.action({ clientId: STR,
                                                     issuer: STR }) },
  rotateFederationKey: { '200': FED_ACTION },
  discoverFederationSignals: { '200': FED_SIGNALS_ACTION },
  createFederationSignalsStream: { '200': FED_SIGNALS_ACTION },
  readFederationSignalsStream: { '200': FED_SIGNALS_ACTION },
  updateFederationSignalsStream: { '200': FED_SIGNALS_ACTION },
  replaceFederationSignalsStream: { '200': FED_SIGNALS_ACTION },
  deleteFederationSignalsStream: { '200': FED_SIGNALS_ACTION },
  readFederationSignalsStatus: { '200': FED_SIGNALS_ACTION },
  verifyFederationSignalsStream: { '200': FED_SIGNALS_ACTION },
  pollFederationSignals: { '200': FED_SIGNALS_ACTION },
  setFederationSignalsStatus: { '200': FED_SIGNALS_ACTION },
  addFederationSignalsSubject: { '200': FED_SIGNALS_ACTION },
  removeFederationSignalsSubject: { '200': FED_SIGNALS_ACTION },
  unblockFederationSignals: { '200': FED_SIGNALS_ACTION },
  deleteFederationRelationship: { '200': Kit.action() }
};

const components: Record<string, unknown> = {
  FederationRelationshipList: FEDERATION_RELATIONSHIP_LIST
};

// ---------------------------------------------------------------------------
// PKI. `admin-ui/pki_admin.ts`'s `pkiJson()` and `pkiAction()`, over
// `common/pki.js`, `common/pki_revocation.js`, `common/person_assertions.js`
// and `common/pki_authoring.ts`. `classify()` there writes `pqc` onto every
// object under `chain`, `tree` and `workbench` that carries a certificate, so
// those rows all declare it.
// ---------------------------------------------------------------------------
const PQC = Kit.nullable(Kit.closed({
  kind: STR, algorithm: STR, label: STR, family: STR, standard: STR
}));
// A tier of a chain, `describeTier()` and `describeChain()` in one.
const CA_TIER = Kit.closed({
  tier: STR, useCase: NSTR, label: STR, what: STR, scope: NSTR, subject: STR,
  serialHex: STR, notBefore: STR, notAfter: STR, keyAlg: STR, signatureAlg: STR,
  altKeyAlg: NSTR, altSignatureAlg: NSTR, thumbprint: STR, imported: BOOL,
  certificatePem: STR, expired: BOOL, pqc: PQC
});
const PKI_CHAIN = Kit.nullable(Kit.closed({
  realm: NSTR, createdAt: WHEN, keyAlg: STR, signatureAlg: STR, altKeyAlg: NSTR,
  organisation: NSTR, country: NSTR, issuedCount: INT, persisted: BOOL,
  tiers: Kit.listOf(CA_TIER)
}));
const PKI_CERTIFIED = Kit.closed({
  slot: STR, useCase: STR, label: NSTR, alg: STR, keyAlg: STR,
  signatureAlg: STR, subject: STR, serialHex: STR, notBefore: STR,
  notAfter: STR, expired: BOOL,
  thumbprint: STR, pinned: BOOL, certificatePem: STR, chainPem: STRS,
  createdAt: WHEN, pqc: PQC
});
const PKI_TREE = Kit.closed({
  root: Kit.nullable(CA_TIER), rootBuilt: BOOL, persisted: BOOL,
  organisation: STR,
  useCases: Kit.listOf(Kit.closed({ id: STR, label: STR, scope: STR,
                                    what: STR })),
  scopes: Kit.listOf(Kit.closed({
    scope: STR, kind: STR, label: STR, built: BOOL, keyAlg: STR,
    signatureAlg: STR, altKeyAlg: NSTR, organisation: STR, country: STR,
    intermediate: Kit.nullable(CA_TIER),
    issuing: Kit.listOf(Kit.closed({
      id: STR, label: STR, what: STR, built: BOOL, ca: Kit.nullable(CA_TIER),
      certified: Kit.listOf(PKI_CERTIFIED)
    }))
  }))
});
const ID_LABEL = Kit.closed({ id: STR, label: STR, what: STR });
const SIGNATURE_ALGORITHM = Kit.closed({ id: STR, label: STR, weak: BOOL,
                                         kind: NSTR });
const PKI_KEY_ALGORITHM = Kit.closed({
  id: STR, label: STR, kind: STR, family: STR, signs: BOOL, slow: BOOL
});
// A workbench draft: one member per field of `pki_authoring.ts`'s FIELDS, whose
// names include one per X.509 key usage, EKU and Netscape bit from the crypto
// engine's tables, so the keys are read from those tables and are data here.
const PKI_DRAFT = Kit.mapOf(Kit.nullable(Kit.oneOf(STR, BOOL)));
// `describeObject()`; and the raw record `issue()` answers with, which adds the
// three key members below it.
const PKI_OBJECT = Kit.closed({
  id: STR, ca: BOOL, profile: STR, profileLabel: STR, subject: STR,
  issuerSubject: STR, issuerId: NSTR, selfSigned: BOOL, serialHex: STR,
  keyAlg: STR, keyAlgLabel: STR, signatureAlg: STR, signatureAlgLabel: STR,
  pqMode: STR, altKeyAlg: NSTR, altSigned: BOOL, notBefore: STR, notAfter: STR,
  expired: BOOL, thumbprint: STR, createdAt: WHEN, hasPrivateKey: BOOL,
  hasCsr: BOOL, certificatePem: STR, csrPem: STR, pqc: PQC,
  privateKeyPem: STR, publicKeyPem: STR, altPrivateKeyPem: NSTR,
  altPublicKeyPem: NSTR
});
const PKI_WORKBENCH = Kit.closed({
  fields: STRS,
  profiles: Kit.listOf(Kit.closed({
    id: STR, label: STR, ca: BOOL, selfSigned: BOOL, years: NUM, keyUsage: STRS,
    extKeyUsage: STRS, pathLen: NINT, note: STR
  })),
  pqModes: Kit.listOf(Kit.closed({ id: STR, label: STR, classical: BOOL,
                                   families: STRS, note: STR })),
  pqMode: STR, keyAlgorithms: Kit.listOf(PKI_KEY_ALGORITHM),
  alternativeKeyAlgorithms: Kit.listOf(PKI_KEY_ALGORITHM),
  signatureAlgorithms: Kit.listOf(SIGNATURE_ALGORITHM), signerLabel: STR,
  keystoreFormats: STRS,
  keyUsageBits: Kit.listOf(Kit.closed({ name: STR, what: STR })),
  extendedKeyUsages: Kit.listOf(Kit.closed({ name: STR, oid: STR })),
  netscapeTypes: Kit.listOf(Kit.closed({ name: STR })),
  accessMethods: STRS,
  dnFields: Kit.listOf(Kit.closed({ attr: STR, field: STR })),
  issuers: Kit.listOf(Kit.closed({
    id: STR, label: STR, subject: STR, keyAlg: STR, notAfter: STR,
    hasAlternativeKey: BOOL
  })),
  objects: Kit.listOf(PKI_OBJECT), maxObjects: INT, slowFamilies: STRS,
  draft: PKI_DRAFT
});
const REVOKED_ENTRY = Kit.closed({
  serialHex: STR, revokedAt: WHEN, reason: STR, reasonCode: INT,
  reasonWhat: STR, subject: STR, note: STR
});
const PKI_REVOCATION = Kit.closed({
  reasons: Kit.listOf(Kit.closed({ id: STR, code: INT, what: STR })),
  authorities: Kit.listOf(Kit.closed({
    scope: STR, scopeSegment: STR, ca: STR, label: STR, subject: STR,
    notAfter: STR, listName: STR,
    issued: Kit.listOf(Kit.closed({
      serialHex: STR, subject: STR, notAfter: STR, kind: STR, label: STR,
      expired: BOOL, revoked: BOOL, revokedAt: WHEN, revokedReason: NSTR,
      held: BOOL
    })),
    issuedTotal: INT, issuedPaging: PAGING, issuedSearch: NSTR,
    orphansSearch: NSTR, revoked: Kit.listOf(REVOKED_ENTRY), revokedTotal: INT,
    revokedNotIssued: Kit.listOf(REVOKED_ENTRY), revokedNotIssuedTotal: INT,
    orphansPaging: PAGING,
    crl: Kit.closed({ http: STR, ldap: NSTR }), ocsp: NSTR, caIssuers: NSTR,
    directoryDn: NSTR
  })),
  totalRevoked: INT, crlLifetimeMinutes: NUM, publishedToDirectory: BOOL
});
// One key pair of a person, as `person_assertions.js` stores and reads it.
const PERSON_KEY = Kit.closed({
  id: STR, label: STR, kid: STR, thumbprint: STR, source: STR, serialHex: STR,
  caId: NSTR, subject: STR, issuer: STR, keyAlg: STR, jwsAlg: STR,
  notBefore: STR, notAfter: STR, expiresAt: STR, certificatePem: STR,
  chainPem: STR, createdAt: WHEN, jwk: Kit.nullable(JWK), withdrawnAt: STR,
  withdrawnReason: STR, state: STR, revokedAt: WHEN, reason: NSTR,
  privateKeyHeld: BOOL, pqc: PQC
});
const PERSON_PROFILE = Kit.closed({
  hasKeyPair: BOOL, keys: Kit.listOf(PERSON_KEY), declaredIssuers: STRS,
  issuers: STRS, declared: BOOL
});
const PKI_VIEW = Kit.closed({
  realm: STR, chain: PKI_CHAIN,
  keyAlgorithms: Kit.listOf(PKI_KEY_ALGORITHM),
  signatureAlgorithms: Kit.listOf(SIGNATURE_ALGORITHM),
  tiers: Kit.listOf(Kit.closed({
    id: STR, label: STR, profile: STR, what: STR, pathLen: NINT, keyUsage: STRS,
    years: NUM
  })),
  revocation: PKI_REVOCATION, revocationNote: STR, residency: STR, encoder: STR,
  pinnedSigners: Kit.closed({
    on: BOOL, leadMinutes: NUM, warningDays: NUM,
    keys: Kit.listOf(Kit.closed({
      useCase: STR, slot: STR, unit: STR, kid: STR, alg: STR, crv: STR,
      kind: STR, role: STR, pinnedAt: STR, activatesAt: STR, retiredAt: STR,
      retiredUntil: STR, operatorCertificate: BOOL, supersedesUntil: STR,
      subject: STR, serialHex: STR, notAfter: STR, expired: BOOL, daysLeft: INT,
      thumbprint: STR, certificatePem: STR, chainPem: STRS, publicKeyPem: STR,
      publicJwk: Kit.nullable(JWK), expiringSoon: BOOL
    }))
  }),
  actions: STRS,
  issued: Kit.listOf(Kit.closed({
    identifier: STR, name: NSTR, purpose: STR, purposeLabel: STR,
    handleLabel: STR, handle: STR, expiresAt: STR, hasKeyPair: BOOL,
    privateKeyHeld: BOOL, source: STR, assertionIssuers: STRS,
    registeredOwnKeys: BOOL, pqc: PQC
  })),
  persons: Kit.listOf(Kit.closed({ username: STR, jwt: PERSON_PROFILE,
                                   saml: PERSON_PROFILE })),
  personSigningKeyMax: NUM, personRevocationReasons: STRS,
  personsStorable: BOOL,
  personAttributes: STRS, personIssuerAttribute: STR,
  subjectKinds: Kit.listOf(ID_LABEL),
  purposes: Kit.listOf(Kit.closed({ id: STR, label: STR, what: STR,
                                    attributes: STRS, issuerAttribute: STR })),
  tree: PKI_TREE, workbench: PKI_WORKBENCH, settings: SETTINGS,
  issuedPaging: PAGING, personsPaging: PAGING, issuedSearch: NSTR,
  personsSearch: NSTR, issuedShown: Kit.listOf(INT),
  personsShown: Kit.listOf(INT),
  pageDefaults: Kit.closed({
    keyAlgorithm: STR, organisation: STR, leafLifetimeDays: NUM,
    alternativeKeyAlgorithm: NSTR
  }),
  tierLabels: Kit.listOf(Kit.closed({ id: STR, label: STR })),
  serviceScope: STR,
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});

// `CertificateDetails.describe()`. The extension's decoded value is free-form:
// the certificate may be anybody's and each extension's shape is its own ASN.1
// module's, as the crypto engine's parser hands it over.
const NAME_OF_CERT = Kit.closed({
  text: STR,
  attributes: Kit.listOf(Kit.closed({ oid: STR, short: STR, label: STR,
                                      value: STR }))
});
const CERT_ALGORITHM = Kit.closed({ oid: STR, name: NSTR, parameters: NSTR });
const CERT_TIME = Kit.closed({ iso: STR, type: STR });
const DESCRIBED_CERTIFICATE = Kit.closed({
  fingerprint: STR, pem: STR,
  summary: Kit.closed({
    subject: STR, issuer: STR, serialHex: STR, notBefore: STR, notAfter: STR,
    expired: BOOL, notYetValid: BOOL, daysRemaining: INT, publicKey: STR,
    signatureAlgorithm: STR, selfIssued: BOOL, ca: BOOL, extensionCount: INT
  }),
  fingerprints: Kit.closed({ sha1: STR, sha256: STR }),
  fields: Kit.closed({
    tbsCertificate: Kit.closed({
      version: Kit.closed({ value: INT, encoded: INT }),
      serialNumber: Kit.closed({ hex: STR, decimal: STR, octets: NUM }),
      signature: CERT_ALGORITHM, issuer: NAME_OF_CERT,
      validity: Kit.closed({ notBefore: CERT_TIME, notAfter: CERT_TIME }),
      subject: NAME_OF_CERT,
      subjectPublicKeyInfo: Kit.closed({
        algorithm: CERT_ALGORITHM, description: STR,
        key: Kit.nullable(Kit.closed({
          type: STR, modulusBits: INT, publicExponent: STR, namedCurve: STR
        })),
        publicKeyOctets: INT, publicKeyHex: STR, spkiSha256: STR
      }),
      issuerUniqueID: NSTR, subjectUniqueID: NSTR,
      extensions: Kit.listOf(Kit.closed({
        oid: STR, name: STR, label: STR, critical: BOOL,
        value: Kit.freeForm('An X.509 extension\'s decoded value, on a ' +
                            'certificate that may be anybody\'s: its shape ' +
                            'is that extension\'s ASN.1 module\'s.'),
        text: NSTR, parseError: NSTR
      }))
    }),
    signatureAlgorithm: CERT_ALGORITHM, signatureAlgorithmsAgree: BOOL,
    signatureValue: Kit.closed({ octets: INT, hex: STR })
  })
});
const APPEARANCE = Kit.closed({ label: STR, where: STR });
// The list, or with `certificate` one of them; `realm` is in both.
const CERTIFICATES = Kit.closed({
  realm: STR, total: INT, matched: INT, page: INT, pages: INT, perPage: INT,
  firstRow: INT, lastRow: INT,
  certificates: Kit.listOf(Kit.closed({
    fingerprint: STR, subject: STR, issuer: STR, notAfter: STR,
    selfIssued: BOOL, appearances: Kit.listOf(APPEARANCE)
  })),
  ok: BOOL, appearances: Kit.listOf(APPEARANCE), pqc: PQC,
  fingerprint: STR, certificate: DESCRIBED_CERTIFICATE,
  chain: Kit.listOf(Kit.closed({
    position: INT, fingerprint: STR, subject: STR, issuer: STR, role: STR,
    signatureValid: NBOOL, signedBy: NSTR, expired: BOOL, notYetValid: BOOL,
    issuerMayCertify: NBOOL, anchor: NSTR, certificate: DESCRIBED_CERTIFICATE
  })),
  chainStatus: STR, chainReason: NSTR, chainTrusted: BOOL
});

// `pkiAction()`. Every refusal there carries `why` beside `errors`,
// `issue-certificate`'s carries `draft` as well, and the management API adds
// `workbench` to any answer holding a `draft`.
const PKI_REASON_FIELDS = { why: STR, draft: PKI_DRAFT,
                            workbench: PKI_WORKBENCH };
const PKI_ACTION = Kit.action(PKI_REASON_FIELDS);
const PKI_ISSUE_FIELDS = {
  purpose: STR, attributes: STRS, kid: STR, thumbprint: STR, notAfter: STR,
  jwsAlg: STR
};
const PKI_PERSON_FIELDS = {
  target: STR, person: STR, label: STR, handle: STR, serialHex: STR
};
const PKI_REVOCATION_CHECK = Kit.nullable(Kit.closed({ status: STR,
                                                       policy: STR }));

Object.assign(operations, {
  getPki: { '200': PKI_VIEW, '400': REFUSED },
  getCertificates: { '200': CERTIFICATES, '400': REFUSED },
  buildPkiChain: { '200': Kit.action(Object.assign({ chain: PKI_CHAIN },
                                                   PKI_REASON_FIELDS)) },
  issuePkiKeyPair: { '200': Kit.action(Object.assign({
    issuer: STR, declared: BOOL, certificatePem: STR, chainPem: STR,
    jwks: Kit.nullable(Kit.closed({ keys: Kit.listOf(JWK) })),
    privateKeyPem: STR
  }, PKI_ISSUE_FIELDS, PKI_PERSON_FIELDS, PKI_REASON_FIELDS)) },
  revokePkiKeyPair: { '200': Kit.action(Object.assign({
    purpose: STR, reason: NSTR, already: BOOL, onList: BOOL, remaining: INT,
    undeclared: BOOL
  }, PKI_PERSON_FIELDS, PKI_REASON_FIELDS)) },
  uploadPkiCertificate: { '200': Kit.action(Object.assign({
    source: STR, subject: STR, issuer: STR, chain: STRS,
    revocation: PKI_REVOCATION_CHECK
  }, PKI_ISSUE_FIELDS, PKI_PERSON_FIELDS, PKI_REASON_FIELDS)) },
  clearPkiChain: { '200': PKI_ACTION },
  issuePkiCertificate: { '200': Kit.action(Object.assign({
    object: PKI_OBJECT, dropped: INT
  }, PKI_REASON_FIELDS)) },
  removePkiObject: { '200': PKI_ACTION },
  clearPkiObjects: { '200': PKI_ACTION },
  exportPkiKeyPair: { '200': Kit.action(Object.assign({
    files: Kit.listOf(Kit.closed({ name: STR, mime: STR, base64: STR }))
  }, PKI_REASON_FIELDS)) },
  buildPkiRoot: { '200': Kit.action(Object.assign({
    root: Kit.nullable(CA_TIER)
  }, PKI_REASON_FIELDS)) },
  buildPkiScope: { '200': PKI_ACTION },
  reissuePkiUseCase: { '200': PKI_ACTION },
  recertifyPkiUseCase: { '200': PKI_ACTION },
  importPkiCa: { '200': PKI_ACTION },
  pinPkiKeyPair: { '200': Kit.action(Object.assign({
    kid: STR, activatesAt: WHEN
  }, PKI_REASON_FIELDS)) },
  unpinPkiKeyPair: { '200': Kit.action(Object.assign({
    unpinned: STRS
  }, PKI_REASON_FIELDS)) },
  revokePkiCertificate: { '200': Kit.action(Object.assign({
    entry: Kit.nullable(REVOKED_ENTRY), already: BOOL
  }, PKI_REASON_FIELDS)) },
  releasePkiCertificateHold: { '200': PKI_ACTION }
});

// ---------------------------------------------------------------------------
// SPIFFE. `admin-core/admin_views.ts`'s `spiffe*Json()`, over
// `spiffe/spiffe_ca.ts`, `spiffe_registry.ts`, `spiffe_auth.ts` and
// `spiffe_server.ts`.
//
// **WRITTEN AS A ONE-MEMBER UNION, WHICH IS DELIBERATE.** These operations (and
// ACME's, EST's and SCEP's reads) mirror `/admin/cert-issuance`, whose
// `protocolEndpoints` holds SPIFFE's socket rows, each carrying `listening`.
// `admin_api_spec.ts`'s `PROTOCOL_ENDPOINT_ROWS` does not declare that member,
// and `ResponseModels.apply()` writes it over a model that has `properties`,
// which would refuse every such answer once a SPIFFE socket is bound. A union
// has no `properties`, so `ENDPOINT_ROW`, above, is what is held to.
// ---------------------------------------------------------------------------
const SPIFFE_SELECTOR = Kit.closed({ type: STR, value: STR });
// An entry's attribute names are data: a directory entry carries what an
// `ldapmodify` gave it, beside the schema's.
const LDAP_ATTRIBUTES = Kit.mapOf(STRS);
const SPIFFE_ENTRY = Kit.closed({
  id: STR, dn: STR, spiffeId: STR, parentId: STR,
  selectors: Kit.listOf(SPIFFE_SELECTOR), x509SvidTtl: NUM, jwtSvidTtl: NUM,
  dnsNames: STRS, federatesWith: STRS, hint: STR, admin: BOOL, downstream: BOOL,
  storeSvid: BOOL, expiresAt: NUM, revisionNumber: NUM, origin: STR,
  svidsIssued: NUM, lastSvidAt: STR, createdAt: WHEN, modifiedAt: WHEN,
  attributes: LDAP_ATTRIBUTES, expired: BOOL, selectorTexts: STRS
});
const SPIFFE_AGENT = Kit.closed({
  id: STR, dn: STR, attestationType: STR,
  selectors: Kit.listOf(SPIFFE_SELECTOR), banned: BOOL, canReattest: BOOL,
  svidHash: STR, expiresAt: NUM, firstSeen: STR, lastSeen: STR,
  attestations: NUM, attributes: LDAP_ATTRIBUTES, selectorTexts: STRS
});
const SPIFFE_BINDING = Kit.closed({
  address: STR, listening: BOOL, error: STR, port: INT, tls: BOOL, socket: BOOL,
  attested: BOOL, peerCredentials: BOOL, restricted: BOOL, authentication: STR,
  realm: STR
});
const SPIFFE_FEDERATED = Kit.closed({
  trustDomain: STR, trustDomainId: STR, x509Keys: INT, jwtKeys: INT, keys: INT,
  sequence: NUM, refreshHint: NUM, bundleEndpointUrl: NSTR,
  bundleEndpointProfile: NSTR, endpointSpiffeId: NSTR, createdAt: WHEN,
  updatedAt: WHEN
});
const SPIFFE_VIEW = Kit.closed({
  enabled: BOOL, ready: BOOL, error: STR, trustDomain: STR, trustDomainId: STR,
  serverId: STR,
  bundle: Kit.closed({ path: STR, sequence: NUM, refreshHint: NUM }),
  authorities: Kit.closed({
    source: STR, realm: STR,
    x509: Kit.listOf(Kit.closed({
      id: STR, active: BOOL, source: STR, keyType: STR, subject: STR,
      serialHex: STR, notBefore: STR, notAfter: STR, certificatePem: STR,
      createdAt: WHEN
    })),
    jwt: Kit.listOf(Kit.closed({ id: STR, active: BOOL, keyType: STR, alg: NSTR,
                                 jwk: Kit.nullable(JWK), createdAt: WHEN })),
    trustAnchors: Kit.listOf(Kit.closed({
      id: STR, source: STR, subject: STR, notBefore: STR, notAfter: STR,
      certificatePem: STR
    })),
    chainSubjects: STRS,
    root: Kit.nullable(Kit.closed({ subject: NSTR, notAfter: NSTR,
                                    certificatePem: NSTR })),
    maxRetained: NUM
  }),
  listeners: Kit.closed({ workloadApi: Kit.listOf(SPIFFE_BINDING),
                          serverApi: Kit.listOf(SPIFFE_BINDING),
                          brokerApi: Kit.listOf(SPIFFE_BINDING) }),
  workloadAttestation: Kit.nullable(Kit.closed({
    tcp: Kit.closed({
      port: INT, host: STR, served: BOOL, declared: BOOL, state: STR, why: STR,
      listening: BOOL, attested: BOOL
    }),
    nativeModule: BOOL, problem: NSTR, unattestedSocketServed: BOOL,
    attestors: Kit.listOf(Kit.closed({ type: STR, enabled: BOOL,
                                       verifies: STR })),
    unknownConfigured: STRS,
    connections: Kit.listOf(Kit.closed({
      tag: STR, pid: NUM, uid: NUM, gid: NUM, visible: BOOL, pidfdSource: STR,
      selectors: INT, error: NSTR, note: NSTR
    }))
  })),
  federated: Kit.listOf(SPIFFE_FEDERATED),
  counts: Kit.closed({ entries: INT, agents: INT, maxEntries: NUM,
                       maxAgents: NUM, maxFederatedBundles: NUM }),
  keyTypes: Kit.listOf(Kit.closed({ id: STR, label: STR, kind: STR,
                                    jwtAlg: NSTR, what: STR })),
  authentication: Kit.closed({
    what: STR, bootstrapping: STR, identityNote: STR, credentialStatusNote: STR,
    enforced: BOOL, trustLocalSocket: BOOL, adminIds: STRS,
    attestWorkloads: BOOL, acceptAssertedSelectors: BOOL,
    assertedSelectorHeader: STR, entities: Kit.listOf(ID_LABEL),
    policy: Kit.listOf(Kit.closed({ method: STR, allow: STRS }))
  }),
  settings: Kit.listOf(Kit.closed({ key: STR, value: NSTR })),
  authorityState: Kit.closed({
    x509Authorities: Kit.listOf(Kit.closed({
      id: STR, active: BOOL, notAfter: STR, subject: STR, createdAt: WHEN,
      keyType: STR
    })),
    jwtAuthorities: Kit.listOf(Kit.closed({
      id: STR, active: BOOL, notAfter: NSTR, alg: NSTR, createdAt: WHEN
    })),
    federated: Kit.listOf(SPIFFE_FEDERATED)
  }),
  serverApiAuthenticated: BOOL, settingsForms: SETTINGS,
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const SPIFFE_ENTRIES_VIEW = Kit.closed({
  // The list.
  total: INT, matched: INT, filter: Kit.closed({ q: STR, origin: STR }),
  origins: STRS, paging: PAGING, max: NUM, container: STR,
  serverApiAuthenticated: BOOL, trustDomain: STR,
  entries: Kit.listOf(SPIFFE_ENTRY),
  // One of them, by `entry`.
  found: BOOL, id: STR, error: STR, entry: SPIFFE_ENTRY, editable: STRS,
  defaults: Kit.closed({ x509SvidTtl: NSTR, jwtSvidTtl: NSTR }),
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const SPIFFE_BROKERS_VIEW = Kit.closed({
  total: INT, matched: INT, filter: Kit.closed({ q: STR }), paging: PAGING,
  trustDomain: STR, setting: STR, port: NSTR, referenceTypes: STRS,
  listeners: Kit.listOf(SPIFFE_BINDING),
  brokers: Kit.listOf(Kit.closed({ id: STR, referenceTypes: STRS,
                                   problem: NSTR })),
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const SPIFFE_AGENTS_VIEW = Kit.closed({
  // The list.
  total: INT, matched: INT, filter: Kit.closed({ q: STR }), max: NUM,
  container: STR, paging: PAGING, serverApiAuthenticated: BOOL,
  agents: Kit.listOf(SPIFFE_AGENT),
  // One of them, by `agent`.
  found: BOOL, id: STR, error: STR, agent: SPIFFE_AGENT,
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const SPIFFE_ENTRY_ACTION = Kit.action({ id: STR, entry: SPIFFE_ENTRY });
const SPIFFE_AGENT_ACTION = Kit.action({ id: STR, agent: SPIFFE_AGENT });

Object.assign(operations, {
  getSpiffe: { '200': Kit.oneOf(SPIFFE_VIEW) },
  getSpiffeEntries: { '200': Kit.oneOf(SPIFFE_ENTRIES_VIEW), '400': REFUSED },
  getSpiffeBrokers: { '200': Kit.oneOf(SPIFFE_BROKERS_VIEW) },
  getSpiffeAgents: { '200': Kit.oneOf(SPIFFE_AGENTS_VIEW) },
  rotateSpiffeAuthority: { '200': Kit.action() },
  setSpiffeFederatedBundle: { '200': Kit.action() },
  removeSpiffeFederatedBundle: { '200': Kit.action() },
  createSpiffeEntry: { '200': SPIFFE_ENTRY_ACTION },
  updateSpiffeEntry: { '200': SPIFFE_ENTRY_ACTION },
  deleteSpiffeEntry: { '200': SPIFFE_ENTRY_ACTION },
  setSpiffeBroker: { '200': Kit.action({ id: STR, referenceTypes: STRS }) },
  removeSpiffeBroker: { '200': Kit.action({ id: STR }) },
  banSpiffeAgent: { '200': SPIFFE_AGENT_ACTION },
  unbanSpiffeAgent: { '200': SPIFFE_AGENT_ACTION },
  deleteSpiffeAgent: { '200': SPIFFE_AGENT_ACTION },
  createSpiffeJoinToken: { '200': Kit.action({
    token: STR, expiresAt: WHEN, agentSpiffeId: STR
  }) }
});

// ---------------------------------------------------------------------------
// ACME, EST AND SCEP: `acme/acme_console.ts`, `est/est_console.ts` and
// `scep/scep_console.ts` over `common/cert_enrollment.ts` and
// `common/enrollment_monitor.ts`. Each read mirrors `/admin/cert-issuance`, and
// the one-member union is SPIFFE's reason, above. Its monitor does not.
// ---------------------------------------------------------------------------
const ENROLL_ENTRY = Kit.closed({ kind: STR, id: STR });
const ENROLL_REVOKED = Kit.nullable(Kit.closed({ at: WHEN, reason: STR,
                                                 by: STR }));
const ENROLL_HOST_NAMES = Kit.listOf(Kit.closed({
  entry: ENROLL_ENTRY, entryUri: STR, hostNames: STRS
}));
const ENROLL_REFUSED_PROFILES = Kit.listOf(Kit.closed({ id: STR, why: STR }));
const NAME_COUNT = Kit.listOf(Kit.closed({ name: STR, count: NUM }));
const ENROLL_RECENT = Kit.listOf(Kit.closed({
  at: STR, operation: STR, outcome: NSTR, status: NINT, profile: NSTR,
  principal: NSTR, target: NSTR, errorCode: NSTR, failInfo: NSTR,
  serialHex: NSTR
}));
// What a monitor's counters began, on this process.
const MONITOR_SINCE = WHEN;
const ENROLL_CERTIFICATE = Kit.closed({
  serialHex: STR, entry: ENROLL_ENTRY, entryUri: STR, profile: NSTR,
  subject: NSTR, names: STRS, keyAlg: STR, keySource: NSTR, via: NSTR,
  status: STR, notBefore: STR, notAfter: STR, issuedAt: WHEN,
  requestedBy: Kit.nullable(Kit.closed({ kind: STR, id: STR, admin: BOOL })),
  replaces: NSTR, revoked: ENROLL_REVOKED, thumbprint: NSTR,
  account: NSTR
});
const ENROLL_CERTIFICATES = Kit.closed({
  paging: PAGING, rows: Kit.listOf(ENROLL_CERTIFICATE)
});
// `core.refuse()`'s `{ ok, status, errors, why }` travels unchanged through
// EST's console.
const ENROLL_ACTION_FIELDS = { status: INT, why: STR };
const ENROLL_HOST_ACTION = Kit.action(Object.assign({
  hostNames: STRS, entryUri: STR, entry: ENROLL_ENTRY, unchanged: BOOL
}, ENROLL_ACTION_FIELDS));
const ENROLL_REVOKE_ACTION = Kit.action(Object.assign({
  serialHex: STR, entry: ENROLL_ENTRY, entryUri: STR, family: STR, reason: STR
}, ENROLL_ACTION_FIELDS));

const ACME_VIEW = Kit.closed({
  page: STR, title: STR, enabled: BOOL, specifications: STRS, directory: STR,
  endpoints: Kit.closed({
    directory: STR, newNonce: STR, newAccount: STR, newOrder: STR, account: STR,
    orders: STR, order: STR, finalize: STR, authorization: STR, challenge: STR,
    certificate: STR, revokeCert: STR, keyChange: STR, renewalInfo: STR
  }),
  challengeType: STR, identifierTypes: STRS,
  authority: Kit.closed({
    present: BOOL, note: STR, subject: STR, serialHex: STR, keyAlg: STR,
    signatureAlg: STR, notBefore: STR, notAfter: STR, thumbprint: STR,
    intermediate: NSTR, root: NSTR
  }),
  profiles: Kit.listOf(Kit.closed({ id: STR, description: STR, needs: NSTR,
                                    allowed: BOOL, isDefault: BOOL })),
  refusedProfiles: ENROLL_REFUSED_PROFILES,
  mode: Kit.closed({ current: STR, what: STR, development: STR, product: STR,
                     inForce: STR }),
  eabLifetimeS: NUM,
  eabKeys: Kit.closed({
    paging: PAGING,
    rows: Kit.listOf(Kit.closed({
      kid: STR, entry: ENROLL_ENTRY, entryUri: STR, status: STR,
      createdAt: WHEN, expiresAt: WHEN, createdBy: STR, boundAt: WHEN,
      boundAccount: NSTR
    }))
  }),
  accounts: Kit.closed({
    paging: PAGING,
    rows: Kit.listOf(Kit.closed({
      id: STR, status: STR, entry: Kit.nullable(ENROLL_ENTRY), entryUri: NSTR,
      eabKid: NSTR, thumbprint: STR, contact: STRS, orders: INT,
      createdAt: WHEN, deactivatedAt: WHEN
    }))
  }),
  certificates: ENROLL_CERTIFICATES,
  hostNames: Kit.closed({ paging: PAGING, rows: ENROLL_HOST_NAMES }),
  revocationReasons: STRS, actions: STRS, settings: SETTINGS,
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const ACME_MONITOR = Kit.closed({
  page: STR, title: STR, since: MONITOR_SINCE, realm: STR, processes: INT,
  totals: Kit.closed({ requests: INT, issued: INT, refused: INT, revoked: INT,
                       accountsBound: INT, accounts: INT,
                       certificatesHeld: INT }),
  operations: NAME_COUNT, profiles: NAME_COUNT, principals: NAME_COUNT,
  errorCodes: NAME_COUNT, statuses: NAME_COUNT, lastAt: WHEN, paging: PAGING,
  recent: ENROLL_RECENT
});
const ACME_ACCOUNT_ROW = Kit.closed({
  id: STR, status: STR, entry: Kit.nullable(ENROLL_ENTRY), entryUri: NSTR,
  eabKid: NSTR, thumbprint: STR, contact: STRS, orders: INT, createdAt: WHEN,
  deactivatedAt: WHEN
});

const EST_VIEW = Kit.closed({
  page: STR, title: STR, enabled: BOOL, specifications: STRS,
  endpoints: Kit.listOf(Kit.closed({
    operation: STR, method: STR, section: STR, what: STR, url: STR,
    labelFormUrl: NSTR
  })),
  labelForm: Kit.nullable(Kit.closed({ base: STR, note: STR })),
  hierarchy: Kit.closed({
    built: BOOL, note: STR,
    authority: Kit.nullable(Kit.closed({
      subject: STR, serialHex: STR, keyAlg: STR, notBefore: STR, notAfter: STR,
      thumbprint: STR, certificatePem: STR
    })),
    chainPem: STRS
  }),
  authentication: Kit.closed({
    basic: BOOL, certificate: BOOL, serverKeyGeneration: BOOL,
    credentials: Kit.listOf(Kit.closed({ kind: STR, what: STR,
                                         managedAt: STR }))
  }),
  profiles: Kit.listOf(Kit.closed({
    id: STR, needs: NSTR, allowed: BOOL, isDefault: BOOL,
    // One URL per EST operation, by the operation's name.
    urls: Kit.mapOf(STR)
  })),
  defaultProfile: NSTR, refusedProfiles: ENROLL_REFUSED_PROFILES,
  hostNames: ENROLL_HOST_NAMES, certificates: ENROLL_CERTIFICATES,
  keyAlgorithms: STRS, revocationReasons: STRS,
  csrAttributes: Kit.closed({
    signatureAlgorithms: Kit.listOf(Kit.closed({ oid: STR, name: STR }))
  }),
  mode: Kit.closed({ current: STR, development: STR, product: STR,
                     where: STR }),
  actions: STRS, settings: SETTINGS, monitor: STR,
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const EST_MONITOR = Kit.closed({
  page: STR, title: STR, since: MONITOR_SINCE, processes: INT,
  totals: Kit.closed({ requests: INT, issued: INT, refused: INT,
                       revoked: INT }),
  certificates: Kit.closed({ held: INT, valid: INT, revoked: INT,
                             expired: INT }),
  operations: NAME_COUNT, profiles: NAME_COUNT, principals: NAME_COUNT,
  errorCodes: NAME_COUNT, statuses: NAME_COUNT, lastAt: WHEN, paging: PAGING,
  recent: ENROLL_RECENT
});

const SCEP_RA = Kit.closed({
  present: BOOL, status: STR, subject: STR, serialHex: STR, keyAlgorithm: STR,
  wantedKeyAlgorithm: STR, notBefore: STR, notAfter: STR, thumbprint: STR,
  certificatePem: STR
});
const SUBJECT_UNTIL = Kit.closed({ subject: STR, notAfter: STR });
const SCEP_VIEW = Kit.closed({
  page: STR, title: STR, realm: STR, enabled: BOOL, specifications: STRS,
  endpoints: Kit.closed({ scep: STR, cgi: STR, getCaCaps: STR, getCaCert: STR,
                          pkiOperation: STR }),
  capabilities: STRS, operations: STRS,
  // RFC 8894 section 3.2.1.2's messageType numbers, keyed by the number.
  messageTypes: Kit.mapOf(STR),
  algorithms: Kit.closed({
    digests: STRS, signatures: STRS, ciphers: STRS, keyTransports: STRS,
    refusedDigests: STRS, refusedCiphers: STRS, replySignature: STR,
    replyKeyTransport: STR, replyCipher: STR
  }),
  authority: Kit.nullable(Kit.closed({
    subject: STR, serialHex: STR, keyAlg: STR, signatureAlg: STR,
    notBefore: STR, notAfter: STR, thumbprint: STR, certificatePem: STR,
    intermediate: Kit.nullable(SUBJECT_UNTIL), root: Kit.nullable(SUBJECT_UNTIL)
  })),
  hierarchyBuilt: BOOL, authorityNote: STR, ra: SCEP_RA,
  profiles: Kit.listOf(Kit.closed({ id: STR, allowed: BOOL, needs: STR,
                                    keys: STR, url: STR })),
  refusedProfiles: ENROLL_REFUSED_PROFILES, defaultProfile: NSTR,
  challenges: Kit.closed({
    paging: PAGING,
    rows: Kit.listOf(Kit.closed({
      id: STR, entry: ENROLL_ENTRY, entryUri: STR, profile: STR, status: STR,
      createdAt: WHEN, expiresAt: WHEN, createdBy: STR, usedAt: WHEN, url: STR
    }))
  }),
  hostNames: ENROLL_HOST_NAMES, certificates: ENROLL_CERTIFICATES,
  exceptions: Kit.listOf(Kit.closed({ what: STR, why: STR })),
  mode: Kit.closed({
    mode: STR,
    requirement: Kit.nullable(Kit.closed({
      id: STR, what: STR, development: STR, product: STR, where: STR
    })),
    scep: STR
  }),
  revokeReasons: STRS, actions: STRS, settings: SETTINGS,
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const SCEP_MONITOR = Kit.closed({
  page: STR, title: STR, realm: STR, since: MONITOR_SINCE, processes: INT,
  totals: Kit.closed({ requests: INT, issued: INT, refused: INT, revoked: INT,
                       challengesCreated: INT }),
  // Counted per name, where ACME's and EST's are tables of the same counts.
  operations: COUNTS, profiles: COUNTS, principals: COUNTS, errorCodes: COUNTS,
  statuses: COUNTS, failInfo: COUNTS, issuedCertificates: INT, lastAt: WHEN,
  paging: PAGING, recent: ENROLL_RECENT
});

Object.assign(operations, {
  getAcme: { '200': Kit.oneOf(ACME_VIEW) },
  getAcmeMonitor: { '200': ACME_MONITOR },
  createAcmeEab: { '200': Kit.action({
    kid: STR, hmacKey: STR, alg: STR, expiresAt: WHEN, target: ENROLL_ENTRY,
    targetUri: STR, directory: STR, certbot: STR
  }) },
  deleteAcmeEab: { '200': Kit.action({ kid: STR }) },
  deactivateAcmeAccount: { '200': Kit.action({ account: ACME_ACCOUNT_ROW }) },
  revokeAcmeCertificate: { '200': Kit.action({ serialHex: STR, reason: STR }) },
  addAcmeHostName: { '200': Kit.action({ hostNames: STRS, entryUri: STR }) },
  removeAcmeHostName: { '200': Kit.action({ hostNames: STRS, entryUri: STR }) },

  getEst: { '200': Kit.oneOf(EST_VIEW) },
  getEstMonitor: { '200': EST_MONITOR },
  issueEstServerKey: { '200': Kit.action(Object.assign({
    target: ENROLL_ENTRY, keyAlg: STR, record: ENROLL_CERTIFICATE,
    certificatePem: STR, chainPem: STRS, privateKeyPem: STR
  }, ENROLL_ACTION_FIELDS)) },
  revokeEstCertificate: { '200': ENROLL_REVOKE_ACTION },
  addEstHostName: { '200': ENROLL_HOST_ACTION },
  removeEstHostName: { '200': ENROLL_HOST_ACTION },

  getScep: { '200': Kit.oneOf(SCEP_VIEW) },
  getScepMonitor: { '200': SCEP_MONITOR },
  createScepChallenge: { '200': Kit.action({
    id: STR, challenge: STR, profile: STR, expiresAt: WHEN,
    target: ENROLL_ENTRY, entryUri: STR, url: STR, plainUrl: STR, hint: STR
  }) },
  deleteScepChallenge: { '200': Kit.action({ id: STR, entryUri: STR }) },
  reissueScepRa: { '200': Kit.action({ ra: SCEP_RA }) },
  revokeScepCertificate: { '200': Kit.action({
    serialHex: STR, entryUri: STR, reason: STR
  }) },
  addScepHostName: { '200': Kit.action({ entryUri: STR, hostNames: STRS }) },
  removeScepHostName: { '200': Kit.action({ entryUri: STR, hostNames: STRS }) }
});

// ---------------------------------------------------------------------------
// GNAP. `gnap/gnap_console.ts` over `gnap_grants.ts`, `gnap_tokens.ts` and
// `gnap_monitor.ts`.
// ---------------------------------------------------------------------------
const GNAP_RIGHT = Kit.freeForm(
  'An RFC 9635 section 8 access right as a resource server registered it: ' +
  'a string reference, or an object whose members are that API\'s own.');
// RFC 9635 section 9's discovery document. An authorization server's overrides
// are written over the defaults, so a member may be whatever an administrator
// gave it (`authorization_servers.ts`'s `capabilitiesOf()`).
const GNAP_CAPABILITY = Kit.oneOf(STRS, STR, BOOL, { type: 'null' });
const GNAP_CAPABILITIES = Kit.closed({
  grant_request_endpoint: STR,
  interaction_start_modes_supported: GNAP_CAPABILITY,
  interaction_finish_methods_supported: GNAP_CAPABILITY,
  key_proofs_supported: GNAP_CAPABILITY,
  sub_id_formats_supported: GNAP_CAPABILITY,
  assertion_formats_supported: GNAP_CAPABILITY,
  key_rotation_supported: GNAP_CAPABILITY,
  token_formats_supported: GNAP_CAPABILITY
});
const GNAP_GRANT_ROW = Kit.closed({
  id: STR, state: STR, authorizationServer: NSTR, grantEndpoint: NSTR,
  client: NSTR, proof: NSTR, resourceOwner: NSTR, decision: NSTR,
  interaction: Kit.nullable(Kit.closed({
    modes: STRS, finish: NSTR, started: WHEN, expiresAt: WHEN
  })),
  tokens: INT, derivedFrom: NSTR, createdAt: WHEN, updatedAt: WHEN,
  finalization: Kit.nullable(Kit.closed({ reason: STR, at: WHEN, note: NSTR })),
  grantExpiresAt: WHEN,
  history: Kit.listOf(Kit.closed({ at: WHEN, state: STR, note: NSTR }))
});
const GNAP_SERVER = Kit.closed({
  page: STR, title: STR, enabled: BOOL, specifications: STRS,
  endpoints: Kit.closed({
    grant: STR, discovery: STR, rsDiscovery: STR, continuation: STR,
    tokenManagement: STR, introspection: STR, resourceRegistration: STR,
    userCode: STR, keys: STR, zcapController: STR, accessTokenStatusList: STR,
    biscuitRevocations: STR
  }),
  capabilities: GNAP_CAPABILITIES,
  authorizationServers: Kit.listOf(Kit.closed({
    id: STR, label: STR, capabilities: GNAP_CAPABILITIES
  })),
  authorizationServersPaging: PAGING, tokenFormats: STRS,
  verificationMaterial: Kit.closed({
    jwt: Kit.closed({ jwks_uri: STR, alg: STR, kid: STR, typ: STR,
                      status_list_aggregation_endpoint: STR }),
    biscuit: Kit.closed({ algorithm: STR, root_public_key: STR,
                          revocation_endpoint: STR, jwk: JWK,
                          root_public_keys: STRS }),
    zcap: Kit.closed({ controller: STR, cryptosuite: STR }),
    macaroon: Kit.closed({ root_key: STR }),
    'jwt-encrypted': Kit.closed({ authorization_server: STR,
                                  resource_server: STR })
  }),
  grants: Kit.closed({
    state: NSTR, states: STRS, paging: PAGING,
    rows: Kit.listOf(GNAP_GRANT_ROW)
  }),
  resourceSets: Kit.closed({
    paging: PAGING,
    rows: Kit.listOf(Kit.closed({
      reference: STR, resourceServer: STR, access: Kit.listOf(GNAP_RIGHT),
      tokenFormats: Kit.nullable(STRS), introspectionRequired: BOOL,
      createdAt: WHEN
    }))
  }),
  actions: STRS, settings: SETTINGS
});
// A counter row: one number per event of `gnap_monitor.ts`'s EVENTS, with
// `lastAt`, `lastEvent`, `formats` and `errors` beside them; the counters'
// names are that table's, and a new event is a row there and no change here.
const GNAP_COUNTERS = Kit.mapOf(Kit.oneOf(NUM, STR, { type: 'null' },
                                          Kit.mapOf(NUM)));
const GNAP_MONITOR = Kit.closed({
  page: STR, title: STR, since: WHEN,
  events: Kit.listOf(Kit.closed({ event: STR, counter: STR, label: STR })),
  totals: COUNTS, tokensByFormat: COUNTS, applications: INT, paging: PAGING,
  rows: Kit.listOf(Kit.closed({
    identifier: STR, name: NSTR, kinds: STRS, role: STR, registered: BOOL,
    finishUris: STRS, webApplication: BOOL,
    grantsHeld: Kit.closed({ total: INT, pending: INT, approved: INT,
                             finalized: INT }),
    activeTokens: INT, counters: GNAP_COUNTERS, lastAt: WHEN, lastEvent: NSTR
  }))
});
Object.assign(components, { GnapServer: GNAP_SERVER,
                            GnapMonitor: GNAP_MONITOR });
Object.assign(operations, {
  revokeGnapGrant: { '200': Kit.action({ grant: GNAP_GRANT_ROW }) },
  deleteGnapResourceSet: { '200': Kit.action({ reference: STR }) }
});

// ---------------------------------------------------------------------------
// SHARED SIGNALS, CAEP AND RISC. `ssf/ssf.ts`'s three reports and three action
// handlers, `ssf/ssf_dead_letter_report.ts`, `ssf/ssf_receivers.ts` and
// `ssf/ssf_transmitters.ts`. A stream's counters and an event's counts are
// counted per name, so they are maps of numbers.
// ---------------------------------------------------------------------------
const SUBJECT_IDENTIFIER = Kit.freeForm(
  'An RFC 9493 subject identifier, as a stream was given it or a person ' +
  'named it: the format decides the members, an `aliases` nests, and SSF 1.0 ' +
  'section 3.3 lets a receiver add its own.');
const SET_CLAIMS = Kit.freeForm(
  'A Security Event Token\'s claims. An event\'s members are each event ' +
  'type\'s, and the claims are what was signed, so a model of them here ' +
  'would be a second list of every event type.');
const SET_SUMMARY = Kit.nullable(Kit.closed({
  jti: STR, iat: NUM, issuer: STR, audience: Kit.oneOrMany(STR), types: STRS,
  name: STR, subject: STR
}));
// `transmit()` and `transmitterVerification()`. **It carries the signed token
// and its claims**: the report on #1353 says where.
const TRANSMIT_REPORT = Kit.closed({
  ok: BOOL, delivered: BOOL, held: BOOL, deadLettered: BOOL, jti: STR,
  token: STR, claims: SET_CLAIMS, status: NINT, err: NSTR, why: NSTR
});
const STREAM_LOG_ROW = Kit.closed({ at: STR, kind: STR, text: STR });
const EVENT_MEMBER = Kit.closed({
  name: STR, required: Kit.oneOf(BOOL, STR, { type: 'null' }), what: STR,
  type: NSTR, values: STRS
});
const SSF_EVENT_TYPE = Kit.closed({
  uri: STR, name: STR, short: STR, family: STR,
  subject: Kit.oneOf(BOOL, STR, { type: 'null' }),
  what: STR, offered: BOOL, members: Kit.listOf(EVENT_MEMBER), required: STRS,
  subjectFormats: STRS, deprecated: STR
});
const PUSH_GATE = Kit.closed({ active: INT, waiting: INT, concurrency: NUM,
                               backlog: NUM });
const SUBJECT_EXAMPLE = Kit.closed({
  format: STR, uri: STR, email: STR, iss: STR, sub: STR, id: STR,
  phone_number: STR, url: STR, jti: STR, issuer: STR, assertion_id: STR,
  'ip-addresses': STRS,
  identifiers: Kit.listOf(Kit.closed({ format: STR, email: STR,
                                       phone_number: STR }))
});
const STREAM_DETAIL = Kit.closed({
  stream_id: STR, iss: NSTR, aud: Kit.nullable(Kit.oneOrMany(STR)), status: STR,
  statusReason: NSTR,
  delivery: Kit.closed({ method: STR, endpoint_url: NSTR }),
  events_delivered: STRS, events_requested: STRS, format: NSTR,
  description: NSTR, createdAt: WHEN, updatedAt: WHEN, createdBy: NSTR,
  internal: BOOL, counters: COUNTS, lastPushError: NSTR, lastPushAt: WHEN,
  subjects: Kit.listOf(Kit.closed({
    text: STR, verified: NBOOL, addedAt: WHEN, subject: SUBJECT_IDENTIFIER
  })),
  queue: Kit.listOf(Kit.closed({
    jti: STR, queuedAt: WHEN, deliveredAt: WHEN, summary: SET_SUMMARY
  })),
  dead: BOOL, deadSince: STR, deadReason: STR, failingSince: STR,
  nextProbeAt: STR,
  deadLetters: Kit.listOf(Kit.closed({
    jti: STR, queuedAt: WHEN, deadAt: WHEN, reason: NSTR, errorCode: NSTR,
    status: NINT, signed: BOOL, summary: SET_SUMMARY
  })),
  log: Kit.listOf(STREAM_LOG_ROW)
});
const SSF = Kit.closed({
  installed: BOOL, enabled: BOOL, issuer: STR, metadataUrl: STR,
  metadata: Kit.closed({
    spec_version: STR, issuer: STR, jwks_uri: STR,
    delivery_methods_supported: STRS, configuration_endpoint: STR,
    status_endpoint: STR, add_subject_endpoint: STR,
    remove_subject_endpoint: STR, verification_endpoint: STR,
    default_subjects: STR,
    authorization_schemes: Kit.listOf(Kit.closed({ spec_urn: STR })),
    critical_subject_members: STRS
  }),
  signingAlgorithm: STR,
  delivery: Kit.listOf(Kit.closed({ method: STR, name: STR, what: STR,
                                    offered: BOOL })),
  push: Kit.closed({
    allowed: BOOL,
    transport: Kit.closed({ allowHttp: BOOL, skipTlsVerificationSet: BOOL,
                            skipTlsVerification: BOOL, caFile: STR }),
    allowedHosts: STRS, retries: NUM, maxResponseBytes: NUM, note: STR
  }),
  eventTypes: Kit.listOf(SSF_EVENT_TYPE),
  subjectFormats: Kit.listOf(Kit.closed({
    format: STR, members: STRS, what: STR, example: SUBJECT_EXAMPLE
  })),
  complexSubjectMembers: Kit.listOf(Kit.closed({ name: STR, what: STR })),
  criticalSubjectMembers: STRS,
  authentication: Kit.closed({
    required: BOOL, realm: STR,
    scopes: Kit.closed({ read: STR, write: STR, readAlso: STRS, writeAlso: STRS,
                         writeIncludesRead: BOOL }),
    refusedPassword: STR, metadataIsOpen: BOOL, passwordVerified: BOOL,
    schemes: Kit.listOf(Kit.closed({ id: STR, name: STR, spec_urn: STR,
                                     what: STR, offered: BOOL })),
    note: STR
  }),
  streams: Kit.listOf(Kit.closed({
    stream_id: STR, status: STR, delivery: STR, events_delivered: STRS,
    subjects: INT, queued: INT, counters: COUNTS, createdAt: WHEN,
    lastPushError: NSTR
  })),
  endpoints: Kit.listOf(Kit.closed({ method: STR, path: STR, what: STR })),
  reachableNegatives: Kit.listOf(Kit.closed({ what: STR, answer: STR })),
  doesNotDo: STRS,
  streamDetail: Kit.listOf(STREAM_DETAIL),
  deadLetters: Kit.closed({ retentionS: NUM, maxPerStream: NUM,
                            deadStreamTimeoutS: NUM, pushes: PUSH_GATE }),
  settings: SETTINGS, statuses: STRS,
  streamTotals: Kit.closed({ streams: INT, enabled: INT, delivered: NUM,
                             failed: NUM, waiting: INT, dead: INT,
                             deadLetters: INT }),
  streamFilter: NSTR, paging: Kit.closed({ streams: PAGING }), note: STR,
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});
const SSF_DEAD_LETTERS = Kit.closed({
  installed: BOOL, enabled: BOOL, note: STR, realm: STR, generatedAt: STR,
  pushDelivery: BOOL,
  causes: Kit.listOf(Kit.closed({ id: STR, label: STR, code: STR, what: STR,
                                  count: INT })),
  totals: Kit.closed({
    held: INT, streamsHolding: INT, signed: INT, unsigned: INT,
    deadStreams: INT, halfOpenStreams: INT, failingStreams: INT,
    pushStreams: INT, oldestAt: STR, newestAt: STR,
    oldestAgeS: Kit.nullable(NUM), newestAgeS: Kit.nullable(NUM),
    deadLetteredEver: NUM
  }),
  timeline: Kit.closed({
    bucketS: NUM, windowS: NUM, from: STR, to: STR,
    buckets: Kit.listOf(Kit.closed({ start: STR, startMs: NUM, total: INT,
                                     counts: COUNTS })),
    peak: INT, olderThanWindow: INT
  }),
  byCode: Kit.listOf(Kit.closed({ errorCode: STR, count: INT, cause: STR,
                                  summary: STR })),
  byStatus: Kit.listOf(Kit.closed({ status: NUM, count: INT })),
  byEventType: Kit.listOf(Kit.closed({ type: STR, name: STR, count: INT })),
  streams: Kit.listOf(Kit.closed({
    stream_id: STR, aud: Kit.nullable(Kit.oneOrMany(STR)), endpoint_url: STR,
    status: STR, state: STR, held: INT, causes: COUNTS, oldestAt: STR,
    newestAt: STR, deadLetteredEver: NUM, deadSince: STR, failingSince: STR,
    nextProbeAt: STR, deadReason: STR, lastPushError: STR, lastPushAt: WHEN
  })),
  letters: Kit.listOf(Kit.closed({
    stream_id: STR, jti: STR, queuedAt: WHEN, deadAt: WHEN,
    ageS: Kit.nullable(NUM),
    cause: STR, reason: STR, errorCode: STR, status: NUM, signed: BOOL,
    streamKnown: BOOL,
    event: Kit.nullable(Kit.closed({ name: STR, types: STRS, subject: STR }))
  })),
  settings: Kit.closed({
    retentionS: NUM, maxPerStream: NUM, deadStreamTimeoutS: NUM, sweepS: NUM,
    pushConcurrency: NUM, pushBacklog: NUM, pushRetries: NUM
  }),
  process: Kit.closed({
    pid: INT, thread: Kit.nullable(Kit.oneOf(INT, STR)), role: STR,
    pushes: PUSH_GATE,
    sweeps: Kit.listOf(Kit.closed({
      at: STR, held: INT, letters: INT, expired: INT, orphaned: INT,
      trimmed: INT, deadStreams: INT, probes: INT,
      byCode: Kit.listOf(Kit.closed({ errorCode: STR, count: INT }))
    })),
    sinceStart: Kit.closed({ firstSweepAt: STR, sweeps: NUM, letters: NUM,
                             expired: NUM, orphaned: NUM, trimmed: NUM,
                             probes: NUM })
  }),
  filter: Kit.closed({ q: NSTR, stream: NSTR, cause: NSTR }),
  matched: INT,
  paging: Kit.closed({ letters: PAGING, streams: PAGING })
});
const SSF_STREAM_ACTION = Kit.action({ report: Kit.nullable(TRANSMIT_REPORT) });

// What both vocabularies say of a stream, and of a receiver.
const VOCABULARY_STREAM = Kit.closed({
  stream_id: STR, aud: Kit.nullable(Kit.oneOrMany(STR)), status: STR,
  delivery: STR, subjects: INT, takes: STRS
});
const VOCABULARY_RECEIVER = Kit.closed({
  identifier: STR, name: NSTR, registered: BOOL, declared: BOOL, dn: STR,
  endpoints: STRS, streams: STRS, streamCount: INT, enabled: INT,
  deliveries: STRS, audiences: STRS, takes: STRS, counts: COUNTS, total: INT,
  sessions: INT, accounts: INT, queued: INT, delivered: INT, failed: INT,
  acknowledged: INT, receiverErrors: INT, lastPushAt: WHEN, lastPushError: NSTR
});
const VOCABULARY_EVENT = Kit.closed({
  jti: STR, uri: STR, name: STR, at: STR, streamId: STR, warnings: STRS
});
const VOCABULARY_STREAM_COUNTS = Kit.closed({ total: INT, taking: INT });
const VOCABULARY_ACTION = Kit.action({ warnings: STRS,
                                       reports: Kit.listOf(TRANSMIT_REPORT) });

const CAEP_SESSION = Kit.closed({
  sessionId: STR, sub: NSTR, username: NSTR, iss: NSTR, protocol: NSTR,
  establishedAt: WHEN, updatedAt: WHEN, state: NSTR, acr: NSTR, amr: STRS,
  assurance: Kit.closed({ namespace: STR, level: STR, previousLevel: STR }),
  compliance: NSTR,
  risk: Kit.closed({ level: STR, previousLevel: STR, reason: STR }),
  claims: Kit.freeForm('The claims a `token-claims-change` event said ' +
                       'changed: whichever a person configured or an ' +
                       'emitter named.'),
  credentials: Kit.listOf(Kit.closed({ at: STR, credentialType: STR,
                                       changeType: STR, friendlyName: STR })),
  counts: COUNTS, total: INT, events: Kit.listOf(VOCABULARY_EVENT),
  streams: STRS, notes: STRS, subject: STR
});
const CAEP = Kit.closed({
  installed: BOOL, enabled: BOOL, note: STR, autoEmit: BOOL, autoEmitActs: STRS,
  omitEventTimestamp: BOOL,
  eventTypes: Kit.listOf(SSF_EVENT_TYPE), totals: COUNTS,
  sessions: Kit.listOf(CAEP_SESSION), tracked: INT, cap: NUM, issuer: STR,
  ssfEnabled: BOOL, applications: Kit.listOf(VOCABULARY_RECEIVER),
  streams: Kit.listOf(VOCABULARY_STREAM),
  catalogue: Kit.listOf(SSF_EVENT_TYPE), settings: SETTINGS,
  filter: Kit.closed({ sessions: NSTR, applications: NSTR }),
  paging: Kit.closed({ sessions: PAGING, applications: PAGING, streams: PAGING,
                       events: PAGING }),
  shown: Kit.closed({ sessions: Kit.listOf(CAEP_SESSION),
                      applications: Kit.listOf(VOCABULARY_RECEIVER),
                      streams: Kit.listOf(VOCABULARY_STREAM) }),
  matched: Kit.closed({ sessions: INT, applications: INT, streams: INT }),
  streamCounts: VOCABULARY_STREAM_COUNTS,
  // One session, by `session`.
  id: STR, session: Kit.nullable(CAEP_SESSION),
  events: Kit.listOf(VOCABULARY_EVENT)
});
const RISC_ACCOUNT = Kit.closed({
  accountId: STR, sub: NSTR, username: NSTR, iss: NSTR, dn: NSTR, realm: NSTR,
  email: NSTR, phone: NSTR, formerIdentifiers: STRS, createdAt: WHEN,
  updatedAt: WHEN, lifecycle: NSTR, kind: STR, application: STR,
  serviceAccount: BOOL, optOut: NSTR, optOutApplies: BOOL,
  credentialStanding: NSTR, credentialChangeRequired: BOOL,
  recoveryActivated: BOOL,
  identifierChanges: Kit.listOf(Kit.closed({ at: STR, from: STR, to: STR })),
  credentials: Kit.listOf(Kit.closed({ at: STR, credentialType: STR,
                                       discoveredAt: NUM })),
  counts: COUNTS, total: INT, suppressed: INT,
  events: Kit.listOf(VOCABULARY_EVENT), streams: STRS, notes: STRS, subject: STR
});
const RISC = Kit.closed({
  installed: BOOL, enabled: BOOL, note: STR, autoEmit: BOOL, autoEmitActs: STRS,
  honourOptOut: BOOL, googleSubjectType: BOOL, subjectFormat: STR,
  omitEventTimestamp: BOOL, eventTypes: Kit.listOf(SSF_EVENT_TYPE),
  optStates: STRS, lifecycleStates: STRS, totals: COUNTS,
  accounts: Kit.listOf(RISC_ACCOUNT), tracked: INT, cap: NUM, issuer: STR,
  ssfEnabled: BOOL, applications: Kit.listOf(VOCABULARY_RECEIVER),
  streams: Kit.listOf(VOCABULARY_STREAM),
  catalogue: Kit.listOf(SSF_EVENT_TYPE), settings: SETTINGS,
  filter: Kit.closed({ accounts: NSTR, applications: NSTR }),
  paging: Kit.closed({ accounts: PAGING, applications: PAGING, streams: PAGING,
                       events: PAGING }),
  shown: Kit.closed({ accounts: Kit.listOf(RISC_ACCOUNT),
                      applications: Kit.listOf(VOCABULARY_RECEIVER),
                      streams: Kit.listOf(VOCABULARY_STREAM) }),
  matched: Kit.closed({ accounts: INT, applications: INT, streams: INT }),
  streamCounts: VOCABULARY_STREAM_COUNTS,
  // One account, by `account`.
  id: STR, account: Kit.nullable(RISC_ACCOUNT),
  events: Kit.listOf(VOCABULARY_EVENT)
});
const SIGNALS = Kit.closed({
  status: Kit.nullable(Kit.closed({
    id: STR, label: STR, audience: STR, receivePath: STR, inboxPath: STR,
    sees: STR, realm: STR, enabled: BOOL, ssfEnabled: BOOL,
    internalReceivers: BOOL, pushDelivery: BOOL, caepEnabled: BOOL,
    riscEnabled: BOOL, held: INT, max: NUM,
    stream: Kit.nullable(Kit.closed({
      stream_id: STR, iss: NSTR, aud: Kit.nullable(Kit.oneOrMany(STR)),
      status: STR, statusReason: NSTR, delivery: STR, endpoint_url: STR,
      pollEveryMs: NUM, delivers: INT, requested: INT, caepDelivered: INT,
      riscDelivered: INT, queued: INT, counters: COUNTS, lastPushAt: WHEN,
      lastPushError: NSTR
    })),
    why: STRS
  })),
  received: Kit.listOf(Kit.closed({
    jti: STR, at: WHEN, tokenDigest: STR, surface: NSTR, stream: NSTR,
    name: STR, types: STRS, vocabulary: STR, issuer: STR, audience: STR,
    audienceOk: BOOL,
    subject: STR,
    payload: Kit.freeForm('An event\'s body as this receiver took it in: ' +
                          'each event type has its own members, and a ' +
                          'refused delivery is held here too.'),
    verified: BOOL, verificationNote: NSTR,
    reactions: Kit.listOf(Kit.closed({
      event: STR, reaction: STR, skipped: STR, observed: BOOL, ended: INT,
      revoked: INT, failed: BOOL
    })),
    contentType: NSTR, correctMediaType: BOOL, problem: STR
  })),
  total: INT, filter: Kit.closed({ received: NSTR }),
  paging: Kit.closed({ received: PAGING })
});
const PARTNER_SIGNALS = Kit.closed({
  relationships: Kit.listOf(FED_SIGNALS), received: Kit.listOf(FED_ARRIVAL),
  blocks: Kit.listOf(FED_BLOCK),
  locks: Kit.listOf(Kit.closed({ username: STR, relationship: STR, at: STR })),
  observeOnly: BOOL,
  counts: Kit.closed({ received: INT, blocks: INT, locks: INT }),
  paging: Kit.closed({ received: PAGING, blocks: PAGING, locks: PAGING })
});

Object.assign(components, {
  Ssf: SSF, SsfDeadLetters: SSF_DEAD_LETTERS, Caep: CAEP, Risc: RISC,
  Signals: SIGNALS, CaepApplication: VOCABULARY_RECEIVER
});
Object.assign(operations, {
  getBroadcast: { '200': Kit.closed({
    realm: STR, surfaces: Kit.listOf(Kit.closed({ id: STR, label: STR })),
    everyRealm: BOOL, realmCount: INT, maxChars: NUM, pollMs: NUM, keepS: NUM,
    ready: BOOL, why: STR
  }) },
  // `code` is an error code in an answer: see the report on #1353.
  sendBroadcast: { '200': Kit.action({
    code: STR, why: STR, sent: INT, streams: INT,
    realms: Kit.listOf(Kit.closed({ realm: STR, sent: INT, streams: INT,
                                    skipped: STRS }))
  }) },
  getConsoleAnnouncements: { '200': Kit.closed({
    now: NUM, everyMs: NUM,
    announcements: Kit.listOf(Kit.closed({ id: STR, at: STR, message: STR }))
  }) },
  getSsfDeadLetters: { '400': REFUSED },
  setSsfStreamStatus: { '200': SSF_STREAM_ACTION },
  transmitSsfEvent: { '200': SSF_STREAM_ACTION },
  deleteSsfStream: { '200': Kit.action() },
  reviveSsfStream: { '200': Kit.action() },
  verifySsfStream: { '200': SSF_STREAM_ACTION },
  clearSsfDeadLetters: { '200': Kit.action() },
  emitCaepEvent: { '200': VOCABULARY_ACTION },
  resetCaepSession: { '200': Kit.action() },
  clearCaepSessions: { '200': Kit.action() },
  emitRiscEvent: { '200': VOCABULARY_ACTION },
  resetRiscAccount: { '200': Kit.action() },
  clearRiscAccounts: { '200': Kit.action() },
  clearSignalsInbox: { '200': Kit.action({ dropped: INT }) },
  getPartnerSignals: { '200': PARTNER_SIGNALS }
});

// ---------------------------------------------------------------------------
// OPENID FEDERATION. `oidfed/oidfed.ts`'s `view()` and `act()`, with
// `oidfed_admin.ts`'s `pageLists()`.
//
// **WHAT A STATEMENT CARRIES IS THAT STATEMENT'S.** An Entity Configuration's
// metadata is keyed by entity type and each type's members are its own
// specification's, a resolved one's is a partner's as resolved, and a metadata
// policy's operators are OpenID Federation 1.1 section 6.1's, extensible by
// `metadata_policy_crit`. This service types what it adds around them.
// ---------------------------------------------------------------------------
const ENTITY_STATEMENT = Kit.freeForm(
  'This realm\'s Entity Configuration, the claims of a signed statement ' +
  '(OpenID Federation 1.1 section 3.1): its `metadata` is one document per ' +
  'entity type, and each is the document that protocol publishes.');
const STATEMENT_MEMBER = Kit.freeForm(
  'A JWK Set, a metadata document, a metadata policy or a constraints object ' +
  'as an administrator gave it or a partner\'s statement carried it ' +
  '(OpenID Federation 1.1 sections 3, 6): nothing here narrows it further.');
const OIDFED_EVENT = Kit.closed({ iat: NUM, event: STR, event_description: STR,
                                  information_uri: STR });
const OIDFED_MARK_TYPE = Kit.closed({
  type: STR, lifetimeS: NUM, logoUri: STR, ref: STR, delegation: STR
});
const OIDFED_VIEW = Kit.closed({
  entityId: STR, role: STR, configurationUrl: STR,
  endpoints: Kit.closed({
    configuration: STR, fetch: STR, list: STR, resolve: STR, trustMark: STR,
    trustMarkStatus: STR, trustMarkList: STR, historicalKeys: STR,
    register: STR, extendedList: STR, collection: STR, subordinateEvents: STR
  }),
  authorityHints: STRS, realmsAreSubordinates: BOOL, signingAlg: STR,
  keys: Kit.listOf(Kit.closed({
    kid: STR, alg: STR, state: STR, sealed: BOOL, createdAt: NSTR,
    activatedAt: NSTR, retiredAt: NSTR, publishedUntil: NSTR, revokedAt: NSTR,
    revokedReason: NSTR, publicJwk: JWK
  })),
  subordinates: Kit.listOf(Kit.closed({
    entityId: STR, localRealm: NSTR, implicit: BOOL, entityTypes: STRS,
    intermediate: BOOL, metadataPolicy: STATEMENT_MEMBER,
    constraints: STATEMENT_MEMBER, createdAt: NSTR, updatedAt: NSTR,
    kids: Kit.listOf(NSTR),
    suspended: Kit.nullable(Kit.closed({ at: NSTR, reason: NSTR,
                                         informationUri: NSTR })),
    events: Kit.listOf(OIDFED_EVENT), eventsTotal: INT
  })),
  formerSubordinates: Kit.listOf(Kit.closed({
    entityId: STR, localRealm: NSTR, events: Kit.listOf(OIDFED_EVENT),
    eventsTotal: INT
  })),
  collection: Kit.closed({
    crawl: Kit.nullable(Kit.closed({
      entityId: STR, forThisIdentifier: BOOL, crawledAt: STR, entities: INT,
      truncated: BOOL,
      problems: STRS
    })),
    crawlEveryS: NUM, jobOff: STR
  }),
  trustAnchors: Kit.listOf(Kit.closed({ entityId: STR, localRealm: NSTR,
                                        kids: Kit.listOf(NSTR) })),
  markTypes: Kit.listOf(OIDFED_MARK_TYPE),
  markPolicies: Kit.listOf(Kit.closed({ type: STR, issuers: STRS,
                                        owner: NSTR })),
  issuedMarks: Kit.listOf(Kit.closed({
    id: STR, type: STR, sub: STR, issuedAt: NSTR, expiresAt: NSTR, status: STR,
    revokedReason: NSTR
  })),
  heldMarks: Kit.listOf(Kit.closed({ id: STR, type: STR, iss: STR,
                                     expiresAt: NSTR })),
  resolutions: Kit.listOf(Kit.closed({
    subject: STR, anchor: STR, expiresAt: STR,
    chain: Kit.listOf(Kit.closed({ iss: STR, sub: STR, exp: NUM })),
    metadata: STATEMENT_MEMBER, trustMarks: Kit.listOf(NSTR)
  })),
  entityConfiguration: ENTITY_STATEMENT, entityConfigurationProblem: NSTR,
  statementLifetimeS: NUM, settings: SETTINGS,
  counts: Kit.closed({ keys: INT, subordinates: INT, formerSubordinates: INT,
                       trustAnchors: INT, issuedMarks: INT, heldMarks: INT,
                       markPolicies: INT }),
  paging: Kit.closed({ keys: PAGING, subordinates: PAGING,
                       formerSubordinates: PAGING, trustAnchors: PAGING,
                       issuedMarks: PAGING, heldMarks: PAGING,
                       markPolicies: PAGING }),
  protocolEndpoints: Kit.listOf(ENDPOINT_ROW)
});

Object.assign(operations, {
  getOidfed: { '200': OIDFED_VIEW },
  addOidfedSubordinate: { '200': Kit.action({
    subordinate: Kit.closed({
      entityId: STR, jwks: STATEMENT_MEMBER, metadata: STATEMENT_MEMBER,
      metadataPolicy: STATEMENT_MEMBER, metadataPolicyCrit: STRS,
      constraints: STATEMENT_MEMBER, entityTypes: STRS, intermediate: BOOL,
      localRealm: NSTR, createdAt: WHEN, updatedAt: WHEN
    })
  }) },
  removeOidfedSubordinate: { '200': Kit.action() },
  suspendOidfedSubordinate: { '200': Kit.action() },
  reinstateOidfedSubordinate: { '200': Kit.action() },
  crawlOidfedCollection: { '200': Kit.action({
    collection: Kit.closed({
      crawl: Kit.nullable(Kit.closed({
        entityId: STR, forThisIdentifier: BOOL, crawledAt: STR, entities: INT,
        truncated: BOOL,
        problems: STRS
      })),
      crawlEveryS: NUM, jobOff: STR
    })
  }) },
  addOidfedTrustAnchor: { '200': Kit.action() },
  removeOidfedTrustAnchor: { '200': Kit.action() },
  addOidfedMarkType: { '200': Kit.action({ markType: OIDFED_MARK_TYPE }) },
  removeOidfedMarkType: { '200': Kit.action() },
  setOidfedMarkPolicy: { '200': Kit.action({
    markPolicy: Kit.closed({
      type: STR, issuers: STRS,
      owner: Kit.closed({ sub: STR, jwks: STATEMENT_MEMBER })
    })
  }) },
  removeOidfedMarkPolicy: { '200': Kit.action() },
  issueOidfedTrustMark: { '200': Kit.action({ trustMark: STR, id: STR }) },
  revokeOidfedTrustMark: { '200': Kit.action() },
  addOidfedHeldMark: { '200': Kit.action() },
  removeOidfedHeldMark: { '200': Kit.action() },
  resolveOidfedEntity: { '200': Kit.action({
    resolution: Kit.closed({
      subject: STR, anchor: STR, expiresAt: STR,
      chain: Kit.listOf(Kit.closed({ iss: STR, sub: STR, exp: NUM })),
      metadata: STATEMENT_MEMBER, trustMarks: Kit.listOf(NSTR)
    })
  }) },
  rotateOidfedKey: { '200': Kit.action({ runId: Kit.oneOf(STR, NUM) }) },
  revokeOidfedKey: { '200': Kit.action() }
});

//@@NEXT@@

export = { components, operations };
