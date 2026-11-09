// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_users.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): Users, Groups, Multi-factor authentication, Admin
// roles, Roles, Sign-out, Sessions, Ownership, TOTP MFA, Recovery codes,
// WebAuthn.
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
//
// **WHO THE MEMBERS CAME FROM.** Every list below was read off the code that
// builds the answer, not off a recording: `AdminActions.usersAction()` and its
// helpers, `AdminViews.userDetailJson()`, `Credentials`, `Logout`, and the
// directory's `groupsFor()`. A member a model misses is an answer that is not
// sent, so where a branch is rare it is listed all the same.
//
// **FOUR NAMED SCHEMAS ARE READ BY A TEST** that asks each documented member
// to be in a live reply (`tests/protocol/admin_api.js`, *the schemas match the
// replies*): `UserList`, `GroupList`, `GroupDetail` and `GroupDetail.group`.
// So those four hold exactly what a healthy reply carries, and the answers a
// healthy reply is not are models of their own beside them (`GROUPS_ABSENT`,
// `GROUP_MISSING`, `GROUP_FOR_OWNER`, `USER_UNKNOWN`), joined in the
// operation's `oneOf`, rather than conditional members on the named schema.
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
const NNUM = Kit.nullable(NUM);
const NBOOL = Kit.nullable(BOOL);
const SCALAR = Kit.oneOf(STR, NUM, BOOL, { type: 'null' });
// A moment some rows hold as an ISO string and others as milliseconds, and a
// directory that may hold either.
const WHEN = Kit.nullable(Kit.oneOf(STR, NUM));
const COUNTS = Kit.mapOf(NUM);
const FLAGS = Kit.mapOf(BOOL);

// `AdminViews.pagingJson()`.
const PAGING = Kit.closed({
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT, total: INT,
  param: STR, noun: STR
});

// `common/config.js`'s `describe()`, a row; `default` and `value` take the type
// of the setting, a list included.
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
  masked: BOOL, realmSettable: BOOL, overridden: BOOL
});
// `AdminConsole.configSettingsJson()`: a page's settings, or null where the
// console has not filled the slot. A `sharedWith` value is the pages that also
// draw a group, each `{ path, label }`.
const SETTINGS = Kit.nullable(Kit.closed({
  page: STR,
  groups: Kit.listOf(Kit.closed({ group: STR,
                                  settings: Kit.listOf(SETTING_ROW) })),
  settingCount: INT, editableCount: INT, overridden: STRS, setWith: STR,
  context: Kit.closed({
    configFile: NSTR, defaultsFile: NSTR, persistsAppconfig: BOOL,
    persistsRealms: BOOL, persistenceMode: STR, inRealm: BOOL, realmId: STR
  }),
  sharedWith: Kit.mapOf(Kit.listOf(Kit.oneOf(
    STR, Kit.closed({ path: STR, label: STR }))))
}));

// ---------------------------------------------------------------------------
// A directory entry. Its attribute NAMES are data: whatever is on the entry,
// less the secrets `withoutSecrets()` masks. A value is a list as the store
// holds it; the lone string is what an older copy of an entry carries.
// ---------------------------------------------------------------------------
const ATTRIBUTES = Kit.mapOf(Kit.oneOrMany(STR));

const GROUP_MEMBER = Kit.closed({
  value: STR, attribute: STR, holds: STR, dn: STR, present: BOOL, kind: STR,
  userKey: STR, cn: STR, mail: STR, displayName: STR
});

const ENTRY = Kit.closed({
  dn: STR, origin: STR, createdAt: WHEN, modifiedAt: WHEN,
  operational: STRS, attributes: ATTRIBUTES,
  // Which rule made it a group, and its members resolved: what the group
  // writers add to the entry they hand back.
  rule: STR, members: Kit.listOf(GROUP_MEMBER)
});

const COUNTED = function (name: string): Json {
  return Kit.listOf(Kit.closed({ [name]: STR, count: NUM }));
};

// ---------------------------------------------------------------------------
// A PERSON'S FACTORS.
// ---------------------------------------------------------------------------
const MFA_REQUIREMENT = Kit.closed({
  required: BOOL, byUser: BOOL, byRealm: BOOL, byAdministrator: BOOL,
  offered: BOOL, exemptServiceAccount: BOOL
});

const TOTP_DETAIL = Kit.nullable(Kit.closed({
  enrolledAt: NUM, lastUsedAt: NUM, algorithm: STR, digits: NUM, period: NUM,
  sealed: BOOL, unusable: BOOL, why: STR
}));

const BACKUP_STATUS = Kit.nullable(Kit.closed({
  present: BOOL, usable: BOOL, total: NUM, remaining: NUM, used: NUM,
  generatedAt: NUM, lastUsedAt: NUM, sealed: BOOL, hashed: BOOL, legacy: BOOL,
  why: STR
}));

// What `Credentials.factorHolderRow()` and the roster row have in common.
const FACTOR_HOLDER = {
  username: STR, inDirectory: BOOL, known: BOOL, password: BOOL,
  primaryKeys: NUM, mfaKeys: NUM, totp: BOOL, totpUsable: BOOL,
  totpDetail: TOTP_DETAIL, backupCodes: BACKUP_STATUS, recoveryAdvised: BOOL,
  mfaRequired: BOOL, secondFactor: NSTR, usable: BOOL
};

const CERT_ALGORITHM = Kit.closed({
  algorithm: STR, oid: STR, family: STR, postQuantum: BOOL, composite: BOOL
});

const ATTESTATION_ALGORITHMS = Kit.closed({
  statement: STR, statementCoseAlg: NINT,
  certificates: Kit.listOf(CERT_ALGORITHM),
  anchor: Kit.nullable(CERT_ALGORITHM),
  postQuantum: BOOL,
  // A composite statement's parts (`algorithmsOf()`): each the same facts of
  // one member, under the format it was in.
  members: Kit.listOf(Kit.closed({
    format: STR, statement: STR, statementCoseAlg: NINT,
    certificates: Kit.listOf(CERT_ALGORITHM),
    anchor: Kit.nullable(CERT_ALGORITHM)
  }))
});

// `AttestationRevocation.consult()`'s verdict on a certificate chain.
const REVOCATION_VERDICT = Kit.closed({
  status: STR, reason: STR, serial: STR, listVersion: STR, checkedAt: WHEN,
  chainSerials: STRS, why: STR
});

// `authn/webauthn_attestation.ts`'s `assess()`, stored on the key as it was.
const ATTESTATION = Kit.nullable(Kit.closed({
  policy: STR, format: STR, type: STR, verified: BOOL, trusted: BOOL,
  anchor: STR, aaguid: NSTR, model: STR, certificationLevel: STR,
  mdsStatus: STR, mdsVersion: Kit.nullable(Kit.oneOf(STR, NUM)),
  checkedAt: NUM, algorithms: Kit.nullable(ATTESTATION_ALGORITHMS),
  conveyance: STR, enterpriseDowngraded: BOOL, attestationKeyId: STR,
  deviceSerial: STR, deviceSerialSource: STR,
  // RFC 4998, `common/passkey_evidence.ts`.
  evidence: Kit.closed({
    syntax: STR, version: NUM, object: STR, objectDigest: STR,
    evidenceRecord: STR, timestamps: STRS, createdAt: WHEN, renewedAt: WHEN,
    renewAfter: WHEN, hashAlgorithm: STR, tsa: NSTR
  }),
  // `common/attestation_revocation.ts`'s verdict on the chain.
  androidRevocation: REVOCATION_VERDICT
}));

const KEY_ALGORITHM = Kit.closed({
  name: STR, coseAlg: Kit.nullable(NUM), text: STR, postQuantum: BOOL,
  insecure: BOOL, lane: STR
});

const ENROLLED_BY = Kit.closed({ username: STR, sub: STR, at: NUM });

// `Credentials.addKey()`'s stored record, as `keysOf()` reads it back, and the
// three things `userPageData()` adds to each. The keys' `publicKeyJwk` is a
// COSE key turned into a JWK: its members are the algorithm's, closed here
// across the four key families a passkey may be.
const STORED_KEY = Kit.closed({
  credentialId: STR, publicKeyJwk: Kit.closed({
    kty: STR, crv: STR, alg: STR, use: STR, kid: STR, x: STR, y: STR, n: STR,
    e: STR, pub: STR, ext: BOOL, key_ops: STRS
  }),
  signCount: NUM, enrolledAt: NUM, lastUsedAt: NUM, label: STR,
  attachment: NSTR, userVerified: NBOOL, aaguid: NSTR,
  algorithm: Kit.oneOf(KEY_ALGORITHM, { type: 'null' }, STR),
  coseAlg: NNUM, attestation: ATTESTATION, backupEligible: NBOOL,
  backupState: NBOOL, transports: STRS, discoverable: NBOOL,
  minPinLength: NNUM, userHandle: STR, lane: STR, enrolledBy: ENROLLED_BY,
  provider: Kit.nullable(STR), providerSource: STR,
  name: STR, group: STR,
  upgradedAt: NUM, upgradedTo: STR, previousAlgorithm: STR,
  previousCoseAlg: NNUM, previousCredentialId: STR, upgradeMode: STR,
  possiblyReplacedBy: STR, possiblyReplacedAt: NUM,
  // Two refusals a sign-in leaves on the key (`noteKeyPolicyRefused()`, and the
  // attestation recheck's): the policy's by its kind, whose name is data.
  policyRefused: Kit.mapOf(Kit.closed({ why: STR, at: NUM })),
  attestationRefused: Kit.closed({ why: STR, at: NUM })
});

// `AdminViews.mfaJson()`'s key: a description, no public key.
const FACTOR_KEY = Kit.closed({
  credentialId: STR, label: NSTR, signCount: NUM, enrolledAt: NUM,
  aaguid: NSTR, algorithm: KEY_ALGORITHM, lane: STR, attestation: ATTESTATION,
  attestationAlgorithms: Kit.closed({
    verified: BOOL, trusted: BOOL, recorded: BOOL, statement: STR,
    statements: STRS,
    certificates: Kit.listOf(Kit.closed({
      algorithm: STR, family: STR, postQuantum: BOOL
    })),
    postQuantum: BOOL
  }),
  name: STR, group: STR, provider: NSTR, lastUsedAt: NUM, backupEligible: NBOOL,
  backupState: NBOOL, transports: STRS, discoverable: NBOOL, deviceSerial: NSTR,
  possiblyReplaced: Kit.nullable(Kit.closed({ by: STR, at: NUM })),
  withoutUsername: Kit.closed({ ready: BOOL, text: STR }),
  postQuantumRefused: STR
});

const APP_PASSWORD = {
  id: STR, name: STR, doors: STRS, doorLabels: STRS, createdAt: NUM,
  createdBy: STR, lastUsedAt: NUM, lastUsedDoor: STR
};

const DOORS_FOR = Kit.closed({
  secondFactor: BOOL, refused: STRS, accepted: STRS, passwordAloneDoors: STRS,
  sentence: STR
});

const RESET_LINK = Kit.nullable(Kit.closed({ expires: NUM, expired: BOOL }));

const FACTORS = Kit.nullable(Kit.closed({
  password: BOOL, passwordChangeRequired: BOOL, passwordResetLink: RESET_LINK,
  disabled: BOOL, mfaRequirement: MFA_REQUIREMENT, usable: BOOL,
  activated: BOOL, mfaRequired: BOOL, secondFactor: NSTR, totp: BOOL,
  totpUsable: BOOL, totpDetail: TOTP_DETAIL, backupCodes: BACKUP_STATUS,
  keys: Kit.listOf(FACTOR_KEY), primaryKeys: NUM, mfaKeys: NUM,
  appPasswords: Kit.listOf(Kit.closed(APP_PASSWORD)),
  passwordOnlyDoors: DOORS_FOR,
  policy: Kit.closed({
    totpEnabled: BOOL, backupCodesEnabled: BOOL, backupCodesCount: NUM,
    webauthnEnabled: BOOL, primaryAllowed: BOOL, mfaAllowed: BOOL,
    maxKeysPerPerson: NUM
  })
}));

// `Credentials.mechanismsFor()`, with the key rows `userPageData()` writes.
const MECHANISMS = Kit.closed({
  username: STR, password: BOOL, primaryKeys: NUM, mfaKeys: NUM,
  keys: Kit.listOf(STORED_KEY), totp: BOOL, totpUsable: BOOL,
  totpDetail: TOTP_DETAIL, usable: BOOL, backupCodes: BACKUP_STATUS,
  mfaRequired: BOOL,
  mailFactor: Kit.closed({ held: STR, optedIn: STR, why: STR, verified: BOOL }),
  secondFactor: NSTR, activated: BOOL, recoveryAdvised: BOOL,
  mfaRequirement: MFA_REQUIREMENT, passwordResetLink: RESET_LINK,
  disabled: BOOL
});

// ---------------------------------------------------------------------------
// A PERSON'S LISTS, each answered alone by an operation of its own and inside
// `page.mfa` on the drill-down.
// ---------------------------------------------------------------------------
const APP_PASSWORDS_VIEW = Kit.closed({
  user: STR, enabled: BOOL, maxPerPerson: NUM, unreadable: BOOL,
  doors: Kit.listOf(Kit.closed({ id: STR, label: STR, what: STR })),
  passwordOnlyDoors: DOORS_FOR, passwords: Kit.listOf(Kit.closed(APP_PASSWORD)),
  page: INT, pages: INT, perPage: INT, total: INT, paging: PAGING
});

const VERIFICATION_RECORD = Kit.closed({
  id: STR, recorded: WHEN, source: STR, by: STR,
  verification: Kit.freeForm(
    'The OpenID Connect for Identity Assurance `verification` element: a ' +
    'caller may post it whole as JSON, and a wallet or a certificate may ' +
    'supply it, so its evidence is that specification\'s to shape.'),
  // A verified claim's value is the entry's, and `address` is an object.
  claims: Kit.freeForm(
    'The verified claims and their values, as the OpenID Connect claim each ' +
    'is: a string for most, an object for `address`, a list for ' +
    '`nationalities`.')
});

const VERIFICATIONS_VIEW = Kit.closed({
  user: STR, trustFrameworks: STRS, evidenceTypes: STRS, documentTypes: STRS,
  checkMethods: STRS, electronicRecordTypes: STRS, attestationTypes: STRS,
  verifiableClaims: STRS, verifications: Kit.listOf(VERIFICATION_RECORD),
  page: INT, pages: INT, perPage: INT, total: INT, paging: PAGING
});

const SELF_ISSUED_SUBJECT = Kit.closed({
  subject: STR, label: STR, enrolledAt: WHEN, by: STR, proof: STR,
  provedAt: WHEN, keyAlg: STR,
  location: Kit.closed({ kind: STR, value: STR }),
  preferred: BOOL, pinnedKeys: STRS
});

const SELF_ISSUED_VIEW = Kit.closed({
  user: STR, entryFound: BOOL, signInEnabled: BOOL, maxPerPerson: NUM,
  subjectSyntaxTypes: STRS, subjects: Kit.listOf(SELF_ISSUED_SUBJECT)
});

const PUBLISHED_DID = Kit.closed({
  rid: STR, did: STR, custody: STR, documentUrl: STR, createdAt: WHEN, by: STR,
  state: STR,
  deactivated: Kit.nullable(Kit.oneOf(BOOL, STR, Kit.closed({
    at: WHEN, by: STR, reason: STR, via: STR
  }))),
  proof: STR, preferred: BOOL, currentVersion: Kit.oneOf(STR, NUM),
  pending: Kit.nullable(Kit.closed({ change: STR, expiresAt: WHEN })),
  versions: Kit.listOf(Kit.closed({
    versionId: Kit.oneOf(STR, NUM), created: WHEN, change: STR,
    keys: Kit.listOf(Kit.closed({ id: STR, kty: STR, crv: STR, alg: STR })),
    // `wallet-proof`, `person`, `current-key-proof` and `new-key-proof`.
    authorizedBy: Kit.listOf(Kit.closed({
      kind: STR, subject: STR, actor: STR, at: WHEN, keyThumbprint: STR,
      versionId: Kit.oneOf(STR, NUM), transaction: STR
    }))
  }))
});

const PUBLISHED_DIDS_VIEW = Kit.closed({
  user: STR, entryFound: BOOL, publishing: BOOL, custody: STR,
  maxPerPerson: NUM, dids: Kit.listOf(PUBLISHED_DID)
});

// A device key: `common/devices.ts`'s header. Its proof is one of the realm's
// words, and its material is the key's own.
const DEVICE_KEY = Kit.closed({
  id: STR, kind: STR, thumbprint: STR, label: STR, added: WHEN, addedBy: STR,
  proof: STR,
  attestation: Kit.closed({
    level: STR, format: STR, summary: STR, verifiedAt: WHEN,
    chainSerials: STRS, revocation: REVOCATION_VERDICT,
    freshness: Kit.closed({ status: STR, detail: STR })
  }),
  material: Kit.freeForm(
    'A device key\'s public material as its kind carries it: a client\'s ' +
    'JWK, a certificate, or a WebAuthn credential.')
});

const DEVICE_CHANGE = Kit.nullable(Kit.closed({
  status: STR, compliance: STR, level: STR, previous: NSTR, at: WHEN,
  source: STR, actor: STR, reason: STR
}));

const DEVICE_VIEW = Kit.closed({
  id: STR, dn: STR, owner: STR, ownerKind: STR, label: STR,
  applications: STRS, keys: Kit.listOf(DEVICE_KEY), keyKinds: STRS,
  attestation: Kit.closed({ level: STR, format: STR, summary: STR,
                            keyId: STR }),
  compliance: STR, complianceChange: DEVICE_CHANGE,
  status: STR, statusChange: DEVICE_CHANGE,
  riskLevel: STR, riskChange: DEVICE_CHANGE,
  platform: STR, model: STR, os: STR,
  enrolment: Kit.closed({ method: STR, at: WHEN, actor: STR }),
  nativeSso: BOOL,
  rememberedBrowser: Kit.nullable(Kit.closed({
    generation: NUM, issuedAt: STR, browser: STR, secondFactorAt: STR
  })),
  sessionLive: BOOL, lastUsed: WHEN, created: WHEN
});

const DEVICES_VIEW = Kit.closed({
  user: STR, maxPerPerson: NUM, devices: Kit.listOf(DEVICE_VIEW)
});

const STORED_CERTIFICATE = Kit.closed({
  sha256: STR, subject: STR, issuer: STR, serialNumber: STR, notBefore: STR,
  notAfter: STR, expired: BOOL, readable: BOOL
});

const CERTIFICATES_VIEW = {
  user: STR, dn: STR, certificates: Kit.listOf(STORED_CERTIFICATE), rule: STR
};

const SIGNING_ROW = Kit.closed({
  serialHex: STR, label: STR, subject: STR, keyAlg: STR, notBefore: WHEN,
  notAfter: WHEN, thumbprint: STR, state: STR, reason: NSTR, revokedAt: WHEN,
  certificatePem: STR
});

const SIGNING_VIEW = Kit.closed({
  ok: BOOL, kind: STR, holder: STR, implicitName: STR,
  certificates: Kit.listOf(SIGNING_ROW), active: NUM, max: NUM,
  keyAlgorithms: STRS, defaultKeyAlg: STR, revocationReasons: STRS,
  passwordMin: NUM, caAvailable: BOOL
});

// ---------------------------------------------------------------------------
// THE SIGN-ON SESSIONS AND WHAT WAS ISSUED ON THEM.
// ---------------------------------------------------------------------------
const DEVICE_BOUND = Kit.nullable(Kit.closed({
  bound: BOOL, fact: STR, alg: STR, boundAt: NUM, refreshedAt: NUM,
  refreshes: NUM, reasons: STRS
}));

// `AdminStats.recordJwt()`: the claims and facts of a token, with its state.
const ISSUED_TOKEN = Kit.closed({
  state: STR, key: STR, jti: STR, kind: STR, typ: STR, revocable: BOOL,
  sub: STR, iss: STR, username: STR,
  client_id: Kit.oneOrMany(STR), audience: STR, scope: Kit.oneOrMany(STR),
  jkt: STR, x5t: STR, x5tSpki: STR, iat: NUM, nbf: NUM, exp: NUM,
  sessionId: STR, sessionAuthenticated: BOOL, setId: STR, grant: STR,
  grantId: STR, grantRefresh: BOOL, issuedAt: NUM, revoked: BOOL,
  revokedAt: NUM, revokedVia: STR, length: NUM
});

// `recordArtifact()`, with each of its four callers' details: an assertion, a
// ticket, an SVID and a credential.
const ISSUED_ARTIFACT = Kit.closed({
  state: STR, kind: STR, issuedAt: NUM, expiresAt: WHEN, subject: STR, key: STR,
  id: STR, audience: STR, signed: BOOL,
  // `revokeArtifact()`: an artifact can be disowned as a token can.
  revoked: BOOL, revokedAt: NUM, revokedVia: STR,
  realm: STR, service: STR, etype: Kit.oneOf(STR, NUM), claimSet: STR,
  username: STR, pacClaims: NUM,
  entryId: STR, serial: STR, hint: STR,
  person: STR, configId: STR
});

const USER_SESSION = Kit.closed({
  id: STR, username: STR, sub: STR, amr: STR, acr: STR, startedAt: NUM,
  authTime: NUM, authentications: NUM, expires: NUM, expired: BOOL,
  wsfedRealms: STRS, deviceBound: DEVICE_BOUND, accountSet: STR,
  tokens: Kit.listOf(ISSUED_TOKEN), tokensPaging: PAGING
});

const AUTH_EVENT = Kit.closed({
  at: NUM, protocol: STR, method: STR, presented: STR, realm: STR, sub: STR,
  address: STR, client_id: STR, amr: Kit.oneOrMany(STR), acr: STR,
  sessionId: STR, note: STR
});

const USER_ROW = {
  key: STR, name: STR, forms: COUNTED('form'), realms: COUNTED('realm'),
  protocols: Kit.listOf(Kit.closed({
    protocol: STR, count: NUM, firstAt: NUM, lastAt: NUM,
    methods: COUNTED('method')
  })),
  authentications: NUM, firstAt: NUM, lastAt: NUM, isClient: BOOL,
  authenticated: BOOL, knownBy: STR, events: Kit.listOf(AUTH_EVENT),
  eventsForgotten: NUM,
  tokens: Kit.closed({ issued: NUM, valid: NUM, expired: NUM, revoked: NUM,
                       other: NUM }),
  artifactKinds: COUNTED('kind'), artifacts: NUM, lastActivityAt: NUM
};

// `common/audit.js`'s row: an audit event, on the drill-down's attempts.
const AUDIT_EVENT = Kit.closed({
  seq: NUM, origin: STR, at: NUM, category: STR, action: STR, outcome: STR,
  errorCode: STR, actor: STR, actorForm: STR, target: STR, protocol: STR,
  channel: STR, address: STR, summary: STR,
  detail: Kit.freeForm(
    'What the call site that wrote the audit row chose to record, which ' +
    'differs at each of hundreds of them; the keys and the values are data.')
});

const OWNER = Kit.closed({ dn: STR, kind: STR, name: STR, present: BOOL });

// `ServiceAccounts.of()`: the facts on the entry.
const SERVICE_ACCOUNT_FACTS = Kit.closed({
  username: STR, dn: STR, serviceAccount: BOOL, owners: Kit.listOf(OWNER),
  destination: STR, secretName: STR, rotatedAt: STR,
  previousPasswordExpires: NUM,
  rotation: Kit.closed({ failures: NUM, lastError: STR, lastAttempt: NUM }),
  ownerProtected: BOOL, policy: STR
});

const OWNERSHIP = Kit.closed({
  kind: STR, name: STR, marked: BOOL, protected: BOOL, reasons: STRS
});

// `AdminViews.serviceAccountJson()`: those facts as a page reads them.
const SERVICE_ACCOUNT_VIEW = Kit.closed({
  username: STR, owners: Kit.listOf(OWNER), ownership: OWNERSHIP,
  destination: NSTR, secretName: NSTR, rotatedAt: NSTR,
  previousPasswordUntil: NSTR,
  rotation: Kit.closed({
    enabled: BOOL, rotates: BOOL, nextDueAt: NSTR, failures: NUM,
    lastError: NSTR, lastAttemptAt: NSTR, alarm: BOOL
  }),
  policy: Kit.closed({
    exemptFromSecondFactor: BOOL, allowBrowserSignIn: BOOL, doors: STRS,
    requiresOwner: BOOL, from: STR, name: NSTR
  })
});

const FIELD_GROUP = Kit.closed({
  id: STR, label: STR, what: STR, attributes: STRS
});

// `PersonEditor.editorFor()`.
const ATTRIBUTE_EDITOR = Kit.nullable(Kit.closed({
  dn: STR,
  attributes: Kit.listOf(Kit.closed({
    name: STR, label: STR, schema: STR, note: STR, simple: BOOL, must: BOOL,
    format: STR, custom: BOOL, values: STRS, required: BOOL, why: STR,
    example: STR, editable: BOOL, group: STR, multi: BOOL,
    choices: STRS
  })),
  withheld: Kit.listOf(Kit.closed({ name: STR, label: STR, kind: STR,
                                    why: STR })),
  mail: STR, pseudonyms: STRS, pseudonymPending: STR
}));

const KEY_CERT = Kit.closed({
  subject: STR, issuer: STR, serialHex: STR, notBefore: STR, notAfter: STR,
  expired: BOOL, selfSigned: BOOL, keyType: STR, thumbprint: STR,
  unreadable: STR
});

const PERSON_KEY = Kit.closed({
  handle: STR, label: STR, source: STR, state: STR, reason: STR, revokedAt: STR,
  serialHex: STR, expiresAt: STR, notAfter: STR, privateKeyHeld: BOOL,
  certificate: Kit.nullable(KEY_CERT), chain: Kit.listOf(KEY_CERT)
});

const KEY_NAMES = Kit.closed({ issuer: STR, keys: STR, privateKey: STR });

const KEY_PAIR_FACTS = {
  label: STR, held: BOOL, keys: Kit.listOf(PERSON_KEY), valid: NUM,
  atCap: BOOL, handleLabel: STR, issuers: STRS, effectiveIssuers: STRS,
  attributes: KEY_NAMES
};

// `AdminViews.personCredentialsState().json`.
const PERSON_CREDENTIALS = Kit.closed({
  storable: BOOL, found: BOOL,
  keyPairs: Kit.listOf(Kit.closed(Object.assign({ purpose: STR },
                                                KEY_PAIR_FACTS))),
  maxPerPerson: NUM, revocationReasons: STRS, caAvailable: BOOL,
  sealsAtRest: BOOL, selfService: BOOL, sources: STRS
});

// The same state as the drawing page reads it (`userPageData()`'s `keyPairs`).
const PERSON_KEY_PAGE = Kit.closed({
  storable: BOOL, found: BOOL, username: STR,
  purposes: Kit.listOf(Kit.closed(Object.assign({ id: STR }, KEY_PAIR_FACTS))),
  ca: Kit.closed({
    available: BOOL, keyAlg: STR, leafLifetimeDays: NUM,
    keyAlgorithms: Kit.listOf(Kit.closed({ id: STR, label: STR, kind: STR }))
  }),
  sealsAtRest: BOOL, selfService: BOOL, sources: STRS, maxPerPerson: NUM,
  revocationReasons: STRS
});

const ETYPE = Kit.closed({ etype: NUM, name: STR });

const KERBEROS_STATE = Kit.closed({
  kdc: BOOL, realm: STR, trustRealm: STR, reason: STR, productKdc: NBOOL,
  personKeys: BOOL, principal: STR, nameUsable: BOOL, person: BOOL,
  disabled: BOOL,
  keys: Kit.nullable(Kit.closed({
    kvno: NNUM, etypes: Kit.listOf(ETYPE), derivedAt: STR, derivedOn: STR,
    sealed: BOOL, current: BOOL,
    retained: Kit.listOf(Kit.closed({
      kvno: NNUM, etypes: Kit.listOf(ETYPE), retiredAt: STR, expiresAt: STR
    }))
  }))
});

const RIGHTS = Kit.freeForm(
  'An RFC 9635 access right as the client asked for it: a reference string ' +
  'or an object in the access type the resource server defines.');

const GNAP_GRANT = Kit.closed({
  id: STR, state: STR,
  finalization: Kit.nullable(Kit.closed({ reason: STR, at: NUM, note: STR })),
  client: NSTR, clientName: NSTR, authorizationServer: NSTR, createdAt: NNUM,
  updatedAt: NNUM, grantExpiresAt: NNUM, approvedBy: STR, rights: RIGHTS,
  rightsAre: STR, subjectReleasedAt: NNUM, derivedFrom: NSTR,
  tokens: Kit.listOf(Kit.closed({
    jti: STR, label: NSTR, format: STR, issuedAt: NNUM, expiresAt: NNUM,
    state: STR, bearer: BOOL, access: RIGHTS, revokedWhy: NSTR
  })),
  revocable: BOOL
});

const UMA_VIEW = Kit.nullable(Kit.closed({
  user: STR,
  resources: Kit.listOf(Kit.closed({
    id: STR, name: STR, type: STR, scopes: STRS, resourceServer: STR,
    owner: STR, ownerKind: STR, createdAt: NUM
  })),
  shares: Kit.listOf(Kit.closed({
    id: STR, resourceId: STR, scopes: STRS,
    recipient: Kit.closed({ kind: STR, value: STR, label: STR }),
    expires: STR, acr: STR, askMe: BOOL
  })),
  held: Kit.listOf(Kit.closed({
    jti: STR, requestingParty: STR, client: STR, resourceServer: STR,
    permissions: Kit.oneOf(STR, STRS), upgradedFrom: STR, createdAt: NUM,
    exp: NUM
  })),
  pending: Kit.listOf(Kit.closed({
    id: STR, state: STR, owner: STR, ownerKind: STR, requester: STR,
    client: STR, resourceServer: STR, permissions: Kit.oneOf(STR, STRS),
    createdAt: NUM, expiresAt: NUM
  }))
}));

const WEBAUTHN_SETTINGS = Kit.closed({
  enabled: BOOL, rpName: STR, rpId: STR, algorithms: STRS, attestation: STR,
  userVerification: STR, residentKey: STR, authenticatorAttachment: STR,
  timeoutMs: NUM, credProps: BOOL,
  minPinLength: Kit.nullable(Kit.oneOf(BOOL, NUM)),
  hints: STRS, maxKeysPerPerson: NUM, primaryAllowed: BOOL, mfaAllowed: BOOL,
  usernameless: BOOL, insecureAlgorithms: BOOL, pqcOnly: BOOL,
  pqcAlongsideClassical: BOOL
});

// What the drawing page reads (`userPageData()`). `mfa` is `{ storable }`
// alone where no credential store is installed.
const USER_PAGE = Kit.closed({
  key: STR, riskAsked: BOOL,
  counts: Kit.closed({ live: NUM, tokens: NUM, valid: NUM, expired: NUM,
                       artifacts: NUM, ended: NUM, sessionless: NUM }),
  back: STR, params: Kit.mapOf(Kit.oneOrMany(SCALAR)), blocksPerPage: NUM,
  perPage: NUM,
  maxEventsPerUser: NUM, directoryLoaded: BOOL,
  mfa: Kit.closed({
    storable: BOOL, mech: MECHANISMS,
    totp: Kit.closed({ enabled: BOOL, issuer: STR, digits: NUM, period: NUM,
                       algorithm: STR, window: NUM, secretBytes: NUM,
                       enrolmentTtlMs: NUM }),
    webauthn: WEBAUTHN_SETTINGS,
    recovery: Kit.closed({ enabled: BOOL, count: NUM, length: NUM,
                           groupSize: NUM }),
    appPasswords: Kit.closed({ ok: BOOL, unreadable: BOOL,
                               passwords: Kit.listOf(Kit.closed(APP_PASSWORD)),
                               errors: STRS }),
    doors: DOORS_FOR, verifications: VERIFICATIONS_VIEW,
    inventsClaimValues: BOOL, devices: DEVICES_VIEW,
    selfIssued: SELF_ISSUED_VIEW, publishedDids: PUBLISHED_DIDS_VIEW,
    certificates: Kit.closed(Object.assign({ ok: BOOL, errors: STRS },
                                           CERTIFICATES_VIEW)),
    signing: SIGNING_VIEW,
    mail: Kit.closed({
      status: Kit.closed({
        optedIn: STR, kind: STR, usable: BOOL, why: STR, verified: BOOL,
        address: STR, offered: Kit.closed({ code: BOOL, link: BOOL }),
        failures: NUM
      }),
      usable: BOOL, audSubs: STRS
    })
  }),
  fieldGroups: Kit.listOf(FIELD_GROUP),
  delegation: Kit.closed({
    found: BOOL, person: BOOL, username: STR, dn: STR, sub: STR,
    notDelegated: BOOL, mayAct: STR, delegate: Kit.nullable(Kit.oneOf(
      STR, Kit.closed({ dn: STR, name: STR, kind: STR, present: BOOL,
                         sub: STR }))),
    semantics: STRS, defaultSemantics: STR,
    groups: Kit.listOf(Kit.closed({ dn: STR, cn: STR }))
  }),
  keyPairs: PERSON_KEY_PAGE,
  serviceAccountRules: Kit.closed({ requiresOwner: BOOL, maxOwners: NUM,
                                    dn: STR }),
  serviceProviders: Kit.listOf(Kit.closed({ fedId: STR, fedPeer: STR }))
});

const DIRECTORY_COUNTS = Kit.nullable(Kit.closed({
  people: NUM, withSecond: NUM, withTotp: NUM, withKeys: NUM, primaryKeys: NUM,
  unreadable: NUM, withPassword: NUM, passwordOnly: NUM, noWayIn: NUM,
  signedInHere: NNUM, neverSignedInHere: NNUM
}));

const USERS_FILTER = Kit.closed({
  q: NSTR, protocol: NSTR, factor: NSTR, kind: NSTR
});

// ---------------------------------------------------------------------------
// THE LIST, AND THE ONE IDENTITY. Named: a test reads `UserList`'s members.
// ---------------------------------------------------------------------------
const USER_LIST = Kit.closed({
  known: NUM, matched: NUM, shown: NUM, authenticatedHere: NUM,
  factors: Kit.closed({
    withSecond: NUM, withTotp: NUM, withKeys: NUM, primaryKeys: NUM,
    passwordOnly: NUM, unreadable: NUM, noCredential: NUM
  }),
  store: BOOL, scanned: NUM, capped: BOOL, scanLimit: NUM,
  directoryPeople: NNUM, directoryCounts: DIRECTORY_COUNTS,
  directoryCountedAt: NSTR, directoryCountsKeptFor: NNUM, registryCap: NUM,
  filter: USERS_FILTER, serviceAccounts: NUM, protocols: STRS,
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  paging: PAGING, withActiveSession: NNUM, personFieldCount: NUM,
  newUserContainer: STR, registryKeeps: NUM,
  users: Kit.listOf(Kit.closed(Object.assign({}, USER_ROW, {
    factors: Kit.nullable(Kit.closed(FACTOR_HOLDER)),
    inDirectory: BOOL, serviceAccount: BOOL, liveSessions: NNUM, dn: STR
  })))
}, { description: 'Everyone this service has authenticated, united with at ' +
                  'most `scanLimit` of the people the directory defines.' });

const USER_DETAIL = Kit.closed({
  known: BOOL, user: Kit.closed(USER_ROW), subject: STR,
  serviceAccount: Kit.nullable(SERVICE_ACCOUNT_VIEW),
  risk: Kit.nullable(Kit.closed({
    subject: STR, level: STR, score: NUM, previousLevel: STR, reason: STR,
    lastAssessment: STR, crossedAt: NUM, updatedAt: NUM
  })),
  factors: FACTORS,
  sessions: Kit.listOf(USER_SESSION), sessionsPaging: PAGING,
  tokensOnEndedSessions: Kit.listOf(ISSUED_TOKEN),
  tokensOnEndedSessionsPaging: PAGING,
  tokensWithNoSession: Kit.listOf(ISSUED_TOKEN),
  tokensWithNoSessionPaging: PAGING,
  artifacts: Kit.listOf(ISSUED_ARTIFACT), artifactsPaging: PAGING,
  ldap: Kit.nullable(Kit.closed({
    dn: STR, found: BOOL, entry: Kit.nullable(ENTRY), alsoNamed: STRS,
    baseDn: STR, usersDn: STR, port: NNUM, listening: BOOL, listenError: NSTR,
    ldapsPort: NNUM, ldapsListening: BOOL, autoCreateUsers: BOOL,
    entryCount: NUM, maxEntries: NUM, full: BOOL
  })),
  credentials: PERSON_CREDENTIALS,
  federationLinks: Kit.listOf(Kit.closed({
    link: STR, relationship: STR, issuer: STR, subject: STR,
    relationshipExists: BOOL
  })),
  federationLinksPaging: PAGING,
  kerberos: KERBEROS_STATE, attributeEditor: ATTRIBUTE_EDITOR,
  gnapGrants: Kit.listOf(GNAP_GRANT), gnapGrantsPaging: Kit.nullable(PAGING),
  gnapGrantsCells: Kit.nullable(Kit.closed({
    multiCell: BOOL, cell: STR, complete: BOOL, note: STR
  })),
  uma: UMA_VIEW,
  authenticationEvents: Kit.listOf(AUDIT_EVENT),
  authenticationEventsPaging: PAGING, authenticationEventsMatched: NUM,
  authenticationEventsKnownActors: FLAGS,
  authenticationEventsLog: Kit.closed({
    held: NUM, recorded: NUM, dropped: NUM, maxEvents: NUM
  }),
  page: USER_PAGE
}, { description: 'One identity: the names it has been seen under, how it ' +
                  'authenticated, every sign-on session it holds with the ' +
                  'tokens issued on each, and its directory entry.' });

// A name nobody knows is an answer about the identity, 200.
const USER_UNKNOWN = Kit.closed({
  user: STR, known: BOOL, registryKeeps: NUM
});

// ---------------------------------------------------------------------------
// THE SESSIONS, ACROSS EVERY FAMILY THAT HOLDS ONE.
// ---------------------------------------------------------------------------
const SESSION_ROW = Kit.closed({
  id: STR, family: STR, kind: STR, derivedFrom: STR, rpClientId: STR, key: STR,
  username: STR, sub: STR, protocol: STR, handle: STR, sessionId: STR,
  startedAt: NUM, expiresAt: NUM, expiryRule: STR, amr: Kit.oneOrMany(STR),
  acr: STR, deviceBound: DEVICE_BOUND, carries: STRS, detail: STR,
  authenticated: BOOL, accountSet: STR, terminable: BOOL, why: STR
}, { description: 'One live session of any kind.' });

const SESSION_LIST = Kit.closed({
  // `note` says why, where `logout/logout.ts` is not in this process.
  installed: BOOL, note: STR, held: NUM, matched: NUM, shown: NUM,
  heldByKind: COUNTS,
  filter: Kit.closed({ q: NSTR, protocol: NSTR }), protocols: STRS, at: NUM,
  expiryRules: Kit.mapOf(STR),
  sessions: Kit.listOf({ $ref: '#/components/schemas/SessionRow' }),
  unauthenticatedHeld: NUM, unauthenticatedKept: BOOL,
  unauthenticatedSessions: Kit.listOf({
    $ref: '#/components/schemas/SessionRow' }),
  unauthenticatedPaging: PAGING, windowed: BOOL,
  accountChoices: Kit.closed({ enabled: BOOL, counts: COUNTS }),
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  paging: PAGING
}, { description: 'Every session this service is holding right now, filtered ' +
                  'and paged.' });

// `Logout.terminate()`, and what it hands the page to make a browser do.
const ENDED = Kit.closed({
  id: STR, family: STR, kind: STR, label: STR, message: STR, pending: BOOL
});

const DELIVERY = Kit.closed({
  id: STR, realm: STR, clientId: STR, uri: STR, state: STR, generation: NUM,
  attempts: NUM, inFlight: BOOL, holder: STR, status: Kit.nullable(NUM),
  errorCode: NSTR, why: NSTR, queuedAt: STR, nextAttemptAt: STR,
  lastAttemptAt: STR, finishedAt: STR,
  sessionId: STR, iss: STR, sub: STR, sid: STR, sessionRequired: BOOL, via: STR,
  trigger: STR, encrypted: STR
});

const TERMINATE_RESULT = Kit.closed({
  ok: BOOL, key: STR, scope: STR, terminated: Kit.listOf(ENDED),
  skipped: Kit.listOf(ENDED), unknown: STRS,
  notifications: Kit.listOf(Kit.closed({
    clientId: STR, uri: STR, url: STR, sessionRequired: BOOL, why: STR
  })),
  cleanups: Kit.listOf(Kit.closed({ realm: STR, wreply: STR, url: STR,
                                    why: STR })),
  logoutRequests: Kit.listOf(Kit.closed({
    entityId: STR, from: STR, destination: STR, url: STR, why: STR
  })),
  partnerLogouts: Kit.listOf(Kit.closed({
    relationship: STR, label: STR, protocol: STR, what: STR, kind: STR,
    url: STR, action: STR, fields: Kit.mapOf(STR)
  })),
  backchannel: Kit.listOf(Kit.withoutCodes(DELIVERY)), message: STR,
  acrossCluster: Kit.listOf(Kit.closed({ family: STR, at: WHEN, message: STR }))
});

const FAMILY = {
  id: STR, label: STR, protocol: STR, spec: STR, what: STR, terminable: BOOL
};

const LIVE_ROW = {
  id: STR, family: STR, kind: STR, handle: STR, label: STR, detail: STR,
  startedAt: NUM, expiresAt: NUM, terminable: BOOL, why: STR, sessionId: STR
};

const LOGOUT_VIEW = Kit.closed({
  user: STR, known: BOOL, canWrite: BOOL, error: STR,
  key: STR, sessions: NUM, total: NUM, listed: NUM, notListed: NUM,
  maxRows: NUM, at: NUM,
  families: Kit.listOf(Kit.closed(Object.assign({
    rows: Kit.listOf(Kit.closed(LIVE_ROW)),
    // `inventoryFor()`: what a family held, what was cut, and a collector's
    // failure. The list of families with no person named has none of them.
    held: NUM, notListed: NUM, failure: STR
  }, FAMILY))),
  rows: Kit.listOf(Kit.closed(Object.assign({ user: STR, familyLabel: STR },
                                            LIVE_ROW))),
  paging: PAGING, family: STR,
  backchannelDeliveries: Kit.listOf(DELIVERY),
  backchannelDeliveriesPaging: PAGING, backchannelCounts: COUNTS,
  deliveryState: STR, deliveryq: STR, settings: SETTINGS, hasReader: BOOL,
  kerberosRealm: STR, opensTestControls: BOOL
});

// ---------------------------------------------------------------------------
// GROUPS. `GroupList`, `GroupDetail` and its `group` are read by a test.
// ---------------------------------------------------------------------------
const DIRECTORY_STATE = {
  baseDn: STR, usersDn: STR, groupsDn: STR, port: NNUM, listening: BOOL,
  listenError: NSTR, ldapsPort: NNUM, ldapsListening: BOOL, entryCount: NUM
};

const ADMIN_GROUPS = Kit.closed({ read: NSTR, write: NSTR });

// `groupsFor()` reads the whole list whichever it was asked, so a drill-down
// carries these two as well.
const GROUP_ROWS = Kit.listOf(Kit.closed({
  dn: STR, cn: STR, rule: STR, description: STR, objectClass: STRS,
  origin: STR, createdAt: WHEN, modifiedAt: WHEN, memberCount: NUM,
  presentCount: NUM, danglingCount: NUM, claimedCount: NUM, ownerCount: NUM,
  attributeCount: NUM
}));

const GROUP_LIST = Kit.closed(Object.assign({}, DIRECTORY_STATE, {
  groupCount: NUM, matched: NUM, shown: NUM, canWrite: BOOL,
  membershipValues: NUM, dangling: NUM, settings: SETTINGS,
  filter: Kit.closed({ q: NSTR, exclude: Kit.nullable(STRS) }),
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  paging: PAGING, adminGroups: ADMIN_GROUPS, groups: GROUP_ROWS
}), { description: 'Every group the embedded directory holds.' });

const GROUP_OBJECT = Kit.closed({
  dn: STR, cn: STR, rule: STR, origin: STR, createdAt: WHEN, modifiedAt: WHEN,
  operational: STRS, memberAttributes: STRS, attributes: ATTRIBUTES,
  members: Kit.listOf(GROUP_MEMBER), memberCount: NUM, presentCount: NUM,
  danglingCount: NUM,
  claimed: Kit.listOf(Kit.closed({
    dn: STR, kind: STR, userKey: STR, cn: STR, mail: STR, displayName: STR,
    value: STR, attribute: STR, holds: STR, present: BOOL
  })),
  owners: Kit.listOf(OWNER), maxOwners: NUM
});

const GROUP_DETAIL = Kit.closed(Object.assign({}, DIRECTORY_STATE, {
  // A drill-down says the directory's cap; the list's answer does not, and
  // `tests/protocol/admin_api.js` reads `GroupList`, so it stays off that one.
  maxEntries: NUM,
  found: BOOL, requested: STR, notAGroup: BOOL, canWrite: BOOL,
  group: GROUP_OBJECT, groups: GROUP_ROWS, groupCount: NUM,
  policyReferences: Kit.listOf(Kit.closed({
    attribute: STR, noun: STR, choices: STRS, value: STR
  })),
  ownership: OWNERSHIP,
  membersPaging: PAGING, claimedPaging: PAGING, known: FLAGS,
  adminGroups: ADMIN_GROUPS
}), { description: 'One group, with the same directory facts the list ' +
                   'carries around it.' });

// No directory is loaded in this process (`AdminViews.groupsJson()`).
const GROUPS_ABSENT = Kit.closed({ directory: BOOL, groups: Kit.listOf(STR) });

// `?group=` naming nothing, or an entry that is not a group: an answer, 200.
const GROUP_MISSING = Kit.closed(Object.assign({}, DIRECTORY_STATE, {
  maxEntries: NUM,
  found: BOOL, requested: STR, notAGroup: BOOL, group: { type: 'null' },
  groups: GROUP_ROWS, groupCount: NUM, entryDn: STR, wanted: STR,
  adminGroups: ADMIN_GROUPS
}));

// What an owner of the group is answered (`OWNER_READS`' projection).
const GROUP_FOR_OWNER = Kit.closed({
  found: BOOL,
  group: Kit.nullable(Kit.closed({
    dn: STR, cn: STR, description: STR, members: Kit.listOf(GROUP_MEMBER),
    memberCount: NUM, owners: Kit.listOf(OWNER), maxOwners: NUM
  })),
  membersPaging: PAGING
});

const GROUP_OWNERS = Kit.action({
  changed: BOOL, dn: STR, owner: STR, owners: Kit.listOf(OWNER)
});

// ---------------------------------------------------------------------------
// THE CONSOLE'S ROLES.
// ---------------------------------------------------------------------------
const RBAC_ROLE = Kit.closed({
  role: STR, label: STR, what: STR, implies: STRS, dn: STR, cn: STR,
  exists: BOOL, origin: STR, createdAt: WHEN, modifiedAt: WHEN,
  memberCount: NUM, presentCount: NUM, danglingCount: NUM, claimedCount: NUM
});

const CANDIDATE = Kit.closed({ username: STR, inDirectory: BOOL, seen: BOOL });

const ADMIN_ROLES = Kit.closed({
  enforced: BOOL, openWhenEmpty: BOOL, openToAnyone: BOOL,
  closedToEveryone: BOOL, windowOpens: BOOL, bootstrapPasswordRequired: BOOL,
  bootstrap: Kit.nullable(Kit.closed({
    claimedAt: NSTR, seeded: BOOL, username: NSTR
  })),
  available: BOOL, groupsDn: STR, usersDn: STR, grantCount: NUM, matched: NUM,
  shown: NUM, settings: SETTINGS,
  filter: Kit.closed({ q: NSTR, role: NSTR }),
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT,
  you: Kit.closed({ username: NSTR, roles: STRS, read: BOOL, write: BOOL,
                    viaEmptyRoster: BOOL }),
  roles: Kit.listOf(RBAC_ROLE),
  grants: Kit.listOf(Kit.closed({
    username: STR, role: STR, roleLabel: STR, cn: STR, dn: STR, value: STR,
    attribute: STR, holds: STR, memberDn: STR, present: BOOL, kind: STR,
    userKey: STR
  })),
  candidates: Kit.listOf(CANDIDATE), candidatesPaging: PAGING,
  candidateSearch: Kit.closed({
    q: NSTR, total: NUM, matched: NUM, countCapped: BOOL, countCap: NUM,
    complete: BOOL,
    incomplete: Kit.nullable(Kit.closed({
      unusable: NUM, short: NUM, capped: BOOL, cap: NUM
    }))
  }),
  picked: Kit.nullable(Kit.closed({
    asked: STR, candidate: Kit.nullable(CANDIDATE)
  })),
  paging: PAGING,
  candidatePane: Kit.closed({
    from: NUM, matched: NUM, countCapped: BOOL, shown: Kit.listOf(CANDIDATE)
  }),
  known: FLAGS,
  roleChoices: Kit.listOf(Kit.closed({
    id: STR, label: STR, what: STR, setting: STR, implies: STRS
  }))
});

// ---------------------------------------------------------------------------
// THE ROSTER OF SECOND FACTORS, AND THE THREE MECHANISM PAGES.
// ---------------------------------------------------------------------------
const TOTP_REPORT = Kit.closed({
  offered: BOOL, digits: NUM, secretBits: NUM, window: NUM, period: NUM,
  truncation: STR, encoding: STR,
  algorithms: Kit.listOf(Kit.closed({ name: STR, id: STR, inUse: BOOL,
                                      note: STR }))
});

const WEBAUTHN_REPORT = Kit.closed({
  offered: BOOL, rpName: STR, rpId: STR, rpIdSource: STR,
  algorithms: Kit.listOf(Kit.closed({
    name: STR, coseAlg: NUM, offered: BOOL, postQuantum: BOOL, rank: NUM,
    insecure: BOOL, notOfferedBecause: STR
  })),
  algorithmsSource: STR, registrationMode: STR, insecureAlgorithms: BOOL,
  pqcOnly: BOOL, pqcAlongsideClassical: BOOL,
  lanes: Kit.listOf(Kit.closed({ lane: STR, algorithms: STRS })),
  upgradeMode: STR, upgradeAlgorithms: STRS,
  curves: Kit.listOf(Kit.closed({ name: STR, coseCurve: NUM })),
  userVerification: STR, userVerificationEnforced: BOOL, attestation: STR,
  attestationPolicy: STR, attestationPolicyConfigured: STR,
  attestationVerified: BOOL, attestationDemandsTrust: BOOL,
  attestationFormats: STRS, attestationAllowedAaguids: STRS,
  attestationMinCertificationLevel: STR, attestationRequireFips: BOOL,
  attestationAllowSafetynet: BOOL, attestationAndroidSoftwareKeys: BOOL,
  attestationTrustAnchors: NUM, timeoutMs: NUM, authenticatorAttachment: STR,
  residentKey: STR, credProps: BOOL, primaryAllowed: BOOL, mfaAllowed: BOOL,
  usernameless: BOOL, maxKeysPerPerson: NUM, signatureCounter: STR,
  clientDataHash: STR,
  // The FIDO Metadata Service, as the mechanism page adds it.
  mds: Kit.closed({
    url: STR, rows: NUM, serial: NUM, job: STR, version: STR, stale: BOOL,
    active: BOOL, loadedAt: NUM, known: BOOL, nextUpdateAt: NUM
  })
});

const BACKUP_REPORT = Kit.closed({
  offered: BOOL, count: NUM, length: NUM, groupSize: NUM, alphabet: STR,
  alphabetSize: NUM, bitsPerCode: NUM, source: STR, comparison: STR,
  atRest: STR, comparisonOfAHash: STR
});

const MECHANISM_PAGE = function (status: Json): Json {
  return Kit.closed({
    page: STR, title: STR, what: STR, notes: STRS,
    links: Kit.listOf(Kit.closed({ href: STR, what: STR })),
    settings: SETTINGS, leadHtml: STR, alsoHtml: STRS, status: status,
    // `sendJson()` adds it to a successful read of a Protocols page.
    protocolEndpoints: Kit.listOf(Kit.closed({
      name: STR, methods: STRS, url: STR, route: STR
    }))
  });
};

const MFA_ROSTER = Kit.closed({
  offered: BOOL, totp: TOTP_REPORT, webauthn: WEBAUTHN_REPORT,
  counts: Kit.closed({
    people: NUM, withSecond: NUM, withTotp: NUM, withKeys: NUM,
    primaryKeys: NUM, passwordOnly: NUM, unreadable: NUM, noCredential: NUM
  }),
  store: BOOL, scanned: NUM, capped: BOOL, scanLimit: NUM,
  directoryPeople: NNUM, directoryCounts: DIRECTORY_COUNTS,
  directoryCountedAt: NSTR, directoryCountsKeptFor: NNUM,
  filter: USERS_FILTER, page: INT, pages: INT, perPage: INT, firstRow: INT,
  lastRow: INT, matched: NUM, shown: NUM,
  people: Kit.listOf(Kit.closed(FACTOR_HOLDER))
});

// ---------------------------------------------------------------------------
// THE RESOURCE ROLES, ON `/admin/roles`.
// ---------------------------------------------------------------------------
const ROLE_ROW = {
  name: STR, localName: STR, application: STR, displayName: STR,
  description: STR, id: STR, dn: STR, console: BOOL, native: BOOL,
  builtIn: BOOL, memberTypes: STRS, users: STRS, groups: STRS,
  applications: STRS, permissions: STRS, conferredBy: STRS,
  ownerProtected: BOOL
};

const ROLE_ENTRY = Kit.nullable(Kit.closed({
  dn: STR, origin: STR, createdAt: WHEN, modifiedAt: WHEN, operational: STRS,
  attributes: ATTRIBUTES
}));

const ROLE_DETAIL = Kit.closed(Object.assign({}, ROLE_ROW, {
  found: BOOL, what: STR, owners: Kit.oneOf(STRS, Kit.listOf(OWNER)),
  requiredBy: Kit.listOf(Kit.closed({ application: STR, name: STR })),
  entry: ROLE_ENTRY, maxOwners: NUM, holderCount: NUM, canWrite: BOOL,
  ownership: OWNERSHIP
}));

const ROLE_POLICY = Kit.nullable(Kit.closed({
  name: STR, ok: BOOL, setting: STR, entry: BOOL, enabled: NBOOL, effect: STR,
  why: STR, builtIn: BOOL, readsRisk: BOOL, template: STR
}));

const ROLES_VIEW = Kit.closed({
  container: NSTR, storable: BOOL, defaultRequired: Kit.oneOf(STR, STRS),
  claim: BOOL, claimName: STR, enforced: BOOL, gated: BOOL,
  policy: ROLE_POLICY,
  builtIn: Kit.listOf(Kit.closed({ name: STR, what: STR, builtIn: BOOL })),
  roles: Kit.listOf(Kit.closed(Object.assign({ owners: STRS }, ROLE_ROW))),
  permissions: Kit.listOf(Kit.closed({ id: STR, application: STR, name: STR,
                                       gated: BOOL })),
  permissionIds: STRS,
  requiring: Kit.listOf(Kit.closed({ application: STR, name: STR,
                                     required: STRS, unknown: STRS })),
  counts: Kit.closed({ builtIn: NUM, configured: NUM, members: NUM,
                       requiring: NUM, unsatisfiable: NUM }),
  requiringPaging: PAGING, matched: NUM, shown: NUM, paging: PAGING,
  query: Kit.closed({ q: STR }),
  memberKinds: Kit.listOf(Kit.closed({ kind: STR, label: STR, field: STR,
                                       what: STR })),
  issuanceKinds: STRS, actions: STRS, settings: SETTINGS,
  shownRoles: Kit.listOf(Kit.closed(Object.assign({ owners: STRS }, ROLE_ROW))),
  applicationChoices: Kit.listOf(Kit.closed({ identifier: STR, name: STR })),
  role: ROLE_DETAIL
});

const VERDICT_FACTS = Kit.freeForm(
  'An exchange or per-right verdict the role PEP passes through from the ' +
  'XACML obligations of the policy that decided it.');

// `AdminViews.rolesPreview()`, with what the role PEP's `preview()` answers.
const ROLE_PREVIEW = Kit.closed({
  answered: BOOL, available: BOOL, why: STR,
  asked: Kit.closed({ application: STR, subject: STR, subjectKind: STR,
                      kind: STR }),
  allowed: BOOL, decision: STR, roles: STRS, required: STRS, policy: STR,
  status: Kit.freeForm(
    'The XACML response\'s `Status` element, which is the PDP\'s to word and ' +
    'can carry a status detail of any shape.'),
  risk: Kit.nullable(Kit.closed({ action: STR, factor: STR, observed: BOOL })),
  device: Kit.nullable(Kit.closed({ refusal: STR })),
  protocolRefused: Kit.nullable(Kit.closed({ declared: STRS, families: STRS })),
  mechanism: Kit.nullable(Kit.closed({ allowed: STRS, satisfied: STRS,
                                       secondFactor: BOOL })),
  scopes: Kit.listOf(Kit.closed({
    scope: STR, allowed: BOOL, decision: STR, why: STR, policy: STR,
    roles: STRS, required: STRS
  })),
  transfer: Kit.nullable(Kit.closed({ verdict: STR, decidedBy: STR })),
  passkey: Kit.nullable(Kit.closed({ verdict: STR, reason: STR,
                                     decidedBy: STR })),
  deferred: BOOL,
  // The two verdicts `IssuanceAnswer` declares for a question a preview does
  // not ask today; a member of the answer all the same.
  exchange: VERDICT_FACTS, gnapRights: Kit.listOf(VERDICT_FACTS)
});

// ---------------------------------------------------------------------------
// WHAT THE ACTIONS ANSWER. `reason` and `problems` are what a refusal from a
// domain module may carry beside `errors`; a '200' here also serves the '400'.
// ---------------------------------------------------------------------------
const REFUSAL = { reason: STR, problems: Kit.listOf(Kit.oneOf(STR, Kit.mapOf(
  SCALAR))) };

const personAction = function (extra?: Json): Json {
  return Kit.action(Object.assign({ username: STR }, REFUSAL, extra || {}));
};

const SIGNED_OUT = Kit.closed({ ended: BOOL, terminated: NUM, message: STR });

const ATTRIBUTE_WRITE = Kit.action({
  dn: STR, attribute: STR, mode: STR, values: STRS, reason: STR
});

const FACTOR_CLEARED = personAction({ sessionsEnded: NUM, remaining: NUM });

const REMOVED_KEY = Kit.closed({ credentialId: STR, label: STR,
                                 enrolledAt: NUM });

const ACCOUNT_WRITE = personAction({
  account: Kit.nullable(SERVICE_ACCOUNT_FACTS), changed: BOOL
});

const CREATION_OPTIONS = Kit.closed({
  rp: Kit.closed({ name: STR, id: STR }), algorithms: Kit.listOf(NUM),
  attestation: STR, timeout: NUM,
  authenticatorSelection: Kit.closed({
    userVerification: STR, residentKey: STR, requireResidentKey: BOOL,
    authenticatorAttachment: STR
  }),
  credProps: BOOL, minPinLength: BOOL, hints: STRS
});

const CEREMONY_USER = Kit.closed({ id: STR, name: STR, displayName: STR });

const MAIL_LINK = { mailedTo: STR, mailError: STR, expiresAt: WHEN };

const SIGNING_ISSUED = Kit.closed({
  serialHex: STR, subject: STR, keyAlg: STR, label: STR, notBefore: WHEN,
  notAfter: WHEN, thumbprint: STR, certificatePem: STR, chainPem: STRS,
  implicitName: STR
});

const FILE = Kit.closed({ name: STR, mime: STR, text: STR, base64: STR });

const CERTIFICATE_CHANGE = Kit.action(Object.assign({
  changed: BOOL, sha256: STR
}, CERTIFICATES_VIEW));

const LOGOUT_ACTION = Kit.action({ result: TERMINATE_RESULT });

const ROLE_MEMBER = Kit.action({ role: STR, kind: STR, member: STR });

const ROLE_PERMISSION = Kit.action({
  role: STR, permission: STR, gated: BOOL
});

const ROLE_CLIENT = Kit.action({ role: STR, client: STR });

const ROLE_OWNERS = Kit.action({
  role: STR, changed: BOOL, owner: STR, owners: Kit.listOf(OWNER)
});

const ACCOUNT_STATE = personAction({
  disabled: BOOL, changed: BOOL,
  // `AccountState.endEverything()`: counts, not the rows `terminate()` said.
  ended: Kit.nullable(Kit.closed({
    ended: BOOL, terminated: NUM, skipped: NUM, notifications: NUM,
    backchannel: Kit.listOf(Kit.withoutCodes(DELIVERY)), message: STR
  }))
});

const FEDERATION_LINK = personAction({
  link: STR, changed: BOOL, links: STRS
});

const SECOND_FACTOR_RULE = personAction({
  required: BOOL, requirement: MFA_REQUIREMENT
});

// A READ'S '400' IS THE REFUSAL AND NOT THE READ: left to itself a status
// borrows the '200' (`applyModels()`), and a query the handler refuses answers
// `{ ok, errors }`, which no view's model holds.
const REFUSED = Kit.action({ error: STR, error_description: STR });

const read = function (model: Json): Json {
  return { '200': model, '400': REFUSED };
};

const schemaRef = function (name: string): Json {
  return { $ref: '#/components/schemas/' + name };
};

export = {
  components: {
    UserList: USER_LIST,
    UserDetail: USER_DETAIL,
    SessionList: SESSION_LIST,
    SessionRow: SESSION_ROW,
    GroupList: GROUP_LIST,
    GroupDetail: GROUP_DETAIL,
    NewUserForm: Kit.closed({
      directory: BOOL, container: NSTR, why: STR,
      realm: Kit.closed({ id: STR, name: STR }), mode: STR,
      offersExampleData: BOOL,
      fields: Kit.listOf(Kit.closed({
        attribute: STR, label: STR, schema: STR, claim: STRS, invented: BOOL
      })),
      fieldGroups: Kit.listOf(FIELD_GROUP),
      gridFields: Kit.listOf(Kit.closed({
        attribute: STR, label: STR, group: STR, multi: BOOL, example: STR,
        simple: BOOL, takes: STR, custom: BOOL
      })),
      requiredAttributes: STRS, requiredEnforced: BOOL,
      credentials: Kit.listOf(Kit.closed({ id: STR, label: STR, what: STR })),
      username: STR,
      fieldRows: Kit.listOf(Kit.closed({
        attribute: STR, type: STR, what: STR, example: STR, forText: STR,
        families: STRS, everyFamily: BOOL, group: STR, simple: BOOL,
        required: BOOL, label: STR, schema: STR, claim: STRS, multi: BOOL,
        custom: BOOL, takes: STR
      })),
      longTextAttributes: STRS, mailAvailable: BOOL,
      persistence: Kit.closed({ persistsDirectory: BOOL, mode: STR }),
      defaultCredential: STR, credential: STR,
      passwordPolicy: Kit.closed({ profile: STR, enforced: BOOL, rules: STRS }),
      // What `?invent=` adds, and why it did not.
      invented: Kit.nullable(Kit.mapOf(Kit.oneOrMany(STR))),
      inventRefused: STR
    }, { description: 'Every attribute a person may be created with, and the ' +
                      'four ways they can be given a way in.' })
  } as Record<string, unknown>,

  operations: {
    getServiceAccounts: read(Kit.closed({
      policy: Kit.closed({
        rotationEnabled: BOOL, intervalDays: NUM, overlapMinutes: NUM,
        alarmFailures: NUM, from: STR
      }),
      totals: Kit.closed({
        accounts: NUM, withDestination: NUM, rotating: NUM, failing: NUM,
        alarms: NUM
      }),
      filter: Kit.closed({ failing: BOOL }),
      accounts: Kit.listOf(SERVICE_ACCOUNT_VIEW), paging: PAGING,
      // `?account=`, an owner's read.
      found: BOOL, account: Kit.nullable(SERVICE_ACCOUNT_FACTS)
    })),
    getUsers: read(Kit.oneOf(schemaRef('UserList'), schemaRef('UserDetail'),
                             USER_UNKNOWN)),
    getUserAppPasswords: read(APP_PASSWORDS_VIEW),
    getUserCertificates: { '200': Kit.action(CERTIFICATES_VIEW) },
    getUserDevices: read(DEVICES_VIEW),
    getUserSelfIssuedSubjects: read(SELF_ISSUED_VIEW),
    getUserPublishedDids: read(PUBLISHED_DIDS_VIEW),
    getUserVerifications: read(VERIFICATIONS_VIEW),
    getNewUserForm: read(schemaRef('NewUserForm')),
    issueActivationLink: {
      '200': personAction(Object.assign({
        activationUrl: STR, activationLink: STR }, MAIL_LINK))
    },
    createUser: {
      '200': personAction(Object.assign({
        dn: STR, entry: ENTRY, typed: STRS, invented: BOOL, credential: STR,
        serviceAccount: BOOL, serviceAccountError: STR, credentialError: STR,
        passwordSet: BOOL, generated: BOOL, password: STR, activationUrl: STR,
        activationLink: STR,
        // A name somebody holds, and what the attribute policy still asks for.
        existing: Kit.closed({ dn: STR, origin: STR }), missing: STRS,
        // The attribute names a create refused because a person does not
        // have them (STS-LDAP-0047). Absent, the refusal is something else
        // (#1404).
        unknown: STRS
      }, MAIL_LINK))
    },
    setUserPassword: {
      '200': personAction({ generated: BOOL, password: STR })
    },
    clearUserAuthenticatorApp: { '200': FACTOR_CLEARED },
    clearUserBackupCodes: { '200': FACTOR_CLEARED },
    clearUserEmailFactor: {
      '200': Kit.action({ removed: BOOL, sessionsEnded: NUM })
    },
    setUserAudSub: { '200': Kit.action() },
    setUserMail: { '200': Kit.action({ mail: STR, verified: BOOL }) },
    setUserPseudonyms: {
      '200': Kit.action({
        pseudonyms: STRS,
        pending: Kit.nullable(Kit.oneOf(STR, BOOL, Kit.mapOf(SCALAR)))
      })
    },
    setUserAttribute: { '200': ATTRIBUTE_WRITE },
    addUserAttributeValue: { '200': ATTRIBUTE_WRITE },
    removeUserAttributeValue: { '200': ATTRIBUTE_WRITE },
    updateUserFields: {
      '200': Kit.action({ changed: STRS, user: STR })
    },
    resetUserPassword: {
      '200': personAction({ password: STR, forcedChange: BOOL,
                            signedOut: SIGNED_OUT })
    },
    issuePasswordResetLink: {
      '200': personAction(Object.assign({
        resetUrl: STR, passwordRevoked: BOOL, signedOut: SIGNED_OUT
      }, MAIL_LINK))
    },
    disableUserPasskeys: {
      '200': personAction({ removed: Kit.listOf(REMOVED_KEY),
                            sessionsEnded: NUM, failed: NUM })
    },
    disableUserSecondFactors: {
      '200': personAction({
        removed: Kit.closed({ totp: BOOL, keys: Kit.listOf(REMOVED_KEY),
                              backupCodes: BOOL }),
        requirement: MFA_REQUIREMENT, sessionsEnded: NUM, failed: NUM
      })
    },
    requireUserSecondFactor: { '200': SECOND_FACTOR_RULE },
    stopRequiringUserSecondFactor: { '200': SECOND_FACTOR_RULE },
    setUserServiceAccount: {
      '200': personAction({
        serviceAccount: BOOL, account: Kit.nullable(SERVICE_ACCOUNT_FACTS),
        signedOut: Kit.nullable(SIGNED_OUT)
      })
    },
    addServiceAccountOwner: { '200': ACCOUNT_WRITE },
    removeServiceAccountOwner: { '200': ACCOUNT_WRITE },
    setServiceAccountDestination: { '200': ACCOUNT_WRITE },
    rotateServiceAccountPassword: {
      '200': personAction({ runId: Kit.oneOf(STR, NUM), alreadyQueued: BOOL })
    },
    setUserNotDelegated: { '200': personAction({ notDelegated: BOOL }) },
    setUserMayAct: { '200': personAction({ mayAct: STR }) },
    setUserDelegationSemantics: {
      '200': personAction({ semantics: STRS, defaultSemantics: NSTR })
    },
    answerUserCibaRequest: { '200': personAction({ state: STR }) },
    removeUserDevice: { '200': personAction({ removed: STR }) },
    addUserCertificate: { '200': CERTIFICATE_CHANGE },
    removeUserCertificate: { '200': CERTIFICATE_CHANGE },
    issueUserSigningCertificate: {
      '200': Kit.action({
        purpose: STR, certificate: SIGNING_ISSUED,
        files: Kit.closed({ pkcs12: FILE, key: FILE, chain: FILE }),
        user: STR, signing: SIGNING_VIEW
      })
    },
    revokeUserSigningCertificate: {
      '200': Kit.action({
        certificate: Kit.closed({
          slot: STR, label: STR, serialHex: STR, subject: STR, keyAlg: STR,
          notBefore: WHEN, notAfter: WHEN, thumbprint: STR, createdAt: WHEN,
          state: STR, revokedAt: WHEN, reason: NSTR, certificatePem: STR
        }),
        reason: STR, already: BOOL, why: STR,
        entry: Kit.closed({
          serialHex: STR, revokedAt: WHEN, reason: STR, reasonCode: NUM,
          reasonWhat: STR, subject: STR, note: STR
        }),
        user: STR, signing: SIGNING_VIEW
      })
    },
    enrolUserSelfIssuedSubject: {
      '200': personAction({ enrolled: SELF_ISSUED_SUBJECT })
    },
    removeUserSelfIssuedSubject: { '200': personAction({ removed: STR }) },
    setUserPreferredSelfIssuedSubject: {
      '200': personAction({ preferred: NSTR })
    },
    deactivateUserPublishedDid: { '200': personAction({ deactivated: STR }) },
    recordUserVerification: {
      '200': personAction({ verification: VERIFICATION_RECORD })
    },
    removeUserVerification: { '200': personAction({ removed: STR }) },
    disableUserAccount: { '200': ACCOUNT_STATE },
    enableUserAccount: { '200': ACCOUNT_STATE },
    linkUserFederation: { '200': FEDERATION_LINK },
    unlinkUserFederation: { '200': FEDERATION_LINK },
    createUserAppPassword: {
      '200': personAction(Object.assign({ appPassword: STR }, APP_PASSWORD))
    },
    revokeUserAppPassword: {
      '200': personAction({ revoked: Kit.closed(APP_PASSWORD) })
    },
    beginUserPasskeyUpgrade: {
      '200': Kit.action({
        reason: STR, upgradeId: STR,
        ceremony: Kit.closed({
          challenge: STR, rpId: STR, allow: STR,
          options: Kit.closed({ userVerification: STR })
        })
      })
    },
    proveUserPasskeyUpgrade: {
      '200': Kit.action({
        reason: STR,
        ceremony: Kit.closed({
          challenge: STR, rpId: STR, user: CEREMONY_USER, exclude: STRS,
          options: CREATION_OPTIONS
        })
      })
    },
    finishUserPasskeyUpgrade: {
      '200': Kit.action({
        reason: STR, credentialId: STR, mode: STR, previousAlgorithm: STR,
        algorithm: STR, lane: STR
      })
    },
    cancelUserPasskeyUpgrade: { '200': Kit.action() },
    clearUserSecurityKey: { '200': FACTOR_CLEARED },
    renameUserPasskey: { '200': Kit.action({ label: STR }) },
    beginUserPasskeyEnrolment: {
      '200': personAction({
        enrolmentId: STR, lane: STR, kind: STR, expiresAt: WHEN,
        ceremony: Kit.closed({
          challenge: STR, rpId: STR, user: CEREMONY_USER, exclude: STRS,
          options: CREATION_OPTIONS
        })
      })
    },
    finishUserPasskeyEnrolment: {
      '200': personAction({
        lane: STR, credentialId: STR, held: NUM,
        enrolledBy: Kit.nullable(ENROLLED_BY)
      })
    },

    getSessions: read(schemaRef('SessionList')),
    revokeSession: { '200': LOGOUT_ACTION },
    getLiveSessions: read(LOGOUT_VIEW),
    globalLogout: { '200': LOGOUT_ACTION },
    endLiveSessions: { '200': LOGOUT_ACTION },
    retryBackchannelDelivery: {
      '200': Kit.action({ delivery: Kit.withoutCodes(DELIVERY) })
    },
    restoreLoggedOutToken: { '200': Kit.action({ jti: STR }) },
    clearKerberosSignOut: { '200': Kit.action() },

    getGroups: read(Kit.oneOf(schemaRef('GroupList'), schemaRef('GroupDetail'),
                              GROUPS_ABSENT, GROUP_MISSING, GROUP_FOR_OWNER)),
    createGroup: {
      '200': Kit.action({
        reason: STR, dn: STR, group: STR, members: STRS, dangling: STRS,
        entry: ENTRY, existing: Kit.closed({ dn: STR, origin: STR })
      })
    },
    addGroupMember: {
      '200': Kit.action({
        reason: STR, changed: BOOL, dn: STR, member: STR, present: BOOL,
        attribute: STR, memberCount: NUM, entry: ENTRY
      })
    },
    setGroupMail: {
      '200': Kit.action({
        reason: STR, changed: BOOL, dn: STR, mail: STR, entry: ENTRY
      })
    },
    setGroupPolicy: {
      '200': Kit.action({
        reason: STR, changed: BOOL, dn: STR, attribute: STR, value: STR
      })
    },
    addGroupOwner: { '200': GROUP_OWNERS },
    removeGroupOwner: { '200': GROUP_OWNERS },

    getAdminRoles: read(ADMIN_ROLES),
    grantAdminRole: {
      '200': personAction({
        changed: BOOL, role: STR, member: STR, created: BOOL, resolves: BOOL,
        entry: ENTRY, dn: STR
      })
    },
    revokeAdminRole: {
      '200': personAction({
        changed: BOOL, role: STR, dn: STR, removed: NUM
      })
    },

    getMultiFactor: read(MFA_ROSTER),
    clearAuthenticatorApp: { '200': FACTOR_CLEARED },
    clearSecurityKey: { '200': FACTOR_CLEARED },
    clearEmailFactor: {
      '200': Kit.action({ removed: BOOL, sessionsEnded: NUM })
    },
    getTotpSettings: read(MECHANISM_PAGE(TOTP_REPORT)),
    getBackupCodesSettings: read(MECHANISM_PAGE(BACKUP_REPORT)),
    getWebauthnSettings: read(MECHANISM_PAGE(WEBAUTHN_REPORT)),

    getRoles: read(ROLES_VIEW),
    previewRoleIssuance: read(ROLE_PREVIEW),
    createRole: { '200': Kit.action({ name: STR }) },
    deleteRole: {
      '200': Kit.action({ name: STR, stillRequired: STRS })
    },
    describeRole: { '200': Kit.action({ name: STR }) },
    addRoleMember: { '200': ROLE_MEMBER },
    removeRoleMember: { '200': ROLE_MEMBER },
    addRolePermission: { '200': ROLE_PERMISSION },
    removeRolePermission: { '200': ROLE_PERMISSION },
    addRoleConferringClient: { '200': ROLE_CLIENT },
    removeRoleConferringClient: { '200': ROLE_CLIENT },
    addRoleOwner: { '200': ROLE_OWNERS },
    removeRoleOwner: { '200': ROLE_OWNERS },

    getOwnership: read(Kit.closed({
      found: BOOL, kind: STR, name: STR, dn: STR, owners: STRS,
      protected: BOOL, reasons: STRS, marked: BOOL
    })),
    setOwnerProtected: {
      '200': Kit.action({
        changed: BOOL, kind: STR, name: STR, ownerProtected: BOOL,
        // What a refusal from the module that owns the object may say.
        why: STR, reason: STR, account: Kit.nullable(SERVICE_ACCOUNT_FACTS)
      })
    }
  } as Record<string, Record<string, unknown>>
};
