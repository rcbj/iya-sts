// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_response_models.ts
//
// ---------------------------------------------------------------------------
// WHAT `/account-api` ANSWERS, PER OPERATION AND STATUS (#1353), keyed by
// operationId. `common/response_model_kit.ts` says how a model is written;
// `tests/openapi_response_models.js` fails on an operation with none.
//
// THE ORDER IS `account_api.ts`'s `PROVIDERS`, so that a reader of one provider
// finds its models together, with its own views above them.
//
// **A POST ANSWERS IN `account-api/CLAUDE.md`'s MEMBERS** (*What an answer
// is*): `message`, `view`, `go`, `errors` with `ok: false`, `stepUp`,
// `location`, `files`. `act()` below is that shape, with the view each
// operation draws.
//
// **EVERY REFUSAL THAT CARRIES MORE THAN `{ ok, errors }` IS NAMED, STATUS BY
// STATUS.** `ctx.refuse(res, status, code, errors, extra)` answers
// `{ ok: false, errors, ...extra }`, and a status with no model takes `ERROR`,
// which has no `view`. So an operation whose refusal draws a page lists every
// status that refusal goes out on, and `answers()` keeps a 400 that has no
// extras from inheriting the 200's model (`Kit.applyModels` would otherwise).
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;
type Models = Record<string, Json>;

const STR = Kit.str();
const INT = Kit.int();
// A number where the source does not promise a whole one: a time read back out
// of a store, a duration out of a setting.
const NUM = Kit.num();
const BOOL = Kit.bool();
const STRS = Kit.listOf(STR);
const NSTR = Kit.nullable(STR);
const NNUM = Kit.nullable(NUM);
// A value a store hands back as it was written: an ISO instant in one register,
// milliseconds in another. `Date.now()` and `toISOString()` both occur.
const WHEN: Json = { type: ['string', 'number', 'null'] };

// A refusal, from the gate or from a handler.
const ERROR: Json = Kit.closed({
  ok: Kit.bool(),
  errors: Kit.listOf(Kit.str()),
  error: Kit.str(),
  error_description: Kit.str()
}, { description: 'A refusal or a failure, in English. No error code is ever ' +
                  'in it.' });

const operations: Record<string, Models> = {};

/**
 * What an action answers on success: the portal's members, all optional, plus
 * what `extra` names.
 *
 * @param extra - the operation's own members (a `view`, a count)
 * @returns the model
 */
function act(extra?: Json): Json {
  return Kit.closed(Object.assign({ ok: BOOL, message: STR, go: STR }, extra));
}

/**
 * A refusal carrying `extra` beside `{ ok: false, errors }`.
 *
 * @param extra - its other members
 * @returns the model
 */
function refusal(extra: Json): Json {
  return Kit.closed(Object.assign({ ok: BOOL, errors: STRS, error: STR },
                                  extra),
                    { required: ['ok', 'errors'] });
}

/**
 * An operation's models: the 200, and the 400 unless a refusal says otherwise.
 *
 * @param ok - the 200's model
 * @param refused - the statuses whose refusal differs from `ERROR`, by status
 * @returns the models by status
 */
function answers(ok: Json, refused?: Models): Models {
  return Object.assign({ '200': ok, '400': ERROR }, refused || {});
}

/**
 * The same refusal on each of several statuses.
 *
 * @param extra - its members beside `{ ok, errors }`
 * @param statuses - where it goes out
 * @returns the models by status
 */
function refusedOn(extra: Json, ...statuses: string[]): Models {
  const model = refusal(extra);
  const out: Models = {};
  statuses.forEach(function (status) {
    out[status] = model;
  });
  return out;
}

// ---------------------------------------------------------------------------
// WHAT MORE THAN ONE PROVIDER'S VIEW NAMES.
// ---------------------------------------------------------------------------

// `{ page, pages, per, total }`, this API's own paging; `shared` leaves `per`
// out.
const PAGING: Json = Kit.closed({
  page: INT, pages: INT, per: INT, total: INT
});

// `AdminViews.pagingJson()`, which GNAP's list shares with the console.
const ADMIN_PAGING: Json = Kit.closed({
  page: INT, pages: INT, perPage: INT, firstRow: INT, lastRow: INT, total: INT,
  param: NSTR, noun: NSTR
});

// `i18n.offered()`.
const OFFERED: Json = Kit.listOf(Kit.closed({ tag: STR, name: STR }));

// `Negotiated` in `common/i18n.ts`.
const NEGOTIATED: Json = Kit.closed({
  locale: STR, chain: STRS, catalog: STR,
  direction: Kit.strEnum(['ltr', 'rtl']), matched: BOOL
});

const VERSION_DATA: Json = Kit.closed({ version: STR, buildInfo: STR });

// `AccountApi.localeData()`.
const LOCALE_DATA: Json = Kit.closed({
  negotiated: NEGOTIATED,
  catalogs: Kit.mapOf(Kit.mapOf(STR, 'A translated message by its key.'),
                      'Each catalog along the chain, by language tag.'),
  offered: OFFERED
});

// A link's own page, refused: what `web_portal_runtime.ts` draws in place.
const REFUSED_VIEW: Json = Kit.closed({ refused: STR });

// `AccountApi`'s `getOpenApi`: closed at the top and free below it.
const OPENAPI_INNER: Json = Kit.freeForm(
  'The inside of an OpenAPI document (its paths and components): a statement ' +
  'about this API in OpenAPI\'s own vocabulary, whose every model is stated ' +
  'at the operation it describes.');

// ---------------------------------------------------------------------------
// `account_api.ts`'s own: the index, the document, who is signed in.
// ---------------------------------------------------------------------------
Object.assign(operations, {
  getIndex: answers(Kit.closed({
    api: STR, document: STR,
    operations: Kit.listOf(Kit.closed({
      method: STR, path: STR, operationId: STR, tag: STR, access: STR,
      mirrors: NSTR, summary: STR
    }))
  })),
  getOpenApi: answers(Kit.closed({
    openapi: STR,
    info: Kit.closed({ title: STR, version: STR, description: STR }),
    servers: Kit.listOf(Kit.closed({ url: STR })),
    tags: Kit.listOf(Kit.closed({ name: STR })),
    paths: OPENAPI_INNER,
    components: OPENAPI_INNER
  })),
  getMe: answers(Kit.closed({
    user: Kit.closed({ username: STR, sub: STR, name: STR, email: STR,
                       photo: STR }),
    realm: Kit.closed({ id: STR, prefix: STR }),
    client: STR, expiresAt: NNUM, mode: STR, locale: LOCALE_DATA,
    version: VERSION_DATA
  })),
  getAnnouncements: answers(Kit.closed({
    now: NUM, everyMs: NUM,
    announcements: Kit.listOf(Kit.closed({ id: STR, at: STR, message: STR }))
  })),
  getLocale: answers(Kit.closed({ locale: LOCALE_DATA, version: VERSION_DATA }))
});

// ---------------------------------------------------------------------------
// `portal/account_overview.ts`.
// ---------------------------------------------------------------------------
const PHOTO_VIEW: Json = Kit.closed({
  path: STR, origin: STR, selfService: BOOL,
  limits: Kit.closed({
    maxFileBytes: NUM, maxStoredBytes: NUM, minPixels: NUM, maxPixels: NUM,
    types: STRS
  })
});

// `inetorgperson.ts`'s `describe()`.
const DIRECTORY_VIEW: Json = Kit.closed({
  classes: Kit.listOf(Kit.closed({
    id: STR, name: STR, rfc: STR, oid: STR, what: STR,
    rows: Kit.listOf(Kit.closed({
      ldap: STR, label: STR, rfc: STR, note: STR, must: BOOL, secret: BOOL,
      binary: BOOL, present: BOOL, count: INT, values: STRS, bytes: INT
    })),
    held: INT, total: INT
  })),
  held: INT, total: INT
});

const OVERVIEW: Json = Kit.closed({
  username: STR, sub: STR,
  entry: Kit.nullable(Kit.closed({ dn: STR })),
  session: Kit.closed({ email: STR, name: STR }),
  signOn: Kit.closed({
    startedAt: NUM, authTime: NUM, authentications: NUM, amr: STRS, acr: STR,
    deviceBound: Kit.closed({ bound: BOOL, alg: STR, fact: STR, reasons: STRS })
  }),
  sessionEnds: NUM, timesSignedIn: NNUM,
  directory: Kit.nullable(DIRECTORY_VIEW),
  mechanisms: Kit.closed({
    password: BOOL, keys: INT, totp: BOOL, totpUsable: BOOL, mfaRequired: BOOL,
    secondFactor: STR,
    backupCodes: Kit.closed({ present: BOOL, usable: BOOL, remaining: NUM,
                              total: NUM })
  }),
  language: Kit.closed({ held: STR, offered: OFFERED }),
  customAttributes: Kit.listOf(Kit.closed({
    name: STR, label: STR, description: STR, syntax: STR, multi: BOOL,
    values: STRS, editable: BOOL
  })),
  photo: Kit.nullable(PHOTO_VIEW)
});

const APPLICATIONS: Json = Kit.closed({
  rows: Kit.listOf(Kit.closed({
    identifier: STR, name: STR, homePage: NSTR, launchable: STRS,
    description: STR, families: STRS, ways: STRS, withheld: STRS,
    launches: Kit.listOf(Kit.closed({ protocol: STR, label: STR, url: STR }))
  })),
  page: INT, pages: INT, refused: INT, notSignIn: INT, scanned: INT, total: INT,
  truncated: BOOL, limit: NUM
});

// `account_overview.ts`'s `signalsView()`: a Shared Signals event as it came.
const SECURITY_ACTIVITY: Json = Kit.closed({
  incomplete: BOOL,
  rows: Kit.listOf(Kit.closed({
    at: WHEN, name: STR, vocabulary: STR, type: STR,
    payload: Kit.freeForm('The event\'s payload as a transmitter signed it: ' +
                          'CAEP and RISC events carry members by event type, ' +
                          'and an unknown type is shown as it came.'),
    verified: BOOL, verificationNote: STR,
    reactions: Kit.listOf(Kit.closed({ failed: BOOL, skipped: STR,
                                       observed: BOOL, ended: NUM }))
  })),
  page: INT, pages: INT,
  participation: Kit.nullable(Kit.closed({
    applies: BOOL, why: STR, state: STR, since: STR, hours: NUM, moves: STRS
  }))
});

Object.assign(operations, {
  getOverview: answers(OVERVIEW),
  setLanguage: answers(act()),
  setProfilePhoto: answers(act({ photo: STR })),
  removeProfilePhoto: answers(act({ photo: STR })),
  setCustomAttribute: answers(act()),
  getApplications: answers(APPLICATIONS),
  getSecurityActivity: answers(SECURITY_ACTIVITY),
  moveRiscParticipation: answers(act())
});

// ---------------------------------------------------------------------------
// `portal/portal_sign_ins.ts`.
// ---------------------------------------------------------------------------
const SIGN_INS: Json = Kit.closed({
  days: NUM, thisSession: STR, paging: PAGING,
  rows: Kit.listOf(Kit.closed({
    id: { type: ['string', 'number'] }, at: WHEN, city: STR, country: STR,
    asOrg: STR, addressPrefix: STR, uaFamily: STR, uaOs: STR, door: STR,
    application: STR, level: STR, feedback: STR
  }))
});

Object.assign(operations, {
  getSignIns: answers(SIGN_INS),
  answerSignIn: answers(act({ ended: BOOL, view: SIGN_INS }))
});

// ---------------------------------------------------------------------------
// `portal/portal_consents.ts`.
// ---------------------------------------------------------------------------
const CONSENT_GROUP: Json = Kit.closed({
  client: STR, name: STR,
  rows: Kit.listOf(Kit.closed({ scope: STR, at: STR }))
});

const CONSENTS: Json = Kit.closed({
  paging: PAGING, groups: Kit.listOf(CONSENT_GROUP),
  administrative: Kit.listOf(CONSENT_GROUP)
});

Object.assign(operations, {
  getConsents: answers(CONSENTS),
  withdrawConsent: answers(act(), refusedOn({ view: CONSENTS }, '400'))
});

// ---------------------------------------------------------------------------
// `portal/portal_gnap.ts`, over `gnap_console.ts`'s `personGrantsView()`.
// ---------------------------------------------------------------------------
const GNAP_RIGHTS: Json = Kit.listOf(Kit.freeForm(
  'An RFC 9635 section 8 access right as the client asked for it: a ' +
  'reference string, or an object whose members the client and the resource ' +
  'server define.'));

const GNAP_GRANTS: Json = Kit.closed({
  user: STR, total: INT,
  rows: Kit.listOf(Kit.closed({
    id: STR, state: STR, finalization: NSTR, client: NSTR, clientName: NSTR,
    authorizationServer: NSTR, createdAt: WHEN, updatedAt: WHEN,
    grantExpiresAt: WHEN, approvedBy: STR, rights: GNAP_RIGHTS,
    rightsAre: STR, subjectReleasedAt: WHEN, derivedFrom: NSTR,
    tokens: Kit.listOf(Kit.closed({
      jti: STR, label: NSTR, format: NSTR, issuedAt: WHEN, expiresAt: WHEN,
      state: STR, bearer: BOOL, access: GNAP_RIGHTS, revokedWhy: NSTR
    })),
    revocable: BOOL
  })),
  paging: ADMIN_PAGING,
  cells: Kit.closed({ multiCell: BOOL, cell: STR, complete: BOOL, note: STR })
});

Object.assign(operations, {
  getGnapGrants: answers(GNAP_GRANTS),
  revokeGnapGrant: answers(act(), refusedOn({ view: GNAP_GRANTS }, '400'))
});

// ---------------------------------------------------------------------------
// `portal/portal_mail.ts`.
// ---------------------------------------------------------------------------
const EMAIL_VIEW: Json = Kit.closed({
  address: STR, verified: BOOL, changing: STR, available: BOOL,
  categories: Kit.listOf(Kit.closed({
    id: STR, label: STR, what: STR, optional: BOOL, sent: BOOL
  })),
  sent: Kit.listOf(Kit.closed({
    queuedAt: WHEN, subject: NSTR, to: Kit.nullable(Kit.oneOrMany(STR)),
    state: NSTR
  })),
  sentPaging: PAGING
});

// A link checked, or spent.
const LINK_CHECKED: Json = Kit.closed({
  address: STR, username: STR, token: STR
});

const LINK_SPENT: Json = act({
  view: Kit.closed({ verified: BOOL, address: STR, username: STR })
});

const FORGOT_VIEW: Json = Kit.closed({
  threeFields: BOOL, note: STR, tooMany: STR, notOffered: STR
});

Object.assign(operations, {
  getEmail: answers(EMAIL_VIEW),
  postEmail: answers(act(), refusedOn({ view: EMAIL_VIEW }, '400', '429')),
  getEmailVerification: answers(LINK_CHECKED,
    refusedOn({ view: REFUSED_VIEW }, '400', '429')),
  verifyEmail: answers(LINK_SPENT,
    refusedOn({ view: REFUSED_VIEW }, '400', '429')),
  getForgotPassword: answers(FORGOT_VIEW,
    refusedOn({ view: FORGOT_VIEW }, '404')),
  requestPasswordReset: answers(act({ view: FORGOT_VIEW }),
    refusedOn({ view: FORGOT_VIEW }, '404', '429'))
});

// ---------------------------------------------------------------------------
// `portal/portal_pseudonyms.ts`.
// ---------------------------------------------------------------------------
const PSEUDONYMS_VIEW: Json = Kit.closed({
  pseudonyms: STRS, pending: NSTR, cap: NUM, available: BOOL
});

// `{ refused }` where the directory could not be asked at all.
const PSEUDONYMS_REFUSED: Json = Kit.closed({
  pseudonyms: STRS, pending: NSTR, cap: NUM, available: BOOL, refused: STR
});

Object.assign(operations, {
  getPseudonyms: answers(PSEUDONYMS_VIEW,
    refusedOn({ view: REFUSED_VIEW }, '503')),
  postPseudonyms: answers(act(),
    refusedOn({ view: PSEUDONYMS_REFUSED }, '400', '429', '503')),
  getPseudonymVerification: answers(LINK_CHECKED,
    refusedOn({ view: REFUSED_VIEW }, '400', '429', '503')),
  verifyPseudonym: answers(LINK_SPENT,
    refusedOn({ view: REFUSED_VIEW }, '400', '429', '503'))
});

// ---------------------------------------------------------------------------
// `portal/portal_owned.ts`.
// ---------------------------------------------------------------------------
const OWNED: Json = Kit.closed({
  kind: STR, paging: PAGING,
  rows: Kit.listOf(Kit.closed({
    name: STR, id: STR, dn: STR, detail: NSTR,
    via: Kit.nullable(Kit.closed({ you: BOOL, groups: STRS })), closed: BOOL
  }))
});

Object.assign(operations, {
  getOwnedRoles: answers(OWNED),
  getOwnedGroups: answers(OWNED),
  getOwnedServiceAccounts: answers(OWNED),
  getOwnedApplications: answers(OWNED)
});

// ---------------------------------------------------------------------------
// `portal/portal_shared.ts`, over `uma/uma_owner_policy.ts`.
// ---------------------------------------------------------------------------
const UMA_SHARE: Json = Kit.closed({
  id: STR, resourceId: STR, scopes: STRS,
  recipient: Kit.closed({ kind: STR, value: STR, claim: STR, label: STR }),
  expires: STR, acr: STR, askMe: BOOL
});

const UMA_PERMISSION: Json = Kit.closed({
  resource_id: STR, resource_scopes: STRS
});

const SHARED_PAGING: Json = Kit.closed({ page: INT, pages: INT, total: INT });

// `code` IS HERE BECAUSE `act()` CAN SEND IT, and reported on #1353 as a
// defect: `view()` answers `{ ok: false, code }` where the owner's document
// will not parse, and a refusal embeds that view whole.
const SHARED_VIEW: Json = Kit.closed({
  ok: BOOL, enabled: BOOL, code: STR,
  resources: Kit.listOf(Kit.closed({
    id: STR, name: STR, type: STR, resourceServer: STR, scopes: STRS,
    shares: Kit.listOf(UMA_SHARE)
  })),
  paging: SHARED_PAGING,
  custom: Kit.listOf(Kit.closed({ id: STR, description: STR, alfa: STR })),
  pending: Kit.listOf(Kit.closed({
    id: STR, client: STR, requestingParty: STR,
    permissions: Kit.listOf(UMA_PERMISSION), expiresAt: NUM
  })),
  alfaEditing: BOOL, alfa: STR, version: { type: ['string', 'number', 'null'] },
  recipients: STRS
});

const SHARED_WITH_ME: Json = Kit.closed({
  ok: BOOL, paging: SHARED_PAGING,
  rows: Kit.listOf(Kit.closed({
    resourceId: STR, name: STR, resourceServer: STR, owner: STR, scopes: STRS,
    client: STR, expiresAt: NUM
  }))
});

Object.assign(operations, {
  getShared: answers(SHARED_VIEW),
  actShared: answers(act({ view: SHARED_VIEW }),
    refusedOn({ view: SHARED_VIEW }, '400', '403', '500')),
  getSharedWithMe: answers(SHARED_WITH_ME)
});

// ---------------------------------------------------------------------------
// `portal/account_password.ts`.
// ---------------------------------------------------------------------------
const PASSWORD_VIEW: Json = Kit.closed({
  hasPassword: BOOL,
  rules: Kit.closed({ enforced: BOOL, rules: STRS })
});

Object.assign(operations, {
  getPassword: answers(PASSWORD_VIEW),
  changePassword: answers(act(),
    refusedOn({ view: PASSWORD_VIEW }, '400', '429'))
});

// ---------------------------------------------------------------------------
// `portal/account_keys.ts`.
// ---------------------------------------------------------------------------
const WEBAUTHN_CREATION_OPTIONS: Json = Kit.closed({
  rp: Kit.closed({ name: STR, id: STR }),
  algorithms: Kit.listOf(INT), attestation: STR, timeout: NUM,
  authenticatorSelection: Kit.closed({
    userVerification: STR, residentKey: STR, requireResidentKey: BOOL,
    authenticatorAttachment: STR
  }),
  credProps: BOOL, minPinLength: BOOL, hints: STRS
});

// `keyRow()`.
const KEY_ROW: Json = Kit.closed({
  credentialId: STR, group: STR, name: STR, provider: STR, enrolledAt: WHEN,
  lastUsedAt: WHEN, syncedRefused: BOOL, attestationRefused: STR,
  pinRefused: STR, postQuantumRefused: BOOL,
  backupEligible: Kit.nullable(BOOL), backupState: BOOL, transports: STRS,
  kind: STR, withoutUsername: STR,
  algorithm: Kit.closed({ text: STR, postQuantum: BOOL, insecure: BOOL }),
  lane: STR,
  // `credentials.ts`'s `keyUpgradeHistory()`.
  upgrade: Kit.nullable(Kit.closed({
    upgradedAt: NUM, mode: STR, previousAlgorithm: STR,
    previousCredentialId: STR, upgradedTo: STR
  })),
  possiblyReplaced: Kit.nullable(Kit.closed({ at: NUM })),
  attestation: Kit.nullable(Kit.closed({
    verified: BOOL, trusted: BOOL, model: STR, type: STR, androidStatus: STR,
    deviceSerial: STR
  })),
  aaguid: STR
});

const PENDING_ENROLMENT: Json = Kit.closed({
  id: STR, kind: STR, lane: STR, challenge: STR, rpId: STR, user: STR,
  userHandle: STR, display: STR, exclude: STRS,
  options: WEBAUTHN_CREATION_OPTIONS,
  fallback: Kit.closed({ asksPostQuantum: BOOL, classical: BOOL,
                         retrying: BOOL })
});

const KEYS_VIEW: Json = Kit.closed({
  password: BOOL, mfaRequired: BOOL, keys: Kit.listOf(KEY_ROW),
  enrol: Kit.closed({
    enabled: BOOL, count: INT, atCap: BOOL, allowed: BOOL, kinds: STRS,
    pending: Kit.nullable(PENDING_ENROLMENT), lanes: STRS
  }),
  signals: Kit.listOf(Kit.closed({
    lane: STR, rpId: STR, userId: STR, accepted: STRS, name: STR, display: STR
  }))
});

// `refused()` is the 400 and the 500; a browser that may retry classically is a
// 400 with no view, which `view` being optional covers.
Object.assign(operations, {
  getKeys: answers(KEYS_VIEW),
  enrolKey: answers(act(), refusedOn({ view: KEYS_VIEW }, '400', '500')),
  removeKey: answers(act({ sessionsEnded: INT }),
    refusedOn({ view: KEYS_VIEW }, '400')),
  renameKey: answers(act(), refusedOn({ view: KEYS_VIEW }, '400'))
});

// ---------------------------------------------------------------------------
// `portal/account_mfa.ts`.
// ---------------------------------------------------------------------------
const MFA_VIEW: Json = Kit.closed({
  username: STR, verifiesCredentials: BOOL,
  totp: Kit.closed({
    enrolled: BOOL, usable: BOOL,
    detail: Kit.nullable(Kit.closed({
      enrolledAt: WHEN, lastUsedAt: WHEN, algorithm: STR, digits: NUM,
      period: NUM
    })),
    offered: BOOL, digits: NNUM, period: NNUM
  }),
  doors: Kit.closed({ applies: BOOL, refused: STRS }),
  setup: Kit.nullable(Kit.closed({
    grouped: STR, issuer: STR, qr: STR, algorithm: STR, digits: NUM, period: NUM
  })),
  emailFactor: Kit.nullable(Kit.closed({
    allowed: Kit.closed({ code: BOOL, link: BOOL }), optedIn: STR, usable: BOOL,
    kind: STR, why: STR, offered: Kit.closed({ code: BOOL, link: BOOL }),
    verified: BOOL, masked: STR
  })),
  codes: Kit.closed({
    enabled: BOOL, count: NNUM, length: NNUM, advised: BOOL, present: BOOL,
    usable: BOOL, why: STR, remaining: NUM, total: NUM, generatedAt: WHEN,
    lastUsedAt: WHEN
  }),
  fresh: Kit.nullable(Kit.closed({
    handle: STR, replacing: BOOL, codes: STRS
  }))
});

Object.assign(operations, {
  getMfa: answers(MFA_VIEW),
  changeMfa: answers(act({ view: MFA_VIEW, sessionsEnded: INT }),
    refusedOn({ view: MFA_VIEW }, '400', '429'))
});

// ---------------------------------------------------------------------------
// `portal/account_signing_key.ts`.
// ---------------------------------------------------------------------------
// `{ name, mime, base64 }`: a file saved once, never on a URL (`files`).
const SAVED_FILE: Json = Kit.closed({ name: STR, mime: STR, base64: STR });

const SIGNING_KEYS_VIEW: Json = Kit.closed({
  username: STR, entry: BOOL, holdsAny: BOOL, offered: BOOL, issuable: BOOL,
  tokenEndpoint: STR, maxPerPerson: NUM, reasons: STRS,
  profiles: Kit.listOf(Kit.closed({
    id: STR, rfc: STR, grantType: STR, atCap: BOOL,
    held: Kit.closed({
      keys: Kit.listOf(Kit.closed({
        handle: STR, label: STR, source: STR, serialHex: STR, keyAlg: STR,
        notAfter: STR, expiresAt: STR, state: STR, reason: STR, revokedAt: STR,
        certificate: STR
      })),
      valid: INT, issuers: STRS
    })
  })),
  tls: Kit.closed({
    signIn: STR, trusted: BOOL, note: STR, maxPerPerson: NUM, keyAlgs: STRS,
    defaultKeyAlg: NSTR,
    held: Kit.listOf(Kit.closed({
      label: STR, serialHex: STR, keyAlg: STR, notAfter: STR, state: STR,
      reason: STR, revokedAt: STR
    }))
  }),
  // A TLS client certificate's (`kind`, `issued`) or a signing key's (the
  // rest); `files` on both.
  fresh: Kit.nullable(Kit.closed({
    kind: STR,
    issued: Kit.closed({ subject: STR, serialHex: STR, keyAlg: STR,
                         notAfter: STR }),
    purpose: STR, handle: STR, label: STR,
    files: Kit.closed({ key: SAVED_FILE, chain: SAVED_FILE }),
    kid: STR, thumbprint: STR, jwsAlg: STR, issuer: STR
  }))
});

Object.assign(operations, {
  getSigningKeys: answers(SIGNING_KEYS_VIEW),
  changeSigningKeys: answers(act({ view: SIGNING_KEYS_VIEW }),
    refusedOn({ view: SIGNING_KEYS_VIEW }, '400', '403', '429', '500'))
});

// ---------------------------------------------------------------------------
// `portal/portal_certificates.ts`, over `common/cert_enrollment.ts`.
// ---------------------------------------------------------------------------
// `publicRecord()`.
const ENROLLED: Json = Kit.closed({
  serialHex: STR, family: STR, profile: STR, subject: STR, names: STRS,
  thumbprint: STR, keyAlg: STR, notBefore: STR, notAfter: STR, issuedAt: STR,
  requestedBy: Kit.nullable(Kit.closed({ kind: STR, id: STR, admin: BOOL })),
  via: STR, keySource: STR, replaces: NSTR, certificatePem: STR,
  chainPem: STRS,
  revoked: Kit.closed({ at: STR, reason: STR, by: STR }),
  expired: BOOL, status: STR
});

// The statuses `core.refuse()` writes, each of which `made.status` can carry.
const CERTIFICATES_VIEW: Json = Kit.closed({
  name: STR, resolved: BOOL, reasons: STRS,
  familyLabels: Kit.mapOf(STR, 'Each enrollment family\'s label, by its id.'),
  urls: Kit.closed({ acmeDirectory: STR, scep: STR, est: STR }),
  // An ACME key's `hmacKey` or a SCEP `challenge`, shown once.
  fresh: Kit.closed({
    kind: STR, kid: STR, hmacKey: STR, challenge: STR, profile: STR,
    expiresAt: WHEN, scepUrl: STR, plainScepUrl: STR
  }),
  enrolled: Kit.listOf(ENROLLED), hostNames: STRS,
  acme: Kit.nullable(Kit.closed({
    keys: Kit.listOf(Kit.closed({
      kid: STR, createdAt: WHEN, expiresAt: WHEN, createdBy: NSTR,
      boundAccount: NSTR, boundAt: WHEN, status: STR
    }))
  })),
  est: Kit.nullable(Kit.closed({ profiles: STRS })),
  scep: Kit.nullable(Kit.closed({
    challenges: Kit.listOf(Kit.closed({
      id: STR, profile: NSTR, createdAt: WHEN, expiresAt: WHEN,
      createdBy: NSTR, usedAt: WHEN, status: STR
    })),
    profiles: STRS, defaultProfile: NSTR
  }))
});

Object.assign(operations, {
  getCertificates: answers(CERTIFICATES_VIEW),
  changeCertificates: answers(act({ view: CERTIFICATES_VIEW }),
    refusedOn({ view: CERTIFICATES_VIEW }, '400', '401', '403', '404', '409',
              '429', '500', '503'))
});

// ---------------------------------------------------------------------------
// `portal/portal_app_passwords.ts`.
// ---------------------------------------------------------------------------
const APP_PASSWORDS_VIEW: Json = Kit.closed({
  username: STR,
  doors: Kit.closed({ refused: STRS, secondFactor: BOOL, applies: BOOL }),
  doorTable: Kit.listOf(Kit.closed({ id: STR, label: STR, what: STR })),
  doorLabels: Kit.mapOf(STR, 'Each door\'s label, by its id.'),
  unreadable: BOOL,
  passwords: Kit.listOf(Kit.closed({
    id: STR, name: STR, doors: STRS, createdAt: WHEN, lastUsedAt: WHEN,
    lastUsedDoor: STR
  })),
  enabled: BOOL, maxName: NUM,
  fresh: Kit.closed({ id: STR, name: STR, doors: STRS, password: STR })
});

Object.assign(operations, {
  getAppPasswords: answers(APP_PASSWORDS_VIEW),
  changeAppPasswords: answers(act({ view: APP_PASSWORDS_VIEW }),
    refusedOn({ view: APP_PASSWORDS_VIEW }, '400', '404', '429'))
});

// ---------------------------------------------------------------------------
// `portal/portal_kerberos.ts`.
// ---------------------------------------------------------------------------
const KERBEROS_VIEW: Json = Kit.closed({
  kdc: BOOL, person: BOOL, principal: STR, productKdc: BOOL, disabled: BOOL,
  keys: Kit.nullable(Kit.closed({
    kvno: NNUM, current: BOOL, etypes: Kit.listOf(Kit.closed({ name: STR }))
  })),
  made: Kit.closed({
    principal: STR, kvno: NNUM, etypes: STRS, source: STR, keytab: STR,
    keytabFilename: STR
  })
});

Object.assign(operations, {
  getKerberos: answers(KERBEROS_VIEW),
  makeKeytab: answers(act({ view: KERBEROS_VIEW }),
    refusedOn({ view: KERBEROS_VIEW }, '400', '429'))
});

// ---------------------------------------------------------------------------
// `portal/portal_delegate.ts`.
// ---------------------------------------------------------------------------
const DELEGATE_VIEW: Json = Kit.closed({
  mayAct: STR, delegate: Kit.nullable(Kit.closed({ kind: STR })),
  notDelegated: BOOL
});

Object.assign(operations, {
  getDelegate: answers(DELEGATE_VIEW),
  setDelegate: answers(act(), refusedOn({ view: DELEGATE_VIEW }, '400')),
  findDelegateCandidates: answers(Kit.closed({
    query: STR,
    people: Kit.listOf(Kit.closed({ uid: STR, cn: STR, dn: STR }),
                       'At most ten.'),
    more: BOOL
  }))
});

// ---------------------------------------------------------------------------
// `portal/portal_self_issued.ts`, over `oid4vc/siop.ts` and `person_did.ts`.
// ---------------------------------------------------------------------------
// `person_did.ts`'s `list()`. A version's `authorizedBy` is one of the records
// its writers keep: the wallet's or the current key's proof, or a person's act.
const DID_AUTHORIZATION: Json = Kit.closed({
  kind: STR, subject: STR, keyThumbprint: STR, versionId: NUM, transaction: STR,
  at: STR, actor: STR
});

const PUBLISHED_DID: Json = Kit.closed({
  rid: STR, did: STR, custody: STR, documentUrl: STR, createdAt: WHEN, by: NSTR,
  state: STR,
  deactivated: Kit.nullable(Kit.closed({ at: STR, by: NSTR, reason: NSTR })),
  proof: STR, preferred: BOOL, currentVersion: NUM,
  pending: Kit.nullable(Kit.closed({ change: STR, expiresAt: STR })),
  versions: Kit.listOf(Kit.closed({
    versionId: NUM, created: WHEN, change: STR,
    keys: Kit.listOf(Kit.closed({ id: STR, kty: STR, crv: STR, alg: STR })),
    authorizedBy: Kit.listOf(DID_AUTHORIZATION)
  }))
});

const SELF_ISSUED_VIEW: Json = Kit.closed({
  enabled: BOOL,
  turnOn: Kit.nullable(Kit.closed({
    setting: STR, env: STR, administrator: BOOL, page: NSTR
  })),
  loginHint: STR, didClaim: BOOL,
  published: Kit.nullable(Kit.closed({
    enabled: BOOL, custody: STR, maxPerPerson: NUM, keyAlgorithm: STR,
    active: INT, canPublish: BOOL,
    dids: Kit.nullable(Kit.listOf(PUBLISHED_DID))
  })),
  subjects: Kit.listOf(Kit.closed({
    subject: STR, label: STR, enrolledAt: WHEN, by: STR, proof: STR,
    preferred: BOOL,
    location: Kit.nullable(Kit.closed({ kind: STR, value: STR })),
    didDocumentUrl: STR, didResolved: BOOL
  })),
  notice: STR,
  fresh: Kit.closed({
    kind: STR, rid: STR, did: STR, file: SAVED_FILE
  })
});

Object.assign(operations, {
  getSelfIssued: answers(SELF_ISSUED_VIEW),
  // A DID this realm hosts is deactivated through `didAct()`, whose answer
  // carries the page's `view`; any other subject answers the message alone.
  removeSelfIssued: answers(act({ view: SELF_ISSUED_VIEW }),
    refusedOn({ view: SELF_ISSUED_VIEW }, '400')),
  getSelfIssuedDidDocument: answers(Kit.closed({
    ok: BOOL, subject: STR,
    // Free-form takes null too, which `Kit.nullable()`'s `oneOf` would refuse
    // as matching both of its arms.
    document: Kit.freeForm(
      'A DID document as the DID\'s method resolved it (W3C DID Core), or ' +
      'null: its verification methods and services are the DID controller\'s ' +
      'to state.')
  })),
  actOnPublishedDid: answers(act({ view: SELF_ISSUED_VIEW }),
    refusedOn({ view: SELF_ISSUED_VIEW }, '400'))
});

// ---------------------------------------------------------------------------
// `portal/portal_wallet.ts`.
// ---------------------------------------------------------------------------
const CREDENTIAL_COPY: Json = Kit.closed({
  id: STR, position: INT, of: INT, issuedAt: STR, expiresAt: STR, status: STR,
  removable: BOOL, removedAt: STR, walletEvent: NSTR, walletEventAt: STR,
  keyThumbprint: NSTR, holderDid: NSTR,
  statusIndex: { type: ['string', 'number', 'null'] }
});

// `vc_offers.ts`'s `buildCredentialOffer()`: OpenID4VCI 1.0 section 4.1.1, with
// the one grant this service puts in it.
const CREDENTIAL_OFFER: Json = Kit.closed({
  credential_issuer: STR, credential_configuration_ids: STRS,
  grants: Kit.closed({
    'urn:ietf:params:oauth:grant-type:pre-authorized_code': Kit.closed({
      'pre-authorized_code': STR,
      tx_code: Kit.closed({ input_mode: STR, length: INT, description: STR })
    }),
    authorization_code: Kit.closed({ issuer_state: STR })
  })
});

const OFFER: Json = Kit.closed({
  configurationId: STR, signingAlg: STR, mode: STR,
  credentialOffer: CREDENTIAL_OFFER, txCode: NSTR, expiresAt: STR,
  byValue: Kit.closed({ offerUri: STR, walletUrl: STR }),
  byReference: Kit.nullable(Kit.closed({
    credentialOfferUri: STR, offerUri: STR, walletUrl: STR
  }))
});

const WALLET_VIEW: Json = Kit.closed({
  configurations: Kit.listOf(Kit.closed({
    id: STR, format: STR, name: STR, issuerDid: BOOL,
    signingAlgs: Kit.listOf(Kit.closed({ alg: STR, what: STR, spec: STR })),
    defaultSigningAlg: STR
  })),
  modes: STRS, lifetimeSeconds: NUM, wallet: NSTR, batchSize: NUM,
  issued: Kit.listOf(Kit.closed({
    id: STR, configurationId: NSTR, name: STR, format: NSTR, issuedAt: STR,
    expiresAt: STR, status: STR,
    counts: Kit.mapOf(INT, 'How many copies are in each status.'),
    removable: BOOL, removedAt: STR, walletEvent: NSTR, walletEventAt: STR,
    copies: Kit.listOf(CREDENTIAL_COPY)
  })),
  paging: PAGING,
  // Beside the list after a POST, so the code never reaches a URL.
  offer: OFFER
});

Object.assign(operations, {
  getOfferableCredentials: answers(WALLET_VIEW),
  createCredentialOffer: answers(act({ offer: OFFER, view: WALLET_VIEW }),
    refusedOn({ view: WALLET_VIEW }, '400', '403')),
  removeIssuedCredential: answers(
    act({ scope: STR, removed: INT, view: WALLET_VIEW }),
    refusedOn({ view: WALLET_VIEW }, '400'))
});

// ---------------------------------------------------------------------------
// `portal/portal_devices.ts`, over `common/devices.ts`.
// ---------------------------------------------------------------------------
const DEVICES_VIEW: Json = Kit.closed({
  devices: Kit.listOf(Kit.closed({
    id: STR, label: STR, applications: STRS, nativeSso: BOOL, sessionLive: BOOL,
    keys: Kit.listOf(Kit.closed({ kind: STR, level: STR })),
    attestation: STR, enrolment: STR, lastUsed: WHEN
  })),
  platforms: STRS,
  proof: Kit.nullable(Kit.closed({ challenge: STR, expiresAt: WHEN })),
  audience: STR, proofTyp: STR,
  linking: Kit.nullable(Kit.closed({
    challenge: STR, rpId: STR, user: STR, allow: STR,
    options: Kit.closed({
      rpId: STR, userVerification: STR, timeout: NUM, hints: STRS
    })
  })),
  link: Kit.closed({
    enrolled: INT,
    keys: Kit.listOf(Kit.closed({ credentialId: STR, name: STR,
                                  trusted: BOOL })),
    roaming: STRS
  }),
  remember: BOOL
});

// `attestation_revocation.ts`'s `verdictOf()`, on a downgraded key.
const ATTESTATION_VERDICT: Json = Kit.closed({
  status: STR, reason: STR, serial: STR, listVersion: STR, checkedAt: STR,
  chainSerials: STRS, why: STR
});

// `DeviceKey` in `common/devices.ts`, one value of `stsDeviceKey`.
const DEVICE_KEY: Json = Kit.closed({
  id: STR, kind: STR, thumbprint: STR, label: STR, added: STR, addedBy: STR,
  proof: STR,
  attestation: Kit.closed({
    level: STR, format: STR, summary: STR, verifiedAt: STR, chainSerials: STRS,
    revocation: ATTESTATION_VERDICT,
    freshness: Kit.closed({ status: STR, detail: STR })
  }),
  // By `kind`: an X.509 certificate's facts, a public JWK, or a passkey's name.
  material: Kit.closed({
    certificate: STR, subject: STR, issuer: STR, serial: STR, notAfter: STR,
    jwk: Kit.freeForm('A public JWK as the device presented it (RFC 7517): ' +
                      'its members depend on its key type.'),
    credentialId: STR, aaguid: STR, attachment: STR
  })
});

const DEVICE_CHANGE: Json = Kit.nullable(Kit.closed({
  status: STR, previous: STR, at: STR, source: STR, actor: STR, reason: STR
}));

const DEVICE_RISK_CHANGE: Json = Kit.nullable(Kit.closed({
  level: STR, previous: STR, at: STR, source: STR, actor: STR, reason: STR,
  beforeCompromise: STR
}));

// `Devices.view()`.
const DEVICE: Json = Kit.closed({
  id: STR, dn: STR, owner: STR, ownerKind: STR, label: STR, applications: STRS,
  keys: Kit.listOf(DEVICE_KEY), keyKinds: STRS,
  attestation: Kit.closed({
    level: STR, format: STR, summary: STR, keyId: STR
  }),
  compliance: STR, complianceChange: DEVICE_CHANGE, status: STR,
  statusChange: DEVICE_CHANGE, riskLevel: STR, riskChange: DEVICE_RISK_CHANGE,
  platform: STR, model: STR, os: STR,
  enrolment: Kit.closed({ method: STR, at: STR, actor: STR }), nativeSso: BOOL,
  rememberedBrowser: Kit.nullable(Kit.closed({
    generation: NUM, issuedAt: STR, browser: STR, secondFactorAt: STR
  })),
  sessionLive: BOOL, lastUsed: STR, created: STR
});

// A key proved: 201, which `operation.responses['200']` also has to name or the
// document would keep the builder's bare object there.
const DEVICE_PROVED: Json = Kit.closed({
  ok: BOOL, device: Kit.nullable(DEVICE), key: Kit.nullable(DEVICE_KEY)
});

Object.assign(operations, {
  getDevices: answers(DEVICES_VIEW),
  actOnDevices: answers(act(), refusedOn({ view: DEVICES_VIEW }, '400')),
  deviceChallenge: answers(Kit.closed({
    ok: BOOL, challenge: STR, audience: STR, typ: STR, expires_at: WHEN,
    proof_endpoint: STR
  })),
  deviceProof: answers(DEVICE_PROVED, { '201': DEVICE_PROVED })
});

// ---------------------------------------------------------------------------
// `portal/portal_ciba.ts`.
// ---------------------------------------------------------------------------
// What a sign-in again asks for. `maxAge` only where a connection wants a
// recent one (`portal_connected_accounts.ts`).
const STEP_UP: Json = Kit.closed({ acrValues: STR, prompt: STR, maxAge: NUM });

const SIGN_IN_REQUESTS_VIEW: Json = Kit.closed({
  enabled: BOOL,
  requests: Kit.listOf(Kit.closed({
    id: STR, clientName: NSTR, bindingMessage: STR,
    requestContext: Kit.nullable(Kit.listOf(Kit.closed({
      name: STR, value: STR
    }))),
    scope: NSTR, acrValues: STRS, expiresAt: WHEN
  })),
  hasCode: BOOL,
  gnap: Kit.listOf(Kit.closed({
    id: STR, display: NSTR, client: NSTR, declared: BOOL, requestedBy: STR,
    acr: STRS, subject: BOOL, expiresAt: WHEN,
    rights: Kit.listOf(Kit.closed({
      field: STR, limitsHtml: STR, reference: STR, type: STR, parts: STR
    }))
  })),
  // `?stepup=` and `?gnapstepup=` answer this alone.
  stepUp: STEP_UP
});

Object.assign(operations, {
  getSignInRequests: answers(SIGN_IN_REQUESTS_VIEW),
  answerSignInRequest: answers(act(),
    refusedOn({ stepUp: STEP_UP }, '403'))
});

// ---------------------------------------------------------------------------
// `portal/portal_access_requests.ts`, over `authzen_access_request.ts`.
// ---------------------------------------------------------------------------
const AUTHZEN_MEMBER: Json = Kit.freeForm(
  'An AuthZEN Authorization API 1.0 member as the PEP sent it: its ' +
  '`properties` and its context are the caller\'s to define.');

const ACCESS_REQUESTS_VIEW: Json = Kit.closed({
  enabled: BOOL,
  rows: Kit.listOf(Kit.closed({
    id: STR, status: STR, requester: NSTR,
    client: Kit.nullable(Kit.closed({ id: STR, name: STR })),
    application: NSTR, subject: AUTHZEN_MEMBER, action: AUTHZEN_MEMBER,
    resource: AUTHZEN_MEMBER, context: AUTHZEN_MEMBER, emergency: BOOL,
    justification: STR, createdAt: WHEN, expiresAt: WHEN, finishedAt: WHEN,
    decidedBy: STR,
    approval: Kit.nullable(Kit.closed({
      id: STR, approvedAt: WHEN, approvedUntil: WHEN, approver: NSTR,
      revoked: BOOL
    })),
    approvers: Kit.closed({ roles: STRS, groups: STRS, owners: BOOL })
  }))
});

Object.assign(operations, {
  getAccessRequests: answers(ACCESS_REQUESTS_VIEW),
  decideAccessRequest: answers(act(),
    refusedOn({ view: ACCESS_REQUESTS_VIEW }, '400'))
});

// ---------------------------------------------------------------------------
// `portal/portal_device.ts`.
// ---------------------------------------------------------------------------
const DEVICE_REQUEST_VIEW: Json = Kit.closed({
  enabled: BOOL, typed: STR,
  record: Kit.nullable(Kit.closed({
    userCode: STR, clientId: STR, clientName: STR, scope: STR, expiresAt: WHEN
  }))
});

Object.assign(operations, {
  getDeviceRequest: answers(DEVICE_REQUEST_VIEW,
    refusedOn({ view: DEVICE_REQUEST_VIEW }, '404', '429')),
  answerDeviceRequest: answers(act(),
    refusedOn({ view: DEVICE_REQUEST_VIEW }, '400', '429'))
});

// ---------------------------------------------------------------------------
// `portal/portal_claim_sources.ts`.
// ---------------------------------------------------------------------------
const CLAIM_SOURCES_VIEW: Json = Kit.closed({
  providers: Kit.listOf(Kit.closed({
    id: STR, name: NSTR, issuer: NSTR, claims: STRS, delivery: NSTR,
    link: Kit.nullable(Kit.closed({ linkedAt: WHEN, stale: BOOL }))
  })),
  paging: PAGING, linked: INT, notice: STR, problem: STR
});

Object.assign(operations, {
  getClaimSources: answers(CLAIM_SOURCES_VIEW),
  linkClaimSource: answers(act({ location: STR }),
    refusedOn({ view: CLAIM_SOURCES_VIEW }, '400'))
});

// ---------------------------------------------------------------------------
// `portal/portal_connected_accounts.ts`.
// ---------------------------------------------------------------------------
const CONNECTED_ACCOUNTS_VIEW: Json = Kit.closed({
  providers: Kit.listOf(Kit.closed({
    id: STR, name: NSTR, provider: NSTR, providerLabel: NSTR, connected: BOOL
  })),
  connected: INT, notice: STR, problem: STR
});

// `{ ok: false, stepUp }` IS A 200 here: the connection is not refused, the
// browser is sent to sign in again and comes back.
Object.assign(operations, {
  getConnectedAccounts: answers(CONNECTED_ACCOUNTS_VIEW),
  connectAccount: answers(act({ location: STR, stepUp: STEP_UP }),
    refusedOn({ view: CONNECTED_ACCOUNTS_VIEW }, '400', '403', '409'))
});

// ---------------------------------------------------------------------------
// `portal/account_activation.ts`: nobody is signed in, and the link's step
// decides which of these a view carries (`setupView()`, `keyView()`,
// `refusedView()`, `finish()`, `afterKey()`).
// ---------------------------------------------------------------------------
const PASSWORD_RULES: Json = Kit.closed({ enforced: BOOL, rules: STRS });

const ACTIVATION_VIEW: Json = Kit.closed({
  step: STR, user: STR, token: STR, base: STR, rules: PASSWORD_RULES,
  webauthnEnabled: BOOL, passkeyOffered: BOOL, passkeyAlone: BOOL, kinds: STRS,
  lanes: STRS, totpOffered: BOOL, title: STR, refused: STR, passkey: BOOL,
  secondStep: BOOL, wantsTotp: BOOL, pending: PENDING_ENROLMENT,
  enrolment: Kit.closed({
    grouped: STR, issuer: STR, qr: STR, algorithm: STR, digits: NUM, period: NUM
  }),
  warning: STR, password: BOOL, withTotp: BOOL, signIn: STR
});

Object.assign(operations, {
  getActivation: answers(ACTIVATION_VIEW,
    refusedOn({ view: ACTIVATION_VIEW }, '400', '429')),
  activate: answers(act({ view: ACTIVATION_VIEW }),
    refusedOn({ view: ACTIVATION_VIEW }, '400', '429'))
});

// ---------------------------------------------------------------------------
// `portal/account_reset.ts`.
// ---------------------------------------------------------------------------
const RESET_VIEW: Json = Kit.closed({
  username: STR, token: STR, base: STR, rules: PASSWORD_RULES, refused: STR,
  tooMany: BOOL, done: BOOL, signIn: STR
});

Object.assign(operations, {
  getPasswordReset: answers(RESET_VIEW,
    refusedOn({ view: RESET_VIEW }, '400', '403', '429')),
  spendPasswordReset: answers(act({ view: RESET_VIEW }),
    refusedOn({ view: RESET_VIEW }, '400', '403', '429', '500'))
});

export = { ERROR: ERROR, operations: operations };
