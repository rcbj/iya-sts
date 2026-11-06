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
// **A POST ANSWERS IN `account-api/CLAUDE.md`'s MEMBERS** (*What an answer is*):
// `message`, `view`, `go`, `errors` with `ok: false`, `stepUp`, `location`,
// `files`. `ACT` below is that shape, with the view each operation draws.
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
  return Kit.closed(Object.assign({ ok: BOOL, errors: STRS, error: STR }, extra),
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
const PAGING: Json = Kit.closed({ page: INT, pages: INT, per: INT, total: INT });

// `AdminViews.pagingJson()`, which GNAP's and a few others' lists share with the
// console.
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

// `account_overview.ts`'s `signalsView()`: a Shared Signals event as it arrived.
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
  'An RFC 9635 section 8 access right as the client asked for it: a reference ' +
  'string, or an object whose members the client and the resource server ' +
  'define.'));

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
const LINK_CHECKED: Json = Kit.closed({ address: STR, username: STR, token: STR });

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

// `code` IS HERE BECAUSE `act()` CAN SEND IT, and reported on #1353 as a defect:
// `view()` answers `{ ok: false, code }` where the owner's document will not
// parse, and a refusal embeds that view whole.
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

//@@NEXT@@

export = { ERROR: ERROR, operations: operations };
