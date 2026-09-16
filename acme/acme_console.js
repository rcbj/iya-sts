// @ts-check
'use strict';
//
// File: acme_console.js
//
// ---------------------------------------------------------------------------
// WHAT THE TWO ACME CONSOLE PAGES AND THEIR MANAGEMENT API OPERATIONS READ AND
// DO — ONE MODEL, TWO DOORS (rule 7).
//
// `gnap/gnap_console.js`'s arrangement for this family: a VIEW computes the
// facts once and both doors render them, an ACTION changes state once and both
// doors report it. **No route, no `res`, no markup**, and a view reads nothing
// from the request but its query and the base URL it was reached at.
// `acme_admin.js` draws the markup and `acme_api.js` sends the JSON, both out
// of the SAME call.
//
//   GET  /admin/acme           acmeView()          Protocols -> ACME
//   GET  /admin/acme/monitor   acmeMonitorView()   Monitoring -> enrollments
//   POST /admin/acme           acmeAction()        the six actions below
//
// **EVERY ACTION VALIDATES ITS OWN BODY** with zod here rather than trusting
// the door that called it: the console posts a form and `/admin-api` posts JSON
// already held to an ajv schema, and a check made once in the shared layer is
// the one a third door would also get.
//
// **THE EAB KEY IS IN A REPLY EXACTLY ONCE.** `create-eab` answers the MAC key
// in the clear, because a client cannot be configured without it; the key is
// stored sealed on the entry and no view ever reads it back — `eabsInRealm()`
// carries no key material by construction.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const audit = require('../common/audit');
const mode = require('../common/mode');
const core = require('../common/cert_enrollment');
const monitor = require('../common/enrollment_monitor');
const validation = require('../common/validation');
const revocation = require('../common/pki_revocation');
const adminViews = require('../admin-core/admin_views');
const store = require('./acme_store');

const vz = validation.z;

const FAMILY = 'acme';

const ACME_ACTIONS = ['create-eab', 'delete-eab', 'deactivate-account',
                      'revoke-certificate', 'add-host-name',
                      'remove-host-name'];

const KIND = vz.enum(['person', 'application']);
const IDENTIFIER = vz.string().min(1).max(256)
  .regex(/^[^\u0000-\u001f\u007f]+$/);

const SCHEMAS = {
  'create-eab': vz.looseObject({
    kind: KIND,
    identifier: IDENTIFIER,
    lifetimeS: vz.union([vz.literal(''),
                         vz.coerce.number().int().min(60).max(31536000)])
      .optional()
  }),
  'delete-eab': vz.looseObject({ kid: vz.string().min(1).max(512) }),
  'deactivate-account': vz.looseObject({
    account: vz.string().regex(/^[A-Za-z0-9_-]{8,64}$/)
  }),
  'revoke-certificate': vz.looseObject({
    serial: vz.string().min(1).max(128).regex(/^[0-9A-Fa-f:]+$/),
    reason: vz.union([vz.literal(''), vz.enum(revocation.REASONS.map(
      function (one) { return one.id; }))]).optional()
  }),
  'add-host-name': vz.looseObject({ kind: KIND, identifier: IDENTIFIER,
                                    hostName: vz.string().min(1).max(253) }),
  'remove-host-name': vz.looseObject({ kind: KIND, identifier: IDENTIFIER,
                                       hostName: vz.string().min(1).max(253) })
};

function refused(code, sentence) {
  log.debug("Entering refused(). code=" + code);
  log.debug("Leaving refused().");
  return errorCodes.mark({ ok: false, errors: [String(sentence)] }, code);
}

// The core's refusal, handed on with its code and without its HTTP status (a
// console action answers the way `respondToAction()` decides).
function handedOn(refusal, fallback) {
  log.debug("Entering handedOn().");
  const out = { ok: false, errors: (refusal.errors || []).slice() };
  log.debug("Leaving handedOn().");
  return errorCodes.mark(out, errorCodes.codeOf(refusal) || fallback);
}

function acmeModule() {
  log.debug("Entering acmeModule().");
  // LAZY: `acme.js` requires `acme_admin.js`, which requires this file, so a
  // require at load would hand back the half-built exports of a module still
  // registering its routes. By the time a view runs, it has finished.
  log.debug("Leaving acmeModule().");
  return require('./acme');
}

function settingsJson() {
  log.debug("Entering settingsJson().");
  const group = config.groups().filter(function (one) {
    return one.group === 'ACME';
  })[0];
  log.debug("Leaving settingsJson().");
  return group ? group.settings : [];
}

function endpointsOf(req) {
  log.debug("Entering endpointsOf().");
  const urls = acmeModule().urlsFor(req);
  log.debug("Leaving endpointsOf().");
  return {
    directory: urls.directory,
    newNonce: urls.newNonce,
    newAccount: urls.newAccount,
    newOrder: urls.newOrder,
    account: urls.base + '/account/{id}',
    orders: urls.base + '/account/{id}/orders',
    order: urls.base + '/order/{id}',
    finalize: urls.base + '/order/{id}/finalize',
    authorization: urls.base + '/authz/{id}',
    challenge: urls.base + '/challenge/{id}',
    certificate: urls.base + '/cert/{id}',
    revokeCert: urls.revokeCert,
    keyChange: urls.keyChange,
    renewalInfo: urls.renewalInfo + '/{certID}'
  };
}

function authorityJson() {
  log.debug("Entering authorityJson().");
  const described = core.authorityOf(FAMILY);
  if (!described) {
    log.debug("Leaving authorityJson(). None.");
    return { present: false,
             note: 'This realm has no ACME Issuing CA yet. Build the ' +
                   'hierarchy on /admin/pki; a branch built before the ' +
                   'enrollment use cases existed is topped up with one on ' +
                   'the first issuance.' };
  }
  log.debug("Leaving authorityJson().");
  return {
    present: true,
    subject: described.subject,
    serialHex: described.serialHex,
    keyAlg: described.keyAlg,
    signatureAlg: described.signatureAlg,
    notBefore: described.notBefore,
    notAfter: described.notAfter,
    thumbprint: described.thumbprint,
    intermediate: described.intermediate ? described.intermediate.subject
                                         : null,
    root: described.root ? described.root.subject : null
  };
}

function profilesJson() {
  log.debug("Entering profilesJson().");
  const allowed = core.allowedProfiles(FAMILY);
  const dflt = core.defaultProfile(FAMILY);
  const descriptions = acmeModule().PROFILE_DESCRIPTIONS;
  log.debug("Leaving profilesJson().");
  return core.PROFILE_IDS.map(function (id) {
    return { id: id, description: descriptions[id] || '',
             needs: core.PROFILE_NEEDS[id] || null,
             allowed: allowed.indexOf(id) >= 0, isDefault: id === dflt };
  });
}

function modeJson() {
  log.debug("Entering modeJson().");
  /** @type {any} */
  const row = mode.REQUIREMENTS.filter(function (one) {
    return one.id === 'certificate-enrollment';
  })[0] || {};
  log.debug("Leaving modeJson().");
  return { current: mode.current(), what: row.what || '',
           development: row.development || '', product: row.product || '',
           inForce: mode.isProduct() ? row.product || '' :
                                       row.development || '' };
}

function paged(query, rows, name, noun) {
  log.debug("Entering paged(). name=" + name);
  const paging = adminViews.pagingOf(query, rows.length,
                                     { name: name, noun: noun });
  log.debug("Leaving paged().");
  return { paging: adminViews.pagingJson(paging),
           rows: rows.slice(paging.offset, paging.offset + paging.perPage) };
}

function certificateRow(one) {
  log.debug("Entering certificateRow().");
  const held = store.certificateBySerial(one.serialHex);
  log.debug("Leaving certificateRow().");
  return {
    serialHex: one.serialHex,
    profile: one.profile,
    subject: one.subject,
    names: one.names || [],
    entry: one.entry,
    entryUri: one.entryUri,
    status: one.status,
    keyAlg: one.keyAlg || '',
    notBefore: one.notBefore,
    notAfter: one.notAfter,
    issuedAt: one.issuedAt,
    revoked: one.revoked || null,
    account: held ? held.accountId : null
  };
}

function accountRow(account) {
  log.debug("Entering accountRow().");
  log.debug("Leaving accountRow().");
  return {
    id: account.id,
    status: account.status,
    entry: account.entry,
    entryUri: account.entry ? core.entryUri(account.entry) : null,
    eabKid: account.eabKid || null,
    thumbprint: account.thumbprint,
    contact: account.contact || [],
    orders: (account.orderIds || []).length,
    createdAt: account.createdAt,
    deactivatedAt: account.deactivatedAt || null
  };
}

// ---------------------------------------------------------------------------
// GET /admin/acme — what the ACME server IS in this realm.
// ---------------------------------------------------------------------------
function acmeView(req) {
  log.debug("Entering acmeView().");
  const query = (req && req.query) || {};
  const eabs = core.eabsInRealm().map(function (one) {
    const bound = one.boundAccount
      ? store.accountByThumbprint(one.boundAccount) : null;
    return { kid: one.kid, entry: one.entry, entryUri: one.entryUri,
             status: one.status, createdAt: one.createdAt,
             expiresAt: one.expiresAt, createdBy: one.createdBy || '',
             boundAt: one.boundAt || null,
             boundAccount: bound ? bound.id : null };
  });
  const json = {
    page: '/admin/acme',
    title: 'ACME',
    enabled: config.value('acme.enabled') !== false,
    specifications: ['RFC 8555', 'RFC 9773', 'RFC 8738', 'RFC 8823',
                     'draft-ietf-acme-profiles',
                     'draft-ietf-acme-device-attest'],
    directory: endpointsOf(req).directory,
    endpoints: endpointsOf(req),
    challengeType: acmeModule().CHALLENGE_TYPE,
    identifierTypes: acmeModule().IDENTIFIER_TYPES,
    authority: authorityJson(),
    profiles: profilesJson(),
    refusedProfiles: core.REFUSED_PROFILES,
    mode: modeJson(),
    eabLifetimeS: Number(config.value('acme.eabLifetimeS')),
    eabKeys: paged(query, eabs, 'credentials', 'EAB keys'),
    accounts: paged(query, store.listAccounts().map(accountRow), 'accounts',
                    'accounts'),
    certificates: paged(query, core.certificatesInRealm(FAMILY)
                          .map(certificateRow), 'certificates',
                        'certificates'),
    hostNames: paged(query, core.hostNamesInRealm(), 'hostNames', 'entries'),
    revocationReasons: revocation.REASONS.map(function (one) {
      return one.id;
    }),
    actions: ACME_ACTIONS,
    settings: settingsJson()
  };
  log.debug("Leaving acmeView().");
  return json;
}

// ---------------------------------------------------------------------------
// GET /admin/acme/monitor — what the ACME server has DONE in this realm.
// ---------------------------------------------------------------------------
function table(counts) {
  log.debug("Entering table().");
  log.debug("Leaving table().");
  return Object.keys(counts || {}).map(function (name) {
    return { name: name, count: Number(counts[name]) };
  }).sort(function (a, b) {
    return b.count - a.count || a.name.localeCompare(b.name);
  });
}

function acmeMonitorView(req) {
  log.debug("Entering acmeMonitorView().");
  const query = (req && req.query) || {};
  const snap = monitor.snapshot(FAMILY) || {};
  const recent = paged(query, snap.recent || [], '', 'requests');
  const json = {
    page: '/admin/acme/monitor',
    title: 'ACME enrollments',
    since: snap.startedAt,
    realm: snap.realm,
    processes: snap.processes,
    totals: { requests: snap.requests || 0, issued: snap.issued || 0,
              refused: snap.refused || 0, revoked: snap.revoked || 0,
              accountsBound: snap.credentialsRedeemed || 0,
              accounts: store.listAccounts().length,
              certificatesHeld: core.certificatesInRealm(FAMILY).length },
    operations: table(snap.operations),
    profiles: table(snap.profiles),
    principals: table(snap.principals),
    errorCodes: table(snap.codes),
    statuses: table(snap.statuses),
    lastAt: snap.lastAt || null,
    paging: recent.paging,
    recent: recent.rows
  };
  log.debug("Leaving acmeMonitorView().");
  return json;
}

// ---------------------------------------------------------------------------
// POST /admin/acme — the six things an operator does by hand.
// ---------------------------------------------------------------------------
function entryOf(value) {
  log.debug("Entering entryOf().");
  log.debug("Leaving entryOf().");
  return { kind: value.kind, id: String(value.identifier) };
}

function certbotLine(directory, kid, hmacKey) {
  log.debug("Entering certbotLine().");
  log.debug("Leaving certbotLine().");
  return 'certbot register --server ' + directory + ' --eab-kid ' + kid +
         ' --eab-hmac-key ' + hmacKey + ' --agree-tos --no-eff-email ' +
         '--register-unsafely-without-email';
}

async function acmeAction(body, context) {
  log.debug("Entering acmeAction(). action=" + (body && body.action));
  const ctx = context || {};
  const action = String((body && body.action) || '');
  const actor = String(ctx.actor || (ctx.via === 'api' ? 'admin-api' : ''));
  if (ACME_ACTIONS.indexOf(action) < 0) {
    log.debug("Leaving acmeAction(). Unknown action.");
    return refused('STS-ACME-0090', 'Unknown action "' +
                   action.slice(0, 60) + '". The six are: ' +
                   ACME_ACTIONS.join(', ') + '.');
  }
  const parsed = SCHEMAS[action].safeParse(body || {});
  if (!parsed.success) {
    const issue = (parsed.error.issues || [])[0] || {};
    log.debug("Leaving acmeAction(). Malformed body.");
    return refused('STS-ACME-0091', 'The ' + action + ' request is not ' +
                   'acceptable: "' + (issue.path || []).join('.') + '" ' +
                   String(issue.message || 'is invalid') + '.');
  }
  const value = parsed.data;
  let result = null;
  if (action === 'create-eab') {
    const created = core.createEab({ target: entryOf(value),
                                     createdBy: actor,
                                     lifetimeS: value.lifetimeS === ''
                                       ? undefined : value.lifetimeS });
    if (!created.ok) {
      log.debug("Leaving acmeAction(). EAB refused.");
      return handedOn(created, 'STS-ACME-0094');
    }
    const directory = ctx.req ? endpointsOf(ctx.req).directory : '';
    monitor.record(FAMILY, { operation: 'create-eab', outcome: 'credential',
                             status: 200, principal: actor,
                             target: core.entryUri(created.target) });
    result = {
      ok: true,
      kid: created.kid,
      hmacKey: created.hmacKey,
      alg: created.alg,
      expiresAt: created.expiresAt,
      target: created.target,
      targetUri: core.entryUri(created.target),
      directory: directory,
      certbot: certbotLine(directory, created.kid, created.hmacKey),
      message: 'An External Account Binding key was created for the ' +
               core.entryLabel(created.target) + '. The HMAC key is shown ' +
               'once and cannot be read back.'
    };
  } else if (action === 'delete-eab') {
    const deleted = core.deleteEab(value.kid, actor);
    if (!deleted.ok) {
      log.debug("Leaving acmeAction(). No such EAB key.");
      return handedOn(deleted, 'STS-ACME-0094');
    }
    result = { ok: true, kid: deleted.kid,
               message: 'The External Account Binding key ' + deleted.kid +
                        ' is deleted. An account it already bound keeps ' +
                        'its binding.' };
  } else if (action === 'deactivate-account') {
    const account = store.getAccount(value.account);
    if (!account) {
      log.debug("Leaving acmeAction(). No such account.");
      return refused('STS-ACME-0092', 'There is no ACME account "' +
                     value.account + '" in this realm.');
    }
    const already = account.status !== 'valid';
    if (!already) {
      account.status = 'deactivated';
      account.deactivatedAt = new Date().toISOString();
      store.saveAccount(account);
      audit.record({
        category: 'configuration',
        action: 'enrollment.acme.account.deactivate',
        protocol: 'ACME', outcome: 'success', actor: actor,
        target: account.entry ? core.entryUri(account.entry) : '',
        summary: 'an administrator deactivated an ACME account',
        detail: { account: account.id, via: ctx.via || '' }
      });
    }
    result = { ok: true, account: accountRow(account),
               message: already ? 'The account was already ' +
                                  account.status + '; nothing changed.'
                                : 'The ACME account ' + account.id + ' is ' +
                                  'deactivated and authorizes nothing more.' };
  } else if (action === 'revoke-certificate') {
    const found = core.findEnrolled(value.serial, FAMILY);
    if (!found) {
      log.debug("Leaving acmeAction(). No such certificate.");
      return refused('STS-ACME-0093', 'No certificate with serial ' +
                     value.serial + ' was issued over ACME in this realm.');
    }
    if (found.record.revoked) {
      log.debug("Leaving acmeAction(). Already revoked.");
      return refused('STS-ACME-0096', 'That certificate is already revoked.');
    }
    const done = await core.revokeEnrolled(found.record.serialHex,
                                           value.reason || 'unspecified',
                                           actor, { family: FAMILY });
    if (!done.ok) {
      log.debug("Leaving acmeAction(). The CA refused.");
      return handedOn(done, 'STS-ACME-0065');
    }
    monitor.record(FAMILY, { operation: 'revoke-certificate',
                             outcome: 'revoked', status: 200,
                             principal: actor,
                             target: core.entryUri(done.entry),
                             serialHex: done.serialHex });
    result = { ok: true, serialHex: done.serialHex, reason: done.reason,
               message: 'The certificate ' + done.serialHex + ' is revoked (' +
                        done.reason + ') and on the ACME Issuing CA\'s CRL.' };
  } else {
    const add = action === 'add-host-name';
    const changed = add
      ? core.addHostName(entryOf(value), value.hostName, actor)
      : core.removeHostName(entryOf(value), value.hostName, actor);
    if (!changed.ok) {
      log.debug("Leaving acmeAction(). Host name refused.");
      return handedOn(changed, 'STS-ACME-0094');
    }
    result = { ok: true, hostNames: changed.hostNames,
               entryUri: core.entryUri(entryOf(value)),
               message: changed.unchanged
                 ? 'That host name was already registered.'
                 : 'The host names of ' + core.entryUri(entryOf(value)) +
                   ' are now: ' + (changed.hostNames.join(', ') || 'none') +
                   '.' };
  }
  log.debug("Leaving acmeAction(). ok=" + result.ok);
  return result;
}

// The console session's username, which an action records as `createdBy` or
// `by`. Here rather than in `acme_admin.js` because the admin view layer may be
// required by this file and not by that one (tests/admin_actions_layer.js);
// it is not a view, and reads the session only to name the actor.
function consoleActorOf(req) {
  log.debug("Entering consoleActorOf().");
  let name = '';
  try {
    name = String(adminViews.gateStateFor(req).username || '');
  } catch (e) {
    log.debug("Caught in consoleActorOf(): " + ((e && e.message) || e));
    name = '';
  }
  log.debug("Leaving consoleActorOf().");
  return name;
}

module.exports = {
  ACME_ACTIONS: ACME_ACTIONS,
  consoleActorOf: consoleActorOf,
  acmeView: acmeView,
  acmeMonitorView: acmeMonitorView,
  acmeAction: acmeAction
};
