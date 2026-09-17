'use strict';
//
// File: acme_console.ts
//
// ---------------------------------------------------------------------------
// WHAT THE TWO ACME CONSOLE PAGES AND THEIR MANAGEMENT API OPERATIONS READ AND
// DO — ONE MODEL, TWO DOORS (rule 7).
//
// `gnap/gnap_console.ts`'s arrangement for this family: a VIEW computes the
// facts once and both doors render them, an ACTION changes state once and both
// doors report it. **No route, no `res`, no markup**, and a view reads nothing
// from the request but its query and the base URL it was reached at.
// `acme_admin.ts` draws the markup and `acme_api.ts` sends the JSON, both out
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

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AcmeConsole` takes the modules it uses through its constructor
// (`AcmeConsoleDeps`). Since #50's R2 the composition root builds the instance
// (`AcmeConsole.defaultDeps()`) and installs it; the module's old export names
// are FACADES that forward to it, for the JavaScript callers, and a process
// without the root builds a default when the module finishes loading.
// `AcmeConsole` is exported beside them for the composition root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import mode = require('../common/mode');
import core = require('../common/cert_enrollment');
import monitor = require('../common/enrollment_monitor');
import validation = require('../common/validation');
import revocation = require('../common/pki_revocation');
import adminViews = require('../admin-core/admin_views');
import store = require('./acme_store');
import InstanceSlot = require('../common/instance_slot');

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

// What `AcmeConsole` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface AcmeConsoleDeps {
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  mode: typeof mode;
  core: typeof core;
  monitor: typeof monitor;
  revocation: typeof revocation;
  adminViews: typeof adminViews;
  store: typeof store;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadAcme(): typeof import('./acme');
}

class AcmeConsole {
  constructor(private readonly deps: AcmeConsoleDeps) {
    deps.log.debug("Entering AcmeConsole.constructor().");
    deps.log.debug("Leaving AcmeConsole.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): AcmeConsoleDeps {
    log.debug("Entering AcmeConsole.defaultDeps().");
    log.debug("Leaving AcmeConsole.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      audit: audit,
      mode: mode,
      core: core,
      monitor: monitor,
      revocation: revocation,
      adminViews: adminViews,
      store: store,
      loadAcme: function () {
        return require('./acme');
      }
    };
  }

  refused(code, sentence) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AcmeConsole.refused(). code=" + code);
    log.debug("Leaving AcmeConsole.refused().");
    return errorCodes.mark({ ok: false, errors: [String(sentence)] }, code);
  }

  // The core's refusal, handed on with its code and without its HTTP status (a
  // console action answers the way `respondToAction()` decides).
  handedOn(refusal, fallback) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AcmeConsole.handedOn().");
    const out = { ok: false, errors: (refusal.errors || []).slice() };
    log.debug("Leaving AcmeConsole.handedOn().");
    return errorCodes.mark(out, errorCodes.codeOf(refusal) || fallback);
  }

  acmeModule() {
    const { log, loadAcme } = this.deps;
    log.debug("Entering AcmeConsole.acmeModule().");
    // LAZY: `acme.ts` requires `acme_admin.ts`, which requires this file, so a
    // require at load would hand back the half-built exports of a module still
    // registering its routes. By the time a view runs, it has finished.
    log.debug("Leaving AcmeConsole.acmeModule().");
    return loadAcme();
  }

  settingsJson() {
    const { log, config } = this.deps;
    log.debug("Entering AcmeConsole.settingsJson().");
    const group = config.groups().filter(function (one) {
      return one.group === 'ACME';
    })[0];
    log.debug("Leaving AcmeConsole.settingsJson().");
    return group ? group.settings : [];
  }

  endpointsOf(req) {
    const { log } = this.deps;
    log.debug("Entering AcmeConsole.endpointsOf().");
    const urls = this.acmeModule().urlsFor(req);
    log.debug("Leaving AcmeConsole.endpointsOf().");
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

  authorityJson() {
    const { log, core } = this.deps;
    log.debug("Entering AcmeConsole.authorityJson().");
    const described = core.authorityOf(FAMILY);
    if (!described) {
      log.debug("Leaving AcmeConsole.authorityJson(). None.");
      return { present: false,
               note: 'This realm has no ACME Issuing CA yet. Build the ' +
                     'hierarchy on /admin/pki; a branch built before the ' +
                     'enrollment use cases existed is topped up with one on ' +
                     'the first issuance.' };
    }
    log.debug("Leaving AcmeConsole.authorityJson().");
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

  profilesJson() {
    const { log, core } = this.deps;
    log.debug("Entering AcmeConsole.profilesJson().");
    const allowed = core.allowedProfiles(FAMILY);
    const dflt = core.defaultProfile(FAMILY);
    const descriptions = this.acmeModule().PROFILE_DESCRIPTIONS;
    log.debug("Leaving AcmeConsole.profilesJson().");
    return core.PROFILE_IDS.map(function (id) {
      return { id: id, description: descriptions[id] || '',
               needs: core.PROFILE_NEEDS[id] || null,
               allowed: allowed.indexOf(id) >= 0, isDefault: id === dflt };
    });
  }

  modeJson() {
    const { log, mode } = this.deps;
    log.debug("Entering AcmeConsole.modeJson().");
    const row: any = mode.REQUIREMENTS.filter(function (one) {
      return one.id === 'certificate-enrollment';
    })[0] || {};
    log.debug("Leaving AcmeConsole.modeJson().");
    return { current: mode.current(), what: row.what || '',
             development: row.development || '', product: row.product || '',
             inForce: mode.isProduct() ? row.product || '' :
                                         row.development || '' };
  }

  paged(query, rows, name, noun) {
    const { log, adminViews } = this.deps;
    log.debug("Entering AcmeConsole.paged(). name=" + name);
    const paging = adminViews.pagingOf(query, rows.length,
                                       { name: name, noun: noun });
    log.debug("Leaving AcmeConsole.paged().");
    return { paging: adminViews.pagingJson(paging),
             rows: rows.slice(paging.offset, paging.offset + paging.perPage) };
  }

  certificateRow(one) {
    const { log, store } = this.deps;
    log.debug("Entering AcmeConsole.certificateRow().");
    const held = store.certificateBySerial(one.serialHex);
    log.debug("Leaving AcmeConsole.certificateRow().");
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

  accountRow(account) {
    const { log, core } = this.deps;
    log.debug("Entering AcmeConsole.accountRow().");
    log.debug("Leaving AcmeConsole.accountRow().");
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
  acmeView(req) {
    const { log, core, store, config, revocation } = this.deps;
    log.debug("Entering AcmeConsole.acmeView().");
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
      directory: this.endpointsOf(req).directory,
      endpoints: this.endpointsOf(req),
      challengeType: this.acmeModule().CHALLENGE_TYPE,
      identifierTypes: this.acmeModule().IDENTIFIER_TYPES,
      authority: this.authorityJson(),
      profiles: this.profilesJson(),
      refusedProfiles: core.REFUSED_PROFILES,
      mode: this.modeJson(),
      eabLifetimeS: Number(config.value('acme.eabLifetimeS')),
      eabKeys: this.paged(query, eabs, 'credentials', 'EAB keys'),
      accounts: this.paged(query,
                           store.listAccounts().map(this.accountRow.bind(this)),
                           'accounts',
                           'accounts'),
      certificates: this.paged(query, core.certificatesInRealm(FAMILY)
                                 .map(this.certificateRow.bind(this)),
                                 'certificates',
                               'certificates'),
      hostNames: this.paged(query, core.hostNamesInRealm(), 'hostNames',
                            'entries'),
      revocationReasons: revocation.REASONS.map(function (one) {
        return one.id;
      }),
      actions: ACME_ACTIONS,
      settings: this.settingsJson()
    };
    log.debug("Leaving AcmeConsole.acmeView().");
    return json;
  }

  // ---------------------------------------------------------------------------
  // GET /admin/acme/monitor — what the ACME server has DONE in this realm.
  // ---------------------------------------------------------------------------
  table(counts) {
    const { log } = this.deps;
    log.debug("Entering AcmeConsole.table().");
    log.debug("Leaving AcmeConsole.table().");
    return Object.keys(counts || {}).map(function (name) {
      return { name: name, count: Number(counts[name]) };
    }).sort(function (a, b) {
      return b.count - a.count || a.name.localeCompare(b.name);
    });
  }

  acmeMonitorView(req) {
    const { log, monitor, store, core } = this.deps;
    log.debug("Entering AcmeConsole.acmeMonitorView().");
    const query = (req && req.query) || {};
    const snap = monitor.snapshot(FAMILY) || {};
    const recent = this.paged(query, snap.recent || [], '', 'requests');
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
      operations: this.table(snap.operations),
      profiles: this.table(snap.profiles),
      principals: this.table(snap.principals),
      errorCodes: this.table(snap.codes),
      statuses: this.table(snap.statuses),
      lastAt: snap.lastAt || null,
      paging: recent.paging,
      recent: recent.rows
    };
    log.debug("Leaving AcmeConsole.acmeMonitorView().");
    return json;
  }

  // ---------------------------------------------------------------------------
  // POST /admin/acme — the six things an operator does by hand.
  // ---------------------------------------------------------------------------
  entryOf(value) {
    const { log } = this.deps;
    log.debug("Entering AcmeConsole.entryOf().");
    log.debug("Leaving AcmeConsole.entryOf().");
    return { kind: value.kind, id: String(value.identifier) };
  }

  certbotLine(directory, kid, hmacKey) {
    const { log } = this.deps;
    log.debug("Entering AcmeConsole.certbotLine().");
    log.debug("Leaving AcmeConsole.certbotLine().");
    return 'certbot register --server ' + directory + ' --eab-kid ' + kid +
           ' --eab-hmac-key ' + hmacKey + ' --agree-tos --no-eff-email ' +
           '--register-unsafely-without-email';
  }

  async acmeAction(body, context) {
    const { log, core, monitor, store, audit } = this.deps;
    log.debug("Entering AcmeConsole.acmeAction(). action=" +
              (body && body.action));
    const ctx = context || {};
    const action = String((body && body.action) || '');
    const actor = String(ctx.actor || (ctx.via === 'api' ? 'admin-api' : ''));
    if (ACME_ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving AcmeConsole.acmeAction(). Unknown action.");
      return this.refused('STS-ACME-0090', 'Unknown action "' +
                          action.slice(0, 60) + '". The six are: ' +
                          ACME_ACTIONS.join(', ') + '.');
    }
    const parsed = SCHEMAS[action].safeParse(body || {});
    if (!parsed.success) {
      const issue = (parsed.error.issues || [])[0] || {};
      log.debug("Leaving AcmeConsole.acmeAction(). Malformed body.");
      return this.refused('STS-ACME-0091',
                          'The ' + action + ' request is not ' +
                          'acceptable: "' + (issue.path || []).join('.') +
                          '" ' +
                          String(issue.message || 'is invalid') + '.');
    }
    const value = parsed.data;
    let result = null;
    if (action === 'create-eab') {
      const created = core.createEab({ target: this.entryOf(value),
                                       createdBy: actor,
                                       lifetimeS: value.lifetimeS === ''
                                         ? undefined : value.lifetimeS });
      if (!created.ok) {
        log.debug("Leaving AcmeConsole.acmeAction(). EAB refused.");
        return this.handedOn(created, 'STS-ACME-0094');
      }
      const directory = ctx.req ? this.endpointsOf(ctx.req).directory : '';
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
        certbot: this.certbotLine(directory, created.kid, created.hmacKey),
        message: 'An External Account Binding key was created for the ' +
                 core.entryLabel(created.target) + '. The HMAC key is shown ' +
                 'once and cannot be read back.'
      };
    } else if (action === 'delete-eab') {
      const deleted = core.deleteEab(value.kid, actor);
      if (!deleted.ok) {
        log.debug("Leaving AcmeConsole.acmeAction(). No such EAB key.");
        return this.handedOn(deleted, 'STS-ACME-0094');
      }
      result = { ok: true, kid: deleted.kid,
                 message: 'The External Account Binding key ' + deleted.kid +
                          ' is deleted. An account it already bound keeps ' +
                          'its binding.' };
    } else if (action === 'deactivate-account') {
      const account = store.getAccount(value.account);
      if (!account) {
        log.debug("Leaving AcmeConsole.acmeAction(). No such account.");
        return this.refused('STS-ACME-0092', 'There is no ACME account "' +
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
      result = { ok: true, account: this.accountRow(account),
                 message: already ? 'The account was already ' +
                                    account.status + '; nothing changed.'
                                  : 'The ACME account ' + account.id + ' is ' +
                                    'deactivated and authorizes nothing ' +
                                    'more.' };
    } else if (action === 'revoke-certificate') {
      const found = core.findEnrolled(value.serial, FAMILY);
      if (!found) {
        log.debug("Leaving AcmeConsole.acmeAction(). No such certificate.");
        return this.refused('STS-ACME-0093', 'No certificate with serial ' +
                            value.serial +
                            ' was issued over ACME in this realm.');
      }
      if (found.record.revoked) {
        log.debug("Leaving AcmeConsole.acmeAction(). Already revoked.");
        return this.refused('STS-ACME-0096',
                            'That certificate is already revoked.');
      }
      const done = await core.revokeEnrolled(found.record.serialHex,
                                             value.reason || 'unspecified',
                                             actor, { family: FAMILY });
      if (!done.ok) {
        log.debug("Leaving AcmeConsole.acmeAction(). The CA refused.");
        return this.handedOn(done, 'STS-ACME-0065');
      }
      monitor.record(FAMILY, { operation: 'revoke-certificate',
                               outcome: 'revoked', status: 200,
                               principal: actor,
                               target: core.entryUri(done.entry),
                               serialHex: done.serialHex });
      result = { ok: true, serialHex: done.serialHex, reason: done.reason,
                 message: 'The certificate ' + done.serialHex +
                          ' is revoked (' +
                          done.reason +
                          ') and on the ACME Issuing CA\'s CRL.' };
    } else {
      const add = action === 'add-host-name';
      const changed = add
        ? core.addHostName(this.entryOf(value), value.hostName, actor)
        : core.removeHostName(this.entryOf(value), value.hostName, actor);
      if (!changed.ok) {
        log.debug("Leaving AcmeConsole.acmeAction(). Host name refused.");
        return this.handedOn(changed, 'STS-ACME-0094');
      }
      result = { ok: true, hostNames: changed.hostNames,
                 entryUri: core.entryUri(this.entryOf(value)),
                 message: changed.unchanged
                   ? 'That host name was already registered.'
                   : 'The host names of ' + core.entryUri(this.entryOf(value)) +
                     ' are now: ' + (changed.hostNames.join(', ') || 'none') +
                     '.' };
    }
    log.debug("Leaving AcmeConsole.acmeAction(). ok=" + result.ok);
    return result;
  }

  // The console session's username, which an action records as `createdBy` or
  // `by`. Here rather than in `acme_admin.ts` because the admin view layer may
  // be required by this file and not by that one
  // (tests/admin_actions_layer.js); it is not a view, and reads the session
  // only to name the actor.
  consoleActorOf(req) {
    const { log, adminViews } = this.deps;
    log.debug("Entering AcmeConsole.consoleActorOf().");
    let name = '';
    try {
      name = String(adminViews.gateStateFor(req).username || '');
    } catch (e) {
      log.debug("Caught in AcmeConsole.consoleActorOf(): " +
                ((e && e.message) || e));
      name = '';
    }
    log.debug("Leaving AcmeConsole.consoleActorOf().");
    return name;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AcmeConsole>(
  'acme/acme_console',
  () => new AcmeConsole(AcmeConsole.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  AcmeConsole: AcmeConsole,
  installInstance: (instance: AcmeConsole): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ACME_ACTIONS: ACME_ACTIONS,
  consoleActorOf: slot.forward('consoleActorOf'),
  acmeView: slot.forward('acmeView'),
  acmeMonitorView: slot.forward('acmeMonitorView'),
  acmeAction: slot.forward('acmeAction')
};
