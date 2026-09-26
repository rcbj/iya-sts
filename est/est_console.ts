'use strict';
//
// File: est_console.ts
//
// ---------------------------------------------------------------------------
// WHAT THE TWO EST CONSOLE PAGES AND THEIR MANAGEMENT API OPERATIONS READ AND
// DO — ONE MODEL, TWO DOORS (2026-09-13).
//
// `gnap/gnap_console.ts`'s arrangement for EST, and for its reason: rule 7 says
// a console page and its `/admin-api` operation cannot disagree, and the way to
// make that structural is one VIEW that computes every fact once and one ACTION
// that changes state once, with `est_admin.ts` drawing the markup and
// `est_api.ts` sending the JSON out of the same call.
//
// **NO ROUTE, NO `res`, NO MARKUP.** A view reads nothing from the request but
// its query and the base URL; an action takes a validated body and a context
// naming who asked and through which door.
//
//   GET  /admin/est           estView()          Protocols -> EST
//   GET  /admin/est/monitor   estMonitorView()   Monitoring -> EST enrollments
//   POST /admin/est           estAction()        issue-server-key,
//                                                revoke-certificate,
//                                                add-host-name,
//                                                remove-host-name
//
// **EVERY ACTION IS THE CORE'S.** Issuing with a server-generated key,
// revoking an enrolled certificate and registering a host name are
// `common/cert_enrollment.ts` functions; what this file adds is the body
// shape, the principal (the console's signed-in administrator, or the
// management API) and the result a page or a machine is handed.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `EstConsole` takes the modules it uses through its constructor
// (`EstConsoleDeps`). Since #50's R2 the composition root builds the instance
// (`EstConsole.defaultDeps()`) and installs it; the module's old export names
// are FACADES that forward to it, for the JavaScript callers, and a process
// without the root builds a default when the module finishes loading.
// `EstConsole` is exported beside them for the composition root.
// ---------------------------------------------------------------------------

import config = require('../common/config');
import helpers = require('../common/helpers');
const { log, baseUrlOf } = helpers;
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import mode = require('../common/mode');
import realms = require('../common/realms');
import core = require('../common/cert_enrollment');
import monitor = require('../common/enrollment_monitor');
import keyMaterial = require('../common/vendored/key_material');
import adminViews = require('../admin-core/admin_views');
import codec = require('./est_codec');
import InstanceSlot = require('../common/instance_slot');

const FAMILY = 'est';

const EST_ACTIONS = ['issue-server-key', 'revoke-certificate',
                     'add-host-name', 'remove-host-name'];

// The six operations and where they live, for the endpoint list. The same table
// `est.ts` registers from would be a require of a route module from a view
// model; the operations are six names fixed by RFC 7030 section 3.2.2, so they
// are written here and `tests/est_handlers.js` compares the two.
const OPERATIONS = [
  { name: 'cacerts', method: 'GET', section: '4.1',
    what: 'the CA certificates (unauthenticated)' },
  { name: 'simpleenroll', method: 'POST', section: '4.2.1',
    what: 'a certificate for a key the client holds' },
  { name: 'simplereenroll', method: 'POST', section: '4.2.2',
    what: 'renew a certificate; the old one is superseded' },
  { name: 'serverkeygen', method: 'POST', section: '4.4',
    what: 'a key pair this service generates, returned once' },
  { name: 'csrattrs', method: 'GET', section: '4.5',
    what: 'what a request should carry (unauthenticated)' },
  { name: 'fullcmc', method: 'POST', section: '4.3',
    what: 'not implemented: answers 501' }
];

const REVOCATION_REASONS = ['unspecified', 'keyCompromise', 'cACompromise',
                            'affiliationChanged', 'superseded',
                            'cessationOfOperation', 'certificateHold',
                            'privilegeWithdrawn', 'aACompromise'];

const vz = validation.z;
const vt = validation.types;

// The console form and the API body. Loose because the console posts its CSRF
// token beside the fields; the API's own ajv schema is strict. Every field is a
// string of a bounded shape, and which are REQUIRED is decided per action.
const ACTION_BODY = vz.looseObject({
  action: vt.opt(vt.token),
  kind: vt.opt(vt.oneOf(['person', 'application'])),
  identifier: vt.opt(vt.name),
  profile: vt.opt(vt.oneOf(core.PROFILE_IDS)),
  keyAlg: vt.opt(vt.identifier),
  serialHex: vt.opt(vz.string().min(1).max(80)
    .regex(/^[0-9A-Fa-f:]+$/, 'must be a hexadecimal serial number')),
  reason: vt.opt(vt.oneOf(REVOCATION_REASONS)),
  hostName: vt.opt(vz.string().min(1).max(253)),
  csrf_token: vt.opt(vt.token)
});

// What `EstConsole` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface EstConsoleDeps {
  config: typeof config;
  log: typeof log;
  baseUrlOf: typeof baseUrlOf;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  mode: typeof mode;
  realms: typeof realms;
  core: typeof core;
  monitor: typeof monitor;
  keyMaterial: typeof keyMaterial;
  adminViews: typeof adminViews;
  codec: typeof codec;
}

class EstConsole {
  constructor(private readonly deps: EstConsoleDeps) {
    deps.log.debug("Entering EstConsole.constructor().");
    deps.log.debug("Leaving EstConsole.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): EstConsoleDeps {
    helpers.log.debug("Entering EstConsole.defaultDeps().");
    helpers.log.debug("Leaving EstConsole.defaultDeps().");
    return {
      config: config,
      log: log,
      baseUrlOf: baseUrlOf,
      errorCodes: errorCodes,
      validation: validation,
      mode: mode,
      realms: realms,
      core: core,
      monitor: monitor,
      keyMaterial: keyMaterial,
      adminViews: adminViews,
      codec: codec
    };
  }

  refused(code, status, sentence) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering EstConsole.refused(). code=" + code);
    log.debug("Leaving EstConsole.refused().");
    return errorCodes.mark({ ok: false, status: status, errors: [sentence] },
                           code);
  }

  settingsJson() {
    const { log, config } = this.deps;
    log.debug("Entering EstConsole.settingsJson().");
    const group = config.groups().filter(function (one) {
      return one.group === 'EST';
    })[0];
    log.debug("Leaving EstConsole.settingsJson().");
    return group ? group.settings : [];
  }

  // Who is acting, for `createdBy` / `by` and the principal. The console's
  // signed-in person; the management API, which authenticates a token rather
  // than a person, is named as itself.
  actorOf(req, via) {
    const { log, adminViews } = this.deps;
    log.debug("Entering EstConsole.actorOf(). via=" + via);
    if (via !== 'console') {
      log.debug("Leaving EstConsole.actorOf(). The management API.");
      return 'admin-api';
    }
    let username = '';
    try {
      username = adminViews.gateStateFor(req).username || '';
    } catch (e) {
      log.debug("Caught in EstConsole.actorOf(): " + ((e && e.message) || e));
      username = '';
    }
    log.debug("Leaving EstConsole.actorOf().");
    return username || 'console';
  }

  certificateRow(one) {
    const { log } = this.deps;
    log.debug("Entering EstConsole.certificateRow().");
    log.debug("Leaving EstConsole.certificateRow().");
    return {
      serialHex: one.serialHex, entry: one.entry, entryUri: one.entryUri,
      profile: one.profile, subject: one.subject, names: one.names || [],
      keyAlg: one.keyAlg || '', keySource: one.keySource, via: one.via,
      notBefore: one.notBefore, notAfter: one.notAfter, issuedAt: one.issuedAt,
      requestedBy: one.requestedBy || null, replaces: one.replaces || null,
      status: one.status, revoked: one.revoked || null,
      thumbprint: one.thumbprint
    };
  }

  modeNote() {
    const { log, mode } = this.deps;
    log.debug("Entering EstConsole.modeNote().");
    const row = (mode.REQUIREMENTS || []).filter(function (one) {
      return one.id === 'certificate-enrollment';
    })[0] || null;
    log.debug("Leaving EstConsole.modeNote().");
    return { current: mode.current(),
             development: row ? row.development : '',
             product: row ? row.product : '',
             where: row ? row.where : '' };
  }

  // ---------------------------------------------------------------------------
  // GET /admin/est — what the EST server IS in this realm.
  // ---------------------------------------------------------------------------
  estView(req) {
    const { log, baseUrlOf, core, adminViews, config, keyMaterial,
            codec, realms } = this.deps;
    log.debug("Entering EstConsole.estView().");
    const query = (req && req.query) || {};
    const base = baseUrlOf(req);
    // THE LABEL FORM (#251): the one address an RFC 7030 client that takes
    // only a host, a port and one label can be given for a realm other than
    // the default — `/.well-known/est/<realm>` at the ORIGIN, not under the
    // realm's prefix. None in the default realm, which needs none.
    const labelPath = realms.estLabelPath();
    const origin = base.slice(0, base.length -
                              realms.currentPrefix().length);
    const labelBase = labelPath ? origin + labelPath : null;
    const allowed = core.allowedProfiles(FAMILY);
    const defaultProfile = core.defaultProfile(FAMILY);
    const chain = core.caChainOf(FAMILY);
    const authority = core.authorityOf(FAMILY);
    const certificates = core.certificatesInRealm(FAMILY);
    const paging = adminViews.pagingOf(query, certificates.length,
                                       { name: 'certificates',
                                         noun: 'certificates' });
    const json = {
      page: '/admin/est',
      title: 'EST',
      enabled: config.value('est.enabled') !== false,
      specifications: ['RFC 7030', 'RFC 8951', 'RFC 5967', 'RFC 2986',
                       'RFC 5652', 'RFC 5958'],
      endpoints: OPERATIONS.map(function (op) {
        return { operation: op.name, method: op.method, section: op.section,
                 what: op.what,
                 url: base + '/.well-known/est/' + op.name,
                 labelFormUrl: labelBase ? labelBase + '/' + op.name : null };
      }),
      labelForm: labelBase ? {
        base: labelBase,
        note: 'For an EST client that can be given only a host, a port and ' +
              'one label (libest\'s estclient is one): this realm is named ' +
              'in the label position, and a profile after it ' +
              '(' + labelBase + '/<profile>/<operation>) for a client that ' +
              'can send two segments. The /realm/ form and this one reach ' +
              'the same server; a request names the realm once.'
      } : null,
      hierarchy: {
        built: !!chain.ok,
        note: chain.ok ? '' : 'This realm has no EST Issuing CA yet: nothing ' +
              'can be enrolled and /cacerts answers 503. Build the hierarchy ' +
              'on /admin/pki; the EST Issuing CA is made with the branch.',
        authority: authority ? {
          subject: authority.subject, serialHex: authority.serialHex,
          keyAlg: authority.keyAlg, notBefore: authority.notBefore,
          notAfter: authority.notAfter, thumbprint: authority.thumbprint,
          certificatePem: authority.certificatePem
        } : null,
        chainPem: chain.chainPem || []
      },
      authentication: {
        basic: config.value('est.basicAuthentication') !== false,
        certificate: config.value('est.certificateAuthentication') !== false,
        serverKeyGeneration: config.value('est.serverKeyGeneration') !== false,
        credentials: [
          { kind: 'password', what: 'HTTP Basic with a person\'s directory ' +
            'password (userPassword). Checked in product mode only.',
            managedAt: '/admin/users' },
          { kind: 'client-secret', what: 'HTTP Basic with an application\'s ' +
            'client_id and client_secret. Required in product mode.',
            managedAt: '/admin/applications' },
          { kind: 'certificate', what: 'A TLS client certificate this realm ' +
            'issued and the entry still holds, mapped by its urn:sts: name. ' +
            'Verified in both modes.',
            managedAt: '/admin/est' }
        ]
      },
      // The device profile (#164 phase 2) beside /admin/pki's nine.
      profiles: core.PROFILE_IDS.concat([core.DEVICE_PROFILE]).map(
        function (id) {
        const urls = {};
        OPERATIONS.forEach(function (op) {
          urls[op.name] = base + '/.well-known/est/' + id + '/' + op.name;
        });
        return { id: id, needs: id === core.DEVICE_PROFILE
                   ? 'a device entry — the one the request\'s ' +
                     'urn:sts:device: names, or a new one; a TPM key ' +
                     'attestation in product; simpleenroll only'
                   : core.PROFILE_NEEDS[id] || null,
                 allowed: allowed.indexOf(id) >= 0,
                 isDefault: id === defaultProfile, urls: urls };
      }),
      defaultProfile: defaultProfile,
      refusedProfiles: core.REFUSED_PROFILES.map(function (one) {
        return { id: one.id, why: one.why };
      }),
      hostNames: core.hostNamesInRealm(),
      certificates: {
        paging: adminViews.pagingJson(paging),
        rows: certificates.slice(paging.offset, paging.offset + paging.perPage)
          .map(this.certificateRow.bind(this))
      },
      keyAlgorithms: keyMaterial.keyAlgIds(),
      revocationReasons: REVOCATION_REASONS,
      csrAttributes: {
        signatureAlgorithms: codec.SIGNATURE_ALGORITHMS
      },
      mode: this.modeNote(),
      actions: EST_ACTIONS,
      settings: this.settingsJson(),
      monitor: '/admin/est/monitor'
    };
    log.debug("Leaving EstConsole.estView(). " + certificates.length +
              " certificate(s).");
    return json;
  }

  tableOf(counts) {
    const { log } = this.deps;
    log.debug("Entering EstConsole.tableOf().");
    log.debug("Leaving EstConsole.tableOf().");
    return Object.keys(counts || {}).map(function (name) {
      return { name: name, count: Number(counts[name] || 0) };
    }).sort(function (a, b) {
      return b.count - a.count || a.name.localeCompare(b.name);
    });
  }

  // ---------------------------------------------------------------------------
  // GET /admin/est/monitor — what the EST server has DONE in this realm.
  // ---------------------------------------------------------------------------
  estMonitorView(req) {
    const { log, monitor, adminViews, core } = this.deps;
    log.debug("Entering EstConsole.estMonitorView().");
    const query = (req && req.query) || {};
    const snapshot = monitor.snapshot(FAMILY) || {};
    const recent = snapshot.recent || [];
    const paging = adminViews.pagingOf(query, recent.length,
                                       { noun: 'requests' });
    const issuedHere = core.certificatesInRealm(FAMILY);
    const json = {
      page: '/admin/est/monitor',
      title: 'EST enrollments',
      since: snapshot.startedAt || null,
      processes: snapshot.processes || 1,
      totals: {
        requests: snapshot.requests || 0,
        issued: snapshot.issued || 0,
        refused: snapshot.refused || 0,
        revoked: snapshot.revoked || 0
      },
      certificates: {
        held: issuedHere.length,
        valid: issuedHere.filter(function (one) {
          return one.status === 'valid';
        }).length,
        revoked: issuedHere.filter(function (one) {
          return one.status === 'revoked';
        }).length,
        expired: issuedHere.filter(function (one) {
          return one.status === 'expired';
        }).length
      },
      operations: this.tableOf(snapshot.operations),
      profiles: this.tableOf(snapshot.profiles),
      principals: this.tableOf(snapshot.principals),
      errorCodes: this.tableOf(snapshot.codes),
      statuses: this.tableOf(snapshot.statuses),
      lastAt: snapshot.lastAt || null,
      paging: adminViews.pagingJson(paging),
      recent: recent.slice(paging.offset, paging.offset + paging.perPage)
    };
    log.debug("Leaving EstConsole.estMonitorView(). " + json.totals.requests +
              " request(s).");
    return json;
  }

  // ---------------------------------------------------------------------------
  // POST /admin/est — the four things an operator does to EST by hand.
  //
  // context: { via: 'console' | 'api', req }
  // ---------------------------------------------------------------------------
  async estAction(body, context) {
    const { log, validation, core, monitor } = this.deps;
    const self = this;
    log.debug("Entering EstConsole.estAction(). action=" +
              (body && body.action));
    const ctx = context || {};
    const via = ctx.via === 'console' ? 'console' : 'api';
    const posted = validation.checkParsed(body || {}, 'body', ACTION_BODY);
    if (!posted.ok) {
      log.debug("Leaving EstConsole.estAction(). Malformed.");
      return this.refused('STS-EST-0031', 400, posted.detail);
    }
    const asked = posted.value;
    const action = String(asked.action || '');
    const actor = this.actorOf(ctx.req, via);
    const need = function need(names) {
      log.debug("Entering need().");
      const missing = names.filter(function (name) {
        return !asked[name];
      });
      log.debug("Leaving need(). " + missing.length + " missing.");
      return missing.length ?
             self.refused('STS-EST-0031', 400, 'The ' + action +
        ' action needs ' + missing.join(', ') + '.') : null;
    };
    let result = null;
    if (action === 'issue-server-key') {
      result = need(['kind', 'identifier']) ||
               await this.issueServerKey(asked, actor, via);
    } else if (action === 'revoke-certificate') {
      result = need(['serialHex']);
      if (!result) {
        const done = await core.revokeEnrolled(asked.serialHex,
                                               asked.reason || 'unspecified',
                                               actor, { family: FAMILY });
        result = done.ok ? Object.assign({}, done, {
          message: 'The EST certificate ' + done.serialHex + ' of ' +
                   core.entryUri(done.entry) + ' is revoked (' + done.reason +
                   ') and on the EST Issuing CA\'s CRL.' }) : done;
      }
    } else if (action === 'add-host-name' || action === 'remove-host-name') {
      result = need(['kind', 'identifier', 'hostName']);
      if (!result) {
        const entry = { kind: asked.kind, id: asked.identifier };
        const adding = action === 'add-host-name';
        const done = adding ? core.addHostName(entry, asked.hostName, actor)
                            : core.removeHostName(entry, asked.hostName, actor);
        result = done.ok ? Object.assign({}, done, {
          message: 'The host name ' + asked.hostName + ' was ' +
                   (adding ? (done.unchanged ? 'already registered on '
                                             : 'registered on ')
                           : 'removed from ') +
                   core.entryUri(entry) + '.' }) : done;
      }
    } else {
      result = this.refused('STS-EST-0032', 400, 'Unknown action "' +
                            action.slice(0, 60) + '". The four are: ' +
                            EST_ACTIONS.join(', ') + '.');
    }
    if (result && result.ok) {
      monitor.record(FAMILY, { operation: action, outcome:
                               action === 'revoke-certificate' ? 'revoked'
                                 : (action === 'issue-server-key' ? 'issued'
                                                                  : 'answered'),
                               status: 200, principal: actor,
                               profile: result.record ? result.record.profile
                                                      : null,
                               serialHex: result.serialHex ||
                                          (result.record &&
                                           result.record.serialHex) || null });
    }
    log.debug("Leaving EstConsole.estAction(). ok=" + !!(result && result.ok));
    return result;
  }

  // The console's and the API's "issue a certificate with a server-generated
  // key". The principal is an ADMINISTRATOR by construction: the console gate
  // and the management API's token gate have both required Admin Write before a
  // POST reaches here, and that — not the roster read again — is what
  // authorizes naming any entry in the realm.
  async issueServerKey(asked, actor, via) {
    const { log, config, core, keyMaterial } = this.deps;
    log.debug("Entering EstConsole.issueServerKey().");
    if (config.value('est.serverKeyGeneration') === false) {
      log.debug("Leaving EstConsole.issueServerKey(). Off.");
      return this.refused('STS-EST-0005', 400,
                          'Server-side key generation is ' +
                          'turned off for EST in this realm ' +
                          '(est.serverKeyGeneration).');
    }
    const profile = asked.profile || core.defaultProfile(FAMILY);
    const keyAlg = asked.keyAlg || 'ec-p256';
    const described = keyMaterial.keyAlg(keyAlg) || {};
    if (described.kind === 'pqc' && described.use === 'kem' &&
        profile !== 'key-encipherment') {
      log.debug("Leaving EstConsole.issueServerKey(). A KEM key for a " +
                "signing profile.");
      return this.refused('STS-EST-0017', 400, 'A ' + keyAlg + ' key is a ' +
                          'key-encapsulation key and can be certified only ' +
                          'for key-encipherment.');
    }
    const principal = core.sessionPrincipal(actor, 'est-' + via,
                                            { admin: true });
    const issued = await core.issueWithServerKey({
      family: FAMILY, profile: profile, principal: principal,
      target: { kind: asked.kind, id: asked.identifier }, keyAlg: keyAlg,
      requested: {}, via: 'est:' + via
    });
    if (!issued.ok) {
      log.debug("Leaving EstConsole.issueServerKey(). Refused.");
      return issued;
    }
    log.debug("Leaving EstConsole.issueServerKey().");
    return {
      ok: true,
      message: 'A ' + profile + ' certificate with a ' + keyAlg + ' key was ' +
               'issued for ' + core.entryUri(issued.target) + '. The private ' +
               'key is shown ONCE; a sealed copy is kept on the entry.',
      target: issued.target,
      keyAlg: keyAlg,
      record: this.certificateRow(Object.assign({ entry: issued.target,
        entryUri: core.entryUri(issued.target) }, issued.record)),
      certificatePem: issued.record.certificatePem,
      chainPem: issued.record.chainPem || [],
      privateKeyPem: issued.privateKeyPem
    };
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
const slot = new InstanceSlot<EstConsole>(
  'est/est_console',
  () => new EstConsole(EstConsole.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  EstConsole: EstConsole,
  installInstance: (instance: EstConsole): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FAMILY: FAMILY,
  EST_ACTIONS: EST_ACTIONS,
  OPERATIONS: OPERATIONS,
  REVOCATION_REASONS: REVOCATION_REASONS,
  estView: slot.forward('estView'),
  estMonitorView: slot.forward('estMonitorView'),
  estAction: slot.forward('estAction')
};
