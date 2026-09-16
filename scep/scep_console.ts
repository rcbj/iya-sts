'use strict';
//
// File: scep_console.ts
//
// ---------------------------------------------------------------------------
// WHAT THE TWO SCEP CONSOLE PAGES AND THEIR MANAGEMENT API OPERATIONS READ AND
// DO — ONE MODEL, TWO DOORS (rule 7).
//
//   GET  /admin/scep           scepView()         Protocols -> SCEP
//   GET  /admin/scep/monitor   scepMonitorView()  Monitoring -> SCEP
//                                                 enrollments
//   POST /admin/scep           scepAction()       create-challenge,
//                                                 delete-challenge, reissue-ra,
//                                                 revoke-certificate,
//                                                 add-host-name,
//                                                 remove-host-name
//
// `gnap/gnap_console.ts`'s arrangement exactly, and `tests/admin_actions_
// layer.js`'s properties hold for it: **no route, no `res`, no markup**, a
// view reads nothing from the request but its query and its base URL, and an
// action is a function of (body, context). `scep_admin.ts` draws the markup and
// `scep_api.ts` sends the JSON, both out of the SAME call.
//
// **THE ACTIONS VALIDATE THEIR OWN BODIES**, here rather than at either door,
// because there are two doors and a schema at each would be two schemas: the
// console's form and a JSON body copied from `/admin-api`'s document reach the
// same `checkParsed()` against the same zod object. The OpenAPI document's ajv
// `requestBody` schema is the THIRD statement of the shape, for a caller
// reading the document, and `tests/scep_enrollment.js` compares the two.
//
// **NO PRIVATE KEY IS IN ANY VIEW.** The RA row carries its certificate and
// nothing else (`scep_ra.describe()`), a challenge row carries its id and never
// its secret, and the one action that reveals a secret — create-challenge —
// answers it once and writes nothing that could repeat it.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScepConsole` takes the modules it uses through its constructor
// (`ScepConsoleDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `ScepConsole` is exported beside them for the
// composition root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log, baseUrlOf } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import mode = require('../common/mode');
import realms = require('../common/realms');
import validation = require('../common/validation');
import core = require('../common/cert_enrollment');
import monitor = require('../common/enrollment_monitor');
import adminViews = require('../admin-core/admin_views');
import cms = require('./scep_cms');
import ra = require('./scep_ra');

const vz = validation.z;
const vt = validation.types;

const SCEP_ACTIONS = ['create-challenge', 'delete-challenge', 'reissue-ra',
                      'revoke-certificate', 'add-host-name',
                      'remove-host-name'];

const KINDS = ['person', 'application'];

// The revocation reasons an operator may give an enrolled certificate: RFC
// 5280's list without the CA and attribute-authority ones, which describe an
// authority rather than a leaf, and without certificateHold, which the core's
// record has no way to lift again.
const REVOKE_REASONS = ['unspecified', 'keyCompromise', 'affiliationChanged',
                        'superseded', 'cessationOfOperation',
                        'privilegeWithdrawn'];

const PROFILE_TEXT = vz.string().min(1).max(64)
  .regex(/^[a-z][a-z0-9-]{0,63}$/, 'must be a profile identifier');

const ENTRY_FIELDS = {
  kind: vt.oneOf(KINDS),
  identifier: vt.name
};

const ACTION_SCHEMAS = {
  'create-challenge': vz.object(Object.assign({}, ENTRY_FIELDS, {
    profile: vt.opt(PROFILE_TEXT),
    lifetimeS: vt.opt(vt.integer(60, 2592000))
  })),
  'delete-challenge': vz.object({
    id: vz.string().min(1).max(600)
      .regex(/^scep-[pa]-[A-Za-z0-9_-]{1,400}-[0-9a-f]{16}$/,
             'must be a SCEP challenge id')
  }),
  'reissue-ra': vz.object({}),
  'revoke-certificate': vz.object({
    serial: vz.string().min(1).max(128)
      .regex(/^[0-9A-Fa-f:]+$/, 'must be a hexadecimal serial number'),
    reason: vt.opt(vt.oneOf(REVOKE_REASONS))
  }),
  'add-host-name': vz.object(Object.assign({}, ENTRY_FIELDS, {
    hostName: vz.string().min(1).max(253)
  })),
  'remove-host-name': vz.object(Object.assign({}, ENTRY_FIELDS, {
    hostName: vz.string().min(1).max(253)
  }))
};

// The query both views accept. Unknown parameters are stripped; a repeated one
// is refused by `validation.check()`.
const VIEW_QUERY = vz.object({
  per: vt.opt(vt.integer(1, 1000)),
  page: vt.opt(vt.integer(1, 1000000)),
  certificatesPage: vt.opt(vt.integer(1, 1000000)),
  credentialsPage: vt.opt(vt.integer(1, 1000000)),
  format: vt.opt(vt.oneOf(['json', 'JSON', 'html'])),
  notice: vt.opt(vt.text),
  error: vt.opt(vt.text)
});

// What SCEP does not do, drawn on the page and in the JSON. scep/CLAUDE.md
// carries the argument for each.
const EXCEPTIONS = [
  { what: 'An ECDSA, EdDSA or post-quantum requester key',
    why: 'A CertRep is encrypted to the requester with RSA key transport ' +
         '(RFC 8894 section 3.2.2), so a request or a signer that is not RSA ' +
         'is refused badAlg. Every one of the nine profiles is issued over ' +
         'SCEP for an RSA key; use ACME or EST for any other key.' },
  { what: 'PENDING (manual approval)',
    why: 'Nothing in this service approves a request by hand. A request is ' +
         'issued or refused in the exchange that makes it, and CertPoll ' +
         'answers what a completed transaction produced.' },
  { what: 'GetNextCACert',
    why: 'There is no pre-announced CA rollover to hand out: a rebuilt ' +
         'hierarchy is published at once. It answers HTTP 501 and is not in ' +
         'GetCACaps.' },
  { what: 'SHA-1 and MD5 signatures, DES and DES-EDE3 content encryption',
    why: 'Refused badAlg. SHA-256/384/512 and AES-128/192/256-CBC are ' +
         'accepted; configure a client with `-S sha256 -E aes`.' },
  { what: 'The requester\'s keyUsage, extendedKeyUsage and basicConstraints',
    why: 'Taken from the profile the challenge names, never from the request ' +
         '— as for every enrollment protocol here.' },
  { what: 'A profile other than the challenge\'s',
    why: 'The challenge names ONE profile; a URL naming another is refused, ' +
         'and a renewal keeps the profile of the certificate it renews.' }
];

// What `ScepConsole` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface ScepConsoleDeps {
  log: typeof log;
  baseUrlOf: typeof baseUrlOf;
  config: typeof config;
  errorCodes: typeof errorCodes;
  mode: typeof mode;
  realms: typeof realms;
  validation: typeof validation;
  core: typeof core;
  monitor: typeof monitor;
  adminViews: typeof adminViews;
  cms: typeof cms;
  ra: typeof ra;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadScep(): typeof import('./scep');
}

class ScepConsole {
  constructor(private readonly deps: ScepConsoleDeps) {
    deps.log.debug("Entering ScepConsole.constructor().");
    deps.log.debug("Leaving ScepConsole.constructor().");
  }

  refused(code, errors) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ScepConsole.refused(). code=" + code);
    log.debug("Leaving ScepConsole.refused().");
    return errorCodes.mark({ ok: false, errors: errors }, code);
  }

  settingsJson() {
    const { log, config } = this.deps;
    log.debug("Entering ScepConsole.settingsJson().");
    const group = config.groups().filter(function (one) {
      return one.group === 'SCEP';
    })[0];
    log.debug("Leaving ScepConsole.settingsJson().");
    return group ? group.settings : [];
  }

  queryOf(req) {
    const { log, validation } = this.deps;
    log.debug("Entering ScepConsole.queryOf().");
    const checked = validation.check(req, 'query', VIEW_QUERY);
    log.debug("Leaving ScepConsole.queryOf(). ok=" + checked.ok);
    return checked;
  }

  // Who a console session is, for `createdBy` and `by`. The management API has
  // no session and passes its own actor.
  actorOf(req) {
    const { log, adminViews } = this.deps;
    log.debug("Entering ScepConsole.actorOf().");
    let state = null;
    try {
      state = adminViews.gateStateFor(req);
    } catch (e) {
      log.debug("Caught in ScepConsole.actorOf(): " + ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving ScepConsole.actorOf().");
    return (state && state.username) || '';
  }

  endpointsOf(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering ScepConsole.endpointsOf().");
    const base = baseUrlOf(req) + '/enroll/scep';
    log.debug("Leaving ScepConsole.endpointsOf().");
    return {
      scep: base,
      cgi: base + '/pkiclient.exe',
      getCaCaps: base + '?operation=GetCACaps',
      getCaCert: base + '?operation=GetCACert',
      pkiOperation: base + '?operation=PKIOperation'
    };
  }

  profileRows(req) {
    const { log, baseUrlOf, core } = this.deps;
    log.debug("Entering ScepConsole.profileRows().");
    const base = baseUrlOf(req) + '/enroll/scep/';
    const allowed = core.allowedProfiles('scep');
    log.debug("Leaving ScepConsole.profileRows().");
    return core.PROFILE_IDS.map(function (id) {
      return { id: id, allowed: allowed.indexOf(id) >= 0,
               needs: core.PROFILE_NEEDS[id] || '',
               keys: 'RSA only over SCEP',
               url: base + id };
    });
  }

  certificateRow(one) {
    const { log } = this.deps;
    log.debug("Entering ScepConsole.certificateRow().");
    log.debug("Leaving ScepConsole.certificateRow().");
    return {
      serialHex: one.serialHex, entry: one.entry, entryUri: one.entryUri,
      profile: one.profile, subject: one.subject, names: one.names || [],
      keyAlg: one.keyAlg || '', status: one.status, notBefore: one.notBefore,
      notAfter: one.notAfter, issuedAt: one.issuedAt,
      requestedBy: one.requestedBy || null, replaces: one.replaces || null,
      revoked: one.revoked || null, thumbprint: one.thumbprint || ''
    };
  }

  modeNote() {
    const { log, mode } = this.deps;
    log.debug("Entering ScepConsole.modeNote().");
    const row = (mode.REQUIREMENTS || []).filter(function (one) {
      return one.id === 'certificate-enrollment';
    })[0] || null;
    log.debug("Leaving ScepConsole.modeNote().");
    return {
      mode: mode.current(),
      requirement: row,
      scep: 'SCEP is not refused over plain HTTP in either mode: its ' +
            'messages are signed and encrypted CMS (RFC 8894 section 2.1). ' +
            'The challenge password and the request signature are verified ' +
            'in both modes.'
    };
  }

  // ---------------------------------------------------------------------------
  // GET /admin/scep
  // ---------------------------------------------------------------------------
  scepView(req) {
    const { log, core, adminViews, baseUrlOf, realms, config, loadScep, cms,
            ra } = this.deps;
    log.debug("Entering ScepConsole.scepView().");
    const query = (req && req.query) || {};
    const chain = core.caChainOf('scep');
    const authority = core.authorityOf('scep');
    const challenges = core.challengesInRealm();
    const credentialPaging = adminViews.pagingOf(query, challenges.length,
      { name: 'credentials', noun: 'challenge passwords' });
    const certificates = core.certificatesInRealm('scep');
    const certificatePaging = adminViews.pagingOf(query, certificates.length,
      { name: 'certificates', noun: 'certificates' });
    const scepBase = baseUrlOf(req) + '/enroll/scep';
    const json = {
      page: '/admin/scep',
      title: 'SCEP',
      realm: realms.currentId(),
      enabled: config.value('scep.enabled') !== false,
      specifications: ['RFC 8894', 'RFC 5652', 'RFC 2986', 'RFC 5280'],
      endpoints: this.endpointsOf(req),
      capabilities: loadScep().CAPABILITIES.slice(),
      operations: loadScep().OPERATIONS.slice(),
      messageTypes: cms.MESSAGE_TYPES,
      algorithms: cms.algorithms(),
      authority: authority ? {
        subject: authority.subject, serialHex: authority.serialHex,
        keyAlg: authority.keyAlg, signatureAlg: authority.signatureAlg,
        notBefore: authority.notBefore, notAfter: authority.notAfter,
        thumbprint: authority.thumbprint,
        certificatePem: authority.certificatePem,
        intermediate: authority.intermediate ? {
          subject: authority.intermediate.subject,
          notAfter: authority.intermediate.notAfter } : null,
        root: authority.root ? { subject: authority.root.subject,
                                 notAfter: authority.root.notAfter } : null
      } : null,
      hierarchyBuilt: !!chain.ok,
      authorityNote: chain.ok ? '' : 'This realm has no SCEP Issuing CA yet. ' +
        'Build the hierarchy on /admin/pki (or POST /admin-api/pki/build); ' +
        'GetCACert answers 503 until then.',
      ra: ra.describe(realms.currentId()),
      profiles: this.profileRows(req),
      refusedProfiles: core.REFUSED_PROFILES.slice(),
      defaultProfile: core.defaultProfile('scep'),
      challenges: {
        paging: adminViews.pagingJson(credentialPaging),
        rows: challenges.slice(credentialPaging.offset,
          credentialPaging.offset + credentialPaging.perPage)
          .map(function (one) {
            return { id: one.id, entry: one.entry, entryUri: one.entryUri,
                     profile: one.profile, status: one.status,
                     createdAt: one.createdAt, expiresAt: one.expiresAt,
                     createdBy: one.createdBy || '', usedAt: one.usedAt,
                     url: scepBase + '/' + one.profile };
          })
      },
      hostNames: core.hostNamesInRealm(),
      certificates: {
        paging: adminViews.pagingJson(certificatePaging),
        rows: certificates.slice(certificatePaging.offset,
          certificatePaging.offset + certificatePaging.perPage)
          .map(this.certificateRow.bind(this))
      },
      exceptions: EXCEPTIONS.slice(),
      mode: this.modeNote(),
      revokeReasons: REVOKE_REASONS.slice(),
      actions: SCEP_ACTIONS.slice(),
      settings: this.settingsJson()
    };
    log.debug("Leaving ScepConsole.scepView(). " + certificates.length +
              " certificate(s).");
    return json;
  }

  // ---------------------------------------------------------------------------
  // GET /admin/scep/monitor
  // ---------------------------------------------------------------------------
  scepMonitorView(req) {
    const { log, monitor, adminViews, realms, core } = this.deps;
    log.debug("Entering ScepConsole.scepMonitorView().");
    const query = (req && req.query) || {};
    const snap = monitor.snapshot('scep') || {};
    const recent = snap.recent || [];
    const paging = adminViews.pagingOf(query, recent.length,
                                       { noun: 'requests' });
    const json = {
      page: '/admin/scep/monitor',
      title: 'SCEP enrollments',
      realm: realms.currentId(),
      since: snap.startedAt,
      processes: snap.processes,
      totals: { requests: snap.requests || 0, issued: snap.issued || 0,
                refused: snap.refused || 0, revoked: snap.revoked || 0,
                challengesCreated: snap.credentialsCreated || 0 },
      operations: snap.operations || {},
      profiles: snap.profiles || {},
      principals: snap.principals || {},
      errorCodes: snap.codes || {},
      statuses: snap.statuses || {},
      failInfo: snap.failInfos || {},
      issuedCertificates: core.certificatesInRealm('scep').length,
      lastAt: snap.lastAt || null,
      paging: adminViews.pagingJson(paging),
      recent: recent.slice(paging.offset, paging.offset + paging.perPage)
    };
    log.debug("Leaving ScepConsole.scepMonitorView().");
    return json;
  }

  // ---------------------------------------------------------------------------
  // POST /admin/scep — the six things an operator does by hand. Asynchronous,
  // because re-issuing the RA certificate generates a key and revoking signs.
  // ---------------------------------------------------------------------------
  entryOf(value) {
    const { log } = this.deps;
    log.debug("Entering ScepConsole.entryOf().");
    log.debug("Leaving ScepConsole.entryOf().");
    return { kind: value.kind, id: String(value.identifier) };
  }

  sscepHint(url, challenge, entry) {
    const { log, core } = this.deps;
    log.debug("Entering ScepConsole.sscepHint().");
    log.debug("Leaving ScepConsole.sscepHint().");
    return [
      'sscep getca -u ' + url + ' -c ca.crt',
      'openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.csr ' +
        '-subj "/CN=' + entry.id + '" -addext "subjectAltName=URI:' +
        core.entryUri(entry) + '" -config <(printf "[req]\\n' +
        'distinguished_name=dn\\nattributes=a\\n[dn]\\n[a]\\n' +
        'challengePassword=' + challenge + '\\n")',
      'sscep enroll -u ' + url + ' -c ca.crt-1 -e ca.crt-0 -k key.pem ' +
        '-r req.csr -l cert.pem -S sha256 -E aes'
    ].join('\n');
  }

  async scepAction(body, context) {
    const { log, validation, core, errorCodes, baseUrlOf, monitor, ra,
            realms } = this.deps;
    log.debug("Entering ScepConsole.scepAction(). action=" +
              (body && body.action));
    const ctx = context || {};
    const actor = String(ctx.actor || '');
    const action = String((body && body.action) || '');
    const schema = ACTION_SCHEMAS[action];
    if (!schema) {
      log.debug("Leaving ScepConsole.scepAction(). Unknown action.");
      return this.refused('STS-SCEP-0062',
                          ['Unknown action "' + action + '". The ' +
        SCEP_ACTIONS.length + ' are: ' + SCEP_ACTIONS.join(', ') + '.']);
    }
    const posted = validation.checkParsed(body || {}, 'body', schema);
    if (!posted.ok) {
      log.debug("Leaving ScepConsole.scepAction(). Malformed.");
      return this.refused('STS-SCEP-0061', [posted.detail]);
    }
    const value = posted.value;
    if (action === 'create-challenge') {
      const target = this.entryOf(value);
      const made = core.createScepChallenge({
        target: target, profile: value.profile || undefined,
        createdBy: actor, lifetimeS: value.lifetimeS || undefined });
      if (!made.ok) {
        log.debug("Leaving ScepConsole.scepAction(). The challenge was " +
                  "refused.");
        return this.refused(errorCodes.codeOf(made) || 'STS-SCEP-0061',
                            made.errors);
      }
      const url = baseUrlOf(ctx.req) + '/enroll/scep/' + made.profile;
      monitor.record('scep', { operation: 'create-challenge',
                               outcome: 'credential', status: 200,
                               profile: made.profile,
                               principal: actor || ctx.via || '',
                               target: core.entryUri(made.target) });
      log.debug("Leaving ScepConsole.scepAction(). A challenge.");
      return { ok: true, id: made.id, challenge: made.challenge,
               profile: made.profile, expiresAt: made.expiresAt,
               target: made.target, entryUri: core.entryUri(made.target),
               url: url, hint: this.sscepHint(url, made.challenge, made.target),
               message: 'A challenge password was created for ' +
                        core.entryUri(made.target) + ' (' + made.profile +
                        '). It is shown once.' };
    }
    if (action === 'delete-challenge') {
      const gone = core.deleteScepChallenge(value.id, actor);
      if (!gone.ok) {
        log.debug("Leaving ScepConsole.scepAction(). No such challenge.");
        return this.refused(errorCodes.codeOf(gone) || 'STS-SCEP-0061',
                            gone.errors);
      }
      log.debug("Leaving ScepConsole.scepAction(). Deleted.");
      return { ok: true, id: gone.id, entryUri: core.entryUri(gone.entry),
               message: 'The challenge ' + gone.id + ' is deleted.' };
    }
    if (action === 'reissue-ra') {
      const made = await ra.ensure(realms.currentId(), { force: true });
      if (!made.ok) {
        log.debug("Leaving ScepConsole.scepAction(). The RA was not " +
                  "re-issued.");
        return this.refused(errorCodes.codeOf(made) || 'STS-SCEP-0006',
                            made.errors);
      }
      log.debug("Leaving ScepConsole.scepAction(). Re-issued.");
      return { ok: true, ra: ra.describe(realms.currentId()),
               message: 'The SCEP RA certificate was re-issued; the one it ' +
                        'replaces is on the SCEP Issuing CA\'s CRL as ' +
                        'superseded. Clients fetch it again with GetCACert.' };
    }
    if (action === 'revoke-certificate') {
      const reason = value.reason || 'unspecified';
      const done = await core.revokeEnrolled(value.serial, reason, actor,
                                             { family: 'scep' });
      if (!done.ok) {
        log.debug("Leaving ScepConsole.scepAction(). Not revoked.");
        return this.refused(errorCodes.codeOf(done) || 'STS-SCEP-0063',
                            done.errors);
      }
      monitor.record('scep', { operation: 'revoke-certificate',
                               outcome: 'revoked', status: 200,
                               principal: actor || ctx.via || '',
                               target: core.entryUri(done.entry),
                               serialHex: done.serialHex });
      log.debug("Leaving ScepConsole.scepAction(). Revoked.");
      return { ok: true, serialHex: done.serialHex,
               entryUri: core.entryUri(done.entry), reason: done.reason,
               message: 'Certificate ' + done.serialHex + ' is revoked (' +
                        done.reason + ') and on the SCEP Issuing CA\'s CRL.' };
    }
    const entry = this.entryOf(value);
    const changed = action === 'add-host-name'
      ? core.addHostName(entry, value.hostName, actor)
      : core.removeHostName(entry, value.hostName, actor);
    if (!changed.ok) {
      log.debug("Leaving ScepConsole.scepAction(). The host name was refused.");
      return this.refused(errorCodes.codeOf(changed) || 'STS-SCEP-0061',
                          changed.errors);
    }
    log.debug("Leaving ScepConsole.scepAction(). Host names changed.");
    return { ok: true, entryUri: core.entryUri(entry),
             hostNames: changed.hostNames,
             message: 'The host names of ' + core.entryUri(entry) +
                      ' are now ' +
                      (changed.hostNames.join(', ') || 'none') + '.' };
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const scepConsole = new ScepConsole({
  log: log,
  baseUrlOf: baseUrlOf,
  config: config,
  errorCodes: errorCodes,
  mode: mode,
  realms: realms,
  validation: validation,
  core: core,
  monitor: monitor,
  adminViews: adminViews,
  cms: cms,
  ra: ra,
  loadScep: function () {
    return require('./scep');
  }
});

export = {
  ScepConsole: ScepConsole,
  SCEP_ACTIONS: SCEP_ACTIONS,
  ACTION_SCHEMAS: ACTION_SCHEMAS,
  REVOKE_REASONS: REVOKE_REASONS,
  EXCEPTIONS: EXCEPTIONS,
  queryOf: scepConsole.queryOf.bind(scepConsole) as ScepConsole['queryOf'],
  actorOf: scepConsole.actorOf.bind(scepConsole) as ScepConsole['actorOf'],
  scepView: scepConsole.scepView.bind(scepConsole) as ScepConsole['scepView'],
  scepMonitorView: scepConsole.scepMonitorView.bind(scepConsole) as
    ScepConsole['scepMonitorView'],
  scepAction: scepConsole.scepAction.bind(scepConsole) as
    ScepConsole['scepAction']
};
