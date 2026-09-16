// @ts-check
'use strict';
//
// File: est_console.js
//
// ---------------------------------------------------------------------------
// WHAT THE TWO EST CONSOLE PAGES AND THEIR MANAGEMENT API OPERATIONS READ AND
// DO — ONE MODEL, TWO DOORS (2026-09-13).
//
// `gnap/gnap_console.js`'s arrangement for EST, and for its reason: rule 7 says
// a console page and its `/admin-api` operation cannot disagree, and the way to
// make that structural is one VIEW that computes every fact once and one ACTION
// that changes state once, with `est_admin.js` drawing the markup and
// `est_api.js` sending the JSON out of the same call.
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
// `common/cert_enrollment.js` functions; what this file adds is the body
// shape, the principal (the console's signed-in administrator, or the
// management API) and the result a page or a machine is handed.
// ---------------------------------------------------------------------------

const config = require('../common/config');
const { log, baseUrlOf } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const validation = require('../common/validation');
const mode = require('../common/mode');
const core = require('../common/cert_enrollment');
const monitor = require('../common/enrollment_monitor');
const keyMaterial = require('../common/vendored/key_material');
const adminViews = require('../admin-core/admin_views');
const codec = require('./est_codec');

const FAMILY = 'est';

const EST_ACTIONS = ['issue-server-key', 'revoke-certificate',
                     'add-host-name', 'remove-host-name'];

// The six operations and where they live, for the endpoint list. The same table
// `est.js` registers from would be a require of a route module from a view
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

function refused(code, status, sentence) {
  log.debug("Entering refused(). code=" + code);
  log.debug("Leaving refused().");
  return errorCodes.mark({ ok: false, status: status, errors: [sentence] },
                         code);
}

function settingsJson() {
  log.debug("Entering settingsJson().");
  const group = config.groups().filter(function (one) {
    return one.group === 'EST';
  })[0];
  log.debug("Leaving settingsJson().");
  return group ? group.settings : [];
}

// Who is acting, for `createdBy` / `by` and the principal. The console's
// signed-in person; the management API, which authenticates a token rather than
// a person, is named as itself.
function actorOf(req, via) {
  log.debug("Entering actorOf(). via=" + via);
  if (via !== 'console') {
    log.debug("Leaving actorOf(). The management API.");
    return 'admin-api';
  }
  let username = '';
  try {
    username = adminViews.gateStateFor(req).username || '';
  } catch (e) {
    log.debug("Caught in actorOf(): " + ((e && e.message) || e));
    username = '';
  }
  log.debug("Leaving actorOf().");
  return username || 'console';
}

function certificateRow(one) {
  log.debug("Entering certificateRow().");
  log.debug("Leaving certificateRow().");
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

function modeNote() {
  log.debug("Entering modeNote().");
  const row = (mode.REQUIREMENTS || []).filter(function (one) {
    return one.id === 'certificate-enrollment';
  })[0] || null;
  log.debug("Leaving modeNote().");
  return { current: mode.current(),
           development: row ? row.development : '',
           product: row ? row.product : '',
           where: row ? row.where : '' };
}

// ---------------------------------------------------------------------------
// GET /admin/est — what the EST server IS in this realm.
// ---------------------------------------------------------------------------
function estView(req) {
  log.debug("Entering estView().");
  const query = (req && req.query) || {};
  const base = baseUrlOf(req);
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
               url: base + '/.well-known/est/' + op.name };
    }),
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
    profiles: core.PROFILE_IDS.map(function (id) {
      const urls = {};
      OPERATIONS.forEach(function (op) {
        urls[op.name] = base + '/.well-known/est/' + id + '/' + op.name;
      });
      return { id: id, needs: core.PROFILE_NEEDS[id] || null,
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
        .map(certificateRow)
    },
    keyAlgorithms: keyMaterial.keyAlgIds(),
    revocationReasons: REVOCATION_REASONS,
    csrAttributes: {
      signatureAlgorithms: codec.SIGNATURE_ALGORITHMS
    },
    mode: modeNote(),
    actions: EST_ACTIONS,
    settings: settingsJson(),
    monitor: '/admin/est/monitor'
  };
  log.debug("Leaving estView(). " + certificates.length + " certificate(s).");
  return json;
}

function tableOf(counts) {
  log.debug("Entering tableOf().");
  log.debug("Leaving tableOf().");
  return Object.keys(counts || {}).map(function (name) {
    return { name: name, count: Number(counts[name] || 0) };
  }).sort(function (a, b) {
    return b.count - a.count || a.name.localeCompare(b.name);
  });
}

// ---------------------------------------------------------------------------
// GET /admin/est/monitor — what the EST server has DONE in this realm.
// ---------------------------------------------------------------------------
function estMonitorView(req) {
  log.debug("Entering estMonitorView().");
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
    operations: tableOf(snapshot.operations),
    profiles: tableOf(snapshot.profiles),
    principals: tableOf(snapshot.principals),
    errorCodes: tableOf(snapshot.codes),
    statuses: tableOf(snapshot.statuses),
    lastAt: snapshot.lastAt || null,
    paging: adminViews.pagingJson(paging),
    recent: recent.slice(paging.offset, paging.offset + paging.perPage)
  };
  log.debug("Leaving estMonitorView(). " + json.totals.requests +
            " request(s).");
  return json;
}

// ---------------------------------------------------------------------------
// POST /admin/est — the four things an operator does to EST by hand.
//
// context: { via: 'console' | 'api', req }
// ---------------------------------------------------------------------------
async function estAction(body, context) {
  log.debug("Entering estAction(). action=" + (body && body.action));
  const ctx = context || {};
  const via = ctx.via === 'console' ? 'console' : 'api';
  const posted = validation.checkParsed(body || {}, 'body', ACTION_BODY);
  if (!posted.ok) {
    log.debug("Leaving estAction(). Malformed.");
    return refused('STS-EST-0031', 400, posted.detail);
  }
  const asked = posted.value;
  const action = String(asked.action || '');
  const actor = actorOf(ctx.req, via);
  const need = function need(names) {
    log.debug("Entering need().");
    const missing = names.filter(function (name) {
      return !asked[name];
    });
    log.debug("Leaving need(). " + missing.length + " missing.");
    return missing.length ? refused('STS-EST-0031', 400, 'The ' + action +
      ' action needs ' + missing.join(', ') + '.') : null;
  };
  let result = null;
  if (action === 'issue-server-key') {
    result = need(['kind', 'identifier']) ||
             await issueServerKey(asked, actor, via);
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
    result = refused('STS-EST-0032', 400, 'Unknown action "' +
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
  log.debug("Leaving estAction(). ok=" + !!(result && result.ok));
  return result;
}

// The console's and the API's "issue a certificate with a server-generated
// key". The principal is an ADMINISTRATOR by construction: the console gate and
// the management API's token gate have both required Admin Write before a POST
// reaches here, and that — not the roster read again — is what authorizes
// naming any entry in the realm.
async function issueServerKey(asked, actor, via) {
  log.debug("Entering issueServerKey().");
  if (config.value('est.serverKeyGeneration') === false) {
    log.debug("Leaving issueServerKey(). Off.");
    return refused('STS-EST-0005', 400, 'Server-side key generation is ' +
                   'turned off for EST in this realm ' +
                   '(est.serverKeyGeneration).');
  }
  const profile = asked.profile || core.defaultProfile(FAMILY);
  const keyAlg = asked.keyAlg || 'ec-p256';
  const described = keyMaterial.keyAlg(keyAlg) || {};
  if (described.kind === 'pqc' && described.use === 'kem' &&
      profile !== 'key-encipherment') {
    log.debug("Leaving issueServerKey(). A KEM key for a signing profile.");
    return refused('STS-EST-0017', 400, 'A ' + keyAlg + ' key is a ' +
                   'key-encapsulation key and can be certified only for ' +
                   'key-encipherment.');
  }
  const principal = core.sessionPrincipal(actor, 'est-' + via,
                                          { admin: true });
  const issued = await core.issueWithServerKey({
    family: FAMILY, profile: profile, principal: principal,
    target: { kind: asked.kind, id: asked.identifier }, keyAlg: keyAlg,
    requested: {}, via: 'est:' + via
  });
  if (!issued.ok) {
    log.debug("Leaving issueServerKey(). Refused.");
    return issued;
  }
  log.debug("Leaving issueServerKey().");
  return {
    ok: true,
    message: 'A ' + profile + ' certificate with a ' + keyAlg + ' key was ' +
             'issued for ' + core.entryUri(issued.target) + '. The private ' +
             'key is shown ONCE; a sealed copy is kept on the entry.',
    target: issued.target,
    keyAlg: keyAlg,
    record: certificateRow(Object.assign({ entry: issued.target,
      entryUri: core.entryUri(issued.target) }, issued.record)),
    certificatePem: issued.record.certificatePem,
    chainPem: issued.record.chainPem || [],
    privateKeyPem: issued.privateKeyPem
  };
}

module.exports = {
  FAMILY: FAMILY,
  EST_ACTIONS: EST_ACTIONS,
  OPERATIONS: OPERATIONS,
  REVOCATION_REASONS: REVOCATION_REASONS,
  estView: estView,
  estMonitorView: estMonitorView,
  estAction: estAction
};
