// @ts-check
'use strict';
//
// File: gnap_console.js
//
// ---------------------------------------------------------------------------
// WHAT THE TWO GNAP CONSOLE PAGES AND THEIR MANAGEMENT API OPERATIONS READ AND
// DO — ONE MODEL, TWO DOORS.
//
// Rule 7 says a console page and its `/admin-api` operation cannot disagree,
// and `admin-core/` is where that is made structural for the older families: a
// VIEW computes the facts once and both doors render them, an ACTION changes
// state once and both doors report it. This file is the same arrangement for
// GNAP, kept beside the protocol rather than added to `admin-core/`'s two large
// files — for the same reason `xacml/xacml_admin.js` draws its own pages: the
// knowledge of what a grant IS lives in `gnap/`, and a view in another
// directory reading this family's stores field by field is a second place for
// that knowledge to go stale.
//
// It holds `admin-core/`'s properties exactly, and
// `tests/admin_actions_layer.js`'s reasoning applies to it: **no route, no
// `res`, no markup**, and a view reads nothing from the request but its query.
// `gnap_admin.js` draws the markup and `mgmt-api/admin_api.js` sends the JSON,
// both out of the SAME call.
//
//   GET  /admin/gnap           gnapView()         Protocols -> GNAP
//   GET  /admin/gnap/monitor   gnapMonitorView()  Monitoring -> GNAP grants
//   POST /admin/gnap           gnapAction()       revoke-grant, delete-resource-set
// ---------------------------------------------------------------------------

const config = require('../common/config');
const { log, baseUrlOf, nowSec } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const applications = require('../common/applications');
const audit = require('../common/audit');
const authorizationServers = require('../oauth-oidc/authorization_servers');
const adminViews = require('../admin-core/admin_views');
const store = require('./gnap_store');
const grants = require('./gnap_grants');
const tokens = require('./gnap_tokens');
const monitor = require('./gnap_monitor');

const GNAP_ACTIONS = ['revoke-grant', 'delete-resource-set'];

const STATES = ['processing', 'pending', 'approved', 'finalized'];

function refused(code, result) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return errorCodes.mark(result, code);
}

function settingsJson() {
  log.debug("Entering settingsJson().");
  const group = config.groups().filter(function (one) {
    return one.group === 'GNAP';
  })[0];
  log.debug("Leaving settingsJson().");
  return group ? group.settings : [];
}

function grantRow(grant) {
  log.debug("Entering grantRow().");
  log.debug("Leaving grantRow().");
  return {
    id: grant.id,
    state: grant.state,
    authorizationServer: grant.as,
    grantEndpoint: grant.grantEndpoint,
    client: grant.client ? grant.client.identifier : null,
    proof: grant.client ? grant.client.proof : null,
    resourceOwner: grant.ro ? grant.ro.username : null,
    decision: grant.decision ?
              (grant.decision.approved ? 'approved' :
               grant.decision.error || 'denied')
                             : null,
    interaction: grant.interaction ? {
      modes: Object.keys(grant.interaction.modes || {}),
      finish: grant.interaction.finish ? grant.interaction.finish.method : null,
      started: grant.interaction.started || null,
      expiresAt: grant.interaction.expiresAt || null
    } : null,
    tokens: (grant.tokens || []).length,
    derivedFrom: grant.derivedFrom || null,
    createdAt: grant.createdAt,
    updatedAt: grant.updatedAt,
    history: (grant.history || []).slice(-10)
  };
}

function resourceRow(row) {
  log.debug("Entering resourceRow().");
  log.debug("Leaving resourceRow().");
  return {
    reference: row.reference,
    resourceServer: row.rsIdentifier,
    access: row.access,
    tokenFormats: row.tokenFormats || null,
    introspectionRequired: !!row.introspectionRequired,
    createdAt: row.createdAt
  };
}

// ---------------------------------------------------------------------------
// GET /admin/gnap — what the authorization server IS: its endpoints, its
// capabilities per authorization server profile, the token formats and their
// verification material, the grants it is holding and the resource sets
// registered with it, and its settings.
// ---------------------------------------------------------------------------
function gnapView(req) {
  log.debug("Entering gnapView().");
  const query = (req && req.query) || {};
  const base = baseUrlOf(req);
  const wantedState = STATES.indexOf(String(query.state || '')) >= 0 ?
                      String(query.state) : '';
  const allGrants = store.listGrants().filter(function (grant) {
    return !wantedState || grant.state === wantedState;
  });
  const grantPaging = adminViews.pagingOf(query, allGrants.length,
                                          { name: 'grants', noun: 'grants' });
  const resources = store.listResources();
  const resourcePaging = adminViews.pagingOf(query, resources.length,
                                             { name: 'resources',
                                               noun: 'resource ' +
                                                 'sets' });
  const profiles = authorizationServers.list().map(function (profile) {
    return { id: profile.id, label: profile.label || '',
             capabilities: grants.capabilities(req, profile.id) };
  });
  let material = {};
  try {
    material = tokens.publicMaterial(base);
  } catch (e) {
    // A realm with no Ed25519 key yet (it is generated on first use). The page
    // says the material is not available rather than failing to draw.
    log.debug("gnapView(): verification material is not available: " +
              e.message);
  }
  const json = {
    page: '/admin/gnap',
    title: 'GNAP',
    enabled: config.value('gnap.enabled') !== false,
    specifications: ['RFC 9635', 'RFC 9767', 'RFC 9421', 'RFC 9530',
                     'RFC 9493'],
    endpoints: {
      grant: base + '/gnap',
      discovery: 'OPTIONS ' + base + '/gnap',
      rsDiscovery: base + '/.well-known/gnap-as-rs',
      continuation: base + '/gnap/continue/{grant}',
      tokenManagement: base + '/gnap/token/{handle}',
      introspection: base + '/gnap/introspect',
      resourceRegistration: base + '/gnap/resource',
      userCode: base + '/gnap/code',
      keys: base + '/gnap/keys',
      zcapController: base + '/gnap/zcap/controller',
      demonstrationResourceServer: base + '/gnap/rs/resource'
    },
    capabilities: grants.capabilities(req, null),
    authorizationServers: profiles,
    tokenFormats: tokens.FORMATS,
    verificationMaterial: material,
    grants: {
      state: wantedState || null,
      states: STATES,
      paging: adminViews.pagingJson(grantPaging),
      rows: allGrants.slice(grantPaging.offset,
                            grantPaging.offset + grantPaging.perPage)
                     .map(grantRow)
    },
    resourceSets: {
      paging: adminViews.pagingJson(resourcePaging),
      rows: resources.slice(resourcePaging.offset,
                            resourcePaging.offset + resourcePaging.perPage)
        .map(resourceRow)
    },
    actions: GNAP_ACTIONS,
    settings: settingsJson()
  };
  log.debug("Leaving gnapView(). " + allGrants.length + " grant(s).");
  return json;
}

// ---------------------------------------------------------------------------
// GET /admin/gnap/monitor — the applications that use GNAP and what each has
// done. "An application that uses GNAP" is an application entry DECLARED for
// the family, or one whose kinds say it spoke it, or one with a counter row —
// the union, because an entry an operator provisioned and nobody has used yet
// is exactly what somebody looking at this page wants to see is idle.
// ---------------------------------------------------------------------------
function gnapMonitorView(req) {
  log.debug("Entering gnapMonitorView().");
  const query = (req && req.query) || {};
  const snapshot = monitor.snapshot();
  const byId = {};
  grants.gnapApplications().forEach(function (app) {
    byId[app.identifier] = app;
  });
  Object.keys(snapshot.rows).forEach(function (id) {
    if (!byId[id]) {
      byId[id] = applications.get(id) ||
                 { identifier: id, name: null, kinds: [], registered: false };
    }
  });
  const liveTokens = store.listTokens();
  const now = nowSec();
  const rows = Object.keys(byId).sort().map(function (id) {
    const app = byId[id];
    const counted = snapshot.rows[id] || snapshot.blank;
    const mine = store.listGrants().filter(function (grant) {
      return grant.client && grant.client.identifier === id;
    });
    const active = liveTokens.filter(function (record) {
      return record.instanceId === id && !record.revoked &&
             (!record.exp || record.exp > now);
    }).length;
    return {
      identifier: id,
      name: app.name || null,
      kinds: app.kinds || [],
      role: (app.kinds || []).indexOf(grants.KIND_RS) >= 0
        ? ((app.kinds || []).indexOf(grants.KIND_CLIENT) >= 0 ? 'client and ' +
            'resource server' : 'resource ' +
            'server')
        : 'client',
      registered: !!app.registered,
      finishUris: grants.fieldValues(app, 'gnapFinishUri'),
      webApplication: grants.fieldValues(app, 'gnapFinishUri').length > 0,
      grantsHeld: { total: mine.length,
                    pending: mine.filter(function (
                        g) { return g.state === 'pending'; }).length,
                    approved: mine.filter(function (
                        g) { return g.state === 'approved'; }).length,
                    finalized: mine.filter(function (
                        g) { return g.state === 'finalized'; }).length },
      activeTokens: active,
      counters: counted,
      lastAt: counted.lastAt,
      lastEvent: counted.lastEvent
    };
  });
  const paging = adminViews.pagingOf(query, rows.length,
                                     { noun: 'applications' });
  const totals = {};
  snapshot.events.forEach(function (event) {
    totals[event.counter] = 0;
  });
  const formats = {};
  snapshot.formats.forEach(function (format) {
    formats[format] = 0;
  });
  rows.forEach(function (row) {
    Object.keys(totals).forEach(function (counter) {
      totals[counter] += Number(row.counters[counter] || 0);
    });
    Object.keys(formats).forEach(function (format) {
      formats[format] += Number((row.counters.formats || {})[format] || 0);
    });
  });
  const json = {
    page: '/admin/gnap/monitor',
    title: 'GNAP grants',
    since: snapshot.startedAt,
    events: snapshot.events,
    totals: totals,
    tokensByFormat: formats,
    applications: rows.length,
    paging: adminViews.pagingJson(paging),
    rows: rows.slice(paging.offset, paging.offset + paging.perPage)
  };
  log.debug("Leaving gnapMonitorView(). " + rows.length + " application(s).");
  return json;
}

// ---------------------------------------------------------------------------
// POST /admin/gnap — the two things an operator does to GNAP state by hand.
//
// **Revoking a grant is the client's section 5.4 act performed by an
// operator**, and it goes through the same path — the grant's tokens revoked,
// the grant finalized, CAEP told — rather than a delete, so what the client
// sees next is exactly what it would see had it revoked the grant itself. A
// resource set is deleted outright: its reference stops resolving, which is the
// operator's intent, and tokens already issued against it keep the rights they
// carry.
// ---------------------------------------------------------------------------
function gnapAction(body, context) {
  log.debug("Entering gnapAction(). action=" + (body && body.action));
  const ctx = context || {};
  const action = String((body && body.action) || '');
  const actor = String(ctx.actor || '');
  if (action === 'revoke-grant') {
    const id = String(body.grant || '').trim();
    const grant = id ? store.getGrant(id) : null;
    if (!grant) {
      log.debug("Leaving gnapAction(). No such grant.");
      return refused('STS-GNAP-0660', { ok: false, errors: ['There is no ' +
          'grant "' + id + '" ' +
                     'in this realm. Name one from the list on ' +
                     '/admin/gnap.'] });
    }
    if (grant.state === store.STATE.FINALIZED) {
      log.debug("Leaving gnapAction(). Already finalized.");
      return { ok: true, grant: grantRow(grant), message: 'The grant was ' +
          'already finalized; nothing changed.' };
    }
    grants.revokeTokens(grant, 'grant revoked by an administrator');
    grant.state = store.STATE.FINALIZED;
    store.dropContinuation(grant);
    store.saveGrant(grant,
                    'revoked by an administrator' +
                    (actor ? ' (' + actor + ')' : ''));
    monitor.record(grant.client.identifier, 'grant.revoked', {});
    audit.audit({ action: 'gnap.grant.revoke', category: 'protocol',
      protocol: 'GNAP',
      channel: 'http', outcome: 'success', actor: actor,
      target: grant.client.identifier,
      summary: 'An administrator revoked a GNAP grant',
      detail: { grant: grant.id, via: ctx.via || '',
                tokens: (grant.tokens || []).length } });
    try {
      require('./gnap_signals').grantRevoked(ctx.req || null, grant, 'An ' +
          'administrator revoked the grant.');
    } catch (e) {
      // The revocation is done; a signal that could not be sent is logged by
      // gnap_signals itself and must not undo the answer.
      log.debug("gnapAction(): the CAEP signal could not be started: " +
                e.message);
    }
    log.debug("Leaving gnapAction(). Revoked.");
    return { ok: true, grant: grantRow(grant),
             message: 'Grant ' + grant.id + ' is finalized and its ' +
                      (grant.tokens || []).length +
                      ' token(s) are revoked.' };
  }
  if (action === 'delete-resource-set') {
    const reference = String(body.reference || '').trim();
    const row = reference ? store.resourceByReference(reference) : null;
    if (!row) {
      log.debug("Leaving gnapAction(). No such resource set.");
      return refused('STS-GNAP-0661', { ok: false, errors: ['There is no ' +
          'registered resource set "' +
                     reference + '" in this realm.'] });
    }
    store.deleteResource(reference);
    audit.audit({ action: 'gnap.rs.register', category: 'protocol',
      protocol: 'GNAP', channel: 'http',
      outcome: 'success', actor: actor, target: row.rsIdentifier,
      summary: 'An administrator deleted a GNAP resource set',
      detail: { reference: reference, via: ctx.via || '' } });
    log.debug("Leaving gnapAction(). Deleted.");
    return { ok: true, reference: reference,
             message: 'The resource set ' + reference + ' ' +
             'is deleted; the reference no longer resolves in a grant ' +
             'request.' };
  }
  log.debug("Leaving gnapAction(). Unknown action.");
  return refused('STS-GNAP-0662',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The two are: ' +
                 GNAP_ACTIONS.join(', ') + '.'] });
}

module.exports = {
  GNAP_ACTIONS: GNAP_ACTIONS,
  STATES: STATES,
  gnapView: gnapView,
  gnapMonitorView: gnapMonitorView,
  gnapAction: gnapAction
};
