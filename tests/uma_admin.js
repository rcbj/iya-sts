// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/uma_admin.js
//
// ---------------------------------------------------------------------------
// PROTOCOLS -> UMA AND /admin-api/uma, IN PROCESS (#1168 phase 6, #1195).
//
// The whole stack in a child process, in a throwaway realm with uma.enabled
// on, driving `uma/uma_console.ts` — the view and the acts both doors call —
// and the operations' own handlers:
//
//   V. the view: the resource servers (declared for uma, the protection
//      application left out), the filters, a ticket shown by a hash prefix
//      and never by its value, the settings homed on /admin/uma
//   S. the resource server acts: enable writes uma and the uma_protection
//      grant, twice is no change; disable takes them off and revokes the
//      resource server's RPTs; set-owns-resources
//   R. delete-resource revokes the RPTs over it; revoke-rpt; the refusals
//      carry their codes
//   O. the owner tab: a person's document is read-only; an application that
//      does not own resources is refused; share, unshare, approve, refuse
//      on an application's document
//   W. the what-if: a share permits, a stranger is refused, every layer is
//      reported, and a dry run counts nothing on the monitor
//   P. a person's UMA on /admin-api/users?user=
//   A. the operations: the table carries the nine acts, a failing act is
//      400 with its code, and an application's owner reaches GET /uma?owner=
//      and the owner-* acts as the owner rule's object
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_UMA_ADMIN_CHILD';
const MARK = 'UMA-ADMIN-CHILD ';
const REALM = 'umaadmin';
const SECRET = 'umaadmin-secret-0123456789abcdef';
const PROTECTION = 'urn:sts:uma-protection-api:uma_protection';
const GRANT = 'urn:ietf:params:oauth:grant-type:uma-ticket';

const log = require('bunyan').createLogger({ name: 'uma_admin',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

// A response an operation's handler writes into.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 0, body: '', headers: {}, locals: {} };
  res.status = function (code) {
    res.statusCode = code;
    return res;
  };
  res.type = function () {
    return res;
  };
  res.set = function (name, value) {
    res.headers[String(name).toLowerCase()] = value;
    return res;
  };
  res.setHeader = res.set;
  res.getHeader = function (name) {
    return res.headers[String(name).toLowerCase()];
  };
  res.send = function (text) {
    res.body = String(text);
    return res;
  };
  log.debug("Leaving fakeRes().");
  return res;
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const stats = require(ROOT + '/common/admin_stats');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const store = require(ROOT + '/uma/uma_store');
  const consoleModel = require(ROOT + '/uma/uma_console');
  const monitor = require(ROOT + '/xacml/xacml_monitor');
  const templates = require(ROOT + '/xacml/xacml_templates');
  const adminApi = require(ROOT + '/mgmt-api/admin_api');
  const adminViews = require(ROOT + '/admin-core/admin_views');

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const client = function (id, fields) {
    log.debug("Entering client().");
    log.debug("Leaving client().");
    return applications.createApplication({ identifier: id,
      protocols: ['oauth2'],
      fields: Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
        oauthTokenEndpointAuthMethod: 'client_secret_basic' },
        fields || {}) });
  };
  const now = function () {
    log.debug("Entering now().");
    log.debug("Leaving now().");
    return Math.floor(Date.now() / 1000);
  };
  const umaRow = function () {
    log.debug("Entering umaRow().");
    const row = (monitor.snapshot().rows || []).filter(function (one) {
      return one && one.id === 'uma';
    })[0] || {};
    log.debug("Leaving umaRow().");
    return row;
  };

  await realms.run(realms.get(REALM), async function () {
    config.setOverride('uma.enabled', true);
    ldap.createUser('ua-ann', { invent: false });
    ldap.createUser('ua-bob', { invent: false });
    ldap.createUser('ua-cat', { invent: false });
    const ann = helpers.subjectForName('ua-ann');
    const bob = helpers.subjectForName('ua-bob');
    client('ua-rs', { appAllowedProtocol: ['oauth2', 'uma'],
      umaOwnsResources: 'TRUE', oauthGrantType: ['client_credentials'],
      oauthDelegatedPermission: [PROTECTION] });
    client('ua-plain', { oauthGrantType: ['client_credentials'] });
    client('ua-noown', { appAllowedProtocol: ['oauth2', 'uma'],
      oauthGrantType: ['client_credentials'],
      oauthDelegatedPermission: [PROTECTION] });
    client('ua-client', { oauthGrantType: [GRANT] });
    t.check(/^urn:uuid:/.test(ann) && /^urn:uuid:/.test(bob),
            'setup: three people with subjects');

    // --- V ---------------------------------------------------------------
    let view = consoleModel.view({ query: {} });
    const ids = view.resourceServers.map(function (row) {
      return row.identifier;
    });
    t.check(ids.indexOf('ua-rs') >= 0 && ids.indexOf('ua-noown') >= 0 &&
            ids.indexOf('ua-plain') < 0 &&
            ids.indexOf('sts-uma-protection-api') < 0,
            'V1. the resource servers are the applications declared for ' +
            'uma, the protection API\'s own entry left out', ids.join(','));
    const rs = view.resourceServers.filter(function (row) {
      return row.identifier === 'ua-rs';
    })[0] || {};
    t.check(rs.ownsResources && rs.protectionGranted,
            'V2. ua-rs owns resources and holds uma_protection',
            JSON.stringify(rs));
    t.check(view.enabled === true && view.page === '/admin/uma' &&
            view.settings && JSON.stringify(view.settings)
              .indexOf('uma.enabled') >= 0,
            'V3. enabled, and the uma.* settings are homed on /admin/uma',
            JSON.stringify(view.settings).slice(0, 300));
    const annPhoto = store.saveResource({ owner: ann, ownerKind: 'user',
      resourceServer: 'ua-rs', resource_scopes: ['view', 'edit'],
      name: 'Ann holiday' });
    const appDoc = store.saveResource({ owner: 'ua-rs',
      ownerKind: 'application', resourceServer: 'ua-rs',
      resource_scopes: ['read'], name: 'Service manual' });
    view = consoleModel.view({ query: { resourceServer: 'ua-rs' } });
    t.check(view.resources.total === 2,
            'V4. the resources filtered by resource server',
            view.resources.total);
    view = consoleModel.view({ query: { owner: 'ua-ann' } });
    t.check(view.resources.total === 1 &&
            view.resources.rows[0].id === annPhoto._id &&
            view.resources.rows[0].owner === 'ua-ann',
            'V5. the resources filtered by owner, named by username',
            JSON.stringify(view.resources.rows));
    const ticket = store.issueTicket({ resourceServer: 'ua-rs', owner: ann,
      ownerKind: 'user', permissions: [{ resource_id: annPhoto._id,
        resource_scopes: ['view'] }] }, 300);
    view = consoleModel.view({ query: {} });
    const viewText = JSON.stringify(view);
    t.check(view.tickets.total >= 1 && viewText.indexOf(ticket.value) < 0 &&
            view.tickets.rows[0].key.length === 12,
            'V6. a live ticket is listed by a hash prefix, never its value',
            JSON.stringify(view.tickets.rows[0]));

    // --- S ---------------------------------------------------------------
    let r = consoleModel.act({ action: 'enable-resource-server',
                               application: 'ua-plain' }, { actor: 't' });
    let plain = applications.get('ua-plain') || {};
    t.check(r.ok && r.changed &&
            [].concat(plain.fields.appAllowedProtocol || [])
              .indexOf('uma') >= 0 &&
            [].concat(plain.fields.oauthDelegatedPermission || [])
              .indexOf(PROTECTION) >= 0,
            'S1. enable writes uma and the uma_protection grant',
            JSON.stringify(r));
    r = consoleModel.act({ action: 'enable-resource-server',
                           application: 'ua-plain' }, { actor: 't' });
    t.check(r.ok && !r.changed, 'S2. enabling twice changes nothing',
            JSON.stringify(r));
    const plainRpt = 'ua-rpt-plain-' + now();
    store.saveRpt({ jti: plainRpt, resourceServer: 'ua-plain',
      requestingParty: bob, client: 'ua-client', exp: now() + 600,
      permissions: [] });
    r = consoleModel.act({ action: 'disable-resource-server',
                           application: 'ua-plain' }, { actor: 't' });
    plain = applications.get('ua-plain') || {};
    t.check(r.ok && r.revoked === 1 && stats.isRevoked(plainRpt) &&
            [].concat(plain.fields.appAllowedProtocol || [])
              .indexOf('uma') < 0 &&
            [].concat(plain.fields.oauthDelegatedPermission || [])
              .indexOf(PROTECTION) < 0,
            'S3. disable takes both off and revokes its RPTs',
            JSON.stringify(r));
    r = consoleModel.act({ action: 'set-owns-resources',
                           application: 'ua-plain', value: 'TRUE' });
    plain = applications.get('ua-plain') || {};
    t.check(r.ok && r.ownsResources &&
            String([].concat(plain.fields.umaOwnsResources || [])[0]) ===
              'TRUE', 'S4. set-owns-resources writes umaOwnsResources',
            JSON.stringify(r));
    r = consoleModel.act({ action: 'no-such-act' });
    const r2 = consoleModel.act({ action: 'enable-resource-server',
                                  application: 'ua-nobody' });
    t.check(!r.ok && errorCodes.codeOf(r) === 'STS-UMA-0501' &&
            !r2.ok && errorCodes.codeOf(r2) === 'STS-UMA-0502',
            'S5. an unknown act and an unknown application are refused ' +
            'with their codes', JSON.stringify([r, r2]));

    // --- R ---------------------------------------------------------------
    const photoRpt = 'ua-rpt-photo-' + now();
    store.saveRpt({ jti: photoRpt, resourceServer: 'ua-rs',
      requestingParty: bob, client: 'ua-client', exp: now() + 600,
      permissions: [{ resource_id: annPhoto._id,
                      resource_scopes: ['view'] }] });
    const p = consoleModel.personView('ua-bob');
    t.check(p.held.length === 1 && p.held[0].jti === photoRpt &&
            p.held[0].permissions[0].name === 'Ann holiday',
            'P1. a person\'s held permissions name the resource',
            JSON.stringify(p.held));
    const annView = consoleModel.personView('ua-ann');
    t.check(annView.resources.length === 1 &&
            annView.resources[0].id === annPhoto._id,
            'P2. a person\'s own resources', JSON.stringify(annView));
    const detail = adminViews.umaOf('ua-bob');
    t.check(detail && detail.held.length === 1,
            'P3. /admin-api/users?user= carries the person\'s UMA',
            JSON.stringify(detail));
    r = consoleModel.act({ action: 'delete-resource',
                           resource: annPhoto._id });
    t.check(r.ok && r.revoked === 1 && stats.isRevoked(photoRpt) &&
            !store.resource(annPhoto._id),
            'R1. delete-resource forgets it and revokes the RPT over it',
            JSON.stringify(r));
    const lone = 'ua-rpt-lone-' + now();
    store.saveRpt({ jti: lone, resourceServer: 'ua-rs',
      requestingParty: bob, client: 'ua-client', exp: now() + 600,
      permissions: [] });
    r = consoleModel.act({ action: 'revoke-rpt', rpt: lone });
    t.check(r.ok && stats.isRevoked(lone) && !store.rpt(lone),
            'R2. revoke-rpt revokes one RPT', JSON.stringify(r));
    r = consoleModel.act({ action: 'revoke-rpt', rpt: lone });
    const r3 = consoleModel.act({ action: 'delete-resource',
                                  resource: 'nothing' });
    t.check(errorCodes.codeOf(r) === 'STS-UMA-0505' &&
            errorCodes.codeOf(r3) === 'STS-UMA-0504',
            'R3. a gone RPT and an unknown resource carry their codes',
            JSON.stringify([r, r3]));

    // --- O ---------------------------------------------------------------
    const person = consoleModel.ownerView('ua-ann');
    t.check(person.found && person.kind === 'user' && !person.editable,
            'O1. a person\'s document is read-only here',
            JSON.stringify(person).slice(0, 300));
    r = consoleModel.act({ action: 'owner-share', owner: 'ua-ann',
      resource: appDoc._id, scope: 'read', recipientKind: 'person',
      recipient: 'ua-bob' });
    const r4 = consoleModel.act({ action: 'owner-share', owner: 'ua-noown',
      resource: appDoc._id, scope: 'read', recipientKind: 'person',
      recipient: 'ua-bob' });
    t.check(errorCodes.codeOf(r) === 'STS-UMA-0502' &&
            errorCodes.codeOf(r4) === 'STS-UMA-0506',
            'O2. a person cannot be shared for, nor an application that ' +
            'owns nothing', JSON.stringify([r, r4]));

    // --- W (before the share) ---------------------------------------------
    const before = umaRow();
    let w = consoleModel.whatIf({ resource: appDoc._id, scope: 'read',
                                  party: 'ua-bob', client: 'ua-client' });
    t.check(w.outcome !== 'permit' && w.layers.length >= 1,
            'W1. no share, no permit', JSON.stringify(w));
    r = consoleModel.act({ action: 'owner-share', owner: 'ua-rs',
      resource: appDoc._id, scope: 'read', recipientKind: 'person',
      recipient: 'ua-bob' }, { actor: 't' });
    let doc = consoleModel.ownerView('ua-rs');
    const shareId = doc.document && doc.document.shares &&
      doc.document.shares[0] && doc.document.shares[0].id;
    t.check(r.ok && doc.editable && shareId,
            'O3. an application\'s document takes a share here',
            JSON.stringify([r, doc.document]).slice(0, 400));
    w = consoleModel.whatIf({ resource: appDoc._id, scope: 'read',
                              party: 'ua-bob', client: 'ua-client' });
    t.check(w.outcome === 'permit' &&
            w.layers.map(function (l) {
              return l.layer;
            }).join(',').indexOf('realm,owner') === 0 &&
            w.layers.every(function (l) {
              return l.outcome === 'permit';
            }),
            'W2. with the share, every layer permits, and each is reported',
            JSON.stringify(w));
    w = consoleModel.whatIf({ resource: appDoc._id, scope: 'read',
                              party: 'ua-cat', client: 'ua-client' });
    t.check(w.outcome !== 'permit', 'W3. a stranger is not permitted',
            JSON.stringify(w));
    const after = umaRow();
    t.check((after.decisions || 0) === (before.decisions || 0),
            'W4. a dry run counts nothing on the monitor',
            (before.decisions || 0) + ' then ' + (after.decisions || 0));
    w = consoleModel.whatIf({ resource: appDoc._id, scope: 'write' });
    const w2 = consoleModel.whatIf({ resource: appDoc._id, scope: 'read',
                                     party: 'ua-nobody' });
    t.check(w.problem === 'scope' && w2.problem === 'party',
            'W5. a scope the resource lacks, and a party nobody is, are ' +
            'named rather than asked', JSON.stringify([w, w2]));
    r = consoleModel.act({ action: 'owner-unshare', owner: 'ua-rs',
                           share: shareId });
    doc = consoleModel.ownerView('ua-rs');
    t.check(r.ok && doc.document.shares.length === 0,
            'O4. unshare takes it off', JSON.stringify(r));
    const waiting = store.savePending({ owner: 'ua-rs',
      ownerKind: 'application', requestingParty: bob, requester: 'ua-bob',
      client: 'ua-client', resourceServer: 'ua-rs',
      permissions: [{ resource_id: appDoc._id, resource_scopes: ['read'] }],
      state: 'pending', expiresAt: now() + 600 });
    const refused = store.savePending({ owner: 'ua-rs',
      ownerKind: 'application', requestingParty: bob, requester: 'ua-bob',
      client: 'ua-client', resourceServer: 'ua-rs',
      permissions: [{ resource_id: appDoc._id, resource_scopes: ['read'] }],
      state: 'pending', expiresAt: now() + 600 });
    t.check(consoleModel.view({ query: {} }).pending.total === 2,
            'O5. the requests waiting are listed', '');
    r = consoleModel.act({ action: 'owner-approve', owner: 'ua-rs',
                           pending: waiting.id });
    const r5 = consoleModel.act({ action: 'owner-refuse', owner: 'ua-rs',
                                  pending: refused.id });
    t.check(r.ok && store.pendingOne(waiting.id).state === 'approved' &&
            r5.ok && store.pendingOne(refused.id).state === 'refused',
            'O6. approve and refuse answer an application\'s requests',
            JSON.stringify([r, r5]).slice(0, 300));
    w = consoleModel.whatIf({ resource: appDoc._id, scope: 'read',
                              party: 'ua-bob', client: 'ua-client' });
    t.check(w.outcome === 'permit',
            'O7. the approval is a rule in the document', JSON.stringify(w));

    // --- A ---------------------------------------------------------------
    const routes = adminApi.ROUTES.filter(function (row) {
      return String(row.path || row.route || '').indexOf('/admin-api/uma') ===
        0;
    });
    const post = routes.filter(function (row) {
      return row.method === 'POST';
    })[0] || {};
    t.check(routes.length === 3 && (post.actions || []).map(function (a) {
      return a.action;
    }).sort().join(',') === consoleModel.ACTIONS.slice().sort().join(','),
            'A1. three operations, the POST carrying the nine acts',
            routes.map(function (row) {
              return row.method + ' ' + (row.path || row.route);
            }).join(', '));
    const res = fakeRes();
    post.handler({ method: 'POST', params: { action: 'revoke-rpt' },
                   body: JSON.stringify({ rpt: 'nothing' }), query: {},
                   headers: { 'content-type': 'application/json' } }, res);
    t.check(res.statusCode === 400 &&
            errorCodes.codeOf(res) === 'STS-UMA-0505' &&
            res.body.indexOf('STS-UMA') < 0,
            'A2. a refused act is 400, its code recorded and not sent',
            res.statusCode + ' ' + res.body.slice(0, 200));
    const api = new adminApi.AdminApi(adminApi.AdminApi.defaultDeps());
    const read = api.ownedOperationOf({ method: 'GET',
      path: '/admin-api/uma', query: { owner: 'ua-rs' } });
    const act = api.ownedOperationOf({ method: 'POST',
      path: '/admin-api/uma/owner-share', query: {},
      body: JSON.stringify({ owner: 'ua-rs' }),
      headers: { 'content-type': 'application/json' } });
    const notOwners = api.ownedOperationOf({ method: 'POST',
      path: '/admin-api/uma/delete-resource', query: {},
      body: JSON.stringify({ resource: 'x' }),
      headers: { 'content-type': 'application/json' } });
    t.check(read && read.kind === 'application' && read.id === 'ua-rs' &&
            read.action === 'read' && act && act.action === 'owner-share' &&
            act.id === 'ua-rs' && notOwners === null,
            'A3. an owner reaches GET /uma?owner= and the owner-* acts on ' +
            'the application, and nothing else of the page',
            JSON.stringify([read, act, notOwners]));
    const projected = read && read.project
      ? read.project({ owner: { owner: 'ua-rs' }, rpts: { rows: [1] } }) : {};
    t.check(projected.owner && projected.rpts === undefined,
            'A4. an owner is answered with the owner tab alone',
            JSON.stringify(projected));
    const parameter = (templates.lookup('access-control').parameters || [])
      .filter(function (one) {
        return one.name === 'ownerApplicationActions';
      })[0] || {};
    t.check(['owner-share', 'owner-unshare', 'owner-approve',
             'owner-refuse'].every(function (name) {
      return String(parameter.dflt || '').indexOf(name) >= 0;
    }), 'A5. the owner rule lets an application\'s owners take the four ' +
        'owner-* acts by default', parameter.dflt);
  });

  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath,
    process.execArgv.concat([__filename]), {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== Protocols -> UMA and /admin-api/uma (#1168, #1195) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'uma_admin',
  describe: 'Protocols -> UMA and /admin-api/uma (#1168 phase 6): the ' +
            'view, the resource server acts, deletion and revocation, an ' +
            'application owner\'s document, the dry-run what-if, a ' +
            'person\'s UMA, and the operations with the owner rule',
  run: run
};
