// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/uma_grant.js
//
// ---------------------------------------------------------------------------
// THE UMA 2.0 GRANT, IN PROCESS (#1168 phase 4, #1193).
//
// The whole stack in a child process, on a plain listener, in a throwaway
// realm with uma.enabled on: a resource server that owns its resources
// (umaOwnsResources) and registers them with a real PAT, a client that
// registered the uma-ticket grant, and a requesting party known through a
// PCT. Each check is named for its line of #1168's section 7 where it is
// one:
//
//   G. the grant: no share is no consent (request_denied); a share issues
//      an RPT — aud the resource server, a permissions claim, no scope;
//      nobody known is need_info with a rotated ticket and required_claims;
//      excess permissions are dropped (partial RPT), or refused with
//      uma.partialRpt off; the wrong client and a spent ticket are
//      invalid_grant; a stray scope is invalid_scope.
//   F. FGA: off, UMA's own requirements still apply; on with the default
//      permit, no share is still no consent; on with a Deny, an owner's
//      Permit does not override it.
//   I. the issuance gate refusing the RPT as a token is request_denied.
//   N. introspection with the PAT: permissions, no scope; another resource
//      server's PAT sees it inactive; an owner's withdrawal ends it.
//   U. upgrade gains only what is decided again, revokes the old RPT, and
//      refuses another resource server's RPT.
//   X. a PDP fault is server_error, never a permit; an undischargeable
//      obligation refuses.
//   R. a PCT revoked at /oauth2/revoke; the discovery document advertises
//      the grant.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const http = require('http');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_UMA_GRANT_CHILD';
const MARK = 'UMA-GRANT-CHILD ';
const REALM = 'umagrant';
const PREFIX = '/realm/' + REALM;
const SECRET = 'umagrant-secret-0123456789abcdef';
const PROTECTION = 'urn:sts:uma-protection-api:uma_protection';

const GRANT = 'urn:ietf:params:oauth:grant-type:uma-ticket';

const log = require('bunyan').createLogger({ name: 'uma_grant',
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

function request(port, method, urlPath, body, headers) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const text = body === undefined ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const sent = Object.assign({ 'content-type': 'application/json',
                                 'content-length': Buffer.byteLength(text) },
                               headers || {});
    const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
      method: method, headers: sent, agent: false }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: raw,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end(text);
  });
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const store = require(ROOT + '/uma/uma_store');
  const owner = require(ROOT + '/uma/uma_owner_policy');
  const fga = require(ROOT + '/xacml/fga_policies');
  const xstore = require(ROOT + '/xacml/xacml_store');
  const xml = require(ROOT + '/xacml/xacml_xml');
  const templates = require(ROOT + '/xacml/xacml_templates');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };

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
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  const client = function (id, fields) {
    log.debug("Entering client().");
    log.debug("Leaving client().");
    return applications.createApplication({ identifier: id,
      protocols: ['oauth2'],
      fields: Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
        oauthTokenEndpointAuthMethod: 'client_secret_basic' },
        fields || {}) });
  };
  let bob = '';
  let cat = '';
  inRealm(function () {
    config.setOverride('uma.enabled', true);
    ldap.createUser('ug-bob', { invent: false });
    ldap.createUser('ug-cat', { invent: false });
    bob = helpers.subjectForName('ug-bob');
    cat = helpers.subjectForName('ug-cat');
    client('ug-rs', { appAllowedProtocol: ['oauth2', 'uma'],
      umaOwnsResources: 'TRUE', oauthGrantType: ['client_credentials'],
      oauthDelegatedPermission: [PROTECTION] });
    client('ug-rs2', { appAllowedProtocol: ['oauth2', 'uma'],
      umaOwnsResources: 'TRUE', oauthGrantType: ['client_credentials'],
      oauthDelegatedPermission: [PROTECTION] });
    client('ug-client', { oauthGrantType: [GRANT] });
    client('ug-other', { oauthGrantType: [GRANT] });
    client('ug-undeclared', { oauthGrantType: ['client_credentials'] });
  });
  t.check(/^urn:uuid:/.test(bob), 'setup: a requesting party, ug-bob');

  const server = http.createServer(app);
  await new Promise(function (ok) {
    server.listen(0, '127.0.0.1', ok);
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port + PREFIX;
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 300);
  };
  const basic = function (id) {
    log.debug("Entering basic().");
    log.debug("Leaving basic().");
    return 'Basic ' + Buffer.from(id + ':' + SECRET).toString('base64');
  };
  const form = function (fields) {
    log.debug("Entering form().");
    log.debug("Leaving form().");
    return Object.keys(fields).filter(function (k) {
      return fields[k] !== undefined;
    }).map(function (k) {
      return k + '=' + encodeURIComponent(fields[k]);
    }).join('&');
  };
  const token = async function (id, fields) {
    log.debug("Entering token(). " + id);
    const r = await request(port, 'POST', PREFIX + '/oauth2/token',
      form(fields), { 'content-type': 'application/x-www-form-urlencoded',
                      authorization: basic(id) });
    log.debug("Leaving token(). " + r.status);
    return r;
  };
  const patOf = async function (id) {
    log.debug("Entering patOf().");
    const r = await token(id, { grant_type: 'client_credentials',
                                scope: 'uma_protection',
                                resource: base + '/uma' });
    log.debug("Leaving patOf().");
    return r.json && r.json.access_token;
  };
  const pat = await patOf('ug-rs');
  const pat2 = await patOf('ug-rs2');
  t.check(!!pat && !!pat2, 'setup: two resource servers hold PATs');
  const bearer = function (value) {
    log.debug("Entering bearer().");
    log.debug("Leaving bearer().");
    return { authorization: 'Bearer ' + value };
  };
  const register = async function (rsPat, scopes, extra) {
    log.debug("Entering register().");
    const r = await request(port, 'POST', PREFIX + '/uma/rreg',
      Object.assign({ resource_scopes: scopes }, extra || {}),
      bearer(rsPat));
    log.debug("Leaving register().");
    return r.json && r.json._id;
  };
  const photo = await register(pat, ['view', 'edit', 'print'],
                               { name: 'Photo', type: 'photo' });
  const other = await register(pat2, ['view']);
  t.check(!!photo && !!other, 'setup: resources registered with the PATs');
  const ticketFor = async function (rsPat, permissions) {
    log.debug("Entering ticketFor().");
    const r = await request(port, 'POST', PREFIX + '/uma/perm', permissions,
                            bearer(rsPat));
    log.debug("Leaving ticketFor().");
    return r.json && r.json.ticket;
  };
  const pctFor = function (subject, clientId) {
    log.debug("Entering pctFor().");
    log.debug("Leaving pctFor().");
    return inRealm(function () {
      return store.issuePct({ requestingParty: subject, client: clientId,
                              claims: {} }, 3600).value;
    });
  };
  const bobPct = pctFor(bob, 'ug-client');
  const ask = async function (id, fields) {
    log.debug("Entering ask().");
    const r = await token(id, Object.assign({ grant_type: GRANT }, fields));
    log.debug("Leaving ask().");
    return r;
  };
  const claimsOf = function (jwt) {
    log.debug("Entering claimsOf().");
    try {
      log.debug("Leaving claimsOf().");
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in claimsOf(): " + e.message);
      return {};
    }
  };

  // --- G. the grant -------------------------------------------------------
  let since = marks.length;
  let r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  t.check(r.status === 403 && r.json && r.json.error === 'request_denied' &&
          markedSince(since, 'STS-UMA-0210'),
          'G1. FGA disabled, UMA enabled: with no owner document there is ' +
          'no consent — request_denied', brief(r));
  const share = inRealm(function () {
    return owner.share('ug-rs', { resource: photo, scopes: ['view', 'print'],
                                  recipientKind: 'person',
                                  recipient: 'ug-bob' });
  });
  t.check(share && share.ok, 'setup: the owner shares view and print with ' +
          'ug-bob', JSON.stringify(share));
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  const rpt = r.json && r.json.access_token;
  const rc = claimsOf(rpt);
  const rptRow = inRealm(function () {
    return store.rpt(rc.jti);
  });
  t.check(r.status === 200 && !!rpt && rc.scope === undefined &&
          JSON.stringify(rc.permissions) ===
            JSON.stringify([{ resource_id: photo,
                              resource_scopes: ['view'] }]) &&
          [].concat(rc.aud).indexOf('ug-rs') >= 0 && rc.sub === bob &&
          !r.json.refresh_token && rptRow && rptRow.client === 'ug-client' &&
          rptRow.requestingParty === bob,
          'G2. a share issues an RPT: aud the resource server, a ' +
          'permissions claim, no scope, no refresh token, recorded in ' +
          'uma.rpts', brief(r) + ' ' + JSON.stringify(rc));
  t.check(Number(rc.exp) - Number(rc.iat) <= 600,
          'G3. no longer than uma.rptLifetimeS', rc.exp - rc.iat);
  const first = await ticketFor(pat, { resource_id: photo,
                                       resource_scopes: ['view'] });
  since = marks.length;
  r = await ask('ug-client', { ticket: first });
  const rotated = r.json && r.json.ticket;
  t.check(r.status === 403 && r.json.error === 'need_info' && !!rotated &&
          rotated !== first && markedSince(since, 'STS-UMA-0209') &&
          r.json.required_claims[0].name ===
            'urn:oasis:names:tc:xacml:1.0:subject:subject-id' &&
          /IDToken$/.test(r.json.required_claims[0].claim_token_format[0]),
          'G4. nobody known is need_info, with a NEW ticket and the missing ' +
          'subject-id in required_claims', brief(r));
  since = marks.length;
  r = await ask('ug-other', { ticket: rotated, pct: bobPct });
  t.check(r.status === 400 && r.json.error === 'invalid_grant' &&
          markedSince(since, 'STS-UMA-0203'),
          'G5. a valid ticket presented by the wrong client fails',
          brief(r));
  since = marks.length;
  r = await ask('ug-client', { ticket: first, pct: bobPct });
  t.check(r.status === 400 && r.json.error === 'invalid_grant',
          'G6. a ticket already used (rotated away) fails', brief(r));
  const excess = await ticketFor(pat, { resource_id: photo,
                                        resource_scopes: ['view', 'edit'] });
  r = await ask('ug-client', { ticket: excess, pct: bobPct });
  const ec = claimsOf(r.json && r.json.access_token);
  t.check(r.status === 200 && ec.permissions &&
          ec.permissions[0].resource_scopes.join() === 'view',
          'G7. requested permissions exceeding the owner\'s grant: the RPT ' +
          'does not include the excess (a partial RPT)', brief(r));
  inRealm(function () {
    config.setOverride('uma.partialRpt', false);
  });
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view', 'edit'] }),
    pct: bobPct });
  inRealm(function () {
    config.setOverride('uma.partialRpt', true);
  });
  t.check(r.status === 403 && r.json.error === 'request_denied',
          'G8. with uma.partialRpt off, any refused permission refuses all',
          brief(r));
  since = marks.length;
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct,
    scope: 'delete' });
  t.check(r.status === 400 && r.json.error === 'invalid_scope' &&
          markedSince(since, 'STS-UMA-0205'),
          'G9. a scope matching no resource in the ticket is invalid_scope',
          brief(r));
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct,
    scope: 'print' });
  t.check(r.status === 200 && claimsOf(r.json.access_token).permissions[0]
            .resource_scopes.join() === 'view,print',
          'G10. section 3.3.4: a scope the resource was registered with is ' +
          'added to the ticket\'s', brief(r));
  const undeclaredPct = pctFor(bob, 'ug-undeclared');
  r = await ask('ug-undeclared', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }),
    pct: undeclaredPct });
  t.check(r.status === 400 || (r.status === 403 &&
          r.json.error === 'request_denied'),
          'G11. a client that did not register the UMA grant is refused',
          brief(r));
  const catPct = pctFor(cat, 'ug-client');
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: catPct });
  t.check(r.status === 403 && r.json.error === 'request_denied',
          'G12. somebody the owner did not share with is denied', brief(r));

  // --- N. introspection with the PAT ---------------------------------------
  const introspect = async function (rsPat, value) {
    log.debug("Entering introspect().");
    const out = await request(port, 'POST', PREFIX + '/oauth2/introspect',
      form({ token: value }),
      Object.assign({ 'content-type': 'application/x-www-form-urlencoded' },
                    bearer(rsPat)));
    log.debug("Leaving introspect().");
    return out;
  };
  r = await introspect(pat, rpt);
  t.check(r.status === 200 && r.json.active === true &&
          r.json.scope === undefined && r.json.permissions &&
          r.json.permissions[0].resource_id === photo &&
          r.json.permissions[0].exp > 0,
          'N1. introspection with the PAT answers permissions and no scope',
          brief(r));
  r = await introspect(pat2, rpt);
  t.check(r.status === 200 && r.json.active === false,
          'N2. another resource server\'s PAT sees it inactive', brief(r));
  r = await introspect('not-a-pat', rpt);
  t.check(r.status === 401, 'N3. a PAT that does not verify is 401',
          brief(r));
  // KEYCLOAK'S WAY (#1196, rcbj 2026-10-30): keycloak-authz-client
  // introspects an RPT with its client credentials and the hint
  // `requesting_party_token`. The hint is ignored (RFC 7662 section 2.1),
  // and the resource server the RPT was issued for is answered its
  // permissions as the PAT door answers them; another client is not.
  const asClient = async function (id) {
    log.debug("Entering asClient().");
    const out = await request(port, 'POST', PREFIX + '/oauth2/introspect',
      'token=' + encodeURIComponent(rpt) +
      '&token_type_hint=requesting_party_token',
      { 'content-type': 'application/x-www-form-urlencoded',
        authorization: basic(id) });
    log.debug("Leaving asClient().");
    return out;
  };
  r = await asClient('ug-rs');
  t.check(r.status === 200 && r.json.active === true &&
          Array.isArray(r.json.permissions) &&
          r.json.permissions[0].resource_id === photo &&
          r.json.scope === undefined,
          'N6. the RPT\'s resource server, introspecting with its client ' +
          'credentials and Keycloak\'s hint, is answered the permissions',
          brief(r));
  r = await asClient('ug-rs2');
  t.check(r.status === 200 && r.json.permissions === undefined,
          'N7. another client\'s credentials are answered no permissions',
          brief(r));

  // --- U. upgrade ------------------------------------------------------------
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['print'] }), pct: bobPct,
    rpt: rpt });
  const up = claimsOf(r.json && r.json.access_token);
  const oldGone = await introspect(pat, rpt);
  t.check(r.status === 200 && r.json.upgraded === true &&
          up.permissions[0].resource_scopes.sort().join() === 'print,view' &&
          oldGone.json.active === false,
          'U1. an upgrade adds what is decided again, says upgraded, and ' +
          'revokes the old RPT', brief(r));
  since = marks.length;
  const otherRpt = r.json.access_token;
  r = await ask('ug-client', { ticket: await ticketFor(pat2,
    { resource_id: other, resource_scopes: ['view'] }), pct: bobPct,
    rpt: otherRpt });
  t.check(r.status === 400 && markedSince(since, 'STS-UMA-0204'),
          'U2. an RPT of another resource server cannot be upgraded with ' +
          'this ticket', brief(r));

  // --- Z. AuthZEN at access time (#1196, rcbj 2026-10-30) ------------------
  // A resource server asking /access/v1/evaluation about a registered UMA
  // resource gets UMA's CURRENT answer; the decision itself is asked here,
  // through the surface's own decideEvaluation(), since the door's mutual
  // TLS is the protocol job's.
  const authzen = require(ROOT + '/authzen/authzen');
  const az = new authzen.AuthzenSurface(authzen.AuthzenSurface.defaultDeps());
  const accessOf = function (who, scope, id) {
    log.debug("Entering accessOf().");
    const decided = inRealm(function () {
      return az.decideEvaluation({
        subject: { type: 'user', id: who }, action: { name: scope },
        resource: { type: 'uma_resource', id: id || photo }, context: {} },
        'caller', 'ug-rs');
    });
    log.debug("Leaving accessOf().");
    return decided.outcome || {};
  };
  t.check(accessOf('ug-bob', 'view').decision === true &&
          accessOf('ug-cat', 'view').decision === false &&
          accessOf('ug-bob', 'no-such-scope').decision === false,
          'Z1. AuthZEN about a UMA resource answers the owner\'s share: the ' +
          'party true, a stranger and a scope it lacks false',
          JSON.stringify([accessOf('ug-bob', 'view'),
                          accessOf('ug-cat', 'view')]));
  const elsewhere = inRealm(function () {
    return az.decideEvaluation({ subject: { type: 'user', id: 'ug-bob' },
      action: { name: 'view' }, resource: { type: 'uma_resource',
      id: photo }, context: {} }, 'caller', 'ug-rs2').outcome;
  });
  t.check(elsewhere.decision === false,
          'Z2. asked by another resource server, false',
          JSON.stringify(elsewhere));

  // --- N4. the owner withdraws: the RPT ends --------------------------------
  inRealm(function () {
    owner.unshare('ug-rs', share.share.id);
  });
  t.check(accessOf('ug-bob', 'view').decision === false,
          'Z3. after the owner withdraws, AuthZEN answers false at once',
          JSON.stringify(accessOf('ug-bob', 'view')));
  r = await introspect(pat, otherRpt);
  t.check(r.status === 200 && r.json.active === false,
          'N4. a resource owner revokes a share: the RPT that carried it is ' +
          'inactive', brief(r));
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  t.check(r.status === 403 && r.json.error === 'request_denied',
          'N5. and the next request is denied', brief(r));

  // --- F. FGA ------------------------------------------------------------
  inRealm(function () {
    owner.share('ug-rs', { resource: photo, scopes: ['view'],
                           recipientKind: 'person', recipient: 'ug-bob' });
    fga.enable('ug-rs');
  });
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['edit'] }), pct: bobPct });
  t.check(r.status === 403 && r.json.error === 'request_denied',
          'F1. FGA enabled with the default-permit policy: an absent UMA ' +
          'share does not become consent', brief(r));
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  t.check(r.status === 200, 'F2. FGA default-permit and a share: issued',
          brief(r));
  let denyWrite = null;
  inRealm(function () {
    const state = fga.state('ug-rs');
    const deny = { kind: 'Policy', id: templates.fgaPolicyId('ug-rs'),
      version: '2.0', description: 'deny all',
      combiningAlgId: 'urn:oasis:names:tc:xacml:3.0:rule-combining-' +
                      'algorithm:deny-unless-permit',
      target: null, variables: {}, rules: [], obligations: [], advice: [] };
    denyWrite = { state: state,
                  wrote: xstore.write(state.policy.name, xml.writePolicy(deny),
                                      { enabled: true }) };
  });
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  t.check(r.status === 403 && r.json.error === 'request_denied',
          'F3. FGA enabled with a custom deny policy: an owner\'s share does ' +
          'not override the FGA denial', brief(r) + ' ' +
          JSON.stringify(denyWrite).slice(0, 400));
  inRealm(function () {
    fga.disable('ug-rs');
  });

  // --- I. the issuance gate ------------------------------------------------
  inRealm(function () {
    applications.updateApplication('ug-client', { mode: 'add',
      attribute: 'appRequiredRole', value: 'nobody-holds-this' });
  });
  since = marks.length;
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  inRealm(function () {
    applications.updateApplication('ug-client', { mode: 'remove',
      attribute: 'appRequiredRole', value: 'nobody-holds-this' });
  });
  t.check(r.status === 403 && r.json.error === 'request_denied' &&
          markedSince(since, 'STS-UMA-0217'),
          'I1. coarse-grained token issuance denied: an otherwise valid UMA ' +
          'authorization does not produce an RPT', brief(r));

  // --- X. faults and obligations -------------------------------------------
  inRealm(function () {
    xstore.write('uma-authorization', xml.writePolicy(templates.build(
      'uma-authorization', {}, { name: 'uma-authorization' }).policy),
      { enabled: false });
  });
  since = marks.length;
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  inRealm(function () {
    xstore.remove('uma-authorization');
  });
  t.check(r.status === 500 && r.json.error === 'server_error' &&
          markedSince(since, 'STS-UMA-0211'),
          'X1. the XACML policy unavailable (a disabled realm entry): no ' +
          'default-permit substitute — server_error', brief(r));
  inRealm(function () {
    const doc = owner.documentOf('ug-rs').policy;
    doc.rules.forEach(function (rule) {
      if (/^share:/.test(rule.id)) {
        rule.obligations = [{ id: 'urn:example:obligation:unknown',
                              on: 'Permit', assignments: [] }];
      }
    });
    store.saveOwnerPolicy('ug-rs', xml.writePolicy(doc), { rules: 3 });
  });
  since = marks.length;
  r = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  t.check(r.status === 403 && r.json.error === 'request_denied',
          'X2. a mandatory obligation that cannot be enforced: no ' +
          'unrestricted grant is reported', brief(r));

  // --- R. the PCT and discovery ---------------------------------------------
  r = await request(port, 'POST', PREFIX + '/oauth2/revoke',
    form({ token: bobPct, token_type_hint: 'pct' }),
    { 'content-type': 'application/x-www-form-urlencoded',
      authorization: basic('ug-client') });
  const after = await ask('ug-client', { ticket: await ticketFor(pat,
    { resource_id: photo, resource_scopes: ['view'] }), pct: bobPct });
  t.check(r.status === 200 && after.status === 400 &&
          after.json.error === 'invalid_grant',
          'R1. a PCT revoked at /oauth2/revoke is not accepted again',
          brief(r) + ' / ' + brief(after));
  r = await request(port, 'GET', PREFIX + '/.well-known/uma2-configuration');
  const meta = await request(port, 'GET', PREFIX +
                             '/.well-known/openid-configuration');
  t.check(r.status === 200 &&
          r.json.grant_types_supported.indexOf(GRANT) >= 0 &&
          meta.json.grant_types_supported.indexOf(GRANT) >= 0,
          'R2. the grant is advertised now it is performed', brief(r));

  await new Promise(function (ok) {
    server.close(ok);
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
  t.log.info('=== the UMA 2.0 grant (#1168, #1193) ===');
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
  name: 'uma_grant',
  describe: 'the UMA 2.0 uma-ticket grant (#1168 phase 4): the four ' +
            'layers, need_info, partial RPTs, FGA, the issuance gate, ' +
            'introspection with a PAT, upgrade, faults and the PCT, each ' +
            'case of the ticket\'s section 7',
  run: run
};
