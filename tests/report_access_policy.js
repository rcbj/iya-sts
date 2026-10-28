// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: report_access_policy.js
//
// ===========================================================================
// THE REPORT API IS DECIDED BY ROLES AND THE PDP, AS THE MANAGEMENT API IS
// (#1030, 2026-10-27).
//
// Until #1030 `report/rights.ts` decided who may be issued `report:use`
// (a group named by a setting, or a console administrator) and who may
// see, run, edit or delete a definition or a job — `if`s over the token's
// scope string and a group's member list, where every other access
// decision goes through `common/access_gate.ts` to the `access-control`
// policy. In a CHILD PROCESS with the whole stack on an ephemeral port:
//
//   A. THE ROLES. REPORT_USE and REPORT_ADMIN are native roles seeded with
//      the groups report-users and report-admins; no resource application
//      defines the scopes, and sts-report holds no delegated permission.
//   B. ISSUANCE. A member of report-users is issued report:use and not
//      report:admin; a member of report-admins the reverse; an outsider
//      neither, and report:use alone is invalid_scope; an application that
//      is a member is issued the scope on client_credentials, one that is
//      not is refused.
//   C. THE POLICY, OVER HTTP. An owner sees, runs, changes and deletes
//      their own definition; a report administrator every one; a member of
//      a group it is shared with reads and runs it and may not change it;
//      an outsider holding report:use sees nothing of it; an application
//      sees, lists and deletes only what it defined, whichever role it
//      holds, and a report administrator sees the application's. A person
//      holding no report role is refused at the API (STS-REPORT-0044); a
//      token whose role was taken away after it was minted is refused on
//      the next call (STS-REPORT-0018); a token without a report scope is
//      insufficient_scope.
//   D. THE SCHEDULE'S QUESTION. `rights.ownerMayRun()` answers for the
//      owner's roles now.
//   E. THE PARAMETER. An override built with `permitReportSharing: no`
//      leaves every row to its owner: the shared member and the
//      administrator are refused, the owner is not.
//   F. CONSOLE ADMINISTRATORS (#1038). Admin Write on a realm's console
//      roster holds REPORT_ADMIN and REPORT_USE there, Admin Read
//      REPORT_USE, in no report group. A service administrator's
//      default-realm token reaches another realm's report API, a default
//      realm report user's is refused (STS-REPORT-0045), a definition made
//      that way records its owner's realm and its schedule asks the
//      default roster, and losing the roster ends both. A realm's own
//      administrator is issued the report scopes in their realm, and their
//      token is believed nowhere else.
//
// THE CONSOLE IS CLOSED FIRST: with nobody on the roster a development
// console is open to everybody, and since #1038 so would every report be.
//
// In process rather than over the suite's stack because the memberships
// are made and unmade here, and an override of `access-control` written
// into the default realm would change every other job's decisions.
// ===========================================================================
const path = require('path');
const fs = require('fs');
const os = require('os');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'report_access_policy',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  const OUT = process.env.AG_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        headers.authorization = 'Bearer ' + token;
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }
  async function refused(fn) {
    try {
      await fn();
    } catch (e) {
      return e;
    }
    return null;
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const roles = require(ROOT_DIR + '/common/roles');
    const applications = require(ROOT_DIR + '/common/applications');
    const adminActions = require(ROOT_DIR + '/admin-core/admin_actions');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const rights = require(ROOT_DIR + '/report/rights');
    const stores = require(ROOT_DIR + '/report/stores');
    const templates = require(ROOT_DIR + '/xacml/xacml_templates');
    const xml = require(ROOT_DIR + '/xacml/xacml_xml');
    const store = require(ROOT_DIR + '/xacml/xacml_store');
    const gate = require(ROOT_DIR + '/common/access_gate');

    config.setOverride('xacml.enforceAccess', 'true');
    const stamp = String(process.pid);
    const OWNER = 'rap-owner-' + stamp;
    const SHARED = 'rap-shared-' + stamp;
    const OUT_PERSON = 'rap-out-' + stamp;
    const ADMIN = 'rap-admin-' + stamp;
    const NOBODY = 'rap-nobody-' + stamp;
    const LATER = 'rap-later-' + stamp;
    const CLIENT = 'rap-client-' + stamp;
    const APP = 'rap-app-' + stamp;
    const APP2 = 'rap-app2-' + stamp;
    const GROUP = 'rap-share-' + stamp;
    const BASE = 'https://sts.report-access.test';

    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const CONSOLE_W = 'rap-cw-' + stamp;
    const CONSOLE_R = 'rap-cr-' + stamp;
    [OWNER, SHARED, OUT_PERSON, ADMIN, NOBODY, LATER, CONSOLE_W,
     CONSOLE_R].forEach(function (n) {
      ldap.createUser(n, { invent: false });
    });
    const granted = [rbac.grant(CONSOLE_W, 'write', { via: 'test' }),
                     rbac.grant(CONSOLE_W, 'read', { via: 'test' }),
                     rbac.grant(CONSOLE_R, 'read', { via: 'test' })];
    note(granted.every(function (one) { return one && one.ok; }),
         'precondition: the console roster names two administrators, so ' +
         'the console is not open to everybody', JSON.stringify(granted));
    const group = ldap.createGroup(GROUP, { actor: 'test' });
    note(group && group.ok, 'precondition: a group to share with',
         JSON.stringify(group));
    const groupDn = 'cn=' + GROUP + ',' + ldap.groupsDn();
    const joined = [
      ldap.addGroupMember('report-users', OWNER, { actor: 'test' }),
      ldap.addGroupMember('report-users', SHARED, { actor: 'test' }),
      ldap.addGroupMember('report-users', OUT_PERSON, { actor: 'test' }),
      ldap.addGroupMember('report-admins', ADMIN, { actor: 'test' }),
      ldap.addGroupMember(GROUP, SHARED, { actor: 'test' })
    ];
    note(joined.every(function (one) { return one && one.ok; }),
         'precondition: the people are in their groups',
         JSON.stringify(joined));
    const made = [
      applications.createApplication({ identifier: CLIENT,
        protocols: ['oauth2'],
        fields: { oauthClientId: CLIENT,
                  oauthTokenEndpointAuthMethod: ['client_secret_basic'],
                  oauthAllowedScope: ['openid', 'report:use',
                                      'report:admin'] } }),
      applications.createApplication({ identifier: APP,
        protocols: ['oauth2'],
        fields: { oauthClientId: APP,
                  oauthTokenEndpointAuthMethod: ['client_secret_basic'],
                  oauthAllowedScope: ['report:use', 'report:admin'] } }),
      applications.createApplication({ identifier: APP2,
        protocols: ['oauth2'],
        fields: { oauthClientId: APP2,
                  oauthTokenEndpointAuthMethod: ['client_secret_basic'],
                  oauthAllowedScope: ['report:use', 'report:admin'] } })
    ];
    note(made.every(function (one) { return one && one.ok; }),
         'precondition: a confidential client for the people, and two ' +
         'applications', JSON.stringify(made));
    const action = function (body) {
      return adminActions.rolesAction(body, { actor: 'test', via: 'test' });
    };
    note(action({ action: 'add-member', role: 'REPORT_USE',
                  kind: 'application', member: APP }).ok &&
         action({ action: 'add-member', role: 'REPORT_ADMIN',
                  kind: 'application', member: APP2 }).ok &&
         action({ action: 'add-member', role: 'REPORT_USE',
                  kind: 'user', member: LATER }).ok,
         'precondition: one application in REPORT_USE, one in ' +
         'REPORT_ADMIN, and a direct user member of REPORT_USE');

    // --- A. the roles -------------------------------------------------------
    const useRole = roles.read('REPORT_USE');
    const adminRole = roles.read('REPORT_ADMIN');
    note(!!useRole && useRole.native && !useRole.console &&
         useRole.groups.indexOf('report-users') >= 0 &&
         useRole.permissions.join() === 'report:use',
         'A1. REPORT_USE is a native role seeded with report-users, ' +
         'authorizing report:use', JSON.stringify(useRole));
    note(!!adminRole && adminRole.native && !adminRole.console &&
         adminRole.groups.indexOf('report-admins') >= 0 &&
         adminRole.permissions.join() === 'report:admin',
         'A2. REPORT_ADMIN is a native role seeded with report-admins, ' +
         'authorizing report:admin', JSON.stringify(adminRole));
    note(!!ldap.entries.get('cn=report-users,' + ldap.groupsDn()) &&
         !!ldap.entries.get('cn=report-admins,' + ldap.groupsDn()),
         'A3. both groups exist in the directory');
    const reportClient = applications.get('sts-report');
    note(!applications.get('sts-report-api') && !!reportClient &&
         !(reportClient.fields || {}).oauthDelegatedPermission,
         'A4. no resource application defines the scopes and sts-report ' +
         'holds no delegated permission');
    note(gate.RESOURCE.REPORT_API === 'report-api',
         'A5. the gate names the resource the policy\'s third rule targets');

    // --- B. issuance ----------------------------------------------------------
    const personToken = function (name, scope) {
      return oauth2.tokenSet(BASE, {
        client_id: CLIENT, grant: 'refresh_token', withRefresh: false,
        scope: scope, sub: name, username: name,
        user: { username: name, sub: name } });
    };
    const machineToken = function (clientId, scope) {
      return oauth2.tokenSet(BASE, {
        client_id: clientId, grant: 'client_credentials', withRefresh: false,
        clientAuthenticated: true, scope: scope, sub: clientId,
        username: clientId, user: { username: clientId, sub: clientId } });
    };
    const asked = 'openid report:use report:admin';
    note((await personToken(OWNER, asked)).scope === 'openid report:use',
         'B1. a member of report-users is issued report:use and not ' +
         'report:admin');
    note((await personToken(ADMIN, asked)).scope === 'openid report:admin',
         'B2. a member of report-admins is issued report:admin and not ' +
         'report:use (REPORT_ADMIN does not authorize it)');
    note((await personToken(NOBODY, asked)).scope === 'openid',
         'B3. an outsider is issued neither');
    const alone = await refused(function () {
      return personToken(NOBODY, 'report:use');
    });
    note(!!alone && alone.refusal && alone.refusal.error === 'invalid_scope',
         'B4. report:use alone is invalid_scope for an outsider',
         alone ? JSON.stringify(alone.refusal) : 'not refused');
    note((await personToken(LATER, asked)).scope === 'openid report:use',
         'B5. a direct user member of REPORT_USE is issued report:use');
    note((await machineToken(APP, 'report:use report:admin')).scope ===
         'report:use',
         'B6. an application in REPORT_USE is issued report:use on ' +
         'client_credentials, and not report:admin');
    note((await machineToken(APP2, 'report:use report:admin')).scope ===
         'report:admin',
         'B7. an application in REPORT_ADMIN is issued report:admin');
    note((await personToken(CONSOLE_W, asked)).scope ===
         'openid report:use report:admin',
         'B9. Admin Write on the console roster is issued report:use and ' +
         'report:admin, in no report group (#1038)');
    note((await personToken(CONSOLE_R, asked)).scope === 'openid report:use',
         'B10. Admin Read is issued report:use and not report:admin');
    const bare = await refused(function () {
      return machineToken(CLIENT, 'report:use');
    });
    note(!!bare && bare.refusal && bare.refusal.error === 'invalid_scope',
         'B8. an application that is no member is refused invalid_scope ' +
         'though it declares the scope',
         bare ? JSON.stringify(bare.refusal) : 'not refused');

    // --- C. the policy, over HTTP ---------------------------------------------
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const subjectOf = function (name) {
      return String(helpers.subjectForName(name) || '');
    };
    const mint = function (claims) {
      return oauth2.accessTokenAsync(base, Object.assign({
        audience: base + '/report-api' }, claims));
    };
    const tOwner = await mint({ client_id: CLIENT, username: OWNER,
                                sub: subjectOf(OWNER), scope: 'report:use' });
    const tShared = await mint({ client_id: CLIENT, username: SHARED,
                                 sub: subjectOf(SHARED),
                                 scope: 'report:use' });
    const tOut = await mint({ client_id: CLIENT, username: OUT_PERSON,
                              sub: subjectOf(OUT_PERSON),
                              scope: 'report:use' });
    const tAdmin = await mint({ client_id: CLIENT, username: ADMIN,
                                sub: subjectOf(ADMIN),
                                scope: 'report:admin' });
    const tNobody = await mint({ client_id: CLIENT, username: NOBODY,
                                 sub: subjectOf(NOBODY),
                                 scope: 'report:use' });
    const tNone = await mint({ client_id: CLIENT, username: OWNER,
                               sub: subjectOf(OWNER), scope: 'openid' });
    const tLater = await mint({ client_id: CLIENT, username: LATER,
                                sub: subjectOf(LATER), scope: 'report:use' });
    const tApp = await mint({ client_id: APP, sub: APP, scope: 'report:use' });
    const tApp2 = await mint({ client_id: APP2, sub: APP2,
                               scope: 'report:admin' });
    note([tOwner, tShared, tOut, tAdmin, tNobody, tNone, tLater, tApp, tApp2]
           .every(Boolean) && subjectOf(OWNER).indexOf('urn:uuid:') === 0,
         'precondition: nine access tokens, the people as urn:uuid subjects');
    const brief = function (r) {
      return r.status + ' ' + (r.text || '').slice(0, 200);
    };

    let r = await call(port, 'GET', '/report-api', tOwner);
    note(r.status === 200, 'C1. a report user reaches the API', brief(r));
    r = await call(port, 'GET', '/report-api', tNobody);
    note(r.status === 403 && r.json && r.json.error === 'forbidden' &&
         /holds no role/.test(r.text),
         'C2. a person holding no report role is refused, though the ' +
         'token carries report:use: held ∩ carried (STS-REPORT-0018)',
         brief(r));
    r = await call(port, 'GET', '/report-api', tNone);
    note(r.status === 403 && r.json && r.json.error === 'insufficient_scope',
         'C3. a token with no report scope is insufficient_scope', brief(r));
    r = await call(port, 'GET', '/report-api', tApp);
    note(r.status === 200, 'C4. an application\'s own token reaches the ' +
         'API (STS-REPORT-0016 is retired)', brief(r));

    // --- the reports application's Shared Signals inbox (#1042) -----------
    // A signal about the owner, delivered to this application's own stream
    // as its poll takes one; a report administrator sees the realm's inbox,
    // the owner sees their own signal, another report user sees none of it,
    // and an application, which is nobody, sees none.
    const receivers = require(ROOT_DIR + '/ssf/ssf_receivers');
    const ssfEvents = require(ROOT_DIR + '/ssf/ssf_events');
    receivers.seedStreams();
    const reportStream = receivers.streamFor(receivers.REPORT);
    const delivered = reportStream ? receivers.acceptPolled(receivers.REPORT,
      ssfEvents.signSetSync(ssfEvents.buildSet({
        uri: ssfEvents.CAEP_PREFIX + 'session-established',
        issuer: reportStream.iss, audience: 'sts-report',
        subject: { format: 'iss_sub', iss: reportStream.iss,
                   sub: subjectOf(OWNER) },
        payload: { event_timestamp: Math.floor(Date.now() / 1000) } })))
      : null;
    note(delivered && delivered.status === 202 && delivered.entry.verified,
         'precondition: a signal about the owner reached the reports ' +
         'application\'s stream', JSON.stringify(delivered &&
           [delivered.status, delivered.body]));
    r = await call(port, 'GET', '/report-api/signals', tAdmin);
    note(r.status === 200 && r.json && r.json.scope === 'realm' &&
         r.json.total >= 1,
         'C32. a report administrator sees every signal the reports ' +
         'application received in the realm', brief(r));
    r = await call(port, 'GET', '/report-api/signals', tOwner);
    note(r.status === 200 && r.json && r.json.scope === 'own' &&
         r.json.total === 1 &&
         /session-established$/.test(String(r.json.rows[0].type)),
         'C33. a report user sees the signal about themselves', brief(r));
    r = await call(port, 'GET', '/report-api/signals', tOut);
    const appSignals = await call(port, 'GET', '/report-api/signals', tApp);
    note(r.status === 200 && r.json && r.json.scope === 'own' &&
         r.json.total === 0 && appSignals.status === 200 &&
         appSignals.json && appSignals.json.total === 0,
         'C34. another report user sees none of it, and nor does an ' +
         'application', brief(r) + ' | ' + brief(appSignals));

    const document = { source: 'users', select: ['username'], limit: 3 };
    const define = async function (token, name) {
      const made = await call(port, 'POST', '/report-api/definitions', token,
                              { name: name, document: document });
      return made.json && made.json.definition ? made.json.definition.id
                                               : null;
    };
    const D1 = await define(tOwner, 'the owner\'s');
    const D2 = await define(tApp, 'the application\'s');
    const D3 = await define(tApp2, 'the admin application\'s');
    note(!!D1 && !!D2 && !!D3,
         'C5. a person and two applications each saved a definition',
         [D1, D2, D3].join(','));
    const d1Row = stores.getDefinition(D1);
    const d2Row = stores.getDefinition(D2);
    note(!!d1Row && d1Row.ownerKind === 'user' && d1Row.owner ===
         subjectOf(OWNER) && !!d2Row && d2Row.ownerKind === 'application' &&
         d2Row.owner === APP,
         'C6. each definition records its owner and the owner\'s kind',
         JSON.stringify([d1Row && d1Row.ownerKind, d2Row && d2Row.ownerKind]));
    r = await call(port, 'POST', '/report-api/definitions/' + D1 + '/share',
                   tOwner, { groups: [groupDn] });
    note(r.status === 200, 'C7. the owner shares it with the group',
         brief(r));

    const get = async function (token, id) {
      return (await call(port, 'GET', '/report-api/definitions/' + id,
                         token)).status;
    };
    note(await get(tOwner, D1) === 200, 'C8. the owner sees it');
    note(await get(tShared, D1) === 200,
         'C9. the shared group\'s member sees it — the PIP\'s groups, the ' +
         'third rule');
    note(await get(tOut, D1) === 404,
         'C10. a report user outside the group is answered not_found');
    note(await get(tAdmin, D1) === 200,
         'C11. a report administrator sees it');
    note(await get(tApp, D1) === 404,
         'C12. an application holding REPORT_USE does not see a person\'s');
    note(await get(tApp2, D1) === 404,
         'C13. nor does one holding REPORT_ADMIN: an application reaches ' +
         'only what it defined');
    note(await get(tApp, D2) === 200 && await get(tOwner, D2) === 404 &&
         await get(tAdmin, D2) === 200,
         'C14. the application sees its own, a report user does not, a ' +
         'report administrator does');

    const update = function (token, id) {
      return call(port, 'POST', '/report-api/definitions/' + id, token,
                  { name: 'renamed by ' + token.slice(-6),
                    document: document });
    };
    r = await update(tShared, D1);
    note(r.status === 404, 'C15. a share does not let its member change ' +
         'the definition', brief(r));
    r = await update(tAdmin, D1);
    note(r.status === 200, 'C16. a report administrator may', brief(r));
    r = await update(tOwner, D1);
    note(r.status === 200, 'C17. and so may the owner', brief(r));
    r = await update(tApp2, D2);
    note(r.status === 404, 'C18. an administrator application may not ' +
         'change another application\'s', brief(r));

    const run = function (token, id) {
      return call(port, 'POST', '/report-api/definitions/' + id + '/run',
                  token, {});
    };
    // A saved definition's run is queued as a job (202), by `run`'s
    // reason in `reportAcceptQuery()`.
    r = await run(tShared, D1);
    note(r.status === 202 || r.status === 200,
         'C19. the shared group\'s member runs it (`run`, the share\'s ' +
         'other act)', brief(r));
    r = await run(tOut, D1);
    note(r.status === 404, 'C20. an outsider may not run it', brief(r));
    r = await run(tApp, D2);
    note(r.status === 202 || r.status === 200,
         'C21. an application runs its own', brief(r));

    const names = async function (token) {
      const listed = await call(port, 'GET', '/report-api/definitions',
                                token);
      return ((listed.json || {}).definitions || []).map(function (one) {
        return one.id;
      }).sort().join(',');
    };
    note(await names(tOwner) === D1,
         'C22. a report user lists their own definition and nobody ' +
         'else\'s', await names(tOwner));
    note(await names(tShared) === D1,
         'C23. the shared member lists the one shared with them',
         await names(tShared));
    note(await names(tOut) === '',
         'C24. an outsider lists nothing', await names(tOut));
    note(await names(tAdmin) === [D1, D2, D3].sort().join(','),
         'C25. a report administrator lists every definition, the ' +
         'applications\' included', await names(tAdmin));
    note(await names(tApp) === D2 && await names(tApp2) === D3,
         'C26. each application lists only what it defined, whichever ' +
         'role it holds', await names(tApp) + ' / ' + await names(tApp2));

    const jobs = async function (token) {
      const listed = await call(port, 'GET', '/report-api/jobs', token);
      return ((listed.json || {}).jobs || []).length;
    };
    note(await jobs(tShared) >= 1 && await jobs(tOut) === 0 &&
         await jobs(tAdmin) >= 2,
         'C27. a job is its runner\'s, a report administrator sees every ' +
         'job, an outsider none',
         [await jobs(tShared), await jobs(tOut), await jobs(tAdmin)].join(','));

    r = await call(port, 'DELETE', '/report-api/definitions/' + D2, tApp2);
    note(r.status === 404, 'C28. an application may not delete another ' +
         'application\'s definition', brief(r));
    r = await call(port, 'DELETE', '/report-api/definitions/' + D2, tApp);
    note(r.status === 200, 'C29. and deletes its own', brief(r));

    // --- a role taken away after the token was minted ----------------------
    r = await call(port, 'GET', '/report-api', tLater);
    note(r.status === 200, 'C30. a direct member reaches the API', brief(r));
    const D4 = await define(tLater, 'before the role went');
    note(action({ action: 'remove-member', role: 'REPORT_USE', kind: 'user',
                  member: LATER }).ok,
         'precondition: the direct member was taken off REPORT_USE');
    r = await call(port, 'GET', '/report-api', tLater);
    note(r.status === 403 && /holds no role/.test(r.text),
         'C31. the same token is refused on the next call: held ∩ carried ' +
         '(STS-REPORT-0018)', brief(r));

    // --- D. the schedule's question -------------------------------------------
    const mayOwner = rights.ownerMayRun(stores.getDefinition(D1));
    note(mayOwner && mayOwner.ok && mayOwner.username === OWNER,
         'D1. the schedule\'s question is answered yes for an owner who ' +
         'holds REPORT_USE', JSON.stringify(mayOwner));
    const mayLater = rights.ownerMayRun(stores.getDefinition(D4));
    note(mayLater && mayLater.ok === false &&
         mayLater.code === 'STS-REPORT-0028',
         'D2. and no for an owner whose role went (STS-REPORT-0028)',
         JSON.stringify(mayLater));
    const mayApp = rights.ownerMayRun(stores.getDefinition(D3));
    note(mayApp && mayApp.ok && mayApp.username === APP2,
         'D3. an application owner\'s definition may be scheduled while ' +
         'the application holds a report role', JSON.stringify(mayApp));

    // --- E. permitReportSharing: no ---------------------------------------------
    const built = templates.build('access-control',
      { permitReportSharing: 'no' }, { name: 'access-control' });
    const written = built.ok
      ? store.write('access-control', xml.writePolicy(built.policy),
                    { enabled: true }) : built;
    note(written && written.ok,
         'precondition: an override built without the third rule is in ' +
         'force', JSON.stringify(written));
    try {
      note(await get(tOwner, D1) === 200,
           'E1. the owner still reaches their own through the first rule');
      note(await get(tShared, D1) === 404,
           'E2. the shared member no longer does');
      note(await get(tAdmin, D1) === 404,
           'E3. nor does the report administrator: the third rule was the ' +
           'whole of their access');
      note(await get(tApp2, D3) === 200,
           'E4. the application still reaches its own');
    } finally {
      store.remove('access-control');
    }
    note(await get(tShared, D1) === 200 && await get(tAdmin, D1) === 200,
         'E5. with the override gone the built-in document decides again');

    // --- F. console administrators (#1038) -----------------------------------
    const R = 'rap' + stamp;
    const madeRealm = realms.create({ id: R, name: 'Report access #1038' });
    note(madeRealm && madeRealm.ok !== false && !!realms.get(R),
         'precondition: a second realm', JSON.stringify(madeRealm));
    const realmApi = '/realm/' + R + '/report-api';
    const tServiceW = await mint({ client_id: CLIENT, username: CONSOLE_W,
                                   sub: subjectOf(CONSOLE_W),
                                   scope: 'report:use report:admin' });
    const tServiceR = await mint({ client_id: CLIENT, username: CONSOLE_R,
                                   sub: subjectOf(CONSOLE_R),
                                   scope: 'report:use' });
    r = await call(port, 'GET', '/report-api', tServiceW);
    note(r.status === 200, 'F1. Admin Write reaches its own realm\'s ' +
         'report API', brief(r));
    r = await call(port, 'GET', realmApi, tServiceW);
    note(r.status === 200,
         'F2. a service administrator\'s default-realm token reaches ' +
         'another realm\'s report API', brief(r));
    r = await call(port, 'GET', realmApi, tServiceR);
    note(r.status === 200, 'F3. so does Admin Read\'s', brief(r));
    r = await call(port, 'GET', realmApi, tOwner);
    note(r.status === 403 && /service administrator/.test(r.text),
         'F4. a default-realm report user\'s token is refused there ' +
         '(STS-REPORT-0045)', brief(r));
    r = await call(port, 'GET', realmApi, tApp);
    note(r.status === 403 && /service administrator/.test(r.text),
         'F5. and so is a default-realm application\'s', brief(r));
    const madeThere = await call(port, 'POST', realmApi + '/definitions',
      tServiceW, { name: 'a service administrator\'s', document: document });
    const DR = madeThere.json && madeThere.json.definition
      ? madeThere.json.definition.id : null;
    const drRow = DR ? realms.run(realms.get(R), function () {
      return stores.getDefinition(DR);
    }) : null;
    note(!!drRow && drRow.owner === subjectOf(CONSOLE_W) &&
         drRow.ownerRealm === realms.DEFAULT_ID,
         'F6. a definition made there records its owner and the owner\'s ' +
         'realm', brief(madeThere) + ' ' + JSON.stringify(drRow &&
           { owner: drRow.owner, ownerRealm: drRow.ownerRealm }));
    note(!!DR && (await call(port, 'GET', realmApi + '/definitions/' + DR,
                             tServiceW)).status === 200,
         'F7. and its owner reads it back there');
    const mayCross = drRow ? realms.run(realms.get(R), function () {
      return rights.ownerMayRun(drRow);
    }) : null;
    note(mayCross && mayCross.ok && mayCross.username === CONSOLE_W,
         'F8. its schedule asks the default realm for the owner, who may ' +
         'run it', JSON.stringify(mayCross));
    note(rbac.revoke(CONSOLE_W, 'write', { via: 'test' }).ok &&
         rbac.revoke(CONSOLE_W, 'read', { via: 'test' }).ok,
         'precondition: the service administrator left the roster');
    r = await call(port, 'GET', realmApi, tServiceW);
    note(r.status === 403,
         'F9. the same token is refused in the other realm at once', brief(r));
    const mayAfter = drRow ? realms.run(realms.get(R), function () {
      return rights.ownerMayRun(drRow);
    }) : null;
    note(mayAfter && mayAfter.ok === false &&
         mayAfter.code === 'STS-REPORT-0028',
         'F10. and the schedule refuses the owner (STS-REPORT-0028)',
         JSON.stringify(mayAfter));
    const RADMIN = 'rap-radmin-' + stamp;
    const RCLIENT = 'rap-rclient-' + stamp;
    const realmBase = base + '/realm/' + R;
    const tRealm = await realms.run(realms.get(R), async function () {
      ldap.createUser(RADMIN, { invent: false });
      rbac.grant(RADMIN, 'write', { via: 'test', realm: R });
      rbac.grant(RADMIN, 'read', { via: 'test', realm: R });
      applications.createApplication({ identifier: RCLIENT,
        protocols: ['oauth2'],
        fields: { oauthClientId: RCLIENT,
                  oauthTokenEndpointAuthMethod: ['client_secret_basic'],
                  oauthAllowedScope: ['openid', 'report:use',
                                      'report:admin'] } });
      const issued = await oauth2.tokenSet(realmBase, {
        client_id: RCLIENT, grant: 'refresh_token', withRefresh: false,
        scope: asked, sub: RADMIN, username: RADMIN,
        user: { username: RADMIN, sub: RADMIN } });
      const token = await oauth2.accessTokenAsync(realmBase, {
        audience: realmBase + '/report-api', client_id: RCLIENT,
        username: RADMIN, sub: String(helpers.subjectForName(RADMIN) || ''),
        scope: 'report:use report:admin' });
      return { scope: issued.scope, token: token };
    });
    note(tRealm.scope === 'openid report:use report:admin',
         'F11. a realm\'s own Admin Write is issued both report scopes in ' +
         'that realm', tRealm.scope);
    r = await call(port, 'GET', realmApi, tRealm.token);
    note(r.status === 200, 'F12. and reaches that realm\'s report API',
         brief(r));
    r = await call(port, 'GET', '/report-api', tRealm.token);
    note(r.status === 401,
         'F13. and is believed in no other realm', brief(r));

    server.close();
    config.clearOverride('xacml.enforceAccess');
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'rap-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  AG_ROOT: ROOT, AG_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_access_policy',
  describe: 'the report API decided by REPORT_USE / REPORT_ADMIN and the ' +
            'access-control policy, an application confined to its own ' +
            'rows (#1030)',
  run: run
};
