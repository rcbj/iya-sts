// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: api_resource_objects.js
//
// ===========================================================================
// THIS SERVICE'S OWN APIS ARE APPLICATION OBJECTS, AS OAUTH 2.0 RESOURCES,
// AND A RESOURCE IS NEVER A CLIENT (#1139, 2026-10-29).
//
// rcbj: the API application objects "represent the APIs as an OAuth2
// Resource. They hold the audience and scope information that is valid",
// and "will never be used to authenticate an application. A separate
// application object has to be created for any API client." In a CHILD
// PROCESS with the whole stack on an ephemeral port, in development mode —
// the mode that verifies no client credential, so the one where a resource
// could most easily have passed for a client:
//
//   A. THE OBJECTS. sts-management-api, sts-account-api, sts-report-api and
//      sts-resource are seeded in the default realm as
//      `oauth2-resource-server` alone, each holding its API's audience, with
//      no secret and no grant type; and in a new realm, under its prefix.
//   B. THE BOOTSTRAP CLIENT. sts-api-client is a confidential
//      client_credentials client declaring admin:read admin:write
//      report:use, a member of ADMIN_READ, ADMIN_WRITE and REPORT_USE and not
//      of REPORT_ADMIN; and in the new realm too.
//   C. THE GUARD. A resource object's client_id is refused at the token,
//      PAR, introspection, revocation, device authorization and CIBA
//      endpoints (401 invalid_client) and at the authorization endpoint
//      (400, never redirected), named in the form, in the query or as the
//      Basic user — STS-OAUTH-0985 on each.
//   D. THE CLIENT AT WORK. sts-api-client is issued an /admin-api token and
//      a /report-api token, one per resource, and each is accepted where it
//      is addressed.
// ===========================================================================
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'api_resource_objects',
  level: process.env.STS_LOG_LEVEL || 'info' });

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
  // A request with a form body (the OAuth endpoints) or none.
  function request(port, method, urlPath, form, headers) {
    return new Promise(function (resolve, reject) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const all = Object.assign({ accept: 'application/json' }, headers || {});
      if (form) {
        all['content-type'] = 'application/x-www-form-urlencoded';
        all['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: all }, function (res) {
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
          resolve({ status: res.statusCode, text: raw, json: json,
                    headers: res.headers });
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  }
  function settle() {
    // The HTTP row is written when the response has finished.
    return new Promise(function (res) { setTimeout(res, 40); });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const roles = require(ROOT_DIR + '/common/roles');
    const audit = require(ROOT_DIR + '/common/audit');
    const applications = require(ROOT_DIR + '/common/applications');
    const scopePolicy = require(ROOT_DIR + '/common/scope_policy');
    require(ROOT_DIR + '/ldap/ldap_server');

    const RESOURCES = [
      ['sts-management-api', '/admin-api'],
      ['sts-account-api', '/account-api'],
      ['sts-report-api', '/report-api'],
      ['sts-resource', '/resource']
    ];
    const CLIENT = 'sts-api-client';
    const brief = function (r) {
      return r.status + ' ' + String(r.text || '').slice(0, 200);
    };
    const audiencesOf = function (entry) {
      const value = ((entry && entry.fields) || {}).oauthAudience;
      return Array.isArray(value) ? value : (value ? [value] : []);
    };
    const membersOf = function (role) {
      const row = roles.read(role);
      return (row && row.applications) || [];
    };

    // --- A and B in the default realm --------------------------------------
    const checkRealm = function (label, prefix) {
      RESOURCES.forEach(function (pair) {
        const entry = applications.get(pair[0]);
        const config = applications.clientConfigOf(pair[0]) || {};
        const named = audiencesOf(entry).filter(function (one) {
          return /^https?:\/\/[^/]+/.test(one) &&
            one.replace(/^https?:\/\/[^/]+/, '') === prefix + pair[1];
        });
        note(!!entry && entry.kinds.join() === 'oauth2-resource-server' &&
             applications.isResourceServer(pair[0]) && named.length >= 1 &&
             !config.client_secret &&
             !((applications.declaredFlowsOf(pair[0]) || {}).grant_types),
             'A. ' + label + ': ' + pair[0] + ' is a resource object holding ' +
             prefix + pair[1] + ', with no secret and no grant type',
             JSON.stringify([entry && entry.kinds, audiencesOf(entry),
                             !!config.client_secret, config.grant_types]));
      });
      const client = applications.get(CLIENT);
      const config = applications.clientConfigOf(CLIENT) || {};
      const flows = applications.declaredFlowsOf(CLIENT) || {};
      const declared = ['admin:read', 'admin:write', 'report:use']
        .every(function (scope) {
          return scopePolicy.declares(CLIENT, scope);
        }) && !scopePolicy.declares(CLIENT, 'report:admin');
      note(!!client && client.kinds.indexOf('oauth2-client') >= 0 &&
           !applications.isResourceServer(CLIENT) &&
           String(config.token_endpoint_auth_method) ===
             'client_secret_basic' && !!config.client_secret &&
           JSON.stringify(flows.grant_types) === '["client_credentials"]' &&
           declared,
           'B. ' + label + ': sts-api-client is a confidential ' +
           'client_credentials client declaring admin:read admin:write ' +
           'report:use', JSON.stringify([client && client.kinds,
             config.token_endpoint_auth_method, flows.grant_types,
             declared]));
      note(['ADMIN_READ', 'ADMIN_WRITE', 'REPORT_USE'].every(function (r) {
        return membersOf(r).indexOf(CLIENT) >= 0;
      }) && membersOf('REPORT_ADMIN').indexOf(CLIENT) < 0,
           'B. ' + label + ': sts-api-client is a member of ADMIN_READ, ' +
           'ADMIN_WRITE and REPORT_USE, and not of REPORT_ADMIN',
           JSON.stringify(['ADMIN_READ', 'ADMIN_WRITE', 'REPORT_USE',
                           'REPORT_ADMIN'].map(membersOf)));
    };
    realms.run(realms.DEFAULT_REALM, function () {
      checkRealm('the default realm', '');
    });
    const REALM = 'aro-' + process.pid;
    const made = realms.create({ id: REALM, name: REALM });
    note(made && (made.ok || made.id), 'precondition: a realm to see the ' +
         'every-realm seed', JSON.stringify(made));
    realms.run(realms.get(REALM), function () {
      checkRealm('a new realm', '/realm/' + REALM);
    });

    // --- C. the guard, over HTTP ---------------------------------------------
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const coded = function () {
      return audit.list().filter(function (event) {
        return event.errorCode === 'STS-OAUTH-0985';
      }).length;
    };
    const ENDPOINTS = ['/oauth2/token', '/oauth2/par', '/oauth2/introspect',
                       '/oauth2/revoke', '/oauth2/device_authorization',
                       '/oauth2/bc-authorize'];
    for (const pair of RESOURCES) {
      for (const endpoint of ENDPOINTS) {
        const before = coded();
        const r = await request(port, 'POST', endpoint, {
          grant_type: 'client_credentials', client_id: pair[0],
          token: 'x', scope: 'openid', login_hint: 'nobody',
          response_type: 'code', redirect_uri: 'https://rp.example/cb' });
        await settle();
        note(r.status === 401 && r.json &&
             r.json.error === 'invalid_client' && coded() === before + 1,
             'C. ' + endpoint + ' refuses ' + pair[0] + ' as a client ' +
             '(STS-OAUTH-0985)', brief(r));
      }
    }
    let before = coded();
    let r = await request(port, 'POST', '/oauth2/token',
      { grant_type: 'client_credentials', scope: 'admin:read' },
      { authorization: 'Basic ' +
          Buffer.from('sts-management-api:anything').toString('base64') });
    await settle();
    note(r.status === 401 && r.json && r.json.error === 'invalid_client' &&
         /^Basic/i.test(String(r.headers['www-authenticate'] || '')) &&
         coded() === before + 1,
         'C. named as the Basic user, the resource is refused with a Basic ' +
         'challenge', brief(r));
    before = coded();
    r = await request(port, 'GET', '/oauth2/authorize?' + new URLSearchParams({
      client_id: 'sts-report-api', response_type: 'code', scope: 'openid',
      redirect_uri: 'https://rp.example/cb', state: 's' }).toString());
    await settle();
    note(r.status === 400 && !r.headers.location &&
         coded() === before + 1,
         'C. the authorization endpoint answers 400 for a resource and does ' +
         'not redirect', brief(r));

    // --- D. the client at work -----------------------------------------------
    const secret = realms.run(realms.DEFAULT_REALM, function () {
      return (applications.clientConfigOf(CLIENT) || {}).client_secret;
    });
    const basic = 'Basic ' + Buffer.from(CLIENT + ':' + String(secret || ''))
      .toString('base64');
    const tokenFor = function (scope, resource) {
      return request(port, 'POST', '/oauth2/token',
        { grant_type: 'client_credentials', scope: scope,
          resource: base + resource }, { authorization: basic });
    };
    r = await tokenFor('admin:read admin:write', '/admin-api');
    const adminToken = (r.json || {}).access_token;
    note(r.status === 200 && !!adminToken &&
         String(r.json.scope) === 'admin:read admin:write',
         'D. sts-api-client is issued an /admin-api token', brief(r));
    if (adminToken) {
      r = await request(port, 'GET', '/admin-api/me', null,
                        { authorization: 'Bearer ' + adminToken });
      note(r.status === 200, 'D. and /admin-api accepts it', brief(r));
    }
    r = await tokenFor('report:use', '/report-api');
    const reportToken = (r.json || {}).access_token;
    note(r.status === 200 && !!reportToken &&
         String(r.json.scope) === 'report:use',
         'D. sts-api-client is issued a /report-api token with report:use',
         brief(r));
    if (reportToken) {
      r = await request(port, 'GET', '/report-api', null,
                        { authorization: 'Bearer ' + reportToken });
      note(r.status === 200, 'D. and /report-api accepts it', brief(r));
    }

    server.close();
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
  const out = path.join(os.tmpdir(), 'aro-' + process.pid + '-' +
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
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  name: 'api_resource_objects',
  describe: 'this service\'s own APIs are resource objects holding their ' +
            'audiences, a resource is refused as a client everywhere, and ' +
            'sts-api-client calls /admin-api and /report-api (#1139)',
  run: run
};
