// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_recent_sign_in.js
//
// ===========================================================================
// THE MANAGEMENT API'S OTHER SENSITIVE ACTS NEED A RECENT SIGN-IN (#2161,
// ASVS 5.0.0 7.5.3; rcbj, 2026-11-24).
//
// Until #2161 only the credential acts of `/users/:action` and
// `/mfa/:action` asked for one (#1538). Now the role grants and removals, the
// trust realms, the PKI, the keys and the key-encryption key, the secret
// push destinations and the settings ask for one as well, through one check
// in `registerRoutes()` driven by `RECENT_SIGN_IN_TAGS`, `_ROUTES` and
// `_ACTIONS` in `mgmt-api/admin_api.ts`. In a CHILD PROCESS with the whole
// stack on an ephemeral port (`admin_users_delete.js`'s arrangement), a
// person holding Admin Write and the console's DPoP-bound token minted for
// them, with `account.recentAuthMinutes` at 15:
//
//   A. THE TABLE: every POST row tagged Admin roles, Roles, Trust realms, PKI
//      or Configuration, and every action of the keys, encryption, TLS
//      truststore and secret destinations routes, is in a family unless it
//      writes nothing; the krbtgt rotations and a person's keytab reset are,
//      and the Kerberos principals' other actions are not; an operation of
//      no family (a session's end) is in none.
//   B. ONE OPERATION OF EACH FAMILY, signed in an hour ago, is answered 401
//      `insufficient_user_authentication` with `max_age=900` (RFC 9470),
//      and nothing changed: a role grant, a realm's creation, a certificate
//      revocation, a key-encryption-key family act, a setting, and
//      `global.mode`.
//   C. THE SAME OPERATIONS, signed in a minute ago, reach their handler:
//      the grant, the realm and the setting are made, and the revocation of
//      a serial nobody issued is the handler's own refusal, not the 401.
//   D. A PROGRAM is never asked: with a client-credentials caller the check
//      answers "not stale", whatever the setting.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_recent_sign_in',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.ARS_ROOT;
  const OUT = process.env.ARS_OUT;
  const http = require('http');
  let dpopKit = null;
  const DPOP = {
    get jkt() {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.jkt;
    },
    headers: function (method, url, token) {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.headers(method, url, token);
    }
  };
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  // One API call, with the console token's proof.
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        Object.assign(headers, DPOP.headers(method, 'http://127.0.0.1:' +
                                            port + urlPath.split('?')[0],
                                            token));
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
          resolve({ status: res.statusCode, headers: res.headers,
                    text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const adminApi = require(ROOT_DIR + '/mgmt-api/admin_api');
    const AdminApi = adminApi.AdminApi;

    config.setOverride('oauth2.consentRequired', false);

    // --- A. the table ----------------------------------------------------
    const FAMILY_TAGS = ['Admin roles', 'Roles', 'Trust realms', 'PKI',
                         'Configuration'];
    const FAMILY_ROUTES = ['/admin-api/keys/:action',
      '/admin-api/encryption/:action', '/admin-api/tls/trust/:action',
      '/admin-api/secret-destinations/:action'];
    const missed = [];
    const wrong = [];
    let covered = 0;
    adminApi.ROUTES.forEach(function (entry) {
      if (entry.method !== 'POST') {
        return;
      }
      const route = String(entry.route || entry.path || '');
      const inFamily = FAMILY_TAGS.indexOf(String(entry.tag)) >= 0 ||
                       FAMILY_ROUTES.indexOf(route) >= 0;
      const actions = (entry.actions && entry.actions.length)
        ? entry.actions : [{ action: '' }];
      actions.forEach(function (one) {
        const family = AdminApi.recentSignInFamilyOf(entry, one.action);
        if (inFamily && !one.writesNothing) {
          covered += 1;
          if (!family) {
            missed.push(route + ' ' + one.action);
          }
        } else if (family && one.writesNothing) {
          wrong.push(route + ' ' + one.action);
        }
      });
    });
    note(missed.length === 0 && wrong.length === 0 && covered > 40,
         'A1. every act of the families\' tags and routes is in a family, ' +
         'and none that writes nothing (' + covered + ' acts)',
         'missed: ' + missed.join(', ') + ' wrong: ' + wrong.join(', '));
    const principals = adminApi.ROUTES.filter(function (entry) {
      return entry.route === '/admin-api/kerberos/principals/:action';
    })[0];
    const kerberos = (principals && principals.actions || [])
      .map(function (one) {
        return one.action + '=' +
          !!AdminApi.recentSignInFamilyOf(principals, one.action);
      });
    note(kerberos.indexOf('rotate-krbtgt=true') >= 0 &&
         kerberos.indexOf('rotate-krbtgt-invalidate=true') >= 0 &&
         kerberos.indexOf('reset-person-keytab=true') >= 0 &&
         kerberos.indexOf('create-service=false') >= 0,
         'A2. the krbtgt rotations and a keytab reset are asked, and the ' +
         'Kerberos principals\' other acts are not', kerberos.join(' '));
    const sessions = adminApi.ROUTES.filter(function (entry) {
      return entry.route === '/admin-api/sessions/:action';
    })[0];
    note(!!sessions && sessions.actions.every(function (one) {
      return !AdminApi.recentSignInFamilyOf(sessions, one.action);
    }) && AdminApi.recentSignInFamilyOf(sessions, 'x',
                                         { kind: 'policy' }) !== null,
         'A3. an act of no family is in none, unless the gate called it a ' +
         'security change (#645)');

    // --- the stack ---------------------------------------------------------
    const stamp = String(process.pid);
    const WRITER = 'ars-writer-' + stamp;
    const GRANTEE = 'ars-grantee-' + stamp;
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    const subjectOf = function (name) {
      const found = ldap.locateEntry(name);
      const stored = found && found.stored;
      return stored ? 'urn:uuid:' +
        String([].concat(stored.attributes.entryuuid)[0]).toLowerCase() : '';
    };
    [WRITER, GRANTEE].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    inDefault(function () {
      rbac.seedBootstrapAdministrator();
      rbac.grant(WRITER, 'write', { via: 'test' });
    });
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const mint = function (secondsAgo) {
      return inDefault(function () {
        return oauth2.accessTokenAsync(base, {
          jkt: DPOP.jkt, audience: base + '/admin-api',
          scope: 'admin:read admin:write', client_id: 'sts-admin-console',
          username: WRITER, sub: subjectOf(WRITER),
          auth_time: Math.floor(Date.now() / 1000) - secondsAgo });
      });
    };
    config.setOverride('account.recentAuthMinutes', 15);
    const stale = await mint(3600);
    const fresh = await mint(60);
    note(!!stale && !!fresh, 'precondition: both tokens were minted');

    const REALM = 'ars' + stamp;
    const SETTING = 'saml.organizationName';
    const before = String(config.value(SETTING) || '');
    const modeBefore = String(config.value('global.mode') || '');
    const holdsRead = function () {
      return inDefault(function () {
        const roster = rbac.rosterFor('read') || { members: [] };
        return JSON.stringify(roster.members).indexOf('uid=' + GRANTEE +
                                                      ',') >= 0;
      });
    };
    const readBefore = holdsRead();
    const FAMILIES = [
      { name: 'a role grant', path: '/admin-api/rbac/grant',
        body: { username: GRANTEE, role: 'read' },
        changed: function () {
          return holdsRead() !== readBefore;
        } },
      { name: 'a realm\'s creation', path: '/admin-api/realms/create',
        body: { id: REALM, name: 'Recent sign-in ' + stamp },
        changed: function () {
          return !!realms.get(REALM);
        } },
      { name: 'a certificate revocation', path: '/admin-api/pki/revoke-certificate',
        body: { ca: 'intermediate', serialHex: '0a1b2c3d4e',
                reason: 'keyCompromise' },
        changed: function () {
          return false;
        }, reachedIsEnough: true },
      { name: 'a key-encryption-key family act',
        path: '/admin-api/encryption/count-data-keys', body: {},
        changed: function () {
          return false;
        }, reachedIsEnough: true },
      { name: 'a setting', path: '/admin-api/config/set',
        body: { key: SETTING, value: 'Recent ' + stamp },
        changed: function () {
          return String(config.value(SETTING) || '') !== before;
        } },
      { name: 'the mode', path: '/admin-api/config/set',
        body: { key: 'global.mode', value: modeBefore === 'product'
          ? 'development' : 'product' },
        changed: function () {
          return String(config.value('global.mode') || '') !== modeBefore;
        }, staleOnly: true }
    ];

    // --- B. stale --------------------------------------------------------
    for (const one of FAMILIES) {
      const r = await call(port, 'POST', one.path, stale, one.body);
      const challenge = String(r.headers['www-authenticate'] || '');
      note(r.status === 401 &&
           /error="insufficient_user_authentication"/.test(challenge) &&
           /max_age=900/.test(challenge) && !one.changed(),
           'B. ' + one.name + ' on a sign-in an hour old is asked to sign ' +
           'in again (401, RFC 9470), and nothing changed',
           r.status + ' ' + challenge + ' ' + r.text.slice(0, 200));
    }

    // --- C. fresh --------------------------------------------------------
    for (const one of FAMILIES) {
      if (one.staleOnly) {
        continue;
      }
      const r = await call(port, 'POST', one.path, fresh, one.body);
      const reached = r.status !== 401 &&
        !/insufficient_user_authentication/.test(r.text);
      // A serial nobody issued, and data keys this store does not keep,
      // are the handler's own refusals: what matters is that it ran.
      const expected = one.reachedIsEnough
        ? reached && r.status < 500
        : reached && r.status === 200 && one.changed();
      note(expected, 'C. ' + one.name + ' on a sign-in a minute old reaches ' +
           'its handler', r.status + ' ' + r.text.slice(0, 300));
    }
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }

    // --- D. a program --------------------------------------------------------
    note(AdminApi.signInIsStale({ kind: 'application' }) === false &&
         AdminApi.signInIsStale({ kind: 'person',
           authTime: Math.floor(Date.now() / 1000) - 3600 }) === true,
         'D. a program is never asked; a person an hour ago is');
    config.clearOverride('account.recentAuthMinutes');
    note(AdminApi.signInIsStale({ kind: 'person', authTime: 1 }) === false,
         'D2. and with the window at 0 (development) nobody is');

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
  const out = path.join(os.tmpdir(), 'ars-' + process.pid + '-' +
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
                                  ARS_ROOT: ROOT, ARS_OUT: out }),
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
  name: 'admin_api_recent_sign_in',
  describe: 'role grants, trust realms, the PKI, the keys and the ' +
            'key-encryption key, secret destinations and the settings need ' +
            'a sign-in within account.recentAuthMinutes on /admin-api, as ' +
            'the credential acts do (#2161, ASVS 5.0.0 7.5.3)',
  run: run
};
