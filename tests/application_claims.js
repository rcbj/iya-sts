// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_claims.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S OWN CUSTOM CLAIMS, SAML ATTRIBUTES AND TOKEN LIFETIMES
// (2026-10-01).
//
// The realm's Custom claims, UserInfo claims and Custom SAML attributes
// pages now have per-application overrides. An application's rows are kept
// as one JSON array per set on its entry; at issuance they are ADDED to the
// realm's set and WIN BY NAME (`admin_stats.effectiveClaimSet()`). Asserted,
// in a CHILD PROCESS that loads the stack, through the functions the token
// endpoint and the SAML builders call:
//
//   A. the JSON sets: an application's row replaces the realm's row of the
//      same name for tokens to that client and adds its own, while another
//      client gets the realm's set; a directory-attribute row is accepted;
//      removing the row brings the realm's value back;
//   B. the refusals (STS-REG-0206): a reserved name, a name to remove that
//      it does not hold, an unknown set, an OAuth set on an application
//      declared for no OAuth family; and a stored row the rules refuse is
//      ignored at issuance rather than costing it;
//   C. SAML 2.0 and SAML 1.1: the same rule by audience, with the
//      nameFormat and namespace kept;
//   D. the view model the configuration tabs draw: rows marked by source,
//      a replaced realm row marked so; and the token lifetimes in force,
//      the application's override and the realm's value.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'application_claims',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.AC_ROOT;
  const OUT = process.env.AC_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const stats = require(ROOT + '/common/admin_stats');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const views = require(ROOT + '/admin-core/admin_views');
    const errorCodes = require(ROOT + '/common/error_codes');
    const stamp = String(Date.now()).slice(-6);
    const realm = realms.create({ id: 'ac-' + stamp, name: 'ac' }).realm;
    await realms.run(realm, async function () {
      const act = function (body) {
        return actions.applicationsAction(body, [], {});
      };
      applications.createApplication({ identifier: 'ac-web',
        protocols: ['oauth2', 'oidc'], fields: {} });
      applications.createApplication({ identifier: 'ac-other',
        protocols: ['oauth2', 'oidc'], fields: {} });
      applications.createApplication({ identifier: 'ac-sp',
        protocols: ['saml2', 'saml11'], fields: {} });
      stats.setClaimSet('access_token', [
        { name: 'tenant', value: 'realm' }, { name: 'region', value: 'us' }]);
      stats.setClaimSet('saml2', [{ name: 'tenant', value: 'realm' }]);
      stats.setClaimSet('saml11', [{ name: 'tenant', value: 'realm' }]);

      // --- A. The JSON sets ---------------------------------------------
      const set = act({ action: 'set-custom-claim', application: 'ac-web',
                        set: 'access_token', name: 'tenant', value: 'app' });
      const extra = act({ action: 'set-custom-claim', application: 'ac-web',
                          set: 'access_token', name: 'plan', value: 'gold' });
      const viaAttribute = act({ action: 'set-custom-claim',
        application: 'ac-web', set: 'id_token', name: 'department',
        attribute: 'departmentNumber', type: 'string' });
      note(set.ok && extra.ok && viaAttribute.ok,
           'A0. three rows set on the application',
           JSON.stringify([set.errors, extra.errors, viaAttribute.errors]));
      const forWeb = stats.jwtClaims('access_token',
        { client_id: 'ac-web', sub: 'x', username: '' });
      const forOther = stats.jwtClaims('access_token',
        { client_id: 'ac-other', sub: 'x', username: '' });
      note(forWeb.tenant === 'app' && forWeb.region === 'us' &&
           forWeb.plan === 'gold',
           'A1. its own row wins by name, the realm\'s other rows stay, its ' +
           'extra row is added', JSON.stringify(forWeb));
      note(forOther.tenant === 'realm' && forOther.plan === undefined,
           'A2. another client gets the realm\'s set',
           JSON.stringify(forOther));
      const stored = applications.get('ac-web').fields.oauthClaimsAccessToken;
      note(JSON.parse(String([].concat(stored)[0])).length === 2,
           'A3. the rows are one JSON array on the entry');
      const removed = act({ action: 'remove-custom-claim',
        application: 'ac-web', set: 'access_token', name: 'tenant' });
      note(removed.ok && stats.jwtClaims('access_token',
             { client_id: 'ac-web', sub: 'x' }).tenant === 'realm',
           'A4. removing its row brings the realm\'s value back');

      // --- B. The refusals ----------------------------------------------
      const code = function (answer) {
        return errorCodes.codeOf(answer);
      };
      const reserved = act({ action: 'set-custom-claim', application: 'ac-web',
                             set: 'access_token', name: 'sub', value: 'x' });
      const notHeld = act({ action: 'remove-custom-claim',
        application: 'ac-web', set: 'access_token', name: 'nobody' });
      const unknown = act({ action: 'set-custom-claim', application: 'ac-web',
                            set: 'nope', name: 'a', value: 'b' });
      const wrongFamily = act({ action: 'set-custom-claim',
        application: 'ac-sp', set: 'access_token', name: 'a', value: 'b' });
      note(code(reserved) === 'STS-REG-0206' &&
           code(notHeld) === 'STS-REG-0206' &&
           code(unknown) === 'STS-REG-0206' && wrongFamily.ok === false,
           'B1. a reserved name, a name not held, an unknown set and an ' +
           'OAuth set on a SAML-only application are refused',
           JSON.stringify([code(reserved), code(notHeld), code(unknown),
                           code(wrongFamily), wrongFamily.errors]));
      note(stats.applicationClaimSet('access_token',
             { identifier: 'hand', fields: {
               oauthClaimsAccessToken: '[{"name":"iss","value":"x"}]' } })
             .length === 0,
           'B2. a stored row the rules refuse is ignored, not issued');

      // --- C. SAML 2.0 and SAML 1.1 ------------------------------------
      act({ action: 'set-custom-claim', application: 'ac-sp', set: 'saml2',
            name: 'tenant', value: 'sp', nameFormat:
              'urn:oasis:names:tc:SAML:2.0:attrname-format:basic' });
      act({ action: 'set-custom-claim', application: 'ac-sp', set: 'saml11',
            name: 'tenant', value: 'sp11',
            namespace: 'urn:example:claims' });
      const saml2 = stats.samlAttributes('saml2',
        { subject: 'alice', audience: 'ac-sp' });
      const saml2Other = stats.samlAttributes('saml2',
        { subject: 'alice', audience: 'somebody-else' });
      const tenant2 = saml2.filter(function (a) {
        return a.name === 'tenant';
      });
      note(tenant2.length === 1 && String(tenant2[0].value) === 'sp' &&
           tenant2[0].nameFormat ===
             'urn:oasis:names:tc:SAML:2.0:attrname-format:basic' &&
           saml2Other.filter(function (a) {
             return a.name === 'tenant' && String(a.value) === 'realm';
           }).length === 1,
           'C1. SAML 2.0: the service provider\'s attribute wins by name, ' +
           'with its nameFormat; another audience gets the realm\'s',
           JSON.stringify([saml2, saml2Other]));
      const saml11 = stats.samlAttributes('saml11',
        { subject: 'alice', audience: 'ac-sp' });
      const tenant11 = saml11.filter(function (a) {
        return a.name === 'tenant';
      });
      note(tenant11.length === 1 && String(tenant11[0].value) === 'sp11' &&
           tenant11[0].namespace === 'urn:example:claims',
           'C2. SAML 1.1: the same, with its namespace',
           JSON.stringify(saml11));

      // --- D. The view model --------------------------------------------
      act({ action: 'set-custom-claim', application: 'ac-web',
            set: 'access_token', name: 'tenant', value: 'app' });
      const state = views.applicationClaimsState(applications.get('ac-web'));
      const access = state.sets.filter(function (one) {
        return one.id === 'access_token';
      })[0] || { effective: [] };
      const tenantRow = access.effective.filter(function (one) {
        return one.name === 'tenant';
      });
      note(state.sets.map(function (one) { return one.id; }).join(',') ===
             'access_token,id_token,userinfo' &&
           tenantRow.length === 1 && tenantRow[0].source === 'application' &&
           tenantRow[0].replacesRealm === true &&
           access.effective.some(function (one) {
             return one.name === 'region' && one.source === 'realm';
           }),
           'D1. the tab\'s model: the sets it is declared for, rows marked ' +
           'by source, a replaced realm row marked so',
           JSON.stringify(access.effective));
      applications.updateApplication('ac-web', { mode: 'set',
        attribute: 'oauthAccessTokenTtlS', value: '120' });
      const lifetimes = views.applicationTokenLifetimesState(
        applications.get('ac-web'));
      const accessTtl = lifetimes.rows.filter(function (one) {
        return one.setting === 'oauth2.accessTokenTtlS';
      })[0];
      const idTtl = lifetimes.rows.filter(function (one) {
        return one.setting === 'oauth2.idTokenTtlS';
      })[0];
      note(accessTtl.value === 120 && accessTtl.source === 'application' &&
           idTtl.source === 'realm' && idTtl.value === idTtl.realmValue,
           'D2. the token lifetimes in force: the application\'s override ' +
           'and the realm\'s value', JSON.stringify(lifetimes.rows));
      stats.setClaimSet('access_token', []);
      stats.setClaimSet('saml2', []);
      stats.setClaimSet('saml11', []);
    });
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'application-claims-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', AC_ROOT: ROOT, AC_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application_claims',
  describe: 'an application\'s own custom claims, SAML attributes and ' +
            'token lifetimes: added to the realm\'s and winning by name, ' +
            'held to the realm\'s rules, and the configuration tabs\' model',
  run: run
};
