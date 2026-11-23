// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

const log = require('bunyan').createLogger({ name: 'role_selection_flows',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: role_selection_flows.js
//
// ===========================================================================
// DYNAMIC SELECTABLE ROLES ACROSS THE FLOWS (#1072's review follow-ups).
//
//   A. THE APPLICATION BY ITS REGISTRY IDENTIFIER: an application whose
//      client_id is not its identifier is offered its own role, a choice
//      made for it is recorded under the identifier, and a row an older
//      build recorded under the client_id is still read.
//   B. FOR THE APPLICATION THE SIGN-IN WAS FOR: an access token for a
//      resource carries the client's choice and never the resource's.
//   C. THE SETTING TURNS THE CARRYING OFF: `appDynamicRoleSelection` false
//      carries no stored choice.
//   S. THE BROWSER PROFILES CARRY IT, WS-TRUST DOES NOT: the SAML 2.0 and
//      SAML 1.1 attribute sets (which WS-Federation's assertions are built
//      with, on the same SessionIndex) carry the session's choice; a
//      WS-Trust Issue, which names no session, carries none.
//   N. A REQUIRED ROLE REFUSES A FLOW WITH NO BROWSER (decision 5):
//      `noBrowserRefusal()` (STS-XACML-0332) for an eligible person and not
//      an ineligible one, nor where the setting is off; the token
//      endpoint's issuance check throws it for the password grant and not
//      for the code.
//   O. SINGLE SIGN-ON OWES THE CHOICE: a session that chose nothing for the
//      application owes it; one that chose (for any of its names) does not.
//   D. THE DOORS THAT CANNOT DRAW THE STEP are refused (STS-XACML-0329):
//      federation, the wallet, SPNEGO, and a certificate with no
//      application.
//   R. REFRESH AND THE GRANTS WITH NO BROWSER (decisions 5 and 6): the
//      device grant and CIBA read no session's choice, nor does a refresh
//      descending from one; the code and its refresh do.
//   P. THE PORTAL'S "SIGN IN AGAIN": each protocol's link asks for a fresh
//      sign-in in its own words.
//
// In process, in a THROWAWAY REALM, the session store stood in for.
// ===========================================================================

delete process.env.CONFIG_FILE;

const POLICY_ALFA = [
  'namespace flo {',
  '    attribute kind {',
  '        category = subjectCat',
  '        id = "employeeType"',
  '        type = string',
  '    }',
  '    policy eligible {',
  '        id = "urn:test:flo-eligible"',
  '        apply denyUnlessPermit',
  '        rule operators {',
  '            permit',
  '            target clause kind == "operator"',
  '        }',
  '    }',
  '}'
].join('\n');

// The role rows' full names, by their local name.
function fullNameOf(roles, local) {
  log.debug("Entering fullNameOf(). " + local);
  const row = roles.dynamicRoles().filter(function (one) {
    return one.localName === local || one.name === local;
  })[0];
  log.debug("Leaving fullNameOf().");
  return row ? row.name : '';
}

// A roles claim's values, from a claim set, whatever the claim is named.
function roleValues(claims) {
  log.debug("Entering roleValues().");
  const out = [];
  Object.keys(claims || {}).forEach(function (name) {
    const value = claims[name];
    [].concat(Array.isArray(value) ? value : []).forEach(function (one) {
      out.push(String(one));
    });
  });
  log.debug("Leaving roleValues().");
  return out;
}

// An attribute list's values.
function attributeValues(list) {
  log.debug("Entering attributeValues().");
  const out = [];
  (list || []).forEach(function (one) {
    [].concat(one.values || []).concat(one.value === undefined ? []
                                                               : [one.value])
      .forEach(function (value) {
        out.push(String(value));
      });
  });
  log.debug("Leaving attributeValues().");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  require('../common/config');
  require('../common/app');
  const ldap = require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const roles = require('../common/roles');
  const applications = require('../common/applications');
  const adminActions = require('../admin-core/admin_actions');
  const eligibility = require('../xacml/role_eligibility');
  const selection = require('../authn/role_selection');
  const stats = require('../common/admin_stats');
  const authn = require('../authn/authn');
  const oauth2 = require('../oauth-oidc/oauth2');
  const LaunchLinks = require('../common/launch_links');

  const id = 'flo-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  const sessions = new Map();
  const instance = new selection.RoleSelection(Object.assign(
    selection.RoleSelection.defaultDeps(), {
      loadAuthn: function () {
        return { sessionById: function (sid) {
          return sessions.get(String(sid)) || null;
        } };
      }
    }));
  const reader = { selectedFor: function (context) {
    return instance.selectedFor(context);
  } };
  const before = roles.selectionReaderInstalled();
  const act = function (body) {
    log.debug("Entering act(). " + body.action);
    log.debug("Leaving act().");
    return adminActions.rolesAction(body, { via: 'api', actor: 'tester' });
  };
  const k = { roles, applications, eligibility, instance, sessions, stats,
              authn, oauth2, LaunchLinks, act, names: {} };
  try {
    realms.run(made.realm, function () {
      log.debug("Entering realmBody().");
      ldap.createUser('flo-op', { invent: false,
        attributes: { employeeType: ['operator'] } });
      ldap.createUser('flo-clerk', { invent: false,
        attributes: { employeeType: ['clerk'] } });
      applications.createApplication({ identifier: 'flo-web',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'flo-web-client' } });
      applications.createApplication({ identifier: 'flo-api',
        protocols: ['oauth2'], fields: { oauthClientId: 'flo-api' } });
      applications.createApplication({ identifier: 'flo-sp',
        protocols: ['saml2', 'saml11'], fields: {} });
      applications.createApplication({ identifier: 'flo-off',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'flo-off', appDynamicRoleSelection: 'FALSE' }
      });
      act({ action: 'create-role', role: 'flo-web-role',
            application: 'flo-web', membershipMode: 'dynamic-selectable' });
      act({ action: 'create-role', role: 'flo-api-role',
            application: 'flo-api', membershipMode: 'dynamic-selectable' });
      act({ action: 'create-role', role: 'flo-any',
            membershipMode: 'dynamic-selectable' });
      ['flo-web-role', 'flo-api-role', 'flo-any'].forEach(function (local) {
        k.names[local] = fullNameOf(roles, local);
        eligibility.setPolicy(k.names[local], { alfa: POLICY_ALFA });
      });
      roles.setSelectionReader(reader);
      sectionA(t, k);
      sectionB(t, k);
      sectionC(t, k);
      sectionS(t, k);
      sectionN(t, k);
      sectionO(t, k);
      sectionD(t, k);
      sectionR(t, k);
      sectionP(t, k);
      log.debug("Leaving realmBody().");
    });
  } finally {
    roles.setSelectionReader(before);
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

// A. By the registry identifier.
function sectionA(t, k) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. the application by its registry identifier ===');
  const { eligibility, instance, sessions, names } = k;
  const offered = eligibility.offer({ username: 'flo-op',
                                      application: 'flo-web-client' });
  t.check(offered.some(function (one) {
    return one.name === names['flo-web-role'];
  }), 'A1. a sign-in naming the client_id is offered the application\'s ' +
      'own role', JSON.stringify(offered.map(function (one) {
        return one.name;
      })));
  const chosen = instance.validateChoice({ username: 'flo-op',
    application: 'flo-web-client', offered: offered,
    chosen: [names['flo-web-role']] });
  t.check(chosen.ok && chosen.rows.length === 1 &&
          chosen.rows[0].application === 'flo-web',
          'A2. the choice is recorded under the registry identifier',
          JSON.stringify(chosen));
  sessions.set('a1', { id: 'a1', user: { username: 'flo-op' },
    expires: Date.now() + 3600 * 1000,
    selectedRoles: [{ role: names['flo-web-role'],
                      application: 'flo-web-client', at: 1 }] });
  const got = instance.selectedFor({ username: 'flo-op', sessionId: 'a1',
                                     applications: ['flo-web'] });
  t.check(got.indexOf(names['flo-web-role']) >= 0,
          'A3. a row recorded under the client_id is read for the ' +
          'identifier', JSON.stringify(got));
  t.equal(eligibility.applicationOf('flo-web-client'), 'flo-web',
          'A4. the client_id resolves to the identifier');
  t.equal(eligibility.applicationOf('nobody-registered-this'),
          'nobody-registered-this',
          'A5. a name nothing registered stands as given');
  log.debug("Leaving sectionA().");
}

// B. The sign-in's application only.
function sectionB(t, k) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. for the application the sign-in was for ===');
  const { stats, sessions, names } = k;
  sessions.set('b1', { id: 'b1', user: { username: 'flo-op' },
    expires: Date.now() + 3600 * 1000,
    selectedRoles: [{ role: names['flo-any'], application: 'flo-web',
                      at: 1 },
                    { role: names['flo-api-role'], application: 'flo-api',
                      at: 1 }] });
  const claims = stats.jwtClaims('access_token', {
    username: 'flo-op', sub: 'x', client_id: 'flo-web-client',
    audience: 'flo-api', session_id: 'b1' });
  const values = roleValues(claims);
  t.check(values.indexOf(names['flo-any']) >= 0 &&
          values.indexOf(names['flo-api-role']) < 0,
          'B1. a token issued to the client for a resource carries the ' +
          'client\'s choice and not the resource\'s', JSON.stringify(values));
  log.debug("Leaving sectionB().");
}

// C. The setting off.
function sectionC(t, k) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. the setting turns the carrying off ===');
  const { instance, sessions, eligibility, names } = k;
  sessions.set('c1', { id: 'c1', user: { username: 'flo-op' },
    expires: Date.now() + 3600 * 1000,
    selectedRoles: [{ role: names['flo-any'], application: 'flo-off',
                      at: 1 }] });
  t.equal(eligibility.selectionOn('flo-off'), false,
          '(precondition) appDynamicRoleSelection is off for flo-off');
  t.equal(instance.selectedFor({ username: 'flo-op', sessionId: 'c1',
                                 applications: ['flo-off'] }).length, 0,
          'C1. a stored choice is not carried while the setting is off');
  log.debug("Leaving sectionC().");
}

// S. The SAML attribute sets.
function sectionS(t, k) {
  log.debug("Entering sectionS().");
  t.log.info('=== S. SAML 2.0, SAML 1.1, WS-Federation, WS-Trust ===');
  const { stats, sessions, names } = k;
  sessions.set('s1', { id: 's1', user: { username: 'flo-op' },
    expires: Date.now() + 3600 * 1000,
    selectedRoles: [{ role: names['flo-any'], application: 'flo-sp',
                      at: 1 }] });
  const saml2 = attributeValues(stats.samlAttributes('saml2', {
    subject: 'flo-op', audience: 'flo-sp', session_id: 's1' }));
  const saml11 = attributeValues(stats.samlAttributes('saml11', {
    subject: 'flo-op', audience: 'flo-sp', session_id: 's1' }));
  t.check(saml2.indexOf(names['flo-any']) >= 0,
          'S1. a SAML 2.0 assertion on the session (and WS-Federation\'s, ' +
          'built the same way) carries the chosen role',
          JSON.stringify(saml2));
  t.check(saml11.indexOf(names['flo-any']) >= 0,
          'S2. a SAML 1.1 assertion on the session carries it',
          JSON.stringify(saml11));
  const wstrust = attributeValues(stats.samlAttributes('saml2', {
    subject: 'flo-op', audience: 'flo-sp', application: 'flo-sp',
    session_id: '' }));
  t.check(wstrust.indexOf(names['flo-any']) < 0,
          'S3. a WS-Trust Issue, which names no session, carries none',
          JSON.stringify(wstrust));
  log.debug("Leaving sectionS().");
}

// N. A required role and a flow with no browser.
function sectionN(t, k) {
  log.debug("Entering sectionN().");
  t.log.info('=== N. a required role refuses a flow with no browser ===');
  const { act, names } = k;
  act({ action: 'set-selection', role: names['flo-any'],
        selection: 'required' });
  const refused = selection().noBrowserRefusal({ username: 'flo-op',
    application: 'flo-web-client', protocol: 'a test' });
  t.check(!!refused && refused.code === 'STS-XACML-0332',
          'N1. an eligible person is refused (0332)', JSON.stringify(refused));
  t.equal(selection().noBrowserRefusal({ username: 'flo-clerk',
    application: 'flo-web-client', protocol: 'a test' }), null,
          'N2. a person the policy does not permit is not');
  t.equal(selection().noBrowserRefusal({ username: 'flo-op',
    application: 'flo-off', protocol: 'a test' }), null,
          'N3. nor where the application turns dynamic roles off');
  const ldapShape = selection().noBrowserRefusal({ username: 'flo-op',
    application: '', protocol: 'LDAP' });
  t.check(!!ldapShape && ldapShape.code === 'STS-XACML-0332',
          'N4. a flow naming no application (LDAP, a TGT) is asked about ' +
          'the realm-wide required role');
  const proto = k.oauth2.OAuth2Server.prototype;
  const fake = {
    deps: { log: log, gate: { check: function () {
      return { allowed: true, why: '' };
    } }, authn: { sessionById: function () { return null; } } },
    issuanceSubjectOf: proto.issuanceSubjectOf,
    issuanceKindsOf: function () { return ['access_token']; }
  };
  let thrown = null;
  try {
    proto.checkIssuance.call(fake, { grant: 'password',
      user: { username: 'flo-op' }, client_id: 'flo-web-client' });
  } catch (e) {
    thrown = e;
  }
  t.check(!!thrown && thrown.name === 'IssuanceRefused' &&
          !!thrown.issuance && thrown.issuance.roleSelection === true,
          'N5. the token endpoint refuses the password grant',
          String(thrown && thrown.message));
  let codeThrown = null;
  try {
    proto.checkIssuance.call(fake, { grant: 'authorization_code',
      user: { username: 'flo-op' }, client_id: 'flo-web-client' });
  } catch (e) {
    codeThrown = e;
  }
  t.equal(codeThrown, null,
          'N6. and not the code, which the role step stood in front of');
  log.debug("Leaving sectionN().");
}

// O. Single sign-on owes the choice.
function sectionO(t, k) {
  log.debug("Entering sectionO().");
  t.log.info('=== O. single sign-on owes a required role\'s choice ===');
  const { instance, authn, names } = k;
  const bare = { id: 'o1', user: { username: 'flo-op' }, selectedRoles: [] };
  const chose = { id: 'o2', user: { username: 'flo-op' },
    selectedRoles: [{ role: names['flo-any'], application: 'flo-web-client',
                      at: 1 }] };
  t.equal(instance.owedFor(bare, 'flo-web-client'), true,
          'O1. a session that chose nothing for the application owes it');
  t.equal(instance.owedFor(chose, 'flo-web'), false,
          'O2. one that chose for it, under any of its names, does not');
  t.equal(authn.roleChoiceOwed(bare, 'flo-web-client'), true,
          'O3. the sign-in service says so to the browser protocols');
  t.equal(instance.owedFor({ id: 'o3', user: { username: 'flo-clerk' } },
                           'flo-web-client'), false,
          'O4. nothing is owed by a person no required role would ask');
  log.debug("Leaving sectionO().");
}

// D. The doors that cannot draw the step.
function sectionD(t, k) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. the doors that cannot draw the role step ===');
  const { authn } = k;
  const shapes = [
    ['federation', ['pwd'], 'Federation',
     { application: 'flo-web-client', federation: { id: 'rel-1' } }],
    ['the wallet', ['pop'], 'OpenID4VP', { application: 'flo-web-client' }],
    ['SPNEGO', ['krb'], 'Kerberos v5',
     { application: 'flo-web-client', presented: 'flo-op@EXAMPLE.COM' }],
    ['a certificate, naming no application', ['x509'], 'TLS', {}]
  ];
  shapes.forEach(function (shape) {
    const res = { set: function () { return res; },
                  append: function () { return res; }, req: null };
    const extra = Object.assign({ request: { headers: {} } }, shape[3]);
    const started = authn.startSession(res, 'flo-op', shape[1], '1',
                                       shape[2], extra);
    t.check(!started && extra.refusedWith === 'STS-XACML-0329',
            'D. ' + shape[0] + ' is refused for a required role (0329)',
            JSON.stringify({ started: !!started,
                             refusedWith: extra.refusedWith }));
  });
  log.debug("Leaving sectionD().");
}

// R. Refresh, the device grant and CIBA.
function sectionR(t, k) {
  log.debug("Entering sectionR().");
  t.log.info('=== R. refresh and the grants with no browser ===');
  const proto = k.oauth2.OAuth2Server.prototype;
  const fake = { deps: { log: log } };
  const of = function (opts) {
    log.debug("Entering of().");
    log.debug("Leaving of().");
    return proto.selectionSessionOf.call(fake,
      Object.assign({ session_id: 'r1' }, opts));
  };
  t.equal(of({ grant: 'authorization_code' }), 'r1',
          'R1. the code reads the session\'s choice');
  t.equal(of({ grant: 'refresh_token', origin_grant: 'authorization_code' }),
          'r1', 'R2. and so does its refresh');
  t.equal(of({ grant: 'device_code' }), '',
          'R3. the device grant reads none');
  t.equal(of({ grant: 'ciba' }), '', 'R4. nor does CIBA');
  t.equal(of({ grant: 'refresh_token', origin_grant: 'device_code' }), '',
          'R5. nor a refresh descending from the device grant');
  t.equal(of({ grant: 'password' }), '',
          'R6. nor the password grant');
  // UserInfo, from the token register: where each access token came from.
  const { stats } = k;
  const stamp = Date.now().toString(36);
  const exp = Math.floor(Date.now() / 1000) + 600;
  const record = function (jti, under) {
    log.debug("Entering record(). " + jti);
    stats.recordJwt({ jti: jti, typ: 'at+jwt', sub: 'flo-op', exp: exp,
                      client_id: 'flo-web-client' }, 'x.y.z',
                    Object.assign({ kind: 'access_token', sessionId: 'r1',
                                    username: 'flo-op' }, under));
    log.debug("Leaving record().");
  };
  record('r-code-' + stamp, { grant: 'authorization_code' });
  record('r-dev-' + stamp, { grant: 'refresh_token',
                             originGrant: 'device_code' });
  record('r-ciba-' + stamp, { grant: 'refresh_token', originGrant: 'ciba' });
  record('r-ref-' + stamp, { grant: 'refresh_token',
                             originGrant: 'authorization_code' });
  record('r-old-' + stamp, { grant: 'refresh_token' });
  const info = function (jti) {
    log.debug("Entering info(). " + jti);
    log.debug("Leaving info().");
    return proto.userinfoSelectionSession.call(
      { deps: { log: log, stats: stats },
        selectionSessionOf: proto.selectionSessionOf },
      { jti: jti, sid: 'r1' });
  };
  t.equal(stats.grantOfJti('r-dev-' + stamp), 'device_code',
          'R7. the register answers a refreshed token by the grant it ' +
          'descends from');
  t.equal(info('r-code-' + stamp), 'r1',
          'R8. UserInfo reads the session for a code-flow access token');
  t.equal(info('r-ref-' + stamp), 'r1',
          'R9. and for a refresh of one');
  t.equal(info('r-dev-' + stamp), '',
          'R10. but not for a refreshed device-grant token');
  t.equal(info('r-ciba-' + stamp), '',
          'R11. nor for a refreshed CIBA token');
  t.equal(info('r-old-' + stamp), '',
          'R12. and a refresh whose origin the register does not hold ' +
          'carries none');
  log.debug("Leaving sectionR().");
}

// P. The portal's "Sign in again".
function sectionP(t, k) {
  log.debug("Entering sectionP().");
  t.log.info('=== P. the portal\'s "Sign in again" ===');
  const { LaunchLinks } = k;
  const base = 'https://sts.flo.example';
  const view = { identifier: 'flo-sp', fields: {} };
  const saml2 = LaunchLinks.endpointUrl(base, view, 'saml2', '', true);
  const saml11 = LaunchLinks.endpointUrl(base, view, 'saml11', '', true);
  const wsfed = LaunchLinks.endpointUrl(base, view, 'wsfed', '', true);
  const plain = LaunchLinks.endpointUrl(base, view, 'saml2', '', false);
  t.check(/[?&]forceAuthn=true(&|$)/.test(saml2) &&
          /[?&]forceAuthn=true(&|$)/.test(saml11) &&
          /[?&]wfresh=0(&|$)/.test(wsfed) &&
          plain.indexOf('forceAuthn') < 0,
          'P1. SAML 2.0 and 1.1 ask ForceAuthn, WS-Federation wfresh=0, ' +
          'and a plain launch neither', JSON.stringify([saml2, saml11,
                                                        wsfed, plain]));
  const oidc = LaunchLinks.thirdPartyLoginUrl('https://rp.flo.example/init',
    { issuer: base, prompt: 'login' });
  t.check(new URL(oidc).searchParams.get('prompt') === 'login',
          'P2. OpenID Connect passes prompt=login for the client to forward',
          oidc);
  log.debug("Leaving sectionP().");
}

// The selection module's facade, built where it is used.
function selection() {
  log.debug("Entering selection().");
  log.debug("Leaving selection().");
  return require('../authn/role_selection');
}

module.exports = {
  name: 'role selection flows',
  describe: 'dynamic selectable roles across the flows: the registry ' +
            'identifier, the sign-in\'s application, the setting, the SAML ' +
            'profiles, the flows with no browser, single sign-on, the doors ' +
            'that cannot draw the step, refresh, and the portal\'s Sign in ' +
            'again (#1072 follow-ups)',
  run: run
};
