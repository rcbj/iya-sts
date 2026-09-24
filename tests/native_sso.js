'use strict';
//
// File: native_sso.js
//
// ===========================================================================
// OPENID CONNECT NATIVE SSO AND THE DEVICE REGISTER (#130, 2026-09-23).
// rcbj's answers: a device_secret lives as long as the sign-on session and is
// never rotated; a client takes part only with the flag AND a group it shares
// with the other app; RFC 8693's token types are read for every exchange; and
// devices are first-class entries in the directory, linked to their person
// and to the applications that used them.
//
// Held here, in process, against the real directory:
//
//   1. the register: a device made under ou=devices with its owner's DN and
//      the application's; the same secret presented again re-binds the same
//      device; a secret presented for another person makes a new one; the
//      bound per person; revocation keeps the device; removal is the
//      owner's;
//   2. who may take part: the flag and a well-formed group, and the scope
//      policy refusing `device_sso` to anybody else in every mode;
//   3. a registration sets them only through a TRUSTED software statement;
//   4. RFC 8693's token types: the presence rules, the supported list, and a
//      verified token held to its declared type;
//   5. the Devices block on a person's console page.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const devices = require('../common/devices');
const scopePolicy = require('../common/scope_policy');
const oauth2 = require('../oauth-oidc/oauth2');

const log = require('bunyan').createLogger({ name: 'native_sso',
  level: process.env.LOG_LEVEL || 'info' });

const ACCESS = 'urn:ietf:params:oauth:token-type:access_token';
const ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
const JWT = 'urn:ietf:params:oauth:token-type:jwt';
const DEVICE = 'urn:openid:params:token-type:device-secret';

function run(t) {
  log.debug("Entering run().");
  try {
    body(t);
  } finally {
    config.clearOverride('oauth2.maxDevicesPerPerson');
  }
  log.debug("Leaving run().");
}

function body(t) {
  log.debug("Entering body().");
  ldap.createUser('nsso-alice', { invent: false,
    attributes: { givenName: 'Alice', sn: 'Native' } });
  ldap.createUser('nsso-bob', { invent: false,
    attributes: { givenName: 'Bob', sn: 'Native' } });
  const made = [
    applications.createApplication({ identifier: 'nsso-app-a',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'nsso-app-a', oauthNativeSso: 'TRUE',
                oauthNativeSsoGroup: 'vendor.one' } }),
    applications.createApplication({ identifier: 'nsso-app-b',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'nsso-app-b', oauthNativeSso: 'TRUE',
                oauthNativeSsoGroup: 'vendor.one' } }),
    applications.createApplication({ identifier: 'nsso-app-flag-only',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'nsso-app-flag-only',
                oauthNativeSso: 'TRUE' } }),
    applications.createApplication({ identifier: 'nsso-app-none',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'nsso-app-none' } })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the four applications were created',
          JSON.stringify(made));

  t.log.info('=== 1. the register ===');
  const first = devices.issueForSession({ username: 'nsso-alice',
    clientId: 'nsso-app-a', sessionId: 'sess-1', label: 'phone' });
  const entry = first.ok ? devices.byId(first.device.id) : null;
  t.check(first.ok && /^[A-Za-z0-9_-]{43}$/.test(first.secret) && entry &&
          /^cn=[0-9a-f-]{36},ou=devices,/.test(entry.dn) &&
          /^uid=nsso-alice,ou=users,/i.test(entry.owner) &&
          entry.applications.length === 1 &&
          /ou=applications/.test(entry.applications[0]) &&
          entry.secretHash === devices.hashOf(first.secret) &&
          entry.session === 'sess-1',
          '1a. a device entry under ou=devices, owned by the person, linked ' +
          'to the application, the secret kept as its hash',
          JSON.stringify(entry));
  const again = devices.issueForSession({ username: 'nsso-alice',
    clientId: 'nsso-app-b', sessionId: 'sess-2',
    presented: first.secret });
  const rebound = devices.byId(first.device.id);
  t.check(again.ok && again.reused && again.secret === first.secret &&
          again.device.id === first.device.id && rebound.session === 'sess-2' &&
          rebound.applications.length === 2 &&
          devices.listFor('nsso-alice').length === 1,
          '1b. the same secret presented again re-binds the SAME device to ' +
          'the new session, unrotated, and links the second application');
  const stolen = devices.issueForSession({ username: 'nsso-bob',
    clientId: 'nsso-app-a', sessionId: 'sess-3', presented: first.secret });
  t.check(stolen.ok && !stolen.reused && stolen.device.id !== first.device.id &&
          devices.byId(first.device.id).session === 'sess-2',
          '1c. somebody else\'s secret is ignored: a new device, and the ' +
          'first untouched');
  config.setOverride('oauth2.maxDevicesPerPerson', 2);
  const second = devices.issueForSession({ username: 'nsso-alice',
    clientId: 'nsso-app-a', sessionId: 'sess-4' });
  const third = devices.issueForSession({ username: 'nsso-alice',
    clientId: 'nsso-app-a', sessionId: 'sess-5',
    isLive: function (sid) { return sid === 'sess-4'; } });
  const held = devices.listFor('nsso-alice').map(function (d) {
    return d.id;
  });
  t.check(second.ok && third.ok && held.length === 2 &&
          held.indexOf(second.device.id) >= 0 &&
          held.indexOf(third.device.id) >= 0 &&
          held.indexOf(first.device.id) < 0,
          '1d. at the bound, the device whose session has ended makes room',
          JSON.stringify(held));
  config.clearOverride('oauth2.maxDevicesPerPerson');
  t.check(devices.revokeSecret(second.secret) &&
          !devices.bySecret(second.secret) &&
          !!devices.byId(second.device.id),
          '1e. a revoked secret is gone; the device stays');
  t.check(!devices.remove(third.device.id, 'nsso-bob').ok &&
          devices.remove(third.device.id, 'nsso-alice').ok &&
          !devices.byId(third.device.id),
          '1f. a person removes their own device and nobody else\'s');
  const view = devices.view(devices.byId(second.device.id));
  t.check(view.secretHash === undefined && view.nativeSso === false,
          '1g. the view never shows the hash');

  t.log.info('=== 2. who may take part ===');
  t.check(applications.nativeSsoOf('nsso-app-a').enabled &&
          applications.nativeSsoOf('nsso-app-a').group === 'vendor.one' &&
          !applications.nativeSsoOf('nsso-app-flag-only').enabled &&
          !applications.nativeSsoOf('nsso-app-none').enabled,
          '2a. the flag AND a group, or not at all');
  const refused = scopePolicy.refusal('openid device_sso', 'nsso-app-none');
  t.check(refused && refused.code === 'STS-OAUTH-0624' &&
          refused.error === 'invalid_scope' &&
          !scopePolicy.refusal('openid device_sso', 'nsso-app-a'),
          '2b. device_sso is refused to a client not enabled, and granted ' +
          'to one that is');
  config.setOverride('global.mode', 'product');
  t.check(!scopePolicy.refusal('openid device_sso', 'nsso-app-a') &&
          scopePolicy.refusal('openid device_sso', 'nsso-app-flag-only'),
          '2c. the same in product mode');
  config.clearOverride('global.mode');

  t.log.info('=== 3. a registration ===');
  applications.register('nsso-dcr-plain', {
    redirect_uris: ['https://dcr.test/cb'], native_sso: true,
    native_sso_group: 'vendor.one' }, {});
  applications.register('nsso-dcr-trusted', {
    redirect_uris: ['https://dcr.test/cb'] },
    { softwareStatement: { trusted: true, issuer: 'https://pub.test',
                           publisher: 'pub', nativeSso: true,
                           nativeSsoGroup: 'vendor.one' } });
  t.check(!applications.nativeSsoOf('nsso-dcr-plain').enabled &&
          applications.nativeSsoOf('nsso-dcr-trusted').enabled,
          '3a. a registration\'s own members change nothing; a trusted ' +
          'software statement\'s do');

  t.log.info('=== 4. RFC 8693 token types ===');
  const problem = function (fields) {
    const got = oauth2.exchangeTypeProblem(fields);
    return got ? got.code : '';
  };
  t.check(problem({}) === 'STS-OAUTH-0626' &&
          problem({ subject_token_type: ACCESS, actor_token: 'x' }) ===
            'STS-OAUTH-0626' &&
          problem({ subject_token_type: ACCESS, actor_token_type: ACCESS }) ===
            'STS-OAUTH-0626',
          '4a. the presence rules of section 2.1');
  t.check(problem({ subject_token_type:
                    'urn:ietf:params:oauth:token-type:saml2' }) ===
            'STS-OAUTH-0627' &&
          problem({ subject_token_type: DEVICE }) === 'STS-OAUTH-0627' &&
          problem({ subject_token_type: ACCESS, actor_token: 'x',
                    actor_token_type: DEVICE }) === 'STS-OAUTH-0627' &&
          problem({ subject_token_type: ID_TOKEN, actor_token: 'x',
                    actor_token_type: DEVICE }) === '' &&
          problem({ subject_token_type: JWT }) === '',
          '4b. the supported types, and the device secret only as the ' +
          'actor beside an ID Token');
  const accessJwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.e30.x';
  t.check(oauth2.ownTokenKind(accessJwt, { typ: 'Bearer', sub: 'a' }) ===
            'access_token' &&
          oauth2.ownTokenKind('a.b.c', { sub: 'a', aud: 'c', iss: 'i' }) ===
            'id_token' &&
          oauth2.ownTokenKind('a.b.c', { typ: 'Refresh' }) ===
            'refresh_token',
          '4c. a token of this realm is told apart by what it carries');

  t.log.info('=== 5. the console block ===');
  const admin = require('../admin-ui/admin');
  const consolePage = new admin.AdminConsole(admin.AdminConsole.defaultDeps());
  const drawn = consolePage.mfaSection({ name: 'nsso-alice' }, 'nsso-alice',
    { write: true }, '').html;
  t.check(/<h3>Devices<\/h3>/.test(drawn) &&
          /value="remove-device"/.test(drawn) &&
          drawn.indexOf(second.device.id) >= 0,
          '5a. a person\'s page lists their devices with a Remove each');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'native sso',
  describe: 'OpenID Connect Native SSO (#130): the device register, who may ' +
            'take part, a registration, and RFC 8693\'s token types',
  run: run
};
