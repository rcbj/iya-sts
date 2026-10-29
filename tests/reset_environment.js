// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/reset_environment.js
//
// ===========================================================================
// WHAT deploy/aws/reset-environment.js MAY DELETE ON A REUSED ENVIRONMENT
// (#344, 2026-09-29).
//
// The script removes what earlier suite runs left in the default realm of a
// long-lived AWS environment, by NAME. Nothing but a live environment can
// test the deleting, and that costs money and interferes with whoever is
// using it; what CAN be held here is the choice, which is the half that
// would do harm if it were wrong:
//
//   1. every name the bulk-load jobs make — built by `bulk_load.js` itself,
//      for every door, so a change to how those names are made fails here
//      rather than leaving 15,000 entries a run behind again;
//   2. nothing else: the bootstrap administrator, an ordinary person, a
//      person whose name merely starts `bulk-`, a group that is not a bulk
//      group;
//   3. applications: the identifiers the jobs name per run in the default
//      realm and sts_userinfo_protected.js's RFC 7591 registrations; never
//      one this service seeded, a fixed identifier the next run finds again,
//      or an operator's;
//   4. trust anchors (#335): a runtime anchor whose common name is one of
//      the suite's test CAs, never a file-source anchor, never an operator's
//      CA, and never the fingerprint this run asked to spare.
//
// Requiring the script runs nothing: it acts only as `require.main`.
// ===========================================================================

const path = require('path');

const log = require('bunyan').createLogger({ name: 'reset_environment',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const reset = require(path.join(ROOT, 'deploy/aws/reset-environment.js'));
const bulk = require(path.join(ROOT, 'tests/protocol/bulk_load.js'));

function bulkNames(t) {
  log.debug("Entering bulkNames().");
  reset.BULK_DOORS.forEach(function (door) {
    const stamp = bulk.stampFor(door);
    const person = bulk.personAt(stamp, 1).username;
    const last = bulk.personAt(stamp, 50000).username;
    const group = bulk.groupNameAt(stamp, 0);
    t.check(reset.isSuitePerson(person) && reset.isSuitePerson(last),
            'a ' + door + ' bulk-load person is the suite\'s', person);
    t.check(!reset.isSuiteGroup(person),
            'and is not taken for a group', person);
    t.check(reset.isSuiteGroup(group),
            'a ' + door + ' bulk-load group is the suite\'s', group);
    t.check(!reset.isSuitePerson(group),
            'and is not taken for a person', group);
  });
  // The LDAP job's bind identity, named outside the run's person prefix.
  const ldap = bulk.stampFor('ldap');
  t.check(reset.isSuitePerson('bulk-' + ldap.door + '-binder-' + ldap.run),
          'the LDAP bulk-load job\'s bind identity is the suite\'s');
  log.debug("Leaving bulkNames().");
}

function nothingElse(t) {
  log.debug("Entering nothingElse().");
  ['admin', 'alice', 'bulk', 'bulk-', 'bulk-loader', 'bulk-hr-2026-000001',
   'Bulk-scim-abc-000001', 'x-bulk-scim-abc-000001', 'bulk-scim-',
   'bulk-scim-abc 000001', 'bulk-scim-abc,ou=x', ''
  ].forEach(function (name) {
    t.check(!reset.isSuitePerson(name), 'person "' + name + '" is left alone');
    t.check(!reset.isSuiteGroup(name), 'group "' + name + '" is left alone');
  });
  ['admins', 'console-administrators', 'bulk-grp-001',
   'bulk-scim-abc-grp-', 'bulk-finance-abc-grp-001'
  ].forEach(function (name) {
    t.check(!reset.isSuiteGroup(name), 'group "' + name + '" is left alone');
  });
  log.debug("Leaving nothingElse().");
}

function applications(t) {
  log.debug("Entering applications().");
  ['sts-admin-console', 'sts-portal', 'sts-management-api', 'sts-api-client'
  ].forEach(function (identifier) {
    t.check(!reset.isSuiteApplication({ identifier: identifier,
                                        registeredBy: 'startup' }),
            'the seeded application ' + identifier + ' is never removed');
  });
  const stamp = 'mumksh9l1axcm';
  ['urn:test:saml11:' + stamp, 'parmon-a-' + stamp, 'parmon-b-' + stamp,
   'portal-probe-open-' + stamp, 'portal-probe-ssf-' + stamp,
   'oauth21-control-c-' + stamp, 'gl-all-' + stamp, 'gl-krb5-' + stamp,
   'https://enc-gcm-' + stamp + '.example.com', 'sp-admin-scopepol-' + stamp,
   'closed-sets-admin-read-mumksh9l', 'consent-client-12345678',
   'consent-other-client-12345678'
  ].forEach(function (identifier) {
    t.check(reset.isSuiteApplication({ identifier: identifier,
                                       registeredBy: 'administrator' }),
            identifier + ', which a job names per run, is removed');
  });
  t.check(reset.isSuiteApplication({ identifier: 'urn:test:not:registered:42',
                                     registeredBy: '' }),
          'sts_saml11.js\'s unregistered sighting is removed');
  // Fixed identifiers are found again by the next run: left in place.
  ['admin-api-test', 'sts-endpoint-test-client', 'dpop-test-client',
   'idptools-debugger-tests', 'abcapp1', 'urn:test:wsfed', 'wa-probe'
  ].forEach(function (identifier) {
    t.check(!reset.isSuiteApplication({ identifier: identifier,
                                        registeredBy: 'administrator' }),
            'the fixed ' + identifier + ' is left for the next run');
  });
  ['payroll', 'gl-all', 'gl-payroll-app', 'https://enc-gcm-x.example.org',
   'https://sp.example.com', 'consent-client-1234', 'urn:test:saml11:',
   'my-parmon-a-x'
  ].forEach(function (identifier) {
    t.check(!reset.isSuiteApplication({ identifier: identifier,
                                        registeredBy: 'administrator' }),
            'an operator\'s ' + identifier + ' is left alone');
  });
  t.check(!reset.isSuiteApplication({ identifier: 'gl-all-' + stamp,
                                      registeredBy: 'startup' }),
          'a seeded application is never removed, whatever it is called');
  const registration = {
    identifier: 'sts-client-7f3a', registeredBy: 'rfc7591',
    attributes: { oauthRedirectUri: ['http://localhost:9999/callback'] }
  };
  t.check(reset.isSuiteApplication(registration),
          'sts_userinfo_protected.js\'s RFC 7591 registration is removed');
  t.check(!reset.isSuiteApplication(Object.assign({}, registration,
    { attributes: { oauthRedirectUri: ['http://localhost:9999/callback',
                                       'https://app.example/cb'] } })),
    'a registration with another redirect URI as well is left alone');
  t.check(!reset.isSuiteApplication(Object.assign({}, registration,
    { attributes: { oauthRedirectUri: ['https://app.example/cb'] } })),
    'a registration redirecting anywhere else is left alone');
  t.check(!reset.isSuiteApplication(Object.assign({}, registration,
    { registeredBy: 'administrator' })),
    'an administrator\'s sts-client-… is left alone');
  t.check(!reset.isSuiteApplication(Object.assign({}, registration,
    { identifier: 'payroll' })),
    'a registration under another client_id is left alone');
  t.check(!reset.isSuiteApplication(null), 'a missing row is left alone');
  log.debug("Leaving applications().");
}

// THE RISK DATASETS (#311): which versions are the suite's, from testidp's
// own history on 2026-09-29 — rcbj's 3-row deny list was replaced by the
// upload job's SHA-256-named versions, which carry no suite prefix.
function riskVersions(t) {
  log.debug("Entering riskVersions().");
  const run7 = 1790710983663;
  const deny = [
    { version: 'aa2c5ce7a2b44bcb', loadedAt: 1790589990187 },
    { version: 'run-mul6riks89a293-a', loadedAt: 1790596235309 },
    { version: 'd6a1d45d6c972775', loadedAt: 1790596243055 },
    { version: '27d9f87b7c781b6f', loadedAt: 1790714581970 },
    { version: 'two-mun57v5p1dc55a', loadedAt: 1790714584382 }
  ];
  const isSuite = reset.suiteVersionTest([
    { dataset: 'iplist.operator-deny', versions: deny },
    { dataset: 'iplist.operator-allow',
      versions: [{ version: 'suite-2026-09-29T19-38-03', loadedAt: run7 }] }
  ]);
  t.check(!isSuite(deny[0]), 'the operator\'s own list is not the suite\'s');
  t.check(isSuite(deny[1]) && isSuite(deny[4]),
          'a version with a suite job\'s prefix is the suite\'s');
  t.check(isSuite(deny[2]),
          'a SHA-256-named version loaded beside a run- version is the ' +
          'suite\'s, from before runs marked their start');
  t.check(isSuite(deny[3]),
          'a SHA-256-named version loaded inside a run\'s window is the ' +
          'suite\'s');
  t.check(isSuite({ version: 'suite-2026-09-29T19-38-03', loadedAt: run7 }),
          'the launcher\'s own allow list is the suite\'s (and is never ' +
          'displaced, by the caller)');
  t.check(!isSuite({ version: 'ffffffffffffffff',
                     loadedAt: run7 + 13 * 3600 * 1000 }),
          'a version loaded long after a run started is the operator\'s');
  log.debug("Leaving riskVersions().");
}

// THE TRUSTSTORE (#335). The deleting needs a live service; the choice of
// which anchor goes is what would fill the 32-anchor cap if it were wrong.
function anchor(subject, source, fingerprint) {
  log.debug("Entering anchor().");
  log.debug("Leaving anchor().");
  return { subject: subject, source: source || 'runtime',
           fingerprint256: fingerprint };
}

function trustAnchors(t) {
  log.debug("Entering trustAnchors().");
  const shared = 'CN=iya-sts test Root CA,O=iya-sts tests';
  t.check(reset.isSuiteTrustAnchor(anchor(shared, 'runtime', 'AA:BB')),
          'the shared test Root is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=mock-sts test Root CA,O=iya-sts tests', 'runtime', 'CC')),
          'the historical mock-sts Root is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=global-logout test CA for alice', 'runtime', 'DD')),
          'a global-logout CA is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=console bootstrap test CA stamp holder', 'runtime', 'EE')),
          'a console bootstrap CA is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=GNAP mTLS test CA realm', 'runtime', 'FF')),
          'a GNAP mTLS CA is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=pooling test Root stamp,O=iya-sts tests', 'runtime', '11')),
          'a pooling Root is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=admin-api-operations truststore realm', 'runtime', '22')),
          'an admin-api truststore CA is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=console-truststore-stamp,O=iya-sts tests', 'runtime', '33')),
          'a console truststore CA is a suite anchor');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'CN=iya-sts test Root CA\nO=iya-sts tests', 'runtime', 'AA:BB')),
          'a subject with newlines still matches');
  t.check(reset.isSuiteTrustAnchor(anchor(
    'O=iya-sts tests, CN=iya-sts test Root CA', 'runtime', 'AA:BB')),
          'a subject with the common name later still matches');
  t.check(!reset.isSuiteTrustAnchor(anchor(shared, 'file', 'AA:BB')),
          'a file-source anchor with the same subject is left alone');
  t.check(!reset.isSuiteTrustAnchor(anchor(
    'CN=operator CA,O=example', 'runtime', '99')),
          'an operator CA is left alone');
  t.check(!reset.isSuiteTrustAnchor(anchor(
    'CN=iya-sts test Root CA extra,O=iya-sts tests', 'runtime', '98')),
          'a longer common name is not the shared Root');
  t.check(!reset.isSuiteTrustAnchor(anchor(
    'CN=not-global-logout test CA', 'runtime', '97')),
          'a name that merely ends with a suite prefix is left alone');
  t.check(!reset.isSuiteTrustAnchor(anchor(
    'CN=admin-api-operations saml2 realm', 'runtime', '96')),
          'the admin-api SAML signing CA is not removed as a trust anchor');
  t.check(!reset.isSuiteTrustAnchor(null),
          'a missing anchor is left alone');
  t.check(!reset.isSuiteTrustAnchor({ source: 'runtime' }),
          'an anchor with no subject is left alone');
  t.check(!reset.isSuiteTrustAnchor(anchor(shared, 'startup', 'AA:BB')),
          'a source other than runtime is left alone');

  const gone = reset.trustAnchorsToRemove([
    anchor(shared, 'runtime', 'AA:BB'),
    anchor(shared, 'file', 'FILE'),
    anchor('CN=operator CA', 'runtime', 'OP'),
    anchor('CN=iya-sts test Root CA extra', 'runtime', 'NEAR'),
    anchor('CN=mock-sts test Root CA', 'runtime', 'MOCK'),
    null
  ], ['aa:bb']);
  t.check(gone.length === 1 && gone[0].fingerprint256 === 'MOCK',
          'a spared fingerprint stays, and only the other suite anchor goes',
          gone.map(function (row) {
            return row.fingerprint256;
          }).join(','));
  t.check(reset.trustAnchorsToRemove([null, undefined, {}], []).length === 0,
          'null and missing rows are left alone');
  t.check(reset.trustAnchorsToRemove([
    anchor(shared, 'runtime', '')
  ], []).length === 0,
          'a suite anchor with no fingerprint is left alone');
  log.debug("Leaving trustAnchors().");
}

function run(t) {
  log.debug("Entering run().");
  bulkNames(t);
  nothingElse(t);
  applications(t);
  riskVersions(t);
  trustAnchors(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'reset_environment',
  describe: 'deploy/aws/reset-environment.js deletes the suite\'s bulk-load ' +
            'people and groups, its applications and its runtime trust ' +
            'anchors, and nothing an operator or this service made',
  run: run
};
