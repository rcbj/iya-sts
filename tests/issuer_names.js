// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: issuer_names.js
//
// ===========================================================================
// THE NAMES THIS SERVICE SIGNS UNDER (#480): `saml.issuer`, `wstrust.issuer`
// and `wsfed.entityId`, through `common/issuer_names.ts`.
//
//   I1. development, nothing set: the placeholder `urn:wstrust:mock:sts`;
//   I2. product, nothing set: the SAML 2.0 entityID /saml2/metadata
//       publishes, for all three;
//   I3. product, an application named: its per-SP entityID
//       (`saml2_sso.idpEntityIdFor()`), as SAML SSO names itself to it;
//   I4. a value somebody set wins, in either mode;
//   I5. in a realm, the SEEDED `urn:<domain>:sts` is read as a default: the
//       realm's own entityID in product, the seed in development; a realm
//       value that is not the seed wins;
//   I6. a WS-Trust SAML assertion for a registered AppliesTo carries that
//       application's entityID as its Issuer in product, and the placeholder
//       in development;
//   I7. `mode.namesIssuersByEntityId()` is product's, and /admin/mode names
//       the requirement.
//
// IN PROCESS: the modes and the layers are set here, which a job over HTTP
// cannot do.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const mode = require('../common/mode');
const IssuerNames = require('../common/issuer_names');
// Arms the issuance gate, which a WS-Trust Issue asks.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'issuer_names',
  level: process.env.LOG_LEVEL || 'info' });

const MOCK = 'urn:wstrust:mock:sts';
const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const SP_URL = 'https://in-sp.example';

function inMode(m, fn) {
  log.debug("Entering inMode(). " + m);
  config.setOverride('global.mode', m);
  try {
    log.debug("Leaving inMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

function three() {
  log.debug("Entering three().");
  log.debug("Leaving three().");
  return [IssuerNames.samlIssuer(), IssuerNames.wstrustIssuer(),
          IssuerNames.wsfedEntityId()];
}

// A WS-Trust Issue for SP_URL, as a person on a signed assertion of theirs.
function issuerOfIssued() {
  log.debug("Entering issuerOfIssued().");
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const body = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-' +
    'envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-' +
    '200401-wss-wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' +
    saml2.buildSamlAssertion('in-alice', 'https://sts.test', 5) +
    '</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="' + WST + '"><wst:RequestType>' + WST + '/Issue' +
    '</wst:RequestType><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.' +
    'org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.' +
    'w3.org/2005/08/addressing"><wsa:Address>' + SP_URL + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo></wst:RequestSecurityToken>' +
    '</s:Body></s:Envelope>';
  const r = wstrust.handleRst(body, 'application/soap+xml',
                              { base: 'https://sts.in.example' });
  const m = /<saml:Issuer>([^<]*)<\/saml:Issuer>/.exec(String(r.body));
  log.debug("Leaving issuerOfIssued().");
  return { status: r.status, issuer: m ? m[1] : '', body: String(r.body) };
}

function defaultRealm(t) {
  log.debug("Entering defaultRealm().");
  const sso = require('../saml/saml2_sso');
  let got = inMode('development', three);
  t.check(got.every(function (one) { return one === MOCK; }),
          'I1. development, nothing set: all three are ' + MOCK,
          JSON.stringify(got));
  const entityId = String(config.value('saml2.entityId'));
  got = inMode('product', three);
  t.check(got.every(function (one) { return one === entityId; }),
          'I2. product, nothing set: all three are saml2.entityId (' +
          entityId + ')', JSON.stringify(got));
  const perSp = inMode('product', function () {
    return IssuerNames.samlIssuer('in-sp');
  });
  t.check(perSp === sso.idpEntityIdFor('in-sp') && perSp !== entityId,
          'I3. product, an application named: its per-SP entityID, as SAML ' +
          'SSO names itself to it', perSp);
  config.setOverride('saml.issuer', 'urn:example:chosen');
  try {
    const set = ['development', 'product'].map(function (m) {
      return inMode(m, function () {
        return IssuerNames.samlIssuer('in-sp');
      });
    });
    t.check(set.every(function (one) { return one === 'urn:example:chosen'; }),
            'I4. a value somebody set wins, in either mode',
            JSON.stringify(set));
  } finally {
    config.clearOverride('saml.issuer');
  }
  t.check(mode.namesIssuersByEntityId() === false &&
          inMode('product', mode.namesIssuersByEntityId) === true &&
          mode.report().requirements.some(function (r) {
            return r.id === 'issuer-names';
          }),
          'I7. namesIssuersByEntityId() is product\'s, and the requirement ' +
          'is reported', '');
  log.debug("Leaving defaultRealm().");
}

function inRealm(t) {
  log.debug("Entering inRealm().");
  const id = 'in-' + process.pid;
  const made = realms.create({ id: id, name: id, domain: id + '.example.net',
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving inRealm().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      const seed = 'urn:' + id + '.example.net:sts';
      const entityId = String(config.value('saml2.entityId'));
      const dev = inMode('development', three);
      const prod = inMode('product', three);
      t.check(dev.every(function (one) { return one === seed; }) &&
              prod.every(function (one) { return one === entityId; }) &&
              entityId !== seed,
              'I5. in a realm, the seeded ' + seed + ' is a default: ' +
              'development keeps it, product names the realm\'s entityID (' +
              entityId + ')', JSON.stringify({ dev: dev, prod: prod }));
      const wrote = realms.setOverride(id, 'wsfed.entityId',
                                       'urn:example:realm-chosen');
      const chosen = inMode('product', function () {
        return IssuerNames.wsfedEntityId();
      });
      t.check(wrote && wrote.ok !== false &&
              chosen === 'urn:example:realm-chosen',
              'I5b. a realm value that is not the seed wins', chosen);
      const app = applications.createApplication({
        identifier: 'in-sp', protocols: ['wstrust', 'saml2'],
        fields: { wstrustAppliesTo: [SP_URL] } });
      const sso = require('../saml/saml2_sso');
      const issuedProd = inMode('product', issuerOfIssued);
      const issuedDev = inMode('development', issuerOfIssued);
      t.check(app && app.ok && issuedProd.status === 200 &&
              issuedProd.issuer === sso.idpEntityIdFor('in-sp') &&
              issuedDev.status === 200 && issuedDev.issuer === seed,
              'I6. a WS-Trust assertion for a registered AppliesTo: the ' +
              'application\'s own entityID in product, the seed in ' +
              'development', JSON.stringify({ prod: issuedProd.issuer,
                                              dev: issuedDev.issuer,
                                              status: [issuedProd.status,
                                                       issuedDev.status] }) +
              ' ' + issuedProd.body.slice(0, 300));
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving inRealm().");
}

function run(t) {
  log.debug("Entering run().");
  defaultRealm(t);
  inRealm(t);
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'issuer_names',
  describe: 'the SAML issuer, the WS-Trust STS name and the WS-Federation ' +
            'entityID: the placeholder in development, the SAML entityID ' +
            '(per SP where an application is named) in product, a set value ' +
            'always (#480)',
  run: run
};
