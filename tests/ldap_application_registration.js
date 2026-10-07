// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_application_registration.js
//
// ===========================================================================
// AN LDAP ADD OF AN APPLICATION ENTRY REGISTERS IT (#504).
//
// Since #496 product serves no application without `appRegisteredBy`. An
// `ldapadd` under `ou=applications` by an identity allowed to write there is
// an administrator registering it, so the add stamps `ldap:<bound DN>`
// (`ldap` for an unbound add, which only development allows):
//
//   R1. in each mode, an application added over LDAP by an administrator is
//       stamped `ldap:<their DN>`; in development an unbound add is stamped
//       `ldap`;
//   R2. an add that carries `appRegisteredBy` keeps the author's value;
//   R3. a MODIFY does not stamp: an entry a development sighting filed,
//       modified over LDAP by an administrator, is still unregistered;
//   R4. an entry added BELOW an application (not a direct child of
//       `ou=applications`) is not stamped;
//   R5. product serves the LDAP-added application: a WS-Trust Issue for its
//       AppliesTo is issued, where the seen-only one (and the seen-only one
//       after the modify) is still wst:InvalidScope (STS-WSTRUST-0030).
//
// IN PROCESS, in a throwaway realm, through `performOperation()` — the
// handler the socket calls — because the cases are both modes' and a job
// over HTTP runs in one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const adminRbac = require('../admin-ui/admin_rbac');
// Arms the issuance gate, which a WS-Trust Issue asks.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({
  name: 'ldap_application_registration',
  level: process.env.LOG_LEVEL || 'info' });

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const STAMP = process.pid + '-' + Date.now().toString(36);
const ADMIN = 'lar-admin-' + STAMP;
const BASE = 'https://sts.lar.example';

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

function add(boundDn, dn, attributes) {
  log.debug("Entering add().");
  log.debug("Leaving add().");
  return ldap.performOperation('add', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    attributes: Object.keys(attributes).map(function (type) {
      return { type: type, values: [].concat(attributes[type]) };
    })
  });
}

function replace(boundDn, dn, type, values) {
  log.debug("Entering replace().");
  log.debug("Leaving replace().");
  return ldap.performOperation('modify', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    changes: [{ operation: 'replace',
                modification: { type: type, values: [].concat(values) } }]
  });
}

// An Issue for `appliesTo`, presenting an assertion this realm signed.
function issue(m, appliesTo) {
  log.debug("Entering issue().");
  const saml2 = require('../saml/saml2');
  const wstrust = require('../ws-trust/wstrust');
  const security = saml2.buildSamlAssertion('lar-alice', 'https://sts.test',
                                            5);
  const body = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-' +
    'envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-' +
    '200401-wss-wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' +
    security + '</wsse:Security></s:Header><s:Body>' +
    '<wst:RequestSecurityToken xmlns:wst="' + WST + '"><wst:RequestType>' +
    WST + '/Issue</wst:RequestType><wsp:AppliesTo xmlns:wsp="http://' +
    'schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    appliesTo + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
  const r = inMode(m, function () {
    return wstrust.handleRst(body, 'application/soap+xml', { base: BASE });
  });
  log.debug("Leaving issue().");
  return { status: r.status, errorCode: r.errorCode || '',
           body: String(r.body).slice(0, 300) };
}

function registeredBy(identifier) {
  log.debug("Entering registeredBy().");
  const view = applications.get(identifier);
  log.debug("Leaving registeredBy().");
  return view ? String(view.registeredBy || '') : null;
}

// An application entry's attributes, for an add.
function appEntry(identifier, extra) {
  log.debug("Entering appEntry().");
  log.debug("Leaving appEntry().");
  return Object.assign({ objectClass: ['top', 'applicationProcess'],
                         appIdentifier: identifier }, extra || {});
}

function stamps(t, m, adminDn) {
  log.debug("Entering stamps(). " + m);
  const apps = ldap.applicationsDn();
  const id = 'https://lar-added-' + m + '-' + STAMP + '.example';
  const dn = 'cn=lar-added-' + m + '-' + STAMP + ',' + apps;
  const added = inMode(m, function () {
    return add(adminDn, dn, appEntry(id));
  });
  t.check(added.ok === true && registeredBy(id) === 'ldap:' + adminDn,
          'R1. ' + m + ': an application added over LDAP by an ' +
          'administrator is registered as ldap:<their DN>',
          JSON.stringify([added, registeredBy(id)]));

  const authored = 'https://lar-authored-' + m + '-' + STAMP + '.example';
  const authoredAdd = inMode(m, function () {
    return add(adminDn, 'cn=lar-authored-' + m + '-' + STAMP + ',' + apps,
               appEntry(authored, { appRegisteredBy: 'administrator' }));
  });
  t.check(authoredAdd.ok === true &&
          registeredBy(authored) === 'administrator',
          'R2. ' + m + ': an add carrying appRegisteredBy keeps the ' +
          'author\'s value', JSON.stringify([authoredAdd,
                                              registeredBy(authored)]));

  const below = 'cn=lar-below,' + dn;
  const belowAdd = inMode(m, function () {
    return add(adminDn, below, { objectClass: ['top'], cn: 'lar-below' });
  });
  const belowEntry = ldap.performOperation('search', {
    dn: below, boundDn: adminDn, channel: 'ldaps', scope: 0,
    filter: '(objectclass=*)', attributes: ['*'], sizeLimit: 0 });
  const names = ((belowEntry.entries || [])[0] || { attributes: [] })
    .attributes.map(function (a) {
      return String(a.type).toLowerCase();
    });
  t.check(belowAdd.ok === true && belowEntry.ok === true &&
          names.length > 0 && names.indexOf('appregisteredby') === -1,
          'R4. ' + m + ': an entry below an application is not stamped',
          JSON.stringify([belowAdd, names]));
  log.debug("Leaving stamps().");
  return id;
}

function modifyDoesNotStamp(t, m, adminDn) {
  log.debug("Entering modifyDoesNotStamp(). " + m);
  const seen = 'https://lar-seen-' + m + '-' + STAMP + '.example';
  inMode('development', function () {
    return applications.seen({ identifier: seen,
                               kind: 'wstrust-relying-party',
                               protocol: 'WS-Trust',
                               note: 'filed by ' + __filename });
  });
  const view = applications.get(seen);
  t.check(!!view && !view.registeredBy && !!view.dn,
          'precondition: ' + m + ': a sighting filed ' + seen +
          ' unregistered', JSON.stringify(view && [view.dn,
                                                   view.registeredBy]));
  if (!view || !view.dn) {
    log.debug("Leaving modifyDoesNotStamp(). No sighting.");
    return seen;
  }
  const modified = inMode(m, function () {
    return replace(adminDn, view.dn, 'appName', 'modified over LDAP');
  });
  const after = applications.get(seen);
  t.check(modified.ok === true && !!after &&
          after.name === 'modified over LDAP' && !after.registeredBy,
          'R3. ' + m + ': an LDAP modify of a seen-only entry changes it and ' +
          'does not register it',
          JSON.stringify([modified, after && [after.name,
                                              after.registeredBy]]));
  log.debug("Leaving modifyDoesNotStamp().");
  return seen;
}

function served(t, ldapAdded, seenOnly) {
  log.debug("Entering served().");
  const ok = issue('product', ldapAdded);
  t.check(ok.status === 200 && !ok.errorCode,
          'R5. product: a WS-Trust Issue for the LDAP-added application is ' +
          'issued', JSON.stringify(ok));
  const refused = issue('product', seenOnly);
  t.check(refused.status === 500 && refused.errorCode === 'STS-WSTRUST-0030',
          'R5b. product: the seen-only application, modified over LDAP, is ' +
          'still refused (STS-WSTRUST-0030)', JSON.stringify(refused));
  log.debug("Leaving served().");
}

function unbound(t) {
  log.debug("Entering unbound().");
  const id = 'https://lar-anon-' + STAMP + '.example';
  const r = inMode('development', function () {
    return add('', 'cn=lar-anon-' + STAMP + ',' + ldap.applicationsDn(),
               appEntry(id));
  });
  t.check(r.ok === true && registeredBy(id) === 'ldap',
          'R1b. development: an unbound add is registered as ldap',
          JSON.stringify([r, registeredBy(id)]));
  log.debug("Leaving unbound().");
}

function run(t) {
  log.debug("Entering run().");
  const id = 'lar' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return undefined;
  }
  try {
    realms.run(made.realm, function () {
      ldap.createUser(ADMIN, { invent: false });
      const adminDn = ldap.objectFor(ADMIN).entry.dn;
      const granted = adminRbac.grant(ADMIN, 'write',
                                      { via: 'test', realm: id });
      t.check(!!granted && granted.ok !== false,
              'precondition: Admin Write on the realm\'s own roster',
              JSON.stringify(granted));
      const productApp = stamps(t, 'product', adminDn);
      stamps(t, 'development', adminDn);
      unbound(t);
      const seenProduct = modifyDoesNotStamp(t, 'product', adminDn);
      modifyDoesNotStamp(t, 'development', adminDn);
      served(t, productApp, seenProduct);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'ldap_application_registration',
  describe: 'an LDAP add under ou=applications registers the application ' +
            '(appRegisteredBy ldap:<bound DN>) and product serves it; an ' +
            'author\'s value is kept, a modify and a sighting never stamp ' +
            '(#504)',
  run: run
};
