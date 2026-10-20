// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_primary_name.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S IDENTIFIER IS ITS CLIENT_ID, ENTITYID, SPN... (#393).
//
// The create form asked for three strings that were usually one: the registry
// identifier, a display name, and the ticked family's own identifier
// attribute (`oauthClientId`, `samlEntityId`, ...). The display name was
// already optional. The family's attribute is now a default too: a create
// that leaves it empty gets the identifier, and the simplified form does not
// draw a second box for it.
//
// What is held here, through the functions the console's forms post to
// (`adminActions.applicationsAction()`):
//
//   1. THE FIELDS: a primary name is marked `primaryName`; a certificate
//      subject, a bind DN and a SPIFFE ID are not, because none of them is
//      the name the entry is filed under.
//   2. A CREATE for OAuth 2.0 and SAML 2.0 with nothing typed gets the
//      identifier as its one client_id and its one entityID, and nothing in
//      the three that are not a primary name.
//   3. A CREATE with a client_id list typed keeps that list as the WHOLE
//      list: the identifier is not forced in beside it, so an application
//      that answers to several client ids still can.
//   4. A SAVE that newly declares a family fills that family's primary name;
//      a re-save of the same families writes nothing, so an entry whose
//      client_id was deliberately cleared stays cleared.
//   5. A SAVE that names the attribute wins over the fill, even when it
//      clears it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({ name: 'application_primary_name',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'primary-name-app-' + process.pid;

function valuesOf(value) {
  log.debug("Entering valuesOf().");
  const out = [].concat(value === undefined || value === null ? [] : value)
    .map(function (one) { return String(one); });
  log.debug("Leaving valuesOf().");
  return out;
}

function fieldsOf(identifier) {
  log.debug("Entering fieldsOf().");
  const entry = applications.get(identifier);
  log.debug("Leaving fieldsOf().");
  return (entry && entry.fields) || {};
}

function run(t) {
  log.debug("Entering run().");

  // --- 1. The fields -----------------------------------------------------
  const byName = {};
  applications.applicationFields().forEach(function (row) {
    byName[row.attribute] = row;
  });
  ['oauthClientId', 'samlEntityId', 'wsfedRealm',
   'krb5ServicePrincipalName'].forEach(function (name) {
    t.check(byName[name] && byName[name].primaryName === true,
            '1. ' + name + ' is a primary name',
            JSON.stringify(byName[name] && byName[name].primaryName));
  });
  ['oauthTlsClientAuthSubjectDn', 'ldapBindDn',
   'spiffeWorkloadId'].forEach(function (name) {
    t.check(!byName[name] || byName[name].primaryName === false,
            '1. ' + name + ' is not a primary name',
            JSON.stringify(byName[name] && byName[name].primaryName));
  });
  t.equal(applications.primaryNameAttributes(['oauth2', 'oidc', 'saml2'])
            .join(','), 'oauthClientId,samlEntityId',
          '1. OAuth 2.0 and OIDC share one primary name, returned once');

  // --- 2. A create with nothing typed ------------------------------------
  const created = adminActions.applicationsAction({
    action: 'create', identifier: ID }, ['oauth2', 'saml2']);
  const made = fieldsOf(ID);
  t.check(created && created.ok === true &&
          valuesOf(made.oauthClientId).join(',') === ID &&
          valuesOf(made.samlEntityId).join(',') === ID,
          '2. a create for OAuth 2.0 and SAML 2.0 gets the identifier as its ' +
          'one client_id and its one entityID',
          JSON.stringify({ ok: created && created.ok,
                           errors: created && created.errors,
                           clientId: made.oauthClientId,
                           entityId: made.samlEntityId }));
  t.check(!valuesOf(made.oauthTlsClientAuthSubjectDn).length,
          '2. no certificate subject is invented',
          JSON.stringify(made.oauthTlsClientAuthSubjectDn));

  // --- 3. A typed list is the whole list ---------------------------------
  const LISTED = ID + '-listed';
  const listed = adminActions.applicationsAction({
    action: 'create', identifier: LISTED,
    'field.oauthClientId.0': LISTED + '-dev',
    'field.oauthClientId.1': LISTED + '-prod' }, ['oauth2']);
  t.equal(valuesOf(fieldsOf(LISTED).oauthClientId).sort().join(','),
          LISTED + '-dev,' + LISTED + '-prod',
          '3. two client ids typed on the create are the whole list, and ' +
          'the identifier is not added beside them' +
          (listed && listed.ok ? '' : ' ' + JSON.stringify(listed.errors)));

  // --- 4. A save that newly declares a family ----------------------------
  const declared = adminActions.applicationsAction({
    action: 'update-fields', application: ID, group: 'every',
    protocolsPresent: '1' }, ['oauth2', 'saml2', 'wsfed']);
  t.check(declared && declared.ok === true &&
          valuesOf(fieldsOf(ID).wsfedRealm).join(',') === ID,
          '4a. ticking WS-Federation on a save fills wsfedRealm with the ' +
          'identifier', JSON.stringify({ errors: declared && declared.errors,
                                         realm: fieldsOf(ID).wsfedRealm }));
  const clearedId = adminActions.applicationsAction({
    action: 'update-fields', application: ID, group: 'oauth',
    present: 'oauthClientId', 'field.oauthClientId': '' });
  const resaved = adminActions.applicationsAction({
    action: 'update-fields', application: ID, group: 'every',
    protocolsPresent: '1' }, ['oauth2', 'saml2', 'wsfed']);
  t.check(clearedId && clearedId.ok === true && resaved &&
          resaved.ok === true &&
          !valuesOf(fieldsOf(ID).oauthClientId).length,
          '4b. a re-save of the same families leaves a cleared client_id ' +
          'cleared', JSON.stringify({ cleared: clearedId && clearedId.errors,
                                      resaved: resaved && resaved.errors,
                                      held: fieldsOf(ID).oauthClientId }));

  // --- 5. A named attribute wins -----------------------------------------
  const named = adminActions.applicationsAction({
    action: 'update-fields', application: ID, group: 'every',
    protocolsPresent: '1', present: 'krb5ServicePrincipalName',
    'field.krb5ServicePrincipalName': 'HTTP/primary.example.com' },
    ['oauth2', 'saml2', 'wsfed', 'krb5']);
  t.check(named && named.ok === true &&
          valuesOf(fieldsOf(ID).krb5ServicePrincipalName).join(',') ===
            'HTTP/primary.example.com',
          '5. an SPN named on the save that declares Kerberos is the one ' +
          'kept', JSON.stringify({ errors: named && named.errors,
                                   spn: fieldsOf(ID)
                                     .krb5ServicePrincipalName }));

  adminActions.applicationsAction({ action: 'forget', application: ID });
  adminActions.applicationsAction({ action: 'forget', application: LISTED });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application primary name',
  describe: 'a family\'s own identifier attribute defaults to the ' +
            'application\'s identifier on a create and on a save that ' +
            'declares the family; a typed list is the whole list (#393)',
  run: run
};
