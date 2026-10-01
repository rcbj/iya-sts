// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_form_roles.js
//
// ---------------------------------------------------------------------------
// EVERY FIELD THE APPLICATION REGISTRY DECLARES IS ON THE CREATE FORM, AND
// THE FIELD GRID'S CATALOGUE IS COMPLETE AND TYPED.
//
// `applications.declarationAttributes()` walks the PROTOCOLS table and gives
// every family attribute a ROLE — identifier, redirect, logout, secret,
// delivery, events, cors. Three readers take that one list:
// `createApplication()`'s accepted fields, `GET /admin-api/applications/new`,
// and the console form at `/admin/applications/new`.
//
// **SO A NEW ROLE COULD REACH THE API AND SILENTLY NOT THE FORM**, and that
// was not hypothetical: `delivery` (`ssfDeliveryEndpoint`) was accepted by the
// API from the day it was added and drawn by nothing until 2026-09-12. This
// file read the form's per-role sections out of `admin-ui/admin.ts` until
// 2026-09-30, when the sections became one FIELD GRID drawn from
// `applications.applicationFields()`. The rule it holds now is the same one
// read through the grid:
//
//   1. every declaration attribute is a grid field marked `declaration`, so
//      the create form's simplified view — which draws exactly those, the
//      setting overrides and the SAML key fields — draws it;
//   2. every editable attribute is a grid field, unless it is one the grid
//      leaves to a control of its own;
//   3. each field's type is the one its schema row and the BOOLEAN table say:
//      a multi-valued attribute is a list, a boolean is single-valued;
//   4. every field belongs to a group the grid draws, and to families that
//      exist;
//   5. the simplified view's filter in the console still reads `declaration`.
//
// In process, reading `admin-ui/admin.ts` as text for the last: requiring the
// console would register every /admin route on the shared app in `run.js`'s
// one process.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const applications = require('../common/applications');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'application_form_roles',
  level: process.env.LOG_LEVEL || 'info' });

// The editable attributes the grid leaves to a control of its own, as its
// header in applications.js names them: the name and the families (the
// form's own fields), the secret's rotation bookkeeping, the issued software
// statement, the registration access token, and every attribute of a managed
// key pair except the issuer declaration and the by-value certificate.
const LEFT_TO_THEIR_OWN_CONTROL = [
  'appName', 'appAllowedProtocol', 'oauthClientSecretPrevious',
  'oauthClientSecretPreviousUntil', 'oauthClientSecretExpiresAt',
  'oauthIssuedSoftwareStatement', 'appRegistrationAccessToken',
  // What the client has asked for, written as the service sees it ask.
  'oauthScope',
  // The DID keys' sealed private halves, written by Generate a key pair.
  'didPrivateKeys',
  // An application's own claim sets (2026-10-01), each one JSON array,
  // written by the Custom claims and Custom SAML attributes sections.
  'oauthClaimsAccessToken', 'oauthClaimsIdToken', 'oauthClaimsUserinfo',
  'saml2CustomAttributes', 'saml11CustomAttributes'
];

function run(t) {
  log.debug("Entering run().");
  const fields = applications.applicationFields();
  const byName = {};
  fields.forEach(function (row) { byName[row.attribute] = row; });

  // --- 1. Every declaration attribute is a declaration field ---------------
  const roles = [];
  applications.declarationAttributes().forEach(function (row) {
    if (roles.indexOf(row.role) < 0) {
      roles.push(row.role);
    }
    t.check(byName[row.attribute] && byName[row.attribute].declaration,
            '1. the "' + row.role + '" field ' + row.attribute + ' is in ' +
            'the grid as a declaration, so the simplified view draws it',
            JSON.stringify(byName[row.attribute] || null));
  });
  t.check(roles.length >= 6, '1. the registry declares at least the six ' +
                             'roles it had on 2026-09-12', roles.join(', '));

  // --- 2. Every editable attribute is a field, or has its own control ------
  const keyPairs = [];
  Object.keys(applications.KEY_PAIR_ATTRIBUTES).forEach(function (profile) {
    const row = applications.KEY_PAIR_ATTRIBUTES[profile];
    ['certificate', 'chain', 'privateKey', 'handle', 'expires', 'source',
     'jwks'].forEach(function (member) {
      if (row[member]) {
        keyPairs.push(row[member]);
      }
    });
  });
  applications.editableAttributes().forEach(function (row) {
    const own = LEFT_TO_THEIR_OWN_CONTROL.indexOf(row.name) >= 0 ||
                keyPairs.indexOf(row.name) >= 0;
    t.check(own ? !byName[row.name] : !!byName[row.name],
            '2. ' + row.name + (own
              ? ' is left to a control of its own'
              : ' is a field of the grid'),
            JSON.stringify(byName[row.name] || null));
  });

  // --- 3. Types ------------------------------------------------------------
  fields.forEach(function (row) {
    const schema = applications.SCHEMA.attributes.filter(function (one) {
      return one.name === row.attribute;
    })[0];
    const expected = schema.kind === 'multi' ? 'array'
      : (applications.BOOLEAN_ATTRIBUTES.indexOf(row.attribute) >= 0
        ? 'boolean' : 'string');
    t.equal(row.type, expected, '3. ' + row.attribute + ' is a ' + expected);
  });
  applications.BOOLEAN_ATTRIBUTES.forEach(function (name) {
    const schema = applications.SCHEMA.attributes.filter(function (one) {
      return one.name === name;
    })[0];
    t.check(schema && schema.kind === 'single' && schema.editable === 'set',
            '3. the boolean ' + name + ' is a single-valued editable ' +
            'attribute', JSON.stringify(schema && {
              kind: schema.kind, editable: schema.editable }));
  });

  // --- 4. Groups and families ---------------------------------------------
  const groups = applications.FIELD_GROUPS.map(function (g) { return g.id; });
  const families = applications.PROTOCOLS.map(function (p) { return p.id; });
  fields.forEach(function (row) {
    t.check(groups.indexOf(row.group) >= 0 &&
            row.families.every(function (f) {
              return families.indexOf(f) >= 0;
            }) && (row.everyFamily ? row.families.length === 0 : true),
            '4. ' + row.attribute + ' is in a group the grid draws, for ' +
            'families that exist',
            row.group + ' / ' + row.families.join(','));
  });
  t.equal(byName.oauthRedirectUri.group, 'oauth',
          '4. a redirect URI is an OAuth field');
  t.equal(byName.samlAssertionConsumerService.group, 'saml',
          '4. an ACS is a SAML field');
  t.check(byName.appCorsOrigin.everyFamily,
          '4. the CORS origins belong to every family');
  t.equal(byName.oauthNativeSso.families.join(','), 'oidc',
          '4. a schema row\'s own families win over the prefix');

  // --- 6. Closed sets ------------------------------------------------------
  // A field whose values are a closed set carries them, read from the source
  // the service checks against; a value outside one is refused where nothing
  // else checks it; an open field carries none.
  const clientAuth = require('../oauth-oidc/client_auth');
  t.equal(JSON.stringify(byName.oauthTokenEndpointAuthMethod.choices),
          JSON.stringify(clientAuth.METHODS),
          '6. the token endpoint auth method offers client_auth.js\'s METHODS');
  t.equal(JSON.stringify(byName.oauthSubjectType.choices),
          JSON.stringify(['public', 'pairwise', 'ephemeral']),
          '6. the subject type offers its three values');
  t.check(byName.oauthRedirectUri.choices === null &&
          !byName.oauthScope,
          '6. an open list carries no choices, and oauthScope is not a field');
  t.check(/is not a value oauthTokenEndpointAuthMethod takes/.test(
            applications.choiceProblem('oauthTokenEndpointAuthMethod',
                                       'client_secret_magic')) &&
          applications.choiceProblem('oauthTokenEndpointAuthMethod',
                                     'private_key_jwt') === '' &&
          applications.choiceProblem('oauthTokenEndpointAuthMethod', '') ===
            '',
          '6. a method outside the set is refused, one inside it and a clear ' +
          'are not');

  // --- 7. Verifiable Credentials is one choice -----------------------------
  // OpenID4VCI and OpenID4VP are one checkbox on the console and one field
  // group, and stay two families in the data. Every other family is a choice
  // of its own, and every family is in exactly one choice.
  const choices = applications.FAMILY_CHOICES;
  const vc = choices.filter(function (c) { return c.id === 'vc'; })[0];
  t.check(vc && vc.families.join(',') === 'oid4vci,oid4vp' &&
          !choices.some(function (c) {
            return c.id === 'oid4vci' || c.id === 'oid4vp';
          }),
          '7. OpenID4VCI and OpenID4VP are one choice, Verifiable Credentials',
          JSON.stringify(vc || null));
  const covered = [];
  choices.forEach(function (c) {
    c.families.forEach(function (f) { covered.push(f); });
  });
  t.equal(covered.slice().sort().join(','), families.slice().sort().join(','),
          '7. every family is in exactly one choice');
  t.equal(applications.familiesOfChoices(['oauth2', 'vc', 'oid4vp']).join(','),
          'oauth2,oid4vci,oid4vp',
          '7. a ticked vc declares both families, each once');
  t.check(applications.FIELD_GROUPS.some(function (g) {
    return g.id === 'vc' && g.families.join(',') === 'oid4vci,oid4vp';
  }) && byName.oid4vpClientId.group === 'vc',
          '7. the configuration has one Verifiable Credentials group',
          byName.oid4vpClientId && byName.oid4vpClientId.group);

  // --- 8. Every text field shows an example of a valid value --------------
  // The console draws `example` as the box's placeholder. A field drawn as
  // radios or checkboxes (a boolean, a closed set) needs none, nor does a
  // setting override, whose type the console refines from the setting and
  // whose empty box shows the setting's default.
  fields.forEach(function (row) {
    if (row.type === 'boolean' || (row.choices && row.choices.length) ||
        row.overrides) {
      return;
    }
    t.check(typeof row.example === 'string' && row.example.length > 0,
            '8. ' + row.attribute + ' carries an example of a valid value',
            JSON.stringify(row.example));
  });
  t.check(Object.keys(byName).length > 0 &&
          ['didService', 'oauthRedirectUri', 'krb5ServicePrincipalName']
            .every(function (name) {
              return applications.fieldExample(name) === byName[name].example;
            }),
          '8. fieldExample() is what the rows carry');

  // --- 5. The console's simplified view reads `declaration` ---------------
  const source = fs.readFileSync(path.join(__dirname, '..', 'admin-ui',
                                           'admin.ts'), 'utf8');
  t.check(/view === 'advanced' \|\| row\.declaration \|\| !!row\.overrides/
            .test(source),
          '5. newApplicationFields() draws every declaration in the ' +
          'simplified view');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application_form_roles',
  describe: 'every field applications.declarationAttributes() declares is on ' +
            '/admin/applications/new, and the field grid is complete and typed',
  run: run
};
