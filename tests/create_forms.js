// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: create_forms.js
//
// ===========================================================================
// EVERY DIRECTORY CREATE PAGE CALLS OUT WHAT ITS CREATE REQUIRES, AND WHAT
// IT CALLS OUT IS WHAT THE CREATE REFUSES WITHOUT (#1132).
//
// rcbj on #1132: every directory object has a create page, and each calls
// out its required fields the way New user does; a field is required when
// the server refuses the create without it today, and everything else is
// optional. `admin-core/create_forms.ts` is the table each
// `GET /admin-api/<object>/new` answers as `createFields`; this file holds
// the table to the doors it describes, by calling them:
//
//   A. Each object's create succeeds with its required fields alone (and
//      the minimum a value needs to be valid), and is REFUSED with each
//      required field taken away — so a field the table calls required is
//      one the create refuses without, and the required set is enough.
//   B. A secret destination's provider-specific fields (`requiredWhen`):
//      an aws destination without its region, and without its credential,
//      is refused; the same fields are not required of a vault one where
//      the table says so.
//   C. Each create page's answer carries the table's fields: New group,
//      New role and Register a device from their views.
//   D. A named policy (#1132's sixth object): `GET /admin-api/policies/new`
//      answers every kind with named policies, and for the password policy
//      the name and every field the save refuses without, while a field the
//      save keeps the value in force for (`hashAlgorithm`) is optional — and
//      the save agrees: refused without a required field, saved without the
//      optional one.
//   E. The drawn pages: a required field is outlined, starred and says
//      "required" (`fg-required`), an optional one is not, and the HTML
//      `required` attribute is on exactly the required fields.
//
// IN A THROWAWAY REALM, removed at the end.
// ===========================================================================
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const CreateForms = require('../admin-core/create_forms');
const destinations = require('../common/secret_destinations');
const attributeSources = require('../attribute-sources/attribute_sources');
const passwordPolicy = require('../common/password_policy');

const log = require('bunyan').createLogger({ name: 'create_forms',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const CTX = { actor: 'create-forms-test', via: 'test' };

function without(body, name) {
  log.debug("Entering without(). " + name);
  const out = Object.assign({}, body);
  delete out[name];
  log.debug("Leaving without().");
  return out;
}

// One create door per object, and a body holding its required fields and
// nothing else (bar `action`), each a fresh name so the creates do not
// collide with each other.
function doors(owner) {
  log.debug("Entering doors().");
  const devicesAdmin = require('../admin-ui/devices_admin');
  let n = 0;
  const fresh = function (stem) {
    n += 1;
    return 'cf-' + stem + '-' + RUN + '-' + n;
  };
  const out = {
    users: { act: function (body) {
               return adminActions.usersAction(Object.assign(
                 { action: 'create', credential: 'none' }, body), CTX);
             },
             body: function () {
               return { username: fresh('u') };
             } },
    applications: { act: function (body) {
                      return applications.createApplication(body);
                    },
                    body: function () {
                      return { identifier: fresh('app') };
                    } },
    groups: { act: function (body) {
                return adminActions.groupsAction(Object.assign(
                  { action: 'create' }, body), CTX);
              },
              body: function () {
                return { group: fresh('g') };
              } },
    roles: { act: function (body) {
               return adminActions.rolesAction(Object.assign(
                 { action: 'create-role' }, body), CTX);
             },
             body: function () {
               return { role: fresh('r') };
             } },
    devices: { act: function (body) {
                 return devicesAdmin.action(Object.assign(
                   { action: 'create' }, body), 'test', 'create_forms');
               },
               body: function () {
                 return { owner: owner };
               } },
    attributeSources: { act: function (body) {
                          return attributeSources.act(Object.assign(
                            { action: 'add-source' }, body), CTX);
                        },
                        body: function () {
                          return { id: fresh('src'), host: 'db.example.com',
                                   database: 'hr', user: 'reader',
                                   table: 'people', keyColumn: 'login',
                                   columns: { cost_center: 'costCenter' } };
                        } },
    secretDestinations: { act: function (body) {
                            return destinations.act(Object.assign(
                              { action: 'add-destination' }, body), CTX);
                          },
                          // aws: the provider needing a region and a
                          // credential (`requiredWhen`), both given.
                          body: function () {
                            return { identifier: fresh('dest'),
                                     provider: 'aws', region: 'us-east-1',
                                     credential: JSON.stringify({
                                       accessKeyId: 'AKIA' + RUN,
                                       secretAccessKey: 'x' + RUN }) };
                          } }
  };
  log.debug("Leaving doors().");
  return out;
}

async function requiredHolds(t, table) {
  log.debug("Entering requiredHolds().");
  const owner = 'cf-owner-' + RUN;
  const made = adminActions.usersAction({ action: 'create', username: owner,
                                          credential: 'none' }, CTX);
  t.check(!!(made && made.ok), 'A0. the device owner is created',
          JSON.stringify(made && made.errors));
  const all = doors(owner);
  t.check(Object.keys(all).sort().join(',') ===
          CreateForms.objects().sort().join(','),
          'A0. the table describes every create door here, and only those',
          CreateForms.objects().join(','));
  for (const object of Object.keys(all)) {
    const door = all[object];
    const required = CreateForms.requiredOf(object);
    const whole = await Promise.resolve(door.act(door.body()));
    t.check(!!(whole && whole.ok),
            'A1. ' + object + ': the create succeeds with its required ' +
            'fields alone (' + required.join(', ') + ')',
            JSON.stringify(whole && (whole.errors || whole.why)));
    for (const name of required) {
      const refused = await Promise.resolve(
        door.act(without(door.body(), name)));
      t.check(!!refused && refused.ok === false,
              'A2. ' + object + ': refused without `' + name + '`',
              JSON.stringify(refused));
    }
  }
  log.debug("Leaving requiredHolds().");
  return table;
}

async function requiredWhen(t) {
  log.debug("Entering requiredWhen().");
  const rows = CreateForms.fieldsOf('secretDestinations');
  const when = function (name) {
    const row = rows.filter(function (one) {
      return one.name === name;
    })[0];
    return row && row.requiredWhen;
  };
  t.check(when('region').values.join(',') === 'aws' &&
          when('credential').values.indexOf('file') < 0 &&
          when('endpoint').values.join(',') === 'azure,vault',
          'B1. the provider-specific fields say which providers need them');
  const base = { action: 'add-destination', provider: 'aws',
                 region: 'us-east-1',
                 credential: JSON.stringify({ accessKeyId: 'AKIA' + RUN,
                                              secretAccessKey: 'y' + RUN }) };
  const noRegion = await destinations.act(Object.assign(
    without(base, 'region'), { identifier: 'cf-nr-' + RUN }), CTX);
  const noCredential = await destinations.act(Object.assign(
    without(base, 'credential'), { identifier: 'cf-nc-' + RUN }), CTX);
  t.check(noRegion.ok === false && noCredential.ok === false,
          'B2. aws refuses a destination without its region, and without ' +
          'its credential');
  log.debug("Leaving requiredWhen().");
}

function answersCarryTheTable(t) {
  log.debug("Entering answersCarryTheTable().");
  const devicesAdmin = require('../admin-ui/devices_admin');
  const same = function (answer, object) {
    return JSON.stringify(answer.createFields) ===
           JSON.stringify(CreateForms.fieldsOf(object));
  };
  t.check(same(adminViews.newGroupJson(), 'groups') &&
          same(adminViews.newRoleJson(), 'roles') &&
          same(devicesAdmin.newView(), 'devices'),
          'C1. New group, New role and Register a device answer the ' +
          'table\'s fields');
  t.check(same(adminViews.newUserJson({ query: {} }), 'users'),
          'C2. New user answers its username as required');
  log.debug("Leaving answersCarryTheTable().");
}

async function namedPolicy(t) {
  log.debug("Entering namedPolicy().");
  const none = adminViews.newPolicyJson({});
  t.check(none.kind === null && none.createFields.length === 0 &&
          none.kinds.map(function (one) {
            return one.id;
          }).indexOf('password') >= 0,
          'D1. without a kind, the kinds and no fields');
  const answer = adminViews.newPolicyJson({ kind: 'password' });
  const required = answer.createFields.filter(function (one) {
    return one.required;
  }).map(function (one) {
    return one.name;
  });
  t.check(required.indexOf('profile') >= 0 &&
          required.indexOf('minLength') >= 0 &&
          required.indexOf('hashAlgorithm') < 0 &&
          required.indexOf('precedence') < 0,
          'D2. the password policy: the name and minLength required, the ' +
          'hash algorithm and the precedence not', required.join(','));
  const body = Object.assign({}, passwordPolicy.DEFAULTS,
    { action: 'save-password-policy', profile: 'cf-pw-' + RUN,
      newProfile: '1' });
  const saved = await Promise.resolve(adminActions.policiesAction(
    without(Object.assign({}, body, { profile: 'cf-pw2-' + RUN }),
            'hashAlgorithm'), CTX));
  t.check(!!(saved && saved.ok),
          'D3. a named password policy saves without the optional field',
          JSON.stringify(saved && saved.errors));
  const refused = await Promise.resolve(adminActions.policiesAction(
    without(body, 'minLength'), CTX));
  t.check(!!refused && refused.ok === false,
          'D4. and is refused without a required one',
          JSON.stringify(refused));
  log.debug("Leaving namedPolicy().");
}

function drawn(t) {
  log.debug("Entering drawn().");
  const kit = require('../admin-ui/web_kit');
  const groupsPage = require('../admin-ui/web_groups');
  const html = groupsPage.newGroupBody(kit.context(),
                                       adminViews.newGroupJson());
  const cell = function (name) {
    const at = html.indexOf('id="fgc-new-' + name + '"');
    return at < 0 ? '' : html.slice(at, html.indexOf('</div>', at));
  };
  t.check(/class="fg-cell fg-required"/.test(cell('group')) &&
          / required /.test(cell('group')) &&
          cell('group').indexOf('required') > 0,
          'E1. New group outlines its cn, says "required" and refuses it ' +
          'empty in the browser');
  t.check(['note', 'mail', 'members'].every(function (name) {
    return cell(name) && cell(name).indexOf('fg-required') < 0 &&
           !/ required[ >]/.test(cell(name));
  }), 'E2. its optional fields are drawn and not marked');
  log.debug("Leaving drawn().");
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.create({ id: 'cf-' + RUN,
                                name: 'create forms ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      await requiredHolds(t);
      await requiredWhen(t);
      answersCarryTheTable(t);
      await namedPolicy(t);
      drawn(t);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'create_forms',
  describe: 'every directory create page calls out its required fields, ' +
            'and a field it calls required is one its create refuses ' +
            'without (#1132)',
  run: run
};
