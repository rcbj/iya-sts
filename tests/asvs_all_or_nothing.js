// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/asvs_all_or_nothing.js
//
// A business operation that is refused in part leaves nothing behind.

const applications = require('../common/applications');
require('../ldap/ldap_server');
const ldap = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const adminActions = require('../admin-core/admin_actions');
const personEditor = require('../ldap/person_editor');

function valueOf(who, name) {
  const row = personEditor.editorFor(who).attributes.filter(function (one) {
    return one.name === name;
  })[0];
  return row ? row.values.map(String).join(',') : '';
}

function run(t) {
  const id = 'aon-app-' + Date.now();
  const made = adminActions.applicationsAction({ action: 'create',
    identifier: id, 'field.samlSpMetadata': 'this is not metadata',
    present: 'samlSpMetadata' }, ['saml2']);
  t.equal(made && made.ok, false,
          'a create whose metadata is refused is refused', JSON.stringify(made));
  t.equal(applications.get(id), null, 'and leaves no application behind');

  const who = 'aon-person-' + Date.now();
  ldap.createUser(who, { invent: false, attributes: { cn: who, sn: 'before', title: 'before',
    givenName: who, mail: who + '@example.com' } });
  void credentials;
  const before = valueOf(who, 'title');
  const saved = adminActions.usersAction({ action: 'update-fields', user: who,
    fields: { title: 'after', c: 'zz' } },
                                         { actor: 'tester', via: 'test' });
  t.equal(saved && saved.ok, false, 'a partly refused save is refused',
          JSON.stringify(saved));
  t.equal(valueOf(who, 'title'), before, 'and what it had changed is put back');
  t.check(/Nothing was saved/.test(JSON.stringify(saved.errors)),
          'and it says so', JSON.stringify(saved));
}

module.exports = {
  name: 'asvs_all_or_nothing',
  describe: 'a partly refused business operation leaves nothing behind',
  run: run
};
