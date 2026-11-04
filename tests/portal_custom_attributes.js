// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_custom_attributes.js
//
// ===========================================================================
// A REALM'S CUSTOM ATTRIBUTES ON THE USER PORTAL (#700, 2026-11-04).
//
// rcbj's ticket: "The portal's account page shows them, with a per-attribute
// flag for whether the person sees each one and whether they may edit it
// themselves (off by default)." In a product-mode realm this test creates,
// driving the modules directly as `attribute_policy.js` does:
//
//   A. A definition's two portal flags are off by default; `define()`
//      stores them; editable implies visible, normalised rather than
//      refused.
//   B. `update-person-attribute` changes the flags, the label and the
//      description of an existing definition, through `policiesAction()`
//      too; hiding one alone ends its editing; a name the realm does not
//      define (STS-LDAP-0206), a flag that is not yes or no (0207) and a
//      changed syntax or cardinality (0208) are refused.
//   C. The Overview's view carries only the visible ones, with the
//      person's values and whether each is editable.
//   D. A self-edit of an editable one succeeds; a multi-valued one is
//      replaced as a set; a single-valued one takes one value (0629 for
//      two); one that is visible but not editable (STS-PORTAL-0628),
//      hidden (0627) or undefined (0626) is refused, changing nothing.
//   E. A custom attribute the realm's policy requires cannot be emptied
//      (STS-LDAP-0164, nothing written) and can be replaced, because the
//      new value is added before the old is removed.
//
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first: the
// flags and the operation's rules are module contracts, and the portal's
// account API route is the generic `account_api.ts` wrapper over the
// handler driven here (`tests/account_api.js` holds the wrapper, its gate
// and that every portal form has the operation that mirrors it).
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const attributePolicy = require('../common/attribute_policy');
const ldap = require('../ldap/ldap_server');
const personEditor = require('../ldap/person_editor');
const policyKinds = require('../admin-core/policy_kinds');
const adminActions = require('../admin-core/admin_actions');
const accountOverview = require('../portal/account_overview');

const log = require('bunyan').createLogger({ name: 'portal_custom_attributes',
  level: process.env.LOG_LEVEL || 'info' });

function codeOf(result) {
  log.debug('Entering codeOf().');
  log.debug('Leaving codeOf().');
  return errorCodes.codeOf(result) || '';
}

// An attribute off the entry, whichever case the store handed it back in.
function attributeOf(name, attribute) {
  log.debug('Entering attributeOf().');
  const view = ldap.objectFor(name);
  const attributes = (view && view.entry && view.entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === attribute.toLowerCase();
  })[0];
  log.debug('Leaving attributeOf().');
  return key ? [].concat(attributes[key]).map(String).sort() : [];
}

// The account API's helpers, as far as the two handlers read them: the
// answer is caught on a plain object rather than sent.
function contextStub() {
  log.debug('Entering contextStub().');
  const ctx = {
    PORTAL: '/portal',
    errorCodes: errorCodes,
    translatorFor: function translatorFor() {
      log.debug('Entering translatorFor().');
      log.debug('Leaving translatorFor().');
      return { text: function text(key) {
        log.debug('Entering text().');
        log.debug('Leaving text().');
        return key;
      } };
    },
    json: function json(res, status, body) {
      log.debug('Entering json().');
      res.status = status;
      res.body = body;
      log.debug('Leaving json().');
      return res;
    },
    refuse: function refuse(res, status, code, errors) {
      log.debug('Entering refuse().');
      res.status = status;
      res.code = code;
      res.body = { ok: false, errors: [].concat(errors) };
      log.debug('Leaving refuse().');
      return res;
    }
  };
  log.debug('Leaving contextStub().');
  return ctx;
}

function callerFor(username) {
  log.debug('Entering callerFor().');
  log.debug('Leaving callerFor().');
  return { username: username, sub: 'urn:uuid:test-' + username,
           session: { user: {}, expires: Date.now() + 60000 },
           signOn: {} };
}

async function run(t) {
  log.debug('Entering run().');
  const tag = require('crypto').randomBytes(3).toString('hex');
  const product = realms.create({ id: 'pcap-' + tag, name: 'pcap-' + tag,
                                  description: 'Created by ' + __filename,
                                  overrides: { 'global.mode': 'product' } });
  // THE REALM GOES IN A finally: this file shares one process with every
  // other in-process test.
  try {
    t.check(product.ok !== false, 'a product realm was made',
            JSON.stringify(product.errors));
    realms.run(product.realm, function () {
      log.debug('Entering run() in the product realm.');
      checks(t, tag);
      log.debug('Leaving run() in the product realm.');
    });
  } finally {
    realms.remove(product.realm ? product.realm.id : 'pcap-' + tag);
  }
  log.debug('Leaving run().');
}

function checks(t, tag) {
  log.debug('Entering checks().');
  const flags = function (name) {
    log.debug('Entering flags().');
    const one = attributePolicy.definition(name) || {};
    log.debug('Leaving flags().');
    return [one.portalVisible, one.portalEditable];
  };

  // A.
  const desk = attributePolicy.define({ name: 'deskNumber', label: 'Desk',
                                        syntax: 'string' });
  const nick = attributePolicy.define({ name: 'nickName',
    label: 'Nicknames', multiValued: true, portalEditable: true });
  const colour = attributePolicy.define({ name: 'badgeColour',
    label: 'Badge colour', portalVisible: 'true' });
  t.check(desk.ok && nick.ok && colour.ok,
          'A. three custom attributes are defined',
          JSON.stringify([desk.errors, nick.errors, colour.errors]));
  t.check(JSON.stringify(flags('deskNumber')) === '[false,false]' &&
          desk.definition.portalVisible === false &&
          desk.definition.portalEditable === false,
          'A. both portal flags are off by default',
          JSON.stringify(desk.definition));
  t.check(JSON.stringify(flags('nickName')) === '[true,true]',
          'A. a definition made editable is stored visible too',
          JSON.stringify(flags('nickName')));
  t.check(JSON.stringify(flags('badgeColour')) === '[true,false]',
          'A. a definition made visible alone is not editable',
          JSON.stringify(flags('badgeColour')));
  const badFlag = attributePolicy.define({ name: 'okName', label: 'x',
                                           portalVisible: 'maybe' });
  t.check(badFlag.ok === false && codeOf(badFlag) === 'STS-LDAP-0169',
          'A. a define with a flag that is neither yes nor no is refused',
          JSON.stringify(badFlag.errors));

  // B.
  t.check(policyKinds.actions().join(',').indexOf(
            'define-person-attribute,update-person-attribute,' +
            'remove-person-attribute') >= 0 &&
          policyKinds.forAction('update-person-attribute').verb === 'act',
          'B. update-person-attribute is the kind\'s act, between define ' +
          'and remove');
  const editable = adminActions.policiesAction(
    { action: 'update-person-attribute', name: 'deskNumber',
      portalEditable: true, label: 'Desk number',
      description: 'Where you sit' },
    { via: 'api', actor: 'portal_custom_attributes' });
  const desk1 = attributePolicy.definition('deskNumber');
  t.check(editable.ok === true && desk1.portalVisible === true &&
          desk1.portalEditable === true && desk1.label === 'Desk number' &&
          desk1.description === 'Where you sit' &&
          desk1.syntax === 'string' && desk1.multi === false,
          'B. an update through policiesAction() makes it editable (and so ' +
          'visible) and changes its label and description, and nothing else',
          JSON.stringify([editable.errors, desk1]));
  const hidden = attributePolicy.redefine({ name: 'deskNumber',
                                            portalVisible: false });
  t.check(hidden.ok === true &&
          JSON.stringify(flags('deskNumber')) === '[false,false]' &&
          attributePolicy.definition('deskNumber').label === 'Desk number',
          'B. hiding it alone ends its editing, and keeps what was not sent',
          JSON.stringify([hidden.errors, flags('deskNumber')]));
  const refusals = [
    [attributePolicy.redefine({ name: 'noSuchThing', label: 'x' }),
     'STS-LDAP-0206', 'a name the realm does not define'],
    [attributePolicy.redefine({ name: 'deskNumber', portalEditable: 'x' }),
     'STS-LDAP-0207', 'a flag that is neither yes nor no'],
    [attributePolicy.redefine({ name: 'deskNumber', label: '' }),
     'STS-LDAP-0207', 'an empty label'],
    [attributePolicy.redefine({ name: 'deskNumber', syntax: 'integer' }),
     'STS-LDAP-0208', 'a changed syntax'],
    [attributePolicy.redefine({ name: 'nickName', multiValued: false }),
     'STS-LDAP-0208', 'a changed cardinality']
  ];
  refusals.forEach(function (one) {
    t.check(one[0].ok === false && codeOf(one[0]) === one[1],
            'B. ' + one[2] + ' is refused as ' + one[1],
            JSON.stringify(one[0].errors));
  });
  const same = attributePolicy.redefine({ name: 'nickName', syntax: 'string',
                                          multiValued: 'multiple' });
  t.check(same.ok === true && JSON.stringify(flags('nickName')) ===
            '[true,true]',
          'B. the syntax and cardinality sent as they are change nothing',
          JSON.stringify(same.errors));

  // A person, and an administrator's value of the visible, read-only one.
  const person = 'pcap-' + tag;
  const made = ldap.createUser(person, { invent: false,
    attributes: { givenName: 'Ada', sn: 'Lovelace',
                  mail: 'ada@pcap.example.test' } });
  const painted = personEditor.update(person,
    { attribute: 'badgeColour', mode: 'set', value: 'blue' },
    { actor: 'portal_custom_attributes', via: 'test' });
  t.check(made.ok === true && painted.ok === true,
          'a person is created and given a badge colour by an administrator',
          JSON.stringify([made.errors, painted.errors]));

  // C.
  const overview = new accountOverview.AccountOverview(
    accountOverview.AccountOverview.defaultDeps());
  const view = overview.overview(callerFor(person));
  const shown = (view.customAttributes || []).map(function (one) {
    return one.name + ':' + one.editable + ':' + one.values.join('|');
  });
  t.check(JSON.stringify(shown) ===
            JSON.stringify(['badgeColour:false:blue', 'nickName:true:']),
          'C. the Overview carries the visible custom attributes only, with ' +
          'the person\'s values and whether each is editable',
          JSON.stringify(view.customAttributes));
  const row = (view.customAttributes || []).filter(function (one) {
    return one.name === 'nickName';
  })[0] || {};
  t.check(row.label === 'Nicknames' && row.multi === true &&
          row.syntax === 'string' && row.description === '',
          'C. each row carries its label, syntax, cardinality and ' +
          'description', JSON.stringify(row));

  // D.
  const ctx = contextStub();
  const post = function (body) {
    log.debug('Entering post().');
    log.debug('Leaving post().');
    return overview.setCustomAttribute(ctx, {}, callerFor(person), body);
  };
  const first = post({ attribute: 'nickName', values: ['Ada', 'Countess'] });
  t.check(first.status === 200 && first.body.ok === true &&
          JSON.stringify(attributeOf(person, 'nickName')) ===
            JSON.stringify(['Ada', 'Countess']),
          'D. a self-edit of an editable multi-valued attribute writes ' +
          'every value sent', JSON.stringify([first.body,
                                              attributeOf(person,
                                                          'nickName')]));
  const second = post({ attribute: 'NICKNAME',
                        values: ['Countess', 'Enchantress', ''] });
  t.check(second.status === 200 &&
          JSON.stringify(attributeOf(person, 'nickName')) ===
            JSON.stringify(['Countess', 'Enchantress']),
          'D. a second edit replaces the set: one kept, one added, one ' +
          'removed, and an empty box is no value',
          JSON.stringify([second.body, attributeOf(person, 'nickName')]));
  const read = post({ attribute: 'badgeColour', values: ['red'] });
  const hiddenEdit = post({ attribute: 'deskNumber', values: ['12B'] });
  const unknown = post({ attribute: 'favouriteColour', values: ['red'] });
  t.check(read.status === 403 && read.code === 'STS-PORTAL-0628' &&
          hiddenEdit.status === 403 && hiddenEdit.code === 'STS-PORTAL-0627' &&
          unknown.status === 400 && unknown.code === 'STS-PORTAL-0626' &&
          JSON.stringify(attributeOf(person, 'badgeColour')) === '["blue"]' &&
          attributeOf(person, 'deskNumber').length === 0,
          'D. one visible but not editable, one hidden and one undefined ' +
          'are refused as 0628, 0627 and 0626, changing nothing',
          JSON.stringify([read.code, hiddenEdit.code, unknown.code]));
  attributePolicy.redefine({ name: 'deskNumber', portalEditable: true });
  const single = post({ attribute: 'deskNumber', values: ['12B'] });
  const moved = post({ attribute: 'deskNumber', values: '12C' });
  const two = post({ attribute: 'deskNumber', values: ['1', '2'] });
  t.check(single.status === 200 && moved.status === 200 &&
          two.status === 400 && two.code === 'STS-PORTAL-0629' &&
          JSON.stringify(attributeOf(person, 'deskNumber')) === '["12C"]',
          'D. a single-valued attribute is set to the one value sent, and ' +
          'two values are refused as 0629',
          JSON.stringify([single.body, moved.body, two.body]));

  // E.
  const required = attributePolicy.save('default', { requiredAttributes:
    ['givenName', 'sn', 'mail', 'nickName'] });
  const emptied = post({ attribute: 'nickName', values: [] });
  t.check(required.ok === true && emptied.status === 400 &&
          emptied.code === 'STS-LDAP-0164' &&
          JSON.stringify(attributeOf(person, 'nickName')) ===
            JSON.stringify(['Countess', 'Enchantress']),
          'E. a required custom attribute cannot be emptied (0164), and ' +
          'nothing is written', JSON.stringify([required.errors,
                                               emptied.body]));
  const replaced = post({ attribute: 'nickName', values: ['Lady'] });
  t.check(replaced.status === 200 &&
          JSON.stringify(attributeOf(person, 'nickName')) === '["Lady"]',
          'E. a required multi-valued attribute is replaced outright: the ' +
          'new value is added before the old ones are removed',
          JSON.stringify([replaced.body, attributeOf(person, 'nickName')]));
  attributePolicy.reset('default');
  log.debug('Leaving checks().');
}

module.exports = {
  name: 'portal_custom_attributes',
  describe: 'a realm\'s custom attributes on the user portal: the two ' +
            'definition flags, update-person-attribute, the Overview\'s ' +
            'customAttributes and POST /account-api/attributes (#700)',
  run: run
};
