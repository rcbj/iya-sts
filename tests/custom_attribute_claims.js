// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/custom_attribute_claims.js
//
// ===========================================================================
// A REALM'S CUSTOM ATTRIBUTES AS CLAIMS (#700, a follow-up of #396).
//
// In a realm this test creates, with three custom attributes — an integer, a
// multi-valued string and a date — and one person holding a value of each:
//
//   A. The catalogue every claim set chooses from carries them, marked
//      custom, after the catalogue's own rows; another realm does not.
//   B. A selection may name them, and an unknown name is still refused; the
//      other realm refuses this realm's names.
//   C. An access token carries each under its own name, typed by its
//      syntax: a number, an array of every value, a date as YYYY-MM-DD.
//   D. A SAML assertion carries them as text, the multi-valued one as one
//      attribute with a value each.
//   E. The Kerberos PAC set carries each ticked one with every value.
//   F. OpenID Connect Core 5.5: a client may ask for one by name.
//   G. Only the directory: a person without a value carries no claim.
//   H. CAEP: a write that moved a ticked custom attribute moves its claim.
//   I. A custom attribute named as a catalogue claim is not offered.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const claimAttributes = require('../common/claim_attributes');
const stats = require('../common/admin_stats');
const attributePolicy = require('../common/attribute_policy');
const caep = require('../ssf/caep');

const log = require('bunyan').createLogger({ name: 'custom_attribute_claims',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const PERSON = 'cac-person-' + RUN;
const BARE = 'cac-bare-' + RUN;

function names(rows) {
  log.debug('Entering names().');
  log.debug('Leaving names().');
  return rows.map(function (row) {
    return row.ldap;
  });
}

function inTheRealm(t) {
  log.debug('Entering inTheRealm().');
  const defined = [
    attributePolicy.define({ name: 'costCentreCode', label: 'Cost centre',
                             syntax: 'integer' }),
    attributePolicy.define({ name: 'badgeIds', label: 'Badges',
                             syntax: 'string', multiValued: true }),
    attributePolicy.define({ name: 'hiredOn', label: 'Hired on',
                             syntax: 'date' })];
  t.check(defined.every(function (one) {
    return one && one.ok;
  }), 'precondition: three custom attributes are defined',
          JSON.stringify(defined.map(function (one) {
            return one.errors || one.ok;
          })));
  ldap.createUser(PERSON, { invent: false, attributes: {
    costCentreCode: ['42'], badgeIds: ['b-1', 'b-2'],
    hiredOn: ['20260131'] } });
  ldap.createUser(BARE, { invent: false, attributes: {} });

  // A.
  const rows = claimAttributes.catalogueRows();
  const custom = rows.filter(function (row) {
    return row.custom;
  });
  t.check(custom.map(function (row) {
    return row.ldap + '=' + row.claim;
  }).join(',') === 'badgeIds=badgeIds,costCentreCode=costCentreCode,' +
                   'hiredOn=hiredOn' &&
          rows.indexOf(custom[0]) === rows.length - 3 &&
          custom.every(function (row) {
            return row.generated === false;
          }),
          'A1. the catalogue carries the three, marked custom, last, ' +
          'never generated', JSON.stringify(custom));

  // B.
  const chosen = ['costCentreCode', 'badgeIds', 'hiredOn'];
  const selected = ['access_token', 'saml2', 'kerberos-pac'].map(
    function (set) {
      return claimAttributes.setSelection(set, chosen.concat(['mail']));
    });
  t.check(selected.every(function (one) {
    return one.ok;
  }) && ['mail'].concat(chosen).every(function (one) {
    return claimAttributes.selectedNames('access_token').indexOf(one) >= 0;
  }),
          'B1. a selection names them, in the three sets',
          JSON.stringify(selected.map(function (one) {
            return one.errors || one.attributes;
          })));
  const unknown = claimAttributes.setSelection('access_token',
                                               ['costCentreCode', 'nope']);
  t.check(unknown.ok === false &&
          claimAttributes.isSelected('access_token', 'costCentreCode'),
          'B2. an unknown name still refuses the whole selection',
          JSON.stringify(unknown.errors));
  const checked = claimAttributes.checkNames(['hiredOn', 'nope']);
  t.check(checked.ok === false && checked.names.join() === 'hiredOn',
          'B3. an application\'s selection may name one too (checkNames)',
          JSON.stringify(checked));

  // C.
  const token = stats.jwtClaims('access_token', { username: PERSON });
  t.check(token.costCentreCode === 42 &&
          JSON.stringify(token.badgeIds) === '["b-1","b-2"]' &&
          token.hiredOn === '2026-01-31',
          'C1. an access token carries each, typed by its syntax',
          JSON.stringify([token.costCentreCode, token.badgeIds,
                          token.hiredOn]));

  // D.
  const saml = stats.samlAttributes('saml2', { subject: PERSON });
  const byName = {};
  saml.forEach(function (one) {
    byName[one.name] = one;
  });
  t.check(byName.costCentreCode && byName.costCentreCode.value === '42' &&
          byName.badgeIds && Array.isArray(byName.badgeIds.values) &&
          byName.badgeIds.values.join() === 'b-1,b-2' &&
          byName.badgeIds.value === undefined &&
          byName.hiredOn && byName.hiredOn.value === '2026-01-31',
          'D1. an assertion carries them as text, the multi-valued one as ' +
          'one attribute with a value each',
          JSON.stringify([byName.costCentreCode, byName.badgeIds,
                          byName.hiredOn]));

  // E.
  const pac = stats.kerberosPacClaims({ username: PERSON });
  const pacBy = {};
  pac.forEach(function (one) {
    pacBy[one.name] = one;
  });
  t.check(pacBy.costCentreCode &&
          JSON.stringify(pacBy.costCentreCode.values) === '["42"]' &&
          pacBy.badgeIds && pacBy.badgeIds.values.length === 2,
          'E1. the Kerberos PAC set carries each with every value',
          JSON.stringify(pac.map(function (one) {
            return one.name + '=' + JSON.stringify(one.values);
          })));

  // F.
  const asked = claimAttributes.requestedClaimsFor(PERSON,
                                                   ['hiredOn', 'nothing']);
  t.check(asked.claims.hiredOn === '2026-01-31' &&
          asked.unknown.join() === 'nothing' &&
          claimAttributes.requestableClaims().some(function (one) {
            return one.claim === 'costCentreCode';
          }),
          'F1. a client may ask for one by name, and it is requestable',
          JSON.stringify(asked));

  // G.
  const bare = stats.jwtClaims('access_token', { username: BARE });
  t.check(!('costCentreCode' in bare) && !('badgeIds' in bare) &&
          !('hiredOn' in bare),
          'G1. only the directory: a person without a value carries none, ' +
          'and nothing is invented', JSON.stringify(bare));

  // H.
  const change = caep.claimsChangeFor({ username: PERSON, kind: 'updated',
    before: { costcentrecode: ['42'] }, after: { costcentrecode: ['43'] } });
  t.check(!!change && change.claims.costCentreCode === '43',
          'H1. a write that moved a custom attribute moves its claim',
          JSON.stringify(change));

  // I.
  const clash = attributePolicy.define({ name: 'birthdate',
                                         label: 'Clash', syntax: 'date' });
  if (clash && clash.ok) {
    t.check(names(claimAttributes.rowsInRealm()).indexOf('birthdate') < 0,
            'I1. a custom attribute named as a catalogue claim is not ' +
            'offered to the claim sets');
  } else {
    t.check(true, 'I1. a custom attribute named as a catalogue claim ' +
            'cannot be defined at all', JSON.stringify(clash.errors));
  }
  log.debug('Leaving inTheRealm().');
}

function inAnotherRealm(t) {
  log.debug('Entering inAnotherRealm().');
  t.check(claimAttributes.catalogueRows().every(function (row) {
    return !row.custom;
  }) && claimAttributes.setSelection('access_token',
                                     ['costCentreCode']).ok === false,
          'A2/B4. another realm offers none of them and refuses the name');
  log.debug('Leaving inAnotherRealm().');
}

async function run(t) {
  log.debug('Entering run().');
  const realm = realms.create({ id: 'cac-' + RUN,
                                name: 'custom claims ' + RUN }).realm;
  const other = realms.create({ id: 'cad-' + RUN,
                                name: 'custom claims other ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      inTheRealm(t);
    });
    await realms.run(other, async function () {
      inAnotherRealm(t);
    });
  } finally {
    realms.remove(realm.id);
    realms.remove(other.id);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'custom_attribute_claims',
  describe: 'A realm\'s custom attributes as claims (#700): in the ' +
            'catalogue a claim set selects from, typed in a JWT, text in a ' +
            'SAML assertion, every value in the Kerberos PAC, requestable ' +
            'by name, only from the directory, announced by CAEP, and none ' +
            'of them in another realm',
  run: run
};
