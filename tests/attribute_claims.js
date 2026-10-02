// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: attribute_claims.js
// ===========================================================================
// A CLAIM THAT CARRIES ANY DIRECTORY ATTRIBUTE (#94, part A).
//
// Until #94 a token or assertion could carry a directory attribute only from
// the fixed catalogue (`VC_ATTRIBUTES`), under a claim name fixed in code, so
// an attribute a federation partner or an attribute source wrote — a cost
// centre, a clearance — could not be released at all. An attribute claim is
// a row in one of the five claim sets whose value is `attribute` on the
// person's entry. Held here:
//   A. the console's and the API's act (`claimsAction` add-attribute-claim)
//      writes one, and refuses a secret, a binary value, what this service
//      keeps, a bad type and a missing attribute;
//   B. a JWT set carries it — first value, every value (`multi`), typed;
//   C. a SAML set carries it as one <Attribute> with its values;
//   D. only the directory: an entry without it adds no claim;
//   E. CAEP's claimsChangeFor() reports the claim when a write moves the
//      attribute;
//   F. `remove` takes it off by name;
//   G. the claim pages' three helps: a pick-list of what attribute sources
//      and federation mappings write, a preview of what each attribute claim
//      carries for a person, and which partners' release lists withhold a
//      claim — each in the model the page and /admin-api both answer.
// In process, in a throwaway realm; the attribute is written onto the entry
// through a federated sign-in, the door #94 part B keeps open for a person's
// own attributes.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
require('../common/claim_attributes');
const stats = require('../common/admin_stats');
const adminActions = require('../admin-core/admin_actions');
const caep = require('../ssf/caep');
const adminViews = require('../admin-core/admin_views');
const federation = require('../federation/federation');
const attributeSources = require('../attribute-sources/attribute_sources');

const log = require('bunyan').createLogger({ name: 'attribute_claims',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const PERSON = 'ac-person-' + RUN;
const BARE = 'ac-bare-' + RUN;

function act(body, sets) {
  log.debug('Entering act(). ' + body.action);
  log.debug('Leaving act().');
  return adminActions.claimsAction(body, [], sets);
}

function writeOnto(name, attributes) {
  log.debug('Entering writeOnto(). ' + name);
  ldap.autoCreateUser({ key: name, federation: {
    id: 'ac-partner-' + RUN, peer: 'https://partner.example', create: false,
    updateAttributes: true, attributes: attributes } });
  log.debug('Leaving writeOnto().');
}

function theAct(t) {
  log.debug('Entering theAct().');
  t.log.info('=== A. writing one ===');
  t.check(act({ action: 'add-attribute-claim', set: 'id_token',
                name: 'cost_center', attribute: 'costCenter' },
              stats.JWT_CLAIM_SET_IDS).ok === true &&
          act({ action: 'add-attribute-claim', set: 'id_token',
                name: 'badge', attribute: 'employeeNumber',
                type: 'number' }, stats.JWT_CLAIM_SET_IDS).ok === true &&
          act({ action: 'add-attribute-claim', set: 'id_token',
                name: 'teams', attribute: 'ou', multi: 'true' },
              stats.JWT_CLAIM_SET_IDS).ok === true,
          'A1. three attribute claims are added: one, one typed, one multi');
  const refused = [
    { attribute: 'userPassword' }, { attribute: 'stsTotpCredential' },
    { attribute: 'jpegPhoto' }, { attribute: 'no spaces' },
    { attribute: 'title', type: 'date' }, { attribute: '' }
  ].map(function (one, at) {
    return act(Object.assign({ action: 'add-attribute-claim', set: 'id_token',
                               name: 'bad' + at }, one),
               stats.JWT_CLAIM_SET_IDS);
  });
  t.check(refused.every(function (one) { return one.ok === false; }),
          'A2. a secret, a credential, a binary value, a bad name, a bad ' +
          'type and no attribute are each refused',
          JSON.stringify(refused.map(function (one) { return one.ok; })));
  t.check(act({ action: 'add-attribute-claim', set: 'saml2',
                name: 'costCenter', attribute: 'costCenter', multi: 'true' },
              stats.SAML_CLAIM_SET_IDS).ok === true,
          'A3. and one in the SAML 2.0 set');
  const rows = stats.attributeClaimRows().map(function (one) {
    return one.name + '<-' + one.attribute;
  }).sort();
  t.check(rows.join() === 'badge<-employeeNumber,costCenter<-costCenter,' +
                          'cost_center<-costCenter,teams<-ou',
          'A4. attributeClaimRows() lists every one, for CAEP',
          rows.join());
  log.debug('Leaving theAct().');
}

function theTokens(t) {
  log.debug('Entering theTokens().');
  t.log.info('=== B-D. what is issued ===');
  ldap.createUser(PERSON, { invent: false, attributes: {} });
  ldap.createUser(BARE, { invent: false, attributes: {} });
  writeOnto(PERSON, { costCenter: ['CC-7'], employeeNumber: ['42'],
                      ou: ['blue', 'green'] });
  const claims = stats.jwtClaims('id_token', { username: PERSON });
  t.check(claims.cost_center === 'CC-7',
          'B1. the claim carries the attribute on the person\'s entry',
          JSON.stringify(claims.cost_center));
  t.check(claims.badge === 42,
          'B2. typed as the row says: a number', JSON.stringify(claims.badge));
  t.check(Array.isArray(claims.teams) && claims.teams.join() === 'blue,green',
          'B3. every value, where the row is multi',
          JSON.stringify(claims.teams));
  const saml = stats.samlAttributes('saml2', { subject: PERSON });
  const cc = saml.filter(function (one) {
    return one.name === 'costCenter';
  })[0];
  t.check(!!cc && Array.isArray(cc.values) && cc.values.join() === 'CC-7',
          'C1. a SAML set carries it as one attribute with its values',
          JSON.stringify(cc));
  const bare = stats.jwtClaims('id_token', { username: BARE });
  t.check(!('cost_center' in bare) && !('badge' in bare) &&
          !('teams' in bare),
          'D1. only the directory: an entry without them carries none',
          JSON.stringify(bare));
  log.debug('Leaving theTokens().');
}

function theSignal(t) {
  log.debug('Entering theSignal().');
  t.log.info('=== E. CAEP ===');
  const change = caep.claimsChangeFor({ username: PERSON, kind: 'updated',
    before: { costcenter: ['CC-7'] }, after: { costcenter: ['CC-9'] } });
  t.check(!!change && change.claims.cost_center === 'CC-9' &&
          Array.isArray(change.claims.costCenter),
          'E1. a write that moved the attribute moves both claims naming it',
          JSON.stringify(change));
  log.debug('Leaving theSignal().');
}

function theRemoval(t) {
  log.debug('Entering theRemoval().');
  t.log.info('=== F. removing one ===');
  t.check(act({ action: 'remove', set: 'id_token', name: 'cost_center' },
              stats.JWT_CLAIM_SET_IDS).ok === true &&
          !('cost_center' in stats.jwtClaims('id_token',
                                             { username: PERSON })),
          'F1. remove takes it off by name');
  log.debug('Leaving theRemoval().');
}

async function theHelps(t) {
  log.debug('Entering theHelps().');
  t.log.info('=== G. pick-list, preview, release warning ===');
  const source = await attributeSources.act({ action: 'add-source',
    id: 'ac-hr', dialect: 'postgres', host: 'db.example.com', database: 'hr',
    user: 'reader', table: 'people', keyColumn: 'login',
    columns: { grade: 'employeeGrade' } }, { actor: 'test' });
  const inbound = federation.create({ fedId: 'ac-in-' + RUN,
    fedRole: 'service-provider', fedProtocol: 'oidc' });
  const mapped = federation.update('ac-in-' + RUN, {
    field: 'fedAttributeMap', value: 'clearance=securityClearance',
    mode: 'add' });
  const choices = adminViews.attributeClaimChoices();
  const named = function (attribute) {
    return choices.filter(function (one) {
      return one.attribute === attribute;
    })[0];
  };
  t.check(source.ok && inbound.ok !== false && mapped.ok !== false &&
          !!named('employeeGrade') &&
          /attribute source ac-hr/.test(named('employeeGrade').from.join()) &&
          !!named('securityClearance') &&
          /federation ac-in-/.test(named('securityClearance').from.join()),
          'G1. the pick-list offers what a source and a federation mapping ' +
          'write, saying who', JSON.stringify(choices));
  act({ action: 'add-attribute-claim', set: 'id_token', name: 'cc',
        attribute: 'costCenter' }, stats.JWT_CLAIM_SET_IDS);
  const preview = adminViews.attributeClaimPreview('id_token', PERSON);
  const bare = adminViews.attributeClaimPreview('id_token', BARE);
  const ccOf = function (rows) {
    return rows.filter(function (one) { return one.name === 'cc'; })[0];
  };
  t.check(ccOf(preview) && ccOf(preview).carried &&
          ccOf(preview).value === 'CC-7' && ccOf(bare) &&
          ccOf(bare).carried === false,
          'G2. the preview says what the claim carries for a person, and ' +
          'that an entry without it carries nothing',
          JSON.stringify([ccOf(preview), ccOf(bare)]));
  const outbound = federation.create({ fedId: 'ac-out-' + RUN,
    fedRole: 'identity-provider', fedProtocol: 'saml2' });
  federation.update('ac-out-' + RUN, { field: 'fedRelease', value: 'email',
                                       mode: 'add' });
  const json = adminViews.claimSetsJson(['id_token'], PERSON);
  const set = json.sets[0];
  t.check(outbound.ok !== false &&
          (set.withheldFrom.cc || []).indexOf('ac-out-' + RUN) >= 0 &&
          Array.isArray(set.attributeClaimPreview) &&
          Array.isArray(json.attributeChoices),
          'G3. a partner whose release list does not name the claim is ' +
          'reported as withholding it, in the JSON the API answers',
          JSON.stringify({ withheld: set.withheldFrom }));
  // AND THE PAGE DRAWS ALL THREE: the section the three claim pages share.
  const admin = require('../admin-ui/admin');
  const html = admin.claimSetSection('id_token', PERSON,
    require('../common/claim_attributes').catalogueValuesFor(PERSON),
    '/admin/claims');
  t.check(html.indexOf('<datalist id="ac-id_token">') >= 0 &&
          html.indexOf('value="employeeGrade"') >= 0 &&
          html.indexOf('&quot;CC-7&quot;') >= 0 &&
          html.indexOf('withheld from') >= 0 &&
          html.indexOf('have a release list') >= 0,
          'G4. the claim page draws the pick-list, the preview and the ' +
          'release warning');
  federation.remove('ac-out-' + RUN);
  federation.remove('ac-in-' + RUN);
  await attributeSources.act({ action: 'remove-source', id: 'ac-hr' },
                             { actor: 'test' });
  log.debug('Leaving theHelps().');
}

async function run(t) {
  log.debug('Entering run().');
  const realm = realms.create({ id: 'ac-' + RUN,
                                name: 'attribute claims ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      theAct(t);
      theTokens(t);
      theSignal(t);
      theRemoval(t);
      await theHelps(t);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'attribute_claims',
  describe: 'A claim that carries any directory attribute (#94): written ' +
            'and refused through claimsAction, carried typed and multi in ' +
            'a JWT set and as values in a SAML set, only from the ' +
            'directory, reported by CAEP when the attribute moves, and ' +
            'removed by name',
  run: run
};
