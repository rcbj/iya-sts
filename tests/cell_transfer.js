// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_transfer.js
//
// ===========================================================================
// THE TRANSFER DECISION AS POLICY (#98 D4 and D11, the design's section 6:
// "geofencing is policy, not code"). `common/cell_transfer.ts` gathers the
// facts and the issuance policy decides; these are the claims about that:
//
//   A. SINGLE-CELL MODE ASKS NOTHING: all three questions answer "allowed"
//      without reaching the gate, and nothing is relayed.
//   B. THE BUILT-IN RULE, with no decider loaded (the gate evaluates the
//      built-in document itself): a session is held away from home only in
//      the same jurisdiction; every other request is served by relaying;
//      residents are released only within their jurisdiction. Both ways
//      round, for each question.
//   C. A REALM THAT LISTS `us>ca` loosens exactly that: a `us` person's
//      session may be held in `ca` and `us` residents released to a `ca`
//      reader — and not the reverse, and not `eu`.
//   D. THE HARD GEOFENCE refuses to serve an unlisted transfer (STS-CELL-0183
//      on the answer), and still serves a listed one and a local one.
//   E. THE STRICT READING the gate falls back to on a defect is the built-in
//      document's truth table, question by question — the two copies and the
//      document cannot drift apart.
//   F. A REALM'S OWN ISSUANCE POLICY IS HONOURED through the issuance PEP: a
//      rule permitting `us` subjects to hold sessions in `eu` makes it so,
//      in that realm only; an override without the transfer rules falls
//      back to the built-in one, so the strict default never switches off.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
// Fills the directory slots the xacml store writes through.
require('../ldap/ldap_server');
const cells = require('../common/cells');
const cellTransfer = require('../common/cell_transfer');
const errorCodes = require('../common/error_codes');
const gate = require('../common/issuance_gate');
const model = require('../xacml/xacml_model');
const pdp = require('../xacml/xacml_pdp');
const xml = require('../xacml/xacml_xml');
const xacmlStore = require('../xacml/xacml_store');
const templates = require('../xacml/xacml_templates');
const transferVerdicts = require('../xacml/xacml_transfer_verdicts');
// THE ISSUANCE PEP. Requiring it installs it as the gate's decider; `run()`
// puts back whatever was there, because every file in `run.js`'s one process
// shares the gate.
const deciderBefore = gate.deciderInstalled();
const rolePep = require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'cell_transfer',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const SUBJECT = 'urn:uuid:00000000-0000-4000-8000-' + RUN + '000000';
const PEERS = JSON.stringify([
  { id: 'cac1', jurisdiction: 'ca', url: 'https://cac1.cells.test' },
  { id: 'euc1', jurisdiction: 'eu', url: 'https://euc1.cells.test' }]);

// A cell map and settings of the test's own: `cells.id` and the peers are
// restart-only, so no override can set them, and a map over a stub reader is
// the arrangement `cells.ts` is built for.
function transferIn(settings, gateOverride) {
  log.debug("Entering transferIn().");
  const values = Object.assign({ 'cells.id': 'usw2',
                                 'cells.jurisdiction': 'us',
                                 'cells.peers': PEERS }, settings || {});
  const value = function (key) {
    log.debug("Entering value().");
    log.debug("Leaving value().");
    return values[key];
  };
  const map = new cells.Cells({ value: value, log: log });
  log.debug("Leaving transferIn().");
  return new cellTransfer.CellTransfer({
    cells: map, value: value, gate: gateOverride || gate, realms: realms,
    log: log });
}

function ask(transfer, home, serving, extra) {
  log.debug("Entering ask().");
  const opts = Object.assign({ realm: '', subject: SUBJECT, homeCell: home,
                               servingCell: serving }, extra || {});
  const out = {
    hold: transfer.holdDecision(opts),
    serve: transfer.serveDecision(opts),
    release: transfer.releaseDecision({ realm: opts.realm, homeCell: home,
                                        servingCell: serving,
                                        purpose: 'directory-list' })
  };
  log.debug("Leaving ask().");
  return out;
}

function singleCell(t) {
  log.debug("Entering singleCell().");
  t.log.info('=== A. single-cell mode asks nothing ===');
  let asked = 0;
  const counting = {
    TRANSFER: gate.TRANSFER,
    checkTransfer: function checkTransfer(facts) {
      log.debug("Entering checkTransfer().");
      asked += 1;
      log.debug("Leaving checkTransfer().");
      return gate.checkTransfer(facts);
    }
  };
  const one = transferIn({ 'cells.id': '', 'cells.jurisdiction': '',
                           'cells.peers': '' }, counting);
  const got = ask(one, 'usw2', 'euc1');
  t.check(got.hold.allowed && got.serve.allowed && !got.serve.relay &&
          got.release.allowed && asked === 0,
          'A1. with cells.id empty all three answer allowed, nothing is ' +
          'relayed and the policy is not asked', JSON.stringify(got));
  const facade = cellTransfer.serveDecision({ realm: '', subject: SUBJECT,
                                              homeCell: 'x',
                                              servingCell: 'y' });
  t.check(facade.allowed && !facade.relay,
          'A2. the module\'s own instance, over this process\'s settings ' +
          '(single-cell), serves locally', JSON.stringify(facade));
  log.debug("Leaving singleCell().");
}

function builtIn(t) {
  log.debug("Entering builtIn().");
  t.log.info('=== B. the built-in rule, both ways round ===');
  const strict = transferIn({});
  const away = ask(strict, 'usw2', 'euc1');
  t.check(!away.hold.allowed,
          'B1. a us session is NOT held in eu (strict default: relay)',
          away.hold.why);
  t.check(away.serve.allowed && away.serve.relay,
          'B2. a request about a us person is still served in eu, by ' +
          'relaying it home', away.serve.why);
  t.check(!away.release.allowed &&
          errorCodes.codeOf(away.release) === 'STS-CELL-0184',
          'B3. us residents are withheld from an eu reader, STS-CELL-0184',
          away.release.why);
  const back = ask(strict, 'euc1', 'usw2');
  t.check(!back.hold.allowed && back.serve.relay && !back.release.allowed,
          'B4. and the other way round: an eu person in us is relayed, ' +
          'eu residents withheld from a us reader', JSON.stringify(back));
  const home = ask(strict, 'usw2', 'usw2');
  t.check(home.hold.allowed && home.serve.allowed && !home.serve.relay &&
          home.release.allowed,
          'B5. at home: held, served here, released', JSON.stringify(home));
  const unrecorded = ask(strict, '', 'usw2');
  t.check(unrecorded.hold.allowed && !unrecorded.serve.relay,
          'B6. a home not recorded is the serving cell: no transfer',
          JSON.stringify(unrecorded));
  const unknown = ask(strict, 'nowhere', 'usw2');
  t.check(!unknown.hold.allowed && !unknown.release.allowed,
          'B7. a home cell the service does not have is never home',
          JSON.stringify(unknown));
  const facts = transferVerdicts.requestFor({
    action: 'hold-session', subject: SUBJECT, home: 'us', serving: 'eu',
    clientCountry: 'de', listed: false, hardGeofence: false,
    category: 'session', realm: 'default' });
  const ids = [];
  facts.categories.forEach(function (c) {
    c.attributes.forEach(function (a) {
      ids.push(a.attributeId);
    });
  });
  const T = templates.TRANSFER_ATTRIBUTE;
  t.check([T.HOME_JURISDICTION, T.SERVING_JURISDICTION, T.CLIENT_COUNTRY,
           T.TRANSFER_LISTED, T.DATA_CATEGORY, T.REALM, T.HARD_GEOFENCE]
    .every(function (id) {
      return ids.indexOf(id) >= 0;
    }), 'B8. the request carries every fact of section 6 as an attribute',
  ids.join(' '));
  log.debug("Leaving builtIn().");
}

function listed(t) {
  log.debug("Entering listed().");
  t.log.info('=== C. a realm that lists us>ca ===');
  const loose = transferIn({ 'cells.permittedTransfers': 'us>ca' });
  const toCa = ask(loose, 'usw2', 'cac1');
  t.check(toCa.hold.allowed && toCa.serve.relay && toCa.release.allowed,
          'C1. a us session is held in ca, and us residents released to a ' +
          'ca reader', JSON.stringify(toCa));
  const fromCa = ask(loose, 'cac1', 'usw2');
  t.check(!fromCa.hold.allowed && !fromCa.release.allowed,
          'C2. the list is directional: a ca session is not held in us',
          JSON.stringify(fromCa));
  const toEu = ask(loose, 'usw2', 'euc1');
  t.check(!toEu.hold.allowed && !toEu.release.allowed,
          'C3. and it loosens nothing else: not us>eu', JSON.stringify(toEu));
  log.debug("Leaving listed().");
}

function geofence(t) {
  log.debug("Entering geofence().");
  t.log.info('=== D. the hard geofence ===');
  const fenced = transferIn({ 'cells.permittedTransfers': 'us>ca',
                              'cells.hardGeofence': true });
  const toEu = ask(fenced, 'usw2', 'euc1', { clientCountry: 'DE' });
  t.check(!toEu.serve.allowed && !toEu.serve.relay &&
          errorCodes.codeOf(toEu.serve) === 'STS-CELL-0183',
          'D1. an unlisted transfer is refused rather than relayed, ' +
          'STS-CELL-0183', toEu.serve.why);
  const toCa = ask(fenced, 'usw2', 'cac1');
  t.check(toCa.serve.allowed && toCa.serve.relay,
          'D2. a listed one is still served, by relaying',
          JSON.stringify(toCa.serve));
  const local = ask(fenced, 'usw2', 'usw2');
  t.check(local.serve.allowed && !local.serve.relay,
          'D3. and a person at home is served here', JSON.stringify(local));
  log.debug("Leaving geofence().");
}

function strictReadings(t) {
  log.debug("Entering strictReadings().");
  t.log.info('=== E. the strict reading is the document\'s truth table ===');
  const built = transferVerdicts.builtInPolicy('role-issuance');
  const disagreements = [];
  [gate.TRANSFER.HOLD_SESSION, gate.TRANSFER.SERVE_REQUEST,
   gate.TRANSFER.RELEASE_ATTRIBUTES].forEach(function (action) {
    [['us', 'us'], ['us', 'eu'], ['', 'us'], ['us', '']]
      .forEach(function (pair) {
        [false, true].forEach(function (isListed) {
          [false, true].forEach(function (fence) {
            const q = { action: action, subject: SUBJECT, home: pair[0],
                        serving: pair[1], listed: isListed,
                        hardGeofence: fence, category: 'session',
                        realm: 'default' };
            const request = transferVerdicts.requestFor(q);
            const doc = transferVerdicts.verdictOf(
              pdp.evaluate(built, request, {}),
              action);
            const lib = transferVerdicts.strictReading(q);
            const leaf = gate.strictTransferReading(q);
            if (doc !== lib || lib !== leaf) {
              disagreements.push(JSON.stringify(q) + ' doc=' + doc +
                                 ' lib=' + lib + ' gate=' + leaf);
            }
          });
        });
      });
  });
  t.check(built && !disagreements.length,
          'E1. the built-in document, the library\'s strict reading and ' +
          'the gate\'s copy agree on every combination of facts',
          disagreements.join('; ') || '48 combinations');
  t.equal([templates.TRANSFER_ATTRIBUTE.HOLD_ACTION,
           templates.TRANSFER_ATTRIBUTE.SERVE_ACTION,
           templates.TRANSFER_ATTRIBUTE.RELEASE_ACTION].join(','),
          [gate.TRANSFER.HOLD_SESSION, gate.TRANSFER.SERVE_REQUEST,
           gate.TRANSFER.RELEASE_ATTRIBUTES].join(','),
          'E2. the gate and the templates spell the three action-ids alike');
  t.check(gate.KINDS.indexOf(gate.TRANSFER.HOLD_SESSION) < 0,
          'E3. the transfer questions are not kinds of issuance');
  log.debug("Leaving strictReadings().");
}

// A Permit rule on `hold-session` for home `us` and serving `eu`, carrying
// the transfer obligation — what an operator writes to state "us subjects
// may hold sessions in eu".
function usMayHoldInEu(idBase) {
  log.debug("Entering usMayHoldInEu().");
  const B = templates.PolicyBuilders;
  const T = templates.TRANSFER_ATTRIBUTE;
  const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
  const is = function (category, id, value) {
    log.debug("Entering is().");
    log.debug("Leaving is().");
    return B.match(F1 + 'string-equal', B.value(model.TYPE.STRING, value),
                   B.designator(category, id, model.TYPE.STRING));
  };
  log.debug("Leaving usMayHoldInEu().");
  return {
    id: idBase + ':rule:us-may-hold-in-eu',
    effect: model.EFFECT.PERMIT,
    description: 'us subjects may hold sessions in eu.',
    // Three groups, each of one alternative: all three must hold.
    target: B.targetOf([
      [is(model.CATEGORY.ACTION, model.ATTRIBUTE.ACTION_ID, T.HOLD_ACTION)],
      [is(model.CATEGORY.ACCESS_SUBJECT, T.HOME_JURISDICTION, 'us')],
      [is(model.CATEGORY.ENVIRONMENT, T.SERVING_JURISDICTION, 'eu')]]),
    condition: null,
    obligations: [{ id: T.OBLIGATION, on: model.EFFECT.PERMIT,
      assignments: [{ attributeId: T.VERDICT, category: null, issuer: null,
                      expression: B.value(model.TYPE.STRING, 'hold') }] }],
    advice: []
  };
}

function writeIssuancePolicy(policy) {
  log.debug("Entering writeIssuancePolicy().");
  const written = xacmlStore.write(rolePep.issuancePolicyName(),
                                   xml.writePolicy(policy), { enabled: true });
  log.debug("Leaving writeIssuancePolicy().");
  return written;
}

function realmPolicy(t, realm) {
  log.debug("Entering realmPolicy().");
  t.log.info('=== F. a realm\'s own issuance policy is honoured ===');
  const strict = transferIn({});
  const opts = { realm: realm.id, subject: SUBJECT, homeCell: 'usw2',
                 servingCell: 'euc1' };
  t.check(!strict.holdDecision(opts).allowed,
          'F0. (precondition) through the PEP, the built-in policy relays ' +
          'a us session in eu');
  const name = rolePep.issuancePolicyName();
  const own = templates.build('role-issuance', { decideTransfers: 'no' },
                              { name: name });
  own.policy.rules.unshift(usMayHoldInEu(own.policy.id));
  const written = realms.run(realm, function () {
    return writeIssuancePolicy(own.policy);
  });
  t.check(written && written.ok, 'precondition: the realm\'s policy was ' +
          'written', (written && written.why) || '');
  const held = strict.holdDecision(opts);
  t.check(held.allowed && /decided by policy/.test(held.why),
          'F1. the realm\'s rule permits it: the session is held in eu, and ' +
          'the realm\'s policy — not the built-in one — decided', held.why);
  const elsewhere = strict.holdDecision(Object.assign({}, opts,
                                                      { realm: '' }));
  t.check(!elsewhere.allowed,
          'F2. in the default realm the built-in policy still relays',
          elsewhere.why);
  const back = strict.holdDecision(Object.assign({}, opts,
    { homeCell: 'euc1', servingCell: 'usw2' }));
  t.check(!back.allowed && /decided by built-in/.test(back.why),
          'F3. a question the realm\'s document has no verdict on (eu>us: ' +
          'it was built without the transfer rules) falls back to the ' +
          'built-in rule', back.why);
  const release = strict.releaseDecision({ realm: realm.id,
                                           homeCell: 'usw2',
                                           servingCell: 'euc1',
                                           purpose: 'api' });
  t.check(!release.allowed && /decided by built-in/.test(release.why),
          'F4. and the realm stated a HOLD, not a release: us residents ' +
          'are still withheld from an eu reader', release.why);
  realms.run(realm, function () {
    xacmlStore.remove(name);
  });
  log.debug("Leaving realmPolicy().");
}

async function run(t) {
  log.debug("Entering run().");
  gate.setDecider(null);
  try {
    singleCell(t);
    builtIn(t);
    listed(t);
    geofence(t);
    strictReadings(t);
  } finally {
    gate.setDecider(deciderBefore || rolePep.decide);
  }
  // THE ISSUANCE PEP IS THE DECIDER FOR F, in a throwaway realm: a policy
  // written on the default realm would decide for every file after this one.
  gate.setDecider(rolePep.decide);
  const realm = realms.create({ id: 'ct-' + RUN,
                                name: 'cell transfer ' + RUN }).realm;
  try {
    realmPolicy(t, realm);
  } finally {
    gate.setDecider(deciderBefore || rolePep.decide);
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_transfer',
  describe: 'the transfer decision as policy (#98 D4, D11): hold-session, ' +
            'serve-request and release-attributes, the strict built-in ' +
            'rule, a listed transfer, the hard geofence and a realm\'s own ' +
            'policy',
  run: run
};
