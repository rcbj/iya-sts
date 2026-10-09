// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_xacml.js
//
// ===========================================================================
// THE PASSKEY REFUSALS AS RULES OF THE ISSUANCE POLICY (#536). The passkey
// policy (#527-#535) is where a realm CONFIGURES its passkeys; whether one
// may be registered (`register-passkey`) or may sign somebody in
// (`use-passkey`) is DECIDED by the issuance policy, from facts
// `common/passkey_policy.ts` gathers. These are the claims about that:
//
//   A. THE BUILT-IN RULES, with no decider loaded (the gate evaluates the
//      built-in document itself): each refusal the passkey policy made as
//      code is made by a rule, with the same error code — STS-AUTHN-0312 to
//      0317, 0320 and 0321 — and every other key is allowed. A rule fires
//      only on a question carrying its fact group.
//   B. THE RULES READ FROM THE FACTS (`common/passkey_rules.js`, the defect
//      path) give the built-in document's answer — verdict, code and reason
//      — over a grid of every fact each rule reads, for both actions, and
//      the two reason tables agree.
//   C. THE PASSKEY POLICY ASKS: `refusalFor()` through the gate answers the
//      code and the sentence the door always said, under a profile saved in
//      a throwaway realm.
//   D. A REALM'S OWN ISSUANCE POLICY IS HONOURED through the issuance PEP:
//      a rule letting synced passkeys sign in makes it so in that realm only;
//      a registration, which its document has no verdict on, still falls to
//      the built-in rule; and a realm rule refusing with a reason of its own
//      and no code records STS-AUTHN-0322.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
// Fills the directory slots the policy and the xacml store go through.
require('../ldap/ldap_server');
const gate = require('../common/issuance_gate');
const passkeyPolicy = require('../common/passkey_policy');
const passkeyRules = require('../common/passkey_rules');
const model = require('../xacml/xacml_model');
const xml = require('../xacml/xacml_xml');
const xacmlStore = require('../xacml/xacml_store');
const templates = require('../xacml/xacml_templates');
const verdicts = require('../xacml/xacml_passkey_verdicts');
// THE ISSUANCE PEP. Requiring it installs it as the gate's decider; `run()`
// puts back whatever was there, because every file in `run.js`'s one process
// shares the gate.
const deciderBefore = gate.deciderInstalled();
const rolePep = require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'passkey_xacml',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const PK = templates.PASSKEY_ATTRIBUTE;
const AAGUID_A = 'ee882879721c491397753dfcce97072a';
const AAGUID_B = 'cb69481e8ff7403993ec0a2729a154a8';

// A passkey policy profile's rows as the question carries them.
function policyRows(fields) {
  log.debug('Entering policyRows().');
  log.debug('Leaving policyRows().');
  return Object.assign({
    backupEligibility: 'allow', enforcePinLength: false, minPinLength: 4,
    pinLengthOnlyIfSupported: false, enforceAttestationAtSignIn: false,
    enterpriseSerialAttribute: '' }, fields || {});
}

// A question, as `passkey_policy.ts`'s `question()` builds one.
function question(action, groups, facts, policy, settings) {
  log.debug('Entering question().');
  log.debug('Leaving question().');
  return Object.assign({ action: action, subject: 'pk-' + RUN,
                         groups: groups, policy: policyRows(policy),
                         settings: settings || {} }, facts || {});
}

// The built-in document's answer, with no decider: the gate's own path.
function builtIn(q) {
  log.debug('Entering builtIn().');
  const out = gate.checkPasskey(q);
  log.debug('Leaving builtIn().');
  return out;
}

function theBuiltInRules(t) {
  log.debug('Entering theBuiltInRules().');
  t.log.info('=== A. the built-in rules, with no decider ===');
  const R = PK.REGISTER_ACTION;
  const U = PK.USE_ACTION;
  const expect = function (label, q, code, reason) {
    log.debug('Entering expect().');
    const got = builtIn(q);
    const ok = code
      ? got.verdict === 'refuse' && got.code === code && got.reason === reason
      : got.verdict === 'allow';
    t.check(ok && got.decidedBy === 'built-in', label, JSON.stringify(got));
    log.debug('Leaving expect().');
  };
  expect('A1. a plain key is registered and signs in under the defaults',
         question(R, ['backup-eligible', 'pin-length', 'serial'],
                  { backupEligible: true, minPinLength: null, serial: '' }),
         '', '');
  expect('A2. a synced key is refused at registration where the policy ' +
         'takes only device-bound ones (STS-AUTHN-0312)',
         question(R, ['backup-eligible'], { backupEligible: true },
                  { backupEligibility: 'disallow' }),
         'STS-AUTHN-0312', 'backup-eligible');
  expect('A2b. and at sign-in (STS-AUTHN-0313)',
         question(U, ['backup-eligible'], { backupEligible: true },
                  { backupEligibility: 'disallow' }),
         'STS-AUTHN-0313', 'backup-eligible');
  expect('A2c. a device-bound key is not',
         question(U, ['backup-eligible'], { backupEligible: false },
                  { backupEligibility: 'disallow' }), '', '');
  expect('A2d. nor one whose flag no door read (no fact, no rule)',
         question(U, ['backup-eligible'], {},
                  { backupEligibility: 'disallow' }), '', '');
  const pin = { enforcePinLength: true, minPinLength: 6 };
  expect('A3. a reported PIN below the minimum is refused at registration ' +
         '(STS-AUTHN-0314)',
         question(R, ['pin-length'], { minPinLength: 4 }, pin),
         'STS-AUTHN-0314', 'pin-length');
  expect('A3b. and at sign-in (STS-AUTHN-0315)',
         question(U, ['pin-length'], { minPinLength: 4 }, pin),
         'STS-AUTHN-0315', 'pin-length');
  expect('A3c. one long enough is not',
         question(U, ['pin-length'], { minPinLength: 6 }, pin), '', '');
  expect('A3d. none reported is refused unless the policy accepts that',
         question(R, ['pin-length'], { minPinLength: null }, pin),
         'STS-AUTHN-0314', 'pin-length');
  expect('A3e. and accepted where pinLengthOnlyIfSupported is on',
         question(R, ['pin-length'], { minPinLength: null },
                  Object.assign({ pinLengthOnlyIfSupported: true }, pin)),
         '', '');
  expect('A3f. a question without the pin-length group never trips the ' +
         'rule, whatever the policy says',
         question(U, ['backup-eligible'], { backupEligible: false }, pin),
         '', '');
  const bound = { enterpriseSerialAttribute: 'employeeSerial' };
  expect('A4. a bound realm refuses a key naming no serial (STS-AUTHN-0321)',
         question(R, ['serial'], { serial: '', serialHeld: false }, bound),
         'STS-AUTHN-0321', 'serial-missing');
  expect('A4b. and one naming a serial the person does not hold ' +
         '(STS-AUTHN-0320)',
         question(R, ['serial'], { serial: 'S1', serialHeld: false }, bound),
         'STS-AUTHN-0320', 'serial-not-held');
  expect('A4c. and registers one they hold',
         question(R, ['serial'], { serial: 'S1', serialHeld: true }, bound),
         '', '');
  const held = { enforceAttestationAtSignIn: true };
  const trusted = { verified: true, trusted: true, aaguid: AAGUID_A,
                    listed: true, compromised: false, rank: 1, fips: false };
  const list = { attestationPolicy: 'verify-if-present',
                 allowedAaguids: [AAGUID_B], requiredRank: 0,
                 requireFips: false };
  expect('A5. an AAGUID off the list is refused at sign-in while the ' +
         'policy holds sign-ins to attestation (STS-AUTHN-0316)',
         question(U, ['attestation'], { attestation: trusted }, held, list),
         'STS-AUTHN-0316', 'attestation-aaguid');
  expect('A5b. and allowed while it does not',
         question(U, ['attestation'], { attestation: trusted }, {}, list),
         '', '');
  expect('A5c. a compromised model is refused first',
         question(U, ['attestation'], {
           attestation: Object.assign({}, trusted, { compromised: true }) },
                  held, list),
         'STS-AUTHN-0316', 'attestation-compromised');
  expect('A5d. metadata that could not be read refuses (STS-AUTHN-0317)',
         question(U, ['attestation'], {
           attestation: { verified: true, trusted: true, aaguid: AAGUID_A,
                          unchecked: true } }, held, list),
         'STS-AUTHN-0317', 'attestation-unchecked');
  expect('A5e. a key with no trusted statement fails a rule demanding trust',
         question(U, ['attestation'], {
           attestation: Object.assign({}, trusted, { trusted: false,
                                                     aaguid: AAGUID_B }) },
                  held, list),
         'STS-AUTHN-0316', 'attestation-untrusted');
  expect('A5f. a model below the certification level is refused',
         question(U, ['attestation'], { attestation: trusted }, held,
                  { attestationPolicy: 'verify-if-present',
                    allowedAaguids: [], requiredRank: 3,
                    requireFips: false }),
         'STS-AUTHN-0316', 'attestation-level');
  expect('A5g. and nothing is refused while the attestation policy is off ' +
         'and nothing demands trust',
         question(U, ['attestation'], {
           attestation: { verified: false, trusted: false, aaguid: '',
                          listed: true, compromised: true } }, held,
                  { attestationPolicy: 'off', allowedAaguids: [],
                    requiredRank: 0, requireFips: false }), '', '');
  t.check(gate.KINDS.indexOf(gate.PASSKEY.REGISTER) < 0 &&
          gate.KINDS.indexOf(gate.PASSKEY.USE) < 0,
          'A6. neither passkey action is an issuance kind');
  log.debug('Leaving theBuiltInRules().');
}

// Every combination of the values each rule reads.
function grid() {
  log.debug('Entering grid().');
  const out = [];
  const R = PK.REGISTER_ACTION;
  const U = PK.USE_ACTION;
  [undefined, false, true].forEach(function (be) {
    ['allow', 'disallow'].forEach(function (bePolicy) {
      [null, 3, 6].forEach(function (reported) {
        [false, true].forEach(function (enforce) {
          [4, 6].forEach(function (min) {
            [false, true].forEach(function (only) {
              const policy = { backupEligibility: bePolicy,
                               enforcePinLength: enforce, minPinLength: min,
                               pinLengthOnlyIfSupported: only };
              const facts = { minPinLength: reported };
              if (be !== undefined) {
                facts.backupEligible = be;
              }
              out.push(question(U, ['backup-eligible', 'pin-length'], facts,
                                policy));
              ['', 'S1'].forEach(function (serial) {
                [false, true].forEach(function (serialHeld) {
                  ['', 'employeeSerial'].forEach(function (attribute) {
                    out.push(question(R, ['backup-eligible', 'pin-length',
                                          'serial'],
                      Object.assign({ serial: serial,
                                      serialHeld: serialHeld }, facts),
                      Object.assign({ enterpriseSerialAttribute: attribute },
                                    policy)));
                  });
                });
              });
            });
          });
        });
      });
    });
  });
  [false, true].forEach(function (enforce) {
    ['off', 'verify-if-present', 'require-trusted'].forEach(function (pol) {
      [[], [AAGUID_A]].forEach(function (aaguids) {
        [0, 3].forEach(function (requiredRank) {
          [false, true].forEach(function (requireFips) {
            ['', 'employeeSerial'].forEach(function (attribute) {
              [false, true].forEach(function (trusted) {
                [AAGUID_A, AAGUID_B].forEach(function (aaguid) {
                  [undefined, false, true].forEach(function (listed) {
                    [false, true].forEach(function (compromised) {
                      [undefined, 1, 5].forEach(function (rank) {
                        [false, true].forEach(function (fips) {
                          [false, true].forEach(function (unchecked) {
                            out.push(question(U, ['attestation'], {
                              attestation: { verified: trusted,
                                trusted: trusted, aaguid: aaguid,
                                listed: listed, compromised: compromised,
                                rank: rank, fips: fips,
                                unchecked: unchecked } },
                              { enforceAttestationAtSignIn: enforce,
                                enterpriseSerialAttribute: attribute },
                              { attestationPolicy: pol,
                                allowedAaguids: aaguids,
                                requiredRank: requiredRank,
                                requireFips: requireFips }));
                          });
                        });
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
  log.debug('Leaving grid(). ' + out.length + ' question(s).');
  return out;
}

function theStrictReading(t) {
  log.debug('Entering theStrictReading().');
  t.log.info('=== B. the rules read from the facts agree with the ' +
             'document ===');
  const built = verdicts.builtInPolicy('');
  const all = grid();
  const disagreements = [];
  all.forEach(function (q) {
    const doc = verdicts.decide(q, { policy: built, builtIn: true }, {});
    const facts = passkeyRules.strictReading(q);
    if (doc.verdict !== facts.verdict || doc.code !== facts.code ||
        doc.reason !== facts.reason) {
      disagreements.push({ q: q, document: doc, facts: facts });
    }
  });
  t.check(built && all.length > 1000 && !disagreements.length,
          'B1. the strict reading and the built-in document agree on all ' +
          all.length + ' questions',
          JSON.stringify(disagreements.slice(0, 3)));
  t.check(JSON.stringify(PK.REASONS) ===
          JSON.stringify(passkeyRules.REASONS),
          'B2. the template\'s reason table and the strict reading\'s are ' +
          'the same table');
  log.debug('Leaving theStrictReading().');
}

function withDefaults(fields) {
  log.debug('Entering withDefaults().');
  log.debug('Leaving withDefaults().');
  return Object.assign({}, passkeyPolicy.DEFAULTS, fields || {});
}

function thePolicyAsks(t, realm) {
  log.debug('Entering thePolicyAsks().');
  t.log.info('=== C. the passkey policy asks the issuance policy ===');
  realms.run(realm, function () {
    const saved = passkeyPolicy.save('default', withDefaults({
      backupEligibility: 'disallow', enforcePinLength: true,
      minPinLength: 6 }));
    t.check(saved && saved.ok, 'precondition: the realm\'s passkey policy ' +
            'was saved', JSON.stringify(saved && saved.errors));
    const synced = passkeyPolicy.refusalFor('registration',
                                            { backupEligible: true,
                                              minPinLength: 8 });
    t.check(synced && synced.code === 'STS-AUTHN-0312' &&
            synced.reason === 'backup-eligible' &&
            /accepts only device-bound passkeys/.test(synced.why),
            'C1. a synced key is refused with the code and the sentence it ' +
            'always had', JSON.stringify(synced));
    const short = passkeyPolicy.refusalFor('sign-in', { backupEligible: false,
                                                        minPinLength: 4 });
    t.check(short && short.code === 'STS-AUTHN-0315' &&
            /accepts a PIN of 4 characters/.test(short.why),
            'C2. a short PIN at sign-in is STS-AUTHN-0315, worded as before',
            JSON.stringify(short));
    t.check(passkeyPolicy.refusalFor('sign-in', { backupEligible: false,
                                                  minPinLength: 8 }) === null,
            'C3. and a device-bound key with a long PIN signs in');
    const q = passkeyPolicy.question('registration', {
      username: 'nobody-' + RUN, backupEligible: false, minPinLength: 8,
      serial: 'S1' });
    t.check(q.action === PK.REGISTER_ACTION &&
            q.groups.join(',') === 'backup-eligible,pin-length,serial' &&
            q.policy.backupEligibility === 'disallow' &&
            q.policy.minPinLength === 6 && q.serialHeld === false,
            'C4. the question carries the facts given and the selected ' +
            'profile\'s rows', JSON.stringify(q));
  });
  log.debug('Leaving thePolicyAsks().');
}

// A Permit rule on `use-passkey` for a backup-eligible key, carrying the
// passkey obligation — what an operator writes to state "synced passkeys
// may sign in here".
function syncedMaySignIn(idBase) {
  log.debug('Entering syncedMaySignIn().');
  const B = templates.PolicyBuilders;
  const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
  log.debug('Leaving syncedMaySignIn().');
  return {
    id: idBase + ':rule:synced-may-sign-in',
    effect: model.EFFECT.PERMIT,
    description: 'Synced passkeys may sign in here.',
    target: B.targetOf([
      [B.match(F1 + 'string-equal', B.value(model.TYPE.STRING, PK.USE_ACTION),
               B.designator(model.CATEGORY.ACTION, model.ATTRIBUTE.ACTION_ID,
                            model.TYPE.STRING))],
      [B.match(F1 + 'boolean-equal', B.value(model.TYPE.BOOLEAN, 'true'),
               B.designator(model.CATEGORY.RESOURCE, PK.BACKUP_ELIGIBLE,
                            model.TYPE.BOOLEAN))]]),
    condition: null,
    obligations: [{ id: PK.OBLIGATION, on: model.EFFECT.PERMIT,
      assignments: [{ attributeId: PK.VERDICT, category: null, issuer: null,
                      expression: B.value(model.TYPE.STRING, 'allow') }] }],
    advice: []
  };
}

// A Deny rule on every `use-passkey` naming a reason of its own and no code.
function noPasskeysAtAll(idBase) {
  log.debug('Entering noPasskeysAtAll().');
  const B = templates.PolicyBuilders;
  const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
  log.debug('Leaving noPasskeysAtAll().');
  return {
    id: idBase + ':rule:no-passkeys',
    effect: model.EFFECT.DENY,
    description: 'No passkey signs anybody in here.',
    target: B.targetOf([
      [B.match(F1 + 'string-equal', B.value(model.TYPE.STRING, PK.USE_ACTION),
               B.designator(model.CATEGORY.ACTION, model.ATTRIBUTE.ACTION_ID,
                            model.TYPE.STRING))]]),
    condition: null,
    obligations: [{ id: PK.OBLIGATION, on: model.EFFECT.DENY,
      assignments: [
        { attributeId: PK.VERDICT, category: null, issuer: null,
          expression: B.value(model.TYPE.STRING, 'refuse') },
        { attributeId: PK.REASON, category: null, issuer: null,
          expression: B.value(model.TYPE.STRING, 'realm-says-no') }] }],
    advice: []
  };
}

function realmPolicy(t, realm) {
  log.debug('Entering realmPolicy().');
  t.log.info('=== D. a realm\'s own issuance policy is honoured ===');
  const name = rolePep.issuancePolicyName();
  const own = templates.build('role-issuance', { decidePasskeys: 'no' },
                              { name: name });
  own.policy.rules.unshift(syncedMaySignIn(own.policy.id));
  const written = realms.run(realm, function () {
    return xacmlStore.write(name, xml.writePolicy(own.policy),
                            { enabled: true });
  });
  t.check(written && written.ok, 'precondition: the realm\'s policy was ' +
          'written', (written && written.why) || '');
  realms.run(realm, function () {
    const signIn = passkeyPolicy.refusalFor('sign-in', {
      backupEligible: true, minPinLength: 8 });
    t.check(signIn === null,
            'D1. the realm\'s rule lets a synced passkey sign in, although ' +
            'its passkey policy takes only device-bound ones',
            JSON.stringify(signIn));
    const answer = gate.checkPasskey(passkeyPolicy.question('sign-in', {
      backupEligible: true, minPinLength: 8 }));
    t.check(answer.verdict === 'allow' && answer.decidedBy === 'policy',
            'D1b. and the realm\'s policy — not the built-in one — decided',
            JSON.stringify(answer));
    const register = passkeyPolicy.refusalFor('registration', {
      backupEligible: true, minPinLength: 8 });
    t.check(register && register.code === 'STS-AUTHN-0312',
            'D2. a registration, which the realm\'s document has no verdict ' +
            'on, falls back to the built-in rule (STS-AUTHN-0312)',
            JSON.stringify(register));
  });
  const elsewhere = gate.checkPasskey(question(PK.USE_ACTION,
    ['backup-eligible'], { backupEligible: true },
    { backupEligibility: 'disallow' }));
  t.check(elsewhere.verdict === 'refuse' &&
          elsewhere.code === 'STS-AUTHN-0313',
          'D3. in the default realm the built-in rule still refuses it',
          JSON.stringify(elsewhere));
  const strict = templates.build('role-issuance', {}, { name: name });
  strict.policy.rules.unshift(noPasskeysAtAll(strict.policy.id));
  realms.run(realm, function () {
    xacmlStore.write(name, xml.writePolicy(strict.policy), { enabled: true });
    const refused = passkeyPolicy.refusalFor('sign-in', {
      backupEligible: false, minPinLength: 8 });
    t.check(refused && refused.code === 'STS-AUTHN-0322' &&
            refused.reason === 'realm-says-no' &&
            /issuance policy/.test(refused.why),
            'D4. a realm rule refusing with a reason of its own and no code ' +
            'records STS-AUTHN-0322, worded as the issuance policy\'s',
            JSON.stringify(refused));
    xacmlStore.remove(name);
  });
  log.debug('Leaving realmPolicy().');
}

async function run(t) {
  log.debug('Entering run().');
  gate.setDecider(null);
  try {
    theBuiltInRules(t);
    theStrictReading(t);
  } finally {
    gate.setDecider(deciderBefore || rolePep.decide);
  }
  // THE ISSUANCE PEP IS THE DECIDER FOR C AND D, in a throwaway realm: a
  // policy written on the default realm would decide for every file after
  // this one.
  gate.setDecider(rolePep.decide);
  const realm = realms.create({ id: 'pkx-' + RUN,
                                name: 'passkey xacml ' + RUN }).realm;
  try {
    thePolicyAsks(t, realm);
    realmPolicy(t, realm);
  } finally {
    gate.setDecider(deciderBefore || rolePep.decide);
    realms.remove(realm.id);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'passkey_xacml',
  describe: 'the passkey refusals as rules of the issuance policy (#536): ' +
            'the built-in rules and their codes, the rules read from the ' +
            'facts, the passkey policy asking, and a realm\'s own policy',
  run: run
};
