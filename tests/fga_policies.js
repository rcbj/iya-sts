// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'fga_policies',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: fga_policies.js
//
// ===========================================================================
// AN APPLICATION'S FINE-GRAINED AUTHORIZATION POLICY, AND ITS LIFECYCLE
// (#564, phase 1).
//
// Every application created through the console's door gets a default
// policy in `ou=policies` that it owns (`xacmlApplication`), named on it as
// `appFgaPolicy`; `appFgaEnforced` is the switch; a deleted application's
// policy is kept, disabled and orphaned. What this file holds, each a
// numbered section below:
//
//   1. a create writes a Permit policy carrying the owner, under the derived
//      PolicyId, which is NOT the root and leaves "the only enabled policy"
//      fallback answering, and is not in the PolicyIdReference map;
//   2. it cannot be made the root, at the store or at the console's action
//      (which leaves the incumbent root in place), and an edit keeps the
//      owner;
//   3. the remote PEP's pull withholds it by name and the sync token does
//      not move when it appears;
//   4. enable and disable, and enable refused for a disabled policy;
//   5. ensure() on an application created without one;
//   6. resolve()'s precise failures;
//   7. delete retires it — disabled, orphaned, kept — and a re-created
//      application of the same identifier gets a NEW policy;
//   8. per-realm isolation: none of it reaches the default realm.
//
// In process, in a THROWAWAY REALM for `xacml/CLAUDE.md`'s reason: a new
// realm's `ou=policies` is empty, so "the only enabled policy" is reachable
// and every count is exact. The pull is held through the surface's
// `pepPull()`, which is the route's body; the route's mutual-TLS gate is
// `tests/protocol/`'s.
// ===========================================================================

delete process.env.CONFIG_FILE;

function run(t) {
  log.debug("Entering run().");
  require('../common/config');
  require('../common/app');
  require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const applications = require('../common/applications');
  const store = require('../xacml/xacml_store');
  const templates = require('../xacml/xacml_templates');
  const xml = require('../xacml/xacml_xml');
  const model = require('../xacml/xacml_model');
  const pdp = require('../xacml/xacml_pdp');
  const peps = require('../xacml/xacml_pep_registry');
  const surface = require('../xacml/xacml');
  const pap = require('../xacml/xacml_admin');
  // Loading it builds its default instance and fills the lifecycle slot, as
  // the composition root's wire step does at 23c.
  const fga = require('../xacml/fga_policies');

  t.check(!!applications.fgaLifecycleInstalled(),
          'loading xacml/fga_policies fills applications.setFgaLifecycle()');

  // ---------------------------------------------------------------------
  // THE POLICYID, which needs no realm.
  // ---------------------------------------------------------------------
  t.equal(templates.fgaPolicyId('https://rs.example/api#v1'),
          'urn:sts:xacml:fga:https%3A%2F%2Frs.example%2Fapi%23v1',
          'the PolicyId percent-encodes everything outside RFC 3986\'s ' +
          'unreserved characters');
  t.equal(templates.fgaPolicyId("a!'()*~b"),
          'urn:sts:xacml:fga:a%21%27%28%29%2A~b',
          'including the five encodeURIComponent leaves bare');
  t.check(templates.fgaPolicyId('a.b') !== templates.fgaPolicyId('a-b'),
          'and is unambiguous where a slug is not: a.b and a-b differ');
  t.check(templates.catalogue().some(function (one) {
    return one.id === 'fga-default';
  }), 'fga-default is in the template catalogue the console lists');

  const id = 'fga-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(made.realm, fn);
  };
  const APP = 'https://rs.example/api#v1';
  const policyNames = [];
  try {
    inRealm(function () {
      log.debug("Entering realmBody().");
      section1to3(t, { applications, store, templates, xml, model, pdp,
                       peps, surface, pap, errorCodes, APP, policyNames });
      section4to6(t, { applications, store, fga, errorCodes, APP });
      section7(t, { applications, store, fga, APP, policyNames });
      log.debug("Leaving realmBody().");
    });
    // ---------------------------------------------------------------------
    // 8. PER-REALM ISOLATION.
    // ---------------------------------------------------------------------
    t.log.info('=== 8. none of it reaches the default realm ===');
    t.check(policyNames.length > 0 && policyNames.every(function (name) {
      return !store.read(name);
    }), '8a. no policy written in the realm is in the default realm\'s ' +
        'ou=policies', policyNames.join(', '));
    t.equal(applications.fgaStateOf(APP).known, false,
            '8b. and the application is not in the default realm\'s ' +
            'registry');
    t.equal(fga.resolve(APP).failure, 'unknown-application',
            '8c. so resolve() there knows no such application');
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

// Sections 1 to 3: the policy a create writes, the root, the pull.
function section1to3(t, k) {
  log.debug("Entering section1to3().");
  const { applications, store, templates, xml, model, pdp, peps, surface,
          pap, errorCodes, APP, policyNames } = k;
  t.log.info('=== 1. a create writes a Permit policy the application ' +
             'owns ===');
  const ordinary = store.write('ordinary', store.SEED_DOCUMENT,
                               { enabled: true });
  t.check(ordinary.ok, 'one ordinary policy in the realm\'s empty ' +
          'repository', ordinary.why);
  t.equal((store.root() || {}).name, 'ordinary',
          'it is the root as the only enabled policy');
  const tokenBefore = peps.syncToken();

  const created = applications.createApplication({
    identifier: APP, name: 'FGA resource', protocols: ['oauth2'] });
  t.check(created.ok, 'an application is created through the console\'s ' +
          'door', (created.errors || []).join(' '));
  const state = applications.fgaStateOf(APP);
  t.check(/^fga-/.test(state.policy) && state.enforced === false,
          '1a. it names its policy in appFgaPolicy, and is not enforced',
          JSON.stringify(state));
  policyNames.push(state.policy);
  const row = store.read(state.policy) || {};
  t.equal(row.application, APP,
          '1b. the policy carries the owner in xacmlApplication');
  t.check(row.enabled === true && !row.orphanedAt && row.isRoot === false,
          '1c. enabled, not orphaned, not flagged root');
  t.equal(row.id, templates.fgaPolicyId(APP),
          '1d. its PolicyId is derived from the identifier');
  t.equal(row.version, '1.0', '1e. Version 1.0');
  let parsed = null;
  try {
    parsed = xml.parsePolicy(row.document);
  } catch (e) {
    log.debug("Caught in section1to3(): " + ((e && e.message) || e));
  }
  t.check(!!parsed && parsed.rules.length === 1 &&
          parsed.rules[0].effect === model.EFFECT.PERMIT,
          '1f. one rule, and its Effect is Permit');
  const request = { returnPolicyIdList: false, combinedDecision: false,
                    categories: [
                      { category: model.CATEGORY.ACCESS_SUBJECT, id: null,
                        content: null, attributes: [] },
                      { category: model.CATEGORY.ACTION, id: null,
                        content: null, attributes: [] }
                    ] };
  t.equal(parsed && pdp.evaluate(parsed, request, {}).decision,
          model.DECISION.PERMIT,
          '1g. evaluated, it answers Permit — a decision, not a fallback');
  t.equal((store.root() || {}).name, 'ordinary',
          '1h. THE ROOT IS UNCHANGED: "the only enabled policy" still ' +
          'answers with an application\'s enabled policy beside it');
  t.equal(Object.prototype.hasOwnProperty.call(store.repository(), row.id),
          false, '1i. and the PolicyIdReference map does not hold it');
  t.equal(store.fgaPolicyFor(APP) && store.fgaPolicyFor(APP).name,
          state.policy, '1j. fgaPolicyFor() finds it by its owner');

  t.log.info('=== 2. never the root, and an edit keeps the owner ===');
  // Flagged now, so that a set-root which demoted first would show.
  store.write('ordinary', store.SEED_DOCUMENT, { enabled: true,
                                                 isRoot: true });
  const asRoot = store.write(state.policy, row.document, { isRoot: true });
  t.equal(errorCodes.codeOf(asRoot), 'STS-FGA-0001',
          '2a. the store refuses it as the root');
  const action = pap.policyAction({ action: 'set-root',
                                    name: state.policy });
  t.equal(errorCodes.codeOf(action), 'STS-FGA-0002',
          '2b. so does the console\'s set-root');
  t.equal((store.read('ordinary') || {}).isRoot, true,
          '2c. and the incumbent root was not demoted first');
  t.equal((store.root() || {}).name, 'ordinary', '2d. the root is still it');
  const edited = store.write(state.policy, row.document, { enabled: true });
  t.check(edited.ok && (store.read(state.policy) || {}).application === APP,
          '2e. a rewrite that does not name the owner keeps it, as the ' +
          'editor\'s save and enable/disable do');
  const listed = pap.policiesJson().policies.filter(function (one) {
    return one.name === state.policy;
  })[0] || {};
  t.equal(listed.application, APP,
          '2f. the console\'s list says whose it is');

  t.log.info('=== 3. withheld from the remote PEP ===');
  const pulled = surface.pepPull();
  t.check(pulled.withheld.indexOf(state.policy) >= 0 &&
          !pulled.policies.some(function (one) {
            return one.name === state.policy;
          }), '3a. the pull withholds it and names it in withheld',
          JSON.stringify(pulled.withheld));
  t.check(pulled.policies.some(function (one) {
    return one.name === 'ordinary';
  }) && pulled.root === 'ordinary', '3b. and still sends the ordinary one ' +
     'as the root');
  t.equal(peps.syncToken(), tokenBefore,
          '3c. THE SYNC TOKEN DID NOT MOVE when the application\'s policy ' +
          'appeared, because nothing sent changed');
  log.debug("Leaving section1to3().");
}

// Sections 4 to 6: the switch, ensure() and resolve().
function section4to6(t, k) {
  log.debug("Entering section4to6().");
  const { applications, store, fga, errorCodes, APP } = k;
  t.log.info('=== 4. the switch ===');
  const on = fga.enable(APP, { actor: 'test' });
  t.check(on.ok && applications.fgaStateOf(APP).enforced,
          '4a. enable sets appFgaEnforced', on.why);
  const resolved = fga.resolve(APP);
  t.check(resolved.ok && resolved.enforced && !!resolved.parsed,
          '4b. resolve() answers the parsed policy, enforced', resolved.why);
  const off = fga.disable(APP, { actor: 'test' });
  t.check(off.ok && !applications.fgaStateOf(APP).enforced &&
          fga.resolve(APP).enforced === false,
          '4c. disable clears it, and the policy still resolves');
  const name = applications.fgaStateOf(APP).policy;
  const row = store.read(name);
  store.write(name, row.document, { enabled: false });
  const refused = fga.enable(APP);
  t.equal(errorCodes.codeOf(refused), 'STS-FGA-0006',
          '4d. enable is refused while the policy is disabled');
  t.equal(applications.fgaStateOf(APP).enforced, false,
          '4e. and left the switch off');
  store.write(name, row.document, { enabled: true });

  t.log.info('=== 5. ensure() for an application created without one ===');
  const hooks = applications.fgaLifecycleInstalled();
  applications.setFgaLifecycle(null);
  let bare = null;
  try {
    bare = applications.createApplication({ identifier: 'fga-bare-app',
                                            protocols: ['oauth2'] });
  } finally {
    applications.setFgaLifecycle(hooks);
  }
  t.check(bare && bare.ok && !applications.fgaStateOf('fga-bare-app').policy,
          '5a. created before the slot is filled, it has no policy');
  t.equal(fga.resolve('fga-bare-app').failure, 'no-policy',
          '5b. resolve() says so (STS-FGA-0003)');
  const ensured = fga.ensure('fga-bare-app');
  t.check(ensured.ok && ensured.created &&
          (store.read(ensured.policy) || {}).application === 'fga-bare-app',
          '5c. ensure() creates its default policy', ensured.why);
  const again = fga.ensure('fga-bare-app');
  t.check(again.ok && !again.created && again.policy === ensured.policy,
          '5d. and a second ensure() keeps it');
  t.equal(errorCodes.codeOf(fga.ensure('no-such-app')), 'STS-FGA-0009',
          '5e. ensure() refuses an application the realm does not hold');

  t.log.info('=== 6. resolve()\'s precise failures ===');
  const reference = function (policy) {
    log.debug("Entering reference().");
    applications.setFgaState('fga-bare-app', { policy: policy });
    const answer = fga.resolve('fga-bare-app');
    log.debug("Leaving reference().");
    return errorCodes.codeOf(answer) + ' ' + answer.failure;
  };
  t.equal(reference('nothing-here'), 'STS-FGA-0004 missing-policy',
          '6a. a reference to no entry');
  t.equal(reference('ordinary'), 'STS-FGA-0005 not-its-policy',
          '6b. a reference to an ordinary policy');
  t.equal(reference(applications.fgaStateOf(APP).policy),
          'STS-FGA-0005 not-its-policy',
          '6c. a reference to another application\'s policy');
  const directory = store.directoryInstalled();
  directory.writePolicy('fga-broken', {
    objectClass: ['top', 'xacmlPolicy'], xacmlPolicyId: 'urn:x:broken',
    xacmlPolicyDocument: '<Policy', xacmlEnabled: 'TRUE',
    xacmlApplication: 'fga-bare-app' });
  t.equal(reference('fga-broken'), 'STS-FGA-0007 unparseable-policy',
          '6d. a policy of its own that does not parse');
  store.remove('fga-broken');
  reference(ensured.policy);
  t.check(fga.resolve('fga-bare-app').ok,
          '6e. and its own policy resolves again');
  log.debug("Leaving section4to6().");
}

// Section 7: deletion retires the policy.
function section7(t, k) {
  log.debug("Entering section7().");
  const { applications, store, fga, APP, policyNames } = k;
  t.log.info('=== 7. delete retires it ===');
  const name = applications.fgaStateOf(APP).policy;
  const gone = applications.deleteApplication(APP, { actor: 'test' });
  t.check(gone.ok, 'the application is deleted', (gone.errors || []).join());
  const row = store.read(name) || {};
  t.check(row.application === APP && row.enabled === false &&
          /^\d{14}Z$/.test(String(row.orphanedAt)),
          '7a. its policy is kept, DISABLED, and marked xacmlOrphanedAt',
          JSON.stringify({ enabled: row.enabled, at: row.orphanedAt }));
  t.equal(store.fgaPolicyFor(APP), null,
          '7b. an orphan is nobody\'s live policy');
  const back = applications.createApplication({ identifier: APP,
                                                protocols: ['oauth2'] });
  const now = applications.fgaStateOf(APP).policy;
  policyNames.push(now);
  t.check(back.ok && now && now !== name &&
          (store.read(now) || {}).enabled === true,
          '7c. re-created, the application gets a NEW policy and does not ' +
          'inherit the orphan', now + ' vs ' + name);
  t.check(!!(store.read(name) || {}).orphanedAt,
          '7d. and the orphan stays an orphan');
  t.equal(fga.resolve(APP).policy, now, '7e. resolve() follows the new one');
  log.debug("Leaving section7().");
}

module.exports = {
  name: 'fga policies',
  describe: 'an application\'s fine-grained policy: created with it, never ' +
            'the root, withheld from the pull, switched, retired (#564 P1)',
  run: run
};
