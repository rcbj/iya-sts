'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'xacml_service_own',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: xacml_service_own.js
//
// ===========================================================================
// THE TWO POLICIES THIS SERVICE DECIDES ITS OWN BOUNDARIES WITH ARE NOT IN THE
// REPOSITORY, AND THE CONSOLE HAS TO SAY SO.
//
// `role-issuance` gates all nine issuance sites and `access-control` gates the
// surfaces `common/access_gate.ts` guards. Both are BUILT IN — the
// template is called at decision time rather than seeded into `ou=policies` —
// because that container is per trust realm, so a policy seeded once into the
// default realm leaves every realm created afterwards unable to decide
// anything at all.
//
// The consequence nobody had noticed: `/admin/xacml/editor` lists
// `ou=policies` and nothing else, so on an ordinary service it offered exactly
// one policy — `seeded-rbac`, marked *root* — which is the one document on
// that page that decides nothing this service enforces. A reader would
// reasonably conclude it was what the PDP decides with.
//
// `issuancePolicyState()` and `accessPolicyState()` are what the pages report
// from. This file pins what they say in the four states that matter.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Two of the four states are reached by DISABLING the override — and disabling
// `role-issuance` takes issuance policy out of the decision for the whole
// service. Driven over HTTP against the shared suite service that is a change
// every other job would run into; here it is a store this file owns, in a
// process nothing else is using.
//
// ---------------------------------------------------------------------------
// THE BUG IT WAS WRITTEN AGAINST, because it is the one this whole change
// exists to stop repeating one level down.
//
// `accessPolicyState()` first read the entry through `store.repository()`,
// which is the facade the PDP resolves references through — so it holds only
// ENABLED policies, and a DISABLED override was simply absent from it. It
// reported `entry: false`, which is exactly the "nobody wrote one" / "somebody
// wrote one and disabled it" confusion the function was added to remove.
//
// The two fields answer two different questions and come from two different
// places: `entry`/`enabled` are facts about the DIRECTORY (`store.read()`),
// and `builtIn` is a fact about the DECISION (`accessPolicy()`, which is what
// the PEP itself calls).
// ===========================================================================

delete process.env.CONFIG_FILE;

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  require('../common/app');
  // The directory, which IS `ou=policies`. Without it both states report the
  // built-in document and neither override case is reachable.
  require('../ldap/ldap_server');
  const store = require('../xacml/xacml_store');
  const templates = require('../xacml/xacml_templates');
  const xml = require('../xacml/xacml_xml');
  const rolePep = require('../xacml/xacml_role_pep');
  const accessPep = require('../xacml/xacml_access_pep');

  t.check(store.directoryInstalled(),
          'the policy repository has a directory behind it, so an override ' +
          'can exist at all');

  // -----------------------------------------------------------------------
  // 1. NOTHING WRITTEN DOWN — the ordinary state of every realm.
  // -----------------------------------------------------------------------
  t.log.info('=== with no override, the BUILT-IN document decides ===');

  const issuance = rolePep.issuancePolicyState();
  const access = accessPep.accessPolicyState();

  t.equal(issuance.name, 'role-issuance',
          'the issuance policy is named by xacml.issuancePolicy');
  t.equal(access.name, 'access-control',
          'and the access policy by xacml.accessPolicy');
  t.equal(issuance.builtIn && access.builtIn, true,
          'BOTH ARE BUILT IN with nothing in the repository — which is why ' +
          'neither has ever appeared in the editor\'s chooser');
  t.equal(issuance.entry || access.entry, false,
          'and neither has a repository entry, which is the fact the console ' +
          'now has to distinguish from a disabled one');
  t.equal(issuance.ok && access.ok, true,
          'both are nevertheless DECIDING — the point of the section: ' +
          'absent from the repository is not absent from the service');
  t.equal(issuance.template + '/' + access.template,
          'role-issuance/access-control',
          'each names the template an override is created from, so the ' +
          'console\'s button cannot offer the wrong one');

  // -----------------------------------------------------------------------
  // 2. AN OVERRIDE, ENABLED — it wins, and it is an ordinary policy.
  // -----------------------------------------------------------------------
  t.log.info('=== an enabled override wins ===');

  const write = function (name, template) {
    log.debug("Entering write().");
    const built = templates.build(template, {}, { name: name });
    if (!built.ok) {
      log.debug("Leaving write().");
      return { ok: false, why: built.why };
    }
    log.debug("Leaving write().");
    return store.write(name, xml.writePolicy(built.policy), { enabled: true });
  };

  const madeIssuance = write('role-issuance', 'role-issuance');
  const madeAccess = write('access-control', 'access-control');
  t.equal(madeIssuance.ok && madeAccess.ok, true,
          'an override is created from the SAME template the built-in ' +
          'document is built from, which is what the console\'s button does');

  const issuance2 = rolePep.issuancePolicyState();
  const access2 = accessPep.accessPolicyState();
  t.equal(issuance2.entry && access2.entry, true,
          'both now have a repository entry');
  t.equal(issuance2.builtIn || access2.builtIn, false,
          'AND NEITHER IS BUILT IN ANY MORE — the stored document decides, ' +
          'which is what makes an override an override');
  t.equal(issuance2.ok && access2.ok, true, 'and both still decide');

  // -----------------------------------------------------------------------
  // 3. AN OVERRIDE, DISABLED — neither falls back.
  //
  // `accessPolicy()` used to fall back to the built-in document here, which
  // makes the console's Disable button mean "evaluate something else instead"
  // — the exact thing `issuancePolicy()` refuses to do and calls a lie. The
  // divergence was invisible because the branch was unreachable: the lookup
  // above it never matched, so an override was never picked up at all.
  //
  // What still differs is the CONSEQUENCE, and that is deliberate rather than
  // leftover: a disabled issuance policy REFUSES a narrowed application, and a
  // disabled access policy ALLOWS every gated surface, because refusing there
  // would close the console that is the only place to fix it.
  // -----------------------------------------------------------------------
  t.log.info('=== a disabled override: neither falls back ===');

  const doc = function (name) {
    log.debug("Entering doc().");
    log.debug("Leaving doc().");
    return store.read(name).document;
  };
  store.write('role-issuance', doc('role-issuance'), { enabled: false });
  store.write('access-control', doc('access-control'), { enabled: false });

  const issuance3 = rolePep.issuancePolicyState();
  const access3 = accessPep.accessPolicyState();

  t.equal(issuance3.entry && access3.entry, true,
          'BOTH STILL REPORT AN ENTRY. This is the assertion the first ' +
          'implementation failed: accessPolicyState() read the PDP\'s ' +
          'resolver facade, which holds only ENABLED policies, so a disabled ' +
          'override reported as no override at all');
  t.equal(issuance3.enabled === false && access3.enabled === false, true,
          'and both report it disabled, which is the other half of that ' +
          'distinction');

  t.equal(issuance3.ok, false,
          'THE ISSUANCE POLICY STOPS DECIDING: disabling it does NOT fall ' +
          'back to the built-in document, because doing so would make the ' +
          'Disable button a lie');
  t.equal(access3.ok, false,
          'AND SO DOES THE ACCESS POLICY, which it did not until 2026-09-06 ' +
          '— it fell back to the built-in document, so the same button meant ' +
          'two opposite things depending on which policy it was pressed on');
  t.check(access3.effect.indexOf('ALLOWED') >= 0,
          'and the sentence the console prints names the CONSEQUENCE, which ' +
          'is where the two legitimately differ: not deciding means every ' +
          'gated surface is allowed, because refusing would close the ' +
          'console that is the only place to fix it',
          access3.effect);

  // -----------------------------------------------------------------------
  // 4. PUT IT BACK. Every later file in this run shares the process, and a
  //    disabled issuance policy left behind refuses narrowed applications
  //    everywhere.
  // -----------------------------------------------------------------------
  store.remove('role-issuance');
  store.remove('access-control');
  const issuance4 = rolePep.issuancePolicyState();
  t.equal(issuance4.builtIn && issuance4.ok, true,
          'and deleting the override brings the built-in document back, ' +
          'which is the way out of the disabled state');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml service-own policies',
  describe: 'the two built-in policies are reported, and a disabled override ' +
            'is not the same as no override',
  run: run
};
