'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'xacml_monitor',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: xacml_monitor.js
//
// ===========================================================================
// THE COUNTERS BEHIND /admin/xacml/monitor, AND THE TWO DISTINCTIONS THAT ARE
// THE WHOLE REASON THAT PAGE IS NOT ONE NUMBER.
//
// The page reports how many authorization decisions this service is making and
// how many are refusals. Both halves of that sentence are easy to get subtly
// wrong in a way nothing shows, and each of the four sections below pins one:
//
//   1. **A DECISION IS NOT AN ENFORCEMENT.** XACML has four decisions and a PEP
//      has two outcomes; what maps between them is the PEP's BIAS, so a
//      deny-biased PEP refuses a NotApplicable that a permit-biased one allows.
//      A monitor that reported `permit` as "allows" would be wrong for every
//      deny-biased refusal of a NotApplicable — which is most of them on a
//      service whose policy does not cover a question.
//   2. **A DECISION THIS SERVICE DID NOT ENFORCE IS NOT A REFUSAL.**
//      `POST /xacml/pdp` answers somebody ELSE's enforcement point, in another
//      process. Counting those as refused (or as allowed) would be reporting an
//      enforcement this service was not present for, and `Number(null)` being 0
//      makes that the failure a reasonable implementation falls into.
//   3. **THE FOUR NUMBERS HAVE TO ADD UP.** `allowed + refused + unenforced ==
//      decisions`, on every row. The first draft had no `unenforced` and the
//      totals silently did not reconcile the moment anything called
//      `/xacml/pdp` — which is the kind of thing that makes a reader distrust
//      every other figure beside it.
//   4. **A COUNTER MUST NEVER BREAK A DECISION.** Every call site is on the
//      path of an issuance, a sign-in or a request to a gated surface. A
//      monitoring feature that could fail one of those would cause the outage
//      it exists to show.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// What is under test is a MODULE CONTRACT — what `record()` does to a counter
// and what `snapshot()` computes from it — and two of the four cases cannot be
// reached over HTTP at all: a decision value the catalogue has never heard of,
// and a counter whose store throws. Driving the page instead would assert the
// rendering of the numbers rather than the numbers, and would need a running
// service to assert that adding up is done correctly.
//
// The page's own rendering is covered where every console page's is:
// `tests/vendored/sts_admin_console.js` draws all of them in a browser.
// ===========================================================================

delete process.env.CONFIG_FILE;

module.exports = {
  name: 'xacml_monitor',
  describe: 'the decision counters: a decision is not an enforcement, and ' +
            'the four figures reconcile',
  run: function (t) {
    log.debug("Entering run().");
    const realms = require('../common/realms');
    const monitor = require('../xacml/xacml_monitor');

    // A REPOSITORY SHAPE RATHER THAN A REAL ONE. `snapshot()` takes the policy
    // counts as an argument precisely so that it needs no store — see its
    // header — and this file is about the counters, not about `ou=policies`.
    const REPOSITORY = { total: 3, enabled: 2, root: 'seeded-rbac' };
    const shot = function () {
      log.debug("Entering shot().");
      log.debug("Leaving shot().");
      return monitor.snapshot(REPOSITORY);
    };

    const rowOf = function (id) {
      log.debug("Entering rowOf().");
      log.debug("Leaving rowOf().");
      return shot().rows.filter(function (one) { return one.id === id; })[0];
    };

    monitor.resetForTests();

    // -------------------------------------------------------------------
    // 1. THE CATALOGUE. Four askers, and only three of them enforce.
    // -------------------------------------------------------------------
    t.log.info('=== the four askers of the PDP in this process ===');

    const first = shot();
    t.equal(first.rows.length, 4,
            'four things ask the PDP in this process and all four are ' +
            'listed — the three embedded PEPs and the PDP endpoint');
    t.equal(first.rows.filter(function (r) { return r.enforces; }).length, 3,
            'THREE of them enforce; the fourth is POST /xacml/pdp, which ' +
            'answers somebody else\'s PEP');
    t.equal(first.peps.embedded, 3,
            'and the enforcement-point count is THREE rather than four: the ' +
            'PDP endpoint is not a PEP, and counting it would answer one too ' +
            'many on a service with no PEPs at all');
    t.equal(first.peps.total, first.peps.embedded + first.peps.remote,
            'the total is the embedded ones plus the registered remote ones');
    t.check(first.rows.every(function (r) { return !!r.guards && !!r.where; }),
            'every row says what it guards and where it is asked from, which ' +
            'is what makes the page a list somebody can act on rather than ' +
            'four counters with names');

    // -------------------------------------------------------------------
    // 2. A DECISION IS NOT AN ENFORCEMENT.
    //
    // The case that matters is a NotApplicable that was REFUSED: it is not a
    // Deny, and an implementation that reported `permit` as "allows" and
    // `deny` as "declines" would show one decision and no outcome at all.
    // -------------------------------------------------------------------
    t.log.info('=== a NotApplicable that was refused ===');

    monitor.record('issuance', { decision: 'NotApplicable', allowed: false });
    const issuance = rowOf('issuance');
    t.equal(issuance.decisions, 1, 'the decision is counted');
    t.equal(issuance.notApplicable, 1, 'as a NotApplicable');
    t.equal(issuance.deny, 0,
            'and NOT as a Deny — a deny-biased PEP refusing a question the ' +
            'policy did not cover is a different fact from the policy saying ' +
            'no');
    t.equal(issuance.refused, 1,
            'while the ENFORCEMENT was a refusal, which is the number an ' +
            'operator asking "how many were declined" wants');
    t.equal(issuance.allowed, 0, 'and nothing was allowed');
    t.equal(issuance.permit, 0,
            'THE POINT OF THE SECTION: `allowed` is 0 and `permit` is 0 for ' +
            'different reasons, and a page that carried only one column ' +
            'would be wrong for whichever question the reader had');

    // The other half of the same distinction: a Permit that was REFUSED,
    // which is section 7.2 working rather than a bug.
    monitor.record('protected', { decision: 'Permit', allowed: false,
                                  undischargeable: true });
    const protectedRow = rowOf('protected');
    t.equal(protectedRow.permit, 1, 'the PDP said Permit');
    t.equal(protectedRow.allowed, 0,
            'AND THE PEP REFUSED IT, which is what an obligation it cannot ' +
            'discharge does (section 7.2) — the one enforcement outcome that ' +
            'looks like a bug from the client side and is the specification ' +
            'working');
    t.equal(protectedRow.undischargeable, 1,
            'and it is counted separately, so the page can say WHY that ' +
            'Permit was refused rather than leaving it as a contradiction');

    // -------------------------------------------------------------------
    // 3. A DECISION NOBODY HERE ENFORCED IS NOT A REFUSAL, AND THE FOUR
    //    FIGURES RECONCILE.
    // -------------------------------------------------------------------
    t.log.info('=== the PDP endpoint, and the arithmetic ===');

    monitor.record('pdp', { decision: 'Deny' });
    const pdpRow = rowOf('pdp');
    t.equal(pdpRow.decisions, 1, 'the decision is counted');
    t.equal(pdpRow.deny, 1, 'as a Deny');
    t.equal(pdpRow.allowed, null,
            'and `allowed` is NULL rather than 0 — this service produced the ' +
            'decision and never saw what was done with it, and a zero would ' +
            'read as "it allowed nothing"');
    t.equal(pdpRow.refused, null,
            'as is `refused`, for the same reason and more sharply: a zero ' +
            'there would be a claim about an enforcement this service was ' +
            'not present for');

    const here = shot().decisions.here;
    t.equal(here.decisions, 3,
            'three decisions have been recorded in this realm');
    t.equal(here.allowed, 0, 'none allowed');
    t.equal(here.refused, 2, 'two refused');
    t.equal(here.unenforced, 1,
            'and ONE not enforced here, which is the PDP endpoint\'s');
    t.equal(here.allowed + here.refused + here.unenforced, here.decisions,
            'ALLOWED + REFUSED + UNENFORCED = DECISIONS. The first draft had ' +
            'no `unenforced` and this stopped being true the moment anything ' +
            'called /xacml/pdp — a total that does not add up is what makes ' +
            'somebody distrust every other number on the page');

    // The combined figure is arithmetic over the two halves and says so; with
    // no remote PEP registered it is the local half exactly.
    const combined = shot().decisions.combined;
    t.equal(combined.decisions, here.decisions,
            'with no remote PEP registered, `combined` is the local half — ' +
            'so the page\'s headline figure is not silently inventing a ' +
            'remote contribution');
    t.equal(shot().decisions.remote.decisions, 0,
            'and the remote half is honestly zero rather than absent');

    // -------------------------------------------------------------------
    // 4. WHAT MUST NOT HAPPEN: an unknown asker, an unknown decision, and a
    //    counter that throws.
    // -------------------------------------------------------------------
    t.log.info('=== the three things a counter must not do ===');

    const beforeUnknown = shot().decisions.here.decisions;
    monitor.record('not-a-real-pep', { decision: 'Permit', allowed: true });
    t.equal(shot().decisions.here.decisions, beforeUnknown,
            'a decision recorded against an asker the catalogue has never ' +
            'heard of is NOT counted — that page claims to list every asker ' +
            'of the PDP in this process, and a row nothing describes would ' +
            'break the claim rather than extend it');
    t.equal(shot().rows.length, 4,
            'and it does not appear as a row');

    monitor.record('access', { decision: 'SomethingNew', allowed: true });
    const access = rowOf('access');
    t.equal(access.decisions, 1, 'a decision value nothing recognises is ' +
            'still COUNTED as a decision');
    t.equal(access.other, 1,
            'and lands in `other` rather than being dropped, so a fifth ' +
            'decision value added to the engine is VISIBLE here instead of ' +
            'silently uncounted');
    t.equal(access.allowed, 1,
            'while the enforcement is counted normally, because what the PEP ' +
            'did is known whatever the PDP called its answer');

    // A THROW INSIDE record() IS SWALLOWED. Every call site is on the path of
    // an issuance or a gated request, so this is the assertion that says a
    // monitoring feature cannot cause the outage it exists to show. The throw
    // is forced through the one argument the function reads.
    const beforeThrow = rowOf('access').decisions;
    let threw = false;
    try {
      monitor.record('access', { get decision() {
        log.debug("Entering decision().");
        log.debug("Leaving decision().");
        throw new Error('boom');
      } });
    } catch (error) {
      log.debug("Caught in run(): " + ((error && error.message) || error));
      threw = true;
    }
    t.equal(threw, false,
            'record() SWALLOWS a failure rather than throwing into its ' +
            'caller — it is called from the issuance PEP and the access PEP, ' +
            'so a counter that could throw would refuse a token or a sign-in ' +
            'because the monitoring broke');
    // AND IT RECORDS NOTHING RATHER THAN HALF. This is the assertion that
    // caught the defect: the first implementation incremented `decisions`
    // and then read the outcome, so a throw left the row with a decision
    // counted, no bucket and no enforcement — and `allowed + refused +
    // unenforced` one short of `decisions` for the life of the process, with
    // nothing to say why. Half a count is worse than none, because it is
    // indistinguishable from a real decision.
    t.equal(rowOf('access').decisions, beforeThrow,
            'AND IT RECORDS NOTHING RATHER THAN HALF — a failure part-way ' +
            'through must not leave a decision counted with no outcome ' +
            'beside it, which is the reconciliation the `unenforced` figure ' +
            'exists to keep');
    const afterThrow = rowOf('access');
    t.equal(afterThrow.allowed + afterThrow.refused, afterThrow.decisions,
            'so the row still reconciles: this one enforces everything it ' +
            'decides, and the two halves add up exactly');

    // -------------------------------------------------------------------
    // 5. PER TRUST REALM, like ou=policies itself.
    // -------------------------------------------------------------------
    t.log.info('=== the counters are per realm ===');

    const made = realms.create
      ? realms.create({ id: 'moncheck', name: 'Monitor check' }) : null;
    if (made && made.ok !== false) {
      realms.run(realms.get('moncheck'), function () {
        const fresh = monitor.snapshot(REPOSITORY);
        t.equal(fresh.decisions.here.decisions, 0,
                'a realm created after those decisions starts at zero — a ' +
                'decision made under /realm/x was made against x\'s ' +
                'policies, and one total over both would be counting two ' +
                'logical services as one');
        t.equal(fresh.realm.id, 'moncheck',
                'and the snapshot names the realm it is reporting, so a ' +
                'reader cannot mistake one realm\'s figures for another\'s');
        monitor.record('access', { decision: 'Permit', allowed: true });
        t.equal(monitor.snapshot(REPOSITORY).decisions.here.decisions, 1,
                'counting inside it works');
      });
      t.equal(shot().decisions.here.decisions, 4,
              'AND THE DEFAULT REALM IS UNCHANGED BY IT — the four it had, ' +
              'not five. This is the assertion realm_isolation.js exists ' +
              'for, made where the store is declared');
      if (realms.remove) {
        realms.remove('moncheck');
      }
    } else {
      t.check(false, 'the throwaway realm could not be created, so the ' +
                     'per-realm assertions did not run');
    }
    log.debug("Leaving run().");
  }
};
