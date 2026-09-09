'use strict';
//
// File: access_policy.js
//
// ===========================================================================
// THE ACCESS-CONTROL POLICY DECIDES WHO REACHES THE FIVE GATED SURFACES, AND
// OWNERSHIP IS A CONSTRAINT RATHER THAN A WAY ROUND THE ROLES.
//
// `common/access_gate.js` is the LEAF the admin console, the management API,
// the User Portal, SCIM and the SPIRE Server API ask before they let anybody
// in; `xacml/xacml_access_pep.js` fills its decider and turns the question
// into a XACML request against the `access-control` policy. This file asserts
// what that document actually decides.
//
// ---------------------------------------------------------------------------
// THE REGRESSION THIS FILE EXISTS FOR, AND WHY IT LOOKED CORRECT.
//
// The policy was first written as ONE Permit rule with THREE OR'D ARMS: the
// subject holds a role the resource requires, OR the resource requires none,
// OR the subject IS the resource's owner. Every arm was right on its own. The
// second one swallowed the third:
//
//   * the User Portal narrows nobody, so `requiredRole` is an empty bag;
//   * so "the resource requires nothing" was TRUE for every portal request;
//   * so the `or` short-circuited and the owner comparison, which was
//     evaluated and was FALSE, made no difference at all.
//
// The result was that any signed-in person was permitted to reach ANY OTHER
// PERSON'S account — the exact thing the policy was written to prevent, in a
// document whose own description said it prevented it. Nothing errored, no
// decision was Indeterminate, and `tests/portal_access.js` stayed green
// throughout, because THAT file asserts the structural rule (the handler reads
// the identity from the session and never from the request) and this is the
// other half: what the POLICY decides once it has been handed a trustworthy
// subject. Both halves are needed and neither implies the other.
//
// It is a conjunction now — satisfy the ROLE requirement AND the OWNERSHIP
// requirement — and the two cases below that would have passed under the old
// spelling are marked.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The claim is about a decision, not about an endpoint. Driving it over HTTP
// would mean signing in as one person and reaching for another's account —
// which is `tests/portal_access.js`'s job and which can only ever exercise the
// ONE owner/subject pair a session makes reachable. Here the request is built
// directly, so the four combinations of (owns it / does not) x (authenticated
// / not) are all reachable, and so is the ownerless surface that has to keep
// behaving as plain RBAC.
// ===========================================================================

delete process.env.CONFIG_FILE;

function run(t) {
  const config = require('../common/config');
  // The gate is a no-op with no decider installed, and requiring the PEP is
  // what installs one — the same act `xacml/xacml.js` performs at 23c.
  require('../xacml/xacml_access_pep');
  const gate = require('../common/access_gate');

  config.setOverride('xacml.enforceAccess', 'true');

  const alice = { name: 'alice', authenticated: true, sessionId: 's-alice' };
  const anon = { name: 'nobody', authenticated: false, sessionId: 's-anon' };

  const decide = function (asked) {
    return gate.check(asked);
  };

  // -----------------------------------------------------------------------
  // THE PORTAL — a resource that NAMES AN OWNER.
  // -----------------------------------------------------------------------
  t.log.info('=== the User Portal, which names an owner ===');

  t.equal(decide({ resource: gate.RESOURCE.PORTAL,
                   action: gate.ACTION.MANAGE_OWN,
                   subject: alice, owner: 'alice' }).allowed, true,
          'a person reaches their OWN account');

  // **THE REGRESSION.** This was PERMIT under the three-arm spelling.
  t.equal(decide({ resource: gate.RESOURCE.PORTAL,
                   action: gate.ACTION.MANAGE_OWN,
                   subject: alice, owner: 'bob' }).allowed, false,
          'AND NOT SOMEBODY ELSE\'S — the case the three-arm spelling ' +
          'permitted, because the portal requires no role and that arm was ' +
          'true for everybody');

  // The same claim for the other action the portal asks about. It matters
  // separately: a fix that keyed on `action-id` rather than on ownership would
  // pass the line above and fail this one.
  t.equal(decide({ resource: gate.RESOURCE.PORTAL,
                   action: gate.ACTION.READ,
                   subject: alice, owner: 'bob' }).allowed, false,
          'nor READ somebody else\'s, which is a separate assertion because ' +
          'a fix written as "manage-own is special" would pass the one above ' +
          'and not this one');

  t.equal(decide({ resource: gate.RESOURCE.PORTAL,
                   action: gate.ACTION.MANAGE_OWN,
                   subject: anon, owner: 'nobody' }).allowed, false,
          'and a session where nobody authenticated is refused even for its ' +
          'own name — the precondition is conjoined, not an alternative');

  // -----------------------------------------------------------------------
  // THE CONSOLE — a resource that names NO owner, so ownership is vacuous and
  // the document has to behave as plain RBAC.
  // -----------------------------------------------------------------------
  t.log.info('=== the admin console, which names no owner ===');

  t.equal(decide({ resource: gate.RESOURCE.CONSOLE,
                   action: gate.ACTION.WRITE,
                   subject: alice }).allowed, true,
          'a signed-in operator may write, with no owner named anywhere — ' +
          'which is what the empty-bag reading buys');

  t.equal(decide({ resource: gate.RESOURCE.CONSOLE,
                   action: gate.ACTION.READ,
                   subject: anon }).allowed, false,
          'and an unauthenticated session may not even read');

  // The ownerless surfaces must not have been narrowed by the ownership
  // conjunct: an owner that is the EMPTY STRING is the same as none, because
  // `attribute()` drops it and the bag-size test then reads zero.
  t.equal(decide({ resource: gate.RESOURCE.MANAGEMENT_API,
                   action: gate.ACTION.WRITE,
                   subject: alice, owner: '' }).allowed, true,
          'an owner of "" is no owner at all, which is the property the four ' +
          'ownerless surfaces rest on');

  // -----------------------------------------------------------------------
  // AND THE GATE IS OFF BY DEFAULT, which is the contract every other mode in
  // this service follows. Asserted LAST so the two above cannot have been
  // passing because nothing was being enforced.
  // -----------------------------------------------------------------------
  t.log.info('=== xacml.enforceAccess off means nothing is decided ===');
  config.setOverride('xacml.enforceAccess', 'false');
  t.equal(decide({ resource: gate.RESOURCE.PORTAL,
                   action: gate.ACTION.MANAGE_OWN,
                   subject: alice, owner: 'bob' }).allowed, true,
          'with enforcement off, the refusal above is not made — so the ' +
          'assertions above are about the POLICY and not about the gate ' +
          'being unreachable');

  // **CLEARED RATHER THAN WRITTEN BACK**, which is this suite's rule: writing
  // the old value back records an OVERRIDE where there may have been none, and
  // the next file to read the setting then sees a runtime override with the
  // default's value in it rather than the default.
  config.clearOverride('xacml.enforceAccess');
}

module.exports = {
  name: 'access policy',
  describe: 'the XACML access-control policy: ownership constrains, it does ' +
            'not excuse',
  run: run
};
