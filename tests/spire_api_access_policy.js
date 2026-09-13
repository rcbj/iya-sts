'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'spire_api_access_policy',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: spire_api_access_policy.js
//
// ===========================================================================
// THE SPIRE SERVER API IS THE ONE GATED SURFACE WITH CALLERS THIS SERVICE
// CANNOT NAME, AND THE POLICY LAYER MUST NOT CLOSE THE BOOTSTRAP.
//
// `tests/access_policy.js` asserts what the `access-control` document decides
// once it has been handed a subject. This file asserts the other half, which
// only this surface has: WHETHER IT IS ASKED AT ALL.
//
// ---------------------------------------------------------------------------
// THE REGRESSION THIS FILE EXISTS FOR, AND WHY EVERY PIECE OF IT WAS CORRECT.
//
// The SPIRE Server API's TCP port asks for a client certificate and does not
// require one. That is SPIFFE and not a convenience: `AttestAgent` has to be
// reachable by an agent that HAS NO SVID YET, and `GetBundle` by whoever is
// about to trust this trust domain. Both are `any` in `spiffe_auth.js`'s
// POLICY table, which is copied from SPIRE's own `policy_data.json`.
//
// The access gate then went in above that table on 2026-09-06, and the
// built-in `access-control` policy conjoins `requireAuthenticated`, which is
// ON by default. That conjunct is right for what it was written for — the
// sign-in screen's "continue without signing in" session, a real subject that
// declined to authenticate and has no business on the console, the management
// API, the portal or SCIM. A SPIRE caller that presented nothing is not that:
// there is no session, no name and no subject, and the policy was being asked
// to decide about nobody. It answered Deny.
//
// So on an unedited service `GetBundle` answered PERMISSION_DENIED to an
// anonymous caller — the bootstrap of the entire trust domain, closed —
// while three places said otherwise: `xacml.enforceAccess`'s own description
// ("it changes nothing on an unedited service"), the note at the call site in
// `spiffe_grpc.js` ("the built-in document permits, because it asks for a role
// only where somebody has required one"), and `access_gate.js`'s header ("the
// five are surfaces an operator NARROWS: they require EVERYBODY until somebody
// says otherwise").
//
// Nothing errored, nothing was Indeterminate, and no test in this directory
// could see it: the decision was correct for the request it was given and the
// defect was in asking. The parent project's `tests/spiffe_protocol.js` — the
// one place all 49 methods are driven as four different entities — is what
// went red, on its second assertion, naming a policy.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The claim is about a DECISION and not about an endpoint. Driving it over the
// wire means two gRPC listeners, a server certificate and a trust bundle to
// assert one branch — which the parent project's suite already does, over a
// stack it already starts. Here `policyRefusal()` is called directly, so the
// four combinations of (named / anonymous) x (enforcement on / off) are all
// reachable and each is one line.
// ===========================================================================

delete process.env.CONFIG_FILE;

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  // The gate is a no-op with no decider installed, and requiring the PEP is
  // what installs one — the same act `xacml/xacml.js` performs at 23c.
  require('../xacml/xacml_access_pep');
  const grpc = require('../spiffe/spiffe_grpc');

  config.setOverride('xacml.enforceAccess', 'true');

  // The two callers, in the shape `spiffe_auth.js`'s callerOf() builds. What
  // separates them is the only thing this file is about: whether there is
  // somebody for a policy to decide about.
  const anonymous = { authenticated: false, spiffeId: '', transport: 'tcp',
                      entities: {} };
  const agent = { authenticated: true, transport: 'tcp',
                  spiffeId: 'spiffe://example.org/spire/agent/x509pop/abc',
                  entities: { agent: true } };

  // -----------------------------------------------------------------------
  // THE BOOTSTRAP. SPIRE's own table has already permitted these by the time
  // policyRefusal() runs — `authorize()` returns null for an `any` row — so
  // what is asserted here is that the layer above does not take it back.
  // -----------------------------------------------------------------------
  t.log.info('=== a caller that presented nothing, with enforcement ON ===');

  t.equal(grpc.policyRefusal(anonymous, 'GetBundle'), null,
          'GetBundle is not refused by the POLICY layer for a caller that ' +
          'presented nothing. It is `any` in SPIRE\'s table because whoever ' +
          'is about to trust this trust domain has to be able to read its ' +
          'bundle, and a policy conjunct written for the "continue without ' +
          'signing in" session must not close it');

  t.equal(grpc.policyRefusal(anonymous, 'AttestAgent'), null,
          'and neither is AttestAgent, which is the stronger half of the ' +
          'same claim: an agent reaches it precisely because it has no SVID ' +
          'yet, so a gate that wanted one there could never be satisfied');

  // A method SPIRE RESTRICTS, asked of the same anonymous caller. It reaches
  // no further than this because `authorize()` has already refused it with
  // UNAUTHENTICATED — so the exemption above widens nothing, and this line is
  // what says so rather than a comment claiming it.
  t.equal(grpc.policyRefusal(anonymous, 'BatchCreateEntry'), null,
          'a RESTRICTED method is not refused HERE either — and that is not ' +
          'a hole: spiffe_auth.js\'s authorize() has already answered ' +
          'UNAUTHENTICATED for it, before this function is reached. The ' +
          'exemption is about which layer refuses, not about whether one does');

  // -----------------------------------------------------------------------
  // AND A CALLER WITH A NAME IS STILL DECIDED ABOUT, which is what keeps the
  // policy layer worth having: an operator narrowing this surface by policy
  // is unaffected by any of the above.
  // -----------------------------------------------------------------------
  t.log.info('=== a caller with a name, with enforcement ON ===');

  t.equal(grpc.policyRefusal(agent, 'GetBundle'), null,
          'an authenticated agent is permitted on an unedited service, ' +
          'because the built-in document asks for a role only where somebody ' +
          'has required one — which is what xacml.enforceAccess promises');

  // AND THE DOCUMENT ITSELF IS UNCHANGED, which is the assertion that says
  // what was actually fixed. The policy is asked directly here, with a subject
  // it CAN name that did not authenticate — the "continue without signing in"
  // session, which is what `requireAuthenticated` was written for — and it
  // must still refuse. So what changed is WHICH CALLERS ARE ASKED ABOUT, and
  // not what the access-control document decides about any of them.
  const gate = require('../common/access_gate');
  t.equal(gate.check({ resource: gate.RESOURCE.SPIRE_SERVER_API,
                       action: gate.ACTION.WRITE,
                       subject: { name: 'somebody', authenticated: false,
                                  sessionId: 's-anon' } }).allowed, false,
          'the POLICY still refuses a NAMED subject that did not ' +
          'authenticate, on this very resource — so the exemption above is ' +
          'about a caller there is nobody to decide about, and the ' +
          'requireAuthenticated conjunct is intact');

  t.equal(gate.check({ resource: gate.RESOURCE.SPIRE_SERVER_API,
                       action: gate.ACTION.WRITE,
                       subject: { name: agent.spiffeId, authenticated: true,
                                  sessionId: 's-agent' } }).allowed, true,
          'and permits a named subject that did — which is what an operator ' +
          'narrowing this surface by policy still writes rules against');

  // -----------------------------------------------------------------------
  // AND THE GATE IS REACHABLE AT ALL, asserted LAST so the lines above cannot
  // have been passing because nothing was being enforced. This is the shape
  // tests/access_policy.js ends with, and for its reason.
  // -----------------------------------------------------------------------
  t.log.info('=== xacml.enforceAccess off means nothing is decided ===');
  config.setOverride('xacml.enforceAccess', 'false');
  t.equal(grpc.policyRefusal(agent, 'BatchCreateEntry'), null,
          'with enforcement off no decision is made here, for anybody');

  // **CLEARED RATHER THAN WRITTEN BACK**, which is this suite's rule: writing
  // the old value back records an OVERRIDE where there may have been none, and
  // the next file to read the setting then sees a runtime override with the
  // default's value in it rather than the default.
  config.clearOverride('xacml.enforceAccess');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spire server api access policy',
  describe: 'the policy layer decides about a caller this service can NAME, ' +
            'and does not close SPIFFE\'s anonymous bootstrap',
  run: run
};
