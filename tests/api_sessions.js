'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'api_sessions',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: api_sessions.js
//
// ===========================================================================
// THE MANAGEMENT API, SCIM AND THE SPIRE SERVER API SIGN IN THROUGH THE SAME
// SESSION STORE AS EVERYTHING ELSE.
//
// Those three authenticate somebody and, until 2026-09-06, held no session:
// nothing on `/admin/sessions`, nothing for a global sign-out to end, and no
// subject with a session behind it for the access policy to be asked about.
//
// **THE FIX WAS NOT A SECOND REGISTER, AND THAT IS THE THING THIS FILE
// GUARDS.** A register of API sessions beside `authn.js`'s was the obvious
// implementation and is exactly what rule 3m forbids: two answers to "is
// somebody signed in", with the wrong one being whichever surface a reader
// happened to look at. They go through `authn.startSession()` like every other
// sign-in, and two fields make that work for a credential presented on every
// request — `detail.key`, which reuses the session instead of minting one per
// call, and `detail.cookie`, which stops a non-browser being handed one.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The claim is about the SHAPE OF THE STORE — one row per credential rather
// than one per request, in the same map browser sessions live in. Over HTTP
// the only visible symptom is a count on a console page, and a test that
// asserted the count would pass against a second register that happened to
// report the same number. Here the store itself is read.
// ===========================================================================

delete process.env.CONFIG_FILE;

function run(t) {
  log.debug("Entering run().");
  require('../common/app');
  const authn = require('../authn/authn');
  const logout = require('../logout/logout');

  // A response that is not a browser: no cookie jar, no express. The three
  // surfaces hand `startSession()` exactly this.
  const noBrowser = function () {
    log.debug("Entering noBrowser().");
    log.debug("Leaving noBrowser().");
    return { set: function () {}, req: null };
  };

  const before = logout.liveSessions().length;

  // -----------------------------------------------------------------------
  // 1. A KEYED SIGN-IN IS ONE SESSION, HOWEVER OFTEN THE CREDENTIAL COMES BACK.
  // -----------------------------------------------------------------------
  t.log.info('=== one row per credential, not per request ===');

  const first = authn.startSession(noBrowser(), 'scim-client', ['pwd'], '1',
                                   'SCIM', { key: 'k-scim-1', cookie: false });
  t.check(first && first.id, 'a SCIM credential starts a session');
  t.equal(first.credentialKey, 'k-scim-1',
          'and the session carries the fingerprint that identifies it — the ' +
          'one field that tells an API row from a browser row');

  let same = null;
  for (let i = 0; i < 25; i++) {
    same = authn.startSession(noBrowser(), 'scim-client', ['pwd'], '1', 'SCIM',
                              { key: 'k-scim-1', cookie: false });
  }
  t.equal(same.id, first.id,
          'TWENTY-FIVE MORE CALLS WITH THE SAME CREDENTIAL ARE THE SAME ' +
          'SESSION. Without this a provisioning client doing a thousand ' +
          'PATCHes leaves a thousand rows nothing will ever present again, ' +
          'and /admin/sessions is useless exactly when somebody needs it');
  t.equal(same.calls, 26,
          'and the row counts the calls, which is what makes it worth ' +
          'drawing at all');

  // -----------------------------------------------------------------------
  // 2. A DIFFERENT CREDENTIAL IS A DIFFERENT SESSION.
  //    Asserted because the reuse above is satisfied by a bug that returns
  //    the first session to everybody.
  // -----------------------------------------------------------------------
  const other = authn.startSession(noBrowser(), 'spire-agent', ['swk'], '1',
                                   'SPIRE Server API',
                                   { key: 'k-spire-1', cookie: false });
  t.check(other.id !== first.id,
          'A DIFFERENT CREDENTIAL IS A DIFFERENT SESSION — without this the ' +
          'reuse above would be satisfied by handing everybody the first one');

  // -----------------------------------------------------------------------
  // 3. THEY ARE IN THE ONE STORE, AND THE ONE MODEL OVER IT SEES THEM.
  // -----------------------------------------------------------------------
  t.log.info('=== one store, and liveSessions() reads it ===');
  const live = logout.liveSessions();
  t.equal(live.length, before + 2,
          'both are in `liveSessions()` — the SAME enumeration the console ' +
          'and the global sign-out read, because they are in the same store ' +
          'and not a register of their own');

  const scimRow =
      live.filter(function (r) { return r.sessionId === first.id; })[0];
  const apiRow =
      live.filter(function (r) { return r.sessionId === other.id; })[0];
  t.check(!!scimRow && !!apiRow, 'each has a row');
  t.equal(scimRow.kind, 'SCIM session',
          'AND IT IS NOT DRAWN AS A BROWSER SIGN-ON SESSION. One store does ' +
          'not mean one kind of row: a SCIM client drawn as a browser would ' +
          'be this page saying something untrue about the one thing it ' +
          'exists to report');
  t.equal(apiRow.kind, 'SPIRE Server API session',
          'and the SPIRE caller is named by its own surface');
  t.check(scimRow.expiryRule.indexOf('Extended by use') === 0,
          'they carry the FOURTH expiry rule, which is the only one here ' +
          'that is extended by use — a browser holds a cookie that outlives ' +
          'its own use, and these exist only while a client is calling',
          scimRow.expiryRule);
  t.check(scimRow.expiryRule.indexOf('revokes NOTHING') > 0,
          'and it says outright that ending one revokes nothing, because the ' +
          'credential behind it is accepted without consulting any register',
          scimRow.expiryRule.slice(0, 60));
  t.check(scimRow.detail.indexOf('26 call(s)') === 0,
          'the row reports the calls rather than the relying parties a ' +
          'browser session carries — nothing signs into an API session',
          scimRow.detail);

  // -----------------------------------------------------------------------
  // 4. A GLOBAL SIGN-OUT REACHES THEM, which is most of why they are in this
  //    store rather than beside it.
  // -----------------------------------------------------------------------
  t.log.info('=== a global sign-out reaches them ===');
  const ended = logout.terminate(
    require('../common/admin_stats').identityKeyOf('scim-client'), [],
    { by: 'tests/api_sessions.js' });
  t.check(!!ended, 'terminate() answered');
  const after = logout.liveSessions().filter(function (r) {
    return r.sessionId === first.id;
  });
  t.equal(after.length, 0,
          'THE SCIM SESSION IS GONE. It is ended by the same function every ' +
          'other session goes through — no new family, no second terminator, ' +
          'which is what putting it in this store bought');
  const survivor = logout.liveSessions().filter(function (r) {
    return r.sessionId === other.id;
  });
  t.equal(survivor.length, 1,
          'and the SPIRE one, which belongs to somebody else, is untouched');

  // -----------------------------------------------------------------------
  // 5. EVERY SESSION GOES THROUGH THE ISSUANCE GATE NOW, at the funnel.
  //
  // `ISSUANCE.SESSION` was asked at exactly ONE door — this module's own
  // sign-in screen — while five other paths minted a session and never asked:
  // a federated assertion, a SPNEGO ticket, a client certificate, a WS-Trust
  // UsernameToken and the WebAuthn funnel. An application narrowed to a role
  // refused a password sign-in and admitted the same person through any of
  // them.
  //
  // It refuses by returning NULL and never by throwing, and that is the half
  // worth asserting: two callers wrap `startSession()` in a `try` that treats
  // a failure as bookkeeping which must not break an exchange already
  // completed. A thrown refusal would be swallowed there and the session
  // started anyway.
  // -----------------------------------------------------------------------
  t.log.info('=== the session funnel asks the issuance gate ===');
  const roles = require('../common/roles');
  const gate = require('../common/issuance_gate');
  // **AN APPLICATION HAS TO BE NAMED OR THE GATE SHORT-CIRCUITS**, and that is
  // the existing rule rather than a quirk of this test: `issuance_gate.check()`
  // allows when nothing named an application, because there is then no
  // requirement to check. So a sign-in path that names one — the sign-in
  // screen's `record.application`, federation's `fedApplication`, SPNEGO's —
  // is gated, and one that names none is allowed exactly as before. The first
  // draft of this file asserted against the decider and never reached it.
  const held = [];
  gate.setDecider(function (asked) {
    held.push(asked);
    return { allowed: asked.subject.name !== 'refused-person',
             why: 'the test decider refused it' };
  });
  try {
    const permitted = authn.startSession(noBrowser(), 'allowed-person', [], '1',
                                         'SCIM', { key: 'k-gate-ok',
                                                   cookie: false,
                                                   application: 'gate-probe' });
    t.check(!!permitted, 'a permitted subject gets a session');
    t.equal(held.length > 0 && held[held.length - 1].kind,
            gate.ISSUANCE.SESSION,
            'AND THE GATE WAS ASKED, with `start-session` — the kind that ' +
            'was in the list from the day it was written and was asked at ' +
            'one door out of six');

    const refused = authn.startSession(noBrowser(), 'refused-person', [], '1',
                                       'SPIRE Server API',
                                       { key: 'k-gate-no', cookie: false,
                                         application: 'gate-probe' });
    t.equal(refused, null,
            'A REFUSED SUBJECT GETS NULL AND NOT A THROW. Two callers wrap ' +
            'this in a try that treats a failure as bookkeeping; a thrown ' +
            'refusal would be swallowed there and the session started anyway');
    t.equal(logout.liveSessions().filter(function (r) {
      return r.username === 'refused-person';
    }).length, 0, 'and no session was created for them');

    // The door that already asked opts out, so a refusal there is a screen
    // with a reason on it rather than one reported in two shapes.
    const optedOut = authn.startSession(noBrowser(), 'refused-person', [], '1',
                                        'OAuth 2.0 / OIDC',
                                        { gated: true,
                                          application: 'gate-probe' });
    t.check(!!optedOut,
            '`gated: true` skips it, which is how this module\'s own sign-in ' +
            'screen says it already asked at the door');

    // AND A SIGN-IN THAT NAMES NO APPLICATION IS ALLOWED, which is the rule
    // read the other way and is what keeps every existing caller unaffected.
    // **IT HAS TO BE ASSERTED IN HERE**, with the refusing decider still
    // installed — the first draft put it after the `finally`, where no decider
    // is installed at all and the assertion could not have failed.
    const unnamed = authn.startSession(noBrowser(), 'refused-person', [], '1',
                                       'OAuth 2.0 / OIDC', {});
    t.check(!!unnamed,
            'a sign-in that names no application is allowed even though the ' +
            'decider refuses this very person — there is no requirement to ' +
            'check, and that is what makes the funnel gate safe to add');
  } finally {
    // RESTORE THE SLOT — with what was there, which is nothing in this
    // process, because no PEP is loaded here. See tests/CLAUDE.md.
    gate.setDecider(null);
  }
  void roles;

  // -----------------------------------------------------------------------
  // 6. A BROWSER SESSION IS UNCHANGED, asserted last so that nothing above
  //    could have passed by making every session an API session.
  // -----------------------------------------------------------------------
  t.log.info('=== a browser session is exactly what it was ===');
  const browser = authn.startSession(noBrowser(), 'alice', ['pwd'], '1',
                                     'OAuth 2.0 / OIDC', {});
  t.equal(browser.credentialKey, null,
          'a caller that names no credential gets no fingerprint');
  const browserRow = logout.liveSessions().filter(function (r) {
    return r.sessionId === browser.id;
  })[0];
  t.equal(browserRow.kind, 'Browser sign-on session',
          'and it is still drawn as a browser sign-on session');
  t.check(browserRow.expiryRule.indexOf('Absolute') === 0,
          'with the ABSOLUTE expiry rule it has always had — the two rules ' +
          'are different sentences and this is what stops the new one ' +
          'quietly becoming everybody\'s',
          browserRow.expiryRule.slice(0, 40));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'api sessions',
  describe: 'the three API surfaces sign in through the ONE session store, ' +
            'one row per credential',
  run: run
};
