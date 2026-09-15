'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'scim_monitor',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: scim_monitor.js
//
// ===========================================================================
// THE COUNTERS BEHIND /admin/scim/monitor, AND THE THREE THINGS THAT PAGE
// CLAIMS THAT NOTHING ELSE WOULD NOTICE GOING WRONG.
//
// The page reports how much traffic the provisioning surface has taken, from
// whom, of what kind, and how much of it failed. Every one of those is easy to
// get subtly wrong in a way that still renders, and the sections below pin one
// each:
//
//   1. **A CLIENT IS AN AUTHENTICATED PRINCIPAL, AND A REFUSED CALLER IS NOT
//      ONE.** Basic and Digest both put a name on the wire and the gate can
//      still turn it away. Counting that name as a client would be the page
//      asserting an identity this service declined to believe — the one
//      mistake here that would matter rather than merely be untidy.
//   2. **AN ABSENT MEASUREMENT IS NULL AND NOT ZERO.** A success rate of 100%
//      on nothing, or an average of 0.0ms over no samples, is the most
//      misleading pair of numbers this page could print: both look like a
//      healthy service.
//   3. **A COUNTER MUST NEVER BREAK A PROVISIONING REQUEST.** `recordScim()` is
//      called from inside the two functions every SCIM answer goes out through.
//      A counter that could throw would turn a monitoring feature into the 500
//      it exists to show — and, worse, half a count is indistinguishable from a
//      real request, so a throw must record NOTHING rather than part of a row.
//
// And a fourth that is not about the page at all: the counters are PER TRUST
// REALM since 2026-09-06, and the guard for that is in
// `tests/realm_isolation.js` beside the other two stores, because that file's
// header asks for it there rather than in one of its own.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// What is under test is a MODULE CONTRACT — what `recordScim()` does to a
// counter and what `scimMonitorSnapshot()` computes from it — and two of the
// cases cannot be reached over HTTP at all: a detail object that throws when it
// is read, and the client cap, which would need two hundred and one distinct
// credentials on the wire to provoke. Driving the page instead would assert the
// rendering of the numbers rather than the numbers.
//
// The page's own rendering is covered where every console page's is:
// `tests/vendored/sts_admin_console.js` draws all of them in a browser, and
// `tests/vendored/admin_api.js` holds it to the parity rule.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: a
// developer with CONFIG_FILE exported would otherwise be asserting against
// their own appconfig rather than against the service as it ships.
delete process.env.CONFIG_FILE;

module.exports = {
  name: 'scim_monitor',
  describe: 'the SCIM traffic counters: a refused caller is not a client, an ' +
            'absent measurement is null, and a counter cannot throw',
  run: function (t) {
    log.debug("Entering run().");
    const stats = require('../common/admin_stats');

    // ---------------------------------------------------------------------
    // NOTHING HAS HAPPENED YET, which is the state every one of these pages is
    // in when somebody first opens it and is the state the misleading numbers
    // live in.
    // ---------------------------------------------------------------------
    stats.resetScimForTests();
    const empty = stats.scimMonitorSnapshot();

    t.equal(empty.calls, 0, 'an untouched service has taken no SCIM calls');
    t.check(empty.successRate === null,
      'THE SUCCESS RATE IS NULL AND NOT 100 — a rate over no requests is ' +
      'absent, and 100% on nothing is the most misleading figure this page ' +
      'could print',
      'got ' + JSON.stringify(empty.successRate));
    t.check(empty.latency.averageMs === null,
      'and the average latency is null for the same reason — a column of 0.0 ' +
      'would read as a server answering instantly',
      'got ' + JSON.stringify(empty.latency.averageMs));
    t.check(empty.operations.length > 0 &&
            empty.operations.every(function (row) {
              return row.count === 0 && row.averageMs === null &&
                     row.maxMs === null;
            }),
      'every operation this server implements is listed AT ZERO — a table of ' +
      'only what has happened answers "does this support PATCH" by omission ' +
      '— and each carries a null duration rather than a zero',
      empty.operations.length + ' operation(s)');
    t.check(empty.operations.some(function (row) {
      return row.operation === 'modify';
    }), 'PATCH is one of them, which is the case that argument is about');

    // ---------------------------------------------------------------------
    // ONE SUCCESSFUL CALL, ONE FAILURE AFTER AUTHENTICATION, ONE REFUSED AT
    // THE GATE, AND ONE ANONYMOUS. Four requests is the smallest set that
    // separates every figure on the page from every other.
    // ---------------------------------------------------------------------
    stats.recordScim({ operation: 'create', resourceType: 'User', status: 201,
                       ok: true, authScheme: 'basic', principal: 'alice',
                       ms: 10, bytes: 100, method: 'POST',
                       path: '/scim/v2/Users' });
    stats.recordScim({ operation: 'read', resourceType: 'User', status: 404,
                       ok: false, scimType: '', authScheme: 'basic',
                       principal: 'alice', ms: 30, bytes: 200, method: 'GET',
                       path: '/scim/v2/Users/nobody' });
    // THE REFUSAL. `scim.js` sends `refused` as the scheme and NO principal
    // when its gate turns somebody away — but this passes a principal as well,
    // because the assertion below is that the counter refuses to use it rather
    // than that the caller was careful.
    stats.recordScim({ operation: 'list', resourceType: 'User', status: 401,
                       ok: false, scimType: '', authScheme: 'refused',
                       principal: 'mallory', ms: 1, bytes: 300, method: 'GET',
                       path: '/scim/v2/Users' });
    stats.recordScim({ operation: 'discovery', resourceType: 'Schema',
                       status: 200, ok: true, authScheme: 'anonymous',
                       principal: '', ms: 1, bytes: 400, method: 'GET',
                       path: '/scim/v2/Schemas' });

    const four = stats.scimMonitorSnapshot();

    t.equal(four.calls, 4,
      'EVERY REQUEST THE IMPLEMENTATION ANSWERED IS COUNTED, including the ' +
      'one its own gate refused — a 401 is a call this service answered, and ' +
      'a total that omitted them would be smaller than the access log');
    t.equal(four.ok, 2, 'two of the four succeeded');
    t.equal(four.failed, 2, 'and two failed');
    t.equal(four.ok + four.failed, four.calls,
      'and the two halves add up to the whole, which is the arithmetic a ' +
      'reader does first');
    t.equal(four.successRate, 50, 'the success rate is now a number');

    // ---------------------------------------------------------------------
    // WHO IS CALLING. The section this page was asked for, and the one with
    // the refusal in it.
    // ---------------------------------------------------------------------
    t.equal(four.authentication.distinct, 1,
      'ONE distinct client: alice called twice, the refused caller is not a ' +
      'client at all, and the anonymous call named nobody');
    t.equal(four.authentication.refused, 1,
      'the refusal is counted, in a figure of its own');
    t.equal(four.authentication.anonymous, 1,
      'and so is the call nothing authenticated');
    t.check(!four.clients.some(function (row) {
      return row.principal === 'mallory';
    }), 'A CALLER THE GATE REFUSED IS IN NO CLIENT ROW, even though the ' +
        'credential carried a name. Attributing traffic to an identity this ' +
        'service declined to believe is the one mistake this page could make ' +
        'that would matter',
        'clients: ' + four.clients.map(function (r) {
          return r.principal;
        }).join(', '));

    const alice = four.clients.filter(function (row) {
      return row.principal === 'alice';
    })[0] || {};
    t.equal(alice.calls, 2, 'alice made two calls');
    t.equal(alice.ok, 1, 'one of which worked');
    t.equal(alice.failed, 1, 'and one of which did not');
    t.equal(alice.kind, 'identity',
      'and she is an identity rather than an application, which is the ' +
      'credential\'s own answer rather than a guess at the shape of the name');
    t.equal(alice.lastOperation, 'read',
      'the LAST operation is the most recent one and not the first');
    t.check(alice.firstAt <= alice.lastAt,
      'and first seen is not after last seen');

    // ---------------------------------------------------------------------
    // THE BREAKDOWN BY CALL TYPE, and the one place its arithmetic is
    // deliberately not the total.
    // ---------------------------------------------------------------------
    const byId = {};
    four.operations.forEach(function (row) { byId[row.operation] = row; });
    t.equal(byId.create.count, 1, 'the create is counted as a create');
    t.equal(byId.create.averageMs, 10,
      'with the duration it was measured at');
    t.equal(byId.read.failed, 1,
      'and the failed read is counted as a failure of THAT operation rather ' +
      'than only in the total — which is the column somebody reads when one ' +
      'verb is failing and the rest are fine');
    t.equal(byId.read.maxMs, 30, 'the slowest read is remembered');
    t.equal(four.latency.maxMs, 30,
      'and the slowest call overall is the same one');
    t.equal(four.latency.totalMs, 42,
      'the total is a SUM rather than a running mean, so any other statistic ' +
      'can still be computed from it');
    t.equal(four.latency.averageMs, 10.5, 'and the mean is derived from it');
    t.equal(four.bytesOut, 1000,
      'the bytes written back are summed across every answer, refusals ' +
      'included');

    t.equal(four.byStatusClass['2xx'], 2, 'two answers were 2xx');
    t.equal(four.byStatusClass['4xx'], 2, 'and two were 4xx');
    t.equal(four.byStatus['404'], 1,
      'the exact codes are kept beside the classes, because "how much is ' +
      'failing" and "with what" are two questions');
    t.equal(four.byScimType['(none)'], 2,
      'a refusal that carried no scimType is counted as (none) rather than ' +
      'dropped, so the two failure tables agree with each other');

    // ---------------------------------------------------------------------
    // THE RING. Newest first, and the individual record an aggregate cannot be.
    // ---------------------------------------------------------------------
    t.equal(four.recent.length, 4, 'all four are remembered individually');
    t.equal(four.recent[0].operation, 'discovery',
      'newest first — the aggregate cannot answer "what just happened" and ' +
      'this is what does');
    t.equal(four.recent[0].principal, '',
      'a call nothing authenticated carries no principal in the ring either');
    t.check(four.recent[1].principal === '',
      'AND NEITHER DOES THE REFUSED ONE. The ring is the other place the ' +
      'name could have leaked back in',
      'got ' + JSON.stringify(four.recent[1].principal));
    t.check(four.recent[1].scheme === 'refused',
      'what it carries instead is the scheme, which is what the page shows ' +
      'in that column');

    // ---------------------------------------------------------------------
    // AN APPLICATION IS TOLD FROM A PERSON, because a `client_id` and a
    // username look alike and only the credential knows which it was.
    // ---------------------------------------------------------------------
    stats.recordScim({ operation: 'list', resourceType: 'User', status: 200,
                       ok: true, authScheme: 'bearer', principal: 'webapp1',
                       isClient: true, ms: 2, bytes: 50 });
    const withApp = stats.scimMonitorSnapshot();
    t.equal(withApp.authentication.applications, 1,
      'a Bearer token minted for an application counts as an application');
    t.equal(withApp.authentication.identities, 1,
      'and the person beside it is still a person');
    t.equal(withApp.authentication.distinct, 2,
      'both are clients, which is what the headline figure means');

    // ---------------------------------------------------------------------
    // THE RING IS BOUNDED, and the tallies are not. A service being load
    // tested must not be able to grow this without limit.
    // ---------------------------------------------------------------------
    stats.resetScimForTests();
    const beyond = stats.SCIM_RECENT + 10;
    for (let i = 0; i < beyond; i++) {
      stats.recordScim({ operation: 'list', resourceType: 'User', status: 200,
                         ok: true, authScheme: 'basic',
                         principal: 'loadtest', ms: 1, bytes: 1 });
    }
    const ringed = stats.scimMonitorSnapshot();
    t.equal(ringed.calls, beyond,
      'every one of them is COUNTED — the tallies are integers and are not ' +
      'capped');
    t.equal(ringed.recent.length, stats.SCIM_RECENT,
      'and only the last ' + stats.SCIM_RECENT + ' are remembered ' +
      'individually, because that ring is one object per request');

    // ---------------------------------------------------------------------
    // A COUNTER MUST NEVER BREAK A PROVISIONING REQUEST, AND A THROW MUST
    // RECORD NOTHING.
    //
    // The second half is the one that is easy to get wrong: an implementation
    // that increments the total and THEN reads the outcome leaves a row whose
    // own arithmetic no longer reconciles, permanently, with nothing to say
    // why. `xacml_monitor.js` has this bug written into its comments as a fix,
    // and this is the same assertion one module over.
    // ---------------------------------------------------------------------
    stats.resetScimForTests();
    const hostile = { operation: 'create', resourceType: 'User', ok: true };
    Object.defineProperty(hostile, 'status', {
      enumerable: true,
      get: function () {
        log.debug("Entering get().");
        log.debug("Leaving get().");
        throw new Error('a getter that throws');
      }
    });
    let threw = false;
    try {
      stats.recordScim(hostile);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      threw = true;
    }
    t.check(!threw,
      'a detail object that throws when it is read does NOT throw into the ' +
      'caller — every call site is on the path of a provisioning request, ' +
      'and a monitoring feature that could fail one would cause the outage ' +
      'it exists to show');
    const afterThrow = stats.scimMonitorSnapshot();
    t.equal(afterThrow.calls, 0,
      'AND IT RECORDS NOTHING RATHER THAN HALF A ROW. Half a count is worse ' +
      'than no count, because it is indistinguishable from a real request ' +
      'and the totals stop adding up for good');
    t.equal(afterThrow.ok + afterThrow.failed, afterThrow.calls,
      'so the arithmetic still reconciles after the failure');

    // A detail object that is missing altogether, which is the other shape of
    // the same argument and the one a refactor produces.
    let threwOnNothing = false;
    try {
      stats.recordScim(undefined);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      threwOnNothing = true;
    }
    t.check(!threwOnNothing,
      'and neither does a call with no detail at all');

    // Leave the counters as they were found, so that a later file in the same
    // run — or a developer reading /admin/scim/monitor after `npm test` — is
    // not looking at this file's traffic.
    stats.resetScimForTests();
    log.debug("Leaving run().");
  }
};
