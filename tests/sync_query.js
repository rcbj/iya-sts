// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sync_query.js
//
// ===========================================================================
// THE DIRECTORY BRIDGE: A SYNCHRONOUS QUESTION THROUGH A WORKER THREAD (#349
// phase 3, 2026-09-29).
//
// `common/sync_query.ts` blocks the calling thread on `Atomics.wait()` while
// `common/sync_query_thread.ts` answers. The stand-in database
// (`tests/sync_query_kit.js`) runs inside the real thread, so everything but
// `pg` itself is the real mechanism:
//
//   A. an answer comes back synchronously, and the event loop really is held
//      while it is awaited (a timer due before the question runs after it);
//   B. no answer within the bound is `STS-LDAP-0130`, after the bound and not
//      long past it; the late answer is dropped, and the next question gets
//      its own;
//   C. a database error is `STS-LDAP-0131`, carrying the database's words;
//   D. a thread that dies is a timeout, and the next question starts a new
//      thread that answers;
//   E. the `pg` path's own front half, with no database: an unknown query is
//      refused before anything is dialled, and an address nobody listens on
//      is a refusal (`STS-LDAP-0131`) inside the bound.
//   F. a console request's budget (#359): `runWithBudget()` cuts a question
//      to the room that is left (`STS-LDAP-0130`) and, once that room is
//      gone, refuses the next question (`STS-LDAP-0162`) without posting it.
//      The kit's thread is one thread, so a question the budget cut short is
//      still running there: the next case waits for it. No slot means no
//      budget.
//
// WHAT NEEDS A REAL POSTGRES (on #349): an answer through `pg` itself, the
// statement timeout taking effect, and a database restarted under a waiting
// question.
// ===========================================================================

const path = require('path');
const SyncQuery = require('../common/sync_query');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'sync_query',
  level: process.env.LOG_LEVEL || 'info' });

const KIT = path.join(__dirname, 'sync_query_kit.js');

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// Runs `f`, answering `{ value, code, message, ms }`.
function attempt(f) {
  log.debug("Entering attempt().");
  const started = Date.now();
  try {
    const value = f();
    log.debug("Leaving attempt().");
    return { value: value, code: '', message: '', ms: Date.now() - started };
  } catch (e) {
    log.debug("Caught in attempt(): " + e.message);
    log.debug("Leaving attempt(). Thrown.");
    return { value: undefined, code: errorCodes.codeOf(e),
             message: e.message, ms: Date.now() - started };
  }
}

async function run(t) {
  log.debug("Entering run().");
  let bound = 300;
  const bridge = new SyncQuery({ backend: KIT,
                                 timeoutMs: function () { return bound; } });
  try {
    t.log.info('=== A. a synchronous answer ===');
    const first = attempt(function () {
      return bridge.query('echo', [{ rows: [1, 2, 3], dn: 'uid=a' }]);
    });
    t.equal(JSON.stringify(first.value), '{"rows":[1,2,3],"dn":"uid=a"}',
            'A1. the thread\'s answer comes back from a synchronous call');
    let ranBetween = false;
    setTimeout(function () {
      ranBetween = true;
    }, 0);
    const slowish = attempt(function () {
      return bridge.query('slow', [50, 'done']);
    });
    t.check(slowish.value === 'done' && !ranBetween && slowish.ms >= 45,
            'A2. the event loop is held while the answer is awaited: a ' +
            'timer due before the question had not run when it returned',
            JSON.stringify({ ms: slowish.ms, ranBetween: ranBetween }));
    let all = true;
    for (let i = 0; i < 200; i++) {
      if (bridge.query('echo', [i]) !== i) {
        all = false;
      }
    }
    t.check(all, 'A3. two hundred questions in a row each get their own ' +
            'answer');

    t.log.info('=== B. the bound ===');
    bound = 100;
    const late = attempt(function () {
      return bridge.query('slow', [400, 'too late']);
    });
    t.check(late.code === 'STS-LDAP-0130' && late.ms >= 95 && late.ms < 600,
            'B1. no answer within the bound is STS-LDAP-0130, at the bound',
            JSON.stringify(late));
    await pause(450);
    bound = 300;
    const next = attempt(function () {
      return bridge.query('echo', ['mine']);
    });
    t.equal(next.value, 'mine',
            'B2. the late answer is dropped and the next question gets its ' +
            'own');

    t.log.info('=== C. a refusal ===');
    const refused = attempt(function () {
      return bridge.query('fail', ['relation "sts_ldap_entries" does not ' +
                                   'exist']);
    });
    t.check(refused.code === 'STS-LDAP-0131' &&
            /does not exist/.test(refused.message),
            'C1. a database error is STS-LDAP-0131 with the database\'s words',
            refused.message);

    t.log.info('=== D. a thread that dies ===');
    bound = 200;
    const startedBefore = bridge.stats().started;
    const died = attempt(function () {
      return bridge.query('crash', []);
    });
    t.equal(died.code, 'STS-LDAP-0130',
            'D1. a thread that dies mid-question is a timeout');
    // The `exit` event is delivered by the event loop the question held.
    await pause(100);
    const after = attempt(function () {
      return bridge.query('echo', ['again']);
    });
    t.check(after.value === 'again' &&
            bridge.stats().started === startedBefore + 1,
            'D2. the next question starts a new thread, which answers',
            JSON.stringify(bridge.stats()));
    const s = bridge.stats();
    t.check(s.timedOut === 2 && s.failed === 1 && s.questions >= 205,
            'D3. stats() counts the questions, timeouts and refusals',
            JSON.stringify(s));
  } finally {
    await bridge.stop();
  }

  t.log.info('=== E. the pg path, with no database ===');
  const nowhere = new SyncQuery({
    connection: { connectionString: 'postgres://nobody@127.0.0.1:1/none',
                  connectionTimeoutMillis: 1000 },
    timeoutMs: function () { return 3000; } });
  try {
    const unknown = attempt(function () {
      return nowhere.query('dropEverything', []);
    });
    t.check(unknown.code === 'STS-LDAP-0131' &&
            /no query called/.test(unknown.message) && unknown.ms < 3000,
            'E1. a query directory_queries.js does not know is refused ' +
            'before anything is dialled', unknown.message);
    const refusedConnection = attempt(function () {
      return nowhere.query('count', ['default', '']);
    });
    t.check(refusedConnection.code === 'STS-LDAP-0131' &&
            refusedConnection.ms < 3000,
            'E2. an address nobody listens on is a refusal inside the bound',
            JSON.stringify(refusedConnection));
  } finally {
    await nowhere.stop();
  }

  t.log.info('=== F. a request\'s budget (#359) ===');
  bound = 300;
  const budgetBridge = new SyncQuery({ backend: KIT,
    timeoutMs: function () { return bound; } });
  try {
    const free = attempt(function () {
      return SyncQuery.runWithBudget(0, function () {
        return budgetBridge.query('echo', ['free']);
      });
    });
    t.check(free.value === 'free' && free.code === '',
            'F1. a non-positive budget runs the question with none',
            JSON.stringify(free));
    const cut = SyncQuery.runWithBudget(40, function () {
      const slow = attempt(function () {
        return budgetBridge.query('slow', [500, 'late']);
      });
      const asked = budgetBridge.stats().questions;
      const refused = attempt(function () {
        return budgetBridge.query('echo', ['no']);
      });
      return { slow: slow, refused: refused, asked: asked,
               questions: budgetBridge.stats().questions,
               budgetRefused: budgetBridge.stats().budgetRefused };
    });
    t.check(cut.slow.code === 'STS-LDAP-0130' && cut.slow.ms >= 20 &&
            cut.slow.ms < 200,
            'F2. a question is cut to the budget that is left, and times ' +
            'out as STS-LDAP-0130', JSON.stringify(cut.slow));
    t.check(cut.refused.code === 'STS-LDAP-0162' && cut.refused.ms < 50 &&
            cut.questions === cut.asked && cut.budgetRefused >= 1,
            'F3. once the budget is spent the next question is ' +
            'STS-LDAP-0162 and is not asked', JSON.stringify(cut));
    // The thread is still inside slow(500). The next case waits it out.
    await pause(600);
    const summed = SyncQuery.runWithBudget(200, function () {
      const one = attempt(function () {
        return budgetBridge.query('slow', [25, 'one']);
      });
      const two = attempt(function () {
        return budgetBridge.query('slow', [25, 'two']);
      });
      const third = attempt(function () {
        return budgetBridge.query('slow', [500, 'three']);
      });
      const asked = budgetBridge.stats().questions;
      const fourth = attempt(function () {
        return budgetBridge.query('echo', ['four']);
      });
      return { one: one, two: two, third: third, fourth: fourth,
               asked: asked, questions: budgetBridge.stats().questions };
    });
    t.check(summed.one.value === 'one' && summed.two.value === 'two',
            'F4. two short questions inside the budget both answer',
            JSON.stringify({ one: summed.one, two: summed.two }));
    t.check(summed.third.code === 'STS-LDAP-0130' && summed.third.ms < 250,
            'F5. a later question is cut to the room that remains',
            JSON.stringify(summed.third));
    t.check(summed.fourth.code === 'STS-LDAP-0162' &&
            summed.questions === summed.asked && summed.fourth.ms < 50,
            'F6. and the question after that is refused without being asked',
            JSON.stringify(summed.fourth));
    await pause(600);
    const open = attempt(function () {
      return budgetBridge.query('slow', [400, 'open']);
    });
    t.check(open.code === 'STS-LDAP-0130' && open.ms >= 250 && open.ms < 700,
            'F7. with no budget a question uses its own bound',
            JSON.stringify(open));
    await pause(450);
    const again = attempt(function () {
      return budgetBridge.query('echo', ['again']);
    });
    t.equal(again.value, 'again',
            'F8. and the next question, still with no budget, is answered');
  } finally {
    await budgetBridge.stop();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sync_query',
  describe: 'the directory bridge (#349): a synchronous answer through a ' +
            'worker thread, the bound, a refusal, a thread that dies, the ' +
            'pg path with no database, and a request\'s budget (#359)',
  run: run
};
