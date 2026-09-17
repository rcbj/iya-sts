'use strict';
//
// File: ldap_logout.js
//
// ===========================================================================
// A SIGN-OUT REACHING A DIRECTORY CONNECTION IT CANNOT SEE AND CANNOT CLOSE.
//
// In LDAP the connection IS the session — RFC 4511 section 4.2 makes a Bind the
// authorization state of a CONNECTION, and it lasts until the next Bind or an
// Unbind — so the only sign-out the protocol has is the socket ending. The
// service's protocol-independent `/logout` therefore has to be able to reach a
// socket, and since 2026-09-07 the process that answers `/logout` is very often
// not the process that HOLDS one: `common/request_pool.js` runs the whole
// protocol stack in N request workers, and a worker binds no protocol port.
//
// ---------------------------------------------------------------------------
// THE BUG THIS FILE EXISTS FOR, WHICH WAS GREEN IN TWO MODES OF THREE.
//
// A worker's `liveConnections` is permanently empty, so `boundConnections()`
// answered "there are none". The sign-out driver in ../logout/logout.ts ends
// what `collect()` finds, an empty list is nothing to end and nothing to
// report, and a global logout therefore reported that it had ended everything
// while a bound LDAP connection went on being signed in. It cost a whole mode
// of the suite on 2026-09-09: `sts_global_logout` failed on "the bound LDAP
// connection is still open" in `dispatch` and passed in `memory` and
// `postgres`, and nothing in the run said why.
//
// **WHAT MAKES IT WORTH AN IN-PROCESS FILE OF ITS OWN IS THAT THE END-TO-END
// JOB CANNOT SAY WHICH HALF BROKE.** `sts_global_logout` drives a real bind
// over 389 and asserts the socket closes; when that fails, the two candidates
// are "the worker never saw the connection" and "the worker saw it and could
// not close it", and the job cannot tell them apart because both look like a
// socket that is still open. The first two sections below are those halves,
// the third is the two ways the mechanism is allowed to fail, and the last two
// are the header and the timing that join the halves — each asserted
// separately and with no port, no container and no fork.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, AND WHAT DELIBERATELY IS NOT.
//
// This file drives the CONTRACT between three modules: `ldap/ldap_server.js`,
// which owns the list and the sockets; `common/request_pool.js`, which holds
// them in the front process; and `common/request_worker.ts`, which holds
// neither and answers the request anyway. What it does not do is bind 389 or
// fork a worker — the first is `sts_global_logout`'s job over a real socket in
// three stacks, and the second would make this file a stack rather than a test.
//
// The one thing a test like this must never do is assert the mechanism against
// itself: every section below either drives `logout.terminate()` — the real
// driver, the real family table — or compares two modules' own constants.
// ===========================================================================

const ldapServer = require('../ldap/ldap_server');
const logout = require('../logout/logout');
const pool = require('../common/request_pool');
const worker = require('../common/request_worker');
const config = require('../common/config');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'ldap_logout',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// A CONNECTION AS THE FRONT PROCESS PUBLISHES ONE. The shape is
// `connectionSnapshot()`'s: everything boundConnections() reports except the
// socket, which is the one member that cannot cross a process boundary.
// ---------------------------------------------------------------------------
function connectionRow(id, key, dn) {
  log.debug("Entering connectionRow().");
  log.debug("Leaving connectionRow().");
  return { id: id, dn: dn || ('uid=' + key + ',ou=users,dc=example,dc=com'),
           key: key, secure: false, port: 389, boundAt: Date.now() };
}

// Put this process into the state a request worker is in — holding somebody
// else's snapshot and no sockets — and take it out again afterwards. EVERY
// section restores, because these hooks are module-wide in `ldap_server.js` and
// every later file in the run reads through them; see tests/CLAUDE.md's rule
// about process-wide state.
function asAWorker(rows, dropper, fn) {
  log.debug("Entering asAWorker().");
  ldapServer.setConnectionMirror(rows);
  ldapServer.setRemoteDropper(dropper);
  try {
    log.debug("Leaving asAWorker().");
    return fn();
  } finally {
    // BACK TO A PROCESS THAT OWNS ITS OWN SOCKETS. Anything that is not an
    // array uninstalls the mirror — an empty array would mean "the front
    // process is holding nothing", which is a different claim and would leave
    // every later file in this run reading a mirror instead of the real Set.
    ldapServer.setConnectionMirror(null);
    ldapServer.setRemoteDropper(null);
  }
}

// ---------------------------------------------------------------------------
// 1. A WORKER CAN SEE WHAT THE FRONT PROCESS IS HOLDING.
//
// The half that was silently wrong. Nothing here is about closing anything: the
// claim is only that a process with no listener answers the question with the
// front process's list rather than with its own empty one.
// ---------------------------------------------------------------------------
function checkTheMirrorIsRead(t) {
  log.debug("Entering checkTheMirrorIsRead().");
  t.log.info('=== a process with no listener reads the front process\'s list ' +
             '===');

  const local = ldapServer.boundConnections();
  t.check(Array.isArray(local),
          'a process with no mirror reads its own sockets',
          'boundConnections() returned ' + typeof local + '; this test ' +
          'process binds nothing, so the honest answer here is an empty list ' +
          '— what matters is that it is the LOCAL one');

  asAWorker([connectionRow('c-1', 'alice'), connectionRow('c-2', 'bob')],
    function () {},
    function () {
      const seen = ldapServer.boundConnections();
      t.check(seen.length === 2,
              'a mirrored process reports the connections it was published',
              'expected 2, got ' + seen.length + '. This is the assertion ' +
              'the dispatch-mode bug would have failed: the worker answered ' +
              '0 and a sign-out therefore had nothing to end');
      t.check(seen.some(function (c) { return c.key === 'alice'; }) &&
              seen.some(function (c) { return c.key === 'bob'; }),
              'and carries the identity key each connection is bound as',
              'the key is what ../logout/logout.ts filters on, so a row ' +
              'without one is a row no sign-out can ever match: ' +
              JSON.stringify(seen.map(function (c) { return c.key; })));
      const one = seen[0];
      t.check(one.socket === undefined,
              'and no socket rides along',
              'a socket cannot cross a process boundary — `child.send()` ' +
              'structured-clones its argument and would throw on one, so a ' +
              'snapshot carrying it would fail to publish at all');
    });

  const after = ldapServer.boundConnections();
  t.check(after.length === local.length,
          'and the local view is back afterwards',
          'these hooks are module-wide; expected ' + local.length + ' as ' +
          'before, got ' + after.length);
  log.debug("Leaving checkTheMirrorIsRead().");
}

// ---------------------------------------------------------------------------
// 2. AND ASKS THE PROCESS THAT HOLDS THEM TO CLOSE THEM.
//
// Through `logout.terminate()` — the real driver over the real family table —
// rather than by calling dropConnectionsFor() directly, because what broke was
// never that one function: it was that the driver above it found nothing to
// call it about.
// ---------------------------------------------------------------------------
function checkTheDropIsAsked(t) {
  log.debug("Entering checkTheDropIsAsked().");
  t.log.info('=== a sign-out in a worker asks the front process ===');

  const on = config.value('logout.ldapDisconnect');
  if (!on) {
    t.check(false, 'logout.ldapDisconnect is on',
            'it is off in this configuration, so a sign-out leaves directory ' +
            'connections alone by policy and the rest of this section would ' +
            'be asserting the wrong thing');
    log.debug("Leaving checkTheDropIsAsked().");
    return;
  }

  const asked = [];
  asAWorker([connectionRow('c-9', 'carol')],
    function (key) { asked.push(key); },
    function () {
      const result = logout.terminate('carol', [], { by: 'ldap_logout.js' });
      // `terminated` and not `done`: that is the field name terminate()
      // answers with, and reading the wrong one is a test that passes while
      // asserting nothing about what was ended.
      const ldapRows = (result.terminated || []).filter(function (r) {
        return r.family === 'ldap';
      });
      t.check(asked.length === 1 && asked[0] === 'carol',
              'the front process is asked to close that person\'s connections',
              'expected one ask for carol, got ' + JSON.stringify(asked) +
              '. Nothing in this process can close the socket, so an ask ' +
              'that is never made is a connection that stays open');
      t.check(ldapRows.length === 1,
              'and the sign-out reports the connection as ended',
              'expected one ldap row in terminated, got ' + ldapRows.length +
              ': ' + JSON.stringify(result.terminated || []));
      t.check(ldapRows.length === 1 && /c-9/.test(ldapRows[0].message || ''),
              'naming the connection it ended',
              'the message is what /logout and /admin/logout draw: ' +
              JSON.stringify(ldapRows.map(function (r) { return r.message; })));
      t.check(ldapServer.boundConnections().length === 0,
              'and the row is out of the mirror at once',
              'a global logout calls the family once per row, and a snapshot ' +
              'that still held it would report the same connection ended ' +
              'twice — the front process\'s next push is the authority, and ' +
              'this is about the seconds before it');
    });
  log.debug("Leaving checkTheDropIsAsked().");
}

// ---------------------------------------------------------------------------
// 3. A SIGN-OUT THAT CANNOT REACH THE SOCKET SAYS SO.
//
// The failure that matters, because the alternative is the original bug wearing
// a different hat: a logout that reports success about a connection nobody was
// asked to close. Both ways of failing are asserted — no way to ask at all, and
// an ask that was refused (which in a worker means the answer this request
// would have ridden out on has already gone).
// ---------------------------------------------------------------------------
function checkAFailedAskIsReported(t) {
  log.debug("Entering checkAFailedAskIsReported().");
  t.log.info('=== a sign-out that cannot reach the socket reports a failure ' +
             '===');

  [{ what: 'with no way to ask the front process',
     dropper: null,
     expect: /no directory listener/ },
   { what: 'when the ask is refused',
     dropper: function () {
       log.debug("Entering dropper().");
       log.debug("Leaving dropper().");
       throw new Error('headers have already gone');
     },
     expect: /could not be asked/ }].forEach(function (one) {
    asAWorker([connectionRow('c-7', 'dave')], one.dropper, function () {
      const result = logout.terminate('dave', [], { by: 'ldap_logout.js' });
      const done = (result.terminated || []).filter(function (r) {
        return r.family === 'ldap';
      });
      const skipped = (result.skipped || []).filter(function (r) {
        return r.family === 'ldap';
      });
      t.check(done.length === 0,
              'the connection is NOT reported as ended ' + one.what,
              'reporting one closed that nobody was asked to close is the ' +
              'bug this mechanism exists to fix, restated one layer up: ' +
              JSON.stringify(done));
      t.check(skipped.length === 1,
              'it is reported as not ended ' + one.what,
              'expected one skipped ldap row, got ' + skipped.length + ': ' +
              JSON.stringify(result.skipped || []));
      t.check(skipped.length === 1 && one.expect.test(skipped[0].message || ''),
              'with a message saying why ' + one.what,
              'expected something matching ' + one.expect + ', got ' +
              JSON.stringify(skipped.map(function (r) { return r.message; })));
    });
  });

  asAWorker([connectionRow('c-6', 'erin')],
    function () { throw new Error('refused'); },
    function () {
      logout.terminate('erin', [], { by: 'ldap_logout.js' });
      t.check(ldapServer.boundConnections().length === 1,
              'and a refused ask leaves the connection in the mirror',
              'it was never closed, so forgetting it would hide a live ' +
              'session from the next sign-out and from /admin/sessions');
    });
  log.debug("Leaving checkAFailedAskIsReported().");
}

// ---------------------------------------------------------------------------
// 4. THE TWO PROCESSES SPELL THE HEADER THE SAME WAY.
//
// The instruction rides OUT on the response — see `request_pool.js`'s
// LDAP_DROP_HEADER for why it is the response and not the IPC channel beside
// it — and the two ends are two constants in two files that share no memory. A
// rename in one is not a crash: it is a header the other end never looks at, so
// every sign-out silently stops closing anything and every mode of the suite
// goes back to where it started.
// ---------------------------------------------------------------------------
function checkTheHeaderAgrees(t) {
  log.debug("Entering checkTheHeaderAgrees().");
  t.log.info('=== the worker and the front process name the same header ===');

  t.check(!!pool.LDAP_DROP_HEADER && !!worker.LDAP_DROP_HEADER,
          'both ends name a header',
          'pool=' + pool.LDAP_DROP_HEADER + ', worker=' +
          worker.LDAP_DROP_HEADER);
  t.check(pool.LDAP_DROP_HEADER === worker.LDAP_DROP_HEADER,
          'and it is the same one',
          'a rename in either file is silent — the other end simply stops ' +
          'reading it, and nothing fails: pool=' + pool.LDAP_DROP_HEADER +
          ', worker=' + worker.LDAP_DROP_HEADER);
  t.check(String(pool.LDAP_DROP_HEADER).toLowerCase() === pool.LDAP_DROP_HEADER,
          'and it is lower case',
          'node lower-cases incoming header names, so a mixed-case constant ' +
          'is a header the pool would strip on the way in and never find on ' +
          'the way out: ' + pool.LDAP_DROP_HEADER);

  // The front process's half of the header, driven without a worker: what it
  // does with the value one would carry. The keys are percent-encoded, so a
  // username with a comma in it stays one key rather than becoming two.
  const seen = [];
  const realDrop = ldapServer.dropConnectionsFor;
  ldapServer.dropConnectionsFor = function (key) {
    log.debug("Entering dropConnectionsFor().");
    seen.push(key);
    log.debug("Leaving dropConnectionsFor().");
    return [];
  };
  try {
    pool.closeDirectoryConnections(encodeURIComponent('a,b') + ',' +
                                   encodeURIComponent('frank'));
    t.check(seen.length === 2 && seen[0] === 'a,b' && seen[1] === 'frank',
            'the front process decodes every key the header carries',
            'expected ["a,b","frank"], got ' + JSON.stringify(seen));
    seen.length = 0;
    pool.closeDirectoryConnections('');
    pool.closeDirectoryConnections(undefined);
    t.check(seen.length === 0,
            'and an answer with no such header closes nothing',
            'every response in this service passes through that code path, ' +
            'so a header-less one must be inert: ' + JSON.stringify(seen));
  } finally {
    ldapServer.dropConnectionsFor = realDrop;
  }
  log.debug("Leaving checkTheHeaderAgrees().");
}

// ---------------------------------------------------------------------------
// 5. THE SNAPSHOT IS TAKEN AFTER THE HANDLER, NOT INSIDE IT.
//
// The subtlest part of the mechanism and the one that cost a second run. The
// front process publishes on BIND, because a bind is what turns an anonymous
// socket into somebody's session — but **ldapjs sets `conn.ldap.bindDN` after
// the handler chain has run**, in node-ldapjs/lib/server.js at the point where
// it finds no handler left. A snapshot taken inside the handler therefore
// carries an empty DN, `consoleKeyFor()` derives no key from it, and
// `logout.ts`'s ldap family filters on exactly that key — so the worker's
// mirror filled up with rows belonging to nobody and the sign-out found
// nothing to end. The mechanism was in place, every part of it worked, and the
// bug it was written to fix was still there.
//
// The assertion is the SHAPE of the fix rather than the ldapjs interaction:
// that a publish asked for synchronously is delivered after the asking scope
// returns. What proves the interaction itself is `sts_global_logout`, which
// binds for real over 389 — and this file exists because that job can only
// report that the socket was still open.
// ---------------------------------------------------------------------------
function checkThePublishIsDeferred(t, done) {
  log.debug("Entering checkThePublishIsDeferred().");
  t.log.info('=== the snapshot is taken after the bind handler returns ===');

  let calledInline = false;
  let calledLater = false;
  ldapServer.setConnectionWatcher(function () {
    if (inTheHandler) {
      calledInline = true;
    } else {
      calledLater = true;
    }
  });
  let inTheHandler = true;
  // Twice, from one synchronous scope, exactly as a burst of connections would.
  ldapServer.publishConnectionsSoon();
  ldapServer.publishConnectionsSoon();
  inTheHandler = false;

  t.check(!calledInline,
          'a publish asked for inside a handler does not happen inside it',
          'ldapjs sets the bound DN after the chain returns, so a snapshot ' +
          'taken here is a snapshot of an anonymous connection — every row ' +
          'keyless, and a sign-out that matches on the key finds nothing');

  setImmediate(function () {
    t.check(calledLater,
            'and does happen on the next tick',
            'a publish that never arrived would leave every worker holding ' +
            'the list it was forked with, which is empty');
    ldapServer.setConnectionWatcher(null);
    done();
  });
  log.debug("Leaving checkThePublishIsDeferred().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheMirrorIsRead(t);
  checkTheDropIsAsked(t);
  checkAFailedAskIsReported(t);
  checkTheHeaderAgrees(t);
  log.debug("Leaving run().");
  // The one section with a tick in it, so `run()` answers a promise the runner
  // awaits — see tests/run.js, which handles both shapes.
  return new Promise(function (resolve) {
    checkThePublishIsDeferred(t, resolve);
  });
}

module.exports = {
  name: 'ldap_logout',
  describe: 'a sign-out reaching a directory connection held by another ' +
            'process: what a request worker can see, what it can close, and ' +
            'what it says when it cannot',
  run: run
};
