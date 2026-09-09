'use strict';
//
// File: request_worker.js
//
// ---------------------------------------------------------------------------
// ONE WORKER THAT HANDLES REQUESTS, RATHER THAN ONE THAT COMPUTES A SIGNATURE.
//
// `worker.js` beside this file is the OTHER kind and the two are not rivals:
// that one runs a JOB TABLE — four leaf computations handed everything they
// need — and it exists because a post-quantum signature took 14.6 seconds on
// the thread that owns every socket. This one runs the SERVICE. It loads the
// same protocol stack the front process loads, in the same order, and answers
// HTTP.
//
// The goal it serves is one sentence: **the front process should be doing
// request/response I/O and nothing else.** Four leaf computations moved off
// that thread; every handler still ran on it. This is the machinery for moving
// the handlers.
//
// ---------------------------------------------------------------------------
// IT SPEAKS REAL HTTP OVER A UNIX SOCKET, AND THAT IS THE DECISION IN THIS FILE
// WORTH ARGUING.
//
// The obvious implementation is to serialize the request into the IPC channel
// this repository already has, rebuild a fake `req`/`res` pair in the worker,
// and hand it to `app.handle()`. It was rejected, and not on taste:
//
//   * **A fake `res` is a second implementation of `http.ServerResponse`**, and
//     the handlers here use the real one's whole surface — `res.write()` in
//     chunks, `res.end()` with and without a body, `res.set()`, `res.status()`,
//     `res.redirect()`, `res.sendFile()`, and a `res.send()` OVERRIDE in
//     app.js that rewrites HTML and re-checks the CSP as the response is
//     flushed. Every one of those would have to be reproduced exactly, and the
//     ones that were reproduced NEARLY exactly would be the bugs.
//   * **A fake `req` is a second HTTP parser.** Chunked bodies, a `content-type`
//     with parameters, repeated headers, a `HEAD` that must send no body,
//     `Expect: 100-continue`, an upgrade — node already implements all of it
//     and there is no version of hand-rolling it that is not worse.
//   * **The response-flush CSP re-check is the one that decides it.** The root
//     CLAUDE.md records that Express's own 404 handler REPLACES the security
//     header, which nothing in this service could see, because the header this
//     service set was correct and something else overwrote it. That check hangs
//     off the real response object. A fake one would have removed a control
//     while every test went on passing — which is precisely the class of defect
//     this repository writes its tests to catch.
//
// So a worker binds an `http.Server` on a **Unix domain socket** and the front
// process proxies to it. Both ends use node's own parser, the handlers get the
// objects they were written against, and **a handler behaves identically in a
// worker and in the front process BY CONSTRUCTION** rather than because a
// compatibility shim was kept up to date.
//
// A unix socket rather than a TCP port because it is not a port: it cannot
// collide with a protocol listener, it is not reachable from off the machine,
// and it needs no free-port dance. It is created under the directory
// `workers.socketDir` names (the system temporary directory by default) and
// unlinked on the way out.
//
// ---------------------------------------------------------------------------
// A WORKER BINDS NO PROTOCOL PORT, AND THAT IS WHY N OF THEM CAN EXIST.
//
// `protocol_stack.js` requires every module, which REGISTERS every route and
// starts nothing: the Kerberos KDC's two sockets, the LDAP directory's two,
// SPIFFE's four and the two TLS endpoints are all bound from `listen()` in
// `server.js`, which a worker never calls. That separation predates this file
// by a fortnight and was made for a different reason — binding can fail, and a
// `require` that throws takes the process down where a route cannot — which is
// the ordinary way a good boundary pays twice.
//
// **A WORKER SERVES MORE THAN HTTP, AND THIS PARAGRAPH SAID OTHERWISE FOR AN
// HOUR.** It read "what a worker does not serve is anything that is not HTTP —
// a Kerberos AS-REQ on UDP 88, an LDAP bind on 389, a gRPC call on the Workload
// API arrive on sockets only the front process holds, and they are handled
// there." The first half is true and the conclusion does not follow: the front
// process holds the SOCKET, and that is a reason for it to do the framing, not
// a reason for it to do the WORK.
//
// An LDAP search has exactly the same reason to leave this thread as a
// `/scim/v2` POST does. So the front process accepts the connection, decodes
// the BER and writes the reply, and hands the OPERATION over — see the
// operation table at the foot of this file. The transport a request arrived on
// is not a property of the work it asks for.
//
// ---------------------------------------------------------------------------
// THE STATE PROBLEM IS REAL AND IT IS NOT SOLVED HERE.
//
// Requiring the protocol stack gives this worker its OWN directory, its own
// session map, its own token registry and its own realm table — seeded at
// require time exactly as the front process's were. Two workers would then
// disagree about everything that is written by one request and read by
// another, which `worker.js`'s header lists at length: replay detection that
// stops detecting, an introspection 404 for a token that exists, a config
// change that lands on one worker of four.
//
// **So this file is the TRANSPORT and `state_channel.js` is the other half.**
// Until every store a handler touches is reached through that channel, a
// worker is correct only for requests that read and write nothing shared —
// which is why `request_pool.js` dispatches by an explicit allow-list rather
// than by default, and why that list starts empty.
// ---------------------------------------------------------------------------

// FIRST, and for the reason server.js gives: this process was forked, so it
// inherited a CONFIG_FILE that may still be the relative path the operator
// typed, and a relative require resolves against the directory of the module
// doing the requiring. Idempotent, so the parent having done it costs nothing.
require('./config_file').resolveConfigFile();

const http = require('http');
const fs = require('fs');
const bunyan = require('bunyan');
const config = require('./config');
// The four startup steps, shared with server.js — the store, the keys, the
// minted rows and COORDINATION. See service_state.js.
const serviceState = require('./service_state');

const log = bunyan.createLogger({
  name: 'request_worker',
  level: (function () {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

// ---------------------------------------------------------------------------
// HOW LONG A WORKER HAS TO COME UP, AND IT COVERS THE STATE AND NOT THE SOCKET.
//
// It was 15 seconds and named BIND_TIMEOUT_MS, on the reasoning that binding a
// unix socket is a filesystem operation that does not contend for a port. That
// was true and it stopped being the thing being timed the moment
// `service_state.start()` moved ahead of the bind: a worker now opens a
// database, restores the directory, the realms, the settings, the signing keys
// and the minted rows, and takes the change log's high-water mark — before it
// listens.
//
// **THE 15 SECONDS THEN FIRED ON HEALTHY WORKERS**, and the failure was
// quiet in the worst way: each worker reported `ready: false`, the pool wrote
// off all three, the front process announced "0 of 3 request worker(s) are
// serving" AND BOUND THE LISTENER ANYWAY — and then the workers finished
// starting and reported ready after all, so requests were served correctly
// while the log said there was nothing to serve them. A window at startup
// where a dispatched path answers 503 is the part that is not merely cosmetic.
//
// Sixty seconds is what a cold postgres restore takes room for. It is a
// backstop against a worker that will never come up rather than a tuned value,
// and the front process waits for the message rather than for the clock.
// ---------------------------------------------------------------------------
const START_TIMEOUT_MS = 60000;

let server = null;
// MODULE SCOPE because start() arms it and bindSocket() clears it, and those
// became two functions when the state startup moved ahead of the bind. It was
// a `const` inside start() for an hour after that split, so every worker threw
// `ReferenceError: timer is not defined` from its own `listening` handler —
// AFTER reporting that its state was up, which is why the log read as three
// healthy workers and the pool counted none.
let startTimer = null;
let socketPath = '';
let inFlight = 0;
let served = 0;

// ---------------------------------------------------------------------------
// THE RESPONSE THIS WORKER IS CURRENTLY WRITING (2026-09-09), AND THE ONE
// THING THAT NEEDS IT.
//
// `ldap_server.js` in a worker cannot close a directory connection: the socket
// belongs to the front process. What it can do is say so ON THIS REQUEST'S
// ANSWER, which the front process reads before it forwards a byte — see
// `request_pool.js`'s LDAP_DROP_HEADER for why the answer and not the IPC
// channel beside it.
//
// **AN AsyncLocalStorage AND NOT A MODULE-LEVEL `let`**, which is the whole
// reason this block exists rather than a variable. Two sign-outs can be in
// flight in one worker; a `let` would hand the second request's response to the
// first one's handler, and the symptom would be a logout that reported a
// connection closed while the header rode away on somebody else's answer —
// intermittent, load-dependent, and identical to the bug this mechanism fixes.
// The realm is ambient for the same class of reason (see `common/realms.js`),
// and this is a second store rather than a field on that one because the realm
// context is entered by `app.js` for EVERY process and this exists only in a
// worker.
// ---------------------------------------------------------------------------
const { AsyncLocalStorage } = require('async_hooks');
const currentResponse = new AsyncLocalStorage();

// The header the front process acts on. Named here and in `request_pool.js`,
// and those two spellings must agree — the pool's copy carries the argument.
const LDAP_DROP_HEADER = 'x-sts-ldap-drop';

// ---------------------------------------------------------------------------
// WHAT THIS WORKER KNOWS ABOUT DIRECTORY CONNECTIONS, AND WHAT IT ASKS FOR.
//
// Called once, after the protocol stack is loaded. The two halves are the two
// ways a process with no listener is wrong about LDAP: it cannot SEE a bound
// connection (so a sign-out finds nothing to end) and it cannot CLOSE one (so
// saying it did would be a lie). `ldap_server.js` argues both at the block
// above its boundConnections().
// ---------------------------------------------------------------------------
function installDirectoryMirror(seed) {
  log.debug('Entering installDirectoryMirror().');
  const ldapServer = require('../ldap/ldap_server');
  ldapServer.setConnectionMirror(seed || []);
  ldapServer.setRemoteDropper(function (key) {
    const res = currentResponse.getStore();
    if (!res) {
      // A sign-out that did not arrive over HTTP — nothing does this today, and
      // the honest answer is that there is no answer for it to ride out on.
      // Thrown rather than logged, because dropConnectionsFor() catches it and
      // says the connections may still be open, which is the truth.
      throw new Error('there is no response in flight in this worker to carry ' +
                      'the request on, so the front process cannot be asked');
    }
    if (res.headersSent) {
      throw new Error('this request\'s headers have already gone to the ' +
                      'client, so the front process cannot be asked in time');
    }
    // APPENDED, because one sign-out can end more than one person's
    // connections — `/admin/logout` acts on a key that is not the caller's —
    // and because the header is the only channel. Percent-encoded: a key is a
    // username and a header is bytes, and a comma in one would otherwise
    // become two keys.
    const had = String(res.getHeader(LDAP_DROP_HEADER) || '');
    const one = encodeURIComponent(String(key || ''));
    const all = had ? had.split(',') : [];
    if (all.indexOf(one) < 0) {
      all.push(one);
    }
    res.setHeader(LDAP_DROP_HEADER, all.join(','));
    log.debug('installDirectoryMirror(): asked the front process to sign ' +
              key + ' out of the directory.');
  });
  log.debug('Leaving installDirectoryMirror().');
}

// ---------------------------------------------------------------------------
// Load the service and answer on the socket.
//
// The app is required AFTER the socket path is known but BEFORE the socket is
// bound, so that a worker never accepts a request it is not yet able to
// answer. Loading the stack is the expensive part of starting a worker — it
// seeds a directory and generates a realm's keys — and the front process waits
// for the `ready` message rather than assuming a duration.
// ---------------------------------------------------------------------------
function start(path) {
  log.debug('Entering start(). socket=' + path);
  socketPath = String(path || '');
  if (!socketPath) {
    throw new Error('request_worker: no socket path was given. The front ' +
      'process passes one in the fork arguments; this file is not meant to ' +
      'be run by hand.');
  }
  // A socket left behind by a worker that was killed rather than drained.
  // Removed rather than treated as an error: the front process gave us this
  // path and nothing else may be listening on it.
  try {
    fs.unlinkSync(socketPath);
    log.debug('start(): removed a stale socket at ' + socketPath);
  } catch (e) {
    // ENOENT is the ordinary case — there was nothing there, which is what we
    // want. Anything else is reported when the bind fails, with a better
    // message than this one could give.
  }

  // THE WHOLE SERVICE, in the one order there is. See protocol_stack.js.
  const app = require('./app');

  // -------------------------------------------------------------------------
  // THE FRONT PROCESS IS A TRUSTED PROXY, AND SAYING SO IS NOT OPTIONAL.
  //
  // A request reaches this worker over a unix socket, which is not TLS, so
  // express computes `req.protocol` as `http` and `req.secure` as false — and
  // it IGNORES the `x-forwarded-proto` the front process sends, because by
  // default express trusts no proxy at all.
  //
  // **WHAT THAT BREAKS IS EVERY ABSOLUTE URL THIS SERVICE BUILDS.** The
  // console's own sign-in was the first casualty: `/admin/tokens` redirected
  // to `http://localhost:8081/oauth2/authorize` on a service listening for
  // TLS, and the browser — or the suite — dialled plain HTTP at a TLS port and
  // got a dropped socket. The error is `UND_ERR_SOCKET` and it names nothing;
  // it took tracing every hop of a console sign-in to see that one redirect
  // had the wrong scheme. The issuer in a token, a SAML endpoint in metadata
  // and every `redirect_uri` check are the same computation.
  //
  // Trusting the proxy here is safe for a reason that is structural rather
  // than conventional: this server listens on a UNIX SOCKET in an owner-only
  // directory, so the only thing that can reach it is the front process, which
  // sets these headers itself after stripping whatever the client sent. If
  // this worker ever gains a second listener, this line has to be revisited
  // with it.
  // -------------------------------------------------------------------------
  app.set('trust proxy', true);

  require('./protocol_stack');

  // -------------------------------------------------------------------------
  // THE CLIENT CERTIFICATE, PUT BACK ON THE REQUEST BEFORE THE APP SEES IT.
  //
  // A proxied request arrives on a unix socket, which has no peer certificate,
  // and three surfaces here decide on one: RFC 8705's token binding, SCIM's
  // certificate scheme, and `/xacml/pep/*`, which admits a remote PEP only on
  // a certificate this service VERIFIED. The front process forwards what it
  // saw; this puts it back where `mtls.js`, `scim_auth.js` and `xacml.js` look
  // for it, so not one of them needed changing.
  //
  // **A PER-REQUEST OBJECT AND NOT A MUTATED SOCKET.** The obvious version
  // assigns `getPeerCertificate` onto the socket itself, and it is wrong for a
  // reason that would be found late and rarely: this server keeps connections
  // ALIVE, so one socket carries many requests, and a certificate written onto
  // it would still be there for the next request on the same connection —
  // handing request B the certificate request A presented. So the shim is made
  // per request with `Object.create(socket)`, which shadows the two members and
  // delegates everything else — `remoteAddress`, `encrypted` and the rest —
  // to the real socket.
  //
  // **AND ONLY WHEN A CERTIFICATE WAS FORWARDED.** With no header the request
  // is left completely alone, so the shim exists only on the requests that
  // need it and the ordinary path is untouched.
  //
  // The headers are TRUSTED HERE, and that is safe for exactly one reason: this
  // server listens on a unix socket in an owner-only directory, so the only
  // thing that can reach it is the front process — which strips these headers
  // off whatever the client sent before writing the real ones. If this server
  // ever gains a second listener, that reasoning goes with it.
  // -------------------------------------------------------------------------
  const PEER_CERT_HEADER = 'x-sts-peer-certificate';
  // The ticket the front process dispatched this request under. Read once, off
  // the request, and stripped before the app sees it — see below.
  const POOL_TICKET_HEADER = 'x-sts-pool-ticket';
  const PEER_AUTHORIZED_HEADER = 'x-sts-peer-authorized';

  // The store, for the commit-before-answer block in the handler below.
  // Required HERE rather than at the top of this file for the reason every
  // other require in `start()` is: nothing of the service is loaded until the
  // `begin` message arrives, which is this module's whole shape. By this line
  // the stack is loaded and it is a cache hit.
  const persistence = require('../persistence/persistence');

  // Whether this request's commit has to be announced. The METHOD is the test,
  // conservatively — this process cannot know whether a POST changed anything,
  // and an announcement for a request that wrote nothing costs one extra
  // sequence read, where a missing one costs a stale answer.
  // **EVERY REQUEST, NOT EVERY WRITE METHOD (2026-09-07).**
  //
  // This tested the METHOD, which is the test `request_pool.js` uses on its
  // side and is wrong here for a reason particular to this service: GETs mint
  // state. `GET /oauth2/authorize` creates the pending authentication record
  // the sign-in form posts back to; the SAML and WS-Federation front doors do
  // the same; and every cookie-less request to a front door mints an arrival
  // session. A GET that wrote set no marker, moved no generation, and left the
  // POST that followed it free to land on a worker that had never heard of the
  // record — measured as `the sign-in form should redirect, got 400` across
  // five jobs, which is `pendingFor()` missing.
  //
  // Announcing after every request is affordable because BOTH halves are cheap
  // when nothing was written: `persistence.flush()` computes no diff unless a
  // dirty bit is set, and the sequence read is one indexed query. What it buys
  // is that "did this request write" stops being a guess made from the method
  // by the process that did not run the handler.
  // The tickets of responses that have finished and whose flush has not been
  // announced yet. Bounded by the number of requests between two
  // announcements, and every request announces.
  let finishedTickets = [];

  function announcesWrites(req) {
    return !!config.value('workers.readYourWrite');
  }

  // ---------------------------------------------------------------------
  // FLUSH, THEN TELL THE FRONT PROCESS WHAT SEQUENCE THIS WORKER REACHED.
  //
  // Called AFTER the response has gone out, so nothing waits on it. The flush
  // is the one already scheduled — awaiting it here coalesces with it rather
  // than forcing a second — and only when it has committed is the sequence
  // read and announced.
  //
  // **COALESCED, because a burst of writes must not become a burst of
  // announcements.** One is in flight at a time; a write that lands while one
  // is running sets `again`, and the next round covers it. The sequence
  // announced is therefore always at least as new as every write that had
  // finished when it was read, which is the property the pool needs.
  // ---------------------------------------------------------------------
  // HOW MANY RESPONSES THIS WORKER HAS FINISHED. An announcement carries the
  // count taken BEFORE its flush started, which is exactly what that flush
  // covers: a request's writes all happen before its response finishes, so
  // everything counted here is in the store once the flush returns. The front
  // process clears tickets against this number rather than clearing whatever
  // the worker happens to owe — see receiveCommitted().
  let finishedCount = 0;
  let announcing = false;
  let again = false;
  function announceWhenCommitted() {
    if (announcing) {
      again = true;
      return;
    }
    announcing = true;
    // THE TICKETS THIS FLUSH WILL COVER, taken BEFORE it starts: a response
    // that finishes while the flush is in flight belongs to the NEXT
    // announcement, which the `again` coalescing above guarantees there will
    // be. They are named rather than counted for the reason
    // `request_pool.js`'s ticketFinished() gives: a count only works if both
    // processes complete the same responses in the same order, and they do
    // not.
    const covered = finishedTickets;
    finishedTickets = [];
    const through = finishedCount;
    // WHETHER THIS FLUSH ACTUALLY WROTE ANYTHING, read either side of it from a
    // local counter. It matters a great deal: the front process bumps the
    // read-your-write generation on every announcement, and a generation that
    // moves for a request that wrote nothing makes every OTHER worker look
    // stale and forces a barrier sync it has no work to do. With every request
    // announcing, that was almost every request — measured as 100ms per SCIM
    // create in the dispatch mode against 2.35ms in one process.
    //
    // The seq query that used to be here is gone with it: the front process
    // clears tickets by `through` and never read the sequence.
    const wroteBefore = persistence.changeRowsWritten();
    Promise.all([
      Promise.resolve().then(function () { return persistence.flush(); }),
      Promise.resolve().then(function () { return persistence.flushMinted(); })
    ]).then(function () {
      const wrote = persistence.changeRowsWritten() > wroteBefore;
      try {
        process.send({ committed: { wrote: wrote, through: through,
                                    tickets: covered } });
      } catch (e) {
        // The front process has gone; this worker is about to be told so.
      }
    }).catch(function (e) {
      // PUT THEM BACK. A flush that failed has covered nothing, and tickets
      // dropped here are tickets the front process waits the full barrier
      // bound for and then gives up on — a stale read reported as a timeout,
      // which is the most misleading pair of symptoms this mechanism can
      // produce.
      finishedTickets = covered.concat(finishedTickets);
      log.warn('request_worker: could not announce a commit: ' + e.message +
               '. A reader may be told it is current before this write is ' +
               'visible.');
    }).then(function () {
      announcing = false;
      if (again) {
        again = false;
        announceWhenCommitted();
      }
    });
  }

  server = http.createServer(function (req, res) {
    const encoded = req.headers[PEER_CERT_HEADER];
    if (encoded) {
      const cert = decodePeer(encoded);
      if (cert) {
        const authorized = req.headers[PEER_AUTHORIZED_HEADER] === 'yes';
        const shim = Object.create(req.socket);
        shim.authorized = authorized;
        shim.getPeerCertificate = function () { return cert; };
        // Both names, because this codebase reads both: `mtls.js` and
        // `xacml.js` use `req.socket`, and `ldap_server.js` and the call log
        // use `req.connection`.
        req.socket = shim;
        req.connection = shim;
      }
      // NOT passed on to the app either way. Nothing downstream reads them,
      // and a header that names a certificate is the kind of thing that ends
      // up echoed into a debug page.
      delete req.headers[PEER_CERT_HEADER];
      delete req.headers[PEER_AUTHORIZED_HEADER];
    }
    // THE DISPATCH TICKET: stashed on the request, then stripped for the same
    // reason the two above are — nothing downstream has any business seeing a
    // routing detail, and a header echoed onto a debug page is how one becomes
    // load-bearing. Stashed rather than read where it is used, because this
    // handler runs BEFORE the `request` listener below that hangs the finish
    // handlers, so reading the header from there would find it already gone.
    req.stsPoolTicket = Number(req.headers[POOL_TICKET_HEADER]) || 0;
    delete req.headers[POOL_TICKET_HEADER];
    // -------------------------------------------------------------------
    // A WRITE IS ANNOUNCED WHEN IT COMMITS, AND THE ANSWER DOES NOT WAIT FOR
    // IT (2026-09-07).
    //
    // `request_pool.js`'s proxy() bumps the read-your-write generation when a
    // write-method request finishes, on the premise that "the write is
    // committed to the change log by the time the answer goes out". That was
    // not true — `persistence.js` schedules its flush with `setTimeout(…, 0)`,
    // so it runs a tick after the response — and the first fix here was to
    // AWAIT the flush before answering.
    //
    // **THAT WAS CORRECT AND UNAFFORDABLE.** `persistence.flush()` computes the
    // directory diff by walking every entry in every realm, which is fine
    // debounced (a burst coalesces into one walk) and quadratic per request: a
    // 5,000-user SCIM load measured 50.9ms per create at the 500th and 75.4ms
    // at the 1,500th, against 3.3ms in a single process.
    //
    // So the wait moved to the side that was already waiting. This worker
    // answers immediately and, when its flush has actually committed, tells the
    // front process the sequence it reached. The pool holds the generation
    // until that arrives, so a reader still cannot be told it is current ahead
    // of the write — the barrier it already runs does the waiting, and no
    // writer blocks on a store.
    // -------------------------------------------------------------------
    // IN THE RESPONSE'S OWN CONTEXT. Everything the handler does — including a
    // sign-out reaching `ldap_server.js` several modules down — can find the
    // answer it is going to ride out on. See currentResponse.
    currentResponse.run(res, function () {
      app(req, res);
    });
  });
  // Every connection is from the front process on this machine, over a socket
  // in a directory only it and this worker know. Keep-alive is what makes the
  // proxy hop cheap, so it is left on and the timeout is generous.
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;

  server.on('request', function (req, res) {
    inFlight++;
    // ---------------------------------------------------------------------
    // THE ANNOUNCEMENT HANGS OFF THE RESPONSE'S TERMINAL STATES, NOT OFF
    // `res.end` (2026-09-07).
    //
    // It was a wrapper around `res.end`, and a response that is ABORTED or
    // closed by the peer never calls it — so the front process, whose own
    // `finish` handler fires either way, took a ticket for that request and
    // nothing ever cleared it. The symptom is exact and was measured as such:
    // `waiting for ticket 1188, confirmed through 1187`, one behind, until the
    // 2000ms bound gave up. 65 of those in one run, each one a stale read.
    //
    // `finish` and `close` between them cover every way a response can end, and
    // announceWhenCommitted() is idempotent-by-coalescing, so being called from
    // both is not a second announcement.
    // ---------------------------------------------------------------------
    let announcedFor = false;
    function announceOnce() {
      if (announcedFor || !announcesWrites(req)) {
        return;
      }
      announcedFor = true;
      // THE TICKET THE FRONT PROCESS DISPATCHED THIS UNDER, recorded in THIS
      // process's finish order — which is the order its flush covers them in,
      // and the only order that can be compared with anything.
      const ticket = Number(req.stsPoolTicket) || 0;
      if (ticket > 0) {
        finishedTickets.push(ticket);
      }
      announceWhenCommitted();
    }
    res.on('finish', function () {
      inFlight--;
      served++;
      finishedCount++;
      announceOnce();
    });
    res.on('close', function () {
      // A response the front process abandoned. Counted the same way, because
      // what this number is for is knowing whether a worker is busy.
      if (!res.writableEnded) {
        inFlight--;
      }
      // AND ANNOUNCED ANYWAY. The request may well have written before the peer
      // went away, and the front process has a ticket for it either way.
      announceOnce();
    });
  });

  startTimer = setTimeout(function () {
    report({ ready: false, error: 'the worker did not finish starting within ' +
             START_TIMEOUT_MS + 'ms — it brings its whole state up (the store, ' +
             'the keys, the minted rows and coordination) before it listens' });
  }, START_TIMEOUT_MS);
  startTimer.unref();

  server.on('error', function (err) {
    clearTimeout(startTimer);
    log.error('request_worker: the socket ' + socketPath + ' failed: ' +
              err.message);
    report({ ready: false, error: err.message });
  });

  // ---------------------------------------------------------------------
  // THE STATE COMES UP BEFORE THE SOCKET DOES, and this is what makes a
  // worker a member of the service rather than a second copy of it.
  //
  // `service_state.start()` is the same four steps `server.js` runs, in the
  // same order and from the same file: the store, the signing keys, what this
  // process minted, and COORDINATION. The last one is the one that matters
  // here — it is what makes another process's write arrive in this worker's
  // memory, and without it this worker holds a private directory and a private
  // session map that nothing else can see.
  //
  // **THE SOCKET IS BOUND AFTERWARDS AND NOT BEFORE**, because a worker that
  // accepted a request while its store was still loading would answer it out
  // of an empty directory — correctly shaped, and wrong. The front process
  // waits for the `ready` message rather than assuming a duration, so the cost
  // is paid where nobody is waiting.
  //
  // A FAILURE HERE IS REPORTED AND FATAL TO THIS WORKER rather than to the
  // service: the front process is told, logs which worker and why, and carries
  // on with the ones that did start — or with none, handling requests itself.
  // ---------------------------------------------------------------------
  serviceState.start().then(function (state) {
    log.info('request_worker ' + process.pid + ': state is up — persistence ' +
             (state.started && state.started.mode) + ', coordinating ' +
             !!(state.coordinating && state.coordinating.coordinating) + '.');
    bindSocket();
  }).catch(function (err) {
    log.error('request_worker ' + process.pid + ': the state could not be ' +
              'brought up: ' + err.message);
    report({ ready: false, error: 'the state could not be brought up: ' +
             err.message });
  });
  log.debug('Leaving start().');
}

function bindSocket() {
  log.debug('Entering bindSocket().');
  server.listen(socketPath, function () {
    clearTimeout(startTimer);
    // The socket is created with the process umask, which on a shared machine
    // could be world-writable. Narrowed to the owner: anything that can write
    // to this socket can make a request AS THE FRONT PROCESS, bypassing every
    // check the front process makes before it dispatches.
    try {
      fs.chmodSync(socketPath, 0o600);
    } catch (e) {
      // Reported rather than fatal: a filesystem that does not carry modes is
      // not a reason to refuse to serve, and the socket is in a directory that
      // is itself owner-only.
      log.warn('request_worker: could not narrow the mode on ' + socketPath +
               ', so it keeps the process umask: ' + e.message);
    }
    log.info('request_worker ' + process.pid + ': ready on ' + socketPath +
             '. It holds NO protocol port — every listener is the front ' +
             'process\'s.');
    report({ ready: true, pid: process.pid, socket: socketPath });
  });
  log.debug('Leaving bindSocket().');
}

// The forwarded certificate, back into the shape node's own
// `getPeerCertificate()` returns — which is what every reader here expects,
// including the `raw` Buffer that RFC 8705 thumbprints.
function decodePeer(encoded) {
  log.debug('Entering decodePeer().');
  let flat;
  try {
    flat = JSON.parse(Buffer.from(String(encoded), 'base64').toString('utf8'));
  } catch (e) {
    // A header this process could not read. Treated as no certificate rather
    // than as an error: the alternative is refusing a request over what is,
    // from the caller's point of view, something they never sent.
    log.warn('request_worker: a forwarded client certificate could not be ' +
             'read and is being treated as absent: ' + e.message);
    log.debug('Leaving decodePeer(). Unreadable.');
    return null;
  }
  Object.keys(flat).forEach(function (name) {
    const value = flat[name];
    if (value && typeof value === 'object' && typeof value.__buffer === 'string') {
      flat[name] = Buffer.from(value.__buffer, 'base64');
    }
  });
  log.debug('Leaving decodePeer().');
  return flat;
}

// One message to the front process. Wrapped because a worker whose channel has
// gone cannot do anything about it and must not die reporting that it cannot.
function report(message) {
  log.debug('Entering report().');
  try {
    if (process.send) {
      process.send(message);
    }
  } catch (e) {
    log.warn('request_worker: could not reach the front process: ' + e.message);
  }
  log.debug('Leaving report().');
}

// ---------------------------------------------------------------------------
// GOING AWAY. The front process closes the channel; this worker stops
// accepting, lets what it is holding finish, and unlinks its socket.
//
// The unlink matters more here than it would for a TCP port: a socket file that
// outlives its process is a path the next worker cannot bind, and `start()`
// above removes a stale one for exactly that reason. Both halves are kept —
// tidy on the way out, tolerant on the way in — because a worker that was
// KILLED never runs this at all.
// ---------------------------------------------------------------------------
function stop() {
  log.debug('Entering stop(). inFlight=' + inFlight);
  if (!server) {
    cleanup();
    process.exit(0);
    return;
  }
  server.close(function () {
    cleanup();
    log.info('request_worker ' + process.pid + ': served ' + served +
             ' request(s); exiting.');
    process.exit(0);
  });
  // `close()` waits for open keep-alive connections, and the front process
  // holds them open on purpose. They are ended so that a drain finishes in the
  // time the front process is willing to wait rather than in the keep-alive
  // timeout.
  if (typeof server.closeIdleConnections === 'function') {
    server.closeIdleConnections();
  }
  log.debug('Leaving stop().');
}

function cleanup() {
  try {
    fs.unlinkSync(socketPath);
  } catch (e) {
    // Already gone, which is the ordinary case when several things tidy up.
  }
}

// ---------------------------------------------------------------------------
// THE OPERATION TABLE: what a worker will do that is not an HTTP request.
//
// The front process owns six listener families and only one speaks HTTP. An
// LDAP search, a Kerberos AS-REQ and a gRPC call all have the same reason to
// leave that process as a `/scim/v2` POST does, and the transport they arrive
// on is not a reason to keep them there — so the front process keeps the socket
// and the framing, and hands over the OPERATION.
//
// **THE TABLE IS FILLED BY THE MODULE THAT OWNS THE OPERATION**, through
// `register()`, rather than being written out here. This file must not require
// `ldap_server.js`: it would be a route-order edge (rule 1) and, worse, it
// would make this module know about one protocol family when the whole point is
// that it knows about none. A family registers what it will answer to when it
// loads, exactly as a protocol module registers its routes.
//
// A handler may return a value or a promise; both are answered the same way.
// ---------------------------------------------------------------------------
const OPERATIONS = new Map();

function register(kind, fn) {
  if (typeof fn !== 'function') {
    throw new Error('request_worker: the "' + kind + '" operation needs a ' +
      'function.');
  }
  if (OPERATIONS.has(kind)) {
    // A SECOND registration is a bug rather than an override: two modules
    // answering to one kind means the answer depends on require order, which
    // is exactly the class of thing this repository writes rules to prevent.
    throw new Error('request_worker: the "' + kind + '" operation is already ' +
      'registered. Two answers to one kind would be decided by require order.');
  }
  OPERATIONS.set(kind, fn);
  log.debug('register(): worker ' + process.pid + ' answers "' + kind + '".');
}

// One operation, and its answer on the channel. A FAILED operation is a
// MESSAGE and not a crash, for the reason worker.js gives about its own jobs: a
// refusal is something the caller has to turn into a protocol error, and a
// worker that exited instead would turn every one of those into a restart plus
// a client waiting for ever on a raw socket.
function handleOperation(message) {
  log.debug('Entering handleOperation(). kind=' + message.kind);
  const fn = OPERATIONS.get(message.kind);
  if (!fn) {
    process.send({ operation: true, id: message.id, ok: false,
      error: 'this worker does not answer to the "' + message.kind + '" ' +
        'operation. It answers to: ' +
        (Array.from(OPERATIONS.keys()).join(', ') || '(nothing)') + '.',
      errorName: 'Error' });
    log.debug('Leaving handleOperation(). No such operation.');
    return;
  }
  let result;
  try {
    result = fn(message.args);
  } catch (e) {
    process.send({ operation: true, id: message.id, ok: false,
                   error: e.message, errorName: e.name || 'Error' });
    log.debug('Leaving handleOperation(). It threw.');
    return;
  }
  Promise.resolve(result).then(function (value) {
    process.send({ operation: true, id: message.id, ok: true, result: value });
  }, function (e) {
    process.send({ operation: true, id: message.id, ok: false,
                   error: e.message, errorName: e.name || 'Error' });
  });
  log.debug('Leaving handleOperation(). Running.');
}

// ---------------------------------------------------------------------------
// THE READ BARRIER, asked for by the front process before this worker serves a
// request that must see somebody else's write.
//
// It is the front process that knows a write happened — it proxied it — and
// this worker that knows whether it has caught up. So the front process asks
// and this answers; neither could decide it alone.
//
// It ALWAYS replies, including when it could not catch up, because the front
// process is holding a request open waiting for this and a silence would be a
// hung client rather than a slow one.
// ---------------------------------------------------------------------------
function handleSync(message) {
  log.debug('Entering handleSync(). id=' + message.id);
  const persistence = require('../persistence/persistence');
  persistence.syncNow().then(function (state) {
    process.send({ sync: true, id: message.id, ok: true,
                   applied: state.applied, caughtUp: state.caughtUp });
    log.debug('Leaving handleSync(). applied=' + state.applied);
  }, function (err) {
    // syncNow() resolves rather than rejects, so this is a defect here rather
    // than a store that is unwell. Answered anyway, for the reason above.
    log.error('request_worker: the read barrier threw: ' + err.message);
    process.send({ sync: true, id: message.id, ok: false,
                   error: err.message });
  });
}

process.on('message', function (message) {
  if (message && message.stop) {
    stop();
    return;
  }
  if (message && message.sync) {
    handleSync(message);
    return;
  }
  if (message && message.operation) {
    handleOperation(message);
  }
});

// The front process closing the channel is how a worker is told to go, exactly
// as it is for the computation pool — see worker.js.
process.on('disconnect', function () {
  log.debug('request_worker ' + process.pid + ': the channel closed.');
  stop();
});

// STATUS ON REQUEST, so the front process can report what its workers are
// doing without keeping a second tally that could disagree with this one.
process.on('SIGUSR2', function () {
  report({ status: true, pid: process.pid, inFlight: inFlight, served: served });
});

// ---------------------------------------------------------------------------
// A WORKER WAITS TO BE TOLD WHAT IT IS BEFORE IT LOADS ANYTHING.
//
// The socket path used to come in `process.argv` and the whole stack loaded at
// once. It cannot any more, because the front process also has to hand over the
// SERVER CERTIFICATE — every process in this service must present and pin the
// same one, or `/admin` and `/portal`, which dial back in as OpenID Connect
// relying parties, fail TLS against themselves. See tls_server.js.
//
// The material arrives over IPC rather than in the fork's environment on
// purpose: a private key in the environment is readable from
// `/proc/<pid>/environ` by anything running as this user, and an assignment
// made after start is not. It is put in `process.env` HERE, before the first
// require of the stack, because that is the one channel a module read at load
// time can be reached through without every module learning about the pool.
// ---------------------------------------------------------------------------
if (require.main === module) {
  process.on('message', function onStart(message) {
    if (!message || !message.begin) {
      return;
    }
    process.removeListener('message', onStart);
    if (message.tls && message.tls.certPem && message.tls.keyPem) {
      process.env.STS_TLS_SERVER_CERT_PEM = message.tls.certPem;
      process.env.STS_TLS_SERVER_KEY_PEM = message.tls.keyPem;
    }
    // -------------------------------------------------------------------
    // THE SIGNING KEYS, ON THE SAME CHANNEL AND FOR THE SAME REASON.
    //
    // Not through `process.env` like the certificate above: that trick works
    // because tls_server.js reads those two variables at load, and there is no
    // equivalent single read here — a realm's keys are made lazily, per realm,
    // for realms that do not exist yet. So the keystore is seeded directly and
    // the publisher is installed BEFORE `start()` requires the stack, because
    // the stack generates the default realm's keys on the way up and that
    // generation has to be able to reach the parent.
    //
    // `require` here rather than at the top of the file: nothing of the service
    // is loaded until this message arrives, which is this module's whole shape.
    // -------------------------------------------------------------------
    const keystore = require('./keystore');
    // THE KEY-ENCRYPTION KEY FIRST: `persistence_minted.js` reads
    // hasEphemeralKek() to decide whether it is on at all, and that decision is
    // made while the stack below loads.
    if (message.kek) {
      keystore.useEphemeralKek(message.kek);
    }
    // The OID4VCI request-encryption key, into the environment before the
    // stack is required — vc_issuer.js reads it at module load. Same channel
    // and same reason as the certificate above.
    if (message.vciRequestEncKeyPem) {
      process.env.STS_VCI_REQUEST_ENC_KEY_PEM = message.vciRequestEncKeyPem;
    }
    // The BBS pair, same channel and same reason — helpers.js reads it the
    // first time anything issues a Data Integrity proof.
    if (message.bbsKeyPair) {
      process.env.STS_BBS_KEYPAIR = message.bbsKeyPair;
    }
    (message.keys || []).forEach(function (one) {
      if (one && one.realm && one.blob) {
        keystore.adoptShared(one.realm, one.blob);
      }
    });
    keystore.setKeyPublisher(function (realmId, blob) {
      try {
        process.send({ publishKeys: { realm: realmId, blob: blob } });
      } catch (e) {
        // The parent has gone; this worker is about to be told so. Its keys
        // stay its own, which is correct for a process on its way out.
      }
    });
    // A LATE ARRIVAL, or a correction: another process generated this realm's
    // keys first and the parent is telling us which set the service uses. It
    // replaces whatever this process holds — see receivePublishedKeys().
    //
    // THE DIRECTORY'S CONNECTION LIST ARRIVES ON THIS SAME LISTENER, and is
    // handed straight to `ldap_server.js` — see installDirectoryMirror() for
    // what it is for and why this process cannot work it out for itself.
    process.on('message', function (later) {
      if (later && later.adoptKeys && later.adoptKeys.realm) {
        keystore.adoptShared(later.adoptKeys.realm, later.adoptKeys.blob);
      }
      if (later && later.ldapConnections) {
        require('../ldap/ldap_server').setConnectionMirror(later.ldapConnections);
      }
    });
    try {
      start(message.socket || '');
      // AFTER start(), which is what loads the protocol stack: requiring the
      // directory before it would put this module in the position server.js
      // holds and register every `/admin/ldap/*` page at a point of this
      // file's choosing. Here it is a cache hit. The seed is the snapshot the
      // front process took when it forked this worker; every later change
      // arrives on the listener above.
      installDirectoryMirror(message.ldapConnections || []);
    } catch (e) {
      report({ ready: false, error: e.message });
    }
  });
}

module.exports = {
  // THE HEADER THIS WORKER ASKS THE FRONT PROCESS ON, exported to be compared
  // with `request_pool.js`'s copy — see that file's export of the same name.
  LDAP_DROP_HEADER: LDAP_DROP_HEADER,
  // Installing the directory mirror, exported so that a test can put this
  // process in the state a worker is in without forking one.
  installDirectoryMirror: installDirectoryMirror,
  start: start,
  stop: stop,
  register: register,
  OPERATIONS: OPERATIONS
};
