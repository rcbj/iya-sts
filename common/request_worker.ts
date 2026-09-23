'use strict';
//
// File: request_worker.ts
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
//   * **A fake `req` is a second HTTP parser.** Chunked bodies, a
//     `content-type` with parameters, repeated headers, a `HEAD` that must send
//     no body, `Expect: 100-continue`, an upgrade — node already implements all
//     of it and there is no version of hand-rolling it that is not worse.
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
// `protocol_stack.ts` requires every module and registers every route (by
// `registerRoutes(app)` for the converted ones, at the require for the
// JavaScript ones) and starts nothing: the Kerberos KDC's two sockets, the LDAP
// directory's two, SPIFFE's gRPC sockets and the embedded debugger's listener
// are all bound from `listen()` in `server.js`, which a worker never calls (the
// two TLS endpoints were on that list until they were deleted on 2026-09-16).
// That separation predates this file by a fortnight and was made for a
// different reason — binding can fail, and a `require` that throws takes the
// process down where a route cannot — which is the ordinary way a good boundary
// pays twice.
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
// THE STATE PROBLEM IS REAL, AND THIS BLOCK NAMED A FILE THAT WAS NEVER
// WRITTEN (corrected 2026-09-12).
//
// Requiring the protocol stack gives this worker its OWN directory, its own
// session map, its own token registry and its own realm table — seeded at
// require time exactly as the front process's were. Two workers would then
// disagree about everything that is written by one request and read by
// another, which `worker.js`'s header lists at length: replay detection that
// stops detecting, an introspection 404 for a token that exists, a config
// change that lands on one worker of four.
//
// **IT SAID: *this file is the TRANSPORT and `state_channel.js` is the other
// half* — and there is no `state_channel.js`.** It was the name the other half
// was going to have, written down before it was built, and what was actually
// built is a different shape with a better argument behind it: a worker is
// ANOTHER PROCESS AGAINST THE STORE, so it runs `common/service_state.ts` —
// the same four startup steps `server.js` runs, from the same file — and the
// stores are reconciled by `persistence/persistence_replication.js`'s change
// log. `common/CLAUDE.md` (*A WORKER IS ANOTHER PROCESS AGAINST THE STORE*)
// argues why that was not a second mechanism.
//
// **SO THE CONDITION FOR DISPATCHING A PATH IS NOW STATED AND CHECKED RATHER
// THAN PENDING.** `request_pool.js`'s `start()` REFUSES to bring the pool up
// unless this process is coordinating, and the list it checks covers the
// operation kinds below as well as the paths. A store is reachable from a
// worker exactly when its changes are rows in `sts_changes`; the directory's
// are, which is why `ldap/ldap_server.js` was the first family to fill the
// operation table.

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-17) — and A PROCESS ENTRY POINT, NOT A
// MODULE THE COMPOSITION ROOT BUILDS.
//
//   * **`RequestWorker` is this process's own object.** It takes the logger,
//     the settings, a loader for `service_state` and the error-code table
//     through its constructor and holds what were module-level `let`s — the
//     server, the start timer, the socket path, the two counters and the
//     operation hook.
//     It is built ONCE, at the bottom of this file, the way `server.js` is the
//     front process's shell: a forked worker has exactly one of it, and
//     nothing else constructs one. So it has NO `InstanceSlot` and no line in
//     `common/protocol_stack.ts`, which this process loads rather than being
//     loaded by.
//   * **`CommitAnnouncer`** is the commit-announcement state `start()` used to
//     keep in closure variables, built at the same point `start()` built them.
//   * **`WorkerWire`** is a static utility class for the one pure helper, the
//     forwarded certificate's decoding.
//   * **The exports keep every name and shape**: `LDAP_DROP_HEADER`,
//     `PROTOCOL_WORKER_HEADER`, `installDirectoryMirror`, `start`, `stop`,
//     `register` and the `OPERATIONS` map itself.
//   * **THE LOAD ORDER.** `import x = require(...)` compiles to a `require`
//     in the same place, so the bare `config_file` call below still runs
//     before anything else is loaded; every require that was lazy (`./app`,
//     `./protocol_stack`, the store, the keystore, `../tls/tls_server`,
//     `../ldap/ldap_server`) is still a bare `require(...)` inside the method
//     that needs it — and `./service_state` has JOINED them (see below).
//     `request_pool.js` still forks `request_worker.js` — the compiled file,
//     which is the only one inside the image.
// ---------------------------------------------------------------------------

// FIRST, and for the reason server.js gives: this process was forked, so it
// inherited a CONFIG_FILE that may still be the relative path the operator
// typed, and a relative require resolves against the directory of the module
// doing the requiring. Idempotent, so the parent having done it costs nothing.
require('./config_file').resolveConfigFile();

// ---------------------------------------------------------------------------
// NOTHING THE COMPOSITION ROOT BUILDS IS LOADED BEFORE THE STACK (#50, R2),
// WHICH IS WHY `service_state` IS NOT REQUIRED HERE.
//
// At load this file requires `config_file`, `config` and `error_codes` and
// nothing else of the service; `start()` then requires `./app`,
// `./protocol_stack` and — only after the stack — `./service_state`, and
// runs `serviceState.start()`.
//
// **2026-09-17, THE FIRST FAILURE.** `service_state` was a require at the top
// of this file, and it requires converted modules the root builds
// (`cluster/cluster_secrets` among them). Loaded before the stack, each built
// its own default instance, the root's install was then refused, and every
// worker failed to start in dispatch mode — with memory and postgres modes
// green, because `server.js` requires nothing the root builds ahead of the
// stack.
//
// **THE FIRST FIX, AND WHY IT WAS REPLACED.** It called
// `instance_slot.deferToRoot()` here, before `service_state`. That flag is
// PROCESS-WIDE, and `tests/run.js` runs every in-process file in one
// process: `tests/ldap_logout.js` and others require this file, so every
// converted module loaded after them built and wired nothing, and
// `tests/spiffe_operations.js` failed with `no handler registered for the
// SPIFFE method` — only in the suite, never alone. A lazy require needs no
// flag: the stack is loaded first, and the root has built everything by the
// time `service_state` is asked for.
// ---------------------------------------------------------------------------

import http = require('http');
import fs = require('fs');
import bunyan = require('bunyan');
import config = require('./config');
// A LEAF with no requires: the failure codes on the log lines below.
import errorCodes = require('./error_codes');

let logLevelProblem = null;
const log = bunyan.createLogger({
  name: 'request_worker',
  level: (function () {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('No log level could be read, so info: ' +
            logLevelProblem.message);
}

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
import asyncHooks = require('async_hooks');
const currentResponse = new asyncHooks.AsyncLocalStorage<http.ServerResponse>();

// The header the front process acts on. Named here and in `request_pool.js`,
// and those two spellings must agree — the pool's copy carries the argument.
const LDAP_DROP_HEADER = 'x-sts-ldap-drop';

// The header the front process TELLS a hosted-surface worker on, at module
// scope rather than beside the three in start() so that it can be exported and
// compared with the pool's spelling, as LDAP_DROP_HEADER is.
const PROTOCOL_WORKER_HEADER = 'x-sts-pool-protocol-worker';

// An operation handler: a value or a promise, both answered the same way.
type OperationHandler = (args: any) => any;

// What a `RequestWorker` needs from the rest of the service, each named for
// the module that supplies it.
interface RequestWorkerDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  config: { value(key: string): any };
  // `common/service_state.ts`, required only when start() asks — after the
  // stack. See the block below the `config_file` call.
  loadServiceState(): { start(): Promise<any> };
  errorCodes: { tag(code: string): string };
}

// What a `CommitAnnouncer` needs: the store, and what the worker has.
interface CommitAnnouncerDeps {
  log: RequestWorkerDeps['log'];
  config: RequestWorkerDeps['config'];
  errorCodes: RequestWorkerDeps['errorCodes'];
  persistence: {
    flush(): any;
    flushMinted(): any;
    changeRowsWritten(): number;
  };
}

// ---------------------------------------------------------------------------
// THE SMALL PURE HELPER, AS A STATIC UTILITY CLASS (#50).
// ---------------------------------------------------------------------------
class WorkerWire {
  // The forwarded certificate, back into the shape node's own
  // `getPeerCertificate()` returns — which is what every reader here expects,
  // including the `raw` Buffer that RFC 8705 thumbprints.
  static decodePeer(encoded: unknown): Record<string, any> | null {
    log.debug('Entering WorkerWire.decodePeer().');
    let flat: Record<string, any>;
    try {
      flat = JSON.parse(
        Buffer.from(String(encoded), 'base64').toString('utf8'));
    } catch (e) {
      // A header this process could not read. Treated as no certificate
      // rather than as an error: the alternative is refusing a request over
      // what is, from the caller's point of view, something they never sent.
      log.warn(errorCodes.tag('STS-WORKER-0033') +
               'request_worker: a forwarded client certificate could not be ' +
               'read and is being treated as absent: ' + e.message);
      log.debug('Leaving WorkerWire.decodePeer(). Unreadable.');
      return null;
    }
    Object.keys(flat).forEach(function (name) {
      const value = flat[name];
      if (value && typeof value === 'object' &&
          typeof value.__buffer === 'string') {
        flat[name] = Buffer.from(value.__buffer, 'base64');
      }
    });
    log.debug('Leaving WorkerWire.decodePeer().');
    return flat;
  }
}

// ---------------------------------------------------------------------------
// THE COMMIT ANNOUNCEMENT'S STATE, which `start()` kept in closure variables
// until #50. Built by `start()` at the point it built them — after the stack
// and the store are loaded — so `announcedWritten` starts where it did.
// ---------------------------------------------------------------------------
class CommitAnnouncer {
  // The tickets of responses that have finished and whose flush has not been
  // announced yet. Bounded by the number of requests between two
  // announcements, and every request announces.
  private finishedTickets: number[] = [];
  // HOW MANY RESPONSES THIS WORKER HAS FINISHED. An announcement carries the
  // count taken BEFORE its flush started, which is exactly what that flush
  // covers: a request's writes all happen before its response finishes, so
  // everything counted here is in the store once the flush returns. The front
  // process clears tickets against this number rather than clearing whatever
  // the worker happens to owe — see receiveCommitted().
  private finishedCount = 0;
  private announcing = false;
  private again = false;
  // The committed change-row count the last announcement reported up to. See
  // announceWhenCommitted(). Starts at what the store had already committed
  // when this worker came up, because that was written before the pool forked
  // it and every other process has it.
  private announcedWritten: number;

  constructor(private readonly deps: CommitAnnouncerDeps) {
    deps.log.debug("Entering CommitAnnouncer.constructor().");
    this.announcedWritten = deps.persistence.changeRowsWritten();
    deps.log.debug("Leaving CommitAnnouncer.constructor().");
  }

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
  announcesWrites(req: http.IncomingMessage): boolean {
    const { log, config } = this.deps;
    log.debug("Entering CommitAnnouncer.announcesWrites().");
    log.debug("Leaving CommitAnnouncer.announcesWrites().");
    return !!config.value('workers.readYourWrite');
  }

  // One more finished response, counted whether or not it is announced.
  countFinished(): void {
    this.deps.log.debug("Entering CommitAnnouncer.countFinished().");
    this.finishedCount++;
    this.deps.log.debug("Leaving CommitAnnouncer.countFinished().");
  }

  // A finished response's ticket, remembered for the next announcement.
  noteTicket(ticket: number): void {
    this.deps.log.debug("Entering CommitAnnouncer.noteTicket().");
    if (ticket > 0) {
      this.finishedTickets.push(ticket);
    }
    this.deps.log.debug("Leaving CommitAnnouncer.noteTicket().");
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
  announceWhenCommitted(): void {
    const { log, persistence, errorCodes } = this.deps;
    log.debug("Entering CommitAnnouncer.announceWhenCommitted().");
    if (this.announcing) {
      this.again = true;
      log.debug("Leaving CommitAnnouncer.announceWhenCommitted().");
      return;
    }
    this.announcing = true;
    // THE TICKETS THIS FLUSH WILL COVER, taken BEFORE it starts: a response
    // that finishes while the flush is in flight belongs to the NEXT
    // announcement, which the `again` coalescing above guarantees there will
    // be. They are named rather than counted for the reason
    // `request_pool.js`'s ticketFinished() gives: a count only works if both
    // processes complete the same responses in the same order, and they do
    // not.
    const covered = this.finishedTickets;
    this.finishedTickets = [];
    const through = this.finishedCount;
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
    //
    // **SINCE THE LAST ANNOUNCEMENT, NOT SINCE THIS FLUSH STARTED
    // (2026-09-13).** Sampled either side of this flush, a commit made by a
    // DIFFERENT flush in this process — the scheduled one `persistence.js`
    // runs a tick after every write, which this one waits behind — could land
    // before the first sample and be announced by nobody: this flush then
    // found nothing new and reported `wrote: false`, and no other worker was
    // ever marked stale for rows it had not fetched. The count is of rows
    // COMMITTED (see `written` in persistence_postgres.js), so everything
    // above the last announced value is something no other process has been
    // told about.
    Promise.all([
      Promise.resolve().then(() => persistence.flush()),
      Promise.resolve().then(() => persistence.flushMinted())
    ]).then(() => {
      const committedNow = persistence.changeRowsWritten();
      const wrote = committedNow > this.announcedWritten;
      this.announcedWritten = Math.max(this.announcedWritten, committedNow);
      try {
        process.send({ committed: { wrote: wrote, through: through,
                                    tickets: covered } });
      } catch (e) {
        // The front process has gone; this worker is about to be told so.
        log.debug("Caught in a callback in " +
                  "CommitAnnouncer.announceWhenCommitted(): " +
                  ((e && e.message) || e));
      }
    }).catch((e) => {
      // PUT THEM BACK. A flush that failed has covered nothing, and tickets
      // dropped here are tickets the front process waits the full barrier
      // bound for and then gives up on — a stale read reported as a timeout,
      // which is the most misleading pair of symptoms this mechanism can
      // produce.
      this.finishedTickets = covered.concat(this.finishedTickets);
      log.warn(errorCodes.tag('STS-WORKER-0032') +
               'request_worker: could not announce a commit: ' + e.message +
               '. A reader may be told it is current before this write is ' +
               'visible.');
    }).then(() => {
      this.announcing = false;
      if (this.again) {
        this.again = false;
        this.announceWhenCommitted();
      }
    });
    log.debug("Leaving CommitAnnouncer.announceWhenCommitted().");
  }

  // ---------------------------------------------------------------------
  // AND THE SAME ANNOUNCEMENT FOR AN OPERATION, WHICH IS NOT A RESPONSE
  // (2026-09-12).
  //
  // Everything above this line counts HTTP responses, because until operations
  // were wired up an HTTP response was the only thing a worker finished. **An
  // LDAP add is a write with no response in this process** — the front process
  // holds the socket and writes the reply — so nothing here would have counted
  // it, its ticket would never have been announced, and the front process would
  // have waited the full barrier bound for it and then served stale.
  //
  // That is the exact wedge `request_pool.js`'s ticketAbandoned() documents,
  // reached by a different road: there the worker never ran the handler, here
  // the worker ran it and had no way to say so. So an operation takes the same
  // two steps a response does — count it, remember its ticket, announce when
  // the flush covers it — through the one function both paths call.
  //
  // It is reached through the worker's `announcer` field rather than a require
  // because this object holds this worker's store handle, and
  // `handleOperation()` answers whatever arrives once the `begin` message has
  // brought the service up. Filled by start(), which is after the store is open
  // and before any operation can arrive.
  // ---------------------------------------------------------------------
  noteOperationFinished(ticket: unknown): void {
    const { log, config } = this.deps;
    log.debug("Entering CommitAnnouncer.noteOperationFinished().");
    if (!config.value('workers.readYourWrite')) {
      log.debug("Leaving CommitAnnouncer.noteOperationFinished().");
      return;
    }
    this.finishedCount++;
    if (Number(ticket) > 0) {
      this.finishedTickets.push(Number(ticket));
    }
    this.announceWhenCommitted();
    log.debug("Leaving CommitAnnouncer.noteOperationFinished().");
  }
}

class RequestWorker {
  static readonly LDAP_DROP_HEADER = LDAP_DROP_HEADER;
  static readonly PROTOCOL_WORKER_HEADER = PROTOCOL_WORKER_HEADER;

  private server: http.Server | null = null;
  // An instance field because start() arms it and bindSocket() clears it, and
  // those became two functions when the state startup moved ahead of the
  // bind. It was a `const` inside start() for an hour after that split, so
  // every worker threw `ReferenceError: timer is not defined` from its own
  // `listening` handler — AFTER reporting that its state was up, which is why
  // the log read as three healthy workers and the pool counted none.
  private startTimer: NodeJS.Timeout | null = null;
  private socketPath = '';
  private inFlight = 0;
  private served = 0;
  // Filled by start(), which is where the store handle the announcement needs
  // lives. Null in a process that never started — and an operation cannot
  // reach one of those, because the front process only sends to a worker it
  // has had a ready report from.
  private announcer: CommitAnnouncer | null = null;

  // ---------------------------------------------------------------------------
  // THE OPERATION TABLE: what a worker will do that is not an HTTP request.
  //
  // The front process owns every listener family, and only the main port's HTTP
  // is dispatched as requests. An LDAP search, a Kerberos AS-REQ and a gRPC
  // call all have the same reason to leave that process as a `/scim/v2` POST
  // does, and the transport they arrive on is not a reason to keep them there
  // — so the front process keeps the socket and the framing, and hands over
  // the OPERATION.
  //
  // **THE TABLE IS FILLED BY THE MODULE THAT OWNS THE OPERATION**, through
  // `register()`, rather than being written out here. This file must not
  // require `ldap_server.js`: it would be a route-order edge (rule 1) and,
  // worse, it would make this module know about one protocol family when the
  // whole point is that it knows about none. A family registers what it will
  // answer to when it loads, exactly as a protocol module registered its
  // routes before #50's R1 (and a JavaScript one still does).
  //
  // A handler may return a value or a promise; both are answered the same way.
  // ---------------------------------------------------------------------------
  readonly operations = new Map<string, OperationHandler>();

  constructor(private readonly deps: RequestWorkerDeps) {
    deps.log.debug("Entering RequestWorker.constructor().");
    deps.log.debug("Leaving RequestWorker.constructor().");
  }

  // What the bottom of this file passes, from the real modules.
  static defaultDeps(): RequestWorkerDeps {
    log.debug("Entering RequestWorker.defaultDeps().");
    log.debug("Leaving RequestWorker.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      loadServiceState: function () {
        return require('./service_state');
      }
    };
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS WORKER KNOWS ABOUT DIRECTORY CONNECTIONS, AND WHAT IT ASKS FOR.
  //
  // Called once, after the protocol stack is loaded. The two halves are the two
  // ways a process with no listener is wrong about LDAP: it cannot SEE a bound
  // connection (so a sign-out finds nothing to end) and it cannot CLOSE one (so
  // saying it did would be a lie). `ldap_server.js` argues both at the block
  // above its boundConnections().
  // ---------------------------------------------------------------------------
  installDirectoryMirror(seed?: unknown[]): void {
    const { log } = this.deps;
    log.debug('Entering RequestWorker.installDirectoryMirror().');
    const ldapServer = require('../ldap/ldap_server');
    ldapServer.setConnectionMirror(seed || []);
    ldapServer.setRemoteDropper(function (key: unknown) {
      const res = currentResponse.getStore();
      if (!res) {
        // A sign-out that did not arrive over HTTP — nothing does this today,
        // and the honest answer is that there is no answer for it to ride out
        // on. Thrown rather than logged, because dropConnectionsFor() catches
        // it and says the connections may still be open, which is the truth.
        throw new Error('there is no response in flight in this worker to ' +
                        'carry the request on, so the front process cannot ' +
                        'be asked');
      }
      if (res.headersSent) {
        throw new Error('this request\'s headers have already gone to the ' +
                        'client, so the front process cannot be asked in time');
      }
      // APPENDED, because one sign-out can end more than one person's
      // connections — `/admin/logout` acts on a key that is not the caller's —
      // and because the header is the only channel. Percent-encoded: a key is
      // a username and a header is bytes, and a comma in one would otherwise
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
    log.debug('Leaving RequestWorker.installDirectoryMirror().');
  }

  // ---------------------------------------------------------------------------
  // Load the service and answer on the socket.
  //
  // The app is required AFTER the socket path is known but BEFORE the socket
  // is bound, so that a worker never accepts a request it is not yet able to
  // answer. Loading the stack is the expensive part of starting a worker — it
  // seeds a directory and generates a realm's keys — and the front process
  // waits for the `ready` message rather than assuming a duration.
  // ---------------------------------------------------------------------------
  start(path?: string): void {
    const { log, config, loadServiceState, errorCodes } = this.deps;
    log.debug('Entering RequestWorker.start(). socket=' + path);
    this.socketPath = String(path || '');
    if (!this.socketPath) {
      throw new Error('request_worker: no socket path was given. The front ' +
        'process passes one in the fork arguments; this file is not meant ' +
        'to be run by hand.');
    }
    // A socket left behind by a worker that was killed rather than drained.
    // Removed rather than treated as an error: the front process gave us this
    // path and nothing else may be listening on it.
    try {
      fs.unlinkSync(this.socketPath);
      log.debug('start(): removed a stale socket at ' + this.socketPath);
    } catch (e) {
      // ENOENT is the ordinary case — there was nothing there, which is what
      // we want. Anything else is reported when the bind fails, with a better
      // message than this one could give.
      log.debug("Caught in RequestWorker.start(): " +
                ((e && e.message) || e));
    }

    // THE WHOLE SERVICE, in the one order there is. See protocol_stack.ts.
    const app = require('./app');

    // -------------------------------------------------------------------------
    // THE FRONT PROCESS IS A TRUSTED PROXY, AND SAYING SO IS NOT OPTIONAL.
    //
    // A request reaches this worker over a unix socket, which is not TLS, so
    // express computes `req.protocol` as `http` and `req.secure` as false —
    // and it IGNORES the `x-forwarded-proto` the front process sends, because
    // by default express trusts no proxy at all.
    //
    // **WHAT THAT BREAKS IS EVERY ABSOLUTE URL THIS SERVICE BUILDS.** The
    // console's own sign-in was the first casualty: `/admin/tokens` redirected
    // to `http://localhost:8081/oauth2/authorize` on a service listening for
    // TLS, and the browser — or the suite — dialled plain HTTP at a TLS port
    // and got a dropped socket. The error is `UND_ERR_SOCKET` and it names
    // nothing; it took tracing every hop of a console sign-in to see that one
    // redirect had the wrong scheme. The issuer in a token, a SAML endpoint in
    // metadata and every `redirect_uri` check are the same computation.
    //
    // Trusting the proxy here is safe for a reason that is structural rather
    // than conventional: this server listens on a UNIX SOCKET in an owner-only
    // directory, so the only thing that can reach it is the front process,
    // which sets these headers itself after stripping whatever the client
    // sent. If this worker ever gains a second listener, this line has to be
    // revisited with it.
    // -------------------------------------------------------------------------
    app.set('trust proxy', true);

    require('./protocol_stack');

    // The four startup steps, shared with server.js — the store, the keys, the
    // minted rows and COORDINATION. See service_state.ts. Required HERE, after
    // the stack, and not at the top of this file: see the block below the
    // `config_file` call for the failure that put it here.
    const serviceState = loadServiceState();

    // -------------------------------------------------------------------------
    // THE CLIENT CERTIFICATE, PUT BACK ON THE REQUEST BEFORE THE APP SEES IT.
    //
    // A proxied request arrives on a unix socket, which has no peer
    // certificate, and three surfaces here decide on one: RFC 8705's token
    // binding, SCIM's certificate scheme, and `/xacml/pep/*`, which admits a
    // remote PEP only on a certificate this service VERIFIED. The front
    // process forwards what it saw; this puts it back where `mtls.js`,
    // `scim_auth.js` and `xacml.js` look for it, so not one of them needed
    // changing.
    //
    // **A PER-REQUEST OBJECT AND NOT A MUTATED SOCKET.** The obvious version
    // assigns `getPeerCertificate` onto the socket itself, and it is wrong for
    // a reason that would be found late and rarely: this server keeps
    // connections ALIVE, so one socket carries many requests, and a
    // certificate written onto it would still be there for the next request
    // on the same connection — handing request B the certificate request A
    // presented. So the shim is made per request with
    // `Object.create(socket)`, which shadows the two members and delegates
    // everything else — `remoteAddress`, `encrypted` and the rest — to the
    // real socket.
    //
    // **AND ONLY WHEN A CERTIFICATE WAS FORWARDED.** With no header the
    // request is left completely alone, so the shim exists only on the
    // requests that need it and the ordinary path is untouched.
    //
    // The headers are TRUSTED HERE, and that is safe for exactly one reason:
    // this server listens on a unix socket in an owner-only directory, so the
    // only thing that can reach it is the front process — which strips these
    // headers off whatever the client sent before writing the real ones. If
    // this server ever gains a second listener, that reasoning goes with it.
    // -------------------------------------------------------------------------
    const PEER_CERT_HEADER = 'x-sts-peer-certificate';
    // The ticket the front process dispatched this request under. Read once,
    // off the request, and stripped before the app sees it — see below.
    const POOL_TICKET_HEADER = 'x-sts-pool-ticket';
    const PEER_AUTHORIZED_HEADER = 'x-sts-peer-authorized';
    // The JA4 reader (#62 P0), required here for persistence's reason below:
    // by this line the stack is loaded and it is a cache hit.
    const clientHello = require('../tls/client_hello');

    // The store, for the commit-before-answer block in the handler below.
    // Required HERE rather than at the top of this file for the reason every
    // other require in `start()` is: nothing of the service is loaded until
    // the `begin` message arrives, which is this module's whole shape. By this
    // line the stack is loaded and it is a cache hit.
    const persistence = require('../persistence/persistence');

    // The announcement's state — the tickets, the finished count and the last
    // committed count announced — built here, where it always was, so the
    // count it starts from is read after the store is loaded. See
    // CommitAnnouncer.
    const announcer = new CommitAnnouncer({ log: log, config: config,
                                            errorCodes: errorCodes,
                                            persistence: persistence });
    // AND THE OPERATION HOOK, FILLED HERE: after the store is open and before
    // any operation can arrive. See CommitAnnouncer.noteOperationFinished().
    this.announcer = announcer;

    const server = http.createServer(function (req, res) {
      // THE CLIENT'S JA4 FINGERPRINT (#62 P0), forwarded beside the
      // certificate and put on the REQUEST, for the keep-alive reason above.
      // Stripped whether or not it is well formed; see
      // tls/client_hello.ts's adoptForwarded().
      clientHello.adoptForwarded(req);
      const encoded = req.headers[PEER_CERT_HEADER];
      if (encoded) {
        const cert = WorkerWire.decodePeer(encoded);
        if (cert) {
          const authorized = req.headers[PEER_AUTHORIZED_HEADER] === 'yes';
          const shim = Object.create(req.socket);
          shim.authorized = authorized;
          shim.getPeerCertificate = function () {
            log.debug("Entering getPeerCertificate().");
            log.debug("Leaving getPeerCertificate().");
            return cert;
          };
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
      // reason the two above are — nothing downstream has any business seeing
      // a routing detail, and a header echoed onto a debug page is how one
      // becomes load-bearing. Stashed rather than read where it is used,
      // because this handler runs BEFORE the `request` listener below that
      // hangs the finish handlers, so reading the header from there would find
      // it already gone.
      req.stsPoolTicket = Number(req.headers[POOL_TICKET_HEADER]) || 0;
      delete req.headers[POOL_TICKET_HEADER];
      // AND WHICH PROTOCOL WORKER THIS BROWSER IS HELD BY, which the front
      // process sends a hosted-surface worker only: `common/oidc_rp.ts`'s back
      // channel reads it off the request to reach the worker holding the code.
      // Stashed and stripped for the ticket's reasons. See `request_pool.js`'s
      // PROTOCOL_WORKER_HEADER, whose spelling this must match.
      req.stsProtocolWorker =
        Number(req.headers[PROTOCOL_WORKER_HEADER]) || 0;
      delete req.headers[PROTOCOL_WORKER_HEADER];
      // -------------------------------------------------------------------
      // A WRITE IS ANNOUNCED WHEN IT COMMITS, AND THE ANSWER DOES NOT WAIT FOR
      // IT (2026-09-07).
      //
      // `request_pool.js`'s proxy() bumps the read-your-write generation when a
      // write-method request finishes, on the premise that "the write is
      // committed to the change log by the time the answer goes out". That was
      // not true — `persistence.js` schedules its flush with
      // `setTimeout(…, 0)`, so it runs a tick after the response — and the
      // first fix here was to AWAIT the flush before answering.
      //
      // **THAT WAS CORRECT AND UNAFFORDABLE.** `persistence.flush()` computes
      // the directory diff by walking every entry in every realm, which is fine
      // debounced (a burst coalesces into one walk) and quadratic per request:
      // a 5,000-user SCIM load measured 50.9ms per create at the 500th and
      // 75.4ms at the 1,500th, against 3.3ms in a single process.
      //
      // So the wait moved to the side that was already waiting. This worker
      // answers immediately and, when its flush has actually committed, tells
      // the front process the sequence it reached. The pool holds the
      // generation until that arrives, so a reader still cannot be told it is
      // current ahead of the write — the barrier it already runs does the
      // waiting, and no writer blocks on a store.
      // -------------------------------------------------------------------
      // IN THE RESPONSE'S OWN CONTEXT. Everything the handler does — including
      // a sign-out reaching `ldap_server.js` several modules down — can find
      // the answer it is going to ride out on. See currentResponse.
      currentResponse.run(res, function () {
        app(req, res);
      });
    });
    this.server = server;
    // Every connection is from the front process on this machine, over a
    // socket in a directory only it and this worker know. Keep-alive is what
    // makes the proxy hop cheap, so it is left on and the timeout is generous.
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 70000;

    server.on('request', (req, res) => {
      this.inFlight++;
      // ---------------------------------------------------------------------
      // THE ANNOUNCEMENT HANGS OFF THE RESPONSE'S TERMINAL STATES, NOT OFF
      // `res.end` (2026-09-07).
      //
      // It was a wrapper around `res.end`, and a response that is ABORTED or
      // closed by the peer never calls it — so the front process, whose own
      // `finish` handler fires either way, took a ticket for that request and
      // nothing ever cleared it. The symptom is exact and was measured as
      // such: `waiting for ticket 1188, confirmed through 1187`, one behind,
      // until the 2000ms bound gave up. 65 of those in one run, each one a
      // stale read.
      //
      // `finish` and `close` between them cover every way a response can end,
      // and announceWhenCommitted() is idempotent-by-coalescing, so being
      // called from both is not a second announcement.
      // ---------------------------------------------------------------------
      let announcedFor = false;
      function announceOnce() {
        log.debug("Entering announceOnce().");
        if (announcedFor || !announcer.announcesWrites(req)) {
          log.debug("Leaving announceOnce().");
          return;
        }
        announcedFor = true;
        // THE TICKET THE FRONT PROCESS DISPATCHED THIS UNDER, recorded in THIS
        // process's finish order — which is the order its flush covers them
        // in, and the only order that can be compared with anything.
        const ticket = Number(req.stsPoolTicket) || 0;
        announcer.noteTicket(ticket);
        announcer.announceWhenCommitted();
        log.debug("Leaving announceOnce().");
      }
      res.on('finish', () => {
        this.inFlight--;
        this.served++;
        announcer.countFinished();
        announceOnce();
      });
      res.on('close', () => {
        // A response the front process abandoned. Counted the same way,
        // because what this number is for is knowing whether a worker is busy.
        if (!res.writableEnded) {
          this.inFlight--;
        }
        // AND ANNOUNCED ANYWAY. The request may well have written before the
        // peer went away, and the front process has a ticket for it either
        // way.
        announceOnce();
      });
    });

    this.startTimer = setTimeout(() => {
      this.report({ ready: false, error: 'the worker did not finish ' +
                    'starting within ' + START_TIMEOUT_MS + 'ms — it brings ' +
                    'its whole state up (the store, the keys, the minted ' +
                    'rows and coordination) before it listens' });
    }, START_TIMEOUT_MS);
    this.startTimer.unref();

    server.on('error', (err) => {
      clearTimeout(this.startTimer);
      log.error(errorCodes.tag('STS-WORKER-0018') +
                'request_worker: the socket ' + this.socketPath + ' failed: ' +
                err.message);
      this.report({ ready: false, error: err.message });
    });

    // ---------------------------------------------------------------------
    // THE STATE COMES UP BEFORE THE SOCKET DOES, and this is what makes a
    // worker a member of the service rather than a second copy of it.
    //
    // `service_state.start()` is the same four steps `server.js` runs, in the
    // same order and from the same file: the store, the signing keys, what
    // this process minted, and COORDINATION. The last one is the one that
    // matters here — it is what makes another process's write arrive in this
    // worker's memory, and without it this worker holds a private directory
    // and a private session map that nothing else can see.
    //
    // **THE SOCKET IS BOUND AFTERWARDS AND NOT BEFORE**, because a worker that
    // accepted a request while its store was still loading would answer it
    // out of an empty directory — correctly shaped, and wrong. The front
    // process waits for the `ready` message rather than assuming a duration,
    // so the cost is paid where nobody is waiting.
    //
    // A FAILURE HERE IS REPORTED AND FATAL TO THIS WORKER rather than to the
    // service: the front process is told, logs which worker and why, and
    // carries on with the ones that did start — or with none, handling
    // requests itself.
    // ---------------------------------------------------------------------
    serviceState.start().then((state) => {
      log.info('request_worker ' + process.pid + ': state is up — ' +
               'persistence ' + (state.started && state.started.mode) +
               ', coordinating ' +
               !!(state.coordinating && state.coordinating.coordinating) +
               '.');
      // THE SCHEDULER, IN PER-PROCESS MODE (#49): this worker runs the jobs
      // that clean what only it holds, and never a cluster job — those run
      // on the scheduler's leader, which is a front process. Required here
      // and not at the top, for `service_state`'s reason above: nothing of
      // the stack is loaded before the stack is.
      require('../cluster/scheduler').start('per-process');
      this.bindSocket();
    }).catch((err) => {
      log.error(errorCodes.tag('STS-WORKER-0019') +
                'request_worker ' + process.pid + ': the state could not be ' +
                'brought up: ' + err.message);
      this.report({ ready: false, error: 'the state could not be brought ' +
                    'up: ' + err.message });
    });
    log.debug('Leaving RequestWorker.start().');
  }

  private bindSocket(): void {
    const { log, errorCodes } = this.deps;
    log.debug('Entering RequestWorker.bindSocket().');
    // ---------------------------------------------------------------------
    // **AN EXPLICIT BACKLOG, AND IT IS THE FIX FOR A MEASURED FAILURE
    // (2026-09-12).** `listen(path, cb)` takes node's default of 511 pending
    // connections. **EAGAIN from an AF_UNIX `connect()` is that queue being
    // full** — and the front process opens a connection per dispatched
    // request, so on a machine running the whole suite at once the queue is
    // shared by every job there is.
    //
    // It reached the suite as `sts_directory_bulk_load_scim`: `4999 of 5000
    // SCIM creates were accepted`, the one refusal `502 … connect EAGAIN
    // /tmp/sts-workers-*/w2.sock`. **Not a rejected write — a request that
    // never reached a worker**, answered with a sentence telling the caller it
    // could simply be made again, which is a thing this service could have
    // done for itself if the body were replayable and is not.
    //
    // **THE FRONT PROCESS'S BOUND IS NOT THIS**, and the two must not be
    // confused: `workers.maxSockets` caps how many connections it may have
    // OPEN at once, and that job issues its five thousand creates one at a
    // time, so no per-worker cap was ever close to being reached by it. This
    // is the queue those connections land in.
    //
    // 1024 rather than a setting: this is the depth of a queue inside one
    // machine between two processes of one service, and there is nothing an
    // operator could usefully know that would make a different number right.
    // ---------------------------------------------------------------------
    this.server.listen({ path: this.socketPath, backlog: 1024 }, () => {
      clearTimeout(this.startTimer);
      // The socket is created with the process umask, which on a shared
      // machine could be world-writable. Narrowed to the owner: anything that
      // can write to this socket can make a request AS THE FRONT PROCESS,
      // bypassing every check the front process makes before it dispatches.
      try {
        fs.chmodSync(this.socketPath, 0o600);
      } catch (e) {
        // Reported rather than fatal: a filesystem that does not carry modes
        // is not a reason to refuse to serve, and the socket is in a directory
        // that is itself owner-only.
        log.warn(errorCodes.tag('STS-WORKER-0010') +
                 'request_worker: could not narrow the mode on ' +
                 this.socketPath + ', so it keeps the process umask: ' +
                 e.message);
      }
      log.info('request_worker ' + process.pid + ': ready on ' +
               this.socketPath + '. It holds NO protocol port — every ' +
               'listener is the front process\'s.');
      this.report({ ready: true, pid: process.pid, socket: this.socketPath });
    });
    log.debug('Leaving RequestWorker.bindSocket().');
  }

  // One message to the front process. Wrapped because a worker whose channel
  // has gone cannot do anything about it and must not die reporting that it
  // cannot.
  report(message: Record<string, unknown>): void {
    const { log, errorCodes } = this.deps;
    log.debug('Entering RequestWorker.report().');
    try {
      if (process.send) {
        process.send(message);
      }
    } catch (e) {
      log.warn(errorCodes.tag('STS-WORKER-0034') +
               'request_worker: could not reach the front process: ' +
               e.message);
    }
    log.debug('Leaving RequestWorker.report().');
  }

  // ---------------------------------------------------------------------------
  // GOING AWAY. The front process closes the channel; this worker stops
  // accepting, lets what it is holding finish, and unlinks its socket.
  //
  // The unlink matters more here than it would for a TCP port: a socket file
  // that outlives its process is a path the next worker cannot bind, and
  // `start()` above removes a stale one for exactly that reason. Both halves
  // are kept — tidy on the way out, tolerant on the way in — because a worker
  // that was KILLED never runs this at all.
  // ---------------------------------------------------------------------------
  stop(): void {
    const { log } = this.deps;
    log.debug('Entering RequestWorker.stop(). inFlight=' + this.inFlight);
    if (!this.server) {
      this.cleanup();
      process.exit(0);
      log.debug("Leaving RequestWorker.stop().");
      return;
    }
    this.server.close(() => {
      this.cleanup();
      log.info('request_worker ' + process.pid + ': served ' + this.served +
               ' request(s); exiting.');
      process.exit(0);
    });
    // `close()` waits for open keep-alive connections, and the front process
    // holds them open on purpose. They are ended so that a drain finishes in
    // the time the front process is willing to wait rather than in the
    // keep-alive timeout.
    if (typeof this.server.closeIdleConnections === 'function') {
      this.server.closeIdleConnections();
    }
    log.debug('Leaving RequestWorker.stop().');
  }

  private cleanup(): void {
    const { log } = this.deps;
    log.debug("Entering RequestWorker.cleanup().");
    try {
      fs.unlinkSync(this.socketPath);
    } catch (e) {
      // Already gone, which is the ordinary case when several things tidy up.
      log.debug("Caught in RequestWorker.cleanup(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving RequestWorker.cleanup().");
  }

  register(kind: string, fn: OperationHandler): void {
    const { log } = this.deps;
    log.debug("Entering RequestWorker.register().");
    if (typeof fn !== 'function') {
      throw new Error('request_worker: the "' + kind + '" operation needs a ' +
        'function.');
    }
    if (this.operations.has(kind)) {
      // A SECOND registration is a bug rather than an override: two modules
      // answering to one kind means the answer depends on require order,
      // which is exactly the class of thing this repository writes rules to
      // prevent.
      throw new Error('request_worker: the "' + kind + '" operation is ' +
        'already registered. Two answers to one kind would be decided by ' +
        'require order.');
    }
    this.operations.set(kind, fn);
    log.debug('register(): worker ' + process.pid + ' answers "' + kind +
              '".');
    log.debug("Leaving RequestWorker.register().");
  }

  // The announcement, made ONCE per operation however it ended. **Including
  // when it ended in a refusal**, and that is not tidiness: a refused LDAP add
  // is a handler that ran, and a handler that ran may have written an audit
  // row — the refusal is exactly what that row records. Announcing only on
  // success would leave the ticket for a refused operation outstanding for
  // ever, which is the wedge again.
  private operationFinished(ticket: number): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering RequestWorker.operationFinished().");
    if (!this.announcer) {
      log.debug("Leaving RequestWorker.operationFinished().");
      return;
    }
    try {
      this.announcer.noteOperationFinished(ticket);
    } catch (e) {
      // Bookkeeping must not fail the operation the client is waiting on —
      // the same guard publishConnections() makes on the other side of this
      // seam.
      log.warn(errorCodes.tag('STS-WORKER-0035') +
               'request_worker: an operation could not be announced: ' +
               e.message + '. A reader may wait the full barrier bound for ' +
               'it.');
    }
    log.debug("Leaving RequestWorker.operationFinished().");
  }

  // One operation, and its answer on the channel. A FAILED operation is a
  // MESSAGE and not a crash, for the reason worker.js gives about its own
  // jobs: a refusal is something the caller has to turn into a protocol
  // error, and a worker that exited instead would turn every one of those
  // into a restart plus a client waiting for ever on a raw socket.
  private handleOperation(message: any): void {
    const { log } = this.deps;
    log.debug('Entering RequestWorker.handleOperation(). kind=' +
              message.kind);
    const ticket = Number(message.ticket) || 0;
    const fn = this.operations.get(message.kind);
    if (!fn) {
      // NOT ANNOUNCED, and this is the one path that must not be: no handler
      // ran, so nothing was written, and the front process releases this
      // ticket rather than arming it — exactly as proxy() does for a request
      // a worker never answered. Announcing here would arm a ticket for a
      // flush that covers nothing.
      process.send({ operation: true, id: message.id, ok: false, ran: false,
        error: 'this worker does not answer to the "' + message.kind + '" ' +
          'operation. It answers to: ' +
          (Array.from(this.operations.keys()).join(', ') || '(nothing)') +
          '.',
        errorName: 'Error' });
      log.debug('Leaving RequestWorker.handleOperation(). No such ' +
                'operation.');
      return;
    }
    let result;
    try {
      result = fn(message.args);
    } catch (e) {
      // It RAN, so it is announced: a handler that threw part way through may
      // still have written.
      this.operationFinished(ticket);
      process.send({ operation: true, id: message.id, ok: false, ran: true,
                     error: e.message, errorName: e.name || 'Error' });
      log.debug('Leaving RequestWorker.handleOperation(). It threw.');
      return;
    }
    Promise.resolve(result).then((value) => {
      this.operationFinished(ticket);
      process.send({ operation: true, id: message.id, ok: true, ran: true,
                     result: value });
    }, (e) => {
      this.operationFinished(ticket);
      process.send({ operation: true, id: message.id, ok: false, ran: true,
                     error: e.message, errorName: e.name || 'Error' });
    });
    log.debug('Leaving RequestWorker.handleOperation(). Running.');
  }

  // ---------------------------------------------------------------------------
  // THE READ BARRIER, asked for by the front process before this worker serves
  // a request that must see somebody else's write.
  //
  // It is the front process that knows a write happened — it proxied it — and
  // this worker that knows whether it has caught up. So the front process asks
  // and this answers; neither could decide it alone.
  //
  // It ALWAYS replies, including when it could not catch up, because the front
  // process is holding a request open waiting for this and a silence would be
  // a hung client rather than a slow one.
  // ---------------------------------------------------------------------------
  private handleSync(message: any): void {
    const { log, errorCodes } = this.deps;
    log.debug('Entering RequestWorker.handleSync(). id=' + message.id);
    const persistence = require('../persistence/persistence');
    persistence.syncNow().then(function (state: any) {
      process.send({ sync: true, id: message.id, ok: true,
                     applied: state.applied, caughtUp: state.caughtUp });
      log.debug('Leaving RequestWorker.handleSync(). applied=' +
                state.applied);
    }, function (err: any) {
      // syncNow() resolves rather than rejects, so this is a defect here
      // rather than a store that is unwell. Answered anyway, for the reason
      // above.
      log.error(errorCodes.tag('STS-WORKER-0036') +
                'request_worker: the read barrier threw: ' + err.message);
      process.send({ sync: true, id: message.id, ok: false,
                     error: err.message });
    });
    log.debug("Leaving RequestWorker.handleSync().");
  }

  // The three process-level listeners every loader of this module installs,
  // as it always did at load: the channel's stop / sync / operation messages,
  // the channel closing, and the status signal.
  listen(): void {
    const { log } = this.deps;
    log.debug("Entering RequestWorker.listen().");
    process.on('message', (message: any) => {
      if (message && message.stop) {
        this.stop();
        return;
      }
      if (message && message.sync) {
        this.handleSync(message);
        return;
      }
      if (message && message.operation) {
        this.handleOperation(message);
      }
    });

    // The front process closing the channel is how a worker is told to go,
    // exactly as it is for the computation pool — see worker.js.
    process.on('disconnect', () => {
      log.debug('request_worker ' + process.pid + ': the channel closed.');
      this.stop();
    });

    // STATUS ON REQUEST, so the front process can report what its workers are
    // doing without keeping a second tally that could disagree with this one.
    process.on('SIGUSR2', () => {
      this.report({ status: true, pid: process.pid, inFlight: this.inFlight,
                    served: this.served });
    });
    log.debug("Leaving RequestWorker.listen().");
  }

  // ---------------------------------------------------------------------------
  // A WORKER WAITS TO BE TOLD WHAT IT IS BEFORE IT LOADS ANYTHING.
  //
  // The socket path used to come in `process.argv` and the whole stack loaded
  // at once. It cannot any more, because the front process also has to hand
  // over the SERVER CERTIFICATE — every process in this service must present
  // and pin the same one, or `/admin` and `/portal`, which dial back in as
  // OpenID Connect relying parties, fail TLS against themselves. See
  // tls_server.js.
  //
  // The material arrives over IPC rather than in the fork's environment on
  // purpose: a private key in the environment is readable from
  // `/proc/<pid>/environ` by anything running as this user, and an assignment
  // made after start is not. It is put in `process.env` HERE, before the first
  // require of the stack, because that is the one channel a module read at
  // load time can be reached through without every module learning about the
  // pool.
  // ---------------------------------------------------------------------------
  waitForBegin(): void {
    const { log } = this.deps;
    log.debug("Entering RequestWorker.waitForBegin().");
    process.on('message', this.onStart);
    log.debug("Leaving RequestWorker.waitForBegin().");
  }

  // A PROPERTY rather than a method, so that the listener removed below is the
  // very function that was added.
  private readonly onStart = (message: any): void => {
    const { log } = this.deps;
    log.debug("Entering RequestWorker.onStart().");
    if (!message || !message.begin) {
      log.debug("Leaving RequestWorker.onStart().");
      return;
    }
    process.removeListener('message', this.onStart);
    this.begin(message);
    log.debug("Leaving RequestWorker.onStart().");
  };

  private begin(message: any): void {
    const { log } = this.deps;
    log.debug("Entering RequestWorker.begin().");
    if (message.tls && message.tls.certPem && message.tls.keyPem) {
      process.env.STS_TLS_SERVER_CERT_PEM = message.tls.certPem;
      process.env.STS_TLS_SERVER_KEY_PEM = message.tls.keyPem;
      // THE CHAIN AND THE ANCHOR (2026-09-11). **PUBLIC MATERIAL**, so unlike
      // the key above there is nothing lost by their being readable in
      // `/proc/<pid>/environ` — a chain travels in every TLS handshake and an
      // anchor is published at `GET /tls/server-certificate`. They are here
      // because a worker that has the leaf alone builds no path and pins a
      // Root of its own making; see tls/tls_server.js's handedInCertificate().
      if (message.tls.chainPem && message.tls.chainPem.length) {
        // **CONCATENATED, NOT JOINED ON A SEPARATOR.** The first version used
        // a NUL between them, on the reasoning that a PEM contains newlines
        // and so a newline could not delimit one. NUL is the one byte an
        // environment variable cannot carry — it is a C string, so the value
        // is TRUNCATED at the first one — and the worker got the Issuing CA
        // and silently lost the Intermediate. It reported `1 chain
        // certificate(s)` where there were two, which is the only reason it
        // was noticed.
        //
        // Concatenated PEMs are self-delimiting: every certificate ends with
        // `-----END CERTIFICATE-----`, which is how `/tls/server-certificate`
        // already publishes a bundle and how every reader in this repository
        // already splits one. There was never a separator to choose.
        process.env.STS_TLS_SERVER_CHAIN_PEM = message.tls.chainPem.join('');
      }
      if (message.tls.trustAnchorPem) {
        process.env.STS_TLS_SERVER_ANCHOR_PEM = message.tls.trustAnchorPem;
      }
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
    // (The OID4VCI request-encryption key used to arrive here, into the
    // environment. It is a member of every realm's key set since 2026-09-12,
    // so it arrives in `message.keys` below with the rest of each set.)
    // The BBS pair used to arrive here too; it is a member of every realm's
    // key set since 2026-09-22 (#49 P5), so it arrives in `message.keys`.
    (message.keys || []).forEach(function (one: any) {
      if (one && one.realm && one.blob) {
        keystore.adoptShared(one.realm, one.blob);
      }
    });
    // THE CERTIFICATE AUTHORITIES, ON THE SAME CHANNEL AND FOR THE SAME
    // REASON. A hierarchy is built by an operator pressing a button on ONE
    // worker; without this a client assertion signed by a certificate that
    // worker issued would fail to chain on any of the others, which is the
    // shape of the signing-key defect keystore.js's shared-key block records.
    (message.pki || []).forEach(function (one: any) {
      if (one && one.realm) {
        keystore.adoptPki(one.realm, one.chain);
      }
    });
    keystore.setKeyPublisher(function (realmId: string, blob: unknown,
                                       options: any) {
      try {
        // `confirmed` (#46): the set is the store's answer, not this
        // process's offer — see request_pool.js's receivePublishedKeys().
        process.send({ publishKeys: { realm: realmId, blob: blob,
                                      confirmed: !!(options &&
                                                    options.confirmed) } });
      } catch (e) {
        // The parent has gone; this worker is about to be told so. Its keys
        // stay its own, which is correct for a process on its way out.
        log.debug("Caught in a callback in RequestWorker.begin(): " +
                  ((e && e.message) || e));
      }
    });
    keystore.setPkiPublisher(function (realmId: string, chain: unknown) {
      try {
        process.send({ publishPki: { realm: realmId, chain: chain || null } });
      } catch (e) {
        // Same case, same answer: the parent has gone and this worker is on
        // its way out.
        log.debug("Caught in a callback in RequestWorker.begin(): " +
                  ((e && e.message) || e));
      }
    });
    // A LATE ARRIVAL, or a correction: another process generated this realm's
    // keys first and the parent is telling us which set the service uses. It
    // replaces whatever this process holds — see receivePublishedKeys().
    //
    // THE DIRECTORY'S CONNECTION LIST ARRIVES ON THIS SAME LISTENER, and is
    // handed straight to `ldap_server.js` — see installDirectoryMirror() for
    // what it is for and why this process cannot work it out for itself.
    process.on('message', function (later: any) {
      if (later && later.adoptKeys && later.adoptKeys.realm) {
        keystore.adoptShared(later.adoptKeys.realm, later.adoptKeys.blob);
      }
      // A hierarchy built, rebuilt or thrown away somewhere else. `chain` is
      // null for the last of those, and adoptPki() reads that as a removal —
      // a worker still holding a CA the operator deleted would go on issuing
      // from it.
      if (later && later.adoptPki && later.adoptPki.realm !== undefined) {
        keystore.adoptPki(later.adoptPki.realm, later.adoptPki.chain);
      }
      // THE FRONT PROCESS RE-ISSUED THE LISTENER CERTIFICATE (2026-09-12).
      //
      // The one this process was handed at fork travelled in `process.env`
      // before the TLS module was loaded, which is a snapshot; when the
      // hierarchy is rebuilt — on a worker, by an operator, through
      // /admin/pki — the front process re-issues the leaf its socket presents
      // and sends the new one here. Without this a worker goes on PINNING the
      // previous certificate, and the first thing to notice is its own OpenID
      // Connect back channel failing with `unable to get local issuer
      // certificate` — which is /admin and /portal answering 400 at their own
      // callback. See common/request_pool.js's reconcileTheListener().
      //
      // No private key comes with it and none is needed: this process pins and
      // reports this certificate, and never presents it.
      if (later && later.adoptServerCertificate) {
        require('../tls/tls_server')
          .adoptServerCertificate(later.adoptServerCertificate);
      }
      if (later && later.ldapConnections) {
        require('../ldap/ldap_server').setConnectionMirror(
            later.ldapConnections);
      }
    });
    try {
      this.start(message.socket || '');
      // AFTER start(), which is what loads the protocol stack: requiring the
      // directory before it would put this module in the position server.js
      // holds and register every `/admin/ldap/*` page at a point of this
      // file's choosing. Here it is a cache hit. The seed is the snapshot the
      // front process took when it forked this worker; every later change
      // arrives on the listener above.
      this.installDirectoryMirror(message.ldapConnections || []);
    } catch (e) {
      this.report({ ready: false, error: e.message });
    }
    log.debug("Leaving RequestWorker.begin().");
  }
}

// ---------------------------------------------------------------------------
// THIS PROCESS'S OWN WORKER — built here, once, because this file is an entry
// point (see the header). The process listeners are installed at load, as
// they always were, and the `begin` listener only when this file is the
// process's main module.
// ---------------------------------------------------------------------------
const worker = new RequestWorker(RequestWorker.defaultDeps());
worker.listen();
if (require.main === module) {
  worker.waitForBegin();
}

export = {
  RequestWorker: RequestWorker,
  // THE HEADER THIS WORKER ASKS THE FRONT PROCESS ON, exported to be compared
  // with `request_pool.js`'s copy — see that file's export of the same name.
  LDAP_DROP_HEADER: LDAP_DROP_HEADER,
  // And the back-channel hint's, for the same comparison.
  PROTOCOL_WORKER_HEADER: PROTOCOL_WORKER_HEADER,
  // Installing the directory mirror, exported so that a test can put this
  // process in the state a worker is in without forking one.
  installDirectoryMirror:
    worker.installDirectoryMirror.bind(worker) as
      RequestWorker['installDirectoryMirror'],
  start: worker.start.bind(worker) as RequestWorker['start'],
  stop: worker.stop.bind(worker) as RequestWorker['stop'],
  register: worker.register.bind(worker) as RequestWorker['register'],
  OPERATIONS: worker.operations
};
