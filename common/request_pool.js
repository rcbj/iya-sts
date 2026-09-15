'use strict';
//
// File: request_pool.js
//
// ---------------------------------------------------------------------------
// THE FRONT PROCESS'S END OF THE REQUEST WORKERS: FORK, ROUTE, PROXY, DRAIN.
//
// `request_worker.js` says what a worker is and why it speaks real HTTP over a
// unix socket. This file is the half that runs where the sockets are, and its
// job is the sentence the whole change exists for: **the front process should
// be doing request/response I/O and nothing else.**
//
// So the middleware below does exactly four things — read the request, choose a
// worker, stream it there, stream the answer back — and every one of them is
// I/O. No handler runs here for a dispatched path.
//
// ---------------------------------------------------------------------------
// ROUTING: AFFINITY WHERE THERE IS A SESSION, FANOUT WHERE THERE IS NOT.
//
// This is the one place the two halves of the design meet, and the distinction
// is NOT "stateful versus stateless" — it is **sessionless versus
// session-bearing**, which is a different cut and the one that decides routing:
//
//   * **SESSIONLESS.** `/scim/v2`, `/ldap`-backed console reads, `/xacml` and
//     `/admin-api` carry their own credential on every request and name their
//     own target. Nothing about one request has to be remembered to answer the
//     next, so they FAN OUT to the least-loaded worker. They are not stateless
//     — SCIM and LDAP writes mutate the directory every other family reads —
//     but that is a question about the STATE CHANNEL and not about which worker
//     answers.
//   * **SESSION-BEARING.** Everything a browser does — the authorization
//     endpoint, both SAML profiles, WS-Federation, the portal, the console —
//     hangs off a sign-on session, so those requests hold AFFINITY to one
//     worker, keyed on the session cookie.
//
// **AFFINITY IS A LOCALITY MEASURE AND NEVER A CORRECTNESS ONE**, and that has
// to be said here because this file is where somebody will be tempted to rely
// on it. Of the stores this service keeps, only the sign-on sessions and the
// pending authentication records are per-session; authorization codes, the
// token registry, credential offers, SAML artifacts, the KDC replay cache, the
// SCIM nonces, the SPIFFE registry, the directory, the realm table, the
// settings, the statistics and the audit log are all read by a request other
// than the one that wrote them. Correctness for every one of those comes from
// the state channel. What affinity buys is that one person's requests queue
// behind each other instead of interleaving across the pool.
//
// ---------------------------------------------------------------------------
// THE ALLOW-LIST STARTS EMPTY, AND THAT IS THE SAFETY PROPERTY.
//
// `workers.dispatch` names the path prefixes that go to a worker. With nothing
// in it — the default — this middleware calls `next()` for everything and the
// service behaves exactly as it did, which is what made this landable before
// the state channel existed.
//
// **THE STATE CHANNEL IS `persistence_replication.js` AND THERE IS NO
// `state_channel.js` (corrected 2026-09-12).** This block named one, and so did
// `request_worker.js`'s header; no such file was ever written. What was built
// instead is the thing the root CLAUDE.md argues at length — a worker is just
// ANOTHER PROCESS AGAINST THE STORE, running the same four startup steps from
// `service_state.js`, reconciled by the change log in
// `persistence/persistence_replication.js`. A reader following either sentence
// went looking for a file that does not exist and could reasonably have
// concluded the channel was unfinished.
//
// So the rule for adding a prefix is not "wait for a module" — it is
// `start()`'s refusal below: **nothing may be dispatched unless this process is
// coordinating**, and what decides whether a store is reachable from a worker
// is whether its changes are rows in `sts_changes`.
//
// **A REQUEST IS NEVER SILENTLY HALF-DISPATCHED.** If a worker cannot be
// reached the request is answered 503 with a sentence naming the pool, rather
// than falling back to running the handler here: a fallback would mean the same
// path is served from two processes depending on timing, which is the shape of
// bug that shows up as one caller in a thousand seeing stale state.
// ---------------------------------------------------------------------------

const path = require('path');
const os = require('os');
const fs = require('fs');
const http = require('http');
const child_process = require('child_process');
const nodeCrypto = require('crypto');
const bunyan = require('bunyan');
const config = require('./config');
// A LEAF (rule 3) — it registers no route, so requiring it here cannot move one
// and cannot join a cycle. It is the shared-key registry this file arbitrates;
// see keystore.js's block above storedFor().
const keystore = require('./keystore');
// A LEAF with no requires: the failure codes on the log lines and the 502s and
// 503s below. See common/error_codes.js.
const errorCodes = require('./error_codes');
// Who a request came from, a LEAF (config, net, bunyan). See the
// `x-forwarded-for` line in proxy() below.
const clientAddress = require('./client_address');

let logLevelProblem = null;
const log = bunyan.createLogger({
  name: 'request_pool',
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

const WORKER_MODULE = path.join(__dirname, 'request_worker.js');

// ---------------------------------------------------------------------------
// THE SERVER CERTIFICATE, HANDED IN BY `server.js` BEFORE THE POOL STARTS.
//
// An INVERTED HOOK for the reason `admin.js` has eleven of them: this file is
// loaded by `app.js`, which is above every route, and `tls/tls_server.js` sits
// at 20 in the require order — so a require in the obvious direction would drag
// three TLS routes to the front of the router (rule 1). The material travels
// the other way instead, filled once, before any worker is forked.
// ---------------------------------------------------------------------------
let tlsMaterial = null;
// (The OpenID4VCI request-encryption key used to be held here and handed down
// the fork beside the certificate. It is a member of each realm's key set since
// 2026-09-12 and travels on the key channel with the rest of it — see
// `common/helpers.js`'s makeRequestEncryptionKey().)
let bbsKeyPairB64 = '';
// Workers announce their own commits (see receiveCommitted()), so proxy()
// must NOT bump the generation when a response goes out — doing both would
// move it twice per write and make every worker permanently one behind.
// Writes that have been ANSWERED and not yet reported committed, as TICKETS.
//
// **A COUNTER WAS NOT ENOUGH AND THE DIFFERENCE IS THE WHOLE OF THIS BLOCK.**
// The first version counted outstanding writes and made a reader wait for the
// count to reach ZERO — which under continuous traffic it never does, because
// the next request arrives before the last one is confirmed. A dispatched run
// measured 52 waits giving up at their 2000ms bound, and a wait that gives up
// serves exactly the stale read it was there to prevent.
//
// What a reader actually needs is narrower: everything answered BEFORE IT
// ARRIVED must be committed. Anything answered after is not its business. So
// each answered request takes a ticket, a reader remembers the ticket count it
// arrived at, and it waits only until every ticket at or below that number is
// confirmed. That terminates under load, because the tickets a reader is
// waiting for are a fixed, finite set that cannot grow while it waits.
let issuedTickets = 0;
let outstanding = new Set();
// Tickets whose response has finished — see blockedBelow().
let finishedTickets = new Set();
// WHEN each of those finished, which is what reapStuckTickets() needs and
// nothing else reads. Kept beside the set rather than on the worker entry
// because the reaper walks `outstanding`, and a ticket's owner is exactly what
// a lost announcement makes unreliable.
const finishedAt = new Map();
let ticketWaiters = [];

// The highest ticket for which EVERY earlier ticket is confirmed too. A reader
// is satisfied when this reaches the number it arrived at.
// **ONLY A FINISHED REQUEST CAN BLOCK A READER (2026-09-07).**
//
// Tickets are taken at DISPATCH, so the outstanding set includes requests still
// IN FLIGHT — and a request in flight has not been acknowledged to anybody, so
// nothing can be depending on having seen it. Counting those made a single slow
// request block every reader behind it for the full 2000ms bound, which is
// exactly the "waiting for ticket N, confirmed through N-1" the log kept
// showing: one ticket, never confirmable, because its request had not returned.
//
// What a reader must wait for is narrower and is the whole of read-your-write:
// every write that had ALREADY BEEN ANSWERED when the reader arrived. A ticket
// counts once its response has finished — and until then it is somebody else's
// business.
//
// ---------------------------------------------------------------------------
// **AND IT WALKS THE FINISHED SET, NOT THE OUTSTANDING ONE (2026-09-13).**
//
// Only a finished ticket can block, so walking `outstanding` to find them was
// walking every request IN FLIGHT to find the few that were answered. Under
// the loopback push storm a session sweep sets off, that was 8,000 in flight
// against 67 finished — and this function is called once per WAITER on every
// release, which is where the quadratic lived. See releaseTicketWaiters().
// ---------------------------------------------------------------------------
function blockedBelow(need, servedBy) {
  log.debug("Entering blockedBelow().");
  log.debug("Leaving blockedBelow().");
  return lowestBlocking(servedBy) <= need;
}

// The lowest ticket that blocks a reader about to be served by `servedBy`, or
// Infinity. A reader is blocked exactly when this is at or below the number it
// arrived at, so one walk answers every waiter served by the same worker.
function lowestBlocking(servedBy) {
  log.debug("Entering lowestBlocking().");
  let lowest = Infinity;
  finishedTickets.forEach(function (t) {
    if (t >= lowest || !outstanding.has(t)) {
      return;
    }
    // --------------------------------------------------------------------
    // A WRITE THIS WORKER ANSWERED DOES NOT BLOCK A READ IT IS ABOUT TO
    // ANSWER (2026-09-08).
    //
    // The wait exists so that a reader cannot be told it is current before
    // a write somebody else answered has reached the store. That reasoning
    // does not apply to the worker's OWN outstanding writes: those are in
    // its memory already, and the request is going to that same worker, so
    // it will see them whether or not they have been flushed.
    //
    // Waiting for them anyway is what made a sequential client pay a full
    // commit round trip per request. Measured on SCIM creates: 16.2ms each
    // with the barrier, 5.1ms with it switched off entirely — so about
    // eleven of those sixteen milliseconds were a client waiting for its
    // own previous write to be written down.
    // --------------------------------------------------------------------
    if (servedBy && servedBy.tickets && servedBy.tickets.has(t)) {
      return;
    }
    lowest = t;
  });
  log.debug("Leaving lowestBlocking().");
  return lowest;
}

// ---------------------------------------------------------------------------
// A WAITER THAT TIMED OUT LEFT THE LIST ONLY WHEN IT STOPPED BEING BLOCKED,
// AND THAT WEDGED THE FRONT PROCESS FOR MINUTES (2026-09-13).
//
// The filter below removed a waiter when its tickets had cleared, and the
// 2,000ms timeout in awaitCommitConfirmations() RESOLVED a waiter without
// removing it. A reader that timed out is a reader whose tickets had not
// cleared, so it stayed in the list for as long as they did — and every
// release walked it again, calling blockedBelow() for it, which walked the
// whole outstanding set. O(waiters × outstanding) per commit announcement.
//
// **IT IS A CLIFF AND IT FEEDS ITSELF.** Measured in process: 10,000 waiters
// timed out against 6,000 outstanding tickets made ONE receiveCommitted() take
// 980ms of synchronous CPU. Announcements arrive from every worker many times
// a second, so the event loop stops being free; every proxied request, every
// timer and every other announcement queues behind it; the queue produces
// more waiters. Measured on the `--modes=dispatch` run of 2026-09-13: a
// session sweep's CAEP storm put 5,752 requests in flight, the front process
// logged nothing for three minutes, one SCIM create went unanswered for 300s
// (undici's headers timeout) and 6,479 loopback pushes died together at the
// server's 300s request timeout. `sts_directory_bulk_load_scim` reported it as
// `fetch failed` after 290 of 5,000 creates.
//
// So a settled waiter is DROPPED here whatever its tickets say, the lowest
// blocking ticket is computed ONCE per worker rather than once per waiter, and
// `settledWaiters` lets the timeout compact the list without a walk per
// timeout. `tests/request_barrier.js` section 6 pins all three.
// ---------------------------------------------------------------------------
let settledWaiters = 0;

function releaseTicketWaiters() {
  log.debug("Entering releaseTicketWaiters().");
  if (!ticketWaiters.length) {
    log.debug("Leaving releaseTicketWaiters().");
    return;
  }
  const lowest = new Map();
  ticketWaiters = ticketWaiters.filter(function (w) {
    if (w.settled) {
      return false;
    }
    const key = w.servedBy || null;
    if (!lowest.has(key)) {
      lowest.set(key, lowestBlocking(key));
    }
    if (lowest.get(key) > w.need) {
      w.resolve();
      return false;
    }
    return true;
  });
  settledWaiters = 0;
  log.debug("Leaving releaseTicketWaiters().");
}

// A waiter that gave up, taken out of the list rather than left in it to be
// walked by every later release. Compacted only once settled waiters are half
// the list, so a burst of timeouts costs a walk per doubling rather than one
// per timeout.
function dropSettledWaiter() {
  log.debug("Entering dropSettledWaiter().");
  settledWaiters++;
  if (settledWaiters * 2 < ticketWaiters.length) {
    log.debug("Leaving dropSettledWaiter(). Left for the next compaction.");
    return;
  }
  ticketWaiters = ticketWaiters.filter(function (w) {
    return !w.settled;
  });
  settledWaiters = 0;
  log.debug("Leaving dropSettledWaiter(). Compacted.");
}

// A ticket for a request about to be sent to `entry`. Cleared when that worker
// reports a commit — see receiveCommitted(), which clears everything the worker
// owes, because its flush covers every request it has finished.
function dispatchTicket(entry) {
  log.debug("Entering dispatchTicket().");
  if (!readYourWrite()) {
    log.debug("Leaving dispatchTicket().");
    return;
  }
  issuedTickets++;
  outstanding.add(issuedTickets);
  if (!entry.tickets) { entry.tickets = new Set(); }
  entry.tickets.add(issuedTickets);
  log.debug("Leaving dispatchTicket().");
  return issuedTickets;
}

// This response has finished, so it may now block a reader — see
// blockedBelow(). It says nothing about whether the WRITE has committed; only
// the worker's announcement says that, and it names the tickets.
//
// **IT USED TO NUMBER THE TICKET IN THIS PROCESS'S FINISH ORDER, and that was
// a real defect (2026-09-08).** The worker's announcement carried a COUNT of
// the responses its flush covered, and clearing "every ticket numbered at or
// below it" assumed the two processes complete the same responses in the same
// order. They do not: the worker finishes when it has written the response,
// this process when it has piped it out, so two concurrent responses of
// different sizes can finish here in the opposite order. The ticket cleared was
// then somebody else's, and a reader was released against a write that had not
// committed — which is a stale read, silent, and rare enough to look like
// nothing. It cost one lost group member in five thousand in the bulk-load
// job, which is exactly what a race like this looks like from outside.
function ticketFinished(entry, ticket) {
  log.debug("Entering ticketFinished().");
  if (!ticket || !entry.tickets || !entry.tickets.has(ticket)) {
    log.debug("Leaving ticketFinished().");
    return;
  }
  finishedTickets.add(ticket);
  finishedAt.set(ticket, Date.now());
  log.debug("Leaving ticketFinished().");
}

// ---------------------------------------------------------------------------
// A TICKET THE WORKER NEVER ANSWERED, DROPPED RATHER THAN MARKED FINISHED
// (2026-09-11).
//
// **THIS IS THE BUG THAT WEDGED `dispatch` MODE, AND IT WEDGED IT FOR GOOD.**
// `proxy()` calls `finish()` from `upstream.on('error')` — the path where the
// request never got an answer out of the worker at all — and `finish()` marked
// the ticket FINISHED, which is what makes a ticket block readers. The worker,
// which in that case never ran the handler, never announces it. So the ticket
// sat in `outstanding` and in `finishedTickets` for the life of the process,
// and EVERY subsequent read waited the full 2000ms bound and then gave up.
//
// It is not a slow degradation; it is a cliff, and it is permanent. Measured on
// the run that found it: a service 41 minutes idle, 5,521 stuck tickets, and a
// `GET /admin-api/ldap/directory?per=1` taking 2.6s — with the four bulk-load
// jobs failing outright because a 10s connect timeout is shorter than the queue
// those waits build. The SCIM job got through 536 of 5,000 creates in 405
// seconds, against 93 in the same suite's single-process mode.
//
// **A 502 IS NOT AN ACKNOWLEDGEMENT**, which is the whole argument for
// dropping rather than keeping. The barrier's contract is "everything ANSWERED
// before this reader arrived must have committed", and the comment above
// blockedBelow() already draws the line where it belongs: a request that has
// not been acknowledged to anybody is one nothing can be depending on. A
// request the client was handed a 502 for is exactly that — the client knows
// its write did not happen, and no reader is owed it.
//
// The worker MAY still announce the ticket later, in the case where it did run
// the handler and the failure was on the way back. That is harmless:
// receiveCommitted() skips a ticket the entry no longer owns.
// ---------------------------------------------------------------------------
function ticketAbandoned(entry, ticket) {
  log.debug("Entering ticketAbandoned().");
  if (!ticket) {
    log.debug("Leaving ticketAbandoned().");
    return;
  }
  outstanding.delete(ticket);
  finishedTickets.delete(ticket);
  finishedAt.delete(ticket);
  if (entry && entry.tickets) {
    entry.tickets.delete(ticket);
  }
  releaseTicketWaiters();
  log.debug("Leaving ticketAbandoned().");
}

// ---------------------------------------------------------------------------
// THE SAFETY NET, AND WHY IT COSTS NOTHING TO BE WRONG ABOUT (2026-09-11).
//
// The drop above closes the one leak this run actually found. It cannot be the
// last one: any path where a worker finishes a response in this process's
// bookkeeping and never announces it in its own leaves a ticket that blocks
// every reader for ever, and the symptom — a service that answers correctly
// and 2,000ms slower than it should, with a warning nobody reads — is the
// hardest shape of failure to notice there is.
//
// So a ticket that has ALREADY been given up on is reaped. The argument is one
// sentence: **a wait that timed out was served without that ticket, and so
// will every wait after it** — the set only grows, and each reader pays the
// full bound to reach the same answer. Reaping changes no read's OUTCOME; it
// changes how long the next one waits to get it.
//
// `REAP_AFTER_MS` is deliberately far above the bound rather than equal to it.
// A flush during a bulk load genuinely can run for seconds — `persistence.
// flush()` diffs the whole directory — and a ticket reaped while its flush is
// merely slow WOULD release a reader early. At thirty seconds that is not a
// slow flush, it is a lost announcement, and the log line says which one so
// that the next leak is reported rather than inferred from the latency.
// ---------------------------------------------------------------------------
const REAP_AFTER_MS = 30000;
let reaped = 0;

// `at` is the clock, and it is a parameter for one reason: the threshold is
// thirty seconds and a test that waited thirty seconds to assert one `if` is a
// test nobody runs. Every caller in this file passes nothing.
function reapStuckTickets(need, clock) {
  log.debug('Entering reapStuckTickets(). need=' + need);
  const now = clock || Date.now();
  const gone = [];
  // THE FINISHED SET AND NOT THE OUTSTANDING ONE: this runs on every timeout,
  // and only a finished ticket can be reaped. See blockedBelow() for what
  // walking every request in flight cost under a storm.
  finishedTickets.forEach(function (t) {
    if (t > need || !outstanding.has(t)) {
      return;
    }
    const armedAt = finishedAt.get(t);
    // NO TIMESTAMP AT ALL MEANS REAP IT. A ticket in `finishedTickets` always
    // gets one; a ticket in there without one is bookkeeping this process can
    // no longer explain, which is exactly the state this function is for.
    if (armedAt && (now - armedAt) < REAP_AFTER_MS) {
      return;
    }
    gone.push(t);
  });
  if (!gone.length) {
    log.debug('Leaving reapStuckTickets(). Nothing old enough.');
    return;
  }
  gone.forEach(function (t) {
    outstanding.delete(t);
    finishedTickets.delete(t);
    finishedAt.delete(t);
    workers.forEach(function (entry) {
      if (entry.tickets) {
        entry.tickets.delete(t);
      }
    });
  });
  reaped += gone.length;
  // AND EVERY OTHER WAITER IS RECONSIDERED, not just the one whose timeout ran
  // this. They are blocked on the same tickets; leaving them to reach their own
  // bounds would pay the 2,000ms again for something that is already gone.
  releaseTicketWaiters();
  // WARN AND NOT ERROR, to match the timeout line this always follows: by the
  // time a ticket is reaped, every reader that met it has already been served
  // without it, so nothing here is a new loss.
  //
  // **TWO CAUSES REACH THIS AND THEY ARE NOT THE SAME THING**, and nothing in
  // this process can tell them apart — which is why the line names both rather
  // than guessing. One is a LOST announcement: a ticket no worker will ever
  // report, which is what ticketAbandoned() exists to stop being created. The
  // other is a flush that has simply been running longer than the threshold —
  // `persistence.flush()` diffs the whole directory, and under a five-thousand
  // entry bulk load it does take tens of seconds. In that second case the
  // barrier has degraded, and it had already degraded at the 2,000ms bound:
  // this only stops the backlog making every OTHER read pay for it too.
  log.warn(errorCodes.tag('STS-WORKER-0008') +
           'request_pool: ' + gone.length + ' ticket(s) had been answered ' +
           'for more than ' + (REAP_AFTER_MS / 1000) + 's without any ' +
           'worker reporting them committed, and were dropped (' + reaped +
           ' so far). Every read since has been served without them anyway, ' +
           'after waiting the full barrier bound for each — so this changes ' +
           'no answer and removes that wait. Either a worker lost an ' +
           'announcement (see ticketAbandoned()) or its flush has been ' +
           'running longer than that, which a bulk load can do.');
  log.debug('Leaving reapStuckTickets(). ' + gone.length + ' dropped.');
}

// ---------------------------------------------------------------------------
// ONE LINE A SECOND PER CODE FOR THE TWO BARRIER TIMEOUTS (2026-09-13).
//
// Both are written once per READER, and a storm is thousands of readers: the
// 2026-09-13 dispatch run wrote 29,504 `STS-WORKER-0007` lines and 6,307
// `STS-WORKER-0027`, 14,246 of them in one minute, every one a synchronous
// write to a pipe from the process whose event loop was the thing in short
// supply. What a reader of the log needs is that it happened, how often, and
// the state at the time — so the first in each second is written whole and the
// next one written says how many were not.
//
// Nothing else reads these lines: the counts an operator can rely on are
// `stats().tickets`, and no audit row was ever written for either code.
// ---------------------------------------------------------------------------
const WARN_WINDOW_MS = 1000;
const sparedWarnings = new Map();

function warnSparingly(code, message) {
  log.debug("Entering warnSparingly(). " + code);
  const now = Date.now();
  const held = sparedWarnings.get(code);
  if (held && (now - held.at) < WARN_WINDOW_MS) {
    held.suppressed += 1;
    log.debug("Leaving warnSparingly(). Counted, not written.");
    return;
  }
  const more = (held && held.suppressed)
    ? ' (' + held.suppressed + ' more like this since the last one written ' +
      'were counted and not logged)'
    : '';
  sparedWarnings.set(code, { at: now, suppressed: 0 });
  log.warn(errorCodes.tag(code) + message + more);
  log.debug("Leaving warnSparingly().");
}

function awaitCommitConfirmations(servedBy) {
  log.debug("Entering awaitCommitConfirmations().");
  if (!readYourWrite()) {
    log.debug("Leaving awaitCommitConfirmations().");
    return Promise.resolve();
  }
  const need = issuedTickets;
  if (!blockedBelow(need, servedBy)) {
    log.debug("Leaving awaitCommitConfirmations().");
    return Promise.resolve();
  }
  log.debug("Leaving awaitCommitConfirmations().");
  return new Promise(function (resolve) {
    let done = false;
    const waiter = { need: need, servedBy: servedBy, resolve: function () {
      log.debug("Entering resolve().");
      if (done) {
        log.debug("Leaving resolve().");
        return;
      }
      done = true;
      resolve();
      log.debug("Leaving resolve().");
    } };
    ticketWaiters.push(waiter);
    setTimeout(function () {
      if (!done) {
        // SETTLED BEFORE ANYTHING ELSE, so that the release reapStuckTickets()
        // may run below drops it rather than walking it — see
        // releaseTicketWaiters() for what keeping it cost.
        waiter.settled = true;
        warnSparingly('STS-WORKER-0007',
                      'request_pool: a write answered before this read was ' +
                      'not reported committed within 2000ms (waiting below ' +
                      'ticket ' + need + '; ' + outstanding.size +
                      ' outstanding, ' + finishedTickets.size + ' of them ' +
                      'finished, ' + (ticketWaiters.length - settledWaiters) +
                      ' reader(s) still held); serving without it.');
        // WHAT THIS READER WAS JUST SERVED WITHOUT, taken out so that the next
        // one does not wait the bound to be served without it too. See
        // reapStuckTickets(); it only reaps what is long past explaining.
        reapStuckTickets(need);
        dropSettledWaiter();
      }
      waiter.resolve();
    }, 2000);
  });
}


// THE BBS PAIR, handed over before the pool forks for setServerCertificate()'s
// reason: it is one per SERVICE, it is what a did:web document publishes, and a
// worker that made its own would publish a verification method nothing it
// signed can be verified against. Generated in server.js because making one is
// asynchronous and this file's start() is not the place to await.
function setBbsKeyPair(encoded) {
  log.debug("Entering setBbsKeyPair().");
  bbsKeyPairB64 = String(encoded || '');
  if (bbsKeyPairB64) {
    process.env.STS_BBS_KEYPAIR = bbsKeyPairB64;
  }
  log.debug("Leaving setBbsKeyPair().");
}

function setServerCertificate(material) {
  log.debug("Entering setServerCertificate().");
  if (!material || !material.certPem || !material.keyPem) {
    throw new Error('request_pool: setServerCertificate() needs certPem and ' +
      'keyPem. Every process in this service must present and pin the SAME ' +
      'certificate, or the console and the portal fail TLS against ' +
      'themselves.');
  }
  // **THE CHAIN AND THE ANCHOR ARE CARRIED TOO**, and they are not optional
  // extras: a worker with the leaf alone presents no chain and, having no
  // anchor handed to it, asks its OWN `common/pki.js` for one — which answers
  // a Root that worker built. See server.js's call site. They are PUBLIC
  // material, unlike the key beside them, which is why they can go through
  // `process.env` at the other end while the key deliberately does not.
  tlsMaterial = { certPem: material.certPem, keyPem: material.keyPem,
                  chainPem: (material.chainPem || []).slice(0),
                  trustAnchorPem: material.trustAnchorPem || '' };
  log.debug("Leaving setServerCertificate().");
}

// ---------------------------------------------------------------------------
// AM I MYSELF A REQUEST WORKER? If so this file does nothing at all, and the
// reason is the first thing that went wrong when the pool was wired up.
//
// A worker loads `app.js` — that is the whole point, it runs the same service —
// and `app.js` installs the middleware below. So without this marker a worker
// matched the dispatch list exactly as the front process did, looked for a
// worker of ITS OWN, found none, and answered 503. The front process then
// faithfully piped that 503 back to the client: the proxy was working
// perfectly and every dispatched request failed.
//
// The marker is an environment variable set on the fork rather than anything
// cleverer, because it has to survive `require` order, be readable before any
// configuration is loaded, and be obviously true or false to somebody reading a
// `ps` line while wondering which process is which.
// ---------------------------------------------------------------------------
const IS_REQUEST_WORKER = !!process.env.STS_REQUEST_WORKER;

// ---------------------------------------------------------------------------
// THE TWO HEADERS THAT CARRY THE TLS CONNECTION INTO A WORKER.
//
// Named here because both ends need the same spelling and because the STRIPPING
// in proxy() has to name them too — a header a client may not set is only safe
// while every place that touches it agrees what it is called.
// ---------------------------------------------------------------------------
const PEER_CERT_HEADER = 'x-sts-peer-certificate';

// ---------------------------------------------------------------------------
// AND THE ONE THAT CARRIES A SIGN-OUT BACK OUT OF A WORKER (2026-09-09).
//
// In LDAP the connection IS the session (RFC 4511 section 4.2), so the only
// sign-out that protocol has is the socket closing — and the socket belongs to
// THIS process, which is the one that called listen(). A worker running
// `/logout` can decide that a directory connection must end and cannot end it.
//
// **IT RIDES THE RESPONSE RATHER THAN THE IPC CHANNEL BESIDE IT, AND THAT IS
// THE WHOLE POINT.** A `process.send()` from the worker would arrive here on a
// different channel from the answer it belongs to, so the answer could reach
// the client first and a sign-out would once again report a connection ended
// while it was still open — the exact bug this fixes, made rarer and harder to
// see rather than fixed. The header is IN the answer, and this process closes
// the socket before it forwards a byte of it, so the order is a property of the
// mechanism and not of a race.
//
// STRIPPED FROM WHAT THE CLIENT SENT, like the two above and for a sharper
// reason: it names an identity whose directory connections are to be closed, so
// a client that could set it could sign anybody out of the directory. It is
// deleted on the way in before anything else touches the request.
// ---------------------------------------------------------------------------
const LDAP_DROP_HEADER = 'x-sts-ldap-drop';

// THE TICKET THIS REQUEST WAS DISPATCHED UNDER, told to the worker so that the
// worker can say which tickets its flush covered — see receiveCommitted().
// Stripped from what the client sent, exactly like the two above: nothing a
// caller says about it may be believed.
const POOL_TICKET_HEADER = 'x-sts-pool-ticket';
const PEER_AUTHORIZED_HEADER = 'x-sts-peer-authorized';

// ---------------------------------------------------------------------------
// AND THE ONE THAT TELLS A HOSTED-SURFACE WORKER WHERE ITS BACK CHANNEL GOES
// (2026-09-13).
//
// The console and the portal redeem their authorization code over a real HTTP
// request to this service's own token endpoint (`common/oidc_rp.js`), and the
// code lives in the memory of the worker that ran `/oauth2/authorize` until
// replication carries it anywhere else. With one pool that worker was the one
// running `/admin/callback` too — the browser's session held both to it — so
// the back channel named ITS OWN pid in the protocol pool's cookie and landed
// where the code was.
//
// With a surface pool the callback runs in a surface worker, whose own pid is
// no protocol worker at all. The browser's request to the callback still
// carries the session cookie the protocol pool bound, and ONLY THIS PROCESS
// holds that binding — so it looks the worker up and says which, on the
// request, before a byte reaches the surface worker. The worker hands it to
// the back channel as the value of that cookie.
//
// **A ROUTING HINT, NOT A CREDENTIAL**, for exactly the reason the pool cookie
// is not one: it selects which of N identical processes answers, and the worst
// a forged one achieves is choosing that. It is STRIPPED from what the client
// sent anyway, like every header here that this process writes, so that no
// handler ever sees a value that did not come from the pool.
// ---------------------------------------------------------------------------
const PROTOCOL_WORKER_HEADER = 'x-sts-pool-protocol-worker';

// What the front process saw of this connection, in a shape that survives a
// header. `raw` is a Buffer and is the only field that needs care; everything
// else node puts on a peer certificate is a string or a plain object.
//
// It returns null for a plain HTTP connection and for an https one where the
// client sent nothing, and those are the same answer to the worker: no
// certificate. The DIFFERENCE between them is reported by the surfaces that
// care, out of `global.https`, exactly as it is today.
function peerOf(req) {
  log.debug("Entering peerOf().");
  const socket = req && req.socket;
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    log.debug("Leaving peerOf().");
    return null;
  }
  let cert;
  try {
    cert = socket.getPeerCertificate();
  } catch (e) {
    log.debug("Caught in peerOf(): " + ((e && e.message) || e));
    log.debug("Leaving peerOf().");
    return null;
  }
  if (!cert || !cert.raw || !cert.raw.length) {
    log.debug("Leaving peerOf().");
    return null;
  }
  const flat = {};
  Object.keys(cert).forEach(function (name) {
    const value = cert[name];
    if (Buffer.isBuffer(value)) {
      flat[name] = { __buffer: value.toString('base64') };
      return;
    }
    // `issuerCertificate` is a CHAIN and is self-referential at the root, so
    // walking it would not terminate. It is not copied as it stands; the DER
    // of each certificate above the leaf goes in `issuerChain` below instead.
    if (name === 'issuerCertificate') {
      return;
    }
    flat[name] = value;
  });
  // THE CHAIN ABOVE THE LEAF, AS DER (2026-09-12). The sentence this replaced
  // said nothing here reads it, and that stopped being true the day
  // `common/revocation_status.js` started CONSULTING revocation: a foreign
  // CRL is verified against the issuer's certificate, and a worker handed the
  // leaf alone has no issuer to verify it with. This is the path OpenSSL built
  // in the front process, anchor included, bounded because its shape is
  // somebody else's bytes. The register half of the check needs none of it.
  const chain = [];
  try {
    let at = socket.getPeerCertificate(true);
    at = at && at.issuerCertificate;
    while (at && at.raw && chain.length < 8) {
      if (at.raw.equals(cert.raw)) {
        break;
      }
      chain.push(at.raw.toString('base64'));
      if (!at.issuerCertificate || at.issuerCertificate === at) {
        break;
      }
      at = at.issuerCertificate;
    }
  } catch (e) {
    log.debug("Caught in peerOf(): " + ((e && e.message) || e));
    // A socket that went away between the two reads. The leaf still goes; a
    // worker without the chain answers a foreign certificate as unknown, which
    // is what the policy exists to decide about.
    chain.length = 0;
  }
  if (chain.length) {
    flat.issuerChain = chain;
  }
  let encoded;
  try {
    encoded = Buffer.from(JSON.stringify(flat), 'utf8').toString('base64');
  } catch (e) {
    log.debug("Caught in peerOf(): " + ((e && e.message) || e));
    log.debug("Leaving peerOf().");
    return null;
  }
  // THE CHAIN IS WHAT IS GIVEN UP FIRST when the header would be too large:
  // the leaf binds a token and names a caller, and losing it would be the
  // request presenting nothing at all.
  if (encoded.length > 12000 && flat.issuerChain) {
    log.warn(errorCodes.tag('STS-WORKER-0037') +
             'request_pool: a client certificate\'s issuer chain is too ' +
             'large to forward ' +
             '(' + encoded.length + ' bytes encoded); the worker ' +
             'gets the leaf alone and cannot verify a foreign CRL about it.');
    delete flat.issuerChain;
    try {
      encoded = Buffer.from(JSON.stringify(flat), 'utf8').toString('base64');
    } catch (e) {
      log.debug("Caught in peerOf(): " + ((e && e.message) || e));
      log.debug("Leaving peerOf().");
      return null;
    }
  }
  // A header this size would be refused by the worker's own parser, and a
  // refused request is worse than one that behaves as though no certificate
  // was sent. 12KB is comfortably under node's default 16KB header limit.
  if (encoded.length > 12000) {
    log.warn(errorCodes.tag('STS-WORKER-0009') +
             'request_pool: a client certificate is too large to forward (' +
             encoded.length + ' bytes encoded); the worker will see this ' +
             'request as having presented none.');
    log.debug("Leaving peerOf().");
    return null;
  }
  log.debug("Leaving peerOf().");
  return { cert: encoded, authorized: socket.authorized === true };
}

// The session cookie, which is the affinity key. Named here rather than
// imported from authn.js because this file must not require a protocol module:
// it is loaded by app.js, which is above every route, and a require in that
// direction would drag authn's routes to the front of the router (rule 1).
const SESSION_COOKIE = 'sts_session';

// AND THE TWO RELYING-PARTY COOKIES (2026-09-08). Since this service's own
// console and user portal became OpenID Connect clients, each holds a session
// of its OWN on a cookie of its own — `common/oidc_rp.js` names them — and a
// request carrying one of those and no sign-on cookie was, to this file, a
// request with no affinity at all. Two consequences, and the second is the one
// that broke a suite: it was routed by load rather than to the worker holding
// the session, and it was handed a pin, which in every client written against
// this service's one-cookie-per-response habit REPLACED the console cookie in
// the jar. So the hop after signing in to `/admin` arrived carrying nothing.
//
// Named here for SESSION_COOKIE's reason: this file is loaded by app.js, above
// every route, so it may not require the module that owns them.
const RP_COOKIES = ['sts_admin', 'sts_portal'];

function sessionCookieName(bit) {
  log.debug("Entering sessionCookieName().");
  if (bit.indexOf(SESSION_COOKIE + '=') === 0) {
    log.debug("Leaving sessionCookieName().");
    return SESSION_COOKIE;
  }
  for (let i = 0; i < RP_COOKIES.length; i++) {
    if (bit.indexOf(RP_COOKIES[i] + '=') === 0) {
      log.debug("Leaving sessionCookieName().");
      return RP_COOKIES[i];
    }
  }
  log.debug("Leaving sessionCookieName().");
  return '';
}

// A worker that exits within this long of being forked, having served no
// request, did not fail — it never started.
const QUICK_EXIT_MS = 5000;
const QUICK_EXIT_LIMIT = 3;

// How many sessions the affinity map remembers, and the same argument
// worker_pool.js makes for its cap: forgetting an entry re-routes the next
// request and loses nothing, because correctness was never in the routing.
const AFFINITY_MAX = 5000;

// ---------------------------------------------------------------------------
// TWO POOLS, ONE TABLE OF WORKERS (2026-09-13).
//
// `protocol` is the pool this file always had: `workers.requestCount` workers
// running every protocol family. `surfaces` is `workers.surfaceCount` workers
// kept for this service's OWN two hosted surfaces, the console and the portal
// (`workers.surfaces`), so that a page a person is waiting on never queues
// behind a SCIM bulk load or a CAEP storm on the same worker — and a console
// page walking the directory never holds a protocol worker.
//
// **WHAT IS PER POOL IS ROUTING, AND NOTHING ELSE.** A worker in either pool
// loads the same stack, runs the same four startup steps and is one more
// process against the same store, so everything that exists to keep PROCESSES
// agreeing stays global and walks the one `workers` array: the read barrier's
// generation and tickets (a write answered in one pool must make every worker
// in BOTH stale — that is the whole of why the console can sign in through a
// protocol worker at all), the signing keys, the certificate authority, the
// listener certificate and the directory's connection list. What each pool has
// of its own is what decides WHICH worker answers: its size, its affinity map,
// its routing cookie and whether it has given up.
//
// **THE AFFINITY MAPS HAVE TO BE TWO.** One browser holds a worker in each
// pool, under the SAME session cookie. With one map, `s:<id>` would name the
// protocol worker on the way to `/oauth2/authorize`, fail to name a surface
// worker on the way to `/admin`, be re-bound there, and then fail the other
// way on the next protocol hop — every request flipping the binding the last
// one made.
//
// **AND SO DO THE ROUTING COOKIES**, for the reason read the other way: the
// pin's value names a worker and is honoured directly, so one cookie could name
// a worker in only one pool, and every browser pinned to a given surface worker
// would share ONE key in the protocol pool's map — every such browser sent to
// the same protocol worker. That is not a locality loss; it is a funnel.
// ---------------------------------------------------------------------------
const PROTOCOL_POOL = 'protocol';
const SURFACE_POOL = 'surfaces';
const POOLS = [PROTOCOL_POOL, SURFACE_POOL];

// The live workers of BOTH pools. Each is
//   { child, pid, pool, socket, ready, inFlight, served, startedAt, retiring }
let workers = [];

// session id -> pid, one map per pool. Insertion-ordered, which makes the cap a
// least-recently-added eviction without a second structure.
const affinities = {};
affinities[PROTOCOL_POOL] = new Map();
affinities[SURFACE_POOL] = new Map();

let socketDir = '';
let nextSocket = 1;
const quickExits = {};
quickExits[PROTOCOL_POOL] = 0;
quickExits[SURFACE_POOL] = 0;
const givenUp = {};
givenUp[PROTOCOL_POOL] = false;
givenUp[SURFACE_POOL] = false;
let stopped = false;
let starting = null;

// ---------------------------------------------------------------------------
// The configured size and the configured allow-list.
// ---------------------------------------------------------------------------
// `pool` defaults to the protocol pool, which is what every caller written
// before the second pool existed means by "the pool".
function size(pool) {
  log.debug('Entering size().');
  const key = pool === SURFACE_POOL ? 'workers.surfaceCount'
                                    : 'workers.requestCount';
  let wanted = 0;
  try {
    wanted = parseInt(config.value(key), 10);
  } catch (e) {
    log.debug("Caught in size(): " + ((e && e.message) || e));
    // A module loaded with no configuration at all — which is how the parent
    // project's in-process jobs and this repository's own npm test load this
    // tree. Handling requests HERE is the right answer for one of those.
    log.debug('Leaving size(). No configuration; 0.');
    return 0;
  }
  if (!(wanted >= 0)) {
    wanted = 0;
  }
  log.debug('Leaving size(). ' + wanted + '.');
  return wanted;
}

// ---------------------------------------------------------------------------
// ONE LIST OF WHAT IS DISPATCHED, AND IT WAS TWO SETTINGS UNTIL 2026-09-12.
//
// `workers.dispatch` held path prefixes and `workers.operations` held operation
// kinds, and **the distinction between them was artificial**: a dispatched
// thing is a dispatched thing, and an operator naming what should leave the
// front process has no reason to care whether this service reaches it over HTTP
// or over a raw socket. Two settings meant two places to look, two things to
// forget, and a coordination guard that had to remember to check both.
//
// So there is one list, and an entry says what it is BY ITS SHAPE:
//
//   `/scim`, `/admin-api`   a PATH PREFIX — it starts with a slash
//   `ldap`, `ldap.search`   an OPERATION KIND — `family` or `family.operation`
//   `*`                     EVERYTHING, of both kinds
//
// **THE LEADING SLASH IS THE WHOLE DISCRIMINATOR AND IT NEEDED NO MIGRATION.**
// Every value this setting has ever held is a path prefix beginning with `/` or
// the `*` wildcard, so a configuration written before the merge means exactly
// what it used to mean. An operation kind cannot begin with a slash — it is a
// module's own name for a unit of work — and a path prefix cannot not, because
// `matchesAny()` compares it against `req.url`.
//
// **`*` NOW REACHES OPERATIONS TOO, WHICH IS A REAL BEHAVIOUR CHANGE AND IS
// THE POINT RATHER THAN A SIDE EFFECT.** It meant "every path" and means
// "everything"; a wildcard that quietly excluded a whole class of work would be
// the artificial distinction surviving the settings it was named after. An
// operator who wants paths and not operations names the paths, which is what
// the list is for.
// ---------------------------------------------------------------------------
function dispatchList() {
  log.debug("Entering dispatchList().");
  let raw;
  try {
    raw = config.value('workers.dispatch');
  } catch (e) {
    log.debug("Caught in dispatchList(): " + ((e && e.message) || e));
    log.debug("Leaving dispatchList().");
    return [];
  }
  if (!raw) {
    log.debug("Leaving dispatchList().");
    return [];
  }
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  log.debug("Leaving dispatchList().");
  return list.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
}

// An entry that names a URL. `*` is in BOTH halves because it names everything,
// and it has to be in this one for `dispatched()`'s wildcard branch to see it.
function dispatchPrefixes() {
  log.debug("Entering dispatchPrefixes().");
  log.debug("Leaving dispatchPrefixes().");
  return dispatchList().filter(function (one) {
    return one === '*' || one.charAt(0) === '/';
  });
}

// ---------------------------------------------------------------------------
// WHICH DISPATCHED PATHS FAN OUT, AND WHY THE LIST IS OF THE EXCEPTIONS.
//
// Everything dispatched holds AFFINITY unless it is named here, and the default
// is the right way round: a protocol subsystem carries a browser flow across
// several requests and belongs on one worker; the four that do not are the
// exception and are short enough to write down.
//
// `/scim/v2`, `/xacml` and `/admin-api` carry their own credential on every
// request and name their own target, so nothing about one request has to be
// remembered to answer the next.
//
// **LDAP IS NOT IN THIS LIST AND CANNOT BE**, which is worth saying because it
// belongs in the same sentence as the other three and behaves the same way. Its
// protocol is raw TCP on 389 and 636 — a socket the front process holds, with
// no HTTP request to route anywhere — and every HTTP view it has is a console
// page under `/admin/ldap/*`, which is the admin UI and therefore holds
// affinity like the rest of the console.
// ---------------------------------------------------------------------------
function fanoutPrefixes() {
  log.debug("Entering fanoutPrefixes().");
  let raw;
  try {
    raw = config.value('workers.fanout');
  } catch (e) {
    log.debug("Caught in fanoutPrefixes(): " + ((e && e.message) || e));
    log.debug("Leaving fanoutPrefixes().");
    return [];
  }
  if (!raw) {
    log.debug("Leaving fanoutPrefixes().");
    return [];
  }
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  log.debug("Leaving fanoutPrefixes().");
  return list.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
}

function matchesAny(url, prefixes) {
  log.debug("Entering matchesAny().");
  if (!prefixes.length) {
    log.debug("Leaving matchesAny().");
    return false;
  }
  let pathOnly = String(url || '').split('?')[0];
  const realmed = pathOnly.match(/^\/realm\/[^/]+(\/.*)?$/);
  if (realmed) {
    pathOnly = realmed[1] || '/';
  }
  for (let i = 0; i < prefixes.length; i++) {
    const prefix = prefixes[i];
    if (pathOnly === prefix || pathOnly.indexOf(prefix + '/') === 0) {
      log.debug("Leaving matchesAny().");
      return true;
    }
  }
  log.debug("Leaving matchesAny().");
  return false;
}

// Whether this request fans out. A dispatched path that is NOT named fans in —
// it holds affinity — which is the way round the header above argues for.
function fansOut(url) {
  log.debug("Entering fansOut().");
  log.debug("Leaving fansOut().");
  return matchesAny(url, fanoutPrefixes());
}

// ---------------------------------------------------------------------------
// THE BATCH LANE (2026-09-14): batch traffic may use a SHARE of a pool's
// workers and a number of requests in flight, and waits in this process for
// the rest.
//
// What it is for, measured: a dispatch run's SCIM bulk load wrote one person at
// a time, and every write emitted two Shared Signals events to forty-two push
// streams — forty of them another realm's receivers by a replication defect
// since fixed, but the shape is what matters — so each create became eighty-
// four pushes, most of them back into this service's own receive endpoints.
// Every worker filled, the read barrier waited on workers that could not
// answer, and nothing at all was answered for fourteen minutes. A batch client
// deserves throughput; it does not deserve every worker.
//
// **TWO LIMITS, BECAUSE ONE CANNOT DO BOTH JOBS.** The SHARE confines batch
// traffic to some workers, so the others are free for everything else — which
// is the whole point with a pool of several. The CONCURRENCY cap bounds how
// much of that share is in flight, which is the whole point with a pool of one
// (the surface pool in the suite's dispatch mode), where the share cannot leave
// anything free.
//
// **A BOUND REQUEST KEEPS ITS WORKER.** `mutationKeyOf()` sends every write to
// one SCIM resource to one worker so two read-modify-writes cannot lose an
// update, and a credential or session binding is locality the caller is
// relying on. The lane decides only where an UNBOUND batch request goes, and
// the cap queues rather than reroutes, so no binding is broken by it.
//
// **WHAT WAITS IS PIPED LATER, NOT BUFFERED.** A queued request's body stays
// in its socket until it is dispatched; what this process holds is a closure.
// The queue is bounded (`workers.batchQueueLimit`) and so is the wait
// (`workers.batchQueueTimeoutS`), and both answer 503 with Retry-After — a
// refusal a batch client is built to handle, where a request held for ever is
// not. A client that goes away while waiting is dropped from the queue.
// ---------------------------------------------------------------------------
function batchPrefixes() {
  log.debug("Entering batchPrefixes().");
  let raw;
  try {
    raw = config.value('workers.batch');
  } catch (e) {
    log.debug("Caught in batchPrefixes(): " + ((e && e.message) || e));
    log.debug("Leaving batchPrefixes().");
    return [];
  }
  const list = Array.isArray(raw) ? raw : String(raw || '').split(',');
  log.debug("Leaving batchPrefixes().");
  return list.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.charAt(0) === '/';
  });
}

function isBatch(url) {
  log.debug("Entering isBatch().");
  log.debug("Leaving isBatch().");
  return matchesAny(url, batchPrefixes());
}

function batchNumber(key, fallback) {
  log.debug("Entering batchNumber(). " + key);
  let raw;
  try {
    raw = Number(config.value(key));
  } catch (e) {
    log.debug("Caught in batchNumber(): " + ((e && e.message) || e));
    raw = NaN;
  }
  log.debug("Leaving batchNumber().");
  return Number.isFinite(raw) ? raw : fallback;
}

// How many of `count` workers batch traffic may use. At least one; one fewer
// than the pool unless the pool has one worker or the share is 100.
function laneSize(count, share) {
  log.debug("Entering laneSize().");
  if (count <= 1) {
    log.debug("Leaving laneSize(). One worker.");
    return count;
  }
  const pct = Math.min(100, Math.max(1, Number(share) || 50));
  // Below 100% the floor is always fewer than `count`, so a worker is left.
  const n = Math.max(1, Math.floor(count * pct / 100));
  log.debug("Leaving laneSize(). " + n + " of " + count + ".");
  return n;
}

// The ready workers of a pool batch traffic may be routed to. The FIRST ones
// by fork order, so the lane is stable across requests and a batch client's
// binding lands on a worker the lane will keep.
function laneOf(ready) {
  log.debug("Entering laneOf().");
  const live = (ready || []).slice().sort(function (a, b) {
    return (a.startedAt || 0) - (b.startedAt || 0) || a.pid - b.pid;
  });
  const out = live.slice(0, laneSize(live.length,
    batchNumber('workers.batchWorkerShare', 50)));
  log.debug("Leaving laneOf(). " + out.length + ".");
  return out;
}

function laneWorkers(pool) {
  log.debug("Entering laneWorkers().");
  log.debug("Leaving laneWorkers().");
  return laneOf(readyWorkers(pool));
}

// Per pool: how many batch requests are in flight, and who is waiting.
const batchState = new Map();

function batchStateOf(pool) {
  log.debug("Entering batchStateOf().");
  const which = pool || PROTOCOL_POOL;
  if (!batchState.has(which)) {
    batchState.set(which, { inFlight: 0, waiting: [], refused: 0,
                            timedOut: 0, queuedEver: 0 });
  }
  log.debug("Leaving batchStateOf().");
  return batchState.get(which);
}

function batchCap(pool) {
  log.debug("Entering batchCap().");
  const per = batchNumber('workers.batchConcurrency', 8);
  if (!(per > 0)) {
    log.debug("Leaving batchCap(). Uncapped.");
    return 0;
  }
  log.debug("Leaving batchCap().");
  return Math.max(1, laneWorkers(pool).length) * Math.floor(per);
}

function refuseBatch(res, code, why) {
  log.debug("Entering refuseBatch(). " + code);
  if (res.headersSent || res.writableEnded) {
    log.debug("Leaving refuseBatch(). Already answered.");
    return;
  }
  errorCodes.mark(res, code);
  // error-code: none — the caller names STS-WORKER-0040 or -0041, marked above
  res.status(503);
  res.set('Retry-After', '5');
  res.type('text/plain');
  res.send('This service is busy with batch traffic (' + why + '). Try ' +
           'again after the Retry-After interval.\n');
  log.debug("Leaving refuseBatch().");
}

// Run `dispatch(release)` when the pool's lane has room, or queue it. `release`
// must be called exactly once when the dispatched request is finished.
function admitBatch(pool, req, res, dispatch) {
  log.debug("Entering admitBatch().");
  const state = batchStateOf(pool);
  let released = false;
  const release = function () {
    log.debug("Entering release().");
    if (released) {
      log.debug("Leaving release(). Twice.");
      return;
    }
    released = true;
    state.inFlight = Math.max(0, state.inFlight - 1);
    drainBatch(pool);
    log.debug("Leaving release().");
  };
  const cap = batchCap(pool);
  if (!cap || state.inFlight < cap) {
    state.inFlight += 1;
    log.debug("Leaving admitBatch(). Dispatched at once.");
    dispatch(release);
    return;
  }
  const limit = Math.max(1, batchNumber('workers.batchQueueLimit', 5000));
  if (state.waiting.length >= limit) {
    state.refused += 1;
    warnSparingly('STS-WORKER-0040', 'request_pool: the ' + pool + ' pool\'s ' +
                  'batch lane is full — ' + state.inFlight + ' in flight, ' +
                  state.waiting.length + ' waiting (workers.batchQueueLimit=' +
                  limit + ') — so a batch request was answered 503.');
    refuseBatch(res, 'STS-WORKER-0040', state.waiting.length +
                ' batch requests are already waiting');
    log.debug("Leaving admitBatch(). Refused; the queue is full.");
    return;
  }
  const entry = { at: Date.now(), dispatch: dispatch, release: release,
                  gone: false, res: res };
  const timeoutS = Math.max(1, batchNumber('workers.batchQueueTimeoutS', 60));
  entry.timer = setTimeout(function () {
    const at = state.waiting.indexOf(entry);
    if (at < 0) {
      return;
    }
    state.waiting.splice(at, 1);
    state.timedOut += 1;
    warnSparingly('STS-WORKER-0041', 'request_pool: a batch request waited ' +
                  timeoutS + 's for the ' + pool + ' pool\'s batch lane ' +
                  '(workers.batchQueueTimeoutS) and was answered 503; ' +
                  state.waiting.length + ' still waiting.');
    refuseBatch(res, 'STS-WORKER-0041', 'it waited ' + timeoutS + 's');
  }, timeoutS * 1000);
  if (entry.timer.unref) {
    entry.timer.unref();
  }
  // A client that goes away while waiting leaves the queue.
  res.on('close', function () {
    if (!res.writableEnded && state.waiting.indexOf(entry) >= 0) {
      state.waiting.splice(state.waiting.indexOf(entry), 1);
      clearTimeout(entry.timer);
    }
  });
  state.waiting.push(entry);
  state.queuedEver += 1;
  log.debug("Leaving admitBatch(). Queued behind " +
            (state.waiting.length - 1) + ".");
}

function drainBatch(pool) {
  log.debug("Entering drainBatch().");
  const state = batchStateOf(pool);
  let started = 0;
  while (state.waiting.length) {
    const cap = batchCap(pool);
    if (cap && state.inFlight >= cap) {
      break;
    }
    const next = state.waiting.shift();
    clearTimeout(next.timer);
    if (next.res.writableEnded || next.res.destroyed) {
      continue;
    }
    state.inFlight += 1;
    started += 1;
    next.dispatch(next.release);
  }
  log.debug("Leaving drainBatch(). " + started + " started.");
}

// For stats(): each pool's lane, as numbers.
function batchStats() {
  log.debug("Entering batchStats().");
  const out = {};
  [PROTOCOL_POOL, SURFACE_POOL].forEach(function (pool) {
    const state = batchStateOf(pool);
    out[pool] = { inFlight: state.inFlight, waiting: state.waiting.length,
      cap: batchCap(pool), laneWorkers: laneWorkers(pool).map(function (one) {
        return one.pid;
      }), queuedEver: state.queuedEver, refused: state.refused,
      timedOut: state.timedOut };
  });
  log.debug("Leaving batchStats().");
  return out;
}

// The prefixes the hosted-surface pool answers. Read the way the fanout list
// is, for the same reasons; see the `workers.surfaces` row for why the default
// stops at `/admin` and `/portal` and does not take `/admin-api`.
function surfacePrefixes() {
  log.debug("Entering surfacePrefixes().");
  let raw;
  try {
    raw = config.value('workers.surfaces');
  } catch (e) {
    log.debug("Caught in surfacePrefixes(): " + ((e && e.message) || e));
    log.debug("Leaving surfacePrefixes().");
    return [];
  }
  if (!raw) {
    log.debug("Leaving surfacePrefixes().");
    return [];
  }
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  log.debug("Leaving surfacePrefixes().");
  return list.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.charAt(0) === '/';
  });
}

// ---------------------------------------------------------------------------
// WHICH POOL A DISPATCHED REQUEST GOES TO.
//
// A question asked only AFTER `dispatched()` has said yes: the one list still
// decides whether a path leaves the front process, and this decides where it
// lands. The same `matchesAny()` as every other prefix here, so the realm
// segment is removed and a prefix ends at a segment boundary — `/admin` does
// not take `/admin-api`, which is the bug `tests/request_routing.js` was
// written for, met a second time in a second list.
//
// **A POOL OF NONE IS NOT A POOL.** With `workers.surfaceCount` at 0 the
// surfaces go to the protocol pool, which is where they always went. And a
// surface pool that GAVE UP — workers that could not start — hands them back
// to the protocol pool too, rather than refusing them for the life of the
// process: it is a decision taken once, logged loudly at `STS-WORKER-0023`,
// and stable from then on, so it is not the timing-dependent half-dispatch the
// header at the top of this file refuses.
// ---------------------------------------------------------------------------
function poolFor(url) {
  log.debug("Entering poolFor().");
  if (size(SURFACE_POOL) > 0 && !givenUp[SURFACE_POOL] &&
      matchesAny(url, surfacePrefixes())) {
    log.debug("Leaving poolFor(). " + SURFACE_POOL);
    return SURFACE_POOL;
  }
  log.debug("Leaving poolFor(). " + PROTOCOL_POOL);
  return PROTOCOL_POOL;
}

// Whether this request is one the pool handles. The REALM PREFIX is stripped
// before the comparison, because a prefix names a protocol surface and
// `/realm/acme/scim/v2` is the same surface as `/scim/v2` — the whole point of
// the realm design is that no route registration carries a realm, and a
// dispatch list that had to name every realm would be the first thing in this
// service that did.
// ---------------------------------------------------------------------------
// `*` MEANS EVERY PATH, and it is how "all protocol requests are processed in
// the worker pool" is actually said.
//
// Naming the families instead was the first version and it is a list that goes
// stale by construction: a protocol family added later would keep running in
// the front process until somebody remembered this setting, and nothing would
// report it. `*` inverts that — everything is dispatched, and what stays behind
// is the short list below, which is short because it is the things that CANNOT
// move rather than the things nobody got round to.
//
// **WHAT CANNOT MOVE, AND WHY EACH ONE.**
//
//   * `/tls` — its whole content is what the SERVER saw of the connection the
//     request arrived on. Proxied, it would report the unix socket between the
//     front process and a worker, which is not a fact about the caller at all.
//     The client certificate is forwarded and that is a different thing: it is
//     what the CLIENT presented, and the surfaces that read it are asking about
//     the client. `/tls` is asking about the socket.
//
// Nothing else is excluded, and in particular the mTLS surfaces are NOT — the
// certificate travels in a header and is put back on the request before the
// app sees it, so `mtls.js`, `scim_auth.js` and `/xacml/pep/*` behave in a
// worker exactly as they do here.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// SPIFFE WAS ON THIS LIST FOR AN HOUR AND IS NOT ANY MORE (2026-09-08), and
// the round trip is worth recording because it is the difference between
// routing around a problem and fixing one.
//
// The problem was real: SPIFFE's four sockets are bound by the front process
// alone, its X.509 SVIDs are signed by the authority that process built, and
// that authority was two module ARRAYS — so a worker answering `GET /spiffe`
// published keys that verified none of the SVIDs actually issued, and
// `/admin/spiffe`'s Rotate button rotated a CA that signs nothing.
//
// Pinning the three prefixes here fixed the symptom by sending those requests
// to the process that happened to hold the state. What it did not fix is that
// the state was private at all, and the cost was a feature serialised through
// one process for no reason anybody would find in the specification.
//
// `spiffe_ca.js` shares the authority now — one trust domain for the service,
// `certificateDer` base64 on the way into the journal — so every process
// answers the same bundle and a rotation from any of them is the service's.
// The pins came off with it. `tests/request_routing.js` asserts they are off
// and `tests/spiffe_authority.js` asserts the sharing that replaced them.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AND THE CLIENT-CERTIFICATE TRUSTSTORE'S TWO GATED DOORS ARE (2026-09-12):
// `/admin/tls/trust` and `/admin-api/tls/trust`.
//
// **THIS IS THE SOCKET ARGUMENT A THIRD TIME AND NOT SPIFFE'S ROUTE AROUND
// ONE**, and the difference is the whole of why the pin is right here when
// SPIFFE's came off after an hour. SPIFFE's authority was STATE that happened
// to be private — two module arrays — and the fix was to make it a row every
// process shares. The truststore is not state in that sense. It is the
// CONFIGURATION OF A LISTENER: the `ca` half of the secure context 8443, 9443,
// LDAPS 636 and the main port were created with, applied by
// `setSecureContext()` on server objects only the front process holds. A
// worker has the same module loaded and its own copy of the array, and
// changing that copy changes nothing any handshake reads — so an add answered
// there would report success about a listener nothing is listening on, and a
// read answered there would list an array no connection is verified against.
//
// **SHARING IT WOULD NOT HAVE FIXED THAT, WHICH IS WHY IT IS PINNED AND NOT A
// ROW.** `tls/tls_server.js`'s note above `anchors` records that it WAS briefly
// a shared, persisted store, and that it implied a sharing that did not happen:
// even with every process holding the same list, the list only matters in the
// one process that can apply it, and that process is where the request has to
// be answered. It is the shape the listener CERTIFICATE took beside it
// (`reconcileTheListener()` below): the decision is the front process's alone.
//
// Both paths, and only those two. `/admin/tls` beside them is the listeners'
// SETTINGS page, which is ordinary configuration read out of the store and is
// dispatched with the rest of the console; `matchesAny()` stops at a segment
// boundary, so neither `/admin/tls` nor `/admin-api/tlsx` is caught by these,
// and the realm prefix and the query string are stripped before the compare.
// What it costs is that those two pages take the front process's affinity
// rather than the console's: their session is read out of the store, where a
// console session minted by a worker arrives by replication.
//
// **THE EMBEDDED DEBUGGER'S STATUS IS THE SAME SHAPE OF FACT (2026-09-13).**
// Its listener and its api child are held by the front process only
// (`debugger/debugger_api_process.js`), so `/admin/debugger` and
// `GET /admin-api/debugger` answered by a worker would report a listener that
// never bound and a child that was never forked. Pinned for that reason; the
// settings drawn on that page are ordinary configuration either way.
// ---------------------------------------------------------------------------
const NEVER_DISPATCHED = ['/tls', '/admin/tls/trust', '/admin-api/tls/trust',
                          '/admin/debugger', '/admin-api/debugger'];

function dispatched(url) {
  log.debug("Entering dispatched().");
  // A SEGMENT BOUNDARY RATHER THAN A BARE PREFIX, and the loose version was
  // written first and was wrong: `/admin` as a prefix also matched
  // `/admin-api`, so naming the console would have silently dragged the
  // management API onto the affinity side of the routing with it. `/admin/` and
  // an exact `/admin` are what a path prefix means.
  const prefixes = dispatchPrefixes();
  if (!prefixes.length) {
    log.debug("Leaving dispatched().");
    return false;
  }
  if (matchesAny(url, NEVER_DISPATCHED)) {
    log.debug("Leaving dispatched().");
    return false;
  }
  if (prefixes.indexOf('*') >= 0) {
    log.debug("Leaving dispatched().");
    return true;
  }
  log.debug("Leaving dispatched().");
  return matchesAny(url, prefixes);
}

// ---------------------------------------------------------------------------
// Where the sockets live. One directory per process, owner-only, removed on the
// way out — so two copies of this service on one machine cannot meet, and a
// socket is never left in a place another user can reach.
// ---------------------------------------------------------------------------
function ensureSocketDir() {
  log.debug('Entering ensureSocketDir().');
  if (socketDir) {
    log.debug('Leaving ensureSocketDir(). Already made.');
    return socketDir;
  }
  let base = '';
  try {
    base = String(config.value('workers.socketDir') || '');
  } catch (e) {
    log.debug("Caught in ensureSocketDir(): " + ((e && e.message) || e));
    base = '';
  }
  base = base || os.tmpdir();
  socketDir = fs.mkdtempSync(path.join(base, 'sts-workers-'));
  try {
    fs.chmodSync(socketDir, 0o700);
  } catch (e) {
    // See request_worker.js: a filesystem that does not carry modes is not a
    // reason to refuse to serve, and the socket itself is narrowed too.
    log.warn(errorCodes.tag('STS-WORKER-0010') +
             'request_pool: could not narrow the mode on ' + socketDir + ': ' +
             e.message);
  }
  log.debug('Leaving ensureSocketDir(). ' + socketDir);
  return socketDir;
}

// ---------------------------------------------------------------------------
// Forking one worker. It answers with `ready` when its socket is up, and this
// promise is what `start()` waits on — a worker that is forked and not yet
// listening must never be routed to.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE FRONT PROCESS IS THE KEY REGISTRY, AND FIRST GENERATOR WINS.
//
// A realm created at runtime is generated independently by every process whose
// realm watcher reaches it (helpers.js's warmPqKeys()), so somebody has to
// decide which of N key sets the service actually has. The parent does: it
// keeps the first it is told about, hands it to everybody else, and tells a
// late publisher to throw its own away.
//
// The parent's OWN generation goes through the same door — `setKeyPublisher()`
// below is what helpers.js calls there — so there is one path and not two.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A WORKER HAS COMMITTED, AND ONLY NOW IS EVERY OTHER WORKER BEHIND
// (2026-09-07).
//
// proxy() used to bump the generation when a write-method request FINISHED, on
// the premise that the write was in the change log by then. It was not:
// `persistence.js` schedules its flush a tick later, so the bump named a write
// that had not landed and a reader was told it was current before it could
// possibly have seen it.
//
// The obvious repair — make the worker flush before answering — was measured
// and rejected: `persistence.flush()` walks the whole directory to diff it, so
// a per-request flush is quadratic over a bulk load (50.9ms per SCIM create at
// the 500th, 75.4ms at the 1,500th, against 3.3ms in one process).
//
// So the worker answers at once and announces the SEQUENCE its flush reached
// when it reaches it. The generation moves then. A reader that arrives in
// between is behind by one generation and waits at the barrier it already
// runs — which is the same wait as before, on the side that was already paying
// it, and no writer blocks on a store.
//
// **THE WORKER THAT WROTE IS MOVED FORWARD WITH IT**, exactly as proxy() did:
// it has the write in its own memory and must not be sent to fetch it.
// ---------------------------------------------------------------------------
function receiveCommitted(entry, committed) {
  log.debug("Entering receiveCommitted().");
  if (!readYourWrite()) {
    log.debug("Leaving receiveCommitted().");
    return;
  }
  // THE GENERATION MOVES ONLY WHEN SOMETHING WAS WRITTEN. Bumping it for a
  // request that wrote nothing marks every other worker stale and sends the
  // next request to each of them through a barrier with nothing to apply —
  // which, once every request began announcing, was nearly every request.
  //
  // **AND THE ANNOUNCER IS MOVED FORWARD ONLY IF IT WAS ALREADY CURRENT
  // (2026-09-13).** It has its OWN write in memory; it does not have a write
  // another worker announced that it was never synced for. Stamping it with the
  // new generation regardless marked it current for those too, so its next
  // read went out without a barrier — and a worker that answers most of the
  // writes (every `/admin-api` call carrying one shared token lands on one)
  // is exactly the worker whose reads were then never synced. Found by the
  // `sts_global_logout` investigation: a sign-out answered by that worker read
  // a session store missing a sign-in another worker had committed.
  if ((committed || {}).wrote) {
    const wasCurrent = entry.generation >= generation;
    generation++;
    if (wasCurrent) {
      entry.generation = generation;
    }
  }
  // EVERY TICKET THIS WORKER OWED IS SATISFIED: it has just told us the
  // sequence its flush reached, and its flush covers everything it had
  // answered up to that point.
  // ONLY WHAT THE FLUSH ACTUALLY COVERED. Tickets are taken at DISPATCH, so a
  // worker owes tickets for requests still IN FLIGHT — and clearing those on an
  // earlier request's announcement is the bug this replaces: the write had not
  // happened yet, so a reader was released against a ticket that guaranteed
  // nothing. `through` is the number of responses the worker had finished when
  // its flush started; a ticket numbered at or below it is covered.
  // THE WORKER NAMES THEM. It knows which responses it had finished when its
  // flush started, because each one carried its ticket in a header — so this is
  // an exact set rather than a count compared against an ordinal this process
  // guessed. See ticketFinished() above for what the guess cost.
  const covered = (committed || {}).tickets;
  if (Array.isArray(covered) && entry.tickets) {
    covered.forEach(function (t) {
      const ticket = Number(t);
      if (!entry.tickets.has(ticket)) {
        return;
      }
      outstanding.delete(ticket);
      finishedTickets.delete(ticket);
      finishedAt.delete(ticket);
      entry.tickets.delete(ticket);
    });
  }
  releaseTicketWaiters();
  log.debug('receiveCommitted(): worker ' + entry.pid + ' committed at seq ' +
            entry.committedSeq + '; generation is now ' + generation + '.');
  log.debug("Leaving receiveCommitted().");
}

function receivePublishedKeys(entry, published) {
  log.debug("Entering receivePublishedKeys().");
  if (!published || !published.realm || !published.blob) {
    log.debug("Leaving receivePublishedKeys().");
    return;
  }
  const realmId = String(published.realm);
  // AN ENRICHMENT IS ACCEPTED FOR A REALM ALREADY HELD, and is not the race.
  // `pqKeysForAsync()` adds a realm's post-quantum keys after the set was first
  // published, so the second publish carries the SAME certificate and more
  // content. keystore.adoptShared() takes it (publishShared() decides), and it
  // has to be broadcast or only the process that warmed them has them.
  //
  // **THE RULE IS `keystore.enriches()` AND NOT A COPY OF IT (2026-09-12).** It
  // was written out here with one member — the post-quantum count — and the
  // OpenID4VCI request-encryption key joined the set that day, backfilled on a
  // set written before it existed. Two copies of the rule is how the offering
  // process and this one come to disagree about what a race is.
  const heldBlob = keystore.sharedBlobFor(realmId);
  const enriches = keystore.enriches(published.blob, heldBlob);
  // -------------------------------------------------------------------------
  // **A CONFIRMED SET IS THE STORE'S ANSWER AND IS NEVER ARBITRATED HERE
  // (2026-09-14, #46).** Where the keystore persists to a store that can
  // arbitrate, a worker whose write found another set in the row adopts that
  // set and publishes it marked `confirmed`. First-heard-wins below would
  // otherwise tell the process that just adopted the store's set to take the
  // one THIS process heard about first — a set the store has already refused —
  // and the two arbiters would disagree for as long as they kept exchanging
  // it. The store decides for every node; this channel only carries it.
  // -------------------------------------------------------------------------
  if (published.confirmed) {
    keystore.adoptShared(realmId, published.blob);
    log.info('request_pool: the "' + realmId + '" realm\'s key set was ' +
             'confirmed by the store through worker ' + (entry && entry.pid) +
             '; every process here now uses it.');
    broadcastKeys(realmId, published.blob, entry);
    log.debug("Leaving receivePublishedKeys().");
    return;
  }
  if (enriches) {
    keystore.adoptShared(realmId, published.blob);
    log.info('request_pool: the "' + realmId + '" realm\'s key set was ' +
             'enriched by worker ' + (entry && entry.pid) + ' (its ' +
             'post-quantum keys or its request-encryption key); every ' +
             'process here now uses them.');
    broadcastKeys(realmId, published.blob, entry);
    log.debug("Leaving receivePublishedKeys().");
    return;
  }
  const held = heldBlob ? true : false;
  if (!held) {
    keystore.adoptShared(realmId, published.blob);
    log.info('request_pool: worker ' + (entry && entry.pid) + ' generated ' +
             'the ' +
             '"' + realmId + '" realm\'s signing keys; every process here ' +
             'now uses them.');
    broadcastKeys(realmId, published.blob, entry);
    log.debug("Leaving receivePublishedKeys().");
    return;
  }
  // SOMEBODY ELSE GOT THERE FIRST. The publisher is told what the answer is and
  // discards what it made — the microseconds between generating and publishing
  // are the one window in which two processes disagree, and anything signed in
  // it is lost. That is the price of a synchronous property read that cannot
  // await, and it is written down rather than discovered.
  sendKeys(entry, realmId);
  log.debug("Leaving receivePublishedKeys().");
}

// ---------------------------------------------------------------------------
// THE DIRECTORY HALF OF THE POOL (2026-09-09), AND IT IS TWO WAYS ROUND.
//
// The front process holds the LDAP listeners and therefore every bound
// connection; a request worker holds the session that decides one should end.
// So the LIST goes out to the workers and the INSTRUCTION comes back:
//
//   publishDirectoryConnections()   here → every worker, on every change
//   closeDirectoryConnections()     a worker → here, on the response it rode
//
// `ldap_server.js` IS REQUIRED LAZILY, INSIDE BOTH, and that is a rule rather
// than a convenience: this module is loaded by `server.js` before the protocol
// stack and by `request_worker.js` as part of it, and a require at the top of
// this file would pull the whole directory — and its eight `/admin/ldap/*`
// console pages — into the router at a point of its own choosing. The same
// lazy-require-inside-the-one-function shape `xacml_admin.js` uses on
// `xacml.js`, for the same reason. By the time either of these runs the module
// is loaded and it is a cache hit.
// ---------------------------------------------------------------------------
function directory() {
  log.debug("Entering directory().");
  log.debug("Leaving directory().");
  return require('../ldap/ldap_server');
}

function publishDirectoryConnections(rows) {
  log.debug("Entering publishDirectoryConnections().");
  const snapshot = rows || [];
  workers.forEach(function (one) {
    if (!one.child || !one.child.connected) {
      return;
    }
    try {
      one.child.send({ ldapConnections: snapshot });
    } catch (e) {
      // A worker that is on its way out. It will be replaced with a fresh
      // snapshot at fork; what is lost meanwhile is one sign-out's view of the
      // directory in a process that is about to stop answering.
      log.debug('request_pool: could not publish directory connections to ' +
                'worker ' + one.pid + ': ' + e.message);
    }
  });
  log.debug("Leaving publishDirectoryConnections().");
}

// Called with whatever the worker put in the header — one or more identity
// keys, comma separated and percent-encoded, because a key is a username and a
// header is bytes.
function closeDirectoryConnections(header) {
  log.debug("Entering closeDirectoryConnections().");
  const raw = String(header || '');
  if (!raw) {
    log.debug("Leaving closeDirectoryConnections().");
    return;
  }
  raw.split(',').forEach(function (encoded) {
    let key = '';
    try {
      key = decodeURIComponent(encoded.trim());
    } catch (e) {
      // Not percent-encoding. The worker wrote this header, so this is a bug
      // here rather than input from anywhere — said out loud rather than
      // silently closing nothing.
      log.warn(errorCodes.tag('STS-WORKER-0011') +
               'request_pool: a worker asked for a directory sign-out with a ' +
               'key this process could not decode (' + encoded + '): ' +
               e.message);
      return;
    }
    if (!key) {
      return;
    }
    try {
      // LOCAL ONLY (2026-09-14, #46): the worker that answered the sign-out
      // already wrote the instruction every other node acts on, inside the
      // commit its response was held for; writing it again from here would be
      // a second change row outside any request.
      const dropped = directory().dropConnectionsFor(key, { localOnly: true });
      log.info('request_pool: a request worker signed ' + key + ' out of the ' +
               'directory; ' + dropped.length + ' connection(s) closed in ' +
               'this process, which is the one holding them.');
    } catch (e) {
      log.warn(errorCodes.tag('STS-WORKER-0012') +
               'request_pool: could not close the directory connections a ' +
               'worker asked to end for ' + key + ': ' + e.message);
    }
  });
  log.debug("Leaving closeDirectoryConnections().");
}

function broadcastKeys(realmId, blob, except) {
  log.debug("Entering broadcastKeys().");
  workers.forEach(function (other) {
    if (other === except || !other.child || !other.child.connected) {
      return;
    }
    try {
      other.child.send({ adoptKeys: { realm: realmId, blob: blob } });
    } catch (e) {
      log.warn(errorCodes.tag('STS-WORKER-0013') +
               'request_pool: could not hand the "' + realmId + '" realm\'s ' +
               'keys to worker ' + other.pid + ': ' + e.message);
    }
  });
  log.debug("Leaving broadcastKeys().");
}

// ---------------------------------------------------------------------------
// A CERTIFICATE AUTHORITY BUILT SOMEWHERE ELSE IN THIS SERVICE.
//
// **NO ARBITRATION, WHICH IS THE ONE WAY THIS DIFFERS FROM THE KEY CHANNEL
// ABOVE.** `receivePublishedKeys()` decides a RACE — several processes
// generating one realm's signing keys at once, because each one's realm
// watcher reached the realm independently — and first-generator-wins is what
// keeps them agreeing. Nothing races here: a hierarchy exists because an
// operator pressed a button, on one worker, once. So the last write wins and
// every other process adopts it, which is also what makes REBUILDING one work
// — under arbitration the rebuild would lose to the hierarchy it replaced.
//
// `chain` is null for a removal and is forwarded as such: a worker still
// holding a CA that was thrown away would go on issuing certificates that
// chain to nothing anybody here will accept.
// ---------------------------------------------------------------------------
function receivePublishedPki(entry, published) {
  log.debug("Entering receivePublishedPki().");
  if (!published || published.realm === undefined) {
    log.debug("Leaving receivePublishedPki().");
    return;
  }
  const realmId = String(published.realm);
  keystore.adoptPki(realmId, published.chain || null);
  log.info('request_pool: the "' + realmId + '" realm\'s certificate ' +
           'authority was ' + (published.chain ? 'built' : 'removed') +
           ' by worker ' + (entry && entry.pid) + '; every process here now ' +
           'agrees.');
  broadcastPki(realmId, published.chain || null, entry);
  // -------------------------------------------------------------------------
  // **AND THE SOCKET (2026-09-12). AGREEING ABOUT THE HIERARCHY IS NOT THE
  // SAME AS SERVING A CERTIFICATE THAT CHAINS TO IT.**
  //
  // The line above shares the CA material, which is a row and travels the way
  // every other row does. The TLS listener is not a row — it is a socket this
  // process holds and no worker can reach — so a `build-root` that landed on a
  // worker left the front process presenting a leaf under a Root that no
  // longer exists anywhere in the service. `GET /tls/server-certificate` then
  // publishes no anchor (tls_server.js's trustAnchorPems() refuses to, and is
  // right to), and every client that had fetched one fails with `unable to get
  // local issuer certificate`: on 2026-09-12 that was six jobs of the suite's
  // dispatch mode, none of which names a certificate.
  //
  // This is the same rule the LDAP connection list established and it is the
  // SECOND thing to need it, which the root CLAUDE.md said would take the
  // argument being made again rather than the mechanism being copied. The
  // shapes differ accordingly: the directory needed a MIRROR pushed out and an
  // instruction sent back, because the decision is a worker's; here the
  // decision is this process's alone — it owns the certificate — so nothing
  // comes back and what goes out is the result.
  //
  // `reconcileWithHierarchy()` does nothing when the certificate still chains,
  // which is every publish but the rare one.
  // -------------------------------------------------------------------------
  reconcileTheListener();
  log.debug("Leaving receivePublishedPki().");
}

// The asynchronous half of the block above, kept out of it so that
// receivePublishedPki() stays a message handler. Nothing waits for this: the
// hierarchy is already shared, and what this adds is a certificate — a worker
// that is handed the new one a few milliseconds late pins the old one for those
// milliseconds, which is the state it was in before this existed.
//
// ---------------------------------------------------------------------------
// **ONE PASS AT A TIME, AND IT WAITS FOR A BRANCH RATHER THAN BUILDING ONE
// (2026-09-13).** Two things were wrong with calling the reconcile bare on
// every publish, and `tests/listener_branch_adoption.js` pins both.
//
//   * **PASSES OVERLAPPED.** A worker publishes a scope's row once per save —
//     a realm build is a dozen — and each started a pass. A pass issuing from
//     the branch it read while a newer branch was adopted underneath it could
//     finish AFTER the pass for the newer one, and put the older leaf back on
//     the socket with nothing left to trigger another. So a call while a pass
//     is running asks for ONE more after it, which re-reads what is held.
//   * **A ROOT ARRIVES AHEAD OF ITS BRANCHES.** `build-root` on a worker
//     publishes the Root, then rebuilds and publishes each branch. The
//     reconcile used to rebuild the process branch here as soon as the Root
//     landed — the same branch that worker was building — and the service
//     ended up serving one Intermediate CA (Process) and publishing another.
//     So a publish-triggered pass passes `buildBranch: false`, and where the
//     listener is left waiting a FALLBACK pass that may build is armed for
//     `LISTENER_BRANCH_GRACE_MS`, for the case where the branch never comes
//     (a worker whose branch rebuild failed logs `STS-PKI-0104` and moves on).
//     A pass that finds the listener current disarms it.
// ---------------------------------------------------------------------------
// Long enough for a worker to build a branch under the slowest key algorithm
// `/admin/pki` offers, and short next to leaving a listener stale for good.
const LISTENER_BRANCH_GRACE_MS = 30000;
let listenerPass = null;          // the pass running now, or null
let listenerPassAgain = null;     // null, or { repair } for the pass after it
let listenerRepairTimer = null;

function reconcileTheListener(options) {
  log.debug("Entering reconcileTheListener().");
  const repair = !!(options && options.repair);
  if (listenerPass) {
    // A pass is running; one more after it, and a repair if either asked.
    listenerPassAgain = { repair: repair ||
                                  !!(listenerPassAgain &&
                                     listenerPassAgain.repair) };
    log.debug("Leaving reconcileTheListener(). Queued behind the running " +
              "pass.");
    return listenerPass;
  }
  listenerPass = runListenerPass(repair).then(function () {
    listenerPass = null;
    const next = listenerPassAgain;
    listenerPassAgain = null;
    if (next) {
      return reconcileTheListener(next);
    }
    return null;
  });
  log.debug("Leaving reconcileTheListener().");
  return listenerPass;
}

function armListenerRepair(armed) {
  log.debug("Entering armListenerRepair(). " + armed);
  if (!armed) {
    if (listenerRepairTimer) {
      clearTimeout(listenerRepairTimer);
      listenerRepairTimer = null;
    }
    log.debug("Leaving armListenerRepair(). Disarmed.");
    return;
  }
  if (listenerRepairTimer) {
    log.debug("Leaving armListenerRepair(). Already armed.");
    return;
  }
  listenerRepairTimer = setTimeout(function () {
    listenerRepairTimer = null;
    log.warn('request_pool: the process branch under this service\'s Root ' +
             'did not arrive from the process that replaced the Root within ' +
             (LISTENER_BRANCH_GRACE_MS / 1000) + 's, so the listener ' +
             'certificate is repaired here, rebuilding that branch.');
    reconcileTheListener({ repair: true });
  }, LISTENER_BRANCH_GRACE_MS);
  if (typeof listenerRepairTimer.unref === 'function') {
    listenerRepairTimer.unref();
  }
  log.debug("Leaving armListenerRepair(). Armed.");
}

// Whether the fallback above is armed — for the test, which cannot wait for it.
function listenerRepairArmed() {
  log.debug("Entering listenerRepairArmed().");
  log.debug("Leaving listenerRepairArmed().");
  return !!listenerRepairTimer;
}

function runListenerPass(repair) {
  log.debug("Entering runListenerPass(). repair=" + repair);
  // **LAZILY, AND THAT IS RULE 1 RATHER THAN TASTE.** `server.js` requires this
  // module at 122 and the protocol stack — `tls/tls_server.js` with it — at
  // 176, so a require at the top of this file would register `/tls`'s three
  // views from HERE, ahead of every protocol module. Inside a function that
  // cannot run until a worker has published something, it is a cache hit.
  const tls = require('../tls/tls_server');
  log.debug("Leaving runListenerPass().");
  return Promise.resolve()
    .then(function () {
      return tls.reconcileWithHierarchy({ buildBranch: repair });
    })
    .then(function (changed) {
      armListenerRepair(!repair && tls.listenerAwaitsBranch());
      if (!changed) {
        return;
      }
      const bundle = tls.serverCertificateBundle();
      let told = 0;
      workers.forEach(function (other) {
        if (!other.child || !other.child.connected) {
          return;
        }
        try {
          other.child.send({ adoptServerCertificate: bundle });
          told += 1;
        } catch (e) {
          log.warn(errorCodes.tag('STS-WORKER-0014') +
                   'request_pool: could not hand worker ' + other.pid +
                   ' the re-issued server certificate: ' + e.message +
                   '. It goes on pinning the previous one, so its own ' +
                   'OpenID Connect back channel will fail until it is ' +
                   'replaced.');
        }
      });
      log.info('request_pool: the listener certificate was re-issued under ' +
               'the rebuilt hierarchy and handed to ' + told + ' worker(s), ' +
               'so every process pins what the socket presents.');
    })
    .catch(function (e) {
      // Reported rather than thrown: this runs off a message handler, where an
      // unhandled rejection would take the front process down and with it
      // every worker — for a certificate that is still being served.
      log.error(errorCodes.tag('STS-WORKER-0015') +
                'request_pool: the listener certificate could not be ' +
                'reconciled with the rebuilt hierarchy: ' + e.message);
    });
}

// ---------------------------------------------------------------------------
// A CERTIFICATE AUTHORITY ANOTHER NODE WROTE WAS ADOPTED FROM THE STORE
// (2026-09-14, #46). `persistence.js` calls this in the process that holds the
// listener; the row itself needs nothing from here, because every process of
// this container reads the change log and adopts it for itself. What only this
// process can do is the socket — `receivePublishedPki()`'s second half, for a
// hierarchy that arrived from another CONTAINER rather than from a worker.
// ---------------------------------------------------------------------------
function hierarchyArrived(scopeId) {
  log.debug("Entering hierarchyArrived(). scope=" + scopeId);
  if (process.env.STS_REQUEST_WORKER) {
    log.debug("Leaving hierarchyArrived(). A worker holds no listener.");
    return null;
  }
  // **ONLY THE TWO ROWS THE LISTENER CHAINS THROUGH, AND ONLY ONCE THE BRANCH
  // IS HERE.** A realm's row certifies nothing on these sockets. And on a cold
  // start the Root arrives from the node that built it a moment before that
  // node's process branch does — reconciling on the Root alone asked the
  // process scope for a TLS Issuing CA it did not have yet and logged
  // STS-PKI-0046 and STS-TLS-0026 about a certificate that was re-issued
  // correctly one row later. The branch's own arrival reconciles.
  const pki = require('./pki');
  const processRow = pki.rawRowFor(pki.PROCESS_SCOPE);
  if ((scopeId !== pki.SERVICE_SCOPE && scopeId !== pki.PROCESS_SCOPE) ||
      !(processRow && processRow.issuing && processRow.issuing.tls)) {
    log.debug("Leaving hierarchyArrived(). Nothing the listener chains " +
              "through yet.");
    return null;
  }
  log.debug("Leaving hierarchyArrived().");
  return reconcileTheListener();
}

function broadcastPki(realmId, chain, except) {
  log.debug("Entering broadcastPki().");
  workers.forEach(function (other) {
    if (other === except || !other.child || !other.child.connected) {
      return;
    }
    try {
      other.child.send({ adoptPki: { realm: realmId, chain: chain } });
    } catch (e) {
      log.warn(errorCodes.tag('STS-WORKER-0013') +
               'request_pool: could not hand the "' + realmId + '" realm\'s ' +
               'certificate authority to worker ' + other.pid + ': ' +
               e.message);
    }
  });
  log.debug("Leaving broadcastPki().");
}

function sendKeys(entry, realmId) {
  log.debug("Entering sendKeys().");
  const all = keystore.sharedAll();
  for (let i = 0; i < all.length; i++) {
    if (all[i].realm === realmId && entry.child && entry.child.connected) {
      try {
        entry.child.send({ adoptKeys: all[i] });
      } catch (e) {
        log.warn(errorCodes.tag('STS-WORKER-0013') +
                 'request_pool: could not correct worker ' + entry.pid +
                 '\'s keys for "' + realmId + '": ' + e.message);
      }
      log.debug("Leaving sendKeys().");
      return;
    }
  }
  log.debug("Leaving sendKeys().");
}

// How many connections the front process may have open to ONE worker at once.
// Read at fork, because an agent is made there and a change would not reach an
// agent that exists — which is why `workers.maxSockets` is restart-only.
function maxSocketsPerWorker() {
  log.debug("Entering maxSocketsPerWorker().");
  const n = Number(config.value('workers.maxSockets'));
  log.debug("Leaving maxSocketsPerWorker().");
  return (n > 0) ? n : 64;
}

function fork(pool) {
  log.debug('Entering fork(). pool=' + (pool || PROTOCOL_POOL));
  const which = pool === SURFACE_POOL ? SURFACE_POOL : PROTOCOL_POOL;
  // `s` for a surface worker's socket, so that a directory listing — and the
  // 502 that names a socket path — says which pool a worker was in.
  const socket = path.join(ensureSocketDir(),
                           (which === SURFACE_POOL ? 's' : 'w') +
                           (nextSocket++) + '.sock');
  const child = child_process.fork(WORKER_MODULE, [socket], {
    // stdout and stderr are the front process's, so a worker's bunyan lines
    // land in the same stream as everything else. They carry the pid.
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
    // -------------------------------------------------------------------
    // STRUCTURED CLONE ON THE CHANNEL, AND IT WAS THE DEFAULT JSON UNTIL
    // 2026-09-12.
    //
    // **THIS IS `worker_pool.js`'s ARGUMENT, ARRIVING HERE FOR THE SECOND
    // FAMILY.** That file says it about a 32,000-byte SLH-DSA signature; the
    // same sentence is true of a DER certificate, and the operation channel
    // now carries them: a SPIFFE gRPC request and reply hold X509-SVIDs,
    // bundles, private keys and CSRs as `bytes`.
    //
    // **JSON DOES NOT MERELY BLOAT A BUFFER, IT CHANGES ITS TYPE.**
    // `JSON.stringify(Buffer)` is `{"type":"Buffer","data":[…]}` — six times
    // the bytes, and it arrives at the far end as a PLAIN OBJECT. Measured
    // here before the change: a Buffer sent over a default channel reaches the
    // child as `Object` and comes back as `Object`. grpc-js would then be
    // handed something that is not a Buffer for a `bytes` field, so the
    // failure lands in protobuf serialization, naming a field, one process
    // away from the cause.
    //
    // **IT IS A STRICT SUPERSET FOR EVERYTHING THIS CHANNEL ALREADY
    // CARRIES** — the LDAP operation shapes are strings and numbers, and so
    // are the commit, sync and ready messages — so nothing that worked before
    // it behaves differently. What it adds is Buffers, Dates and Maps
    // surviving as themselves, which is what stopped the SPIFFE codec needing
    // a base64 layer of its own that every new `bytes` field would have had to
    // be added to.
    // -------------------------------------------------------------------
    serialization: 'advanced',
    // THE MARKER THAT STOPS A WORKER PROXYING TO ITSELF. See the constant at
    // the top of this file for what happens without it.
    //
    // AND WHICH POOL IT IS IN. One thing in a worker reads it: the OpenID
    // Connect back channel in `common/oidc_rp.js`, which names the worker that
    // should redeem a code and has to know whether that can be itself — see
    // PROTOCOL_WORKER_HEADER.
    env: Object.assign({}, process.env, { STS_REQUEST_WORKER: '1',
                                          STS_REQUEST_WORKER_POOL: which })
  });
  const entry = { child: child, pid: child.pid, pool: which, socket: socket,
                  ready: false,
                  // -------------------------------------------------------
                  // ONE AGENT PER WORKER, AND IT IS A BOUND RATHER THAN A
                  // CACHE (2026-09-12).
                  //
                  // Every dispatched request used node's GLOBAL agent, whose
                  // `maxSockets` is Infinity — so nothing limited how many
                  // unix-socket connections the front process could have open
                  // to one worker, and an unbounded proxy in front of a
                  // single-threaded worker is a bug whether or not it has
                  // been observed.
                  //
                  // **IT IS NOT WHAT FIXED THE FAILURE THAT PROMPTED IT, AND
                  // SAYING SO IS THE POINT OF THIS BLOCK.** The measured
                  // failure was `sts_directory_bulk_load_scim` in a
                  // `--modes=dispatch` run — `4999 of 5000 SCIM creates were
                  // accepted`, the one refusal `502 … connect EAGAIN
                  // /tmp/sts-workers-*/w2.sock`, a request that never reached
                  // a worker at all. EAGAIN on an AF_UNIX `connect()` is the
                  // listen backlog being full, and **that job issues its five
                  // thousand creates one at a time** (`for … await`), so a cap
                  // of 64 was never anywhere near being reached by it. What
                  // fixes that failure is the explicit backlog on the worker's
                  // own socket — see `bindSocket()` in
                  // `common/request_worker.js`. This bounds the OTHER end,
                  // which is real (the suite runs many jobs at once) and is
                  // not the thing that was measured.
                  //
                  // **NOT KEPT ALIVE.** `keepAlive: true` would remove nearly
                  // every connect and is the obvious answer; it was refused
                  // because it trades a rare failure for a nastier one — a
                  // socket reused in the instant the worker closes it, which
                  // arrives as an ECONNRESET on a request that had been
                  // accepted rather than on one that never left.
                  //
                  // **THE HAZARD A BOUND CREATES, WRITTEN DOWN BECAUSE IT IS
                  // THE REASON THE NUMBER IS NOT SMALL**: this service makes
                  // requests to ITSELF — `common/oidc_rp.js`'s back channel
                  // dials the front process, which dispatches again — so a
                  // worker holding N in-flight requests that are each waiting
                  // on a reentrant call needs an N+1th connection to make
                  // progress. At 64 that needs sixty-four simultaneous
                  // sign-ins landing on ONE worker, which is not a load this
                  // service sees; at 4 it would be a deadlock somebody meets.
                  // -------------------------------------------------------
                  agent: new http.Agent({ keepAlive: false,
                                          maxSockets: maxSocketsPerWorker() }),
                  inFlight: 0, served: 0, startedAt: Date.now(),
                  retiring: false,
                  // A FRESH WORKER IS CURRENT: it ran service_state.start(),
                  // which takes the change log's high-water mark, so it has
                  // seen everything committed before it started.
                  generation: generation };
  workers.push(entry);
  // TELL IT WHAT IT IS. Nothing is loaded in the child until this arrives —
  // see request_worker.js for why the certificate travels here rather than in
  // the fork's environment.
  try {
    // THE SIGNING KEYS TRAVEL WITH THE CERTIFICATE, for the same reason and on
    // the same channel — see keystore.js's shared-key block. Every realm this
    // process has already generated goes down at fork; realms made later are
    // published the other way and rebroadcast below.
    child.send({ begin: true, socket: socket, tls: tlsMaterial,
                 keys: keystore.sharedAll(),
                 // AND EVERY CERTIFICATE AUTHORITY, on the same channel and
                 // for the same reason: a worker forked after a hierarchy was
                 // built would otherwise have none, and would refuse the
                 // assertions its siblings accept.
                 pki: keystore.pkiAll(),
                 kek: keystore.ephemeralKek(),
                 bbsKeyPair: bbsKeyPairB64,
                 // WHAT IS BOUND ON THE DIRECTORY RIGHT NOW. A worker that
                 // started with an empty list and was never told otherwise
                 // would answer a sign-out for a connection made before it
                 // existed with "there is nothing to end" — which is the bug
                 // this whole mechanism is about, narrowed to one worker.
                 ldapConnections: directory().connectionSnapshot() });
  } catch (e) {
    log.error(errorCodes.tag('STS-WORKER-0016') +
              'request_pool: could not start worker ' + child.pid + ': ' +
              e.message);
  }

  const settled = new Promise(function (resolve) {
    child.on('message', function (message) {
      if (message && message.ready) {
        entry.ready = true;
        quickExits[entry.pool] = 0;
        log.info('request_pool: ' + entry.pool + ' worker ' + entry.pid +
                 ' is ready on ' + entry.socket + '. ' +
                 readyWorkers(entry.pool).length + ' of ' + size(entry.pool) +
                 ' serving.');
        resolve(entry);
        return;
      }
      if (message && message.ready === false) {
        log.error(errorCodes.tag('STS-WORKER-0017') +
                  'request_pool: worker ' + entry.pid + ' could not start: ' +
                  message.error);
        resolve(null);
        return;
      }
      if (message && message.committed) {
        receiveCommitted(entry, message.committed);
        return;
      }
      if (message && message.publishKeys) {
        receivePublishedKeys(entry, message.publishKeys);
        return;
      }
      if (message && message.publishPki) {
        receivePublishedPki(entry, message.publishPki);
        return;
      }
      if (message && message.sync) {
        receiveSync(entry, message);
        return;
      }
      if (message && message.operation) {
        receiveOperation(entry, message);
        return;
      }
      if (message && message.status) {
        entry.served = message.served;
      }
    });
    child.on('error', function (err) {
      log.warn(errorCodes.tag('STS-WORKER-0020') +
               'request_pool: the channel to worker ' + entry.pid +
               ' failed: ' + err.message);
      resolve(null);
    });
    child.on('exit', function (code, signal) {
      reap(entry, code, signal);
      resolve(null);
    });
  });
  entry.settled = settled;
  log.debug('Leaving fork(). pid=' + entry.pid);
  return entry;
}

// A worker that has gone. Unlike the computation pool there is nothing to
// reject: a request in flight is an open socket, and the proxy below fails it
// when the connection drops, with the pid in the sentence.
function reap(entry, code, signal) {
  log.debug('Entering reap(). pid=' + entry.pid);
  workers = workers.filter(function (one) { return one !== entry; });
  // ITS AGENT GOES WITH IT. The agent holds sockets to a socket PATH that has
  // just stopped being served, and a worker replaced often enough — a crash
  // loop is the case — would otherwise leave one agent per dead worker for
  // the life of the process. `destroy()` closes what is idle; anything still
  // in flight fails through `proxy()`'s error path, which is what it did
  // before this agent existed.
  if (entry.agent && typeof entry.agent.destroy === 'function') {
    entry.agent.destroy();
  }
  const affinity = affinities[entry.pool] || affinities[PROTOCOL_POOL];
  affinity.forEach(function (pid, session) {
    if (pid === entry.pid) {
      affinity.delete(session);
    }
  });
  // ------------------------------------------------------------------------
  // AND ITS TICKETS ARE RELEASED, because nothing will ever confirm them now.
  //
  // A ticket is cleared when the worker that holds it says its flush covered
  // it. A worker that has died says nothing ever again, so every reader whose
  // barrier includes one of its finished tickets would wait the full bound and
  // then give up — a stale read reported as a timeout, for as long as this
  // process runs.
  //
  // **THIS IS A LOSS AND IT IS SAID OUT LOUD.** What those tickets stood for
  // is writes that were ANSWERED and may not have reached the store: the
  // worker died between the response and its flush. Nothing here can recover
  // them — the memory that held them is gone — so the honest thing is to stop
  // blocking readers over it and to log what may have been lost.
  // ------------------------------------------------------------------------
  if (entry.tickets && entry.tickets.size) {
    let answered = 0;
    entry.tickets.forEach(function (t) {
      if (finishedTickets.has(t)) {
        answered += 1;
      }
      outstanding.delete(t);
      finishedTickets.delete(t);
      finishedAt.delete(t);
    });
    entry.tickets.clear();
    if (answered) {
      log.warn(errorCodes.tag('STS-WORKER-0021') +
               'request_pool: worker ' + entry.pid + ' died holding ' +
               answered + ' answered request(s) whose flush it had not ' +
               'reported. Those writes may not have reached the store, and ' +
               'no reader is being made to wait for them any longer.');
    }
    releaseTicketWaiters();
  }
  try {
    fs.unlinkSync(entry.socket);
  } catch (e) {
    // The worker unlinks its own on a clean exit; this is for one that was
    // killed. Already gone is the ordinary case.
    log.debug("Caught in reap(): " + ((e && e.message) || e));
  }
  failOperations(entry);
  const how = signal ? 'was killed with ' + signal : 'exited with code ' + code;
  const shortLived = (Date.now() - entry.startedAt) < QUICK_EXIT_MS &&
                     entry.served === 0;
  const pool = entry.pool || PROTOCOL_POOL;
  if (shortLived && !stopped) {
    quickExits[pool]++;
  }
  if (entry.inFlight) {
    log.warn(errorCodes.tag('STS-WORKER-0022') +
             'request_pool: ' + pool + ' worker ' + entry.pid + ' ' + how +
             ' with ' + entry.inFlight + ' request(s) in flight; each is ' +
             'answered 502.');
  } else {
    log.info('request_pool: ' + pool + ' worker ' + entry.pid + ' ' + how +
             '.');
  }
  if (quickExits[pool] >= QUICK_EXIT_LIMIT && !givenUp[pool] && !stopped) {
    givenUp[pool] = true;
    // WHERE THE WORK GOES NOW IS THE ONE THING THE TWO POOLS SAY DIFFERENTLY:
    // the protocol pool's paths come back to this process, which is what
    // workers.requestCount=0 means; the surface pool's go to the protocol
    // pool, which is what workers.surfaceCount=0 means. See poolFor().
    log.error(errorCodes.tag('STS-WORKER-0023') +
      'request_pool: ' + quickExits[pool] + ' ' + pool + ' workers in a ' +
      'row exited within ' + QUICK_EXIT_MS + 'ms without serving anything, ' +
      'so this service has STOPPED FORKING THEM and ' +
      (pool === SURFACE_POOL
        ? 'is sending the hosted surfaces to the protocol workers — which ' +
          'is what workers.surfaceCount=0 means'
        : 'is handling every request in the process that holds the sockets ' +
          '— which is what workers.requestCount=0 means: correct, and on ' +
          'one thread') +
      '. A worker that cannot start is usually a CONFIG_FILE it cannot ' +
      'read, a port a protocol module tried to bind, or a machine out of ' +
      'memory; ' + WORKER_MODULE + ' run by hand with a socket path says ' +
      'which.');
  }
  log.debug('Leaving reap().');
}

// The ready workers of ONE pool — the protocol pool when none is named. Every
// ROUTING decision goes through here; the broadcasts above walk `workers`
// whole, because agreement is between processes and not between pools.
function readyWorkers(pool) {
  log.debug("Entering readyWorkers().");
  const which = pool || PROTOCOL_POOL;
  log.debug("Leaving readyWorkers().");
  return workers.filter(function (one) {
    return one.ready && !one.retiring && (one.pool || PROTOCOL_POOL) === which;
  });
}

// Fewest in flight, then least served — the same two-part rule the computation
// pool uses, and for the same reason: the first keeps a slow request from being
// queued behind another, and the second stops a burst landing on whichever
// child was forked first.
// `among`, when given, narrows the choice to those workers — the batch lane.
function leastLoaded(pool, among) {
  log.debug("Entering leastLoaded().");
  const live = among || readyWorkers(pool);
  if (!live.length) {
    log.debug("Leaving leastLoaded().");
    return null;
  }
  const chosen = live.slice().sort(function (a, b) {
    if (a.inFlight !== b.inFlight) {
      return a.inFlight - b.inFlight;
    }
    return a.served - b.served;
  })[0];
  // THE LOAD VECTOR, not just the answer. A pool that is routing badly looks
  // exactly like a pool that is routing well from the outside — every request
  // is answered correctly either way — so the numbers the decision was made on
  // are logged beside the decision. This is the line that found the fanout
  // sending everything to one worker.
  log.debug('leastLoaded(): ' + live.map(function (one) {
    return one.pid + '(' + one.inFlight + '/' + one.served + ')';
  }).join(' ') + ' -> ' + (chosen ? chosen.pid : '(none)'));
  log.debug("Leaving leastLoaded().");
  return chosen;
}

// ---------------------------------------------------------------------------
// WHAT A REQUEST IS STUCK TO, AND IT IS NOT ONLY THE COOKIE.
//
// The session cookie is the obvious key and it is not enough, because **the
// requests that most need affinity are the ones made before there is a session
// at all.** A browser sign-on is a chain of hops that carries its state in the
// URL: `/oauth2/authorize` mints a PENDING AUTHENTICATION RECORD and redirects
// to `/authn/login?authn_id=…`; the consent screen carries a consent id; the
// device flow carries a `device_code`; SAML's Browser/Artifact profile carries
// an `artifact` that the service provider resolves over SOAP. Every one of
// those names a record that lives in the memory of the worker that made it, and
// a second hop routed anywhere else finds nothing.
//
// So the key is the first of these the request carries, in this order. The
// cookie comes first because a request that has both is a browser that is
// already signed in, and the session outlives the flow.
//
// A request carrying NONE of them has nothing to be stuck to yet — the first
// hop of a flow, or a fresh browser — so it fans out, and `learn()` below binds
// whatever that worker mints.
// ---------------------------------------------------------------------------
// THE REAL SPELLINGS, taken from the handlers rather than guessed. The first
// version of this list said `authn_id` and `consent_id`, which are what the
// POST BODIES carry; the redirects carry `authn` and `consent`, so not one key
// was ever extracted and every browser flow fanned out. It was found by
// driving an authorization code flow and reading the Location header.
const FLOW_PARAMS = ['authn', 'consent', 'device_code', 'SAMLart'];

// ---------------------------------------------------------------------------
// THE POOL'S OWN ROUTING COOKIE, WHICH IS WHAT ACTUALLY HOLDS A BROWSER FLOW
// TOGETHER.
//
// Reading flow identifiers out of the URL is necessary and NOT sufficient, and
// the reason is structural rather than a matter of getting the list right: the
// hop that most needs affinity is the FORM POST, and a form post carries its
// identifier in the BODY. The front process does not parse bodies — it pipes
// them, which is the whole reason a dispatched request costs it nothing — so
// the identifier that would pin `/authn/login` is precisely the one it cannot
// see. Enumerating parameter names could never have fixed that.
//
// So the pool sets a cookie of its own on the first dispatched answer to a
// browser that has none, and routes by it afterwards. It is the sticky-session
// cookie every load balancer has, for the same reason every load balancer has
// one, and it has three properties worth stating:
//
//   * **It is opaque and it is not a credential.** It names a worker and
//     nothing else. Anybody may forge one, and the worst they achieve is
//     choosing which worker answers them — which the pool would otherwise
//     choose by load. Nothing is authorized by it.
//   * **It is invisible to the application.** It is added to the response here
//     and stripped from the request before the worker sees it, so no handler
//     can come to depend on it and it cannot collide with an application
//     cookie.
//   * **It survives a worker's death.** The value names a worker that may be
//     gone; `workerFor()` then picks a live one and re-binds, which is the same
//     recovery every other affinity key gets.
// ---------------------------------------------------------------------------
const POOL_COOKIE = 'sts_pool';

// AND THE SURFACE POOL'S, a second name for the reason the two-pools block at
// the top of the worker table gives: a value can name a worker in one pool
// only. The protocol pool keeps the old name, so every browser and every
// back channel that already carries `sts_pool` means what it meant.
//
// `tests/vendored/sts_metadata_anonymous.js` reads POOL_COOKIE's spelling out
// of this file to exempt it on metadata documents; this one needs no such
// exemption, because no metadata document is under a surface prefix.
const SURFACE_POOL_COOKIE = 'sts_pool_surfaces';

function poolCookieFor(pool) {
  log.debug("Entering poolCookieFor().");
  log.debug("Leaving poolCookieFor().");
  return pool === SURFACE_POOL ? SURFACE_POOL_COOKIE : POOL_COOKIE;
}

// ---------------------------------------------------------------------------
// A WRITE TO ONE RESOURCE GOES TO ONE WORKER, EVEN ON A FANOUT PATH
// (2026-09-08).
//
// Fanning out is right for a surface whose every request carries its own
// credential and names its own target — `/scim`, `/xacml` and `/admin-api` all
// do. It is NOT right for two writes to the SAME resource, because several of
// those are READ-MODIFY-WRITE: `PATCH /scim/v2/Groups/{id}` reads the group,
// appends a member and writes the whole entry back. Two of those on two workers
// and one member is lost — the second read precedes the first write, and no
// read barrier can help, because the barrier releases a reader that is current
// and both of these are.
//
// It is not hypothetical. A 5,000-membership SCIM bulk load left two groups
// holding 99 of their 100 members, with NO dangling references: the members
// named entries that exist, there were simply fewer of them than were written.
// That is the signature of a lost update rather than a stale read, and it is
// why this is keyed on the resource rather than fixed by waiting longer.
//
// **ONLY WHEN THE PATH NAMES ONE RESOURCE, AND ONLY FOR A WRITE.** Keying every
// fanout write on its path would put every `POST /scim/v2/Users` — a create,
// which names no resource — on a single worker and serialise the whole load
// through it. A collection is fanned out as before; an individual resource is
// pinned by its own identity, which spreads across workers by resource and
// costs nothing.
//
// Reads are untouched: a read that must see a write is what the barrier is for,
// and this is about two writers rather than a writer and a reader.
// ---------------------------------------------------------------------------
const RESOURCE_PATHS = [
  // `/scim/v2/<Type>/<id>` — RFC 7644's resource shape, and the only one in
  // this service whose writes are read-modify-write over a whole entry.
  //
  // THE REALM PREFIX IS OPTIONAL AND MATTERS: this runs on `req.originalUrl`,
  // which app.js deliberately leaves un-stripped, so a realm-scoped SCIM call
  // arrives as `/realm/<id>/scim/v2/Groups/<id>`. Anchoring at `/scim` alone
  // would have matched only the default realm and left every realm racing —
  // which is where the bulk-load jobs run.
  /^(?:\/realm\/[^/]+)?\/scim\/v2\/[A-Za-z]+\/([^/?#]+)/
];

// ---------------------------------------------------------------------------
// A CREDENTIAL IS AN AFFINITY KEY (2026-09-08).
//
// `/scim`, `/xacml` and `/admin-api` fan out because each request carries its
// own credential and names its own target — nothing about them needs the
// previous request's worker. That is true, and it is not the same as saying
// they should be SPREAD: a client that writes and then writes again pays a full
// commit round trip per request when consecutive calls land on different
// workers, because each has to wait for the last one to reach the store.
//
// Measured on SCIM creates, sequential, as a provisioning client actually
// behaves: 16.2ms each with the barrier, 5.1ms with it off. Nearly all of that
// gap is one client waiting for its own previous write — and it disappears if
// the client keeps landing on the worker that already holds it.
//
// So a fanout request with a credential is keyed on THAT, and one without is
// spread as before. It is still only a locality measure: correctness for
// everybody else is unchanged, because a reader on another worker still waits
// for this one's tickets in the ordinary way.
//
// The header is hashed rather than used raw so that a routing key can never be
// a password sitting in a Map — `affinity` is dumped by nothing today, and
// that is not a reason to put a Basic credential in it.
// ---------------------------------------------------------------------------
function credentialKeyOf(req) {
  log.debug("Entering credentialKeyOf().");
  const said = req.headers && req.headers.authorization;
  if (!said) {
    log.debug("Leaving credentialKeyOf().");
    return '';
  }
  log.debug("Leaving credentialKeyOf().");
  return 'c:' + nodeCrypto.createHash('sha256').update(String(said))
    .digest('base64url').slice(0, 22);
}

function mutationKeyOf(req, url) {
  log.debug("Entering mutationKeyOf().");
  if (!mayWrite(req.method)) {
    log.debug("Leaving mutationKeyOf().");
    return credentialKeyOf(req);
  }
  const path = String(url || '').split('?')[0];
  for (let i = 0; i < RESOURCE_PATHS.length; i++) {
    const found = RESOURCE_PATHS[i].exec(path);
    if (found) {
      log.debug("Leaving mutationKeyOf().");
      return 'r:' + found[0];
    }
  }
  log.debug("Leaving mutationKeyOf().");
  return credentialKeyOf(req);
}

// `pool` decides which routing cookie is read — see SURFACE_POOL_COOKIE — and
// defaults to the protocol pool. Everything else about the key is the same in
// both pools: the session cookies are the browser's, and which pool holds a
// binding for them is a question for that pool's map.
// ---------------------------------------------------------------------------
// A SESSION COOKIE IS `<sid>.<handle>` SINCE 2026-09-14, AND AFFINITY IS BOUND
// TO THE SID.
//
// The handle ROTATES — on every re-authentication, and when an arrival session
// becomes a sign-in (`authn/authn.js`, `mintSessionHandle()`) — and the sid
// does not. Binding `s:<whole value>` would add a binding per rotation and
// leave the old one pointing at a worker for a value no browser will present
// again. The sid is also what the worker's store is keyed by, so it names the
// same thing the binding is about. A value with no dot (an old cookie, or a
// test's) is taken whole, which is what this did before.
// ---------------------------------------------------------------------------
function sidOfCookieValue(value) {
  log.debug("Entering sidOfCookieValue().");
  const text = String(value || '');
  const dot = text.indexOf('.');
  log.debug("Leaving sidOfCookieValue().");
  return dot > 0 ? text.slice(0, dot) : text;
}

function affinityKeyOf(req, pool) {
  log.debug("Entering affinityKeyOf().");
  const POOL_COOKIE = poolCookieFor(pool);
  const header = req.headers && req.headers.cookie;
  if (header) {
    const parts = String(header).split(';');
    let pooled = '';
    let session = '';
    let rp = '';
    for (let i = 0; i < parts.length; i++) {
      const bit = parts[i].trim();
      if (bit.indexOf(SESSION_COOKIE + '=') === 0) {
        session = sidOfCookieValue(bit.slice(SESSION_COOKIE.length + 1));
      }
      const named = sessionCookieName(bit);
      if (named && named !== SESSION_COOKIE && !rp) {
        rp = sidOfCookieValue(bit.slice(named.length + 1));
      }
      if (bit.indexOf(POOL_COOKIE + '=') === 0) {
        pooled = bit.slice(POOL_COOKIE.length + 1);
      }
    }
    // THE SIGN-ON SESSION FIRST, and it resolves by LOOKUP rather than by
    // hashing: `learn()` binds `s:<id>` to the worker whose answer set that
    // cookie, so this key names the worker that actually holds the session.
    // The pin is the fallback for a browser whose binding this process has
    // lost — a worker that died, or a pool that restarted.
    if (session) {
      log.debug("Leaving affinityKeyOf().");
      return 's:' + session;
    }
    // THE RELYING-PARTY SESSION SECOND. It is bound the same way — `learn()`
    // remembers whichever of the three cookies an answer set — so this is a
    // lookup and not a hash. It ranks BELOW the sign-on session because a
    // browser holding both is one browser, and the sign-on session is the one
    // the other one dies with.
    if (rp) {
      log.debug("Leaving affinityKeyOf().");
      return 's:' + rp;
    }
    if (pooled) {
      log.debug("Leaving affinityKeyOf().");
      return 'p:' + pooled;
    }
  }
  const url = String(req.originalUrl || req.url || '');
  const q = url.indexOf('?');
  if (q < 0) {
    log.debug("Leaving affinityKeyOf().");
    return '';
  }
  const query = url.slice(q + 1);
  for (let i = 0; i < FLOW_PARAMS.length; i++) {
    const found = flowParam(query, FLOW_PARAMS[i]);
    if (found) {
      log.debug("Leaving affinityKeyOf().");
      return FLOW_PARAMS[i] + ':' + found;
    }
  }
  log.debug("Leaving affinityKeyOf().");
  return '';
}

// One query parameter, without building a URL object. This runs on every
// dispatched request and the whole value of this file is that the front process
// does as little as possible per request.
function flowParam(query, name) {
  log.debug("Entering flowParam().");
  const parts = String(query || '').split('&');
  for (let i = 0; i < parts.length; i++) {
    const bit = parts[i];
    if (bit.indexOf(name + '=') === 0) {
      const raw = bit.slice(name.length + 1);
      try {
        log.debug("Leaving flowParam().");
        return decodeURIComponent(raw);
      } catch (e) {
        log.debug("Caught in flowParam(): " + ((e && e.message) || e));
        log.debug("Leaving flowParam().");
        // A value that is not valid percent-encoding. Used as it arrived: this
        // is a routing key and never a credential, so the only thing that
        // matters is that the same string maps to the same worker.
        return raw;
      }
    }
  }
  log.debug("Leaving flowParam().");
  return '';
}

// ---------------------------------------------------------------------------
// LEARNING THE AFFINITY FROM THE ANSWER, WHICH IS THE HALF THAT MAKES IT WORK.
//
// Reading the key off the REQUEST is only half of it, and on its own it fails
// on the very first hop of every flow: `/oauth2/authorize` arrives with no
// cookie and no flow id, fans out to worker X, and X mints a session and a
// pending record IN ITS OWN MEMORY. The next request carries the cookie, finds
// nothing in the affinity map, and is routed to the least-loaded worker — which
// is not X, and the session does not exist there.
//
// So the answer is read on its way past: a `Set-Cookie` for the session, and a
// `Location` carrying one of the flow parameters. Whatever the worker minted is
// bound to that worker before the client ever presents it back.
//
// It reads two headers and nothing else. The BODY is never inspected — that
// would mean buffering a response the front process is otherwise only piping,
// which is the one thing this file exists not to do.
// ---------------------------------------------------------------------------
function learn(entry, answer) {
  log.debug('Entering learn(). pid=' + entry.pid);
  const setCookie = answer.headers && answer.headers['set-cookie'];
  if (setCookie) {
    const list = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (let i = 0; i < list.length; i++) {
      const bit = String(list[i]).split(';')[0].trim();
      // ALL THREE SESSION COOKIES, under ONE key space. A relying-party session
      // id and a sign-on session id are both ids of rows in `authn.js`'s single
      // session map (rule 3m), so `s:` is the right prefix for both and there
      // is no second namespace to keep in step.
      const named = sessionCookieName(bit);
      if (named) {
        const value = sidOfCookieValue(bit.slice(named.length + 1));
        // An EMPTY value is a sign-out clearing the cookie, not a new session.
        // Binding it would map the empty key to a worker and pin every future
        // signed-out request to it.
        if (value) {
          remember('s:' + value, entry);
        }
      }
    }
  }
  const location = answer.headers && answer.headers.location;
  if (location) {
    const q = String(location).indexOf('?');
    if (q >= 0) {
      const query = String(location).slice(q + 1);
      for (let i = 0; i < FLOW_PARAMS.length; i++) {
        const found = flowParam(query, FLOW_PARAMS[i]);
        if (found) {
          remember(FLOW_PARAMS[i] + ':' + found, entry);
        }
      }
    }
  }
  log.debug('Leaving learn().');
}

// Bound in the map of the pool the worker is IN, which is what keeps one
// browser's two bindings — one per pool — from overwriting each other.
function remember(key, entry) {
  log.debug("Entering remember().");
  const affinity = affinities[entry.pool] || affinities[PROTOCOL_POOL];
  if (affinity.get(key) === entry.pid) {
    log.debug("Leaving remember().");
    return;
  }
  if (affinity.size >= AFFINITY_MAX) {
    affinity.delete(affinity.keys().next().value);
  }
  affinity.delete(key);
  affinity.set(key, entry.pid);
  log.debug('remember(): ' + key.split(':')[0] + ' -> worker ' + entry.pid +
            '. ' + affinity.size + ' affinity/affinities held.');
  log.debug("Leaving remember().");
}

// The worker this request goes to. A session holds affinity; everything else
// fans out. A session whose worker has gone gets a new one, which is the whole
// of the recovery story — see the header on why that is safe.
// `among` narrows a NEW choice to those workers — the batch lane — and never
// overrides a binding the key already holds. See the batch lane's header.
function workerFor(key, pool, among) {
  log.debug('Entering workerFor(). key=' +
            (key ? key.split(':')[0] : '(none)') + ' pool=' +
            (pool || PROTOCOL_POOL));
  const candidates = among && among.length ? among : null;
  if (!key) {
    // Either this path fans out by policy, or it is the first hop of a flow and
    // has nothing to be stuck to yet. Both are the same routing decision, and
    // learn() binds whatever the chosen worker mints.
    const any = leastLoaded(pool, candidates);
    log.debug('Leaving workerFor(). Fanout to ' + (any ? any.pid : '(none)'));
    return any;
  }
  const held = heldWorker(key, pool);
  if (held) {
    log.debug('Leaving workerFor(). Held affinity to ' + held.pid + '.');
    return held;
  }
  const chosen = leastLoaded(pool, candidates);
  if (chosen) {
    // A key we have not seen, or one whose worker has gone. Either way it is
    // bound to whoever answers now — which is the whole of the recovery story,
    // and is safe for the reason the header gives: affinity is locality and
    // never correctness.
    remember(key, chosen);
  }
  log.debug('Leaving workerFor(). New affinity to ' +
            (chosen ? chosen.pid : '(none)') + '.');
  return chosen;
}

// The ready worker of `pool` that `key` is ALREADY bound to, or null — with no
// fallback and nothing remembered. Split out of workerFor() for the one caller
// that must not bind anything: proxy() asking, on a surface request, which
// protocol worker this browser is held by. Binding there would pin a browser to
// a protocol worker chosen by load for a request no protocol worker answers.
function heldWorker(key, pool) {
  log.debug("Entering heldWorker().");
  if (!key) {
    log.debug("Leaving heldWorker(). No key.");
    return null;
  }
  const affinity = affinities[pool] || affinities[PROTOCOL_POOL];
  // ---------------------------------------------------------------------
  // THE POOL COOKIE NAMES ITS WORKER, so it is honoured directly rather than
  // being looked up. The first version bound it in the affinity map when it
  // was SET and looked it up like any other key, and that was wrong in a way
  // the map cannot see: the cookie goes out on a response, the map is in this
  // process, and the two are not the same lifetime — a pool that had evicted
  // the entry, or a front process that restarted while the browser kept its
  // cookie, would route the next request by LOAD to a worker that has none of
  // that browser's flow. Reading the pid out of the value is self-healing:
  // the pin survives anything except the worker itself going away.
  // ---------------------------------------------------------------------
  let pid = affinity.get(key);
  if (!pid && key.indexOf('p:') === 0) {
    const named = parseInt(key.slice(2), 10);
    if (named > 0) {
      pid = named;
    }
  }
  // A pid from the OTHER pool is no worker here, which is what the filter on
  // readyWorkers(pool) says without a second test.
  const held = pid ? readyWorkers(pool).filter(function (one) {
    return one.pid === pid;
  })[0] : null;
  log.debug("Leaving heldWorker().");
  return held || null;
}

// ---------------------------------------------------------------------------
// WHAT IS WRONG WITH THE SURFACE POOL AS CONFIGURED, OR NULL (2026-09-13).
//
// Two answers, and they are opposite in kind on purpose:
//
//   * **NOTHING IT ANSWERS IS DISPATCHED — A WARNING, AND IT IS NOT FORKED.**
//     `workers.dispatch` is the one list of what leaves this process, so a
//     surface pool whose prefixes it does not name would be workers that load
//     the whole service and receive nothing. That is waste and not wrongness,
//     so it is said out loud and the service starts without them.
//   * **READ-YOUR-WRITE IS OFF — FATAL, ON `start()`'S COORDINATION ARGUMENT.**
//     With one pool a browser's sign-in to the console lands on ONE worker:
//     the arrival session, the authorization code, the sign-on session and the
//     console session are all minted in the process that reads them next.
//     With two, `/admin/callback` is answered in a surface worker and reads a
//     sign-on session a protocol worker minted a few milliseconds earlier; the
//     console session it mints then names that parent, and every later console
//     page checks the parent is alive. Coordination gets those rows there in
//     half a second to a second, and a browser — or the suite — is faster. So
//     the console would fail to sign in, or sign in and then end the session as
//     an orphan, SOMETIMES. The barrier (`workers.readYourWrite`) is what makes
//     a surface worker wait for a write a protocol worker already answered, and
//     without it this is the silent, intermittent wrongness this repository
//     refuses to start with rather than warn about.
//
// Exported for `tests/request_routing.js`: the decision is two settings and a
// list, and reaching it through start() needs a coordinating store first.
// ---------------------------------------------------------------------------
function surfacePoolProblem() {
  log.debug("Entering surfacePoolProblem().");
  const count = size(SURFACE_POOL);
  if (!count) {
    log.debug("Leaving surfacePoolProblem(). No surface pool.");
    return null;
  }
  const prefixes = surfacePrefixes();
  // REACHED EITHER WAY ROUND: `/admin` dispatched reaches the `/admin` pool,
  // and so does `/admin/users` dispatched on its own — a surface pool left unforked
  // for that second shape would answer every `/admin/users` request 503.
  const narrower = dispatchPrefixes();
  const reached = prefixes.filter(function (one) {
    return dispatched(one) || narrower.some(function (entry) {
      return entry.indexOf(one + '/') === 0;
    });
  });
  if (!reached.length) {
    log.debug("Leaving surfacePoolProblem(). Nothing reaches it.");
    return { code: 'STS-WORKER-0039', fatal: false,
             message: 'request_pool: workers.surfaceCount is ' + count +
               ' and none of workers.surfaces (' +
               (prefixes.join(', ') || 'empty') + ') is named by ' +
               'workers.dispatch, so no request would ever reach those ' +
               'workers. They are not being started; name the paths in ' +
               'workers.dispatch (or use "*") to give the console and the ' +
               'portal workers of their own.' };
  }
  if (!readYourWrite()) {
    log.debug("Leaving surfacePoolProblem(). No read-your-write.");
    return { code: 'STS-WORKER-0038', fatal: true,
             message: 'request_pool: workers.surfaceCount is ' + count +
               ' and workers.readYourWrite is OFF. Signing in to ' +
               reached.join(' or ') + ' would then cross two processes that ' +
               'only converge — the sign-in minted in a protocol worker, the ' +
               'session that depends on it read in a hosted-surface worker ' +
               'up to a second before it arrives — so those surfaces would ' +
               'fail to sign in, or sign in and lose the session, ' +
               'intermittently. Turn workers.readYourWrite on, or set ' +
               'workers.surfaceCount to 0 to keep those paths with the ' +
               'protocol workers.' };
  }
  log.debug("Leaving surfacePoolProblem(). None.");
  return null;
}

// ---------------------------------------------------------------------------
// Bring the pool up. Called ONCE from server.js before the listener binds,
// rather than lazily on the first request the way the computation pool is.
//
// The two are lazy and eager for opposite reasons and both are right. A
// computation worker is forked when a post-quantum signature is first asked
// for, because a process that never signs one must not pay for a pool — which
// is what keeps `npm test` and the parent project's in-process jobs free of
// children. A REQUEST worker takes seconds to start (it loads the whole
// service, seeds a directory and generates a realm's keys), so forking one on
// the first request would make that request wait for all of it. The front
// process is not answering yet at this point, so the cost is paid where nobody
// is waiting.
// ---------------------------------------------------------------------------
function start() {
  log.debug('Entering start().');
  if (starting) {
    log.debug('Leaving start(). Already starting.');
    return starting;
  }
  if (IS_REQUEST_WORKER) {
    // Belt to the middleware's braces. A worker never calls this — it does not
    // run server.js — but a worker that forked a pool of its own would fork
    // one per worker per generation, and that is a fork bomb rather than a bug.
    log.debug('Leaving start(). This process is a request worker.');
    starting = Promise.resolve({ started: 0, wanted: 0 });
    log.debug("Leaving start().");
    return starting;
  }
  // BOTH POOLS COUNT. A service with no protocol workers and a surface pool is
  // a supported shape — the console and the portal off the front process, every
  // protocol still on it — so neither size alone decides whether to go on.
  // Its refusal is raised BELOW the coordination guard, not here: a service
  // that is not coordinating at all has the more fundamental problem, and the
  // message an operator reads first should be about that one.
  const surfaceCheck = surfacePoolProblem();
  if (surfaceCheck && !surfaceCheck.fatal) {
    log.warn(errorCodes.tag(surfaceCheck.code) + surfaceCheck.message);
  }
  const wantedByPool = {};
  wantedByPool[PROTOCOL_POOL] = size(PROTOCOL_POOL);
  // A FATAL check still counts its workers as wanted, or a service configured
  // with a surface pool and no protocol pool would take the early return below
  // and never reach the refusal.
  wantedByPool[SURFACE_POOL] = (surfaceCheck && !surfaceCheck.fatal)
    ? 0 : size(SURFACE_POOL);
  const wanted = wantedByPool[PROTOCOL_POOL] + wantedByPool[SURFACE_POOL];
  if (!wanted) {
    log.debug('Leaving start(). No request workers are configured.');
    starting = Promise.resolve({ started: 0, wanted: 0 });
    log.debug("Leaving start().");
    return starting;
  }

  // ---------------------------------------------------------------------
  // NOTHING MAY BE DISPATCHED WITHOUT COORDINATION, AND THIS REFUSES TO START
  // RATHER THAN WARNING ABOUT IT.
  //
  // A worker holds its OWN copy of every store this service keeps — the
  // directory, the sessions, the token registry, the realm table, the
  // settings. `persistence.coordinate()` is what makes another process's write
  // arrive in this one's memory, and with it off, dispatching is not slower or
  // partial: it is WRONG, silently and intermittently. It was measured before
  // this guard existed — `/admin-api` across three workers, one setting
  // written, six reads, and the fifth read returned the value from before the
  // write. Nothing errored and nothing logged.
  //
  // **FATAL RATHER THAN A WARNING, and that is the one call here worth
  // arguing.** Everything else in this file degrades: no pool means the front
  // process does the work, a dead worker means a 502, a pool that gave up
  // means every request is handled here. All of those leave a service that is
  // CORRECT and slow. This one leaves a service that answers wrongly, and this
  // repository's rule for a misconfiguration that produces silent wrongness is
  // to refuse — the same argument `persistence.start()` makes about a store it
  // was told to use and cannot open, and `keystore.start()` about a signing
  // key it cannot read.
  //
  // The way out is to configure a coordinating store, or to empty
  // `workers.dispatch`, which is named in the message because a refusal that
  // does not say what to do instead is a refusal somebody works around.
  //
  // **IT READS ONE SETTING AND USED TO READ TWO.** The list it checks is the
  // whole of `workers.dispatch` — paths and operation kinds alike — which is
  // what merging the two settings bought here: a guard that had to remember to
  // concatenate a second list is a guard that would have been half a guard the
  // first time somebody added a third kind of dispatchable thing.
  // ---------------------------------------------------------------------
  const wants = dispatchList();
  if (wants.length) {
    // Required HERE rather than at the top of the file: `persistence` is above
    // every protocol module in the require order and this file is loaded by
    // app.js, so a top-level require would pull the store into the router's
    // position. By the time start() runs, it is a cache hit.
    const persistence = require('../persistence/persistence');
    const state = persistence.status();
    if (!state.coordinates) {
      const why = state.enabled
        ? 'the store is "' + state.mode + '", which this build cannot ' +
          'coordinate through (it needs a change log — see ' +
          'persistence_replication.js\'s supports())'
        : 'nothing is being persisted (persistence.mode is "' + state.mode +
          '")';
      starting = Promise.reject(new Error(errorCodes.tag('STS-WORKER-0024') +
        'request_pool: ' + wants.length + ' entry/entries in ' +
        'workers.dispatch are configured to be handled in a request worker (' +
        wants.join(', ') + ') and THIS PROCESS IS NOT COORDINATING: ' + why +
        '. Every worker would hold its own private copy of the directory, ' +
        'the sessions and the settings, and a request answered by one would ' +
        'not see what another had written — which does not fail, it answers ' +
        'wrongly and intermittently. Configure a coordinating store ' +
        '(persistence.mode postgres with persistence.coordinate on), or ' +
        'clear workers.dispatch.'));
      log.debug("Leaving start().");
      return starting;
    }
    log.info('request_pool: coordinating through the ' + state.mode + ' ' +
             'store, so a worker sees what the others write.');

  }
  // THE SURFACE POOL'S OWN REFUSAL, for the same class of reason and in the
  // same shape. See surfacePoolProblem().
  if (surfaceCheck && surfaceCheck.fatal) {
    starting = Promise.reject(new Error(errorCodes.tag(surfaceCheck.code) +
                                        surfaceCheck.message));
    log.debug("Leaving start(). The surface pool is refused.");
    return starting;
  }
  // ---------------------------------------------------------------------
  // THE EPHEMERAL KEY-ENCRYPTION KEY, WITHOUT WHICH NOTHING MINTED IS SHARED.
  //
  // The store coordinates and the signing keys are shared, and neither reaches
  // sessions, tokens, codes or revoked jtis: those live in `sts_minted`, whose
  // rows are sealed, and development mode has no KEK to seal them with. So one
  // is generated here and handed to every worker with everything else.
  //
  // In PRODUCT mode this does nothing — `useEphemeralKek()` refuses, because
  // there the operator's KEK is already in place and the store is meant to
  // outlive the process. See keystore.js.
  // ---------------------------------------------------------------------
  // (THE OID4VCI REQUEST-ENCRYPTION KEY WAS GENERATED HERE until 2026-09-12 —
  // one key for the whole process, handed to every worker in the environment,
  // shared by every trust realm. It is a member of each realm's key set now, so
  // the key channel installed below carries it per realm and the keystore
  // writes it down in product mode; nothing about it happens in this file.)
  if (!keystore.hasEphemeralKek()) {
    const generated = nodeCrypto.randomBytes(32).toString('hex');
    if (keystore.useEphemeralKek(generated)) {
      log.info('request_pool: a per-run key-encryption key was generated, so ' +
               'every worker seals and opens the same minted rows. Nothing ' +
               'minted survives a restart, which is unchanged.');
    }
  }

  // THE PARENT'S OWN KEY GENERATION JOINS THE REGISTRY. Installed before the
  // first fork so that a realm generated here on the way up is already in
  // `sharedAll()` when the workers are handed their seed.
  keystore.setKeyPublisher(function (realmId, blob) {
    broadcastKeys(realmId, blob, null);
  });

  // AND THE PARENT'S OWN CERTIFICATE AUTHORITY WORK, for the same reason and
  // installed at the same point. `/admin` holds affinity, so the console's
  // build normally lands on one worker — but `/admin-api` FANS OUT and the
  // front process itself restores hierarchies from the store at startup, so
  // both directions have to be covered.
  keystore.setPkiPublisher(function (realmId, chain) {
    broadcastPki(realmId, chain || null, null);
  });

  // AND THE DIRECTORY'S CONNECTION LIST, for the same reason and installed at
  // the same point: a client can be bound on 389 before the first worker is
  // ready — the listeners start from `listen()` in server.js and nothing waits
  // for this pool — and a worker forked afterwards is handed the current
  // snapshot at `begin`. So the two paths together cover every ordering. See
  // publishDirectoryConnections().
  directory().setConnectionWatcher(function (rows) {
    publishDirectoryConnections(rows);
  });
  log.info('request_pool: starting ' + wanted + ' request worker(s) — ' +
           wantedByPool[PROTOCOL_POOL] + ' for the protocols and ' +
           wantedByPool[SURFACE_POOL] + ' for the hosted surfaces (' +
           (wantedByPool[SURFACE_POOL] ? surfacePrefixes().join(', ')
                                       : 'none') + '). Each ' +
           'loads the whole protocol stack and binds no protocol port.');
  const forks = [];
  POOLS.forEach(function (pool) {
    for (let i = 0; i < wantedByPool[pool]; i++) {
      forks.push(fork(pool).settled);
    }
  });
  starting = Promise.all(forks).then(function (settled) {
    const up = settled.filter(Boolean).length;
    const upByPool = {};
    POOLS.forEach(function (pool) {
      upByPool[pool] = settled.filter(function (one) {
        return one && one.pool === pool;
      }).length;
    });
    if (!up) {
      // EVERY worker failed. Reported loudly and NOT fatal: the front process
      // can still serve every request itself, which is what
      // `workers.requestCount = 0` means. A service that refused to start
      // because its workers did would be a worse outcome than a slow one.
      log.error(errorCodes.tag('STS-WORKER-0025') +
        'request_pool: not one of ' + wanted + ' request worker(s) ' +
        'started, so every request is being handled in the process that ' +
        'holds the sockets. The reason is in the lines above this one.');
    } else if (up < wanted) {
      log.warn(errorCodes.tag('STS-WORKER-0026') +
               'request_pool: ' + up + ' of ' + wanted + ' request worker(s) ' +
               'started (' + upByPool[PROTOCOL_POOL] + ' of ' +
               wantedByPool[PROTOCOL_POOL] + ' protocol, ' +
               upByPool[SURFACE_POOL] + ' of ' + wantedByPool[SURFACE_POOL] +
               ' hosted-surface).');
    }
    return { started: up, wanted: wanted,
             pools: POOLS.map(function (pool) {
               return { pool: pool, started: upByPool[pool],
                        wanted: wantedByPool[pool] };
             }) };
  });
  log.debug('Leaving start().');
  return starting;
}

// ---------------------------------------------------------------------------
// READ-YOUR-WRITE ACROSS WORKERS (2026-09-07).
//
// Coordination makes workers CONVERGE, and convergence is not read-your-write:
// measured at 0.5 to 1.0 seconds, a client that wrote through one worker and
// read through another could be answered by a worker that had not caught up.
// Within one worker a write is instant; across the pool it was not, and for
// `/scim/v2`, `/xacml` and `/admin-api` — which fan out precisely so that
// consecutive requests land anywhere — that is the shape a caller notices.
//
// ---------------------------------------------------------------------------
// THE DESIGN, AND THE ONE THAT WAS REJECTED FIRST.
//
// The obvious fix is to make the WRITE wait: on a mutating request, wake every
// worker and hold the response until they all confirm. It is simple and it
// puts the cost in the wrong place — every write pays for every worker, on
// every write, whether or not anybody was ever going to read it from
// elsewhere. A bulk load of five thousand entries would pay it five thousand
// times to serve a read-back that happens once.
//
// So the cost is paid by the READER that needs it. The pool keeps a
// GENERATION: a counter bumped when a request that may have written completes.
// Each worker remembers the generation it has caught up to. Before a worker
// serves, if its generation is behind, it is asked to catch up and the request
// waits for that — one barrier per worker per write-burst, and none at all
// while nothing is being written.
//
// **WHAT COUNTS AS A WRITE IS THE METHOD AND NOT THE HANDLER**, which is
// conservative on purpose. The front process is proxying bytes and does not
// know whether a POST changed anything; treating every non-idempotent method
// as a write costs an occasional unnecessary pull and cannot miss one. Reading
// the handler's mind — or the store's dirty flag, which lives in the WORKER —
// would be the version of this that is wrong in the direction that matters.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES AND DOES NOT PROMISE.
//
// It gives **read-your-write and monotonic reads across the pool**: no worker
// serves a request having seen less than what the pool had already answered
// for. It is deliberately GLOBAL rather than per-client — a per-client version
// token would be tighter, and it would mean inventing a client identity for
// surfaces that authenticate per call and have none. The cost of the wider
// scope is one extra pull, on workers that were behind anyway.
//
// It says nothing about the KDC replay caches or the DPoP jti sets, which
// converge and are documented as converging — see replication.status()'s own
// note. A barrier in front of a request cannot fix a window inside a protocol.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AND IT IS OFF BY DEFAULT, which is a policy choice rather than a doubt about
// the mechanism.
//
// What it costs is real and is paid on the READ side: after any write, the
// next request on each worker that is behind waits for that worker to pull —
// milliseconds against a healthy store, and a wait that did not exist before.
// A service whose callers never write and immediately read from a different
// connection pays it for nothing.
//
// What it buys is a guarantee that the fanout subsystems otherwise do not
// make. Turning it on is therefore a decision about the CALLERS rather than
// about the pool, and only an operator knows which they have — so the default
// is the behaviour that existed before it, and the setting is the way to ask
// for more.
// ---------------------------------------------------------------------------
function readYourWrite() {
  log.debug("Entering readYourWrite().");
  try {
    log.debug("Leaving readYourWrite().");
    return !!config.value('workers.readYourWrite');
  } catch (e) {
    log.debug("Caught in readYourWrite(): " + ((e && e.message) || e));
    log.debug("Leaving readYourWrite().");
    // No configuration at all — the parent project's in-process jobs, npm
    // test. Off is the answer that changes nothing.
    return false;
  }
}

// Bumped when a request that may have written completes. Workers carry the
// generation they have caught up to; a worker at the current one needs no
// barrier.
let generation = 0;

// ---------------------------------------------------------------------------
// AND BUMPED WHEN **THIS** PROCESS WRITES, WHICH IT DOES MORE THAN IT LOOKS
// (2026-09-09).
//
// The generation moved only in receiveCommitted(), on a WORKER's announcement.
// That is the whole story for anything that arrives over the dispatched HTTP
// port — and this process answers on five more socket families that are never
// dispatched at all, because they are not `app`: the two TLS listeners have a
// handler of their own (`tls_server.js`), the directory has its own protocol,
// and so do the KDC and SPIFFE's gRPC pair. Every session, principal and entry
// minted there is written by THIS process, and no worker was ever told.
//
// **THE SYMPTOM WAS A SIGN-OUT THAT LEFT A SESSION BEHIND.** A verified client
// certificate on 9443 starts a sign-on session (2026-09-05); the session is
// minted here, `/logout` is answered by a worker, and the worker's own copy of
// the session store had never heard of it — so a global sign-out reported
// ending everything and left a live way in. It is intermittent by nature: the
// worker gets there eventually on the replication poll, so the failure depends
// on how long the run takes to reach the sign-out.
//
// **THE COUNTER IS THE SIGNAL AND IT IS THE RIGHT ONE.**
// `persistence.changeRowsWritten()` counts rows COMMITTED to the change log,
// so it moves when there is something a worker can actually pull — never
// merely when this process changed its own memory. Bumping on that is the same
// contract receiveCommitted() keeps for a worker: the generation moves once
// the write is fetchable, and the barrier does the waiting.
//
// It is sampled at DISPATCH rather than pushed from the writer, and that is
// deliberate: the alternative is every one of those five socket families
// learning about this pool, which is the coupling `worker.js` and the
// request-worker design have avoided from the start. A comparison of two
// integers on a request that was about to cross a process boundary anyway is
// not a cost worth avoiding.
//
// The FIRST sample bumps nothing. This process writes plenty on the way up —
// seeding the directory, the realm registry, the applications — and all of it
// is in the store before a worker forks, so a bump there would send every
// worker through a barrier to fetch what it already had.
// ---------------------------------------------------------------------------
let localWritesSeen = -1;

function noteLocalWrites(written) {
  log.debug("Entering noteLocalWrites().");
  if (!readYourWrite()) {
    log.debug("Leaving noteLocalWrites().");
    return false;
  }
  const count = Number(written) || 0;
  if (localWritesSeen < 0) {
    localWritesSeen = count;
    log.debug("Leaving noteLocalWrites().");
    return false;
  }
  if (count <= localWritesSeen) {
    log.debug("Leaving noteLocalWrites().");
    return false;
  }
  // The delta is read BEFORE the baseline moves, which is the ordinary shape
  // of this mistake and prints "0 change row(s)" for ever when it is got wrong.
  const added = count - localWritesSeen;
  localWritesSeen = count;
  generation++;
  log.debug('noteLocalWrites(): this process committed ' + added +
            ' change row(s) of its own; the generation is now ' + generation +
            ', so every worker catches up before it answers again.');
  log.debug("Leaving noteLocalWrites().");
  return true;
}

// What this process has committed, asked of the store rather than remembered.
// `persistence` is required HERE for the reason every other require in this
// file is lazy: it sits above the protocol modules in the require order and a
// top-level require would pull it into the router's position.
function localWriteCount() {
  log.debug("Entering localWriteCount().");
  try {
    log.debug("Leaving localWriteCount().");
    return require('../persistence/persistence').changeRowsWritten();
  } catch (e) {
    log.debug("Caught in localWriteCount(): " + ((e && e.message) || e));
    log.debug("Leaving localWriteCount().");
    // No store, or none that counts. Nothing to notice, which is the honest
    // answer for a process that cannot have written a change row.
    return 0;
  }
}

// Methods that may write. HEAD and GET are the whole of the other list, and
// OPTIONS is a preflight — anything else is treated as a write.
const READ_ONLY_METHODS = { GET: true, HEAD: true, OPTIONS: true };

function mayWrite(method) {
  log.debug("Entering mayWrite().");
  log.debug("Leaving mayWrite().");
  return !READ_ONLY_METHODS[String(method || '').toUpperCase()];
}

// How long a barrier may hold a request. Reaching it means the store is
// unwell rather than that more time is needed, and the request is then served
// from what that worker has — which is the behaviour before this existed.
const BARRIER_TIMEOUT_MS = 5000;

let nextSyncId = 1;
const pendingSyncs = new Map();

// Ask one worker to catch up, and resolve when it has. Resolves rather than
// rejects on every path: the caller is about to serve a request.
//
// ---------------------------------------------------------------------------
// ONE SYNC PER WORKER AT A TIME, SHARED BY EVERY READER IT COVERS (2026-09-13).
//
// Every reader used to send a sync message of its own. Each one is a
// `persistence.syncNow()` in the worker, which reads the change log's target
// and pulls — a database round trip or two per READER. Under the loopback
// storm a session sweep sets off that was 5,759 syncs outstanding at one
// worker inside a minute, every one of them timing out at the 5,000ms bound,
// and a pool whose connections were all held by them: the same run logged
// `Connection terminated due to connection timeout` for a minted flush.
//
// **SHARING IS SOUND IN ONE DIRECTION ONLY, AND THE RULE IS `wanted`.** A
// round started for generation W was started after W had been announced, so
// the target it reads covers every write that moved the generation to W or
// below — a reader wanting W or less may take its answer. A reader wanting MORE
// may not: that write can have committed after the round read its target. So
// it waits for ONE queued round, started when the running one settles, for the
// highest generation asked for in between. Two syncs per worker at most,
// however many readers.
//
// The per-reader bound is unchanged — each reader still gives up at
// BARRIER_TIMEOUT_MS — and a round has the same bound of its own, so a worker
// that never answers costs one round rather than wedging every later reader
// behind a sync that will not come back.
// ---------------------------------------------------------------------------
function barrier(entry, wanted) {
  log.debug('Entering barrier(). pid=' + entry.pid + ' want=' + wanted);
  if (entry.generation >= wanted) {
    log.debug('Leaving barrier(). Already current.');
    return Promise.resolve(true);
  }
  log.debug("Leaving barrier().");
  return new Promise(function (resolve) {
    let done = false;
    const timer = setTimeout(function () {
      if (done) {
        return;
      }
      done = true;
      warnSparingly('STS-WORKER-0027',
                    'request_pool: worker ' + entry.pid + ' did not answer a ' +
                    'read barrier within ' + BARRIER_TIMEOUT_MS + 'ms; the ' +
                    'request is being served from what that worker has.');
      resolve(false);
    }, BARRIER_TIMEOUT_MS);
    syncRoundFor(entry, wanted).then(function (ok) {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(timer);
      resolve(!!ok);
    });
  });
}

// The round a reader wanting `wanted` may take its answer from: the running
// one if it covers that generation, otherwise the one queued behind it.
function syncRoundFor(entry, wanted) {
  log.debug('Entering syncRoundFor(). pid=' + entry.pid + ' want=' + wanted);
  const running = entry.syncing;
  if (!running || running.settled) {
    log.debug("Leaving syncRoundFor(). A new round.");
    return startSyncRound(entry, wanted).promise;
  }
  if (running.wanted >= wanted) {
    log.debug("Leaving syncRoundFor(). The running round covers it.");
    return running.promise;
  }
  if (entry.syncQueued) {
    // RAISED, NOT REPLACED: everybody already waiting on the queued round
    // still wants no more than it did, and the round reads `wanted` only when
    // it starts.
    if (entry.syncQueued.wanted < wanted) {
      entry.syncQueued.wanted = wanted;
    }
    log.debug("Leaving syncRoundFor(). Joined the queued round.");
    return entry.syncQueued.promise;
  }
  const queued = { wanted: wanted, promise: null };
  queued.promise = running.promise.then(function () {
    if (entry.syncQueued === queued) {
      entry.syncQueued = null;
    }
    // Another round may have covered it while this one waited.
    if (entry.generation >= queued.wanted) {
      return true;
    }
    return startSyncRound(entry, queued.wanted).promise;
  });
  entry.syncQueued = queued;
  log.debug("Leaving syncRoundFor(). Queued a round behind the running one.");
  return queued.promise;
}

// One sync message to one worker, settled by its answer, by the bound, or by a
// channel that would not take the message. Resolves `ok` and never rejects.
function startSyncRound(entry, wanted) {
  log.debug('Entering startSyncRound(). pid=' + entry.pid + ' want=' +
            wanted);
  const id = nextSyncId++;
  const round = { wanted: wanted, settled: false, promise: null };
  // SET BEFORE THE MESSAGE IS SENT, because a channel that refuses it settles
  // the round synchronously below, and a round recorded after it had settled
  // would read as running to every reader after it.
  entry.syncing = round;
  let settle = null;
  round.promise = new Promise(function (resolve) {
    settle = resolve;
  });
  let timer = null;
  const finish = function (message) {
    log.debug("Entering finish().");
    if (round.settled) {
      log.debug("Leaving finish(). Already settled.");
      return;
    }
    round.settled = true;
    if (timer) {
      clearTimeout(timer);
    }
    pendingSyncs.delete(id);
    // STAMPED WITH THE GENERATION THAT WAS ASKED FOR, not the one now: a
    // write that landed while this barrier ran bumps the counter again and
    // must make this worker stale again. Stamping `generation` here would
    // mark it current for a write it has not seen. And NEVER BACKWARDS: two
    // rounds can settle out of order, and the earlier one's generation is
    // the smaller.
    if (message.ok && !(entry.generation >= round.wanted)) {
      entry.generation = round.wanted;
    }
    if (entry.syncing === round) {
      entry.syncing = null;
    }
    settle(!!message.ok);
    log.debug("Leaving finish().");
  };
  timer = setTimeout(function () {
    finish({ ok: false });
  }, BARRIER_TIMEOUT_MS);
  pendingSyncs.set(id, finish);
  try {
    entry.child.send({ sync: true, id: id });
  } catch (e) {
    log.debug("Caught in startSyncRound(): " + ((e && e.message) || e));
    finish({ ok: false });
  }
  log.debug('Leaving startSyncRound(). id=' + id);
  return round;
}

function receiveSync(entry, message) {
  log.debug("Entering receiveSync().");
  const waiter = pendingSyncs.get(message.id);
  if (!waiter) {
    log.debug("Leaving receiveSync().");
    return;
  }
  pendingSyncs.delete(message.id);
  waiter(message);
  log.debug("Leaving receiveSync().");
}

// ---------------------------------------------------------------------------
// THE MIDDLEWARE. Everything above exists for these forty lines.
//
// It is installed in app.js ABOVE every route and BELOW the realm middleware —
// above, because a dispatched request must not be handled here; below, because
// the realm is what the worker has to be told and app.js's first middleware is
// what works it out.
// ---------------------------------------------------------------------------
function middleware(options) {
  log.debug("Entering middleware().");
  // `enterRealm` is app.js's realm middleware, asked once more for a request
  // kept here that it could not place in a realm before the catch-up below.
  const enterRealm = options && typeof options.enterRealm === 'function'
    ? options.enterRealm : null;
  if (IS_REQUEST_WORKER) {
    // A worker HANDLES requests; it does not dispatch them. Returning a bare
    // pass-through rather than checking on every request keeps the hot path in
    // a worker free of a test whose answer cannot change.
    log.debug('request_pool: this process is a request worker, so the ' +
              'dispatch middleware is a pass-through.');
    log.debug("Leaving middleware().");
    return function (req, res, next) { next(); };
  }
  log.debug("Leaving middleware().");
  return function (req, res, next) {
    if (!dispatched(req.originalUrl || req.url)) {
      // ---------------------------------------------------------------------
      // KEPT HERE — AND THIS PROCESS CATCHES UP FIRST (2026-09-08).
      //
      // The front process was the ONE participant in this service that never
      // ran a read barrier. Every dispatched request gets one before it
      // reaches a worker; a request kept here got none, so this process
      // answered from whatever it had last pulled on its timer.
      //
      // `/tls` does not need it — its whole content is the connection in front
      // of it. **The two truststore doors DO (2026-09-12)**: they are a console
      // page behind a session and an API behind a token, answered by a process
      // that did not mint either, which is exactly the case the next sentence
      // describes. It was written for the next entry, and it is here rather
      // than in a comment because the list is exactly where somebody adds a
      // path without thinking about staleness. It was written when
      // `/admin/spiffe` was briefly on the list: a console page behind a
      // session, answered by a process that could not yet see the session a
      // worker had just minted. That path is dispatched again — `spiffe_ca.js`
      // shares the authority now — and the lesson it taught is worth keeping.
      //
      // `syncNow()` rather than the generation check, because the generation
      // is a property of the WORKERS and this process is not one of them; and
      // it resolves rather than rejects on a store that cannot be read, so
      // the request is answered from what this process has — which is what
      // every other caller of it already does.
      // ---------------------------------------------------------------------
      if (!readYourWrite()) {
        next();
        return;
      }
      // Required HERE rather than at the top of the file, for the reason
      // start() gives below: this file is loaded by app.js, above every
      // protocol module, so a top-level require would pull the store into the
      // router's position. By now it is a cache hit.
      const persistence = require('../persistence/persistence');
      // **AND IT WAITS FOR WHAT A WORKER HAS ANSWERED FIRST (2026-09-14).**
      // `syncNow()` pulls what is COMMITTED, and a write a worker answered a
      // moment ago may not be yet — that is exactly the window the tickets
      // exist for, and a dispatched reader waits them out below. This process
      // did not: a console sign-in finished on a surface worker and the very
      // next request, to `/admin/tls/trust`, was answered here 30ms later with
      // a 401, because the session was answered and not committed.
      // `sts_realm_administrators` failed on it in `dispatch` mode. No worker
      // answers this request, so none is exempted (`servedBy` null).
      awaitCommitConfirmations(null).then(function () {
        return persistence.syncNow();
      }).catch(function (e) {
        log.debug('request_pool: the front process could not catch up before ' +
                  'answering ' + (req.originalUrl || req.url) + ': ' +
                  e.message);
      }).then(function () {
        // **AND A REALM THE CATCH-UP BROUGHT IS ENTERED NOW (2026-09-15).**
        // app.js placed this request in a realm before the wait above, so a
        // realm a worker created a moment ago was unknown then and the
        // `/realm/<id>` prefix was left on the path — which the router answers
        // `Cannot POST`. A request already in a realm is not asked again;
        // `enterRealm` calls `next()` itself whether or not it matches now.
        if (!req.realm && enterRealm) {
          enterRealm(req, res, next);
          return;
        }
        next();
      });
      return;
    }
    // THE ROUTING POLICY, IN ONE LINE. A path named in `workers.fanout` goes to
    // the least-loaded worker whatever it carries; everything else dispatched
    // is stuck to the session or flow it belongs to. See fanoutPrefixes().
    const url = req.originalUrl || req.url;
    // AND WHICH POOL FIRST — the hosted surfaces have workers of their own when
    // `workers.surfaceCount` says so. Everything below is the same in either
    // pool; see the two-pools block above the worker table.
    const pool = poolFor(url);
    const key = fansOut(url) ? mutationKeyOf(req, url)
                             : affinityKeyOf(req, pool);
    // BATCH TRAFFIC WAITS FOR ITS LANE FIRST (2026-09-14) — see the batch
    // lane's header. Only where the pool has workers to protect: a pool that
    // is empty, gave up or is stopping is answered below exactly as before.
    if (isBatch(url) && size(pool) && !givenUp[pool] && !stopped &&
        readyWorkers(pool).length) {
      admitBatch(pool, req, res, function (release) {
        res.on('finish', release);
        res.on('close', release);
        route(laneWorkers(pool));
      });
      return;
    }
    route(null);
    // THE ROUTING AND THE BARRIER, as a function so that a batch request can
    // run it when its lane has room. A HOT PATH — every dispatched request
    // passes through it — so no Entering/Leaving pair, for the reason the
    // middleware around it has none: it would drown the log.
    function route(among) {
      const entry = workerFor(key, pool, among);
      if (!entry) {
        if (!size(pool) || givenUp[pool] || stopped) {
          // No pool is configured, or it gave up, or we are shutting down.
          // Handled here, which is the supported configuration rather than a
          // degraded one. (A SURFACE pool that is configured never reaches
          // this with `size(pool)` zero or given up — poolFor() has already
          // sent the request to the protocol pool — so this is the protocol
          // pool's line.)
          next();
          return;
        }
        // A pool IS configured and has no worker to give. Refused rather than
        // handled here — see the header: the same path served from two
        // processes depending on timing is the bug this is avoiding.
        log.error(errorCodes.tag('STS-WORKER-0028') +
          'request_pool: ' + req.method + ' ' + req.url + ' matched the ' +
          'dispatch list and no ' + pool + ' worker is serving, so it is ' +
          'refused. Handling ' +
          'it here instead would mean this path is answered by whichever ' +
          'process happened to be available, out of two that do not share ' +
          'state.');
        errorCodes.mark(res, 'STS-WORKER-0028');
        res.status(503);
        res.set('Retry-After', '5');
        res.type('text/plain');
        res.send('No request worker is available. This path is dispatched to ' +
                 'the worker pool (workers.dispatch) and the pool is empty; ' +
                 'the service log says why.\n');
        return;
      }
      // ---------------------------------------------------------------------
      // THE BARRIER, BEFORE THE REQUEST IS SENT AND NOT AFTER.
      //
      // The generation is read HERE and carried into the proxy, so a write that
      // lands while this request is in flight does not retroactively make this
      // worker look current for it. A request only waits when the worker chosen
      // for it is actually behind, which after a quiet second is never.
      // ---------------------------------------------------------------------
      // ANSWERED-BUT-UNCOMMITTED WRITES FIRST, and only then the generation.
      // The two are different questions: this one is "has everything that has
      // been answered actually landed in the store", which no generation can
      // express because the generation does not move until it has. Without it a
      // reader that arrives inside that window never waits at all — measured as
      // stale reads with zero barrier timeouts.
      if (!readYourWrite()) {
        proxy(entry, req, res, generation);
        return;
      }
      // ONE TICKET PER DISPATCHED REQUEST, TAKEN BEFORE IT IS SENT. Anything
      // that arrives after this line necessarily sees this request
      // outstanding, which is the property taking it on `finish` could not
      // give.
      // **WAIT FIRST, THEN TAKE THE TICKET.** The other order deadlocks: the
      // request would be waiting for a ticket it holds itself, which nothing
      // can confirm until it has finished. So this waits for everything
      // dispatched BEFORE it, and only then registers itself as outstanding
      // for everything that comes after.
      awaitCommitConfirmations(entry).then(function () {
        const ticket = dispatchTicket(entry);
        // WHAT THIS PROCESS ITSELF HAS WRITTEN SINCE THE LAST REQUEST, before
        // the generation is read — a bump after this line would be a bump this
        // request does not wait for. See noteLocalWrites().
        noteLocalWrites(localWriteCount());
        const wanted = generation;
        if (entry.generation >= wanted) {
          proxy(entry, req, res, wanted, ticket);
          return;
        }
        return barrier(entry, wanted).then(function () {
          proxy(entry, req, res, wanted, ticket);
        });
      });
    }
  };
}

// One request, streamed to a worker and streamed back. The front process copies
// no body into memory and parses nothing: `req` is piped in and the answer is
// piped out.
function proxy(entry, req, res, atGeneration, ticket) {
  log.debug('Entering proxy(). pid=' + entry.pid + ' ' + req.method + ' ' +
            req.url);
  const wrote = mayWrite(req.method);
  entry.inFlight++;
  let done = false;
  // WHETHER THE WORKER EVER GOT AS FAR AS AN ANSWER. It decides which of the
  // two ticket endings this request has — see ticketAbandoned(), which is the
  // one for a request the client was handed a 502 for.
  let answered = false;
  // WHETHER THIS PROCESS ENDED THE UPSTREAM REQUEST ITSELF, because the client
  // went away first. See the response's `close` handler at the foot.
  let clientGone = false;
  const finish = function (lost) {
    log.debug("Entering finish().");
    if (!done) {
      done = true;
      entry.inFlight--;
      entry.served++;
      // THE TICKET IS TAKEN AT DISPATCH NOW, NOT HERE — see dispatchTicket().
      // Taking it on `finish` left a window the client could drive straight
      // through: `finish` fires after the response has been flushed, so a
      // client that sends its next request the moment it has the answer
      // arrived before its ticket existed, waited for nothing, and was served
      // by a worker that had not seen the write. Measured exactly: register a
      // client then immediately ask for a token and the registration is
      // overwritten by the stale reader; put four seconds between them and it
      // survives.
      if (ticket) {
        // A REQUEST THE WORKER NEVER ANSWERED RELEASES ITS TICKET INSTEAD OF
        // ARMING IT. `ticketFinished()` is what makes a ticket block readers,
        // and the worker only announces tickets for responses IT completed —
        // so arming one the worker never saw is a ticket nothing will ever
        // clear. That is the wedge ticketAbandoned() documents.
        if (lost) {
          ticketAbandoned(entry, ticket);
        } else {
          ticketFinished(entry, ticket);
        }
      }
      // ----------------------------------------------------------------
      // NEITHER A SECOND TICKET NOR A GENERATION BUMP IS TAKEN HERE, and both
      // were tried (2026-09-07).
      //
      // A SECOND TICKET, marked synchronously on `finish` so that a reader
      // arriving before the announcement could see something in flight: it was
      // redundant once the ticket moved to DISPATCH, because the dispatched
      // ticket already covers that window and is not cleared until the worker
      // says its flush covered it.
      //
      // A GENERATION BUMP on a write-method request finishing: it named a
      // write that had not landed. `persistence.js` schedules its flush a tick
      // after the response, so a reader released on that bump was told it was
      // current before the change log could possibly have held the row. The
      // bump is in receiveCommitted() now, on the worker's own `wrote` flag,
      // which is the only thing that knows whether anything was actually
      // written — and gates it, so a request that wrote nothing does not make
      // every other worker stale for no reason.
      // ----------------------------------------------------------------
    }
    log.debug("Leaving finish().");
  };

  const headers = Object.assign({}, req.headers);

  // ---------------------------------------------------------------------
  // THE CLIENT CERTIFICATE, AND THE HEADERS A CLIENT MAY NOT SET.
  //
  // Several surfaces here decide on the TLS CONNECTION rather than on the
  // request: RFC 8705 binds an access token to the certificate that completed
  // the handshake, SCIM offers a client-certificate scheme, and `/xacml/pep/*`
  // admits a remote PEP only on a certificate this service VERIFIED whose DN
  // resolves to a directory entry holding `REMOTE_PEPS`. A proxied request
  // arrives in the worker on a unix socket, which has no peer certificate at
  // all — so without this, dispatching would silently turn every one of those
  // into "no certificate presented".
  //
  // **STRIPPED FIRST, ALWAYS.** These headers are how the worker learns the
  // certificate, so a client that could set them itself could claim a verified
  // certificate for any subject — which on `/xacml/pep/*` is the difference
  // between a gate and a doorway. They are deleted from what the client sent
  // BEFORE the real values are written, so a forged one cannot survive even if
  // this process later decides there is no certificate to forward.
  // ---------------------------------------------------------------------
  delete headers[PEER_CERT_HEADER];
  delete headers[PEER_AUTHORIZED_HEADER];
  // Nothing a client says about whose directory connections should close may be
  // believed. See LDAP_DROP_HEADER.
  delete headers[LDAP_DROP_HEADER];
  // THE POOL'S OWN COOKIE IS THE POOL'S. Removed from what the worker sees so
  // that no handler can come to depend on a routing detail, and so that it
  // cannot be confused with an application cookie by anything that enumerates
  // them — `/admin/logout` draws a list of cookies, and a routing token in it
  // would be a question nobody can answer.
  // BOTH pools' cookies, whichever pool this request is going to: a surface
  // worker has no more business seeing the protocol pool's pin than its own.
  if (headers.cookie) {
    const kept = String(headers.cookie).split(';').filter(function (bit) {
      const trimmed = bit.trim();
      return trimmed.indexOf(POOL_COOKIE + '=') !== 0 &&
             trimmed.indexOf(SURFACE_POOL_COOKIE + '=') !== 0;
    });
    if (kept.length) {
      headers.cookie = kept.join(';');
    } else {
      delete headers.cookie;
    }
  }
  const peer = peerOf(req);
  if (peer) {
    headers[PEER_CERT_HEADER] = peer.cert;
    headers[PEER_AUTHORIZED_HEADER] = peer.authorized ? 'yes' : 'no';
  }
  delete headers[POOL_TICKET_HEADER];
  if (ticket) {
    headers[POOL_TICKET_HEADER] = String(ticket);
  }
  // WHICH PROTOCOL WORKER THIS BROWSER IS HELD BY, told to a SURFACE worker
  // only — see PROTOCOL_WORKER_HEADER. Asked with heldWorker() and not
  // workerFor(), so that nothing is bound by asking; a browser the protocol
  // pool holds no binding for gets no header, and its back channel is routed by
  // load exactly as a cookie-less request is.
  delete headers[PROTOCOL_WORKER_HEADER];
  if (entry.pool === SURFACE_POOL) {
    const holder = heldWorker(affinityKeyOf(req, PROTOCOL_POOL),
                              PROTOCOL_POOL);
    if (holder) {
      headers[PROTOCOL_WORKER_HEADER] = String(holder.pid);
    }
  }
  // ---------------------------------------------------------------------
  // THE REALM IS NOT TOLD TO THE WORKER; THE WORKER WORKS IT OUT.
  //
  // `req.originalUrl` still carries the `/realm/<id>` prefix — app.js's first
  // middleware strips `req.url` and deliberately leaves the original alone —
  // so sending THAT gives the worker the path the client actually asked for,
  // and the worker's own copy of that same middleware derives the same realm
  // by the same rule.
  //
  // A header carrying the realm id was written first and thrown away: it would
  // have been a SECOND mechanism for deciding which realm a request is in,
  // and the two would disagree the first time somebody changed
  // `realms.matchPath()`. One rule, run twice, cannot.
  // ---------------------------------------------------------------------
  //
  // The address the request came from, for the rate limiter and the audit log.
  // Without it every request in a worker appears to come from a unix socket —
  // which would put the whole service in ONE rate-limit bucket, and that is
  // not a subtle failure: `tests/CLAUDE.md` records the suite tripping the
  // per-address limiter when it was one address.
  //
  // **THE CLIENT AS RESOLVED HERE, AND ONE ADDRESS (2026-09-14, #46).** This
  // wrote `req.ip`, which in this process is the socket's peer — behind a load
  // balancer, the balancer, so every caller shared one bucket — and the worker
  // read it only when `global.trustProxy` was on, answering `unknown` (a unix
  // socket has no peer address) for everybody otherwise. It is now
  // `client_address.js`'s answer: the peer, or with `global.trustedProxies`
  // set the right-most forwarded hop that is not one of them, and the worker
  // believes it because nothing but this process reaches its socket. A
  // forwarded host from a peer that may not forward is dropped, so the worker
  // cannot believe what this process would not have. **Behind an L4 balancer
  // with `global.proxyProtocol` on, the peer IS the client**:
  // `common/proxy_protocol.js` put the header's address on the socket before
  // this request was parsed, so what is written here is that address and the
  // balancer never appears (`tests/proxy_protocol.js` 3a).
  headers['x-forwarded-for'] = clientAddress.clientAddressOf(req) ||
    req.ip || (req.connection && req.connection.remoteAddress) || '';
  if (!clientAddress.forwardedBelieved(req)) {
    delete headers['x-forwarded-host'];
  }
  headers['x-forwarded-proto'] = req.protocol || 'https';
  if (req.headers && req.headers.host) {
    headers.host = req.headers.host;
  }

  const upstream = http.request({
    socketPath: entry.socket,
    path: req.originalUrl || req.url,
    method: req.method,
    headers: headers,
    // THIS WORKER'S OWN AGENT, which is what bounds how many connections the
    // front process may have open to it at once. See the block where it is
    // made: without it this used the global agent, `maxSockets: Infinity`, and
    // a bulk load answered one request in five thousand with a 502 that named
    // `connect EAGAIN`.
    agent: entry.agent
  }, function (answer) {
    // **AND NOT ALONGSIDE A SESSION COOKIE (2026-09-07).** The pin is APPENDED
    // to `set-cookie`, and a client that keeps only the last one it is sent —
    // which several of this repository's own test browsers do, on the premise
    // that "this service sets exactly one cookie", true until this pool existed
    // — then keeps the pin and DROPS the session. The service is handed a
    // request with no session cookie and answers "nobody is signed in", which
    // is what sts_consent, sts_portal_sessions, sts_global_logout and sts_roles
    // were all measuring.
    //
    // Nothing is lost by skipping it here: `learn()` below binds `s:<id>` from
    // this very response, so the session cookie routes to this worker by lookup
    // on the next request. The pin is for the hops a session id cannot cover.
    const setsSession = (function () {
      const set = answer.headers && answer.headers['set-cookie'];
      if (!set) { return false; }
      const list = Array.isArray(set) ? set : [set];
      return list.some(function (one) {
          const bit = String(one).split(';')[0].trim();
        const named = sessionCookieName(bit);
        return !!named && bit.length > named.length + 1;
      });
    })();
    if (!fansOut(req.originalUrl || req.url) &&
        !affinityKeyOf(req, entry.pool) && !setsSession) {
      // ------------------------------------------------------------------
      // PIN THIS BROWSER TO THIS WORKER. Only on an affinity path, and only
      // when the request ARRIVED WITH NO AFFINITY OF ITS OWN — a fanout caller
      // is routed by load on purpose, and re-pinning an already-pinned browser
      // on every answer would be a Set-Cookie on every response for no change.
      //
      // THE TEST IS `affinityKeyOf()` AND NOT "did it already carry a pin",
      // AND THAT IS THE WHOLE OF A BUG THAT COST A DAY. A request carrying a
      // SESSION
      // cookie already resolves to a worker — `learn()` bound that id to the
      // worker that minted it — so a pin adds nothing, and adding it is not
      // free: this service sets ONE cookie per response and every client in
      // the suite was written against that, keeping only the last `Set-Cookie`
      // it is handed. So a second cookie on a response does not join the jar,
      // it REPLACES what was in it. `GET /authn/login` answers with no session
      // cookie of its own, so a pin appended there wiped the session cookie
      // the browser had, and the login POST one hop later arrived carrying
      // nothing at all — `arrivalSessionOf()` returning null on the worker
      // that held the very session it was looking for. The pin is for a
      // request with NO other way to be routed; that is now what it says.
      //
      // `setsSession` stays beside it for the same reason read the other way:
      // a response that is MINTING a session must not have that cookie
      // displaced by a pin appended after it.
      //
      // `SameSite=Lax` rather than Strict: a SAML or WS-Federation sign-in
      // comes BACK to this service as a cross-site POST from the service
      // provider, and Strict would drop the cookie on exactly the hop the pin
      // exists for. Not `Secure` unconditionally, because this service
      // supports a plain-HTTP listener and a Secure cookie would simply never
      // be sent there — it is set when the request arrived over TLS.
      // ------------------------------------------------------------------
      // In the name of the pool the worker is in — see SURFACE_POOL_COOKIE.
      const pin = poolCookieFor(entry.pool) + '=' + entry.pid +
        '; Path=/; HttpOnly; ' +
        'SameSite=Lax' + (req.secure ? '; Secure' : '');
      const already = answer.headers['set-cookie'];
      const list = already
        ? (Array.isArray(already) ? already.slice(0) : [already])
        : [];
      list.push(pin);
      answer.headers['set-cookie'] = list;
    }
    if (!fansOut(req.originalUrl || req.url)) {
      // NOT for a fanout path. `/admin-api` and SCIM both mint sessions of
      // their own — an API session keyed on the credential — and binding those
      // would pin a caller that was deliberately routed by load, for a session
      // it never presents back on a browser cookie.
      learn(entry, answer);
    }
    // ------------------------------------------------------------------
    // THE SOCKETS THIS ANSWER SAYS TO CLOSE, CLOSED BEFORE IT GOES OUT.
    //
    // BEFORE `res.status()` and not after the pipe: everything below writes to
    // the client, and the promise this mechanism makes is that a sign-out which
    // says a directory connection ended is answering about a socket that is
    // already gone. See LDAP_DROP_HEADER.
    // ------------------------------------------------------------------
    closeDirectoryConnections(answer.headers[LDAP_DROP_HEADER]);
    // FROM HERE THE WORKER HAS ANSWERED: it ran the handler, so it will
    // announce this ticket on its own `finish` or `close` whatever happens to
    // the pipe from now on. See ticketAbandoned().
    answered = true;
    res.status(answer.statusCode);
    Object.keys(answer.headers).forEach(function (name) {
      // The worker's instruction to this process, and no business of the
      // client's — for the reason the hop-by-hop headers below are dropped, and
      // because a header naming an identity key has no place on a page.
      if (name === LDAP_DROP_HEADER) {
        return;
      }
      // Hop-by-hop headers belong to the connection this process made and not
      // to the one the client made. Passing them on is how a proxy breaks
      // keep-alive for its own clients.
      if (name === 'connection' || name === 'keep-alive' ||
          name === 'transfer-encoding') {
        return;
      }
      res.setHeader(name, answer.headers[name]);
    });
    answer.pipe(res);
    answer.on('end', finish);
    answer.on('error', function (err) {
      if (clientGone) {
        // Ended by this process for a client that had gone. Not a fault.
        log.debug('request_pool: an answer from worker ' + entry.pid +
                  ' was cut off after its client went away: ' + err.message);
      } else {
        log.warn(errorCodes.tag('STS-WORKER-0029') +
                 'request_pool: the answer from worker ' + entry.pid +
                 ' failed mid-flight: ' + err.message);
      }
      finish();
      res.destroy();
    });
  });

  upstream.on('error', function (err) {
    // `!answered` IS THE WHOLE OF THE ARGUMENT: the worker never ran the
    // handler (or died before a byte of the answer left it), so there is
    // nothing for it to announce and nothing a reader is owed.
    finish(!answered);
    if (clientGone) {
      // THIS PROCESS DESTROYED IT, because the client had already gone — see
      // the `close` handler below. Nobody is waiting for a 502 and the worker
      // did nothing wrong, so it is not an error line.
      log.debug('request_pool: ' + req.method + ' ' + req.url + ' was ' +
                'abandoned on worker ' + entry.pid + ' after its client ' +
                'went away: ' + err.message);
      return;
    }
    log.error(errorCodes.tag('STS-WORKER-0030') +
              'request_pool: worker ' + entry.pid + ' could not answer ' +
              req.method + ' ' + req.url + ': ' + err.message);
    if (res.headersSent) {
      // Already streaming. There is no status left to send, so the connection
      // is destroyed — which is what a truncated answer has to look like.
      res.destroy();
      return;
    }
    errorCodes.mark(res, 'STS-WORKER-0030');
    res.status(502);
    res.type('text/plain');
    res.send('The request worker handling this request went away (' +
             err.message + '). A worker holds no state of its own that this ' +
             'request needed, so it can simply be made again.\n');
  });

  req.pipe(upstream);
  req.on('aborted', function () {
    upstream.destroy();
    // THE CLIENT WENT AWAY. If the worker had already begun answering it will
    // announce this ticket itself; if it had not, `upstream.destroy()` means it
    // never will, and holding the ticket would block every reader for ever.
    finish(!answered);
  });
  // -------------------------------------------------------------------------
  // AND THE CLIENT GOING AWAY AFTER IT HAD SENT EVERYTHING (2026-09-13).
  //
  // `aborted` above is emitted only for a request whose BODY was cut short. A
  // client that sent a whole request and then gave up waiting — a timeout, a
  // closed tab, a loopback SSF push reaching `ssf.pushTimeoutMs` — emits
  // nothing on `req` at all, only `close` on the response with nothing
  // written. Measured on node 22: `req end`, `req close`, `res close,
  // writableFinished=false`, and no `aborted`.
  //
  // So until this handler the request went on holding its place: queued in
  // this worker's agent behind the `workers.maxSockets` cap, counted in
  // `inFlight` so that leastLoaded() steered around a worker for work nobody
  // wanted, and delivered minutes later to a handler whose answer went
  // nowhere. On the 2026-09-13 dispatch run 6,479 pushes their sender had
  // stopped waiting for were still queued that way when the server's own 300s
  // request timeout finally ended them.
  //
  // The ticket goes the way `aborted`'s does, and for its reason.
  // -------------------------------------------------------------------------
  res.on('close', function () {
    if (done || res.writableFinished) {
      return;
    }
    clientGone = true;
    upstream.destroy();
    finish(!answered);
  });
  log.debug('Leaving proxy().');
}

// ---------------------------------------------------------------------------
// OPERATIONS, WHICH ARE HOW A NON-HTTP FRONT END REACHES THE POOL.
//
// Everything above this line is about the express app, and it would be a
// mistake to read the pool as being about HTTP. **The front process owns SIX
// listener families and only one of them speaks HTTP**: the Kerberos KDC on TCP
// and UDP 88, the Kerberos service on 8888, the LDAP directory on 389 and 636,
// and SPIFFE's two gRPC surfaces are the others. The work those do has exactly
// the same reason to leave the front process as a `/scim/v2` POST does, and the
// transport they arrive on is not a reason to keep it there.
//
// So an OPERATION is the protocol-independent half: a `{ kind, args }` pair the
// front process sends to a worker and gets a result back from. The front
// process keeps the socket and the framing — it accepts the LDAP connection,
// decodes the BER, and writes the reply — and the worker does the operation.
//
// **IT GOES OVER THE IPC CHANNEL RATHER THAN THE UNIX SOCKET, and that is the
// one decision here worth arguing.** The HTTP path above uses the socket
// because a request IS HTTP and node's own parser at both ends is what makes a
// handler behave identically in a worker. An LDAP search is not HTTP and
// wrapping it in an HTTP request would be inventing a second encoding for it,
// with a URL space that then has to be kept unreachable from the outside. The
// IPC channel carries a structured clone, which takes a Buffer whole — and
// `worker_pool.js` already established that shape for the computation jobs.
//
// **THIS BLOCK SAID THE STORE WAS NOT SHARED, AND THAT STOPPED BEING TRUE
// BEFORE IT WAS WRITTEN (corrected 2026-09-12).** It read: *A worker's
// directory is ITS OWN. An LDAP `add` dispatched to a worker writes an entry
// the front process cannot see and the next worker has never heard of… So
// `ldap.*` operations are NOT dispatched by default and must not be until the
// store behind them is shared. The mechanism is here; the switch is
// deliberately not thrown.*
//
// It was the pre-coordination argument — `request_worker.js`'s "the state
// problem is real and it is not solved here", which was honest on the day it
// was written — carried forward into a file whose HTTP half had since been
// rebuilt around the change log. Three things make it false:
//
//   * **Directory changes ARE change-log rows.** `persistence.js` registers
//     `applyDirectoryChange`, which calls `directory.applyEntry(realm, key,
//     entry)` and `removeEntry()` in every other process. An entry written in
//     a worker reaches the front process and every sibling the same way a
//     realm or a setting does.
//   * **The configuration it warned about cannot be reached.** `start()`
//     refuses to bring the pool up unless the store coordinates, and the list
//     it checks is `dispatchPrefixes().concat(operationKinds())` — operations
//     are inside that guard. Naming `ldap` with a memory store does not fork
//     the directory N ways; it stops the service, naming the setting.
//   * **The same store is already written from a worker over HTTP.** `/scim/v2`
//     is a fanout prefix and SCIM has no store of its own — it writes this
//     directory entry for entry. A SCIM POST creating a person and an LDAP
//     `add` creating the same person are one mutation through one path.
//
// **WHAT IS ACTUALLY PARTICULAR TO LDAP IS THE CONNECTION, AND IT IS WHY THESE
// HOLD AFFINITY WHERE THE COMMENT BELOW USED TO SAY THEY FAN OUT.** RFC 4511
// section 4.2: the connection carries the authorization state and a client may
// have several operations outstanding on it at once. Two consequences neither
// the change log nor a credential-per-call covers:
//
//   * **A client reads its own writes on its own connection.** Over HTTP a
//     caller is a series of independent requests and `workers.readYourWrite` is
//     a question about that caller's expectations. On one socket an `ldapadd`
//     followed by an `ldapsearch` is not two callers, and answering the search
//     from a worker that has not caught up is a directory contradicting itself
//     within one conversation.
//   * **Order within a connection is the client's to rely on.** Fanned out,
//     two operations sent back to back can be answered by two workers in either
//     order.
//
// Affinity is still **a locality measure and never a correctness one** — the
// rule at the top of this file is unchanged and must stay unchanged. What
// makes a dispatched LDAP write safe to read back is the barrier below, the
// same one the HTTP path uses; affinity is what keeps the common case from
// needing it. `opts.affinity` carries the CONNECTION id for exactly that
// reason, and an operation arriving without one still fans out.
// ---------------------------------------------------------------------------

let nextOperationId = 1;
const pendingOperations = new Map();

// The other half of the SAME list — the entries that do not name a URL. See
// `dispatchList()`: the leading slash is what tells the two apart, and `*` is
// in both halves because it names everything.
function operationKinds() {
  log.debug("Entering operationKinds().");
  log.debug("Leaving operationKinds().");
  return dispatchList().filter(function (one) {
    return one === '*' || one.charAt(0) !== '/';
  });
}

// Whether this operation is dispatched. A kind is `family.operation`, and a
// list entry may name the whole family (`ldap`), one of its operations
// (`ldap.search`), or everything (`*`) — so a family can be moved a piece at a
// time, which is how a store this size has any chance of being moved safely.
function operationDispatched(kind) {
  log.debug("Entering operationDispatched().");
  const kinds = operationKinds();
  if (!kinds.length) {
    log.debug("Leaving operationDispatched().");
    return false;
  }
  const family = String(kind || '').split('.')[0];
  for (let i = 0; i < kinds.length; i++) {
    if (kinds[i] === '*' || kinds[i] === kind || kinds[i] === family) {
      log.debug("Leaving operationDispatched().");
      return true;
    }
  }
  log.debug("Leaving operationDispatched().");
  return false;
}

// ---------------------------------------------------------------------------
// RUN ONE OPERATION IN A WORKER.
//
// `opts.affinity` names something to be stuck to, exactly as a session cookie
// does for a request; an operation with none FANS OUT. **LDAP passes the
// CONNECTION** — see the block above for why a connection-oriented protocol is
// different here from a credential-per-call one, and why that is a locality
// argument rather than a correctness one.
//
// It resolves `{ dispatched: false }` rather than rejecting when there is no
// pool, so a caller is written one way and the front process does the work
// itself — which is what `workers.requestCount = 0` means and is a supported
// configuration rather than a degraded one.
//
// **IT GOES THROUGH THE READ BARRIER, WHICH IT DID NOT UNTIL 2026-09-12.** The
// barrier was built for the HTTP path and nothing took an operation through
// it, so a dispatched operation was outside read-your-write entirely: a write
// through one worker moved no generation anybody waited on, and a read through
// another was never held for it. That is invisible while nothing is dispatched
// and is the whole of the guarantee the moment something is — so the three
// steps below are `dispatch()`'s, in `dispatch()`'s order, for `dispatch()`'s
// reasons. **WAIT, THEN TAKE THE TICKET**: the other order deadlocks on a
// ticket the waiter holds itself.
// ---------------------------------------------------------------------------
function runOperation(kind, args, opts) {
  log.debug('Entering runOperation(). kind=' + kind);
  const options = opts || {};
  if (IS_REQUEST_WORKER || !operationDispatched(kind)) {
    log.debug('Leaving runOperation(). Not dispatched.');
    return Promise.resolve({ dispatched: false });
  }
  // THE PROTOCOL POOL, ALWAYS. An operation is the work behind a protocol
  // socket — LDAP, SPIFFE's gRPC — and never a hosted surface's, so the surface
  // workers are not asked even when the protocol pool is empty; the caller then
  // does it here, as it does with no pool at all.
  const entry = workerFor(options.affinity ? 'op:' + options.affinity : '',
                          PROTOCOL_POOL);
  if (!entry) {
    // Unlike a dispatched PATH, this is not refused. A path named in the
    // dispatch list has an HTTP answer to give and a 503 is one; an operation
    // has a caller in this process that can simply do the work, and failing it
    // would take a protocol listener down for a pool that is a performance
    // measure.
    log.debug('Leaving runOperation(). No worker; the caller does it here.');
    return Promise.resolve({ dispatched: false });
  }
  if (!readYourWrite()) {
    log.debug('Leaving runOperation(). Sent without a barrier.');
    return sendOperation(entry, kind, args, 0);
  }
  log.debug("Leaving runOperation().");
  return awaitCommitConfirmations(entry).then(function () {
    const ticket = dispatchTicket(entry);
    // WHAT THIS PROCESS ITSELF HAS WRITTEN SINCE THE LAST ONE, before the
    // generation is read. It matters more here than on the HTTP path, not
    // less: the front process is the one that holds every socket this service
    // has, so it is the process that mints a session on 9443 and writes the
    // Kerberos replay cache — and an LDAP operation is very often the next
    // thing that has to see it.
    noteLocalWrites(localWriteCount());
    const wanted = generation;
    if (entry.generation >= wanted) {
      return sendOperation(entry, kind, args, ticket);
    }
    return barrier(entry, wanted).then(function () {
      return sendOperation(entry, kind, args, ticket);
    });
  });
}

// The send itself, split out so that the three paths above share one copy of
// the bookkeeping. A ticket of 0 means read-your-write is off and there is
// none.
function sendOperation(entry, kind, args, ticket) {
  log.debug('Entering sendOperation(). kind=' + kind + ' pid=' + entry.pid);
  const id = nextOperationId++;
  const promise = new Promise(function (resolve, reject) {
    pendingOperations.set(id, { resolve: resolve, reject: reject, kind: kind,
                                pid: entry.pid, ticket: ticket });
  });
  entry.inFlight++;
  try {
    entry.child.send({ operation: true, id: id, kind: kind, args: args,
                       ticket: ticket });
  } catch (e) {
    log.debug("Caught in sendOperation(): " + ((e && e.message) || e));
    const pending = pendingOperations.get(id);
    pendingOperations.delete(id);
    entry.inFlight--;
    // THE TICKET IS RELEASED AND NOT ARMED. The worker never got the message,
    // so it will never announce it — an armed ticket here is one nothing can
    // ever clear, which is the wedge ticketAbandoned() was written for.
    ticketAbandoned(entry, ticket);
    if (pending) {
      pending.resolve({ dispatched: false });
    }
  }
  log.debug('Leaving sendOperation(). id=' + id + ' on worker ' + entry.pid);
  return promise;
}

// One worker's answer to an operation. Called from the message handler in
// fork(); a reply for an operation this process has given up on is dropped
// rather than settling a promise twice.
function receiveOperation(entry, message) {
  log.debug('Entering receiveOperation(). id=' + message.id);
  const pending = pendingOperations.get(message.id);
  if (!pending) {
    log.debug('Leaving receiveOperation(). Nothing is waiting for that id.');
    return;
  }
  pendingOperations.delete(message.id);
  entry.inFlight--;
  entry.served++;
  // ---------------------------------------------------------------------
  // THE TICKET, AND THE TWO ENDINGS ARE THE ONES proxy() HAS.
  //
  // `ran` says whether the worker got as far as the handler. If it did, the
  // ticket is ARMED — it may now block a reader, and the worker's own
  // announcement is what will clear it. If it did not — an operation kind this
  // worker does not answer to — nothing was written and nothing will ever be
  // announced, so the ticket is RELEASED. Arming one the worker never saw is
  // the wedge that cost a 2,000ms wait on every read for the life of a
  // process; see ticketAbandoned().
  //
  // An older worker predates the `ran` field and sends neither value.
  // `message.ran !== false` reads that as "it ran", which is the safe side:
  // arming a ticket the worker will announce costs nothing, and releasing one
  // it does announce would release a reader early.
  // ---------------------------------------------------------------------
  if (pending.ticket) {
    if (message.ran === false) {
      ticketAbandoned(entry, pending.ticket);
    } else {
      ticketFinished(entry, pending.ticket);
    }
  }
  if (message.ok) {
    pending.resolve({ dispatched: true, result: message.result });
    log.debug('Leaving receiveOperation(). Resolved.');
    return;
  }
  const err = new Error(message.error);
  err.name = message.errorName || 'Error';
  pending.reject(err);
  log.debug('Leaving receiveOperation(). Rejected.');
}

// Everything a dead worker was carrying. Rejected HERE, because a promise
// nobody settles is a protocol operation that hangs — and on a raw socket that
// is a client waiting for ever, which is the failure `ldap/CLAUDE.md` records
// having already had once from a missing result message.
function failOperations(entry) {
  log.debug("Entering failOperations().");
  pendingOperations.forEach(function (pending, id) {
    if (pending.pid !== entry.pid) {
      return;
    }
    pendingOperations.delete(id);
    // ITS TICKET GOES WITH IT, RELEASED RATHER THAN ARMED. The worker is gone,
    // so it will never announce a flush covering this — and a ticket nothing
    // can clear makes every later read wait the full barrier bound and then
    // serve stale anyway. That is the wedge ticketAbandoned() was written for,
    // reached here by a worker dying rather than by a 502.
    ticketAbandoned(entry, pending.ticket);
    pending.reject(new Error('the worker process running this ' + pending.kind +
      ' operation went away before it answered. A worker holds no state that ' +
      'this operation needed, so it can simply be tried again.'));
  });
  log.debug("Leaving failOperations().");
}

// ---------------------------------------------------------------------------
// DRAIN, for shutdown. Every worker is asked to stop, given time to finish what
// it is holding, and killed if it will not. Resolves rather than rejects for
// the reason worker_pool.js gives: this is called from the SIGTERM handler,
// where a rejection would replace the sentence saying what was flushed.
// ---------------------------------------------------------------------------
function stop(timeoutMs) {
  log.debug('Entering stop().');
  stopped = true;
  const limit = timeoutMs === undefined ? 8000 : timeoutMs;
  const going = workers.slice();
  if (!going.length) {
    removeSocketDir();
    log.debug('Leaving stop(). Nothing was running.');
    return Promise.resolve({ stopped: 0, killed: 0 });
  }
  log.info('request_pool: draining ' + going.length + ' request worker(s).');
  log.debug("Leaving stop().");
  return new Promise(function (resolve) {
    let killed = 0;
    let left = going.length;
    const timer = setTimeout(function () {
      going.forEach(function (entry) {
        if (entry.child.exitCode === null && entry.child.signalCode === null) {
          killed++;
          log.warn(errorCodes.tag('STS-WORKER-0031') +
                   'request_pool: worker ' + entry.pid + ' did not finish ' +
                   'within ' + limit + 'ms and was killed.');
          entry.child.kill('SIGKILL');
        }
      });
      done();
    }, limit);
    function done() {
      log.debug("Entering done().");
      left = 0;
      clearTimeout(timer);
      // AND EVERY AGENT, for `reap()`'s reason: `stop()` is what a test calls
      // between cases, so an agent left holding sockets to a removed socket
      // directory is a handle the next `start()` has no way to reach.
      workers.forEach(function (one) {
        if (one.agent && typeof one.agent.destroy === 'function') {
          one.agent.destroy();
        }
      });
      workers = [];
      POOLS.forEach(function (pool) {
        affinities[pool].clear();
      });
      removeSocketDir();
      log.debug('Leaving stop().');
      resolve({ stopped: going.length - killed, killed: killed });
      log.debug("Leaving done().");
    }
    going.forEach(function (entry) {
      entry.retiring = true;
      entry.child.on('exit', function () {
        left--;
        if (left === 0) {
          done();
        }
      });
      try {
        entry.child.send({ stop: true });
      } catch (e) {
        // The channel has already gone; the exit handler above covers it.
        log.debug("Caught in a callback in stop(): " + ((e && e.message) || e));
      }
    });
  });
}

function removeSocketDir() {
  log.debug("Entering removeSocketDir().");
  if (!socketDir) {
    log.debug("Leaving removeSocketDir().");
    return;
  }
  try {
    fs.rmSync(socketDir, { recursive: true, force: true });
  } catch (e) {
    // Reported at debug and no further: a leftover directory in the system
    // temporary directory is untidy and is not a fault worth a line at exit.
    log.debug('request_pool: could not remove ' + socketDir + ': ' + e.message);
  }
  socketDir = '';
  log.debug("Leaving removeSocketDir().");
}

// What the pool is doing, for `/admin` and for the tests. A copy, so a reader
// cannot reach into the live entries.
function stats() {
  log.debug("Entering stats().");
  log.debug("Leaving stats().");
  // THE TOP-LEVEL COUNTS ARE THE PROTOCOL POOL'S, which is what they meant
  // before there was a second one; `running` is every worker of both, and
  // `pools` breaks both down.
  return {
    configured: size(PROTOCOL_POOL),
    running: workers.length,
    ready: readyWorkers(PROTOCOL_POOL).length,
    inProcess: readyWorkers(PROTOCOL_POOL).length === 0,
    gaveUp: givenUp[PROTOCOL_POOL],
    pools: POOLS.map(function (pool) {
      return { pool: pool, configured: size(pool),
               ready: readyWorkers(pool).length, gaveUp: givenUp[pool],
               affinities: affinities[pool].size,
               prefixes: pool === SURFACE_POOL ? surfacePrefixes() : [] };
    }),
    readYourWrite: readYourWrite(),
    generation: generation,
    // THE BATCH LANE per pool: in flight, waiting, the cap, which workers are
    // in the lane, and how many were ever queued, refused or timed out.
    batch: batchStats(),
    // THE BARRIER'S OWN BOOKKEEPING, reported because the failure it can have
    // is invisible from outside: a ticket nothing will ever clear makes this
    // service answer correctly and 2,000ms slower per read, for ever. See
    // ticketAbandoned(). `reaped` being anything but zero means a worker has
    // lost an announcement and the safety net caught it.
    tickets: { outstanding: outstanding.size, finished: finishedTickets.size,
               reaped: reaped,
               // READERS HELD RIGHT NOW. A number that stays large once
               // nothing is being written is the waiter leak
               // releaseTicketWaiters() describes, come back.
               waiters: ticketWaiters.length - settledWaiters },
    dispatch: dispatchPrefixes(),
    affinities: affinities[PROTOCOL_POOL].size,
    socketDir: socketDir,
    workers: workers.map(function (one) {
      return { pid: one.pid, pool: one.pool, ready: one.ready,
               inFlight: one.inFlight,
               served: one.served, socket: one.socket,
               generation: one.generation };
    })
  };
}

// For the tests, which have to drive the give-up path and then keep going.
function reset() {
  log.debug("Entering reset().");
  generation = 0;
  pendingSyncs.clear();
  POOLS.forEach(function (pool) {
    givenUp[pool] = false;
    quickExits[pool] = 0;
  });
  stopped = false;
  starting = null;
  // AND THE BARRIER, because it is process-wide module state exactly as the
  // generation is: a test that armed a ticket and left it would make every
  // later file in the same run wait the full bound.
  issuedTickets = 0;
  outstanding.clear();
  finishedTickets.clear();
  finishedAt.clear();
  ticketWaiters = [];
  settledWaiters = 0;
  reaped = 0;
  // And the batch lane's counts and queue, for the same reason.
  batchState.forEach(function (state) {
    state.waiting.forEach(function (entry) { clearTimeout(entry.timer); });
  });
  batchState.clear();
  log.debug("Leaving reset().");
}

module.exports = {
  size: size,
  start: start,
  stop: stop,
  stats: stats,
  reset: reset,
  middleware: middleware,
  setServerCertificate: setServerCertificate,
  setBbsKeyPair: setBbsKeyPair,
  runOperation: runOperation,
  operationDispatched: operationDispatched,
  operationKinds: operationKinds,
  dispatched: dispatched,
  fansOut: fansOut,
  readYourWrite: readYourWrite,
  dispatchPrefixes: dispatchPrefixes,
  fanoutPrefixes: fanoutPrefixes,
  affinityKeyOf: affinityKeyOf,
  // THE SECOND POOL (2026-09-13), exported for tests/request_routing.js: which
  // pool a path goes to, what it answers, and what refuses or idles it are
  // decisions over settings and a list, asserted without forking anything.
  poolFor: poolFor,
  surfacePrefixes: surfacePrefixes,
  surfacePoolProblem: surfacePoolProblem,
  PROTOCOL_POOL: PROTOCOL_POOL,
  SURFACE_POOL: SURFACE_POOL,
  SURFACE_POOL_COOKIE: SURFACE_POOL_COOKIE,
  // The spelling both ends of the back-channel hint must agree on, exported to
  // be compared with the worker's, as LDAP_DROP_HEADER is.
  PROTOCOL_WORKER_HEADER: PROTOCOL_WORKER_HEADER,
  SESSION_COOKIE: SESSION_COOKIE,
  POOL_COOKIE: POOL_COOKIE,
  PEER_CERT_HEADER: PEER_CERT_HEADER,
  // WHAT A WORKER IS HANDED OF A CLIENT CERTIFICATE, exported for
  // tests/revocation_status.js (2026-09-12): the issuer chain it now carries is
  // what lets a worker verify a foreign CRL, and a real socket is the only
  // honest input to the function that reads one.
  peerOf: peerOf,
  // THE SPELLING, EXPORTED SO THAT IT CAN BE COMPARED WITH THE WORKER'S. Both
  // ends name this header and neither can read the other's constant at
  // runtime — the two processes share no memory — so the only thing that can
  // catch a rename is a test holding them side by side. tests/ldap_logout.js
  // does exactly that.
  LDAP_DROP_HEADER: LDAP_DROP_HEADER,
  // THIS PROCESS'S OWN WRITES MOVING THE GENERATION, exported so that
  // tests/front_process_writes.js can drive it without a store, a fork or a
  // socket: it takes the count rather than reading it, precisely so that the
  // decision is testable apart from the thing that counts.
  noteLocalWrites: noteLocalWrites,
  // The two halves of the directory mirror, exported for that same test: what
  // this process does with the header a worker sent, without a worker.
  closeDirectoryConnections: closeDirectoryConnections,
  // ---------------------------------------------------------------------
  // THE READ BARRIER, EXPORTED FOR tests/request_barrier.js, on
  // noteLocalWrites()'s argument: the decision is bookkeeping over integers
  // and is testable with no store, no fork and no socket — and the bookkeeping
  // is the part that was wrong. A pool started for real would test node's
  // unix-socket proxying, which is not what wedged.
  //
  // `ticketAbandoned` is the one that matters: it is the difference between a
  // 502 releasing its ticket and a 502 holding every reader for the life of
  // the process.
  // ---------------------------------------------------------------------
  dispatchTicket: dispatchTicket,
  ticketFinished: ticketFinished,
  ticketAbandoned: ticketAbandoned,
  reapStuckTickets: reapStuckTickets,
  awaitCommitConfirmations: awaitCommitConfirmations,
  receiveCommitted: receiveCommitted,
  // THE SYNC HALF OF THE BARRIER AND THE PROXY, exported for the same file
  // (2026-09-13): that one sync round per worker is shared by every reader it
  // covers is a decision about promises and an IPC `send`, and that a client
  // leaving releases its place needs a real socket and nothing else.
  barrier: barrier,
  receiveSync: receiveSync,
  proxy: proxy,
  // THE LISTENER'S RECONCILE, exported for tests/listener_branch_adoption.js
  // (2026-09-13): that one pass runs at a time and that a pass left waiting
  // for a branch arms the fallback are decisions about promises and a timer,
  // asserted without a worker.
  reconcileTheListener: reconcileTheListener,
  listenerRepairArmed: listenerRepairArmed,
  // A hierarchy adopted from the store (#46), for persistence.js.
  hierarchyArrived: hierarchyArrived,
  // For tests/request_routing.js — the routing decisions are pure functions and
  // are asserted directly rather than by starting a pool.
  mutationKeyOf: mutationKeyOf,
  // THE BATCH LANE (2026-09-14), for tests/request_batch_lane.js: which paths
  // are batch, how many workers a lane is, which ones, and the admission queue
  // — bookkeeping over settings and closures, asserted with no worker.
  isBatch: isBatch,
  laneSize: laneSize,
  laneOf: laneOf,
  admitBatch: admitBatch,
  batchStats: batchStats,
  leastLoaded: leastLoaded,
  PEER_AUTHORIZED_HEADER: PEER_AUTHORIZED_HEADER
};
