// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: commit_announcer.ts
//
// ---------------------------------------------------------------------------
// A REQUEST WORKER'S COMMIT ANNOUNCEMENTS: WHICH ANSWERED TICKETS HAVE LANDED.
//
// `common/request_pool.js` gives every dispatched request and operation a
// TICKET; the ticket ARMS when the front process has the answer, and CLEARS
// when the worker that answered says the write behind it has committed. This
// class is that worker's half: it remembers the tickets it answered and tells
// the front process which of them are in the store. `common/CLAUDE.md`
// (*The barrier has a second half — the tickets*) has the design.
//
// It lived inside `request_worker.ts` until #620 (2026-10-14), and moved out
// for one reason: a test has to drive it, and requiring `request_worker` from
// a test builds a worker and installs its channel listeners. Nothing about
// what it does changed by moving; the class, its dependencies and the one
// place that builds it (`RequestWorker.start()`) are the same.
//
// ---------------------------------------------------------------------------
// **AN ANSWER SENT AFTER ITS COMMIT IS ANNOUNCED WITH IT (#620, 2026-10-14).**
//
// Since #351 a worker on a postgres store answers a write only once it has
// committed (`cluster/cluster_barrier.js`, rule 2). The announcement still
// waited for a FURTHER flush after the answer — this worker's next flush,
// which, when one was already running, is the one queued behind it — and only
// then named the ticket. So a ticket whose write was already in the store
// stayed armed for as long as that later flush took, or for as long as this
// worker's event loop was blocked before it could finish it.
//
// That is what STS-WORKER-0008 was reporting under the 2026-10-14 LDAPS bulk
// load on 8081 (200K → 270K people, two protocol workers): six tickets in 40
// minutes, each answered and never announced within thirty seconds, and every
// read on the other worker paying the full 2,000 ms bound (STS-WORKER-0007)
// until each was dropped. The first one is explained to the second by the
// log: worker 2 missed two read barriers (STS-WORKER-0027) and a thread
// reported its event loop blocked for 61.7 s (STS-STORE-0068) around the
// ticket it held — answered, then a synchronous walk, and the announcement's
// flush could not complete until the walk had (#616, #618 are those walks).
//
// So where the answer was held for its commit, the ticket is announced in the
// SAME TICK as the answer — `announceAnswered()` — and nothing that happens to
// this worker afterwards can keep it armed. The flush-gated announcement
// still runs beside it, because it is what tells the front process about the
// rows an answer is NOT held for (the call log's success row, a search's
// audit rows) by moving the generation; those were never the barrier's
// business (`persistence/CLAUDE.md`, *A write is answered after its commit*).
// ---------------------------------------------------------------------------

// For the request type announcesWrites() takes; elided once compiled.
import http = require('http');
import WorkerChannel = require('./worker_channel');

// What a `CommitAnnouncer` needs: the store, and what the worker has.
interface CommitAnnouncerDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  config: { value(key: string): any };
  errorCodes: { tag(code: string): string };
  persistence: {
    flush(): any;
    flushMinted(): any;
    changeRowsWritten(): number;
    // Whether a response that wrote is held until its commit — a postgres
    // store, open and not restoring. Optional because a test double, or a
    // store that predates #351, has no such thing; absent means "no".
    answersAfterCommit?(): boolean;
  };
  // How an announcement reaches the front process. `WorkerChannel.send` in a
  // worker; a test passes a function that hands it to the pool directly.
  send?(message: any): any;
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

  // The one door an announcement leaves by: the channel to the front process,
  // or what a test put in its place.
  private post(message: any): void {
    const { log } = this.deps;
    log.debug("Entering CommitAnnouncer.post().");
    if (typeof this.deps.send === 'function') {
      this.deps.send(message);
    } else {
      WorkerChannel.send(message);
    }
    log.debug("Leaving CommitAnnouncer.post().");
  }

  // ---------------------------------------------------------------------
  // A TICKET WHOSE ANSWER WAS HELD FOR ITS COMMIT, ANNOUNCED AT ONCE (#620).
  //
  // Called when a response has finished, or an operation's handler has
  // settled, on a store that holds a writing answer until its commit
  // (`persistence.answersAfterCommit()`). Everything that answer was held for
  // is in the store by now — that is what holding it meant — so the ticket
  // can be named in the same tick, and no later flush, and no later block of
  // this worker's event loop, can keep it armed. See the header.
  //
  // **`wrote` IS STILL TOLD THE TRUTH, AND IT HAS TO BE.** Clearing a ticket
  // releases a reader on another worker; the generation is what then sends
  // that reader through a sync. An announcement that cleared the ticket and
  // said `wrote: false` for a committed row would release the reader into a
  // worker that has not fetched it — the stale read the barrier exists to
  // stop. The count is of rows COMMITTED, read now, after the commit the
  // answer waited for, so it covers this answer's rows; it is shared with
  // announceWhenCommitted() so that neither announces a row twice.
  //
  // Answers false, and does nothing, where an answer is not held for its
  // commit (ldif, memory, a store still restoring): the flush-gated
  // announcement is then the only thing that knows the write has landed.
  // ---------------------------------------------------------------------
  announceAnswered(ticket: unknown): boolean {
    const { log, config, persistence } = this.deps;
    log.debug("Entering CommitAnnouncer.announceAnswered().");
    if (!config.value('workers.readYourWrite') ||
        typeof persistence.answersAfterCommit !== 'function' ||
        !persistence.answersAfterCommit()) {
      log.debug("Leaving CommitAnnouncer.announceAnswered(). Not held here.");
      return false;
    }
    const committedNow = persistence.changeRowsWritten();
    const wrote = committedNow > this.announcedWritten;
    this.announcedWritten = Math.max(this.announcedWritten, committedNow);
    const tickets = Number(ticket) > 0 ? [Number(ticket)] : [];
    this.post({ committed: { wrote: wrote, through: this.finishedCount,
                             tickets: tickets, answered: true } });
    log.debug("Leaving CommitAnnouncer.announceAnswered(). wrote=" + wrote);
    return true;
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
        this.post({ committed: { wrote: wrote, through: through,
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
  //
  // `settled` says the handler RAN TO ITS ANSWER — its promise resolved, which
  // for an LDAP operation is after `answerAfterCommit()` released the held
  // result — so its ticket goes out at once (#620, announceAnswered()). A
  // handler that threw or rejected may have stopped part way through a write
  // nothing held, so its ticket waits for the flush, as every ticket did.
  noteOperationFinished(ticket: unknown, settled?: boolean): void {
    const { log, config } = this.deps;
    log.debug("Entering CommitAnnouncer.noteOperationFinished().");
    if (!config.value('workers.readYourWrite')) {
      log.debug("Leaving CommitAnnouncer.noteOperationFinished().");
      return;
    }
    this.finishedCount++;
    const announced = !!settled && this.announceAnswered(ticket);
    if (!announced && Number(ticket) > 0) {
      this.finishedTickets.push(Number(ticket));
    }
    this.announceWhenCommitted();
    log.debug("Leaving CommitAnnouncer.noteOperationFinished().");
  }
}

export = CommitAnnouncer;
