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
// service behaves exactly as it did, which is what makes this landable before
// the state channel is finished. A prefix is added when the stores its handlers
// touch are reachable from a worker, and `state_channel.js` is what decides
// when that is true.
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

const log = bunyan.createLogger({
  name: 'request_pool',
  level: (function () {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

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
let vciRequestEncKeyPem = '';
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
function blockedBelow(need, servedBy) {
  let blocked = false;
  outstanding.forEach(function (t) {
    if (t <= need && finishedTickets.has(t)) {
      // ------------------------------------------------------------------
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
      // ------------------------------------------------------------------
      if (servedBy && servedBy.tickets && servedBy.tickets.has(t)) {
        return;
      }
      blocked = true;
    }
  });
  return blocked;
}

function releaseTicketWaiters() {
  if (!ticketWaiters.length) {
    return;
  }
  ticketWaiters = ticketWaiters.filter(function (w) {
    if (!blockedBelow(w.need, w.servedBy)) {
      w.resolve();
      return false;
    }
    return true;
  });
}

// A ticket for a request about to be sent to `entry`. Cleared when that worker
// reports a commit — see receiveCommitted(), which clears everything the worker
// owes, because its flush covers every request it has finished.
function dispatchTicket(entry) {
  if (!readYourWrite()) {
    return;
  }
  issuedTickets++;
  outstanding.add(issuedTickets);
  if (!entry.tickets) { entry.tickets = new Set(); }
  entry.tickets.add(issuedTickets);
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
  if (!ticket || !entry.tickets || !entry.tickets.has(ticket)) {
    return;
  }
  finishedTickets.add(ticket);
}

function awaitCommitConfirmations(servedBy) {
  if (!readYourWrite()) {
    return Promise.resolve();
  }
  const need = issuedTickets;
  if (!blockedBelow(need, servedBy)) {
    return Promise.resolve();
  }
  return new Promise(function (resolve) {
    let done = false;
    const waiter = { need: need, servedBy: servedBy, resolve: function () {
      if (done) { return; }
      done = true;
      resolve();
    } };
    ticketWaiters.push(waiter);
    setTimeout(function () {
      if (!done) {
        log.warn('request_pool: a write answered before this read was not ' +
                 'reported committed within 2000ms (waiting below ticket ' +
                 need + '; ' + outstanding.size + ' outstanding, ' +
                 finishedTickets.size + ' of them finished); serving ' +
                 'without it.');
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
  bbsKeyPairB64 = String(encoded || '');
  if (bbsKeyPairB64) {
    process.env.STS_BBS_KEYPAIR = bbsKeyPairB64;
  }
}

function setServerCertificate(material) {
  if (!material || !material.certPem || !material.keyPem) {
    throw new Error('request_pool: setServerCertificate() needs certPem and ' +
      'keyPem. Every process in this service must present and pin the SAME ' +
      'certificate, or the console and the portal fail TLS against themselves.');
  }
  tlsMaterial = { certPem: material.certPem, keyPem: material.keyPem };
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

// What the front process saw of this connection, in a shape that survives a
// header. `raw` is a Buffer and is the only field that needs care; everything
// else node puts on a peer certificate is a string or a plain object.
//
// It returns null for a plain HTTP connection and for an https one where the
// client sent nothing, and those are the same answer to the worker: no
// certificate. The DIFFERENCE between them is reported by the surfaces that
// care, out of `global.https`, exactly as it is today.
function peerOf(req) {
  const socket = req && req.socket;
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    return null;
  }
  let cert;
  try {
    cert = socket.getPeerCertificate();
  } catch (e) {
    return null;
  }
  if (!cert || !cert.raw || !cert.raw.length) {
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
    // walking it would not terminate. It is dropped rather than followed:
    // nothing in this service reads it, and the verification verdict — which
    // is what a chain would have been consulted for — travels beside it.
    if (name === 'issuerCertificate') {
      return;
    }
    flat[name] = value;
  });
  let encoded;
  try {
    encoded = Buffer.from(JSON.stringify(flat), 'utf8').toString('base64');
  } catch (e) {
    return null;
  }
  // A header this size would be refused by the worker's own parser, and a
  // refused request is worse than one that behaves as though no certificate
  // was sent. 12KB is comfortably under node's default 16KB header limit.
  if (encoded.length > 12000) {
    log.warn('request_pool: a client certificate is too large to forward (' +
             encoded.length + ' bytes encoded); the worker will see this ' +
             'request as having presented none.');
    return null;
  }
  return { cert: encoded, authorized: socket.authorized === true };
}

// The session cookie, which is the affinity key. Named here rather than
// imported from authn.js because this file must not require a protocol module:
// it is loaded by app.js, which is above every route, and a require in that
// direction would drag authn's routes to the front of the router (rule 1).
const SESSION_COOKIE = 'sts_mock_session';

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
const RP_COOKIES = ['sts_mock_admin', 'sts_mock_portal'];

function sessionCookieName(bit) {
  if (bit.indexOf(SESSION_COOKIE + '=') === 0) {
    return SESSION_COOKIE;
  }
  for (let i = 0; i < RP_COOKIES.length; i++) {
    if (bit.indexOf(RP_COOKIES[i] + '=') === 0) {
      return RP_COOKIES[i];
    }
  }
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

// The live workers. Each is
//   { child, pid, socket, ready, inFlight, served, startedAt, retiring }
let workers = [];

// session id -> pid. Insertion-ordered, which makes the cap a
// least-recently-added eviction without a second structure.
const affinity = new Map();

let socketDir = '';
let nextSocket = 1;
let quickExits = 0;
let givenUp = false;
let stopped = false;
let starting = null;

// ---------------------------------------------------------------------------
// The configured size and the configured allow-list.
// ---------------------------------------------------------------------------
function size() {
  log.debug('Entering size().');
  let wanted = 0;
  try {
    wanted = parseInt(config.value('workers.requestCount'), 10);
  } catch (e) {
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

// The path prefixes that go to a worker. A list of strings; empty means none,
// which is the default and is what makes this file inert until it is asked for.
function dispatchPrefixes() {
  let raw;
  try {
    raw = config.value('workers.dispatch');
  } catch (e) {
    return [];
  }
  if (!raw) {
    return [];
  }
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  return list.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
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
  let raw;
  try {
    raw = config.value('workers.fanout');
  } catch (e) {
    return [];
  }
  if (!raw) {
    return [];
  }
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  return list.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
}

function matchesAny(url, prefixes) {
  if (!prefixes.length) {
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
      return true;
    }
  }
  return false;
}

// Whether this request fans out. A dispatched path that is NOT named fans in —
// it holds affinity — which is the way round the header above argues for.
function fansOut(url) {
  return matchesAny(url, fanoutPrefixes());
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
const NEVER_DISPATCHED = ['/tls'];

function dispatched(url) {
  // A SEGMENT BOUNDARY RATHER THAN A BARE PREFIX, and the loose version was
  // written first and was wrong: `/admin` as a prefix also matched
  // `/admin-api`, so naming the console would have silently dragged the
  // management API onto the affinity side of the routing with it. `/admin/` and
  // an exact `/admin` are what a path prefix means.
  const prefixes = dispatchPrefixes();
  if (!prefixes.length) {
    return false;
  }
  if (matchesAny(url, NEVER_DISPATCHED)) {
    return false;
  }
  if (prefixes.indexOf('*') >= 0) {
    return true;
  }
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
    base = '';
  }
  base = base || os.tmpdir();
  socketDir = fs.mkdtempSync(path.join(base, 'sts-workers-'));
  try {
    fs.chmodSync(socketDir, 0o700);
  } catch (e) {
    // See request_worker.js: a filesystem that does not carry modes is not a
    // reason to refuse to serve, and the socket itself is narrowed too.
    log.warn('request_pool: could not narrow the mode on ' + socketDir + ': ' +
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
// A WORKER HAS COMMITTED, AND ONLY NOW IS EVERY OTHER WORKER BEHIND (2026-09-07).
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
  if (!readYourWrite()) {
    return;
  }
  // THE GENERATION MOVES ONLY WHEN SOMETHING WAS WRITTEN. Bumping it for a
  // request that wrote nothing marks every other worker stale and sends the
  // next request to each of them through a barrier with nothing to apply —
  // which, once every request began announcing, was nearly every request.
  if ((committed || {}).wrote) {
    generation++;
    entry.generation = generation;
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
      entry.tickets.delete(ticket);
    });
  }
  releaseTicketWaiters();
  log.debug('receiveCommitted(): worker ' + entry.pid + ' committed at seq ' +
            entry.committedSeq + '; generation is now ' + generation + '.');
}

function receivePublishedKeys(entry, published) {
  if (!published || !published.realm || !published.blob) {
    return;
  }
  const realmId = String(published.realm);
  // AN ENRICHMENT IS ACCEPTED FOR A REALM ALREADY HELD, and is not the race.
  // `pqKeysForAsync()` adds a realm's post-quantum keys after the set was first
  // published, so the second publish carries the SAME certificate and more
  // content. keystore.adoptShared() takes it (publishShared() decides), and it
  // has to be broadcast or only the process that warmed them has them.
  const heldBlob = keystore.sharedBlobFor(realmId);
  const enriches = heldBlob && published.blob &&
    heldBlob.certB64 === published.blob.certB64 &&
    (published.blob.pqKeys || []).length > (heldBlob.pqKeys || []).length;
  if (enriches) {
    keystore.adoptShared(realmId, published.blob);
    log.info('request_pool: the "' + realmId + '" realm\'s post-quantum keys ' +
             'were generated by worker ' + (entry && entry.pid) + '; every ' +
             'process here now uses them.');
    broadcastKeys(realmId, published.blob, entry);
    return;
  }
  const held = heldBlob ? true : false;
  if (!held) {
    keystore.adoptShared(realmId, published.blob);
    log.info('request_pool: worker ' + (entry && entry.pid) + ' generated the ' +
             '"' + realmId + '" realm\'s signing keys; every process here now ' +
             'uses them.');
    broadcastKeys(realmId, published.blob, entry);
    return;
  }
  // SOMEBODY ELSE GOT THERE FIRST. The publisher is told what the answer is and
  // discards what it made — the microseconds between generating and publishing
  // are the one window in which two processes disagree, and anything signed in
  // it is lost. That is the price of a synchronous property read that cannot
  // await, and it is written down rather than discovered.
  sendKeys(entry, realmId);
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
  return require('../ldap/ldap_server');
}

function publishDirectoryConnections(rows) {
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
}

// Called with whatever the worker put in the header — one or more identity
// keys, comma separated and percent-encoded, because a key is a username and a
// header is bytes.
function closeDirectoryConnections(header) {
  const raw = String(header || '');
  if (!raw) {
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
      log.warn('request_pool: a worker asked for a directory sign-out with a ' +
               'key this process could not decode (' + encoded + '): ' +
               e.message);
      return;
    }
    if (!key) {
      return;
    }
    try {
      const dropped = directory().dropConnectionsFor(key);
      log.info('request_pool: a request worker signed ' + key + ' out of the ' +
               'directory; ' + dropped.length + ' connection(s) closed in ' +
               'this process, which is the one holding them.');
    } catch (e) {
      log.warn('request_pool: could not close the directory connections a ' +
               'worker asked to end for ' + key + ': ' + e.message);
    }
  });
}

function broadcastKeys(realmId, blob, except) {
  workers.forEach(function (other) {
    if (other === except || !other.child || !other.child.connected) {
      return;
    }
    try {
      other.child.send({ adoptKeys: { realm: realmId, blob: blob } });
    } catch (e) {
      log.warn('request_pool: could not hand the "' + realmId + '" realm\'s ' +
               'keys to worker ' + other.pid + ': ' + e.message);
    }
  });
}

function sendKeys(entry, realmId) {
  const all = keystore.sharedAll();
  for (let i = 0; i < all.length; i++) {
    if (all[i].realm === realmId && entry.child && entry.child.connected) {
      try {
        entry.child.send({ adoptKeys: all[i] });
      } catch (e) {
        log.warn('request_pool: could not correct worker ' + entry.pid +
                 '\'s keys for "' + realmId + '": ' + e.message);
      }
      return;
    }
  }
}

function fork() {
  log.debug('Entering fork().');
  const socket = path.join(ensureSocketDir(), 'w' + (nextSocket++) + '.sock');
  const child = child_process.fork(WORKER_MODULE, [socket], {
    // stdout and stderr are the front process's, so a worker's bunyan lines
    // land in the same stream as everything else. They carry the pid.
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
    // THE MARKER THAT STOPS A WORKER PROXYING TO ITSELF. See the constant at
    // the top of this file for what happens without it.
    env: Object.assign({}, process.env, { STS_REQUEST_WORKER: '1' })
  });
  const entry = { child: child, pid: child.pid, socket: socket, ready: false,
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
                 kek: keystore.ephemeralKek(),
                 vciRequestEncKeyPem: vciRequestEncKeyPem,
                 bbsKeyPair: bbsKeyPairB64,
                 // WHAT IS BOUND ON THE DIRECTORY RIGHT NOW. A worker that
                 // started with an empty list and was never told otherwise
                 // would answer a sign-out for a connection made before it
                 // existed with "there is nothing to end" — which is the bug
                 // this whole mechanism is about, narrowed to one worker.
                 ldapConnections: directory().connectionSnapshot() });
  } catch (e) {
    log.error('request_pool: could not start worker ' + child.pid + ': ' +
              e.message);
  }

  const settled = new Promise(function (resolve) {
    child.on('message', function (message) {
      if (message && message.ready) {
        entry.ready = true;
        quickExits = 0;
        log.info('request_pool: worker ' + entry.pid + ' is ready on ' +
                 entry.socket + '. ' + readyWorkers().length + ' of ' + size() +
                 ' serving.');
        resolve(entry);
        return;
      }
      if (message && message.ready === false) {
        log.error('request_pool: worker ' + entry.pid + ' could not start: ' +
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
      log.warn('request_pool: the channel to worker ' + entry.pid +
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
    });
    entry.tickets.clear();
    if (answered) {
      log.warn('request_pool: worker ' + entry.pid + ' died holding ' +
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
  }
  failOperations(entry);
  const how = signal ? 'was killed with ' + signal : 'exited with code ' + code;
  const shortLived = (Date.now() - entry.startedAt) < QUICK_EXIT_MS &&
                     entry.served === 0;
  if (shortLived && !stopped) {
    quickExits++;
  }
  if (entry.inFlight) {
    log.warn('request_pool: worker ' + entry.pid + ' ' + how + ' with ' +
             entry.inFlight + ' request(s) in flight; each is answered 502.');
  } else {
    log.info('request_pool: worker ' + entry.pid + ' ' + how + '.');
  }
  if (quickExits >= QUICK_EXIT_LIMIT && !givenUp && !stopped) {
    givenUp = true;
    log.error('request_pool: ' + quickExits + ' request workers in a row ' +
      'exited within ' + QUICK_EXIT_MS + 'ms without serving anything, so ' +
      'this service has STOPPED FORKING THEM and is handling every request ' +
      'in the process that holds the sockets — which is what ' +
      'workers.requestCount=0 means: correct, and on one thread. A worker ' +
      'that cannot start is usually a CONFIG_FILE it cannot read, a port a ' +
      'protocol module tried to bind, or a machine out of memory; ' +
      WORKER_MODULE + ' run by hand with a socket path says which.');
  }
  log.debug('Leaving reap().');
}

function readyWorkers() {
  return workers.filter(function (one) {
    return one.ready && !one.retiring;
  });
}

// Fewest in flight, then least served — the same two-part rule the computation
// pool uses, and for the same reason: the first keeps a slow request from being
// queued behind another, and the second stops a burst landing on whichever
// child was forked first.
function leastLoaded() {
  const live = readyWorkers();
  if (!live.length) {
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
  const said = req.headers && req.headers.authorization;
  if (!said) {
    return '';
  }
  return 'c:' + nodeCrypto.createHash('sha256').update(String(said))
    .digest('base64url').slice(0, 22);
}

function mutationKeyOf(req, url) {
  if (!mayWrite(req.method)) {
    return credentialKeyOf(req);
  }
  const path = String(url || '').split('?')[0];
  for (let i = 0; i < RESOURCE_PATHS.length; i++) {
    const found = RESOURCE_PATHS[i].exec(path);
    if (found) {
      return 'r:' + found[0];
    }
  }
  return credentialKeyOf(req);
}

function affinityKeyOf(req) {
  const header = req.headers && req.headers.cookie;
  if (header) {
    const parts = String(header).split(';');
    let pooled = '';
    let session = '';
    let rp = '';
    for (let i = 0; i < parts.length; i++) {
      const bit = parts[i].trim();
      if (bit.indexOf(SESSION_COOKIE + '=') === 0) {
        session = bit.slice(SESSION_COOKIE.length + 1);
      }
      const named = sessionCookieName(bit);
      if (named && named !== SESSION_COOKIE && !rp) {
        rp = bit.slice(named.length + 1);
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
      return 's:' + session;
    }
    // THE RELYING-PARTY SESSION SECOND. It is bound the same way — `learn()`
    // remembers whichever of the three cookies an answer set — so this is a
    // lookup and not a hash. It ranks BELOW the sign-on session because a
    // browser holding both is one browser, and the sign-on session is the one
    // the other one dies with.
    if (rp) {
      return 's:' + rp;
    }
    if (pooled) {
      return 'p:' + pooled;
    }
  }
  const url = String(req.originalUrl || req.url || '');
  const q = url.indexOf('?');
  if (q < 0) {
    return '';
  }
  const query = url.slice(q + 1);
  for (let i = 0; i < FLOW_PARAMS.length; i++) {
    const found = flowParam(query, FLOW_PARAMS[i]);
    if (found) {
      return FLOW_PARAMS[i] + ':' + found;
    }
  }
  return '';
}

// One query parameter, without building a URL object. This runs on every
// dispatched request and the whole value of this file is that the front process
// does as little as possible per request.
function flowParam(query, name) {
  const parts = String(query || '').split('&');
  for (let i = 0; i < parts.length; i++) {
    const bit = parts[i];
    if (bit.indexOf(name + '=') === 0) {
      const raw = bit.slice(name.length + 1);
      try {
        return decodeURIComponent(raw);
      } catch (e) {
        // A value that is not valid percent-encoding. Used as it arrived: this
        // is a routing key and never a credential, so the only thing that
        // matters is that the same string maps to the same worker.
        return raw;
      }
    }
  }
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
        const value = bit.slice(named.length + 1);
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

function remember(key, entry) {
  if (affinity.get(key) === entry.pid) {
    return;
  }
  if (affinity.size >= AFFINITY_MAX) {
    affinity.delete(affinity.keys().next().value);
  }
  affinity.delete(key);
  affinity.set(key, entry.pid);
  log.debug('remember(): ' + key.split(':')[0] + ' -> worker ' + entry.pid +
            '. ' + affinity.size + ' affinity/affinities held.');
}

// The worker this request goes to. A session holds affinity; everything else
// fans out. A session whose worker has gone gets a new one, which is the whole
// of the recovery story — see the header on why that is safe.
function workerFor(key) {
  log.debug('Entering workerFor(). key=' + (key ? key.split(':')[0] : '(none)'));
  if (!key) {
    // Either this path fans out by policy, or it is the first hop of a flow and
    // has nothing to be stuck to yet. Both are the same routing decision, and
    // learn() binds whatever the chosen worker mints.
    const any = leastLoaded();
    log.debug('Leaving workerFor(). Fanout to ' + (any ? any.pid : '(none)'));
    return any;
  }
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
  const held = pid ? readyWorkers().filter(function (one) {
    return one.pid === pid;
  })[0] : null;
  if (held) {
    log.debug('Leaving workerFor(). Held affinity to ' + held.pid + '.');
    return held;
  }
  const chosen = leastLoaded();
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
    return starting;
  }
  const wanted = size();
  if (!wanted) {
    log.debug('Leaving start(). No request workers are configured.');
    starting = Promise.resolve({ started: 0, wanted: 0 });
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
  // `workers.dispatch` and `workers.operations`. Both are named in the message,
  // because a refusal that does not say what to do instead is a refusal
  // somebody works around.
  // ---------------------------------------------------------------------
  const wants = dispatchPrefixes().concat(operationKinds());
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
      starting = Promise.reject(new Error(
        'request_pool: ' + wants.length + ' path(s)/operation(s) are ' +
        'configured to be handled in a request worker (' + wants.join(', ') +
        ') and THIS PROCESS IS NOT COORDINATING: ' + why + '. Every worker ' +
        'would hold its own private copy of the directory, the sessions and ' +
        'the settings, and a request answered by one would not see what ' +
        'another had written — which does not fail, it answers wrongly and ' +
        'intermittently. Configure a coordinating store (persistence.mode ' +
        'postgres with persistence.coordinate on), or clear ' +
        'workers.dispatch and workers.operations.'));
      return starting;
    }
    log.info('request_pool: coordinating through the ' + state.mode + ' store, ' +
             'so a worker sees what the others write.');

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
  // THE OID4VCI REQUEST-ENCRYPTION KEY. Generated here, once, and handed to
  // every worker with the rest — see vc_issuer.js's VCI_REQUEST_ENC_KEY. It is
  // made in this file rather than read out of that module because that module
  // must not be loaded in the front process before the protocol stack is.
  if (!vciRequestEncKeyPem) {
    vciRequestEncKeyPem = nodeCrypto.generateKeyPairSync('rsa', {
      modulusLength: 2048
    }).privateKey.export({ type: 'pkcs8', format: 'pem' });
    process.env.STS_VCI_REQUEST_ENC_KEY_PEM = vciRequestEncKeyPem;
  }
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

  // AND THE DIRECTORY'S CONNECTION LIST, for the same reason and installed at
  // the same point: a client can be bound on 389 before the first worker is
  // ready — the listeners start from `listen()` in server.js and nothing waits
  // for this pool — and a worker forked afterwards is handed the current
  // snapshot at `begin`. So the two paths together cover every ordering. See
  // publishDirectoryConnections().
  directory().setConnectionWatcher(function (rows) {
    publishDirectoryConnections(rows);
  });
  log.info('request_pool: starting ' + wanted + ' request worker(s). Each ' +
           'loads the whole protocol stack and binds no protocol port.');
  const forks = [];
  for (let i = 0; i < wanted; i++) {
    forks.push(fork().settled);
  }
  starting = Promise.all(forks).then(function (settled) {
    const up = settled.filter(Boolean).length;
    if (!up) {
      // EVERY worker failed. Reported loudly and NOT fatal: the front process
      // can still serve every request itself, which is what
      // `workers.requestCount = 0` means. A service that refused to start
      // because its workers did would be a worse outcome than a slow one.
      log.error('request_pool: not one of ' + wanted + ' request worker(s) ' +
        'started, so every request is being handled in the process that ' +
        'holds the sockets. The reason is in the lines above this one.');
    } else if (up < wanted) {
      log.warn('request_pool: ' + up + ' of ' + wanted + ' request worker(s) ' +
               'started.');
    }
    return { started: up, wanted: wanted };
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
  try {
    return !!config.value('workers.readYourWrite');
  } catch (e) {
    // No configuration at all — the parent project's in-process jobs, npm
    // test. Off is the answer that changes nothing.
    return false;
  }
}

// Bumped when a request that may have written completes. Workers carry the
// generation they have caught up to; a worker at the current one needs no
// barrier.
let generation = 0;

// Methods that may write. HEAD and GET are the whole of the other list, and
// OPTIONS is a preflight — anything else is treated as a write.
const READ_ONLY_METHODS = { GET: true, HEAD: true, OPTIONS: true };

function mayWrite(method) {
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
function barrier(entry, wanted) {
  log.debug('Entering barrier(). pid=' + entry.pid + ' want=' + wanted);
  if (entry.generation >= wanted) {
    log.debug('Leaving barrier(). Already current.');
    return Promise.resolve(true);
  }
  const id = nextSyncId++;
  return new Promise(function (resolve) {
    const timer = setTimeout(function () {
      pendingSyncs.delete(id);
      log.warn('request_pool: worker ' + entry.pid + ' did not answer a read ' +
               'barrier within ' + BARRIER_TIMEOUT_MS + 'ms; the request is ' +
               'being served from what that worker has.');
      resolve(false);
    }, BARRIER_TIMEOUT_MS);
    pendingSyncs.set(id, function (message) {
      clearTimeout(timer);
      // STAMPED WITH THE GENERATION THAT WAS ASKED FOR, not the one now: a
      // write that landed while this barrier ran bumps the counter again and
      // must make this worker stale again. Stamping `generation` here would
      // mark it current for a write it has not seen.
      if (message.ok) {
        entry.generation = wanted;
      }
      resolve(!!message.ok);
    });
    try {
      entry.child.send({ sync: true, id: id });
    } catch (e) {
      clearTimeout(timer);
      pendingSyncs.delete(id);
      resolve(false);
    }
  });
}

function receiveSync(entry, message) {
  const waiter = pendingSyncs.get(message.id);
  if (!waiter) {
    return;
  }
  pendingSyncs.delete(message.id);
  waiter(message);
}

// ---------------------------------------------------------------------------
// THE MIDDLEWARE. Everything above exists for these forty lines.
//
// It is installed in app.js ABOVE every route and BELOW the realm middleware —
// above, because a dispatched request must not be handled here; below, because
// the realm is what the worker has to be told and app.js's first middleware is
// what works it out.
// ---------------------------------------------------------------------------
function middleware() {
  if (IS_REQUEST_WORKER) {
    // A worker HANDLES requests; it does not dispatch them. Returning a bare
    // pass-through rather than checking on every request keeps the hot path in
    // a worker free of a test whose answer cannot change.
    log.debug('request_pool: this process is a request worker, so the ' +
              'dispatch middleware is a pass-through.');
    return function (req, res, next) { next(); };
  }
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
      // `/tls` is the only thing on that list today and does not need it —
      // its whole content is the connection in front of it. It is here for
      // the next entry rather than for that one, and it is here rather than
      // in a comment because the list is exactly where somebody adds a path
      // without thinking about staleness. It was written when `/admin/spiffe`
      // was briefly on the list: a console page behind a session, answered by
      // a process that could not yet see the session a worker had just
      // minted. That path is dispatched again — `spiffe_ca.js` shares the
      // authority now — and the lesson it taught is worth keeping.
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
      persistence.syncNow().catch(function (e) {
        log.debug('request_pool: the front process could not catch up before ' +
                  'answering ' + (req.originalUrl || req.url) + ': ' +
                  e.message);
      }).then(function () {
        next();
      });
      return;
    }
    // THE ROUTING POLICY, IN ONE LINE. A path named in `workers.fanout` goes to
    // the least-loaded worker whatever it carries; everything else dispatched
    // is stuck to the session or flow it belongs to. See fanoutPrefixes().
    const url = req.originalUrl || req.url;
    const key = fansOut(url) ? mutationKeyOf(req, url) : affinityKeyOf(req);
    const entry = workerFor(key);
    if (!entry) {
      if (!size() || givenUp || stopped) {
        // No pool is configured, or it gave up, or we are shutting down.
        // Handled here, which is the supported configuration rather than a
        // degraded one.
        next();
        return;
      }
      // A pool IS configured and has no worker to give. Refused rather than
      // handled here — see the header: the same path served from two processes
      // depending on timing is the bug this is avoiding.
      log.error('request_pool: ' + req.method + ' ' + req.url + ' matched the ' +
        'dispatch list and no worker is serving, so it is refused. Handling ' +
        'it here instead would mean this path is answered by whichever ' +
        'process happened to be available, out of two that do not share ' +
        'state.');
      res.status(503);
      res.set('Retry-After', '5');
      res.type('text/plain');
      res.send('No request worker is available. This path is dispatched to ' +
               'the worker pool (workers.dispatch) and the pool is empty; the ' +
               'service log says why.\n');
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
    // ONE TICKET PER DISPATCHED REQUEST, TAKEN BEFORE IT IS SENT. Anything that
    // arrives after this line necessarily sees this request outstanding, which
    // is the property taking it on `finish` could not give.
    // **WAIT FIRST, THEN TAKE THE TICKET.** The other order deadlocks: the
    // request would be waiting for a ticket it holds itself, which nothing can
    // confirm until it has finished. So this waits for everything dispatched
    // BEFORE it, and only then registers itself as outstanding for everything
    // that comes after.
    awaitCommitConfirmations(entry).then(function () {
      const ticket = dispatchTicket(entry);
      const wanted = generation;
      if (entry.generation >= wanted) {
        proxy(entry, req, res, wanted, ticket);
        return;
      }
      return barrier(entry, wanted).then(function () {
        proxy(entry, req, res, wanted, ticket);
      });
    });
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
  const finish = function () {
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
        ticketFinished(entry, ticket);
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
  if (headers.cookie) {
    const kept = String(headers.cookie).split(';').filter(function (bit) {
      return bit.trim().indexOf(POOL_COOKIE + '=') !== 0;
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
  headers['x-forwarded-for'] = req.ip ||
    (req.connection && req.connection.remoteAddress) || '';
  headers['x-forwarded-proto'] = req.protocol || 'https';
  if (req.headers && req.headers.host) {
    headers.host = req.headers.host;
  }

  const upstream = http.request({
    socketPath: entry.socket,
    path: req.originalUrl || req.url,
    method: req.method,
    headers: headers
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
    if (!fansOut(req.originalUrl || req.url) && !affinityKeyOf(req) &&
        !setsSession) {
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
      const pin = POOL_COOKIE + '=' + entry.pid + '; Path=/; HttpOnly; ' +
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
      log.warn('request_pool: the answer from worker ' + entry.pid +
               ' failed mid-flight: ' + err.message);
      finish();
      res.destroy();
    });
  });

  upstream.on('error', function (err) {
    finish();
    log.error('request_pool: worker ' + entry.pid + ' could not answer ' +
              req.method + ' ' + req.url + ': ' + err.message);
    if (res.headersSent) {
      // Already streaming. There is no status left to send, so the connection
      // is destroyed — which is what a truncated answer has to look like.
      res.destroy();
      return;
    }
    res.status(502);
    res.type('text/plain');
    res.send('The request worker handling this request went away (' +
             err.message + '). A worker holds no state of its own that this ' +
             'request needed, so it can simply be made again.\n');
  });

  req.pipe(upstream);
  req.on('aborted', function () {
    upstream.destroy();
    finish();
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
// **WHAT THIS DOES NOT SOLVE IS THE SAME THING THE HTTP PATH DOES NOT SOLVE.**
// A worker's directory is ITS OWN. An LDAP `add` dispatched to a worker writes
// an entry the front process cannot see and the next worker has never heard of,
// and unlike the settings case — where the divergence was one stale read in six
// — the directory would fork N ways on the first write. So `ldap.*` operations
// are NOT dispatched by default and must not be until the store behind them is
// shared. The mechanism is here; the switch is deliberately not thrown.
// ---------------------------------------------------------------------------

let nextOperationId = 1;
const pendingOperations = new Map();

// Which operation kinds go to a worker. Same shape and same discipline as the
// path list: empty means none, which is the default.
function operationKinds() {
  let raw;
  try {
    raw = config.value('workers.operations');
  } catch (e) {
    return [];
  }
  if (!raw) {
    return [];
  }
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  return list.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
}

// Whether this operation is dispatched. A kind is `family.operation`, and a
// list entry may name either the whole family (`ldap`) or one of its
// operations (`ldap.search`) — so a family can be moved a piece at a time,
// which is how a store this size has any chance of being moved safely.
function operationDispatched(kind) {
  const kinds = operationKinds();
  if (!kinds.length) {
    return false;
  }
  const family = String(kind || '').split('.')[0];
  for (let i = 0; i < kinds.length; i++) {
    if (kinds[i] === kind || kinds[i] === family) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// RUN ONE OPERATION IN A WORKER.
//
// `opts.affinity` names something to be stuck to, exactly as a session cookie
// does for a request; an operation with none FANS OUT. **LDAP passes none on
// purpose**: a directory operation carries its own DN and its own credential,
// and nothing about one has to be remembered to answer the next — the bind that
// authenticated the connection is state the FRONT process holds, because the
// front process is the one holding the connection.
//
// It resolves `{ dispatched: false }` rather than rejecting when there is no
// pool, so a caller is written one way and the front process does the work
// itself — which is what `workers.requestCount = 0` means and is a supported
// configuration rather than a degraded one.
// ---------------------------------------------------------------------------
function runOperation(kind, args, opts) {
  log.debug('Entering runOperation(). kind=' + kind);
  const options = opts || {};
  if (IS_REQUEST_WORKER || !operationDispatched(kind)) {
    log.debug('Leaving runOperation(). Not dispatched.');
    return Promise.resolve({ dispatched: false });
  }
  const entry = workerFor(options.affinity ? 'op:' + options.affinity : '');
  if (!entry) {
    // Unlike a dispatched PATH, this is not refused. A path named in the
    // dispatch list has an HTTP answer to give and a 503 is one; an operation
    // has a caller in this process that can simply do the work, and failing it
    // would take a protocol listener down for a pool that is a performance
    // measure.
    log.debug('Leaving runOperation(). No worker; the caller does it here.');
    return Promise.resolve({ dispatched: false });
  }
  const id = nextOperationId++;
  const promise = new Promise(function (resolve, reject) {
    pendingOperations.set(id, { resolve: resolve, reject: reject, kind: kind,
                                pid: entry.pid });
  });
  entry.inFlight++;
  try {
    entry.child.send({ operation: true, id: id, kind: kind, args: args });
  } catch (e) {
    const pending = pendingOperations.get(id);
    pendingOperations.delete(id);
    entry.inFlight--;
    if (pending) {
      pending.resolve({ dispatched: false });
    }
  }
  log.debug('Leaving runOperation(). id=' + id + ' on worker ' + entry.pid);
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
  pendingOperations.forEach(function (pending, id) {
    if (pending.pid !== entry.pid) {
      return;
    }
    pendingOperations.delete(id);
    pending.reject(new Error('the worker process running this ' + pending.kind +
      ' operation went away before it answered. A worker holds no state that ' +
      'this operation needed, so it can simply be tried again.'));
  });
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
  return new Promise(function (resolve) {
    let killed = 0;
    let left = going.length;
    const timer = setTimeout(function () {
      going.forEach(function (entry) {
        if (entry.child.exitCode === null && entry.child.signalCode === null) {
          killed++;
          log.warn('request_pool: worker ' + entry.pid + ' did not finish ' +
                   'within ' + limit + 'ms and was killed.');
          entry.child.kill('SIGKILL');
        }
      });
      done();
    }, limit);
    function done() {
      left = 0;
      clearTimeout(timer);
      workers = [];
      affinity.clear();
      removeSocketDir();
      log.debug('Leaving stop().');
      resolve({ stopped: going.length - killed, killed: killed });
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
      }
    });
  });
}

function removeSocketDir() {
  if (!socketDir) {
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
}

// What the pool is doing, for `/admin` and for the tests. A copy, so a reader
// cannot reach into the live entries.
function stats() {
  return {
    configured: size(),
    running: workers.length,
    ready: readyWorkers().length,
    inProcess: readyWorkers().length === 0,
    gaveUp: givenUp,
    readYourWrite: readYourWrite(),
    generation: generation,
    dispatch: dispatchPrefixes(),
    affinities: affinity.size,
    socketDir: socketDir,
    workers: workers.map(function (one) {
      return { pid: one.pid, ready: one.ready, inFlight: one.inFlight,
               served: one.served, socket: one.socket,
               generation: one.generation };
    })
  };
}

// For the tests, which have to drive the give-up path and then keep going.
function reset() {
  generation = 0;
  pendingSyncs.clear();
  givenUp = false;
  quickExits = 0;
  stopped = false;
  starting = null;
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
  SESSION_COOKIE: SESSION_COOKIE,
  POOL_COOKIE: POOL_COOKIE,
  PEER_CERT_HEADER: PEER_CERT_HEADER,
  // THE SPELLING, EXPORTED SO THAT IT CAN BE COMPARED WITH THE WORKER'S. Both
  // ends name this header and neither can read the other's constant at
  // runtime — the two processes share no memory — so the only thing that can
  // catch a rename is a test holding them side by side. tests/ldap_logout.js
  // does exactly that.
  LDAP_DROP_HEADER: LDAP_DROP_HEADER,
  // The two halves of the directory mirror, exported for that same test: what
  // this process does with the header a worker sent, without a worker.
  closeDirectoryConnections: closeDirectoryConnections,
  // For tests/request_routing.js — the routing decisions are pure functions and
  // are asserted directly rather than by starting a pool.
  mutationKeyOf: mutationKeyOf,
  PEER_AUTHORIZED_HEADER: PEER_AUTHORIZED_HEADER
};
