// @ts-check
'use strict';
//
// File: lingering_close.js
//
// ===========================================================================
// AN ANSWER SENT BEFORE THE REQUEST'S BODY HAS ALL ARRIVED, CLOSED WITHOUT
// A RESET (2026-09-26).
//
// A dataset upload (#215) is refused as early as it can be — over its cap,
// a realm the fields do not name, a form with no file — while the file may
// still be arriving, and the answer says `Connection: close` so the client
// is not left sending hundreds of megabytes into a request already
// answered. Node's http server then closes the socket the moment the answer
// is flushed (`socket.destroySoon()`), and A SOCKET CLOSED WITH UNREAD DATA
// IN ITS RECEIVE BUFFER SENDS A TCP RESET, NOT A FIN. A reset makes the
// peer's kernel DISCARD what it had received and not yet read — the answer
// itself. So the refusal was written and never read:
//
//   * dispatched, the front process's connection to the request worker
//     failed with `read ECONNRESET` or `socket hang up` (STS-WORKER-0030)
//     and the person got a 502 or a connection cut mid-answer;
//   * and the front process did the same to the browser, which showed a
//     connection error instead of the console's refusal.
//
// The fix is what nginx calls a LINGERING CLOSE: the answer goes out, then
// the write side is closed (a FIN — "that was all of it"), and what the
// client is still sending is read and discarded until it closes its side,
// stops for LINGER_IDLE_MS, or LINGER_TOTAL_MS has passed. Only then is the
// socket destroyed, and by then nothing unread is left to turn the close
// into a reset. The client reads the whole answer, sees the FIN and stops.
//
// `arm(req, res)` is called by a route BEFORE it answers, in place of
// `res.set('Connection', 'close')`: it sets that header and replaces this
// one socket's `destroySoon()`, which is the call node's server makes when
// an answer that closes its connection has finished. Nothing else about the
// socket changes, and a request whose body HAS all arrived is closed the
// ordinary way, since there is nothing left to read.
//
// The two timers are per connection and one-shot — a bound on one close,
// not periodic work (see "Anything periodic is a scheduler job").
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({ name: 'sts-lingering-close' });
config.registerLogger(log);

// How long a client that is still sending is read and discarded after its
// answer: at most this in all, and at most LINGER_IDLE_MS without a byte.
// nginx's defaults (lingering_time 30s, lingering_timeout 5s).
const LINGER_TOTAL_MS = 30000;
const LINGER_IDLE_MS = 5000;

// The sockets already armed, so a second `arm()` on one does not wrap its
// `destroySoon()` twice.
/** @type {WeakSet<object>} */
const armed = new WeakSet();

// Replace this one socket's `destroySoon()` with a lingering close. Called
// by node's server once the answer has been flushed. Every exit destroys
// the socket, so a peer that never closes costs at most LINGER_TOTAL_MS.
function lingerOn(socket) {
  log.debug("Entering lingerOn().");
  let over = false;
  let total = null;
  const done = function (why) {
    if (over) {
      return;
    }
    over = true;
    if (total) {
      clearTimeout(total);
    }
    socket.setTimeout(0);
    log.debug('lingering close: the socket is destroyed (' + why + ').');
    socket.destroy();
  };
  socket.destroySoon = function () {
    log.debug("Entering destroySoon().");
    if (socket.destroyed) {
      log.debug("Leaving destroySoon(). Already destroyed.");
      return;
    }
    // The answer is flushed: say that was all of it, and keep reading. The
    // http parser is still attached and discards the rest of the body (the
    // request was dumped when its answer finished); a socket nobody reads
    // would stall the client on a full window and never close.
    if (socket.writable) {
      socket.end();
    }
    socket.resume();
    socket.once('end', function () {
      done('the client closed its side');
    });
    socket.once('close', function () {
      done('closed');
    });
    socket.setTimeout(LINGER_IDLE_MS, function () {
      done('nothing arrived for ' + LINGER_IDLE_MS + ' ms');
    });
    total = setTimeout(function () {
      done(LINGER_TOTAL_MS + ' ms of lingering');
    }, LINGER_TOTAL_MS);
    if (total && typeof total.unref === 'function') {
      total.unref();
    }
    log.debug("Leaving destroySoon().");
  };
  log.debug("Leaving lingerOn().");
}

// Call before answering a request that may still be arriving: the answer
// closes the connection, and the close lingers if the body is unfinished.
function arm(req, res) {
  log.debug("Entering arm().");
  // `set()` where there is no `setHeader()`: an in-process test drives a
  // route with express's response shape and nothing below it.
  if (typeof res.setHeader === 'function') {
    res.setHeader('Connection', 'close');
  } else if (typeof res.set === 'function') {
    res.set('Connection', 'close');
  }
  const socket = req && req.socket;
  if (!socket || socket.destroyed || req.complete) {
    log.debug("Leaving arm(). Nothing still arriving.");
    return;
  }
  if (!armed.has(socket)) {
    armed.add(socket);
    lingerOn(socket);
  }
  log.debug("Leaving arm().");
}

module.exports = {
  arm: arm,
  LINGER_TOTAL_MS: LINGER_TOTAL_MS,
  LINGER_IDLE_MS: LINGER_IDLE_MS
};
