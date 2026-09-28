// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: cell_link.js
//
// ===========================================================================
// THE LINK BETWEEN THE TWO CELLS, WHICH A JOB CAN CUT (#98 D6, 2026-09-28).
//
// The `cells` mode's layer (tests/docker-compose-run-tests-cells.yml) runs
// this as `sts-cell-link`, and gives cell A an /etc/hosts line naming THIS
// container as `sts2`. So every inter-cell call cell A makes to cell B — the
// channel's operations and every relayed request — is a TCP connection here,
// passed through unread to cell B's real channel port. The TLS is end to
// end: the link sees ciphertext, holds no key, and cannot answer for cell B
// (the channel checks the peer's certificate names cell B, and this has
// none).
//
// WHY IT EXISTS: D6 — what a cell does when a person's home cannot be
// reached — can only be tested by making home unreachable, and the runner
// has no docker socket to stop a container with (nor should it: a stopped
// cell B would take every other job down with it). A realm setting cannot do
// it either, because `cells.peers` is read once at start. So the runner is
// given a switch instead:
//
//   GET  /state   `{ up, connections, accepted }`
//   POST /down    stops listening and destroys every open connection, so the
//                 next dial from cell A is ECONNREFUSED — the fastest
//                 unreachable there is, and the same one a dead cell gives
//   POST /up      listens again
//
// ONE DIRECTION ONLY: cell B dials cell A directly, so a job can still write
// at cell B (disable someone, say) while cell A cannot reach it.
//
// On the stack's private network and nowhere else: nothing publishes either
// port, and the service never runs it.
// ===========================================================================
"use strict";

const http = require("http");
const net = require("net");
const log = require("bunyan").createLogger({ name: "cell_link",
  level: process.env.LOG_LEVEL || "info" });

const LISTEN_PORT = Number(process.env.CELL_LINK_LISTEN_PORT || 8446);
const CONTROL_PORT = Number(process.env.CELL_LINK_CONTROL_PORT || 8447);
const TARGET = String(process.env.CELL_LINK_TARGET || "sts2:8446");
const TARGET_HOST = TARGET.split(":")[0];
const TARGET_PORT = Number(TARGET.split(":")[1] || 8446);

const state = { up: false, accepted: 0 };
const open = new Set();
let server = null;

/**
 * Passes one accepted connection through to the target, byte for byte.
 *
 * @param client - the socket cell A opened
 */
function pass(client) {
  log.debug("Entering pass().");
  state.accepted += 1;
  const upstream = net.connect({ host: TARGET_HOST, port: TARGET_PORT });
  open.add(client);
  open.add(upstream);
  const end = function () {
    log.debug("Entering end().");
    client.destroy();
    upstream.destroy();
    open.delete(client);
    open.delete(upstream);
    log.debug("Leaving end().");
  };
  client.on("error", function (e) {
    log.debug("Caught in pass() (client): " + ((e && e.message) || e));
    end();
  });
  upstream.on("error", function (e) {
    log.debug("Caught in pass() (upstream): " + ((e && e.message) || e));
    end();
  });
  client.on("close", end);
  upstream.on("close", end);
  client.pipe(upstream);
  upstream.pipe(client);
  log.debug("Leaving pass().");
}

/**
 * Starts listening for cell A, when not already.
 *
 * @returns a promise settled once listening
 */
function up() {
  log.debug("Entering up().");
  if (state.up) {
    log.debug("Leaving up(). Already up.");
    return Promise.resolve();
  }
  server = net.createServer(pass);
  log.debug("Leaving up().");
  return new Promise(function (resolve, reject) {
    server.once("error", reject);
    server.listen(LISTEN_PORT, "0.0.0.0", function () {
      state.up = true;
      log.info("cell_link: up — " + LISTEN_PORT + " -> " + TARGET + ".");
      resolve();
    });
  });
}

/**
 * Stops listening and cuts every connection in flight.
 *
 * @returns a promise settled once the listener is closed
 */
function down() {
  log.debug("Entering down().");
  if (!state.up) {
    log.debug("Leaving down(). Already down.");
    return Promise.resolve();
  }
  state.up = false;
  const closing = server;
  server = null;
  open.forEach(function (socket) {
    socket.destroy();
  });
  open.clear();
  log.info("cell_link: down — cell A cannot reach " + TARGET + ".");
  log.debug("Leaving down().");
  return new Promise(function (resolve) {
    closing.close(function () {
      resolve();
    });
  });
}

/**
 * The control port's one handler.
 *
 * @param req - the request
 * @param res - the response
 */
function control(req, res) {
  log.debug("Entering control(). " + req.method + " " + req.url);
  const answer = function (status) {
    log.debug("Entering answer(). " + status);
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ up: state.up, connections: open.size / 2,
                             accepted: state.accepted }));
    log.debug("Leaving answer().");
  };
  const path = String(req.url || "").split("?")[0];
  let act = null;
  if (req.method === "POST" && path === "/down") {
    act = down();
  } else if (req.method === "POST" && path === "/up") {
    act = up();
  } else if (req.method === "GET" && path === "/state") {
    act = Promise.resolve();
  }
  if (!act) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("GET /state, POST /down or POST /up\n");
    log.debug("Leaving control(). Not a control.");
    return;
  }
  act.then(function () {
    answer(200);
  }, function (e) {
    log.error("cell_link: " + path + " failed: " + ((e && e.message) || e));
    answer(500);
  });
  log.debug("Leaving control().");
}

up().then(function () {
  http.createServer(control).listen(CONTROL_PORT, "0.0.0.0", function () {
    log.info("cell_link: control on " + CONTROL_PORT + ".");
  });
}, function (e) {
  log.error("cell_link: could not listen on " + LISTEN_PORT + ": " +
            ((e && e.message) || e));
  process.exit(1);
});
