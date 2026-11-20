// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sync_query_thread.ts
//
// ---------------------------------------------------------------------------
// THE DIRECTORY BRIDGE'S THREAD (#349 phase 3, 2026-09-29).
//
// `common/sync_query.ts` starts this in a `worker_thread` and blocks its own
// thread while this one answers. It holds ONE connection of its own, dialled
// with the driver's read-side options (`bridgeConnection()`) through the
// service's one door to PostgreSQL, `persistence/knex_store.js` (#326): a
// Knex instance is built HERE, in the thread, from the posted options,
// because neither a Knex instance nor a connection can cross a thread
// boundary — and it is the same door, so the thread dials exactly as the
// driver's pools do. It answers a
// question by building the named statement with
// `persistence/directory_queries.js` — the same builder the driver's async
// door uses, so the two cannot disagree about a WHERE clause.
//
// Each answer is POSTED FIRST and the shared counter bumped SECOND: the other
// side reads the port once it sees the counter move, and a message posted
// after the bump could be looked for before it arrived.
//
// A LOST CONNECTION is dropped and the next question dials again; a question
// is answered with the error and never retried here, because the other side's
// bound is what decides how long a request may wait. The statement timeout is
// that bound too, so a query the other side has given up on does not keep
// running in the database.
//
// `backend`, when given, is a module whose `run(name, args)` answers instead
// of the database — `tests/sync_query_kit.js` — so the mechanism can be held in
// process without a database.
// ---------------------------------------------------------------------------

import workerThreads = require('worker_threads');

// The thread's own shape of what it was handed.
interface ThreadData {
  counter: SharedArrayBuffer;
  port: workerThreads.MessagePort;
  connection: Record<string, unknown> | null;
  backend: string | null;
  queries?: string | null;
}

// A backend: answers one named question.
interface Backend {
  run(name: string, args: unknown[]): Promise<unknown>;
}

// NO LOGGER IN HERE, AND SO NO Entering/Leaving PAIRS: the code style's
// exemption for code that runs outside the service's own process context (a
// `node -e` child, a browser) applies to a thread for the same reason — a
// bunyan line from here interleaves with the process's own, and everything
// this thread does is reported by the other side (an answer, an error, a
// timeout). A failure to start is thrown, and arrives there as the Worker's
// `error` event.
const data = workerThreads.workerData as ThreadData;
const counter = new Int32Array(data.counter);
const port = data.port;

// The database backend: one connection, dialled on the first question and
// again after it is lost. The statement is the named module's `build()`
// `$n` text — `directory_queries.js`, or the bridge's own (#350's
// `session_queries.js`) — handed to the connection Knex made
// (`knex_store.js` says why it is not `knex.raw()`).
function databaseBackend(connection: Record<string, unknown>,
                         queriesModule: string | null): Backend {
  const queries = require(queriesModule ||
                          '../persistence/directory_queries');
  const knexStore = require('../persistence/knex_store');
  // A thread has a `tls` module of its own, so the host check, the path rules
  // and the outbound gate are installed here too (#1360).
  require('./outbound_tls').installProcessWide();
  // A function cannot be posted here, so the driver's `bridgeConnection()`
  // says the TLS decision as data (`knex_store.postableSsl()`) and it is
  // turned back into options by its inverse, `knex_store.restoredSsl()`
  // (#951's review, 2026-11-13). The hooks are the ones `dialOptions()`
  // gives the driver's own pools, made by the same two functions — the
  // configured host checked for an address (#951), verify-ca checking
  // nothing (#543 round 2) — and they call `tls.checkServerIdentity` at the
  // handshake, which is this thread's `outbound_tls` check installed just
  // above: RFC 9525's names and the path rules. Until then this thread
  // built its own hooks, a second copy of the decision a change could
  // miss. The trust anchors and `stsOutboundVariant` are kept: dropping the
  // anchors would verify against node's default store.
  const ssl = connection.ssl as Record<string, unknown> | undefined;
  if (ssl) {
    connection = Object.assign({}, connection,
                               { ssl: knexStore.restoredSsl(ssl) });
  }
  let client: any = null;
  let connecting: Promise<any> | null = null;
  function connected(): Promise<any> {
    if (client) {
      return Promise.resolve(client);
    }
    if (!connecting) {
      const c = knexStore.openConnection(connection);
      c.on('error', function () {
        // An idle client that died: forget it (closing it and the Knex
        // instance it was made by), and the next question dials again. The
        // error itself reaches the question that was running.
        if (client === c) {
          client = null;
        }
        c.end();
      });
      // JIT OFF FOR THE BRIDGE'S WHOLE SESSION (2026-10-21). Every question
      // this thread asks is a short indexed lookup, which JIT never helps —
      // and one whose estimate is wrong pays for a compile anyway:
      // `withUuids` cost 89 ms of JIT for 150 ms of work on 8081, the
      // `jitOff` the driver's own door honours, which this connection did
      // not. One statement per connection, not per question.
      connecting = c.connect().then(function () {
        return c.query('SET jit = off');
      }).then(function () {
        client = c;
        connecting = null;
        return c;
      }, function (err: Error) {
        connecting = null;
        throw err;
      });
    }
    return connecting as Promise<any>;
  }
  return {
    run: function (name: string, args: unknown[]): Promise<unknown> {
      let statement: { text: string; values: unknown[] };
      try {
        statement = queries.build(name, args);
      } catch (e) {
        return Promise.reject(e);
      }
      return connected().then(function (c: any) {
        return c.query(statement.text, statement.values);
      }).then(function (result: any) {
        return queries.answerOf(name, (result && result.rows) || []);
      }, function (err: any) {
        // A connection-level failure leaves the client unusable.
        if (!err || !err.code || /^08|^57P/.test(String(err.code))) {
          if (client) {
            client.end();
          }
          client = null;
        }
        throw err;
      });
    }
  };
}

const backend: Backend = data.backend
  ? require(data.backend)
  : databaseBackend(data.connection || {}, data.queries || null);

// Posts an answer, then moves the counter: in that order (see the header).
function answer(message: Record<string, unknown>): void {
  port.postMessage(message);
  Atomics.add(counter, 0, 1);
  Atomics.notify(counter, 0);
}

port.on('message', function (question: { id: number; name: string;
                                          args: unknown[] }) {
  Promise.resolve().then(function () {
    return backend.run(question.name, question.args);
  }).then(function (value: unknown) {
    answer({ id: question.id, ok: true, value: value });
  }, function (err: any) {
    answer({ id: question.id, ok: false,
             error: { message: String((err && err.message) || err),
                      code: err && err.code ? String(err.code) : '' } });
  });
});
