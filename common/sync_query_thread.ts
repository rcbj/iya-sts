// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: sync_query_thread.ts
//
// ---------------------------------------------------------------------------
// THE DIRECTORY BRIDGE'S THREAD (#349 phase 3, 2026-09-29).
//
// `common/sync_query.ts` starts this in a `worker_thread` and blocks its own
// thread while this one answers. It holds ONE `pg` client of its own, dialled
// with the driver's read-side options (`bridgeConnection()`), and answers a
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
// of `pg` — `tests/sync_query_kit.js` — so the mechanism can be held in
// process without a database.
// ---------------------------------------------------------------------------

import workerThreads = require('worker_threads');

// The thread's own shape of what it was handed.
interface ThreadData {
  counter: SharedArrayBuffer;
  port: workerThreads.MessagePort;
  connection: Record<string, unknown> | null;
  backend: string | null;
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

// The `pg` backend: one client, dialled on the first question and again
// after it is lost.
function pgBackend(connection: Record<string, unknown>): Backend {
  const queries = require('../persistence/directory_queries');
  const pg = require('pg');
  let client: any = null;
  let connecting: Promise<any> | null = null;
  function connected(): Promise<any> {
    if (client) {
      return Promise.resolve(client);
    }
    if (!connecting) {
      const c = new pg.Client(connection);
      c.on('error', function () {
        // An idle client that died: forget it, and the next question dials
        // again. The error itself reaches the question that was running.
        client = null;
      });
      connecting = c.connect().then(function () {
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
          client = null;
        }
        throw err;
      });
    }
  };
}

const backend: Backend = data.backend
  ? require(data.backend)
  : pgBackend(data.connection || {});

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
