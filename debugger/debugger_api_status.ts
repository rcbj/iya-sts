// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: debugger_api_status.ts
//
// ===========================================================================
// PRELOADED INTO THE DEBUGGER'S API CHILD, AND ANSWERING ONE QUESTION: WHAT
// ITS MEMORY IS (#329, 2026-09-28).
//
// Monitoring → Node Health lists every process of the node with its
// `process.memoryUsage()`, and only the process itself can read its heap.
// The debugger's api is the parent project's build output — never source
// here, and never edited here (`debugger/CLAUDE.md`) — and it listens for no
// message: its only use of the channel is to SEND `debugger-api-listening`
// and to exit on `disconnect`. So `debugger_api_process.ts` forks it with
// `--require` of THIS file, which runs in the child before its `server.js`
// and answers `{ type: 'sts-memory-status', id }` on the channel the fork
// already has with `{ type: 'sts-memory-status', id, pid, memory, cpu,
// uptimeS }`.
//
// **NOTHING IS OPENED.** No socket, no route on the debugger's listener, no
// file; the api's own listener and its access-token gate are untouched. It
// reads three counters of the process it is in and answers the parent over
// the IPC channel the parent made — the one channel the contract already
// has. It changes nothing the api does: a message of any other type is not
// this file's, and the api ignores every message.
//
// **IT HAS NO LOGGER, AND THAT IS THE CODE-STYLE EXEMPTION FOR CODE THAT
// RUNS IN SOMEBODY ELSE'S PROCESS**: it is loaded into the api's process,
// whose `node_modules` and logging are that project's, and it requires
// nothing — not even this repository's `helpers.js`, which would load this
// service's configuration into the api (the collision the fork exists to
// avoid). A send that fails is a parent that has gone, which the api's own
// `disconnect` handler is already ending the process for.
//
// Standalone — no IPC channel — it installs nothing.
// ===========================================================================

// The one message this file answers.
const QUESTION = 'sts-memory-status';

// A named function, called for each message on the channel.
function answerMemoryStatus(message: any): void {
  if (!message || message.type !== QUESTION || !process.send) {
    return;
  }
  let memory: unknown = null;
  let cpu: unknown = null;
  try {
    memory = process.memoryUsage();
    cpu = process.cpuUsage();
  } catch (e) {
    // `memoryUsage()` reads /proc and can fail for want of a descriptor; the
    // answer goes back without it, which the parent draws as a /proc row.
    memory = null;
  }
  process.send({ type: QUESTION, id: message.id, pid: process.pid,
                 memory: memory, cpu: cpu,
                 uptimeS: Math.round(process.uptime()) },
               undefined, undefined, function (err: Error | null): void {
                 // The parent went; see the header.
                 return void err;
               });
}

if (typeof process.send === 'function') {
  process.on('message', answerMemoryStatus);
}

export = { QUESTION: QUESTION };
