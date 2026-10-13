// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: thread_echo.js
//
// NOT A TEST. One worker THREAD that says what it saw on its channel, for
// `tests/spiffe_operations.js` section 2 — the CONTROL there.
//
// It is in `tools/` because `run.js` discovers a test as any `.js` file in
// `tests/` that is not itself or `harness.js` — a probe sitting beside them
// would have to be added to an exclusion list, which is the "second place to
// forget" that directory is designed not to have.
//
// **IT LISTENS ON THE BARE `parentPort`, WITH NOTHING REVIVED.** It was
// `ipc_echo.js` until #364, a forked child showing that node's
// `serialization: 'advanced'` IPC hands back a real Buffer. A request worker
// is a thread since #364, and `postMessage()`'s structured clone has no
// Buffer — so this shows the Uint8Array that arrives when nothing turns it
// back, which is the reason `common/worker_channel.ts` revives every message.
const workerThreads = require('worker_threads');

const port = workerThreads.parentPort;
if (port) {
  port.once('message', function (message) {
    const csr = message && message.csr;
    port.postMessage({
      sawBuffer: Buffer.isBuffer(csr),
      sawType: (csr && csr.constructor && csr.constructor.name) || typeof csr,
      sameBytes: !!csr && Buffer.compare(Buffer.from(csr),
        Buffer.from([0x30, 0x82, 0x01, 0xff, 0x00, 0x7f])) === 0
    });
  });
}
