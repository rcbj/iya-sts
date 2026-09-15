'use strict';
//
// File: ipc_echo.js
//
// NOT A TEST. One child that says what it saw on the IPC channel, for
// `tests/spiffe_operations.js` section 2.
//
// It is in `tools/` because `run.js` discovers a test as any `.js` file in
// `tests/` that is not itself or `harness.js` — a probe sitting beside them
// would have to be added to an exclusion list, which is the "second place to
// forget" that directory is designed not to have.
//
// **IT EXISTS BECAUSE `structuredClone()` IS NOT THE CHANNEL.** That is the
// algorithm the documentation names for `serialization: 'advanced'`, and it
// downgrades a `Buffer` to a `Uint8Array` where node's IPC hands back a real
// Buffer. Modelling the channel got the answer wrong; this asks it.
process.on('message', function (message) {
  const csr = message && message.csr;
  process.send({
    sawBuffer: Buffer.isBuffer(csr),
    sawType: (csr && csr.constructor && csr.constructor.name) || typeof csr,
    sameBytes: Buffer.isBuffer(csr) &&
      Buffer.compare(csr,
                     Buffer.from([0x30, 0x82, 0x01, 0xff, 0x00, 0x7f])) === 0
  });
});
