// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: worker_channel.ts
//
// ---------------------------------------------------------------------------
// THE CHANNEL BETWEEN THE FRONT PROCESS AND A REQUEST WORKER THREAD (#364,
// 2026-09-30).
//
// Until #364 a request or surface worker was a forked PROCESS and spoke to
// the front over node's IPC channel: `process.send()` out and
// `process.on('message')` in. Since #364 it is a `worker_threads` Worker in
// the front process, and the channel is `parentPort`. This is the one place
// that knows which, so `request_worker.ts`, `process_memory.ts` and the
// commit announcer are written once.
//
// TWO THINGS DIFFER FROM THE PROCESS CHANNEL, AND BOTH ARE HANDLED HERE:
//
//   1. **A Buffer arrives as a plain Uint8Array.** The structured clone
//      `postMessage` uses has no Buffer; child_process's `advanced`
//      serialisation did. SPIFFE's dispatched gRPC operations carry `bytes`
//      fields as Buffers, and a Uint8Array handed to protobuf serialisation
//      fails naming a field, one thread from the cause. So every message
//      received on either side is REVIVED: each Uint8Array that is not a
//      Buffer becomes a Buffer over the same memory. A Buffer IS a
//      Uint8Array, so nothing that wanted the plain kind is harmed.
//   2. **Every thread has the process's pid.** A worker's identity is its
//      `threadId` (`id()`), and `processTag()` is pid AND thread for the
//      places that used the pid to tell processes apart.
//
// A LEAF: it requires `worker_threads` and `bunyan` and nothing of this
// service.
// ---------------------------------------------------------------------------

import workerThreads = require('worker_threads');
import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-worker-channel' });

type Listener = (message: any) => void;

class WorkerChannel {
  /**
   * Whether this code runs in a request or surface worker THREAD — the one
   * test every caller that used to ask `process.send` asks instead.
   *
   * @returns true in a worker thread that has a parent port
   */
  static inWorkerThread(): boolean {
    log.debug('Entering WorkerChannel.inWorkerThread().');
    log.debug('Leaving WorkerChannel.inWorkerThread().');
    return !workerThreads.isMainThread && !!workerThreads.parentPort;
  }

  /**
   * This thread's identity: the `threadId` in a worker thread, the pid in
   * the main thread. Numeric, so it fits the `sts_pool` pin cookie as the
   * pid did.
   *
   * @returns the id
   */
  static id(): number {
    log.debug('Entering WorkerChannel.id().');
    log.debug('Leaving WorkerChannel.id().');
    return workerThreads.isMainThread ? process.pid : workerThreads.threadId;
  }

  /**
   * The pid, and the thread when this is not the main one: for what used the
   * pid to tell processes apart (a claim holder, a per-process run key).
   *
   * @returns `pid` or `pid.threadId`
   */
  static processTag(): string {
    log.debug('Entering WorkerChannel.processTag().');
    log.debug('Leaving WorkerChannel.processTag().');
    return workerThreads.isMainThread ? String(process.pid)
      : process.pid + '.' + workerThreads.threadId;
  }

  /**
   * Sends a message to the front process. A no-op outside a worker thread,
   * which is what a module loaded in the front or by a test wants.
   *
   * @param message - a structured-clonable value
   * @returns true when it was posted
   */
  static send(message: any): boolean {
    log.debug('Entering WorkerChannel.send().');
    const port = workerThreads.parentPort;
    if (workerThreads.isMainThread || !port) {
      log.debug('Leaving WorkerChannel.send(). Not a worker thread.');
      return false;
    }
    port.postMessage(message);
    log.debug('Leaving WorkerChannel.send().');
    return true;
  }

  /**
   * Listens for messages from the front process, each revived (Buffers).
   * The listener returned is the one to hand to `off()`.
   *
   * @param listener - called with each message
   * @returns the installed listener, or null outside a worker thread
   */
  static on(listener: Listener): Listener | null {
    log.debug('Entering WorkerChannel.on().');
    const port = workerThreads.parentPort;
    if (workerThreads.isMainThread || !port) {
      log.debug('Leaving WorkerChannel.on(). Not a worker thread.');
      return null;
    }
    const installed = function (message: any): void {
      listener(WorkerChannel.revive(message));
    };
    port.on('message', installed);
    log.debug('Leaving WorkerChannel.on().');
    return installed;
  }

  /**
   * Removes a listener `on()` installed.
   *
   * @param installed - what `on()` returned
   */
  static off(installed: Listener | null): void {
    log.debug('Entering WorkerChannel.off().');
    const port = workerThreads.parentPort;
    if (port && installed) {
      port.removeListener('message', installed);
    }
    log.debug('Leaving WorkerChannel.off().');
  }

  // HOT PATH: once per message on every channel, and it walks the message;
  // no Entering/Leaving pair, which would double the log of every request.
  /**
   * Turns every Uint8Array that is not a Buffer, at any depth, back into a
   * Buffer over the same memory. Arrays and plain objects are walked in
   * place; anything else is returned as it is.
   *
   * @param value - a received message or part of one
   * @returns the value, revived
   */
  static revive(value: any): any {
    if (value === null || typeof value !== 'object') {
      return value;
    }
    if (value instanceof Uint8Array) {
      return Buffer.isBuffer(value) ? value
        : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        value[i] = WorkerChannel.revive(value[i]);
      }
      return value;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      return value;
    }
    const keys = Object.keys(value);
    for (let i = 0; i < keys.length; i++) {
      value[keys[i]] = WorkerChannel.revive(value[keys[i]]);
    }
    return value;
  }
}

export = WorkerChannel;
