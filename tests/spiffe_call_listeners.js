// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/spiffe_call_listeners.js
//
// ===========================================================================
// A LISTENER BOUND TO THE SOCKET'S REALM CAN STILL BE REMOVED (#695).
//
// `spiffe/spiffe_server.ts`'s bindCallListeners() wraps every listener a
// gRPC handler registers on its call, so that grpc-js, which emits outside
// the handler's realm run, still runs it in the socket's realm (#324). The
// emitter then holds the WRAPPER, and until #695 `removeListener(event,
// listener)` with the function the handler registered found nothing. No
// SPIFFE code removes a listener today; this holds the method to what an
// EventEmitter promises before one does.
//
// IN PROCESS: the method on an EventEmitter, with `realms.bind` replaced by
// a wrapper that records the realm it ran in.
// ===========================================================================

const EventEmitter = require('events');
const spiffeServer = require('../spiffe/spiffe_server');

const log = require('bunyan').createLogger({
  name: 'spiffe_call_listeners',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = { id: 'acme' };

// The method needs only `log` and `realms` from its deps.
function bindOn(call, seen) {
  log.debug('Entering bindOn().');
  const fake = {
    deps: {
      log: log,
      realms: {
        bind: function (realm, fn) {
          return function () {
            seen.push(realm.id);
            return fn.apply(this, arguments);
          };
        }
      }
    }
  };
  spiffeServer.SpiffeServer.prototype.bindCallListeners.call(fake, call,
                                                             REALM);
  log.debug('Leaving bindOn().');
}

function run(t) {
  log.debug('Entering run().');
  t.log.info('=== a listener added through the wrap runs in the realm, ' +
             'and the function it was added as removes it ===');
  const call = new EventEmitter();
  const seen = [];
  bindOn(call, seen);
  let heard = 0;
  const onData = function () {
    heard += 1;
  };
  call.on('data', onData);
  call.emit('data');
  t.equal(heard, 1, 'the listener runs');
  t.equal(seen.join(','), 'acme', 'in the socket\'s realm');
  call.removeListener('data', onData);
  call.emit('data');
  t.equal(heard, 1, 'removeListener with the original function removes it');
  t.equal(call.listenerCount('data'), 0, 'and nothing is left registered');

  call.once('end', onData);
  call.off('end', onData);
  call.emit('end');
  t.equal(heard, 1, 'off removes a once listener by its original function');

  t.log.info('=== one function added twice is two registrations ===');
  call.on('data', onData);
  call.on('data', onData);
  t.equal(call.listenerCount('data'), 2, 'both are registered');
  call.removeListener('data', onData);
  t.equal(call.listenerCount('data'), 1,
          'one removeListener takes one of them, as EventEmitter does');
  call.removeListener('data', onData);
  t.equal(call.listenerCount('data'), 0, 'and the second the other');

  t.log.info('=== a function never added through the wrap ===');
  const other = function () {};
  call.removeListener('data', other);
  t.equal(call.listenerCount('data'), 0,
          'removing an unknown listener changes nothing and does not throw');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'spiffe_call_listeners',
  describe: 'A gRPC call listener bound to the SPIFFE socket\'s realm is ' +
            'still removed by its original function (#695)',
  run: run
};
