// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: lazy_module.ts
//
// ---------------------------------------------------------------------------
// A PACKAGE REQUIRED AT FIRST USE, NOT AT LOAD (#348, 2026-09-29).
//
// `common/protocol_stack.ts` requires every module in every process, and
// every request or surface worker is a full fork of the service — so a
// package a module requires at its top is paid for once PER PROCESS, whether
// that process ever calls it or not. #348 measured which packages are worth
// deferring (the numbers are on the ticket): the gRPC runtime and its proto
// loader, which only the front process needs when it binds the SPIFFE
// sockets, and `jsonld` (through the vendored `bbs2023.js`), which only a
// credential issuance, a presentation or a VC-API call needs.
//
// `LazyModule.of()` hands back a stand-in for the module that requires it
// the first time a property is READ, and forwards to it from then on. So a
// call site keeps its shape (`bbs2023.CRYPTOSUITE`, `grpc.status`) and the
// require moves to whichever call first needs it. Two things follow and both
// are deliberate:
//
//   * **HOLDING THE STAND-IN COSTS NOTHING.** Passing it through a
//     constructor, destructuring it out of a deps object, or exporting it
//     loads nothing — only a property read does. That is what lets a class
//     keep the module in its deps (#50) without paying for it at build.
//   * **IT CHANGES NO LOAD-TIME EFFECT OF THIS SERVICE.** Use it only for a
//     package (or a vendored copy) with no side effect on this service when
//     it loads — no slot filled, no route registered, no store declared.
//     A module of THIS service stays an ordinary require, because the order
//     those run in is the require order (root CLAUDE.md), and moving one to
//     first use would move its effects to wherever that happens to be.
//
// A load that fails is thrown to the caller, as a top-level require's
// failure would have been at start, and logged under STS-CORE-0140 first —
// because it now happens during a request, where the stack trace alone
// would not say that a dependency is missing from the image.
//
// A LIBRARY (rule 3): it requires only the error-code table, a leaf, so any
// module can require it without joining a cycle; its logger is handed in.
// NOT for `common/helpers.js` or anything else in the parent project's
// Kerberos COPY closure (kerberos/CLAUDE.md): a require from there would add
// this file to that closure, so those files defer by hand.
// ---------------------------------------------------------------------------

import errorCodes = require('./error_codes');

interface LazyLog {
  debug(message: string): void;
  error(message: string): void;
}

/**
 * Stand-ins for packages that are required the first time they are used.
 */
class LazyModule {
  /**
   * Returns a stand-in for a module that requires it on the first property
   * read and forwards every read to it after that.
   *
   * @param what - the module's name, for the log and the error
   * @param load - requires the module; called at most once, successfully
   * @param log - the caller's logger
   * @returns the stand-in, typed as the module
   * @throws the load's own error, on the read that triggered a failed load
   */
  static of<T extends object>(what: string, load: () => T,
                              log: LazyLog): T {
    log.debug("Entering LazyModule.of(). " + what);
    let loaded: T | null = null;
    // Runs on every property read of the stand-in, so no Entering/Leaving
    // pair — the hot-path exception the code style allows, stated here as
    // it requires. It logs the one time it actually requires.
    const target = function (): T {
      if (loaded) {
        return loaded;
      }
      log.debug('LazyModule: requiring ' + what + ' at first use (#348).');
      try {
        loaded = load();
      } catch (e) {
        log.error(errorCodes.tag('STS-CORE-0140') + 'lazy_module: ' + what +
                  ', required at first use, did not load: ' +
                  ((e && e.message) || e));
        throw e;
      }
      return loaded;
    };
    // Every trap forwards to the real module; the traps run on every read,
    // so they carry no Entering/Leaving pair (the hot-path exception above).
    // `getOwnPropertyDescriptor` reports each property CONFIGURABLE because
    // the proxy's own target is an empty object: a non-configurable
    // descriptor for a property the target lacks is a TypeError (a Proxy
    // invariant), and TypeScript's compiled exports are non-configurable.
    const handler: ProxyHandler<object> = {
      get: function (_t, key) {
        return Reflect.get(target(), key);
      },
      has: function (_t, key) {
        return Reflect.has(target(), key);
      },
      ownKeys: function () {
        return Reflect.ownKeys(target());
      },
      getOwnPropertyDescriptor: function (_t, key) {
        const found = Reflect.getOwnPropertyDescriptor(target(), key);
        if (found) {
          found.configurable = true;
        }
        return found;
      },
      set: function () {
        return false;
      }
    };
    log.debug("Leaving LazyModule.of().");
    return new Proxy({}, handler) as T;
  }
}

/**
 * Stand-ins for packages required at first use (#348).
 * @namespace
 */
export = LazyModule;
