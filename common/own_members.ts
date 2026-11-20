// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: own_members.ts
//
// ---------------------------------------------------------------------------
// A NAME A CALLER CHOSE READS A MEMBER THE OBJECT HOLDS, NEVER ONE IT
// INHERITS (2026-11-12).
//
// `table[name]` follows the prototype chain. Where `name` came from outside
// — a request, an RFC 9396 detail, an AuthZEN subject, resource, action or
// context, a policy document, a stored row — `constructor`, `toString`,
// `hasOwnProperty` and `__proto__` are not "absent": they answer a function
// or `Object.prototype`, which every test of the form `if (table[name])`
// reads as present. #1664 found the WRITE side of this in the XACML editor
// (a path through `__proto__` gave every object in the process a `rules`)
// and fixed it there with `XacmlEditor.ownStep()`. The READ side was the
// same walk in a dozen other places, and each one answered something other
// than "no such thing":
//
//   * an RFC 9396 detail of `type: "constructor"` passed the unknown-type
//     refusal (`STS-OAUTH-0453`), with `Object` as its definition;
//   * an FGA or AuthZEN attribute row with `category: "constructor"` or
//     `dataType: "toString"` was accepted, holding a function;
//   * a JSON Profile request's `DataType: "constructor"` escaped the
//     unknown-datatype refusal;
//   * a policy naming a function, a combining algorithm, a variable or a
//     referenced policy called `toString` or `constructor` got a function
//     back, and the refusal it met was the wrong one (or none);
//   * a scope called `constructor` in an AuthZEN token-exchange question
//     carried a "delegated permission" fact into the issuance policy.
//
// **THIS IS THE ONE PLACE THE RULE IS WRITTEN**, and every one of those reads
// goes through it. An inherited member resolves as ABSENT, which is the
// answer a missing name already gave, so no caller needs a new refusal; and
// an own member answers exactly what `table[name]` answered, so nothing that
// resolved before resolves differently.
//
//   * `has(node, key)` — whether `key` names a member `node` itself holds:
//     an array's index (digits, below its length) or an object's own
//     member. #1664's `ownStep()`, moved here; the editor calls it.
//   * `read(node, key)` — that member, or `undefined`.
//   * `put(node, key, value)` — sets an own member, `__proto__` included.
//     A plain assignment of `__proto__` REPLACES THE PROTOTYPE instead of
//     storing a member, after which every name the new prototype holds
//     reads as present. A map whose reads go through `read()` has its
//     writes go through here, so a name that resolved before — by the
//     accident of being the prototype — still resolves, now as itself.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');

const log = helpers.log;

const DIGITS = /^[0-9]+$/;

/**
 * Own-member reads and writes for names a caller chose.
 */
class OwnMembers {
  /**
   * Whether `key` names a member `node` holds itself: an array's index
   * (digits, below its length), or an object's own member — never one it
   * inherits.
   *
   * A hot path (every function, variable and datatype a policy names, at
   * every evaluation): no Entering/Leaving pair, which would drown the log.
   *
   * @param node - the object or array the step leaves
   * @param key - the name
   * @returns true where the member is the node's own
   */
  static has(node: unknown, key: unknown): boolean {
    if (node === null || typeof node !== 'object') {
      return false;
    }
    const name = String(key);
    if (Array.isArray(node)) {
      return DIGITS.test(name) && Number(name) < node.length;
    }
    return Object.prototype.hasOwnProperty.call(node, name);
  }

  /**
   * The member `key` names, when `node` holds it itself; otherwise
   * `undefined`, the answer a missing name gives.
   *
   * A hot path, as `has()`: no Entering/Leaving pair.
   *
   * @param node - the object or array
   * @param key - the name
   * @returns the own member, or undefined
   */
  static read(node: unknown, key: unknown): any {
    if (!OwnMembers.has(node, key)) {
      return undefined;
    }
    return (node as Record<string, unknown>)[String(key)];
  }

  /**
   * Sets an own member of a plain object, `__proto__` included: an
   * ordinary data member, enumerable, writable and configurable, as an
   * assignment makes one — but never the prototype.
   *
   * @param node - the object
   * @param key - the name
   * @param value - the value
   */
  static put(node: Record<string, any>, key: unknown, value: unknown): void {
    log.debug("Entering OwnMembers.put().");
    Object.defineProperty(node, String(key), { value: value, writable: true,
                                               enumerable: true,
                                               configurable: true });
    log.debug("Leaving OwnMembers.put().");
  }
}

/**
 * Own-member reads and writes for names a caller chose (2026-11-12).
 * @namespace
 */
export = {
  OwnMembers: OwnMembers,
  has: OwnMembers.has,
  read: OwnMembers.read,
  put: OwnMembers.put
};
