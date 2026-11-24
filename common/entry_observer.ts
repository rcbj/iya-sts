// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: entry_observer.ts
//
// ===========================================================================
// THE PERSON'S CREDENTIAL ATTRIBUTES, OBSERVED AT EVERY DIRECTORY WRITE
// (#2050, #2051; rcbj 2026-11-23: "Be consistent. The user objects need to
// contain the master copy of the credential data.").
//
// The person's entry is the MASTER of their S/MIME certificates
// (`userSMIMECertificate`), their SSH user certificates
// (`stsSshUserCertificate`), their hardware tokens (`stsHardwareToken`) and
// their assigned OATH and YubiKey OTP tokens (`stsOathToken`,
// `stsYubiOtpToken`). The stores beside them — `ssh_user_ca.issued`,
// `hardware_tokens.register`, `oath_tokens.inventory`, `yubiotp.inventory`
// and `yubiotp.publicIds` — are INDEXES derived from the entries, kept for
// what is not one person's question: the KRL, a credential's token at a
// sign-in, a YK-VAL public identity, a serial at a claim, retirement.
//
// **ONE MECHANISM KEEPS THEM RIGHT, AND IT IS CHANGE-DRIVEN.** Every write
// of a person's entry, by every door — the console, `/admin-api`, the
// attribute editor, SCIM, an LDAP add, modify or delete — reaches
// `ldap_server.js`'s `noteAccountChange()` with the entry's attributes
// before and after, and that function hands them here (`entryChanged()`).
// Each module that owns one of these attributes registered a HANDLER for it
// (`register()`), and is told, for that one entry, the attribute's values
// before and after and who wrote them. It updates the index rows of that
// entry and nothing else: no walk keeps an index right day to day.
//
// **THE ORDER OF A WRITE IS THE SAME FOR EVERY KIND: THE ENTRY FIRST, THEN
// THE INDEX.** A module writing its own attribute (an issuance, a
// revocation, a recorded token) writes the entry, and then its index row
// itself; while it does, its handler is told the write is its own
// (`selfWrite`) and does nothing. A write by any other door is a FOREIGN
// write, and the handler decides what it means: a value removed is the
// credential given up (an SSH certificate REVOKED, an OATH or YubiKey OTP
// token retired, a person's credentials dropped from a hardware token's
// index row), and a value ADDED or CHANGED is refused — dropped from the
// entry again and audited — because no door but the CA issues a
// certificate, and no door but attestation records a token's serial. A
// handler's work that needs the store runs in a promise job after the write
// has returned (`ldap_server.js`'s rule for every consequence of a write).
//
// **A HOOK, ARGUED UNDER RULE 3e AS `hardware_tokens.registerRetirer()` IS.**
// The owners are built long before the directory (21) and are reached by
// `pki.js` and the credential store; the directory requiring each of them
// to tell it of a write would be a chain of ifs a new kind can be missing
// from, and each requiring the directory would drag its `/admin/ldap/*`
// pages forward. So each registers here, a library both sides require
// (a cache hit that moves nothing), validated WHOLE: an attribute this file
// lists and a `changed` function (STS-LDAP-0224).
//
// A LIBRARY (rule 3): it registers no route and requires only `helpers` and
// `error_codes`; `audit` is reached at the moment of use, for the actor.
// ===========================================================================

import helpers = require('./helpers');
import errorCodes = require('./error_codes');

type Json = any;

// The attributes a handler may be registered for: the five credential
// kinds on a person.
const ATTRIBUTES = ['userSMIMECertificate', 'stsSshUserCertificate',
                    'stsHardwareToken', 'stsOathToken', 'stsYubiOtpToken'];

interface EntryChange {
  kind: string;
  dn: string;
  username: string;
  subject: string;
  realm: string;
  actor: string;
  door: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

interface Handler {
  changed(change: Json): void;
}

const handlers: Record<string, Handler> = {};

// The values of one attribute in a snapshot, under its RFC 4522 `;binary`
// spelling too, lower-cased names (the store's).
function valuesIn(attributes: Record<string, unknown>,
                  attribute: string): string[] {
  helpers.log.debug("Entering valuesIn().");
  const name = attribute.toLowerCase();
  const out: string[] = [];
  [name + ';binary', name].forEach(function (key: string): void {
    const held = (attributes || {})[key];
    (Array.isArray(held) ? held : (held === undefined ? [] : [held]))
      .forEach(function (one: unknown): void {
        if (one !== undefined && one !== null) {
          out.push(String(one));
        }
      });
  });
  helpers.log.debug("Leaving valuesIn().");
  return out;
}

/**
 * The observer of the person's credential attributes (header).
 */
class EntryObserver {
  static readonly ATTRIBUTES = ATTRIBUTES;

  /**
   * Registers a module's handler for one attribute (header), validated
   * whole; a second registration replaces the first.
   *
   * @param attribute - one of ATTRIBUTES
   * @param handler - `{ changed(change) }`
   * @returns true when registered
   */
  static register(attribute: string, handler: Json): boolean {
    helpers.log.debug("Entering EntryObserver.register(). " + attribute);
    if (ATTRIBUTES.indexOf(attribute) < 0 || !handler ||
        typeof handler.changed !== 'function') {
      helpers.log.error(errorCodes.tag('STS-LDAP-0224') + 'entry observer: ' +
        'a handler for "' + String(attribute) + '" was refused: the ' +
        'attribute must be one of ' + ATTRIBUTES.join(', ') + ' and the ' +
        'handler must offer changed().');
      helpers.log.debug("Leaving EntryObserver.register(). Refused.");
      return false;
    }
    handlers[attribute] = handler;
    helpers.log.debug("Leaving EntryObserver.register().");
    return true;
  }

  /**
   * The attributes a handler is registered for.
   *
   * @returns their names
   */
  static registered(): string[] {
    helpers.log.debug("Entering EntryObserver.registered().");
    helpers.log.debug("Leaving EntryObserver.registered().");
    return Object.keys(handlers).sort();
  }

  /**
   * One person's entry was written (header): each registered attribute
   * whose values differ is handed to its owner, synchronously, in the
   * entry's realm. A handler that throws does not undo the write.
   *
   * @param change - `{ kind, dn, username, subject, realm, actor, door,
   *   before, after }`
   * @returns the attributes handed over
   */
  static entryChanged(change: EntryChange): string[] {
    helpers.log.debug("Entering EntryObserver.entryChanged().");
    const c = change || ({} as EntryChange);
    const told: string[] = [];
    // WHO WROTE IT (#2050): the door's own word where it has one (an LDAP
    // operation's bound DN), else the ambient source's — the API's or the
    // portal's token subject, the SCIM client, a scheduler job — the same
    // actor model every audit row uses (`audit.currentActor()`). A write
    // made outside any request or job says so rather than naming nobody.
    let actor = String(c.actor || '');
    if (!actor) {
      try {
        actor = String(require('./audit').currentActor() || '');
      } catch (e) {
        helpers.log.debug("Caught in EntryObserver.entryChanged(): " +
                          ((e && e.message) || e));
        actor = '';
      }
    }
    if (!actor) {
      actor = 'unknown: ' + String(c.door || 'a directory write') +
        ', outside any request or job';
    }
    Object.keys(handlers).forEach(function (attribute: string): void {
      const before = valuesIn(c.before || {}, attribute);
      const after = valuesIn(c.after || {}, attribute);
      if (before.length === after.length &&
          before.every(function (one: string, i: number): boolean {
            return one === after[i];
          })) {
        return;
      }
      told.push(attribute);
      try {
        handlers[attribute].changed({
          attribute: attribute, kind: String(c.kind || ''),
          dn: String(c.dn || ''), username: String(c.username || ''),
          subject: String(c.subject || ''), realm: String(c.realm || ''),
          actor: actor, door: String(c.door || ''),
          deleted: String(c.kind || '').indexOf('deleted') === 0,
          before: before, after: after
        });
      } catch (e) {
        helpers.log.error(errorCodes.tag('STS-LDAP-0225') + 'entry ' +
          'observer: the handler of ' + attribute + ' threw on a write of ' +
          String(c.dn || '') + ': ' + ((e && e.message) || e));
      }
    });
    helpers.log.debug("Leaving EntryObserver.entryChanged(). " +
                      told.length);
    return told;
  }

  /**
   * An attribute's values in an attribute snapshot, under either spelling.
   *
   * @param attributes - the snapshot
   * @param attribute - the attribute
   * @returns its values
   */
  static valuesIn(attributes: Record<string, unknown>,
                  attribute: string): string[] {
    helpers.log.debug("Entering EntryObserver.valuesIn().");
    helpers.log.debug("Leaving EntryObserver.valuesIn().");
    return valuesIn(attributes, attribute);
  }
}

/**
 * The observer of the person's credential attributes (#2050, #2051). A
 * library (rule 3) whose state is the handler table, a fact about the
 * process like `hardware_tokens`' retirers.
 * @namespace
 */
export = {
  EntryObserver: EntryObserver,
  ATTRIBUTES: ATTRIBUTES,
  register: EntryObserver.register,
  registered: EntryObserver.registered,
  entryChanged: EntryObserver.entryChanged,
  valuesIn: EntryObserver.valuesIn
};
