// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: account_state.ts
//
// ===========================================================================
// A DISABLED ACCOUNT — THE ONE PLACE ONE IS DISABLED, ENABLED AND ASKED
// ABOUT (2026-09-17, #36 follow-up).
//
// Until this file the directory had no "disabled" state: the issuance policy
// could refuse somebody an application, and SCIM's `active: false` was stored
// as `scimActive` and read by nothing. A disabled account is now
// `pwdAccountLockedTime` on the person's entry (`common/credentials.ts`,
// `accountDisabled()`, argues the attribute), and this file is what the
// doors ask and what an administrator's act goes through.
//
// **WHAT DISABLING DOES, IN THE ORDER IT DOES IT.**
//
//   1. The lock is written (`credentials.setAccountDisabled()`), which the
//      directory hands to the account observer — RISC's `account-disabled`,
//      once, whichever door wrote it.
//   2. EVERYTHING THE PERSON HOLDS IS ENDED, through the same
//      `logout.terminate()` a global logout calls: every sign-on session (and
//      with each, `authn.dropSession()`'s consequences — CAEP
//      `session-revoked`, the back-channel Logout Tokens through the
//      session-end claim, the RFC 9700 refresh revocation), every revocable
//      token, every outstanding code, every directory connection bound as
//      them, a Kerberos sign-out instant, and the disowning of what cannot be
//      revoked. The front-channel notifications cannot be sent from here —
//      they are iframes, and an administrator's console is not the person's
//      browser — and the result says so, as a global logout's does.
//   3. One `account.disable` audit row naming who did it and from where.
//
// Enabling clears the lock (RISC `account-enabled`) and ends nothing.
//
// **WHERE IT IS ASKED**, which is the half that makes the state mean
// anything: `credentials.verify()` (every password door, both modes),
// `authn.startSession()` (every session), `authn.sessionOf()` (a live
// session), `issuance_gate.check()` (every issuance site), the KDC (an
// AS-REQ and S4U2Self), and the management API's bearer check. The list of
// doors, and how each is enforced, is in `authn/CLAUDE.md`.
//
// **A WRITE THAT DID NOT COME THROUGH HERE** — SCIM's `active`, an
// `ldapmodify` of the attribute — is handed to `directoryChanged()` by the
// directory, which ends what the person holds after the write has been
// answered. So the consequence does not depend on the door.
//
// A LIBRARY (rule 3). It requires `helpers`, `credentials`, `audit`,
// `admin_stats` and `error_codes`, none of which requires it back; the
// directory reaches it LAZILY, at the moment a lock moves. The logout family
// is found in `require.cache` and never required — `ssf/account_signals.ts`'s
// arrangement, for its reason: this file is loaded long before that family,
// and a process that never loaded it (an in-process test) is told so in the
// answer rather than given nine modules it did not ask for.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import credentials = require('./credentials');
import audit = require('./audit');
import stats = require('./admin_stats');
import errorCodes = require('./error_codes');
import realms = require('./realms');

// A loose JSON-shaped value: a result, an audit detail.
type Json = any;

// What this file needs of the logout family.
interface LogoutFamily {
  terminate(key?: string, selection?: string[], opts?: Json): Json;
  heldIds?(key?: string): string[];
  heldIdsFor?(keys?: string[]): Map<string, string[]>;
  terminateEach?(list?: Json[], opts?: Json): Json[];
}

interface AccountStateDeps {
  log: typeof helpers.log;
  credentials: typeof credentials;
  audit: typeof audit;
  stats: typeof stats;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  findLogout(): LogoutFamily | null;
  later(fn: () => void): void;
}

// What an act answers.
interface AccountAct {
  ok: boolean;
  username?: string;
  disabled?: boolean;
  changed?: boolean;
  ended?: Json;
  message?: string;
  errors?: string[];
}

/**
 * Disables and enables accounts, and answers whether one is disabled.
 *
 * A disabled account is `pwdAccountLockedTime` on the person's entry; disabling
 * it also ends everything the person holds, through the global logout.
 */
class AccountState {
  /**
   * Builds the account-state service.
   *
   * @param deps - the logger, credentials, audit, statistics, error codes,
   *   realms, the logout finder and a deferral function
   */
  constructor(private readonly deps: AccountStateDeps) {
    deps.log.debug("Entering AccountState.constructor().");
    deps.log.debug("Leaving AccountState.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules, the loaded-logout finder, and
   *   `setImmediate` as the deferral
   */
  static defaultDeps(): AccountStateDeps {
    helpers.log.debug("Entering AccountState.defaultDeps().");
    helpers.log.debug("Leaving AccountState.defaultDeps().");
    return {
      log: helpers.log,
      credentials: credentials,
      audit: audit,
      stats: stats,
      errorCodes: errorCodes,
      realms: realms,
      findLogout: AccountState.loadedLogout,
      later: function (fn: () => void): void {
        setImmediate(fn);
      }
    };
  }

  // `logout/logout.ts` as it is loaded in THIS process, or null. Never a
  // require — see the header.
  /**
   * Returns `logout/logout.ts` as loaded in this process, or null.
   *
   * It looks in `require.cache` and never requires the module.
   *
   * @returns the logout module's exports, or null when it is not loaded
   */
  static loadedLogout(): LogoutFamily | null {
    const { log } = helpers;
    log.debug('Entering AccountState.loadedLogout().');
    let id = '';
    try {
      id = require.resolve('../logout/logout');
    } catch (e) {
      log.debug('Caught in AccountState.loadedLogout(): ' +
                ((e && e.message) || e));
      log.debug('Leaving AccountState.loadedLogout(). Not resolvable.');
      return null;
    }
    const cached = require.cache[id];
    log.debug('Leaving AccountState.loadedLogout(). ' +
              (cached ? 'Loaded.' : 'Not loaded.'));
    return cached && cached.exports
      ? cached.exports as unknown as LogoutFamily : null;
  }

  // THE NAME A DOOR HAS IN HAND, as the directory's key. A token's `sub`, a
  // Kerberos `alice@REALM` and a plain `alice` are one person; the key is
  // `admin_stats.identityKeyOf()`'s, which is the one every sign-out uses.
  private keyOf(who: unknown): string {
    const { log, stats } = this.deps;
    log.debug("Entering AccountState.keyOf().");
    const text = String(who == null ? '' : who).trim();
    if (!text) {
      log.debug("Leaving AccountState.keyOf(). Nothing.");
      return '';
    }
    let key = text;
    try {
      key = String(stats.identityKeyOf(text) || text);
    } catch (e) {
      log.debug("Caught in AccountState.keyOf(): " + ((e && e.message) || e));
      key = text;
    }
    log.debug("Leaving AccountState.keyOf().");
    return key;
  }

  // -------------------------------------------------------------------------
  // IS THIS ACCOUNT DISABLED? The question every door asks. It never throws.
  // The anonymous principal and an application are never disabled here: an
  // application is refused by the issuance policy, and nobody is the
  // anonymous principal.
  // -------------------------------------------------------------------------
  /**
   * Says whether an account is disabled; the question every door asks.
   *
   * Never throws. The anonymous principal and an empty name are never disabled.
   *
   * @param who - the name a door has in hand: a username, a token `sub` or a
   *   Kerberos principal
   * @returns true when the person's entry carries the lock
   */
  isDisabled(who: unknown): boolean {
    const { log, credentials } = this.deps;
    log.debug("Entering AccountState.isDisabled().");
    const raw = String(who == null ? '' : who).trim();
    if (!raw || raw === 'anonymous') {
      log.debug("Leaving AccountState.isDisabled(). Nobody.");
      return false;
    }
    let disabled = false;
    try {
      disabled = credentials.accountDisabled(raw) ||
        (this.keyOf(raw) !== raw && credentials.accountDisabled(
          this.keyOf(raw)));
    } catch (e) {
      log.debug("Caught in AccountState.isDisabled(): " +
                ((e && e.message) || e));
      disabled = false;
    }
    log.debug("Leaving AccountState.isDisabled(). " + disabled);
    return !!disabled;
  }

  // -------------------------------------------------------------------------
  // END EVERYTHING THE PERSON HOLDS — step 2 of the header. Answers what the
  // global logout answered, or why nothing could be ended here.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // THE IDS OF WHAT A PERSON HOLDS NOW (#226), for an `endEverything()`
  // later that must end only these — or null where no sign-out module is
  // loaded in this process, which the caller reads as "cannot say".
  // -------------------------------------------------------------------------
  /**
   * Lists the ids of what a person holds now, for a later `endEverything()`
   * that must end only those.
   *
   * @param who - the person's name
   * @returns the ids, or null when no sign-out module is loaded in this process
   */
  heldBy(who: string): string[] | null {
    const { log, findLogout } = this.deps;
    log.debug("Entering AccountState.heldBy(). who=" + who);
    const logout = findLogout();
    if (!logout || typeof logout.heldIds !== 'function') {
      log.debug("Leaving AccountState.heldBy(). No logout family.");
      return null;
    }
    const ids = logout.heldIds(this.keyOf(who));
    log.debug("Leaving AccountState.heldBy(). " + ids.length + ".");
    return ids;
  }

  // `opts.selection`, when given, is the ids to end (`heldBy()`), and
  // nothing else; absent, EVERYTHING — a global logout.
  /**
   * Ends every session, token, code and connection a person holds, through
   * `logout.terminate()`.
   *
   * Front-channel notifications are not sent from here. A failure is logged
   * under STS-AUTHN-0203 and reported in the answer rather than thrown.
   *
   * @param who - the person's name
   * @param opts - `selection` (the ids to end, else everything), `actor`,
   *   `channel`, `by` and `initiatingEntity`
   * @returns whether anything was ended, the counts, the back-channel
   *   deliveries queued and a message
   */
  endEverything(who: string, opts?: Json): Json {
    const { log, findLogout, errorCodes } = this.deps;
    log.debug("Entering AccountState.endEverything(). who=" + who);
    const o = opts || {};
    const logout = findLogout();
    if (!logout || typeof logout.terminate !== 'function') {
      log.debug("Leaving AccountState.endEverything(). No logout family.");
      return { ended: false, terminated: 0, backchannel: [],
               message: 'No sign-out module is loaded in this process, so ' +
                        'nothing the person held was ended here.' };
    }
    let result: Json = null;
    try {
      result = logout.terminate(this.keyOf(who),
                                Array.isArray(o.selection) ? o.selection : [], {
        actor: o.actor || '', channel: o.channel || 'internal',
        by: o.by || 'an administrator disabling the account',
        // WHO ENDED IT, for CAEP's `initiating_entity` (#242): the caller
        // says, and an administrator's act is the default of this file's
        // callers — risk scoring says `policy`.
        initiatingEntity: o.initiatingEntity || 'admin',
        // The disable's own `suspend` (#151) says it; no `invalidate` too.
        providerCommand: false
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0203') + 'account state: ending ' +
                'what ' + who + ' holds failed after the account was ' +
                'disabled; the lock stands and every door refuses them: ' +
                ((e && e.message) || e));
      log.debug("Leaving AccountState.endEverything(). Threw.");
      return { ended: false, terminated: 0, backchannel: [],
               message: 'The account is disabled, and ending what it held ' +
                        'failed: ' + ((e && e.message) || e) };
    }
    log.debug("Leaving AccountState.endEverything(). " +
              ((result && result.terminated) || []).length + " ended.");
    return { ended: true,
             terminated: ((result && result.terminated) || []).length,
             skipped: ((result && result.skipped) || []).length,
             notifications: ((result && result.notifications) || []).length,
             backchannel: (result && result.backchannel) || [],
             message: String((result && result.message) || '') };
  }

  // THE PERSON IS TOLD BY MAIL (#63): `common/mail_uses.ts`'s security
  // notice, which they cannot decline. `bySystem` — risk scoring disabled
  // them, not an administrator — tells the realm's administrators too.
  // Lazily required, and never allowed to throw into the disable.
  private mailNotice(name: string, why: string, bySystem: boolean): void {
    const { log } = this.deps;
    log.debug("Entering AccountState.mailNotice().");
    try {
      require('./mail_uses').accountDisabled(name, why, bySystem);
    } catch (e) {
      log.debug("Caught in AccountState.mailNotice(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving AccountState.mailNotice().");
  }

  // -------------------------------------------------------------------------
  // DISABLE OR ENABLE — the administrator's act, from `/admin/users` and
  // `POST /admin-api/users/{disable|enable}`. `opts`: `actor`, `via`
  // (`console` or `api`, for the sentence and the channel), `reason`.
  // -------------------------------------------------------------------------
  /**
   * Disables or enables an account: the administrator's act from the console or
   * the management API.
   *
   * Disabling writes the lock, ends everything the person holds, writes one
   * audit row and mails the person a security notice. Enabling clears the lock
   * and ends nothing.
   *
   * @param who - the person's name
   * @param disabled - true to disable, false to enable
   * @param opts - `actor`, `via` (`console` or `api`), `door`, `reason`,
   *   `riscReason`, `by` and `initiatingEntity`
   * @returns the outcome, with `changed` false when the account was already in
   *   that state; a refusal carries `ok: false` and `errors`
   */
  setDisabled(who: string, disabled: boolean, opts?: Json): AccountAct {
    const { log, credentials, audit, errorCodes } = this.deps;
    log.debug("Entering AccountState.setDisabled(). disabled=" + !!disabled);
    const o = opts || {};
    const name = String(who || '').trim();
    if (!name) {
      log.debug("Leaving AccountState.setDisabled(). No name.");
      return errorCodes.mark({ ok: false,
        errors: ['Name the person to ' + (disabled ? 'disable' : 'enable') +
                 '.'] }, 'STS-ADMIN-0792');
    }
    if (name === 'anonymous') {
      log.debug("Leaving AccountState.setDisabled(). The anonymous " +
                "principal.");
      return errorCodes.mark({ ok: false,
        errors: ['The anonymous principal is not an account and cannot be ' +
                 'disabled; turn authn.unauthenticatedSessions off ' +
                 'instead.'] }, 'STS-ADMIN-0792');
    }
    const was = this.isDisabled(name);
    // `door` names an actor that is not an administrator at either surface
    // — risk scoring (#62 P4) disables where its policy says to.
    const door = o.door ? String(o.door)
      : (o.via === 'api' ? '/admin-api/users' : 'the admin console');
    if (was === !!disabled) {
      log.debug("Leaving AccountState.setDisabled(). No change.");
      return { ok: true, username: name, disabled: !!disabled,
               changed: false,
               message: name + ' is already ' +
                        (disabled ? 'disabled' : 'enabled') + '; nothing ' +
                        'was changed.' };
    }
    // RISC's reason, when the administrator gave one of section 2.2's two
    // (#146); `o.reason` stays the free text the audit row keeps.
    const written: Json = credentials.setAccountDisabled(name, !!disabled,
      { riscReason: String(o.riscReason || '') });
    if (!written || !written.ok) {
      log.debug("Leaving AccountState.setDisabled(). Not written.");
      return written;
    }
    const ended = disabled
      ? this.endEverything(name, {
          actor: o.actor || '', channel: o.via || 'http',
          // `door` names an actor that is not an administrator — risk
          // scoring, a foreign transmitter's SET — and each of those is a
          // policy deciding (#242).
          initiatingEntity: o.initiatingEntity ||
                            (o.door ? 'policy' : 'admin'),
          // A noun phrase naming the act (#294): it finishes CAEP's
          // "The session was ended by …" and the mail's "… by …".
          by: o.by ? String(o.by)
            : (o.door ? door + ' disabling the account'
                      : 'an administrator disabling the account (' + door +
                        ')') })
      : null;
    audit.audit({
      action: disabled ? 'account.disable' : 'account.enable',
      actor: o.actor || '',
      channel: o.via === 'api' ? 'api' : 'http',
      protocol: 'Directory',
      target: name,
      summary: name + '\'s account was ' +
               (disabled ? 'DISABLED' : 'enabled') + ' from ' + door +
               (ended ? '; ' + ended.terminated + ' live item(s) were ' +
                        'ended' : ''),
      detail: {
        username: name,
        attribute: 'pwdAccountLockedTime',
        reason: String(o.reason || ''),
        ended: ended ? String(ended.terminated) : '',
        backchannel: ended ? String(ended.backchannel.length) : ''
      }
    });
    log.info('account state: ' + name + ' was ' +
             (disabled ? 'DISABLED' : 'enabled') + ' from ' + door + '.');
    if (disabled) {
      this.mailNotice(name, String(o.reason || ''), !!o.door);
    }
    log.debug("Leaving AccountState.setDisabled(). Changed.");
    return {
      ok: true, username: name, disabled: !!disabled, changed: true,
      ended: ended,
      message: disabled
        ? name + ' is disabled: every door refuses them from now on, and ' +
          (ended && ended.ended
            ? ended.terminated + ' live item(s) they held were ended' +
              (ended.backchannel.length
                ? ', with ' + ended.backchannel.length + ' back-channel ' +
                  'Logout Token(s) queued'
                : '') + '. Front-channel notifications need the person\'s ' +
              'own browser and are not sent from here.'
            : 'nothing they held could be ended here: ' +
              (ended ? ended.message : '')) +
          ' RISC receivers are told account-disabled.'
        : name + ' is enabled again. Nothing they held before the disable ' +
          'comes back; they sign in afresh. RISC receivers are told ' +
          'account-enabled.'
    };
  }

  // -------------------------------------------------------------------------
  // THE DIRECTORY SAW A LOCK MOVE THAT DID NOT COME THROUGH `setDisabled()` —
  // SCIM's `active`, an `ldapmodify`, a console create. The consequence runs
  // AFTER the write has been answered, in the realm the entry is in. Enabling
  // ends nothing, so only a disable is scheduled; both are audited.
  // -------------------------------------------------------------------------
  /**
   * Handles a lock the directory saw move without `setDisabled()` (SCIM, an
   * LDAP modify, a console create).
   *
   * After the write has been answered it ends what the person holds (for a
   * disable) and writes the audit row.
   *
   * @param change - `username`, `realm`, `disabled` and `kind` of the write
   */
  directoryChanged(change: Json): void {
    const { log, later, realms, audit } = this.deps;
    const self = this;
    log.debug("Entering AccountState.directoryChanged().");
    const c = change || {};
    const name = String(c.username || '');
    if (!name) {
      log.debug("Leaving AccountState.directoryChanged(). Nobody named.");
      return;
    }
    const realm = realms.get(String(c.realm || '')) || realms.current();
    later(function (): void {
      realms.run(realm, function (): void {
        if (c.disabled) {
          self.mailNotice(name, '', false);
        }
        const ended = c.disabled
          ? self.endEverything(name, {
              channel: 'internal',
              initiatingEntity: 'admin',
              by: 'an administrator disabling the account through the ' +
                  'directory (' + String(c.kind || 'a write') + ')' })
          : null;
        audit.audit({
          action: c.disabled ? 'account.disable' : 'account.enable',
          actor: '',
          channel: 'internal',
          protocol: 'Directory',
          target: name,
          summary: name + '\'s account was ' +
                   (c.disabled ? 'DISABLED' : 'enabled') + ' by a directory ' +
                   'write (pwdAccountLockedTime ' +
                   (c.disabled ? 'set' : 'cleared') + ')' +
                   (ended ? '; ' + ended.terminated + ' live item(s) were ' +
                            'ended' : ''),
          detail: { username: name, attribute: 'pwdAccountLockedTime',
                    write: String(c.kind || ''),
                    ended: ended ? String(ended.terminated) : '' }
        });
      });
    });
    log.debug("Leaving AccountState.directoryChanged(). Scheduled.");
  }

  // -------------------------------------------------------------------------
  // A PERSON WAS DELETED (#241, 2026-09-26) — SCIM's DELETE, an LDAP delete,
  // anything that reaches the directory's `deletePerson()`. What they held
  // ends as a disable's does: every sign-on session through `dropSession()`
  // (CAEP session-revoked, `initiating_entity: admin`, and the back-channel
  // Logout Tokens), every token and code, every connection. Until #241 the
  // directory skipped this for a delete on the belief that "a deleted entry
  // takes its sessions with it by other means"; nothing did, and a deleted
  // person went on signing in to relying parties until their session ran out.
  //
  // **WHAT IS ENDED IS WHAT THEY HELD AT THE MOMENT OF THE DELETE**, read
  // synchronously here (`heldBy()`, #226's arrangement) and ended after the
  // write has been answered — so a person made again under the same name in
  // the meantime keeps what they hold. Where no sign-out module is loaded the
  // ids cannot be read and everything under the name is ended, as a disable
  // does. `authn.sessionOf()` is the catch-up for a session this could not
  // reach: a delete made on another node.
  // -------------------------------------------------------------------------
  /**
   * Ends what a deleted person held at the moment of the delete.
   *
   * The held ids are read now and ended after the write has been answered, so a
   * person re-created under the same name keeps what they hold. A batch of one
   * of directoryDeletedMany().
   *
   * @param change - `username`, `realm` and `door` of the delete
   */
  directoryDeleted(change: Json): void {
    const { log } = this.deps;
    log.debug("Entering AccountState.directoryDeleted().");
    this.directoryDeletedMany([change]);
    log.debug("Leaving AccountState.directoryDeleted().");
  }

  // -------------------------------------------------------------------------
  // SEVERAL PEOPLE DELETED AT ONCE (#351, 2026-09-29) — a SCIM Bulk, or any
  // door's run of deletes the directory hands over together. Everything above
  // holds per person: what they held is read NOW, ended LATER, and a person
  // made again under the name in between keeps theirs. What changes is how
  // often the stores are read: once for the whole set (`heldIdsFor()`), not
  // once per person, and ended with one index (`terminateEach()`) — each
  // person's sign-out still its own act, with its own audit row, CAEP and
  // back-channel Logout Tokens. A person holding nothing is dropped here and
  // costs nothing after; the deferred step logs ONE line per batch.
  //
  // The ending runs in chunks of `CHUNK`, a macrotask apart, so a thousand
  // sign-outs never hold the event loop for the whole thousand.
  // -------------------------------------------------------------------------
  static readonly CHUNK = 500;

  /**
   * Ends what each deleted person held at the moment of the delete, reading
   * the stores once for the set.
   *
   * @param changes - `username`, `realm` and `door` per delete
   */
  directoryDeletedMany(changes: Json[]): void {
    const { log, realms } = this.deps;
    log.debug("Entering AccountState.directoryDeletedMany(). " +
              (changes || []).length + ".");
    // By realm, in the order given; a name once per realm.
    const byRealm = new Map<string, { realm: Json, door: string,
                                      names: string[] }>();
    (changes || []).forEach((change) => {
      const c = change || {};
      const name = String(c.username || '');
      if (!name || name === 'anonymous') {
        return;
      }
      const realm = realms.get(String(c.realm || '')) || realms.current();
      let group = byRealm.get(realm.id);
      if (!group) {
        group = { realm: realm, door: String(c.door || 'a directory delete'),
                  names: [] };
        byRealm.set(realm.id, group);
      }
      if (group.names.indexOf(name) < 0) {
        group.names.push(name);
      }
    });
    byRealm.forEach((group) => {
      this.endHeldByDeleted(group.realm, group.names, group.door);
    });
    log.debug("Leaving AccountState.directoryDeletedMany().");
  }

  // One realm's deleted people: read what they hold now, end it later.
  private endHeldByDeleted(realm: Json, names: string[], door: string): void {
    const { log, later, realms } = this.deps;
    const self = this;
    log.debug("Entering AccountState.endHeldByDeleted(). " + names.length +
              ".");
    const held: Map<string, string[]> | null = realms.run(realm,
      function (): Map<string, string[]> | null {
        return self.heldByMany(names);
      });
    const toEnd = names.filter(function (name) {
      return !held || (held.get(name) || []).length > 0;
    });
    if (!toEnd.length) {
      log.debug("Leaving AccountState.endHeldByDeleted(). They held " +
                "nothing.");
      return;
    }
    const totals = { people: 0, ended: 0, backchannel: 0 };
    const step = function (from: number): void {
      if (!realms.get(realm.id)) {
        // The realm went in the meantime, and its removal ended everything
        // in it already (`realms.retire()`).
        return;
      }
      const chunk = toEnd.slice(from, from + AccountState.CHUNK);
      realms.run(realm, function (): void {
        const results = self.endEach(chunk.map(function (name) {
          return { who: name,
                   selection: held ? held.get(name) : undefined };
        }), {
          channel: 'internal',
          initiatingEntity: 'admin',
          by: 'the deletion of the account (' + door + ')' });
        results.forEach(function (ended: Json) {
          totals.people += 1;
          totals.ended += ended.terminated;
          totals.backchannel += ended.backchannel.length;
        });
      });
      if (from + AccountState.CHUNK < toEnd.length) {
        later(function (): void {
          step(from + AccountState.CHUNK);
        });
        return;
      }
      log.info('account state: ' + (names.length === 1
        ? names[0] + ' was deleted; '
        : names.length + ' people were deleted (' + door + '); ' +
          totals.people + ' of them held something, and ') +
        totals.ended + ' live item(s) they held were ended' +
        (totals.backchannel
          ? ', with ' + totals.backchannel +
            ' back-channel Logout Token(s) queued'
          : '') + '.');
    };
    later(function (): void {
      step(0);
    });
    log.debug("Leaving AccountState.endHeldByDeleted(). Scheduled " +
              toEnd.length + ".");
  }

  // heldBy() for several people at once: the stores read once for the set.
  // Null where no sign-out module is loaded, as heldBy()'s.
  private heldByMany(names: string[]): Map<string, string[]> | null {
    const { log, findLogout } = this.deps;
    log.debug("Entering AccountState.heldByMany(). " + names.length + ".");
    const logout = findLogout();
    if (!logout) {
      log.debug("Leaving AccountState.heldByMany(). No logout family.");
      return null;
    }
    const out = new Map<string, string[]>();
    if (typeof logout.heldIdsFor === 'function') {
      const byKey = logout.heldIdsFor(names.map((name) => {
        return this.keyOf(name);
      }));
      names.forEach((name) => {
        out.set(name, byKey.get(this.keyOf(name)) || []);
      });
    } else if (typeof logout.heldIds === 'function') {
      names.forEach((name) => {
        out.set(name, this.heldBy(name) || []);
      });
    } else {
      log.debug("Leaving AccountState.heldByMany(). No logout family.");
      return null;
    }
    log.debug("Leaving AccountState.heldByMany().");
    return out;
  }

  // endEverything() for several people, through `terminateEach()` where the
  // sign-out offers it, so the stores are read once; each person's answer is
  // endEverything()'s, and each one's info line becomes the caller's one.
  private endEach(list: Json[], opts: Json): Json[] {
    const { log, findLogout, errorCodes } = this.deps;
    log.debug("Entering AccountState.endEach(). " + list.length + ".");
    const logout = findLogout();
    if (!logout || typeof logout.terminateEach !== 'function') {
      log.debug("Leaving AccountState.endEach(). One at a time.");
      return list.map((one) => {
        return this.endEverything(one.who, Object.assign({}, opts,
          { selection: one.selection }));
      });
    }
    let results: Json[] = [];
    try {
      results = logout.terminateEach(list.map((one) => {
        return { key: this.keyOf(one.who),
                 selection: Array.isArray(one.selection) ? one.selection
                   : [] };
      }), {
        actor: opts.actor || '', channel: opts.channel || 'internal',
        by: opts.by, initiatingEntity: opts.initiatingEntity || 'admin',
        providerCommand: false, quiet: true
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-LDAP-0120') + 'account state: ending ' +
                'what ' + list.length + ' deleted person(s) held failed: ' +
                ((e && e.message) || e));
      log.debug("Leaving AccountState.endEach(). Threw.");
      return list.map(function (): Json {
        return { ended: false, terminated: 0, backchannel: [] };
      });
    }
    log.debug("Leaving AccountState.endEach().");
    return results.map(function (result: Json): Json {
      return { ended: true,
               terminated: ((result && result.terminated) || []).length,
               backchannel: (result && result.backchannel) || [] };
    });
  }
}

const slot = new InstanceSlot<AccountState>(
  'common/account_state',
  () => new AccountState(AccountState.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

/**
 * The disabled-account state: the one place an account is disabled, enabled and
 * asked about.
 *
 * A library the doors ask (`credentials.verify()`, `authn`, the issuance gate,
 * the KDC, the management API). The exports forward to the instance the
 * composition root installs.
 *
 * @namespace
 */
export = {
  AccountState: AccountState,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: AccountState): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  isDisabled: slot.forward('isDisabled'),
  endEverything: slot.forward('endEverything'),
  heldBy: slot.forward('heldBy'),
  setDisabled: slot.forward('setDisabled'),
  directoryChanged: slot.forward('directoryChanged'),
  directoryDeleted: slot.forward('directoryDeleted'),
  directoryDeletedMany: slot.forward('directoryDeletedMany')
};
