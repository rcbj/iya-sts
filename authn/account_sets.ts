// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_sets.ts
//
// ---------------------------------------------------------------------------
// A BROWSER'S ACCOUNT SET (#561): WHICH SIGN-ON SESSIONS ONE BROWSER HOLDS.
//
// With `authn.multipleAccounts` on, a browser may be signed in as several
// people at once. The sessions are the ordinary sign-on sessions of
// `authn/authn.ts` — each with its own lifetime, idle timeout, step-up state
// and sign-out — and this module is the LIST of them, kept on the server
// (the plan's D1 and D7): a row per browser in `authn.accountSets`, named
// by the `sts_accounts` cookie, holding
//
//   * `sessions`   sid → `{ sub, username, displayName, addedAt }`, the
//                  sessions this browser signed in to. A row lists sids and
//                  never decides whether one is live: the session store
//                  does, every time (`authn.ts` hands in `isLive`).
//   * `remembered` key → `{ sub, username, displayName, signedOutAt }`, an
//                  account that signed out (or whose session ran out) in
//                  this browser, offered by the picker until it is
//                  forgotten or `authn.rememberedAccountDays` passes. No
//                  credential, no sid: what the plan's D6 keeps.
//   * `lastActiveSid` the session most recently selected or signed in.
//   * `endedSids`, `forgotten` — what two nodes' copies need to merge
//                  (`merge()` below): a sid taken out and a key forgotten,
//                  so a stale copy cannot put either back.
//
// **THE COOKIE IS `<setId>.<handle>`, AND ONLY THE HANDLE IS A SECRET**, the
// session cookie's own arrangement (`authn.ts`, `mintSessionHandle()`): the
// row holds the handle's SHA-256 and nothing that opens it. A realm other
// than the default writes `sts_accounts_<realm>`, so one realm's sign-in
// does not overwrite another's set the way one `sts_session` slot is shared
// (`authn/CLAUDE.md`, *consoleSession()*).
//
// **THE HANDLE ROTATES WHEN A SESSION IS ADDED**, which is a sign-in and so
// a change of privilege — not on every change, as the plan said. A row is
// also changed where this browser is not present: a session that runs out
// on the sweep, is evicted at `authn.maxSessions` or is ended by an
// administrator moves to `remembered` on a request (or a job) that has no
// response to this browser to write a new cookie on, and a rotation there
// would cost the browser its whole set. Two tabs acting at once would race
// the same way. So the handle changes at the act that can carry it.
//
// **A SELECTION IS PER FLOW, NEVER PER BROWSER (the plan's section 2).** A
// person choosing an account inside a protocol flow — at the picker, or by
// signing in — resumes the flow with a TICKET (`sts_account=<ticket>` on
// the address the flow returns to), single use, short lived, bound to this
// set and to the path it was minted for. `authn.ts`'s middleware takes it
// off the request before any protocol module reads the query, spends it,
// and leaves the chosen sid on the request for `sessionOf()`. That is what
// keeps two tabs apart: neither flow reads the shared default cookie.
//
// A LIBRARY (rule 3): it registers no route. It requires `realms`,
// `config`, `crypto`, `helpers` and `error_codes`, none of which requires
// it back; `authn.ts` is its only caller. Static methods over the two
// module-level stores, because a store becomes per realm at its
// declaration and nowhere else.
// ---------------------------------------------------------------------------

import realms = require('../common/realms');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');

type Json = any;

/**
 * The cookie naming the default realm's account set.
 */
const COOKIE = 'sts_accounts';

/**
 * The query parameter a selection ticket rides on.
 */
const TICKET_PARAM = 'sts_account';

// How long a ticket lives: the redirect it rides on is followed at once, so
// this only has to outlast a slow browser.
const TICKET_TTL_MS = 2 * 60 * 1000;

// How many ended sids and forgotten keys a row keeps for the merge. A copy
// older than that many changes is older than any write still in flight.
const MERGE_MEMORY = 40;

const DAY_MS = 24 * 60 * 60 * 1000;

// THE TWO STORES, PER REALM (`tests/realm_isolation.js`'s rule).
//
// `authn.accountSets` is TOMBSTONED and MERGED: its key is a random id that
// is never written again once deleted, and two nodes can each edit one row
// (a sign-in on one, an expiry on another) — `merge()` is what the two
// copies become. Kept until the expiry job deletes an empty row.
const sets = realms.map({ persist: 'authn.accountSets', tombstone: true,
                          mergeRow: function (mine: Json, theirs: Json) {
                            return AccountSets.merge(mine, theirs);
                          } });

// `authn.accountTickets` is SHORT-LIVED BY NATURE: a ticket is spent on the
// next request or expires in two minutes.
const tickets = realms.map({ persist: 'authn.accountTickets',
                             retain: 'age',
                             expiresAt: realms.expiryField('expires', 1) });

/**
 * A browser's account set: the stores, the cookie and the operations on a
 * row. A static utility class.
 */
class AccountSets {
  static readonly COOKIE = COOKIE;
  static readonly TICKET_PARAM = TICKET_PARAM;

  /**
   * Whether several signed-in accounts are on in the ambient realm.
   *
   * @returns `authn.multipleAccounts`
   */
  static enabled(): boolean {
    helpers.log.debug("Entering AccountSets.enabled().");
    let on = false;
    try {
      on = config.value('authn.multipleAccounts') === true;
    } catch (e) {
      // A setting that cannot be read is the default, which is off.
      helpers.log.debug("Caught in AccountSets.enabled(): " +
                        ((e && e.message) || e));
      on = false;
    }
    helpers.log.debug("Leaving AccountSets.enabled(). " + on);
    return on;
  }

  /**
   * The most accounts a set holds, live and remembered together.
   *
   * @returns `authn.maxBrowserAccounts`
   */
  static maxAccounts(): number {
    helpers.log.debug("Entering AccountSets.maxAccounts().");
    const n = Math.floor(Number(config.value('authn.maxBrowserAccounts')));
    helpers.log.debug("Leaving AccountSets.maxAccounts().");
    return n > 0 ? n : 10;
  }

  /**
   * How long a signed-out account is remembered, in milliseconds.
   *
   * @returns `authn.rememberedAccountDays` in milliseconds
   */
  static rememberMs(): number {
    helpers.log.debug("Entering AccountSets.rememberMs().");
    const days = Math.floor(Number(
      config.value('authn.rememberedAccountDays')));
    helpers.log.debug("Leaving AccountSets.rememberMs().");
    return (days > 0 ? days : 30) * DAY_MS;
  }

  /**
   * The cookie that names the ambient realm's account set.
   *
   * @returns `sts_accounts`, or `sts_accounts_<realm>` outside the default
   */
  static cookieName(): string {
    helpers.log.debug("Entering AccountSets.cookieName().");
    const id = realms.currentId();
    helpers.log.debug("Leaving AccountSets.cookieName().");
    return !id || id === 'default' ? COOKIE : COOKIE + '_' + id;
  }

  /**
   * The Set-Cookie line for a set's cookie value; an empty value clears it.
   *
   * @param value - `<setId>.<handle>`, or '' to clear
   * @returns the header line
   */
  static cookieLine(value: string): string {
    helpers.log.debug("Entering AccountSets.cookieLine().");
    const line = AccountSets.cookieName() + '=' + (value || '') +
      '; Path=/; HttpOnly; SameSite=Lax' +
      (value ? '' : '; Max-Age=0') +
      helpers.cookieDomainAttribute() +
      (config.value('global.https') ? '; Secure' : '');
    helpers.log.debug("Leaving AccountSets.cookieLine().");
    return line;
  }

  /**
   * Appends a set's cookie to a response, beside any cookie already on it.
   *
   * @param res - the response
   * @param value - the cookie value, or '' to clear it
   * @returns whether it was written
   */
  static writeCookie(res: Json, value: string): boolean {
    helpers.log.debug("Entering AccountSets.writeCookie().");
    if (!res || res.headersSent || typeof res.append !== 'function') {
      helpers.log.debug("Leaving AccountSets.writeCookie(). No response.");
      return false;
    }
    res.append('Set-Cookie', AccountSets.cookieLine(value));
    helpers.log.debug("Leaving AccountSets.writeCookie().");
    return true;
  }

  // The digest a handle is kept as.
  private static hashOf(handle: string): string {
    helpers.log.debug("Entering AccountSets.hashOf().");
    helpers.log.debug("Leaving AccountSets.hashOf().");
    return stsCrypto.digest('sha256', String(handle), 'base64url');
  }

  /**
   * The set a request's cookie names, if the cookie carries its current
   * handle.
   *
   * @param cookies - the request's cookies, name → value
   * @returns the row (a copy), or null
   */
  static setOf(cookies: Json): Json {
    helpers.log.debug("Entering AccountSets.setOf().");
    const value = String((cookies || {})[AccountSets.cookieName()] || '');
    const dot = value.indexOf('.');
    if (dot <= 0 || dot === value.length - 1) {
      helpers.log.debug("Leaving AccountSets.setOf(). No cookie.");
      return null;
    }
    const row = sets.get(value.slice(0, dot));
    if (!row || !row.handleHash ||
        !stsCrypto.constantTimeEquals(
          AccountSets.hashOf(value.slice(dot + 1)), row.handleHash)) {
      helpers.log.debug("Leaving AccountSets.setOf(). No set holds that " +
                        "handle.");
      return null;
    }
    helpers.log.debug("Leaving AccountSets.setOf(). " + row.id);
    return AccountSets.copy(row);
  }

  /**
   * A set by its id, with no cookie check: for a session's own set when it
   * ends, which knows the id and has no browser in front of it.
   *
   * @param id - the set's id
   * @returns the row (a copy), or null
   */
  static byId(id: string): Json {
    helpers.log.debug("Entering AccountSets.byId().");
    const row = id ? sets.get(String(id)) : null;
    helpers.log.debug("Leaving AccountSets.byId().");
    return row ? AccountSets.copy(row) : null;
  }

  // A deep enough copy that editing it never edits the store's object.
  private static copy(row: Json): Json {
    helpers.log.debug("Entering AccountSets.copy().");
    helpers.log.debug("Leaving AccountSets.copy().");
    return JSON.parse(JSON.stringify(row));
  }

  /**
   * A new, empty set, not yet saved.
   *
   * @returns the row
   */
  static fresh(): Json {
    helpers.log.debug("Entering AccountSets.fresh().");
    const now = Date.now();
    helpers.log.debug("Leaving AccountSets.fresh().");
    return { id: helpers.randomId(18), handleHash: '', createdAt: now,
             updatedAt: now, lastActiveSid: '', sessions: {},
             remembered: {}, endedSids: {}, forgotten: {} };
  }

  /**
   * Gives a row a fresh handle and answers the cookie value. The caller
   * saves the row and writes the cookie.
   *
   * @param row - the set
   * @returns `<setId>.<handle>`
   */
  static rotate(row: Json): string {
    helpers.log.debug("Entering AccountSets.rotate(). " + row.id);
    const handle = helpers.randomId(32);
    row.handleHash = AccountSets.hashOf(handle);
    row.handleIssuedAt = Date.now();
    helpers.log.debug("Leaving AccountSets.rotate().");
    return row.id + '.' + handle;
  }

  /**
   * Writes a row back to the store.
   *
   * @param row - the set
   */
  static save(row: Json): void {
    helpers.log.debug("Entering AccountSets.save(). " + row.id);
    row.updatedAt = Date.now();
    AccountSets.trim(row);
    sets.set(row.id, AccountSets.copy(row));
    helpers.log.debug("Leaving AccountSets.save().");
  }

  /**
   * Deletes a row (an empty set, at the expiry job).
   *
   * @param id - the set's id
   */
  static remove(id: string): void {
    helpers.log.debug("Entering AccountSets.remove(). " + id);
    sets.delete(String(id));
    helpers.log.debug("Leaving AccountSets.remove().");
  }

  /**
   * The key an account goes by in the picker and the API: its subject, or
   * its name where it has none. Never a sid.
   *
   * @param account - `{ sub, username }`
   * @returns the key
   */
  static keyOf(account: Json): string {
    helpers.log.debug("Entering AccountSets.keyOf().");
    const a = account || {};
    helpers.log.debug("Leaving AccountSets.keyOf().");
    return a.sub ? String(a.sub) : 'name:' + String(a.username || '');
  }

  /**
   * How many places a row holds: its sessions and its remembered accounts.
   *
   * @param row - the set
   * @returns the count
   */
  static size(row: Json): number {
    helpers.log.debug("Entering AccountSets.size().");
    helpers.log.debug("Leaving AccountSets.size().");
    return Object.keys(row.sessions || {}).length +
      Object.keys(row.remembered || {}).length;
  }

  /**
   * Adds a session to a set. A remembered entry for the same account is
   * replaced by it; a set at its cap first drops the account that signed
   * out longest ago, and refuses only when every place is a session.
   *
   * @param row - the set, edited in place
   * @param sid - the session
   * @param account - `{ sub, username, displayName }`
   * @returns `{ ok, dropped }`, or `{ ok: false, full: true }`
   */
  static addSession(row: Json, sid: string, account: Json): Json {
    helpers.log.debug("Entering AccountSets.addSession(). " + sid);
    const key = AccountSets.keyOf(account);
    row.sessions = row.sessions || {};
    row.remembered = row.remembered || {};
    if (row.sessions[sid]) {
      row.lastActiveSid = sid;
      helpers.log.debug("Leaving AccountSets.addSession(). Already there.");
      return { ok: true, dropped: 0 };
    }
    delete row.remembered[key];
    let dropped = 0;
    const cap = AccountSets.maxAccounts();
    while (AccountSets.size(row) >= cap) {
      const oldest = Object.keys(row.remembered).sort(function (a, b) {
        return (Number(row.remembered[a].signedOutAt) || 0) -
               (Number(row.remembered[b].signedOutAt) || 0);
      })[0];
      if (!oldest) {
        helpers.log.debug("Leaving AccountSets.addSession(). Full.");
        return { ok: false, full: true };
      }
      delete row.remembered[oldest];
      dropped++;
    }
    row.sessions[sid] = { sub: String(account.sub || ''),
                          username: String(account.username || ''),
                          displayName: String(account.displayName || ''),
                          addedAt: Date.now() };
    if (row.endedSids) {
      delete row.endedSids[sid];
    }
    if (row.forgotten) {
      delete row.forgotten[key];
    }
    row.lastActiveSid = sid;
    helpers.log.debug("Leaving AccountSets.addSession(). " + dropped +
                      " remembered account(s) dropped.");
    return { ok: true, dropped: dropped };
  }

  /**
   * Whether a set has room for one more session without refusing: a free
   * place, or a remembered account to drop.
   *
   * @param row - the set
   * @param liveCount - how many of its sessions are live
   * @returns true when a sign-in may add one
   */
  static hasRoom(row: Json, liveCount: number): boolean {
    helpers.log.debug("Entering AccountSets.hasRoom().");
    const cap = AccountSets.maxAccounts();
    helpers.log.debug("Leaving AccountSets.hasRoom().");
    return !row || liveCount < cap;
  }

  /**
   * Takes a session out of a set, remembering its account as signed out.
   *
   * @param row - the set, edited in place
   * @param sid - the session
   * @param at - when it ended, epoch ms; now by default
   * @returns the account it remembered, or null when the sid was not there
   */
  static endSession(row: Json, sid: string, at?: number): Json {
    helpers.log.debug("Entering AccountSets.endSession(). " + sid);
    const entry = row && row.sessions ? row.sessions[sid] : null;
    if (!entry) {
      helpers.log.debug("Leaving AccountSets.endSession(). Not in the set.");
      return null;
    }
    delete row.sessions[sid];
    row.endedSids = row.endedSids || {};
    row.endedSids[sid] = Date.now();
    row.remembered = row.remembered || {};
    const key = AccountSets.keyOf(entry);
    // AN ACCOUNT WITH ANOTHER LIVE SESSION HERE IS NOT SIGNED OUT. One
    // session per subject per browser is the rule (a second sign-in
    // re-authenticates the first), but a set merged from two nodes could
    // briefly hold two.
    const stillLive = Object.keys(row.sessions).some(function (other) {
      return AccountSets.keyOf(row.sessions[other]) === key;
    });
    const remembered = { sub: entry.sub, username: entry.username,
                         displayName: entry.displayName,
                         signedOutAt: Number(at) || Date.now() };
    if (!stillLive) {
      row.remembered[key] = remembered;
    }
    if (row.lastActiveSid === sid) {
      row.lastActiveSid = '';
    }
    helpers.log.debug("Leaving AccountSets.endSession().");
    return remembered;
  }

  /**
   * Forgets a remembered account. A live one is not touched.
   *
   * @param row - the set, edited in place
   * @param key - the account's key
   * @returns true when it was forgotten
   */
  static forget(row: Json, key: string): boolean {
    helpers.log.debug("Entering AccountSets.forget().");
    if (!row || !row.remembered || !row.remembered[key]) {
      helpers.log.debug("Leaving AccountSets.forget(). Not remembered.");
      return false;
    }
    delete row.remembered[key];
    row.forgotten = row.forgotten || {};
    row.forgotten[key] = Date.now();
    helpers.log.debug("Leaving AccountSets.forget().");
    return true;
  }

  /**
   * Brings a row up to date: every session `isLive` says has ended moves to
   * remembered, and every remembered account older than
   * `authn.rememberedAccountDays` is dropped.
   *
   * @param row - the set, edited in place
   * @param isLive - sid → whether its session is live
   * @param nowMs - now
   * @returns `{ ended, expired }`, the counts
   */
  static prune(row: Json, isLive: (sid: string) => boolean,
               nowMs?: number): Json {
    helpers.log.debug("Entering AccountSets.prune(). " + row.id);
    const now = Number(nowMs) || Date.now();
    let ended = 0;
    let expired = 0;
    Object.keys(row.sessions || {}).forEach(function (sid) {
      if (!isLive(sid)) {
        AccountSets.endSession(row, sid, now);
        ended++;
      }
    });
    const keep = AccountSets.rememberMs();
    Object.keys(row.remembered || {}).forEach(function (key) {
      if (now - (Number(row.remembered[key].signedOutAt) || 0) >= keep) {
        delete row.remembered[key];
        expired++;
      }
    });
    helpers.log.debug("Leaving AccountSets.prune(). " + ended + " ended, " +
                      expired + " expired.");
    return { ended: ended, expired: expired };
  }

  // Keeps the merge memory bounded: the newest MERGE_MEMORY of each.
  private static trim(row: Json): void {
    helpers.log.debug("Entering AccountSets.trim().");
    ['endedSids', 'forgotten'].forEach(function (field) {
      const table = row[field] || {};
      const keys = Object.keys(table);
      if (keys.length <= MERGE_MEMORY) {
        return;
      }
      keys.sort(function (a, b) {
        return (Number(table[b]) || 0) - (Number(table[a]) || 0);
      }).slice(MERGE_MEMORY).forEach(function (key) {
        delete table[key];
      });
    });
    helpers.log.debug("Leaving AccountSets.trim().");
  }

  // -------------------------------------------------------------------------
  // WHAT TWO NODES' COPIES OF ONE SET BECOME (#46's rule for a row edited in
  // place). Pure, and it converges: merging the answer with either side
  // again gives the answer.
  //
  //   * the handle, `createdAt` and `lastActiveSid` are the copy whose handle
  //     was issued later's (a rotation is a sign-in, which is the newer
  //     state);
  //   * `sessions` is the union, less every sid either copy ended;
  //   * `remembered` is the union, each account's latest sign-out, less an
  //     account either copy forgot after it signed out, and less one that
  //     is live again in the merged sessions;
  //   * `endedSids` and `forgotten` are unions with the latest instant.
  // -------------------------------------------------------------------------
  /**
   * Merges two nodes' copies of one account set.
   *
   * @param mine - this process's copy
   * @param theirs - the stored copy
   * @returns the merged row
   */
  static merge(mine: Json, theirs: Json): Json {
    helpers.log.debug("Entering AccountSets.merge().");
    if (!mine || typeof mine !== 'object') {
      helpers.log.debug("Leaving AccountSets.merge(). Nothing of mine.");
      return theirs;
    }
    if (!theirs || typeof theirs !== 'object') {
      helpers.log.debug("Leaving AccountSets.merge(). Nothing stored.");
      return mine;
    }
    const mineAhead = (Number(mine.handleIssuedAt) || 0) >=
                      (Number(theirs.handleIssuedAt) || 0);
    const base = mineAhead ? mine : theirs;
    const out: Json = Object.assign({}, base);
    const latest = function (field: string): Json {
      const table: Json = {};
      [mine[field] || {}, theirs[field] || {}].forEach(function (one: Json) {
        Object.keys(one).forEach(function (key) {
          table[key] = Math.max(Number(table[key]) || 0,
                                Number(one[key]) || 0);
        });
      });
      return table;
    };
    out.endedSids = latest('endedSids');
    out.forgotten = latest('forgotten');
    out.sessions = {};
    [theirs.sessions || {}, mine.sessions || {}].forEach(function (one: Json) {
      Object.keys(one).forEach(function (sid) {
        if (!out.endedSids[sid]) {
          out.sessions[sid] = one[sid];
        }
      });
    });
    const liveKeys: Json = {};
    Object.keys(out.sessions).forEach(function (sid) {
      liveKeys[AccountSets.keyOf(out.sessions[sid])] = true;
    });
    out.remembered = {};
    [theirs.remembered || {}, mine.remembered || {}].forEach(function (one) {
      Object.keys(one).forEach(function (key) {
        const entry = one[key] || {};
        const have = out.remembered[key];
        if (!have || (Number(entry.signedOutAt) || 0) >
                     (Number(have.signedOutAt) || 0)) {
          out.remembered[key] = entry;
        }
      });
    });
    Object.keys(out.remembered).forEach(function (key) {
      const forgot = Number(out.forgotten[key]) || 0;
      if (liveKeys[key] ||
          (forgot && forgot >= (Number(out.remembered[key].signedOutAt) ||
                                0))) {
        delete out.remembered[key];
      }
    });
    if (out.lastActiveSid && !out.sessions[out.lastActiveSid]) {
      out.lastActiveSid = '';
    }
    out.updatedAt = Math.max(Number(mine.updatedAt) || 0,
                             Number(theirs.updatedAt) || 0);
    helpers.log.debug("Leaving AccountSets.merge().");
    return out;
  }

  // --- selection tickets ----------------------------------------------------

  /**
   * Mints a single-use ticket that resumes one flow as one session.
   *
   * @param setId - the browser's set
   * @param sid - the chosen session
   * @param path - the path (no query) the ticket may be spent on
   * @param pendingId - the pending sign-in it was chosen in, for the record
   * @returns the ticket
   */
  static mintTicket(setId: string, sid: string, path: string,
                    pendingId: string): string {
    helpers.log.debug("Entering AccountSets.mintTicket().");
    const ticket = helpers.randomId(24);
    tickets.set(ticket, { setId: String(setId), sid: String(sid),
                          path: String(path || ''),
                          pendingId: String(pendingId || ''),
                          expires: Date.now() + TICKET_TTL_MS });
    helpers.log.debug("Leaving AccountSets.mintTicket().");
    return ticket;
  }

  /**
   * An address with a ticket added to its query.
   *
   * @param target - the address, a path on this service
   * @param ticket - the ticket
   * @returns the address with `sts_account=` on it
   */
  static withTicket(target: string, ticket: string): string {
    helpers.log.debug("Entering AccountSets.withTicket().");
    helpers.log.debug("Leaving AccountSets.withTicket().");
    return String(target) + (String(target).indexOf('?') === -1 ? '?' : '&') +
      TICKET_PARAM + '=' + encodeURIComponent(ticket);
  }

  /**
   * Spends a ticket: it is deleted whatever it held, and its row is
   * answered only while it has not expired.
   *
   * @param ticket - the ticket
   * @returns `{ setId, sid, path, pendingId }`, or null
   */
  static spendTicket(ticket: string): Json {
    helpers.log.debug("Entering AccountSets.spendTicket().");
    const key = String(ticket || '');
    const row = key ? tickets.get(key) : null;
    if (key) {
      tickets.delete(key);
    }
    if (!row || !(Number(row.expires) > Date.now())) {
      helpers.log.debug("Leaving AccountSets.spendTicket(). None live.");
      return null;
    }
    helpers.log.debug("Leaving AccountSets.spendTicket().");
    return row;
  }

  /**
   * Takes the ticket parameter off a request's address — `url`,
   * `originalUrl` and the parsed `query` — so no protocol module ever sees
   * it, and answers its value.
   *
   * @param req - the request
   * @returns the ticket, or '' where it carried none
   */
  static stripTicket(req: Json): string {
    helpers.log.debug("Entering AccountSets.stripTicket().");
    const found = AccountSets.ticketIn(String((req && req.url) || ''));
    if (!found) {
      helpers.log.debug("Leaving AccountSets.stripTicket(). None.");
      return '';
    }
    req.url = AccountSets.withoutTicket(String(req.url));
    if (typeof req.originalUrl === 'string') {
      req.originalUrl = AccountSets.withoutTicket(req.originalUrl);
    }
    if (req.query && typeof req.query === 'object') {
      delete req.query[TICKET_PARAM];
    }
    helpers.log.debug("Leaving AccountSets.stripTicket().");
    return found;
  }

  // The ticket on an address's query, or ''.
  private static ticketIn(url: string): string {
    helpers.log.debug("Entering AccountSets.ticketIn().");
    const at = url.indexOf('?');
    if (at < 0) {
      helpers.log.debug("Leaving AccountSets.ticketIn(). No query.");
      return '';
    }
    const parts = url.slice(at + 1).split('&');
    for (let i = 0; i < parts.length; i++) {
      if (parts[i].indexOf(TICKET_PARAM + '=') === 0) {
        let value = '';
        try {
          value = decodeURIComponent(parts[i].slice(TICKET_PARAM.length + 1));
        } catch (e) {
          // A value that is not URI-encoded is no ticket this service made.
          helpers.log.debug("Caught in AccountSets.ticketIn(): " +
                            ((e && e.message) || e));
          value = '';
        }
        helpers.log.debug("Leaving AccountSets.ticketIn(). Found.");
        return value || ' ';
      }
    }
    helpers.log.debug("Leaving AccountSets.ticketIn(). None.");
    return '';
  }

  // An address without the ticket parameter, every other byte as it was.
  private static withoutTicket(url: string): string {
    helpers.log.debug("Entering AccountSets.withoutTicket().");
    const at = url.indexOf('?');
    if (at < 0) {
      helpers.log.debug("Leaving AccountSets.withoutTicket(). No query.");
      return url;
    }
    const kept = url.slice(at + 1).split('&').filter(function (part) {
      return part.indexOf(TICKET_PARAM + '=') !== 0;
    });
    helpers.log.debug("Leaving AccountSets.withoutTicket().");
    return url.slice(0, at) + (kept.length ? '?' + kept.join('&') : '');
  }

  // --- the expiry job -------------------------------------------------------

  /**
   * The body of `authn.account-set-expiry` for the ambient realm: every set
   * pruned, and every set left with nothing in it deleted.
   *
   * @param isLive - sid → whether its session is live
   * @returns `{ sets, ended, expired, deleted }`
   */
  static sweep(isLive: (sid: string) => boolean): Json {
    helpers.log.debug("Entering AccountSets.sweep().");
    const now = Date.now();
    const out = { sets: 0, ended: 0, expired: 0, deleted: 0 };
    // Collected first: a save or a delete while the map is walked would
    // change what is being walked.
    const rows: Json[] = [];
    sets.forEach(function (row: Json) {
      if (row && row.id) {
        rows.push(row);
      }
    });
    rows.forEach(function (stored: Json) {
      out.sets++;
      try {
        const row = AccountSets.copy(stored);
        const done = AccountSets.prune(row, isLive, now);
        out.ended += done.ended;
        out.expired += done.expired;
        if (!AccountSets.size(row)) {
          AccountSets.remove(row.id);
          out.deleted++;
        } else if (done.ended || done.expired) {
          AccountSets.save(row);
        }
      } catch (e) {
        // One row that cannot be read costs that row, never the sweep.
        helpers.log.error(errorCodes.tag('STS-AUTHN-0344') + 'authn: the ' +
                          'account-set expiry could not prune a set: ' +
                          ((e && e.message) || e));
      }
    });
    helpers.log.debug("Leaving AccountSets.sweep(). " + JSON.stringify(out));
    return out;
  }
}

export = AccountSets;
