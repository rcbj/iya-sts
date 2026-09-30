// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cells.ts
//
// ---------------------------------------------------------------------------
// WHICH CELL THIS PROCESS IS, AND WHICH OTHER CELLS THERE ARE (#98,
// 2026-09-28).
//
// One logical service can be deployed as several CELLS: each a copy of the
// whole stack in one cloud region, with its own postgres, in exactly one
// legal JURISDICTION. A person is HOMED in one cell and their personal data
// lives there and nowhere else; configuration, keys and the routing index are
// the GLOBAL tier every cell reads (`persistence/CLAUDE.md`, *Tiers*). The
// design and its decisions are issue #98's body; this module is the map.
//
// **A CELL IS NOT A NODE, AND IT IS NEVER PUBLISHED.** Every published name,
// issuer, certificate and document names the SERVICE. A cell id is a routing
// fact: it travels between cells on the inter-cell channel, and inside the
// ciphertext of a sealed locator (`cell_locator.ts`), and nowhere a client
// can read it.
//
// **EMPTY `cells.id` IS SINGLE-CELL MODE** and every question here then has
// the answer that makes the rest of the service behave exactly as it did
// before cells: this process is the only cell, every person is homed here,
// every transfer is local.
//
// A LEAF LIBRARY (rule 3): no route, and it requires `config`, the error-code
// table and a logger and nothing else, because `persistence/persistence.js`
// (require order 4a) asks it which database the tiers live in, long before
// anything that could require it back is loaded.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('./config');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cells' });

// A cell id, as `cells.id` and a peer's `id` must spell it. Short and plain,
// because it is a key in the routing index, a claim scope and part of a node
// certificate's name.
const CELL_ID = /^[a-z0-9]{1,16}$/;
// A jurisdiction code. Lower-case letters, digits and hyphens, because some
// boundaries are sub-national (`ca-qc`) and some are unions (`eu`).
const JURISDICTION = /^[a-z][a-z0-9-]{0,15}$/;

/**
 * One cell of the service: its id, its jurisdiction and, for another cell,
 * the private address of its inter-cell listener.
 */
interface Cell {
  id: string;
  jurisdiction: string;
  url: string;
  // The cell's own console origin (#361), '' when none is configured.
  consoleUrl: string;
  self: boolean;
}

// A console origin: https, a host, an optional port, nothing after it.
const CONSOLE_ORIGIN = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/;

// What the map reads from the rest of the service; a test supplies a stub.
interface CellsDeps {
  value(key: string): unknown;
  log: { debug(message: string): void; warn(message: string): void };
}

/**
 * The cell map: this process's cell, the other cells, and the facts about
 * them every transfer decision starts from.
 */
class Cells {
  // `cells.peers` parsed, and the raw text it was parsed from: the setting is
  // restart-only, so this is parsed once in practice, and re-parsed only if a
  // test changes the value under it.
  private parsedFrom: string | null = null;
  private parsed: Cell[] = [];

  /**
   * Builds a map over the settings reader and a logger.
   *
   * @param deps - `value()` (config.value) and a logger
   */
  constructor(private readonly deps: CellsDeps) {
    deps.log.debug("Entering Cells.constructor().");
    deps.log.debug("Leaving Cells.constructor().");
  }

  /**
   * Returns the dependencies of the module's own map.
   *
   * @returns `config.value` and this module's logger
   */
  static defaultDeps(): CellsDeps {
    log.debug("Entering Cells.defaultDeps().");
    log.debug("Leaving Cells.defaultDeps().");
    return { value: (key: string) => config.value(key), log: log };
  }

  /**
   * This process's cell id, or '' in single-cell mode.
   *
   * @returns `cells.id`, trimmed
   */
  id(): string {
    this.deps.log.debug("Entering Cells.id().");
    const out = String(this.deps.value('cells.id') || '').trim();
    this.deps.log.debug("Leaving Cells.id().");
    return out;
  }

  /**
   * Tells whether this service is deployed as cells at all.
   *
   * @returns true when `cells.id` is set
   */
  isMulti(): boolean {
    this.deps.log.debug("Entering Cells.isMulti().");
    this.deps.log.debug("Leaving Cells.isMulti().");
    return !!this.id();
  }

  /**
   * This cell's jurisdiction, or '' in single-cell mode.
   *
   * @returns `cells.jurisdiction`, trimmed and lower-cased
   */
  jurisdiction(): string {
    this.deps.log.debug("Entering Cells.jurisdiction().");
    const out = String(this.deps.value('cells.jurisdiction') || '')
      .trim().toLowerCase();
    this.deps.log.debug("Leaving Cells.jurisdiction().");
    return out;
  }

  /**
   * The private host name the other cells dial this one at, or '' when it
   * is not set (the channel then names the node's own host).
   *
   * @returns `cells.hostname`, trimmed and lower-cased
   */
  hostname(): string {
    this.deps.log.debug("Entering Cells.hostname().");
    const out = String(this.deps.value('cells.hostname') || '')
      .trim().toLowerCase();
    this.deps.log.debug("Leaving Cells.hostname().");
    return out;
  }

  // The peers, parsed. Tolerant here — a malformed value parses to what it
  // can — because `validate()` is where a malformed value is REFUSED, at
  // startup, and a reader later must not throw inside a request.
  private readPeers(): Cell[] {
    this.deps.log.debug("Entering Cells.readPeers().");
    const raw = String(this.deps.value('cells.peers') || '').trim();
    if (raw === this.parsedFrom) {
      this.deps.log.debug("Leaving Cells.readPeers(). Cached.");
      return this.parsed;
    }
    let list: unknown = [];
    if (raw) {
      try {
        list = JSON.parse(raw);
      } catch (e) {
        this.deps.log.debug("Caught in Cells.readPeers(): " +
                            ((e && e.message) || e));
        list = [];
      }
    }
    const self = this.id();
    this.parsed = (Array.isArray(list) ? list : [])
      .filter((one) => one && typeof one === 'object')
      .map((one) => ({
        id: String(one.id || '').trim(),
        jurisdiction: String(one.jurisdiction || '').trim().toLowerCase(),
        url: String(one.url || '').trim().replace(/\/+$/, ''),
        consoleUrl: String(one.consoleUrl || '').trim().replace(/\/+$/, ''),
        self: false
      }))
      .filter((one) => one.id && one.id !== self);
    this.parsedFrom = raw;
    this.deps.log.debug("Leaving Cells.readPeers(). " + this.parsed.length +
                        " peer(s).");
    return this.parsed;
  }

  /**
   * Every OTHER cell of this service.
   *
   * @returns a copy of the peer list; empty in single-cell mode
   */
  peers(): Cell[] {
    this.deps.log.debug("Entering Cells.peers().");
    const out = this.isMulti() ? this.readPeers().slice() : [];
    this.deps.log.debug("Leaving Cells.peers().");
    return out;
  }

  /**
   * This cell's own console origin (`cells.consoleUrl`, #361), without a
   * trailing slash; '' when none is configured.
   *
   * @returns the origin, or ''
   */
  consoleUrl(): string {
    this.deps.log.debug("Entering Cells.consoleUrl().");
    const out = String(this.deps.value('cells.consoleUrl') || '').trim()
      .replace(/\/+$/, '');
    this.deps.log.debug("Leaving Cells.consoleUrl().");
    return out;
  }

  /**
   * The cell whose console origin a request's Host names — this cell's or
   * another's — or null. The console signs in AT a cell's own address, and
   * a request there may be served here (relayed, or the address is this
   * cell's), so every cell's is recognised.
   *
   * @param host - the request's Host header
   * @returns `{ id, consoleUrl }`, or null
   */
  consoleOfHost(host: string): { id: string; consoleUrl: string } | null {
    this.deps.log.debug("Entering Cells.consoleOfHost().");
    const want = String(host || '').trim().toLowerCase();
    if (!want || !this.isMulti()) {
      this.deps.log.debug("Leaving Cells.consoleOfHost(). None.");
      return null;
    }
    const hit = this.all().filter((one) => {
      if (!one.consoleUrl) {
        return false;
      }
      const at = one.consoleUrl.replace(/^https:\/\//, '').toLowerCase();
      return at === want || at === want.replace(/:443$/, '');
    })[0];
    this.deps.log.debug("Leaving Cells.consoleOfHost(). " +
                        (hit ? hit.id : 'none'));
    return hit ? { id: hit.id, consoleUrl: hit.consoleUrl } : null;
  }

  /**
   * This cell and every other one.
   *
   * @returns this cell first, then its peers; in single-cell mode one cell
   *   whose id is ''
   */
  all(): Cell[] {
    this.deps.log.debug("Entering Cells.all().");
    const self: Cell = { id: this.id(), jurisdiction: this.jurisdiction(),
                         url: '', consoleUrl: this.consoleUrl(),
                         self: true };
    this.deps.log.debug("Leaving Cells.all().");
    return [self].concat(this.peers());
  }

  /**
   * Finds a cell by id, this one included.
   *
   * @param cellId - the id
   * @returns the cell, or null when the service has no such cell
   */
  get(cellId: string): Cell | null {
    this.deps.log.debug("Entering Cells.get().");
    const wanted = String(cellId || '');
    const found = this.all().filter((one) => one.id === wanted)[0] || null;
    this.deps.log.debug("Leaving Cells.get(). " + (found ? 'found' : 'none'));
    return found;
  }

  /**
   * Tells whether a cell id is this process's cell. In single-cell mode the
   * empty id is, and so is every other: there is only one place to be.
   *
   * @param cellId - the id, '' meaning "not recorded"
   * @returns true when it names this cell
   */
  isHere(cellId: string): boolean {
    this.deps.log.debug("Entering Cells.isHere().");
    const out = !this.isMulti() || !cellId || String(cellId) === this.id();
    this.deps.log.debug("Leaving Cells.isHere(). " + out);
    return out;
  }

  /**
   * The jurisdiction a cell sits in.
   *
   * @param cellId - the id
   * @returns its jurisdiction, or '' for a cell the service does not have
   */
  jurisdictionOf(cellId: string): string {
    this.deps.log.debug("Entering Cells.jurisdictionOf().");
    const found = this.get(cellId);
    this.deps.log.debug("Leaving Cells.jurisdictionOf().");
    return found ? found.jurisdiction : '';
  }

  /**
   * The cells in one jurisdiction, this one first when it is among them.
   *
   * @param jurisdiction - the code
   * @returns the cells there, possibly none
   */
  cellsIn(jurisdiction: string): Cell[] {
    this.deps.log.debug("Entering Cells.cellsIn().");
    const wanted = String(jurisdiction || '').toLowerCase();
    const out = this.all().filter((one) => one.jurisdiction === wanted);
    this.deps.log.debug("Leaving Cells.cellsIn(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // WHERE A NEW PERSON IS HOMED (#98 D1). The ambient realm's
  // `cells.homeCell`, or this cell when that is empty; and a cell named by
  // the creation itself wins. A named cell must exist and be in a
  // jurisdiction the realm allows (`cells.jurisdictions`), or the creation is
  // refused — a person silently homed somewhere else than asked is the one
  // outcome a residency rule cannot have.
  // -------------------------------------------------------------------------
  /**
   * Decides the home cell of a person about to be created.
   *
   * @param asked - a cell the creation named, or ''
   * @returns `{ cell }`, or `{ error }` saying why the named or default cell
   *   is refused
   */
  homeFor(asked: string): { cell: string } | { error: string } {
    this.deps.log.debug("Entering Cells.homeFor().");
    if (!this.isMulti()) {
      this.deps.log.debug("Leaving Cells.homeFor(). Single-cell.");
      return { cell: '' };
    }
    const named = String(asked || '').trim() ||
      String(this.deps.value('cells.homeCell') || '').trim() || this.id();
    const cell = this.get(named);
    if (!cell) {
      this.deps.log.debug("Leaving Cells.homeFor(). No such cell.");
      return { error: 'this service has no cell "' + named + '"' };
    }
    const allowed = this.allowedJurisdictions();
    if (allowed.length && allowed.indexOf(cell.jurisdiction) < 0) {
      this.deps.log.debug("Leaving Cells.homeFor(). Jurisdiction refused.");
      return { error: 'cell "' + named + '" is in jurisdiction "' +
                      cell.jurisdiction + '", and this realm may place ' +
                      'people only in ' + allowed.join(', ') };
    }
    this.deps.log.debug("Leaving Cells.homeFor(). " + named);
    return { cell: named };
  }

  /**
   * The jurisdictions the ambient realm may home people in.
   *
   * @returns the list; empty means any jurisdiction the service has a cell in
   */
  allowedJurisdictions(): string[] {
    this.deps.log.debug("Entering Cells.allowedJurisdictions().");
    const raw = this.deps.value('cells.jurisdictions');
    const list = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map((one) => String(one).trim().toLowerCase())
      .filter((one) => one);
    this.deps.log.debug("Leaving Cells.allowedJurisdictions().");
    return list;
  }

  // -------------------------------------------------------------------------
  // THE REALM'S STATED LOOSENINGS OF THE STRICT DEFAULT (#98 D4), as facts.
  // Whether a transfer is permitted is DECIDED by the issuance policy
  // (`cell_transfer.ts` asks it); this only reads what the realm wrote, so
  // the policy's built-in rule and a person's own policy see the same list.
  // `<home>><serving>`, `*` on either side meaning any.
  // -------------------------------------------------------------------------
  /**
   * Tells whether the ambient realm LISTS a transfer between two
   * jurisdictions. Staying in one jurisdiction is always listed.
   *
   * @param home - the subject's home jurisdiction
   * @param serving - the serving cell's jurisdiction
   * @returns true when `cells.permittedTransfers` names it
   */
  transferListed(home: string, serving: string): boolean {
    this.deps.log.debug("Entering Cells.transferListed().");
    const from = String(home || '').toLowerCase();
    const to = String(serving || '').toLowerCase();
    if (from === to) {
      this.deps.log.debug("Leaving Cells.transferListed(). Same.");
      return true;
    }
    const raw = this.deps.value('cells.permittedTransfers');
    const listed = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map((one) => String(one).trim().toLowerCase())
      .filter((one) => one.indexOf('>') > 0)
      .some((one) => {
        const [a, b] = one.split('>');
        return (a === '*' || a === from) && (b === '*' || b === to);
      });
    this.deps.log.debug("Leaving Cells.transferListed(). " + listed);
    return listed;
  }

  // -------------------------------------------------------------------------
  // THE STARTUP CHECK. Everything a cell deployment needs that is a fact
  // about the settings alone — the id, the jurisdiction, the peer list — and
  // is refused with one code, because each is the same mistake: a cell
  // configured as something other than what it is.
  // -------------------------------------------------------------------------
  /**
   * Refuses inconsistent cell settings. Single-cell mode passes.
   *
   * @returns nothing
   * @throws an Error (STS-CELL-0001) naming what is wrong
   */
  validate(): void {
    this.deps.log.debug("Entering Cells.validate().");
    if (!this.isMulti()) {
      this.deps.log.debug("Leaving Cells.validate(). Single-cell.");
      return;
    }
    const problems: string[] = [];
    const self = this.id();
    if (!CELL_ID.test(self)) {
      problems.push('cells.id "' + self + '" is not [a-z0-9]{1,16}');
    }
    if (!JURISDICTION.test(this.jurisdiction())) {
      problems.push('cells.jurisdiction "' + this.jurisdiction() + '" is ' +
                    'empty or not a jurisdiction code');
    }
    const ownConsole = this.consoleUrl();
    if (ownConsole && !CONSOLE_ORIGIN.test(ownConsole)) {
      problems.push('cells.consoleUrl "' + ownConsole + '" is not ' +
                    'https://host[:port]');
    }
    const raw = String(this.deps.value('cells.peers') || '').trim();
    let list: unknown = [];
    if (raw) {
      try {
        list = JSON.parse(raw);
      } catch (e) {
        this.deps.log.debug("Caught in Cells.validate(): " +
                            ((e && e.message) || e));
        problems.push('cells.peers is not JSON (' + ((e && e.message) || e) +
                      ')');
      }
    }
    if (!Array.isArray(list)) {
      problems.push('cells.peers is not a JSON array');
      list = [];
    }
    const seen: Record<string, boolean> = {};
    (list as unknown[]).forEach((one: any, i: number) => {
      const id = String((one && one.id) || '');
      if (!CELL_ID.test(id)) {
        problems.push('cells.peers[' + i + '].id "' + id + '" is not ' +
                      '[a-z0-9]{1,16}');
      }
      if (id === self) {
        problems.push('cells.peers[' + i + '] is this cell ("' + id + '")');
      }
      if (seen[id]) {
        problems.push('cells.peers names "' + id + '" twice');
      }
      seen[id] = true;
      if (!JURISDICTION.test(String((one && one.jurisdiction) || ''))) {
        problems.push('cells.peers[' + i + '].jurisdiction is missing or ' +
                      'not a jurisdiction code');
      }
      const consoleAt = String((one && one.consoleUrl) || '');
      if (consoleAt && !CONSOLE_ORIGIN.test(consoleAt.replace(/\/+$/, ''))) {
        problems.push('cells.peers[' + i + '].consoleUrl "' + consoleAt +
                      '" is not https://host[:port]');
      }
      const url = String((one && one.url) || '');
      if (!/^https:\/\/[^/\s]+(:\d+)?\/?$/.test(url)) {
        problems.push('cells.peers[' + i + '].url "' + url + '" is not ' +
                      'https://host[:port] — the inter-cell channel is ' +
                      'mutual TLS and nothing else');
      }
    });
    if (problems.length) {
      this.deps.log.debug("Leaving Cells.validate(). Refused.");
      throw new Error(errorCodes.tag('STS-CELL-0001') + 'the cell settings ' +
                      'are inconsistent: ' + problems.join('; ') + '.');
    }
    this.deps.log.debug("Leaving Cells.validate().");
  }

  /**
   * What `/admin/cells` and `GET /admin-api/cells` report about the map.
   *
   * @returns this cell, its jurisdiction, and every cell with its
   *   jurisdiction and console origin (never a channel address)
   */
  describe(): { multi: boolean; id: string; jurisdiction: string;
                cells: { id: string; jurisdiction: string; self: boolean;
                         consoleUrl: string }[] } {
    this.deps.log.debug("Entering Cells.describe().");
    const out = {
      multi: this.isMulti(),
      id: this.id(),
      jurisdiction: this.jurisdiction(),
      // The console origin is the one address this page draws (#361): the
      // administrators' door into each cell. The channel's `url` never is.
      cells: this.all().map((one) => ({ id: one.id,
                                        jurisdiction: one.jurisdiction,
                                        self: one.self,
                                        consoleUrl: one.consoleUrl }))
    };
    this.deps.log.debug("Leaving Cells.describe().");
    return out;
  }
}

// The module's own map, over the real settings. A LIBRARY with no load-time
// effect beyond this, so there is nothing for the composition root to
// install: `persistence.js` reads it at 4a, far above that root.
const cells = new Cells(Cells.defaultDeps());

/**
 * Which cell this process is and which other cells the service has (#98).
 *
 * A leaf library: no route. Single-cell mode — `cells.id` empty — answers
 * every question as the one cell there is.
 * @namespace
 */
export = {
  Cells: Cells,
  CELL_ID: CELL_ID,
  JURISDICTION: JURISDICTION,
  id: (): string => cells.id(),
  isMulti: (): boolean => cells.isMulti(),
  consoleUrl: (): string => cells.consoleUrl(),
  consoleOfHost: (host: string): { id: string; consoleUrl: string } | null =>
    cells.consoleOfHost(host),
  jurisdiction: (): string => cells.jurisdiction(),
  hostname: (): string => cells.hostname(),
  peers: (): Cell[] => cells.peers(),
  all: (): Cell[] => cells.all(),
  get: (cellId: string): Cell | null => cells.get(cellId),
  isHere: (cellId: string): boolean => cells.isHere(cellId),
  jurisdictionOf: (cellId: string): string => cells.jurisdictionOf(cellId),
  cellsIn: (jurisdiction: string): Cell[] => cells.cellsIn(jurisdiction),
  homeFor: (asked: string) => cells.homeFor(asked),
  allowedJurisdictions: (): string[] => cells.allowedJurisdictions(),
  transferListed: (home: string, serving: string): boolean =>
    cells.transferListed(home, serving),
  validate: (): void => cells.validate(),
  describe: () => cells.describe()
};
