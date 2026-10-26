// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_window.ts
//
// ---------------------------------------------------------------------------
// THE DIRECTORY AS A WINDOW ONTO THE STORE (#349 phase 4, 2026-09-29).
//
// `ldap_server.js` holds its entries in `const entries = realms.map()`: a Map
// per realm, every entry of every realm in the memory of every process. With
// `ldap.workerDirectory=postgres-lru` a request or surface worker holds
// instead THIS — the same Map-shaped object, answering the ambient realm, so
// not one of that file's ~150 readers and writers changes — built from three
// parts (rcbj's decisions on #349):
//
//   * **RESIDENT**: every entry that is NOT under a windowed container, held
//     whole as before — the containers, groups, applications, federations,
//     policies, roles, SPIFFE, oidfed. Their cardinality is the operator's,
//     and the change log keeps them current exactly as it always has.
//   * **WINDOWED**: the entries strictly under `ou=users` and `ou=devices` of
//     each realm, held in a bounded LRU (`common/bounded_lru.ts`,
//     `ldap.workerCacheEntries`). A key not held is asked of the store
//     through the synchronous bridge (`common/sync_query.ts`); an absent key
//     is held too, as a negative answer, so a create's "is anybody there"
//     costs one round trip rather than one per ask.
//   * **SCANS**: a walk (`forEach`, `values`, `keys`, iteration) visits the
//     resident entries and then pages through each windowed container in key
//     order, a bridge question per page. Correct, and O(n) in the store's
//     rows; #349's phase 5 turns the hot walks into indexed questions.
//
// **A WRITE STAYS LOCAL (rcbj).** An entry this process changed is PINNED in
// the window until the flush has written it; the flush finds what changed by
// comparing each candidate entry's JSON with the JSON it had when it was
// loaded or last written — its BASE, which is also the base of the store's
// three-way merge (`persistence/directory_merge.js`). A digest could say
// "changed" and could not be that base, so the JSON is kept, for held
// entries only: bounded by the window.
//
// **WHAT A CANDIDATE IS.** The service edits entries IN PLACE and then calls
// `touchDirectory()`, which names the DN in eighteen places and nothing in
// fifty-eight. So the candidates for a flush are: every entry set or deleted
// through the store; every entry HANDED OUT since the last flush (held
// strongly until it, which is how an in-place edit made in the same tick is
// seen); every entry the journal names; and, when a write named nothing,
// every held entry and every EVICTED entry some caller still holds (a
// WeakRef — an object nobody holds cannot be edited). An entry evicted,
// collected and never edited is simply gone, and read again from the store
// the next time.
//
// **WHAT ANOTHER PROCESS WROTE** reaches `forget()`: a held, clean entry is
// dropped and read again when next asked for. A changed one is written first
// (the store merges it), then dropped. `persistence.js` does the waiting.
//
// **`size`** is the resident count plus a windowed count read from the store
// when first asked, moved by this process's own creates and deletes. Another
// process's creates do not move it until `exactCount()` reads the store
// again: it is what the directory's caches compare as a change detector
// beside `directoryVersion`, and `ldap.maxEntries` is the store's count
// (`exactCount()`), not this — since #618 a counter row read, never a
// `count(*)`.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import BoundedLru = require('../common/bounded_lru');

const log = bunyan.createLogger({ name: 'sts-directory-window' });

// An entry as the directory holds it.
type Entry = Record<string, any>;

// What the window holds for one key: the entry (null for "the store has
// none"), and the JSON the store last held for it (null for none).
interface Slot {
  entry: Entry | null;
  base: string | null;
}

// The bridge: a synchronous question to the store — and, where the store
// offers one, the same question asked asynchronously on the driver's read
// pool, for a caller that can wait (`holdersAsync()`, #615).
interface Bridge {
  query(name: string, args: unknown[]): unknown;
  queryAsync?(name: string, args: unknown[]): Promise<unknown>;
}

// A row as `persistence/directory_queries.js` answers.
interface Row {
  realm: string;
  key: string;
  entry: Entry;
  // Set by `rdnPage`: the row's `rdn_value`, the page's order.
  rdn?: string;
}

// One change the flush writes.
interface Change {
  realm: string;
  key: string;
  entry?: Entry;
  json?: string;
  base: string | null;
}

// What the constructor takes.
interface WindowDeps {
  // `realms.js`: the ambient realm, and the purge of a removed one.
  currentId: () => string;
  onRemove: (fn: (id: string) => void) => void;
  // The normalised keys of a realm's windowed containers.
  windowedContainers: (realmId: string) => string[];
  // Makes a row read from the store into a stored entry (the directory's
  // own construction: `ldap_server.js`'s `storedFromRow()`).
  fromRow: (realmId: string, row: Entry) => Entry;
  // The bound, in entries.
  maxEntries: () => number;
  // Told when an entry was handed out or written, so a flush is scheduled;
  // answers whether one was (false before the store is open).
  onTouched: () => boolean | void;
  // The cache registry, for `/admin/caches`.
  registry?: any;
}

// Rows per page of a scan.
const PAGE = 500;
// How many of a long list's pages are asked at once (2026-10-21).
const PAGES_AT_ONCE = 4;

// The composite key the window holds a realm's entry under.
function slotKey(realmId: string, key: string): string {
  return realmId + '\n' + key;
}

// THE PAGING OF `keysUnder()` AND `keysUnderAsync()` (#616), once for both:
// the question for the next page, each page's rows taken as this process
// holds them (a key deleted here left out, the DN as held), and — below the
// cap — the entries created here and not yet written added at the end.
class KeysUnder {
  private readonly out: Array<{ key: string; dn: string }> = [];
  private readonly seen = new Set<string>();
  private after = '';
  private more = false;
  private done = false;
  private want = 0;

  constructor(private readonly window: DirectoryWindow,
              private readonly realmId: string,
              private readonly base: string,
              private readonly limit: number) {
    log.debug("Entering KeysUnder.constructor().");
    log.debug("Leaving KeysUnder.constructor().");
  }

  // Whether another page is to be asked for.
  wants(): boolean {
    log.debug("Entering KeysUnder.wants().");
    log.debug("Leaving KeysUnder.wants().");
    return !this.done && !this.more;
  }

  // The next page's arguments.
  question(): unknown[] {
    log.debug("Entering KeysUnder.question().");
    this.want = Math.min(1000, this.limit + 1 - this.out.length);
    log.debug("Leaving KeysUnder.question().");
    return [this.realmId, this.base, this.after, this.want];
  }

  // One page's answer.
  take(answer: unknown, counter?: { pages: number; rows: number }): void {
    log.debug("Entering KeysUnder.take().");
    const rows = (answer as Array<{ key: string; dn: string }>) || [];
    if (counter) {
      counter.pages += 1;
      counter.rows += rows.length;
    }
    for (const row of rows) {
      this.seen.add(row.key);
      const slot = this.window.heldSlotOf(this.realmId, row.key);
      if (slot && !slot.entry) {
        continue;
      }
      if (this.out.length === this.limit) {
        this.more = true;
        log.debug("Leaving KeysUnder.take(). Past the cap.");
        return;
      }
      this.out.push({ key: row.key, dn: slot && slot.entry
        ? String(slot.entry.dn) : row.dn });
    }
    if (rows.length < this.want) {
      this.done = true;
      log.debug("Leaving KeysUnder.take(). The last page.");
      return;
    }
    this.after = rows[rows.length - 1].key;
    log.debug("Leaving KeysUnder.take().");
  }

  // The answer.
  finish(): { rows: Array<{ key: string; dn: string }>; more: boolean } {
    log.debug("Entering KeysUnder.finish().");
    if (!this.more) {
      for (const pair of this.window.createdHereUnder(this.realmId,
                                                      this.base,
                                                      this.seen)) {
        if (this.out.length === this.limit) {
          this.more = true;
          break;
        }
        this.out.push({ key: pair[0], dn: String(pair[1].dn) });
      }
    }
    log.debug("Leaving KeysUnder.finish().");
    return { rows: this.out, more: this.more };
  }
}

/**
 * The directory as a bounded window onto the store, in the shape of
 * `realms.map()` (#349).
 */
class DirectoryWindow {
  private bridge: Bridge | null = null;
  private readonly resident: Map<string, Map<string, Entry>> = new Map();
  private readonly lru: BoundedLru<string, Slot>;
  // Changed here and not yet written, by composite key. Each is pinned.
  private readonly dirty: Set<string> = new Set();
  // Sent by the flush in flight: composite key -> the JSON sent.
  private readonly inFlight: Map<string, string> = new Map();
  // Handed out since the last flush: composite key -> the slot.
  private readonly touched: Map<string, Slot> = new Map();
  // Evicted and possibly still held by a caller.
  private readonly ghosts: Map<string, { ref: WeakRef<Entry>;
                                         base: string | null }> = new Map();
  private readonly finalizer: FinalizationRegistry<string>;
  // EVERY REALM WITH A KEY IN THE LRU OR THE GHOSTS (#612): what lets
  // `collect(named)` look a journal's keys UP rather than scan for them. A
  // journal names keys without a realm, so a key is probed once per realm
  // here. A superset is harmless (a probe that misses), a subset would lose
  // a write — so every insertion into the LRU goes through `put()`, which
  // adds the realm first, and a ghost is only ever made from an LRU key.
  // Bounded by the realms that exist; `dropRealm()` removes one.
  private readonly realmsHeld: Set<string> = new Set();
  // The windowed count per realm, from the store, and this process's net.
  private readonly counts: Map<string, number> = new Map();
  private readonly countedAt: Map<string, number> = new Map();
  // A container's count (#610), keyed `realm\ncontainer`: the store's
  // reading, when it was taken, and this process's net since — the realm
  // count's arrangement above, for one container. See `recentCountUnder()`.
  private readonly containerCounts: Map<string, { n: number; at: number }> =
    new Map();
  // Keys another process changed while this one was busy with them: dropped
  // once this process's own flush has let them go (see `markStale()`).
  private readonly stale: Set<string> = new Set();
  // THE KEYS A `warmAsync()` IS ASKING THE STORE ABOUT (#621), and whether
  // anything has happened to each since it asked: composite key -> how many
  // asks are out for it and whether it MOVED (written, adopted, forgotten,
  // committed or released here). A slot is put from the store's answer only
  // for a key that did not move while the question was out, so an answer
  // older than this process's own state is never what the window holds.
  // Empty except while a warm is waiting, so the check on the hot paths is
  // one `size` test.
  private readonly watched: Map<string, { asks: number; moved: boolean }> =
    new Map();
  private touchScheduled = false;

  /**
   * Builds the window. It asks nothing of the store until `attach()`.
   *
   * @param deps - the realm hooks, the containers, the bound and the
   *   registry
   */
  constructor(private readonly deps: WindowDeps) {
    log.debug("Entering DirectoryWindow.constructor().");
    this.lru = new BoundedLru<string, Slot>({
      name: 'ldap.worker-directory',
      title: 'Directory window (request workers)',
      description: 'The people and devices a request or surface worker ' +
        'holds, with ldap.workerDirectory=postgres-lru (#349): the entries ' +
        'it read most recently, and those it changed and has not yet ' +
        'written (pinned). Anything else is read from the store when asked ' +
        'for.',
      owner: 'ldap/directory_window.ts',
      scope: 'process',
      settings: ['ldap.workerDirectory', 'ldap.workerCacheEntries'],
      registry: deps.registry || null,
      maxEntries: deps.maxEntries,
      rowOf: function (key: string) {
        const cut = key.indexOf('\n');
        return { realm: key.slice(0, cut), key: key.slice(cut + 1) };
      },
      onEvict: (key: string, value: unknown) => {
        const slot = value as Slot;
        if (slot && slot.entry) {
          this.ghosts.set(key, { ref: new WeakRef(slot.entry),
                                 base: slot.base });
          this.finalizer.register(slot.entry, key, slot.entry);
        }
      }
    });
    this.finalizer = new FinalizationRegistry((key: string) => {
      const ghost = this.ghosts.get(key);
      if (ghost && !ghost.ref.deref()) {
        this.ghosts.delete(key);
      }
    });
    deps.onRemove((id: string) => {
      this.dropRealm(String(id));
    });
    log.debug("Leaving DirectoryWindow.constructor().");
  }

  /**
   * Gives the window its bridge, once the store is open, and drops every
   * CLEAN answer given before it — an absence recorded before the store
   * could be asked is not an absence.
   *
   * @param bridge - the synchronous question to the store
   */
  attach(bridge: Bridge): void {
    log.debug("Entering DirectoryWindow.attach().");
    this.bridge = bridge;
    this.touchScheduled = false;
    this.movedEverywhere();
    this.lru.keys().forEach((key) => {
      if (!this.dirty.has(key)) {
        this.lru.delete(key);
      }
    });
    this.counts.clear();
    this.containerCounts.clear();
    log.debug("Leaving DirectoryWindow.attach().");
  }

  /**
   * Whether the store can be asked yet.
   *
   * @returns true once `attach()` has run
   */
  attached(): boolean {
    log.debug("Entering DirectoryWindow.attached().");
    log.debug("Leaving DirectoryWindow.attached().");
    return !!this.bridge;
  }

  /**
   * Whether a key of a realm is windowed: strictly under one of its
   * windowed containers.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns true when windowed
   */
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  isWindowed(realmId: string, key: string): boolean {
    const k = String(key);
    return this.deps.windowedContainers(realmId).some(function (c) {
      return k.length > c.length + 1 && k.endsWith(',' + c);
    });
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private residentOf(realmId: string): Map<string, Entry> {
    let held = this.resident.get(realmId);
    if (!held) {
      held = new Map();
      this.resident.set(realmId, held);
    }
    return held;
  }

  // Puts a slot in the LRU, the one door every insertion goes through so
  // that `realmsHeld` covers every key there (#612).
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private put(ck: string, slot: Slot): void {
    this.realmsHeld.add(ck.slice(0, ck.indexOf('\n')));
    this.lru.set(ck, slot);
  }

  // A ghost, if its entry is still held by somebody; a ghost whose entry
  // has been collected is dropped HERE, when met, rather than left to the
  // FinalizationRegistry, whose callback runs when the engine pleases —
  // under a bulk load, far behind the evictions (#612).
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private liveGhost(ck: string): Slot | null {
    const ghost = this.ghosts.get(ck);
    if (!ghost) {
      return null;
    }
    const alive = ghost.ref.deref();
    if (!alive) {
      this.ghosts.delete(ck);
      return null;
    }
    return { entry: alive, base: ghost.base };
  }

  // Hands an entry out: remembered until the next flush, which is scheduled.
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private touch(ck: string, slot: Slot): void {
    this.touched.set(ck, slot);
    this.askForFlush();
  }

  // A flush is asked for once until it has run; a request nobody could take
  // (the store not open yet) is asked again next time.
  private askForFlush(): void {
    if (!this.touchScheduled) {
      this.touchScheduled = this.deps.onTouched() !== false;
    }
  }

  // THE ONE READ OF A WINDOWED KEY. In order: the window, what was handed
  // out, an evicted entry a caller still holds, the store. Hot path: no
  // Entering/Leaving pair.
  private slotFor(realmId: string, key: string): Slot | null {
    const ck = slotKey(realmId, key);
    const held = this.lru.get(ck);
    if (held) {
      return held;
    }
    const handed = this.touched.get(ck);
    if (handed) {
      this.put(ck, handed);
      return handed;
    }
    const back = this.liveGhost(ck);
    if (back) {
      this.ghosts.delete(ck);
      this.put(ck, back);
      return back;
    }
    if (!this.bridge) {
      // The store is not open yet (the seed, at require time): nothing can
      // be known about it, and nothing is recorded.
      return null;
    }
    const rows = this.bridge.query('byKeys', [realmId, [key]]) as Row[];
    const row = (rows || [])[0];
    const slot: Slot = row
      ? this.slotFromRow(realmId, row)
      : { entry: null, base: null };
    this.put(ck, slot);
    return slot;
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private slotFromRow(realmId: string, row: Row): Slot {
    const entry = this.deps.fromRow(realmId, row.entry);
    return { entry: entry, base: JSON.stringify(entry) };
  }

  // ---- the Map, for a named realm ---------------------------------------

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * The entry at a key, or undefined.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns the entry
   */
  getIn(realmId: string, key: string): Entry | undefined {
    if (!this.isWindowed(realmId, key)) {
      return this.residentOf(realmId).get(key);
    }
    const slot = this.slotFor(realmId, key);
    if (!slot || !slot.entry) {
      return undefined;
    }
    this.touch(slotKey(realmId, key), slot);
    return slot.entry;
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * Whether a key holds an entry.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns true when it does
   */
  hasIn(realmId: string, key: string): boolean {
    return this.getIn(realmId, key) !== undefined;
  }

  // A write: the slot keeps its base (what the store holds), the entry is
  // the new one, and the key is pinned until the flush writes it.
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private write(realmId: string, key: string, entry: Entry | null): boolean {
    const ck = slotKey(realmId, key);
    this.moved(ck);
    const before = this.slotFor(realmId, key);
    const existed = !!(before && before.entry);
    const slot: Slot = { entry: entry,
                         base: before ? before.base : null };
    if (!this.dirty.has(ck)) {
      this.dirty.add(ck);
      this.lru.pin(ck);
    }
    this.put(ck, slot);
    this.ghosts.delete(ck);
    if (entry) {
      this.touch(ck, slot);
    } else {
      this.touched.delete(ck);
      this.askForFlush();
    }
    const delta = (entry && !existed ? 1 : 0) - (!entry && existed ? 1 : 0);
    if (this.counts.has(realmId)) {
      const n = this.counts.get(realmId) as number;
      this.counts.set(realmId, n + delta);
    }
    // A container count held (#610) moves with this process's own create or
    // delete under it, so an operator who just made somebody sees them
    // counted; a handful of containers at most, so the loop is short.
    if (delta !== 0 && this.containerCounts.size) {
      this.containerCounts.forEach(function (held, cck) {
        const cut = cck.indexOf('\n');
        const base = cck.slice(cut + 1);
        if (cck.slice(0, cut) === realmId && key !== base &&
            DirectoryWindow.within(key, base)) {
          held.n += delta;
        }
      });
    }
    return existed;
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * Puts an entry at a key: a write, pinned until the flush writes it.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @param entry - the entry
   */
  setIn(realmId: string, key: string, entry: Entry): void {
    if (!this.isWindowed(realmId, key)) {
      this.residentOf(realmId).set(key, entry);
      return;
    }
    this.write(realmId, key, entry);
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * Removes a key: a write, pinned until the flush writes it.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns true when it held an entry
   */
  deleteIn(realmId: string, key: string): boolean {
    if (!this.isWindowed(realmId, key)) {
      return this.residentOf(realmId).delete(key);
    }
    return this.write(realmId, key, null);
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * Puts an entry the STORE holds: not a write. For a restore and for a row
   * another process wrote.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @param entry - the entry
   */
  adopt(realmId: string, key: string, entry: Entry): void {
    if (!this.isWindowed(realmId, key)) {
      this.residentOf(realmId).set(key, entry);
      return;
    }
    const ck = slotKey(realmId, key);
    this.moved(ck);
    if (this.dirty.has(ck)) {
      // A change made here stands; the flush writes it against this base.
      const held = this.lru.peek(ck) as Slot;
      held.base = JSON.stringify(entry);
      return;
    }
    this.put(ck, { entry: entry, base: JSON.stringify(entry) });
    this.ghosts.delete(ck);
    this.touched.delete(ck);
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * Forgets a key: a row another process wrote or removed, read again when
   * next asked for. A resident key is removed.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns true when something was held
   */
  forget(realmId: string, key: string): boolean {
    if (!this.isWindowed(realmId, key)) {
      return this.residentOf(realmId).delete(key);
    }
    const ck = slotKey(realmId, key);
    this.moved(ck);
    const held = this.lru.peek(ck);
    this.lru.delete(ck);
    this.ghosts.delete(ck);
    this.touched.delete(ck);
    this.stale.delete(ck);
    if (this.dirty.delete(ck)) {
      this.lru.unpin(ck);
    }
    // The count is NOT read again here: another process's create or delete
    // moves it only at `capCount()`'s next reading (see the header on size).
    return !!(held && held.entry);
  }

  /**
   * Another process changed a key this one is busy with: once this
   * process's flush has let it go — written and merged by the store, or
   * found unchanged — it is dropped, and read again when next asked for.
   * Without this a key merely HANDED OUT when the change arrived would keep
   * the older copy until it was evicted.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   */
  markStale(realmId: string, key: string): void {
    log.debug("Entering DirectoryWindow.markStale().");
    this.stale.add(slotKey(realmId, key));
    this.askForFlush();
    log.debug("Leaving DirectoryWindow.markStale().");
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * Whether a key has a change here not yet written, or one in flight, or
   * was handed out since the last flush — the states in which a row from
   * another process must wait for the flush rather than replace it.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns true when the flush must go first
   */
  busy(realmId: string, key: string): boolean {
    const ck = slotKey(realmId, key);
    return this.dirty.has(ck) || this.inFlight.has(ck) ||
      this.touched.has(ck);
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * The entry held at a key, without asking the store and without handing
   * it out: `persistence.js`'s `entryAt()` for a windowed key.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns the entry, or null
   */
  peekIn(realmId: string, key: string): Entry | null {
    if (!this.isWindowed(realmId, key)) {
      return this.residentOf(realmId).get(key) || null;
    }
    const slot = this.lru.peek(slotKey(realmId, key));
    return slot && slot.entry ? slot.entry : null;
  }

  // Hot path (every write of the directory, through `touchDirectory()`): no
  // Entering/Leaving pair, the exception the code style allows, stated as it
  // requires.
  /**
   * What this process holds at a key, WITHOUT asking the store (#618): the
   * group index's question "is the entry just written a group", which must
   * never cost a round trip. A resident key is always known (the Map is
   * the whole truth); a windowed key is known when the window, what was
   * handed out since the last flush, or an evicted entry a caller still
   * holds has it — an absence held counts — and is NOT known otherwise.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns `{ known, entry }`; `entry` null for none
   */
  heldIn(realmId: string, key: string): { known: boolean;
                                          entry: Entry | null } {
    if (!this.isWindowed(realmId, key)) {
      return { known: true,
               entry: this.residentOf(realmId).get(key) || null };
    }
    const ck = slotKey(realmId, key);
    const slot = this.lru.peek(ck) || this.touched.get(ck) ||
      this.liveGhost(ck);
    if (!slot) {
      return { known: false, entry: null };
    }
    return { known: true, entry: slot.entry };
  }

  /**
   * Whether anything is under a key.
   *
   * @param realmId - the realm id
   * @param key - the normalised DN
   * @returns true when something is
   */
  hasChildIn(realmId: string, key: string): boolean {
    log.debug("Entering DirectoryWindow.hasChildIn().");
    const suffix = ',' + key;
    for (const other of this.residentOf(realmId).keys()) {
      if (other !== key && other.endsWith(suffix)) {
        log.debug("Leaving DirectoryWindow.hasChildIn(). Resident.");
        return true;
      }
    }
    let local = false;
    this.dirty.forEach((ck) => {
      const cut = ck.indexOf('\n');
      if (ck.slice(0, cut) === realmId && ck.slice(cut + 1).endsWith(suffix)) {
        const slot = this.lru.peek(ck);
        local = local || !!(slot && slot.entry);
      }
    });
    if (local) {
      log.debug("Leaving DirectoryWindow.hasChildIn(). Written here.");
      return true;
    }
    const reaches = this.deps.windowedContainers(realmId).some(function (c) {
      return c === key || c.endsWith(suffix) || key.endsWith(',' + c);
    });
    if (!reaches || !this.bridge) {
      log.debug("Leaving DirectoryWindow.hasChildIn(). No.");
      return false;
    }
    // Asked of the store; a child deleted here and not yet written is still
    // there, which errs towards "has children" — the refusal side.
    const answer = this.bridge.query('hasChild', [realmId, key]) === true;
    log.debug("Leaving DirectoryWindow.hasChildIn().");
    return answer;
  }

  /**
   * The resident entries of a realm, keyed: what `persistence.js`'s write
   * shadow covers. A windowed entry is never in that shadow — the window
   * holds its own base.
   *
   * @param realmId - the realm id
   * @returns `[{ key, entry }]`
   */
  residentRows(realmId: string): Array<{ key: string; entry: Entry }> {
    log.debug("Entering DirectoryWindow.residentRows().");
    const out: Array<{ key: string; entry: Entry }> = [];
    this.residentOf(realmId).forEach(function (entry, key) {
      out.push({ key: key, entry: entry });
    });
    log.debug("Leaving DirectoryWindow.residentRows().");
    return out;
  }

  // Whether `key` is `base` or under it (a DN key; `base` '' is everything).
  private static within(key: string, base: string): boolean {
    return !base || key === base || key.endsWith(',' + base);
  }

  // THE WALK: resident first, then each windowed container that meets
  // `base`, a page at a time. A key held here is answered from here (a local
  // change wins); a key deleted here is skipped; a key created here and not
  // yet written comes after its container's pages. LAZY, so a walk that stops
  // early (a size-limited search) pages no further. `readOnly` hands nothing
  // out: a walk whose caller edits no entry holds no reference to what it
  // visited, which is what keeps a scan of every person from being held in
  // memory until the next flush.
  /**
   * Walks a realm's entries at or under a base, lazily.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN, or '' for the whole realm
   * @param readOnly - true when the caller edits nothing it is handed
   * @returns an iterator of `[key, entry]`
   */
  *walk(realmId: string, base: string, readOnly?: boolean):
      Generator<[string, Entry]> {
    log.debug("Entering DirectoryWindow.walk(). " + realmId + ' ' + base);
    const resident = Array.from(this.residentOf(realmId).entries());
    for (const pair of resident) {
      if (DirectoryWindow.within(pair[0], base)) {
        yield pair;
      }
    }
    for (const container of this.deps.windowedContainers(realmId)) {
      // The part of this container the base reaches: all of it when the
      // base is at or above it, the base's own subtree when the base is in
      // it, and none of it otherwise.
      let from = '';
      let self = false;
      if (DirectoryWindow.within(container, base)) {
        from = container;
      } else if (base.endsWith(',' + container)) {
        from = base;
        self = true;
      } else {
        continue;
      }
      const seen = new Set<string>();
      let after = '';
      while (this.bridge) {
        const rows = this.bridge.query('page', [realmId, from, after, PAGE,
                                                { self: self }]) as Row[];
        if (!rows || !rows.length) {
          break;
        }
        for (const row of rows) {
          seen.add(row.key);
          const ck = slotKey(realmId, row.key);
          let slot = this.lru.peek(ck) || this.touched.get(ck) || null;
          if (!slot) {
            slot = this.liveGhost(ck) || this.slotFromRow(realmId, row);
          }
          if (slot.entry) {
            if (!readOnly) {
              this.touch(ck, slot);
            }
            yield [row.key, slot.entry];
          }
        }
        after = rows[rows.length - 1].key;
        if (rows.length < PAGE) {
          break;
        }
      }
      const local: Array<[string, Entry]> = [];
      this.dirty.forEach((ck) => {
        const cut = ck.indexOf('\n');
        const key = ck.slice(cut + 1);
        if (ck.slice(0, cut) !== realmId || seen.has(key) ||
            !(key.length > container.length + 1 &&
              key.endsWith(',' + container)) ||
            !DirectoryWindow.within(key, base)) {
          return;
        }
        const slot = this.lru.peek(ck);
        if (slot && slot.entry) {
          local.push([key, slot.entry]);
        }
      });
      for (const pair of local) {
        yield pair;
      }
    }
    log.debug("Leaving DirectoryWindow.walk().");
  }

  // The whole realm, handed out: what `forEach` and iteration of the Map do.
  private scan(realmId: string, fn: (entry: Entry, key: string) => void):
      void {
    log.debug("Entering DirectoryWindow.scan(). " + realmId);
    for (const pair of this.walk(realmId, '')) {
      fn(pair[1], pair[0]);
    }
    log.debug("Leaving DirectoryWindow.scan().");
  }

  /**
   * Calls `fn` for each RESIDENT entry of a realm: for a walk whose filter
   * can only match an entry outside the windowed containers.
   *
   * @param realmId - the realm id
   * @param fn - called with each entry and its key
   */
  eachResident(realmId: string, fn: (entry: Entry, key: string) => void):
      void {
    log.debug("Entering DirectoryWindow.eachResident().");
    Array.from(this.residentOf(realmId).entries()).forEach(function (pair) {
      fn(pair[1], pair[0]);
    });
    log.debug("Leaving DirectoryWindow.eachResident().");
  }

  // THE STORE'S ANSWER TO A QUESTION ABOUT WINDOWED ENTRIES, MADE TRUE FOR
  // THIS PROCESS: each row is read back through the window (so a change made
  // here wins, and one deleted here is gone), `predicate` is asked of what
  // this process holds rather than of the row, and entries changed here and
  // not yet written that match are added — the store cannot know them.
  /**
   * The windowed entries of a realm matching an indexed question, as this
   * process holds them.
   *
   * @param realmId - the realm id
   * @param name - one of `persistence/directory_queries.js`'s queries
   * @param args - its arguments
   * @param predicate - the service's own rule, asked of each candidate
   * @param info - optional; `rows` is set to how many rows the store
   *   answered, before any was dropped, so a caller that asked with a limit
   *   can tell a capped answer (#320); `readOnly` takes each row as the
   *   store answered it where this process holds nothing newer, as
   *   `holdersAsync()` does, rather than reading it again by key
   * @returns `[{ key, entry }]`, in key order, local additions last
   */
  findWindowed(realmId: string, name: string, args: unknown[],
               predicate: (entry: Entry, key: string) => boolean,
               info?: { rows?: number; readOnly?: boolean }):
      Array<{ key: string; entry: Entry }> {
    log.debug("Entering DirectoryWindow.findWindowed(). " + name);
    const out: Array<{ key: string; entry: Entry }> = [];
    const seen = new Set<string>();
    const rows = this.bridge
      ? (this.bridge.query(name, args) as Row[]) || [] : [];
    if (info) {
      info.rows = rows.length;
    }
    rows.forEach((row) => {
      if (seen.has(row.key) || !this.isWindowed(realmId, row.key)) {
        return;
      }
      seen.add(row.key);
      // READ ONLY (a batch of subjects resolved for a page, the audit
      // log's among them): `getIn()` is a second synchronous round trip per
      // row the window does not hold — `holdersAsync()`'s reason — and the
      // row IS the store's answer, so it is taken unless this process holds
      // something newer, and nothing is handed out or put in the LRU.
      const ck = slotKey(realmId, row.key);
      const entry = info && info.readOnly
        ? (this.lru.peek(ck) || this.touched.get(ck) ||
           this.liveGhost(ck) || this.slotFromRow(realmId, row)).entry
        : this.getIn(realmId, row.key);
      if (entry && predicate(entry, row.key)) {
        out.push({ key: row.key, entry: entry });
      }
    });
    this.dirty.forEach((ck) => {
      const cut = ck.indexOf('\n');
      const key = ck.slice(cut + 1);
      if (ck.slice(0, cut) !== realmId || seen.has(key)) {
        return;
      }
      const slot = this.lru.peek(ck);
      if (slot && slot.entry && predicate(slot.entry, key)) {
        seen.add(key);
        out.push({ key: key, entry: slot.entry });
      }
    });
    log.debug("Leaving DirectoryWindow.findWindowed(). " + out.length + '.');
    return out;
  }

  /**
   * The windowed entries under a base that hold an attribute, as this
   * process holds them: the store's holders a page at a time, each read back
   * through the window and asked `predicate`, and changes made here added.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN (a windowed container, usually)
   * @param attribute - the attribute name, lower-cased as stored
   * @param predicate - the service's own rule, asked of each candidate
   * @returns `[{ key, entry }]`
   */
  holders(realmId: string, base: string, attribute: string,
          predicate: (entry: Entry, key: string) => boolean):
      Array<{ key: string; entry: Entry }> {
    log.debug("Entering DirectoryWindow.holders(). " + attribute);
    const out: Array<{ key: string; entry: Entry }> = [];
    const seen = new Set<string>();
    let after = '';
    while (this.bridge) {
      const rows = this.bridge.query('withAttribute',
        [realmId, base, attribute, after, PAGE]) as Row[];
      if (!rows || !rows.length) {
        break;
      }
      rows.forEach((row) => {
        seen.add(row.key);
        const entry = this.getIn(realmId, row.key);
        if (entry && predicate(entry, row.key)) {
          out.push({ key: row.key, entry: entry });
        }
      });
      after = rows[rows.length - 1].key;
      if (rows.length < PAGE) {
        break;
      }
    }
    this.dirty.forEach((ck) => {
      const cut = ck.indexOf('\n');
      const key = ck.slice(cut + 1);
      if (ck.slice(0, cut) !== realmId || seen.has(key) ||
          !DirectoryWindow.within(key, base) || key === base) {
        return;
      }
      const slot = this.lru.peek(ck);
      if (slot && slot.entry &&
          (slot.entry.attributes || {})[attribute] &&
          predicate(slot.entry, key)) {
        out.push({ key: key, entry: slot.entry });
      }
    });
    log.debug("Leaving DirectoryWindow.holders(). " + out.length + '.');
    return out;
  }

  // ONE PAGE OF A CONTAINER AFTER A KEY, FOR A JOB THAT WALKS IT A PAGE PER
  // RUN (#615's audit: `attribute-sources.refresh`). `walk()` starts at the
  // container's first key every time; a job whose cursor survives between
  // runs asks for the page after it — the store's `page()` question, ONE
  // statement, in key order — and each row is taken as the store answered
  // it unless this process holds a newer one, handing nothing out.
  // An entry this process created and has not written yet is not in the
  // store's page and is not here: the next cycle meets it.
  /**
   * The windowed entries strictly under a base whose keys follow `afterKey`,
   * at most `limit` of them, in key order.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN
   * @param afterKey - the last key of the previous page, or ''
   * @param limit - the page size
   * @returns `{ rows: [{ key, entry }], more }` — `more` when the store
   *   answered a full page
   */
  pageAfter(realmId: string, base: string, afterKey: string, limit: number):
      { rows: Array<{ key: string; entry: Entry }>; more: boolean } {
    log.debug("Entering DirectoryWindow.pageAfter().");
    const out: Array<{ key: string; entry: Entry }> = [];
    const asked = this.bridge
      ? (this.bridge.query('page', [realmId, base, String(afterKey || ''),
                                    limit, { self: false }]) as Row[]) || []
      : [];
    asked.forEach((row) => {
      if (row.key === base || !this.isWindowed(realmId, row.key)) {
        return;
      }
      const ck = slotKey(realmId, row.key);
      const slot = this.lru.peek(ck) || this.touched.get(ck) ||
        this.liveGhost(ck) || this.slotFromRow(realmId, row);
      if (slot.entry) {
        out.push({ key: row.key, entry: slot.entry });
      }
    });
    log.debug("Leaving DirectoryWindow.pageAfter(). " + out.length + '.');
    return { rows: out, more: asked.length >= limit };
  }

  // `holders()` FOR A BACKGROUND JOB (#615, 2026-10-13). The scheduler's
  // Android attestation recheck read every person through the synchronous
  // bridge, one entry at a time, on the serving front process — 191,000
  // round trips with every listener stopped. What it needs is the handful
  // of people the store says hold one attribute, and it can wait for them.
  //
  // Three differences from `holders()`, and each is the point:
  //
  //   * **EACH PAGE IS ASKED ASYNCHRONOUSLY** where the bridge offers
  //     `queryAsync()` — the driver's read pool, the statement and the
  //     keyed/opened values exactly the synchronous door's — and the event
  //     loop is given back between pages (`setImmediate`) either way. A
  //     bridge without it (a test's) is asked synchronously, one statement a
  //     page, which is the same cost `holders()` has.
  //   * **A ROW IS TAKEN AS THE STORE ANSWERED IT** when the window holds
  //     nothing newer, as `walk()` takes it, rather than read again by key:
  //     `holders()`' `getIn()` is a second synchronous round trip per row
  //     the window does not hold, which is O(holders) bridge questions on
  //     top of the page.
  //   * **NOTHING IS HANDED OUT OR PUT IN THE LRU** (`walk()`'s `readOnly`):
  //     the caller reads, and one that then writes reaches the entry through
  //     the directory's own lookup, which holds it then.
  //
  // What this process changed and has not written is added from the window,
  // as `holders()` adds it.
  /**
   * The windowed entries under a base that hold an attribute, as this
   * process holds them, asked a page at a time without blocking the event
   * loop between pages.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN (a windowed container, usually)
   * @param attribute - the attribute name, lower-cased as stored
   * @param predicate - the service's own rule, asked of each candidate
   * @returns a promise of `[{ key, entry }]`
   */
  async holdersAsync(realmId: string, base: string, attribute: string,
                     predicate: (entry: Entry, key: string) => boolean):
      Promise<Array<{ key: string; entry: Entry }>> {
    log.debug("Entering DirectoryWindow.holdersAsync(). " + attribute);
    const out: Array<{ key: string; entry: Entry }> = [];
    const seen = new Set<string>();
    let after = '';
    let pages = 0;
    while (this.bridge) {
      const bridge = this.bridge;
      const args = [realmId, base, attribute, after, PAGE];
      const rows = (typeof bridge.queryAsync === 'function'
        ? await bridge.queryAsync('withAttribute', args)
        : bridge.query('withAttribute', args)) as Row[];
      pages += 1;
      if (!rows || !rows.length) {
        break;
      }
      rows.forEach((row) => {
        if (seen.has(row.key) || !this.isWindowed(realmId, row.key)) {
          return;
        }
        seen.add(row.key);
        const ck = slotKey(realmId, row.key);
        const slot = this.lru.peek(ck) || this.touched.get(ck) ||
          this.liveGhost(ck) || this.slotFromRow(realmId, row);
        if (slot.entry && predicate(slot.entry, row.key)) {
          out.push({ key: row.key, entry: slot.entry });
        }
      });
      after = rows[rows.length - 1].key;
      if (rows.length < PAGE) {
        break;
      }
      await new Promise<void>(function (resolve) {
        setImmediate(resolve);
      });
    }
    this.dirty.forEach((ck) => {
      const cut = ck.indexOf('\n');
      const key = ck.slice(cut + 1);
      if (ck.slice(0, cut) !== realmId || seen.has(key) ||
          !DirectoryWindow.within(key, base) || key === base) {
        return;
      }
      const slot = this.lru.peek(ck);
      if (slot && slot.entry &&
          (slot.entry.attributes || {})[attribute] &&
          predicate(slot.entry, key)) {
        out.push({ key: key, entry: slot.entry });
      }
    });
    log.debug("Leaving DirectoryWindow.holdersAsync(). " + out.length +
              ' in ' + pages + ' page(s).');
    return out;
  }

  // ONE PAGE OF HOLDERS, AND HOW MANY (2026-10-22, #820). `holdersAsync()`
  // answers every holder, which is right for a job that must see them all
  // and wrong for a console page: Monitoring → Consent read about 470,000
  // people to draw fifty. These two answer the page's questions —
  // `directory_queries.js`'s `countWithAttribute` and `withAttributeAt` —
  // asynchronously on the read pool, each row taken as the store answered
  // it unless this process holds a newer copy (`holdersAsync()`'s rule),
  // nothing handed out. What this process changed and has not written is
  // NOT added: a page of the store is the store's page, and the count is
  // the store's count.
  /**
   * How many windowed entries under a base the store says hold an
   * attribute.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN
   * @param attribute - the attribute name, lower-cased as stored
   * @returns a promise of the count (0 before `attach()`)
   */
  async countHoldersAsync(realmId: string, base: string,
                          attribute: string): Promise<number> {
    log.debug("Entering DirectoryWindow.countHoldersAsync(). " + attribute);
    const n = Number(await this.askAsync('countWithAttribute',
      [realmId, base, attribute])) || 0;
    log.debug("Leaving DirectoryWindow.countHoldersAsync(). " + n + '.');
    return n;
  }

  /**
   * One page of the windowed entries under a base that hold an attribute,
   * in key order at an offset.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN
   * @param attribute - the attribute name, lower-cased as stored
   * @param offset - holders to skip
   * @param limit - the page size
   * @param predicate - the service's own rule, asked of each row
   * @returns a promise of `{ rows: [{ key, entry }], read }`, `read` the
   *   rows the store answered (for a caller paging on)
   */
  async holdersPageAsync(realmId: string, base: string, attribute: string,
                         offset: number, limit: number,
                         predicate: (entry: Entry, key: string) => boolean):
      Promise<{ rows: Array<{ key: string; entry: Entry }>; read: number }> {
    log.debug("Entering DirectoryWindow.holdersPageAsync(). " + attribute);
    const out: Array<{ key: string; entry: Entry }> = [];
    const rows = (await this.askAsync('withAttributeAt',
      [realmId, base, attribute, offset, limit]) || []) as Row[];
    rows.forEach((row) => {
      if (!row || !this.isWindowed(realmId, row.key)) {
        return;
      }
      const ck = slotKey(realmId, row.key);
      const slot = this.lru.peek(ck) || this.touched.get(ck) ||
        this.liveGhost(ck) || this.slotFromRow(realmId, row);
      if (slot.entry && predicate(slot.entry, row.key)) {
        out.push({ key: row.key, entry: slot.entry });
      }
    });
    log.debug("Leaving DirectoryWindow.holdersPageAsync(). " + out.length +
              ' of ' + rows.length + '.');
    return { rows: out, read: rows.length };
  }

  // ONE PAGE AFTER A CURSOR, FOR THE PASSKEY REPORT (#942, 2026-10-23).
  // `holdersPageAsync()` pages at an OFFSET, which is the console's page
  // number and costs the database the rows it skips; the passkey report's
  // lists are FILTERED (post-quantum only, one algorithm, one model) and its
  // recount reads every holder once, so both carry a KEY CURSOR instead —
  // the last key of the page before, as `holdersAsync()` does between its
  // own pages. One question, asked asynchronously on the read pool:
  // `withAttribute` for the holders of an attribute (the asked names'
  // index), or `page` for every entry under the base (the list of people
  // holding NO passkey, which no index can name). Each row is taken as the
  // store answered it unless this process holds a newer copy
  // (`heldOrRow()`), nothing handed out or put in the LRU; what this
  // process changed and has not written is NOT added — a page of the store
  // is the store's page, `holdersPageAsync()`'s rule.
  /**
   * One page of the windowed entries under a base, in key order after a
   * cursor: those holding an attribute, or every one.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN (a windowed container)
   * @param attribute - the attribute held, lower-cased as stored; '' for
   *   every entry under the base
   * @param after - the last key of the page before, or ''
   * @param limit - the page size (at most `PAGE`)
   * @param predicate - the service's own rule, asked of each row
   * @returns a promise of `{ rows: [{ key, entry }], last, read }`: `last`
   *   the last key the store answered (the next page's cursor), `read` how
   *   many rows it answered
   */
  async rowsAfterAsync(realmId: string, base: string, attribute: string,
                       after: string, limit: number,
                       predicate: (entry: Entry, key: string) => boolean):
      Promise<{ rows: Array<{ key: string; entry: Entry }>; last: string;
                read: number }> {
    log.debug("Entering DirectoryWindow.rowsAfterAsync(). " +
              (attribute || '(every entry)'));
    const size = Math.max(1, Math.min(PAGE, Math.floor(Number(limit) || 1)));
    const rows = (attribute
      ? await this.askAsync('withAttribute',
                            [realmId, base, attribute, after || '', size])
      : await this.askAsync('page', [realmId, base, after || '', size,
                                     { self: false }])) as Row[] || [];
    const out: Array<{ key: string; entry: Entry }> = [];
    rows.forEach((row) => {
      if (!row || row.key === base || !this.isWindowed(realmId, row.key)) {
        return;
      }
      const entry = this.heldOrRow(realmId, row);
      if (entry && predicate(entry, row.key)) {
        out.push({ key: row.key, entry: entry });
      }
    });
    const last = rows.length ? String(rows[rows.length - 1].key) : '';
    log.debug("Leaving DirectoryWindow.rowsAfterAsync(). " + out.length +
              ' of ' + rows.length + '.');
    return { rows: out, last: last, read: rows.length };
  }

  // ---------------------------------------------------------------------
  // THE STORE ASKED WITHOUT HOLDING THE EVENT LOOP (#616, 2026-10-14).
  //
  // `walk()` and the request paths built on it — `/admin-api/ldap/directory`,
  // an LDAP search the index could not narrow, `/admin-api/users`' first
  // names — paged every person out of the store through the synchronous
  // bridge on a request worker's event loop: 38–45 s for one row of the
  // directory page at 200,000 people, every request dispatched to that
  // worker waiting behind it. rcbj's direction on #616: fewer whole scans,
  // and what must read many rows reads them ASYNCHRONOUSLY. These are
  // `holdersAsync()`'s arrangement for the rest: the driver's read pool
  // through the bridge's `queryAsync()` (a bridge without it — a test's — is
  // asked synchronously, one statement a page), the event loop given back
  // between pages, each row taken as the store answered it unless this
  // process holds a newer one, nothing handed out or put in the LRU.
  // ---------------------------------------------------------------------
  /**
   * Asks the store one of `directory_queries.js`'s questions, on the
   * driver's read pool where the bridge offers it.
   *
   * @param name - the query's name
   * @param args - its arguments
   * @returns a promise of the answer (null before `attach()`)
   */
  async askAsync(name: string, args: unknown[]): Promise<unknown> {
    log.debug("Entering DirectoryWindow.askAsync(). " + name);
    const bridge = this.bridge;
    if (!bridge) {
      log.debug("Leaving DirectoryWindow.askAsync(). No store yet.");
      return null;
    }
    const answer = typeof bridge.queryAsync === 'function'
      ? await bridge.queryAsync(name, args)
      : bridge.query(name, args);
    log.debug("Leaving DirectoryWindow.askAsync().");
    return answer;
  }

  // `fn` over every item with at most `limit` running at once; resolves when
  // all are done, rejects with the first failure once the running ones have
  // finished. A store question each, overlapped and still bounded.
  private static async inParallel<T>(items: T[], limit: number,
                                     fn: (item: T) => Promise<void>):
      Promise<void> {
    log.debug("Entering DirectoryWindow.inParallel(). " + items.length);
    let next = 0;
    let failure: unknown = null;
    const runner = async function (): Promise<void> {
      while (next < items.length && !failure) {
        const item = items[next];
        next += 1;
        try {
          await fn(item);
        } catch (e) {
          log.debug("Caught in DirectoryWindow.inParallel(): " +
                    ((e && (e as Error).message) || e));
          failure = failure || e;
        }
      }
    };
    const runners: Promise<void>[] = [];
    for (let i = 0; i < Math.max(1, Math.min(limit, items.length)); i++) {
      runners.push(runner());
    }
    await Promise.all(runners);
    log.debug("Leaving DirectoryWindow.inParallel().");
    if (failure) {
      throw failure;
    }
  }

  // The event loop given back: what runs between two pages.
  private static yieldToLoop(): Promise<void> {
    log.debug("Entering DirectoryWindow.yieldToLoop().");
    log.debug("Leaving DirectoryWindow.yieldToLoop().");
    return new Promise<void>(function (resolve) {
      setImmediate(resolve);
    });
  }

  // A row the store answered, as this process holds it: what it holds when
  // it holds the key (a local change wins; null for a delete made here), the
  // row otherwise. Nothing is handed out or put in the LRU.
  // Hot path (once per row paged): no Entering/Leaving pair, the exception
  // the code style allows, stated as it requires.
  private heldOrRow(realmId: string, row: Row): Entry | null {
    const ck = slotKey(realmId, row.key);
    const slot = this.lru.peek(ck) || this.touched.get(ck) ||
      this.liveGhost(ck) || this.slotFromRow(realmId, row);
    return slot.entry;
  }

  // The entries created here under `container` and at or under `base` that
  // the store has not yet answered with (`seen`), as `walk()` adds them.
  private localUnder(realmId: string, container: string, base: string,
                     seen: Set<string>): Array<[string, Entry]> {
    log.debug("Entering DirectoryWindow.localUnder().");
    const local: Array<[string, Entry]> = [];
    this.dirty.forEach((ck) => {
      const cut = ck.indexOf('\n');
      const key = ck.slice(cut + 1);
      if (ck.slice(0, cut) !== realmId || seen.has(key) ||
          !(key.length > container.length + 1 &&
            key.endsWith(',' + container)) ||
          !DirectoryWindow.within(key, base)) {
        return;
      }
      const slot = this.lru.peek(ck);
      if (slot && slot.entry) {
        local.push([key, slot.entry]);
      }
    });
    log.debug("Leaving DirectoryWindow.localUnder().");
    return local;
  }

  /**
   * `walk()`, read-only, with every page asked asynchronously and the event
   * loop given back between pages: a realm's entries at or under a base,
   * lazily, so a consumer that stops (a size or time limit) pages no
   * further.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN, or '' for the whole realm
   * @param counter - optional; `pages` and `rows` are added to as the store
   *   is asked, for a caller (or a test) that reports what it read
   * @returns an async iterator of `[key, entry]`
   */
  async *walkAsync(realmId: string, base: string,
                   counter?: { pages: number; rows: number }):
      AsyncGenerator<[string, Entry]> {
    log.debug("Entering DirectoryWindow.walkAsync(). " + realmId + ' ' +
              base);
    const resident = Array.from(this.residentOf(realmId).entries());
    let visited = 0;
    for (const pair of resident) {
      if (DirectoryWindow.within(pair[0], base)) {
        yield pair;
      }
      visited += 1;
      if (visited % PAGE === 0) {
        await DirectoryWindow.yieldToLoop();
      }
    }
    for (const container of this.deps.windowedContainers(realmId)) {
      // `walk()`'s three cases: all of the container, the base's own
      // subtree inside it, or none of it.
      let from = '';
      let self = false;
      if (DirectoryWindow.within(container, base)) {
        from = container;
      } else if (base.endsWith(',' + container)) {
        from = base;
        self = true;
      } else {
        continue;
      }
      const seen = new Set<string>();
      let after = '';
      while (this.bridge) {
        const rows = await this.askAsync('page', [realmId, from, after, PAGE,
                                                  { self: self }]) as Row[];
        if (counter) {
          counter.pages += 1;
          counter.rows += rows ? rows.length : 0;
        }
        if (!rows || !rows.length) {
          break;
        }
        for (const row of rows) {
          seen.add(row.key);
          const entry = this.heldOrRow(realmId, row);
          if (entry) {
            yield [row.key, entry];
          }
        }
        after = rows[rows.length - 1].key;
        if (rows.length < PAGE) {
          break;
        }
        await DirectoryWindow.yieldToLoop();
      }
      for (const pair of this.localUnder(realmId, container, base, seen)) {
        yield pair;
      }
    }
    log.debug("Leaving DirectoryWindow.walkAsync().");
  }

  /**
   * The windowed entries strictly under a base holding any of some object
   * classes (`classesUnder`, the GIN index over `class_keys`), asked once
   * and asynchronously, as this process holds them: `findWindowed()`'s
   * answer for a caller that can wait — an LDAP search for groups.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN (a windowed container)
   * @param classes - the object classes, lower-cased
   * @param predicate - the service's own rule, asked of each candidate
   * @returns a promise of `[{ key, entry }]`, local additions last
   */
  async classesUnderAsync(realmId: string, base: string, classes: string[],
                          predicate: (entry: Entry, key: string) => boolean):
      Promise<Array<{ key: string; entry: Entry }>> {
    log.debug("Entering DirectoryWindow.classesUnderAsync().");
    const out: Array<{ key: string; entry: Entry }> = [];
    const seen = new Set<string>();
    const rows = (await this.askAsync('classesUnder',
                                      [realmId, base, classes]) as Row[]) ||
      [];
    rows.forEach((row) => {
      if (seen.has(row.key) || !this.isWindowed(realmId, row.key)) {
        return;
      }
      seen.add(row.key);
      const entry = this.heldOrRow(realmId, row);
      if (entry && predicate(entry, row.key)) {
        out.push({ key: row.key, entry: entry });
      }
    });
    this.dirty.forEach((ck) => {
      const cut = ck.indexOf('\n');
      const key = ck.slice(cut + 1);
      if (ck.slice(0, cut) !== realmId || seen.has(key) ||
          !DirectoryWindow.within(key, base) || key === base) {
        return;
      }
      const slot = this.lru.peek(ck);
      if (slot && slot.entry && predicate(slot.entry, key)) {
        out.push({ key: key, entry: slot.entry });
      }
    });
    log.debug("Leaving DirectoryWindow.classesUnderAsync(). " + out.length +
              '.');
    return out;
  }

  /**
   * The first keys strictly under a base, with their DNs and nothing else,
   * asked asynchronously a page at a time (`keysUnder`: no attribute is read
   * or opened) until `limit` + 1 are found — as this process holds them: a
   * key deleted here is left out, and below the cap the entries created
   * here and not yet written are added.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN (a windowed container)
   * @param limit - how many at most
   * @param counter - optional; `pages` and `rows` are added to
   * @returns a promise of `{ rows: [{ key, dn }], more }`, `more` when
   *   there were more than `limit`
   */
  async keysUnderAsync(realmId: string, base: string, limit: number,
                       counter?: { pages: number; rows: number }):
      Promise<{ rows: Array<{ key: string; dn: string }>; more: boolean }> {
    log.debug("Entering DirectoryWindow.keysUnderAsync(). " + limit);
    const keys = new KeysUnder(this, realmId, base, limit);
    while (keys.wants()) {
      const rows = await this.askAsync('keysUnder', keys.question());
      keys.take(rows, counter);
      if (keys.wants()) {
        await DirectoryWindow.yieldToLoop();
      }
    }
    const answer = keys.finish();
    log.debug("Leaving DirectoryWindow.keysUnderAsync(). " +
              answer.rows.length + (answer.more ? ', and more.' : '.'));
    return answer;
  }

  /**
   * `keysUnderAsync()`, asked synchronously: for a caller that cannot wait.
   * At most `limit` + 1 keys and no attribute, so a bounded handful of
   * statements (one per thousand keys), never a walk.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN (a windowed container)
   * @param limit - how many at most
   * @returns `{ rows: [{ key, dn }], more }`
   */
  keysUnder(realmId: string, base: string, limit: number):
      { rows: Array<{ key: string; dn: string }>; more: boolean } {
    log.debug("Entering DirectoryWindow.keysUnder(). " + limit);
    const keys = new KeysUnder(this, realmId, base, limit);
    while (keys.wants() && this.bridge) {
      keys.take(this.bridge.query('keysUnder', keys.question()));
    }
    const answer = keys.finish();
    log.debug("Leaving DirectoryWindow.keysUnder(). " + answer.rows.length +
              (answer.more ? ', and more.' : '.'));
    return answer;
  }

  // ---------------------------------------------------------------------
  // MANY KEYS, AND ONE INDEXED QUESTION, ASKED WITHOUT HOLDING THE EVENT
  // LOOP (#621, 2026-10-14).
  //
  // `GET /admin-api/users` handed up to `credentials.factorScanLimit`
  // (5,000) names to the credential census, and the census found each with
  // `locateEntry()`: one SYNCHRONOUS `byKeys` round trip per person the
  // window did not hold, and one `byName` for each that was not at
  // `uid=<name>`. On 8081 at 382,000 people that froze a request worker for
  // 10 s every time the page was asked for. These are the two halves of
  // `locateEntry()`'s resolution of a name — the key, then the index —
  // asked the way #616's questions are: through the bridge's `queryAsync()`,
  // the event loop given back between pages, each row taken as the store
  // answered it unless this process holds a newer one (`heldOrRow()`), and
  // NOTHING handed out or put in the LRU.
  // ---------------------------------------------------------------------
  /**
   * The entries at many keys, as this process holds them: a key held here
   * (in the window, handed out, or evicted and still held by a caller) is
   * answered from what is held — an absence or a delete made here included
   * — and the rest are asked of the store with `byKeys`, a page at a time,
   * asynchronously.
   *
   * @param realmId - the realm id
   * @param keys - normalised DNs; a resident key is answered from memory
   * @param counter - optional; `pages` and `rows` are added to
   * @returns a promise of a Map from each key to its entry, or to null
   */
  async entriesAtAsync(realmId: string, keys: string[],
                       counter?: { pages: number; rows: number }):
      Promise<Map<string, Entry | null>> {
    log.debug("Entering DirectoryWindow.entriesAtAsync(). " + keys.length);
    const out = new Map<string, Entry | null>();
    const ask: string[] = [];
    // A SET BESIDE THE LIST (2026-10-21): `ask.indexOf()` for every key made
    // this quadratic, and the Users page's census hands it every register
    // name — on 8081, 67,000 of them held a request worker's event loop for
    // twelve seconds before a single question went to the store.
    const asking = new Set<string>();
    keys.forEach((key) => {
      if (out.has(key) || asking.has(key)) {
        return;
      }
      if (!this.isWindowed(realmId, key)) {
        out.set(key, this.residentOf(realmId).get(key) || null);
        return;
      }
      const held = this.heldSlot(realmId, key);
      if (held) {
        out.set(key, held.entry);
      } else {
        ask.push(key);
        asking.add(key);
      }
    });
    // A FEW PAGES AT A TIME (2026-10-21), not one after another: the Users
    // page's census asked 311 of them in turn on 8081, 4 s of waiting on the
    // store. Each page asks its own keys and fills only them.
    const pages: string[][] = [];
    for (let from = 0; from < ask.length && this.bridge; from += PAGE) {
      pages.push(ask.slice(from, from + PAGE));
    }
    await DirectoryWindow.inParallel(pages, PAGES_AT_ONCE, async (page) => {
      await DirectoryWindow.yieldToLoop();
      const rows = (await this.askAsync('byKeys', [realmId, page]) as Row[]) ||
        [];
      if (counter) {
        counter.pages += 1;
        counter.rows += rows.length;
      }
      rows.forEach((row) => {
        out.set(row.key, this.heldOrRow(realmId, row));
      });
      // A key the store has no row for is absent — unless this process
      // came to hold it while the question was out.
      page.forEach((key) => {
        if (!out.has(key)) {
          const held = this.heldSlot(realmId, key);
          out.set(key, held ? held.entry : null);
        }
      });
    });
    ask.forEach(function (key) {
      if (!out.has(key)) {
        // No store yet (before `attach()`): nothing can be known about it.
        out.set(key, null);
      }
    });
    log.debug("Leaving DirectoryWindow.entriesAtAsync(). " + ask.length +
              ' asked.');
    return out;
  }

  /**
   * `findWindowed()`, asked asynchronously and read-only: the windowed
   * entries of a realm matching an indexed question and `predicate`, each
   * as this process holds it, in the store's key order, the entries changed
   * here and not yet written that match added last — the order
   * `findWindowed()` answers in, so a caller taking the first answer takes
   * the entry it would have taken.
   *
   * @param realmId - the realm id
   * @param name - one of `persistence/directory_queries.js`'s queries
   * @param args - its arguments
   * @param predicate - the service's own rule, asked of each candidate
   * @returns a promise of `[{ key, entry }]`
   */
  async findWindowedAsync(realmId: string, name: string, args: unknown[],
                          predicate: (entry: Entry, key: string) => boolean):
      Promise<Array<{ key: string; entry: Entry }>> {
    log.debug("Entering DirectoryWindow.findWindowedAsync(). " + name);
    const out: Array<{ key: string; entry: Entry }> = [];
    const seen = new Set<string>();
    const rows = (await this.askAsync(name, args) as Row[]) || [];
    rows.forEach((row) => {
      if (seen.has(row.key) || !this.isWindowed(realmId, row.key)) {
        return;
      }
      seen.add(row.key);
      const entry = this.heldOrRow(realmId, row);
      if (entry && predicate(entry, row.key)) {
        out.push({ key: row.key, entry: entry });
      }
    });
    this.dirty.forEach((ck) => {
      const cut = ck.indexOf('\n');
      const key = ck.slice(cut + 1);
      if (ck.slice(0, cut) !== realmId || seen.has(key)) {
        return;
      }
      const slot = this.lru.peek(ck);
      if (slot && slot.entry && predicate(slot.entry, key)) {
        seen.add(key);
        out.push({ key: key, entry: slot.entry });
      }
    });
    log.debug("Leaving DirectoryWindow.findWindowedAsync(). " + out.length +
              '.');
    return out;
  }

  // ---------------------------------------------------------------------
  // THE KEYS AN OPERATION IS ABOUT TO READ, READ FIRST AND ASYNCHRONOUSLY
  // (#621): an LDAP add asks `getEntry(dn)` and then writes the DN, and in a
  // window both reach `slotFor()`, whose miss is a synchronous `byKeys` on
  // the event loop — every add, since a new person is never held. The add
  // can wait, so it asks here first, and the synchronous body finds the
  // slot held: exactly what `slotFor()` would have put, put a moment
  // earlier.
  //
  // **AN ANSWER OLDER THAN THIS PROCESS'S OWN STATE IS NEVER PUT.** Between
  // the question and its answer this process may write the key, adopt or
  // forget a row another process wrote, or flush — and the store's answer
  // then predates what the window should hold. Each key is WATCHED while
  // its question is out (`watched`, moved by every one of those), and a
  // key that moved, or is held by the time the answer comes, is left
  // alone: the synchronous read asks the store then, as it always did.
  // ---------------------------------------------------------------------
  /**
   * Reads the slots of some windowed keys from the store, asynchronously,
   * and puts in the window those that nothing here changed meanwhile —
   * absences included, as `slotFor()` holds them.
   *
   * @param realmId - the realm id
   * @param keys - normalised DNs; resident or held keys are skipped
   * @returns a promise of how many slots were put
   */
  async warmAsync(realmId: string, keys: string[]): Promise<number> {
    log.debug("Entering DirectoryWindow.warmAsync(). " + keys.length);
    // Each key once, by a Set and not `keys.indexOf()` (2026-10-21), for
    // `entriesAtAsync()`'s reason: that made it quadratic in the keys.
    const once = new Set<string>();
    const ask = keys.filter((key) => {
      if (once.has(key)) {
        return false;
      }
      once.add(key);
      return this.isWindowed(realmId, key) && !this.heldSlot(realmId, key);
    }).slice(0, PAGE);
    if (!ask.length || !this.bridge) {
      log.debug("Leaving DirectoryWindow.warmAsync(). Nothing to ask.");
      return 0;
    }
    const cks = ask.map(function (key) {
      return slotKey(realmId, key);
    });
    cks.forEach((ck) => {
      const one = this.watched.get(ck) || { asks: 0, moved: false };
      one.asks += 1;
      this.watched.set(ck, one);
    });
    let rows: Row[] = [];
    const movedOf: boolean[] = [];
    try {
      rows = (await this.askAsync('byKeys', [realmId, ask]) as Row[]) || [];
    } finally {
      cks.forEach((ck) => {
        const one = this.watched.get(ck);
        movedOf.push(!one || one.moved);
        if (one) {
          one.asks -= 1;
          if (one.asks <= 0) {
            this.watched.delete(ck);
          }
        }
      });
    }
    const byKey = new Map<string, Row>();
    rows.forEach(function (row) {
      byKey.set(row.key, row);
    });
    let put = 0;
    ask.forEach((key, at) => {
      if (movedOf[at] || this.heldSlot(realmId, key)) {
        return;
      }
      const row = byKey.get(key);
      this.put(cks[at], row ? this.slotFromRow(realmId, row)
                            : { entry: null, base: null });
      put += 1;
    });
    log.debug("Leaving DirectoryWindow.warmAsync(). " + put + ' put.');
    return put;
  }

  // What this process holds for a windowed key without asking the store:
  // the window, what was handed out, an evicted entry a caller still holds
  // — `slotFor()`'s first three places, looked at and not moved.
  // Hot path (once per key asked about): no Entering/Leaving pair, the
  // exception the code style allows, stated as it requires.
  private heldSlot(realmId: string, key: string): Slot | null {
    const ck = slotKey(realmId, key);
    return this.lru.peek(ck) || this.touched.get(ck) ||
      this.liveGhost(ck) || null;
  }

  // A watched key moved (see `watched`).
  // Hot path (every write, adoption, forgetting and commit): no
  // Entering/Leaving pair, the exception the code style allows, stated as
  // it requires.
  private moved(ck: string): void {
    if (this.watched.size) {
      const one = this.watched.get(ck);
      if (one) {
        one.moved = true;
      }
    }
  }

  // Every watched key moved: the store attached again, or a realm dropped.
  private movedEverywhere(): void {
    log.debug("Entering DirectoryWindow.movedEverywhere().");
    this.watched.forEach(function (one) {
      one.moved = true;
    });
    log.debug("Leaving DirectoryWindow.movedEverywhere().");
  }

  // What `KeysUnder` reads of the window: whether a key is held deleted or
  // held at all, and the entries created here under a base.
  // Hot path (once per key paged): no Entering/Leaving pair, the exception
  // the code style allows, stated as it requires.
  heldSlotOf(realmId: string, key: string): Slot | null {
    return this.lru.peek(slotKey(realmId, key)) || null;
  }

  createdHereUnder(realmId: string, base: string, seen: Set<string>):
      Array<[string, Entry]> {
    log.debug("Entering DirectoryWindow.createdHereUnder().");
    log.debug("Leaving DirectoryWindow.createdHereUnder().");
    return this.localUnder(realmId, base, base, seen);
  }

  // ---------------------------------------------------------------------
  // ONE PAGE OF THE WHOLE REALM, FOR `/admin/ldap/directory` (#616).
  //
  // The store holds every entry of a realm, resident and windowed, so a page
  // of all of them in key order is one statement (`realmPage`), with the
  // origin filter and the offset pushed down. Each row is answered as this
  // process holds it: a RESIDENT key from the resident Map (current here,
  // and absent when deleted here), a windowed key as `heldOrRow()` says. An
  // entry created here and not yet flushed is not in the store's page and
  // is not here — the next flush puts it there, as `pageAfter()` says of
  // its own pages.
  // ---------------------------------------------------------------------
  /**
   * One page of a realm's entries in the store's key order, asked
   * asynchronously.
   *
   * @param realmId - the realm id
   * @param afterKey - the last key of the previous page, or ''
   * @param limit - the page size (at most 1,000)
   * @param options - `offset` (rows past the cursor to skip) and `origin`
   * @returns a promise of `{ rows: [{ key, entry }], more, asked, last }`
   *   — `asked` how many rows the store answered, `more` when that was a
   *   full page, `last` the last key it answered (the next page's cursor,
   *   '' for none)
   */
  async realmPageAsync(realmId: string, afterKey: string, limit: number,
                       options?: { offset?: number; origin?: string }):
      Promise<{ rows: Array<{ key: string; entry: Entry }>; more: boolean;
                asked: number; last: string }> {
    log.debug("Entering DirectoryWindow.realmPageAsync().");
    const asked = (await this.askAsync('realmPage',
      [realmId, String(afterKey || ''), limit, options || {}]) as Row[]) ||
      [];
    const resident = this.residentOf(realmId);
    const out: Array<{ key: string; entry: Entry }> = [];
    asked.forEach((row) => {
      const entry = this.isWindowed(realmId, row.key)
        ? this.heldOrRow(realmId, row)
        : resident.get(row.key) || null;
      if (entry) {
        out.push({ key: row.key, entry: entry });
      }
    });
    log.debug("Leaving DirectoryWindow.realmPageAsync(). " + out.length +
              ' of ' + asked.length + '.');
    return { rows: out, more: asked.length >= limit, asked: asked.length,
             last: asked.length ? asked[asked.length - 1].key : '' };
  }

  /**
   * One page of a parent's direct children in `rdn_value` order, asked
   * asynchronously (#359). Nothing is put in the LRU. `asked` is how many
   * rows the store answered, including ones this process has deleted;
   * `last` is the last of those rows' RDN, so a cursor moves past a row
   * this process no longer holds.
   *
   * @param realmId - the realm id
   * @param parentKey - the parent's normalised DN
   * @param afterRdn - the previous page's last RDN, or ''
   * @param limit - the page size (at most 1,000)
   * @param options - `offset` and `needle`
   * @returns `{ rows, asked, last }`
   */
  async rdnPageAsync(realmId: string, parentKey: string, afterRdn: string,
                     limit: number,
                     options?: { offset?: number; needle?: string }):
      Promise<{ rows: Array<{ key: string; entry: Entry; rdn: string }>;
                asked: number; last: string }> {
    log.debug("Entering DirectoryWindow.rdnPageAsync().");
    const raw = (await this.askAsync('rdnPage',
      [realmId, parentKey, String(afterRdn || ''), limit,
       options || {}]) as Row[]) || [];
    const resident = this.residentOf(realmId);
    const out: Array<{ key: string; entry: Entry; rdn: string }> = [];
    raw.forEach((row) => {
      const entry = this.isWindowed(realmId, row.key)
        ? this.heldOrRow(realmId, row)
        : resident.get(row.key) || null;
      if (entry) {
        out.push({ key: row.key, entry: entry,
                   rdn: String(row.rdn || '') });
      }
    });
    const last = raw.length ? String(raw[raw.length - 1].rdn || '') : '';
    log.debug("Leaving DirectoryWindow.rdnPageAsync(). " + out.length +
              ' of ' + raw.length + '.');
    return { rows: out, asked: raw.length, last: last };
  }

  /**
   * At most `limit` direct children of a realm's `ou=users` whose RDN value
   * contains `needle`, asked asynchronously (`directory_queries.js`'s
   * `uidContains`, 2026-10-20, `/portal/delegate`). Each row is what this
   * process holds for its key, or the store's row; `asked` is how many
   * rows the store answered, so a caller can tell a full answer from one
   * the limit cut short.
   *
   * @param realmId - the realm id
   * @param parentKey - the realm's `ou=users`, normalised
   * @param needle - the substring, lower-cased
   * @param limit - the most rows
   * @returns `{ rows, asked }`
   */
  async uidContainsAsync(realmId: string, parentKey: string, needle: string,
                         limit: number):
      Promise<{ rows: Array<{ key: string; entry: Entry }>;
                asked: number }> {
    log.debug("Entering DirectoryWindow.uidContainsAsync().");
    const raw = (await this.askAsync('uidContains',
      [realmId, parentKey, String(needle || ''), limit]) as Row[]) || [];
    const out: Array<{ key: string; entry: Entry }> = [];
    raw.forEach((row) => {
      const entry = this.heldOrRow(realmId, row);
      if (entry) {
        out.push({ key: row.key, entry: entry });
      }
    });
    log.debug("Leaving DirectoryWindow.uidContainsAsync(). " + out.length +
              ' of ' + raw.length + '.');
    return { rows: out, asked: raw.length };
  }

  /**
   * One numbered page of a parent's direct children in key order, asked
   * asynchronously (#359). `asked` counts rows the store answered before
   * a delete made here dropped one, so a short page is the end of the
   * container and not a page of deletions.
   *
   * @param realmId - the realm id
   * @param parentKey - the parent's normalised DN
   * @param offset - rows to skip
   * @param limit - the page size (at most 1,000)
   * @returns `{ rows, asked }`
   */
  async containerPageAsync(realmId: string, parentKey: string,
                           offset: number, limit: number):
      Promise<{ rows: Array<{ key: string; entry: Entry }>;
                asked: number }> {
    log.debug("Entering DirectoryWindow.containerPageAsync().");
    const raw = (await this.askAsync('containerPage',
      [realmId, parentKey, offset, limit]) as Row[]) || [];
    const resident = this.residentOf(realmId);
    const out: Array<{ key: string; entry: Entry }> = [];
    raw.forEach((row) => {
      const entry = this.isWindowed(realmId, row.key)
        ? this.heldOrRow(realmId, row)
        : resident.get(row.key) || null;
      if (entry) {
        out.push({ key: row.key, entry: entry });
      }
    });
    log.debug("Leaving DirectoryWindow.containerPageAsync(). " +
              out.length + ' of ' + raw.length + '.');
    return { rows: out, asked: raw.length };
  }

  /**
   * Whether any windowed entry of a realm holds an attribute: a change made
   * here first, then the store.
   *
   * @param realmId - the realm id
   * @param attribute - the attribute name, lower-cased as stored
   * @returns true when one does
   */
  anyHolder(realmId: string, attribute: string): boolean {
    log.debug("Entering DirectoryWindow.anyHolder().");
    let local = false;
    this.dirty.forEach((ck) => {
      if (!ck.startsWith(realmId + '\n')) {
        return;
      }
      const slot = this.lru.peek(ck);
      const values = slot && slot.entry
        ? (slot.entry.attributes || {})[attribute] : null;
      local = local || !!(values && values.length);
    });
    if (local || !this.bridge) {
      log.debug("Leaving DirectoryWindow.anyHolder(). " + local);
      return local;
    }
    const stored = this.bridge.query('anyWithAttribute',
                                     [realmId, attribute]) === true;
    log.debug("Leaving DirectoryWindow.anyHolder(). " + stored);
    return stored;
  }

  /**
   * How many entries are strictly under a base, from the store's count and
   * this process's changes not yet written.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN
   * @returns the count
   */
  countUnder(realmId: string, base: string): number {
    log.debug("Entering DirectoryWindow.countUnder().");
    let n = 0;
    this.residentOf(realmId).forEach(function (entry, key) {
      if (key !== base && DirectoryWindow.within(key, base)) {
        n += 1;
      }
    });
    const reaches = this.deps.windowedContainers(realmId).some(function (c) {
      return DirectoryWindow.within(c, base) || base.endsWith(',' + c);
    });
    if (reaches && this.bridge) {
      n += Number(this.bridge.query('count', [realmId, base]));
      this.dirty.forEach((ck) => {
        const cut = ck.indexOf('\n');
        const key = ck.slice(cut + 1);
        if (ck.slice(0, cut) !== realmId || key === base ||
            !DirectoryWindow.within(key, base) || this.inFlight.has(ck)) {
          return;
        }
        const slot = this.lru.peek(ck) as Slot;
        if (slot.entry && slot.base === null) {
          n += 1;
        } else if (!slot.entry && slot.base !== null) {
          n -= 1;
        }
      });
    }
    log.debug("Leaving DirectoryWindow.countUnder().");
    return Math.max(0, n);
  }

  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  /**
   * How many entries a realm holds, from the store's count of the windowed
   * containers the first time and this process's own net since.
   *
   * @param realmId - the realm id
   * @returns the count
   */
  sizeIn(realmId: string): number {
    const resident = this.residentOf(realmId).size;
    if (!this.bridge) {
      let local = 0;
      this.dirty.forEach((ck) => {
        if (ck.startsWith(realmId + '\n')) {
          const slot = this.lru.peek(ck);
          local += slot && slot.entry ? 1 : 0;
        }
      });
      return resident + local;
    }
    if (!this.counts.has(realmId)) {
      this.counts.set(realmId, this.storeCount(realmId));
      this.countedAt.set(realmId, Date.now());
    }
    return resident + (this.counts.get(realmId) as number);
  }

  // The store's count of the windowed containers, plus what is written here
  // and not yet there.
  private storeCount(realmId: string): number {
    log.debug("Entering DirectoryWindow.storeCount().");
    let n = 0;
    this.deps.windowedContainers(realmId).forEach((c) => {
      n += Number(this.bridge ? this.bridge.query('count', [realmId, c]) : 0);
    });
    this.dirty.forEach((ck) => {
      if (!ck.startsWith(realmId + '\n') || this.inFlight.has(ck)) {
        return;
      }
      const slot = this.lru.peek(ck) as Slot;
      if (slot.entry && slot.base === null) {
        n += 1;
      } else if (!slot.entry && slot.base !== null) {
        n -= 1;
      }
    });
    log.debug("Leaving DirectoryWindow.storeCount().");
    return Math.max(0, n);
  }

  /**
   * A realm's count for `ldap.maxEntries`: the store's, read again when the
   * last reading is more than ten seconds old, plus this process's own net
   * since. Stale by at most that much for another process's creates; the
   * ceiling is a ceiling, not a quota to the entry.
   *
   * @param realmId - the realm id
   * @returns the count
   */
  capCount(realmId: string): number {
    log.debug("Entering DirectoryWindow.capCount().");
    const at = this.countedAt.get(realmId) || 0;
    if (!this.counts.has(realmId) || Date.now() - at > 10000) {
      this.counts.delete(realmId);
    }
    log.debug("Leaving DirectoryWindow.capCount().");
    return this.sizeIn(realmId);
  }

  /**
   * How many entries are strictly under a base and how many of them hold an
   * attribute, now: the store's two counts in one statement and this
   * process's changes not yet written (#610). An entry "holds" an attribute
   * when it carries the NAME with at least one value — what the store's
   * `attr_names` says, the only reading of an entry's attributes the
   * database can make, its values being sealed.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN
   * @param attribute - the attribute name, lower-cased as stored
   * @returns `{ n, holding }`
   */
  countHolding(realmId: string, base: string, attribute: string):
      { n: number; holding: number } {
    log.debug("Entering DirectoryWindow.countHolding(). " + attribute);
    const reaches = this.holdingReaches(realmId, base);
    const stored = reaches && this.bridge
      ? this.bridge.query('countHolding', [realmId, base, attribute]) as
          { n: number; holding: number }
      : null;
    const out = this.holdingWith(realmId, base, attribute, reaches, stored);
    log.debug("Leaving DirectoryWindow.countHolding().");
    return out;
  }

  // `countHolding()` FOR A CALLER THAT CAN WAIT (2026-10-21): the store's
  // two counts asked on the driver's read pool, so the event loop runs while
  // a realm of a million people is counted. `/admin/users`' tiles asked it
  // synchronously, on the worker that serves sign-ins.
  /**
   * `countHolding()`, the store asked asynchronously.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN
   * @param attribute - the attribute name, lower-cased as stored
   * @returns a promise of `{ n, holding }`
   */
  async countHoldingAsync(realmId: string, base: string, attribute: string):
      Promise<{ n: number; holding: number }> {
    log.debug("Entering DirectoryWindow.countHoldingAsync(). " + attribute);
    const reaches = this.holdingReaches(realmId, base);
    const stored = reaches && this.bridge
      ? await this.askAsync('countHolding', [realmId, base, attribute]) as
          { n: number; holding: number }
      : null;
    const out = this.holdingWith(realmId, base, attribute, reaches, stored);
    log.debug("Leaving DirectoryWindow.countHoldingAsync().");
    return out;
  }

  // Whether the base reaches a windowed container: only then is the store
  // asked.
  private holdingReaches(realmId: string, base: string): boolean {
    log.debug("Entering DirectoryWindow.holdingReaches().");
    log.debug("Leaving DirectoryWindow.holdingReaches().");
    return this.deps.windowedContainers(realmId).some(function (c) {
      return DirectoryWindow.within(c, base) || base.endsWith(',' + c);
    });
  }

  // The resident entries' counts, the store's, and this process's unwritten
  // changes, added up: `countHolding()`'s arithmetic, whichever way the
  // store was asked.
  private holdingWith(realmId: string, base: string, attribute: string,
                      reaches: boolean,
                      stored: { n: number; holding: number } | null):
      { n: number; holding: number } {
    log.debug("Entering DirectoryWindow.holdingWith(). " + attribute);
    const has = function (entry: Entry | null | undefined): number {
      const values = entry ? (entry.attributes || {})[attribute] : null;
      return Array.isArray(values) && values.length > 0 ? 1 : 0;
    };
    let n = 0;
    let holding = 0;
    this.residentOf(realmId).forEach(function (entry, key) {
      if (key !== base && DirectoryWindow.within(key, base)) {
        n += 1;
        holding += has(entry);
      }
    });
    if (reaches && this.bridge) {
      n += Number(stored && stored.n) || 0;
      holding += Number(stored && stored.holding) || 0;
      // `countUnder()`'s net, and the attribute's beside it: the entry as
      // it is here against its BASE, the JSON the store holds.
      this.dirty.forEach((ck) => {
        const cut = ck.indexOf('\n');
        const key = ck.slice(cut + 1);
        if (ck.slice(0, cut) !== realmId || key === base ||
            !DirectoryWindow.within(key, base) || this.inFlight.has(ck)) {
          return;
        }
        const slot = this.lru.peek(ck) as Slot;
        let before: Entry | null = null;
        if (slot.base !== null) {
          try {
            before = JSON.parse(slot.base) as Entry;
          } catch (e) {
            log.debug("Caught in DirectoryWindow.holdingWith(): " +
                      ((e && e.message) || e));
            // A base that does not parse is one this window wrote itself
            // and cannot be; counted as an entry holding nothing.
            before = { dn: key, attributes: {} } as Entry;
          }
        }
        n += (slot.entry ? 1 : 0) - (before ? 1 : 0);
        holding += has(slot.entry) - has(before);
      });
    }
    log.debug("Leaving DirectoryWindow.holdingWith().");
    return { n: Math.max(0, n), holding: Math.max(0, holding) };
  }

  // ---------------------------------------------------------------------
  // A CONTAINER'S COUNT FOR A PAGE'S HEADLINE (#610, 2026-10-13).
  //
  // `countUnder()` asks the store every time, and the store's answer is a
  // `count(*)` that is LINEAR in the realm's rows: `underClause()`'s
  // `right(dn_key, n)` cannot use an index, and even `parent_key = $2`,
  // which can, is a sequential scan when nearly every row of the realm is
  // a person — measured on 8081's postgres on 2026-10-13 at 13–15 ms for
  // 29,303 rows, both forms, so about 100 ms at 200,000. That is cheap
  // beside listing every name (which is what `/admin/users` did), and too
  // much to pay on every poll of a console page from a thread that answers
  // every socket. So the reading is `capCount()`'s: the store's count at
  // most ten seconds old, plus this process's own creates and deletes under
  // the container since (`write()` moves it). Another process's writes
  // reach it within ten seconds; this process's at once.
  //
  // SINCE #618 THE STORE'S ANSWER IS A COUNTER, NOT A COUNT: `count` and
  // `countHolding` read `sts_ldap_counts`, which the database's triggers
  // keep in the transaction that wrote (`persistence/directory_queries.js`),
  // one primary-key read whatever the realm's size. The ten seconds are
  // kept — a question to the store from the front's event loop is still a
  // round trip — and so is every caller's arithmetic: the store's committed
  // count plus this process's own net not yet written, as before.
  // ---------------------------------------------------------------------
  /**
   * How many entries are strictly under a base: the store's count, read
   * again when the last reading is more than ten seconds old, plus this
   * process's own net since.
   *
   * @param realmId - the realm id
   * @param base - the base's normalised DN
   * @returns the count
   */
  recentCountUnder(realmId: string, base: string): number {
    log.debug("Entering DirectoryWindow.recentCountUnder().");
    const cck = slotKey(realmId, base);
    const held = this.containerCounts.get(cck);
    if (held && Date.now() - held.at <= 10000) {
      log.debug("Leaving DirectoryWindow.recentCountUnder(). Held.");
      return Math.max(0, held.n);
    }
    const n = this.countUnder(realmId, base);
    // Only once there is a store to have asked: a count taken before the
    // bridge is resident entries alone, and holding it would hide the
    // store's rows for ten seconds.
    if (this.bridge) {
      this.containerCounts.set(cck, { n: n, at: Date.now() });
    }
    log.debug("Leaving DirectoryWindow.recentCountUnder(). Counted.");
    return n;
  }

  // A CHANGE FROM ANOTHER PROCESS DROPS THE COUNTS ABOVE IT (2026-10-14).
  // The ten seconds above held a container's count across another
  // process's create or delete that this process had already APPLIED: the
  // read barrier serves a request only after the writes before it are
  // applied, and the count then still answered from before them
  // (sts_devices section 6, cluster on ccf5741a: a device removed through
  // one node, `total` read as 2 through the other). Since #618 the store's
  // count is a primary-key read, so dropping the held reading for every
  // container above the key — and the next `recentCountUnder()` asking
  // again — costs one round trip per container and only after a change.
  /**
   * Drops the held count of every container above a key another process
   * just created, changed or deleted.
   *
   * @param realmId - the realm id
   * @param key - the changed entry's normalised DN
   */
  dropCountsAbove(realmId: string, key: string): void {
    log.debug("Entering DirectoryWindow.dropCountsAbove().");
    const prefix = realmId + '\n';
    for (const cck of Array.from(this.containerCounts.keys())) {
      if (cck.indexOf(prefix) !== 0) {
        continue;
      }
      const base = cck.slice(prefix.length);
      if (key.endsWith(',' + base)) {
        this.containerCounts.delete(cck);
      }
    }
    log.debug("Leaving DirectoryWindow.dropCountsAbove().");
  }

  /**
   * A realm's count read from the store now, for `ldap.maxEntries` and for
   * a report.
   *
   * @param realmId - the realm id
   * @returns the count
   */
  exactCount(realmId: string): number {
    log.debug("Entering DirectoryWindow.exactCount().");
    this.counts.delete(realmId);
    log.debug("Leaving DirectoryWindow.exactCount().");
    return this.sizeIn(realmId);
  }

  /**
   * Empties a realm: the restore's `replaceRealm()`. Changes not yet
   * written are dropped with the rest — a restore is "this is the
   * directory".
   *
   * @param realmId - the realm id
   */
  clearIn(realmId: string): void {
    log.debug("Entering DirectoryWindow.clearIn().");
    this.dropRealm(realmId);
    log.debug("Leaving DirectoryWindow.clearIn().");
  }

  private dropRealm(realmId: string): void {
    log.debug("Entering DirectoryWindow.dropRealm().");
    this.movedEverywhere();
    this.resident.delete(realmId);
    this.realmsHeld.delete(realmId);
    const prefix = realmId + '\n';
    this.lru.keys().forEach((ck) => {
      if (ck.startsWith(prefix)) {
        this.lru.delete(ck);
      }
    });
    [this.dirty, this.touched, this.ghosts, this.inFlight, this.stale].forEach(
      function (held: Set<string> | Map<string, unknown>) {
        Array.from(held.keys()).forEach(function (ck: string) {
          if (ck.startsWith(prefix)) {
            held.delete(ck);
          }
        });
      });
    this.counts.delete(realmId);
    Array.from(this.containerCounts.keys()).forEach((cck) => {
      if (cck.startsWith(prefix)) {
        this.containerCounts.delete(cck);
      }
    });
    log.debug("Leaving DirectoryWindow.dropRealm().");
  }

  // ---- the flush ----------------------------------------------------------

  /**
   * What the flush writes for the windowed keys, and the release of every
   * entry handed out and left unchanged.
   *
   * @param named - the journal's keys (without a realm), or null when a
   *   write named nothing: then every held and evicted-but-held entry is a
   *   candidate
   * @returns the upserts (`entry`, `json`, `base`) and deletes (`base`)
   */
  collect(named: Set<string> | null): { upserts: Change[];
                                         deletes: Change[] } {
    log.debug("Entering DirectoryWindow.collect().");
    this.touchScheduled = false;
    const candidates = new Map<string, Slot>();
    this.dirty.forEach((ck) => {
      candidates.set(ck, this.lru.peek(ck) as Slot);
    });
    this.touched.forEach((slot, ck) => {
      candidates.set(ck, slot);
    });
    if (named === null) {
      // A write that named nothing: everything held is a candidate, so this
      // walks the LRU and every ghost — O(LRU + ghosts), and legitimately,
      // since the question IS "everything". It runs only after a
      // `touchDirectory()` with no DN, a realm change, or a failed flush
      // that had walked everything; a bulk load's adds name their DN.
      this.lru.keys().forEach((ck) => {
        candidates.set(ck, this.lru.peek(ck) as Slot);
      });
      // Deleting the entry being visited (a dead ghost, in `liveGhost()`)
      // is defined for a Map's iterator: the walk goes on to the next.
      for (const ck of this.ghosts.keys()) {
        const alive = this.liveGhost(ck);
        if (alive && !candidates.has(ck)) {
          candidates.set(ck, alive);
        }
      }
    } else if (named.size) {
      // THE JOURNAL'S KEYS ARE LOOKED UP, NOT SCANNED FOR (#612). Until
      // 2026-10-13 this walked every LRU key and every ghost to find the
      // handful named, once per flush; a ghost is made on every eviction
      // and went only when the FinalizationRegistry got round to it, so
      // under a 200K bulk load the ghost map grew with uptime and the walk
      // was 7.4 s of a 15.6 s profile — the add rate halved in 33K adds and
      // came back on a restart. Now O(|named| x realms held). The answer is
      // the walk's: an LRU slot replaces a dirty or handed-out candidate's
      // (the same slot, in practice), and a live ghost is taken only when
      // nothing else made the key a candidate. Only the ORDER differs, and
      // nothing reads it: the postgres driver sorts what it locks by key.
      named.forEach((key) => {
        this.realmsHeld.forEach((realmId) => {
          const ck = slotKey(realmId, key);
          const held = this.lru.peek(ck);
          if (held) {
            candidates.set(ck, held);
            return;
          }
          if (!candidates.has(ck)) {
            const alive = this.liveGhost(ck);
            if (alive) {
              candidates.set(ck, alive);
            }
          }
        });
      });
    }
    this.touched.clear();
    const upserts: Change[] = [];
    const deletes: Change[] = [];
    candidates.forEach((slot, ck) => {
      if (!slot || this.inFlight.has(ck)) {
        return;
      }
      const cut = ck.indexOf('\n');
      const realm = ck.slice(0, cut);
      const key = ck.slice(cut + 1);
      if (!slot.entry) {
        if (slot.base !== null) {
          deletes.push({ realm: realm, key: key, base: slot.base });
          this.inFlight.set(ck, '');
          this.pinDirty(ck, slot);
        } else {
          this.release(ck);
        }
        return;
      }
      const json = JSON.stringify(slot.entry);
      if (json === slot.base) {
        this.release(ck);
        return;
      }
      upserts.push({ realm: realm, key: key, entry: slot.entry, json: json,
                     base: slot.base });
      this.inFlight.set(ck, json);
      this.pinDirty(ck, slot);
    });
    log.debug("Leaving DirectoryWindow.collect(). " + upserts.length +
              " upsert(s), " + deletes.length + " delete(s).");
    return { upserts: upserts, deletes: deletes };
  }

  // A candidate found changed: held, pinned, and no longer a ghost.
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private pinDirty(ck: string, slot: Slot): void {
    if (!this.dirty.has(ck)) {
      this.dirty.add(ck);
      this.lru.pin(ck);
    }
    if (this.lru.peek(ck) !== slot) {
      this.put(ck, slot);
    }
    this.ghosts.delete(ck);
  }

  // A candidate found unchanged: no longer dirty — and dropped, if another
  // process changed it meanwhile (`markStale()`).
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private release(ck: string): void {
    this.moved(ck);
    if (this.dirty.delete(ck)) {
      this.lru.unpin(ck);
    }
    if (this.stale.delete(ck)) {
      this.lru.delete(ck);
      this.ghosts.delete(ck);
      this.touched.delete(ck);
    }
  }

  /**
   * The flush wrote what `collect()` answered: each base is what was sent,
   * and a key unchanged since is released. A key the store answered
   * differently for (`outcomes`) is forgotten, or — changed again since —
   * given the store's row as its base.
   *
   * @param changes - what `collect()` answered
   * @param outcomes - the driver's `{ realm, key, outcome, entry }` rows
   */
  committed(changes: { upserts: Change[]; deletes: Change[] },
            outcomes?: Array<{ realm: string; key: string; outcome: string;
                               entry?: Entry | null }>): void {
    log.debug("Entering DirectoryWindow.committed().");
    const decided = new Map<string, { outcome: string;
                                      entry?: Entry | null }>();
    (outcomes || []).forEach(function (one) {
      decided.set(slotKey(one.realm, one.key), one);
    });
    changes.upserts.concat(changes.deletes).forEach((change) => {
      const ck = slotKey(change.realm, change.key);
      this.moved(ck);
      const sent = this.inFlight.get(ck);
      this.inFlight.delete(ck);
      const slot = this.lru.peek(ck);
      if (!slot) {
        this.release(ck);
        return;
      }
      const now = slot.entry ? JSON.stringify(slot.entry) : '';
      const other = decided.get(ck);
      if (other) {
        if (now === sent) {
          this.release(ck);
          this.lru.delete(ck);
        } else {
          slot.base = other.entry ? JSON.stringify(other.entry) : null;
        }
        return;
      }
      slot.base = change.entry ? (sent as string) : null;
      if (now === sent) {
        this.release(ck);
      }
    });
    log.debug("Leaving DirectoryWindow.committed().");
  }

  /**
   * The flush failed: the keys it took are still changed, and are taken
   * again by the next one.
   *
   * @param changes - what `collect()` answered
   */
  failed(changes: { upserts: Change[]; deletes: Change[] }): void {
    log.debug("Entering DirectoryWindow.failed().");
    changes.upserts.concat(changes.deletes).forEach((change) => {
      this.inFlight.delete(slotKey(change.realm, change.key));
    });
    log.debug("Leaving DirectoryWindow.failed().");
  }

  /**
   * The window's figures, for a status page and tests.
   *
   * @returns the LRU's figures, and the dirty, in-flight, handed-out and
   *   evicted-but-held counts
   */
  stats(): Record<string, unknown> {
    log.debug("Entering DirectoryWindow.stats().");
    let resident = 0;
    this.resident.forEach(function (held) {
      resident += held.size;
    });
    log.debug("Leaving DirectoryWindow.stats().");
    const out: Record<string, unknown> = { ...this.lru.stats() };
    Object.assign(out, { resident: resident, dirty: this.dirty.size,
                         inFlight: this.inFlight.size,
                         touched: this.touched.size, ghosts: this.ghosts.size,
                         attached: !!this.bridge });
    return out;
  }

  // ---- the Map facades ------------------------------------------------------

  // THE VIEW'S MEMBERS ARE THE DIRECTORY'S Map — every read and write of it
  // passes through one — so they carry no Entering/Leaving pair: the
  // hot-path exception, stated here as the code style requires.
  /**
   * A Map-shaped view of one realm.
   *
   * @param realmId - the realm id
   * @returns the view
   */
  viewOf(realmId: string): any {
    log.debug("Entering DirectoryWindow.viewOf().");
    const w = this;
    const id = String(realmId);
    const view: any = {
      get: function (key: string) {
        return w.getIn(id, key);
      },
      has: function (key: string) {
        return w.hasIn(id, key);
      },
      set: function (key: string, entry: Entry) {
        w.setIn(id, key, entry);
        return view;
      },
      delete: function (key: string) {
        return w.deleteIn(id, key);
      },
      clear: function () {
        w.clearIn(id);
      },
      forEach: function (fn: (entry: Entry, key: string, m: any) => void) {
        w.scan(id, function (entry, key) {
          fn(entry, key, view);
        });
      },
      entries: function () {
        return w.walk(id, '');
      },
      keys: function* () {
        for (const pair of w.walk(id, '')) {
          yield pair[0];
        }
      },
      values: function* () {
        for (const pair of w.walk(id, '')) {
          yield pair[1];
        }
      }
    };
    Object.defineProperty(view, 'size', {
      get: function () {
        return w.sizeIn(id);
      }
    });
    view[Symbol.iterator] = view.entries;
    log.debug("Leaving DirectoryWindow.viewOf().");
    return view;
  }

  // The facade's members are hot for the view's reason; only the call that
  // builds it logs.
  /**
   * The facade `ldap_server.js` holds as `entries`: the ambient realm's view
   * for every Map member, `realmMap(id)` for a named realm, and the window
   * itself as `window`.
   *
   * @returns the facade
   */
  facade(): any {
    log.debug("Entering DirectoryWindow.facade().");
    const w = this;
    const ambient = function () {
      return w.viewOf(w.deps.currentId());
    };
    const f: any = {
      window: w,
      realmMap: function (id?: string) {
        return id === undefined ? ambient() : w.viewOf(String(id));
      }
    };
    ['get', 'has', 'set', 'delete', 'clear', 'forEach', 'entries', 'keys',
     'values'].forEach(function (name) {
      f[name] = function () {
        const v = ambient();
        const out = v[name].apply(v, arguments);
        return out === v ? f : out;
      };
    });
    Object.defineProperty(f, 'size', {
      get: function () {
        return ambient().size;
      }
    });
    f[Symbol.iterator] = function () {
      return ambient().entries();
    };
    log.debug("Leaving DirectoryWindow.facade().");
    return f;
  }
}

export = DirectoryWindow;
