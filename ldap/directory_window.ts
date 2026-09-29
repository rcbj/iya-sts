// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
// beside `directoryVersion`, and `ldap.maxEntries` is a SQL count
// (`exactCount()`), not this.
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

// The bridge: a synchronous question to the store.
interface Bridge {
  query(name: string, args: unknown[]): unknown;
}

// A row as `persistence/directory_queries.js` answers.
interface Row {
  realm: string;
  key: string;
  entry: Entry;
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

// The composite key the window holds a realm's entry under.
function slotKey(realmId: string, key: string): string {
  return realmId + '\n' + key;
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
  // The windowed count per realm, from the store, and this process's net.
  private readonly counts: Map<string, number> = new Map();
  private readonly countedAt: Map<string, number> = new Map();
  // Keys another process changed while this one was busy with them: dropped
  // once this process's own flush has let them go (see `markStale()`).
  private readonly stale: Set<string> = new Set();
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
    this.lru.keys().forEach((key) => {
      if (!this.dirty.has(key)) {
        this.lru.delete(key);
      }
    });
    this.counts.clear();
    log.debug("Leaving DirectoryWindow.attach().");
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
      this.lru.set(ck, handed);
      return handed;
    }
    const ghost = this.ghosts.get(ck);
    const alive = ghost ? ghost.ref.deref() : undefined;
    if (ghost && alive) {
      this.ghosts.delete(ck);
      const back = { entry: alive, base: ghost.base };
      this.lru.set(ck, back);
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
    this.lru.set(ck, slot);
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
    const before = this.slotFor(realmId, key);
    const existed = !!(before && before.entry);
    const slot: Slot = { entry: entry,
                         base: before ? before.base : null };
    if (!this.dirty.has(ck)) {
      this.dirty.add(ck);
      this.lru.pin(ck);
    }
    this.lru.set(ck, slot);
    this.ghosts.delete(ck);
    if (entry) {
      this.touch(ck, slot);
    } else {
      this.touched.delete(ck);
      this.askForFlush();
    }
    if (this.counts.has(realmId)) {
      const n = this.counts.get(realmId) as number;
      this.counts.set(realmId, n + (entry && !existed ? 1 : 0) -
                      (!entry && existed ? 1 : 0));
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
    if (this.dirty.has(ck)) {
      // A change made here stands; the flush writes it against this base.
      const held = this.lru.peek(ck) as Slot;
      held.base = JSON.stringify(entry);
      return;
    }
    this.lru.set(ck, { entry: entry, base: JSON.stringify(entry) });
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
            const ghost = this.ghosts.get(ck);
            const alive = ghost ? ghost.ref.deref() : undefined;
            slot = ghost && alive
              ? { entry: alive, base: ghost.base }
              : this.slotFromRow(realmId, row);
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
   * @returns `[{ key, entry }]`, in key order, local additions last
   */
  findWindowed(realmId: string, name: string, args: unknown[],
               predicate: (entry: Entry, key: string) => boolean):
      Array<{ key: string; entry: Entry }> {
    log.debug("Entering DirectoryWindow.findWindowed(). " + name);
    const out: Array<{ key: string; entry: Entry }> = [];
    const seen = new Set<string>();
    const rows = this.bridge
      ? (this.bridge.query(name, args) as Row[]) || [] : [];
    rows.forEach((row) => {
      if (seen.has(row.key) || !this.isWindowed(realmId, row.key)) {
        return;
      }
      seen.add(row.key);
      const entry = this.getIn(realmId, row.key);
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
    this.resident.delete(realmId);
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
      this.lru.keys().forEach((ck) => {
        candidates.set(ck, this.lru.peek(ck) as Slot);
      });
      this.ghosts.forEach((ghost, ck) => {
        const alive = ghost.ref.deref();
        if (alive && !candidates.has(ck)) {
          candidates.set(ck, { entry: alive, base: ghost.base });
        }
      });
    } else if (named.size) {
      const wanted = named;
      this.lru.keys().forEach((ck) => {
        if (wanted.has(ck.slice(ck.indexOf('\n') + 1))) {
          candidates.set(ck, this.lru.peek(ck) as Slot);
        }
      });
      this.ghosts.forEach((ghost, ck) => {
        const alive = ghost.ref.deref();
        if (alive && !candidates.has(ck) &&
            wanted.has(ck.slice(ck.indexOf('\n') + 1))) {
          candidates.set(ck, { entry: alive, base: ghost.base });
        }
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
      this.lru.set(ck, slot);
    }
    this.ghosts.delete(ck);
  }

  // A candidate found unchanged: no longer dirty — and dropped, if another
  // process changed it meanwhile (`markStale()`).
  // Hot path (every read or write of the directory): no Entering/Leaving
  // pair, the exception the code style allows, stated as it requires.
  private release(ck: string): void {
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
