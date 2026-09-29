// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: bounded_lru.ts
//
// ---------------------------------------------------------------------------
// A BOUNDED LEAST-RECENTLY-USED CACHE, AND THE FIRST SHARED CACHE CLASS
// (#349 phase 1, 2026-09-29).
//
// `common/cache_registry.js` says there is no shared cache class and that
// every cache stays the `Map` it was, describing itself once. That was right
// for the caches it was written about — each is small, each has its own
// reason to drop an entry (an expiry, a version stamp, a container clock) and
// `makeRoom()` evicts the OLDEST INSERTED entry, which is the right victim for
// a replay store and a fetched document. It is the wrong one for what #349
// needs: a request worker holding a window onto a directory of 200,000
// entries, where the entry to keep is the one somebody READ a moment ago,
// whenever it was put there. That is recency of USE, and it is a policy worth
// writing once rather than three times.
//
// So this is a Map in recency order: a read moves the key to the young end,
// an insert past the bound drops keys from the old end. What it adds to a
// bare Map is exactly three things:
//
//   * **THE BOUND IS A FUNCTION**, asked on every insert, so a runtime setting
//     that lowers it takes effect at the next insert (and a raise, at once).
//     A bound that is not a finite number above zero is treated as one: an
//     unbounded cache is the thing #339 is about.
//   * **A PINNED KEY IS NEVER EVICTED.** #349's worker cache has entries it
//     must not drop: one it has changed and not yet written down (the flush
//     finds what to write by looking at what it holds), and the working set
//     of a request still running. `pin()` is counted, so two holders of one
//     key each release their own. If every key is pinned the cache stays over
//     its bound rather than drop one, and `stats().overBound` says by how
//     much — a correctness rule outranks a size rule, and the report is what
//     makes the overrun visible rather than silent.
//   * **IT DESCRIBES ITSELF TO THE CACHE REGISTRY** when it is handed one
//     (rule 3ap), so `/admin/caches` shows its size, its bound, its hit ratio
//     and its evictions like every other cache. A row carries the key and
//     never the value, which is the registry's own rule; a caller whose keys
//     are credentials passes `rowOf` and digests them.
//
// **A LEAF (rule 3)**: it requires `bunyan` and nothing of this service, and
// the registry arrives through the constructor, so a test builds one with no
// registry at all and nothing is shown anywhere.
//
// **WHAT IT DOES NOT DO**: expire entries by time (an owner with a lifetime
// checks it at the read, as every cache here does), coordinate with another
// process (a cache is the one thing that is not shared — root CLAUDE.md, *One
// front process*), or weigh entries by size. The bound is a COUNT; #349's
// design comment on the ticket measured what an entry costs, and the setting
// that sizes the directory cache is stated in entries for that reason.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-bounded-lru' });

// The part of `common/cache_registry.js` this class uses. Declared here rather
// than imported, because the registry is JavaScript and a leaf: what matters
// is the two members a descriptor needs, and a test hands in a double.
interface CacheRegistryLike {
  register(descriptor: Record<string, unknown>): CacheCounter;
}

// What `cacheRegistry.register()` answers.
interface CacheCounter {
  hit(): void;
  miss(): void;
  evicted(n: number): void;
  refused(): void;
}

// One row on `/admin/caches`: which realm, and the key as it may be shown.
interface CacheRow {
  realm: string | null;
  key: string;
}

// The description a cache gives the registry. Every member but `name` and
// `maxEntries` is the registry's (common/cache_registry.js's header).
interface BoundedLruOptions<K> {
  // The registry name, e.g. `ldap.worker-directory`.
  name: string;
  // The bound, in entries, asked on every insert.
  maxEntries: () => number;
  // The registry, when this cache is to be shown on `/admin/caches`.
  registry?: CacheRegistryLike | null;
  title?: string;
  description?: string;
  owner?: string;
  // `process` by default: one bound for the whole cache. A caller whose keys
  // carry a realm still has one bound, and says which realm in `rowOf`.
  scope?: 'process' | 'realm';
  settings?: string[];
  lifetime?: () => string;
  bound?: string;
  // How a key is shown. Defaults to the key as a string in no realm.
  rowOf?: (key: K) => CacheRow;
  // Told of every key the bound evicted, after it has gone.
  onEvict?: (key: K, value: unknown) => void;
}

// What `stats()` reports.
interface BoundedLruStats {
  name: string;
  size: number;
  maxEntries: number;
  pinned: number;
  overBound: number;
  hits: number;
  misses: number;
  evictions: number;
}

/**
 * A bounded cache in least-recently-used order, with pinning and an optional
 * description on `/admin/caches` (#349).
 *
 * A read (`get`) moves a key to the young end; an insert past the bound drops
 * unpinned keys from the old end.
 */
class BoundedLru<K, V> {
  private readonly held: Map<K, V> = new Map();
  private readonly pins: Map<K, number> = new Map();
  private readonly counter: CacheCounter | null;
  private hits = 0;
  private misses = 0;
  private evictions = 0;

  /**
   * Builds the cache and, when a registry is given, describes it there.
   *
   * @param options - the name, the bound, and the registry's description
   * @throws an Error when the name or the bound is missing
   */
  constructor(private readonly options: BoundedLruOptions<K>) {
    log.debug("Entering BoundedLru.constructor().");
    if (!options || typeof options.name !== 'string' || !options.name ||
        typeof options.maxEntries !== 'function') {
      log.debug("Leaving BoundedLru.constructor(). Incomplete.");
      throw new Error('BoundedLru needs a name and a maxEntries() function.');
    }
    this.counter = options.registry
      ? options.registry.register(this.descriptor())
      : null;
    log.debug("Leaving BoundedLru.constructor().");
  }

  // The bound as a usable number: a finite integer of at least one. Anything
  // else — a setting read as NaN, zero, a negative — is ONE, because the
  // failure this class exists to prevent is a cache that grows without limit,
  // and a bound nobody can read is not permission to.
  //
  // Called on every insert, so no Entering/Leaving pair — the hot-path
  // exception the code style allows, stated here as it requires.
  /**
   * Answers the bound now, as a whole number of at least one.
   *
   * @returns the bound
   */
  limit(): number {
    let n = NaN;
    try {
      n = Number(this.options.maxEntries());
    } catch (e) {
      log.debug("Caught in BoundedLru.limit(): " +
                ((e && (e as Error).message) || e));
      n = NaN;
    }
    return isFinite(n) && n >= 1 ? Math.floor(n) : 1;
  }

  // Read on hot paths (every status draw, every test); no Entering/Leaving
  // pair.
  /**
   * How many keys are held.
   *
   * @returns the count
   */
  get size(): number {
    return this.held.size;
  }

  // The one counted lookup (rule 3ap: a cache counts at the place it is
  // looked up). A hit moves the key to the young end.
  //
  // Called on every read, so no Entering/Leaving pair (the hot-path
  // exception).
  /**
   * Reads a key, counting a hit or a miss and making it the most recently
   * used.
   *
   * @param key - the key
   * @returns the value, or undefined when it is not held
   */
  get(key: K): V | undefined {
    if (!this.held.has(key)) {
      this.misses += 1;
      if (this.counter) {
        this.counter.miss();
      }
      return undefined;
    }
    const value = this.held.get(key) as V;
    this.held.delete(key);
    this.held.set(key, value);
    this.hits += 1;
    if (this.counter) {
      this.counter.hit();
    }
    return value;
  }

  // A read that is neither counted nor a use: for a flush or an applier that
  // asks what is held without meaning that anybody wanted it.
  //
  // Hot path; no Entering/Leaving pair.
  /**
   * Reads a key without counting it or changing its recency.
   *
   * @param key - the key
   * @returns the value, or undefined when it is not held
   */
  peek(key: K): V | undefined {
    return this.held.get(key);
  }

  // Hot path; no Entering/Leaving pair.
  /**
   * Whether a key is held. Neither counted nor a use.
   *
   * @param key - the key
   * @returns true when held
   */
  has(key: K): boolean {
    return this.held.has(key);
  }

  // Hot path (every fill of the cache); no Entering/Leaving pair.
  /**
   * Puts a value under a key as the most recently used, then evicts unpinned
   * keys from the old end until the cache is within its bound.
   *
   * @param key - the key
   * @param value - the value
   * @returns this cache
   */
  set(key: K, value: V): this {
    if (this.held.has(key)) {
      this.held.delete(key);
    }
    this.held.set(key, value);
    this.trim();
    return this;
  }

  /**
   * Drops a key, and any pins on it.
   *
   * @param key - the key
   * @returns true when it was held
   */
  delete(key: K): boolean {
    log.debug("Entering BoundedLru.delete().");
    this.pins.delete(key);
    const was = this.held.delete(key);
    log.debug("Leaving BoundedLru.delete().");
    return was;
  }

  /**
   * Drops every key and every pin. The counters are kept: they are about the
   * life of the process, as every registered cache's are.
   */
  clear(): void {
    log.debug("Entering BoundedLru.clear().");
    this.held.clear();
    this.pins.clear();
    log.debug("Leaving BoundedLru.clear().");
  }

  /**
   * The keys held, from the least to the most recently used.
   *
   * @returns the keys
   */
  keys(): K[] {
    log.debug("Entering BoundedLru.keys().");
    log.debug("Leaving BoundedLru.keys().");
    return Array.from(this.held.keys());
  }

  // A key may be pinned before it is held: a caller about to load an entry
  // pins it first, so the load cannot be evicted by another load finishing
  // in between.
  /**
   * Keeps a key from being evicted until it is unpinned as many times.
   *
   * @param key - the key
   */
  pin(key: K): void {
    log.debug("Entering BoundedLru.pin().");
    this.pins.set(key, (this.pins.get(key) || 0) + 1);
    log.debug("Leaving BoundedLru.pin().");
  }

  // Unpinning may bring the cache back within its bound, so it trims: the
  // overrun a pin allowed ends when the last pin goes, not at the next
  // insert.
  /**
   * Releases one pin on a key, and evicts if the cache is over its bound.
   *
   * @param key - the key
   */
  unpin(key: K): void {
    log.debug("Entering BoundedLru.unpin().");
    const n = this.pins.get(key) || 0;
    if (n <= 1) {
      this.pins.delete(key);
    } else {
      this.pins.set(key, n - 1);
    }
    this.trim();
    log.debug("Leaving BoundedLru.unpin().");
  }

  // Asked once per held key on every eviction walk; no Entering/Leaving pair
  // (the hot-path exception).
  /**
   * Whether a key is pinned.
   *
   * @param key - the key
   * @returns true when at least one pin is held on it
   */
  isPinned(key: K): boolean {
    return (this.pins.get(key) || 0) > 0;
  }

  // THE EVICTION. From the old end, skipping pinned keys; when only pinned
  // keys are left the cache stays over its bound (see the header). The walk
  // past pinned keys is the cost of pinning, and it is bounded by the number
  // of pins, which are few: a request's working set and what is unwritten.
  //
  // Hot path (every insert); no Entering/Leaving pair.
  private trim(): void {
    const max = this.limit();
    if (this.held.size <= max) {
      return;
    }
    const victims: Array<[K, V]> = [];
    let excess = this.held.size - max;
    for (const [key, value] of this.held) {
      if (excess <= 0) {
        break;
      }
      if (this.isPinned(key)) {
        continue;
      }
      victims.push([key, value]);
      excess -= 1;
    }
    victims.forEach(([key]) => {
      this.held.delete(key);
    });
    if (victims.length) {
      this.evictions += victims.length;
      if (this.counter) {
        this.counter.evicted(victims.length);
      }
      if (typeof this.options.onEvict === 'function') {
        victims.forEach(([key, value]) => {
          try {
            (this.options.onEvict as (k: K, v: unknown) => void)(key, value);
          } catch (e) {
            // A listener that throws must not undo an eviction that has
            // already happened, nor stop the next listener call.
            log.debug("Caught in BoundedLru.trim(): " +
                      ((e && (e as Error).message) || e));
          }
        });
      }
    }
  }

  /**
   * The cache's figures, for a status page and for tests.
   *
   * @returns size, bound, pins, overrun and the counters
   */
  stats(): BoundedLruStats {
    log.debug("Entering BoundedLru.stats().");
    const max = this.limit();
    let pinned = 0;
    this.pins.forEach((n, key) => {
      if (n > 0 && this.held.has(key)) {
        pinned += 1;
      }
    });
    log.debug("Leaving BoundedLru.stats().");
    return {
      name: this.options.name,
      size: this.held.size,
      maxEntries: max,
      pinned: pinned,
      overBound: Math.max(0, this.held.size - max),
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions
    };
  }

  // THE REGISTRY'S DESCRIPTOR (rule 3ap). Its functions are called when the
  // page is drawn and never before. A row is the key as `rowOf` shows it and
  // never the value.
  private descriptor(): Record<string, unknown> {
    log.debug("Entering BoundedLru.descriptor().");
    const o = this.options;
    const rowOf = typeof o.rowOf === 'function'
      ? o.rowOf
      : function (key: K): CacheRow {
        return { realm: null, key: String(key) };
      };
    log.debug("Leaving BoundedLru.descriptor().");
    return {
      name: o.name,
      title: o.title || o.name,
      description: o.description ||
        'A bounded cache in least-recently-used order.',
      owner: o.owner || 'common/bounded_lru.ts',
      scope: o.scope || 'process',
      kind: 'cache',
      settings: Array.isArray(o.settings) ? o.settings.slice() : [],
      bound: o.bound || 'Enforced: an insert past the bound evicts the ' +
        'least recently used unpinned entries.',
      hitMeaning: 'a read answered from the cache without going to the ' +
        'store',
      maxEntries: () => this.limit(),
      lifetime: typeof o.lifetime === 'function'
        ? o.lifetime
        : function () {
          return 'Until evicted by the bound or dropped by its owner.';
        },
      entries: () => {
        const rows: Array<Record<string, unknown>> = [];
        this.held.forEach(function (_value, key) {
          const row = rowOf(key);
          rows.push({ realm: row.realm, key: row.key, validUntil: null,
                      valid: true, basis: 'least recently used' });
        });
        return rows;
      }
    };
  }
}

export = BoundedLru;
