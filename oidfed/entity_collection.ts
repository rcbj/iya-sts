'use strict';
//
// File: entity_collection.ts
//
// ===========================================================================
// THE ENTITY COLLECTION (#136, 2026-09-24): OpenID Federation Entity
// Collection Endpoint 1.0, draft 01 — `federation_collection_endpoint`, at
// `/oidfed/collection` under the realm's base.
//
// The list endpoints name a superior's IMMEDIATE subordinates. This one names
// every entity beneath the realm — subordinates, their subordinates, and so
// on — with what a login picker or a catalogue draws for each (`ui_infos`,
// the informational metadata of 5.2.2 per entity type) and its Trust Marks,
// filterable by entity type, Trust Mark type and free text, and paged.
//
// ---------------------------------------------------------------------------
// rcbj's answer (2026-09-24): THE REALM'S OWN SUBTREE, VERIFIED.
//
//   * `trust_anchor` may name only this realm — the default when it is left
//     out ("the responder sets this parameter to its own Entity
//     Identifier") — and anything else is 404 `invalid_trust_anchor`. The
//     collection is of what this realm vouches for; it never crawls a
//     foreign federation from a configured anchor down.
//   * AN ENTITY IS COLLECTED ONLY WHEN ITS TRUST CHAIN TO THIS REALM
//     VALIDATES — the draft's "Only Entities that have a valid Trust Chain to
//     the Trust Anchor" — resolved with this realm's own Federation Entity
//     Key as the anchor, so its metadata is the RESOLVED metadata (every
//     policy above it applied) and its Trust Marks are the ones 7.3 verifies
//     (`oidfed.ts`'s `verifiedMarks()`). An entity that does not validate is
//     left out and named among the crawl's problems.
//
// ---------------------------------------------------------------------------
// THE CRAWL DIALS URLS OTHER ENTITIES PUBLISHED, AND THIS IS THE ARGUMENT
// (the root CLAUDE.md's "dials a caller's URL" index).
//
// Going DOWN a federation means asking each Intermediate for its list, and
// then each entity on the list for its Entity Configuration: URLs this
// service did not choose. What bounds them:
//
//   * **A LIST IS FETCHED ONLY FROM AN ENTITY WHOSE CHAIN ALREADY VALIDATED**,
//     at the `federation_list_endpoint` its RESOLVED metadata names — signed
//     by its own key, which a statement signed by its superior pinned, and
//     so on up to this realm's key. An unverified entity is never asked for
//     anything but what validating it takes.
//   * **AN ENTITY ON A LIST IS ONLY RESOLVED** — `trust_chain.ts`'s walk,
//     with every bound it already argues (hints, depth, fetches per
//     resolution, loops), towards THIS REALM as the one anchor.
//   * **THE CRAWL AS A WHOLE IS BOUNDED**: `oidfed.collectionMaxEntities`
//     collected, `oidfed.collectionMaxFetches` lists fetched,
//     `oidfed.maxChainDepth` levels down, and an entity already seen is not
//     seen again (a list that names an ancestor loops nowhere).
//   * **EVERY FETCH IS `fetchPublished()`**: https with the certificate
//     verified, no redirect, a body cap and a timeout, and in product mode no
//     internal address.
//   * **NOTHING ANONYMOUS STARTS IT.** The endpoint answers from what a crawl
//     found; a crawl is the `oidfed.collection-crawl` job or an
//     administrator's act (Crawl now on `/admin/oidfed`,
//     `POST /admin-api/oidfed/crawl-collection`).
//
// This service's own realms are never dialled — they are resolved in
// process, as they are for every resolution (`trust_chain.ts`).
//
// ---------------------------------------------------------------------------
// WHERE A CRAWL IS KEPT, AND WHY A JOB NEEDS `global.publicBaseUrl`.
//
// A crawl is kept in the realm's register (`ou=oidfed`, the `collection`
// entry), so every node and every request worker answers from the same one
// — a per-process copy would answer differently from each. It is written
// with the Entity Identifier it was crawled for, and used while that is the
// realm's identifier and it is younger than `oidfed.collectionMaxAgeS`.
//
// **AND IT IS NEVER THE WHOLE ANSWER.** What this service can collect IN
// PROCESS — its own realms, and anything an earlier resolution holds — is
// collected fresh (or from this process's cache, whose key changes with the
// realms and the active subordinates), and the kept crawl adds only the
// entities it reached THROUGH a subordinate that is still active. So a realm
// created after the crawl is there at once, and a foreign subordinate
// suspended or revoked after it takes everything beneath it out at once —
// the first answer kept the crawl whole, and a realm made a minute after a
// Crawl now went unlisted for a day. What waits for the next crawl is only
// what needs one: a new foreign subordinate's own subtree.
//
// A realm's Entity Identifier is its issuer AS SEEN FROM A REQUEST'S HOST
// (`oidfed/CLAUDE.md`), and a scheduled job has no request. So the job runs
// only where `global.publicBaseUrl` pins the base, and says so on
// `/admin/scheduler` otherwise; Crawl now uses the administrator's request.
//
// WITH NO CRAWL TO ANSWER FROM, the endpoint collects IN PROCESS ONLY — this
// service's own realms, and a registered subordinate whose chain an earlier
// resolution already holds — with no fetch at all, and keeps the result for
// `oidfed.collectionCacheS` per process (`oidfed.collections`, described to
// `/admin/caches`), so a stream of anonymous requests does not sign a
// statement per realm each.
//
// The response is UNSIGNED, and the draft says what that means: it is
// informational, and "proper trust validation … still MUST be done" by
// whoever relies on an entity it names.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
import EntityStatement = require('./entity_statement');
import OidfedStore = require('./oidfed_store');
import PagePointer = require('./page_pointer');

type Json = any;
type Req = any;

const ENDPOINT = 'collection';
const CRAWL_JOB = 'oidfed.collection-crawl';

// 5.2.2's informational metadata — what the draft's UI Info carries.
const UI_CLAIMS = Object.freeze(['display_name', 'description', 'keywords',
                                 'logo_uri', 'policy_uri', 'information_uri']);
// The Entity Info claims (draft 01).
const ENTITY_CLAIMS = Object.freeze(['entity_id', 'entity_types', 'ui_infos',
                                     'trust_marks']);
// Where `display_name` is absent, the name the entity type's own metadata
// gives (the draft's "Mapping Entity Configuration Claims").
const DISPLAY_FALLBACK: Record<string, string> = {
  openid_relying_party: 'client_name',
  oauth_client: 'client_name',
  oauth_resource: 'resource_name'
};
// The most problems a crawl keeps, and the most marks one entity carries.
const MAX_PROBLEMS = 50;
const MAX_MARKS = 20;

// Local collections this process made, per realm, keyed by the Entity
// Identifier they were made for. A CACHE: re-derivable, unpersisted.
const collections = realms.map();
const collectionCount = cacheRegistry.register({
  name: 'oidfed.collections',
  title: 'OpenID Federation collections, made in process',
  description: 'The Entity Collection as this process makes it without ' +
    'fetching anything — this service\'s own realms, and subordinates ' +
    'already resolved — used where no crawl has been kept, so anonymous ' +
    'requests do not sign statements for every realm each (#136).',
  owner: 'oidfed/entity_collection.ts',
  scope: 'realm',
  kind: 'cache',
  maxEntries: function (): number {
    return 8;
  },
  bound: 'Enforced: 8 per realm (one per host the realm is reached by), ' +
    'the oldest evicted first.',
  lifetime: function (): string {
    return 'oidfed.collectionCacheS.';
  },
  eject: cacheRegistry.realmMapEjector(realms, collections,
    function (value: Json, key: unknown, now: number): boolean {
      return !value || Number(value.expMs) <= now;
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, collections,
      function (value: Json, key: unknown): object {
        return { key: cacheRegistry.digestKey(key),
                 validUntil: Number(value && value.expMs) || 0 };
      });
  }
});

interface EntityInfo {
  entity_id: string;
  entity_types: string[];
  ui_infos: Json;
  trust_marks: Json[];
  superior: string;
  // The realm's immediate subordinate this entity was reached through (the
  // entity itself, for one of those), so a kept crawl can drop what was
  // reached through a subordinate that is no longer active.
  via: string;
  expMs: number;
}

interface Collected {
  entityId: string;
  crawledAt: number;
  dialled: boolean;
  truncated: boolean;
  problems: string[];
  entities: EntityInfo[];
}

interface EntityCollectionDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  store: typeof OidfedStore;
  // Lazily: the entity (`oidfed.ts`, which requires this module back), the
  // key table, the outbound requester and the scheduler.
  entity: () => Json;
  keys: () => Json;
  fedHttp: () => Json;
  scheduler: () => Json;
  now: () => number;
}

interface Outcome {
  ok: boolean;
  code?: string;
  why?: string;
  error?: string;
  status?: number;
  body?: Json;
  [key: string]: Json;
}

class EntityCollection {
  static readonly CRAWL_JOB = CRAWL_JOB;
  static readonly UI_CLAIMS = UI_CLAIMS;
  static readonly ENTITY_CLAIMS = ENTITY_CLAIMS;

  constructor(private readonly deps: EntityCollectionDeps) {
    deps.log.debug("Entering EntityCollection.constructor().");
    deps.log.debug("Leaving EntityCollection.constructor().");
  }

  static defaultDeps(): EntityCollectionDeps {
    helpers.log.debug("Entering EntityCollection.defaultDeps().");
    helpers.log.debug("Leaving EntityCollection.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms,
      errorCodes: errorCodes, store: OidfedStore,
      entity: function (): Json {
        return require('./oidfed');
      },
      keys: function (): Json {
        return require('./federation_keys');
      },
      fedHttp: function (): Json {
        return require('../federation/federation_http');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  private refuse(code: string, why: string, error: string,
                 status: number): Outcome {
    this.deps.log.debug("Entering EntityCollection.refuse(). " + code);
    this.deps.log.debug("Leaving EntityCollection.refuse().");
    return { ok: false, code: code, why: why, error: error, status: status };
  }

  private int(key: string, floor: number): number {
    this.deps.log.debug("Entering EntityCollection.int(). " + key);
    this.deps.log.debug("Leaving EntityCollection.int().");
    return Math.max(floor, Number(this.deps.config.value(key)));
  }

  // ===========================================================================
  // COLLECTING
  // ===========================================================================

  // -------------------------------------------------------------------------
  // THE UI INFOS of one resolved entity: per entity type, the informational
  // claims its resolved metadata holds — each with its language-tagged
  // forms (`display_name#de`) — and `display_name` from the type's own name
  // where it has none.
  // -------------------------------------------------------------------------
  static uiInfosOf(metadata: Json): Json {
    helpers.log.debug("Entering EntityCollection.uiInfosOf().");
    const out: Json = {};
    Object.keys(metadata || {}).sort().forEach(function (type: string): void {
      const m = metadata[type] || {};
      const u: Json = {};
      Object.keys(m).forEach(function (name: string): void {
        if (UI_CLAIMS.indexOf(name.split('#')[0]) >= 0) {
          u[name] = m[name];
        }
      });
      const fallback = DISPLAY_FALLBACK[type];
      if (fallback && u.display_name === undefined) {
        Object.keys(m).forEach(function (name: string): void {
          const parts = name.split('#');
          if (parts[0] === fallback) {
            u['display_name' + (parts[1] ? '#' + parts[1] : '')] = m[name];
          }
        });
      }
      if (Object.keys(u).length) {
        out[type] = u;
      }
    });
    helpers.log.debug("Leaving EntityCollection.uiInfosOf().");
    return out;
  }

  // The immediate subordinates of one node of the walk: in process for this
  // realm and for a realm of this service, fetched from a foreign
  // Intermediate's list endpoint — only when the crawl may dial, and while
  // its budget of list fetches lasts.
  private async childrenOf(entity: Json, req: Req, node: Json, dial: boolean,
                           budget: Json): Promise<Json> {
    const { log, config, fedHttp } = this.deps;
    log.debug("Entering EntityCollection.childrenOf(). " + node.id);
    const idsOf = function (facts: Json[]): string[] {
      log.debug("Entering idsOf().");
      log.debug("Leaving idsOf().");
      return facts.map(function (s: Json): string {
        return String(s.entityId);
      });
    };
    if (node.self) {
      const ids = idsOf(await entity.subordinateFacts(req));
      log.debug("Leaving EntityCollection.childrenOf(). This realm's.");
      return { ids: ids };
    }
    const local = entity.localRealmOf(node.id, req);
    if (local) {
      const facts = await entity.inRealm(local, req, function (r: Req) {
        return entity.subordinateFacts(r);
      });
      log.debug("Leaving EntityCollection.childrenOf(). A realm's.");
      return { ids: idsOf(facts) };
    }
    if (!dial) {
      log.debug("Leaving EntityCollection.childrenOf(). May not dial.");
      return { ids: [], problem: node.id + ': an Intermediate outside this ' +
               'service, whose subordinates only a crawl fetches.' };
    }
    if (budget.fetches >= budget.maxFetches) {
      budget.exhausted = true;
      log.debug("Leaving EntityCollection.childrenOf(). Out of fetches.");
      return { ids: [], problem: node.id + ': not listed — the crawl ' +
               'fetched oidfed.collectionMaxFetches lists already.' };
    }
    budget.fetches += 1;
    const got: Json = await fedHttp().fetchPublished(node.listUrl, {
      accept: 'application/json',
      timeoutMs: Math.max(100, Number(config.value('oidfed.fetchTimeoutMs'))),
      maxBytes: Math.max(1024, Number(config.value('oidfed.fetchMaxBytes')))
    });
    if (!got.ok) {
      log.debug("Leaving EntityCollection.childrenOf(). Fetch failed.");
      return { ids: [], problem: node.id + ': its list could not be ' +
               'fetched (' + String(got.why || got.status) + ').' };
    }
    let list: Json = null;
    try {
      list = JSON.parse(got.body ? got.body.toString('utf8') : '');
    } catch (e: any) {
      log.debug("Caught in EntityCollection.childrenOf(): " +
                ((e && e.message) || e));
      list = null;
    }
    if (!Array.isArray(list)) {
      log.debug("Leaving EntityCollection.childrenOf(). Not a list.");
      return { ids: [], problem: node.id + ': its list endpoint did not ' +
               'answer a JSON array (8.2.2).' };
    }
    const ids = list.filter(function (one: Json): boolean {
      return typeof one === 'string' && EntityStatement.isEntityId(one);
    }).slice(0, budget.maxEntities);
    log.debug("Leaving EntityCollection.childrenOf(). " + ids.length);
    return { ids: ids };
  }

  // -------------------------------------------------------------------------
  // COLLECT everything beneath this realm (see the header): breadth first,
  // each entity resolved to this realm before it is kept and before its own
  // list is asked for. `dial` lets the walk fetch; without it only what this
  // process can answer in process is collected.
  // -------------------------------------------------------------------------
  async collect(entity: Json, req: Req, dial: boolean): Promise<Collected> {
    const { log, keys, now } = this.deps;
    log.debug("Entering EntityCollection.collect(). dial=" + dial);
    const selfId = String(entity.entityId(req));
    await keys().ensure();
    const anchor = { entityId: selfId, jwks: keys().jwks() };
    const tc = entity.chainResolver(req, dial);
    const maxDepth = this.int('oidfed.maxChainDepth', 2);
    const budget: Json = {
      fetches: 0, exhausted: false,
      maxFetches: this.int('oidfed.collectionMaxFetches', 0),
      maxEntities: this.int('oidfed.collectionMaxEntities', 1)
    };
    const out: EntityInfo[] = [];
    const problems: string[] = [];
    const seen: Record<string, boolean> = {};
    seen[selfId] = true;
    const queue: Json[] = [{ id: selfId, depth: 0, self: true, via: '' }];
    let truncated = false;
    const problem = function (text: string): void {
      log.debug("Entering problem().");
      if (problems.length < MAX_PROBLEMS) {
        problems.push(text);
      }
      log.debug("Leaving problem().");
    };
    while (queue.length && !truncated) {
      const node = queue.shift();
      const kids: Json = await this.childrenOf(entity, req, node, dial,
                                               budget);
      if (kids.problem) {
        problem(kids.problem);
      }
      const ids: string[] = kids.ids.slice().sort();
      for (let i = 0; i < ids.length; i++) {
        const id = ids[i];
        if (seen[id]) {
          continue;
        }
        seen[id] = true;
        if (out.length >= budget.maxEntities) {
          truncated = true;
          break;
        }
        const resolved: Json = await tc.resolve(id, [anchor]);
        if (!resolved.ok) {
          problem(id + ': ' + String(resolved.why));
          continue;
        }
        const marks: Json[] = await entity.verifiedMarks(resolved, tc, anchor,
                                                        req);
        const metadata = resolved.metadata || {};
        const expMs = marks.reduce(function (min: number, m: Json): number {
          return Number.isFinite(m.exp) ? Math.min(min, m.exp * 1000) : min;
        }, Number(resolved.exp) * 1000);
        out.push({
          entity_id: id,
          entity_types: Object.keys(metadata).sort(),
          ui_infos: EntityCollection.uiInfosOf(metadata),
          trust_marks: marks.slice(0, MAX_MARKS).map(function (m: Json) {
            return { trust_mark_type: m.trust_mark_type,
                     trust_mark: m.trust_mark };
          }),
          superior: String(node.id),
          via: node.self ? id : String(node.via),
          expMs: expMs
        });
        const fe = metadata.federation_entity || {};
        if (typeof fe.federation_list_endpoint === 'string' &&
            node.depth + 1 < maxDepth) {
          queue.push({ id: id, depth: node.depth + 1,
                       listUrl: fe.federation_list_endpoint,
                       via: node.self ? id : String(node.via) });
        }
      }
    }
    out.sort(function (a: EntityInfo, b: EntityInfo): number {
      return a.entity_id < b.entity_id ? -1 : a.entity_id > b.entity_id ? 1
                                                                        : 0;
    });
    log.debug("Leaving EntityCollection.collect(). " + out.length +
              " entities, " + problems.length + " problems.");
    return { entityId: selfId, crawledAt: now(), dialled: dial,
             truncated: truncated || budget.exhausted, problems: problems,
             entities: out };
  }

  // -------------------------------------------------------------------------
  // CRAWL NOW (the act, and the job): collect with fetching allowed, and keep
  // the result for every node. `{ ok, entities, problems, view }`.
  // -------------------------------------------------------------------------
  async crawlNow(entity: Json, req: Req): Promise<Outcome> {
    const { log, store, errorCodes } = this.deps;
    log.debug("Entering EntityCollection.crawlNow().");
    let got: Collected;
    try {
      got = await this.collect(entity, req, true);
    } catch (e: any) {
      log.error(errorCodes.tag('STS-OIDFED-0066') + 'oidfed: the Entity ' +
                'Collection crawl failed: ' + ((e && e.stack) || e));
      log.debug("Leaving EntityCollection.crawlNow(). Failed.");
      return { ok: false, code: 'STS-OIDFED-0066',
               why: 'the crawl failed: ' + ((e && e.message) || e) };
    }
    if (!store.put(OidfedStore.KINDS.COLLECTION, '', got.entityId, got)) {
      log.error(errorCodes.tag('STS-OIDFED-0066') + 'oidfed: the Entity ' +
                'Collection could not be written to the register.');
      log.debug("Leaving EntityCollection.crawlNow(). Not kept.");
      return { ok: false, code: 'STS-OIDFED-0066',
               why: 'the crawl could not be kept in the register.' };
    }
    collections.clear();
    if (got.problems.length) {
      log.info('oidfed: the Entity Collection crawl left ' +
               got.problems.length + ' entities out: ' +
               got.problems.slice(0, 5).join('; '));
    }
    log.debug("Leaving EntityCollection.crawlNow(). " + got.entities.length);
    return { ok: true, entities: got.entities.length,
             problems: got.problems.length, view: this.view(entity, req) };
  }

  // The job's crawl: a request that is only a base, which is what
  // `global.publicBaseUrl` makes of every request (`helpers.baseUrlOf()`).
  async scheduledCrawl(): Promise<Json> {
    const { log, entity } = this.deps;
    log.debug("Entering EntityCollection.scheduledCrawl().");
    const req = { headers: {}, query: {}, params: {}, url: '/',
                  originalUrl: '/', method: 'GET', protocol: 'https',
                  secure: true, socket: {}, connection: {},
                  get: function (): string {
                    return '';
                  } };
    const got = await this.crawlNow(entity().instance(), req);
    log.debug("Leaving EntityCollection.scheduledCrawl(). " + got.ok);
    if (!got.ok) {
      throw new Error(String(got.why));
    }
    return { summary: got.entities + ' entities collected' +
             (got.problems ? ', ' + got.problems + ' left out' : '') };
  }

  // Why the job cannot run now, or ''.
  jobOff(): string {
    const { log, config } = this.deps;
    log.debug("Entering EntityCollection.jobOff().");
    const pinned = String(config.value('global.publicBaseUrl') || '').trim();
    log.debug("Leaving EntityCollection.jobOff().");
    return pinned ? ''
      : 'needs global.publicBaseUrl: a job has no request to take the ' +
        'realm\'s Entity Identifier from — Crawl now on /admin/oidfed uses ' +
        'the administrator\'s';
  }

  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering EntityCollection.scheduleJobs().");
    const s = scheduler();
    if (s.job(CRAWL_JOB)) {
      log.debug("Leaving EntityCollection.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: CRAWL_JOB,
      title: 'OpenID Federation Entity Collection crawl',
      describe: 'Walks every entity beneath the realm — each resolved to ' +
                'the realm before its own list is fetched — and keeps what ' +
                'it finds for the collection endpoint (#136).',
      owner: 'oidfed/entity_collection.ts',
      kind: 'cluster', scope: 'realm',
      everySetting: 'oidfed.collectionCrawlS', everySettingUnit: 's',
      off: function (): string {
        return self.jobOff();
      },
      manual: true,
      run: function (): Promise<Json> {
        return self.scheduledCrawl();
      }
    });
    log.debug("Leaving EntityCollection.scheduleJobs(). On the scheduler.");
  }

  // What the in-process collection depends on, as one digest: the realm's
  // REGISTER GENERATION (`oidfed.ts` — replaced, and replicated, by every
  // act that changes what a chain resolves to, a Trust Mark included), the
  // realms (each a subordinate in the default topology) and the realm's
  // active subordinates with their last change. A cached collection is used
  // only under the digest it was made with, so a new realm, a suspension or
  // a mark is never hidden behind the cache's lifetime — in this process or
  // in any other.
  private fingerprint(entity: Json, req: Req): string {
    const { log, realms } = this.deps;
    log.debug("Entering EntityCollection.fingerprint().");
    const parts: string[] = realms.list().map(function (r: Json): string {
      return String(r.id) + ':' + String(r.createdAt || '');
    });
    parts.push('generation:' + String(entity.generation()));
    entity.activeSubordinates(req).forEach(function (s: Json): void {
      parts.push(String(s.key) + '@' + String(s.updatedAt || 0));
    });
    const out = OidfedStore.digest(parts.sort().join('|'));
    log.debug("Leaving EntityCollection.fingerprint().");
    return out;
  }

  // What this process collects without fetching, from its cache while the
  // fingerprint holds.
  private async inProcess(entity: Json, req: Req): Promise<Collected> {
    const { log, now } = this.deps;
    log.debug("Entering EntityCollection.inProcess().");
    const key = String(entity.entityId(req)) + ' ' +
                this.fingerprint(entity, req);
    const hit = collections.get(key);
    if (hit && Number(hit.expMs) > now()) {
      collectionCount.hit();
      log.debug("Leaving EntityCollection.inProcess(). Cached.");
      return hit.collected;
    }
    collectionCount.miss();
    const collected = await this.collect(entity, req, false);
    const ttlMs = this.int('oidfed.collectionCacheS', 0) * 1000;
    if (ttlMs > 0) {
      cacheRegistry.makeRoom(collections, 8, { counter: collectionCount,
        expired: function (v: Json): boolean {
          return Number(v && v.expMs) <= now();
        } });
      collections.set(key, { collected: collected, expMs: now() + ttlMs });
    }
    log.debug("Leaving EntityCollection.inProcess(). Made.");
    return collected;
  }

  // -------------------------------------------------------------------------
  // THE COLLECTION TO ANSWER FROM (see the header): what this process
  // collects in process, and — from the kept crawl, while it is for this
  // identifier and young enough — what the crawl reached through a
  // subordinate that is still active.
  // -------------------------------------------------------------------------
  async current(entity: Json, req: Req): Promise<Collected> {
    const { log, store, now } = this.deps;
    log.debug("Entering EntityCollection.current().");
    const selfId = String(entity.entityId(req));
    const local = await this.inProcess(entity, req);
    const kept = store.get(OidfedStore.KINDS.COLLECTION, '');
    const maxAgeMs = this.int('oidfed.collectionMaxAgeS', 60) * 1000;
    if (!kept || !kept.data || kept.data.entityId !== selfId ||
        Number(kept.data.crawledAt) + maxAgeMs <= now()) {
      log.debug("Leaving EntityCollection.current(). In process only.");
      return local;
    }
    const active: Record<string, boolean> = {};
    entity.activeSubordinates(req).forEach(function (s: Json): void {
      active[String(s.entityId)] = true;
    });
    const have: Record<string, boolean> = {};
    local.entities.forEach(function (e: EntityInfo): void {
      have[e.entity_id] = true;
    });
    const extra = (kept.data.entities || []).filter(function (e: EntityInfo) {
      return !have[e.entity_id] && active[String(e.via)] === true;
    });
    const entities = local.entities.concat(extra);
    entities.sort(function (a: EntityInfo, b: EntityInfo): number {
      return a.entity_id < b.entity_id ? -1 : a.entity_id > b.entity_id ? 1
                                                                        : 0;
    });
    log.debug("Leaving EntityCollection.current(). " + extra.length +
              " from the crawl.");
    return { entityId: selfId, crawledAt: local.crawledAt, dialled: true,
             truncated: local.truncated || !!kept.data.truncated,
             problems: local.problems, entities: entities };
  }

  // ===========================================================================
  // THE ENDPOINT
  // ===========================================================================

  // Whether `info` matches the free-text query: its identifier, or any
  // display name, description or keyword it carries, case folded.
  static matches(info: EntityInfo, query: string): boolean {
    helpers.log.debug("Entering EntityCollection.matches().");
    const needle = query.toLowerCase();
    const texts: string[] = [info.entity_id];
    Object.keys(info.ui_infos || {}).forEach(function (type: string): void {
      const u = info.ui_infos[type] || {};
      Object.keys(u).forEach(function (name: string): void {
        const base = name.split('#')[0];
        if (base === 'display_name' || base === 'description' ||
            base === 'keywords') {
          [].concat(u[name]).forEach(function (v: Json): void {
            texts.push(String(v));
          });
        }
      });
    });
    const out = texts.some(function (t: string): boolean {
      return t.toLowerCase().indexOf(needle) >= 0;
    });
    helpers.log.debug("Leaving EntityCollection.matches(). " + out);
    return out;
  }

  // One Entity Info as the request shapes it.
  private shaped(info: EntityInfo, types: string[], entityClaims: string[],
                 uiClaims: string[]): Json {
    const { log } = this.deps;
    log.debug("Entering EntityCollection.shaped().");
    const wants = function (name: string): boolean {
      log.debug("Entering wants(). " + name);
      log.debug("Leaving wants().");
      return !entityClaims.length || entityClaims.indexOf(name) >= 0;
    };
    const one: Json = { entity_id: info.entity_id };
    if (wants('entity_types')) {
      one.entity_types = info.entity_types;
    }
    if (wants('ui_infos')) {
      const ui: Json = {};
      Object.keys(info.ui_infos || {}).forEach(function (type: string): void {
        // With entity_type asked for, only those types — and
        // federation_entity, which the draft lets through.
        if (types.length && types.indexOf(type) < 0 &&
            type !== 'federation_entity') {
          return;
        }
        const u: Json = {};
        Object.keys(info.ui_infos[type]).forEach(function (name: string) {
          if (!uiClaims.length || uiClaims.indexOf(name.split('#')[0]) >= 0) {
            u[name] = info.ui_infos[type][name];
          }
        });
        if (Object.keys(u).length) {
          ui[type] = u;
        }
      });
      if (Object.keys(ui).length) {
        one.ui_infos = ui;
      }
    }
    if (wants('trust_marks') && info.trust_marks.length) {
      one.trust_marks = info.trust_marks;
    }
    log.debug("Leaving EntityCollection.shaped().");
    return one;
  }

  // -------------------------------------------------------------------------
  // THE ANSWER to one request, `{ ok, body }` or a refusal (draft 01's
  // error format). `entity` is the `Oidfed` instance serving the realm.
  // -------------------------------------------------------------------------
  async answer(entity: Json, req: Req, params: Json): Promise<Outcome> {
    const { log, config, realms, now } = this.deps;
    log.debug("Entering EntityCollection.answer().");
    const p = params || {};
    const values = function (v: Json): string[] {
      log.debug("Entering values().");
      const out = [].concat(v === undefined || v === null ? [] : v)
        .map(String).filter(Boolean);
      log.debug("Leaving values().");
      return out;
    };
    const selfId = String(entity.entityId(req));
    const anchors = values(p.trust_anchor);
    if (anchors.length > 1) {
      log.debug("Leaving EntityCollection.answer(). Two anchors.");
      return this.refuse('STS-OIDFED-0060', 'trust_anchor names one Trust ' +
                         'Anchor.', 'invalid_request', 400);
    }
    if (anchors.length && anchors[0] !== selfId) {
      log.debug("Leaving EntityCollection.answer(). Another anchor.");
      return this.refuse('STS-OIDFED-0062', 'this entity collects only the ' +
                         'entities beneath itself; trust_anchor may name ' +
                         selfId + ' alone.', 'invalid_trust_anchor', 404);
    }
    const cap = Math.max(1, Number(config.value('oidfed.listPageMax')));
    const limits = values(p.limit);
    if (limits.length > 1 ||
        (limits.length && !/^[1-9][0-9]{0,8}$/.test(limits[0]))) {
      log.debug("Leaving EntityCollection.answer(). A bad limit.");
      return this.refuse('STS-OIDFED-0060', 'limit is a positive integer.',
                         'invalid_request', 400);
    }
    const limit = limits.length ? Math.min(cap, Number(limits[0])) : cap;
    const entityClaims = values(p.entity_claims);
    const uiClaims = values(p.ui_claims);
    const unknown = entityClaims.filter(function (c: string): boolean {
      return ENTITY_CLAIMS.indexOf(c) < 0;
    }).concat(uiClaims.filter(function (c: string): boolean {
      return UI_CLAIMS.indexOf(c) < 0;
    }));
    if (unknown.length) {
      log.debug("Leaving EntityCollection.answer(). Unsupported claims.");
      return this.refuse('STS-OIDFED-0061', 'this entity does not support ' +
                         'the claim' + (unknown.length > 1 ? 's ' : ' ') +
                         unknown.join(', ') + '.', 'unsupported_claim', 400);
    }
    const queries = values(p.query);
    if (queries.length > 1) {
      log.debug("Leaving EntityCollection.answer(). Two queries.");
      return this.refuse('STS-OIDFED-0060', 'query is given once.',
                         'invalid_request', 400);
    }
    const types = values(p.entity_type);
    const markTypes = values(p.trust_mark_type);
    const collected = await this.current(entity, req);
    const at = now();
    const matching = collected.entities.filter(function (e: EntityInfo) {
      if (Number(e.expMs) <= at) {
        return false;
      }
      if (types.length && !types.some(function (t: string): boolean {
        return e.entity_types.indexOf(t) >= 0;
      })) {
        return false;
      }
      if (markTypes.length && !markTypes.every(function (t: string) {
        return e.trust_marks.some(function (m: Json): boolean {
          return m.trust_mark_type === t;
        });
      })) {
        return false;
      }
      return !queries.length || EntityCollection.matches(e, queries[0]);
    });
    const paged = PagePointer.page(matching, function (e: EntityInfo) {
      return e.entity_id;
    }, String(realms.current().id), ENDPOINT, p.from, limit);
    if (!paged.ok) {
      log.debug("Leaving EntityCollection.answer(). Unknown pointer.");
      return this.refuse('STS-OIDFED-0059', 'from is not, or no longer, a ' +
                         'pointer this entity returned as next.',
                         'page_not_found', 404);
    }
    const self = this;
    const body: Json = {
      entities: paged.page.map(function (e: EntityInfo): Json {
        return self.shaped(e, types, entityClaims, uiClaims);
      }),
      last_updated: Math.floor(Number(collected.crawledAt) / 1000)
    };
    if (paged.next) {
      body.next = paged.next;
    }
    log.debug("Leaving EntityCollection.answer(). " + body.entities.length);
    return { ok: true, body: body };
  }

  // What the console page and the API show of the kept crawl.
  view(entity: Json, req: Req): Json {
    const { log, store, config } = this.deps;
    log.debug("Entering EntityCollection.view().");
    const kept = store.get(OidfedStore.KINDS.COLLECTION, '');
    const d = kept && kept.data;
    const out = {
      crawl: d ? {
        entityId: d.entityId,
        forThisIdentifier: d.entityId === String(entity.entityId(req)),
        crawledAt: new Date(Number(d.crawledAt)).toISOString(),
        entities: (d.entities || []).length,
        truncated: !!d.truncated,
        problems: d.problems || []
      } : null,
      crawlEveryS: Number(config.value('oidfed.collectionCrawlS')),
      jobOff: this.jobOff()
    };
    log.debug("Leaving EntityCollection.view().");
    return out;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<EntityCollection>(
  'oidfed/entity_collection',
  () => new EntityCollection(EntityCollection.defaultDeps()),
  function (instance: EntityCollection): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  EntityCollection: EntityCollection,
  installInstance: (instance: EntityCollection): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  CRAWL_JOB: CRAWL_JOB,
  uiInfosOf: EntityCollection.uiInfosOf,
  collect: slot.forward('collect'),
  crawlNow: slot.forward('crawlNow'),
  current: slot.forward('current'),
  answer: slot.forward('answer'),
  view: slot.forward('view')
};
