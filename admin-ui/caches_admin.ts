// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: caches_admin.ts
//
// ===========================================================================
// MONITORING → CACHES (#74, 2026-09-17): EVERY CACHE THIS SERVICE HOLDS, HOW
// FULL IT IS, HOW MUCH OF IT IS STILL GOOD, AND HOW OFTEN IT WAS WORTH HAVING.
//
// `GET /admin/caches` lists every store `common/cache_registry.js` knows, in
// the two tables `docs/caches.md` has — the caches, then the replay caches
// and nonces — and for each one
// gives its name, what it is for, the file that owns it, whether it is one per
// process or one per trust realm, its size against its bound, how many of its
// entries are still valid and how many have expired without being evicted
// yet, how its entries end, and its hit ratio since the process started.
// `GET /admin/caches?cache=<name>` is one cache's entries, paged, each with
// how long it is still valid, oldest deadline first.
//
// **THE REGISTRY IS THE KNOWLEDGE AND THIS FILE IS ONLY THE DRAWING.** Which
// caches exist is said by the modules that own them, beside their
// declarations; nothing here names one, so a cache added tomorrow appears
// here the day it registers and a cache removed goes with it. What is NOT
// registered — the three things `docs/caches.md` or this page could be read
// as naming that this process does not hold between requests — is the one
// list this file keeps (`NOT_LISTED`), for `encryption_admin.ts`'s reason:
// the interesting question about a page like this is often *is X on it*, and
// a page that lists only the yeses answers it by silence. It listed four
// single-value memos as well until 2026-09-18; each is a registered cache of
// one row now, and the version stamp is described from THIS file (below),
// because `common/version.js` runs in the remote PEP container against a
// thirty-line shim and may require nothing of this service.
//
// **EVERY ROW HAS A BOUND** (2026-09-18, `cache_registry.js`'s header): the
// Max size column never says *unbounded*, says "per realm" for a per-realm
// store (whose Current size counts every realm) beside its fullest realm, and
// the bound's kind — enforced or structural — is under it with how many
// entries were dropped or refused at it.
//
// **KEYS, NEVER VALUES, AND NO CONTROL.** A row is what the registry lets it
// be (`cache_registry.js`'s header): a realm, a key, a deadline. Several of
// these caches hold key material — decrypted signing keys, Kerberos long-term
// keys — and a page that could show one would be a door onto it. There is no
// Clear button either: every bound here is a setting on the page of the
// protocol it belongs to, and emptying a cache by hand is a test's act
// (each owner has a `reset…()` for that), not an operator's.
//
// **A SERVICE PAGE** (`admin_scope.ts`): it shows every realm's partition of
// every per-realm cache and the process-wide ones beside them, so a realm's
// own administrator is refused it, as they are `/admin/encryption`.
//
// **THE FIGURES ARE THE ANSWERING PROCESS'S** — with request workers or a
// cluster, each process has caches of its own and the page says which pid
// drew it. **AND THE OTHER NODES' TOO** (2026-09-18), as far as the one
// channel between nodes carries them: each front process puts a compact
// snapshot of its stores on its membership row (`cluster/cluster.js`,
// refreshed every thirty seconds), and this page draws every snapshot it can
// see that is not its own process's — the other nodes, and this node's front
// process when a request worker is answering. Sizes and counters only: rows
// cannot cross, so a drill-down is always this process's.
//
// **An unknown `cache` is not a 404**: the console's drill-down convention is
// a 200 page saying there is no such record, marked `STS-ADMIN-0021`.
//
// Rule 7: `GET /admin-api/caches` answers `cachesJson()`, the function the
// page's `?format=json` answers, with the same parameters.
//
// TYPESCRIPT, AS A CLASS (#50): `encryption_admin.ts`'s shape — dependencies
// through the constructor, `registerRoutes(app)` called by
// `common/protocol_stack.ts` (18g), and facades for the JavaScript callers.
// ===========================================================================

import admin = require('./admin');
import adminViews = require('../admin-core/admin_views');
import helpers = require('../common/helpers');
import cacheRegistry = require('../common/cache_registry');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import version = require('../common/version');
import cluster = require('../cluster/cluster');
// This thread's identity (#364): a request worker is a thread of this
// process, so the pid alone no longer tells two of them apart.
import WorkerChannel = require('../common/worker_channel');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import CachesPage = require('./web_caches');

type Req = any;
type Res = any;
type Json = any;

const PAGE = '/admin/caches';

// What is NOT registered: three things this page or `docs/caches.md` could
// be read as naming that this process does not hold between requests. Named
// here so their absence is a decision a reader can see. (The four
// single-value memos that were on this list until 2026-09-18 are registered
// caches now.)
/**
 * What is deliberately not registered: things this page or `docs/caches.md`
 * could be read as naming that the process does not hold between requests, each
 * with the reason.
 */
const NOT_LISTED = [
  { what: 'SAML service provider metadata',
    where: 'saml/sp_metadata.ts',
    why: 'stored on the application entry as received, not held in ' +
         'memory; refreshed from the application\'s page' },
  { what: 'A remote PEP\'s policy',
    where: 'xacml-pep/',
    why: 'held by the remote PEP container, not by this process' },
  { what: 'A secret-store login',
    where: 'common/secrets.js',
    why: 'a local of one /admin/secrets report, so a store is logged into ' +
         'once per report; it is gone when the report is drawn, and ' +
         'nothing holds it between requests' }
];

// THE VERSION STAMP, described from here (2026-09-18). `common/version.js`
// keeps the record it read from version.json for the life of the process —
// a cache of one row — and cannot register it itself: that file runs in the
// remote PEP container against a thirty-line shim and may require nothing of
// this service (`xacml-pep/CLAUDE.md`). Its lookups are therefore not counted.
cacheRegistry.register({
  name: 'version.stamp',
  title: 'Version stamp',
  description: 'The build record (M.N.O, the commit, the build instant) ' +
    'read from version.json once, which every surface that draws a version ' +
    'reads.',
  owner: 'common/version.js',
  scope: 'process',
  counted: false,
  notCountedWhy: 'common/version.js also runs in the remote PEP container ' +
    'and may not require the registry',
  maxEntries: function (): number {
    return 1;
  },
  bound: 'Structural: one record.',
  lifetime: function (): string {
    return 'For the life of the process: the build cannot change while it ' +
      'runs.';
  },
  entries: function (): unknown[] {
    const v: any = version.load();
    return v && v.version
      ? [{ key: String(v.version) + (v.stamped ? ' (stamped)' : ' (computed)'),
           validUntil: null, basis: 'no expiry' }]
      : [];
  }
});

interface CachesAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  cacheRegistry: typeof cacheRegistry;
  errorCodes: typeof errorCodes;
  cluster: typeof cluster;
  now: () => number;
}

/**
 * Monitoring → Caches: every cache and replay store the registry knows, its
 * size against its bound, how much of it is still valid, and its hit ratio.
 */
class CachesAdmin {
  /**
   * See the module's `NOT_LISTED`.
   */
  static readonly NOT_LISTED = NOT_LISTED;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the console shell, the cache registry and the
   * cluster
   */
  constructor(private readonly deps: CachesAdminDeps) {
    deps.log.debug("Entering CachesAdmin.constructor().");
    deps.log.debug("Leaving CachesAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): CachesAdminDeps {
    helpers.log.debug("Entering CachesAdmin.defaultDeps().");
    helpers.log.debug("Leaving CachesAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      adminViews: adminViews,
      cacheRegistry: cacheRegistry,
      errorCodes: errorCodes,
      cluster: cluster,
      now: Date.now
    };
  }

  // A repeated parameter arrives as an array; the first one wins, as it does
  // in `listViewOf()`.
  private firstOf(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.firstOf().");
    const one = Array.isArray(value) ? value[0] : value;
    log.debug("Leaving CachesAdmin.firstOf().");
    return one === undefined || one === null || typeof one === 'object'
      ? '' : String(one);
  }

  // "4 min 10 s", "2 h 5 min", "3 d 4 h" — two units at most.
  /**
   * Says a duration in at most two units: "4 min 10 s", "2 h 5 min".
   *
   * @param ms - the duration in milliseconds
   * @returns the duration as text
   */
  span(ms: number): string {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.span().");
    const s = Math.max(0, Math.round(ms / 1000));
    const units: Array<[number, string]> = [[86400, 'd'], [3600, 'h'],
                                             [60, 'min'], [1, 's']];
    const parts: string[] = [];
    let left = s;
    units.forEach(function (unit: [number, string]): void {
      if (parts.length < 2 && (left >= unit[0] || (unit[0] === 1 &&
                                                   !parts.length))) {
        const n = Math.floor(left / unit[0]);
        left -= n * unit[0];
        parts.push(n + ' ' + unit[1]);
      }
    });
    log.debug("Leaving CachesAdmin.span().");
    return parts.join(' ');
  }

  // How long one row is still good, as a sentence.
  /**
   * Says how long one cache entry is still good, or how long ago it expired.
   *
   * @param row - one entry row from the registry
   * @param at - the current time in milliseconds
   * @returns the remaining time as a sentence
   */
  remainingText(row: Json, at: number): string {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.remainingText().");
    let text: string;
    if (row.validUntil !== null) {
      text = row.validUntil > at
        ? this.span(row.validUntil - at)
        : 'expired ' + this.span(at - row.validUntil) + ' ago';
    } else if (row.basis === 'no expiry' || row.basis === 'content-keyed') {
      text = row.basis === 'content-keyed'
        ? 'no expiry (keyed by content)' : 'no expiry';
    } else if (/^(until|held) /.test(row.basis)) {
      // A basis that is already a sentence ("until rotated or adopted").
      text = row.valid ? row.basis : 'stale';
    } else {
      text = row.valid
        ? 'until the ' + row.basis + ' changes'
        : 'stale: the ' + row.basis + ' has changed';
    }
    log.debug("Leaving CachesAdmin.remainingText().");
    return text;
  }

  private entryJson(row: Json, at: number): Json {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.entryJson().");
    const out = {
      realm: row.realm,
      key: row.key,
      valid: row.valid,
      validUntil: row.validUntil === null
        ? null : new Date(row.validUntil).toISOString(),
      remainingSeconds: row.validUntil === null
        ? null : Math.round((row.validUntil - at) / 1000),
      basis: row.basis,
      remaining: this.remainingText(row, at)
    };
    log.debug("Leaving CachesAdmin.entryJson().");
    return out;
  }

  // THE VIEW MODEL: the list, or one cache when `cache` is named. One
  // function for the page's `?format=json` and for `GET /admin-api/caches`.
  /**
   * Builds the view model: the list of caches, or one cache's entries when the
   * query names `cache`.
   *
   * One function for the page's `?format=json` and `GET /admin-api/caches`.
   * @param query - the request's query (`cache`, and paging)
   * @returns the caches or the one cache's page of entries
   */
  cachesJson(query?: Json): Json {
    const { log, cacheRegistry, adminViews, now } = this.deps;
    const self = this;
    log.debug("Entering CachesAdmin.cachesJson().");
    const q = query || {};
    const at = now();
    const base = { generatedAt: new Date(at).toISOString(),
                   pid: WorkerChannel.processTag() };
    const wanted = self.firstOf(q.cache);
    if (!wanted) {
      const caches = cacheRegistry.report(at);
      const out = Object.assign(base, {
        caches: caches,
        totals: {
          caches: caches.length,
          entries: caches.reduce(function (n: number, c: Json): number {
            return n + c.size;
          }, 0),
          expired: caches.reduce(function (n: number, c: Json): number {
            return n + c.expired;
          }, 0)
        },
        notListed: NOT_LISTED,
        otherProcesses: self.otherProcesses(at)
      });
      log.debug("Leaving CachesAdmin.cachesJson(). " + caches.length +
                " cache(s).");
      return out;
    }
    const detail = cacheRegistry.detail(wanted, at);
    if (!detail) {
      log.debug("Leaving CachesAdmin.cachesJson(). No such cache.");
      return Object.assign(base, { cache: wanted, found: false,
                                   known: cacheRegistry.names() });
    }
    const paged = adminViews.pagedRows(q, detail.rows, { noun: 'entries' });
    const out = Object.assign(base, {
      cache: wanted,
      found: true,
      summary: detail.summary,
      entries: paged.shown.map(function (row: Json): Json {
        return self.entryJson(row, at);
      }),
      entriesPaging: adminViews.pagingJson(paged.paging),
      paging: paged.paging
    });
    log.debug("Leaving CachesAdmin.cachesJson(). " + wanted + ", " +
              detail.rows.length + " entr(ies).");
    return out;
  }

  // THE OTHER PROCESSES' FIGURES (2026-09-18): every cache snapshot on a
  // live membership row that is not this process's own — the other nodes,
  // and this node's front process when a request worker draws the page.
  // Read from `cluster.snapshot()`, which is at most a heartbeat old, and the
  // snapshot itself is at most thirty seconds older; each says when it was
  // taken. Empty without a cluster.
  /**
   * Reads every other process's cache snapshot from the live cluster
   * membership: the other nodes, and the front process when a request worker
   * draws the page.
   *
   * Each snapshot says when it was taken; empty without a cluster.
   * @param at - the current time in milliseconds
   * @returns one row per other process
   */
  otherProcesses(at: number): Json[] {
    const { log, cluster, cacheRegistry } = this.deps;
    log.debug("Entering CachesAdmin.otherProcesses().");
    let snap: Json = null;
    try {
      snap = cluster.snapshot();
    } catch (e) {
      log.debug("Caught in CachesAdmin.otherProcesses(): " +
                ((e && e.message) || e));
      snap = null;
    }
    const state = snap && snap.state;
    const selfId = String(cluster.nodeId() || '');
    const registered: Json = {};
    cacheRegistry.report(at).forEach(function (c: Json): void {
      registered[c.name] = { title: c.title, scope: c.scope };
    });
    const out: Json[] = [];
    ((state && state.nodes) || []).forEach(function (node: Json): void {
      const info = (node && node.info) || {};
      const report = info.caches;
      if (!report || !Array.isArray(report.caches) || node.leftAt ||
          (String(report.pid) === WorkerChannel.processTag() &&
           node.nodeId === selfId)) {
        return;
      }
      // Each row named and scoped as this process registers it: a row
      // published by another node carries only its counters, and a page
      // drawn from this answer has no registry to ask (#446).
      const caches = report.caches.map(function (row: unknown): Json {
        const one = cacheRegistry.unpackSnapshotRow(row);
        const here = registered[one.name] || {};
        return Object.assign({ scope: here.scope }, one,
                             { title: here.title || one.name });
      });
      out.push({
        nodeId: String(node.nodeId || ''),
        name: String(node.name || ''),
        host: String(info.host || ''),
        pid: report.pid,
        thisNode: node.nodeId === selfId,
        takenAt: new Date(Number(report.at) || 0).toISOString(),
        ageSeconds: Math.max(0, Math.round((at - Number(report.at)) / 1000)),
        caches: caches,
        totals: {
          entries: caches.reduce(function (n: number, c: Json): number {
            return n + c.size;
          }, 0),
          evictions: caches.reduce(function (n: number, c: Json): number {
            return n + c.evictions;
          }, 0),
          refusals: caches.reduce(function (n: number, c: Json): number {
            return n + c.refusals;
          }, 0)
        }
      });
    });
    log.debug("Leaving CachesAdmin.otherProcesses(). " + out.length +
              " other process(es).");
    return out;
  }

  // The JSON the page answers: `paging` is the drawing's, with its parameter
  // name and noun, and `entriesPaging` is what a client walks.
  private publicJson(json: Json): Json {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.publicJson().");
    const out = Object.assign({}, json);
    delete out.paging;
    log.debug("Leaving CachesAdmin.publicJson().");
    return out;
  }

  // For `mgmt-api/admin_api.ts`.
  /**
   * Answers the page's JSON for `mgmt-api/admin_api.ts` (rule 7), the same
   * shape `?format=json` answers.
   *
   * @param query - the request's query
   * @returns the public JSON view
   */
  cachesView(query?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.cachesView().");
    log.debug("Leaving CachesAdmin.cachesView().");
    return this.publicJson(this.cachesJson(query));
  }

  // DRAWN BY `web_caches.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private body(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering CachesAdmin.body().");
    const drawn = CachesPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving CachesAdmin.body().");
    return drawn;
  }

  private renderCaches(req: Req, res: Res): void {
    const { log, admin, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering CachesAdmin.renderCaches().");
    const json = self.publicJson(self.cachesJson(req.query));
    if (json.cache === undefined) {
      admin.respond(req, res, json, 'Caches', PAGE, self.body(req, json));
      log.debug("Leaving CachesAdmin.renderCaches(). The list.");
      return;
    }
    const title = json.found ? json.summary.title : 'No such cache';
    const up = admin.upTo(PAGE, title, {});
    if (!json.found) {
      errorCodes.mark(res, 'STS-ADMIN-0021');
    }
    admin.respond(req, res, json, 'Caches — ' + title, PAGE,
                  self.body(req, json), up);
    log.debug("Leaving CachesAdmin.renderCaches(). One cache.");
  }

  /**
   * Registers `GET /admin/caches`, the page and its `?format=json`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CachesAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.renderCaches(req, res);
      log.debug('Leaving GET ' + PAGE + '.');
    });
    log.debug("Leaving CachesAdmin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2): `common/
// protocol_stack.ts` builds one and calls `installInstance()`; the exports
// below forward to it. A process that never runs the root gets a default
// instance (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// EJECTING WHAT HAS EXPIRED IS A SCHEDULER JOB (#49 P5): `caches.eject-expired`,
// a QUIET PER-PROCESS job every minute — every process holds its own copy of
// every store — calling `cacheRegistry.ejectExpired()`, which calls each
// store's own `eject()`. HERE, beside the page that reports the stores,
// because `cache_registry.js` is a leaf the parent project loads and may not
// reach the scheduler. Switched off, like any job, by `scheduler.disabledJobs`.
// ---------------------------------------------------------------------------
const EJECT_JOB = 'caches.eject-expired';

function registerEjectJob(): void {
  helpers.log.debug("Entering registerEjectJob().");
  const scheduler = require('../cluster/scheduler');
  if (scheduler.job(EJECT_JOB)) {
    helpers.log.debug("Leaving registerEjectJob(). Registered.");
    return;
  }
  const registry = require('../common/cache_registry');
  scheduler.register({
    id: EJECT_JOB,
    title: 'Expired cache entries ejection',
    describe: 'Deletes, in this process, every cache and replay-store entry ' +
              'whose lifetime has passed — housekeeping only: each store ' +
              'still refuses an expired entry where it reads it.',
    owner: 'admin-ui/caches_admin.ts',
    kind: 'per-process', quiet: true,
    everyMs: function (): number {
      return 60000;
    },
    run: function (ctx: any): any {
      const done = registry.ejectExpired(ctx.nowMs());
      if (done.failed.length) {
        helpers.log.warn(errorCodes.tag('STS-CORE-0102') + 'caches: ' +
                         done.failed.length + ' store(s) could not eject ' +
                         'their expired entries: ' + done.failed.join('; '));
      }
      return { ejected: done.ejected, stores: Object.keys(done.byCache)
        .length, failed: done.failed.length };
    }
  });
  helpers.log.debug("Leaving registerEjectJob().");
}

const slot = new InstanceSlot<CachesAdmin>(
  'admin-ui/caches_admin',
  () => new CachesAdmin(CachesAdmin.defaultDeps()),
  function (): void {
    registerEjectJob();
  },
  helpers.log);

// Standalone, build the default now, as every console module does.
slot.buildNowUnlessDeferred();

/**
 * Monitoring → Caches: every cache this service holds, how full it is, how much
 * of it is still good and how often it was worth having.
 *
 * The registry is the knowledge and this file is only the drawing; it also
 * registers the per-process job that ejects expired entries.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  CachesAdmin: CachesAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: CachesAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts` (rule 7): the page's own JSON.
  cachesView: slot.forward('cachesView'),
  NOT_LISTED: NOT_LISTED
};
