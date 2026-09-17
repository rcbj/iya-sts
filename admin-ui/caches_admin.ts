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
// here the day it registers and a cache removed goes with it. What is
// deliberately NOT registered — four single-value memos, and the two things
// `docs/caches.md` names that are not held in this process's memory — is the
// one list this file keeps (`NOT_LISTED`), for `encryption_admin.ts`'s
// reason: the interesting question about a page like this is often *is X on
// it*, and a page that lists only the yeses answers it by silence.
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
// drew it.
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

type Req = any;
type Res = any;
type Json = any;

const PAGE = '/admin/caches';

// What is deliberately NOT registered: two things `docs/caches.md` names
// that this process does not hold in memory, and four single-value memos,
// each one value, where a row apiece would be noise. Named here so their
// absence is a decision a reader can see.
const NOT_LISTED = [
  { what: 'SAML service provider metadata',
    where: 'saml/sp_metadata.ts',
    why: 'stored on the application entry as received, not held in ' +
         'memory; refreshed from the application\'s page' },
  { what: 'A remote PEP\'s policy',
    where: 'xacml-pep/',
    why: 'held by the remote PEP container, not by this process' },
  { what: 'The trusted-proxy address list',
    where: 'common/client_address.js',
    why: 'one parsed copy of global.trustedProxies, re-parsed when the ' +
         'setting text changes' },
  { what: 'The version stamp',
    where: 'common/version.js',
    why: 'read once from version.json; it cannot change while the process ' +
         'runs' },
  { what: 'A secret-store login',
    where: 'common/secrets.js',
    why: 'one promise, kept for the length of one report' },
  { what: 'Whether a minted store is observational',
    where: 'persistence/persistence_minted.js',
    why: 'one flag per store handle' }
];

interface CachesAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  cacheRegistry: typeof cacheRegistry;
  errorCodes: typeof errorCodes;
  now: () => number;
}

class CachesAdmin {
  static readonly NOT_LISTED = NOT_LISTED;

  constructor(private readonly deps: CachesAdminDeps) {
    deps.log.debug("Entering CachesAdmin.constructor().");
    deps.log.debug("Leaving CachesAdmin.constructor().");
  }

  static defaultDeps(): CachesAdminDeps {
    helpers.log.debug("Entering CachesAdmin.defaultDeps().");
    helpers.log.debug("Leaving CachesAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      adminViews: adminViews,
      cacheRegistry: cacheRegistry,
      errorCodes: errorCodes,
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
  cachesJson(query?: Json): Json {
    const { log, cacheRegistry, adminViews, now } = this.deps;
    const self = this;
    log.debug("Entering CachesAdmin.cachesJson().");
    const q = query || {};
    const at = now();
    const base = { generatedAt: new Date(at).toISOString(),
                   pid: process.pid };
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
        notListed: NOT_LISTED
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
  cachesView(query?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.cachesView().");
    log.debug("Leaving CachesAdmin.cachesView().");
    return this.publicJson(this.cachesJson(query));
  }

  private ratioText(c: Json): string {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.ratioText().");
    log.debug("Leaving CachesAdmin.ratioText().");
    if (!c.counted) {
      log.debug("Leaving CachesAdmin.ratioText(). Not counted.");
      return 'not counted';
    }
    return c.hitRatio === null
      ? '—' : (Math.round(c.hitRatio * 1000) / 10) + '%';
  }

  private boundText(c: Json): string {
    const { log } = this.deps;
    log.debug("Entering CachesAdmin.boundText().");
    log.debug("Leaving CachesAdmin.boundText().");
    return c.maxEntries === null ? 'unbounded' : String(c.maxEntries);
  }

  private settingsText(c: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering CachesAdmin.settingsText().");
    log.debug("Leaving CachesAdmin.settingsText().");
    return c.settings.length
      ? c.settings.map(function (k: string): string {
        return '<code>' + admin.esc(k) + '</code>';
      }).join(', ')
      : '—';
  }

  private tableOf(caches: Json[]): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering CachesAdmin.tableOf().");
    const rows = caches.map(function (c: Json): string {
      return '<tr>' +
        '<td><a href="' + admin.esc(PAGE + '?cache=' +
                                    encodeURIComponent(c.name)) + '">' +
        admin.esc(c.title) + '</a><br><code>' + admin.esc(c.name) +
        '</code></td>' +
        '<td>' + admin.esc(c.description) +
        '<br><small>' + admin.esc(c.lifetime) + '</small>' +
        (c.problem ? admin.warn('Its entries could not be listed: ' +
                                admin.esc(c.problem)) : '') + '</td>' +
        '<td>' + admin.esc((c.scope === 'realm' ? 'per realm' : 'process') +
                           (c.persisted ? ', persisted' : '')) + '</td>' +
        '<td class="num">' + c.size + '</td>' +
        '<td class="num">' + c.valid + '</td>' +
        '<td class="num">' + c.expired + '</td>' +
        '<td class="num">' + admin.esc(self.boundText(c)) + '</td>' +
        '<td class="num">' + admin.esc(self.ratioText(c)) +
        (c.counted ? '<br><small>' + c.hits + ' hit(s), ' + c.misses +
                     ' miss(es)</small>' : '') + '</td>' +
        '<td><code>' + admin.esc(c.owner) + '</code><br>' +
        self.settingsText(c) + '</td>' +
        '</tr>';
    }).join('');
    log.debug("Leaving CachesAdmin.tableOf(). " + caches.length + " row(s).");
    return '<table class="grid"><thead><tr>' +
      '<th>Name</th><th>Description</th><th>Scope</th>' +
      '<th>Current size</th><th>Valid</th><th>Expired</th>' +
      '<th>Max size</th><th>Hit ratio</th><th>Owner and settings</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="9">None is registered.</td></tr>') +
      '</tbody></table>';
  }

  private listHtml(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering CachesAdmin.listHtml().");
    const tiles = '<div class="tiles">' +
      admin.tile(String(json.totals.caches), 'caches') +
      admin.tile(String(json.totals.entries), 'entries held') +
      admin.tile(String(json.totals.expired), 'expired, not yet evicted') +
      admin.tile(String(json.pid), 'process') +
      '</div>';
    const what = admin.note(
      '<p>This page answers <strong>what this service is holding in memory ' +
      'that it could rebuild, and whether holding it is paying off</strong>. ' +
      'A cache is listed here by the module that owns it; a store whose ' +
      'entries cannot be rebuilt &mdash; a replay history, a session, an ' +
      'issued code &mdash; is a register and is not a cache, whatever its ' +
      'variable is called.</p>' +
      '<p><strong>Valid</strong> entries are still good. ' +
      '<strong>Expired</strong> ones are past their deadline, or were built ' +
      'from something that has since changed, and are still held because ' +
      'nothing has looked them up or pushed them out yet. The <strong>hit ' +
      'ratio</strong> is lookups answered from the cache over all lookups, ' +
      'since this process started. Every figure is this process\'s own ' +
      '(pid ' + admin.esc(json.pid) + '): a request worker or another ' +
      'cluster node holds caches of its own. Keys are shown and values ' +
      'never are.</p>', 'What this page is');
    const caches = json.caches.filter(function (c: Json): boolean {
      return c.kind !== 'replay';
    });
    const replays = json.caches.filter(function (c: Json): boolean {
      return c.kind === 'replay';
    });
    const table = '<h3>Caches</h3>' + self.tableOf(caches) +
      '<h3>Replay caches and nonces</h3>' +
      admin.note('These make a one-time value work once, so their entries ' +
                 'cannot be rebuilt and none of them has a control. A ' +
                 '<strong>hit</strong> here is a value found already held ' +
                 '&mdash; for a replay history, a second use refused; for a ' +
                 'nonce store, a nonce honoured &mdash; and each row says ' +
                 'which. A store that refuses when full says so in its ' +
                 'lifetime.', 'What a hit means here') +
      self.tableOf(replays);
    const skipped = '<h3>Held in memory and not listed</h3>' +
      '<table class="grid"><thead><tr><th>What</th><th>Where</th>' +
      '<th>Why it is not a row above</th></tr></thead><tbody>' +
      json.notListed.map(function (n: Json): string {
        return '<tr><td>' + admin.esc(n.what) + '</td><td><code>' +
          admin.esc(n.where) + '</code></td><td>' + admin.esc(n.why) +
          '</td></tr>';
      }).join('') + '</tbody></table>';
    log.debug("Leaving CachesAdmin.listHtml().");
    return tiles + what + table + skipped;
  }

  private detailHtml(json: Json, query: Json): string {
    const { log, admin, adminViews } = this.deps;
    log.debug("Entering CachesAdmin.detailHtml().");
    if (!json.found) {
      log.debug("Leaving CachesAdmin.detailHtml(). No such cache.");
      return admin.warn('There is no cache called <code>' +
        admin.esc(json.cache) + '</code> in this process. <a href="' +
        PAGE + '">Every cache</a> is listed on the Caches page.');
    }
    const c = json.summary;
    const tiles = '<div class="tiles">' +
      admin.tile(String(c.size), 'current size') +
      admin.tile(String(c.valid), 'valid') +
      admin.tile(String(c.expired), 'expired') +
      admin.tile(this.boundText(c), 'max size') +
      admin.tile(this.ratioText(c), 'hit ratio') +
      '</div>';
    const about = '<table class="grid"><tbody>' +
      '<tr><th>Name</th><td><code>' + admin.esc(c.name) + '</code></td></tr>' +
      '<tr><th>Description</th><td>' + admin.esc(c.description) +
      '</td></tr>' +
      '<tr><th>How an entry ends</th><td>' + admin.esc(c.lifetime) +
      '</td></tr>' +
      '<tr><th>Scope</th><td>' +
      admin.esc(c.scope === 'realm' ? 'One per trust realm' :
                'One for the process') + '</td></tr>' +
      '<tr><th>Kind</th><td>' +
      admin.esc(c.kind === 'replay' ? 'Replay cache or nonce store' :
                'Cache') + (c.persisted ? ', persisted' : '') +
      '</td></tr>' +
      '<tr><th>Lookups</th><td>' + (c.counted
        ? c.hits + ' hit(s), ' + c.misses + ' miss(es) since pid ' +
          admin.esc(json.pid) + ' started. A hit is ' +
          admin.esc(c.hitMeaning) + '.'
        : 'Not counted: the lookup is in a file this repository does not ' +
          'edit.') + '</td></tr>' +
      '<tr><th>Owner</th><td><code>' + admin.esc(c.owner) + '</code></td></tr>' +
      '<tr><th>Settings</th><td>' + this.settingsText(c) + '</td></tr>' +
      '</tbody></table>' +
      (c.problem ? admin.warn('Its entries could not be listed: ' +
                              admin.esc(c.problem)) : '');
    const params = adminViews.pageParamsOf(query);
    const nav = admin.pageNavPair(PAGE, params, json.paging);
    const rows = json.entries.map(function (e: Json): string {
      return '<tr>' +
        '<td>' + (e.realm === null ? '—' : '<code>' + admin.esc(e.realm) +
                  '</code>') + '</td>' +
        '<td>' + admin.clipped(e.key, 120) + '</td>' +
        '<td>' + admin.esc(e.valid ? 'valid' : 'expired') + '</td>' +
        '<td>' + admin.esc(e.remaining) + '</td>' +
        '<td>' + (e.validUntil ? '<code>' + admin.esc(e.validUntil) +
                  '</code>' : '—') + '</td>' +
        '</tr>';
    }).join('');
    const table = '<h3>Entries</h3>' +
      admin.perPageForm(PAGE, 'cache', c.name, json.paging.perPage,
                        'The entries are ordered by deadline, soonest ' +
                        'first; those with none come last.') +
      nav.head +
      '<table class="grid"><thead><tr><th>Realm</th><th>Key</th>' +
      '<th>State</th><th>Still valid for</th><th>Valid until</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="5">This cache holds nothing right ' +
       'now.</td></tr>') +
      '</tbody></table>' + nav.foot;
    log.debug("Leaving CachesAdmin.detailHtml().");
    return tiles + about + table;
  }

  private renderCaches(req: Req, res: Res): void {
    const { log, admin, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering CachesAdmin.renderCaches().");
    const json = self.cachesJson(req.query);
    if (json.cache === undefined) {
      admin.respond(req, res, self.publicJson(json), 'Caches', PAGE,
                    self.listHtml(json));
      log.debug("Leaving CachesAdmin.renderCaches(). The list.");
      return;
    }
    const title = json.found ? json.summary.title : 'No such cache';
    const up = admin.upTo(PAGE, title, {});
    if (!json.found) {
      errorCodes.mark(res, 'STS-ADMIN-0021');
    }
    admin.respond(req, res, self.publicJson(json), 'Caches — ' + title, PAGE,
                  self.detailHtml(json, req.query), up);
    log.debug("Leaving CachesAdmin.renderCaches(). One cache.");
  }

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
const slot = new InstanceSlot<CachesAdmin>(
  'admin-ui/caches_admin',
  () => new CachesAdmin(CachesAdmin.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as every console module does.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  CachesAdmin: CachesAdmin,
  installInstance: (instance: CachesAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts` (rule 7): the page's own JSON.
  cachesView: slot.forward('cachesView'),
  NOT_LISTED: NOT_LISTED
};
