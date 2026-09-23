'use strict';
//
// File: risk/risk_datasets.ts
//
// ===========================================================================
// THE EXTERNAL DATASETS A RISK SCORE READS (#62 P1, 2026-09-22).
//
// Geolocation, the network an address belongs to (its ASN), Tor exits, IP
// reputation, and an operator's own allow and deny lists. `risk/CLAUDE.md`
// argues the design; #62's plan, §6 and §7, is where it was agreed. The rules
// this file enforces, in the order a version meets them:
//
//   1. **THE SERVICE FETCHES NOTHING.** A dataset arrives as a FILE — pulled
//      into the database at install time by `risk_install.ts` (an operator's
//      tool, under the provider terms the operator accepted), uploaded on
//      Monitoring → Risk or `/admin-api/risk`, or dropped in
//      `risk.datasetsDirectory` with a manifest — and is imported before any
//      lookup reads it. This file opens no connection to any provider, and
//      no dataset is ever shipped with iya-sts (`risk_terms.ts`).
//   2. **A VERSION IS VERIFIED BEFORE IT IS ACTIVE.** The file's SHA-256 is
//      checked against the one its manifest names; a version with more than
//      `risk.datasetShrinkLimitPercent` fewer rows than the active one is
//      refused, because that is what a truncated download looks like. A
//      refused version is KEPT with its reason and the active one stays.
//   3. **ONE VERSION IS ACTIVE, AND THE LAST ONE IS KEPT.** Activation names
//      the new version and remembers the one it replaced, so rollback is one
//      action; a superseded version's rows go after
//      `risk.supersededRetentionDays` (GeoLite2's licence says thirty).
//   4. **STALE DATA COUNTS FOR NOTHING, AND NEVER FOR A REFUSAL.** A lookup
//      leaves out any dataset older than its staleness limit and says it did;
//      a missing dataset is simply absent. Neither can stop anybody signing
//      in, and neither can stop this service starting.
//
// Every version is a row in `sts_risk_dataset_versions` with its provider,
// licence, attribution, checksum, row count and state; `risk_store.ts` keeps
// the same shapes in memory where there is no database.
//
// A LIBRARY (rule 3): it registers no route. Its two scheduler jobs are
// registered when its instance is wired, in every process, as the scheduler
// asks (`cluster/CLAUDE.md`).
// ===========================================================================

import bunyan = require('bunyan');
import fs = require('fs');
import path = require('path');
import readline = require('readline');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
import riskStore = require('./risk_store');
import riskTerms = require('./risk_terms');

const log = bunyan.createLogger({ name: 'sts-risk-datasets' });
config.registerLogger(log);

type Json = any;

// ---------------------------------------------------------------------------
// THE DATASETS THIS SERVICE KNOWS, and what each is. `stale` names the
// setting that ages it (`never` for an operator's own list). An operator
// list is per realm; every other dataset is the whole service's.
// ---------------------------------------------------------------------------
const CATALOGUE: Record<string, Json> = {
  'geo.city': { kind: 'geo', title: 'Geolocation (city)', stale: 'geo',
    formats: ['dbip-city-csv'],
    what: 'Country, region and city of an address, with coordinates. The ' +
          'city and coordinates are often wrong by tens of kilometres; the ' +
          'country is dependable.' },
  'geo.country': { kind: 'geo', title: 'Geolocation (country)', stale: 'geo',
    formats: ['dbip-country-csv', 'ipinfo-lite-csv'],
    what: 'The country of an address. Used where no city dataset is active.' },
  'asn': { kind: 'asn', title: 'Network (ASN)', stale: 'geo',
    formats: ['dbip-asn-csv', 'ipinfo-lite-csv'],
    what: 'The autonomous system an address is announced by, and who runs ' +
          'it — the signal that stays true behind a VPN or a mobile network ' +
          'when the city does not.' },
  'iplist.tor-exit': { kind: 'iplist', title: 'Tor exit nodes',
    category: 'tor-exit', stale: 'iplist', formats: ['ip-list'],
    provider: 'tor-project',
    what: 'Addresses the Tor Project publishes as exits. Worth little a few ' +
          'hours after it was published.' },
  'iplist.reputation': { kind: 'iplist', title: 'IP reputation',
    category: 'reputation', stale: 'iplist', formats: ['ip-list'],
    provider: 'firehol',
    what: 'A curated reputation list (FireHOL level 1, say). A score input ' +
          'and never a deny list: these lists are built from many sources of ' +
          'uneven quality.' },
  'iplist.operator-deny': { kind: 'iplist', title: 'Operator deny list',
    category: 'operator-deny', stale: 'never', perRealm: true,
    formats: ['ip-list'], provider: 'operator',
    what: 'Networks this realm\'s operator says are hostile.' },
  'iplist.operator-allow': { kind: 'iplist', title: 'Operator allow list',
    category: 'operator-allow', stale: 'never', perRealm: true,
    formats: ['ip-list'], provider: 'operator',
    what: 'Networks this realm\'s operator vouches for — a corporate egress, ' +
          'a VPN concentrator.' },
  // THE FIDO METADATA SERVICE (#62 P5): every certified authenticator model,
  // by AAGUID, and what is known about it — above all whether it has been
  // REVOKED or its keys reported compromised. One signed BLOB, verified
  // (`pki.verifyFidoMdsBlob()`, then revocation) before anything is kept;
  // only the LATEST is kept, as FIDO's terms require (`latestOnly`), and it
  // is stale past its own `nextUpdate` plus `risk.mdsStaleGraceDays`.
  'fido.mds3': { kind: 'fido', title: 'FIDO authenticator metadata (MDS3)',
    stale: 'fido', formats: ['fido-mds3-jwt'], provider: 'fido-mds3',
    latestOnly: true,
    what: 'Every FIDO-certified authenticator model and its status reports. ' +
          'A security key whose model the metadata reports REVOKED or ' +
          'compromised is a risk signal; the rest is shown, not scored.' }
};

// WHO A DATASET COMES FROM, AND ON WHAT TERMS, is `risk_terms.ts`'s: the
// provider table, the licence links a result is credited with, and the
// recorded acceptance without which no provider's data is imported (the two
// licence reviews on #62).
const PROVIDERS = riskTerms.PROVIDERS;

// ---------------------------------------------------------------------------
// THE FORMATS A FILE MAY BE IN, and whose data each one normally carries.
// An IP list names no provider of its own: the dataset says (a Tor list is
// the Tor Project's, a reputation list FireHOL's) and the importer may say
// otherwise.
// ---------------------------------------------------------------------------
const FORMATS: Record<string, Json> = {
  'dbip-city-csv': { provider: 'dbip-lite',
    what: 'DB-IP Lite "IP to City": start, end, continent, country, region, ' +
          'city, latitude, longitude; no header.' },
  'dbip-country-csv': { provider: 'dbip-lite',
    what: 'DB-IP Lite "IP to Country": start, end, country; no header.' },
  'dbip-asn-csv': { provider: 'dbip-lite',
    what: 'DB-IP Lite "IP to ASN": start, end, ASN, organisation; no header.' },
  'ipinfo-lite-csv': { provider: 'ipinfo-lite',
    what: 'IPinfo Lite, with its header row: network, country, ' +
          'country_code, continent, continent_code, asn, as_name, as_domain.' },
  'fido-mds3-jwt': { provider: 'fido-mds3',
    what: 'The MDS3 BLOB exactly as FIDO publishes it: one signed JWT, whose ' +
          'x5c chain must end at the FIDO root.' },
  'ip-list': { provider: '',
    what: 'One address, CIDR block or "first - last" range per line; text ' +
          'after # or ; is a comment. The Tor Project\'s exit list and ' +
          'FireHOL\'s netsets are both in this form.' }
};

// Rows written to the store in one statement.
const BATCH_ROWS = 5000;
// Rows deleted in one statement when a version goes.
const DELETE_BATCH = 20000;
// How many lookups a process keeps; the oldest go first. Cleared whenever a
// version is activated anywhere.
const MAX_CACHED_LOOKUPS = 10000;
// The two scheduler jobs.
const DIRECTORY_JOB = 'risk.dataset-directory';
const RETENTION_JOB = 'risk.retention';
const RETENTION_EVERY_MS = 60 * 60 * 1000;

interface RiskDatasetsDeps {
  log: { debug(m: string): void; info(m: string): void; warn(m: string): void;
         error(m: string): void };
  config: { value(key: string): any };
  store: typeof riskStore;
  now(): number;
  // Lazily, for the audit rows: `audit.js` is a leaf, and requiring it here
  // at load would still be one more thing loaded before the root.
  audit(): { audit(event: Json): unknown };
  scheduler(): Json;
  realms(): Json;
}

class RiskDatasets {
  static readonly CATALOGUE = CATALOGUE;
  static readonly FORMATS = FORMATS;
  static readonly PROVIDERS = PROVIDERS;
  static readonly DIRECTORY_JOB = DIRECTORY_JOB;
  static readonly RETENTION_JOB = RETENTION_JOB;

  // realm + dataset -> { version, publishedAt, kind } for the active version.
  private active: Map<string, Json> | null = null;
  private readonly lookups = new Map<string, Json>();
  private readonly counter: Json;

  constructor(private readonly deps: RiskDatasetsDeps) {
    deps.log.debug("Entering RiskDatasets.constructor().");
    const self = this;
    // Described to `/admin/caches` (rule 3ap): the lookups this process has
    // answered, keyed by address and realm, dropped whenever any version is
    // activated.
    this.counter = cacheRegistry.register({
      name: 'risk.dataset-lookups',
      title: 'Risk dataset lookups',
      description: 'What the active geolocation, ASN and IP-list datasets ' +
        'said about an address, per realm. Cleared whenever a dataset ' +
        'version is activated on any node.',
      owner: 'risk/risk_datasets.ts',
      scope: 'process',
      maxEntries: function (): number {
        return MAX_CACHED_LOOKUPS;
      },
      bound: 'Enforced: ' + MAX_CACHED_LOOKUPS + ' lookups, the oldest ' +
        'dropped first.',
      lifetime: function (): string {
        return 'Until a dataset version is activated, or the bound drops it.';
      },
      entries: function (): unknown[] {
        const out: unknown[] = [];
        self.lookups.forEach(function (value: Json, key: string): void {
          out.push({ key: key.split('\u0000').join(' in realm '),
                     validUntil: null, basis: 'until-activation' });
        });
        return out;
      }
    });
    deps.log.debug("Leaving RiskDatasets.constructor().");
  }

  static defaultDeps(): RiskDatasetsDeps {
    log.debug("Entering RiskDatasets.defaultDeps().");
    log.debug("Leaving RiskDatasets.defaultDeps().");
    return {
      log: log,
      config: config,
      store: riskStore,
      now: function (): number {
        return Date.now();
      },
      audit: function (): Json {
        return require('../common/audit');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      realms: function (): Json {
        return require('../common/realms');
      }
    };
  }

  // The store's activation, here or on another node through the change log,
  // drops what this process cached. Wired once per instance.
  listen(): void {
    const { log, store } = this.deps;
    const self = this;
    log.debug("Entering RiskDatasets.listen().");
    store.onActivated(function (): void {
      self.forget();
    });
    log.debug("Leaving RiskDatasets.listen().");
  }

  forget(): void {
    const { log } = this.deps;
    log.debug("Entering RiskDatasets.forget().");
    this.active = null;
    this.lookups.clear();
    log.debug("Leaving RiskDatasets.forget().");
  }

  // ===== THE CSV AND LIST READERS ==========================================

  // One CSV line into its fields, with RFC 4180 quoting (a city name may hold
  // a comma). A hot path — one call per line of a file of millions — so no
  // Entering/Leaving pair.
  static csvFields(line: string): string[] {
    const out = [];
    let field = '';
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (quoted) {
        if (c === '"' && line[i + 1] === '"') {
          field += '"';
          i++;
        } else if (c === '"') {
          quoted = false;
        } else {
          field += c;
        }
      } else if (c === '"') {
        quoted = true;
      } else if (c === ',') {
        out.push(field);
        field = '';
      } else {
        field += c;
      }
    }
    out.push(field);
    return out;
  }

  // A number field, or null. The same hot path as csvFields().
  private static num(text: string): number | null {
    const value = parseFloat(String(text || '').trim());
    return isFinite(value) ? value : null;
  }

  // ---------------------------------------------------------------------------
  // ONE LINE OF A FILE AS A ROW OF A DATASET, or null for a line that is not
  // one (a blank, a comment, a header, garbage — counted, never fatal). The
  // same hot path as csvFields(). `header` is the IPinfo file's column index,
  // filled from its first line.
  // ---------------------------------------------------------------------------
  static rowOf(format: string, kind: string, category: string, line: string,
               header: Json): Json | null {
    const text = String(line || '').replace(/\r$/, '');
    if (!text.trim()) {
      return null;
    }
    if (format === 'ip-list') {
      const bare = text.replace(/[#;].*$/, '').trim();
      if (!bare) {
        return null;
      }
      const range = riskStore.rangeOf(bare.split(/\s+/).length > 2 ||
                                      bare.indexOf('-') >= 0
        ? bare : bare.split(/\s+/)[0]);
      return range ? { start: range.start, end: range.end,
                       category: category, note: '' } : null;
    }
    const f = RiskDatasets.csvFields(text);
    let range = null;
    if (format === 'ipinfo-lite-csv') {
      if (!header.index) {
        header.index = {};
        f.forEach(function (name, i) {
          header.index[name.trim().toLowerCase()] = i;
        });
        header.justRead = true;
        return null;
      }
      const at = function (name: string): string {
        const i = header.index[name];
        return i === undefined ? '' : String(f[i] || '').trim();
      };
      range = riskStore.rangeOf(at('network'));
      if (!range) {
        return null;
      }
      if (kind === 'asn') {
        const asn = parseInt(at('asn').replace(/^AS/i, ''), 10);
        return isFinite(asn) ? { start: range.start, end: range.end,
                                 asn: asn, asOrg: at('as_name'),
                                 asDomain: at('as_domain') } : null;
      }
      return { start: range.start, end: range.end,
               country: at('country_code'), continent: at('continent_code') };
    }
    range = riskStore.rangeOf(String(f[0] || '').trim() + ' - ' +
                              String(f[1] || '').trim());
    if (!range) {
      return null;
    }
    if (format === 'dbip-asn-csv') {
      const asn = parseInt(String(f[2] || ''), 10);
      // The organisation is the rest of the line: a name like "Cloudflare,
      // Inc." is not always quoted.
      return isFinite(asn) ? { start: range.start, end: range.end, asn: asn,
                               asOrg: f.slice(3).join(',').trim() } : null;
    }
    if (format === 'dbip-country-csv') {
      return { start: range.start, end: range.end,
               country: String(f[2] || '').trim() };
    }
    if (format === 'dbip-city-csv') {
      return { start: range.start, end: range.end,
               continent: String(f[2] || '').trim(),
               country: String(f[3] || '').trim(),
               subdivision: String(f[4] || '').trim(),
               city: String(f[5] || '').trim(),
               latitude: RiskDatasets.num(f[6]),
               longitude: RiskDatasets.num(f[7]) };
    }
    return null;
  }

  // The lines of the file or the text, one at a time, without holding a
  // file of millions of lines in memory.
  private static async *linesOf(source: Json): AsyncGenerator<string> {
    if (source.path) {
      const reader = readline.createInterface({
        input: fs.createReadStream(source.path, { encoding: 'utf8' }),
        crlfDelay: Infinity });
      for await (const line of reader) {
        yield line;
      }
      return;
    }
    for (const line of String(source.content || '').split('\n')) {
      yield line;
    }
  }

  // ===== IMPORT ============================================================

  // What an import is asked to do, checked before anything is read: the
  // dataset exists, takes this format, and is per realm or not as it says.
  private refusalOf(o: Json): string {
    const { log } = this.deps;
    log.debug("Entering RiskDatasets.refusalOf().");
    const entry = CATALOGUE[o.dataset];
    let why = '';
    if (!entry) {
      why = 'There is no dataset "' + o.dataset + '". The ' +
            Object.keys(CATALOGUE).length + ' are: ' +
            Object.keys(CATALOGUE).join(', ') + '.';
    } else if (entry.formats.indexOf(o.format) < 0) {
      why = 'The dataset "' + o.dataset + '" is not read from "' + o.format +
            '". It takes: ' + entry.formats.join(', ') + '.';
    } else if (entry.perRealm && !o.realm) {
      why = '"' + o.dataset + '" is a list per realm; name the realm.';
    } else if (entry.perRealm && o.realm !== 'default' &&
               !this.deps.realms().get(o.realm)) {
      why = 'There is no realm "' + o.realm + '" to hold this list.';
    } else if (!entry.perRealm && o.realm) {
      why = '"' + o.dataset + '" is the whole service\'s, not a realm\'s.';
    } else if (!o.path && typeof o.content !== 'string') {
      why = 'Nothing to import: give the file\'s content or its path.';
    }
    log.debug("Leaving RiskDatasets.refusalOf(). " + (why ? 'Refused.' : 'OK.'));
    return why;
  }

  // ---------------------------------------------------------------------------
  // IMPORT ONE VERSION OF ONE DATASET.
  //
  // `o`: { dataset, format, realm?, content? | path?, version?, publishedAt?,
  //        provider?, licence?, attribution?, sha256?, source, sourceUri?,
  //        activate?, actor? }.
  //
  // Answers { ok, dataset, version, state, rows, skipped, activated,
  // duplicate?, errors?, errorCode? }. A refusal is `ok: false` with the
  // reason and a code, and a refusal after rows were written deletes them
  // and records the version as refused — rule 2 of the header.
  // ---------------------------------------------------------------------------
  async importVersion(o: Json): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskDatasets.importVersion(). dataset=" + o.dataset +
              " format=" + o.format);
    const realm = String(o.realm || '');
    const refusal = this.refusalOf(Object.assign({}, o, { realm: realm }));
    if (refusal) {
      log.debug("Leaving RiskDatasets.importVersion(). Refused.");
      return this.refused('STS-RISK-0001', refusal, o);
    }
    const entry = CATALOGUE[o.dataset];
    const format = FORMATS[o.format];
    // Whose data this is: what the caller named, the dataset's own, or the
    // format's. It must be a provider this service knows and supports, so
    // that its terms and its attribution are the ones recorded and drawn.
    const providerId = String(o.provider || entry.provider || format.provider);
    const provider = PROVIDERS[providerId];
    if (!provider || !provider.supported) {
      log.debug("Leaving RiskDatasets.importVersion(). Provider.");
      return this.refused('STS-RISK-0001', provider
        ? provider.title + ' is not supported yet: ' + provider.terms
        : 'There is no provider "' + providerId + '". The supported ones ' +
          'are: ' + Object.keys(PROVIDERS).filter(function (id) {
            return PROVIDERS[id].supported;
          }).join(', ') + '.', o);
    }
    // THE PROVIDER'S TERMS MUST BE ACCEPTED (the second licence review on
    // #62). An import may carry the acceptance itself (`acceptTerms`, the
    // console's checkbox and the API's field), recorded for its actor; a
    // directory import may not, and needs one recorded already.
    let acceptance = null;
    if (riskTerms.needsAcceptance(providerId)) {
      acceptance = await riskTerms.currentFor(providerId);
      if (!acceptance && o.acceptTerms === true) {
        const accepted = await riskTerms.accept({
          provider: providerId, acceptedBy: String(o.actor || 'unnamed'),
          via: String(o.source || 'upload') });
        acceptance = accepted.ok ? accepted.acceptance : null;
      }
      if (!acceptance) {
        log.debug("Leaving RiskDatasets.importVersion(). Terms.");
        return this.refused('STS-RISK-0014', 'The terms of ' +
          provider.title + ' have not been accepted' +
          ((await riskTerms.status()).providers.some(function (p: Json) {
            return p.provider === providerId && p.changed;
          }) ? ' since they changed' : '') + '. ' + provider.terms +
          ' Accept them on Monitoring → Risk, through POST ' +
          '/admin-api/risk/accept-terms, or with the install-time ' +
          'loader\'s --accept-terms ' + providerId + '.', o);
      }
    }
    const sha256 = o.path
      ? await stsCrypto.sha256OfFile(o.path, 0)
      : stsCrypto.truncatedSha256Hex(o.content, 64);
    const byteCount = o.path ? fs.statSync(o.path).size
                             : Buffer.byteLength(o.content, 'utf8');
    const version = String(o.version || sha256.slice(0, 16));
    const fetchedAt = now();
    const meta = {
      realm: realm, dataset: o.dataset, version: version, format: o.format,
      provider: providerId,
      licence: String(o.licence || provider.licence),
      // A provider's attribution is its own and cannot be replaced by the
      // caller; only the operator's own list may carry one of its choosing.
      attribution: providerId === 'operator' && o.attribution !== undefined
        ? String(o.attribution) : provider.attribution,
      source: String(o.source || 'upload'),
      sourceUri: String(o.sourceUri || ''),
      sha256: sha256, byteCount: byteCount,
      parameters: { attributionUrl: provider.url,
                    termsAcceptance: acceptance ? String(acceptance.id) : '',
                    termsDigest: acceptance
                      ? String(acceptance.termsDigest) : '' },
      verification: o.sha256 ? 'checksum' : 'none',
      publishedAt: Number(o.publishedAt) || fetchedAt,
      nextUpdateAt: 0, fetchedAt: fetchedAt
    };
    if (entry.kind === 'fido') {
      log.debug("Leaving RiskDatasets.importVersion(). An MDS3 BLOB.");
      return this.importMds(o, meta);
    }
    const began = await store.beginVersion(meta);
    if (!began) {
      log.debug("Leaving RiskDatasets.importVersion(). Already recorded.");
      return { ok: true, duplicate: true, dataset: o.dataset, version: version,
               message: 'Version ' + version + ' of ' + o.dataset + ' is ' +
                        'already recorded; nothing was loaded again.' };
    }
    if (o.sha256 && String(o.sha256).toLowerCase() !== sha256) {
      await store.finishVersion(realm, o.dataset, version, {
        state: 'refused', rowCount: 0, loadedAt: now(),
        refusal: 'SHA-256 ' + sha256 + ' is not the ' + o.sha256 +
                 ' that was named', errorCode: 'STS-RISK-0002' });
      log.debug("Leaving RiskDatasets.importVersion(). Checksum.");
      return this.refused('STS-RISK-0002', 'The file\'s SHA-256 is ' + sha256 +
                          ', not the ' + o.sha256 + ' that was named. ' +
                          'Nothing was loaded.', o, version);
    }
    let rows = 0;
    let skipped = 0;
    const header: Json = {};
    let batch = [];
    try {
      for await (const line of RiskDatasets.linesOf(o)) {
        const row = RiskDatasets.rowOf(o.format, entry.kind,
                                       entry.category || '', line, header);
        if (!row) {
          if (header.justRead) {
            header.justRead = false;
          } else if (String(line).trim() && !/^\s*[#;]/.test(line)) {
            skipped += 1;
          }
          continue;
        }
        batch.push(row);
        if (batch.length >= BATCH_ROWS) {
          rows += await store.insertRows(entry.kind, realm, o.dataset,
                                         version, batch);
          batch = [];
        }
      }
      if (batch.length) {
        rows += await store.insertRows(entry.kind, realm, o.dataset, version,
                                       batch);
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-RISK-0005') + 'risk: importing ' +
                o.dataset + ' ' + version + ' failed in the store: ' +
                ((e && e.message) || e));
      await this.dropRows(entry.kind, realm, o.dataset, version);
      await store.finishVersion(realm, o.dataset, version, {
        state: 'refused', rowCount: 0, loadedAt: now(),
        refusal: 'the store failed: ' + ((e && e.message) || e),
        errorCode: 'STS-RISK-0005' });
      log.debug("Leaving RiskDatasets.importVersion(). Store failure.");
      return this.refused('STS-RISK-0005', 'The store failed part-way ' +
                          'through; nothing of this version is kept. ' +
                          ((e && e.message) || e), o, version);
    }
    const counted = { skippedLines: skipped };
    if (!rows) {
      await store.finishVersion(realm, o.dataset, version, {
        state: 'refused', rowCount: 0, loadedAt: now(),
        refusal: 'no line was a row of ' + o.format,
        errorCode: 'STS-RISK-0004', parameters: counted });
      log.debug("Leaving RiskDatasets.importVersion(). Empty.");
      return this.refused('STS-RISK-0004', 'No line of the file was a row of ' +
                          o.format + ' (' + skipped + ' line(s) were not).',
                          o, version);
    }
    const shrink = await this.shrinkRefusal(realm, o.dataset, rows);
    if (shrink) {
      await this.dropRows(entry.kind, realm, o.dataset, version);
      await store.finishVersion(realm, o.dataset, version, {
        state: 'refused', rowCount: rows, loadedAt: now(), refusal: shrink,
        errorCode: 'STS-RISK-0003', parameters: counted });
      log.debug("Leaving RiskDatasets.importVersion(). Shrunk.");
      return this.refused('STS-RISK-0003', shrink, o, version);
    }
    await store.finishVersion(realm, o.dataset, version, {
      state: 'ready', rowCount: rows, loadedAt: now(), parameters: counted });
    let activated = false;
    if (o.activate !== false) {
      const answer = await store.activate(realm, o.dataset, entry.kind,
                                          version, now());
      activated = !!(answer && answer.activated);
    }
    this.auditRow('risk.dataset.import', o, version, 'success', '',
                  rows + ' row(s) of ' + o.dataset + ' ' + version +
                  ' loaded' + (activated ? ' and activated' : ''));
    log.info('risk: ' + o.dataset + (realm ? ' (realm ' + realm + ')' : '') +
             ' version ' + version + ': ' + rows + ' row(s) loaded, ' +
             skipped + ' line(s) skipped' +
             (activated ? '; it is now active.' : '.'));
    log.debug("Leaving RiskDatasets.importVersion(). Loaded.");
    return { ok: true, dataset: o.dataset, realm: realm, version: version,
             state: activated ? 'active' : 'ready', rows: rows,
             skipped: skipped, activated: activated, sha256: sha256,
             message: rows + ' row(s) of ' + o.dataset + ' loaded as ' +
                      'version ' + version +
                      (activated ? ', now active.' : '.') +
                      (skipped ? ' ' + skipped + ' line(s) were not rows ' +
                                 'and were skipped.' : '') };
  }

  // A refusal, audited and coded.
  // -------------------------------------------------------------------------
  // THE FIDO MDS3 BLOB (#62 P5), MDS3 section 3.1.8's steps in order:
  //
  //   1. the signature and the chain to the FIDO root (`pki.js`);
  //   2. every certificate in the chain not revoked — `revocation_status.js`
  //      fetches their CRLs, and the mode's revocation policy decides what an
  //      unknown answer means, as it does for any presented chain;
  //   3. the serial number `no` GREATER than the active BLOB's: an older one
  //      is a rollback and is refused (STS-RISK-0024), whatever it is signed
  //      with;
  //   4. then the entries, one row per key an authenticator model is listed
  //      under (AAGUID, AAID, attestation key identifier), activated — and
  //      every OLDER version's rows deleted at once (`latestOnly`): FIDO's
  //      terms are the latest BLOB and nothing kept to roll back to.
  //
  // A refused BLOB is still recorded as a refused version, with its reason
  // and code, as every dataset's is.
  // -------------------------------------------------------------------------
  private async importMds(o: Json, meta: Json): Promise<Json> {
    const { log, store, now, config } = this.deps;
    log.debug("Entering RiskDatasets.importMds().");
    const text = o.path ? fs.readFileSync(o.path, 'utf8') : String(o.content);
    const refuse = async (code: string, why: string,
                          params?: Json): Promise<Json> => {
      log.debug("Entering refuse(). " + code);
      await store.beginVersion(meta);
      await store.finishVersion('', meta.dataset, meta.version, {
        state: 'refused', rowCount: 0, loadedAt: now(), refusal: why,
        errorCode: code, parameters: params || {} });
      log.debug("Leaving refuse().");
      return this.refused(code, why, o, meta.version);
    };
    if (o.sha256 && String(o.sha256).toLowerCase() !== meta.sha256) {
      log.debug("Leaving RiskDatasets.importMds(). Checksum.");
      return refuse('STS-RISK-0002', 'The file\'s SHA-256 is ' + meta.sha256 +
                    ', not the ' + o.sha256 + ' that was named.');
    }
    const pki = require('../common/pki');
    const verified = await pki.verifyFidoMdsBlob(text, {
      anchorsPem: String(config.value('risk.mdsTrustAnchors') || ''),
      now: now() });
    if (!verified.ok) {
      log.debug("Leaving RiskDatasets.importMds(). Does not verify.");
      return refuse('STS-RISK-0022', 'The BLOB does not verify: ' +
                    verified.reason + '. Nothing was loaded.');
    }
    const verdict = await require('../common/revocation_status').verdictFor({
      leaf: verified.chainPems[0], chain: verified.chainPems.slice(1),
      verified: true }, { external: 'fetch' });
    if (verdict.refused || verdict.status === 'revoked') {
      log.debug("Leaving RiskDatasets.importMds(). Revocation.");
      return refuse('STS-RISK-0023', 'The BLOB\'s signing chain is ' +
                    (verdict.status === 'revoked' ? 'REVOKED'
                                                  : 'of unknown status') +
                    ', and the revocation policy (' + String(verdict.policy ||
                    '') + ') refuses it: ' + String(verdict.message ||
                    verdict.why || '') + '. Nothing was loaded.',
                    { revocation: String(verdict.status || '') });
    }
    const payload = verified.payload;
    const serial = Number(payload.no);
    const versions = await store.listVersions('', meta.dataset);
    const newest = versions.reduce(function (most: number, v: Json): number {
      const no = Number(v.parameters && v.parameters.mdsNo);
      return (v.state === 'active' || v.state === 'superseded') &&
             isFinite(no) && no > most ? no : most;
    }, -1);
    if (serial <= newest) {
      log.debug("Leaving RiskDatasets.importMds(). Not newer.");
      return refuse('STS-RISK-0024', 'This BLOB\'s serial number is ' +
                    serial + ', and ' + newest + ' has already been ' +
                    'processed. MDS3 section 3.1.8 refuses a BLOB that is ' +
                    'not newer: an older one is a rollback, however well ' +
                    'it is signed.');
    }
    const nextUpdate = Date.parse(String(payload.nextUpdate || ''));
    const staged = Object.assign({}, meta, {
      version: String(o.version || 'no-' + serial),
      verification: 'signature',
      nextUpdateAt: isFinite(nextUpdate) ? nextUpdate : 0,
      parameters: Object.assign({}, meta.parameters, {
        mdsNo: serial, revocation: String(verdict.status || ''),
        legalHeader: String(payload.legalHeader || '').slice(0, 500) }) });
    const began = await store.beginVersion(staged);
    if (!began) {
      log.debug("Leaving RiskDatasets.importMds(). Already recorded.");
      return { ok: true, duplicate: true, dataset: staged.dataset,
               version: staged.version,
               message: 'BLOB ' + serial + ' is already recorded.' };
    }
    const rows: Json[] = [];
    payload.entries.forEach(function (entry: Json): void {
      RiskDatasets.mdsRowsOf(entry).forEach(function (row: Json): void {
        rows.push(row);
      });
    });
    let written = 0;
    for (let i = 0; i < rows.length; i += BATCH_ROWS) {
      written += await store.insertRows('fido', '', staged.dataset,
                                        staged.version,
                                        rows.slice(i, i + BATCH_ROWS));
    }
    if (!written) {
      await store.finishVersion('', staged.dataset, staged.version, {
        state: 'refused', rowCount: 0, loadedAt: now(),
        refusal: 'the BLOB lists no authenticator', errorCode: 'STS-RISK-0004' });
      log.debug("Leaving RiskDatasets.importMds(). Empty.");
      return this.refused('STS-RISK-0004', 'The BLOB lists no authenticator.',
                          o, staged.version);
    }
    await store.finishVersion('', staged.dataset, staged.version, {
      state: 'ready', rowCount: written, loadedAt: now() });
    let activated = false;
    if (o.activate !== false) {
      const answer = await store.activate('', staged.dataset, 'fido',
                                          staged.version, now());
      activated = !!(answer && answer.activated);
    }
    let dropped = 0;
    if (activated) {
      // THE LATEST ONLY: every older BLOB's rows go now, not at the
      // retention job's next pass. Its version row stays, as the record.
      for (const v of await store.listVersions('', staged.dataset)) {
        if (v.version !== staged.version && v.state !== 'refused' &&
            v.rowCount) {
          dropped += await this.dropRows('fido', '', staged.dataset,
                                         v.version);
          await store.markRowsDeleted('', staged.dataset, v.version, now());
        }
      }
    }
    this.auditRow('risk.dataset.import', o, staged.version, 'success', '',
                  'FIDO MDS3 BLOB ' + serial + ': ' + written +
                  ' authenticator key(s) loaded' +
                  (activated ? ' and activated' : '') +
                  (dropped ? '; ' + dropped + ' older row(s) deleted' : ''));
    log.info('risk: FIDO MDS3 BLOB ' + serial + ' verified (revocation ' +
             String(verdict.status || 'unchecked') + '): ' + written +
             ' authenticator key(s)' + (activated ? ', now active' : '') +
             (dropped ? '; the older BLOB\'s ' + dropped + ' row(s) deleted'
                      : '') + '.');
    log.debug("Leaving RiskDatasets.importMds(). Loaded.");
    return { ok: true, dataset: staged.dataset, realm: '',
             version: staged.version, state: activated ? 'active' : 'ready',
             rows: written, skipped: 0, activated: activated,
             sha256: meta.sha256, serial: serial,
             message: 'FIDO MDS3 BLOB ' + serial + ' verified: ' + written +
                      ' authenticator key(s) loaded' +
                      (activated ? ', now active' : '') + '.' };
  }

  // The statuses MDS3 section 3.1.4 uses to say an authenticator model can
  // no longer be trusted to protect a key.
  static readonly MDS_COMPROMISED = ['REVOKED', 'USER_VERIFICATION_BYPASS',
    'ATTESTATION_KEY_COMPROMISE', 'USER_KEY_REMOTE_COMPROMISE',
    'USER_KEY_PHYSICAL_COMPROMISE'];

  // -------------------------------------------------------------------------
  // ONE MDS3 ENTRY AS ROWS: one per key the model is listed under. The
  // latest status report is the one with the latest effective date; the
  // model is COMPROMISED if any report ever said so (a later "update
  // available" does not recall a key the model already leaked); the
  // certification level is the latest FIDO_CERTIFIED* report's. The metadata
  // statement is kept for the page without its icon, which is an image.
  // -------------------------------------------------------------------------
  static mdsRowsOf(entry: Json): Json[] {
    log.debug("Entering RiskDatasets.mdsRowsOf().");
    const e = entry || {};
    const reports = (Array.isArray(e.statusReports) ? e.statusReports : [])
      .slice().sort(function (a: Json, b: Json): number {
        return String(a.effectiveDate || '') < String(b.effectiveDate || '')
          ? -1 : 1;
      });
    const latest = reports.length ? reports[reports.length - 1] : {};
    const certified = reports.filter(function (r: Json): boolean {
      return /^FIDO_CERTIFIED/.test(String(r.status || ''));
    });
    const statement = Object.assign({}, e.metadataStatement || {});
    delete statement.icon;
    const base = {
      description: String(statement.description || ''),
      protocolFamily: String(statement.protocolFamily || ''),
      certificationLevel: certified.length
        ? String(certified[certified.length - 1].status) : '',
      latestStatus: String(latest.status || ''),
      latestStatusAt: Date.parse(String(latest.effectiveDate || '')) || 0,
      compromised: reports.some(function (r: Json): boolean {
        return RiskDatasets.MDS_COMPROMISED.indexOf(String(r.status)) >= 0;
      }),
      statusReports: reports.map(function (r: Json): Json {
        return { status: String(r.status || ''),
                 effectiveDate: String(r.effectiveDate || '') };
      }),
      metadataStatement: statement
    };
    const rows: Json[] = [];
    if (e.aaguid) {
      rows.push(Object.assign({ keyKind: 'aaguid',
                                key: String(e.aaguid).toLowerCase() }, base));
    }
    if (e.aaid) {
      rows.push(Object.assign({ keyKind: 'aaid',
                                key: String(e.aaid).toLowerCase() }, base));
    }
    (Array.isArray(e.attestationCertificateKeyIdentifiers)
      ? e.attestationCertificateKeyIdentifiers : [])
      .forEach(function (one: unknown): void {
        rows.push(Object.assign({ keyKind: 'acki',
                                  key: String(one).toLowerCase() }, base));
      });
    log.debug("Leaving RiskDatasets.mdsRowsOf(). " + rows.length + ".");
    return rows;
  }

  // -------------------------------------------------------------------------
  // WHAT THE METADATA SAYS ABOUT ONE AUTHENTICATOR MODEL, by AAGUID (#62
  // P5): `{ model, version }`, or null — no active BLOB, a stale one, the
  // all-zero AAGUID of an authenticator that attests nothing, or a model the
  // BLOB does not list. Null decides nothing: unknown never denies.
  // -------------------------------------------------------------------------
  async lookupAuthenticator(aaguid: string): Promise<Json | null> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskDatasets.lookupAuthenticator().");
    const key = String(aaguid || '').toLowerCase();
    if (!key || /^[0-]+$/.test(key)) {
      log.debug("Leaving RiskDatasets.lookupAuthenticator(). No AAGUID.");
      return null;
    }
    const active = (await this.activeVersions()).get('\u0000fido.mds3');
    if (!active || this.isStale(CATALOGUE['fido.mds3'], active, now())) {
      log.debug("Leaving RiskDatasets.lookupAuthenticator(). No usable BLOB.");
      return null;
    }
    const model = await store.lookupFido('fido.mds3', active.version,
                                         'aaguid', key);
    log.debug("Leaving RiskDatasets.lookupAuthenticator(). " +
              (model ? 'Listed.' : 'Not listed.'));
    return model ? { model: model, version: active.version } : null;
  }

  private refused(code: string, why: string, o: Json, version?: string): Json {
    const { log } = this.deps;
    log.debug("Entering RiskDatasets.refused(). " + code);
    this.auditRow('risk.dataset.import', o, version || '', 'failure', code,
                  'importing ' + (o.dataset || '?') + ' was refused: ' + why);
    log.debug("Leaving RiskDatasets.refused().");
    return errorCodes.mark({ ok: false, dataset: o.dataset,
                             version: version || '', errors: [why] }, code);
  }

  private auditRow(action: string, o: Json, version: string, outcome: string,
                   code: string, summary: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering RiskDatasets.auditRow(). " + action);
    audit().audit({
      action: action, outcome: outcome, errorCode: code || undefined,
      actor: String(o.actor || ''), protocol: 'Risk scoring',
      channel: String(o.source || 'upload'), target: String(o.dataset || ''),
      summary: summary,
      detail: { version: version, realm: String(o.realm || ''),
                format: String(o.format || '') }
    });
    log.debug("Leaving RiskDatasets.auditRow().");
  }

  // The shrink rule (rule 2): '' when this many rows may replace the active
  // version, and the reason when not.
  private async shrinkRefusal(realm: string, dataset: string,
                              rows: number): Promise<string> {
    const { log, config, store } = this.deps;
    log.debug("Entering RiskDatasets.shrinkRefusal().");
    const versions = await store.listVersions(realm, dataset);
    const active = versions.filter(function (v: Json): boolean {
      return v.state === 'active';
    })[0];
    const limit = Number(config.value('risk.datasetShrinkLimitPercent'));
    if (!active || !active.rowCount || limit >= 100) {
      log.debug("Leaving RiskDatasets.shrinkRefusal(). Nothing to compare.");
      return '';
    }
    const floor = Math.ceil(active.rowCount * (100 - limit) / 100);
    log.debug("Leaving RiskDatasets.shrinkRefusal().");
    return rows >= floor ? ''
      : 'This version has ' + rows + ' row(s) and the active one (' +
        active.version + ') has ' + active.rowCount + '; more than ' + limit +
        '% fewer is refused (risk.datasetShrinkLimitPercent), because that ' +
        'is what a truncated download looks like. The active version stays.';
  }

  // Every row of one version, a batch at a time.
  private async dropRows(kind: string, realm: string, dataset: string,
                         version: string): Promise<number> {
    const { log, store } = this.deps;
    log.debug("Entering RiskDatasets.dropRows(). " + dataset + " " + version);
    let total = 0;
    try {
      for (;;) {
        const gone = await store.deleteRows(kind, realm, dataset, version,
                                            DELETE_BATCH);
        total += gone;
        if (!gone) {
          break;
        }
      }
    } catch (e) {
      log.debug("Caught in RiskDatasets.dropRows(): " +
                ((e && e.message) || e));
      // Rows left behind belong to a version that is refused or deleted, and
      // no lookup reads a version that is not active; the next retention run
      // tries again.
    }
    log.debug("Leaving RiskDatasets.dropRows(). " + total + " row(s).");
    return total;
  }

  // ===== ACTIVATION, ROLLBACK, DELETION ====================================

  async activateVersion(realm: string, dataset: string, version: string,
                        actor: string): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskDatasets.activateVersion(). " + dataset + " " +
              version);
    const entry = CATALOGUE[dataset];
    if (!entry) {
      log.debug("Leaving RiskDatasets.activateVersion(). No such dataset.");
      return errorCodes.mark({ ok: false, errors: ['There is no dataset "' +
                                                   dataset + '".'] },
                             'STS-RISK-0001');
    }
    const answer = await store.activate(String(realm || ''), dataset,
                                        entry.kind, version, now());
    if (!answer || !answer.activated) {
      log.debug("Leaving RiskDatasets.activateVersion(). Refused.");
      const why = 'Version "' + version + '" of ' + dataset + ' cannot be ' +
                  'made active: it is ' + ((answer && answer.state) ||
                                           'not recorded') + '.';
      this.auditRow('risk.dataset.activate', { dataset: dataset, realm: realm,
                                               actor: actor, source: 'admin' },
                    version, 'failure', 'STS-RISK-0007', why);
      return errorCodes.mark({ ok: false, errors: [why] }, 'STS-RISK-0007');
    }
    this.auditRow('risk.dataset.activate', { dataset: dataset, realm: realm,
                                             actor: actor, source: 'admin' },
                  version, 'success', '', dataset + ' version ' + version +
                  ' is active' + (answer.previous ? ', replacing ' +
                                  answer.previous : ''));
    log.debug("Leaving RiskDatasets.activateVersion(). Active.");
    return { ok: true, dataset: dataset, version: version,
             previous: answer.previous || '',
             message: dataset + ' version ' + version + ' is active' +
                      (answer.unchanged ? ' already.' : '.') };
  }

  async rollback(realm: string, dataset: string, actor: string): Promise<Json> {
    const { log, store } = this.deps;
    log.debug("Entering RiskDatasets.rollback(). " + dataset);
    const rows = await store.listDatasets();
    const row = rows.filter(function (r: Json): boolean {
      return r.realm === String(realm || '') && r.dataset === dataset;
    })[0];
    if (!row || !row.previousVersion) {
      log.debug("Leaving RiskDatasets.rollback(). Nothing to roll back to.");
      return errorCodes.mark({ ok: false, errors: [
        dataset + ' has no previous version to roll back to.'] },
        'STS-RISK-0007');
    }
    log.debug("Leaving RiskDatasets.rollback().");
    return this.activateVersion(realm, dataset, row.previousVersion, actor);
  }

  async deleteVersion(realm: string, dataset: string, version: string,
                      actor: string): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskDatasets.deleteVersion(). " + dataset + " " +
              version);
    const entry = CATALOGUE[dataset];
    const versions = entry ? await store.listVersions(String(realm || ''),
                                                      dataset) : [];
    const row = versions.filter(function (v: Json): boolean {
      return v.version === version;
    })[0];
    if (!row || row.state === 'active' || row.state === 'loading') {
      log.debug("Leaving RiskDatasets.deleteVersion(). Refused.");
      return errorCodes.mark({ ok: false, errors: [
        'Version "' + version + '" of ' + dataset + ' cannot be deleted: ' +
        (row ? 'it is ' + row.state + '.' : 'it is not recorded.')] },
        'STS-RISK-0007');
    }
    const gone = await this.dropRows(entry.kind, String(realm || ''), dataset,
                                     version);
    await store.markRowsDeleted(String(realm || ''), dataset, version, now());
    this.auditRow('risk.dataset.delete', { dataset: dataset, realm: realm,
                                           actor: actor, source: 'admin' },
                  version, 'success', '', gone + ' row(s) of ' + dataset +
                  ' ' + version + ' deleted');
    log.debug("Leaving RiskDatasets.deleteVersion().");
    return { ok: true, dataset: dataset, version: version, rows: gone,
             message: gone + ' row(s) of ' + dataset + ' version ' + version +
                      ' deleted; its record stays.' };
  }

  // ===== WHAT IS ACTIVE, AND WHETHER IT IS FRESH ============================

  private staleAfterMs(entry: Json): number {
    const { log, config } = this.deps;
    log.debug("Entering RiskDatasets.staleAfterMs().");
    log.debug("Leaving RiskDatasets.staleAfterMs().");
    if (entry.stale === 'geo') {
      return Number(config.value('risk.geoStaleAfterDays')) * 86400000;
    }
    if (entry.stale === 'iplist') {
      return Number(config.value('risk.ipListStaleAfterHours')) * 3600000;
    }
    return 0;
  }

  // The active version of every dataset in every realm, read once and kept
  // until an activation drops it.
  private async activeVersions(): Promise<Map<string, Json>> {
    const { log, store } = this.deps;
    log.debug("Entering RiskDatasets.activeVersions().");
    if (this.active) {
      log.debug("Leaving RiskDatasets.activeVersions(). Held.");
      return this.active;
    }
    const out = new Map<string, Json>();
    const rows = await store.listDatasets();
    for (const row of rows) {
      if (!row.activeVersion || !CATALOGUE[row.dataset]) {
        continue;
      }
      const versions = await store.listVersions(row.realm, row.dataset);
      const v = versions.filter(function (one: Json): boolean {
        return one.version === row.activeVersion;
      })[0];
      out.set(row.realm + '\u0000' + row.dataset, {
        realm: row.realm, dataset: row.dataset, version: row.activeVersion,
        previousVersion: row.previousVersion,
        publishedAt: v ? v.publishedAt : 0, rowCount: v ? v.rowCount : 0,
        nextUpdateAt: v ? Number(v.nextUpdateAt) || 0 : 0,
        provider: v ? v.provider : '',
        attribution: v ? v.attribution : '',
        attributionUrl: v && v.parameters
          ? String(v.parameters.attributionUrl || '') : '' });
    }
    this.active = out;
    log.debug("Leaving RiskDatasets.activeVersions(). " + out.size + ".");
    return out;
  }

  private isStale(entry: Json, active: Json, at: number): boolean {
    const { log, config } = this.deps;
    log.debug("Entering RiskDatasets.isStale().");
    if (entry.stale === 'fido') {
      // The BLOB says when the next one is due; past it, and the grace, the
      // metadata is out of date and says nothing (#62 P5).
      const due = Number(active.nextUpdateAt || 0);
      log.debug("Leaving RiskDatasets.isStale(). FIDO.");
      return !due || at > due +
        Number(config.value('risk.mdsStaleGraceDays')) * 86400000;
    }
    const limit = this.staleAfterMs(entry);
    log.debug("Leaving RiskDatasets.isStale().");
    return limit > 0 && at - Number(active.publishedAt || 0) > limit;
  }

  // ---------------------------------------------------------------------------
  // WHAT THE DATASETS SAY ABOUT ONE ADDRESS, for a realm.
  //
  // { address, prefix, geo, asn, lists: [{ dataset, category }], datasets:
  //   { id: version }, stale: [id] }. `geo` is the city dataset's answer, or
  // the country dataset's where no fresh city one is active. A stale dataset
  // is named in `stale` and says nothing (rule 4); `datasets` names every
  // version that did answer, which is what an assessment will record beside
  // the values.
  // ---------------------------------------------------------------------------
  async lookup(address: string, realmId: string): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskDatasets.lookup().");
    const realm = String(realmId || '');
    const cacheKey = String(address) + '\u0000' + realm;
    const held = this.lookups.get(cacheKey);
    if (held) {
      this.counter.hit();
      log.debug("Leaving RiskDatasets.lookup(). Cached.");
      return held;
    }
    this.counter.miss();
    const at = now();
    const actives = await this.activeVersions();
    const out: Json = { address: String(address),
                        prefix: riskStore.prefixOf(address), geo: null,
                        asn: null, lists: [], datasets: {}, stale: [],
                        attributions: [] };
    if (riskStore.addressNumber(address) === null) {
      log.debug("Leaving RiskDatasets.lookup(). Not an address.");
      return out;
    }
    const usable = (id: string, inRealm: string): Json => {
      const active = actives.get(inRealm + '\u0000' + id);
      if (!active) {
        return null;
      }
      if (this.isStale(CATALOGUE[id], active, at)) {
        out.stale.push(id);
        return null;
      }
      return active;
    };
    for (const id of ['geo.city', 'geo.country']) {
      const active = usable(id, '');
      if (!active || out.geo) {
        continue;
      }
      const hit = await store.lookupRange('geo', '', id, active.version,
                                          address);
      out.datasets[id] = active.version;
      if (hit) {
        out.geo = Object.assign({ dataset: id }, hit);
      }
    }
    const asn = usable('asn', '');
    if (asn) {
      out.datasets.asn = asn.version;
      const hit = await store.lookupRange('asn', '', 'asn', asn.version,
                                          address);
      out.asn = hit ? Object.assign({ dataset: 'asn' }, hit) : null;
    }
    for (const id of Object.keys(CATALOGUE)) {
      const entry = CATALOGUE[id];
      if (entry.kind !== 'iplist') {
        continue;
      }
      const inRealm = entry.perRealm ? realm : '';
      if (entry.perRealm && !realm) {
        continue;
      }
      const active = usable(id, inRealm);
      if (!active) {
        continue;
      }
      out.datasets[id] = active.version;
      const hit = await store.lookupRange('iplist', inRealm, id,
                                          active.version, address);
      if (hit) {
        out.lists.push({ dataset: id, category: hit.category });
      }
    }
    // WHOSE DATA ANSWERED, with the link each provider's terms require —
    // DB-IP's on every page that displays or uses its results. Every reader
    // of a lookup gets it with the values, so no page can show one without
    // the other.
    const seen = new Set<string>();
    Object.keys(out.datasets).forEach(function (id: string): void {
      const active = actives.get((CATALOGUE[id].perRealm ? realm : '') +
                                 '\u0000' + id);
      const credit = active ? riskTerms.attributionOf(active.provider)
                            : null;
      if (credit && !seen.has(credit.provider)) {
        seen.add(credit.provider);
        out.attributions.push(credit);
      }
    });
    if (this.lookups.size >= MAX_CACHED_LOOKUPS) {
      const oldest = this.lookups.keys().next().value;
      this.lookups.delete(oldest);
      this.counter.evicted(1);
    }
    this.lookups.set(cacheKey, out);
    log.debug("Leaving RiskDatasets.lookup().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE REGISTRY, for Monitoring → Risk and GET /admin-api/risk: every
  // dataset in the catalogue — for the service and, for a per-realm list,
  // for the realm asked about — with its active version, whether it is
  // fresh, and every version recorded.
  // ---------------------------------------------------------------------------
  async registry(realmId: string): Promise<Json> {
    const { log, store, now } = this.deps;
    log.debug("Entering RiskDatasets.registry().");
    const realm = String(realmId || '');
    const actives = await this.activeVersions();
    const at = now();
    const rows = [];
    const terms = await riskTerms.status();
    const attributions: Json[] = [];
    actives.forEach(function (active: Json): void {
      const credit = riskTerms.attributionOf(active.provider);
      if (credit && !attributions.some(function (c: Json): boolean {
        return c.provider === credit.provider;
      })) {
        attributions.push(credit);
      }
    });
    for (const id of Object.keys(CATALOGUE)) {
      const entry = CATALOGUE[id];
      const inRealm = entry.perRealm ? realm : '';
      const active = actives.get(inRealm + '\u0000' + id) || null;
      const versions = await store.listVersions(inRealm, id);
      rows.push({
        dataset: id, realm: inRealm, kind: entry.kind, title: entry.title,
        what: entry.what, formats: entry.formats, perRealm: !!entry.perRealm,
        staleAfterMs: this.staleAfterMs(entry),
        state: !active ? 'empty'
          : (this.isStale(entry, active, at) ? 'stale' : 'active'),
        activeVersion: active ? active.version : '',
        previousVersion: active ? active.previousVersion : '',
        publishedAt: active ? active.publishedAt : 0,
        rows: active ? active.rowCount : 0,
        provider: active ? active.provider : entry.provider || '',
        attribution: active ? active.attribution : '',
        attributionUrl: active ? active.attributionUrl : '',
        versions: versions
      });
    }
    log.debug("Leaving RiskDatasets.registry().");
    return { store: store.describe(), datasets: rows,
             formats: Object.keys(FORMATS).map(function (id: string): Json {
               return Object.assign({ format: id }, FORMATS[id]);
             }),
             providers: terms.providers,
             acceptances: terms.acceptances,
             // Every provider whose data an ACTIVE dataset holds, credited
             // as its licence asks: the page draws these under everything
             // it shows, and the API returns them with every view.
             attributions: attributions,
             redistribution: 'iya-sts distributes no third-party dataset. ' +
               'Every dataset here was supplied by this deployment\'s ' +
               'administrator under its provider\'s terms.',
             directory: String(this.deps.config.value(
               'risk.datasetsDirectory') || '') };
  }

  // ===== THE DATASET DIRECTORY ==============================================

  // ---------------------------------------------------------------------------
  // IMPORT WHAT AN OPERATOR PUT IN `risk.datasetsDirectory`. Each `*.json`
  // there is a manifest: { dataset, format, file, realm?, version?,
  // publishedAt?, provider?, licence?, attribution?, sha256? }, with `file`
  // a name in the same directory. A version already recorded is not loaded
  // again (the store refuses the second `begin`), so this is idempotent and
  // safe on every node — though as a cluster job it runs on one.
  // ---------------------------------------------------------------------------
  async importDirectory(): Promise<Json> {
    const { log, config } = this.deps;
    log.debug("Entering RiskDatasets.importDirectory().");
    const dir = String(config.value('risk.datasetsDirectory') || '');
    const out = { imported: 0, duplicates: 0, refused: 0, skipped: 0 };
    let names = [];
    try {
      names = fs.readdirSync(dir).filter(function (name: string): boolean {
        return /\.json$/i.test(name);
      }).sort();
    } catch (e) {
      log.warn(errorCodes.tag('STS-RISK-0008') + 'risk: the dataset ' +
               'directory ' + dir + ' could not be read: ' +
               ((e && e.message) || e));
      log.debug("Leaving RiskDatasets.importDirectory(). Unreadable.");
      throw e;
    }
    for (const name of names) {
      let manifest = null;
      try {
        manifest = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
      } catch (e) {
        log.debug("Caught in RiskDatasets.importDirectory(): " +
                  ((e && e.message) || e));
        // Reported below with the manifest's name, as every bad one is.
        manifest = null;
      }
      const file = manifest && typeof manifest.file === 'string'
        ? path.join(dir, path.basename(manifest.file)) : '';
      if (!manifest || !manifest.dataset || !manifest.format || !file ||
          !fs.existsSync(file)) {
        log.warn(errorCodes.tag('STS-RISK-0008') + 'risk: the manifest ' +
                 name + ' in ' + dir + ' is not JSON naming a dataset, a ' +
                 'format and a file beside it; skipped.');
        out.skipped += 1;
        continue;
      }
      const result = await this.importVersion({
        dataset: manifest.dataset, format: manifest.format,
        realm: manifest.realm || '', path: file,
        version: manifest.version, publishedAt: manifest.publishedAt
          ? Date.parse(manifest.publishedAt) || Number(manifest.publishedAt)
          : 0,
        provider: manifest.provider, licence: manifest.licence,
        attribution: manifest.attribution, sha256: manifest.sha256,
        source: 'directory', sourceUri: file,
        actor: 'the dataset directory' });
      if (result.duplicate) {
        out.duplicates += 1;
      } else if (result.ok) {
        out.imported += 1;
      } else {
        out.refused += 1;
      }
    }
    log.debug("Leaving RiskDatasets.importDirectory().");
    return out;
  }

  // ===== RETENTION =========================================================

  // Superseded versions past `risk.supersededRetentionDays` lose their rows
  // (their record stays); refused ones lose whatever rows a failure left.
  async retainVersions(): Promise<Json> {
    const { log, config, store, now } = this.deps;
    log.debug("Entering RiskDatasets.retainVersions().");
    const keepMs = Number(config.value('risk.supersededRetentionDays')) *
      86400000;
    const at = now();
    const out = { versions: 0, rows: 0 };
    const realmsSeen = new Set<string>(['']);
    const rows = await store.listDatasets();
    rows.forEach(function (row: Json): void {
      realmsSeen.add(row.realm);
    });
    for (const realm of realmsSeen) {
      const versions = await store.listVersions(realm, '');
      for (const v of versions) {
        const entry = CATALOGUE[v.dataset];
        const due = (v.state === 'superseded' &&
                     at - Number(v.supersededAt || 0) >= keepMs) ||
                    v.state === 'refused';
        if (!entry || !due) {
          continue;
        }
        out.rows += await this.dropRows(entry.kind, realm, v.dataset,
                                        v.version);
        if (v.state === 'superseded') {
          await store.markRowsDeleted(realm, v.dataset, v.version, at);
          out.versions += 1;
        }
      }
    }
    log.debug("Leaving RiskDatasets.retainVersions(). " + out.versions +
              " version(s).");
    return out;
  }

  // ===== THE SCHEDULER =====================================================

  // The two jobs, registered in every process when the instance is wired.
  // Both are cluster jobs: the rows are the whole cluster's, so one node
  // imports and one node deletes.
  registerJobs(): boolean {
    const { log, scheduler } = this.deps;
    log.debug("Entering RiskDatasets.registerJobs().");
    const s = scheduler();
    if (!s || typeof s.register !== 'function' || s.job(DIRECTORY_JOB)) {
      log.debug("Leaving RiskDatasets.registerJobs(). Nothing to do.");
      return false;
    }
    const self = this;
    s.register({
      id: DIRECTORY_JOB,
      title: 'Risk dataset directory import',
      describe: 'Imports each dataset an operator put in ' +
                'risk.datasetsDirectory, by its manifest, verifying and ' +
                'activating it; a version already recorded is not loaded ' +
                'again.',
      owner: 'risk/risk_datasets.ts',
      kind: 'cluster',
      everySetting: 'risk.datasetsDirectoryScanS', everySettingUnit: 's',
      manual: true,
      off: function (): string {
        return String(self.deps.config.value('risk.datasetsDirectory') || '')
          ? '' : 'risk.datasetsDirectory is empty';
      },
      run: function (): Promise<Json> {
        return self.importDirectory();
      }
    });
    s.register({
      id: RETENTION_JOB,
      title: 'Risk retention',
      describe: 'Deletes the rows of dataset versions superseded more than ' +
                'risk.supersededRetentionDays ago and of refused versions, ' +
                'the failures older than risk.failureRetentionDays, and the ' +
                'assessments and the model\'s history past ' +
                'risk.assessmentRetentionDays and risk.historyRetentionDays.',
      owner: 'risk/risk_datasets.ts',
      kind: 'cluster',
      everyMs: function (): number {
        return RETENTION_EVERY_MS;
      },
      manual: true,
      run: function (): Promise<Json> {
        return self.retainVersions().then(function (versions: Json): Json {
          return require('./risk_failures').purge().then(
            function (failures: number): Json {
              return require('./risk_engine').purge().then(
                function (history: Json): Json {
                  return { versions: versions.versions, rows: versions.rows,
                           failures: failures, history: history };
                });
            });
        }).catch(function (e: Json): never {
          self.deps.log.warn(errorCodes.tag('STS-RISK-0009') + 'risk: the ' +
                             'retention job failed: ' +
                             ((e && e.message) || e));
          throw e;
        });
      }
    });
    log.debug("Leaving RiskDatasets.registerJobs().");
    return true;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). Wiring it listens
// for activations and registers the two jobs.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RiskDatasets>(
  'risk/risk_datasets',
  () => new RiskDatasets(RiskDatasets.defaultDeps()),
  function (instance: RiskDatasets): void {
    instance.listen();
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

export = {
  RiskDatasets: RiskDatasets,
  installInstance: (instance: RiskDatasets): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  CATALOGUE: RiskDatasets.CATALOGUE,
  FORMATS: RiskDatasets.FORMATS,
  PROVIDERS: RiskDatasets.PROVIDERS,
  DIRECTORY_JOB: RiskDatasets.DIRECTORY_JOB,
  RETENTION_JOB: RiskDatasets.RETENTION_JOB,
  csvFields: RiskDatasets.csvFields,
  rowOf: RiskDatasets.rowOf,
  forget: slot.forward('forget'),
  importVersion: slot.forward('importVersion'),
  activateVersion: slot.forward('activateVersion'),
  rollback: slot.forward('rollback'),
  deleteVersion: slot.forward('deleteVersion'),
  lookup: slot.forward('lookup'),
  lookupAuthenticator: slot.forward('lookupAuthenticator'),
  mdsRowsOf: RiskDatasets.mdsRowsOf,
  registry: slot.forward('registry'),
  importDirectory: slot.forward('importDirectory'),
  retainVersions: slot.forward('retainVersions'),
  registerJobs: slot.forward('registerJobs')
};
