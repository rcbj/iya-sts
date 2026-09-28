// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
// File: attribute_sources.ts
// ---------------------------------------------------------------------------
// ATTRIBUTE SOURCES: PEOPLE'S ATTRIBUTES, READ FROM AN OPERATOR'S DATABASE
// ONTO THEIR DIRECTORY ENTRIES (#94 part C, 2026-09-28).
//
// A realm may hold what it knows about a person somewhere else — an HR
// system's table of cost centres, a clearance register. A SOURCE says where:
// a database (`attribute_source_drivers.ts` reads it, through Knex), a table
// or view, the column that holds the person's key and the attribute of
// theirs it matches, and which columns become which directory attributes.
// What it reads is WRITTEN ONTO THE ENTRY, through the one write
// `ldap_server.js` offers (`apply`), and from there it reaches a token or an
// assertion the way any attribute does: an attribute claim (#94 part A) or
// the catalogue.
//
// rcbj's decisions on #94, each held here:
//   * **STRUCTURED, NO SQL** — a table, a key column, a key attribute and a
//     column map; Knex builds the statement and binds the key.
//   * **FOUR REFRESH MODES**, any of them per source: `once` (the first
//     sign-in after the source exists), `sign-in` (every new session, before
//     the first artifact, bounded by the source's timeout), `schedule` (a
//     cluster job pages through the realm's people) and `on-demand` (a person
//     at a time, from the console or the API).
//   * **ON FAILURE, PER SOURCE, DEFAULT KEEP** — the stored values stay and
//     the sign-in proceeds, under a code; `refuse` refuses the sign-in.
//   * **REALM ADMINISTRATORS MAY CONFIGURE SOURCES**, host included;
//     `attributeSources.hostPatterns` can narrow the hosts a realm's sources
//     name, and is EMPTY BY DEFAULT — any host — which the setting's own
//     description warns about (rcbj, 2026-09-28).
//   * **NO CACHE BELOW THE REGISTRY** — the one cache here is a short
//     per-process one for a burst of sign-ins, registered with
//     `cache_registry.js` so /admin/caches shows it.
//
// **EACH ATTRIBUTE HAS ONE OWNER**: two sources naming one attribute is
// refused when the second is written, so which source a value came from is
// never a race. **NO SOURCE WRITES WHAT AN OUTSIDE SOURCE MAY NOT**
// (`common/sourced_attributes.ts`), **NOR `mail`**, whose verification and
// change notice belong to the mail flow.
//
// A library: it registers no route (the console page and the API are
// `attribute_sources_admin.ts` and `attribute_sources_api.ts`) and requires
// nothing that registers one. `ldap_server.js` fills its directory slot.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import audit = require('../common/audit');
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
import SourcedAttributes = require('../common/sourced_attributes');
// Reading and describing a source's own CA chain: X.509 lives in
// `common/pki.js`, never in a feature (rcbj's rule).
import pki = require('../common/pki');
import AttributeSourceDrivers = require('./attribute_source_drivers');

type Json = Record<string, any>;

const log = helpers.log;

// The refresh modes, and what a failure does.
const MODES = ['once', 'sign-in', 'schedule', 'on-demand'];
const ON_FAILURE = ['keep', 'refuse'];
const PASSWORD_PROVIDERS = ['none', 'file', 'aws', 'gcp', 'azure', 'vault'];

// The scheduled refresh (#49): a cluster job per realm, every minute, which
// takes the next page of people for each source whose interval is due.
const REFRESH_JOB = 'attribute-sources.refresh';

// A source's id is its entry's `cn` and a value in provenance
// (`<source>:<attribute>`), so it is kept to a name a person can read.
const SOURCE_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;
// A directory attribute name.
const ATTRIBUTE = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
// The most PEM a source's own CA chain may hold.
const MAX_CA_TEXT = 65536;

// THE BURST CACHE: what one lookup found for one person's key, for
// CACHE_MS, per process. Several sign-ins in a moment are one query.
const CACHE_MS = 30000;
const CACHE_MAX = 2000;
const lookups: Map<string, { at: number; row: Record<string, string[]> | null }>
  = new Map();
const lookupCount = cacheRegistry.register({
  name: 'attribute-sources.lookups',
  title: 'Attribute source lookups',
  description: 'The row an attribute source returned for one person\'s ' +
    'key, held briefly so a burst of sign-ins is one query (#94).',
  owner: 'attribute-sources/attribute_sources.ts',
  scope: 'process',
  kind: 'cache',
  hitMeaning: 'a sign-in answered from a lookup made seconds before',
  maxEntries: function (): number {
    return CACHE_MAX;
  },
  bound: 'Enforced: ' + CACHE_MAX + ' rows per process, the oldest dropped.',
  lifetime: function (): string {
    return (CACHE_MS / 1000) + ' s after the lookup; a change to the source ' +
      'drops its rows.';
  },
  entries: function (): number {
    return lookups.size;
  },
  eject: function (now: number): number {
    let gone = 0;
    lookups.forEach(function (held, key) {
      if (now - held.at > CACHE_MS) {
        lookups.delete(key);
        gone++;
      }
    });
    return gone;
  }
});

// What each source last did, per realm: persisted so every node's console
// says the same, and aged out with minted state — it is an observation.
const status = realms.map({ persist: 'attribute_sources.status',
                            retain: 'age' });

// THE DIRECTORY'S SLOT, filled by `ldap_server.js` when it loads. Held at
// module level rather than on the instance, so the order the composition
// root builds this in and the directory loads in cannot matter.
interface DirectoryHooks {
  listSources(): Array<{ dn: string; attributes: Record<string, string[]> }>;
  writeSource(cn: string, attributes: Json): boolean;
  deleteSource(cn: string): boolean;
  personAttributes(key: string): Record<string, string[]> | null;
  people(after: string, limit: number): string[];
  apply(key: string, sourceId: string,
        changes: Record<string, string[] | null>):
    { found: boolean; changed: string[] };
  seen(key: string, sourceId: string): boolean;
}
let directory: DirectoryHooks | null = null;

interface AttributeSourcesDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  drivers: {
    lookup(realmId: string, source: Json, key: string):
      Promise<Record<string, string[]> | null>;
    close(realmId: string, id: string): void;
  };
  directory(): DirectoryHooks | null;
  scheduler(): any;
  now(): number;
}

/**
 * The register of attribute sources, and the refresh that reads them onto
 * people's entries.
 */
class AttributeSources {
  deps: AttributeSourcesDeps;

  /**
   * Builds the register from its dependencies.
   *
   * @param deps - from `AttributeSources.defaultDeps()`, or a test's
   */
  constructor(deps: AttributeSourcesDeps) {
    deps.log.debug("Entering AttributeSources.constructor().");
    this.deps = deps;
    deps.log.debug("Leaving AttributeSources.constructor().");
  }

  /**
   * The dependencies a running service gives the register.
   *
   * @returns the deps
   */
  static defaultDeps(): AttributeSourcesDeps {
    log.debug("Entering AttributeSources.defaultDeps().");
    const drivers = new AttributeSourceDrivers(
      AttributeSourceDrivers.defaultDeps());
    log.debug("Leaving AttributeSources.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      drivers: drivers,
      directory: function (): DirectoryHooks | null {
        return directory;
      },
      scheduler: function (): any {
        return require('../cluster/scheduler');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // ===========================================================================
  // THE REGISTER.
  // ===========================================================================

  // One entry's definition: the JSON value, with the id from its `cn`.
  private recordOf(entry: { attributes: Record<string, string[]> }):
      Json | null {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.recordOf().");
    const at = entry.attributes || {};
    const data = (at.stsattributesourcedata || at.stsAttributeSourceData ||
                  [])[0];
    const cn = (at.cn || [])[0];
    try {
      const parsed = JSON.parse(String(data || '{}'));
      log.debug("Leaving AttributeSources.recordOf().");
      return Object.assign(parsed, { id: String(cn || parsed.id || '') });
    } catch (e) {
      log.debug("Caught in AttributeSources.recordOf(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-ATTR-0005') + 'attribute sources: the ' +
               'entry ' + cn + ' does not hold a definition that parses, ' +
               'and is ignored.');
      log.debug("Leaving AttributeSources.recordOf().");
      return null;
    }
  }

  /**
   * Every source in the ambient realm, by id.
   *
   * @returns the definitions
   */
  list(): Json[] {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.list().");
    const dir = this.deps.directory();
    const out = dir ? dir.listSources().map((entry) => this.recordOf(entry))
      .filter(Boolean) : [];
    out.sort(function (a, b) {
      return a.id < b.id ? -1 : (a.id > b.id ? 1 : 0);
    });
    log.debug("Leaving AttributeSources.list(). " + out.length + ".");
    return out;
  }

  /**
   * One source by id, or null.
   *
   * @param id - the source
   * @returns its definition
   */
  get(id: unknown): Json | null {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.get(). " + id);
    const found = this.list().filter(function (one) {
      return one.id === String(id || '');
    })[0] || null;
    log.debug("Leaving AttributeSources.get().");
    return found;
  }

  // A column map from what a form or a body gives: an object, or lines of
  // `column=attribute`.
  private columnsOf(given: unknown): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.columnsOf().");
    const out: Record<string, string> = {};
    if (given && typeof given === 'object' && !Array.isArray(given)) {
      Object.keys(given).forEach(function (column) {
        out[column.trim()] = String((given as Json)[column]).trim();
      });
    } else {
      String(given || '').split(/[\r\n,]+/).forEach(function (line) {
        const at = line.indexOf('=');
        if (at > 0) {
          out[line.slice(0, at).trim()] = line.slice(at + 1).trim();
        }
      });
    }
    log.debug("Leaving AttributeSources.columnsOf().");
    return out;
  }

  // A list from an array, or a form's repeated or comma-separated field.
  private listOf(given: unknown): string[] {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.listOf().");
    log.debug("Leaving AttributeSources.listOf().");
    return (Array.isArray(given) ? given : String(given || '').split(/[\s,]+/))
      .map(function (one) { return String(one).trim(); }).filter(Boolean);
  }

  // A definition from a body, over the source it changes (an update names
  // only what it changes).
  private normalise(body: Json, existing: Json | null): Json {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.normalise().");
    const was = existing || {};
    const pick = function (name: string, fallback: unknown): unknown {
      return body[name] !== undefined ? body[name]
        : (was[name] !== undefined ? was[name] : fallback);
    };
    const dialect = String(pick('dialect', 'postgres')).trim();
    const out: Json = {
      id: String(body.id || body.source || was.id || '').trim(),
      dialect: dialect,
      host: String(pick('host', '')).trim(),
      port: Number(pick('port', 0)) ||
            AttributeSourceDrivers.defaultPort(dialect),
      database: String(pick('database', '')).trim(),
      user: String(pick('user', '')).trim(),
      passwordProvider: String(pick('passwordProvider', 'none')).trim(),
      passwordRef: String(pick('passwordRef', '')).trim(),
      passwordField: String(pick('passwordField', '')).trim(),
      caFile: String(pick('caFile', '')).trim(),
      // THE SOURCE'S OWN TRUST CHAIN, pasted on the console (#94): PEM
      // certificates, stored with the definition — public, never a secret —
      // and tidied to one block per certificate. `trustPublicRoots` adds
      // node's store beside it; off, the chain given is trusted ALONE.
      caCertificates: this.tidyChain(pick('caCertificates', '')),
      trustPublicRoots: String(pick('trustPublicRoots', false)) === 'true',
      serverName: String(pick('serverName', '')).trim(),
      table: String(pick('table', '')).trim(),
      keyColumn: String(pick('keyColumn', '')).trim(),
      keyAttribute: String(pick('keyAttribute', 'uid')).trim(),
      columns: body.columns !== undefined ? this.columnsOf(body.columns)
                                          : (was.columns || {}),
      refresh: body.refresh !== undefined ? this.listOf(body.refresh)
                                          : (was.refresh || ['sign-in']),
      scheduleS: Number(pick('scheduleS', 3600)) || 3600,
      timeoutMs: Number(pick('timeoutMs', 2000)) || 2000,
      onFailure: String(pick('onFailure', 'keep')).trim(),
      enabled: String(pick('enabled', true)) !== 'false'
    };
    log.debug("Leaving AttributeSources.normalise().");
    return out;
  }

  // A pasted chain as one PEM block per certificate that parsed, in the
  // order given; '' for nothing. What did not parse is refused by
  // problemOf(), which reads the text as given.
  private tidyChain(given: unknown): string {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.tidyChain().");
    const text = String(given == null ? '' : given).trim();
    if (!text) {
      log.debug("Leaving AttributeSources.tidyChain(). Empty.");
      return '';
    }
    const read = pki.certificateBundle(text);
    log.debug("Leaving AttributeSources.tidyChain().");
    return read.unreadable || !read.certificates.length ? text
      : read.certificates.map(function (one: any) {
          return String(one.pem).trim();
        }).join('\n') + '\n';
  }

  /**
   * Describes a source's own CA chain for a page, and whether the public
   * roots are trusted beside it.
   *
   * @param source - the definition
   * @returns `{ certificates, unreadable, publicRoots, caFile }`
   */
  trustOf(source: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering AttributeSources.trustOf(). " + source.id);
    const described = source.caCertificates
      ? pki.describeCertificateBundle(source.caCertificates, now())
      : { certificates: [], unreadable: 0 };
    log.debug("Leaving AttributeSources.trustOf().");
    return {
      certificates: described.certificates,
      unreadable: described.unreadable,
      caFile: source.caFile || '',
      // Node's store is trusted where the source asks for it, and where the
      // source names no chain of its own — which would otherwise trust
      // nothing and connect nowhere.
      publicRoots: !!source.trustPublicRoots ||
                   (!source.caCertificates && !source.caFile)
    };
  }

  // Whether a host is one `attributeSources.hostPatterns` allows: empty
  // allows any (the default, rcbj's decision); otherwise a pattern with `*`
  // for any run of characters, compared without regard to case.
  private hostAllowed(host: string): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AttributeSources.hostAllowed(). " + host);
    const patterns = String(config.value('attributeSources.hostPatterns') ||
                            '').split(/[\s,]+/).filter(Boolean);
    if (!patterns.length) {
      log.debug("Leaving AttributeSources.hostAllowed(). Any host.");
      return true;
    }
    const allowed = patterns.some(function (pattern) {
      const re = new RegExp('^' + pattern.toLowerCase()
        .replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
      return re.test(host.toLowerCase());
    });
    log.debug("Leaving AttributeSources.hostAllowed(). " + allowed);
    return allowed;
  }

  /**
   * Says what is wrong with a definition, or null when it may be stored.
   *
   * @param record - the definition
   * @param others - the realm's other sources
   * @returns `{ code, why }`, or null
   */
  problemOf(record: Json, others: Json[]): { code: string; why: string } |
      null {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.problemOf(). " + record.id);
    const bad = function (code: string, why: string) {
      log.debug("Leaving AttributeSources.problemOf(). " + code);
      return { code: code, why: why };
    };
    if (!SOURCE_ID.test(record.id)) {
      return bad('STS-ATTR-0005', 'A source\'s id is lower-case letters, ' +
        'digits and -, up to 63; "' + record.id + '" is not.');
    }
    if (AttributeSourceDrivers.dialects().indexOf(record.dialect) < 0) {
      return bad('STS-ATTR-0005', '"' + record.dialect + '" is not a ' +
        'dialect this service reads: ' +
        AttributeSourceDrivers.dialects().join(', ') + '. SQL Server and ' +
        'Oracle arrive with #94\'s next step.');
    }
    if (!record.host || /\s/.test(record.host)) {
      return bad('STS-ATTR-0005', 'Name the database\'s host.');
    }
    if (!this.hostAllowed(record.host)) {
      return bad('STS-ATTR-0010', '"' + record.host + '" is not a host ' +
        'attributeSources.hostPatterns allows in this realm.');
    }
    if (!(record.port >= 1 && record.port <= 65535)) {
      return bad('STS-ATTR-0005', 'The port is 1 to 65535.');
    }
    if (!record.database || !record.user) {
      return bad('STS-ATTR-0005', 'Name the database and the user.');
    }
    if (record.caCertificates) {
      if (record.caCertificates.length > MAX_CA_TEXT) {
        return bad('STS-ATTR-0015', 'The CA chain is at most ' + MAX_CA_TEXT +
          ' characters of PEM.');
      }
      const chain = pki.describeCertificateBundle(record.caCertificates,
                                                  this.deps.now());
      if (chain.unreadable || !chain.certificates.length) {
        return bad('STS-ATTR-0015', 'The CA chain is PEM certificates ' +
          '(-----BEGIN CERTIFICATE-----); ' +
          (chain.unreadable ? chain.unreadable + ' block(s) did not parse.'
                            : 'none was found.'));
      }
      const stale = chain.certificates.filter(function (one: Json) {
        return one.expired || one.notYetValid;
      })[0];
      if (stale) {
        return bad('STS-ATTR-0015', 'The CA certificate ' + stale.subject +
          ' is ' + (stale.expired ? 'expired (' + stale.notAfter + ')'
                                  : 'not valid until ' + stale.notBefore) +
          '; a connection could not be verified against it.');
      }
    }
    if (PASSWORD_PROVIDERS.indexOf(record.passwordProvider) < 0) {
      return bad('STS-ATTR-0005', 'The password comes from one of: ' +
        PASSWORD_PROVIDERS.join(', ') + '.');
    }
    const identifier = AttributeSourceDrivers.identifierProblem('table',
                                                                record.table)
      || AttributeSourceDrivers.identifierProblem('column', record.keyColumn);
    if (identifier) {
      return bad('STS-ATTR-0005', identifier);
    }
    if (!ATTRIBUTE.test(record.keyAttribute)) {
      return bad('STS-ATTR-0005', '"' + record.keyAttribute + '" is not an ' +
        'attribute name.');
    }
    const columns = Object.keys(record.columns || {});
    if (!columns.length) {
      return bad('STS-ATTR-0005', 'Map at least one column onto an ' +
        'attribute, as column=attribute.');
    }
    const targets: string[] = [];
    for (const column of columns) {
      const attribute = String(record.columns[column]);
      const problem = AttributeSourceDrivers.identifierProblem('column',
                                                               column) ||
        (ATTRIBUTE.test(attribute) ? ''
          : '"' + attribute + '" is not an attribute name.');
      if (problem) {
        return bad('STS-ATTR-0005', problem);
      }
      const lower = attribute.toLowerCase();
      const refused = lower === 'mail'
        ? 'mail is the mail flow\'s: its verification and change notice ' +
          'are not a source\'s to skip'
        : SourcedAttributes.refusal(attribute);
      if (refused) {
        return bad('STS-ATTR-0008', 'A source may not write "' + attribute +
          '": ' + refused + '.');
      }
      if (targets.indexOf(lower) >= 0) {
        return bad('STS-ATTR-0005', 'Two columns map onto ' + attribute +
          '; one source writes an attribute from one column.');
      }
      targets.push(lower);
      const owner = others.filter(function (other) {
        return other.id !== record.id &&
          Object.keys(other.columns || {}).some(function (c) {
            return String(other.columns[c]).toLowerCase() === lower;
          });
      })[0];
      if (owner) {
        return bad('STS-ATTR-0009', attribute + ' is written by source ' +
          owner.id + '; an attribute has one source.');
      }
    }
    if (!record.refresh.length || record.refresh.some(function (m: string) {
      return MODES.indexOf(m) < 0;
    })) {
      return bad('STS-ATTR-0005', 'Refresh is any of: ' + MODES.join(', ') +
        '.');
    }
    if (!(record.scheduleS >= 60)) {
      return bad('STS-ATTR-0005', 'The scheduled interval is at least 60 s.');
    }
    if (!(record.timeoutMs >= 100 && record.timeoutMs <= 30000)) {
      return bad('STS-ATTR-0005', 'The timeout is 100 to 30000 ms.');
    }
    if (ON_FAILURE.indexOf(record.onFailure) < 0) {
      return bad('STS-ATTR-0005', 'On failure is keep or refuse.');
    }
    log.debug("Leaving AttributeSources.problemOf(). In order.");
    return null;
  }

  // The entry a definition is stored as.
  private entryOf(record: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.entryOf().");
    log.debug("Leaving AttributeSources.entryOf().");
    return { objectClass: ['top', 'stsAttributeSource'], cn: [record.id],
             stsAttributeSourceData: [JSON.stringify(record)] };
  }

  // Drops what this process holds for a source: its pool and its rows in the
  // burst cache.
  private forget(id: string): void {
    const { log, drivers } = this.deps;
    log.debug("Entering AttributeSources.forget(). " + id);
    const realmId = realms.current().id;
    drivers.close(realmId, id);
    const prefix = realmId + '\n' + id + '\n';
    Array.from(lookups.keys()).forEach(function (key) {
      if (key.indexOf(prefix) === 0) {
        lookups.delete(key);
      }
    });
    log.debug("Leaving AttributeSources.forget().");
  }

  // ===========================================================================
  // THE REFRESH.
  // ===========================================================================

  // One lookup, bounded by the source's timeout whatever the driver does.
  // A SIGN-IN may be answered from the burst cache; an on-demand read, a
  // scheduled one and a test always ask the database, because each is
  // somebody asking what it holds NOW.
  private async lookup(source: Json, key: string, cached?: boolean):
      Promise<Record<string, string[]> | null> {
    const { log, drivers, now } = this.deps;
    log.debug("Entering AttributeSources.lookup(). " + source.id);
    const realmId = realms.current().id;
    const cacheKey = realmId + '\n' + source.id + '\n' + key;
    const held = cached ? lookups.get(cacheKey) : undefined;
    if (held && now() - held.at <= CACHE_MS) {
      lookupCount.hit();
      log.debug("Leaving AttributeSources.lookup(). Held.");
      return held.row;
    }
    lookupCount.miss();
    const timeout = Number(source.timeoutMs) || 2000;
    let timer: any = null;
    // A PER-OPERATION TIMEOUT, cleared when the lookup settles: not periodic
    // work (root CLAUDE.md), and recorded as such in
    // tests/no_periodic_timers.js.
    const bound = new Promise<never>(function (resolve, reject) {
      timer = setTimeout(function () {
        reject(errorCodes.mark(new Error(errorCodes.tag('STS-ATTR-0003') +
          'attribute source ' + source.id + ' did not answer within ' +
          timeout + ' ms.'), 'STS-ATTR-0003'));
      }, timeout + 250);
    });
    try {
      const row = await Promise.race([drivers.lookup(realmId, source, key),
                                      bound]);
      if (lookups.size >= CACHE_MAX) {
        lookups.delete(lookups.keys().next().value);
      }
      lookups.set(cacheKey, { at: now(), row: row });
      log.debug("Leaving AttributeSources.lookup().");
      return row;
    } finally {
      clearTimeout(timer);
    }
  }

  // What happened, on the source's status row: a failure always, a success
  // only when it clears a failure or ends a scheduled run — a steady sign-in
  // is not a persisted write.
  private noteStatus(source: Json, change: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering AttributeSources.noteStatus(). " + source.id);
    const was = status.get(source.id) || {};
    if (!change.force && !change.error && !was.lastError) {
      log.debug("Leaving AttributeSources.noteStatus(). Nothing new.");
      return;
    }
    const next: Json = Object.assign({}, was, change.fields || {});
    if (change.error) {
      next.lastError = String(change.error.message || change.error);
      next.lastCode = errorCodes.codeOf(change.error) || 'STS-ATTR-0002';
      next.lastErrorAt = new Date(now()).toISOString();
      next.failures = (Number(was.failures) || 0) + 1;
    } else if (change.cleared !== false) {
      next.lastError = '';
      next.lastCode = '';
      next.lastOkAt = new Date(now()).toISOString();
    }
    delete next.force;
    status.set(source.id, next);
    log.debug("Leaving AttributeSources.noteStatus().");
  }

  /**
   * Reads one person from the sources a mode names, and writes what they
   * hold onto the person's entry.
   *
   * @param username - the person
   * @param mode - `sign-in` (with `once` for a source that has not read
   *   them), `schedule` or `on-demand`
   * @param only - one source's id, or '' for every source the mode names
   * @returns `{ refused, failures, changed }`: `refused` when a failing
   *   source says refuse
   */
  async refreshPerson(username: string, mode: string, only?: string):
      Promise<{ refused: boolean; failures: Json[]; changed: string[] }> {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.refreshPerson(). " + username +
              ", " + mode);
    const dir = this.deps.directory();
    const out = { refused: false, failures: [] as Json[],
                  changed: [] as string[] };
    const person = dir && username ? dir.personAttributes(username) : null;
    if (!dir || !person) {
      log.debug("Leaving AttributeSources.refreshPerson(). Nobody.");
      return out;
    }
    const sources = this.list().filter(function (source) {
      if (!source.enabled || (only && source.id !== only)) {
        return false;
      }
      if (mode === 'sign-in') {
        return source.refresh.indexOf('sign-in') >= 0 ||
               (source.refresh.indexOf('once') >= 0 &&
                !dir.seen(username, source.id));
      }
      return source.refresh.indexOf(mode) >= 0 || !!only;
    });
    for (const source of sources) {
      const keyValues = person[String(source.keyAttribute).toLowerCase()] ||
                        [];
      const key = String(keyValues[0] || '');
      if (!key) {
        continue;
      }
      try {
        const row = await this.lookup(source, key, mode === 'sign-in');
        if (row) {
          const changes: Record<string, string[] | null> = {};
          Object.keys(source.columns).forEach(function (column) {
            const values = row[column] || [];
            changes[source.columns[column]] = values.length ? values : null;
          });
          const written = dir.apply(username, source.id, changes);
          out.changed = out.changed.concat(written.changed);
        }
        this.noteStatus(source, {});
      } catch (e) {
        log.debug("Caught in AttributeSources.refreshPerson(): " +
                  ((e && e.message) || e));
        const code = errorCodes.codeOf(e) || 'STS-ATTR-0002';
        log.warn(errorCodes.tag(code) + 'attribute sources: ' + source.id +
                 ' could not refresh ' + username + ' (' + mode + '); ' +
                 (source.onFailure === 'refuse' && mode === 'sign-in'
                   ? 'the sign-in is refused. '
                   : 'what the entry holds stands. ') +
                 ((e && e.message) || e));
        this.noteStatus(source, { error: e });
        out.failures.push({ source: source.id, code: code,
                            why: String((e && e.message) || e) });
        if (source.onFailure === 'refuse') {
          out.refused = true;
        }
      }
    }
    log.debug("Leaving AttributeSources.refreshPerson(). " +
              out.changed.length + " changed, " + out.failures.length +
              " failure(s).");
    return out;
  }

  /**
   * The sign-in refresh (`authn.ts` awaits it before the browser is sent
   * back, and so before the first artifact): the sources whose mode is
   * `sign-in`, and `once` for a source that has not read this person.
   *
   * @param username - the person who just signed in
   * @returns `{ refused, code, why }`: `refused` when a failing source says
   *   refuse (STS-ATTR-0012)
   */
  async refreshAtSignIn(username: string):
      Promise<{ refused: boolean; code: string; why: string }> {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.refreshAtSignIn(). " + username);
    const result = await this.refreshPerson(username, 'sign-in');
    if (!result.refused) {
      log.debug("Leaving AttributeSources.refreshAtSignIn(). Proceed.");
      return { refused: false, code: '', why: '' };
    }
    const failed = result.failures.map(function (one) {
      return one.source;
    }).join(', ');
    log.warn(errorCodes.tag('STS-ATTR-0012') + 'attribute sources: the ' +
             'sign-in of ' + username + ' is refused: ' + failed +
             ' could not be read and says refuse.');
    log.debug("Leaving AttributeSources.refreshAtSignIn(). Refused.");
    return { refused: true, code: 'STS-ATTR-0012',
             why: 'An attribute source this sign-in depends on (' + failed +
                  ') could not be read.' };
  }

  // ===========================================================================
  // THE SCHEDULED REFRESH (#49).
  // ===========================================================================

  /**
   * One run of the scheduled refresh in the ambient realm: for each source
   * whose interval is due (or which was asked for by `params.source`), the
   * next page of people after its cursor.
   *
   * @param ctx - the scheduler's run context
   * @returns what the run did
   */
  async runScheduled(ctx: Json): Promise<Json> {
    const { log, config, now } = this.deps;
    log.debug("Entering AttributeSources.runScheduled().");
    const dir = this.deps.directory();
    const asked = String((ctx && ctx.params && ctx.params.source) || '');
    const batch = Number(config.value('attributeSources.refreshBatch')) || 200;
    const done: Json[] = [];
    if (!dir) {
      log.debug("Leaving AttributeSources.runScheduled(). No directory.");
      return { sources: done };
    }
    for (const source of this.list()) {
      const was = status.get(source.id) || {};
      const running = !!was.cursorOpen;
      const due = source.enabled && source.refresh.indexOf('schedule') >= 0 &&
        now() - (Number(was.cycleEndedAt) || 0) >= source.scheduleS * 1000;
      if (!(source.id === asked || running || due)) {
        continue;
      }
      if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
        log.debug("Leaving AttributeSources.runScheduled(). Not the owner.");
        return { sources: done, stopped: 'no longer the owner' };
      }
      const after = running ? String(was.cursor || '') : '';
      const page = dir.people(after, batch);
      let failures = 0;
      for (const username of page) {
        const result = await this.refreshPerson(username, 'schedule',
                                                source.id);
        failures += result.failures.length;
      }
      const ended = page.length < batch;
      this.noteStatus(source, { force: true, cleared: failures === 0,
        fields: { cursor: ended ? '' : page[page.length - 1],
                  cursorOpen: !ended,
                  cycleEndedAt: ended ? now() : was.cycleEndedAt,
                  lastRunAt: new Date(now()).toISOString(),
                  lastRunPeople: page.length } });
      done.push({ source: source.id, people: page.length, ended: ended,
                  failures: failures });
    }
    log.debug("Leaving AttributeSources.runScheduled(). " + done.length +
              " source(s).");
    return { sources: done };
  }

  /**
   * Registers the scheduled refresh on the scheduler (the wire step).
   */
  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering AttributeSources.scheduleJobs().");
    const s = scheduler();
    if (!s || typeof s.register !== 'function' || s.job(REFRESH_JOB)) {
      log.debug("Leaving AttributeSources.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: REFRESH_JOB,
      title: 'Attribute sources: scheduled refresh',
      describe: 'Reads the next page of the realm\'s people from each ' +
                'attribute source whose scheduled interval is due, onto ' +
                'their entries (#94). attributeSources.refreshBatch people ' +
                'per source per run.',
      owner: 'attribute-sources/attribute_sources.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return 60000;
      },
      manual: true,
      run: function (ctx: Json): Promise<Json> {
        return self.runScheduled(ctx);
      }
    });
    log.debug("Leaving AttributeSources.scheduleJobs(). On the scheduler.");
  }

  // ===========================================================================
  // WHAT THE CONSOLE AND THE API DRAW AND DO.
  // ===========================================================================

  /**
   * The register as the console and the API answer it: every source, its
   * status, and the rules a definition is held to. Never a password.
   *
   * @returns the view
   */
  view(): Json {
    const { log, config } = this.deps;
    log.debug("Entering AttributeSources.view().");
    const sources = this.list().map((source) => {
      return Object.assign({}, source, { status: status.get(source.id) || {},
                                         trust: this.trustOf(source) });
    });
    log.debug("Leaving AttributeSources.view().");
    return {
      sources: sources,
      dialects: AttributeSourceDrivers.dialects(),
      modes: MODES.slice(),
      onFailure: ON_FAILURE.slice(),
      passwordProviders: PASSWORD_PROVIDERS.slice(),
      hostPatterns: String(config.value('attributeSources.hostPatterns') ||
                           ''),
      refused: SourcedAttributes.rule(),
      job: REFRESH_JOB
    };
  }

  // A refusal, coded, in the shape every action here answers.
  private refusal(code: string, why: string): Json {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.refusal(). " + code);
    log.debug("Leaving AttributeSources.refusal().");
    return errorCodes.mark({ ok: false, errors: [why] }, code);
  }

  /**
   * Performs one act on the register, for the console and the API.
   *
   * @param body - `action` and its fields
   * @param context - `actor` and `via`
   * @returns `{ ok, message, ... }` or a coded refusal
   */
  async act(body: Json, context?: Json): Promise<Json> {
    const { log, scheduler } = this.deps;
    const given = body || {};
    const ctx = context || {};
    const action = String(given.action || '');
    log.debug("Entering AttributeSources.act(). " + action);
    const id = String(given.id || given.source || '').trim();
    const record = id ? this.get(id) : null;
    const note = function (what: string, detail: string) {
      audit.audit({ action: 'attribute-sources.' + what,
                    actor: String(ctx.actor || ''), target: id,
                    protocol: 'SQL', channel: ctx.via || 'http',
                    detail: detail });
    };

    if (action === 'add-source' || action === 'update-source') {
      if (action === 'add-source' && record) {
        log.debug("Leaving AttributeSources.act(). It exists.");
        return this.refusal('STS-ATTR-0011', 'There is already a source ' +
          'called "' + id + '".');
      }
      if (action === 'update-source' && !record) {
        log.debug("Leaving AttributeSources.act(). No such source.");
        return this.refusal('STS-ATTR-0011', 'There is no source called "' +
          id + '".');
      }
      const next = this.normalise(given, record);
      const problem = this.problemOf(next, this.list());
      if (problem) {
        log.debug("Leaving AttributeSources.act(). " + problem.code);
        return this.refusal(problem.code, problem.why);
      }
      const dir = this.deps.directory();
      if (!dir || !dir.writeSource(next.id, this.entryOf(next))) {
        log.debug("Leaving AttributeSources.act(). Not stored.");
        return this.refusal('STS-ATTR-0014', 'The directory would not store ' +
          'the source.');
      }
      this.forget(next.id);
      note(action === 'add-source' ? 'add' : 'update',
           (action === 'add-source' ? 'added' : 'changed') + ' attribute ' +
           'source ' + next.id + ' (' + next.dialect + ' at ' + next.host +
           ', writing ' + Object.keys(next.columns).map(function (c) {
             return next.columns[c];
           }).join(', ') + ')');
      log.debug("Leaving AttributeSources.act(). Stored.");
      return { ok: true, source: next,
               message: 'Attribute source ' + next.id + ' is ' +
                        (action === 'add-source' ? 'added' : 'changed') +
                        '. It is read ' + next.refresh.join(', ') + '.' };
    }

    if (!record) {
      log.debug("Leaving AttributeSources.act(). No such source.");
      if (action === 'refresh-person') {
        return this.refreshPersonAct(given, note);
      }
      return this.refusal(['remove-source', 'test-source',
                           'refresh-source'].indexOf(action) >= 0
        ? 'STS-ATTR-0011' : 'STS-ADMIN-0500',
        ['remove-source', 'test-source', 'refresh-source'].indexOf(action) >=
          0 ? 'There is no source called "' + id + '".'
            : 'Unknown action "' + action + '". The six are: add-source, ' +
              'update-source, remove-source, test-source, refresh-source, ' +
              'refresh-person.');
    }

    if (action === 'remove-source') {
      const dir = this.deps.directory();
      if (!dir || !dir.deleteSource(id)) {
        log.debug("Leaving AttributeSources.act(). Not removed.");
        return this.refusal('STS-ATTR-0014', 'The directory would not remove ' +
          'the source.');
      }
      this.forget(id);
      status.delete(id);
      note('remove', 'removed attribute source ' + id + '; what it wrote on ' +
           'people\'s entries stays');
      log.debug("Leaving AttributeSources.act(). Removed.");
      return { ok: true, message: 'Attribute source ' + id + ' is removed. ' +
               'What it wrote on people\'s entries stays there.' };
    }

    if (action === 'test-source') {
      const username = String(given.username || given.user || '').trim();
      const dir = this.deps.directory();
      const person = username && dir ? dir.personAttributes(username) : null;
      const key = person
        ? String((person[record.keyAttribute.toLowerCase()] || [])[0] || '')
        : String(given.key || '');
      if (!key) {
        log.debug("Leaving AttributeSources.act(). No key to test with.");
        return this.refusal('STS-ATTR-0005', 'Name a person whose entry has ' +
          record.keyAttribute + ' (username), or a key value (key).');
      }
      try {
        this.forget(id);
        const row = await this.lookup(record, key);
        this.noteStatus(record, {});
        log.debug("Leaving AttributeSources.act(). Tested.");
        return { ok: true, key: key, found: !!row, row: row,
                 message: row ? 'Connected, and found the row for ' + key +
                                '. Nothing was written.'
                              : 'Connected; no row has ' + record.keyColumn +
                                ' = ' + key + '.' };
      } catch (e) {
        log.debug("Caught in AttributeSources.act(): " +
                  ((e && e.message) || e));
        this.noteStatus(record, { error: e });
        return this.refusal(errorCodes.codeOf(e) || 'STS-ATTR-0002',
                            String((e && e.message) || e));
      }
    }

    if (action === 'refresh-source') {
      const s = scheduler();
      const asked = s && typeof s.requestRun === 'function'
        ? s.requestRun(REFRESH_JOB, { realm: realms.current().id,
                                      params: { source: id },
                                      requestedBy: String(ctx.actor || ''),
                                      via: ctx.via || 'console' })
        : { ok: false, why: 'there is no scheduler in this process' };
      if (!asked || asked.ok === false) {
        log.debug("Leaving AttributeSources.act(). Not queued.");
        return this.refusal((asked && asked.errorCode) || 'STS-ATTR-0013',
          'The refresh could not be queued: ' +
          ((asked && asked.why) || 'the scheduler refused it') + '.');
      }
      note('refresh', 'asked for attribute source ' + id + ' to read every ' +
           'person now');
      log.debug("Leaving AttributeSources.act(). Queued.");
      return { ok: true, runId: asked.runId,
               message: 'Attribute source ' + id + ' reads the realm\'s ' +
                        'people now, a page at a time, on the scheduler.' };
    }

    if (action === 'refresh-person') {
      return this.refreshPersonAct(given, note);
    }

    log.debug("Leaving AttributeSources.act(). Unknown action.");
    return this.refusal('STS-ADMIN-0500', 'Unknown action "' + action +
      '". The six are: add-source, update-source, remove-source, ' +
      'test-source, refresh-source, refresh-person.');
  }

  // refresh-person: one person, from every source that allows on-demand
  // (or the one named).
  private async refreshPersonAct(given: Json,
                                 note: (w: string, d: string) => void):
      Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering AttributeSources.refreshPersonAct().");
    const username = String(given.username || given.user || '').trim();
    const dir = this.deps.directory();
    if (!username || !dir || !dir.personAttributes(username)) {
      log.debug("Leaving AttributeSources.refreshPersonAct(). Nobody.");
      return this.refusal('STS-ATTR-0011', 'There is no person "' + username +
        '" in this realm.');
    }
    const only = String(given.id || given.source || '').trim();
    const result = await this.refreshPerson(username, 'on-demand', only);
    note('refresh', 'read ' + username + ' from ' +
         (only || 'the on-demand sources') + ': ' +
         (result.changed.join(', ') || 'nothing changed'));
    log.debug("Leaving AttributeSources.refreshPersonAct().");
    return { ok: result.failures.length === 0, changed: result.changed,
             failures: result.failures,
             errors: result.failures.map(function (one) {
               return one.source + ': ' + one.why;
             }),
             message: username + ' was read: ' +
                      (result.changed.length ? result.changed.join(', ') +
                        ' changed' : 'nothing changed') +
                      (result.failures.length ? '; ' + result.failures.length +
                        ' source(s) failed' : '') + '.' };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). Its wiring
// registers the scheduled refresh.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AttributeSources>(
  'attribute-sources/attribute_sources',
  () => new AttributeSources(AttributeSources.defaultDeps()),
  function (instance: AttributeSources): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Attribute sources: the register, and the refresh that reads people's
 * attributes from operators' databases onto their entries (#94).
 *
 * A library that registers no route. The composition root builds the
 * instance; each function here forwards to it.
 *
 * @namespace
 */
export = {
  AttributeSources: AttributeSources,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: AttributeSources): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * Fills the directory's slot; `ldap_server.js` calls it when it loads.
   *
   * @param hooks - the register's store, a person's entry, the realm's
   *   people and the one write
   */
  setDirectory: function (hooks: DirectoryHooks | null): void {
    log.debug("Entering setDirectory().");
    directory = hooks || null;
    log.debug("Leaving setDirectory().");
  },
  REFRESH_JOB: REFRESH_JOB,
  MODES: MODES,
  list: slot.forward('list'),
  get: slot.forward('get'),
  view: slot.forward('view'),
  act: slot.forward('act'),
  refreshPerson: slot.forward('refreshPerson'),
  refreshAtSignIn: slot.forward('refreshAtSignIn'),
  runScheduled: slot.forward('runScheduled')
};
