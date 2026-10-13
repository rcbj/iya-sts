// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: server_prose.ts
//
// ---------------------------------------------------------------------------
// THE PROSE THE SERVER WRITES INTO A CONSOLE VIEW, IN THE READER'S LANGUAGE
// (#543, 2026-10-12).
//
// #539 translated every word the console's own renderers write and left one
// kind of text English: the sentences a VIEW carries — a setting's label,
// description and restart reason, and (in later phases) a policy's rule
// sentences and a module's notes — which the console draws as they arrive.
// rcbj's four answers on #543:
//
//   1. THE SERVER TRANSLATES, AND ONLY ON REQUEST. `/admin-api` translates
//      while it answers, and only when the caller names a language in
//      `Accept-Language`: the console sends the locale it negotiated, any
//      other caller may send its own. A caller that names none reads
//      English, whatever a realm's locale policy defaults to, so automation
//      sees no change. Only the request's own header is negotiated — not the
//      cookie, not the entry, not the policy — because the console already
//      negotiated those and sends the answer.
//   2. CONSOLE PROSE ONLY. The OpenAPI documents stay English
//      (`admin_api.ts` asks `translatesAnswer()` and is told no for them).
//   3. ENGLISH STAYS IN THE SOURCE, beside the code it documents (`config.js`'s
//      rows). `common/prose_locales/<ns>/en.json` is GENERATED from it
//      (`extract()`, `node tests/tools/prose-catalogs.js`), and
//      `tests/server_prose_catalogs.js` fails when it is stale. Every
//      translation records the hash of the English it was made from; when
//      the English changes the translation is no longer served — the reader
//      gets the new English — and the test lists it as stale.
//   4. PHASED, MACHINE-TRANSLATED, MARKED UNREVIEWED as #539's catalogs are
//      (`common/locales/catalogs.json`'s `status`, which these share).
//
// ---------------------------------------------------------------------------
// WHY NOT `common/locales/`. Those catalogs are ICU messages: a brace is
// syntax, and the catalog test refuses a literal one. This prose is PLAIN
// TEXT — a setting description says `/pki/chain/{scope}/{sha256}.pem` — and
// each translation carries a hash beside its text. So it is a second kind
// of catalog, in a directory of its own, as the mail templates are
// (`common/mail_locales/`). It shares #539's catalog list and its
// negotiation (`i18n.negotiate()`), so a language is added once.
//
//   common/prose_locales/<ns>/en.json     generated: key → English
//   common/prose_locales/<ns>/<tag>.json  key → { en: <hash>, text }
//
// A regional catalog is an overlay, holding only what differs, exactly as
// in #539.
//
// ---------------------------------------------------------------------------
// HOW A VIEW IS TRANSLATED: BY EXACT MATCH, AFTER IT IS BUILT.
// `translateView()` walks an answer and asks each namespace's RECOGNISER of
// every plain object in it. The settings recogniser knows a described
// setting by its `key`, and replaces `label`, `description`, `restartReason`
// and each `csvValueNotes` sentence only where the member is EXACTLY that
// setting's English. So a
// value a caller stored is never touched (it is not the row's English), and
// every view that carries described settings — `/admin-api/config`, each
// page's settings block, the token-lifetime and claim pages — is translated
// without a translator threaded through the dozens of places that build
// one. The alternative was a translator argument on `config.describe()`,
// which the OpenAPI example also calls.
//
// A LIBRARY (rule 3): `helpers`, `config`, `error_codes`, `crypto`, `i18n`,
// the instance slot, `fs` and `path` — `page_locale.ts`'s neighbours, none of
// which requires this back. It registers nothing.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import helpers = require('./helpers');
import config = require('./config');
import errorCodes = require('./error_codes');
import stsCrypto = require('./crypto');
import i18n = require('./i18n');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

/**
 * One translation as a catalog stores it: the hash of the English it was
 * made from, and the text.
 */
interface ProseEntry {
  en: string;
  text: string;
}

/**
 * A namespace's source of English, and how a view carries it.
 */
interface ProseSource {
  /**
   * Every message of the namespace in English, by key, from the source.
   */
  extract(): Record<string, string>;
  /**
   * Answers a translated copy of one object of a view, or null when the
   * object is not this namespace's.
   */
  recognise?(obj: Record<string, unknown>,
             lookup: (key: string, english: string) => string):
    Record<string, unknown> | null;
  /**
   * A PHRASE source: answers the translation of one string of an answer to
   * one of its routes, or null when the string is not its English.
   */
  translateString?(route: string, text: string,
                   lookup: (key: string, english: string) => string):
    string | null;
}

/**
 * What a phrase source is built from: the routes whose answers carry its
 * English, and the English itself — a message holding `{{name}}` is a
 * TEMPLATE, filled with `ServerProse.fill()` where the sentence is made.
 */
interface PhraseSpec {
  routes: string[];
  extract(): Record<string, string>;
}

/**
 * A negotiated reader: the catalogs to read, best first, English excluded.
 */
interface ProseTranslator {
  locale: string;
  chain: string[];
  route: string;
  lookup(ns: string, key: string, english: string): string;
}

/**
 * How one catalog covers one namespace.
 */
interface ProseCoverage {
  total: number;
  current: number;
  stale: string[];
  missing: string[];
  orphans: string[];
}

/**
 * The dependencies the instance is built from.
 */
interface ServerProseDeps {
  log: typeof helpers.log;
  errorCodes: { tag(code: string): string };
  directory: string;
  sources: Record<string, ProseSource>;
}

/**
 * The catalog every translation is made from.
 */
const SOURCE = 'en';

/**
 * The prose members of a described setting, in the order a key names them.
 */
const SETTING_FIELDS = ['label', 'description', 'restartReason'];

/**
 * The separator between a setting's key and the member it names. A
 * setting key has dots in it, so a dot cannot be the separator.
 */
const SEP = '|';

/**
 * A template's placeholders: `{{name}}`, a word of letters and digits.
 */
const PLACEHOLDER = /\{\{([A-Za-z0-9]+)\}\}/g;

/**
 * The members whose strings are identifiers or values a caller acts on —
 * never translated, whatever namespace has their words (#543 phase 3, where
 * the probe found a setting's `group` translated because "Admin console" is
 * also an endpoint name). The console joins on several of them.
 */
const NEVER_TRANSLATED = new Set([
  'group', 'key', 'id', 'path', 'route', 'routes', 'action',
  'actions', 'value', 'values', 'default', 'env', 'legacyEnv',
  'appconfigPath', 'enumValues', 'csvValues', 'source', 'dn', 'href', 'url',
  'container', 'attribute', 'method', 'methods', 'operationId', 'page',
  'pages', 'setWith', 'mirrors', 'realm', 'kind', 'type', 'state', 'status',
  'by', 'cards', 'specs', 'mode', 'category', 'protocol', 'family', 'tag',
  'locale', 'lang'
]);

/**
 * The separator a list of phrases is joined with, inside a filled template.
 */
const LIST_SEP = ', ';

/**
 * Builds a PHRASE source (#543 phase 2): the prose of a module's tables and
 * the sentences it makes from templates, translated wherever an answer to
 * one of its routes carries them EXACTLY.
 *
 * - A string equal to a message's English is replaced by its translation.
 * - A string a template matches is refilled in the translated template,
 *   each parameter translated in turn when it is itself a message of this
 *   namespace, a filled template, or a list of those joined with ', ';
 *   anything else (a number, a name, a DN) is carried over as it was.
 * - A key holding `.param.` names a phrase used only as a parameter.
 * - Only on the source's routes (`*` naming every route), so a value
 *   elsewhere that happens to read like a sentence of it is never touched.
 *
 * @param given - the routes and the English, or a function answering them
 * @returns the source
 */
function phraseSource(given: PhraseSpec | (() => PhraseSpec)): ProseSource {
  log.debug("Entering phraseSource().");
  // A source may be declared LAZILY, so that building this module's
  // instance loads none of the modules whose prose it translates.
  let loaded: PhraseSpec | null = typeof given === 'function' ? null : given;
  const specOf = function (): PhraseSpec {
    if (!loaded) {
      loaded = (given as () => PhraseSpec)();
    }
    return loaded;
  };
  let index: { exact: Map<string, string>, params: Map<string, string>,
               templates: { key: string, english: string, re: RegExp,
                            names: string[] }[] } | null = null;
  const build = function () {
    if (index) {
      return index;
    }
    const all = specOf().extract();
    const exact = new Map<string, string>();
    // A PARAMETER-ONLY phrase (a key holding `.param.`) — 'none' in 'first
    // factors: none' — is translated inside a filled template and never as
    // a whole string, where it could be a value a form sends back.
    const params = new Map<string, string>();
    const templates = [];
    Object.keys(all).forEach(function (key) {
      const english = all[key];
      const names: string[] = [];
      english.replace(PLACEHOLDER, function (m, name) {
        names.push(name);
        return m;
      });
      if (!names.length) {
        const into = key.indexOf('.param.') >= 0 ? params : exact;
        if (!into.has(english)) {
          into.set(english, key);
        }
        return;
      }
      const source = english.split(PLACEHOLDER).map(function (part, i) {
        // split() with a capture group interleaves the names at odd places.
        return i % 2 ? '([\\s\\S]+?)'
                     : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      }).join('');
      templates.push({ key: key, english: english,
                       re: new RegExp('^' + source + '$'), names: names });
    });
    // The template with the most literal text first, so 'at least {{n}}
    // symbols' is tried before anything shorter it would also match.
    templates.sort(function (a, b) {
      return b.english.replace(PLACEHOLDER, '').length -
             a.english.replace(PLACEHOLDER, '').length;
    });
    index = { exact: exact, params: params, templates: templates };
    return index;
  };
  // Called for every string of every translated answer, so no
  // Entering/Leaving pair (the hot-path exception).
  const translate = function (text: string, lookup, depth: number): string |
      null {
    const { exact, templates } = build();
    const key = exact.get(text);
    if (key) {
      return lookup(key, text);
    }
    if (depth > 3 || !templates.length) {
      return null;
    }
    for (const one of templates) {
      const m = one.re.exec(text);
      if (!m) {
        continue;
      }
      const params: Record<string, string> = {};
      one.names.forEach(function (name, i) {
        params[name] = value(m[i + 1], lookup, depth + 1);
      });
      return ServerProse.fill(lookup(one.key, one.english), params);
    }
    return null;
  };
  // A parameter: a phrase, or a list of them, or data left as it was. The
  // list is segmented so that a phrase holding a comma stays whole.
  const value = function (text: string, lookup, depth: number): string {
    const only = build().params.get(text);
    if (only) {
      return lookup(only, text);
    }
    const whole = translate(text, lookup, depth);
    if (whole !== null) {
      return whole;
    }
    const parts = text.split(LIST_SEP);
    if (parts.length < 2) {
      return text;
    }
    // best[i]: the translated pieces of parts[0..i), or null.
    const best: (string[] | null)[] = [[]];
    for (let i = 1; i <= parts.length; i++) {
      best[i] = null;
      for (let j = i - 1; j >= 0 && !best[i]; j--) {
        if (!best[j]) {
          continue;
        }
        const piece = translate(parts.slice(j, i).join(LIST_SEP), lookup,
                                depth);
        if (piece !== null) {
          best[i] = best[j].concat([piece]);
        }
      }
    }
    return best[parts.length] ? best[parts.length].join(LIST_SEP) : text;
  };
  log.debug("Leaving phraseSource().");
  return {
    extract: function () {
      return specOf().extract();
    },
    translateString: function (route, text, lookup) {
      // `*` is EVERY route: a namespace whose phrases every page may carry
      // — the endpoint names each Protocols page lists — and which is kept
      // to names short and specific enough to be matched anywhere.
      const routes = specOf().routes;
      if (routes.indexOf('*') < 0 && routes.indexOf(route) < 0) {
        return null;
      }
      return translate(text, lookup, 0);
    }
  };
}

/**
 * Collects the prose of a module's table — the string members named, at
 * any depth — keyed by where it sits: `<prefix>.<id>.<member>`, an array
 * element named by its own `key`, `name`, `id`, `attribute`, `method`,
 * `kind` or `type` where it has one and by its index where it has none.
 *
 * @param prefix - the key's first part
 * @param table - the table: an object or an array
 * @param members - the member names that hold prose
 * @returns key → English
 */
function harvest(prefix: string, table: unknown,
                 members: string[]): Record<string, string> {
  log.debug("Entering harvest(). " + prefix);
  const out: Record<string, string> = {};
  const IDS = ['key', 'name', 'id', 'attribute', 'method', 'kind', 'type',
               'role', 'mode', 'category', 'action'];
  const walk = function (value: unknown, path: string, depth: number) {
    if (depth > 8 || !value || typeof value !== 'object') {
      return;
    }
    if (Array.isArray(value)) {
      const used = new Set<string>();
      value.forEach(function (one, i) {
        const id = one && typeof one === 'object'
          ? IDS.map(function (name) {
            return (one as Record<string, unknown>)[name];
          }).filter(function (v) {
            return typeof v === 'string' && v;
          })[0]
          : '';
        // TWO ELEMENTS WITH ONE ID (an audit action's `category` is shared
        // by many) would collide and one message would be lost: the second
        // and later take their index as well.
        let at = path + '.' + (id || String(i));
        if (used.has(at)) {
          at = at + '#' + i;
        }
        used.add(at);
        walk(one, at, depth + 1);
      });
      return;
    }
    const obj = value as Record<string, unknown>;
    Object.keys(obj).forEach(function (name) {
      const v = obj[name];
      // An IDENTIFIER is not prose — a `governs` of `userPassword`, a value
      // with no letter, a bare path — and harvesting it would translate it
      // wherever the route's answer carries it.
      if (typeof v === 'string' && v.trim() && members.indexOf(name) >= 0 &&
          /[A-Za-z]/.test(v) && !/^[a-z]+[A-Z][A-Za-z0-9]*$/.test(v) &&
          !/^\/\S*$/.test(v)) {
        out[path + '.' + name] = v;
      } else if (v && typeof v === 'object') {
        walk(v, path + '.' + name, depth + 1);
      }
    });
  };
  walk(table, prefix, 0);
  log.debug("Leaving harvest(). " + Object.keys(out).length);
  return out;
}

// ---------------------------------------------------------------------------
// THE PHRASE NAMESPACES (#543 phase 2): namespace → the modules whose prose
// it is, by require path from here. Each module exports `PROSE_ROUTES` —
// the `/admin-api` routes whose answers carry its prose, as the registration
// loop names them (`res.locals.proseRoute`) — and `prose()`, its English by
// key, its keys prefixed so that two modules of a namespace cannot collide.
// A namespace's catalogs are `common/prose_locales/<ns>/`. An entry may be
// `{ path, routes, prose }` instead, naming other exports: a module whose
// `PROSE_ROUTES`/`prose()` are one namespace's and which offers a part of
// another (`admin_views.ts`, kerberos's, holds the delegation map keys).
// ---------------------------------------------------------------------------
const PHRASE_MODULES: Record<string, Array<string | { path: string,
  routes: string, prose: string }>> = {
  // Directory → Policies: every kind's tables, its `describe()` templates
  // and the page's own sentences.
  policies: ['../admin-core/policy_kinds'],
  // Server configuration → Mode: the requirements and the refusal reasons.
  mode: ['./mode'],
  // Server configuration → Realms: what is separated, and what is shared.
  realms: ['./realms'],
  // Monitoring → Audit: the categories and the actions.
  audit: ['./audit'],
  // Server configuration → Listeners: the sockets and the hosted
  // applications on them.
  listeners: ['../admin-ui/listeners_admin', './hosted_applications',
              './listener_map'],
  // Directory → the LDAP pages, and the application register's schema
  // wherever the applications pages carry it.
  ldap: ['../ldap/ldap_server', './applications', './devices',
         '../xacml/xacml_store', '../xacml/xacml_pep_registry'],
  // Federation: the roles, protocols, mechanisms, subject policies and the
  // relationship schema, and the map's labels.
  federation: ['../federation/federation', '../federation/federation_graph'],
  // Protocols → SPIFFE: who authenticates where, the key types, the
  // registry's schema and the attestors.
  spiffe: ['../spiffe/spiffe_auth', '../spiffe/spiffe_ca',
           '../spiffe/spiffe_registry', '../spiffe/spiffe_server',
           '../spiffe/spiffe_peer'],
  // Protocols → SCIM and Monitoring → SCIM: the operations, what it does
  // not do, the endpoints, the reachable negatives and the policy.
  scim: ['./admin_stats', '../scim/scim', '../scim/scim_auth'],
  // Server configuration → PKI: the tiers, use cases, subject kinds,
  // purposes, residency and revocation reasons.
  pki: ['./pki', './pki_revocation'],
  // Monitoring → Encryption: the data classes and the page's notes.
  encryption: ['../admin-ui/encryption_admin'],
  // Monitoring → Secrets: each secret's notes.
  secrets: ['../admin-ui/secrets_admin'],
  // Monitoring → Database: what the page is, why it is or is not drawn,
  // and each probe.
  database: ['../admin-ui/database_admin', '../persistence/persistence',
             '../persistence/persistence_postgres'],
  // Directory → Roles and the console's roster: the built-in roles, the
  // member kinds, the console's own roles and the roles schema.
  roles: ['./roles', '../admin-core/admin_actions', '../admin-ui/admin_rbac'],
  // Directory → Delegation: the modes, types and roles, and the map keys
  // drawn as markup, each a filled template.
  delegation: ['./delegation',
               { path: '../admin-core/admin_views',
                 routes: 'MAP_KEY_PROSE_ROUTES', prose: 'mapKeyProse' }],
  // Protocols → Device registration: enrolment, recognition and the notes.
  devices: ['../admin-ui/devices_admin'],
  // A person's GNAP grants, where this service runs several cells.
  gnap: ['../gnap/gnap_console'],
  // Protocols → Kerberos → Principals: the page's notes.
  kerberos: ['../admin-core/admin_views'],
  // Monitoring → Scheduler: every registered job's title and description,
  // read from the registry, and the schedule, overdue and clock sentences.
  scheduler: ['../cluster/scheduler', '../admin-ui/scheduler_admin'],
  // Monitoring → Caches: every registered cache's title, description,
  // bound, lifetime and meaning of a hit, and the page's own sentences.
  caches: ['./cache_registry', './bounded_lru', '../admin-ui/caches_admin'],
  // Server configuration → Cryptography: the families, the standards,
  // hashing, post-quantum and key establishment.
  crypto: ['../admin-ui/crypto_metadata'],
  // Monitoring → Node Health and → Worker Pools: the computed sentences
  // about limits, usage, processes and pools, each a template.
  nodehealth: ['../admin-ui/node_health_admin'],
  workerpools: ['../admin-ui/worker_pools_admin'],
  // The SCIM page's attribute mapping notes.
  scimmap: ['../scim/scim_map'],
  // The secret store's providers, probes and sources, wherever a page
  // describes where a secret or the database password comes from.
  secretstore: ['./secrets'],
  // Service → Protocol metadata: every specification's coverage, every
  // endpoint's description and effect, and every protocol card's prose.
  stsmetadata: ['../sts_metadata'],
  // The endpoint names every Protocols page lists — on EVERY route (`*`),
  // so only names that are phrases, never a bare product or protocol name.
  endpoints: ['../admin-core/protocol_endpoints']
};

/**
 * Builds the settings source: `config.js`'s `SETTINGS` rows, keyed
 * `<setting>|label`, `<setting>|description`, `<setting>|restartReason`
 * and `<setting>|csvValueNotes|<value>`.
 *
 * @returns the source
 */
function settingsSource(): ProseSource {
  log.debug("Entering settingsSource().");
  let byKey: Record<string, any> | null = null;
  // Indexed on first use rather than here: `SETTINGS` gains its per-listener
  // rows at the end of `config.js`'s load, and an index taken earlier would
  // miss them.
  const rows = function (): Record<string, any> {
    if (!byKey) {
      byKey = {};
      config.SETTINGS.forEach(function (row) {
        byKey[row.key] = row;
      });
    }
    return byKey;
  };
  log.debug("Leaving settingsSource().");
  return {
    extract: function () {
      log.debug("Entering settingsSource.extract().");
      const out: Record<string, string> = {};
      const all = rows();
      Object.keys(all).forEach(function (key) {
        const row = all[key];
        SETTING_FIELDS.forEach(function (field) {
          if (typeof row[field] === 'string' && row[field]) {
            out[key + SEP + field] = row[field];
          }
        });
        if (row.csvValueNotes && typeof row.csvValueNotes === 'object') {
          Object.keys(row.csvValueNotes).forEach(function (value) {
            const note = row.csvValueNotes[value];
            if (typeof note === 'string' && note) {
              out[key + SEP + 'csvValueNotes' + SEP + value] = note;
            }
          });
        }
      });
      log.debug("Leaving settingsSource.extract(). " +
                Object.keys(out).length);
      return out;
    },
    // Called for every object of every translated answer, so no
    // Entering/Leaving pair (the hot-path exception).
    recognise: function (obj, lookup) {
      if (typeof obj.key !== 'string') {
        return null;
      }
      const row = rows()[obj.key];
      if (!row) {
        return null;
      }
      let out: Record<string, unknown> | null = null;
      SETTING_FIELDS.forEach(function (field) {
        if (typeof obj[field] === 'string' && obj[field] === row[field]) {
          out = out || Object.assign({}, obj);
          out[field] = lookup(obj.key + SEP + field, row[field]);
        }
      });
      const notes = obj.csvValueNotes;
      if (notes && typeof notes === 'object' && row.csvValueNotes) {
        const copy: Record<string, unknown> =
          Object.assign({}, notes as Record<string, unknown>);
        Object.keys(copy).forEach(function (value) {
          const english = row.csvValueNotes[value];
          if (typeof english === 'string' && copy[value] === english) {
            copy[value] = lookup(obj.key + SEP + 'csvValueNotes' + SEP +
                                 value, english);
          }
        });
        out = out || Object.assign({}, obj);
        out.csvValueNotes = copy;
      }
      return out;
    }
  };
}

/**
 * The prose catalogs, the negotiation of a request's `Accept-Language`
 * against them, and the translation of a view.
 */
class ServerProse {
  /**
   * The catalog every translation is made from.
   */
  static readonly SOURCE = SOURCE;
  /**
   * The separator between a setting key and the member it names.
   */
  static readonly SEP = SEP;

  /**
   * Fills a prose template (#543 phase 2): each `{{name}}` replaced by its
   * parameter. Where a module makes a sentence, it makes it with this from a
   * template it declares, so the sentence and the template the server
   * matches it against cannot differ. A placeholder with no parameter is
   * left as written.
   *
   * @param template - the template
   * @param params - name → value
   * @returns the sentence
   */
  static fill(template: string, params: Record<string, unknown>): string {
    log.debug("Entering ServerProse.fill().");
    const out = String(template).replace(PLACEHOLDER, function (m, name) {
      return Object.prototype.hasOwnProperty.call(params, name)
        ? String(params[name]) : m;
    });
    log.debug("Leaving ServerProse.fill().");
    return out;
  }

  /**
   * Builds the phrase namespaces from `PHRASE_MODULES`: each a phrase
   * source over the union of its modules' `PROSE_ROUTES` and `prose()`,
   * every module required LAZILY — they require this one to fill their
   * templates, and a require at load would close a cycle.
   *
   * @returns namespace → source
   */
  static phraseNamespaces(): Record<string, ProseSource> {
    log.debug("Entering ServerProse.phraseNamespaces().");
    const out: Record<string, ProseSource> = {};
    Object.keys(PHRASE_MODULES).forEach(function (ns) {
      out[ns] = phraseSource(function () {
        const parts = PHRASE_MODULES[ns].map(function (entry) {
          const spec = typeof entry === 'string'
            ? { path: entry, routes: 'PROSE_ROUTES', prose: 'prose' } : entry;
          return { mod: require(spec.path), spec: spec };
        });
        return {
          routes: parts.reduce(function (all, part) {
            return all.concat(part.mod[part.spec.routes] || []);
          }, []),
          extract: function () {
            return parts.reduce(function (all, part) {
              return Object.assign(all, part.mod[part.spec.prose]());
            }, {});
          }
        };
      });
    });
    log.debug("Leaving ServerProse.phraseNamespaces(). " +
              Object.keys(out).length);
    return out;
  }

  /**
   * Builds a phrase source; see `phraseSource()`.
   */
  static phraseSource = phraseSource;

  /**
   * Collects a table's prose; see `harvest()`.
   */
  static harvest = harvest;

  // namespace → catalog tag → key → entry
  private catalogs: Record<string, Record<string, Record<string,
    ProseEntry>>> | null = null;
  private loadProblems: string[] = [];
  // namespace → key → English, extracted once: the source is fixed for the
  // life of the process.
  private english: Record<string, Record<string, string>> = {};

  /**
   * Builds the catalogs; nothing is read until first asked.
   *
   * @param deps - the logger, the error codes, the catalog directory and
   *   the sources
   */
  constructor(private readonly deps: ServerProseDeps) {
    deps.log.debug("Entering ServerProse.constructor().");
    deps.log.debug("Leaving ServerProse.constructor(). " + deps.directory);
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules, `common/prose_locales` and the
   *   sources
   */
  static defaultDeps(): ServerProseDeps {
    log.debug("Entering ServerProse.defaultDeps().");
    log.debug("Leaving ServerProse.defaultDeps().");
    return { log: log, errorCodes: errorCodes,
             directory: path.join(__dirname, 'prose_locales'),
             sources: Object.assign({ settings: settingsSource() },
                                    ServerProse.phraseNamespaces()) };
  }

  /**
   * The hash a translation records of the English it was made from: the
   * first sixteen hex digits of its SHA-256.
   *
   * @param english - the English text
   * @returns the hash
   */
  static hashOf(english: string): string {
    log.debug("Entering ServerProse.hashOf().");
    const out = stsCrypto.sha256Hex(Buffer.from(String(english), 'utf8'))
      .slice(0, 16);
    log.debug("Leaving ServerProse.hashOf().");
    return out;
  }

  // -------------------------------------------------------------------------
  // LOADING. Read once, on first use, as #539's catalogs are. A file that
  // cannot be read costs its translations, never the start: the reader gets
  // English, and the problem is logged under its code.
  // -------------------------------------------------------------------------
  private load(): void {
    const { log, errorCodes, directory } = this.deps;
    if (this.catalogs) {
      return;
    }
    log.debug("Entering ServerProse.load(). " + directory);
    const catalogs: Record<string, Record<string, Record<string,
      ProseEntry>>> = {};
    const tags = i18n.catalogs().map(function (c) {
      return c.tag;
    }).filter(function (tag) {
      return tag !== SOURCE;
    });
    this.namespaces().forEach((ns) => {
      catalogs[ns] = {};
      tags.forEach((tag) => {
        const file = path.join(directory, ns, tag + '.json');
        if (!fs.existsSync(file)) {
          return;
        }
        try {
          const body = JSON.parse(fs.readFileSync(file, 'utf8'));
          const flat: Record<string, ProseEntry> = {};
          Object.keys(body).forEach(function (key) {
            const one = body[key];
            if (one && typeof one.en === 'string' &&
                typeof one.text === 'string') {
              flat[key] = { en: one.en, text: one.text };
            }
          });
          catalogs[ns][tag] = flat;
        } catch (e) {
          log.debug("Caught in ServerProse.load(): " +
                    ((e && e.message) || e));
          log.error(errorCodes.tag('STS-I18N-0011') + 'i18n: ' +
                    'common/prose_locales/' + ns + '/' + tag + '.json ' +
                    'could not be read (' + ((e && e.message) || e) +
                    '); its prose falls back along the chain to English.');
          this.loadProblems.push(ns + '/' + tag + '.json could not be ' +
                                 'read: ' + ((e && e.message) || e));
        }
      });
    });
    this.catalogs = catalogs;
    log.debug("Leaving ServerProse.load(). " +
              Object.keys(catalogs).length + " namespace(s).");
  }

  /**
   * Lists the namespaces: one per source.
   *
   * @returns the namespace names, sorted
   */
  namespaces(): string[] {
    log.debug("Entering ServerProse.namespaces().");
    log.debug("Leaving ServerProse.namespaces().");
    return Object.keys(this.deps.sources).sort();
  }

  /**
   * Returns a namespace's English, from the source, by key — what
   * `en.json` must hold.
   *
   * @param ns - the namespace
   * @returns key → English; empty for an unknown namespace
   */
  extract(ns: string): Record<string, string> {
    log.debug("Entering ServerProse.extract(). " + ns);
    const source = this.deps.sources[ns];
    if (!source) {
      log.debug("Leaving ServerProse.extract(). No such namespace.");
      return {};
    }
    if (!this.english[ns]) {
      this.english[ns] = source.extract();
    }
    log.debug("Leaving ServerProse.extract().");
    return Object.assign({}, this.english[ns]);
  }

  /**
   * Returns one namespace's translations in one catalog, as stored.
   *
   * @param ns - the namespace
   * @param tag - the catalog
   * @returns key → `{ en, text }`; empty when there are none
   */
  entriesOf(ns: string, tag: string): Record<string, ProseEntry> {
    log.debug("Entering ServerProse.entriesOf(). " + ns + '/' + tag);
    this.load();
    const found = (this.catalogs[ns] || {})[tag] || {};
    log.debug("Leaving ServerProse.entriesOf(). " +
              Object.keys(found).length);
    return Object.assign({}, found);
  }

  /**
   * Says how one catalog covers one namespace: how many of the English
   * messages it translates from the CURRENT English, which it translated
   * from an older English (stale), which it lacks, and which keys it holds
   * that the English no longer has.
   *
   * @param ns - the namespace
   * @param tag - the catalog
   * @returns the coverage
   */
  coverage(ns: string, tag: string): ProseCoverage {
    log.debug("Entering ServerProse.coverage(). " + ns + '/' + tag);
    const english = this.extract(ns);
    const entries = this.entriesOf(ns, tag);
    const out: ProseCoverage = { total: 0, current: 0, stale: [],
                                 missing: [], orphans: [] };
    Object.keys(english).forEach(function (key) {
      out.total++;
      const one = entries[key];
      if (!one) {
        out.missing.push(key);
      } else if (one.en === ServerProse.hashOf(english[key])) {
        out.current++;
      } else {
        out.stale.push(key);
      }
    });
    Object.keys(entries).forEach(function (key) {
      if (!(key in english)) {
        out.orphans.push(key);
      }
    });
    log.debug("Leaving ServerProse.coverage(). " + out.current + '/' +
              out.total);
    return out;
  }

  /**
   * Lists what went wrong while the catalogs were read.
   *
   * @returns the problems, as sentences
   */
  problems(): string[] {
    log.debug("Entering ServerProse.problems().");
    this.load();
    log.debug("Leaving ServerProse.problems().");
    return this.loadProblems.slice();
  }

  // -------------------------------------------------------------------------
  // NEGOTIATION. Only the request's own `Accept-Language`, with English as
  // the last resort — never the locale policy's default (rcbj's answer 1).
  // -------------------------------------------------------------------------
  /**
   * Builds a translator for an `Accept-Language` value, or answers null
   * when there is nothing to translate into: no header, or one only
   * English answers.
   *
   * @param acceptLanguage - the header's value, or undefined
   * @param route - the route the answer is to (`res.locals.proseRoute`),
   *   which a phrase source is scoped by
   * @returns the translator, or null
   */
  translatorFor(acceptLanguage: unknown,
                route?: string): ProseTranslator | null {
    log.debug("Entering ServerProse.translatorFor().");
    if (typeof acceptLanguage !== 'string' || !acceptLanguage.trim()) {
      log.debug("Leaving ServerProse.translatorFor(). No language named.");
      return null;
    }
    const negotiated = i18n.negotiate(i18n.acceptLanguage(acceptLanguage));
    const chain = negotiated.chain.filter(function (tag) {
      return tag !== SOURCE;
    });
    if (!chain.length) {
      log.debug("Leaving ServerProse.translatorFor(). English.");
      return null;
    }
    this.load();
    const self = this;
    log.debug("Leaving ServerProse.translatorFor(). " + negotiated.locale);
    return {
      locale: negotiated.locale,
      chain: chain,
      route: String(route || ''),
      // Called for every translated member, so no Entering/Leaving pair
      // (the hot-path exception).
      lookup: function (ns, key, english) {
        const hash = ServerProse.hashOf(english);
        for (const tag of chain) {
          const one = ((self.catalogs[ns] || {})[tag] || {})[key];
          // A translation of an OLDER English is not served: the reader
          // gets what the source says now, and the catalog test lists it.
          if (one && one.en === hash) {
            return one.text;
          }
        }
        return english;
      }
    };
  }

  /**
   * Answers a translated copy of a view: every object a namespace
   * recognises is replaced by its translated copy; nothing else changes,
   * and the view given is never modified.
   *
   * @param body - the view
   * @param translator - from `translatorFor()`; null answers the view as
   *   it is
   * @returns the view, translated
   */
  translateView(body: unknown, translator: ProseTranslator | null): unknown {
    log.debug("Entering ServerProse.translateView().");
    if (!translator) {
      log.debug("Leaving ServerProse.translateView(). Nothing to do.");
      return body;
    }
    const sources = this.deps.sources;
    const names = this.namespaces();
    const seen = new Set<unknown>();
    // Called for every value of the answer, so no Entering/Leaving pair
    // (the hot-path exception).
    const phrases = names.filter(function (ns) {
      return typeof sources[ns].translateString === 'function';
    });
    const walk = function (value: unknown, member?: string): unknown {
      if (typeof value === 'string') {
        // A string under an IDENTIFIER member is never translated, whatever
        // namespace has its words: a setting's `group` "Admin console" is
        // also an endpoint name and an audit label, and the console joins
        // settings to their pages on it.
        if (member && NEVER_TRANSLATED.has(member)) {
          return value;
        }
        for (const ns of phrases) {
          const found = sources[ns].translateString(translator.route, value,
            function (key, english) {
              return translator.lookup(ns, key, english);
            });
          if (found !== null) {
            return found;
          }
        }
        return value;
      }
      if (!value || typeof value !== 'object' || seen.has(value)) {
        return value;
      }
      if (Array.isArray(value)) {
        seen.add(value);
        // An array's strings are its member's: `enumValues` are values.
        const out = value.map(function (one) {
          return walk(one, member);
        });
        seen.delete(value);
        return out;
      }
      const proto = Object.getPrototypeOf(value);
      // A Date, a Buffer, a Map: JSON decides what those become, so they
      // are left for it.
      if (proto !== Object.prototype && proto !== null) {
        return value;
      }
      seen.add(value);
      let obj = value as Record<string, unknown>;
      names.forEach(function (ns) {
        if (typeof sources[ns].recognise !== 'function') {
          return;
        }
        const found = sources[ns].recognise(obj, function (key, english) {
          return translator.lookup(ns, key, english);
        });
        if (found) {
          obj = found;
        }
      });
      const out: Record<string, unknown> = {};
      Object.keys(obj).forEach(function (key) {
        out[key] = walk(obj[key], key);
      });
      seen.delete(value);
      return out;
    };
    const out = walk(body);
    log.debug("Leaving ServerProse.translateView(). " + translator.locale);
    return out;
  }
}

const slot = new InstanceSlot<ServerProse>(
  'common/server_prose',
  () => new ServerProse(ServerProse.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The prose the server writes into a console view, in the reader's language
 * (#543). The exports forward to the instance the composition root
 * installs; the hash is static and needs none.
 *
 * @namespace
 */
export = {
  ServerProse: ServerProse,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: ServerProse): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  SOURCE: ServerProse.SOURCE,
  SEP: ServerProse.SEP,
  hashOf: ServerProse.hashOf,
  fill: ServerProse.fill,
  phraseSource: ServerProse.phraseSource,
  harvest: ServerProse.harvest,
  namespaces: slot.forward('namespaces'),
  extract: slot.forward('extract'),
  entriesOf: slot.forward('entriesOf'),
  coverage: slot.forward('coverage'),
  problems: slot.forward('problems'),
  translatorFor: slot.forward('translatorFor'),
  translateView: slot.forward('translateView')
};
