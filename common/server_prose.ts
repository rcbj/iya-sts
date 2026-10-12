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
  recognise(obj: Record<string, unknown>,
            lookup: (key: string, english: string) => string):
    Record<string, unknown> | null;
}

/**
 * A negotiated reader: the catalogs to read, best first, English excluded.
 */
interface ProseTranslator {
  locale: string;
  chain: string[];
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
             sources: { settings: settingsSource() } };
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
   * @returns the translator, or null
   */
  translatorFor(acceptLanguage: unknown): ProseTranslator | null {
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
    const walk = function (value: unknown): unknown {
      if (!value || typeof value !== 'object' || seen.has(value)) {
        return value;
      }
      if (Array.isArray(value)) {
        seen.add(value);
        const out = value.map(walk);
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
        const found = sources[ns].recognise(obj, function (key, english) {
          return translator.lookup(ns, key, english);
        });
        if (found) {
          obj = found;
        }
      });
      const out: Record<string, unknown> = {};
      Object.keys(obj).forEach(function (key) {
        out[key] = walk(obj[key]);
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
  namespaces: slot.forward('namespaces'),
  extract: slot.forward('extract'),
  entriesOf: slot.forward('entriesOf'),
  coverage: slot.forward('coverage'),
  problems: slot.forward('problems'),
  translatorFor: slot.forward('translatorFor'),
  translateView: slot.forward('translateView')
};
