// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: config_dump.ts
// ---------------------------------------------------------------------------
// MASKING THE SETTINGS TABLE (#1478), AND THE CONFIGURATION DUMP, ITS ONE
// EXPORT. `maskDescribed()` is what `GET /admin-api/config`, every page's
// settings block and the configuration operations' answers show of a sensitive
// parameter. `config.describe()` stays exact, because the service runs on it.
//
// A FORM POSTS BACK WHAT IT WAS DRAWN WITH. Saving a settings section posts
// every field, so the mask would be stored as the new password.
// `isEchoOfMask()` is how the writers leave such a field alone.
//
// THE CONFIGURATION DUMP: every configuration parameter of this running
// instance, the global values and what each trust realm sets, with every
// sensitive value masked. `GET /admin-api/config-dump`, the console's Server
// configuration -> Configuration dump and `utilities/config-dump.js` all read
// this one answer, so there is one place a value is masked and none of the
// three doors can show what another hides.
//
// ONLY PARAMETERS. `common/config.js`'s table and a realm's own values of it.
// Directory objects (people, groups, applications, federation relationships)
// are data, read through their own operations.
//
// MASKING ERRS TOWARDS HIDING. A parameter is sensitive when `config.js` marks
// it `secret: true` or its name says it holds a secret, and a parameter whose
// name only POINTS at a secret (`mail.smtpPasswordRef`, `tls.keyFile`) is
// shown, because where a secret lives is what an operator reads a dump for. A
// new parameter called `something.apiKey` is masked with nothing to remember.
// Every other string is still read for a secret carried inside it: a database
// URL's password, a PEM private key, a JWT, a JWK's private members.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import version = require('../common/version');
import auditLog = require('../common/audit');

type Json = any;

interface ConfigDumpDeps {
  log: typeof helpers.log;
  config: Json;
  realms: Json;
  version: Json;
  auditLog: Json;
  now(): Date;
}

const FORMAT = 'iya-sts-config-dump/1';
const MASK = '********';

const SENSITIVE_NAME = new RegExp(
  'secret|passw|passphrase|token|salt|credential|privatekey|clientkey|apikey',
  'i');
// A name ending in one of these says where a secret is, or describes one.
const POINTER_NAME = new RegExp(
  '(file|files|ref|field|vault|region|mount|role|url|urls|uri|endpoint|' +
  'host|hosts|port|alg|algs|algorithm|algorithms|format|formats|type|types|' +
  'doors|method|methods|lifetime|ttl|length|prefix|header|attribute)$', 'i');

const PEM_PRIVATE = new RegExp(
  '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----' +
  '[\\s\\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----|$)', 'g');
const JOSE = /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*(?:\.[\w-]+\.[\w-]+)?/g;
const URL_PASSWORD = /\b([a-z][a-z0-9+.-]*:\/\/[^\s/:@]*):([^\s/@]+)@/gi;
const AUTH_HEADER = /\b(Basic|Bearer|DPoP)\s+[A-Za-z0-9+/._~-]{8,}=*/g;
const ASSIGNED = new RegExp(
  '(["\']?[\\w-]*(?:secret|password|passwd|pwd|token|accesskey|apikey)' +
  '[\\w-]*["\']?\\s*[=:]\\s*)(["\']?)[^"\'&;,\\s]+', 'gi');
const JWK_PRIVATE = /("(?:d|p|q|dp|dq|qi|k|oth|priv|seed)"\s*:\s*)"[^"]*"/g;

/**
 * Builds the configuration dump and masks what it carries.
 */
class ConfigDump {
  // The table's rows by key, built once: the table does not change, and a
  // realm list asks once per value of every realm.
  private settingRows: Map<string, Json> | null = null;

  /**
   * @param deps - the logger, the settings table, the realms, the version,
   *   the audit log and the clock
   */
  constructor(private readonly deps: ConfigDumpDeps) {
    deps.log.debug("Entering ConfigDump.constructor().");
    deps.log.debug("Leaving ConfigDump.constructor().");
  }

  /**
   * The dependencies this is built with.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ConfigDumpDeps {
    helpers.log.debug("Entering ConfigDump.defaultDeps().");
    helpers.log.debug("Leaving ConfigDump.defaultDeps().");
    return { log: helpers.log, config: config, realms: realms,
             version: version, auditLog: auditLog,
             now: function (): Date {
               return new Date();
             } };
  }

  // A hot path, run for every parameter of every realm in a dump: no
  // Entering/Leaving pair in this or the three helpers below, which would
  // drown the log.
  /**
   * Says whether a parameter's name means its value is a secret.
   *
   * @param key - the dotted key
   * @returns true when the value is masked whole
   */
  static nameIsSensitive(key: string): boolean {
    const last = String(key || '').split('.').pop() || '';
    return SENSITIVE_NAME.test(last) && !POINTER_NAME.test(last);
  }

  /**
   * Masks any secret carried inside a string.
   *
   * @param text - the string
   * @returns the string with each secret in it replaced
   */
  static maskText(text: string): string {
    let out = text.replace(PEM_PRIVATE, MASK)
                  .replace(JOSE, MASK)
                  .replace(URL_PASSWORD, '$1:' + MASK + '@')
                  .replace(AUTH_HEADER, '$1 ' + MASK)
                  .replace(ASSIGNED, '$1$2' + MASK);
    if (out.indexOf('"kty"') >= 0) {
      out = out.replace(JWK_PRIVATE, '$1"' + MASK + '"');
    }
    return out;
  }

  /**
   * Masks one value of a parameter.
   *
   * @param value - a string, a list of strings, or anything else
   * @param whole - true when the parameter is sensitive by name or mark
   * @returns the masked value, the same value when nothing was hidden
   */
  static maskValue(value: Json, whole: boolean): Json {
    if (Array.isArray(value)) {
      return value.map(function (one: Json): Json {
        return ConfigDump.maskValue(one, whole);
      });
    }
    if (typeof value !== 'string' || value === '') {
      return value;
    }
    return whole ? MASK : ConfigDump.maskText(value);
  }

  /**
   * A described parameter with its sensitive values masked: the same row,
   * `masked: true` on it when anything was hidden.
   *
   * @param row - the parameter as `config.describe()` answers it
   * @param secrets - the keys `config.js` marks secret
   * @returns a copy of the row
   */
  static maskDescribed(row: Json, secrets: Set<string>): Json {
    if (row.type !== 'string' && row.type !== 'csv') {
      return row;
    }
    const whole = secrets.has(row.key) || ConfigDump.nameIsSensitive(row.key);
    const value = ConfigDump.maskValue(row.value, whole);
    const dflt = ConfigDump.maskValue(row.default, whole);
    const out = Object.assign({}, row, {
      value: value, default: dflt,
      text: ConfigDump.maskValue(row.text, whole)
    });
    if (JSON.stringify(value) !== JSON.stringify(row.value) ||
        JSON.stringify(dflt) !== JSON.stringify(row.default)) {
      out.masked = true;
    }
    return out;
  }

  /**
   * One parameter as a dump carries it: no prose, the value masked.
   *
   * @param row - the parameter as `config.describe()` answers it
   * @param secrets - the keys `config.js` marks secret
   * @returns the row, `masked: true` on it when anything was hidden
   */
  static row(row: Json, secrets: Set<string>): Json {
    const shown = ConfigDump.maskDescribed(row, secrets);
    const out: Json = {
      key: shown.key, group: shown.group, type: shown.type,
      value: shown.value, default: shown.default, source: shown.source,
      env: shown.env, overridden: shown.overridden, editable: shown.editable
    };
    if (shown.masked) {
      out.masked = true;
    }
    return out;
  }

  /**
   * The settings groups as an answer shows them.
   *
   * @param groups - `{ group, settings }` rows from `config.js`
   * @returns the groups, each row masked
   */
  maskGroups(groups: Json[]): Json[] {
    const { log, config: cfg } = this.deps;
    log.debug("Entering ConfigDump.maskGroups().");
    const secrets = new Set<string>(cfg.secretKeys());
    const out = groups.map(function (group: Json): Json {
      return Object.assign({}, group, {
        settings: group.settings.map(function (row: Json): Json {
          return ConfigDump.maskDescribed(row, secrets);
        })
      });
    });
    log.debug("Leaving ConfigDump.maskGroups().");
    return out;
  }

  /**
   * One described parameter as an answer shows it.
   *
   * @param row - the parameter as `config.describe()` answers it
   * @returns the row, masked
   */
  maskRow(row: Json): Json {
    const { log, config: cfg } = this.deps;
    log.debug("Entering ConfigDump.maskRow().");
    log.debug("Leaving ConfigDump.maskRow().");
    return ConfigDump.maskDescribed(row, new Set<string>(cfg.secretKeys()));
  }

  /**
   * One parameter's value as an answer shows it, for an answer that carries
   * a key and a value rather than a described row. A key no row has is
   * treated as a string, which errs towards hiding.
   *
   * @param key - the dotted key
   * @param value - its value
   * @returns the value, masked
   */
  maskKeyed(key: string, value: Json): Json {
    const { log, config: cfg } = this.deps;
    log.debug("Entering ConfigDump.maskKeyed().");
    if (!this.settingRows) {
      this.settingRows = new Map(cfg.SETTINGS.map(function (one: Json) {
        return [one.key, one] as [string, Json];
      }));
    }
    const row = this.settingRows.get(key);
    const free = !row || row.type === 'string' || row.type === 'csv';
    const out = free
      ? ConfigDump.maskValue(value, !!(row && row.secret) ||
                                    ConfigDump.nameIsSensitive(key))
      : value;
    log.debug("Leaving ConfigDump.maskKeyed().");
    return out;
  }

  /**
   * Says whether a posted value is the mask this service drew for the
   * parameter, which means "leave it as it is".
   *
   * @param row - the parameter as `config.describe()` answers it
   * @param posted - the posted value
   * @returns true when nothing should be written
   */
  isEchoOfMask(row: Json, posted: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering ConfigDump.isEchoOfMask().");
    const shown = this.maskRow(row);
    const echo = !!shown.masked && String(posted) === String(shown.text);
    log.debug("Leaving ConfigDump.isEchoOfMask(). " + echo);
    return echo;
  }

  /**
   * Builds the dump. In the default realm it is the global parameters and
   * every realm's own values; under a realm's prefix it is that realm's
   * effective parameters alone.
   *
   * @param actor - who asked, for the audit row
   * @returns the dump
   */
  build(actor: string): Json {
    const { log, config: cfg, realms: rlm, version: ver, auditLog: audit,
            now } = this.deps;
    log.debug("Entering ConfigDump.build().");
    const secrets = new Set<string>(cfg.secretKeys());
    const toRow = function (row: Json): Json {
      return ConfigDump.row(row, secrets);
    };
    const snapshot = cfg.snapshot();
    const settings: Json[] = [];
    snapshot.groups.forEach(function (group: Json): void {
      group.settings.forEach(function (row: Json): void {
        settings.push(toRow(row));
      });
    });
    const here = rlm.currentId();
    const service = here === rlm.DEFAULT_ID;
    const others = !service ? [] : rlm.list().filter(function (r: Json) {
      return r.id !== rlm.DEFAULT_ID;
    }).map(function (r: Json): Json {
      const keys = Object.keys(r.overrides || {});
      return { id: r.id, settings: rlm.run(r, function (): Json[] {
        return cfg.describeKeys(keys);
      }).map(toRow) };
    });
    const count = function (rows: Json[]): number {
      return rows.filter(function (one: Json): boolean {
        return !!one.masked;
      }).length;
    };
    const maskedValues = others.reduce(function (n: number, r: Json) {
      return n + count(r.settings);
    }, count(settings));
    const out = {
      format: FORMAT,
      generatedAt: now().toISOString(),
      version: ver.load().version,
      scope: service ? 'service' : 'realm',
      realm: here,
      configFile: snapshot.configFile,
      defaultsFile: snapshot.defaultsFile,
      settingCount: settings.length,
      masking: { mask: MASK, maskedValues: maskedValues },
      settings: settings,
      realms: others
    };
    audit.record({ category: 'admin', action: 'admin.config-dump',
      actor: actor || '', target: here, outcome: 'success',
      summary: 'The configuration was exported: ' + settings.length +
               ' parameters, ' + others.length + ' other realm(s), ' +
               maskedValues + ' value(s) masked.',
      detail: { scope: out.scope, realms: others.length,
                maskedValues: maskedValues } });
    log.debug("Leaving ConfigDump.build(). " + settings.length +
              " parameter(s), " + others.length + " other realm(s).");
    return out;
  }
}

const instance = new ConfigDump(ConfigDump.defaultDeps());

export = {
  ConfigDump: ConfigDump,
  MASK: MASK,
  FORMAT: FORMAT,
  /**
   * Builds the dump.
   *
   * @param actor - who asked
   * @returns the dump
   */
  build: (actor: string): Json => instance.build(actor),
  /**
   * The settings groups as an answer shows them.
   *
   * @param groups - the groups
   * @returns the groups, masked
   */
  maskGroups: (groups: Json[]): Json[] => instance.maskGroups(groups),
  /**
   * One described parameter as an answer shows it.
   *
   * @param row - the row
   * @returns the row, masked
   */
  maskRow: (row: Json): Json => instance.maskRow(row),
  /**
   * One parameter's value as an answer shows it.
   *
   * @param key - the dotted key
   * @param value - its value
   * @returns the value, masked
   */
  maskKeyed: (key: string, value: Json): Json =>
    instance.maskKeyed(key, value),
  /**
   * Says whether a posted value only repeats the mask.
   *
   * @param row - the described parameter
   * @param posted - the posted value
   * @returns true when nothing should be written
   */
  isEchoOfMask: (row: Json, posted: Json): boolean =>
    instance.isEchoOfMask(row, posted)
};
