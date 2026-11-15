// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_settings.ts
//
// ===========================================================================
// A REMOTE PEP'S SETTINGS, MANAGED FROM ITS CONSOLE PAGE (#1760).
//
// rcbj (2026-11-14): "all information about the remote PEP (and reverse
// proxy) should be configurable on this new screen except the minimum
// config required for the remote PEP to be able to initially connect."
//
// So every setting the container used to take only from its environment,
// and that is not needed to REACH this service the first time, may be set
// here: stored on the PEP's own `ou=peps` entry (`xacmlPepSettings`, one
// JSON document), validated whole on write, pulled by the PEP from
// `GET /xacml/pep/settings` and applied while it runs
// (`rust/bins/xacml-pep/src/settings.rs`, whose table is this one in Rust;
// `tests/xacml_pep_settings.js` holds the two to the same keys, variables
// and bounds).
//
// THE PRECEDENCE IS SERVICE, THEN ENVIRONMENT, THEN DEFAULT. A value set
// here wins; a setting not set here is the environment variable that always
// configured it; a variable that is unset is the built-in default. That is
// the backwards compatibility rcbj's directive requires, in both
// directions: an OLDER PEP never asks for its settings and goes on reading
// its environment, and a NEWER PEP talking to an OLDER service gets a 404
// for the pull and reads its environment too.
//
// WHAT STAYS IN THE ENVIRONMENT (`BOOTSTRAP`), each for a reason a reader
// can check: what is needed before the first pull (the service's URL, the
// PEP's name, its client certificate, key, anchors and whether to verify
// the service), the ports it binds (rebinding a listening socket while it
// serves is not attempted), the files on its own disk its TLS stacks read,
// whether the proxy's listeners are bound at all (the proxy configuration's
// own `enabled` is the managed switch), and the operator's local narrowing
// of the AuthZEN callers this service sends — a narrowing this service
// could set would narrow nothing.
//
// NO PROSE IN THE CATALOGUE. The rows answer keys, types and bounds; what
// each means is the console's catalog in the reader's language (#570's
// decision 3: the APIs stay language-free).
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import mode = require('../common/mode');
import stsCrypto = require('../common/crypto');
// The listeners defined for a PEP (#1760), which travel on this pull.
import pepListeners = require('./xacml_pep_listeners');

const { log } = helpers;

// One managed setting. `applies` says when a change takes effect at the
// PEP: `now` (read at each use), `nextRound` (the poll or heartbeat
// timer's next wait), `nextReload` (the HTTPS listeners' next re-read) or
// `nextReconcile` (the proxy's relying parties rebuilt after the next
// poll).
interface SettingRow {
  key: string;
  env: string;
  type: 'integer' | 'boolean' | 'enum' | 'text' | 'url' | 'origin';
  group: 'registration' | 'enforcement' | 'sync' | 'listener' | 'logging' |
         'authzen' | 'proxy';
  default: string | number | boolean;
  min?: number;
  max?: number;
  values?: string[];
  maxLength?: number;
  applies: 'now' | 'nextRound' | 'nextReload' | 'nextReconcile';
  // True where product mode refuses the value `true` (a verification
  // turned off).
  refusedInProduct?: boolean;
}

// One environment variable that stays the PEP's own.
interface BootstrapRow {
  env: string;
  reason: 'connect' | 'bind' | 'file' | 'listeners' | 'narrowing';
  default: string;
}

interface Refusal {
  ok: false;
  why: string;
  code: string;
}

interface Validated {
  ok: true;
  settings: Record<string, unknown>;
}

// What a PEP reports on its heartbeat about each setting in force.
interface InUse {
  at: string;
  token: string;
  values: Record<string, { value: unknown; source: string }>;
}

interface PepSettingsDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    tag(code: string): string;
  };
  // Whether product mode refuses a verification turned off.
  skipsVerification(): boolean;
  dialsPlainHttp(): boolean;
  sha256Base64(text: string): string;
}

const DAY_MS = 86400000;
const BIASES = ['deny-biased', 'permit-biased'];
const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];
const SOURCES = ['service', 'environment', 'default'];
// No C0 control character and no DEL.
const CONTROL = /[\u0000-\u001f\u007f]/;
const URL_MAX = 2048;

// THE TABLE, in the order the console draws it. The defaults are the
// container's (`options.rs`); the bounds are what this service accepts,
// and the PEP reads a pulled value again by the same ones.
const SETTINGS: SettingRow[] = [
  { key: 'description', env: 'PEP_DESCRIPTION', type: 'text',
    group: 'registration', maxLength: 1024, applies: 'nextRound',
    default: 'A remote XACML Policy Enforcement Point holding its own copy ' +
             'of the engine and pulling this repository.' },
  { key: 'resource', env: 'PEP_RESOURCE', type: 'text', group: 'enforcement',
    maxLength: URL_MAX, applies: 'now', default: '' },
  { key: 'notifyUrl', env: 'PEP_NOTIFY_URL', type: 'url',
    group: 'registration', applies: 'now', default: '' },
  { key: 'bias', env: 'PEP_BIAS', type: 'enum', group: 'enforcement',
    values: BIASES, applies: 'now', default: 'deny-biased' },
  { key: 'pip', env: 'PEP_PIP', type: 'boolean', group: 'enforcement',
    applies: 'now', default: true },
  { key: 'pollIntervalMs', env: 'PEP_POLL_INTERVAL_MS', type: 'integer',
    group: 'sync', min: 1000, max: DAY_MS, applies: 'nextRound',
    default: 15000 },
  { key: 'heartbeatIntervalMs', env: 'PEP_HEARTBEAT_INTERVAL_MS',
    type: 'integer', group: 'sync', min: 1000, max: DAY_MS,
    applies: 'nextRound', default: 60000 },
  { key: 'backoffMaxMs', env: 'PEP_BACKOFF_MAX_MS', type: 'integer',
    group: 'sync', min: 1000, max: DAY_MS, applies: 'nextRound',
    default: 300000 },
  { key: 'timeoutMs', env: 'PEP_TIMEOUT_MS', type: 'integer', group: 'sync',
    min: 100, max: 120000, applies: 'now', default: 5000 },
  { key: 'maxBodyBytes', env: 'PEP_MAX_BODY_BYTES', type: 'integer',
    group: 'sync', min: 1024, max: 104857600, applies: 'now',
    default: 4194304 },
  { key: 'httpsReloadIntervalMs', env: 'PEP_HTTPS_RELOAD_INTERVAL_MS',
    type: 'integer', group: 'listener', min: 1000, max: 3600000,
    applies: 'nextReload', default: 5000 },
  { key: 'logLevel', env: 'PEP_LOG_LEVEL', type: 'enum', group: 'logging',
    values: LOG_LEVELS, applies: 'now', default: 'info' },
  { key: 'authzen', env: 'PEP_AUTHZEN', type: 'boolean', group: 'authzen',
    applies: 'now', default: true },
  { key: 'authzenPdpIdentifier', env: 'PEP_AUTHZEN_PDP_IDENTIFIER',
    type: 'origin', group: 'authzen', applies: 'now', default: '' },
  { key: 'authzenForwardTimeoutMs', env: 'PEP_AUTHZEN_FORWARD_TIMEOUT_MS',
    type: 'integer', group: 'authzen', min: 1, max: 120000, applies: 'now',
    default: 5000 },
  { key: 'proxySessionRecheckMs', env: 'PEP_PROXY_SESSION_RECHECK_MS',
    type: 'integer', group: 'proxy', min: 0, max: 3600000, applies: 'now',
    default: 5000 },
  { key: 'proxySessionTtlMs', env: 'PEP_PROXY_SESSION_TTL_MS',
    type: 'integer', group: 'proxy', min: 1000, max: 30 * DAY_MS,
    applies: 'now', default: 28800000 },
  { key: 'proxyMaxSessions', env: 'PEP_PROXY_MAX_SESSIONS', type: 'integer',
    group: 'proxy', min: 1, max: 1000000, applies: 'now', default: 10000 },
  { key: 'proxyJwksTtlMs', env: 'PEP_PROXY_JWKS_TTL_MS', type: 'integer',
    group: 'proxy', min: 0, max: DAY_MS, applies: 'nextReconcile',
    default: 300000 },
  { key: 'proxyUpstreamInsecure', env: 'PEP_PROXY_UPSTREAM_INSECURE',
    type: 'boolean', group: 'proxy', applies: 'now', default: false,
    refusedInProduct: true },
  { key: 'proxyRpAllowInsecure', env: 'PEP_PROXY_RP_ALLOW_INSECURE',
    type: 'boolean', group: 'proxy', applies: 'nextReconcile',
    default: false, refusedInProduct: true },
  { key: 'proxySignalsPollMs', env: 'PEP_PROXY_SIGNALS_POLL_MS',
    type: 'integer', group: 'proxy', min: 100, max: 3600000,
    applies: 'nextReconcile', default: 5000 },
  { key: 'proxySignalsStaleMs', env: 'PEP_PROXY_SIGNALS_STALE_MS',
    type: 'integer', group: 'proxy', min: 1, max: DAY_MS,
    applies: 'nextReconcile', default: 60000 }
];

// THE ENVIRONMENT THAT STAYS THE PEP'S, with why (the console's catalog
// says each reason in words).
const BOOTSTRAP: BootstrapRow[] = [
  { env: 'PEP_PDP_URL', reason: 'connect',
    default: 'https://localhost:8081' },
  { env: 'PEP_NAME', reason: 'connect', default: 'pep-1' },
  { env: 'PEP_TLS_CERT', reason: 'connect', default: '' },
  { env: 'PEP_TLS_KEY', reason: 'connect', default: '' },
  { env: 'PEP_TLS_CA', reason: 'connect', default: '' },
  { env: 'PEP_TLS_INSECURE', reason: 'connect', default: 'false' },
  { env: 'PEP_PORT', reason: 'bind', default: '9090' },
  // PLAIN HTTP IS OFF BY DEFAULT (#1760): each switch binds its listener
  // before the first pull, so it is the environment's; a listener defined
  // on the Listener tab is the managed way to serve plain HTTP.
  { env: 'PEP_HTTP', reason: 'bind', default: 'false' },
  { env: 'PEP_PROXY_HTTP', reason: 'bind', default: 'false' },
  { env: 'PEP_HTTPS_PORT', reason: 'bind', default: '9443' },
  { env: 'PEP_PROXY_PORT', reason: 'bind', default: '9180' },
  { env: 'PEP_PROXY_HTTPS_PORT', reason: 'bind', default: '9543' },
  { env: 'PEP_HTTPS_CERT', reason: 'file', default: '' },
  { env: 'PEP_HTTPS_KEY', reason: 'file', default: '' },
  { env: 'PEP_CRL_DIR', reason: 'file', default: '' },
  { env: 'PEP_AUTHZEN_CLIENT_CA', reason: 'file', default: '' },
  { env: 'PEP_PROXY_UPSTREAM_CA', reason: 'file', default: '' },
  { env: 'PEP_PROXY', reason: 'listeners', default: 'true' },
  { env: 'PEP_AUTHZEN_CALLERS', reason: 'narrowing', default: '' }
];

/**
 * A remote PEP's managed settings: the table, the validation of what an
 * administrator sets, the pull the PEP reads them from, and the reading
 * of what the PEP reports it has in force.
 */
class PepSettings {
  static readonly SETTINGS: readonly SettingRow[] = SETTINGS;
  static readonly BOOTSTRAP: readonly BootstrapRow[] = BOOTSTRAP;
  static readonly SOURCES: readonly string[] = SOURCES;

  /**
   * Builds it over its dependencies.
   * @param deps - the logger, the error codes, the two mode answers and a
   *   SHA-256 function
   */
  constructor(private readonly deps: PepSettingsDeps) {
    deps.log.debug("Entering PepSettings.constructor().");
    deps.log.debug("Leaving PepSettings.constructor().");
  }

  /**
   * The dependencies from the real modules.
   * @returns the dependencies
   */
  static defaultDeps(): PepSettingsDeps {
    helpers.log.debug("Entering PepSettings.defaultDeps().");
    helpers.log.debug("Leaving PepSettings.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      skipsVerification: function (): boolean {
        helpers.log.debug("Entering skipsVerification().");
        helpers.log.debug("Leaving skipsVerification().");
        return mode.skipsOutboundTlsVerification();
      },
      dialsPlainHttp: function (): boolean {
        helpers.log.debug("Entering dialsPlainHttp().");
        helpers.log.debug("Leaving dialsPlainHttp().");
        return mode.dialsPlainHttpOutbound();
      },
      sha256Base64: function (text: string): string {
        helpers.log.debug("Entering sha256Base64().");
        helpers.log.debug("Leaving sha256Base64().");
        return stsCrypto.digest('sha256', text, 'base64');
      }
    };
  }

  /**
   * The row of a setting.
   * @param key - the member name
   * @returns the row, or null for a member that is not a setting
   */
  static rowOf(key: string): SettingRow | null {
    helpers.log.debug("Entering PepSettings.rowOf(). " + key);
    const row = SETTINGS.filter(function (one) {
      return one.key === key;
    })[0] || null;
    helpers.log.debug("Leaving PepSettings.rowOf().");
    return row;
  }

  /**
   * What `GET /admin-api/xacml/peps` answers about the settings: every
   * managed row, the environment that stays the PEP's and the precedence.
   * Keys, types and bounds only.
   * @returns the catalogue
   */
  catalogue(): Record<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering PepSettings.catalogue().");
    const self = this;
    const settings = SETTINGS.map(function (row) {
      const out: Record<string, unknown> =
        Object.assign({}, row) as unknown as Record<string, unknown>;
      if (row.values) {
        out.values = row.values.slice();
      }
      out.refusedInProduct = !!row.refusedInProduct &&
        !self.allowsInsecure(row);
      return out;
    });
    log.debug("Leaving PepSettings.catalogue().");
    return {
      settings: settings,
      bootstrap: BOOTSTRAP.map(function (row) {
        return Object.assign({}, row);
      }),
      precedence: SOURCES.slice()
    };
  }

  // Whether this realm's mode allows a verification-off row to be true.
  private allowsInsecure(row: SettingRow): boolean {
    const { log } = this.deps;
    log.debug("Entering PepSettings.allowsInsecure(). " + row.key);
    const allowed = row.key === 'proxyRpAllowInsecure'
      ? this.deps.dialsPlainHttp() : this.deps.skipsVerification();
    log.debug("Leaving PepSettings.allowsInsecure(). " + allowed);
    return allowed;
  }

  private refuse(why: string, code: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepSettings.refuse(). " + code);
    log.debug("Leaving PepSettings.refuse().");
    return errorCodes.mark({ ok: false, why: why, code: code }, code);
  }

  // One given value read by its row: the value, a refusal, or undefined
  // for "not set" (absent, null or an empty box).
  private one(row: SettingRow, given: unknown): unknown {
    const { log } = this.deps;
    log.debug("Entering PepSettings.one(). " + row.key);
    if (given === undefined || given === null || given === '') {
      log.debug("Leaving PepSettings.one(). Not set.");
      return undefined;
    }
    if (row.type === 'integer') {
      const n = typeof given === 'number' ? given
        : (typeof given === 'string' && /^\d{1,16}$/.test(given)
            ? Number(given) : NaN);
      if (!Number.isSafeInteger(n)) {
        log.debug("Leaving PepSettings.one(). Not an integer.");
        return this.refuse('`' + row.key + '` must be an integer.',
                           'STS-XACML-0237');
      }
      if (n < (row.min as number) || n > (row.max as number)) {
        log.debug("Leaving PepSettings.one(). Out of bounds.");
        return this.refuse('`' + row.key + '` must be from ' + row.min +
                           ' to ' + row.max + '; it was ' + n + '.',
                           'STS-XACML-0238');
      }
      log.debug("Leaving PepSettings.one(). An integer.");
      return n;
    }
    if (row.type === 'boolean') {
      const b = given === true || given === 'true' ? true
        : (given === false || given === 'false' ? false : null);
      if (b === null) {
        log.debug("Leaving PepSettings.one(). Not a boolean.");
        return this.refuse('`' + row.key + '` must be true or false.',
                           'STS-XACML-0237');
      }
      if (b && row.refusedInProduct && !this.allowsInsecure(row)) {
        log.debug("Leaving PepSettings.one(). Refused in product.");
        return this.refuse('`' + row.key + '` turns a certificate or ' +
                           'scheme check off, which product mode refuses: ' +
                           'name the anchor with ' +
                           (row.key === 'proxyUpstreamInsecure'
                             ? 'PEP_PROXY_UPSTREAM_CA' : 'an https issuer') +
                           ' instead.', 'STS-XACML-0240');
      }
      log.debug("Leaving PepSettings.one(). A boolean.");
      return b;
    }
    if (typeof given !== 'string') {
      log.debug("Leaving PepSettings.one(). Not a string.");
      return this.refuse('`' + row.key + '` must be a string.',
                         'STS-XACML-0237');
    }
    if (row.type === 'enum') {
      if ((row.values as string[]).indexOf(given) < 0) {
        log.debug("Leaving PepSettings.one(). Not in the closed set.");
        return this.refuse('`' + row.key + '` must be one of ' +
                           (row.values as string[]).join(', ') + '.',
                           'STS-XACML-0237');
      }
      log.debug("Leaving PepSettings.one(). In the closed set.");
      return given;
    }
    if (row.type === 'text') {
      if (given.length > (row.maxLength as number) || CONTROL.test(given)) {
        log.debug("Leaving PepSettings.one(). Bad text.");
        return this.refuse('`' + row.key + '` must be at most ' +
                           row.maxLength + ' characters with no control ' +
                           'character.', 'STS-XACML-0239');
      }
      log.debug("Leaving PepSettings.one(). Text.");
      return given;
    }
    let url: URL | null = null;
    try {
      url = new URL(given);
    } catch (e) {
      log.debug("Caught in PepSettings.one(): " + ((e && e.message) || e));
      url = null;
    }
    if (row.type === 'url') {
      if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:') ||
          url.username || url.password || url.hash ||
          given.length > URL_MAX || CONTROL.test(given)) {
        log.debug("Leaving PepSettings.one(). Not a usable URL.");
        return this.refuse('`' + row.key + '` must be an absolute http or ' +
                           'https URL with no user name, password or ' +
                           'fragment.', 'STS-XACML-0239');
      }
      log.debug("Leaving PepSettings.one(). A URL.");
      return given;
    }
    const origin = given.replace(/\/+$/, '');
    if (!url || url.protocol !== 'https:' || url.username || url.password ||
        url.search || url.hash || (url.pathname && url.pathname !== '/') ||
        /[?#]/.test(given) || origin.length > URL_MAX) {
      log.debug("Leaving PepSettings.one(). Not an https origin.");
      return this.refuse('`' + row.key + '` must be an https origin with no ' +
                         'path, query or fragment.', 'STS-XACML-0239');
    }
    log.debug("Leaving PepSettings.one(). An origin.");
    return origin;
  }

  /**
   * Validates what an administrator sets, WHOLE: `settings` (an object of
   * setting members; one it does not name is refused), or — the console's
   * form — the members named on the body itself, where an empty box means
   * "not set". What is not set is the environment's at the PEP.
   * @param body - `{ settings }`, or a body carrying the members
   * @returns `{ ok: true, settings }` with only the members set, in the
   *   table's order, or a coded refusal naming the first that is wrong
   */
  validate(body: unknown): Validated | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepSettings.validate().");
    const self = this;
    const given: any = body && typeof body === 'object' ? body : null;
    if (!given) {
      log.debug("Leaving PepSettings.validate(). Not an object.");
      return this.refuse('The settings must be an object.', 'STS-XACML-0236');
    }
    let source: any = given;
    if (given.settings !== undefined) {
      source = given.settings;
      if (typeof source === 'string') {
        try {
          source = JSON.parse(source);
        } catch (e) {
          log.debug("Caught in PepSettings.validate(): " +
                    ((e && e.message) || e));
          source = null;
        }
      }
      if (!source || typeof source !== 'object' || Array.isArray(source)) {
        log.debug("Leaving PepSettings.validate(). `settings` not an object.");
        return this.refuse('`settings` must be an object of the managed ' +
                           'settings.', 'STS-XACML-0236');
      }
      const unknown = Object.keys(source).filter(function (key) {
        return !PepSettings.rowOf(key);
      });
      if (unknown.length) {
        log.debug("Leaving PepSettings.validate(). Unknown member.");
        return this.refuse('`' + unknown[0] + '` is not a setting this ' +
                           'service manages. The managed settings are ' +
                           SETTINGS.map(function (row) {
                             return row.key;
                           }).join(', ') + '.', 'STS-XACML-0236');
      }
    }
    const out: Record<string, unknown> = {};
    for (let i = 0; i < SETTINGS.length; i++) {
      const row = SETTINGS[i];
      const value: any = self.one(row, source[row.key]);
      if (value && typeof value === 'object' && value.ok === false) {
        log.debug("Leaving PepSettings.validate(). Refused: " + value.code);
        return value as Refusal;
      }
      if (value !== undefined) {
        out[row.key] = value;
      }
    }
    log.debug("Leaving PepSettings.validate(). " + Object.keys(out).length +
              " set.");
    return { ok: true, settings: out };
  }

  /**
   * Reads a stored document again (an `ldapmodify` reaches it too).
   * @param text - the stored JSON, or ''
   * @returns `{ settings, problem }`: the settings when the document
   *   validates, else null and why
   */
  stored(text: string): { settings: Record<string, unknown> | null;
                          problem: string | null } {
    const { log } = this.deps;
    log.debug("Entering PepSettings.stored().");
    if (!text) {
      log.debug("Leaving PepSettings.stored(). None.");
      return { settings: null, problem: null };
    }
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in PepSettings.stored(): " + ((e && e.message) || e));
      parsed = null;
    }
    const checked = this.validate({ settings: parsed });
    log.debug("Leaving PepSettings.stored(). ok=" + checked.ok);
    return checked.ok
      ? { settings: (checked as Validated).settings, problem: null }
      : { settings: null, problem: (checked as Refusal).why };
  }

  /**
   * `GET /xacml/pep/settings`'s answer for one PEP, and its sync token (a
   * digest of what is sent, the other pulls' rule).
   * @param row - the PEP's register row, or null when it has none
   * @param name - the name the PEP's certificate gives it
   * @returns `{ token, body }`
   */
  pull(row: { name: string; settings: string; listeners?: string;
              listenersInUse?: any } | null, name: string):
      { token: string; body: Record<string, unknown> } {
    const { log, errorCodes, sha256Base64 } = this.deps;
    log.debug("Entering PepSettings.pull(). name=" + name);
    let settings: Record<string, unknown> | null = null;
    let note = '';
    if (!row) {
      note = 'No Policy Enforcement Point is registered under this name in ' +
        'this realm, so none of its settings is set here: every setting is ' +
        'the environment\'s or the default.';
    } else if (!row.settings) {
      note = 'This service sets none of this PEP\'s settings: every ' +
        'setting is the environment\'s or the default.';
    } else {
      const read = this.stored(row.settings);
      if (read.settings) {
        settings = read.settings;
      } else {
        log.warn(errorCodes.tag('STS-XACML-0242') + 'xacml: the settings ' +
                 'stored for remote PEP "' + row.name + '" do not validate (' +
                 read.problem + '); they are pulled as configured: false.');
        note = 'The settings stored for this PEP do not validate, so none ' +
          'is sent and every setting is the environment\'s or the default. ' +
          'An administrator sees why on the PEP\'s page and saves them ' +
          'again.';
      }
    }
    const sent: Record<string, unknown> = {
      pep: row ? row.name : name,
      configured: !!settings
    };
    if (settings) {
      sent.settings = settings;
    } else {
      sent.note = note;
    }
    // THE LISTENERS DEFINED FOR THIS PEP (#1760), beside the settings and
    // under the same token, so a definition added, edited, renewed or
    // removed reaches the PEP on its next poll. Sent only when there are
    // some, so a PEP with none pulls the body it always did; one stored
    // that does not validate sends none, and the PEP binds only its
    // environment's.
    if (row && row.listeners) {
      const read = pepListeners.stored(row.listeners,
                                       row.listenersInUse || null);
      if (read.listeners && read.listeners.length) {
        sent.listeners = read.listeners;
      } else if (!read.listeners) {
        log.warn(errorCodes.tag('STS-XACML-0252') + 'xacml: the listeners ' +
                 'stored for remote PEP "' + row.name + '" do not validate (' +
                 read.problem + '); none is pulled.');
      }
    }
    const token = sha256Base64(JSON.stringify(sent))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    log.debug("Leaving PepSettings.pull(). configured=" + !!settings);
    return { token: token,
             body: Object.assign({ syncToken: token }, sent) };
  }

  // -------------------------------------------------------------------------
  // WHAT THE PEP SAYS IT HAS IN FORCE, held to its members. A REMOTE_PEPS
  // holder writes this, so — `signalsOf()`'s argument — only the settings
  // the table names, each value of its row's type and every source of the
  // closed set are kept; anything else is dropped rather than stored. The
  // same function reads the stored value back.
  // -------------------------------------------------------------------------
  /**
   * Normalises a heartbeat's `settings` member, or the stored text.
   * @param raw - the reported object, or the stored JSON text
   * @param at - when it was received; the stored `at` when omitted
   * @returns the members kept, or null when there is no object to read
   */
  static inUseOf(raw: unknown, at?: string): InUse | null {
    helpers.log.debug("Entering PepSettings.inUseOf().");
    let said: any = raw;
    if (typeof said === 'string') {
      try {
        said = said ? JSON.parse(said) : null;
      } catch (e) {
        helpers.log.debug("Caught in PepSettings.inUseOf(): " +
                          ((e && e.message) || e));
        said = null;
      }
    }
    if (!said || typeof said !== 'object' || Array.isArray(said)) {
      helpers.log.debug("Leaving PepSettings.inUseOf(). Nothing to read.");
      return null;
    }
    const values: Record<string, { value: unknown; source: string }> = {};
    const reported = said.values && typeof said.values === 'object'
      ? said.values : {};
    SETTINGS.forEach(function (row) {
      const one = reported[row.key];
      if (!one || typeof one !== 'object' ||
          SOURCES.indexOf(one.source) < 0) {
        return;
      }
      const v = one.value;
      let kept: unknown;
      if (row.type === 'integer') {
        kept = typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
          ? v : undefined;
      } else if (row.type === 'boolean') {
        kept = typeof v === 'boolean' ? v : undefined;
      } else if (row.type === 'enum') {
        kept = (row.values as string[]).indexOf(v) >= 0 ? v : undefined;
      } else {
        kept = typeof v === 'string' && v.length <= URL_MAX &&
          !CONTROL.test(v) ? v : undefined;
      }
      if (kept !== undefined) {
        values[row.key] = { value: kept, source: one.source };
      }
    });
    const token = typeof said.token === 'string' &&
      /^[A-Za-z0-9_-]{0,128}$/.test(said.token) ? said.token : '';
    const stamp = at !== undefined ? at
      : (typeof said.at === 'string' && !isNaN(Date.parse(said.at))
          ? new Date(Date.parse(said.at)).toISOString() : '');
    helpers.log.debug("Leaving PepSettings.inUseOf(). " +
                      Object.keys(values).length + " value(s).");
    return { at: stamp, token: token, values: values };
  }

  /**
   * The notify URL the nudge dials: the one set here, else the one the
   * PEP registered with.
   * @param row - the PEP's register row
   * @returns the URL, '' for none
   */
  notifyUrlOf(row: { notifyUrl: string; settings: string }): string {
    const { log } = this.deps;
    log.debug("Entering PepSettings.notifyUrlOf().");
    const read = this.stored(row.settings || '');
    const set = read.settings && typeof read.settings.notifyUrl === 'string'
      ? read.settings.notifyUrl as string : '';
    log.debug("Leaving PepSettings.notifyUrlOf().");
    return set || row.notifyUrl || '';
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), and a default one
// where nothing runs the root.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PepSettings>(
  'xacml/xacml_pep_settings',
  () => new PepSettings(PepSettings.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * A remote PEP's managed settings (#1760).
 * @namespace
 */
export = {
  PepSettings: PepSettings,
  installInstance: (instance: PepSettings): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SETTINGS: PepSettings.SETTINGS,
  BOOTSTRAP: PepSettings.BOOTSTRAP,
  SOURCES: PepSettings.SOURCES,
  rowOf: PepSettings.rowOf,
  inUseOf: PepSettings.inUseOf,
  catalogue: slot.forward('catalogue'),
  validate: slot.forward('validate'),
  stored: slot.forward('stored'),
  pull: slot.forward('pull'),
  notifyUrlOf: slot.forward('notifyUrlOf')
};
