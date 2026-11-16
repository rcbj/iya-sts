// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_listener_tuning.ts
//
// ===========================================================================
// ONE REMOTE PEP LISTENER'S TUNING (#1760).
//
// The listener-details form exposes the same knobs Server Settings →
// Listeners exposes for one listener (`common/config.js`'s
// `PER_LISTENER_SETTINGS`): the TLS policy, the TLS session cache, HTTP
// connection pooling, HTTP/2, and the client-certificate questions, plus a
// thread pool of that listener's own (min and max). A PEP listener does not
// inherit. An absent `tuning` means the listener was saved before these
// knobs existed and keeps validating; the pull fills the defaults so a PEP
// that has never been given a value still gets a pool. A value that does
// not fit is STS-XACML-0281. The PEP that cannot apply one logs
// STS-XPEP-0119 and keeps the previous acceptor.
//
// THE REVERSE PROXY'S POOL IS THE LARGEST BY DEFAULT: api 4/32, proxy
// 16/128, crl 1/4. The environment's `api-http` uses the API defaults even
// when the process is serving CRLs only, because this service does not know
// `PEP_CRL_HTTP`; an administrator sets 1/4 on that listener when that is
// what the port is for.
//
// Stored on the listener, or, for the environment's four, beside the array
// (`xacml_pep_listeners.ts`). No new attribute and no upgrade script: both
// are the JSON already held in `xacmlPepListeners`.
//
// A LIBRARY. It requires nothing that requires it.
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');

const { log } = helpers;

const MIN_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const TLS13_SUITES = ['TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256',
                      'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_CCM_SHA256',
                      'TLS_AES_128_CCM_8_SHA256'];
const PQ_SUITES = ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'];
const CIPHERS_DEFAULT = 'ECDHE-ECDSA-AES128-GCM-SHA256:' +
  'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:' +
  'ECDHE-RSA-AES256-GCM-SHA384';
const TLS13_DEFAULT = 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,' +
  'TLS_CHACHA20_POLY1305_SHA256';
const GROUPS_DEFAULT = 'X25519MLKEM768:SecP256r1MLKEM768:' +
  'SecP384r1MLKEM1024 / X25519:P-256 / X448:P-384:P-521';
const SIGALGS_DEFAULT = 'mldsa65:mldsa87:mldsa44:' +
  'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:' +
  'ed25519:ed448:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:' +
  'rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:' +
  'rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512';

const KEYS = ['minVersion', 'disableTls12', 'ciphers', 'tls13CipherSuites',
              'pqcOnly', 'groups', 'signatureAlgorithms', 'trustAnchorsFile',
              'trustIssuedClientCertificates', 'askClientCertificate',
              'requireClientCertificate', 'sessionTimeoutS',
              'sessionCacheSize', 'keepAliveTimeoutS', 'headersTimeoutS',
              'maxRequestsPerSocket', 'maxConnections', 'http2',
              'http2MaxConcurrentStreams', 'threadPoolMin', 'threadPoolMax'];

const CONTROL = /[\u0000-\u001f\u007f]/;
const PQ_GROUP = /ml-?kem/i;
const BOOTSTRAP = [
  { id: 'api-http', purpose: 'api', https: false },
  { id: 'api-https', purpose: 'api', https: true },
  { id: 'proxy-http', purpose: 'proxy', https: false },
  { id: 'proxy-https', purpose: 'proxy', https: true }
];

interface Tuning {
  minVersion: string;
  disableTls12: boolean;
  ciphers: string;
  tls13CipherSuites: string;
  pqcOnly: boolean;
  groups: string;
  signatureAlgorithms: string;
  trustAnchorsFile: string;
  trustIssuedClientCertificates: boolean;
  askClientCertificate: boolean;
  requireClientCertificate: boolean;
  sessionTimeoutS: number;
  sessionCacheSize: number;
  keepAliveTimeoutS: number;
  headersTimeoutS: number;
  maxRequestsPerSocket: number;
  maxConnections: number;
  http2: boolean;
  http2MaxConcurrentStreams: number;
  threadPoolMin: number;
  threadPoolMax: number;
}

interface Refusal {
  ok: false;
  why: string;
  code: string;
}

interface Accepted {
  ok: true;
  tuning: Tuning;
}

interface PoolStats {
  min: number;
  max: number;
  current: number;
  busy: number;
  idle: number;
  queued: number;
  completed: number;
}

interface ListenerStats {
  accepted?: number;
  open?: number;
  refused?: number;
  http1?: number;
  http2?: number;
  handshakes?: number;
  handshakeFailures?: number;
  pool?: PoolStats;
}

interface MemoryStats {
  rssBytes?: number;
  virtualBytes?: number;
  dataBytes?: number;
  threads?: number;
}

interface PathStat {
  method: string;
  path: string;
  count: number;
  refused: number;
}

/**
 * The knobs of one remote PEP listener, and the figures it reports about
 * them. A static utility class; the defaults are the service's.
 */
class PepListenerTuning {
  static readonly KEYS: readonly string[] = KEYS;
  static readonly MIN_VERSIONS: readonly string[] = MIN_VERSIONS;
  static readonly TLS13_SUITES: readonly string[] = TLS13_SUITES;
  static readonly BOOTSTRAP: readonly { id: string; purpose: string;
                                         https: boolean }[] = BOOTSTRAP;

  /**
   * The pool a purpose starts with. The reverse proxy's is the largest.
   * @param purpose - api, proxy or crl
   * @returns `{ min, max }`
   */
  static threadsFor(purpose: string): { min: number; max: number } {
    log.debug("Entering PepListenerTuning.threadsFor().");
    const out = purpose === 'proxy' ? { min: 16, max: 128 }
      : (purpose === 'crl' ? { min: 1, max: 4 } : { min: 4, max: 32 });
    log.debug("Leaving PepListenerTuning.threadsFor().");
    return out;
  }

  /**
   * The built-in tuning for a purpose and a protocol. HTTP forces HTTP/2
   * and the client-certificate questions off; the other TLS fields are
   * still the defaults, so turning the listener to HTTPS has them.
   * @param purpose - api, proxy or crl
   * @param https - whether the listener is HTTPS
   * @returns the tuning
   */
  static defaultsFor(purpose: string, https: boolean): Tuning {
    log.debug("Entering PepListenerTuning.defaultsFor().");
    const threads = PepListenerTuning.threadsFor(purpose);
    const ask = https === true;
    const out: Tuning = {
      minVersion: 'TLSv1.2',
      disableTls12: true,
      ciphers: CIPHERS_DEFAULT,
      tls13CipherSuites: TLS13_DEFAULT,
      pqcOnly: false,
      groups: GROUPS_DEFAULT,
      signatureAlgorithms: SIGALGS_DEFAULT,
      trustAnchorsFile: '',
      trustIssuedClientCertificates: https === true && purpose === 'api',
      askClientCertificate: ask,
      requireClientCertificate: false,
      sessionTimeoutS: 300,
      sessionCacheSize: 2048,
      keepAliveTimeoutS: 60,
      headersTimeoutS: 0,
      maxRequestsPerSocket: 0,
      maxConnections: 0,
      http2: https === true,
      http2MaxConcurrentStreams: 100,
      threadPoolMin: threads.min,
      threadPoolMax: threads.max
    };
    if (out.disableTls12) {
      out.minVersion = 'TLSv1.3';
    }
    log.debug("Leaving PepListenerTuning.defaultsFor().");
    return out;
  }

  /**
   * What the console's catalogue tells the form: the HTTPS defaults for
   * api and proxy, and the CRL pool. The form forces HTTP's three flags.
   * @returns `{ api, proxy, crl }`
   */
  static catalogueDefaults(): Record<string, Tuning> {
    log.debug("Entering PepListenerTuning.catalogueDefaults().");
    const out = {
      api: PepListenerTuning.defaultsFor('api', true),
      proxy: PepListenerTuning.defaultsFor('proxy', true),
      crl: PepListenerTuning.defaultsFor('crl', true)
    };
    log.debug("Leaving PepListenerTuning.catalogueDefaults().");
    return out;
  }

  private static refuse(why: string): Refusal {
    log.debug("Entering PepListenerTuning.refuse().");
    log.debug("Leaving PepListenerTuning.refuse().");
    return errorCodes.mark({ ok: false, why: why, code: 'STS-XACML-0281' },
                           'STS-XACML-0281');
  }

  // A posted bool: on/true/1, off/false/0. Absent is undefined. Anything
  // else is a refusal. No Entering/Leaving pair: it runs for every bool of
  // every listener a save validates.
  private static bool(value: unknown, name: string):
      boolean | undefined | Refusal {
    if (value === undefined || value === null || value === '') {
      return undefined;
    }
    if (value === true || value === 'true' || value === 'on' ||
        value === '1' || value === 1) {
      return true;
    }
    if (value === false || value === 'false' || value === 'off' ||
        value === '0' || value === 0) {
      return false;
    }
    return PepListenerTuning.refuse('`' + name + '` is on or off.');
  }

  private static integer(value: unknown, name: string, min: number,
                         max: number, fallback: number): number | Refusal {
    if (value === undefined || value === null || value === '') {
      return fallback;
    }
    const n = typeof value === 'number' ? value
      : (typeof value === 'string' && /^-?\d{1,10}$/.test(value.trim())
          ? Number(value.trim()) : NaN);
    if (!Number.isSafeInteger(n) || n < min || n > max) {
      return PepListenerTuning.refuse('`' + name + '` is an integer from ' +
                                      min + ' to ' + max + '.');
    }
    return n;
  }

  private static text(value: unknown, name: string, max: number,
                      fallback: string, emptyOk: boolean): string | Refusal {
    if (value === undefined || value === null || value === '') {
      return emptyOk ? '' : fallback;
    }
    if (typeof value !== 'string' || value.length > max ||
        CONTROL.test(value)) {
      return PepListenerTuning.refuse('`' + name + '` is text of at most ' +
                                      max + ' characters, with no control ' +
                                      'character.');
    }
    return value;
  }

  /**
   * Validates one tuning object and fills what it left out.
   * @param raw - the object, or the form's members
   * @param where - how a refusal names the listener
   * @param purpose - api, proxy or crl, which picks the pool's default
   * @param https - whether HTTP/2 and client certificates may be on
   * @returns the tuning, or STS-XACML-0281
   */
  static parse(raw: unknown, where: string, purpose: string,
               https: boolean): Accepted | Refusal {
    log.debug("Entering PepListenerTuning.parse().");
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepListenerTuning.parse(). Not an object.");
      return PepListenerTuning.refuse(where + ': `tuning` is an object of ' +
                                      'the listener\'s settings.');
    }
    const given = raw as Record<string, unknown>;
    const stray = Object.keys(given).filter(function (key) {
      return KEYS.indexOf(key) < 0;
    })[0];
    if (stray) {
      log.debug("Leaving PepListenerTuning.parse(). Stray.");
      return PepListenerTuning.refuse(where + ': `tuning` carries "' +
                                      stray + '", which a listener\'s ' +
                                      'settings do not have.');
    }
    const base = PepListenerTuning.defaultsFor(purpose, https);
    const minVersion = given.minVersion === undefined ||
      given.minVersion === '' ? base.minVersion : given.minVersion;
    if (typeof minVersion !== 'string' ||
        MIN_VERSIONS.indexOf(minVersion) < 0) {
      log.debug("Leaving PepListenerTuning.parse(). minVersion.");
      return PepListenerTuning.refuse(where + ': `minVersion` is one of ' +
                                      MIN_VERSIONS.join(', ') + '.');
    }
    const flag = function (name: string, fallback: boolean):
        boolean | Refusal {
      const one = PepListenerTuning.bool(given[name], name);
      if (one && typeof one === 'object') {
        return one;
      }
      return one === undefined ? fallback : one;
    };
    const disableTls12 = flag('disableTls12', base.disableTls12);
    const pqcOnly = flag('pqcOnly', base.pqcOnly);
    const trustIssued = flag('trustIssuedClientCertificates',
                            base.trustIssuedClientCertificates);
    const ask = flag('askClientCertificate', base.askClientCertificate);
    const requireCert = flag('requireClientCertificate',
                            base.requireClientCertificate);
    const http2 = flag('http2', base.http2);
    const flags = [disableTls12, pqcOnly, trustIssued, ask, requireCert,
                   http2];
    for (let i = 0; i < flags.length; i++) {
      if (flags[i] && typeof flags[i] === 'object') {
        log.debug("Leaving PepListenerTuning.parse(). A flag.");
        return flags[i] as Refusal;
      }
    }
    const ciphers = PepListenerTuning.text(given.ciphers, 'ciphers', 1024,
                                          base.ciphers, false);
    const groups = PepListenerTuning.text(given.groups, 'groups', 1024,
                                         base.groups, false);
    const sigs = PepListenerTuning.text(given.signatureAlgorithms,
                                       'signatureAlgorithms', 2048,
                                       base.signatureAlgorithms, false);
    const anchors = PepListenerTuning.text(given.trustAnchorsFile,
                                          'trustAnchorsFile', 1024, '', true);
    const suitesGiven = PepListenerTuning.text(given.tls13CipherSuites,
                                              'tls13CipherSuites', 512,
                                              base.tls13CipherSuites, false);
    const texts = [ciphers, groups, sigs, anchors, suitesGiven];
    for (let i = 0; i < texts.length; i++) {
      if (typeof texts[i] !== 'string') {
        log.debug("Leaving PepListenerTuning.parse(). Text.");
        return texts[i] as Refusal;
      }
    }
    let suites = String(suitesGiven);
    const suiteTokens = suites.split(/[,:\s]+/).map(function (one) {
      return one.trim();
    }).filter(function (one) { return !!one; });
    const unknown = suiteTokens.filter(function (one) {
      return TLS13_SUITES.indexOf(one) < 0;
    })[0];
    if (unknown) {
      log.debug("Leaving PepListenerTuning.parse(). A suite.");
      return PepListenerTuning.refuse(where + ': `tls13CipherSuites` names ' +
                                      '"' + unknown + '", which is not one ' +
                                      'of ' + TLS13_SUITES.join(', ') + '.');
    }
    let groupText = String(groups);
    if (pqcOnly === true) {
      const keptSuites = (suiteTokens.length ? suiteTokens
        : TLS13_DEFAULT.split(',')).filter(function (one) {
          return PQ_SUITES.indexOf(one) >= 0;
        });
      if (!keptSuites.length) {
        log.debug("Leaving PepListenerTuning.parse(). No PQ suite.");
        return PepListenerTuning.refuse(where + ': `pqcOnly` leaves no ' +
                                        'TLS 1.3 suite. The two it keeps ' +
                                        'are ' + PQ_SUITES.join(', ') + '.');
      }
      suites = keptSuites.join(',');
      const keptGroups = groupText.split(/[:\/\s]+/).map(function (one) {
        return one.trim();
      }).filter(function (one) { return PQ_GROUP.test(one); });
      if (!keptGroups.length) {
        log.debug("Leaving PepListenerTuning.parse(). No PQ group.");
        return PepListenerTuning.refuse(where + ': `pqcOnly` leaves no ' +
                                        'key-exchange group whose name ' +
                                        'contains ML-KEM.');
      }
      groupText = keptGroups.join(':');
    } else if (suiteTokens.length) {
      suites = suiteTokens.join(',');
    }
    const threads = PepListenerTuning.threadsFor(purpose);
    const numbers: Array<[string, number, number, number]> = [
      ['sessionTimeoutS', 1, 86400, base.sessionTimeoutS],
      ['sessionCacheSize', 0, 1000000, base.sessionCacheSize],
      ['keepAliveTimeoutS', 1, 3600, base.keepAliveTimeoutS],
      ['headersTimeoutS', 0, 3600, base.headersTimeoutS],
      ['maxRequestsPerSocket', 0, 1000000, base.maxRequestsPerSocket],
      ['maxConnections', 0, 1000000, base.maxConnections],
      ['http2MaxConcurrentStreams', 1, 1000, base.http2MaxConcurrentStreams],
      ['threadPoolMin', 1, 256, threads.min],
      ['threadPoolMax', 1, 1024, threads.max]
    ];
    const nums: Record<string, number> = {};
    for (let i = 0; i < numbers.length; i++) {
      const spec = numbers[i];
      const one = PepListenerTuning.integer(given[spec[0]], spec[0], spec[1],
                                           spec[2], spec[3]);
      if (typeof one !== 'number') {
        log.debug("Leaving PepListenerTuning.parse(). " + spec[0]);
        return one;
      }
      nums[spec[0]] = one;
    }
    if (nums.threadPoolMax < nums.threadPoolMin) {
      log.debug("Leaving PepListenerTuning.parse(). Pool.");
      return PepListenerTuning.refuse(where + ': `threadPoolMax` is at ' +
                                      'least `threadPoolMin` (' +
                                      nums.threadPoolMin + ').');
    }
    const tls12Off = disableTls12 === true || pqcOnly === true;
    const tuning: Tuning = {
      minVersion: tls12Off ? 'TLSv1.3' : String(minVersion),
      disableTls12: tls12Off,
      ciphers: String(ciphers),
      tls13CipherSuites: suites,
      pqcOnly: pqcOnly === true,
      groups: groupText,
      signatureAlgorithms: String(sigs),
      trustAnchorsFile: String(anchors),
      trustIssuedClientCertificates: trustIssued === true,
      askClientCertificate: https && ask === true,
      requireClientCertificate: https && requireCert === true,
      sessionTimeoutS: nums.sessionTimeoutS,
      sessionCacheSize: nums.sessionCacheSize,
      keepAliveTimeoutS: nums.keepAliveTimeoutS,
      headersTimeoutS: nums.headersTimeoutS,
      maxRequestsPerSocket: nums.maxRequestsPerSocket,
      maxConnections: nums.maxConnections,
      http2: https && http2 === true,
      http2MaxConcurrentStreams: nums.http2MaxConcurrentStreams,
      threadPoolMin: nums.threadPoolMin,
      threadPoolMax: nums.threadPoolMax
    };
    log.debug("Leaving PepListenerTuning.parse(). Usable.");
    return { ok: true, tuning: tuning };
  }

  /**
   * A stored tuning, or the defaults where none was stored, with HTTP's
   * three flags forced off.
   * @param stored - the stored object, or undefined
   * @param purpose - api, proxy or crl
   * @param https - whether the listener is HTTPS
   * @returns the tuning the pull sends
   */
  static effective(stored: unknown, purpose: string, https: boolean): Tuning {
    log.debug("Entering PepListenerTuning.effective().");
    const base = PepListenerTuning.defaultsFor(purpose, https);
    if (!stored || typeof stored !== 'object' || Array.isArray(stored)) {
      log.debug("Leaving PepListenerTuning.effective(). Defaults.");
      return base;
    }
    const out = Object.assign({}, base, stored) as Tuning;
    if (!https) {
      out.http2 = false;
      out.askClientCertificate = false;
      out.requireClientCertificate = false;
    }
    if (out.pqcOnly || out.disableTls12) {
      out.disableTls12 = true;
      out.minVersion = 'TLSv1.3';
    }
    log.debug("Leaving PepListenerTuning.effective().");
    return out;
  }

  /**
   * The form's members that belong to a tuning, when the body posted any.
   * An empty box is left out, so validation fills the default.
   * @param body - the action's body
   * @returns the object, or undefined when the body set nothing
   */
  static fromBody(body: Record<string, unknown> | null):
      Record<string, unknown> | undefined {
    log.debug("Entering PepListenerTuning.fromBody().");
    const given = body || {};
    const out: Record<string, unknown> = {};
    let any = false;
    KEYS.forEach(function (key) {
      if (given[key] !== undefined && given[key] !== '') {
        out[key] = given[key];
        any = true;
      }
    });
    if (!any && given.tuning && typeof given.tuning === 'object') {
      log.debug("Leaving PepListenerTuning.fromBody(). Nested.");
      return given.tuning as Record<string, unknown>;
    }
    log.debug("Leaving PepListenerTuning.fromBody(). " + any);
    return any ? out : undefined;
  }

  /**
   * Splits a stored attribute into the definitions array and the
   * environment's tuning. A bare array is the definitions and no
   * environment tuning, which is how every listener saved before this
   * was stored.
   * @param raw - the attribute's text, or the parsed value
   * @returns the two parts, or why the document is not one
   */
  static split(raw: unknown): { list: unknown; environment: unknown;
                               why: string | null } {
    log.debug("Entering PepListenerTuning.split().");
    let given = raw;
    if (typeof given === 'string') {
      if (!given) {
        log.debug("Leaving PepListenerTuning.split(). Empty.");
        return { list: [], environment: {}, why: null };
      }
      try {
        given = JSON.parse(given);
      } catch (e) {
        log.debug("Caught in PepListenerTuning.split(): " +
                  ((e && (e as Error).message) || e));
        given = null;
      }
    }
    if (Array.isArray(given)) {
      log.debug("Leaving PepListenerTuning.split(). An array.");
      return { list: given, environment: {}, why: null };
    }
    if (!given || typeof given !== 'object') {
      log.debug("Leaving PepListenerTuning.split(). Not a document.");
      return { list: null, environment: {},
               why: 'The listeners are a JSON array of listener objects.' };
    }
    const doc = given as Record<string, unknown>;
    const stray = Object.keys(doc).filter(function (key) {
      return key !== 'listeners' && key !== 'environment';
    })[0];
    if (stray || !Array.isArray(doc.listeners)) {
      log.debug("Leaving PepListenerTuning.split(). Shape.");
      return { list: null, environment: {},
               why: 'The listeners are a JSON array of listener objects.' };
    }
    log.debug("Leaving PepListenerTuning.split(). Wrapped.");
    return { list: doc.listeners,
             environment: doc.environment === undefined ? {}
               : doc.environment,
             why: null };
  }

  /**
   * The environment's four tunings, each validated for that listener.
   * @param raw - the document's `environment`, or {}
   * @returns the map, or STS-XACML-0281
   */
  static environment(raw: unknown):
      { ok: true; environment: Record<string, Tuning> } | Refusal {
    log.debug("Entering PepListenerTuning.environment().");
    if (raw === undefined || raw === null) {
      log.debug("Leaving PepListenerTuning.environment(). None.");
      return { ok: true, environment: {} };
    }
    if (typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepListenerTuning.environment(). Not an object.");
      return PepListenerTuning.refuse('`environment` is an object whose ' +
                                      'keys are the environment\'s ' +
                                      'listeners.');
    }
    const given = raw as Record<string, unknown>;
    const known = BOOTSTRAP.map(function (one) { return one.id; });
    const stray = Object.keys(given).filter(function (key) {
      return known.indexOf(key) < 0;
    })[0];
    if (stray) {
      log.debug("Leaving PepListenerTuning.environment(). Stray.");
      return PepListenerTuning.refuse('"' + stray + '" is not one of the ' +
                                      'environment\'s listeners (' +
                                      known.join(', ') + ').');
    }
    const out: Record<string, Tuning> = {};
    for (let i = 0; i < BOOTSTRAP.length; i++) {
      const one = BOOTSTRAP[i];
      if (given[one.id] === undefined) {
        continue;
      }
      const parsed = PepListenerTuning.parse(given[one.id],
                                            'Listener "' + one.id + '"',
                                            one.purpose, one.https);
      if (parsed.ok === false) {
        log.debug("Leaving PepListenerTuning.environment(). Refused.");
        return parsed;
      }
      out[one.id] = parsed.tuning;
    }
    log.debug("Leaving PepListenerTuning.environment().");
    return { ok: true, environment: out };
  }

  /**
   * The attribute's text. A bare array when no environment tuning is
   * stored, so a value written before this still parses as an array; the
   * wrapped document only when an environment listener has a tuning.
   * @param list - the definitions
   * @param environment - the environment's tunings
   * @returns the text, or null when both are empty
   */
  static documentText(list: unknown[],
                      environment: Record<string, unknown> | null):
      string | null {
    log.debug("Entering PepListenerTuning.documentText().");
    const env = environment || {};
    const keys = Object.keys(env);
    let text: string | null;
    if (!keys.length) {
      text = list.length ? JSON.stringify(list) : null;
    } else {
      text = JSON.stringify({ listeners: list, environment: env });
    }
    log.debug("Leaving PepListenerTuning.documentText().");
    return text;
  }

  /**
   * A definitions document with one member's environment tuning kept
   * beside a cluster's array.
   * @param listenersText - the definitions, a JSON array or ''
   * @param environment - the member's own environment tuning
   * @returns the text to store
   */
  static withEnvironmentText(listenersText: string,
                             environment: Record<string, unknown>): string {
    log.debug("Entering PepListenerTuning.withEnvironmentText().");
    const split = PepListenerTuning.split(listenersText || '[]');
    // A DOCUMENT THAT IS NOT ONE IS LEFT AS IT WAS, so a cluster's
    // listeners the grammar will refuse stay the text the pull is sent.
    if (split.why || !Array.isArray(split.list)) {
      log.debug("Leaving PepListenerTuning.withEnvironmentText(). Kept.");
      return listenersText || '[]';
    }
    const text = PepListenerTuning.documentText(split.list, environment) ||
      '[]';
    log.debug("Leaving PepListenerTuning.withEnvironmentText().");
    return text;
  }

  // A non-negative integer, or null. No Entering/Leaving pair: a heartbeat
  // carries one per figure of every listener.
  private static count(value: unknown): number | null {
    return typeof value === 'number' && Number.isSafeInteger(value) &&
      value >= 0 ? value : null;
  }

  /**
   * The figures one reported listener may carry. A bad field is dropped;
   * a listener with none is null.
   * @param raw - the reported `stats`
   * @returns the figures kept, or null
   */
  static statsOf(raw: unknown): ListenerStats | null {
    log.debug("Entering PepListenerTuning.statsOf().");
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepListenerTuning.statsOf(). None.");
      return null;
    }
    const given = raw as Record<string, unknown>;
    const out: ListenerStats = {};
    ['accepted', 'open', 'refused', 'http1', 'http2', 'handshakes',
     'handshakeFailures'].forEach(function (key) {
      const n = PepListenerTuning.count(given[key]);
      if (n !== null) {
        (out as unknown as Record<string, number>)[key] = n;
      }
    });
    if (given.pool && typeof given.pool === 'object') {
      const pool = given.pool as Record<string, unknown>;
      const names = ['min', 'max', 'current', 'busy', 'idle', 'queued',
                     'completed'];
      const got: Record<string, number> = {};
      let whole = true;
      names.forEach(function (key) {
        const n = PepListenerTuning.count(pool[key]);
        if (n === null) {
          whole = false;
        } else {
          got[key] = n;
        }
      });
      if (whole) {
        out.pool = got as unknown as PoolStats;
      }
    }
    const any = Object.keys(out).length > 0;
    log.debug("Leaving PepListenerTuning.statsOf(). " + any);
    return any ? out : null;
  }

  /**
   * The process's memory, from the heartbeat's `memory`.
   * @param raw - the reported object
   * @returns the figures kept, or null
   */
  static memoryOf(raw: unknown): MemoryStats | null {
    log.debug("Entering PepListenerTuning.memoryOf().");
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepListenerTuning.memoryOf(). None.");
      return null;
    }
    const given = raw as Record<string, unknown>;
    const out: MemoryStats = {};
    ['rssBytes', 'virtualBytes', 'dataBytes', 'threads'].forEach(
      function (key) {
        const n = PepListenerTuning.count(given[key]);
        if (n !== null) {
          (out as unknown as Record<string, number>)[key] = n;
        }
      });
    const any = Object.keys(out).length > 0;
    log.debug("Leaving PepListenerTuning.memoryOf(). " + any);
    return any ? out : null;
  }

  /**
   * Per-path counts. The query string is never kept. At most 256 paths;
   * the rest are dropped.
   * @param raw - the reported array
   * @returns the rows kept, or null
   */
  static pathsOf(raw: unknown): PathStat[] | null {
    log.debug("Entering PepListenerTuning.pathsOf().");
    if (!Array.isArray(raw)) {
      log.debug("Leaving PepListenerTuning.pathsOf(). None.");
      return null;
    }
    const out: PathStat[] = [];
    raw.slice(0, 256).forEach(function (one) {
      if (!one || typeof one !== 'object') {
        return;
      }
      const row = one as Record<string, unknown>;
      const method = typeof row.method === 'string' &&
        /^[A-Z*]{1,16}$/.test(row.method) ? row.method : '';
      let path = typeof row.path === 'string' ? row.path : '';
      const cut = path.indexOf('?');
      if (cut >= 0) {
        path = path.slice(0, cut);
      }
      if (path.length > 200) {
        path = path.slice(0, 200);
      }
      if (!method || !path || CONTROL.test(path) || path.indexOf(' ') >= 0) {
        return;
      }
      const count = PepListenerTuning.count(row.count);
      const refused = PepListenerTuning.count(row.refused);
      if (count === null) {
        return;
      }
      out.push({ method: method, path: path, count: count,
                 refused: refused === null ? 0 : refused });
    });
    log.debug("Leaving PepListenerTuning.pathsOf(). " + out.length);
    return out.length ? out : null;
  }
}

export = {
  PepListenerTuning: PepListenerTuning,
  KEYS: PepListenerTuning.KEYS,
  MIN_VERSIONS: PepListenerTuning.MIN_VERSIONS,
  TLS13_SUITES: PepListenerTuning.TLS13_SUITES,
  BOOTSTRAP: PepListenerTuning.BOOTSTRAP,
  threadsFor: PepListenerTuning.threadsFor,
  defaultsFor: PepListenerTuning.defaultsFor,
  catalogueDefaults: PepListenerTuning.catalogueDefaults,
  parse: PepListenerTuning.parse,
  effective: PepListenerTuning.effective,
  fromBody: PepListenerTuning.fromBody,
  split: PepListenerTuning.split,
  environment: PepListenerTuning.environment,
  documentText: PepListenerTuning.documentText,
  withEnvironmentText: PepListenerTuning.withEnvironmentText,
  statsOf: PepListenerTuning.statsOf,
  memoryOf: PepListenerTuning.memoryOf,
  pathsOf: PepListenerTuning.pathsOf
};
