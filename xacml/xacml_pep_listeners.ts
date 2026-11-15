// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_listeners.ts
//
// ===========================================================================
// A REMOTE PEP'S LISTENERS, DEFINED ON ITS CONSOLE PAGE (#1760).
//
// rcbj (2026-11-14): "expose all listener details for the XACML PEP on this
// page. Model this tab after the Server configuration->Listeners. By
// default, have the HTTPS/TLS listener that is available now, but provide
// the ability to define an arbitrary # of listeners (HTTP, HTTPS)."
//
// TWO KINDS OF LISTENER, and the line between them is the settings' line.
//
//   * THE ENVIRONMENT'S FOUR (`BOOTSTRAP`): PEP_PORT and PEP_HTTPS_PORT for
//     the decision API, PEP_PROXY_PORT and PEP_PROXY_HTTPS_PORT for the
//     reverse proxy. They are what lets the PEP be reached before it has
//     pulled anything, so they stay its environment's and are drawn
//     read-only. Their certificate is still the pair on the PEP's mount,
//     issued by `issue-pep-certificate` (`xacml_pep_tls.ts`).
//   * THE ONES DEFINED HERE: any number (up to `MAX_LISTENERS`) of HTTP or
//     HTTPS listeners for either purpose, stored on the PEP's `ou=peps`
//     entry as `xacmlPepListeners`, validated WHOLE on every write and again
//     when the pull is built (an ldapmodify reaches the attribute too), and
//     sent on `GET /xacml/pep/settings` beside the settings. The PEP binds a
//     new one, unbinds a removed one and rebinds a changed one while it
//     runs, with no restart.
//
// THE KEY OF A DEFINED HTTPS LISTENER NEVER LEAVES THE PEP. The PEP
// generates it, proves possession in a PKCS #10 request and sends the
// request to `POST /xacml/pep/listener-certificate` over its mutual TLS;
// this service issues the certificate from the realm's `pep-tls` Issuing CA
// over the PUBLIC key in it, naming what the listener's definition names,
// and answers the certificate and its chain, `no-store`. So no answer and
// no audit row carries a private key, and nothing here keeps one — the same
// promise `xacml_pep_tls.ts` makes for the environment's pair, kept by not
// having the key at all rather than by handing it over once.
//
// WHAT THE PEP REPORTS (`inUseOf()`): every listener it has, the
// environment's and the defined ones, with whether it is listening, waiting
// or failed and why — the why from a CLOSED set, never the operating
// system's sentence, since a REMOTE_PEPS holder writes it and an
// administrator reads it (`PepRegistry.signalsOf()`'s argument) — and the
// certificate it serves. An older PEP reports none, and the console says so.
//
// PRODUCT MODE REFUSES A PLAIN-HTTP PROXY LISTENER unless
// `xacml.pepPlainHttpProxyListeners` says the realm means it: the proxy is
// where a browser signs in and carries its session cookie, so in the clear
// it is only right behind something that terminates TLS in front of it —
// which is a fact about the deployment only an administrator can state.
// `mode.servesProxyBrowsersInTheClear()` is the question, as it is for the
// proxy's public base URL.
//
// A LIBRARY: it registers no route. `xacml_admin.ts` answers the three
// actions, `xacml_pep_settings.ts` puts the definitions on the pull,
// `xacml_pep_registry.ts` keeps the report and `xacml.ts` answers the
// certificate request.
// ===========================================================================

import net = require('net');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import mode = require('../common/mode');
import config = require('../common/config');

const { log } = helpers;

// One listener defined here, as stored and sent.
interface Listener {
  id: string;
  protocol: 'http' | 'https';
  purpose: 'api' | 'proxy';
  address: string;
  port: number;
  dnsNames: string[];
  ipAddresses: string[];
  keyAlg: string;
  // Moved by `renew-pep-listener-certificate`; a PEP holding a certificate
  // requested under another value asks for a new one.
  renew: number;
}

// One of the environment's four.
interface BootstrapListener {
  id: string;
  protocol: 'http' | 'https';
  purpose: 'api' | 'proxy';
  env: string;
  port: number;
  // The switch that binds a plain-HTTP one (#1760: off by default), or ''.
  enable: string;
}

// One listener as the PEP reported it.
interface ReportedListener {
  id: string;
  source: 'environment' | 'service';
  protocol: string;
  purpose: string;
  address: string;
  port: number;
  state: string;
  reason: string;
  renew: number;
  certificate: Record<string, string> | null;
}

interface InUse {
  at: string;
  listeners: ReportedListener[];
}

interface Refusal {
  ok: false;
  why: string;
  code: string;
}

interface Validated {
  ok: true;
  listeners: Listener[];
}

interface PepListenersDeps {
  log: { debug(message: string): void; warn(message: string): void };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    tag(code: string): string;
  };
  isIP(text: string): number;
  // Whether this realm lets a reverse-proxy listener answer in plain HTTP.
  allowsPlainHttpProxy(): boolean;
}

const MAX_LISTENERS = 32;
const MAX_NAMES = 16;
const PROTOCOLS = ['http', 'https'];
const PURPOSES = ['api', 'proxy'];
// What a PEP may REPORT a listener is for: a definition's two, and `crl`,
// the plain-HTTP CRL-only listener on `PEP_PORT` (`PEP_CRL_HTTP` with
// `PEP_HTTP` off), which serves `GET /crl/<name>` and nothing else
// (2026-11-15). Never definable here; an older PEP reports it as `api`
// with the reason `crl-only`, which `XacmlPage.listenerPurpose()` reads.
const REPORTED_PURPOSES = ['api', 'proxy', 'crl'];
// What the PEP can generate with OpenSSL and the `pep-tls` Issuing CA
// certifies: a subset of `pki.TLS_SERVER_KEY_ALGS`.
const KEY_ALGS = ['ec-p256', 'ec-p384', 'rsa-2048', 'rsa-3072'];
const SOURCES = ['environment', 'service'];
// What a reported listener is doing.
const STATES = ['listening', 'waiting', 'failed', 'off'];
// Why it is not listening, or `none`. CLOSED: see the header.
const REASONS = ['none', 'address-in-use', 'permission-denied',
                 'address-unavailable', 'no-certificate',
                 'certificate-refused', 'certificate-request-refused',
                 'proxy-off', 'http-off', 'not-configured', 'crl-only',
                 'other'];
const MEMBERS = ['id', 'protocol', 'purpose', 'address', 'port', 'dnsNames',
                 'ipAddresses', 'keyAlg', 'renew'];
const ID = /^[A-Za-z0-9._-]{1,64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const CERT_MEMBERS = ['subject', 'issuer', 'serialHex', 'subjectAltName',
                      'validFrom', 'validTo', 'fingerprint256'];

// THE ENVIRONMENT'S FOUR, with the ports the container defaults to. Their
// ids are reserved, so a defined listener can never be mistaken for one.
// THE TWO PLAIN-HTTP ONES ARE OFF BY DEFAULT (#1760, rcbj 2026-11-14):
// `enable` names the switch that binds each, and a PEP reports one nobody
// turned on as `off` with the reason `http-off`.
const BOOTSTRAP: BootstrapListener[] = [
  { id: 'api-http', protocol: 'http', purpose: 'api', env: 'PEP_PORT',
    port: 9090, enable: 'PEP_HTTP' },
  { id: 'api-https', protocol: 'https', purpose: 'api',
    env: 'PEP_HTTPS_PORT', port: 9443, enable: '' },
  { id: 'proxy-http', protocol: 'http', purpose: 'proxy',
    env: 'PEP_PROXY_PORT', port: 9180, enable: 'PEP_PROXY_HTTP' },
  { id: 'proxy-https', protocol: 'https', purpose: 'proxy',
    env: 'PEP_PROXY_HTTPS_PORT', port: 9543, enable: '' }
];

/**
 * A remote PEP's listeners: the environment's four, the ones defined on its
 * page, their validation, the pull's section and the reading of the PEP's
 * report.
 */
class PepListeners {
  static readonly BOOTSTRAP: readonly BootstrapListener[] = BOOTSTRAP;
  static readonly PROTOCOLS: readonly string[] = PROTOCOLS;
  static readonly PURPOSES: readonly string[] = PURPOSES;
  static readonly KEY_ALGS: readonly string[] = KEY_ALGS;
  static readonly STATES: readonly string[] = STATES;
  static readonly REASONS: readonly string[] = REASONS;
  static readonly MAX_LISTENERS = MAX_LISTENERS;

  /**
   * Builds it over its dependencies.
   * @param deps - the logger, the error codes, an IP parser and the
   *   plain-HTTP proxy question
   */
  constructor(private readonly deps: PepListenersDeps) {
    deps.log.debug("Entering PepListeners.constructor().");
    deps.log.debug("Leaving PepListeners.constructor().");
  }

  /**
   * The dependencies from the real modules.
   * @returns the dependencies
   */
  static defaultDeps(): PepListenersDeps {
    log.debug("Entering PepListeners.defaultDeps().");
    log.debug("Leaving PepListeners.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      isIP: net.isIP,
      allowsPlainHttpProxy: function (): boolean {
        log.debug("Entering allowsPlainHttpProxy().");
        const allowed = mode.servesProxyBrowsersInTheClear() ||
          config.value('xacml.pepPlainHttpProxyListeners') === true;
        log.debug("Leaving allowsPlainHttpProxy(). " + allowed);
        return allowed;
      }
    };
  }

  private refuse(why: string, code: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepListeners.refuse(). " + code);
    log.debug("Leaving PepListeners.refuse().");
    return errorCodes.mark({ ok: false, why: why, code: code }, code);
  }

  /**
   * What `GET /admin-api/xacml/peps` answers about listeners: the
   * environment's four, the closed sets and the bounds. No prose.
   * @returns the catalogue
   */
  catalogue(): Record<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering PepListeners.catalogue().");
    log.debug("Leaving PepListeners.catalogue().");
    return {
      bootstrap: BOOTSTRAP.map(function (one) {
        return Object.assign({}, one);
      }),
      protocols: PROTOCOLS.slice(),
      purposes: PURPOSES.slice(),
      keyAlgorithms: KEY_ALGS.slice(),
      defaultKeyAlg: KEY_ALGS[0],
      maxListeners: MAX_LISTENERS,
      plainHttpProxyAllowed: this.deps.allowsPlainHttpProxy()
    };
  }

  // A list of names from a JSON array or one text box (one per line, or
  // separated by commas or spaces).
  private namesOf(value: unknown): string[] | null {
    const { log } = this.deps;
    log.debug("Entering PepListeners.namesOf().");
    if (value === undefined || value === null || value === '') {
      log.debug("Leaving PepListeners.namesOf(). None.");
      return [];
    }
    const raw: unknown[] = Array.isArray(value) ? value
      : (typeof value === 'string' ? value.split(/[\s,]+/) : [null]);
    const out: string[] = [];
    for (let i = 0; i < raw.length; i++) {
      if (typeof raw[i] !== 'string') {
        log.debug("Leaving PepListeners.namesOf(). Not a string.");
        return null;
      }
      const one = (raw[i] as string).trim();
      if (one && out.indexOf(one.toLowerCase()) < 0) {
        out.push(one.toLowerCase());
      }
    }
    log.debug("Leaving PepListeners.namesOf(). " + out.length);
    return out;
  }

  // Whether a string is a DNS name a certificate can carry.
  private isDnsName(text: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PepListeners.isDnsName().");
    const ok = text.length <= 253 && text.split('.').every(function (label) {
      return /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label);
    });
    log.debug("Leaving PepListeners.isDnsName(). " + ok);
    return ok;
  }

  // An integer from a number or a string of digits, or NaN.
  private integerOf(value: unknown): number {
    const { log } = this.deps;
    log.debug("Entering PepListeners.integerOf().");
    const n = typeof value === 'number' ? value
      : (typeof value === 'string' && /^\d{1,10}$/.test(value.trim())
          ? Number(value.trim()) : NaN);
    log.debug("Leaving PepListeners.integerOf().");
    return Number.isSafeInteger(n) ? n : NaN;
  }

  // Whether two addresses can both hold one port: they can unless they are
  // the same, or either is a wildcard (which holds the port on every
  // address of its family, and on Linux on both families for `::`).
  static overlaps(a: string, b: string): boolean {
    log.debug("Entering PepListeners.overlaps().");
    const wild = function (one: string): boolean {
      return one === '0.0.0.0' || one === '::';
    };
    const out = a === b || wild(a) || wild(b);
    log.debug("Leaving PepListeners.overlaps(). " + out);
    return out;
  }

  /**
   * Validates one listener definition, normalised, or refuses it naming it.
   * @param raw - the definition (an API body's `listener`, the console's
   *   form members, or a stored row)
   * @param where - how a refusal names it
   * @returns the listener, or a coded refusal
   */
  one(raw: unknown, where: string): Listener | Refusal {
    const { log, isIP } = this.deps;
    log.debug("Entering PepListeners.one(). " + where);
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepListeners.one(). Not an object.");
      return this.refuse(where + ' is not an object of ' +
                         MEMBERS.join(', ') + '.', 'STS-XACML-0243');
    }
    const given = raw as Record<string, unknown>;
    const stray = Object.keys(given).filter(function (key) {
      return MEMBERS.indexOf(key) < 0;
    })[0];
    if (stray) {
      log.debug("Leaving PepListeners.one(). Stray member.");
      return this.refuse(where + ' carries "' + stray + '", which a ' +
                         'listener does not have. A listener has ' +
                         MEMBERS.join(', ') + '.', 'STS-XACML-0243');
    }
    const id = given.id;
    if (typeof id !== 'string' || !ID.test(id)) {
      log.debug("Leaving PepListeners.one(). Id.");
      return this.refuse(where + '\'s `id` must be 1 to 64 letters, ' +
                         'digits, dots, dashes or underscores.',
                         'STS-XACML-0244');
    }
    if (BOOTSTRAP.some(function (one) { return one.id === id; })) {
      log.debug("Leaving PepListeners.one(). Reserved id.");
      return this.refuse('"' + id + '" is one of the environment\'s ' +
                         'listeners (' + BOOTSTRAP.map(function (one) {
                           return one.id;
                         }).join(', ') + '); a listener defined here takes ' +
                         'another id.', 'STS-XACML-0244');
    }
    const protocol = given.protocol;
    const purpose = given.purpose;
    if (typeof protocol !== 'string' || PROTOCOLS.indexOf(protocol) < 0 ||
        typeof purpose !== 'string' || PURPOSES.indexOf(purpose) < 0) {
      log.debug("Leaving PepListeners.one(). Protocol or purpose.");
      return this.refuse(where + ' ("' + id + '"): `protocol` is one of ' +
                         PROTOCOLS.join(', ') + ' and `purpose` one of ' +
                         PURPOSES.join(', ') + '.', 'STS-XACML-0245');
    }
    const address = given.address === undefined || given.address === ''
      ? '0.0.0.0' : given.address;
    const port = this.integerOf(given.port);
    if (typeof address !== 'string' || !isIP(address) ||
        !(port >= 1 && port <= 65535)) {
      log.debug("Leaving PepListeners.one(). Address or port.");
      return this.refuse(where + ' ("' + id + '"): `address` is an IPv4 or ' +
                         'IPv6 address (0.0.0.0 or :: for every one) and ' +
                         '`port` an integer from 1 to 65535.',
                         'STS-XACML-0246');
    }
    const dnsNames = this.namesOf(given.dnsNames);
    const ipAddresses = this.namesOf(given.ipAddresses);
    const keyAlg = given.keyAlg === undefined || given.keyAlg === ''
      ? (protocol === 'https' ? KEY_ALGS[0] : '') : given.keyAlg;
    if (protocol === 'http' &&
        ((dnsNames && dnsNames.length) ||
         (ipAddresses && ipAddresses.length) || keyAlg)) {
      log.debug("Leaving PepListeners.one(). Names on plain HTTP.");
      return this.refuse(where + ' ("' + id + '") is plain HTTP and names ' +
                         'a certificate\'s names or key: only an HTTPS ' +
                         'listener has a certificate.', 'STS-XACML-0248');
    }
    const self = this;
    if (dnsNames === null || ipAddresses === null ||
        dnsNames.length > MAX_NAMES || ipAddresses.length > MAX_NAMES ||
        dnsNames.some(function (one) { return !self.isDnsName(one); }) ||
        ipAddresses.some(function (one) { return !isIP(one); }) ||
        (protocol === 'https' &&
         (typeof keyAlg !== 'string' || KEY_ALGS.indexOf(keyAlg) < 0))) {
      log.debug("Leaving PepListeners.one(). Certificate names or key.");
      return this.refuse(where + ' ("' + id + '"): `dnsNames` are at most ' +
                         MAX_NAMES + ' DNS names, `ipAddresses` at most ' +
                         MAX_NAMES + ' IPv4 or IPv6 addresses, and `keyAlg` ' +
                         'one of ' + KEY_ALGS.join(', ') + '.',
                         'STS-XACML-0248');
    }
    if (protocol === 'http' && purpose === 'proxy' &&
        !this.deps.allowsPlainHttpProxy()) {
      log.debug("Leaving PepListeners.one(). Plain-HTTP proxy in product.");
      return this.refuse(where + ' ("' + id + '") is a plain-HTTP reverse ' +
                         'proxy listener, which product mode refuses: a ' +
                         'browser signs in through the proxy and carries ' +
                         'its session cookie there. Define it as https, ' +
                         'or — when something in front of it terminates ' +
                         'TLS — turn on xacml.pepPlainHttpProxyListeners.',
                         'STS-XACML-0249');
    }
    const renew = given.renew === undefined ? 0 : this.integerOf(given.renew);
    if (!(renew >= 0)) {
      log.debug("Leaving PepListeners.one(). renew.");
      return this.refuse(where + ' ("' + id + '"): `renew` is a ' +
                         'non-negative integer.', 'STS-XACML-0243');
    }
    log.debug("Leaving PepListeners.one(). Usable.");
    return {
      id: id, protocol: protocol as 'http' | 'https',
      purpose: purpose as 'api' | 'proxy', address: address, port: port,
      dnsNames: dnsNames, ipAddresses: ipAddresses,
      keyAlg: protocol === 'https' ? keyAlg as string : '', renew: renew
    };
  }

  /**
   * The environment's listeners as this PEP last reported them, or the
   * container's defaults where it reported nothing: what a defined
   * listener's address and port must not collide with.
   * @param inUse - the PEP's report, normalised, or null
   * @returns `{ id, address, port }` for each
   */
  static environmentOf(inUse: InUse | null):
      Array<{ id: string; address: string; port: number }> {
    log.debug("Entering PepListeners.environmentOf().");
    const reported = inUse ? inUse.listeners.filter(function (one) {
      return one.source === 'environment';
    }) : [];
    // ONE THE PEP REPORTS `off` HOLDS NO PORT (#1760): with plain HTTP off
    // by default, 9090 is free for a listener defined here — which is the
    // managed way to serve plain HTTP. Unreported, the default port is
    // held, the safe reading of a PEP that has not said.
    const out = BOOTSTRAP.filter(function (one) {
      const said = reported.filter(function (r) {
        return r.id === one.id;
      })[0];
      return !said || said.state !== 'off';
    }).map(function (one) {
      const said = reported.filter(function (r) {
        return r.id === one.id;
      })[0];
      return said
        ? { id: one.id, address: said.address || '0.0.0.0', port: said.port }
        : { id: one.id, address: '0.0.0.0', port: one.port };
    });
    log.debug("Leaving PepListeners.environmentOf().");
    return out;
  }

  /**
   * Validates a whole list of definitions: each one, the ids unique, no two
   * holding one address and port, and none on an environment listener's.
   * @param list - the definitions (an array, or its JSON text)
   * @param inUse - the PEP's report, for the environment's ports
   * @param environment - false to leave out the environment's ports: a
   *   stored list is read again without them, since the PEP's report can
   *   move after the write and the PEP refuses a clash by failing to bind
   * @returns `{ ok: true, listeners }` or a coded refusal
   */
  validate(list: unknown, inUse: InUse | null,
           environment?: boolean): Validated | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepListeners.validate().");
    let given: unknown = list;
    if (typeof given === 'string') {
      try {
        given = JSON.parse(given);
      } catch (e) {
        log.debug("Caught in PepListeners.validate(): " +
                  ((e && e.message) || e));
        given = null;
      }
    }
    if (!Array.isArray(given)) {
      log.debug("Leaving PepListeners.validate(). Not a list.");
      return this.refuse('The listeners are a JSON array of listener ' +
                         'objects.', 'STS-XACML-0243');
    }
    if (given.length > MAX_LISTENERS) {
      log.debug("Leaving PepListeners.validate(). Too many.");
      return this.refuse('A PEP may have at most ' + MAX_LISTENERS +
                         ' listeners defined here; this is ' + given.length +
                         '.', 'STS-XACML-0243');
    }
    const out: Listener[] = [];
    const held = environment === false ? []
      : PepListeners.environmentOf(inUse);
    for (let i = 0; i < given.length; i++) {
      const one: any = this.one(given[i], 'Listener ' + (i + 1));
      if (one.ok === false) {
        log.debug("Leaving PepListeners.validate(). Refused: " + one.code);
        return one as Refusal;
      }
      if (out.some(function (other) { return other.id === one.id; })) {
        log.debug("Leaving PepListeners.validate(). Id twice.");
        return this.refuse('Two listeners are called "' + one.id + '"; a ' +
                           'listener `id` is unique.', 'STS-XACML-0244');
      }
      const clash = out.map(function (other) {
        return { id: other.id, address: other.address, port: other.port };
      }).concat(held).filter(function (other) {
        return other.port === one.port &&
          PepListeners.overlaps(other.address, one.address);
      })[0];
      if (clash) {
        log.debug("Leaving PepListeners.validate(). Address clash.");
        return this.refuse('Listener "' + one.id + '" would listen on ' +
                           one.address + ':' + one.port + ', which ' +
                           'listener "' + clash.id + '" holds (' +
                           clash.address + ':' + clash.port + ').',
                           'STS-XACML-0247');
      }
      out.push(one as Listener);
    }
    log.debug("Leaving PepListeners.validate(). " + out.length);
    return { ok: true, listeners: out };
  }

  /**
   * Reads a stored document again.
   * @param text - the stored JSON, or ''
   * @param inUse - the PEP's report, for the environment's ports
   * @returns `{ listeners, problem }`: the list when it validates (empty
   *   when none is stored), else null and why
   */
  stored(text: string, inUse: InUse | null):
      { listeners: Listener[] | null; problem: string | null } {
    const { log } = this.deps;
    log.debug("Entering PepListeners.stored().");
    if (!text) {
      log.debug("Leaving PepListeners.stored(). None.");
      return { listeners: [], problem: null };
    }
    const checked = this.validate(text, inUse, false);
    log.debug("Leaving PepListeners.stored(). ok=" + checked.ok);
    return checked.ok
      ? { listeners: (checked as Validated).listeners, problem: null }
      : { listeners: null, problem: (checked as Refusal).why };
  }

  /**
   * The list with one listener added or replaced by its id (an edit keeps
   * where it was and its `renew`), validated whole.
   * @param current - the stored definitions
   * @param given - the listener
   * @param inUse - the PEP's report
   * @param environment - optional; false to leave out the environment's
   *   ports (a cluster's definitions, which each member's own report is
   *   asked of afterwards, #1760)
   * @returns the new list, or a coded refusal
   */
  withListener(current: Listener[], given: unknown,
               inUse: InUse | null,
               environment?: boolean): Validated | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepListeners.withListener().");
    const one: any = this.one(given, 'The listener');
    if (one.ok === false) {
      log.debug("Leaving PepListeners.withListener(). Refused.");
      return one as Refusal;
    }
    const list = current.slice();
    const at = list.map(function (row) { return row.id; }).indexOf(one.id);
    if (at >= 0) {
      one.renew = list[at].renew;
      list[at] = one;
    } else {
      list.push(one);
    }
    const checked = this.validate(list, inUse, environment);
    log.debug("Leaving PepListeners.withListener(). ok=" + checked.ok);
    return checked;
  }

  /**
   * The list without one listener, or the list with its `renew` moved.
   * @param current - the stored definitions
   * @param id - the listener's id
   * @param renew - true to move `renew` rather than remove
   * @returns the new list, or a coded refusal naming an unknown id
   */
  without(current: Listener[], id: string, renew: boolean):
      Validated | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepListeners.without(). " + id);
    const at = current.map(function (row) { return row.id; }).indexOf(id);
    if (at < 0) {
      log.debug("Leaving PepListeners.without(). No such listener.");
      return this.refuse('No listener "' + id + '" is defined here for ' +
                         'this PEP. ' + (BOOTSTRAP.some(function (one) {
                           return one.id === id;
                         }) ? 'It is one of the environment\'s, which only ' +
                              'the PEP\'s environment changes.' : ''),
                         'STS-XACML-0250');
    }
    const list = current.slice();
    if (renew) {
      if (list[at].protocol !== 'https') {
        log.debug("Leaving PepListeners.without(). Plain HTTP.");
        return this.refuse('Listener "' + id + '" is plain HTTP and has ' +
                           'no certificate to renew.', 'STS-XACML-0250');
      }
      list[at] = Object.assign({}, list[at], { renew: list[at].renew + 1 });
    } else {
      list.splice(at, 1);
    }
    log.debug("Leaving PepListeners.without().");
    return { ok: true, listeners: list };
  }

  /**
   * The certificate register's slot for a defined HTTPS listener.
   * @param name - the PEP's name
   * @param id - the listener's id
   * @returns the slot
   */
  static slotOf(name: string, id: string): string {
    log.debug("Entering PepListeners.slotOf().");
    log.debug("Leaving PepListeners.slotOf().");
    return name + '/' + id;
  }

  // -------------------------------------------------------------------------
  // WHAT THE PEP SAYS ABOUT ITS LISTENERS, held to its members (see the
  // header). The same function reads the stored value back.
  // -------------------------------------------------------------------------
  /**
   * Normalises a heartbeat's `listeners` member, or the stored text.
   * @param raw - the reported object `{ listeners: [...] }`, or its text
   * @param at - when it was received; the stored `at` when omitted
   * @returns the members kept, or null when there is nothing to read
   */
  static inUseOf(raw: unknown, at?: string): InUse | null {
    log.debug("Entering PepListeners.inUseOf().");
    let said: any = raw;
    if (typeof said === 'string') {
      try {
        said = said ? JSON.parse(said) : null;
      } catch (e) {
        log.debug("Caught in PepListeners.inUseOf(): " +
                  ((e && e.message) || e));
        said = null;
      }
    }
    if (said && Array.isArray(said)) {
      said = { listeners: said };
    }
    if (!said || typeof said !== 'object' || !Array.isArray(said.listeners)) {
      log.debug("Leaving PepListeners.inUseOf(). Nothing to read.");
      return null;
    }
    // No Entering/Leaving pair on these two: they run for every member of
    // every reported listener, and a pair would drown the log.
    const text = function (value: unknown, max: number): string {
      return typeof value === 'string' && value.length <= max &&
        !CONTROL.test(value) ? value : '';
    };
    const closed = function (value: unknown, set: string[],
                             fallback: string): string {
      return typeof value === 'string' && set.indexOf(value) >= 0
        ? value : fallback;
    };
    const kept: ReportedListener[] = [];
    said.listeners.slice(0, MAX_LISTENERS + BOOTSTRAP.length)
      .forEach(function (one: any) {
        if (!one || typeof one !== 'object' || typeof one.id !== 'string' ||
            !ID.test(one.id) || kept.some(function (k) {
              return k.id === one.id;
            })) {
          return;
        }
        const port = typeof one.port === 'number' &&
          Number.isSafeInteger(one.port) && one.port >= 0 &&
          one.port <= 65535 ? one.port : 0;
        const address = typeof one.address === 'string' &&
          net.isIP(one.address) ? one.address : '';
        let certificate: Record<string, string> | null = null;
        if (one.certificate && typeof one.certificate === 'object') {
          certificate = {};
          CERT_MEMBERS.forEach(function (key) {
            (certificate as Record<string, string>)[key] =
              text(one.certificate[key], 2048);
          });
        }
        kept.push({
          id: one.id,
          source: closed(one.source, SOURCES, 'service') as
            'environment' | 'service',
          protocol: closed(one.protocol, PROTOCOLS, 'http'),
          purpose: closed(one.purpose, REPORTED_PURPOSES, 'api'),
          address: address,
          port: port,
          state: closed(one.state, STATES, 'failed'),
          reason: closed(one.reason, REASONS, 'other'),
          renew: typeof one.renew === 'number' &&
            Number.isSafeInteger(one.renew) && one.renew >= 0
            ? one.renew : 0,
          certificate: certificate
        });
      });
    const stamp = at !== undefined ? at
      : (typeof said.at === 'string' && !isNaN(Date.parse(said.at))
          ? new Date(Date.parse(said.at)).toISOString() : '');
    log.debug("Leaving PepListeners.inUseOf(). " + kept.length);
    return { at: stamp, listeners: kept };
  }

  /**
   * Every listener of a PEP as its page draws it: the environment's four
   * and the ones defined here, each joined to what the PEP reported about
   * it (or null for "not reported").
   * @param defined - the definitions
   * @param inUse - the PEP's report, or null
   * @returns the rows, environment first
   */
  rows(defined: Listener[], inUse: InUse | null): any[] {
    const { log } = this.deps;
    log.debug("Entering PepListeners.rows().");
    const reported = function (id: string): ReportedListener | null {
      return inUse ? inUse.listeners.filter(function (one) {
        return one.id === id;
      })[0] || null : null;
    };
    const out = BOOTSTRAP.map(function (one) {
      return { id: one.id, source: 'environment', protocol: one.protocol,
               purpose: one.purpose, env: one.env, enable: one.enable,
               defaultPort: one.port, definition: null,
               reported: reported(one.id) };
    }).concat(defined.map(function (one) {
      return { id: one.id, source: 'service', protocol: one.protocol,
               purpose: one.purpose, env: '', enable: '',
               defaultPort: one.port, definition: one,
               reported: reported(one.id) };
    }) as any[]);
    log.debug("Leaving PepListeners.rows(). " + out.length);
    return out;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), and a default one
// where nothing runs the root.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PepListeners>(
  'xacml/xacml_pep_listeners',
  () => new PepListeners(PepListeners.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * A remote PEP's listeners (#1760).
 * @namespace
 */
export = {
  PepListeners: PepListeners,
  installInstance: (instance: PepListeners): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BOOTSTRAP: PepListeners.BOOTSTRAP,
  PROTOCOLS: PepListeners.PROTOCOLS,
  PURPOSES: PepListeners.PURPOSES,
  KEY_ALGS: PepListeners.KEY_ALGS,
  STATES: PepListeners.STATES,
  REASONS: PepListeners.REASONS,
  MAX_LISTENERS: PepListeners.MAX_LISTENERS,
  inUseOf: PepListeners.inUseOf,
  slotOf: PepListeners.slotOf,
  overlaps: PepListeners.overlaps,
  environmentOf: PepListeners.environmentOf,
  catalogue: slot.forward('catalogue'),
  one: slot.forward('one'),
  validate: slot.forward('validate'),
  stored: slot.forward('stored'),
  withListener: slot.forward('withListener'),
  without: slot.forward('without'),
  rows: slot.forward('rows')
};
