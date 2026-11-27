// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: forwarded_client_certificate.ts
//
// ===========================================================================
// A CLIENT CERTIFICATE FORWARDED BY A TLS-TERMINATING PROXY, RFC 9440
// (#2012, 2026-11-23).
//
// **THE RULE THIS FILE BENDS, AND HOW FAR.** `oauth-oidc/oauth2_bcp.js`'s
// `no-certificate-header` said this service reads a client certificate out
// of no header, in either mode, because a header costs nothing to write. That
// stays true of every sender but one: a proxy the administrator named, by
// BOTH the client certificate it presents when it connects here
// (`tls.trustedProxyCertificates`, SHA-256 fingerprints) AND the address it
// connects from (`tls.trustedProxyAddresses`, CIDR ranges) — rcbj's decision
// on #2012. Either alone trusts nobody, and says so once (STS-TLS-0076).
//
// **A PIN NAMES THE CERTIFICATE OR ITS KEY** (rcbj, 2026-11-23: "accept
// both"). A bare value is the SHA-256 of the proxy's whole certificate (DER),
// as it always was — 64 hex digits, colons and a `sha256:` prefix allowed —
// so it breaks when the proxy's certificate is renewed. `spki:<the same
// hex>` is the SHA-256 of its SubjectPublicKeyInfo (RFC 7469's pin, in this
// setting's encoding), which a renewal under the same key keeps. The SPKI
// is read off the certificate's own DER (`crypto.certificateSpkiDer()`), so
// a key node cannot load is still a key here. A malformed entry is refused
// at the write (STS-TLS-0077, `writeRule()`); one already stored or read
// from the environment is skipped, as it always was, never widened.
//
// **FROM THAT PROXY**, RFC 9440's two headers are read:
//
//   * `Client-Cert` — one Structured Field byte sequence (RFC 8941 section
//     3.3.5), `:base64 DER:`, the leaf the client presented;
//   * `Client-Cert-Chain` — an optional list of byte sequences, the
//     certificates the client sent with it.
//
// The proxy proved the client holds the key (RFC 9440 section 2); what it did
// NOT do is decide the certificate is acceptable HERE, so this file does that
// as the handshake would have: the path is built and verified to the client
// truststore (`tls_server.anchorCertificates()` — the operator's anchors and,
// where `tls.trustIssuedClientCertificates`, the service Root) with every
// path rule (`pki.verifyPathToAnchors()`). Revocation, the identity gate and
// every certificate sign-in profile then run on it exactly as on a
// handshake's certificate, because the request's socket is REPLACED, for that
// request only, by a view of the real socket whose `authorized`,
// `getPeerCertificate()` and `getPeerX509Certificate()` answer the forwarded
// certificate (`viewOf()`). Every door that reads a client certificate reads
// it through the socket — the sign-in, RFC 8705, SCIM, XACML, SSF — so none
// of them changed, and none of them can see the proxy's own certificate: a
// request from the proxy with no `Client-Cert`, or with one that does not
// verify (STS-TLS-0073), presents NO certificate.
//
// **FROM ANYBODY ELSE**, both headers are REMOVED before any door or request
// worker could read them, and the removal is recorded (STS-TLS-0072), at most
// once a minute per process, because a client spraying them would otherwise
// write a line per request.
//
// **WHERE IT RUNS.** `common/app.js` installs `middleware()` below the realm
// and the CDN-edge refusal and ABOVE the request pool, so it runs in the
// front process before dispatch: the worker is handed what `peerOf()` reads
// off the replaced socket — the forwarded leaf and its built chain — and the
// headers are already gone. In a worker it finds no header and no proxy.
//
// A LIBRARY (rule 3): no route. `tls/tls_server.js` (the anchors) is reached
// at the request, never at load.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import pki = require('./pki');
import stsCrypto = require('./crypto');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import clientAddress = require('./client_address');
import CertificateTrust = require('./certificate_trust');

type Json = any;

const CERT_HEADER = 'client-cert';
const CHAIN_HEADER = 'client-cert-chain';
const MAX_HEADER = 32768;
const MAX_CHAIN = 8;
const RECORD_EVERY_MS = 60000;
const BYTE_SEQUENCE = /^:([A-Za-z0-9+/]+={0,2}):$/;
const PINS_SETTING = 'tls.trustedProxyCertificates';

interface ForwardedClientCertificateDeps {
  log: typeof helpers.log;
  config: typeof config;
  pki: typeof pki;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  clientAddress: typeof clientAddress;
  trust: typeof CertificateTrust;
  now: () => number;
  // The anchors of the listener a socket arrived on, as X509Certificate
  // objects (header).
  anchors: (socket: Json) => Json[];
  // #212's curve guard: why a certificate's key is refused, or ''.
  curveProblem: (cert: Json) => string;
}

/**
 * RFC 9440's forwarded client certificate, believed from a named proxy only
 * (#2012).
 */
class ForwardedClientCertificate {
  private lastRecorded = 0;
  private lastHalfConfigured = 0;
  private rangesText = '';
  private ranges: Json = null;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: ForwardedClientCertificateDeps) {
    deps.log.debug("Entering ForwardedClientCertificate.constructor().");
    deps.log.debug("Leaving ForwardedClientCertificate.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): ForwardedClientCertificateDeps {
    helpers.log.debug("Entering ForwardedClientCertificate.defaultDeps().");
    helpers.log.debug("Leaving ForwardedClientCertificate.defaultDeps().");
    return {
      log: helpers.log, config: config, pki: pki, stsCrypto: stsCrypto,
      errorCodes: errorCodes, audit: audit, clientAddress: clientAddress,
      trust: CertificateTrust, now: Date.now,
      anchors: function (socket: Json): Json[] {
        const tlsServer = require('../tls/tls_server');
        if (socket && socket.server &&
            typeof tlsServer.caPemsFor === 'function') {
          return tlsServer.caPemsFor(socket.server)
            .map(function (pem: string): Json {
              return stsCrypto.parseCertificate(pem);
            });
        }
        return tlsServer.anchorCertificates();
      },
      curveProblem: function (cert: Json): string {
        const tlsServer = require('../tls/tls_server');
        return typeof tlsServer.refusedCurveKey === 'function'
          ? String(tlsServer.refusedCurveKey(cert) || '') : '';
      }
    };
  }

  // -------------------------------------------------------------------------
  // WHO THE PROXY IS.
  // -------------------------------------------------------------------------
  /**
   * One entry of `tls.trustedProxyCertificates`, read: a certificate's
   * SHA-256 (bare, `sha256:` or `sha-256:`) or a SubjectPublicKeyInfo's
   * (`spki:`), as lower-case hex, or null for an entry that is neither.
   *
   * @param text - the entry
   * @returns `{ kind: 'certificate' | 'spki', hex }`, or null
   */
  static pinOf(text: unknown): Json {
    helpers.log.debug("Entering ForwardedClientCertificate.pinOf().");
    const s = String(text == null ? '' : text).trim().toLowerCase();
    const spki = s.indexOf('spki:') === 0;
    const body = spki ? s.slice(5) : s.replace(/^sha-?256:/, '');
    const hex = body.replace(/[:\s]/g, '');
    const ok = /^[0-9a-f]{64}$/.test(hex);
    helpers.log.debug("Leaving ForwardedClientCertificate.pinOf(). " + ok);
    return ok ? { kind: spki ? 'spki' : 'certificate', hex: hex } : null;
  }

  /**
   * The rule `config.addWriteRule()` asks of every write of
   * `tls.trustedProxyCertificates`: each entry a certificate pin or an
   * `spki:` pin, else refused (STS-TLS-0077) naming the first that is not.
   *
   * @param key - the setting written
   * @param parsed - its value, parsed
   * @returns `{ problem, code }` for a refusal, or null
   */
  static writeRule(key: string, parsed: unknown): Json {
    helpers.log.debug("Entering ForwardedClientCertificate.writeRule(). " +
                      key);
    if (key !== PINS_SETTING) {
      helpers.log.debug("Leaving ForwardedClientCertificate.writeRule(). " +
                        "Not ours.");
      return null;
    }
    const entries = (Array.isArray(parsed) ? parsed
      : String(parsed == null ? '' : parsed).split(','))
      .map(function (one: unknown): string {
        return String(one).trim();
      }).filter(Boolean);
    const bad = entries.filter(function (one: string): boolean {
      return !ForwardedClientCertificate.pinOf(one);
    })[0];
    helpers.log.debug("Leaving ForwardedClientCertificate.writeRule(). " +
                      (bad === undefined ? 'Taken.' : 'Refused.'));
    return bad === undefined ? null : {
      problem: PINS_SETTING + ' is refused: "' + bad.slice(0, 80) + '" is ' +
        'neither the SHA-256 of a certificate (64 hex digits, colons and a ' +
        'sha256: prefix allowed) nor spki: followed by the SHA-256 of a ' +
        'SubjectPublicKeyInfo in the same form.',
      code: 'STS-TLS-0077' };
  }

  /**
   * The configured proxy pins, canonical, and the address ranges.
   *
   * @returns `{ fingerprints, keys, ranges }`: the certificates' SHA-256,
   *   the SubjectPublicKeyInfos', and the ranges; all empty where it is off
   */
  configured(): Json {
    const { log, config: settings, clientAddress: addresses } = this.deps;
    log.debug("Entering ForwardedClientCertificate.configured().");
    const listOf = function (key: string): string[] {
      const raw = settings.value(key);
      return (Array.isArray(raw) ? raw : String(raw || '').split(','))
        .map(function (one: unknown): string {
          return String(one).trim();
        }).filter(Boolean);
    };
    const fingerprints: string[] = [];
    const keys: string[] = [];
    listOf(PINS_SETTING).forEach(function (one: string): void {
      const pin = ForwardedClientCertificate.pinOf(one);
      if (pin) {
        (pin.kind === 'spki' ? keys : fingerprints).push(pin.hex);
      }
    });
    const entries = listOf('tls.trustedProxyAddresses');
    const text = entries.join(',');
    if (text !== this.rangesText || !this.ranges) {
      this.rangesText = text;
      this.ranges = addresses.parseRanges(entries,
                                          'tls.trustedProxyAddresses');
    }
    log.debug("Leaving ForwardedClientCertificate.configured(). " +
              fingerprints.length + " certificate(s), " + keys.length +
              " key(s), " + this.ranges.count + " range(s).");
    return { fingerprints: fingerprints, keys: keys, ranges: this.ranges };
  }

  /**
   * Whether a request arrived from a trusted TLS-terminating proxy: on a
   * connection whose own client certificate verified and is one of
   * `tls.trustedProxyCertificates` — by its own SHA-256 or, for an `spki:`
   * pin, its SubjectPublicKeyInfo's — from an address in
   * `tls.trustedProxyAddresses`.
   *
   * @param req - the request
   * @returns true where it did
   */
  fromTrustedProxy(req: Json): boolean {
    const { log, stsCrypto: c, errorCodes: codes,
            clientAddress: addresses } = this.deps;
    log.debug("Entering ForwardedClientCertificate.fromTrustedProxy().");
    const wanted = this.configured();
    const pins = wanted.fingerprints.length + wanted.keys.length;
    if (!pins || !wanted.ranges.count) {
      if ((pins || wanted.ranges.count) &&
          this.deps.now() - this.lastHalfConfigured > RECORD_EVERY_MS) {
        this.lastHalfConfigured = this.deps.now();
        log.warn(codes.tag('STS-TLS-0076') + 'forwarded_client_certificate: ' +
                 'only one of tls.trustedProxyCertificates and ' +
                 'tls.trustedProxyAddresses is set, so no proxy is trusted ' +
                 'to forward a client certificate.');
      }
      log.debug("Leaving ForwardedClientCertificate.fromTrustedProxy(). " +
                "Not configured.");
      return false;
    }
    const socket = req && req.socket;
    if (!socket || socket.authorized !== true ||
        typeof socket.getPeerCertificate !== 'function' ||
        !addresses.inRanges(addresses.peerAddressOf(req), wanted.ranges)) {
      log.debug("Leaving ForwardedClientCertificate.fromTrustedProxy(). " +
                "Not from a proxy's address with a verified certificate.");
      return false;
    }
    let raw: Buffer | null = null;
    try {
      const peer = socket.getPeerCertificate();
      raw = peer && peer.raw && peer.raw.length ? peer.raw : null;
    } catch (e) {
      log.debug("Caught in ForwardedClientCertificate.fromTrustedProxy(): " +
                ((e && e.message) || e));
      raw = null;
    }
    if (!raw) {
      log.debug("Leaving ForwardedClientCertificate.fromTrustedProxy(). " +
                "No certificate.");
      return false;
    }
    let trusted = wanted.fingerprints.indexOf(
      c.digest('sha256', raw, 'hex')) >= 0;
    if (!trusted && wanted.keys.length) {
      try {
        trusted = wanted.keys.indexOf(c.digest('sha256',
          c.certificateSpkiDer(raw.toString('base64')), 'hex')) >= 0;
      } catch (e) {
        // A certificate whose key cannot be read matches no key pin.
        log.debug("Caught in ForwardedClientCertificate.fromTrustedProxy(): " +
                  ((e && e.message) || e));
        trusted = false;
      }
    }
    log.debug("Leaving ForwardedClientCertificate.fromTrustedProxy(). " +
              trusted);
    return trusted;
  }

  // -------------------------------------------------------------------------
  // WHAT THE PROXY SENT.
  // -------------------------------------------------------------------------
  /**
   * One RFC 8941 byte sequence's bytes, or null.
   *
   * @param item - the item's text
   * @returns the bytes, or null
   */
  static byteSequence(item: string): Buffer | null {
    helpers.log.debug("Entering ForwardedClientCertificate.byteSequence().");
    const m = BYTE_SEQUENCE.exec(String(item || '').trim());
    helpers.log.debug("Leaving ForwardedClientCertificate.byteSequence().");
    return m ? Buffer.from(m[1], 'base64') : null;
  }

  /**
   * The two headers read: `{ leaf, chain }` as DER, or `{ problem }`.
   *
   * @param headers - the request's headers
   * @returns the certificates, or the reason they are not
   */
  static parse(headers: Json): Json {
    helpers.log.debug("Entering ForwardedClientCertificate.parse().");
    const cert = headers[CERT_HEADER];
    const chain = headers[CHAIN_HEADER];
    if (typeof cert !== 'string' || !cert.trim()) {
      helpers.log.debug("Leaving ForwardedClientCertificate.parse(). " +
                        "No Client-Cert.");
      return { problem: chain ? 'Client-Cert-Chain arrived without ' +
                                'Client-Cert' : '' };
    }
    if (cert.length > MAX_HEADER ||
        (typeof chain === 'string' && chain.length > MAX_HEADER)) {
      helpers.log.debug("Leaving ForwardedClientCertificate.parse(). " +
                        "Too large.");
      return { problem: 'a header is larger than ' + MAX_HEADER + ' bytes' };
    }
    const leaf = ForwardedClientCertificate.byteSequence(cert);
    if (!leaf) {
      helpers.log.debug("Leaving ForwardedClientCertificate.parse(). " +
                        "Not a byte sequence.");
      return { problem: 'Client-Cert is not one RFC 8941 byte sequence ' +
                        '(:base64:)' };
    }
    const items = typeof chain === 'string' && chain.trim()
      ? chain.split(',') : [];
    if (items.length > MAX_CHAIN) {
      helpers.log.debug("Leaving ForwardedClientCertificate.parse(). " +
                        "A long chain.");
      return { problem: 'Client-Cert-Chain holds more than ' + MAX_CHAIN +
                        ' certificates' };
    }
    const ders: Buffer[] = [];
    for (let i = 0; i < items.length; i++) {
      const one = ForwardedClientCertificate.byteSequence(items[i]);
      if (!one) {
        helpers.log.debug("Leaving ForwardedClientCertificate.parse(). " +
                          "A bad chain item.");
        return { problem: 'Client-Cert-Chain item ' + (i + 1) + ' is not ' +
                          'an RFC 8941 byte sequence' };
      }
      ders.push(one);
    }
    helpers.log.debug("Leaving ForwardedClientCertificate.parse().");
    return { leaf: leaf, chain: ders };
  }

  /**
   * Verifies what the proxy forwarded as the listener it reached verifies a
   * handshake's certificate (the #2012 review): the path to THAT listener's
   * `ca` list through the #1360 door for `tls-client`, the leaf's keyUsage
   * and extendedKeyUsage (clientAuth) always, the path rules and — under
   * paranoid PKI mode — the fields `holdPeer()` asks of a handshake, and
   * #212's curve guard on every certificate of the path. `{ ok, path }`,
   * `path` the X509Certificate objects leaf first and the anchor last, or
   * `{ ok: false, why }`.
   *
   * @param parsed - `parse()`'s answer
   * @param socket - the real socket the proxy connected on
   * @returns a promise of the verdict
   */
  async verify(parsed: Json, socket?: Json): Promise<Json> {
    const { log, pki: p, stsCrypto: c, trust } = this.deps;
    log.debug("Entering ForwardedClientCertificate.verify().");
    let anchors: Json[] = [];
    try {
      anchors = (this.deps.anchors(socket) || []).map(function (one: Json) {
        return p.certificateFromDer(Buffer.from(one.raw));
      }).filter(Boolean);
    } catch (e) {
      log.debug("Caught in ForwardedClientCertificate.verify(): " +
                ((e && e.message) || e));
      anchors = [];
    }
    const refuse = function (why: string): Json {
      log.debug("Leaving ForwardedClientCertificate.verify(). " + why);
      return { ok: false, why: why };
    };
    const built = await trust.path('tls-client', parsed.leaf, parsed.chain,
      anchors, { now: this.deps.now() });
    if (!built.ok) {
      return refuse('its chain does not verify to the listener\'s client ' +
                    'truststore: ' + String(built.reason || ''));
    }
    let path: Json[] = [];
    try {
      path = (built.chain || []).map(function (one: Json): Json {
        return c.parseCertificate(Buffer.from(one.der || one.raw || one));
      });
    } catch (e) {
      log.debug("Caught in ForwardedClientCertificate.verify(): " +
                ((e && e.message) || e));
      path = [];
    }
    if (!path.length) {
      return refuse('its certificates cannot be read');
    }
    const purpose = trust.purpose('tls-client');
    let field: Json = null;
    try {
      field = c.certificateFieldProblem(path[0], Object.assign({},
        purpose.leaf, { role: 'leaf', now: this.deps.now() }));
    } catch (e) {
      log.debug("Caught in ForwardedClientCertificate.verify(): " +
                ((e && e.message) || e));
      field = { why: 'its leaf cannot be read' };
    }
    if (field) {
      return refuse('it is not a TLS client certificate: ' +
                    String(field.why || field.check || ''));
    }
    const curve = path.map(this.deps.curveProblem).filter(Boolean)[0];
    if (curve) {
      return refuse('a certificate of its path has ' + curve);
    }
    const held = trust.holdPeer('tls-client',
      ForwardedClientCertificate.legacyOf(path, true), {});
    if (!held.ok) {
      return refuse(String(held.why || 'the path rules refused it'));
    }
    log.debug("Leaving ForwardedClientCertificate.verify(). " + path.length +
              " certificate(s).");
    return { ok: true, path: path };
  }

  // -------------------------------------------------------------------------
  // THE REQUEST'S VIEW OF ITS SOCKET (header).
  // -------------------------------------------------------------------------
  /**
   * node's `getPeerCertificate(detailed)` over a path of X509Certificate
   * objects: the leaf's legacy object, with each `issuerCertificate` linked
   * when detailed and a self-issued top linked to itself, as node answers.
   *
   * @param path - leaf first
   * @param detailed - whether the chain is linked
   * @returns the legacy object, or `{}` for no certificate
   */
  static legacyOf(path: Json[], detailed: boolean): Json {
    helpers.log.debug("Entering ForwardedClientCertificate.legacyOf().");
    if (!path.length) {
      helpers.log.debug("Leaving ForwardedClientCertificate.legacyOf(). " +
                        "None.");
      return {};
    }
    const objects = (detailed ? path : path.slice(0, 1))
      .map(function (one: Json): Json {
        return one.toLegacyObject();
      });
    if (detailed) {
      objects.forEach(function (object: Json, i: number) {
        if (i + 1 < objects.length) {
          object.issuerCertificate = objects[i + 1];
        }
      });
      // SELF-ISSUED IN RFC 5280 SECTION 3.3's SENSE, subject equal to issuer
      // (`crypto.certificateFacts()`' `selfIssued`), and not node's
      // `checkIssued()`: this only links the legacy object as node links a
      // handshake's, after the door (`CertificateTrust.path()`) has decided
      // the path, so it decides nothing and asks no path function
      // (`tests/certificate_trust_callers.js`, run 45236493306).
      const top = path[path.length - 1];
      if (String(top.subject) === String(top.issuer)) {
        objects[objects.length - 1].issuerCertificate =
          objects[objects.length - 1];
      }
    }
    helpers.log.debug("Leaving ForwardedClientCertificate.legacyOf().");
    return objects[0];
  }

  /**
   * A view of the real socket for one request, answering the forwarded
   * certificate (or none) where a door reads a client certificate, and the
   * real socket for everything else.
   *
   * @param socket - the real socket
   * @param path - the verified path, leaf first; empty for no certificate
   * @param why - why the request presents none, where it does not
   * @returns the view
   */
  static viewOf(socket: Json, path: Json[], why: string): Json {
    helpers.log.debug("Entering ForwardedClientCertificate.viewOf().");
    const verified = path.length > 0;
    const memo: Json = {};
    const own: Json = {
      authorized: verified,
      authorizationError: verified ? null
        : (why || 'NO_CLIENT_CERTIFICATE_FORWARDED'),
      forwardedClientCertificate: true,
      getPeerCertificate: function (detailed?: boolean): Json {
        const key = detailed ? 'detailed' : 'leaf';
        if (!memo[key]) {
          memo[key] = ForwardedClientCertificate.legacyOf(path, !!detailed);
        }
        return memo[key];
      },
      getPeerX509Certificate: function (): Json {
        return verified ? path[0] : undefined;
      },
      // A forwarded certificate arrived whole on this request: nothing is
      // resumed, so nothing is waited for (`revocation_status.js`).
      isSessionReused: function (): boolean {
        return false;
      }
    };
    helpers.log.debug("Leaving ForwardedClientCertificate.viewOf().");
    return new Proxy(socket, {
      get: function (target: Json, name: string | symbol): Json {
        if (typeof name === 'string' &&
            Object.prototype.hasOwnProperty.call(own, name)) {
          return own[name];
        }
        const value = Reflect.get(target, name, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });
  }

  /**
   * Records, at most once a minute, that a sender who is not a trusted proxy
   * sent the headers and they were removed.
   *
   * @param req - the request
   */
  private recordUntrusted(req: Json): void {
    const { log, errorCodes: codes, audit: rows,
            clientAddress: addresses } = this.deps;
    log.debug("Entering ForwardedClientCertificate.recordUntrusted().");
    const now = this.deps.now();
    if (now - this.lastRecorded < RECORD_EVERY_MS) {
      log.debug("Leaving ForwardedClientCertificate.recordUntrusted(). " +
                "Recorded lately.");
      return;
    }
    this.lastRecorded = now;
    log.info(codes.tag('STS-TLS-0072') + 'forwarded_client_certificate: ' +
             'removed Client-Cert headers from ' +
             addresses.clientAddressOf(req) + ', which is not a trusted ' +
             'TLS-terminating proxy (recorded at most once a minute).');
    rows.failure('STS-TLS-0072', {
      protocol: 'HTTP', channel: req.secure ? 'https' : 'http',
      address: addresses.clientAddressOf(req),
      target: rows.redactedPath(String(req.originalUrl || req.url || '')
        .split('?')[0]),
      summary: 'RFC 9440 client certificate headers from a sender that is ' +
               'not a trusted TLS-terminating proxy were removed.',
      outcome: 'refused'
    });
    log.debug("Leaving ForwardedClientCertificate.recordUntrusted().");
  }

  /**
   * The middleware `common/app.js` installs (header).
   *
   * @returns `(req, res, next)`
   */
  middleware(): (req: Json, res: Json, next: () => void) => void {
    const self = this;
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering ForwardedClientCertificate.middleware().");
    log.debug("Leaving ForwardedClientCertificate.middleware().");
    // A HOT PATH: every request passes it, so no Entering/Leaving pair
    // around a header test that is almost always false.
    return function forwardedClientCertificate(req: Json, res: Json,
                                               next: () => void): void {
      const headers = (req && req.headers) || {};
      const sent = headers[CERT_HEADER] !== undefined ||
                   headers[CHAIN_HEADER] !== undefined;
      let trusted = false;
      try {
        trusted = self.fromTrustedProxy(req);
      } catch (e) {
        log.debug("Caught in forwardedClientCertificate(): " +
                  ((e && e.message) || e));
        trusted = false;
      }
      if (!trusted) {
        if (sent) {
          delete headers[CERT_HEADER];
          delete headers[CHAIN_HEADER];
          self.recordUntrusted(req);
        }
        next();
        return;
      }
      const parsed = ForwardedClientCertificate.parse(headers);
      delete headers[CERT_HEADER];
      delete headers[CHAIN_HEADER];
      const real = req.socket;
      const finish = function (path: Json[], why: string): void {
        // DEFINED, NOT ASSIGNED (the #2012 review): an HTTP/2 request's
        // `socket` is a getter with no setter, and an assignment throws in
        // strict mode; an own property shadows it for this request alone.
        const view = ForwardedClientCertificate.viewOf(real, path, why);
        Object.defineProperty(req, 'socket', { value: view,
                                               configurable: true,
                                               writable: true });
        Object.defineProperty(req, 'connection', { value: view,
                                                   configurable: true,
                                                   writable: true });
        req.forwardedClientCertificate = { presented: path.length > 0,
                                           why: why };
        next();
      };
      if (!parsed.leaf) {
        if (parsed.problem) {
          log.info(codes.tag('STS-TLS-0073') + 'forwarded_client_' +
                   'certificate: the trusted proxy forwarded no usable ' +
                   'client certificate: ' + parsed.problem + '.');
        }
        finish([], parsed.problem || '');
        return;
      }
      self.verify(parsed, real).then(function (verdict: Json) {
        if (!verdict.ok) {
          log.info(codes.tag('STS-TLS-0073') + 'forwarded_client_' +
                   'certificate: the client certificate the trusted proxy ' +
                   'forwarded was not accepted: ' + verdict.why + '.');
          finish([], String(verdict.why));
          return;
        }
        finish(verdict.path, '');
      }, function (e: Json) {
        log.debug("Caught in forwardedClientCertificate(): " +
                  ((e && e.message) || e));
        finish([], 'the forwarded certificate could not be verified');
      });
    };
  }
}

config.addWriteRule(ForwardedClientCertificate.writeRule);

const slot = new InstanceSlot<ForwardedClientCertificate>(
  'common/forwarded_client_certificate',
  () => new ForwardedClientCertificate(
    ForwardedClientCertificate.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * RFC 9440's forwarded client certificate, from a named proxy only (#2012).
 * A library (rule 3).
 * @namespace
 */
export = {
  ForwardedClientCertificate: ForwardedClientCertificate,
  parse: ForwardedClientCertificate.parse,
  byteSequence: ForwardedClientCertificate.byteSequence,
  pinOf: ForwardedClientCertificate.pinOf,
  writeRule: ForwardedClientCertificate.writeRule,
  viewOf: ForwardedClientCertificate.viewOf,
  installInstance: (instance: ForwardedClientCertificate): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  configured: slot.forward('configured'),
  fromTrustedProxy: slot.forward('fromTrustedProxy'),
  verify: slot.forward('verify'),
  middleware: slot.forward('middleware')
};
