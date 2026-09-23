'use strict';
//
// File: common/outbound_tls.ts
//
// ===========================================================================
// THE TRANSPORT POLICY OF EVERY OUTBOUND REQUEST THIS SERVICE MAKES TO AN
// ADDRESS SOMEBODY ELSE ANSWERS (#171, 2026-09-23): may it be plain http, and
// is the certificate of whoever answers verified.
//
// Four families send something across the network, each to an address a
// caller registered or an administrator configured: GNAP's push interaction
// finish (`gnap/gnap_http.ts`), SSF push delivery (`ssf/ssf_http.ts`),
// federation's back channels and the fetches that borrow its policy
// (`federation/federation_http.ts`), and the XACML PEP nudge
// (`xacml/xacml_pep_http.ts`). Each had ONE boolean — `…AllowInsecure` — that
// allowed plain http AND turned certificate verification off for every https
// request it covered, and product mode honoured it: with
// `gnap.pushAllowInsecure` on, a push to a registered `https://` finish URI
// went to whoever answered the TLS handshake. What travels is an interaction
// reference, a Security Event Token beside the receiver's own
// `authorization_header`, a client secret and an authorization code, and a
// "repository changed" nudge.
//
// **EACH SWITCH IS NOW THREE SETTINGS, AND NONE OF THEM IS THE OLD ONE.**
//
//   * `<family>…AllowHttp` — plain http. Development: any host, while it is
//     on. Product: REFUSED (`mode.dialsPlainHttpOutbound()`), except where the
//     family's own specification names loopback — GNAP only, RFC 9635 section
//     2.5.2.1, the rule `STS-GNAP-0103` already applied at grant time.
//   * `<family>…SkipTlsVerification` — certificate verification off.
//     DEVELOPMENT ONLY (`mode.skipsOutboundTlsVerification()`): honoured there
//     with a warning on every request; in product it is IGNORED, logged ONCE
//     per setting per process with the family's code, and refused on write
//     (`common/config.js`, the `onlyWhile` marker, STS-CORE-0103). RFC 9635
//     section 11.1, RFC 8935 and BCP 195 (RFC 9325) all require the peer to
//     be authenticated, and none of them admits an unverified one.
//   * `<family>…CaFile` — a PEM file of CA certificates the peer may chain to,
//     BESIDE node's own store (`tls.rootCertificates`), which is what product
//     uses to reach a private CA with verification ON. A file that cannot be
//     read, or holds no certificate, REFUSES the request (STS-CORE-0104)
//     rather than falling back to node's store: the operator named a trust
//     anchor, and a request made without it would fail later with a
//     certificate error that names neither the file nor the setting.
//
// **THE OLD KEYS ARE GONE, WITH NO SHIM**: `common/config.js`'s
// `REPLACED_SETTINGS` refuses to start while an appconfig file or the
// environment still names one, and says what replaced it.
//
// ---------------------------------------------------------------------------
// WHY ONE MODULE, AND WHY HERE.
//
// Four copies of this decision were four places for "is the certificate
// checked" to be answered differently — `saml/sp_metadata.ts` already had one
// that applied the old switch to the scheme and not to the certificate, the
// opposite half from its neighbour. rcbj's rule is that crypto, PKI and TLS
// code lives in a shared module rather than a feature-local helper, so the
// policy is here in `common/`, where no protocol family owns it; each family
// keeps its own settings, its own codes and its own sentences, and hands them
// in as an `OutboundFamily`. `federation/federation_http.ts` would have been
// the other candidate — it already takes `opts.ca` — but GNAP, SSF and XACML
// requiring the FEDERATION module for their transport would have been a
// dependency pointing across three directories for no reason but proximity.
//
// **NO CACHE OF THE CA FILE.** It is read on every request that uses it. A
// TLS handshake costs orders of magnitude more than reading a few kilobytes,
// and a file replaced on disk is then in force for the very next request with
// nothing to invalidate — which is the property an operator rotating a CA
// wants, and the one a memoised copy would take away.
//
// **"LOGGED ONCE" IS PER PROCESS AND PER SETTING**: a set of at most five
// names (the four families' and the kubelet's), so it is bounded by
// construction and is not a cache in `common/cache_registry.js`'s sense.
//
// A LIBRARY (rule 3), and a UTILITY CLASS OF STATIC METHODS (`common/html.ts`'s
// shape): it holds no state worth an instance and registers nothing. It
// requires `helpers`, `config`, `mode` and `error_codes`, all libraries every
// caller has already loaded, and node's own `fs` and `tls`, so it cannot close
// a cycle.
// ===========================================================================

import fs = require('fs');
import tls = require('tls');
import helpers = require('./helpers');
import config = require('./config');
import mode = require('./mode');
import errorCodes = require('./error_codes');

// What a family hands in: its three settings, what it calls the request in a
// sentence, whether product admits plain http to loopback, and its two codes.
interface OutboundFamily {
  what: string;
  allowHttpKey: string;
  skipTlsKey: string;
  caFileKey: string;
  loopbackHttpInProduct: boolean;
  httpRefusedCode: string;
  skipIgnoredCode: string;
}

// The answer about plain http. `errorCode` is set only for the product-mode
// refusal; a refusal because the setting is off is the family's own URL
// refusal and carries the family's existing code.
interface HttpVerdict {
  ok: boolean;
  why: string;
  errorCode: string;
}

// The answer about TLS: the options to hand node, or why the request is not
// to be made.
interface TlsVerdict {
  ok: boolean;
  why: string;
  errorCode: string;
  rejectUnauthorized: boolean;
  ca?: string[];
  skipped: boolean;
}

// The code a refused write of a development-only setting carries; it is
// raised in `common/config.js`, beside the marker.
const CA_FILE_CODE = 'STS-CORE-0104';

const CERTIFICATE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

class OutboundTls {
  static readonly CA_FILE_CODE = CA_FILE_CODE;

  // Settings whose ignored value has already been logged in this process.
  private static readonly announced = new Set<string>();

  // localhost, 127.0.0.0/8 and ::1 — the addresses a request to which does
  // not leave this host.
  static isLoopbackHost(hostname: unknown): boolean {
    helpers.log.debug("Entering OutboundTls.isLoopbackHost().");
    const host = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
    const loopback = host === 'localhost' || host === '::1' ||
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
    helpers.log.debug("Leaving OutboundTls.isLoopbackHost(). " + loopback);
    return loopback;
  }

  // -------------------------------------------------------------------------
  // MAY THIS http:// URL BE DIALLED? Asked only for a URL whose scheme is
  // http; https never reaches it.
  // -------------------------------------------------------------------------
  static httpVerdict(family: OutboundFamily, hostname: unknown): HttpVerdict {
    const log = helpers.log;
    log.debug("Entering OutboundTls.httpVerdict(). " + family.allowHttpKey);
    if (!config.value(family.allowHttpKey)) {
      log.debug("Leaving OutboundTls.httpVerdict(). The setting is off.");
      return { ok: false, errorCode: '',
               why: 'it is an http:// URL and ' + family.allowHttpKey +
                    ' is off' };
    }
    if (mode.dialsPlainHttpOutbound()) {
      log.debug("Leaving OutboundTls.httpVerdict(). Development.");
      return { ok: true, why: '', errorCode: '' };
    }
    if (family.loopbackHttpInProduct && OutboundTls.isLoopbackHost(hostname)) {
      log.debug("Leaving OutboundTls.httpVerdict(). Loopback, allowed.");
      return { ok: true, why: '', errorCode: '' };
    }
    log.debug("Leaving OutboundTls.httpVerdict(). Refused in product.");
    return { ok: false, errorCode: family.httpRefusedCode,
             why: 'it is an http:// URL, and this realm is in product mode ' +
                  '(global.mode=product), where ' + family.what + ' goes ' +
                  'over https' + (family.loopbackHttpInProduct
                    ? ' unless it is to a loopback address'
                    : ' only') + ' whatever ' + family.allowHttpKey +
                  ' says' };
  }

  // -------------------------------------------------------------------------
  // IS CERTIFICATE VERIFICATION TO BE SKIPPED? True only when the setting is
  // on AND the mode allows it. In product a setting that is on is ignored and
  // said ONCE, with the code the caller names. Exported separately from
  // `tlsVerdict()` for SPIRE's kubelet, whose setting is not a family's.
  // -------------------------------------------------------------------------
  static skipsVerification(settingKey: string, ignoredCode: string,
                           what: string): boolean {
    const log = helpers.log;
    log.debug("Entering OutboundTls.skipsVerification(). " + settingKey);
    if (!config.value(settingKey)) {
      log.debug("Leaving OutboundTls.skipsVerification(). Off.");
      return false;
    }
    if (mode.skipsOutboundTlsVerification()) {
      log.debug("Leaving OutboundTls.skipsVerification(). Development: yes.");
      return true;
    }
    if (!OutboundTls.announced.has(settingKey)) {
      OutboundTls.announced.add(settingKey);
      log.warn(errorCodes.tag(ignoredCode) + 'outbound: ' + settingKey +
               ' is on and is IGNORED, because this realm is in product ' +
               'mode (global.mode=product): ' + what + ' verifies the ' +
               'certificate of whoever answers. Name a private CA in the ' +
               'family\'s CA file setting instead. Said once per process.');
    }
    log.debug("Leaving OutboundTls.skipsVerification(). Product: ignored.");
    return false;
  }

  // -------------------------------------------------------------------------
  // THE TLS OPTIONS FOR ONE REQUEST to `origin` (for the log line). Never
  // throws; a CA file that cannot be used is `ok: false` with a sentence.
  // -------------------------------------------------------------------------
  static tlsVerdict(family: OutboundFamily, origin: string): TlsVerdict {
    const log = helpers.log;
    log.debug("Entering OutboundTls.tlsVerdict(). " + origin);
    if (OutboundTls.skipsVerification(family.skipTlsKey,
                                      family.skipIgnoredCode, family.what)) {
      // Every such request, not only the setting: a check disabled six
      // months ago and forgotten is the worst kind of leftover.
      log.warn('outbound: ' + family.what + ' to ' + origin + ' is sent ' +
               'WITHOUT verifying the certificate of whoever answers, ' +
               'because ' + family.skipTlsKey + ' is on (development mode ' +
               'only).');
      log.debug("Leaving OutboundTls.tlsVerdict(). Skipped.");
      return { ok: true, why: '', errorCode: '', rejectUnauthorized: false,
               skipped: true };
    }
    const file = String(config.value(family.caFileKey) || '');
    if (!file) {
      log.debug("Leaving OutboundTls.tlsVerdict(). Node's store.");
      return { ok: true, why: '', errorCode: '', rejectUnauthorized: true,
               skipped: false };
    }
    const pems = OutboundTls.caFilePems(file);
    if (typeof pems === 'string') {
      log.warn(errorCodes.tag(CA_FILE_CODE) + 'outbound: ' + family.what +
               ' to ' + origin + ' was not sent: ' + pems);
      log.debug("Leaving OutboundTls.tlsVerdict(). The CA file is unusable.");
      return { ok: false, errorCode: CA_FILE_CODE, rejectUnauthorized: true,
               skipped: false,
               why: family.caFileKey + ' names "' + file + '", and ' + pems };
    }
    log.debug("Leaving OutboundTls.tlsVerdict(). " + pems.length +
              " CA certificate(s) beside node's store.");
    return { ok: true, why: '', errorCode: '', rejectUnauthorized: true,
             ca: tls.rootCertificates.concat(pems), skipped: false };
  }

  // The certificates in a PEM file, or a sentence saying why there are none.
  static caFilePems(file: string): string[] | string {
    const log = helpers.log;
    log.debug("Entering OutboundTls.caFilePems(). " + file);
    let text = '';
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (e) {
      log.debug("Caught in OutboundTls.caFilePems(): " +
                ((e && e.message) || e));
      log.debug("Leaving OutboundTls.caFilePems(). Unreadable.");
      return 'it could not be read (' + ((e && e.code) || e.message) + ')';
    }
    const pems = text.match(CERTIFICATE) || [];
    if (!pems.length) {
      log.debug("Leaving OutboundTls.caFilePems(). No certificate.");
      return 'it holds no PEM certificate';
    }
    log.debug("Leaving OutboundTls.caFilePems(). " + pems.length + ".");
    return pems;
  }

  // What the console and `/admin-api` show for a family: the three settings
  // as they are IN FORCE here, which in product is not what is stored.
  static describe(family: OutboundFamily): { allowHttp: boolean;
      skipTlsVerification: boolean; skipTlsVerificationSet: boolean;
      caFile: string } {
    helpers.log.debug("Entering OutboundTls.describe().");
    const set = !!config.value(family.skipTlsKey);
    helpers.log.debug("Leaving OutboundTls.describe().");
    return {
      allowHttp: !!config.value(family.allowHttpKey),
      skipTlsVerificationSet: set,
      skipTlsVerification: set && mode.skipsOutboundTlsVerification(),
      caFile: String(config.value(family.caFileKey) || '')
    };
  }
}

export = OutboundTls;
