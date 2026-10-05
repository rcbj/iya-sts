// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: krb5_pkinit.ts
//
// ===========================================================================
// PKINIT: A CERTIFICATE AS THE KERBEROS PRE-AUTHENTICATION (RFC 4556, RFC
// 8070, RFC 8636, RFC 5349, RFC 8062), FOR THE AS EXCHANGE (#179,
// 2026-10-05).
//
// **WHY THIS EXISTS.** #173 refuses, in product, an AS-REQ that proved only a
// password for a person who holds or owes a second factor, and gave a person
// with an authenticator app a way in (FAST with OTP). A person whose only
// second factor is a SECURITY KEY had none: Kerberos defines no WebAuthn
// pre-authentication. What it defines is PKINIT — the AS-REQ signed with a
// certificate's key, which lives on a smart card or a PIV token behind
// PKCS#11 — and this file is the KDC's half of it.
//
// ---------------------------------------------------------------------------
// WHAT IS IMPLEMENTED, BY SECTION.
//
//   * RFC 4556 section 3.2.1-3.2.2 — the PA-PK-AS-REQ: the signedAuthPack
//     verified (`common/crypto.js` section 16), the client's certificate
//     validated to the service Root THROUGH THIS REALM'S OWN HIERARCHY
//     (`pki.verifyPathToAnchors()`, then the authority that signed the leaf
//     read off the register), its revocation consulted under
//     `pki.revocationCheck` (`revocation_status.localVerdictFor()`), the EKU
//     — id-pkinit-KPClientAuth, or id-ms-kp-sc-logon which the section says
//     a KDC SHOULD also accept — with digitalSignature, the binding to the
//     AS-REQ's client name, the paChecksum, the timestamp and a replay check.
//     Each refusal is the error code and the TYPED-DATA the section names.
//   * Section 3.2.3.1 — the Diffie-Hellman reply: an ephemeral key, a
//     KDCDHKeyInfo signed with the realm's KDC key, and the reply key. **NOT
//     section 3.2.3.2**, public-key encryption of the reply key: refused
//     KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED, because a reply key
//     encrypted to the client's RSA key has no forward secrecy (#179's
//     scope says so). DH keys are never reused (no serverDHNonce).
//   * RFC 5349 — ECDH on P-256, P-384 and P-521 beside MODP groups 14 to 18.
//   * RFC 8070 — the freshness token: sealed under the realm's krbtgt key
//     like FAST's cookie, offered in every KDC_ERR_PREAUTH_REQUIRED that asks
//     for one, REQUIRED by default (`krb5.pkinitRequireFreshness`). It is what
//     stops a signed AuthPack made on a stolen card in advance from being
//     replayed later.
//   * RFC 8636 — KDF agility: the strongest of the client's KDFs, and the
//     OtherInfo that binds the whole AS-REQ and the PA-PK-AS-REP into the
//     reply key. RFC 4556's own derivation, which binds neither, is refused
//     unless `krb5.pkinitLegacyKdf` allows it (KDC_ERR_NO_ACCEPTABLE_KDF);
//     RFC 8636's CMS digest error data is sent with the digest refusal.
//   * RFC 8062 — anonymous PKINIT: `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`
//     with an unsigned AuthPack, a TGT that names nobody, and PA-PKINIT-KX,
//     whose KDC contribution makes the ticket session key KRB-FX-CF2 of it
//     and the reply key. It exists to be FAST ARMOR for a client with no host
//     keytab (`kinit -n`, then `kinit -T`), and `krb5_kdc.js` refuses an
//     anonymous TGT anywhere else — a TGS-REQ presenting one is refused.
//   * RFC 8129 — the ticket's authentication indicators: `pkinit` always,
//     and `pkinit-hardware` beside it when the certificate is MARKED as a
//     hardware-bound key (below). The KDC sets hw-authent on such a ticket.
//
// ---------------------------------------------------------------------------
// WHICH CERTIFICATES, AND WHOSE (rcbj's answer of 2026-10-05).
//
// A leaf from one of THIS REALM'S identity Issuing CAs — the TLS client
// authority and the three enrollment ones, `tls_client_certificates.js`'s
// IDENTITY_USE_CASES — with id-pkinit-KPClientAuth or id-ms-kp-sc-logon, and
// bound to the AS-REQ's client in one of RFC 4556 section 3.2.2's two ways:
//
//   1. THE KDC'S OWN BINDING: the certificate is recorded on the person's
//      entry — enrolled over ACME, EST or SCEP, still listed there
//      (`identityOf()` then `stillHeld()`), the person being the client.
//   2. THE CERTIFICATE'S: an id-pkinit-san whose KRB5PrincipalName is exactly
//      the client and this Kerberos realm.
//
// A certificate that carries an id-pkinit-san naming somebody else is refused
// whatever else it says: one certificate naming two people names neither.
// The portal's TLS client certificates are not changed: they carry
// clientAuth alone and are refused KDC_ERR_INCONSISTENT_KEY_PURPOSE here.
//
// **HARDWARE-BOUND** (rcbj's other answer): the KDC cannot see a smart card.
// What it can see is that the certificate is the SMARTCARD-LOGON profile
// (id-ms-kp-sc-logon) and that this service did NOT generate its key (EST's
// /serverkeygen records `keySource: 'server'`). Only then does the ticket
// say `pkinit-hardware`, which `spnego_authn.ts` turns into `hwk`; every
// other PKINIT ticket says `pkinit` and becomes `swk`, as `/tls/sign-in`
// says of a certificate. Neither is a password, so neither is `pwd`.
//
// ---------------------------------------------------------------------------
// POST-QUANTUM. No post-quantum PKINIT is standardised. Where it would go is
// `common/crypto.js` section 16's header: an ML-KEM encapsulation in place of
// `pkinitKeyAgreement()`, through the same RFC 8636 KDF, and ML-DSA for the
// CMS signatures. The KDC certificate's key algorithm is a setting
// (`krb5.pkinitKdcKeyAlgorithm`) so an ML-DSA KDC key is a row away once a
// client can verify one.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS. A LIBRARY (rule 3): it registers nothing. It is built by
// `krb5_person_keys.ts` and handed to `krb5_principals.js` INSIDE the key
// source, beside FAST (`setKeySource({ ..., fast, pkinit })`), so the KDC
// reaches it through `principals.pkinitProvider()` and `krb5_kdc.js` gains
// no require — the parent project's COPY set is what it was. A process
// without the key source has no PKINIT, and PA-PK-AS-REQ is unknown padata
// to it as it always was.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import cryptoLib = require('../common/crypto');
import pki = require('../common/pki');
import realms = require('../common/realms');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');
import claims = require('../cluster/cluster_claims');
import kcrypto = require('./krb5_crypto');
import asn1 = require('./krb5_asn1');
import msgs = require('./krb5_messages');
import principals = require('./krb5_principals');
import codec = require('./krb5_pkinit_codec');

type Json = any;

interface Key {
  etype: number;
  key: Uint8Array;
  kvno?: number | null;
}

// A refusal, in the shape `krb5_kdc.js` hands to errorReply().
interface Refusal {
  ok: false;
  code: number;
  errorCode: string;
  eText: string;
  eData?: Uint8Array | null;
}

interface Krb5PkinitDeps {
  log: typeof helpers.log;
  config: typeof config;
  cryptoLib: Json;
  pki: Json;
  realms: Json;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  claims: Json;
  kcrypto: Json;
  asn1: Json;
  msgs: Json;
  principals: Json;
  codec: typeof codec;
  tlsClientCertificates: () => Json;
  revocationStatus: () => Json;
  nodeName: () => string;
}

// The KDC's key and certificate in this process, per trust realm.
interface KdcCredential {
  privateKeyPem: string;
  certificateDer: Buffer;
  chainDers: Buffer[];
  notAfter: number;
  keyAlg: string;
  serialHex: string;
}

/**
 * The EKUs a PKINIT client certificate may carry for the purpose: RFC 4556's
 * id-pkinit-KPClientAuth and Microsoft's smart-card logon.
 */
const CLIENT_EKUS = ['1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'];
const SMARTCARD_LOGON_EKU = '1.3.6.1.4.1.311.20.2.2';

// The Issuing CAs whose leaves are identities (tls_client_certificates.js's
// IDENTITY_USE_CASES), read from there so the two lists cannot disagree.
const FALLBACK_IDENTITY_CAS = ['tls-client', 'acme', 'est', 'scep'];

/** The indicator every PKINIT ticket carries. */
const PKINIT_INDICATOR = 'pkinit';
/** The indicator beside it for a certificate marked hardware-bound. */
const HARDWARE_INDICATOR = 'pkinit-hardware';

// RFC 8062's anonymous principal and realm.
const ANONYMOUS_REALM = 'WELLKNOWN:ANONYMOUS';
const ANONYMOUS_NAME = ['WELLKNOWN', 'ANONYMOUS'];

// The magic in front of a freshness token this KDC sealed, and the private
// key usage it is sealed under (MIT's FAST cookie is 513; 514 is unused).
const FRESHNESS_MAGIC = 'STSP';
const KEY_USAGE_FRESHNESS = 514;

// The claim scope a signed AuthPack is spent under.
const REPLAY_SCOPE = 'krb5.pkinit-authpack';

// How long before its certificate expires a KDC key is replaced.
const KDC_RENEW_MARGIN_MS = 24 * 60 * 60 * 1000;

/**
 * PKINIT for the KDC's AS exchange: the request checked, the client's
 * certificate validated and bound, the Diffie-Hellman reply signed and the
 * reply key derived. Reached by the KDC through the key source; it
 * registers nothing.
 */
class Krb5Pkinit {
  /** The indicator every PKINIT ticket carries, `pkinit`. */
  static readonly PKINIT_INDICATOR = PKINIT_INDICATOR;
  /** The indicator for a certificate marked hardware-bound. */
  static readonly HARDWARE_INDICATOR = HARDWARE_INDICATOR;
  /** The claim scope a signed AuthPack is spent under. */
  static readonly REPLAY_SCOPE = REPLAY_SCOPE;

  // The KDC credential per trust realm, and the issuance in flight for one,
  // so two requests at once make one key.
  private readonly kdcCredentials = new Map<string, KdcCredential>();
  private readonly kdcIssuing = new Map<string, Promise<Json>>();

  /**
   * Builds the PKINIT handler over the given dependencies.
   *
   * @param deps - the modules it uses
   */
  constructor(private readonly deps: Krb5PkinitDeps) {
    deps.log.debug('Entering Krb5Pkinit.constructor().');
    deps.log.debug('Leaving Krb5Pkinit.constructor().');
  }

  /**
   * Returns the dependencies the key source builds this with, from the real
   * modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): Krb5PkinitDeps {
    helpers.log.debug('Entering Krb5Pkinit.defaultDeps().');
    helpers.log.debug('Leaving Krb5Pkinit.defaultDeps().');
    return {
      log: helpers.log,
      config: config,
      cryptoLib: cryptoLib,
      pki: pki,
      realms: realms,
      mode: mode,
      errorCodes: errorCodes,
      claims: claims,
      kcrypto: kcrypto,
      asn1: asn1,
      msgs: msgs,
      principals: principals,
      codec: codec,
      // LAZILY: both are reached from `common/app.js`'s chain and this file
      // is built inside the key source, whose order is not theirs.
      tlsClientCertificates: function () {
        return require('../common/tls_client_certificates');
      },
      revocationStatus: function () {
        return require('../common/revocation_status');
      },
      nodeName: function () {
        try {
          return String(require('../cluster/cluster').nodeName() || '');
        } catch (e) {
          helpers.log.debug('Caught in nodeName(): ' +
                            ((e && e.message) || e));
          return '';
        }
      }
    };
  }

  // -------------------------------------------------------------------------
  // SMALL THINGS.
  // -------------------------------------------------------------------------
  private refuse(code: number, errorCode: string, eText: string,
                 eData?: Uint8Array | null): Refusal {
    const { log } = this.deps;
    log.debug('Entering Krb5Pkinit.refuse(). ' + errorCode);
    log.info('krb5-pkinit: refusing with ' + code + ' (' + errorCode + '): ' +
             eText);
    log.debug('Leaving Krb5Pkinit.refuse().');
    return { ok: false, code: code, errorCode: errorCode, eText: eText,
             eData: eData || null };
  }

  private now(): Date {
    const { log, mode } = this.deps;
    log.debug('Entering Krb5Pkinit.now().');
    log.debug('Leaving Krb5Pkinit.now().');
    return new Date(Date.now() +
                    (Number(mode.valueInForce('krb5.clockOffset')) || 0) *
                    1000);
  }

  private skewMs(): number {
    const { log, config } = this.deps;
    log.debug('Entering Krb5Pkinit.skewMs().');
    log.debug('Leaving Krb5Pkinit.skewMs().');
    return Number(config.value('krb5.clockSkew') || 300) * 1000;
  }

  /**
   * Says whether PKINIT is on in the ambient trust realm (`krb5.pkinit`).
   *
   * @returns whether it is
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug('Entering Krb5Pkinit.enabled().');
    const on = config.value('krb5.pkinit') !== false;
    log.debug('Leaving Krb5Pkinit.enabled(). ' + on);
    return on;
  }

  /**
   * Says whether anonymous PKINIT (RFC 8062) is on in the ambient realm
   * (`krb5.anonymousPkinit`), PKINIT being on.
   *
   * @returns whether it is
   */
  anonymousEnabled(): boolean {
    const { log, config } = this.deps;
    log.debug('Entering Krb5Pkinit.anonymousEnabled().');
    const on = this.enabled() && config.value('krb5.anonymousPkinit') !==
      false;
    log.debug('Leaving Krb5Pkinit.anonymousEnabled(). ' + on);
    return on;
  }

  /**
   * Says whether a principal name is RFC 8062's anonymous principal.
   *
   * @param cname - a PrincipalName
   * @returns whether it is WELLKNOWN/ANONYMOUS
   */
  static isAnonymous(cname: Json): boolean {
    helpers.log.debug('Entering Krb5Pkinit.isAnonymous().');
    const name = (cname && cname.name) || [];
    helpers.log.debug('Leaving Krb5Pkinit.isAnonymous().');
    return name.length === 2 && name[0] === ANONYMOUS_NAME[0] &&
           name[1] === ANONYMOUS_NAME[1];
  }

  /**
   * The anonymous realm, `WELLKNOWN:ANONYMOUS`.
   */
  static readonly ANONYMOUS_REALM = ANONYMOUS_REALM;

  // The krbtgt key a freshness token is sealed under — the realm's, at its
  // first enctype, a previous version still kept when one is asked for
  // (#169), as `Krb5Fast.tgsKey()` reads it.
  private async tgsKey(realm: string, kvno?: number | null):
      Promise<Key | null> {
    const { log, principals } = this.deps;
    log.debug('Entering Krb5Pkinit.tgsKey(). ' + realm);
    const krbtgt = principals.find(['krbtgt', realm], realm);
    const etypes = krbtgt ? principals.supportedEtypes(krbtgt) : [];
    if (!krbtgt || !etypes.length) {
      log.debug('Leaving Krb5Pkinit.tgsKey(). None.');
      return null;
    }
    if (kvno !== undefined && kvno !== null && krbtgt.directoryKeys &&
        Number(kvno) !== Number(krbtgt.kvno)) {
      const kept = principals.retainedKeyFor(krbtgt, etypes[0], Number(kvno));
      log.debug('Leaving Krb5Pkinit.tgsKey(). ' + (kept ? 'Kept.' : 'Gone.'));
      return kept ? { etype: etypes[0], key: kept.key, kvno: kept.kvno }
                  : null;
    }
    const key = await principals.longTermKey(krbtgt, etypes[0]);
    log.debug('Leaving Krb5Pkinit.tgsKey().');
    return { etype: etypes[0], key: key,
             kvno: krbtgt.directoryKeys ? Number(krbtgt.kvno) : null };
  }

  // -------------------------------------------------------------------------
  // RFC 8070'S FRESHNESS TOKEN. "Implementation-specific" (section 2.4): the
  // realm and the KDC's time, sealed under the realm's krbtgt key, so any
  // node of the cluster that holds the key checks one any other issued, and
  // a client can neither make nor alter one. Valid for the clock skew — the
  // window a PKAuthenticator's own timestamp is held to.
  // -------------------------------------------------------------------------
  /**
   * Seals a freshness token for a realm.
   *
   * @param realm - the Kerberos realm
   * @returns a promise of the token, or null without a krbtgt key
   */
  async freshnessToken(realm: string): Promise<Uint8Array | null> {
    const { log, kcrypto, msgs } = this.deps;
    log.debug('Entering Krb5Pkinit.freshnessToken().');
    const key = await this.tgsKey(realm);
    if (!key) {
      log.debug('Leaving Krb5Pkinit.freshnessToken(). No krbtgt key.');
      return null;
    }
    const body = Buffer.from(JSON.stringify({ v: 1, r: realm,
                                              t: this.now().getTime() }),
                             'utf8');
    const cipher = await kcrypto.etypeById(key.etype).encrypt(
      key.key, KEY_USAGE_FRESHNESS, body);
    log.debug('Leaving Krb5Pkinit.freshnessToken().');
    return new Uint8Array(Buffer.concat([
      Buffer.from(FRESHNESS_MAGIC, 'latin1'),
      Buffer.from(msgs.encEncryptedData({
        etype: key.etype, kvno: key.kvno === undefined ? null : key.kvno,
        cipher: cipher }))]));
  }

  // Whether a token a PKAuthenticator carries is one this realm sealed inside
  // the window. Answers `fresh`, `stale` (ours, expired) or `bad`.
  private async tokenState(token: Uint8Array, realm: string): Promise<string> {
    const { log, kcrypto, msgs, asn1 } = this.deps;
    log.debug('Entering Krb5Pkinit.tokenState().');
    const bytes = Buffer.from(token || []);
    if (bytes.length < 5 ||
        bytes.subarray(0, 4).toString('latin1') !== FRESHNESS_MAGIC) {
      log.debug('Leaving Krb5Pkinit.tokenState(). Not ours.');
      return 'bad';
    }
    let body;
    try {
      const sealed = msgs.readEncryptedData(asn1.readTlv(
        new Uint8Array(bytes.subarray(4)), 0));
      const key = await this.tgsKey(realm, sealed.kvno);
      if (!key) {
        log.debug('Leaving Krb5Pkinit.tokenState(). Key gone.');
        return 'stale';
      }
      body = JSON.parse(Buffer.from(await kcrypto.etypeById(sealed.etype)
        .decrypt(key.key, KEY_USAGE_FRESHNESS, sealed.cipher))
        .toString('utf8'));
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.tokenState(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Pkinit.tokenState(). Does not open.');
      return 'bad';
    }
    if (!body || body.v !== 1 || body.r !== realm) {
      log.debug('Leaving Krb5Pkinit.tokenState(). Another realm\'s.');
      return 'bad';
    }
    const age = this.now().getTime() - Number(body.t);
    log.debug('Leaving Krb5Pkinit.tokenState(). age=' + age);
    return age >= -this.skewMs() && age <= this.skewMs() ? 'fresh' : 'stale';
  }

  // A METHOD-DATA carrying a fresh token, RFC 8070 section 2.4's e-data for
  // both of its refusals.
  private async freshnessMethodData(realm: string): Promise<Uint8Array | null> {
    const { log, asn1, msgs } = this.deps;
    log.debug('Entering Krb5Pkinit.freshnessMethodData().');
    const token = await this.freshnessToken(realm);
    log.debug('Leaving Krb5Pkinit.freshnessMethodData().');
    return token ? asn1.encSequenceOf([msgs.encPaData({
      type: codec.PA.AS_FRESHNESS, value: token })]) : null;
  }

  // -------------------------------------------------------------------------
  // WHAT A KDC_ERR_PREAUTH_REQUIRED OFFERS: PA-PK-AS-REQ, empty (RFC 4556
  // section 3.4); PA-PKINIT-KX, empty, where anonymous PKINIT is on (RFC 8062
  // section 4.1.1's MUST); and PA-AS-FRESHNESS with a token when the request
  // asked for one or the realm requires one (RFC 8070 section 2.2).
  // -------------------------------------------------------------------------
  /**
   * Returns what a KDC_ERR_PREAUTH_REQUIRED offers for PKINIT.
   *
   * @param request - the AS-REQ (the inner one under FAST)
   * @param realm - the Kerberos realm answering
   * @returns a promise of the PA-DATA
   */
  async offers(request: Json, realm: string): Promise<Json[]> {
    const { log, config } = this.deps;
    log.debug('Entering Krb5Pkinit.offers().');
    if (!this.enabled()) {
      log.debug('Leaving Krb5Pkinit.offers(). Off.');
      return [];
    }
    const out: Json[] = [{ type: codec.PA.PK_AS_REQ,
                           value: new Uint8Array(0) }];
    if (this.anonymousEnabled()) {
      out.push({ type: codec.PA.PKINIT_KX, value: new Uint8Array(0) });
    }
    const asked = ((request && request.padata) || []).some(function (pa: Json) {
      return pa.type === codec.PA.AS_FRESHNESS;
    });
    if (asked || config.value('krb5.pkinitRequireFreshness') !== false) {
      const token = await this.freshnessToken(realm);
      if (token) {
        out.push({ type: codec.PA.AS_FRESHNESS, value: token });
      }
    }
    log.debug('Leaving Krb5Pkinit.offers(). ' + out.length + '.');
    return out;
  }

  // -------------------------------------------------------------------------
  // THE KDC'S OWN KEY AND CERTIFICATE, per realm, in this process. Issued on
  // first use from the realm's `kdc` Issuing CA (`pki.issueKdcKeyPair()`),
  // replaced a day before it expires, and held nowhere but here.
  // -------------------------------------------------------------------------
  private slot(): string {
    const { log } = this.deps;
    log.debug('Entering Krb5Pkinit.slot().');
    let thread = 0;
    try {
      thread = Number(require('worker_threads').threadId) || 0;
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.slot(): ' + ((e && e.message) || e));
      thread = 0;
    }
    log.debug('Leaving Krb5Pkinit.slot().');
    return 'kdc:' + (this.deps.nodeName() || require('os').hostname()) +
           ':' + process.pid + ':' + thread;
  }

  /**
   * Returns this realm's KDC credential in this process, issuing one when
   * there is none or it is about to expire.
   *
   * @param realm - the Kerberos realm the certificate names
   * @returns a promise of `{ ok: true, credential }` or `{ ok: false, why }`
   */
  async kdcCredential(realm: string): Promise<Json> {
    const { log, realms, pki, config, codec } = this.deps;
    log.debug('Entering Krb5Pkinit.kdcCredential(). ' + realm);
    const realmId = String(realms.currentId() || '');
    const held = this.kdcCredentials.get(realmId);
    if (held && held.notAfter - KDC_RENEW_MARGIN_MS > Date.now()) {
      log.debug('Leaving Krb5Pkinit.kdcCredential(). Held.');
      return { ok: true, credential: held };
    }
    let pending = this.kdcIssuing.get(realmId);
    if (!pending) {
      const self = this;
      const nameDer = codec.encKrb5PrincipalName(realm,
        { type: 2, name: ['krbtgt', realm] });
      pending = Promise.resolve(pki.issueKdcKeyPair(realmId, {
        slot: self.slot(),
        principalNameDer: nameDer,
        commonName: 'krbtgt/' + realm,
        keyAlg: String(config.value('krb5.pkinitKdcKeyAlgorithm') ||
                       pki.DEFAULT_KDC_KEY_ALG)
      })).then(function (result: Json) {
        self.kdcIssuing.delete(realmId);
        if (!result || !result.ok) {
          return { ok: false, why: ((result && result.errors) || [])
                                     .join(' ') || 'no answer' };
        }
        const issued = result.issued;
        const der = function (pem: string) {
          return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
                                        .replace(/\s+/g, ''), 'base64');
        };
        // RFC 4556 section 3.2.3.1 item 6: "The certificates field MUST NOT
        // contain root CA certificates" — `issueKdcKeyPair()` leaves it out.
        const chain = (issued.chainWithoutRootPem || []).map(der);
        const credential: KdcCredential = {
          privateKeyPem: issued.privateKeyPem,
          certificateDer: der(issued.certificatePem),
          chainDers: chain,
          notAfter: new Date(issued.notAfter).getTime(),
          keyAlg: String(issued.keyAlg || ''),
          serialHex: String(issued.serialHex || '')
        };
        self.kdcCredentials.set(realmId, credential);
        return { ok: true, credential: credential };
      }, function (e: Json) {
        self.kdcIssuing.delete(realmId);
        log.debug('Caught in Krb5Pkinit.kdcCredential(): ' +
                  ((e && e.message) || e));
        return { ok: false, why: (e && e.message) || String(e) };
      });
      this.kdcIssuing.set(realmId, pending);
    }
    const answer = await pending;
    log.debug('Leaving Krb5Pkinit.kdcCredential(). ' + answer.ok);
    return answer;
  }

  // -------------------------------------------------------------------------
  // THE CLIENT'S CERTIFICATE (RFC 4556 section 3.2.2): validated, its
  // authority read, revocation consulted, its EKU, and its binding to the
  // client. Answers `{ ok: true, leaf, chain, hardware, notAfter, path }`
  // or a refusal.
  // -------------------------------------------------------------------------
  private async checkCertificate(signed: Json, cname: Json, realm: string):
      Promise<Json> {
    const { log, cryptoLib, pki, realms, codec } = this.deps;
    log.debug('Entering Krb5Pkinit.checkCertificate().');
    const signer = signed.signerInfos[0];
    const leaf = signed.certificates.filter(function (one: Buffer) {
      return cryptoLib.pkinitSignerIdentifies(signer.sid, one);
    })[0];
    const realmId = String(realms.currentId() || '');
    const anchorsPem: string[] = pki.trustAnchorsFor(realmId);
    const anchorEpis = this.trustedCertifiers(anchorsPem);
    if (!leaf) {
      log.debug('Leaving Krb5Pkinit.checkCertificate(). No signer cert.');
      return this.refuse(codec.ERROR.CANT_VERIFY_CERTIFICATE, 'STS-KRB-0181',
                         'the signedAuthPack does not carry the signer\'s ' +
                         'certificate', anchorEpis);
    }
    let facts;
    try {
      facts = pki.pkinitCertificateFacts(leaf);
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.checkCertificate(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Pkinit.checkCertificate(). Unreadable.');
      return this.refuse(codec.ERROR.INVALID_CERTIFICATE, 'STS-KRB-0181',
                         'the signer\'s certificate cannot be read');
    }
    if (facts.signatureDigest === 'sha1' || facts.signatureDigest === 'md5' ||
        !facts.signatureDigest) {
      log.debug('Leaving Krb5Pkinit.checkCertificate(). Cert digest.');
      return this.refuse(codec.ERROR.DIGEST_IN_CERT_NOT_ACCEPTED,
                         'STS-KRB-0182', 'the client certificate is signed ' +
                         'with ' + (facts.signatureDigest
                           ? facts.signatureDigest.toUpperCase()
                           : 'an unknown algorithm (' +
                             facts.signatureAlgorithm + ')') +
                         '; this KDC accepts SHA-256, SHA-384 and SHA-512',
                         codec.encTypedData([{
                           type: codec.TD.CERT_DIGEST_ALGORITHMS,
                           value: this.asn1Seq([this.deps.asn1.encContext(0,
                             codec.encSequenceOfRaw(
                               cryptoLib.pkinitDigestAlgorithms()))]) }]));
    }
    const others = signed.certificates.filter(function (one: Buffer) {
      return one !== leaf;
    });
    // THE REALM'S OWN AUTHORITIES as intermediates, beside whatever the
    // client sent: MIT's `kinit -X X509_user_identity=FILE:` sends the leaf
    // alone, and the KDC holds the rest — each identity Issuing CA and the
    // realm's Intermediate (`pki.describeIssuer()`, Root excluded).
    const held: Buffer[] = [];
    this.identityCas().forEach(function (ca: string) {
      const issuer = pki.describeIssuer(realmId, ca);
      ((issuer && issuer.chainPem) || []).forEach(function (pem: string) {
        held.push(Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
                                         .replace(/\s+/g, ''), 'base64'));
      });
    });
    const intermediates = others.concat(held);
    const anchors = anchorsPem.map(function (pem: string) {
      return pki.certificateFromDer(Buffer.from(String(pem)
        .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'));
    }).filter(Boolean);
    const path = await pki.verifyPathToAnchors(leaf, intermediates, anchors,
      { now: this.now().getTime(), skewMs: this.skewMs() });
    if (!path.ok) {
      log.debug('Leaving Krb5Pkinit.checkCertificate(). No path: ' +
                path.check);
      if (path.check === 'signature') {
        return this.refuse(codec.ERROR.INVALID_CERTIFICATE, 'STS-KRB-0183',
                           'a certificate in the request has a signature ' +
                           'that does not verify: ' + path.reason,
                           codec.encTypedData([{
                             type: codec.TD.INVALID_CERTIFICATES,
                             value: codec.encSequenceOfRaw([
                               codec.encExternalPrincipalIdentifier(
                                 this.epiOf(leaf))]) }]));
      }
      return this.refuse(codec.ERROR.CANT_VERIFY_CERTIFICATE, 'STS-KRB-0183',
                         'the client certificate does not validate to this ' +
                         'service\'s Root: ' + path.reason, anchorEpis);
    }
    const chainDers: Buffer[] = path.chain.slice(1).map(function (one: Json) {
      return Buffer.from(one.der);
    });
    // WHICH AUTHORITY SIGNED IT, off the register: one of THIS realm's
    // identity Issuing CAs, or it is not a client here. Every key pair this
    // service issues chains to the same Root, so the path alone says nothing.
    let status: Json = null;
    let walked: Json = null;
    try {
      status = this.deps.revocationStatus();
      walked = status.walk({ leaf: leaf, chain: chainDers });
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.checkCertificate(): ' +
                ((e && e.message) || e));
      walked = null;
    }
    const first = walked && walked.links && walked.links[0];
    const identityCas = this.identityCas();
    if (!first || first.source !== 'register' || !first.authority ||
        String(first.authority.scope) !== realmId ||
        identityCas.indexOf(String(first.authority.ca)) < 0) {
      log.debug('Leaving Krb5Pkinit.checkCertificate(). Not an identity CA.');
      return this.refuse(codec.ERROR.CLIENT_NOT_TRUSTED, 'STS-KRB-0184',
                         'the client certificate was not issued by one of ' +
                         'this realm\'s identity Issuing CAs (' +
                         identityCas.join(', ') + ')' +
                         (first && first.authority
                           ? '; it was signed by the "' + first.authority.ca +
                             '" authority of "' +
                             (first.authority.scope || 'default') + '"'
                           : ''));
    }
    // REVOCATION, under pki.revocationCheck (rule 3ad), from the register:
    // every link of this path is this service's own.
    let verdict: Json = null;
    try {
      verdict = status.localVerdictFor({ leaf: leaf, chain: chainDers,
                                         verified: true });
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.checkCertificate(): ' +
                ((e && e.message) || e));
      verdict = { refused: true, revoked: false,
                  why: 'the revocation status could not be read' };
    }
    if (verdict && verdict.refused) {
      const revoked = verdict.status === 'revoked' || verdict.revoked === true;
      log.debug('Leaving Krb5Pkinit.checkCertificate(). Revocation.');
      return this.refuse(revoked ? codec.ERROR.REVOKED_CERTIFICATE
                                 : codec.ERROR.REVOCATION_STATUS_UNKNOWN,
                         revoked ? 'STS-KRB-0185' : 'STS-KRB-0186',
                         'the client certificate was refused on revocation ' +
                         '(pki.revocationCheck): ' + (verdict.why || ''),
                         codec.encTypedData([{
                           type: codec.TD.INVALID_CERTIFICATES,
                           value: codec.encSequenceOfRaw([
                             codec.encExternalPrincipalIdentifier(
                               this.epiOf(leaf))]) }]));
    }
    // THE PURPOSE: id-pkinit-KPClientAuth or smart-card logon, with
    // digitalSignature (section 3.2.2's MUST beside that EKU).
    const purposed = facts.ekus.some(function (oid: string) {
      return CLIENT_EKUS.indexOf(oid) >= 0;
    });
    if (!purposed || !facts.digitalSignature) {
      log.debug('Leaving Krb5Pkinit.checkCertificate(). Key purpose.');
      return this.refuse(codec.ERROR.INCONSISTENT_KEY_PURPOSE, 'STS-KRB-0187',
                         !purposed
                           ? 'the client certificate carries neither ' +
                             'id-pkinit-KPClientAuth nor smart-card logon ' +
                             'in its extended key usage'
                           : 'the client certificate\'s keyUsage does not ' +
                             'allow digitalSignature');
    }
    const bound = this.binding(leaf, chainDers, facts, cname, realm);
    if (!bound.ok) {
      log.debug('Leaving Krb5Pkinit.checkCertificate(). Not bound.');
      return bound;
    }
    log.debug('Leaving Krb5Pkinit.checkCertificate(). ' + bound.how);
    return { ok: true, leaf: leaf, chain: chainDers, how: bound.how,
             hardware: facts.ekus.indexOf(SMARTCARD_LOGON_EKU) >= 0 &&
                       bound.keySource !== 'server',
             notAfter: facts.notAfter, authority: first.authority,
             path: path.chain };
  }

  // RFC 4556 section 3.2.2's binding. The two ways, in the RFC's order; and
  // an id-pkinit-san naming anybody but the client refuses whatever else.
  private binding(leaf: Buffer, chainDers: Buffer[], facts: Json, cname: Json,
                  realm: string): Json {
    const { log, codec, realms } = this.deps;
    log.debug('Entering Krb5Pkinit.binding().');
    const names = (cname && cname.name) || [];
    const asked = names.join('/') + '@' + realm;
    const sans: string[] = [];
    for (const der of facts.pkinitSans) {
      try {
        const one = codec.readKrb5PrincipalName(new Uint8Array(der));
        sans.push(one.name.name.join('/') + '@' + one.realm);
      } catch (e) {
        log.debug('Caught in Krb5Pkinit.binding(): ' + ((e && e.message) || e));
        sans.push('(an id-pkinit-san that does not decode)');
      }
    }
    const foreign = sans.filter(function (one) {
      return one !== asked;
    });
    if (foreign.length) {
      log.debug('Leaving Krb5Pkinit.binding(). The SAN names another.');
      return this.refuse(codec.ERROR.CLIENT_NAME_MISMATCH, 'STS-KRB-0188',
                         'the client certificate\'s id-pkinit-san names ' +
                         foreign.join(', ') + ', not ' + asked);
    }
    if (names.length !== 1) {
      log.debug('Leaving Krb5Pkinit.binding(). Not a person\'s name.');
      return this.refuse(codec.ERROR.CLIENT_NAME_MISMATCH, 'STS-KRB-0188',
                         'PKINIT binds a certificate to a person, whose ' +
                         'principal has one component; ' + asked +
                         ' has ' + names.length);
    }
    // 1. THE KDC'S OWN BINDING: recorded on the person's entry.
    let identity: Json = null;
    let held = false;
    let keySource = '';
    try {
      const tlsCerts = this.deps.tlsClientCertificates();
      identity = tlsCerts.identityOf({ leaf: leaf, chain: chainDers,
                                       verified: true });
      held = !!(identity && identity.accepted && identity.kind === 'person' &&
                String(identity.realm) === String(realms.currentId() || '') &&
                identity.username === names[0] &&
                tlsCerts.stillHeld(identity));
      if (held && identity.authority && identity.authority.ca !==
          'tls-client') {
        const found = require('../common/cert_enrollment').findEnrolled(
          identity.serialHex, identity.authority.ca);
        keySource = found && found.record
          ? String(found.record.keySource || '') : '';
      }
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.binding(): ' + ((e && e.message) || e));
      held = false;
    }
    if (held) {
      log.debug('Leaving Krb5Pkinit.binding(). On the entry.');
      return { ok: true, how: 'recorded on ' + names[0] + '\'s entry',
               keySource: keySource };
    }
    if (identity && identity.accepted && identity.kind === 'person' &&
        identity.username !== names[0]) {
      log.debug('Leaving Krb5Pkinit.binding(). Another person\'s.');
      return this.refuse(codec.ERROR.CLIENT_NAME_MISMATCH, 'STS-KRB-0188',
                         'the client certificate was issued to ' +
                         identity.username + ', not ' + asked);
    }
    // 2. THE CERTIFICATE'S OWN: an id-pkinit-san that is exactly the client.
    if (sans.length) {
      log.debug('Leaving Krb5Pkinit.binding(). By its id-pkinit-san.');
      return { ok: true, how: 'its id-pkinit-san names ' + asked,
               keySource: '' };
    }
    log.debug('Leaving Krb5Pkinit.binding(). No binding.');
    return this.refuse(codec.ERROR.CLIENT_NAME_MISMATCH, 'STS-KRB-0188',
                       'the client certificate is not recorded on ' +
                       names[0] + '\'s entry and carries no id-pkinit-san ' +
                       'naming ' + asked);
  }

  private identityCas(): string[] {
    const { log } = this.deps;
    log.debug('Entering Krb5Pkinit.identityCas().');
    let list = FALLBACK_IDENTITY_CAS;
    try {
      const declared = this.deps.tlsClientCertificates().IDENTITY_USE_CASES;
      if (Array.isArray(declared) && declared.length) {
        list = declared;
      }
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.identityCas(): ' +
                ((e && e.message) || e));
    }
    log.debug('Leaving Krb5Pkinit.identityCas().');
    return list.slice();
  }

  private asn1Seq(fields: Uint8Array[]): Uint8Array {
    const { log, asn1 } = this.deps;
    log.debug('Entering Krb5Pkinit.asn1Seq().');
    log.debug('Leaving Krb5Pkinit.asn1Seq().');
    return asn1.encSequence(fields);
  }

  // An ExternalPrincipalIdentifier for a certificate: its subject Name and
  // its IssuerAndSerialNumber (RFC 4556 section 3.2.1's REQUIRED pair).
  private epiOf(certDer: Buffer): Json {
    const { log, cryptoLib, asn1 } = this.deps;
    log.debug('Entering Krb5Pkinit.epiOf().');
    const ids = cryptoLib.pkinitCertificateIds(certDer);
    // The subject Name's DER: the field after the validity in the TBS.
    let subjectName: Uint8Array | null = null;
    try {
      const tbs = asn1.readChildren(asn1.readChildren(
        asn1.readTlv(new Uint8Array(certDer), 0).value)[0].value);
      const start = tbs[0].tag === asn1.contextTag(0) ? 1 : 0;
      subjectName = tbs[start + 4].raw;
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.epiOf(): ' + ((e && e.message) || e));
      subjectName = null;
    }
    log.debug('Leaving Krb5Pkinit.epiOf().');
    return {
      subjectName: subjectName,
      issuerAndSerialNumber: asn1.encSequence([new Uint8Array(ids.issuer),
                                               new Uint8Array(ids.serial)])
    };
  }

  // TD-TRUSTED-CERTIFIERS: the anchors this KDC validates a client to, as
  // the TYPED-DATA KDC_ERR_CANT_VERIFY_CERTIFICATE carries.
  private trustedCertifiers(anchorsPem: string[]): Uint8Array {
    const { log, codec } = this.deps;
    log.debug('Entering Krb5Pkinit.trustedCertifiers().');
    const self = this;
    const epis = anchorsPem.map(function (pem) {
      return codec.encExternalPrincipalIdentifier(self.epiOf(
        Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
                               .replace(/\s+/g, ''), 'base64')));
    });
    log.debug('Leaving Krb5Pkinit.trustedCertifiers().');
    return codec.encTypedData([{ type: codec.TD.TRUSTED_CERTIFIERS,
                                 value: codec.encSequenceOfRaw(epis) }]);
  }

  // -------------------------------------------------------------------------
  // THE REQUEST. `opts`:
  //
  //   pa           the PA-PK-AS-REQ
  //   request      the AS-REQ (the INNER one under FAST)
  //   asReqBytes   the AS-REQ as received — the OUTER message under FAST —
  //                which RFC 8636's OtherInfo binds into the reply key
  //   realm        the Kerberos realm answering
  //   etype        the reply key's enctype
  //   anonymous    whether the client is RFC 8062's anonymous principal
  //
  // Answers `{ ok: true, replyKey, kdcPadata, indicators, hardware,
  // notAfter, verifiedCas, sessionKeyFor, method }` or a refusal for
  // `errorReply()`. `sessionKeyFor(etype)` answers the ticket session key and
  // its PA-PKINIT-KX for an anonymous client, and null otherwise.
  // -------------------------------------------------------------------------
  /**
   * Checks a PA-PK-AS-REQ and builds the PKINIT reply: the client's
   * signature and certificate (or none, for anonymous PKINIT), the freshness
   * token, the key agreement, the signed KDCDHKeyInfo and the reply key.
   *
   * @param opts - `pa`, `request`, `asReqBytes`, `realm`, `etype` and
   *   `anonymous`
   * @returns a promise of the outcome, or a refusal
   */
  async checkRequest(opts: Json): Promise<Json> {
    const { log, codec, cryptoLib, config, claims, kcrypto, msgs } = this.deps;
    log.debug('Entering Krb5Pkinit.checkRequest(). anonymous=' +
              !!opts.anonymous);
    const realm = String(opts.realm);
    const body = opts.request.reqBody;
    let pkReq;
    let signed;
    let pack;
    try {
      pkReq = codec.readPaPkAsReq(opts.pa.value);
      signed = cryptoLib.pkinitReadSignedData(pkReq.signedAuthPack);
      if (signed.eContentType !== cryptoLib.PKINIT_OID.authData) {
        // error-code: none — caught below and refused under STS-KRB-0178
        throw new Error('the SignedData holds ' + signed.eContentType +
                        ', not id-pkinit-authData');
      }
      pack = codec.readAuthPack(new Uint8Array(signed.eContent || []));
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.checkRequest(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Pkinit.checkRequest(). Does not decode.');
      return this.refuse(24, 'STS-KRB-0178', 'the PA-PK-AS-REQ does not ' +
                         'decode: ' + ((e && e.message) || e));
    }
    // ANONYMOUS OR SIGNED, and nothing in between (RFC 8062 section 4.1.1:
    // an anonymous AuthPack has no SignerInfo and no certificate).
    const unsigned = !signed.signerInfos.length &&
                     !signed.certificates.length;
    if (opts.anonymous !== unsigned) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). Signed for anonymous, ' +
                'or unsigned for a name.');
      return this.refuse(codec.ERROR.CLIENT_NOT_TRUSTED, 'STS-KRB-0179',
                         opts.anonymous
                           ? 'anonymous PKINIT carries no signature and no ' +
                             'certificate (RFC 8062 section 4.1.1)'
                           : 'the AuthPack is unsigned, which only the ' +
                             'anonymous principal may send');
    }
    // THE paChecksum (section 3.2.1 item 6) over the KDC-REQ-BODY the AuthPack
    // was signed for.
    if (!pack.paChecksum) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). No paChecksum.');
      return this.refuse(codec.ERROR.PA_CHECKSUM_MUST_BE_INCLUDED,
                         'STS-KRB-0180', 'the PKAuthenticator carries no ' +
                         'paChecksum');
    }
    if (!cryptoLib.pkinitPaChecksumMatches(body.raw, pack.paChecksum)) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). paChecksum mismatch.');
      return this.refuse(41, 'STS-KRB-0180', 'the paChecksum is not the ' +
                         'SHA-1 of this request\'s KDC-REQ-BODY');
    }
    // THE TIMESTAMP (section 3.2.2: "the time skew falls within acceptable
    // limits").
    if (Math.abs(this.now().getTime() - pack.ctime.getTime()) >
        this.skewMs()) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). Skew.');
      return this.refuse(37, 'STS-KRB-0189', 'the PKAuthenticator\'s time ' +
                         'is outside the clock tolerance');
    }
    // THE FRESHNESS TOKEN (RFC 8070 section 2.4).
    if (pack.freshnessToken) {
      const state = await this.tokenState(pack.freshnessToken, realm);
      if (state !== 'fresh') {
        log.debug('Leaving Krb5Pkinit.checkRequest(). Token ' + state + '.');
        return this.refuse(codec.ERROR.PREAUTH_EXPIRED, 'STS-KRB-0190',
                           state === 'stale'
                             ? 'the freshness token has expired; use the ' +
                               'new one'
                             : 'the freshness token was not issued by this ' +
                               'realm',
                           await this.freshnessMethodData(realm));
      }
    } else if (config.value('krb5.pkinitRequireFreshness') !== false) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). No token.');
      return this.refuse(24, 'STS-KRB-0190', 'this realm requires an RFC ' +
                         '8070 freshness token in the PKAuthenticator',
                         await this.freshnessMethodData(realm));
    }
    // THE CERTIFICATE, then THE SIGNATURE (section 3.2.2's order).
    let certificate: Json = null;
    if (!opts.anonymous) {
      certificate = await this.checkCertificate(signed, body.cname, realm);
      if (!certificate.ok) {
        log.debug('Leaving Krb5Pkinit.checkRequest(). The certificate.');
        return certificate;
      }
      const verified = cryptoLib.pkinitVerifySignedData(signed,
                                                        certificate.leaf);
      if (!verified.ok) {
        log.debug('Leaving Krb5Pkinit.checkRequest(). The signature.');
        return verified.reason === 'digest'
          ? this.refuse(codec.ERROR.DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,
                        'STS-KRB-0191', verified.why,
                        codec.encTypedData([{
                          type: codec.TD.CMS_DIGEST_ALGORITHMS,
                          value: codec.encSequenceOfRaw(
                            cryptoLib.pkinitDigestAlgorithms()) }]))
          : this.refuse(codec.ERROR.INVALID_SIG, 'STS-KRB-0192',
                        verified.why);
      }
    }
    // THE REPLAY CHECK: the same signed AuthPack twice, across the cluster,
    // for as long as its timestamp could still be inside the tolerance.
    const spent = await claims.claim({
      scope: REPLAY_SCOPE,
      value: cryptoLib.digest('sha256', pkReq.signedAuthPack, 'hex'),
      ttlMs: 2 * this.skewMs() + 60000
    });
    if (!spent.ok && spent.reason === 'used') {
      log.debug('Leaving Krb5Pkinit.checkRequest(). Replayed.');
      return this.refuse(34, 'STS-KRB-0193', 'this signed AuthPack has been ' +
                         'presented before');
    }
    if (!spent.ok) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). No store.');
      return this.refuse(60, 'STS-KRB-0193', 'the AuthPack could not be ' +
                         'proved unused just now; try again');
    }
    // THE KEY AGREEMENT. Diffie-Hellman or nothing (#179's scope).
    if (!pack.clientPublicValue) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). No DH.');
      return this.refuse(codec.ERROR.PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED,
                         'STS-KRB-0194', 'this KDC delivers the reply key ' +
                         'by Diffie-Hellman only; RSA key transport (RFC ' +
                         '4556 section 3.2.3.2) has no forward secrecy and ' +
                         'is not implemented');
    }
    const agreed = cryptoLib.pkinitKeyAgreement(pack.clientPublicValue);
    if (!agreed.ok) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). Key agreement.');
      return this.refuse(codec.ERROR.DH_KEY_PARAMETERS_NOT_ACCEPTED,
                         'STS-KRB-0195', agreed.why,
                         codec.encTypedData([{
                           type: codec.TD.DH_PARAMETERS,
                           value: codec.encSequenceOfRaw(
                             cryptoLib.pkinitDhParameters()) }]));
    }
    // THE KDF (RFC 8636 section 6): the strongest the client offers.
    let kdf: string | null = null;
    if (pack.supportedKdfs) {
      kdf = cryptoLib.PKINIT_KDFS.map(function (one: Json) {
        return one.oid;
      }).filter(function (oid: string) {
        return pack.supportedKdfs.indexOf(oid) >= 0;
      })[0] || null;
      if (!kdf) {
        log.debug('Leaving Krb5Pkinit.checkRequest(). No common KDF.');
        return this.refuse(codec.ERROR.NO_ACCEPTABLE_KDF, 'STS-KRB-0196',
                           'none of the client\'s KDFs is one of RFC ' +
                           '8636\'s (SHA-1, SHA-256, SHA-384, SHA-512)');
      }
    } else if (config.value('krb5.pkinitLegacyKdf') !== true) {
      log.debug('Leaving Krb5Pkinit.checkRequest(). Legacy KDF refused.');
      return this.refuse(codec.ERROR.NO_ACCEPTABLE_KDF, 'STS-KRB-0196',
                         'the AuthPack offers no RFC 8636 KDF, and RFC ' +
                         '4556\'s own derivation binds neither the request ' +
                         'nor the reply into the key; this realm refuses it ' +
                         '(krb5.pkinitLegacyKdf)');
    }
    // THE SIGNED REPLY.
    const kdc = await this.kdcCredential(realm);
    if (!kdc.ok) {
      log.error(this.deps.errorCodes.tag('STS-KRB-0197') +
                'krb5-pkinit: no KDC certificate for ' + realm + ': ' +
                kdc.why);
      log.debug('Leaving Krb5Pkinit.checkRequest(). No KDC certificate.');
      return this.refuse(codec.ERROR.CLIENT_NOT_TRUSTED, 'STS-KRB-0197',
                         'this KDC holds no PKINIT certificate just now');
    }
    let dhSignedData;
    try {
      dhSignedData = cryptoLib.pkinitSignedData({
        contentType: cryptoLib.PKINIT_OID.dhKeyData,
        content: codec.encKdcDhKeyInfo({
          subjectPublicKey: agreed.kdcPublicValue, nonce: pack.nonce }),
        signerCertDer: kdc.credential.certificateDer,
        chainDers: kdc.credential.chainDers,
        privateKey: kdc.credential.privateKeyPem
      });
    } catch (e) {
      log.debug('Caught in Krb5Pkinit.checkRequest(): ' +
                ((e && e.message) || e));
      log.error(this.deps.errorCodes.tag('STS-KRB-0197') +
                'krb5-pkinit: signing the KDCDHKeyInfo failed: ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Pkinit.checkRequest(). Signing failed.');
      return this.refuse(codec.ERROR.CLIENT_NOT_TRUSTED, 'STS-KRB-0197',
                         'this KDC could not sign its PKINIT reply');
    }
    const pkAsRep = codec.encPaPkAsRep({ dhSignedData: dhSignedData,
                                         kdf: kdf });
    // THE REPLY KEY.
    let replyKey: Key;
    if (kdf) {
      const otherInfo = codec.encOtherInfo({
        kdf: kdf,
        client: codec.encKrb5PrincipalName(body.realm, body.cname),
        server: codec.encKrb5PrincipalName(body.realm, body.sname),
        etype: opts.etype,
        asReq: opts.asReqBytes,
        pkAsRep: pkAsRep
      });
      replyKey = cryptoLib.pkinitKdf(kdf, agreed.secret, otherInfo,
                                     opts.etype);
    } else {
      replyKey = cryptoLib.pkinitOctetString2Key(opts.etype, agreed.secret);
    }
    const indicators = opts.anonymous ? []
      : [PKINIT_INDICATOR].concat(certificate.hardware
                                    ? [HARDWARE_INDICATOR] : []);
    // AD-INITIAL-VERIFIED-CAS (section 3.2.3): the CAs the path went
    // through, the leaf left out. Never in an anonymous ticket (RFC 8062
    // section 4.1).
    const self = this;
    const verifiedCas = opts.anonymous ? null
      : codec.initialVerifiedCas(certificate.path.slice(1).map(
          function (one: Json) {
            return self.epiOf(Buffer.from(one.der));
          }));
    const kdfLabel = kdf ? (cryptoLib.PKINIT_KDFS.filter(function (one: Json) {
      return one.oid === kdf;
    })[0] || { label: kdf }).label : 'RFC 4556 octetstring2key';
    log.info('krb5-pkinit: ' + (opts.anonymous ? 'anonymous PKINIT'
               : body.cname.name.join('/') + '@' + realm + ', certificate ' +
                 certificate.how) + '; ' + agreed.group.label + ', ' +
             kdfLabel);
    log.debug('Leaving Krb5Pkinit.checkRequest(). Accepted.');
    return {
      ok: true,
      replyKey: replyKey,
      kdcPadata: [{ type: codec.PA.PK_AS_REP, value: pkAsRep }],
      indicators: indicators,
      hardware: !!(certificate && certificate.hardware),
      notAfter: certificate ? certificate.notAfter : null,
      verifiedCas: verifiedCas,
      method: (opts.anonymous ? 'anonymous PKINIT' : 'PKINIT') + ' (' +
              agreed.group.label + ', ' + kdfLabel + ')',
      // RFC 8062 section 7: the KDC's contribution to the session key, for
      // anonymous PKINIT, where it is a MUST. Not sent for a named client,
      // where it is a SHOULD: MIT's KDC sends it to the anonymous client
      // only, and so does this one.
      sessionKeyFor: async function (etype: number): Promise<Json> {
        log.debug('Entering sessionKeyFor().');
        if (!opts.anonymous) {
          log.debug('Leaving sessionKeyFor(). Not anonymous.');
          return null;
        }
        const contribution = {
          etype: etype,
          key: new Uint8Array(cryptoLib.randomBytes(
            kcrypto.etypeById(etype).keyBytes))
        };
        const session = cryptoLib.krbFxCf2(contribution, replyKey, 'PKINIT',
                                           'KEYEXCHANGE');
        const kx = msgs.encEncryptedData({
          etype: replyKey.etype,
          cipher: await kcrypto.etypeById(replyKey.etype).encrypt(
            replyKey.key, codec.KEY_USAGE_PA_PKINIT_KX,
            msgs.encEncryptionKey(contribution))
        });
        log.debug('Leaving sessionKeyFor().');
        return { sessionKey: session.key,
                 padata: { type: codec.PA.PKINIT_KX, value: kx } };
      }
    };
  }

  // -------------------------------------------------------------------------
  // WHAT THE KDC DOES WITH PKINIT, for `/admin/kerberos` and `GET
  // /admin-api/kerberos` (rule 7), per the ambient realm.
  // -------------------------------------------------------------------------
  /**
   * Describes PKINIT in the ambient realm, for the console and the
   * management API.
   *
   * @returns the description
   */
  policy(): Json {
    const { log, config, cryptoLib, realms } = this.deps;
    log.debug('Entering Krb5Pkinit.policy().');
    const held = this.kdcCredentials.get(String(realms.currentId() || ''));
    log.debug('Leaving Krb5Pkinit.policy().');
    return {
      pkinit: this.enabled(),
      anonymousPkinit: this.anonymousEnabled(),
      anonymousTickets: 'FAST armor only: a TGS-REQ presenting one is refused',
      freshnessRequired: config.value('krb5.pkinitRequireFreshness') !== false,
      legacyKdf: config.value('krb5.pkinitLegacyKdf') === true,
      kdfs: cryptoLib.PKINIT_KDFS.map(function (one: Json) {
        return one.label;
      }),
      keyAgreement: cryptoLib.PKINIT_DH_GROUPS.map(function (one: Json) {
        return one.label;
      }),
      rsaKeyTransport: 'not implemented (no forward secrecy)',
      cmsDigests: Object.keys(cryptoLib.PKINIT_CMS_DIGEST_OIDS)
        .map(function (oid) {
          return cryptoLib.PKINIT_CMS_DIGEST_OIDS[oid].label;
        }),
      clientCertificates: 'from this realm\'s ' +
        this.identityCas().join(', ') + ' Issuing CAs, with ' +
        'id-pkinit-KPClientAuth or smart-card logon, recorded on the ' +
        'person\'s entry or naming them in an id-pkinit-san',
      indicators: [PKINIT_INDICATOR, HARDWARE_INDICATOR],
      kdcKeyAlgorithm: String(config.value('krb5.pkinitKdcKeyAlgorithm') ||
                              ''),
      kdcCertificate: held
        ? { serialHex: held.serialHex, keyAlg: held.keyAlg,
            notAfter: new Date(held.notAfter).toISOString() }
        : null,
      postQuantum: 'none standardised; ML-KEM would replace the key ' +
        'agreement and ML-DSA the CMS signatures (common/crypto.js section ' +
        '16)'
    };
  }
}

export = Krb5Pkinit;
