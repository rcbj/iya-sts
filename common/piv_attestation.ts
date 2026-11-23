// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: piv_attestation.ts
//
// ===========================================================================
// YUBIKEY PIV KEY ATTESTATION, THE PIV SLOT PROFILES' RULES, AND THE OUTSIDE
// PIV / CAC CARD MAPPING (#1955 P2, design S1 and X3, decisions D7 and D8).
//
// **WHAT A PIV ATTESTATION IS.** `ykman piv keys attest <slot>` asks a YubiKey
// for a certificate over the public key in one of its PIV slots, signed by
// the key's factory attestation key in slot f9, whose own certificate
// (`ykman piv certificates export f9`) chains to a Yubico PIV root. A key the
// YubiKey IMPORTED cannot be attested, so a verified attestation is proof
// that the key was generated on that card and has never left it. The slot
// certificate carries Yubico's extensions (`crypto.js`'s
// `yubicoPivAttestationFacts()`): the key's serial, firmware, PIN policy,
// touch policy and form factor.
//
// **HOW IT ARRIVES**, in the design's order:
//   1. inside the certificate request, as draft-ietf-lamps-csr-attestation's
//      id-aa-attestation attribute (1.2.840.113549.1.9.16.2.59, read in
//      revision 33 of 2026-11-02): one AttestationBundle whose `attestations`
//      hold an AttestationStatement of type 1.3.6.1.4.1.41482.3.2 whose
//      `stmt` is the slot's attestation Certificate, and whose `certs` hold
//      the f9 certificate (and any intermediate). **THE DRAFT DEFINES NO
//      STATEMENT TYPE FOR THIS** — section 4.2 registers none, and its
//      AttestationStatementSet is empty — so the type is THIS SERVICE'S
//      CHOICE, Yubico's own OID for "attestation certificate" under its PIV
//      arc (developers.yubico.com/PIV/Introduction/Yubico_Attestation_OID),
//      and `docs/v1.2.0/hardware-tokens.md` says so to a client author. It
//      reaches EST, SCEP and ACME alike, because all three read a request
//      through `cert_enrollment.parseCsr()`, which already lifts the
//      attribute out (#164 phase 2's TPM statement uses the same bundle);
//   2. on the portal's and the console's enrolment form, as the request and
//      the two certificates pasted beside it (`/account-api/tokens`
//      `enrol-piv`, `/admin-api/hardware-tokens/enrol-piv`, parity).
//
// **WHAT IS CHECKED**, every one a refusal with its own code, in both modes:
//   * the slot certificate's key IS the request's key (STS-PIV-0005);
//   * the slot certificate chains through the f9 certificate (and Yubico's
//     shipped PIV intermediates, `pki.pivAttestationAnchors()`) to the
//     realm's PIV attestation anchors — Yubico's two roots by default,
//     `piv.attestationAnchors` replacing them — through the #1360 validation
//     door, use case `piv-attestation` (STS-PIV-0006);
//   * it names a serial (STS-PIV-0007), since the register keys a token by
//     it and records a serial only from attestation;
//   * the slot its subject names ("YubiKey PIV Attestation 9a") is the
//     profile's slot, when a PIV profile was asked (STS-PIV-0008): a 9e key
//     works without a PIN, so its attestation must not buy a 9a certificate;
//   * its PIN and touch policies are at least the realm's `piv.pinPolicy`
//     and `piv.touchPolicy` (STS-PIV-0011, -0012).
// An attestation that does not verify is REFUSED, never issued without
// evidence: a client that sent one meant it. A PIV profile asked WITHOUT one
// is issued with no evidence, unless `piv.requireAttestation` (STS-PIV-0010).
//
// **WHAT A VERIFIED ONE EARNS (X3).** `cert_enrollment.issue()` marks the
// issued certificate's register row `keySource: 'attested-hardware'` with the
// attestation's facts, and records the token and the certificate in the
// hardware token register (`hardware_tokens.recordAttested()`, evidence
// source `piv-attestation`, smart card: a PIV key is a smart-card key
// whatever the YubiKey's shape). From then on PKINIT earns
// `pkinit-hardware`/`pkinit-smartcard` (`hwk`, `sc`) and `/tls/sign-in`
// `hwk` and `sc` from that EVIDENCE (P1's plumbing), and the lost-key act
// revokes it.
//
// **`piv-card-auth` IS REFUSED FOR SIGN-IN BY DEFAULT** (`signInRefusal()`,
// STS-PIV-0013): SP 800-73's Card Authentication key needs no PIN — it is
// for a door reader — so a certificate issued under it would be a sign-in
// with no second factor. `piv.cardAuthSignIn` lets it through.
//
// **D8: AN OUTSIDE PIV OR CAC CARD, MAPPED BY ITS CARD UUID** (rcbj's
// decision on #1955, 2026-11-20; off by default). `cardIdentityOf()` is the
// second mapping an outside certificate may take, beside #1061's "the one
// entry storing it": a certificate one of the realm's `piv.externalIssuers`
// issued directly (the door's `piv-card` use case), asserting one of
// `piv.externalPolicyOids` (FIPS 201-3's PIV Authentication policy by
// default), and carrying exactly ONE `urn:uuid:` URI in its subjectAltName
// (FIPS 201-3 section 4.2.1: the card UUID, the GUID of the card's CHUID),
// maps to the ONE person whose `stsPivCardUuid` holds that UUID. Never by a
// name — an issuing CA we do not run could write anybody's — and never by
// creating an entry. Two people holding one UUID, or a card asserting two,
// names nobody. A government card is reissued with a new UUID, so a new card
// is a new value, as #1061's renewed certificate is stored again.
//
// A LIBRARY (rule 3): no route. It requires `helpers`, `config`, `pki`,
// `crypto`, `certificate_trust`, `error_codes` and `audit`; the hardware
// token register and certificate enrollment are reached at the moment of use.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import pki = require('./pki');
import stsCrypto = require('./crypto');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import CertificateTrust = require('./certificate_trust');

type Json = any;

/** The four PIV slot profiles, by the slot each is for. */
const PIV_PROFILES: Record<string, string> = Object.freeze({
  'piv-auth': '9a',
  'piv-sign': '9c',
  'piv-key-management': '9d',
  'piv-card-auth': '9e'
});

// The PIN and touch policies, ranked: a policy meets a requirement when its
// rank is at least the requirement's. A Bio key's fingerprint match counts
// as the PIN it stands in for.
const PIN_RANK: Record<string, number> = { never: 0, once: 1,
  'match-once': 1, always: 2, 'match-always': 2 };
const PIN_REQUIRED: Record<string, number> = { any: -1, once: 1, always: 2 };
const TOUCH_RANK: Record<string, number> = { never: 0, cached: 1,
                                             always: 2 };
const TOUCH_REQUIRED: Record<string, number> = { any: -1, cached: 1,
                                                 always: 2 };

const SLOT_SUBJECT = /YubiKey PIV Attestation\s+([0-9a-f]{2})\b/i;

// THE PROFILES A CERTIFICATE SIGNS IN WITH (2026-11-23, the #1955 review):
// each carries clientAuth, smart-card logon or id-pkinit-KPClientAuth, so
// the TLS sign-in or PKINIT accepts it. A slot 9e (Card Authentication)
// key needs no PIN, and an attestation of it is refused for every one of
// them, not only for the PIV profiles: a 9e key under `smartcard-logon`
// was a smart-card sign-in with no PIN, earning `hwk` and `sc`.
const SIGN_IN_PROFILES = ['tls-client', 'tls-server-client',
                          'smartcard-logon', 'piv-auth'];

// The slot that needs no PIN (SP 800-73-4 Part 1, the Card Authentication
// key).
const CARD_AUTH_SLOT = '9e';
const CARD_UUID = /^urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const MAX_CERTS = 8;

interface PivAttestationDeps {
  log: typeof helpers.log;
  config: typeof config;
  pki: typeof pki;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  trust: typeof CertificateTrust;
  now: () => number;
  // Reached at the moment of use (header).
  loadTokens: () => Json;
  loadEnrollment: () => Json;
}

/**
 * YubiKey PIV key attestation, the PIV slot profiles' rules and the outside
 * PIV / CAC card mapping (#1955 P2).
 */
class PivAttestation {
  static readonly PIV_PROFILES = PIV_PROFILES;
  static readonly STATEMENT_TYPE = stsCrypto.YUBICO_PIV_STATEMENT;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: PivAttestationDeps) {
    deps.log.debug("Entering PivAttestation.constructor().");
    deps.log.debug("Leaving PivAttestation.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PivAttestationDeps {
    helpers.log.debug("Entering PivAttestation.defaultDeps().");
    helpers.log.debug("Leaving PivAttestation.defaultDeps().");
    return {
      log: helpers.log, config: config, pki: pki, stsCrypto: stsCrypto,
      errorCodes: errorCodes, audit: audit, trust: CertificateTrust,
      now: Date.now,
      loadTokens: function (): Json {
        return require('./hardware_tokens');
      },
      loadEnrollment: function (): Json {
        return require('./cert_enrollment');
      }
    };
  }

  private refuse(code: string, why: string): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering PivAttestation.refuse(). " + code);
    log.debug("Leaving PivAttestation.refuse().");
    // error-code: none — the caller's code, passed in as `code`
    return codes.mark({ ok: false, status: 400, error: why, errors: [why],
                        why: why }, code);
  }

  private setting(key: string, fallback: string): string {
    const { log } = this.deps;
    log.debug("Entering PivAttestation.setting(). " + key);
    let value = fallback;
    try {
      const raw = this.deps.config.value(key);
      value = raw === undefined || raw === null ? fallback
        : (Array.isArray(raw) ? raw.join(',') : String(raw));
    } catch (e) {
      log.debug("Caught in PivAttestation.setting(): " +
                ((e && e.message) || e));
      // A setting that cannot be read keeps its default: the behaviour
      // before #1955.
      value = fallback;
    }
    log.debug("Leaving PivAttestation.setting().");
    return value;
  }

  private flag(key: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PivAttestation.flag(). " + key);
    const on = this.setting(key, 'false') === 'true';
    log.debug("Leaving PivAttestation.flag(). " + on);
    return on;
  }

  /**
   * Whether a profile is one of the four PIV slot profiles.
   *
   * @param profile - a profile id
   * @returns true for piv-auth, piv-sign, piv-key-management, piv-card-auth
   */
  static isPivProfile(profile: unknown): boolean {
    helpers.log.debug("Entering PivAttestation.isPivProfile().");
    helpers.log.debug("Leaving PivAttestation.isPivProfile().");
    return Object.prototype.hasOwnProperty.call(PIV_PROFILES,
                                                String(profile || ''));
  }

  // -------------------------------------------------------------------------
  // THE CARRIERS (header). Each answers `{ ok: true, found: false }` when
  // there is no PIV statement, `{ ok: true, found: true, slotDer, certs }`
  // when there is one, or a refusal for one that cannot be read.
  // -------------------------------------------------------------------------
  /**
   * Finds a YubiKey PIV statement among a request's id-aa-attestation
   * values.
   *
   * @param bundles - each attribute value's DER (`parseCsr()`'s
   *   `attestations`)
   * @returns `{ ok, found, slotDer?, certs? }`, or a refusal
   */
  statementFromBundles(bundles: Buffer[]): Json {
    const { log, stsCrypto: c } = this.deps;
    log.debug("Entering PivAttestation.statementFromBundles().");
    const list = Array.isArray(bundles) ? bundles : [];
    for (const one of list) {
      let bundle: Json = null;
      try {
        bundle = c.csrAttestationBundle(one);
      } catch (e) {
        log.debug("Caught in PivAttestation.statementFromBundles(): " +
                  ((e && e.message) || e));
        log.debug("Leaving PivAttestation.statementFromBundles(). " +
                  "Unreadable.");
        return this.refuse('STS-PIV-0004', 'The request\'s attestation ' +
          'attribute cannot be read: ' +
          String((e && e.message) || e).replace(/\.+$/, '') + '.');
      }
      const piv = (bundle.attestations || []).filter(function (s: Json) {
        return s.type === c.YUBICO_PIV_STATEMENT;
      })[0];
      if (piv) {
        log.debug("Leaving PivAttestation.statementFromBundles(). Found.");
        return { ok: true, found: true, slotDer: Buffer.from(piv.stmt),
                 certs: (bundle.certs || []).slice(0, MAX_CERTS) };
      }
    }
    log.debug("Leaving PivAttestation.statementFromBundles(). None.");
    return { ok: true, found: false };
  }

  /**
   * Reads the enrolment form's two certificates as a PIV statement.
   *
   * @param slotPem - the slot's attestation certificate
   * @param attestationPem - the f9 attestation certificate (and any
   *   intermediate after it)
   * @returns `{ ok, found, slotDer?, certs? }`, or a refusal
   */
  statementFromPem(slotPem: unknown, attestationPem: unknown): Json {
    const { log, pki: p } = this.deps;
    log.debug("Entering PivAttestation.statementFromPem().");
    const slot = p.certificateBundle(String(slotPem || '')).certificates;
    const rest = p.certificateBundle(String(attestationPem || ''))
      .certificates;
    if (!String(slotPem || '').trim() && !String(attestationPem || '').trim()) {
      log.debug("Leaving PivAttestation.statementFromPem(). None.");
      return { ok: true, found: false };
    }
    if (slot.length !== 1 || !rest.length) {
      log.debug("Leaving PivAttestation.statementFromPem(). Unreadable.");
      return this.refuse('STS-PIV-0004', 'A PIV attestation is two PEM ' +
        'certificates: the slot\'s attestation certificate (ykman piv keys ' +
        'attest) and the f9 attestation certificate (ykman piv ' +
        'certificates export f9). ' + (slot.length !== 1
          ? 'The first field holds ' + slot.length + ' readable ' +
            'certificate(s).' : 'The second field holds none.'));
    }
    log.debug("Leaving PivAttestation.statementFromPem(). Found.");
    return { ok: true, found: true, slotDer: slot[0].der,
             certs: rest.slice(0, MAX_CERTS).map(function (one: Json) {
               return one.der;
             }) };
  }

  // -------------------------------------------------------------------------
  // VERIFY (header). `spec`: { statement, publicKeyPem, profile }.
  // -------------------------------------------------------------------------
  /**
   * Verifies a YubiKey PIV key attestation against a request's key, the
   * realm's anchors and its PIN and touch policy.
   *
   * @param spec - `statement` (a carrier's answer), `publicKeyPem` (the
   *   request's key) and `profile` (the profile asked, for the slot check)
   * @returns `{ ok: true, facts }`, or a refusal
   */
  async verify(spec: Json): Promise<Json> {
    const { log, pki: p, stsCrypto: c, trust } = this.deps;
    log.debug("Entering PivAttestation.verify().");
    const s = spec || {};
    const statement = s.statement || {};
    const slot = p.attestationCertificateFacts(statement.slotDer);
    if (!slot) {
      log.debug("Leaving PivAttestation.verify(). Not a certificate.");
      return this.refuse('STS-PIV-0004', 'The PIV attestation\'s slot ' +
                         'certificate is not a certificate.');
    }
    let requestJwk: Json = null;
    try {
      requestJwk = c.publicKeyOf(String(s.publicKeyPem || ''))
        .export({ format: 'jwk' });
    } catch (e) {
      log.debug("Caught in PivAttestation.verify(): " +
                ((e && e.message) || e));
      requestJwk = null;
    }
    if (!requestJwk || !slot.publicKeyJwk ||
        PivAttestation.thumbprint(requestJwk) !==
          PivAttestation.thumbprint(slot.publicKeyJwk)) {
      log.debug("Leaving PivAttestation.verify(). Another key.");
      return this.refuse('STS-PIV-0005', 'The PIV attestation certifies a ' +
        'different public key from the one in the request, so it says ' +
        'nothing about where the request\'s key lives.');
    }
    const anchors = p.pivAttestationAnchors(
      this.setting('piv.attestationAnchors', ''));
    if (!anchors.anchors.length) {
      log.debug("Leaving PivAttestation.verify(). No anchor.");
      return this.refuse('STS-PIV-0006', 'No PIV attestation anchor is ' +
        'configured for this realm (piv.attestationAnchors), and none of ' +
        'the shipped ones could be used.');
    }
    const intermediates = (statement.certs || []).map(function (d: Buffer) {
      return Buffer.from(d);
    }).concat(anchors.intermediates.map(function (one: Json): Buffer {
      return one.der;
    }));
    const path = await trust.path('piv-attestation', statement.slotDer,
      intermediates, anchors.anchors, { now: this.deps.now() });
    if (!path.ok) {
      log.debug("Leaving PivAttestation.verify(). " + path.reason);
      return this.refuse('STS-PIV-0006', 'The PIV attestation does not ' +
        'chain to a PIV attestation anchor of this realm (' +
        anchors.source + '): ' + String(path.reason || 'no path') + '.');
    }
    const facts = c.yubicoPivAttestationFacts(slot.extensions);
    // The f9 certificate says FIPS or CSPN for the whole key (header). It is
    // read from the VALIDATED PATH — the certificate that signed the slot's
    // — and never from whatever the caller sent first: the path builder
    // treats what it was given as a pool, so `statement.certs[0]` could be
    // any certificate, a FIPS-marked one of another key included (the
    // #1955 review).
    const issuer = path.chain && path.chain.length > 1 ? path.chain[1]
                                                       : null;
    const issuerDer = issuer && issuer.der ? Buffer.from(issuer.der) : null;
    const f9 = issuerDer ? p.attestationCertificateFacts(issuerDer) : null;
    const f9facts = f9 ? c.yubicoPivAttestationFacts(f9.extensions) : null;
    if (!facts.serial) {
      log.debug("Leaving PivAttestation.verify(). No serial.");
      return this.refuse('STS-PIV-0007', 'The PIV attestation names no ' +
        'serial number (Yubico extension 1.3.6.1.4.1.41482.3.7), so no ' +
        'hardware token can be recorded from it.');
    }
    const match = SLOT_SUBJECT.exec(String(slot.subject.CN || ''));
    const slotId = match ? match[1].toLowerCase() : '';
    const profile = String(s.profile || '');
    const wanted = PIV_PROFILES[profile] || '';
    const signsIn = SIGN_IN_PROFILES.indexOf(profile) >= 0;
    // A SLOT THAT CANNOT BE READ IS NOT A SLOT THAT FITS: for a PIV profile,
    // and for a profile that signs in, the slot check is the point, so an
    // attestation whose subject names no slot is refused rather than let
    // through unchecked (the #1955 review).
    if (!slotId && (wanted || signsIn)) {
      log.debug("Leaving PivAttestation.verify(). No slot.");
      return this.refuse('STS-PIV-0036', 'The PIV attestation\'s subject ' +
        'names no slot ("YubiKey PIV Attestation <slot>"), and a ' + profile +
        ' certificate is issued only for an attestation of a known slot.');
    }
    if (slotId === CARD_AUTH_SLOT && wanted !== CARD_AUTH_SLOT) {
      log.debug("Leaving PivAttestation.verify(). A card-auth key.");
      return this.refuse('STS-PIV-0037', 'The PIV attestation is of slot ' +
        '9e, the Card Authentication key, which works without a PIN; it is ' +
        'certified only under piv-card-auth, never under ' + profile + '.');
    }
    if (wanted && slotId !== wanted) {
      log.debug("Leaving PivAttestation.verify(). Another slot.");
      return this.refuse('STS-PIV-0008', 'The PIV attestation is of slot ' +
        slotId + ', and a ' + s.profile + ' certificate is for slot ' +
        wanted + '.');
    }
    const policy = this.policyRefusal(facts);
    if (policy) {
      log.debug("Leaving PivAttestation.verify(). The policy refused it.");
      return policy;
    }
    const top = path.chain && path.chain.length
      ? path.chain[path.chain.length - 1] : null;
    const out = {
      source: 'piv-attestation', vendor: 'yubico', serial: facts.serial,
      firmware: facts.firmware, slot: slotId,
      pinPolicy: facts.pinPolicy, touchPolicy: facts.touchPolicy,
      formFactor: facts.formFactorName, shape: facts.shape,
      fips: facts.fips || !!(f9facts && f9facts.fips),
      cspn: facts.cspn || !!(f9facts && f9facts.cspn),
      anchor: String((top && top.x509 && top.x509.subject) || '')
        .replace(/\n/g, ', ') + ' (' + anchors.source + ')',
      verifiedAt: new Date(this.deps.now()).toISOString()
    };
    log.debug("Leaving PivAttestation.verify(). Verified, serial " +
              out.serial + ".");
    return { ok: true, facts: out };
  }

  // A key's RFC 7638 thumbprint, or '' for one that cannot be read.
  private static thumbprint(jwk: Json): string {
    helpers.log.debug("Entering PivAttestation.thumbprint().");
    try {
      helpers.log.debug("Leaving PivAttestation.thumbprint().");
      return stsCrypto.jwkThumbprint(jwk);
    } catch (e) {
      helpers.log.debug("Caught in PivAttestation.thumbprint(): " +
                        ((e && e.message) || e));
      helpers.log.debug("Leaving PivAttestation.thumbprint(). Unreadable.");
      return '';
    }
  }

  /**
   * The realm's PIN and touch policy, held to an attestation's facts.
   *
   * @param facts - `yubicoPivAttestationFacts()`' answer
   * @returns a refusal, or null when the policies are met
   */
  policyRefusal(facts: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PivAttestation.policyRefusal().");
    const pin = this.setting('piv.pinPolicy', 'any');
    const touch = this.setting('piv.touchPolicy', 'any');
    const pinNeed = PIN_REQUIRED[pin] === undefined ? -1 : PIN_REQUIRED[pin];
    const touchNeed = TOUCH_REQUIRED[touch] === undefined ? -1
      : TOUCH_REQUIRED[touch];
    const pinHas = PIN_RANK[String(facts.pinPolicy || '')];
    const touchHas = TOUCH_RANK[String(facts.touchPolicy || '')];
    if (pinNeed >= 0 && !(pinHas >= pinNeed)) {
      log.debug("Leaving PivAttestation.policyRefusal(). PIN.");
      return this.refuse('STS-PIV-0011', 'The attested key\'s PIN policy ' +
        'is ' + (facts.pinPolicy || 'not stated') + ', and this realm ' +
        'requires at least "' + pin + '" (piv.pinPolicy). Generate the key ' +
        'again with ykman piv keys generate --pin-policy ' + pin + '.');
    }
    if (touchNeed >= 0 && !(touchHas >= touchNeed)) {
      log.debug("Leaving PivAttestation.policyRefusal(). Touch.");
      return this.refuse('STS-PIV-0012', 'The attested key\'s touch policy ' +
        'is ' + (facts.touchPolicy || 'not stated') + ', and this realm ' +
        'requires at least "' + touch + '" (piv.touchPolicy). Generate the ' +
        'key again with ykman piv keys generate --touch-policy ' + touch +
        '.');
    }
    log.debug("Leaving PivAttestation.policyRefusal(). Met.");
    return null;
  }

  // -------------------------------------------------------------------------
  // THE ONE QUESTION ISSUANCE ASKS. `spec`: { profile, attestations (the
  // request's id-aa-attestation values), pivAttestation (the form's
  // `{ slotPem, attestationPem }`), publicKeyPem, keySource }. Answers
  // `{ ok: true, facts: null }` for a request with nothing to say,
  // `{ ok: true, facts }` for a verified attestation, or a refusal.
  // -------------------------------------------------------------------------
  /**
   * Decides what a certificate request's PIV attestation says, or refuses
   * the request.
   *
   * @param spec - the profile, the request's attestations or the form's
   *   certificates, the request's key and where the key came from
   * @returns `{ ok: true, facts }` (facts null when there is none), or a
   *   refusal
   */
  async evidenceForRequest(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering PivAttestation.evidenceForRequest().");
    const s = spec || {};
    const form = s.pivAttestation || null;
    const statement = form
      ? this.statementFromPem(form.slotPem, form.attestationPem)
      : this.statementFromBundles(s.attestations || []);
    if (!statement.ok) {
      log.debug("Leaving PivAttestation.evidenceForRequest(). Unreadable.");
      return statement;
    }
    const piv = PivAttestation.isPivProfile(s.profile);
    if (!statement.found) {
      // A server-generated key is this service's, and escrow is its point
      // (D7): nothing to attest, and nothing claimed.
      if (piv && s.keySource !== 'server' &&
          this.flag('piv.requireAttestation')) {
        log.debug("Leaving PivAttestation.evidenceForRequest(). Required.");
        return this.refuse('STS-PIV-0010', 'This realm issues a ' + s.profile +
          ' certificate only with a YubiKey PIV attestation of the key ' +
          '(piv.requireAttestation), and the request carries none. Send ' +
          'the output of ykman piv keys attest with the request.');
      }
      log.debug("Leaving PivAttestation.evidenceForRequest(). None.");
      return { ok: true, facts: null };
    }
    if (s.keySource === 'server') {
      log.debug("Leaving PivAttestation.evidenceForRequest(). A server " +
                "key.");
      return this.refuse('STS-PIV-0004', 'A key this service generates ' +
        '(EST /serverkeygen) cannot carry a PIV attestation: an attested ' +
        'key was generated on the card.');
    }
    const out = await this.verify({ statement: statement,
                                    publicKeyPem: s.publicKeyPem,
                                    profile: s.profile });
    log.debug("Leaving PivAttestation.evidenceForRequest(). ok=" + out.ok);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE TOKEN (X1, X3): a verified attestation recorded in the register, the
  // certificate as its credential. A person's only: a token has a holder.
  // A failure is logged and the certificate stands — it was issued, and a
  // token that is not recorded earns no claim, which errs the right way.
  // -------------------------------------------------------------------------
  /**
   * Records the token and the issued certificate in the hardware token
   * register.
   *
   * @param spec - `username`, `serialHex`, `thumbprint` (the certificate's
   *   SHA-256, hex), `family`, `profile`, `facts`, `actor`, `via`
   * @returns the register's answer, or null
   */
  recordToken(spec: Json): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering PivAttestation.recordToken().");
    const s = spec || {};
    const f = s.facts || {};
    let out: Json = null;
    try {
      out = this.deps.loadTokens().recordAttested({
        username: String(s.username || ''), vendor: 'yubico',
        serial: String(f.serial || ''),
        model: 'YubiKey' + (f.formFactor ? ' (' + f.formFactor + ')' : '') +
          (f.fips ? ' FIPS' : ''),
        firmware: String(f.firmware || ''),
        formFactor: String(f.shape || 'other'), fips: f.fips === true,
        // BY ITS THUMBPRINT, its serial beside it (the #1955 review): a
        // serial names a certificate only together with its issuer.
        credential: { kind: 'x509',
                      ref: s.thumbprint ? 'sha256:' + String(s.thumbprint)
                                        : String(s.serialHex || ''),
                      serial: String(s.serialHex || ''),
                      thumbprint: String(s.thumbprint || ''),
                      family: String(s.family || ''),
                      label: String(s.profile || '') +
                        (f.slot ? ' (slot ' + f.slot + ')' : '') },
        evidence: { source: 'piv-attestation', smartCard: true,
                    format: 'yubico-piv',
                    pinPolicy: String(f.pinPolicy || ''),
                    touchPolicy: String(f.touchPolicy || ''),
                    slot: String(f.slot || ''),
                    detail: 'slot ' + (f.slot || '?') + ', PIN ' +
                      (f.pinPolicy || '?') + ', touch ' +
                      (f.touchPolicy || '?') },
        actor: String(s.actor || s.username || ''),
        via: String(s.via || '')
      });
    } catch (e) {
      log.debug("Caught in PivAttestation.recordToken(): " +
                ((e && e.message) || e));
      out = null;
    }
    if (!out || !out.ok) {
      log.error(codes.tag('STS-PIV-0014') + 'piv_attestation: certificate ' +
                String(s.serialHex || '') + ' was issued from a verified PIV ' +
                'attestation, and its token could not be recorded (' +
                String((out && (out.errors || [])[0]) || 'no answer') +
                '); it earns no hardware claim.');
    }
    log.debug("Leaving PivAttestation.recordToken().");
    return out;
  }

  // -------------------------------------------------------------------------
  // SIGN-IN (header): a piv-card-auth certificate is refused unless the
  // realm lets it through. Asked by the TLS sign-in and PKINIT with the
  // certificate's serial; a certificate this service did not enrol is no
  // business of this rule.
  // -------------------------------------------------------------------------
  /**
   * Whether a certificate may sign in, by the profile it was enrolled
   * under.
   *
   * @param serialHex - the certificate's serial, hex
   * @param thumbprint - the certificate's SHA-256, hex, where the caller
   *   has the certificate: a serial is unique per issuer only, so an
   *   enrolled record whose thumbprint differs is another certificate
   * @returns a refusal sentence marked with its code, or null
   */
  signInRefusal(serialHex: string, thumbprint?: string): Json {
    const { log } = this.deps;
    log.debug("Entering PivAttestation.signInRefusal().");
    if (this.flag('piv.cardAuthSignIn')) {
      log.debug("Leaving PivAttestation.signInRefusal(). Allowed.");
      return null;
    }
    let found: Json = null;
    try {
      found = this.deps.loadEnrollment().findEnrolled(String(serialHex || ''));
    } catch (e) {
      log.debug("Caught in PivAttestation.signInRefusal(): " +
                ((e && e.message) || e));
      // Not enrolled here, or no register to ask: not this rule's.
      found = null;
    }
    const given = String(thumbprint || '').toLowerCase()
      .replace(/[^0-9a-f]/g, '');
    if (found && found.record && given && found.record.thumbprint &&
        String(found.record.thumbprint).toLowerCase() !== given) {
      log.debug("Leaving PivAttestation.signInRefusal(). Another " +
                "certificate with the serial.");
      return null;
    }
    // BY THE PROFILE, AND BY THE SLOT THE ATTESTATION NAMED (the #1955
    // review): a slot 9e key is refused whatever profile it was issued
    // under. `verify()` refuses that issuance now; a row from before it is
    // still on the register, and is refused here.
    const record = (found && found.record) || {};
    const slot = String((record.attestation || {}).slot || '')
      .toLowerCase();
    if (record.profile !== 'piv-card-auth' && slot !== CARD_AUTH_SLOT) {
      log.debug("Leaving PivAttestation.signInRefusal(). Not card auth.");
      return null;
    }
    log.debug("Leaving PivAttestation.signInRefusal(). Refused.");
    return this.refuse('STS-PIV-0013', 'A PIV Card Authentication (slot ' +
      '9e) certificate works without a PIN and does not sign in here ' +
      '(piv.cardAuthSignIn).');
  }

  // -------------------------------------------------------------------------
  // D8 (header). Answers null when the mapping does not apply (no issuers
  // configured, or the certificate is not one of theirs), so the caller's
  // own answer stands; otherwise an identity in `storedIdentityOf()`'s
  // shape, accepted or refused.
  // -------------------------------------------------------------------------
  /**
   * Maps an outside PIV or CAC card's certificate to the person whose
   * stsPivCardUuid holds its card UUID.
   *
   * @param leafBytes - the certificate's DER
   * @param realmId - the realm asked
   * @returns null, or `{ accepted, kind, username, ... }` / `{ accepted:
   *   false, error, why }`
   */
  cardIdentityOf(leafBytes: Buffer, realmId: string): Json {
    const { log, pki: p, stsCrypto: c, trust, errorCodes: codes } =
      this.deps;
    log.debug("Entering PivAttestation.cardIdentityOf().");
    const issuers = p.certificateBundle(
      this.setting('piv.externalIssuers', '')).certificates;
    if (!issuers.length) {
      log.debug("Leaving PivAttestation.cardIdentityOf(). Not configured.");
      return null;
    }
    // The DER of each: `verifyIssuedDirectly()` reads a Buffer, not a
    // bundle's entry.
    const issued = trust.direct('piv-card', Buffer.from(leafBytes),
      issuers.map(function (one: Json): Buffer {
        return one.der;
      }), { realmId: realmId, now: this.deps.now() });
    if (!issued.ok) {
      log.debug("Leaving PivAttestation.cardIdentityOf(). Not a listed " +
                "issuer's: " + String(issued.reason || ''));
      return null;
    }
    const base = { issuedHere: false, outside: true, accepted: false,
                   realm: realmId, pivCard: true };
    const refused = (why: string): Json => {
      log.info(codes.tag('STS-PIV-0030') + 'piv_attestation: an outside ' +
               'PIV card certificate was not mapped: ' + why);
      return Object.assign({}, base, { error: 'NOT_STORED', why: why });
    };
    const wanted = this.setting('piv.externalPolicyOids', '').split(',')
      .map(function (one: string): string {
        return one.trim();
      }).filter(Boolean);
    const asserted = c.certificatePolicyOids(Buffer.from(leafBytes));
    if (!asserted.some(function (oid: string): boolean {
      return wanted.indexOf(oid) >= 0;
    })) {
      log.debug("Leaving PivAttestation.cardIdentityOf(). No PIV policy.");
      return refused('the card certificate asserts none of the PIV ' +
        'Authentication policies piv.externalPolicyOids lists (' +
        (asserted.join(', ') || 'it asserts none') + ')');
    }
    let uris: string[] = [];
    try {
      uris = c.certificateFacts(Buffer.from(leafBytes)).san.uri || [];
    } catch (e) {
      log.debug("Caught in PivAttestation.cardIdentityOf(): " +
                ((e && e.message) || e));
      uris = [];
    }
    const uuids = uris.map(function (u: string): string {
      const m = CARD_UUID.exec(String(u));
      return m ? m[1].toLowerCase() : '';
    }).filter(Boolean);
    if (uuids.length !== 1) {
      log.debug("Leaving PivAttestation.cardIdentityOf(). " + uuids.length +
                " card UUIDs.");
      return refused('a PIV card certificate names its card by exactly one ' +
        'urn:uuid subjectAltName (FIPS 201-3 section 4.2.1), and this one ' +
        'carries ' + uuids.length);
    }
    let holders: Json[] = [];
    try {
      holders = this.deps.loadEnrollment().pivCardHolders(uuids[0]) || [];
    } catch (e) {
      log.debug("Caught in PivAttestation.cardIdentityOf(): " +
                ((e && e.message) || e));
      holders = [];
    }
    const people = holders.filter(function (h: Json): boolean {
      return h && h.kind === 'person';
    });
    if (people.length > 1) {
      log.info(codes.tag('STS-PIV-0032') + 'piv_attestation: card UUID ' +
               uuids[0] + ' is held by ' + people.length + ' people.');
      log.debug("Leaving PivAttestation.cardIdentityOf(). Several.");
      return Object.assign({}, base, { error: 'STORED_TWICE',
        holders: people.map(function (h: Json): string {
          return String(h.dn);
        }),
        why: 'the PIV card UUID ' + uuids[0] + ' is in stsPivCardUuid on ' +
             'more than one person of the "' + realmId + '" realm, so it ' +
             'names nobody' });
    }
    if (!people.length) {
      log.info(codes.tag('STS-PIV-0031') + 'piv_attestation: card UUID ' +
               uuids[0] + ' is held by nobody.');
      log.debug("Leaving PivAttestation.cardIdentityOf(). Nobody.");
      return Object.assign({}, base, { error: 'NOT_STORED',
        why: 'the PIV card certificate names card UUID ' + uuids[0] +
             ', which is in stsPivCardUuid on no person of the "' + realmId +
             '" realm; an administrator records it on the card holder\'s ' +
             'entry first (a reissued card has a new UUID)' });
    }
    const one = people[0];
    log.debug("Leaving PivAttestation.cardIdentityOf(). The person " +
              one.id + ".");
    return Object.assign({}, base, { accepted: true, stored: true,
      kind: 'person', username: String(one.id), dn: String(one.dn),
      cardUuid: uuids[0],
      why: 'an outside PIV card\'s certificate, mapped by its card UUID ' +
           uuids[0] + ' to ' + String(one.dn) + ' in the "' + realmId +
           '" realm' });
  }

  /**
   * Whether a value is a FIPS 201 card UUID as `stsPivCardUuid` holds it:
   * lower case, hyphenated, no `urn:uuid:` prefix.
   *
   * @param value - the value
   * @returns true when it is one
   */
  static isCardUuid(value: unknown): boolean {
    helpers.log.debug("Entering PivAttestation.isCardUuid().");
    helpers.log.debug("Leaving PivAttestation.isCardUuid().");
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      .test(String(value || ''));
  }
}

const slot = new InstanceSlot<PivAttestation>(
  'common/piv_attestation',
  () => new PivAttestation(PivAttestation.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * YubiKey PIV key attestation and the outside PIV card mapping (#1955 P2).
 * A library (rule 3).
 * @namespace
 */
export = {
  PivAttestation: PivAttestation,
  PIV_PROFILES: PIV_PROFILES,
  isPivProfile: PivAttestation.isPivProfile,
  isCardUuid: PivAttestation.isCardUuid,
  installInstance: (instance: PivAttestation): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  statementFromBundles: slot.forward('statementFromBundles'),
  statementFromPem: slot.forward('statementFromPem'),
  verify: slot.forward('verify'),
  policyRefusal: slot.forward('policyRefusal'),
  evidenceForRequest: slot.forward('evidenceForRequest'),
  recordToken: slot.forward('recordToken'),
  signInRefusal: slot.forward('signInRefusal'),
  cardIdentityOf: slot.forward('cardIdentityOf')
};
