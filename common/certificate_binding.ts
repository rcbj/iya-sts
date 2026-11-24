// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: certificate_binding.ts
//
// ===========================================================================
// CERTIFICATE SIGN-IN PROFILES AND THEIR BINDINGS (#2012, 2026-11-23).
//
// **WHAT THIS IS FOR.** A person presents a client certificate from an
// authority this service does not run — a federal PIV card, an enterprise
// smart card — and something has to say which ONE account it is. Until this
// file there were two answers, both still standing: the very certificate
// stored in `userCertificate` on exactly one entry (#1061), and an outside
// PIV or CAC card's FIPS 201 card UUID in `stsPivCardUuid` (#1955 D8). A
// realm that wants more says so with a PROFILE.
//
// **A PROFILE** is one element of the realm's `certSignIn.profiles`, a JSON
// array, empty by default — and EMPTY IS THE SERVICE AS IT WAS: no
// certificate is covered by a profile, and `tls_client_certificates.js`'s
// `storedIdentityOf()` answers exactly what it did. A profile names:
//
//   * `issuers` — the CAs it covers, each the SHA-256 of a CA's DER
//     SubjectPublicKeyInfo (so it survives that CA's certificate being
//     renewed under the same key). A certificate is covered by the FIRST
//     profile one of whose issuers is in its VALIDATED path above the leaf:
//     the chain OpenSSL built to an anchor of the client truststore. So a
//     profile may name a Federal PKI root and accept every agency CA under
//     it, which `piv.externalIssuers` (one hop only) cannot;
//   * `keyUsage` — keyUsage bits the leaf must ALL carry;
//   * `extendedKeyUsage` — purposes, ONE of which the leaf must carry;
//   * `policies` — certificate policies, asked through RFC 5280 section
//     6.1's policy processing over the validated path with these as the
//     initial-policy-set and initial-explicit-policy set
//     (`pki.pathPolicyOutcome()`, over the path already validated), so an agency policy MAPPED to
//     id-fpki-common-authentication through a bridge is accepted and a
//     policy the path does not carry to the leaf is not;
//   * `bindings` — the methods that say whose it is (below), by default
//     `certificate-sha256` and `issuer-serial`;
//   * `smartCard` — true where the certificates it covers are smart cards
//     (PIV/CAC), so a sign-in on one is the authentication policy's smart
//     card row rather than its TLS client certificate row (#2031). Absent
//     is false, so a profile stored before it keeps its meaning;
//   * `lowAffinity` — true only where an administrator opts in to a NAME
//     method (rcbj's decision on #2012). False, a name method in the list is
//     refused when the setting is written.
//
// **THE METHODS.** High affinity, bound to one certificate or one key:
//
//   certificate-sha256  the SHA-256 of the leaf's DER: `userCertificate`
//                       (#1061), or the stored value below
//   issuer-serial       the issuing CA (its SubjectPublicKeyInfo's SHA-256)
//                       and the leaf's serial
//   issuer-ski          the issuing CA and the leaf's subjectKeyIdentifier;
//                       a leaf with none matches nobody
//   spki-sha256         the SHA-256 of the leaf's SubjectPublicKeyInfo, which
//                       a renewal under the same key carries over
//   card-uuid           the FIPS 201 card UUID (`stsPivCardUuid`, #1955 D8)
//
// Low affinity, a NAME, which another certificate may carry too:
//
//   upn                 the SAN UPN to the directory's `userPrincipalName`
//   email               the SAN rfc822Name to the directory's `mail`
//   issuer-subject      the issuing CA and the leaf's subject DN
//   subject             the leaf's subject DN
//
// The values a high-affinity method (and the two DN methods) matches are
// stored in `stsCertificateBinding` on the person, in the grammar
// `bindingValueOf()` canonicalises, which `ldap/ldap_server.js` holds every
// write to. `upn` and `email` read the person's own attributes: the
// directory is the authority for those names.
//
// **THE RESOLUTION.** Every enabled method is asked. One that names two
// people is ambiguous; two methods naming different people disagree; both
// are refused as `STORED_TWICE`, because every door already refuses that
// answer with its own code (`tls/tls_server.js`, SCIM, WS-Trust, XACML, SSF,
// the sign-in screen) and "names more than one account" is one condition.
// No method naming anybody is `NOT_STORED`. A leaf outside the profile it is
// covered by (keyUsage, extendedKeyUsage, policies) is `NOT_STORED` too,
// with its own code in the log (STS-TLS-0066): it is covered and is not a
// certificate this realm takes, and it never falls through to the older
// mappings. **A failed high-affinity method never falls back to a name**:
// a profile without `lowAffinity` has no name method to fall back to.
//
// **AND REVOCATION FOR A SIGN-IN** (`revocationRefusal()`): the realm's
// `certSignIn.requireRevocation`, `auto` (a verified status in product mode,
// `mode.refusesUnknownRevocationStatus()`, the revocation policy's answer in
// development) or `on` (a verified status in every mode). A certificate
// sign-in under it refuses a status that is unknown or was not consulted,
// whatever soft-fail would have let through.
//
// A LIBRARY (rule 3): no route. It requires `helpers`, `config`, `pki`,
// `crypto`, `error_codes` and `mode`; the directory is reached through
// certificate enrollment's slot at the moment of use (`loadEnrollment()`),
// for `storedIdentityOf()`'s reason.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import pki = require('./pki');
import stsCrypto = require('./crypto');
import errorCodes = require('./error_codes');
import mode = require('./mode');

type Json = any;

/** The methods bound to one certificate or one key. */
const HIGH_AFFINITY = ['certificate-sha256', 'issuer-serial', 'issuer-ski',
                       'spki-sha256', 'card-uuid'];

/** The methods that match a name another certificate may carry. */
const LOW_AFFINITY = ['upn', 'email', 'issuer-subject', 'subject'];

/** The methods whose values are stored in `stsCertificateBinding`. */
const STORED_METHODS = ['certificate-sha256', 'issuer-serial', 'issuer-ski',
                        'spki-sha256', 'issuer-subject', 'subject'];

/** A profile that names no `bindings`. */
const DEFAULT_BINDINGS = ['certificate-sha256', 'issuer-serial'];

// The keyUsage bit names `crypto.certificateFacts()` answers.
const KEY_USAGE_NAMES = ['digitalSignature', 'nonRepudiation',
                         'keyEncipherment', 'dataEncipherment',
                         'keyAgreement', 'keyCertSign', 'cRLSign',
                         'encipherOnly', 'decipherOnly'];

const HEX64 = /^[0-9a-f]{64}$/;
const OID = /^[0-2](\.(0|[1-9][0-9]*))+$/;
const PROFILE_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const CARD_UUID = /^urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const MAX_PROFILES = 32;
const MAX_LIST = 32;

/** The setting that holds a realm's profiles. */
const PROFILES_SETTING = 'certSignIn.profiles';

/** The setting that asks for a verified revocation status at sign-in. */
const REVOCATION_SETTING = 'certSignIn.requireRevocation';

interface CertificateBindingDeps {
  log: typeof helpers.log;
  config: typeof config;
  pki: typeof pki;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  mode: typeof mode;
  now: () => number;
  // Certificate enrollment, whose directory slot answers who holds a value
  // (header).
  loadEnrollment: () => Json;
  // Whether every stored userPrincipalName carries its index key (the
  // second backfill walk, `persistence/granting_index_backfill.js`).
  upnKeysComplete: () => boolean;
}

/**
 * Certificate sign-in profiles, the bindings that resolve a covered
 * certificate to one account, and the revocation a sign-in requires
 * (#2012).
 */
class CertificateBinding {
  static readonly HIGH_AFFINITY = HIGH_AFFINITY;
  static readonly LOW_AFFINITY = LOW_AFFINITY;
  static readonly STORED_METHODS = STORED_METHODS;
  static readonly DEFAULT_BINDINGS = DEFAULT_BINDINGS;
  static readonly PROFILES_SETTING = PROFILES_SETTING;
  static readonly REVOCATION_SETTING = REVOCATION_SETTING;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: CertificateBindingDeps) {
    deps.log.debug("Entering CertificateBinding.constructor().");
    deps.log.debug("Leaving CertificateBinding.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): CertificateBindingDeps {
    helpers.log.debug("Entering CertificateBinding.defaultDeps().");
    helpers.log.debug("Leaving CertificateBinding.defaultDeps().");
    return {
      log: helpers.log, config: config, pki: pki, stsCrypto: stsCrypto,
      errorCodes: errorCodes, mode: mode, now: Date.now,
      loadEnrollment: function (): Json {
        return require('./cert_enrollment');
      },
      upnKeysComplete: function (): boolean {
        return require('../persistence/granting_index_backfill')
          .keysComplete() === true;
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE PROFILES, READ AND HELD TO THEIR SHAPE.
  // -------------------------------------------------------------------------
  /**
   * A SHA-256 written by hand, canonical: lower case, no colons or spaces,
   * an optional `sha256:` in front. '' where it is not 64 hex digits.
   *
   * @param value - the value as written
   * @returns the digest, or ''
   */
  static hex64(value: unknown): string {
    helpers.log.debug("Entering CertificateBinding.hex64().");
    const text = String(value == null ? '' : value).trim().toLowerCase()
      .replace(/^sha-?256:/, '').replace(/[:\s]/g, '');
    helpers.log.debug("Leaving CertificateBinding.hex64().");
    return HEX64.test(text) ? text : '';
  }

  /**
   * Why a parsed `certSignIn.profiles` value is not one, or ''.
   *
   * @param list - the parsed JSON
   * @returns the problem, or ''
   */
  static profilesProblem(list: unknown): string {
    helpers.log.debug("Entering CertificateBinding.profilesProblem().");
    if (!Array.isArray(list)) {
      helpers.log.debug("Leaving CertificateBinding.profilesProblem(). " +
                        "Not an array.");
      return 'it is a JSON array of profiles';
    }
    if (list.length > MAX_PROFILES) {
      helpers.log.debug("Leaving CertificateBinding.profilesProblem(). " +
                        "Too many.");
      return 'it holds at most ' + MAX_PROFILES + ' profiles';
    }
    const ids: string[] = [];
    for (let i = 0; i < list.length; i++) {
      const problem = CertificateBinding.profileProblem(list[i]);
      if (problem) {
        helpers.log.debug("Leaving CertificateBinding.profilesProblem(). " +
                          "Profile " + i + ".");
        return 'profile ' + (i + 1) + ' ' + problem;
      }
      const id = String(list[i].id);
      if (ids.indexOf(id) >= 0) {
        helpers.log.debug("Leaving CertificateBinding.profilesProblem(). " +
                          "A repeated id.");
        return 'two profiles are called "' + id + '"';
      }
      ids.push(id);
    }
    helpers.log.debug("Leaving CertificateBinding.profilesProblem().");
    return '';
  }

  /**
   * Why one profile is not one, or ''.
   *
   * @param one - the profile as parsed
   * @returns the problem, or ''
   */
  static profileProblem(one: Json): string {
    helpers.log.debug("Entering CertificateBinding.profileProblem().");
    const allowed = ['id', 'issuers', 'keyUsage', 'extendedKeyUsage',
                     'policies', 'bindings', 'lowAffinity', 'description',
                     'smartCard'];
    let problem = '';
    if (!one || typeof one !== 'object' || Array.isArray(one)) {
      problem = 'is not a JSON object';
    } else {
      const unknown = Object.keys(one).filter(function (name) {
        return allowed.indexOf(name) < 0;
      })[0];
      const list = function (name: string): unknown[] | null {
        const value = one[name];
        return value === undefined ? [] :
          (Array.isArray(value) && value.length <= MAX_LIST ? value : null);
      };
      const issuers = list('issuers');
      const usages = list('keyUsage');
      const purposes = list('extendedKeyUsage');
      const policies = list('policies');
      const bindings = one.bindings === undefined ? DEFAULT_BINDINGS
        : list('bindings');
      if (unknown) {
        problem = 'names "' + unknown + '", which a profile does not have';
      } else if (!PROFILE_ID.test(String(one.id || ''))) {
        problem = 'needs an "id" of lower-case letters, digits and hyphens';
      } else if (!issuers || !issuers.length ||
                 issuers.some(function (v) {
                   return !CertificateBinding.hex64(v);
                 })) {
        problem = '("' + one.id + '") needs "issuers": the SHA-256 of each ' +
                  'covered CA\'s SubjectPublicKeyInfo, 64 hexadecimal digits';
      } else if (!usages || usages.some(function (v) {
        return KEY_USAGE_NAMES.indexOf(String(v)) < 0;
      })) {
        problem = '("' + one.id + '") names a keyUsage that is not one of ' +
                  KEY_USAGE_NAMES.join(', ');
      } else if (!purposes || purposes.some(function (v) {
        return !OID.test(String(v));
      })) {
        problem = '("' + one.id + '") needs "extendedKeyUsage" as dotted ' +
                  'object identifiers';
      } else if (!policies || policies.some(function (v) {
        return !OID.test(String(v));
      })) {
        problem = '("' + one.id + '") needs "policies" as dotted object ' +
                  'identifiers';
      } else if (!bindings || !bindings.length ||
                 bindings.some(function (v) {
                   return HIGH_AFFINITY.indexOf(String(v)) < 0 &&
                          LOW_AFFINITY.indexOf(String(v)) < 0;
                 })) {
        problem = '("' + one.id + '") needs "bindings" from ' +
                  HIGH_AFFINITY.concat(LOW_AFFINITY).join(', ');
      } else if (one.lowAffinity !== undefined &&
                 typeof one.lowAffinity !== 'boolean') {
        problem = '("' + one.id + '") has a "lowAffinity" that is not true ' +
                  'or false';
      } else if (one.lowAffinity !== true && bindings.some(function (v) {
        return LOW_AFFINITY.indexOf(String(v)) >= 0;
      })) {
        // rcbj's decision on #2012: a name method is an explicit opt-in.
        problem = '("' + one.id + '") names a low-affinity binding (' +
                  bindings.filter(function (v) {
                    return LOW_AFFINITY.indexOf(String(v)) >= 0;
                  }).join(', ') + ') without "lowAffinity": true';
      } else if (one.smartCard !== undefined &&
                 typeof one.smartCard !== 'boolean') {
        problem = '("' + one.id + '") has a "smartCard" that is not true ' +
                  'or false';
      } else if (one.description !== undefined &&
                 (typeof one.description !== 'string' ||
                  one.description.length > 500)) {
        problem = '("' + one.id + '") has a "description" that is not a ' +
                  'string of at most 500 characters';
      }
    }
    helpers.log.debug("Leaving CertificateBinding.profileProblem(). " +
                      (problem ? 'Refused.' : 'Well formed.'));
    return problem;
  }

  /**
   * Why a profile names one of this service's own authorities, or '': a
   * certificate this service issued is an identity by #1061's other rule
   * (`identityOf()`'s `issuedHere`) and never reaches a profile, so such a
   * profile would cover nothing and say nothing (the #2012 review).
   *
   * @param list - the profiles, well formed
   * @returns the problem, or ''
   */
  static heldIssuerProblem(list: Json[]): string {
    helpers.log.debug("Entering CertificateBinding.heldIssuerProblem().");
    let held: string[] = [];
    try {
      held = require('./revocation_status').heldCertificates()
        .map(function (one: Json): string {
          return String(stsCrypto.certificateFacts(one).spkiSha256 || '');
        }).filter(Boolean);
    } catch (e) {
      helpers.log.debug("Caught in CertificateBinding.heldIssuerProblem(): " +
                        ((e && e.message) || e));
      held = [];
    }
    const named = list.filter(function (one: Json): boolean {
      return (one.issuers || []).some(function (v: unknown): boolean {
        return held.indexOf(CertificateBinding.hex64(v)) >= 0;
      });
    })[0];
    helpers.log.debug("Leaving CertificateBinding.heldIssuerProblem(). " +
                      (named ? 'Named.' : 'None.'));
    return named ? 'profile "' + named.id + '" names one of this service\'s ' +
      'own certificate authorities, whose certificates are identities by ' +
      'their urn:sts names and never reach a profile' : '';
  }

  /**
   * The rule `config.addWriteRule()` asks of every write of
   * `certSignIn.profiles`.
   *
   * @param key - the setting written
   * @param parsed - its parsed value
   * @returns null, or `{ problem, code }`
   */
  static writeRule(key: string, parsed: unknown): Json {
    helpers.log.debug("Entering CertificateBinding.writeRule(). " + key);
    if (key !== PROFILES_SETTING) {
      helpers.log.debug("Leaving CertificateBinding.writeRule(). Not ours.");
      return null;
    }
    const text = String(parsed == null ? '' : parsed).trim();
    if (!text) {
      helpers.log.debug("Leaving CertificateBinding.writeRule(). Empty.");
      return null;
    }
    let list: unknown = null;
    try {
      list = JSON.parse(text);
    } catch (e) {
      helpers.log.debug("Caught in CertificateBinding.writeRule(): " +
                        ((e && e.message) || e));
      list = undefined;
    }
    let problem = list === undefined ? 'it is not JSON'
      : CertificateBinding.profilesProblem(list);
    if (!problem) {
      problem = CertificateBinding.heldIssuerProblem(list as Json[]);
    }
    helpers.log.debug("Leaving CertificateBinding.writeRule(). " +
                      (problem ? 'Refused.' : 'Taken.'));
    return problem
      ? { problem: PROFILES_SETTING + ' is refused: ' + problem + '.',
          code: 'STS-TLS-0065' }
      : null;
  }

  /**
   * The ambient realm's profiles, canonical: each `issuers` lower-case hex,
   * `bindings` defaulted. A value that is not well formed is LOGGED and
   * answers none, which is the service as it was rather than a guess.
   *
   * @returns the profiles
   */
  profiles(): Json[] {
    const { log, config: settings, errorCodes: codes } = this.deps;
    log.debug("Entering CertificateBinding.profiles().");
    let text = '';
    try {
      text = String(settings.value(PROFILES_SETTING) || '').trim();
    } catch (e) {
      log.debug("Caught in CertificateBinding.profiles(): " +
                ((e && e.message) || e));
      text = '';
    }
    if (!text) {
      log.debug("Leaving CertificateBinding.profiles(). None.");
      return [];
    }
    let list: Json = null;
    try {
      list = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in CertificateBinding.profiles(): " +
                ((e && e.message) || e));
      list = undefined;
    }
    const problem = list === undefined ? 'it is not JSON'
      : CertificateBinding.profilesProblem(list);
    if (problem) {
      log.warn(codes.tag('STS-TLS-0065') + 'certificate_binding: ' +
               PROFILES_SETTING + ' is not used: ' + problem + '.');
      log.debug("Leaving CertificateBinding.profiles(). Malformed.");
      return [];
    }
    const out = list.map(function (one: Json): Json {
      const strings = function (v: unknown): string[] {
        return (Array.isArray(v) ? v : []).map(String);
      };
      return {
        id: String(one.id),
        issuers: strings(one.issuers).map(CertificateBinding.hex64),
        keyUsage: strings(one.keyUsage),
        extendedKeyUsage: strings(one.extendedKeyUsage),
        policies: strings(one.policies),
        bindings: one.bindings === undefined ? DEFAULT_BINDINGS.slice(0)
          : strings(one.bindings),
        lowAffinity: one.lowAffinity === true,
        // #2031: the certificates it covers are smart cards (PIV/CAC), for
        // the authentication policy's smart card row. Absent is false.
        smartCard: one.smartCard === true
      };
    });
    log.debug("Leaving CertificateBinding.profiles(). " + out.length + ".");
    return out;
  }

  // -------------------------------------------------------------------------
  // WHICH PROFILE COVERS A CERTIFICATE, AND WHETHER IT IS INSIDE IT.
  // -------------------------------------------------------------------------
  /**
   * The facts of a certificate, or null where it cannot be read.
   *
   * @param der - the certificate's DER
   * @returns `crypto.certificateFacts()`'s answer, or null
   */
  private factsOf(der: Buffer): Json {
    const { log, stsCrypto: c } = this.deps;
    log.debug("Entering CertificateBinding.factsOf().");
    let facts: Json = null;
    try {
      facts = c.certificateFacts(der);
    } catch (e) {
      log.debug("Caught in CertificateBinding.factsOf(): " +
                ((e && e.message) || e));
      facts = null;
    }
    log.debug("Leaving CertificateBinding.factsOf().");
    return facts;
  }

  /**
   * The longest prefix of a presented chain whose every certificate signed
   * the one below it, from the leaf up. A link that does not verify, or
   * that OpenSSL cannot verify (a key it does not read), ends the path.
   *
   * @param leaf - the leaf's DER
   * @param chain - the DER above it, issuer first
   * @returns the verified certificates above the leaf, in order
   */
  signedPath(leaf: Buffer, chain: Buffer[]): Buffer[] {
    const { log, stsCrypto: c } = this.deps;
    log.debug("Entering CertificateBinding.signedPath(). " + chain.length);
    const out: Buffer[] = [];
    let below: Json = null;
    try {
      below = c.parseCertificate(leaf);
    } catch (e) {
      log.debug("Caught in CertificateBinding.signedPath(): " +
                ((e && e.message) || e));
      below = null;
    }
    for (let i = 0; below && i < chain.length; i++) {
      let above: Json = null;
      let signed = false;
      try {
        above = c.parseCertificate(chain[i]);
        signed = c.certificateSignedWith(below, above.publicKey) === true;
      } catch (e) {
        log.debug("Caught in CertificateBinding.signedPath(): " +
                  ((e && e.message) || e));
        signed = false;
      }
      if (!signed) {
        log.debug("Leaving CertificateBinding.signedPath(). Link " + i +
                  " did not sign the one below it.");
        return out;
      }
      out.push(Buffer.from(chain[i]));
      below = above;
    }
    log.debug("Leaving CertificateBinding.signedPath(). " + out.length + ".");
    return out;
  }

  /**
   * The profile that covers a certificate: the first whose `issuers` holds
   * the SubjectPublicKeyInfo digest of a certificate in its validated path
   * above the leaf. Null where none does.
   *
   * @param chain - the DER of each certificate above the leaf, the leaf's
   *   issuer first, as `revocation_status.fromSocket()` answers it
   * @returns the profile, or null
   */
  profileFor(chain: Buffer[]): Json {
    const { log } = this.deps;
    log.debug("Entering CertificateBinding.profileFor().");
    const list = this.profiles();
    if (!list.length || !chain.length) {
      log.debug("Leaving CertificateBinding.profileFor(). None.");
      return null;
    }
    const self = this;
    const keys = chain.map(function (der: Buffer): string {
      const facts = self.factsOf(der);
      return facts ? String(facts.spkiSha256 || '') : '';
    }).filter(Boolean);
    const found = list.find(function (one: Json): boolean {
      return one.issuers.some(function (key: string): boolean {
        return keys.indexOf(key) >= 0;
      });
    }) || null;
    log.debug("Leaving CertificateBinding.profileFor(). " +
              (found ? found.id : 'None.'));
    return found;
  }

  /**
   * Why a leaf is outside the profile that covers it, or '': its keyUsage,
   * its extendedKeyUsage, and the policies RFC 5280 section 6.1 carries
   * through its validated path.
   *
   * @param profile - the profile
   * @param leaf - the leaf's DER
   * @param chain - the DER above it, issuer first, the anchor last
   * @returns the reason, or ''
   */
  profileRefusal(profile: Json, leaf: Buffer, chain: Buffer[]): string {
    const { log, pki: p } = this.deps;
    log.debug("Entering CertificateBinding.profileRefusal(). " + profile.id);
    const facts = this.factsOf(leaf);
    if (!facts) {
      log.debug("Leaving CertificateBinding.profileRefusal(). Unreadable.");
      return 'the certificate cannot be read';
    }
    const usages: string[] = Array.isArray(facts.keyUsage) ? facts.keyUsage
                                                           : [];
    const missing = profile.keyUsage.filter(function (one: string): boolean {
      return usages.indexOf(one) < 0;
    });
    if (missing.length) {
      log.debug("Leaving CertificateBinding.profileRefusal(). keyUsage.");
      return 'its keyUsage does not carry ' + missing.join(', ') +
             ', which the "' + profile.id + '" profile requires';
    }
    const purposes: string[] = Array.isArray(facts.eku) ? facts.eku : [];
    if (profile.extendedKeyUsage.length &&
        !profile.extendedKeyUsage.some(function (one: string): boolean {
          return purposes.indexOf(one) >= 0;
        })) {
      log.debug("Leaving CertificateBinding.profileRefusal(). EKU.");
      return 'its extendedKeyUsage carries none of ' +
             profile.extendedKeyUsage.join(', ') + ', one of which the "' +
             profile.id + '" profile requires';
    }
    if (profile.policies.length) {
      // THE PATH IS THE ONE ALREADY VALIDATED — OpenSSL's at the handshake,
      // or `forwarded_client_certificate.ts`'s for a proxy's — so its
      // signatures are not asked again: section 6.1's policy processing is
      // what is asked, and `pki.pathPolicyOutcome()` is synchronous, which
      // every door that reads an identity is.
      const path = [leaf].concat(chain).map(function (der: Buffer): Json {
        return p.certificateFromDer(der);
      });
      if (chain.length === 0 || path.some(function (one: Json): boolean {
        return !one;
      })) {
        log.debug("Leaving CertificateBinding.profileRefusal(). No path.");
        return 'no validated path is held for it, so the policies the "' +
               profile.id + '" profile requires cannot be asked';
      }
      let outcome: Json = null;
      try {
        outcome = p.pathPolicyOutcome(path,
          { initialPolicySet: profile.policies.slice(0),
            initialExplicitPolicy: true });
      } catch (e) {
        log.debug("Caught in CertificateBinding.profileRefusal(): " +
                  ((e && e.message) || e));
        outcome = { ok: false, why: 'its policies could not be read' };
      }
      const accepted: string[] = (outcome && outcome.ok &&
        outcome.userConstrainedPolicySet) || [];
      if (!accepted.length) {
        log.debug("Leaving CertificateBinding.profileRefusal(). Policy.");
        return 'its path does not carry one of the certificate policies ' +
               'the "' + profile.id + '" profile requires (' +
               profile.policies.join(', ') + '; RFC 5280 section 6.1)' +
               (outcome && outcome.why ? ': ' + String(outcome.why) : '');
      }
    }
    log.debug("Leaving CertificateBinding.profileRefusal(). Inside.");
    return '';
  }

  // -------------------------------------------------------------------------
  // THE VALUES A CERTIFICATE IS FOUND BY, AND THE STORED GRAMMAR.
  // -------------------------------------------------------------------------
  /**
   * A subject DN as the two DN methods compare it: RFC 4514 order, each RDN
   * trimmed around its `=` and its separators, lower-cased.
   *
   * @param dn - the DN
   * @returns the canonical form
   */
  static canonicalDn(dn: unknown): string {
    helpers.log.debug("Entering CertificateBinding.canonicalDn().");
    const text = String(dn == null ? '' : dn).trim();
    const parts: string[] = [];
    let at = '';
    for (let i = 0; i < text.length; i++) {
      const ch = text.charAt(i);
      if (ch === '\\' && i + 1 < text.length) {
        at += ch + text.charAt(i + 1);
        i += 1;
      } else if (ch === ',' || ch === ';') {
        parts.push(at);
        at = '';
      } else {
        at += ch;
      }
    }
    parts.push(at);
    helpers.log.debug("Leaving CertificateBinding.canonicalDn().");
    return parts.map(function (rdn: string): string {
      const eq = rdn.indexOf('=');
      return eq < 0 ? rdn.trim().toLowerCase()
        : rdn.slice(0, eq).trim().toLowerCase() + '=' +
          rdn.slice(eq + 1).trim().toLowerCase();
    }).filter(function (rdn: string): boolean {
      return rdn.length > 0;
    }).join(',');
  }

  /**
   * A value of `stsCertificateBinding`, canonical, or '' where it is not
   * one. The grammar:
   *
   *   certificate-sha256:<sha256>
   *   issuer-serial:<issuer spki sha256>:<serial, hex>
   *   issuer-ski:<issuer spki sha256>:<subjectKeyIdentifier, hex>
   *   spki-sha256:<sha256>
   *   issuer-subject:<issuer spki sha256>:<subject DN>
   *   subject:<subject DN>
   *
   * Hex is lower-cased with colons taken out, a serial loses its leading
   * zeros, a DN is `canonicalDn()`'s.
   *
   * @param value - the value as written
   * @returns the canonical value, or ''
   */
  static bindingValueOf(value: unknown): string {
    helpers.log.debug("Entering CertificateBinding.bindingValueOf().");
    const text = String(value == null ? '' : value).trim();
    const colon = text.indexOf(':');
    const method = colon < 0 ? '' : text.slice(0, colon).trim().toLowerCase();
    const rest = colon < 0 ? '' : text.slice(colon + 1);
    const hex = function (v: string): string {
      const h = String(v).trim().toLowerCase().replace(/[:\s]/g, '');
      return /^[0-9a-f]+$/.test(h) ? h : '';
    };
    // An issuer-scoped value: the issuer's digest, then what follows it.
    const scoped = function (): string[] | null {
      const cut = rest.indexOf(':');
      if (cut < 0) {
        return null;
      }
      const issuer = CertificateBinding.hex64(rest.slice(0, cut));
      return issuer ? [issuer, rest.slice(cut + 1)] : null;
    };
    let out = '';
    if (method === 'certificate-sha256' || method === 'spki-sha256') {
      const digest = CertificateBinding.hex64(rest);
      out = digest ? method + ':' + digest : '';
    } else if (method === 'issuer-serial') {
      const pair = scoped();
      const serial = pair ? hex(pair[1]).replace(/^0+(?=[0-9a-f])/, '') : '';
      out = pair && serial && serial.length <= 40
        ? method + ':' + pair[0] + ':' + serial : '';
    } else if (method === 'issuer-ski') {
      const pair = scoped();
      const ski = pair ? hex(pair[1]) : '';
      out = pair && ski && ski.length <= 128 && ski.length % 2 === 0
        ? method + ':' + pair[0] + ':' + ski : '';
    } else if (method === 'issuer-subject') {
      const pair = scoped();
      const dn = pair ? CertificateBinding.canonicalDn(pair[1]) : '';
      out = pair && dn && dn.length <= 1024
        ? method + ':' + pair[0] + ':' + dn : '';
    } else if (method === 'subject') {
      const dn = CertificateBinding.canonicalDn(rest);
      out = dn && dn.length <= 1024 ? method + ':' + dn : '';
    }
    helpers.log.debug("Leaving CertificateBinding.bindingValueOf(). " +
                      (out ? method : 'Not a binding.'));
    return out;
  }

  /**
   * What one method finds a certificate by: `{ kind, value }`, `kind` one
   * of `binding` (a stored `stsCertificateBinding` value), `stored` (the
   * `userCertificate` digest), `card`, `upn` or `mail`. Null where the
   * certificate carries nothing the method can match — no SKI, no card
   * UUID, not exactly one UPN or address — which matches nobody.
   *
   * @param method - the method
   * @param leaf - the leaf's DER
   * @param facts - its facts
   * @param issuer - the facts of its issuer, or null
   * @returns the key, or null
   */
  keyOf(method: string, leaf: Buffer, facts: Json, issuer: Json): Json {
    const { log, stsCrypto: c } = this.deps;
    log.debug("Entering CertificateBinding.keyOf(). " + method);
    const issuerKey = issuer ? String(issuer.spkiSha256 || '') : '';
    const san = (facts && facts.san) || {};
    let out: Json = null;
    if (method === 'certificate-sha256') {
      out = { kind: 'stored', value: c.digest('sha256', leaf, 'hex') };
    } else if (method === 'spki-sha256' && facts.spkiSha256) {
      out = { kind: 'binding',
              value: 'spki-sha256:' + String(facts.spkiSha256) };
    } else if (method === 'issuer-serial' && issuerKey && facts.serialHex) {
      out = { kind: 'binding', value: CertificateBinding.bindingValueOf(
        'issuer-serial:' + issuerKey + ':' + String(facts.serialHex)) };
    } else if (method === 'issuer-ski' && issuerKey && facts.ski) {
      out = { kind: 'binding', value: 'issuer-ski:' + issuerKey + ':' +
                                      String(facts.ski) };
    } else if (method === 'issuer-subject' && issuerKey && facts.subject) {
      out = { kind: 'binding', value: CertificateBinding.bindingValueOf(
        'issuer-subject:' + issuerKey + ':' + String(facts.subject)) };
    } else if (method === 'subject' && facts.subject) {
      out = { kind: 'binding', value: CertificateBinding.bindingValueOf(
        'subject:' + String(facts.subject)) };
    } else if (method === 'card-uuid') {
      const uuids = (san.uri || []).map(function (u: string): string {
        const m = CARD_UUID.exec(String(u));
        return m ? m[1].toLowerCase() : '';
      }).filter(Boolean);
      out = uuids.length === 1 ? { kind: 'card', value: uuids[0] } : null;
    } else if (method === 'upn' && !this.deps.upnKeysComplete()) {
      // NOT YET (the #2012 review): an entry written before #2012 carries no
      // `upn:` key until the backfill reaches it, so a duplicate UPN there
      // could make an ambiguous name look unique. Nobody matches by UPN
      // until the walk's mark is seen.
      this.deps.log.info('certificate_binding: the upn binding is not asked ' +
                         'until the directory index backfill has finished.');
      out = null;
    } else if (method === 'upn') {
      const names = (san.upn || []).map(function (u: string): string {
        return String(u).trim().toLowerCase();
      }).filter(Boolean);
      out = names.length === 1 ? { kind: 'upn', value: names[0] } : null;
    } else if (method === 'email') {
      const names = (san.email || []).map(function (u: string): string {
        return String(u).trim().toLowerCase();
      }).filter(Boolean);
      out = names.length === 1 ? { kind: 'mail', value: names[0] } : null;
    }
    if (out && !out.value) {
      out = null;
    }
    log.debug("Leaving CertificateBinding.keyOf(). " +
              (out ? out.kind : 'Nothing to match.'));
    return out;
  }

  /**
   * Who holds one key: `[{ kind, id, dn }]`, at most three, people and (for
   * `stored`, #1061's rule) applications.
   *
   * @param key - from `keyOf()`
   * @returns the holders
   */
  private holdersOf(key: Json): Json[] {
    const { log } = this.deps;
    log.debug("Entering CertificateBinding.holdersOf(). " + key.kind);
    const enrollment = this.deps.loadEnrollment();
    let found: Json[] = [];
    try {
      if (key.kind === 'stored') {
        found = enrollment.certificateHolders(key.value) || [];
      } else if (key.kind === 'card') {
        found = enrollment.pivCardHolders(key.value) || [];
      } else {
        found = enrollment.certificateBindingHolders(key.kind, key.value) ||
          [];
      }
    } catch (e) {
      log.debug("Caught in CertificateBinding.holdersOf(): " +
                ((e && e.message) || e));
      found = [];
    }
    log.debug("Leaving CertificateBinding.holdersOf(). " + found.length +
              ".");
    return Array.isArray(found) ? found : [];
  }

  // -------------------------------------------------------------------------
  // THE RESOLUTION (header).
  // -------------------------------------------------------------------------
  /**
   * Resolves a certificate a profile covers to one account, in
   * `storedIdentityOf()`'s shape; null where no profile covers it, so the
   * caller's own mappings answer as they did.
   *
   * @param leaf - the leaf's DER
   * @param chain - the DER above it, issuer first
   * @param realmId - the realm asked, for the sentences
   * @returns null or the answer
   */
  identityOf(leaf: Buffer, presented: Buffer[], realmId: string): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering CertificateBinding.identityOf().");
    // ONLY WHAT SIGNED (the #2012 review): the chain a socket reports is
    // node's issuer linkage, matched by name and key identifier and never
    // signature-checked, so a client could append a certificate naming a
    // trusted CA's subject over a profile CA's key. Coverage, the issuer of
    // an issuer-scoped binding and the policy path are read from the prefix
    // whose every link really signed the one below it.
    const chain = this.signedPath(leaf, presented);
    const profile = this.profileFor(chain);
    if (!profile) {
      log.debug("Leaving CertificateBinding.identityOf(). No profile.");
      return null;
    }
    const base = { issuedHere: false, outside: true, accepted: false,
                   realm: realmId, profile: profile.id,
                   smartCard: profile.smartCard === true };
    const outside = this.profileRefusal(profile, leaf, chain);
    if (outside) {
      log.info(codes.tag('STS-TLS-0066') + 'certificate_binding: a client ' +
               'certificate covered by the "' + profile.id + '" profile ' +
               'was refused: ' + outside + '.');
      log.debug("Leaving CertificateBinding.identityOf(). Outside.");
      return Object.assign(base, { error: 'NOT_STORED', outsideProfile: true,
        why: 'the certificate is covered by the "' + profile.id + '" ' +
             'certificate sign-in profile and is outside it: ' + outside });
    }
    const answer = this.resolveIn(profile, leaf, chain, realmId);
    log.debug("Leaving CertificateBinding.identityOf(). " +
              (answer.accepted ? 'Bound.' : String(answer.error)));
    return Object.assign(base, answer);
  }

  /**
   * Asks every method of a profile and agrees an answer (header).
   *
   * @param profile - the profile
   * @param leaf - the leaf's DER
   * @param chain - the DER above it, issuer first
   * @param realmId - the realm, for the sentences
   * @returns `{ accepted, kind, username, dn, stored, methods, why }` or
   *   `{ error, why, holders }`
   */
  resolveIn(profile: Json, leaf: Buffer, chain: Buffer[],
            realmId: string): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering CertificateBinding.resolveIn(). " + profile.id);
    const facts = this.factsOf(leaf);
    const issuer = chain.length ? this.factsOf(chain[0]) : null;
    const byDn = new Map<string, Json>();
    const matched: string[] = [];
    const ambiguous: string[] = [];
    const self = this;
    (facts ? profile.bindings : []).forEach(function (method: string) {
      const key = self.keyOf(method, leaf, facts, issuer);
      if (!key) {
        return;
      }
      // `certificate-sha256` is the certificate in `userCertificate` (#1061)
      // OR the same digest stored as a binding: one method, both asked.
      const keys = key.kind === 'stored'
        ? [key, { kind: 'binding', value: 'certificate-sha256:' + key.value }]
        : [key];
      const seen = new Set<string>();
      const holders = ([] as Json[]).concat(...keys.map(function (k: Json) {
        return self.holdersOf(k).filter(function (h: Json) {
          return h && (h.kind === 'person' ||
                       (k.kind === 'stored' && h.kind === 'application'));
        });
      })).filter(function (h: Json) {
        const dn = String(h.dn || '').toLowerCase();
        if (seen.has(dn)) {
          return false;
        }
        seen.add(dn);
        return true;
      });
      if (holders.length > 1) {
        ambiguous.push(method);
      }
      if (holders.length) {
        matched.push(method);
      }
      holders.forEach(function (h: Json) {
        const dn = String(h.dn || '').toLowerCase();
        if (!byDn.has(dn)) {
          byDn.set(dn, { holder: h, methods: [] });
        }
        byDn.get(dn).methods.push(method);
      });
    });
    const people = Array.from(byDn.values());
    if (ambiguous.length || people.length > 1) {
      log.info(codes.tag('STS-TLS-0067') + 'certificate_binding: a client ' +
               'certificate under the "' + profile.id + '" profile names ' +
               people.length + ' accounts (' + (ambiguous.length
                 ? 'ambiguous: ' + ambiguous.join(', ')
                 : 'the methods disagree') + ').');
      log.debug("Leaving CertificateBinding.resolveIn(). Several.");
      return { error: 'STORED_TWICE',
               holders: people.map(function (one: Json): string {
                 return String(one.holder.dn);
               }),
               why: 'the certificate is covered by the "' + profile.id +
                    '" certificate sign-in profile and its bindings name ' +
                    'more than one account of the "' + realmId + '" realm (' +
                    people.map(function (one: Json): string {
                      return String(one.holder.dn) + ' by ' +
                             one.methods.join(' and ');
                    }).join('; ') + '), so it names nobody' };
    }
    if (!people.length) {
      log.info(codes.tag('STS-TLS-0068') + 'certificate_binding: a client ' +
               'certificate under the "' + profile.id + '" profile is ' +
               'bound to nobody (' + profile.bindings.join(', ') + ').');
      log.debug("Leaving CertificateBinding.resolveIn(). Nobody.");
      return { error: 'NOT_STORED',
               why: 'the certificate is covered by the "' + profile.id +
                    '" certificate sign-in profile and none of its bindings ' +
                    '(' + profile.bindings.join(', ') + ') names an account ' +
                    'of the "' + realmId + '" realm; an administrator binds ' +
                    'it on the person\'s entry first (stsCertificateBinding' +
                    (profile.bindings.indexOf('certificate-sha256') >= 0
                      ? ', or the certificate in userCertificate' : '') +
                    ')' };
    }
    const one = people[0];
    const lowOnly = one.methods.every(function (m: string): boolean {
      return LOW_AFFINITY.indexOf(m) >= 0;
    });
    // NEVER A FALLBACK FROM A FAILED HIGH-AFFINITY METHOD (rcbj's decision
    // 1 on #2012, the review): where the profile enables one, a person found
    // by names alone is refused. Names then only corroborate — and a name
    // naming somebody else is still a disagreement, above.
    const highEnabled = profile.bindings.some(function (m: string): boolean {
      return HIGH_AFFINITY.indexOf(m) >= 0;
    });
    if (lowOnly && highEnabled) {
      log.info(codes.tag('STS-TLS-0068') + 'certificate_binding: a client ' +
               'certificate under the "' + profile.id + '" profile matched ' +
               'by name only (' + one.methods.join(', ') + '), and the ' +
               'profile\'s high-affinity bindings matched nobody.');
      log.debug("Leaving CertificateBinding.resolveIn(). Names only.");
      return { error: 'NOT_STORED',
               why: 'the certificate is covered by the "' + profile.id +
                    '" certificate sign-in profile, its high-affinity ' +
                    'bindings name nobody, and a name (' +
                    one.methods.join(', ') + ') is never a fallback from ' +
                    'them' };
    }
    log.debug("Leaving CertificateBinding.resolveIn(). " +
              String(one.holder.id) + ".");
    return { accepted: true, stored: true,
             kind: String(one.holder.kind || 'person'),
             username: String(one.holder.id), dn: String(one.holder.dn),
             methods: one.methods.slice(0), lowAffinity: lowOnly,
             why: 'covered by the "' + profile.id + '" certificate sign-in ' +
                  'profile and bound to ' + String(one.holder.dn) + ' in ' +
                  'the "' + realmId + '" realm by ' +
                  one.methods.join(' and ') };
  }

  // -------------------------------------------------------------------------
  // REVOCATION AT A CERTIFICATE SIGN-IN (header).
  // -------------------------------------------------------------------------
  /**
   * Whether a certificate sign-in in the ambient realm requires a verified
   * revocation status.
   *
   * @returns true where it does
   */
  revocationRequired(): boolean {
    const { log, config: settings, mode: m } = this.deps;
    log.debug("Entering CertificateBinding.revocationRequired().");
    let raw = 'auto';
    try {
      raw = String(settings.value(REVOCATION_SETTING) || 'auto');
    } catch (e) {
      log.debug("Caught in CertificateBinding.revocationRequired(): " +
                ((e && e.message) || e));
      raw = 'auto';
    }
    const required = raw === 'on' || m.refusesUnknownRevocationStatus();
    log.debug("Leaving CertificateBinding.revocationRequired(). " +
              required);
    return required;
  }

  /**
   * Why a certificate sign-in is refused for want of a verified revocation
   * status, or '' where it may go on: nothing where none is required, and
   * otherwise a status of `good` — every link looked up, none on a list.
   * A refused verdict is the revocation refusal's to report, not this.
   *
   * @param verdict - `revocation_status.verdictFor()`'s, or null
   * @returns the sentence, or ''
   */
  revocationRefusal(verdict: Json): string {
    const { log } = this.deps;
    log.debug("Entering CertificateBinding.revocationRefusal().");
    if (!this.revocationRequired() || (verdict && verdict.refused)) {
      log.debug("Leaving CertificateBinding.revocationRefusal(). Not ours.");
      return '';
    }
    const status = verdict ? String(verdict.status || '') : '';
    if (status === 'good') {
      log.debug("Leaving CertificateBinding.revocationRefusal(). Good.");
      return '';
    }
    log.debug("Leaving CertificateBinding.revocationRefusal(). " +
              (status || 'No verdict.'));
    return 'a certificate sign-in here requires a verified revocation ' +
           'status (' + REVOCATION_SETTING + '), and ' +
           (status === 'unchecked'
             ? 'revocation was not consulted (pki.revocationCheck is off)'
             : (status === 'unknown'
               ? 'the status could not be established: ' +
                 String(verdict.why || '')
               : 'no revocation verdict was reached for it'));
  }
}

config.addWriteRule(CertificateBinding.writeRule);

const slot = new InstanceSlot<CertificateBinding>(
  'common/certificate_binding',
  () => new CertificateBinding(CertificateBinding.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Certificate sign-in profiles and their bindings (#2012). A library
 * (rule 3).
 * @namespace
 */
export = {
  CertificateBinding: CertificateBinding,
  HIGH_AFFINITY: HIGH_AFFINITY,
  LOW_AFFINITY: LOW_AFFINITY,
  STORED_METHODS: STORED_METHODS,
  bindingValueOf: CertificateBinding.bindingValueOf,
  canonicalDn: CertificateBinding.canonicalDn,
  hex64: CertificateBinding.hex64,
  profilesProblem: CertificateBinding.profilesProblem,
  installInstance: (instance: CertificateBinding): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  profiles: slot.forward('profiles'),
  profileFor: slot.forward('profileFor'),
  profileRefusal: slot.forward('profileRefusal'),
  identityOf: slot.forward('identityOf'),
  resolveIn: slot.forward('resolveIn'),
  revocationRequired: slot.forward('revocationRequired'),
  revocationRefusal: slot.forward('revocationRefusal')
};
