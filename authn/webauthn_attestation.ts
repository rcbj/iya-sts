'use strict';
// File: webauthn_attestation.ts
//
// ---------------------------------------------------------------------------
// A WEBAUTHN REGISTRATION'S ATTESTATION STATEMENT, VERIFIED (#105,
// 2026-09-23).
//
// Until this file `authn/webauthn.js` decoded the attestation object, read
// `fmt` and `authData`, and never read `attStmt` at all: the statement was
// "parsed, reported and believed", in the words the console used, and the
// AAGUID recorded on a key was whatever the authenticator data claimed. This
// is WebAuthn Level 3 section 7.1 steps 21-25:
//
//   21. the format, by a case-sensitive match against the eight of section 8
//       — `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`,
//       `none`, `apple` and `compound` — and nothing else;
//   22. that format's VERIFICATION PROCEDURE over `attStmt`, the raw
//       authenticator data and the client data hash, which answers an
//       attestation TYPE (section 6.5.3: Basic, Self, AttCA, AnonCA, None)
//       and a trust path;
//   23. the trust anchors, "from a trusted source or from policy": the
//       realm's `webauthn.attestationTrustAnchors`, and the attestation root
//       certificates the FIDO Metadata Service lists for the model — the
//       MDS3 BLOB #62 P5 imports (`risk/risk_datasets.ts`), looked up by
//       AAGUID, or by attestation key identifier for fido-u2f;
//   24. the trustworthiness: None and Self are acceptable only "under
//       Relying Party policy", anything else must chain to an anchor;
//   25. "If the attestation statement is not deemed trustworthy, the
//       Relying Party SHOULD fail the registration ceremony" — or MAY
//       register it as self attestation.
//
// ---------------------------------------------------------------------------
// THE POLICY, AND WHY ITS PRODUCT DEFAULT IS NOT THE STRICTEST VALUE.
//
// `webauthn.attestationPolicy` (read by `webauthn_policy.ts`):
//
//   off                 records the format; verifies nothing. DEVELOPMENT
//                       ONLY, and development's `by-mode`.
//   verify-if-present   product's `by-mode`. Every statement is verified by
//                       its format's procedure and a failure is refused. A
//                       trust path is checked against the anchors; a model
//                       the FIDO Metadata Service LISTS must chain to the
//                       roots MDS lists for it, and one MDS reports
//                       compromised is refused. None and Self are accepted
//                       and recorded as untrusted, and so is a chain that no
//                       anchor this service holds knows anything about —
//                       section 7.1 step 25's note, "treat the credential as
//                       one with self attestation": such a chain proves no
//                       more than a self-signed statement does, and refusing
//                       it would refuse every hardware key in a deployment
//                       that has not loaded MDS.
//   require-trusted     refuses everything that does not chain to an anchor.
//
// **`require-trusted` WAS NOT MADE THE PRODUCT DEFAULT** (the decision
// recorded on #105): synced passkeys — iCloud Keychain, Google Password
// Manager — send `none`, as section 5.4.7 allows, and would all be refused.
// An AAGUID allow-list, a certification level and FIPS each REQUIRE a
// trusted statement whatever the policy says, because each is a claim about
// the authenticator that only a statement chaining to an anchor can make: an
// AAGUID in the authenticator data is otherwise the authenticator's say-so.
//
// ---------------------------------------------------------------------------
// WHAT IS STRICTER THAN THE SPECIFICATION, AND WHY.
//
//   * **The syntax.** Each format's CDDL is a closed map; a statement with a
//     member the format does not define is refused, as is `none` with
//     anything in it. "Valid CBOR conforming to the syntax defined above".
//   * **android-key** reads `origin` and `purpose` from the hardware-enforced
//     list only (the specification's option for a relying party that accepts
//     only TEE keys); `webauthn.attestationAndroidSoftwareKeys` reads the
//     union, with a warning. And `purpose` must be SIGN and nothing else.
//   * **compound** — "decide the appropriate result based on Relying Party
//     policy": every sub-statement must verify. It is trusted when at least
//     one sub-statement is.
//   * **MDS status**: a model is refused when ANY status report ever said
//     REVOKED, USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE or a
//     USER_KEY_*_COMPROMISE — the `compromised` flag #62 P5 computes — not
//     only when the latest one does. MDS3 section 3.1.4 lets a later
//     UPDATE_AVAILABLE address earlier issues for authenticators that took
//     the update, and nothing a registration carries says which firmware a
//     key runs; `risk_datasets.ts` argues the same reading for scoring.
//   * **Revocation** is `revocation_status.verdictFor()` on an anchored
//     chain, under `pki.revocationCheck` — with one exception: a
//     certificate that names no distribution point is not refused for it,
//     because sections 8.2.1 and 8.3.1 make the CRL distribution point
//     OPTIONAL "as the status of many attestation certificates is available
//     through metadata services". What revocation `pki.revocationRequire-
//     DistributionPoint` guards against is, for these certificates, what the
//     MDS status reports above are for.
//
// ---------------------------------------------------------------------------
// THIS IS RULE 3: A LIBRARY. It registers no route. It requires
// `common/config`, `common/helpers`, `common/crypto`, `common/pki`,
// `common/error_codes`, `common/instance_slot` and `./webauthn_policy`, and
// reads the FIDO metadata and revocation through LAZY requires (both load
// more of the service than a verifier should drag in at load). Every codec
// it needs is `crypto.js`'s section 10 and every certificate question
// `pki.js`'s (rcbj's rule of 2026-09-21).
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import errorCodes = require('../common/error_codes');
import webauthnPolicy = require('./webauthn_policy');

const { log } = helpers;

type Json = any;

// The formats, as section 8 names them. The same list `webauthn_policy.ts`
// reports; `tests/webauthn_attestation.js` asserts they agree.
const FORMATS = ['packed', 'tpm', 'android-key', 'android-safetynet',
                 'fido-u2f', 'none', 'apple', 'compound'];

// The OIDs the formats name.
const OID = {
  fidoAaguid: '1.3.6.1.4.1.45724.1.1.4',
  androidKey: '1.3.6.1.4.1.11129.2.1.17',
  appleNonce: '1.2.840.113635.100.8.2',
  tcgAikCertificate: '2.23.133.8.3',
  tpmManufacturer: '2.23.133.2.1',
  tpmModel: '2.23.133.2.2',
  tpmVersion: '2.23.133.2.3'
};

// Android Keymaster's constants (section 8.4).
const KM_ORIGIN_GENERATED = 0;
const KM_PURPOSE_SIGN = 2;

// A SafetyNet response older than this, or this far in the future, is
// refused: the specification defers to Google's documentation, which checks
// `timestampMs` against the time of the request.
const SAFETYNET_WINDOW_MS = 60 * 1000;

// The FIDO certification levels in order (MDS3 section 3.1.4.1); the retired
// FIDO_CERTIFIED counts as L1.
const LEVELS = ['none', 'L1', 'L1plus', 'L2', 'L2plus', 'L3', 'L3plus'];

// How deep a compound statement may nest: one level, since a compound's
// members may not themselves be compound.
const MAX_DEPTH = 1;

// What a format's verification procedure answers (section 7.1 step 22): a
// refusal (`ok` false, its code and the sentence for the page), or the
// attestation type and trust path.
interface StatementResult {
  ok: boolean;
  format: string;
  code?: string;
  why?: string;
  type?: string;              // basic | self | attca | anonca | none | compound
  trustPath?: Buffer[];       // the x5c, leaf first; [] for none and self
  acki?: string;              // fido-u2f's attestation key identifier
  safetynet?: boolean;
  subs?: StatementResult[];
}
type Verified = StatementResult;
type Refusal = StatementResult;

// Everything the verification procedures are given.
interface Context {
  authData: Buffer;
  clientDataHash: Buffer;
  cose: Map<number, any>;
  coseAlg: number;
  credentialJwk: Json;
  aaguid: Buffer;
  credentialId: Buffer;
  rpIdHash: Buffer;
  settings: Json;
}

interface WebauthnAttestationDeps {
  log: typeof helpers.log;
  crypto: typeof stsCrypto;
  pki: typeof pki;
  errorCodes: typeof errorCodes;
  policy: typeof webauthnPolicy;
  now(): number;
  // The FIDO metadata, lazily: `risk/risk_datasets.ts` loads the risk store
  // and its terms, which a verifier has no business loading at require time.
  metadata(): Json;
  // Revocation, lazily for the same reason: it loads the PKI's register.
  revocation(): Json;
}

class WebauthnAttestation {
  static readonly FORMATS = FORMATS;

  constructor(private readonly deps: WebauthnAttestationDeps) {
    deps.log.debug("Entering WebauthnAttestation.constructor().");
    deps.log.debug("Leaving WebauthnAttestation.constructor().");
  }

  static defaultDeps(): WebauthnAttestationDeps {
    helpers.log.debug("Entering WebauthnAttestation.defaultDeps().");
    helpers.log.debug("Leaving WebauthnAttestation.defaultDeps().");
    return {
      log: helpers.log,
      crypto: stsCrypto,
      pki: pki,
      errorCodes: errorCodes,
      policy: webauthnPolicy,
      now: function (): number {
        return Date.now();
      },
      metadata: function (): Json {
        return require('../risk/risk_datasets');
      },
      revocation: function (): Json {
        return require('../common/revocation_status');
      }
    };
  }

  // =========================================================================
  // THE ONE ENTRY POINT. `verdict` is what `webauthn.verifyRegistration()`
  // answered for a ceremony whose own checks passed. Resolves
  //
  //   { ok: true, attestation }            — the record the key carries, or
  //   { ok: false, why, attestation }      — with its code under the Symbol
  //                                          `errorCodes.mark()` uses.
  //
  // Never rejects: a defect here is a refused registration with its own code
  // (STS-AUTHN-0241), never an accepted one.
  // =========================================================================
  async assess(verdict: Json): Promise<Json> {
    const { log, policy, errorCodes } = this.deps;
    log.debug("Entering WebauthnAttestation.assess(). fmt=" +
              (verdict && verdict.fmt));
    const settings = policy.attestationSettings();
    const format = String((verdict && verdict.fmt) || '');
    const base = {
      policy: settings.policy, format: format, type: 'unverified',
      verified: false, trusted: false, anchor: '',
      aaguid: WebauthnAttestation.aaguidString(verdict && verdict.aaguid),
      model: '', certificationLevel: '', mdsStatus: '', mdsVersion: '',
      checkedAt: this.deps.now()
    };
    if (settings.policy === 'off' && !settings.demandsTrust) {
      log.debug("Leaving WebauthnAttestation.assess(). The policy is off.");
      return { ok: true, attestation: base };
    }
    try {
      const out = await this.assessUnder(verdict, settings, base);
      log.debug("Leaving WebauthnAttestation.assess(). ok=" + out.ok);
      return out;
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0241') + 'webauthn: verifying a ' +
                format + ' attestation statement threw: ' +
                ((e && e.stack) || e));
      log.debug("Leaving WebauthnAttestation.assess(). Threw.");
      return errorCodes.mark({ ok: false, attestation: base,
        why: 'The authenticator\'s attestation statement could not be ' +
             'checked: ' + ((e && e.message) || e) }, 'STS-AUTHN-0241');
    }
  }

  private async assessUnder(verdict: Json, settings: Json,
                            base: Json): Promise<Json> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering WebauthnAttestation.assessUnder().");
    const refuse = function (code: string, why: string,
                             extra?: Json): Json {
      log.debug("Entering refuse(). " + code);
      log.debug("Leaving refuse().");
      return errorCodes.mark({ ok: false, why: why,
                               attestation: Object.assign({}, base,
                                                          extra || {}) },
                             code);
    };
    const ctx: Context = {
      authData: Buffer.from(verdict.authDataRaw || []),
      clientDataHash: Buffer.from(verdict.clientDataHash || []),
      cose: verdict.credentialPublicKeyCose,
      coseAlg: Number(verdict.coseAlg),
      credentialJwk: verdict.publicKeyJwk,
      aaguid: Buffer.from(String(verdict.aaguid || ''), 'hex'),
      credentialId: Buffer.from(verdict.credentialIdRaw || []),
      rpIdHash: Buffer.from(verdict.rpIdHash || []),
      settings: settings
    };
    // STEPS 21 AND 22.
    const statement = await this.verifyStatement(base.format,
                                                 verdict.attStmt, ctx, 0);
    if (!statement.ok) {
      log.info('webauthn: a ' + base.format + ' attestation statement was ' +
               'REFUSED: ' + statement.why);
      log.debug("Leaving WebauthnAttestation.assessUnder(). Statement.");
      return refuse(statement.code, 'The authenticator\'s attestation ' +
                    'statement does not verify: ' + statement.why + '.');
    }
    const recorded = Object.assign({}, base, {
      verified: true, type: statement.type });
    // STEP 23: what the FIDO Metadata Service says about the model.
    const listed = await this.modelOf(statement, base.aaguid);
    if (listed) {
      const m = listed.model || {};
      Object.assign(recorded, {
        model: String(m.description || ''),
        certificationLevel: String(m.certificationLevel || ''),
        mdsStatus: String(m.latestStatus || ''),
        mdsVersion: String(listed.version || '') });
      if (m.compromised) {
        log.info('webauthn: a key from "' + recorded.model + '" was REFUSED: ' +
                 'the FIDO Metadata Service reports the model compromised.');
        log.debug("Leaving WebauthnAttestation.assessUnder(). MDS status.");
        return refuse('STS-AUTHN-0237', 'The FIDO Metadata Service reports ' +
                      'this authenticator model (' + (recorded.model ||
                      base.aaguid || 'unnamed') + ') as ' +
                      WebauthnAttestation.compromisedStatuses(m).join(', ') +
                      ', so a key from it is not registered here.',
                      recorded);
      }
    }
    // STEP 24.
    const trust = await this.trustOf(statement, listed, settings);
    if (trust.refusal) {
      log.info('webauthn: a ' + base.format + ' attestation was REFUSED: ' +
               trust.refusal.why);
      log.debug("Leaving WebauthnAttestation.assessUnder(). Trust.");
      return refuse(trust.refusal.code, trust.refusal.why, recorded);
    }
    recorded.trusted = trust.trusted;
    recorded.anchor = trust.anchor;
    // STEP 25, under the policy and the settings that demand trust.
    if (settings.demandsTrust && !trust.trusted) {
      const selfOrNone = ['none', 'self'].indexOf(statement.type) >= 0;
      log.debug("Leaving WebauthnAttestation.assessUnder(). Untrusted.");
      return refuse(selfOrNone ? 'STS-AUTHN-0240' : 'STS-AUTHN-0235',
                    (selfOrNone
                      ? 'The authenticator sent ' +
                        (statement.type === 'none' ? 'no attestation'
                                                   : 'a self attestation') +
                        ', which proves nothing about what made the key'
                      : 'The attestation does not chain to a trust anchor ' +
                        'this realm or the FIDO Metadata Service holds' +
                        (trust.why ? ' (' + trust.why + ')' : '')) +
                    ', and this realm requires a trusted one (' +
                    WebauthnAttestation.demandedBy(settings) + ').',
                    recorded);
    }
    if (settings.allowedAaguids.length &&
        settings.allowedAaguids.indexOf(
          String(base.aaguid).replace(/-/g, '')) < 0) {
      log.debug("Leaving WebauthnAttestation.assessUnder(). AAGUID.");
      return refuse('STS-AUTHN-0236', 'This authenticator model (AAGUID ' +
                    (base.aaguid || 'none') + ') is not one this realm ' +
                    'allows (webauthn.attestationAllowedAaguids).', recorded);
    }
    const levelProblem = WebauthnAttestation.levelProblem(listed, settings);
    if (levelProblem) {
      log.debug("Leaving WebauthnAttestation.assessUnder(). Level.");
      return refuse('STS-AUTHN-0238', levelProblem, recorded);
    }
    log.info('webauthn: a ' + base.format + ' attestation verified (' +
             statement.type + ', ' + (recorded.trusted
               ? 'trusted through ' + recorded.anchor : 'untrusted') +
             (recorded.model ? ', ' + recorded.model : '') + ').');
    log.debug("Leaving WebauthnAttestation.assessUnder(). Accepted.");
    return { ok: true, attestation: recorded };
  }

  // =========================================================================
  // STEP 22: THE FORMAT'S VERIFICATION PROCEDURE.
  // =========================================================================
  async verifyStatement(format: string, attStmt: Json, ctx: Context,
                        depth: number): Promise<StatementResult> {
    const { log } = this.deps;
    log.debug("Entering WebauthnAttestation.verifyStatement(). " + format);
    let out: StatementResult;
    if (FORMATS.indexOf(format) < 0) {
      out = this.fail('STS-AUTHN-0231', format, 'the format "' + format +
                      '" is not one of WebAuthn Level 3 section 8\'s ' +
                      '(' + FORMATS.join(', ') + ')');
    } else if (format === 'packed') {
      out = this.packed(attStmt, ctx);
    } else if (format === 'tpm') {
      out = this.tpm(attStmt, ctx);
    } else if (format === 'android-key') {
      out = this.androidKey(attStmt, ctx);
    } else if (format === 'android-safetynet') {
      out = this.safetynet(attStmt, ctx);
    } else if (format === 'fido-u2f') {
      out = this.fidoU2f(attStmt, ctx);
    } else if (format === 'none') {
      out = this.none(attStmt);
    } else if (format === 'apple') {
      out = this.apple(attStmt, ctx);
    } else {
      out = await this.compound(attStmt, ctx, depth);
    }
    log.debug("Leaving WebauthnAttestation.verifyStatement(). ok=" + out.ok);
    return out;
  }

  // A refusal, with its code and the format it came from.
  private fail(code: string, format: string, why: string): Refusal {
    const { log } = this.deps;
    log.debug("Entering WebauthnAttestation.fail(). " + code);
    log.debug("Leaving WebauthnAttestation.fail().");
    return { ok: false, code: code, why: format + ': ' + why,
             format: format };
  }

  // Is `attStmt` a map with exactly the members its CDDL allows, the
  // `required` ones present? '' or why not (STS-AUTHN-0232).
  private shapeProblem(attStmt: Json, required: string[],
                       optional: string[]): string {
    const { log } = this.deps;
    log.debug("Entering WebauthnAttestation.shapeProblem().");
    if (!attStmt || typeof attStmt !== 'object' || Array.isArray(attStmt) ||
        attStmt instanceof Map || Buffer.isBuffer(attStmt)) {
      log.debug("Leaving WebauthnAttestation.shapeProblem(). Not a map.");
      return 'attStmt is not a map with text keys';
    }
    const allowed = required.concat(optional);
    const extra = Object.keys(attStmt).filter(function (k: string): boolean {
      return allowed.indexOf(k) < 0;
    });
    if (extra.length) {
      log.debug("Leaving WebauthnAttestation.shapeProblem(). Extra.");
      return 'attStmt carries ' + extra.join(', ') + ', which the format ' +
             'does not define';
    }
    const missing = required.filter(function (k: string): boolean {
      return attStmt[k] === undefined;
    });
    if (missing.length) {
      log.debug("Leaving WebauthnAttestation.shapeProblem(). Missing.");
      return 'attStmt has no ' + missing.join(', ');
    }
    const bad = Object.keys(attStmt).filter(function (k: string): boolean {
      const v = attStmt[k];
      if (k === 'alg') {
        return !Number.isInteger(v);
      }
      if (k === 'ver') {
        return typeof v !== 'string' || !v;
      }
      if (k === 'x5c') {
        return !Array.isArray(v) || !v.length ||
               !v.every(function (one: Json): boolean {
                 return Buffer.isBuffer(one) && one.length > 0;
               });
      }
      return !Buffer.isBuffer(v);
    });
    if (bad.length) {
      log.debug("Leaving WebauthnAttestation.shapeProblem(). Types.");
      return bad.join(', ') + ' ' + (bad.length === 1 ? 'is' : 'are') +
             ' not of the type the format defines';
    }
    log.debug("Leaving WebauthnAttestation.shapeProblem().");
    return '';
  }

  // The public key of a certificate, as `crypto.verifyCoseSignature()`
  // takes it — including an ML-DSA key node cannot read.
  private certificateKey(der: Buffer): Json {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.certificateKey().");
    const one = pki.certificateFromDer(der);
    const spki = one ? pki.spkiOf(one) : null;
    log.debug("Leaving WebauthnAttestation.certificateKey().");
    return spki ? crypto.publicKeyFromSpki(spki) : null;
  }

  // The AAGUID extension, where a certificate carries one (sections 8.2.1
  // and 8.3): not critical, and the same AAGUID the authenticator data
  // claims. '' or why not.
  private aaguidExtensionProblem(facts: Json, ctx: Context): string {
    const { log, crypto } = this.deps;
    log.debug("Entering WebauthnAttestation.aaguidExtensionProblem().");
    const ext = facts.extensions[OID.fidoAaguid];
    if (!ext) {
      log.debug("Leaving WebauthnAttestation.aaguidExtensionProblem(). " +
                "None.");
      return '';
    }
    if (ext.critical) {
      log.debug("Leaving WebauthnAttestation.aaguidExtensionProblem(). " +
                "Critical.");
      return 'the certificate\'s id-fido-gen-ce-aaguid extension is ' +
             'marked critical, which section 8.2.1 forbids';
    }
    const aaguid = crypto.fidoAaguidExtension(ext.value);
    if (!aaguid || !aaguid.equals(ctx.aaguid)) {
      log.debug("Leaving WebauthnAttestation.aaguidExtensionProblem(). " +
                "Different.");
      return 'the certificate\'s id-fido-gen-ce-aaguid extension names ' +
             (aaguid ? aaguid.toString('hex') : 'no readable AAGUID') +
             ' and the authenticator data ' + ctx.aaguid.toString('hex');
    }
    log.debug("Leaving WebauthnAttestation.aaguidExtensionProblem().");
    return '';
  }

  // Section 8.2: Basic / AttCA with x5c, Self without.
  private packed(st: Json, ctx: Context): StatementResult {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.packed().");
    const shape = this.shapeProblem(st, ['alg', 'sig'], ['x5c']);
    if (shape) {
      log.debug("Leaving WebauthnAttestation.packed(). Shape.");
      return this.fail('STS-AUTHN-0232', 'packed', shape);
    }
    const signed = Buffer.concat([ctx.authData, ctx.clientDataHash]);
    if (!st.x5c) {
      // SELF ATTESTATION: the credential's own key, and its own algorithm.
      if (st.alg !== ctx.coseAlg) {
        log.debug("Leaving WebauthnAttestation.packed(). Self, alg.");
        return this.fail('STS-AUTHN-0234', 'packed', 'a self attestation ' +
                         'names alg ' + st.alg + ' and the credential key ' +
                         'is ' + ctx.coseAlg);
      }
      if (!crypto.verifyCoseSignature(st.alg, ctx.credentialJwk, signed,
                                      st.sig)) {
        log.debug("Leaving WebauthnAttestation.packed(). Self, signature.");
        return this.fail('STS-AUTHN-0233', 'packed', 'the self attestation ' +
                         'signature does not verify under the credential key');
      }
      log.debug("Leaving WebauthnAttestation.packed(). Self.");
      return { ok: true, format: 'packed', type: 'self', trustPath: [] };
    }
    if (!crypto.verifyCoseSignature(st.alg, this.certificateKey(st.x5c[0]),
                                    signed, st.sig)) {
      log.debug("Leaving WebauthnAttestation.packed(). Signature.");
      return this.fail('STS-AUTHN-0233', 'packed', 'the signature does not ' +
                       'verify under the attestation certificate\'s key ' +
                       'with alg ' + st.alg);
    }
    const facts = pki.attestationCertificateFacts(st.x5c[0]);
    const problem = !facts ? 'the attestation certificate cannot be read'
      : WebauthnAttestation.packedCertificateProblem(facts) ||
        this.aaguidExtensionProblem(facts, ctx);
    if (problem) {
      log.debug("Leaving WebauthnAttestation.packed(). Certificate.");
      return this.fail('STS-AUTHN-0234', 'packed', problem);
    }
    log.debug("Leaving WebauthnAttestation.packed(). Basic.");
    return { ok: true, format: 'packed', type: 'basic',
             trustPath: st.x5c.slice() };
  }

  // Section 8.2.1's requirements of the attestation certificate. '' or why.
  static packedCertificateProblem(facts: Json): string {
    log.debug("Entering WebauthnAttestation.packedCertificateProblem().");
    const s = facts.subject || {};
    let why = '';
    if (facts.version !== 3) {
      why = 'the attestation certificate is version ' + facts.version +
            ', not 3';
    } else if (!/^[A-Za-z]{2}$/.test(String(s.C || ''))) {
      why = 'the attestation certificate\'s subject has no ISO 3166 ' +
            'country (C)';
    } else if (!s.O) {
      why = 'the attestation certificate\'s subject has no vendor (O)';
    } else if (s.OU !== 'Authenticator Attestation') {
      why = 'the attestation certificate\'s subject OU is "' +
            String(s.OU || '') + '", not "Authenticator Attestation"';
    } else if (!s.CN) {
      why = 'the attestation certificate\'s subject has no CN';
    } else if (facts.ca !== false) {
      why = 'the attestation certificate\'s basicConstraints ' +
            (facts.ca === null ? 'is absent' : 'says it is a CA') +
            '; section 8.2.1 requires CA false';
    }
    log.debug("Leaving WebauthnAttestation.packedCertificateProblem().");
    return why;
  }

  // Section 8.3: AttCA through an AIK certificate.
  private tpm(st: Json, ctx: Context): StatementResult {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.tpm().");
    const shape = this.shapeProblem(st, ['ver', 'alg', 'x5c', 'sig',
                                         'certInfo', 'pubArea'], []);
    if (shape) {
      log.debug("Leaving WebauthnAttestation.tpm(). Shape.");
      return this.fail('STS-AUTHN-0232', 'tpm', shape);
    }
    if (st.ver !== '2.0') {
      log.debug("Leaving WebauthnAttestation.tpm(). Version.");
      return this.fail('STS-AUTHN-0232', 'tpm', 'ver is "' + st.ver +
                       '", and only "2.0" is defined');
    }
    let pub = null;
    let attest = null;
    try {
      pub = crypto.tpmParsePublic(st.pubArea);
      attest = crypto.tpmParseAttest(st.certInfo);
    } catch (e) {
      log.debug("Caught in WebauthnAttestation.tpm(): " +
                ((e && e.message) || e));
      log.debug("Leaving WebauthnAttestation.tpm(). Unreadable.");
      return this.fail('STS-AUTHN-0234', 'tpm', 'pubArea or certInfo cannot ' +
                       'be read: ' + ((e && e.message) || e));
    }
    if (!WebauthnAttestation.sameKey(pub.jwk, ctx.credentialJwk)) {
      log.debug("Leaving WebauthnAttestation.tpm(). Different key.");
      return this.fail('STS-AUTHN-0234', 'tpm', 'the key in pubArea is not ' +
                       'the credential public key');
    }
    const facts = pki.attestationCertificateFacts(st.x5c[0]);
    const problem = !facts ? 'the AIK certificate cannot be read'
      : WebauthnAttestation.tpmCertificateProblem(facts) ||
        this.aaguidExtensionProblem(facts, ctx);
    if (problem) {
      log.debug("Leaving WebauthnAttestation.tpm(). Certificate.");
      return this.fail('STS-AUTHN-0234', 'tpm', problem);
    }
    // `sig` is a TPMT_SIGNATURE, as section 8.3 says; Windows has long sent
    // the bare signature inside it, and both are read — a structure is used
    // only when the bytes are exactly one.
    const parsed = crypto.tpmParseSignature(st.sig);
    const signature = parsed ? parsed.signature : st.sig;
    if (!crypto.verifyCoseSignature(st.alg, this.certificateKey(st.x5c[0]),
                                    st.certInfo, signature)) {
      log.debug("Leaving WebauthnAttestation.tpm(). Signature.");
      return this.fail('STS-AUTHN-0233', 'tpm', 'the signature over ' +
                       'certInfo does not verify under the AIK ' +
                       'certificate\'s key with alg ' + st.alg);
    }
    const spec = crypto.coseSignatureAlg(st.alg);
    const expected = spec && spec.hash
      ? nodeCrypto.createHash(spec.hash).update(
          Buffer.concat([ctx.authData, ctx.clientDataHash])).digest()
      : null;
    let why = '';
    if (attest.magic !== crypto.TPM_GENERATED_VALUE) {
      why = 'certInfo\'s magic is not TPM_GENERATED_VALUE';
    } else if (attest.type !== crypto.TPM_ST_ATTEST_CERTIFY) {
      why = 'certInfo is not a TPM_ST_ATTEST_CERTIFY';
    } else if (!expected || !expected.equals(attest.extraData)) {
      why = 'certInfo\'s extraData is not the ' +
            ((spec && spec.hash) || 'alg\'s') + ' hash of ' +
            'authenticatorData ‖ clientDataHash';
    } else {
      let name = null;
      try {
        name = crypto.tpmName(pub);
      } catch (e) {
        log.debug("Caught in WebauthnAttestation.tpm(): " +
                  ((e && e.message) || e));
        // `name` stays null and the check below refuses.
      }
      if (!name || !name.equals(attest.name)) {
        why = 'certInfo\'s attested name is not the Name of pubArea';
      }
    }
    if (why) {
      log.debug("Leaving WebauthnAttestation.tpm(). certInfo.");
      return this.fail('STS-AUTHN-0234', 'tpm', why);
    }
    log.debug("Leaving WebauthnAttestation.tpm(). AttCA.");
    return { ok: true, format: 'tpm', type: 'attca',
             trustPath: st.x5c.slice() };
  }

  // Section 8.3.1's requirements of the AIK certificate. '' or why.
  static tpmCertificateProblem(facts: Json): string {
    log.debug("Entering WebauthnAttestation.tpmCertificateProblem().");
    let why = '';
    const san = facts.sanDirectoryTypes || [];
    if (facts.version !== 3) {
      why = 'the AIK certificate is version ' + facts.version + ', not 3';
    } else if (!facts.subjectEmpty) {
      why = 'the AIK certificate\'s subject is not empty';
    } else if (!facts.extensions['2.5.29.17'] ||
               [OID.tpmManufacturer, OID.tpmModel, OID.tpmVersion]
                 .some(function (oid: string): boolean {
                   return san.indexOf(oid) < 0;
                 })) {
      why = 'the AIK certificate\'s subjectAltName does not name the TPM ' +
            'manufacturer, model and version (TCG EK Credential Profile ' +
            'section 3.2.9)';
    } else if ((facts.eku || []).indexOf(OID.tcgAikCertificate) < 0) {
      why = 'the AIK certificate\'s extended key usage lacks ' +
            'tcg-kp-AIKCertificate (2.23.133.8.3)';
    } else if (facts.ca !== false) {
      why = 'the AIK certificate\'s basicConstraints ' +
            (facts.ca === null ? 'is absent' : 'says it is a CA');
    }
    log.debug("Leaving WebauthnAttestation.tpmCertificateProblem().");
    return why;
  }

  // Section 8.4: Basic, the credential key certified by Android's keystore.
  private androidKey(st: Json, ctx: Context): StatementResult {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.androidKey().");
    const shape = this.shapeProblem(st, ['alg', 'sig', 'x5c'], []);
    if (shape) {
      log.debug("Leaving WebauthnAttestation.androidKey(). Shape.");
      return this.fail('STS-AUTHN-0232', 'android-key', shape);
    }
    const signed = Buffer.concat([ctx.authData, ctx.clientDataHash]);
    if (!crypto.verifyCoseSignature(st.alg, this.certificateKey(st.x5c[0]),
                                    signed, st.sig)) {
      log.debug("Leaving WebauthnAttestation.androidKey(). Signature.");
      return this.fail('STS-AUTHN-0233', 'android-key', 'the signature does ' +
                       'not verify under the first certificate\'s key');
    }
    const facts = pki.attestationCertificateFacts(st.x5c[0]);
    if (!facts || !WebauthnAttestation.sameKey(facts.publicKeyJwk,
                                               ctx.credentialJwk)) {
      log.debug("Leaving WebauthnAttestation.androidKey(). Different key.");
      return this.fail('STS-AUTHN-0234', 'android-key', 'the first ' +
                       'certificate\'s key is not the credential public key');
    }
    const ext = facts.extensions[OID.androidKey];
    let description = null;
    try {
      description = ext ? crypto.androidKeyDescription(ext.value) : null;
    } catch (e) {
      log.debug("Caught in WebauthnAttestation.androidKey(): " +
                ((e && e.message) || e));
      return this.fail('STS-AUTHN-0234', 'android-key',
                       String((e && e.message) || e));
    }
    if (!description) {
      log.debug("Leaving WebauthnAttestation.androidKey(). No extension.");
      return this.fail('STS-AUTHN-0234', 'android-key', 'the certificate ' +
                       'carries no key attestation extension (' +
                       OID.androidKey + ')');
    }
    const lists = ctx.settings.androidSoftwareKeys
      ? [description.teeEnforced, description.softwareEnforced]
      : [description.teeEnforced];
    const origin = lists.map(function (l: Json): Json {
      return l.origin;
    }).filter(function (o: Json): boolean {
      return o !== null && o !== undefined;
    })[0];
    const purposes = lists.reduce(function (all: number[],
                                            l: Json): number[] {
      return all.concat(l.purpose || []);
    }, []);
    let why = '';
    if (!description.attestationChallenge.equals(ctx.clientDataHash)) {
      why = 'the attestationChallenge is not the client data hash';
    } else if (description.softwareEnforced.allApplications ||
               description.teeEnforced.allApplications) {
      why = 'the key is usable by all applications (allApplications), and ' +
            'a credential must be scoped to its RP ID';
    } else if (origin !== KM_ORIGIN_GENERATED) {
      why = 'the key\'s origin is ' + (origin === undefined ? 'not stated'
                                                            : origin) +
            ' in the ' + (ctx.settings.androidSoftwareKeys
                            ? 'authorization lists'
                            : 'hardware-enforced list') +
            ', not KM_ORIGIN_GENERATED';
    } else if (!purposes.length ||
               purposes.some(function (p: number): boolean {
                 return p !== KM_PURPOSE_SIGN;
               })) {
      why = 'the key\'s purpose is ' + (purposes.join(', ') || 'not stated') +
            ', not KM_PURPOSE_SIGN alone';
    }
    if (why) {
      log.debug("Leaving WebauthnAttestation.androidKey(). " + why);
      return this.fail('STS-AUTHN-0234', 'android-key', why);
    }
    log.debug("Leaving WebauthnAttestation.androidKey(). Basic.");
    return { ok: true, format: 'android-key', type: 'basic',
             trustPath: st.x5c.slice() };
  }

  // Section 8.5: Basic, a SafetyNet JWS. Verified, and TRUSTED only where
  // `webauthn.attestationAllowSafetynet` says (see trustOf()).
  private safetynet(st: Json, ctx: Context): StatementResult {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.safetynet().");
    const shape = this.shapeProblem(st, ['ver', 'response'], []);
    if (shape) {
      log.debug("Leaving WebauthnAttestation.safetynet(). Shape.");
      return this.fail('STS-AUTHN-0232', 'android-safetynet', shape);
    }
    const jws = st.response.toString('utf8');
    let header = null;
    try {
      header = JSON.parse(Buffer.from(jws.split('.')[0], 'base64url')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in WebauthnAttestation.safetynet(): " +
                ((e && e.message) || e));
      // `header` stays null and is refused below.
    }
    const x5c = header && Array.isArray(header.x5c)
      ? header.x5c.map(function (one: string): Buffer {
        return Buffer.from(String(one), 'base64');
      }) : [];
    const facts = x5c.length ? pki.attestationCertificateFacts(x5c[0]) : null;
    if (!facts) {
      log.debug("Leaving WebauthnAttestation.safetynet(). No chain.");
      return this.fail('STS-AUTHN-0232', 'android-safetynet', 'the ' +
                       'response is not a JWS carrying an x5c chain');
    }
    if (!/(^|,\s*)DNS:attest\.android\.com(,|$)/.test(facts.subjectAltName) &&
        !/(^|\n)CN=attest\.android\.com(\n|$)/.test(facts.subjectText)) {
      log.debug("Leaving WebauthnAttestation.safetynet(). Not Google's.");
      return this.fail('STS-AUTHN-0234', 'android-safetynet', 'the ' +
                       'response is not signed by attest.android.com');
    }
    let claims = null;
    try {
      claims = crypto.verifyCompactJws(jws, facts.pem,
        { algorithms: ['RS256', 'ES256'] }).claims;
    } catch (e) {
      log.debug("Caught in WebauthnAttestation.safetynet(): " +
                ((e && e.message) || e));
      log.debug("Leaving WebauthnAttestation.safetynet(). Signature.");
      return this.fail('STS-AUTHN-0233', 'android-safetynet', 'the ' +
                       'response\'s signature does not verify: ' +
                       ((e && e.message) || e));
    }
    const nonce = nodeCrypto.createHash('sha256').update(
      Buffer.concat([ctx.authData, ctx.clientDataHash])).digest('base64');
    const at = Number(claims && claims.timestampMs);
    const now = this.deps.now();
    let why = '';
    if (!claims || claims.nonce !== nonce) {
      why = 'the nonce is not the base64 SHA-256 of authenticatorData ‖ ' +
            'clientDataHash';
    } else if (claims.ctsProfileMatch !== true) {
      why = 'ctsProfileMatch is not true: the device failed Android ' +
            'compatibility';
    } else if (!isFinite(at) || at > now + SAFETYNET_WINDOW_MS ||
               at < now - SAFETYNET_WINDOW_MS) {
      why = 'the response\'s timestampMs is not within a minute of now';
    }
    if (why) {
      log.debug("Leaving WebauthnAttestation.safetynet(). " + why);
      return this.fail('STS-AUTHN-0234', 'android-safetynet', why);
    }
    log.debug("Leaving WebauthnAttestation.safetynet(). Basic.");
    return { ok: true, format: 'android-safetynet', type: 'basic',
             trustPath: x5c, safetynet: true };
  }

  // Section 8.6: Basic or AttCA over the U2F registration message.
  private fidoU2f(st: Json, ctx: Context): StatementResult {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.fidoU2f().");
    const shape = this.shapeProblem(st, ['x5c', 'sig'], []);
    if (shape) {
      log.debug("Leaving WebauthnAttestation.fidoU2f(). Shape.");
      return this.fail('STS-AUTHN-0232', 'fido-u2f', shape);
    }
    if (st.x5c.length !== 1) {
      log.debug("Leaving WebauthnAttestation.fidoU2f(). Chain.");
      return this.fail('STS-AUTHN-0232', 'fido-u2f', 'x5c has ' +
                       st.x5c.length + ' certificates, and must have one');
    }
    const facts = pki.attestationCertificateFacts(st.x5c[0]);
    if (!facts || facts.keyType !== 'ec' || facts.curve !== 'prime256v1') {
      log.debug("Leaving WebauthnAttestation.fidoU2f(). Not P-256.");
      return this.fail('STS-AUTHN-0234', 'fido-u2f', 'the attestation ' +
                       'certificate\'s key is not EC P-256');
    }
    const x = ctx.cose instanceof Map ? ctx.cose.get(-2) : null;
    const y = ctx.cose instanceof Map ? ctx.cose.get(-3) : null;
    if (!Buffer.isBuffer(x) || x.length !== 32 || !Buffer.isBuffer(y) ||
        y.length !== 32) {
      log.debug("Leaving WebauthnAttestation.fidoU2f(). Coordinates.");
      return this.fail('STS-AUTHN-0234', 'fido-u2f', 'the credential key ' +
                       'is not a P-256 point with 32-byte coordinates');
    }
    const verificationData = Buffer.concat([
      Buffer.from([0x00]), ctx.rpIdHash, ctx.clientDataHash, ctx.credentialId,
      Buffer.from([0x04]), x, y]);
    if (!crypto.verifyCoseSignature(-7, this.certificateKey(st.x5c[0]),
                                    verificationData, st.sig)) {
      log.debug("Leaving WebauthnAttestation.fidoU2f(). Signature.");
      return this.fail('STS-AUTHN-0233', 'fido-u2f', 'the signature over ' +
                       'the U2F registration message does not verify');
    }
    log.debug("Leaving WebauthnAttestation.fidoU2f(). Basic.");
    return { ok: true, format: 'fido-u2f', type: 'basic',
             trustPath: st.x5c.slice(),
             acki: pki.attestationKeyIdentifier(st.x5c[0]) };
  }

  // Section 8.7: nothing, and it must be nothing.
  private none(st: Json): StatementResult {
    const { log } = this.deps;
    log.debug("Entering WebauthnAttestation.none().");
    const shape = this.shapeProblem(st, [], []);
    if (shape) {
      log.debug("Leaving WebauthnAttestation.none(). Not empty.");
      return this.fail('STS-AUTHN-0232', 'none', shape);
    }
    log.debug("Leaving WebauthnAttestation.none().");
    return { ok: true, format: 'none', type: 'none', trustPath: [] };
  }

  // Section 8.8: AnonCA, a certificate for the credential key with the nonce
  // in it.
  private apple(st: Json, ctx: Context): StatementResult {
    const { log, crypto, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.apple().");
    const shape = this.shapeProblem(st, ['x5c'], []);
    if (shape) {
      log.debug("Leaving WebauthnAttestation.apple(). Shape.");
      return this.fail('STS-AUTHN-0232', 'apple', shape);
    }
    const facts = pki.attestationCertificateFacts(st.x5c[0]);
    const ext = facts ? facts.extensions[OID.appleNonce] : null;
    const nonce = ext ? crypto.appleAttestationNonce(ext.value) : null;
    const expected = nodeCrypto.createHash('sha256').update(
      Buffer.concat([ctx.authData, ctx.clientDataHash])).digest();
    if (!nonce || !nonce.equals(expected)) {
      log.debug("Leaving WebauthnAttestation.apple(). Nonce.");
      return this.fail('STS-AUTHN-0234', 'apple', nonce
        ? 'the certificate\'s nonce is not the SHA-256 of ' +
          'authenticatorData ‖ clientDataHash'
        : 'the certificate carries no nonce extension (' + OID.appleNonce +
          ')');
    }
    if (!WebauthnAttestation.sameKey(facts.publicKeyJwk, ctx.credentialJwk)) {
      log.debug("Leaving WebauthnAttestation.apple(). Different key.");
      return this.fail('STS-AUTHN-0234', 'apple', 'the certificate\'s key ' +
                       'is not the credential public key');
    }
    log.debug("Leaving WebauthnAttestation.apple(). AnonCA.");
    return { ok: true, format: 'apple', type: 'anonca',
             trustPath: st.x5c.slice() };
  }

  // Section 8.9: two or more statements, each verified by its own procedure.
  private async compound(st: Json, ctx: Context,
                         depth: number): Promise<StatementResult> {
    const { log } = this.deps;
    log.debug("Entering WebauthnAttestation.compound().");
    if (depth >= MAX_DEPTH) {
      log.debug("Leaving WebauthnAttestation.compound(). Nested.");
      return this.fail('STS-AUTHN-0232', 'compound', 'a compound statement ' +
                       'may not contain another');
    }
    if (!Array.isArray(st) || st.length < 2) {
      log.debug("Leaving WebauthnAttestation.compound(). Shape.");
      return this.fail('STS-AUTHN-0232', 'compound', 'attStmt is not an ' +
                       'array of at least two statements');
    }
    const subs: Verified[] = [];
    for (let i = 0; i < st.length; i++) {
      const one = st[i];
      if (!one || typeof one !== 'object' || typeof one.fmt !== 'string' ||
          one.fmt === 'compound' || one.attStmt === undefined ||
          Object.keys(one).length !== 2) {
        log.debug("Leaving WebauthnAttestation.compound(). Member " + i + ".");
        return this.fail('STS-AUTHN-0232', 'compound', 'member ' + i +
                         ' is not a { fmt, attStmt } pair of another format');
      }
      const verified = await this.verifyStatement(one.fmt, one.attStmt, ctx,
                                                  depth + 1);
      if (!verified.ok) {
        log.debug("Leaving WebauthnAttestation.compound(). Member failed.");
        return this.fail(verified.code, 'compound', 'member ' + i + ' — ' +
                         verified.why);
      }
      subs.push(verified);
    }
    log.debug("Leaving WebauthnAttestation.compound(). " + subs.length +
              " verified.");
    return { ok: true, format: 'compound', type: 'compound', trustPath: [],
             subs: subs };
  }

  // =========================================================================
  // STEPS 23 AND 24: THE ANCHORS, AND WHETHER THE PATH REACHES ONE.
  // =========================================================================

  // The model the FIDO Metadata Service lists for this statement: by AAGUID,
  // and — for a statement with a certificate and no AAGUID (fido-u2f) — by
  // the attestation certificate's key identifier. null when there is no
  // usable BLOB or it lists nothing; null decides nothing.
  private async modelOf(statement: Verified, aaguid: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering WebauthnAttestation.modelOf().");
    const metadata = this.deps.metadata();
    if (aaguid) {
      const byAaguid = await metadata.lookupAuthenticatorBy('aaguid', aaguid);
      if (byAaguid) {
        log.debug("Leaving WebauthnAttestation.modelOf(). By AAGUID.");
        return byAaguid;
      }
    }
    const leaf = WebauthnAttestation.leafOf(statement);
    const acki = statement.acki ||
      (leaf ? this.deps.pki.attestationKeyIdentifier(leaf) : '');
    const byKey = acki ? await metadata.lookupAuthenticatorBy('acki', acki)
                       : null;
    log.debug("Leaving WebauthnAttestation.modelOf(). " +
              (byKey ? 'By key identifier.' : 'Not listed.'));
    return byKey;
  }

  // Whether the statement is trusted, and through what: `{ trusted, anchor,
  // why, refusal }`. `refusal` is set when the path must be refused
  // outright — a listed model whose chain does not reach MDS's roots, or a
  // revoked certificate — whatever the policy.
  private async trustOf(statement: Verified, listed: Json,
                        settings: Json): Promise<Json> {
    const { log, pki } = this.deps;
    log.debug("Entering WebauthnAttestation.trustOf(). " + statement.type);
    if (statement.type === 'compound') {
      let trusted = null;
      for (const sub of statement.subs || []) {
        const one = await this.trustOf(sub, listed, settings);
        if (one.refusal) {
          log.debug("Leaving WebauthnAttestation.trustOf(). A member.");
          return one;
        }
        if (one.trusted && !trusted) {
          trusted = one;
        }
      }
      log.debug("Leaving WebauthnAttestation.trustOf(). Compound.");
      return trusted || { trusted: false, anchor: '',
                          why: 'no member chains to an anchor' };
    }
    if (!statement.trustPath.length) {
      log.debug("Leaving WebauthnAttestation.trustOf(). No path.");
      return { trusted: false, anchor: '', why: statement.type };
    }
    const configured = pki.certificateBundle(settings.trustAnchorsPem)
      .certificates;
    const fromMds = WebauthnAttestation.mdsRoots(listed);
    const anchors = configured.concat(fromMds);
    const leaf = statement.trustPath[0];
    const rest = statement.trustPath.slice(1);
    const path = anchors.length
      ? await pki.verifyPathToAnchors(leaf, rest, anchors,
                                      { now: this.deps.now() })
      : { ok: false, reason: 'no trust anchor is configured or listed' };
    if (!path.ok) {
      if (fromMds.length) {
        log.debug("Leaving WebauthnAttestation.trustOf(). Not MDS's roots.");
        return { trusted: false, anchor: '', why: path.reason, refusal: {
          code: 'STS-AUTHN-0235',
          why: 'The FIDO Metadata Service lists this authenticator model, ' +
               'and its attestation does not chain to the roots MDS lists ' +
               'for it: ' + path.reason + '.' } };
      }
      log.debug("Leaving WebauthnAttestation.trustOf(). Unanchored.");
      return { trusted: false, anchor: '', why: path.reason };
    }
    const top = path.chain[path.chain.length - 1];
    const anchor = fromMds.some(function (one: Json): boolean {
      return one.der.equals(top.der);
    }) ? 'mds' : 'configured';
    const revocation = await this.revocationOf(path.chain);
    if (revocation) {
      log.debug("Leaving WebauthnAttestation.trustOf(). Revocation.");
      return { trusted: false, anchor: '', why: revocation.why,
               refusal: revocation };
    }
    if (statement.safetynet && !settings.allowSafetynet) {
      log.debug("Leaving WebauthnAttestation.trustOf(). SafetyNet.");
      return { trusted: false, anchor: '',
               why: 'android-safetynet is not trusted here ' +
                    '(webauthn.attestationAllowSafetynet)' };
    }
    log.debug("Leaving WebauthnAttestation.trustOf(). Trusted, " + anchor +
              ".");
    return { trusted: true, anchor: anchor, why: '' };
  }

  // The chain's revocation, through `revocation_status.verdictFor()` — the
  // one reading of "is this certificate revoked" every door here asks —
  // with the header's one exception: an attestation certificate that names
  // no distribution point is not refused for it. null, or the refusal.
  private async revocationOf(chain: Json[]): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering WebauthnAttestation.revocationOf().");
    const verdict = await this.deps.revocation().verdictFor({
      leaf: chain[0].pem,
      chain: chain.slice(1).map(function (one: Json): string {
        return one.pem;
      }),
      verified: true }, { external: 'fetch' });
    if (!verdict || !verdict.refused) {
      log.debug("Leaving WebauthnAttestation.revocationOf(). Good.");
      return null;
    }
    const onlyUnpublished = verdict.status === 'unknown' &&
      (verdict.unknown || []).filter(function (one: Json): boolean {
        return one.refusable || one.invalid;
      }).every(function (one: Json): boolean {
        return one.kind === 'no-distribution-point' && !one.invalid;
      });
    if (onlyUnpublished) {
      log.debug("Leaving WebauthnAttestation.revocationOf(). Publishes " +
                "none, which an attestation certificate may.");
      return null;
    }
    log.debug("Leaving WebauthnAttestation.revocationOf(). Refused.");
    return { code: 'STS-AUTHN-0239',
             why: 'A certificate in the attestation chain is ' +
                  (verdict.status === 'revoked' ? 'REVOKED'
                    : 'of a revocation status that could not be ' +
                      'established') + ': ' + String(verdict.why || '') };
  }

  // =========================================================================
  // SMALL THINGS, STATIC: they read no dependency.
  // =========================================================================

  // The attestation root certificates MDS lists for a model.
  static mdsRoots(listed: Json): Json[] {
    log.debug("Entering WebauthnAttestation.mdsRoots().");
    const statement = listed && listed.model &&
      listed.model.metadataStatement;
    const roots = statement && Array.isArray(
      statement.attestationRootCertificates)
      ? statement.attestationRootCertificates : [];
    const out = roots.map(function (b64: string): Json {
      return pki.certificateFromDer(Buffer.from(String(b64), 'base64'));
    }).filter(function (one: Json): boolean {
      return !!one;
    });
    log.debug("Leaving WebauthnAttestation.mdsRoots(). " + out.length + ".");
    return out;
  }

  // The first certificate a statement carries, for a compound its first
  // member's; null for none and self.
  static leafOf(statement: Verified): Buffer {
    log.debug("Entering WebauthnAttestation.leafOf().");
    if (statement.trustPath.length) {
      log.debug("Leaving WebauthnAttestation.leafOf().");
      return statement.trustPath[0];
    }
    const withPath = (statement.subs || []).filter(function (s: Verified):
        boolean {
      return s.trustPath.length > 0;
    })[0];
    log.debug("Leaving WebauthnAttestation.leafOf().");
    return withPath ? withPath.trustPath[0] : null;
  }

  // The statuses that make a model compromised, for the sentence.
  static compromisedStatuses(model: Json): string[] {
    log.debug("Entering WebauthnAttestation.compromisedStatuses().");
    const bad = ['REVOKED', 'USER_VERIFICATION_BYPASS',
                 'ATTESTATION_KEY_COMPROMISE', 'USER_KEY_REMOTE_COMPROMISE',
                 'USER_KEY_PHYSICAL_COMPROMISE'];
    const seen = (model.statusReports || []).map(function (r: Json): string {
      return String(r.status || '');
    }).filter(function (s: string, at: number, all: string[]): boolean {
      return bad.indexOf(s) >= 0 && all.indexOf(s) === at;
    });
    log.debug("Leaving WebauthnAttestation.compromisedStatuses().");
    return seen.length ? seen : ['compromised'];
  }

  // Which settings demand a trusted statement, for the sentence.
  static demandedBy(settings: Json): string {
    log.debug("Entering WebauthnAttestation.demandedBy().");
    const why = [];
    if (settings.policy === 'require-trusted') {
      why.push('webauthn.attestationPolicy is require-trusted');
    }
    if (settings.allowedAaguids.length) {
      why.push('webauthn.attestationAllowedAaguids is set');
    }
    if (settings.minCertificationLevel !== 'none') {
      why.push('webauthn.attestationMinCertificationLevel is ' +
               settings.minCertificationLevel);
    }
    if (settings.requireFips) {
      why.push('webauthn.attestationRequireFips is on');
    }
    log.debug("Leaving WebauthnAttestation.demandedBy().");
    return why.join('; ');
  }

  // A certification level or FIPS the model does not meet, as a sentence;
  // '' when none is demanded or the model meets it.
  static levelProblem(listed: Json, settings: Json): string {
    log.debug("Entering WebauthnAttestation.levelProblem().");
    const wantLevel = settings.minCertificationLevel !== 'none';
    if (!wantLevel && !settings.requireFips) {
      log.debug("Leaving WebauthnAttestation.levelProblem(). None asked.");
      return '';
    }
    if (!listed) {
      log.debug("Leaving WebauthnAttestation.levelProblem(). Not listed.");
      return 'The FIDO Metadata Service does not list this authenticator ' +
             'model, so its certification cannot be known, and this realm ' +
             'requires ' + WebauthnAttestation.demandedBy(settings) + '.';
    }
    const m = listed.model || {};
    if (wantLevel) {
      const held = String(m.certificationLevel || '')
        .replace(/^FIDO_CERTIFIED_?/, '') || (m.certificationLevel ? 'L1'
                                                                    : 'none');
      if (LEVELS.indexOf(held) < LEVELS.indexOf(
            settings.minCertificationLevel)) {
        log.debug("Leaving WebauthnAttestation.levelProblem(). Level.");
        return 'This authenticator model is certified at ' + held +
               ' and this realm requires at least ' +
               settings.minCertificationLevel +
               ' (webauthn.attestationMinCertificationLevel).';
      }
    }
    if (settings.requireFips && !(m.statusReports || []).some(
          function (r: Json): boolean {
            return /^FIPS140_CERTIFIED_L/.test(String(r.status || ''));
          })) {
      log.debug("Leaving WebauthnAttestation.levelProblem(). FIPS.");
      return 'The FIDO Metadata Service reports no FIPS 140 certification ' +
             'for this authenticator model, and this realm requires one ' +
             '(webauthn.attestationRequireFips).';
    }
    log.debug("Leaving WebauthnAttestation.levelProblem().");
    return '';
  }

  // Two public keys as JWKs, compared by their defining members.
  static sameKey(a: Json, b: Json): boolean {
    log.debug("Entering WebauthnAttestation.sameKey().");
    if (!a || !b || a.kty !== b.kty) {
      log.debug("Leaving WebauthnAttestation.sameKey(). Different types.");
      return false;
    }
    const trim = function (v: Json): string {
      log.debug("Entering trim().");
      log.debug("Leaving trim().");
      return Buffer.from(String(v || ''), 'base64url').toString('hex')
        .replace(/^(00)+/, '');
    };
    const members = a.kty === 'RSA' ? ['n', 'e']
      : (a.kty === 'EC' ? ['crv', 'x', 'y']
        : (a.kty === 'OKP' ? ['crv', 'x'] : ['pub']));
    const same = members.every(function (k: string): boolean {
      return k === 'crv' ? a.crv === b.crv : trim(a[k]) === trim(b[k]);
    });
    log.debug("Leaving WebauthnAttestation.sameKey(). " + same);
    return same;
  }

  // An AAGUID as a UUID string; '' for none or the all-zero one.
  static aaguidString(value: Json): string {
    log.debug("Entering WebauthnAttestation.aaguidString().");
    const hex = String(value || '').toLowerCase().replace(/-/g, '');
    if (!/^[0-9a-f]{32}$/.test(hex) || /^0+$/.test(hex)) {
      log.debug("Leaving WebauthnAttestation.aaguidString(). None.");
      return '';
    }
    log.debug("Leaving WebauthnAttestation.aaguidString().");
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' +
      hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), with facades for
// the JavaScript callers and the tests — `webauthn_policy.ts`'s arrangement.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<WebauthnAttestation>(
  'authn/webauthn_attestation',
  () => new WebauthnAttestation(WebauthnAttestation.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  WebauthnAttestation: WebauthnAttestation,
  installInstance: (instance: WebauthnAttestation): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  assess: slot.forward('assess'),
  verifyStatement: slot.forward('verifyStatement'),
  FORMATS: FORMATS,
  sameKey: WebauthnAttestation.sameKey,
  packedCertificateProblem: WebauthnAttestation.packedCertificateProblem,
  tpmCertificateProblem: WebauthnAttestation.tpmCertificateProblem
};
