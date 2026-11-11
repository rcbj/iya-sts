// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_algorithms.ts
//
// ---------------------------------------------------------------------------
// WHICH JWS ALGORITHMS OPENID4VCI AND OPENID4VP OFFER, SIGN WITH AND ACCEPT,
// AND THE WALLET COMPATIBILITY MODE (#657, 2026-11-02).
//
// Every asymmetric JWS algorithm this service holds is offered for the two
// JOSE credential formats (dc+sd-jwt and jwt_vc_json), for the OpenID4VP
// Request Object and for every holder proof — the post-quantum and composite
// ones included. rcbj asked for a switch that turns off what a wallet in use
// today would refuse, or what no published specification defines, as a
// backwards compatibility mode: `oid4vc.walletCompatibility`, off by default,
// per realm.
//
// **WHAT IT TURNS OFF IS THE `pq` FAMILY OF `crypto.js`'s JWS_ALGS, ALL
// ELEVEN**, and the line is drawn there on both of rcbj's tests at once:
//
//   * ML-DSA-44, -65 and -87 are RFC 9964's (IANA-registered JOSE
//     algorithms) — blessed by a specification, and refused by every wallet
//     in use: OpenID4VC HAIP 1.0 has a wallet accept ES256 and names nothing
//     post-quantum;
//   * SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s (draft-ietf-cose-sphincs-plus)
//     and the six composite ML-DSA algorithms
//     (draft-ietf-jose-pq-composite-sigs) are Internet-Drafts, so neither
//     test passes.
//
// The classical algorithms stay: each is in an RFC (7518, 8037, 8812) and
// the ones a HAIP wallet must accept are among them. ES256K is kept although
// HAIP does not name it, because RFC 8812 registers it for JOSE and turning it
// off would change what a classical realm has always offered.
//
// **NOT ldp_vc** (rcbj, #657): its credential is bbs-2023 and its holder
// suites are vc_data_integrity.ts's, which this mode does not touch. **NOT
// ANY OTHER PROTOCOL**: `keys.postQuantumSigning` is the realm-wide switch,
// and this one only narrows further, inside OpenID4VCI and OpenID4VP.
//
// **A SETTING THAT NAMES ONE IS REFUSED, NEVER REPLACED** (`signingRefusal()`,
// STS-VC-0152): a credential signed with ES256 where the operator asked for
// ML-DSA-65 would be a credential nobody asked for, so nothing is signed, the
// keys.postQuantumSigning refusal's arrangement (STS-KEYS-0158).
//
// A static utility class (rule 3): it registers nothing and holds no state.
// ---------------------------------------------------------------------------
import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');

/**
 * Which JWS algorithms OpenID4VCI and OpenID4VP offer, sign with and accept,
 * and the wallet compatibility mode (`oid4vc.walletCompatibility`).
 *
 * A static utility class; it holds no state.
 */
class VcAlgorithms {
  /**
   * Tells whether the realm in force is in wallet compatibility mode.
   *
   * @returns true when `oid4vc.walletCompatibility` is on
   */
  static walletCompatibility(): boolean {
    const log = helpers.log;
    log.debug("Entering VcAlgorithms.walletCompatibility().");
    const on = config.value('oid4vc.walletCompatibility') === true ||
               String(config.value('oid4vc.walletCompatibility')) === 'true';
    log.debug("Leaving VcAlgorithms.walletCompatibility(). " + on);
    return on;
  }

  /**
   * Tells whether the mode turns an algorithm off: a post-quantum or
   * composite one, while `oid4vc.walletCompatibility` is on.
   *
   * @param alg - a JOSE algorithm name
   * @returns true when the algorithm may not be offered, signed or accepted
   */
  static turnedOff(alg: string): boolean {
    const log = helpers.log;
    log.debug("Entering VcAlgorithms.turnedOff(). alg=" + alg);
    const off = stsCrypto.isPqJwsAlg(String(alg || '')) &&
                VcAlgorithms.walletCompatibility();
    log.debug("Leaving VcAlgorithms.turnedOff(). " + off);
    return off;
  }

  /**
   * Narrows a list of JWS algorithms to what this realm offers in OpenID4VCI
   * and OpenID4VP: `helpers.offeredJwsAlgs()` (keys.postQuantumSigning), then
   * the wallet compatibility mode.
   *
   * @param list - the algorithms
   * @returns the ones offered, in the same order
   */
  static offered(list: string[]): string[] {
    const log = helpers.log;
    log.debug("Entering VcAlgorithms.offered().");
    const compatible = VcAlgorithms.walletCompatibility();
    const out = helpers.offeredJwsAlgs(list).filter(function (alg: string) {
      return !(compatible && stsCrypto.isPqJwsAlg(alg));
    });
    log.debug("Leaving VcAlgorithms.offered(). " + out.length);
    return out;
  }

  /**
   * The refusal for a signature this realm was asked to MAKE with an
   * algorithm the mode turns off, or null.
   *
   * @param alg - the algorithm
   * @param asker - what named it: a setting's key, or a sentence
   * @returns an Error carrying `code` STS-VC-0152, or null
   */
  static signingRefusal(alg: string, asker: string): any {
    const log = helpers.log;
    log.debug("Entering VcAlgorithms.signingRefusal(). alg=" + alg);
    if (!VcAlgorithms.turnedOff(alg)) {
      log.debug("Leaving VcAlgorithms.signingRefusal(). Allowed.");
      return null;
    }
    log.error(errorCodes.tag('STS-VC-0152') + 'oid4vc: ' + asker + ' names ' +
              alg + ', and oid4vc.walletCompatibility is on, so nothing is ' +
              'signed with it.');
    const refused: any = new Error(asker + ' names ' + alg + ', a ' +
      'post-quantum algorithm, and this realm is in wallet compatibility ' +
      'mode (oid4vc.walletCompatibility), which signs nothing with one.');
    refused.code = 'STS-VC-0152';
    errorCodes.mark(refused, 'STS-VC-0152');
    log.debug("Leaving VcAlgorithms.signingRefusal(). Refused.");
    return refused;
  }

  /**
   * The refusal for a signature PRESENTED to this realm with an algorithm the
   * mode turns off, or null.
   *
   * @param alg - the `alg` the presented JWS names
   * @param what - what was presented ("the credential", "the KB-JWT")
   * @returns an Error carrying `code` STS-VC-0153, or null
   */
  static acceptanceRefusal(alg: string, what: string): any {
    const log = helpers.log;
    log.debug("Entering VcAlgorithms.acceptanceRefusal(). alg=" + alg);
    if (!VcAlgorithms.turnedOff(alg)) {
      log.debug("Leaving VcAlgorithms.acceptanceRefusal(). Allowed.");
      return null;
    }
    log.info(errorCodes.tag('STS-VC-0153') + 'oid4vc: ' + what + ' is ' +
             'signed with ' + alg + ', which oid4vc.walletCompatibility ' +
             'refuses.');
    const refused: any = new Error(what + ' is signed with ' + alg + ', a ' +
      'post-quantum algorithm, and this realm is in wallet compatibility ' +
      'mode, which accepts none.');
    refused.code = 'STS-VC-0153';
    errorCodes.mark(refused, 'STS-VC-0153');
    log.debug("Leaving VcAlgorithms.acceptanceRefusal(). Refused.");
    return refused;
  }

  /**
   * The `alg` of a compact JWS's protected header, or '' where it cannot be
   * read.
   *
   * @param jws - the compact JWS
   * @returns the algorithm name
   */
  static algOf(jws: unknown): string {
    const log = helpers.log;
    log.debug("Entering VcAlgorithms.algOf().");
    try {
      const header = JSON.parse(Buffer.from(String(jws || '').split('.')[0],
        'base64url').toString('utf8'));
      log.debug("Leaving VcAlgorithms.algOf().");
      return String((header && header.alg) || '');
    } catch (e) {
      log.debug("Caught in VcAlgorithms.algOf(): " + ((e && e.message) || e));
      log.debug("Leaving VcAlgorithms.algOf(). Unreadable.");
      return '';
    }
  }
}

export = VcAlgorithms;
