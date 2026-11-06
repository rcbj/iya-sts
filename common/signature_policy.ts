// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: signature_policy.ts
//
// ===========================================================================
// WHICH ALGORITHM A REALM MAY SIGN WITH OR ACCEPT, ASKED IN ONE PLACE (#1368).
//
// Until this file the same question had three answers. `crypto.js` refused a
// post-quantum JWS in `prepareVerification()` and nowhere else, so a GNAP `jws`
// proof and an HTTP message signature were never asked. `helpers.js` applied
// `keys.signingAlgorithms` and `keys.eddsaSigning` in `signJwtAs()` and not in
// `signJwt()`. Each publisher narrowed its own list. A gate kept beside each
// door is a gate one door forgets, so every door now asks this class, and each
// surface has one chokepoint in `crypto.js` or `helpers.js`.
//
// A LIBRARY (rule 3), and it reads only `config`, `error_codes` and the
// registry, so `crypto.js` may require it and no cycle can form. It needs no
// `realms`: `config.value()` already answers for the ambient realm.
//
// ---------------------------------------------------------------------------
// WHAT THE FAMILY SWITCHES COVER, AND WHAT THEY DO NOT.
//
// `keys.postQuantumSigning` governs JOSE and the HTTP signatures that use a
// JWS name, in both directions. `keys.eddsaSigning` governs JOSE signing only:
// it was never about what this realm accepts (#1292). **Neither touches COSE
// passkeys, XML signatures, TLS or certificate algorithms**, as their rows say:
// a realm with post-quantum signing off and a post-quantum CA must still be
// able to check its own certificates.
//
// `verifyCoseSignature()` is deliberately not a chokepoint: passkeys and
// attestation statements go through it, and WebAuthn keeps its own two lists.
//
// A REFUSAL'S CODE IS MARKED ON THE ERROR AND NEVER PUT IN ITS MESSAGE, because
// callers copy the message into an `error_description` (`error_codes.js`).
// ===========================================================================

import bunyan = require('bunyan');
import config = require('./config');
import algorithmRegistry = require('./crypto_impl/algorithm_registry');

const log = bunyan.createLogger({
  name: 'signature_policy',
  level: config.value('global.logLevel')
});

type Surface = 'jose' | 'httpsig';
type Direction = 'sign' | 'accept';

// Why an algorithm may not be used, or null where it may.
interface Cause {
  code: string;
  message: string;
}

class SignaturePolicy {
  // -------------------------------------------------------------------------
  // THE ANSWERS BELOW ARE A HOT PATH, asked for every signature made or
  // checked, so they carry no Entering/Leaving pair, which would drown the log.
  // -------------------------------------------------------------------------
  /**
   * `keys.signingAlgorithms` as a list, RS256 always in it, in the order
   * configured. OpenID Connect Discovery requires RS256.
   *
   * @returns the list, or null where it is empty: every algorithm the realm
   *   otherwise has
   */
  static joseSignList(): string[] | null {
    const raw: unknown = config.value('keys.signingAlgorithms');
    const list = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: unknown) {
        return String(one).trim();
      })
      .filter(function (one: string) {
        return one.length > 0;
      });
    if (!list.length) {
      return null;
    }
    if (list.indexOf('RS256') < 0) {
      list.push('RS256');
    }
    return list;
  }

  /**
   * @returns whether the ambient realm signs, publishes and verifies the
   *   post-quantum JOSE algorithms (`keys.postQuantumSigning`, on by default)
   */
  static postQuantumOn(): boolean {
    return config.value('keys.postQuantumSigning') !== false;
  }

  /**
   * @returns whether the ambient realm signs with EdDSA and publishes its OKP
   *   signing keys (`keys.eddsaSigning`, off by default)
   */
  static eddsaOn(): boolean {
    return config.value('keys.eddsaSigning') === true;
  }

  // The row a JOSE name means. Ed25519 and Ed448 have no JOSE spelling here but
  // are what a caller may name for an OKP signature.
  private static joseRow(alg: string): any {
    return algorithmRegistry.bySpelling('jose', alg) ||
      algorithmRegistry.byId(alg);
  }

  /**
   * Why the ambient realm may not sign with an algorithm.
   *
   * @param surface - `jose` or `httpsig`
   * @param alg - the surface's name for it
   * @returns the cause, or null where it may. `none` and a name no row has are
   *   null: not a signature here, or the engine's own refusal to make
   */
  static signCause(surface: Surface, alg: string): Cause | null {
    const name = String(alg);
    if (surface === 'httpsig') {
      const row = algorithmRegistry.bySpelling('httpsig', name);
      return row && row.pqc !== null && !SignaturePolicy.postQuantumOn()
        ? { code: 'STS-KEYS-0177',
            message: 'this realm does not sign with ' + name +
              ': keys.postQuantumSigning is off.' }
        : null;
    }
    if (name === 'none') {
      return null;
    }
    const list = SignaturePolicy.joseSignList();
    if (list && list.indexOf(name) < 0) {
      return { code: 'STS-KEYS-0166',
               message: 'this realm does not sign with ' + name +
                 ': keys.signingAlgorithms does not list it.' };
    }
    const row = SignaturePolicy.joseRow(name);
    if (row && row.family === 'okp' && !SignaturePolicy.eddsaOn()) {
      return { code: 'STS-KEYS-0165',
               message: 'this realm does not sign with ' + name +
                 ': keys.eddsaSigning is off, so it publishes no EdDSA key ' +
                 'to verify the signature with.' };
    }
    if (row && row.pqc !== null && !SignaturePolicy.postQuantumOn()) {
      return { code: 'STS-KEYS-0158',
               message: 'this realm does not sign with ' + name +
                 ': keys.postQuantumSigning is off, so it publishes no ' +
                 'post-quantum key to verify the signature with.' };
    }
    return null;
  }

  /**
   * Why the ambient realm may not accept a signature in an algorithm. Asked
   * before any key operation.
   *
   * @param surface - `jose` or `httpsig`
   * @param alg - the surface's name for it
   * @returns the cause, or null where it may
   */
  static acceptCause(surface: Surface, alg: string): Cause | null {
    const name = String(alg);
    const row = algorithmRegistry.bySpelling(surface, name);
    if (!row || row.pqc === null || SignaturePolicy.postQuantumOn()) {
      return null;
    }
    return surface === 'jose'
      ? { code: 'STS-KEYS-0157',
          message: 'this JWS is signed with "' + name + '", a post-quantum ' +
            'algorithm this realm does not accept ' +
            '(keys.postQuantumSigning is off).' }
      : { code: 'STS-KEYS-0176',
          message: 'The signature algorithm ' + name + ' is post-quantum, ' +
            'and this realm does not accept one ' +
            '(keys.postQuantumSigning is off).' };
  }

  /**
   * The algorithms the ambient realm may use on a surface. An empty setting
   * means today's order, not preference order: post-quantum signing is on by
   * default, so preference order would move every default signature to ML-DSA.
   *
   * @param surface - `jose` or `httpsig`
   * @param direction - `sign` or `accept`
   * @returns the surface's names, in order
   */
  static effective(surface: Surface, direction: Direction): string[] {
    log.debug("Entering SignaturePolicy.effective(). " + surface + " " +
              direction);
    const today: string[] = surface === 'jose' ? algorithmRegistry.joseNames()
      : algorithmRegistry.recorded('httpsig')
        .concat(algorithmRegistry.joseNames());
    const list = surface === 'jose' && direction === 'sign'
      ? SignaturePolicy.joseSignList() : null;
    const out = (list || today).filter(function (alg: string) {
      return (direction === 'sign'
        ? SignaturePolicy.signCause(surface, alg)
        : SignaturePolicy.acceptCause(surface, alg)) === null;
    });
    log.debug("Leaving SignaturePolicy.effective(). " + out.length);
    return out;
  }
}

export = SignaturePolicy;
