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
// `coseSign1Sign()` and `coseSign1Verify()` are, for mdoc and the CWTs.
//
// ---------------------------------------------------------------------------
// THE LISTS (phase 4). A surface has an ordered `sign` list and an `accept`
// set, each a setting holding registry row ids. **EMPTY MEANS TODAY**: every
// algorithm the surface otherwise has, in the order it uses now, and each use
// case's own default. Only a configured list's order is a preference. A
// specification's default beats it: RS256 for an ID Token whose client named
// nothing (OpenID Connect Dynamic Client Registration), PS256 or ES256 for
// FAPI.
//
// `keys.pqcOnly` narrows every sign list to its post-quantum rows, or to all of
// the surface's where the list names none, the rule `webauthn.pqcOnly` has. It
// leaves `accept` alone, and it does not touch X.509, whose CA algorithms are
// `pki.*` settings a running hierarchy depends on, or DKIM, which has no
// post-quantum algorithm. **RS256 stays for ID Tokens**, because OpenID Connect
// Discovery requires it in `id_token_signing_alg_values_supported` (rcbj's
// decision on #1368).
//
// **`signJws()` IS NOT A CHOKEPOINT, ON PURPOSE.** The DID, status-list and
// trust-list signers sign with keys their own documents publish, and a refusal
// that low would move what they do by default. A signer asks where it CHOOSES
// its algorithm: `signJwt()`, `signJwtAs()`, `usableSigningAlg()`.
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

type Surface = 'jose' | 'httpsig' | 'cose' | 'xml' | 'di' | 'x509';
type Direction = 'sign' | 'accept';

// Why an algorithm may not be used, or null where it may.
interface Cause {
  code: string;
  message: string;
}

// What a signature is for, where that changes the answer.
interface SignContext {
  idToken?: boolean;
}

// The setting holding each surface's list, and its code when it refuses.
const LISTS: Record<string, any> = {
  jose: { sign: 'keys.signingAlgorithms', signCode: 'STS-KEYS-0166',
          accept: 'keys.acceptedSigningAlgorithms',
          acceptCode: 'STS-KEYS-0179' },
  httpsig: { accept: 'oauth2.httpSignatureAcceptedAlgorithms',
             acceptCode: 'STS-KEYS-0180' },
  cose: { sign: 'cose.algorithms', signCode: 'STS-KEYS-0186',
          accept: 'cose.acceptedAlgorithms', acceptCode: 'STS-KEYS-0181' },
  xml: { sign: 'saml.signatureAlgorithms', signCode: 'STS-KEYS-0187',
         accept: 'saml.acceptedSignatureAlgorithms',
         acceptCode: 'STS-KEYS-0182' },
  di: { sign: 'vc.cryptosuites', signCode: 'STS-KEYS-0188',
        accept: 'vc.acceptedCryptosuites', acceptCode: 'STS-KEYS-0184' },
  x509: { accept: 'pki.acceptedSignatureAlgorithms',
          acceptCode: 'STS-KEYS-0185' }
};

// The surfaces `keys.pqcOnly` narrows.
const PQC_ONLY_SURFACES = ['jose', 'cose', 'xml', 'di'];

// A setting that names the one algorithm a use case signs with, and the list it
// must be within. A value outside it is refused at the write; one that reached
// the store anyway is replaced where it is read (`usableSigningAlg()`).
const CHOSEN: Record<string, { surface: string }> = {
  'oauth2.accessTokenSigningAlg': { surface: 'jose' },
  'oauth2.signedMetadataAlgorithm': { surface: 'jose' },
  'oauth2.httpSignatureResponseAlg': { surface: 'jose' },
  'wstrust.jwtAlgorithm': { surface: 'jose' },
  'ssf.signingAlgorithm': { surface: 'jose' },
  'oidfed.signingAlg': { surface: 'jose' },
  'oid4vci.credentialSigningAlgorithm': { surface: 'jose' },
  'oid4vp.requestObjectSigningAlgorithm': { surface: 'jose' },
  'oid4vp.x509SigningAlgorithm': { surface: 'jose' },
  'gnap.zcapCryptosuite': { surface: 'di' }
};

class SignaturePolicy {
  // -------------------------------------------------------------------------
  // THE ANSWERS BELOW ARE A HOT PATH, asked for every signature made or
  // checked, so they carry no Entering/Leaving pair, which would drown the log.
  // -------------------------------------------------------------------------
  // A csv setting's value as a list. It may be a string where it came from the
  // environment.
  private static parsed(raw: unknown): string[] {
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: unknown) {
        return String(one).trim();
      })
      .filter(function (one: string) {
        return one.length > 0;
      });
  }

  /**
   * `keys.signingAlgorithms` as a list, RS256 always in it, in the order
   * configured. OpenID Connect Discovery requires RS256.
   *
   * @returns the list, or null where it is empty: every algorithm the realm
   *   otherwise has
   */
  static joseSignList(): string[] | null {
    const list = SignaturePolicy.parsed(
      config.value('keys.signingAlgorithms'));
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

  /** @returns whether the ambient realm signs only post-quantum */
  static pqcOnly(): boolean {
    return config.value('keys.pqcOnly') === true;
  }

  // The row a surface's name means. Ed25519 and Ed448 have no JOSE spelling
  // here but are what a caller may name for an OKP signature, and a setting's
  // list names a row by its id.
  private static rowOf(surface: Surface, name: string): any {
    return algorithmRegistry.bySpelling(surface, name) ||
      algorithmRegistry.byId(name);
  }

  // The surface's configured sign list as row ids, or null. Under
  // `keys.pqcOnly` a list naming nothing post-quantum is not a list: every
  // post-quantum row is (webauthn.pqcOnly's rule).
  private static signIds(surface: Surface): string[] | null {
    const lists = LISTS[surface];
    if (!lists || !lists.sign) {
      return null;
    }
    const list = surface === 'jose' ? SignaturePolicy.joseSignList()
      : SignaturePolicy.parsed(config.value(lists.sign));
    if (!list || !list.length) {
      return null;
    }
    if (SignaturePolicy.pqcOnly() &&
        PQC_ONLY_SURFACES.indexOf(surface) >= 0 &&
        !list.some(function (id: string) {
          const row = algorithmRegistry.byId(id);
          return row && row.pqc !== null;
        })) {
      return null;
    }
    return list;
  }

  /**
   * Why the ambient realm may not sign with an algorithm.
   *
   * @param surface - the surface
   * @param alg - the surface's name for it, or its row id
   * @param context - `idToken`, for RS256's place under `keys.pqcOnly`
   * @returns the cause, or null where it may. `none` and a name no row has are
   *   null: not a signature here, or the engine's own refusal to make
   */
  static signCause(surface: Surface, alg: string,
                   context?: SignContext): Cause | null {
    const name = String(alg);
    if (name === 'none') {
      return null;
    }
    const row = SignaturePolicy.rowOf(surface, name);
    if (surface === 'httpsig') {
      return row && row.pqc !== null && !SignaturePolicy.postQuantumOn()
        ? { code: 'STS-KEYS-0177',
            message: 'this realm does not sign with ' + name +
              ': keys.postQuantumSigning is off.' }
        : null;
    }
    const lists = LISTS[surface];
    const ids = SignaturePolicy.signIds(surface);
    if (ids && ids.indexOf(row ? row.id : name) < 0) {
      return { code: lists.signCode,
               message: 'this realm does not sign with ' + name + ': ' +
                 lists.sign + ' does not list it.' };
    }
    if (row && row.pqc === null && SignaturePolicy.pqcOnly() &&
        PQC_ONLY_SURFACES.indexOf(surface) >= 0 &&
        !(context && context.idToken && row.id === 'RS256')) {
      return { code: 'STS-KEYS-0191',
               message: 'this realm does not sign with ' + name +
                 ': keys.pqcOnly is on.' };
    }
    if (surface === 'jose' && row) {
      if (row.family === 'okp' && !SignaturePolicy.eddsaOn()) {
        return { code: 'STS-KEYS-0165',
                 message: 'this realm does not sign with ' + name +
                   ': keys.eddsaSigning is off, so it publishes no EdDSA ' +
                   'key to verify the signature with.' };
      }
      if (row.pqc !== null && !SignaturePolicy.postQuantumOn()) {
        return { code: 'STS-KEYS-0158',
                 message: 'this realm does not sign with ' + name +
                   ': keys.postQuantumSigning is off, so it publishes no ' +
                   'post-quantum key to verify the signature with.' };
      }
    }
    return null;
  }

  /**
   * Why the ambient realm may not accept a signature in an algorithm. Asked
   * before any key operation.
   *
   * @param surface - the surface
   * @param alg - the surface's name for it
   * @returns the cause, or null where it may
   */
  static acceptCause(surface: Surface, alg: string): Cause | null {
    const name = String(alg);
    const row = algorithmRegistry.bySpelling(surface, name);
    if (!row) {
      return null;
    }
    if ((surface === 'jose' || surface === 'httpsig') && row.pqc !== null &&
        !SignaturePolicy.postQuantumOn()) {
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
    const lists = LISTS[surface];
    const accepted = SignaturePolicy.parsed(config.value(lists.accept));
    if (accepted.length && accepted.indexOf(row.id) < 0) {
      return { code: lists.acceptCode,
               message: 'this signature is in ' + row.id + ', which ' +
                 lists.accept + ' does not list.' };
    }
    return null;
  }

  /**
   * Why the ambient realm may not accept an X.509 signature, from what the
   * certificate says. RSASSA-PSS's OID names no hash, so any row it may mean
   * counts unless the caller knows the hash.
   *
   * @param oid - the signature algorithm's object identifier
   * @param hash - the node digest name, where the parameters gave one
   * @returns the cause, or null where it may
   */
  static acceptX509Cause(oid: string, hash?: string): Cause | null {
    const accepted = SignaturePolicy.parsed(
      config.value(LISTS.x509.accept));
    if (!accepted.length) {
      return null;
    }
    const rows = algorithmRegistry.byOid(oid).filter(function (row: any) {
      return !hash || !row.hash || row.hash === hash;
    });
    if (rows.some(function (row: any) {
      return accepted.indexOf(row.id) >= 0;
    })) {
      return null;
    }
    return { code: LISTS.x509.acceptCode,
             message: 'its signature algorithm ' + String(oid) +
               ' is not one pki.acceptedSignatureAlgorithms lists' };
  }

  /**
   * Why the ambient realm may not accept an XML DigestMethod.
   *
   * @param label - the digest's label, as `SHA-256`
   * @returns the cause, or null where it may
   */
  static acceptXmlDigestCause(label: string): Cause | null {
    const accepted = SignaturePolicy.parsed(
      config.value('saml.acceptedDigestAlgorithms'));
    return accepted.length && accepted.indexOf(String(label)) < 0
      ? { code: 'STS-KEYS-0183',
          message: 'the DigestMethod ' + String(label) + ' is not one ' +
            'saml.acceptedDigestAlgorithms lists' }
      : null;
  }

  /**
   * The algorithm a JOSE signature uses where nothing names one: the first
   * usable element of a configured list, else RS256, else, under
   * `keys.pqcOnly`, the first post-quantum one. A specification's own default
   * is its caller's to apply first.
   *
   * @returns the JOSE name
   */
  static defaultJoseAlg(): string {
    const ids = SignaturePolicy.signIds('jose');
    const usable = (ids || ['RS256'].concat(algorithmRegistry.joseNames()))
      .filter(function (alg: string) {
        const row = algorithmRegistry.bySpelling('jose', alg);
        return row && row.family !== 'hmac' &&
          SignaturePolicy.signCause('jose', alg) === null;
      });
    return usable.length ? usable[0] : 'RS256';
  }

  /**
   * The algorithm a setting's choice signs with under `keys.pqcOnly`: its own,
   * unless that flag is what refuses it. Narrower than `usableSigningAlg()`,
   * for a setting whose other refusals are documented as the operator's to
   * avoid (`oid4vci.credentialSigningAlgorithm`).
   *
   * @param alg - the algorithm a setting names
   * @returns the algorithm to sign with
   */
  static underPqcOnly(alg: string): string {
    const cause = SignaturePolicy.signCause('jose', alg);
    return cause && cause.code === 'STS-KEYS-0191'
      ? SignaturePolicy.defaultJoseAlg() : alg;
  }

  /**
   * The row `saml.signatureAlgorithm`'s short name means: the fragment of its
   * URI, which is how every one of them is spelled.
   *
   * @param name - the short name, as `rsa-sha256`
   * @returns the row, or null
   */
  static xmlRowNamed(name: string): any {
    return algorithmRegistry.on('xml').filter(function (row: any) {
      return String(row.xml).split('#')[1] === String(name);
    })[0] || null;
  }

  /**
   * The algorithms the ambient realm may use on a surface. An empty setting
   * means today's order, not preference order: post-quantum signing is on by
   * default, so preference order would move every default signature to ML-DSA.
   *
   * @param surface - the surface
   * @param direction - `sign` or `accept`
   * @returns the surface's names, in order
   */
  static effective(surface: Surface, direction: Direction): string[] {
    log.debug("Entering SignaturePolicy.effective(). " + surface + " " +
              direction);
    const spell = function (id: string): string {
      const row = algorithmRegistry.byId(id);
      return row && row[surface] !== null ? String(row[surface]) : id;
    };
    let today: string[];
    if (surface === 'jose') {
      today = algorithmRegistry.joseNames();
    } else if (surface === 'httpsig') {
      today = algorithmRegistry.recorded('httpsig')
        .concat(algorithmRegistry.joseNames());
    } else {
      today = algorithmRegistry.recorded(surface).map(String);
    }
    const ids = direction === 'sign' ? SignaturePolicy.signIds(surface) : null;
    const out = (ids ? ids.map(spell) : today).filter(function (alg: string) {
      return (direction === 'sign'
        ? SignaturePolicy.signCause(surface, alg)
        : SignaturePolicy.acceptCause(surface, alg)) === null;
    });
    log.debug("Leaving SignaturePolicy.effective(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE WRITE RULE, asked of every door that writes a setting.
  // -------------------------------------------------------------------------
  private static problem(code: string, message: string): any {
    log.debug("Entering SignaturePolicy.problem(). " + code);
    log.debug("Leaving SignaturePolicy.problem().");
    return { code: code, problem: message };
  }

  /**
   * The rule the lists hold at every write. A list names nothing twice; a
   * realm accepts what it signs, so it cannot refuse its own tokens; a setting
   * choosing one algorithm chooses within its list; and `keys.pqcOnly` needs
   * post-quantum signing on.
   *
   * @param key - the setting being written
   * @param value - its value, parsed
   * @param inRealm - whether the write lands in a realm's overrides
   * @param beside - a companion setting's value as this write leaves it
   * @returns `{ problem, code }`, or null
   */
  static writeRule(key: string, value: unknown, inRealm?: boolean,
                   beside?: (other: string) => unknown): any {
    log.debug("Entering SignaturePolicy.writeRule(). " + key);
    const other = function (name: string): unknown {
      log.debug("Entering other(). " + name);
      log.debug("Leaving other().");
      return beside ? beside(name) : config.value(name);
    };
    const surfaces = Object.keys(LISTS);
    for (let i = 0; i < surfaces.length; i++) {
      const lists = LISTS[surfaces[i]];
      const isSign = key === lists.sign;
      const isAccept = key === lists.accept;
      if (!isSign && !isAccept) {
        continue;
      }
      const list = SignaturePolicy.parsed(value);
      if (new Set(list).size !== list.length) {
        log.debug("Leaving SignaturePolicy.writeRule(). A duplicate.");
        return SignaturePolicy.problem('STS-KEYS-0189', '"' + key +
          '" names an algorithm twice.');
      }
      const signs = isSign ? list
        : (lists.sign ? SignaturePolicy.parsed(other(lists.sign)) : []);
      const accepts = isAccept ? list : (lists.accept
        ? SignaturePolicy.parsed(other(lists.accept)) : []);
      // Where nothing is listed to sign with, what the surface signs with by
      // default must still be accepted, or the realm refuses its own tokens.
      const signed = signs.length ? signs
        : (surfaces[i] === 'jose' || surfaces[i] === 'xml' ? ['RS256'] : []);
      const missing = signed.filter(function (id: string) {
        return accepts.length > 0 && accepts.indexOf(id) < 0;
      });
      if (missing.length) {
        log.debug("Leaving SignaturePolicy.writeRule(). Would refuse itself.");
        return SignaturePolicy.problem('STS-KEYS-0190', '"' + lists.accept +
          '" must include what this realm signs with, or it refuses its own ' +
          'signatures: ' + missing.join(', ') + '.');
      }
    }
    const chosen = CHOSEN[key];
    if (chosen && value && value !== 'default') {
      const lists = LISTS[chosen.surface];
      const signs = SignaturePolicy.parsed(other(lists.sign));
      if (signs.length && signs.indexOf(String(value)) < 0 &&
          !(chosen.surface === 'jose' && value === 'RS256')) {
        log.debug("Leaving SignaturePolicy.writeRule(). Outside its list.");
        return SignaturePolicy.problem('STS-KEYS-0192', '"' + key + '" must ' +
          'name an algorithm ' + lists.sign + ' lists; ' + String(value) +
          ' is not one.');
      }
    }
    if (key === 'saml.signatureAlgorithm' ||
        key === 'saml.signatureAlgorithms') {
      const signs = SignaturePolicy.parsed(key === 'saml.signatureAlgorithms'
        ? value : other('saml.signatureAlgorithms'));
      const named = String(key === 'saml.signatureAlgorithm'
        ? value : other('saml.signatureAlgorithm'));
      const row = SignaturePolicy.xmlRowNamed(named);
      if (signs.length && named && row && signs.indexOf(row.id) < 0) {
        log.debug("Leaving SignaturePolicy.writeRule(). SAML outside its " +
                  "list.");
        return SignaturePolicy.problem('STS-KEYS-0192',
          '"saml.signatureAlgorithm" must name an algorithm ' +
          'saml.signatureAlgorithms lists; ' + named + ' is not one.');
      }
    }
    if ((key === 'keys.pqcOnly' && value === true &&
         other('keys.postQuantumSigning') === false) ||
        (key === 'keys.postQuantumSigning' && value === false &&
         other('keys.pqcOnly') === true)) {
      log.debug("Leaving SignaturePolicy.writeRule(). Nothing could sign.");
      return SignaturePolicy.problem('STS-KEYS-0193',
        'keys.pqcOnly cannot be on while keys.postQuantumSigning is off: ' +
        'nothing could sign.');
    }
    if (key === 'tls.signatureAlgorithms' && value) {
      const unknown = String(value).split(':').filter(function (name: string) {
        return name && !algorithmRegistry.bySpelling('tls', name);
      });
      if (unknown.length) {
        log.debug("Leaving SignaturePolicy.writeRule(). An unknown sigalg.");
        return SignaturePolicy.problem('STS-KEYS-0194', '"' + key + '" names ' +
          'what this service has no row for: ' + unknown.join(', ') + '.');
      }
    }
    log.debug("Leaving SignaturePolicy.writeRule().");
    return null;
  }
}

config.addWriteRule(SignaturePolicy.writeRule);

export = SignaturePolicy;
