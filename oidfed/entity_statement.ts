'use strict';
//
// File: entity_statement.ts
//
// ===========================================================================
// THE SIX TYPED JWTS OF OPENID FEDERATION 1.1, SIGNED AND READ (#132, #133,
// 2026-09-23).
//
// Every artifact a federation exchanges is a signed JWT with its own `typ`
// (RFC 8725 section 3.11): an Entity Statement (`entity-statement+jwt`,
// section 3), a Trust Mark (`trust-mark+jwt`, 7) and its delegation
// (`trust-mark-delegation+jwt`, 7.2.1), a Resolve Response
// (`resolve-response+jwt`, 8.3.2), a Trust Mark Status Response
// (`trust-mark-status-response+jwt`, 8.4.2) and a signed JWK Set
// (`jwk-set+jwt`, 8.7.2 and 5.2.1). This file is where each is MADE and
// where a received one is READ: the `typ` exact, the algorithm asymmetric
// and never `none`, a non-empty `kid` naming a key in the JWK Set it is
// checked against, and the signature verified by `common/crypto.js` —
// nothing here computes a signature itself (rule 3r).
//
// **WHICH JWK SET A STATEMENT IS VERIFIED AGAINST IS THE CALLER'S DECISION,
// AND IT IS THE WHOLE SECURITY OF THE FEDERATION.** An Entity Configuration
// verifies against its OWN `jwks` — which proves only that whoever published
// it holds the key it names. What makes that key trustworthy is the
// Subordinate Statement ABOVE it, verified against its issuer's key, and so
// on up to a Trust Anchor whose key was configured out of band.
// `trust_chain.ts` walks that; this file never decides that a key is
// trusted, only that a signature was made by the key the caller named.
//
// ---------------------------------------------------------------------------
// SECTION 3.2, AND WHAT IS CHECKED HERE RATHER THAN IN THE CHAIN.
//
// The claim checks of 3.2 that a statement can fail ON ITS OWN — a missing
// claim, a time out of range, a `crit` naming something not understood, a
// claim in the wrong kind of statement, metadata carrying `null` — are
// `validateClaims()`. The ones that need another statement — `iss` among the
// subject's `authority_hints`, the issuer's key — are the chain's.
//
// A STATIC UTILITY CLASS (#50): it holds no state, reads no setting and
// requires the crypto module, the policy library (for the syntax of
// `constraints` and `metadata_policy`) and the logger.
// ===========================================================================

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import MetadataPolicy = require('./metadata_policy');

type Json = any;

const log = helpers.log;

const TYP = Object.freeze({
  ENTITY_STATEMENT: 'entity-statement+jwt',
  TRUST_MARK: 'trust-mark+jwt',
  TRUST_MARK_DELEGATION: 'trust-mark-delegation+jwt',
  RESOLVE_RESPONSE: 'resolve-response+jwt',
  TRUST_MARK_STATUS: 'trust-mark-status-response+jwt',
  JWK_SET: 'jwk-set+jwt',
  EXPLICIT_REGISTRATION_RESPONSE: 'explicit-registration-response+jwt'
});

// The claims 3.1 defines for Entity Statements. `crit` may not name any of
// them (3.1.1, 13.4).
const DEFINED_CLAIMS = Object.freeze([
  'iss', 'sub', 'iat', 'exp', 'jwks', 'metadata', 'crit', 'authority_hints',
  'trust_anchor_hints', 'trust_marks', 'trust_mark_issuers',
  'trust_mark_owners', 'constraints', 'metadata_policy',
  'metadata_policy_crit', 'source_endpoint'
]);
// Claims that may appear only in an Entity Configuration (3.1.2) and only in
// a Subordinate Statement (3.1.3).
const CONFIGURATION_ONLY = Object.freeze([
  'authority_hints', 'trust_anchor_hints', 'trust_marks',
  'trust_mark_issuers', 'trust_mark_owners'
]);
const SUBORDINATE_ONLY = Object.freeze([
  'constraints', 'metadata_policy', 'metadata_policy_crit', 'source_endpoint'
]);
// The JWK Set parameters 5.2.1 forbids in `federation_entity` metadata.
const NO_JWKS_IN_FEDERATION_ENTITY = Object.freeze([
  'jwks', 'jwks_uri', 'signed_jwks_uri'
]);

const CODE_UNREADABLE = 'STS-OIDFED-0010';
const CODE_TYP = 'STS-OIDFED-0011';
const CODE_ALG = 'STS-OIDFED-0012';
const CODE_KID = 'STS-OIDFED-0013';
const CODE_SIGNATURE = 'STS-OIDFED-0014';
const CODE_CLAIM = 'STS-OIDFED-0015';
const CODE_TIME = 'STS-OIDFED-0016';
const CODE_CRIT = 'STS-OIDFED-0017';
const CODE_PLACEMENT = 'STS-OIDFED-0018';
const CODE_METADATA = 'STS-OIDFED-0019';

interface Read {
  ok: boolean;
  header?: Json;
  claims?: Json;
  key?: Json;
  code?: string;
  why?: string;
}

// What signs: the private key, its algorithm and the `kid` it is published
// under. `federation_keys.ts` hands one out.
interface Signer {
  key: Json;
  alg: string;
  kid: string;
}

class EntityStatement {
  static readonly TYP = TYP;
  static readonly DEFINED_CLAIMS = DEFINED_CLAIMS;

  private static refuse(code: string, why: string): Read {
    log.debug("Entering EntityStatement.refuse(). " + code);
    log.debug("Leaving EntityStatement.refuse().");
    return { ok: false, code: code, why: why };
  }

  // -------------------------------------------------------------------------
  // THE ALGORITHMS A FEDERATION SIGNATURE MAY USE: every asymmetric one
  // `crypto.js` implements, the post-quantum ones included. Never an HMAC —
  // a statement verified against a key its reader also holds proves nothing
  // about who made it — and never `none` (3.2).
  // -------------------------------------------------------------------------
  static acceptedAlgorithms(): string[] {
    log.debug("Entering EntityStatement.acceptedAlgorithms().");
    const out = Object.keys(stsCrypto.JWS_ALGS).filter(function (alg) {
      return (stsCrypto.JWS_ALGS as Json)[alg].family !== 'hmac';
    });
    log.debug("Leaving EntityStatement.acceptedAlgorithms(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // AN ENTITY IDENTIFIER (1.2): an https URL with a host, optionally a port
  // and a path, and NO query and NO fragment. Compared everywhere else as a
  // string, code point for code point (16) — nothing here normalises one.
  // -------------------------------------------------------------------------
  static isEntityId(value: Json): boolean {
    log.debug("Entering EntityStatement.isEntityId().");
    if (typeof value !== 'string' || !value) {
      log.debug("Leaving EntityStatement.isEntityId(). Not a string.");
      return false;
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch (e: any) {
      log.debug("Caught in EntityStatement.isEntityId(): " +
                ((e && e.message) || e));
      log.debug("Leaving EntityStatement.isEntityId(). Not a URL.");
      return false;
    }
    const ok = url.protocol === 'https:' && !!url.hostname &&
               !url.search && !url.hash && value.indexOf('?') < 0 &&
               value.indexOf('#') < 0 && !url.username && !url.password;
    log.debug("Leaving EntityStatement.isEntityId(). " + ok);
    return ok;
  }

  // An https URL with no fragment: what every federation endpoint in
  // `federation_entity` metadata must be (5.1.1). A query is allowed there.
  static isEndpointUrl(value: Json): boolean {
    log.debug("Entering EntityStatement.isEndpointUrl().");
    let ok = false;
    try {
      const url = new URL(String(value));
      ok = typeof value === 'string' && url.protocol === 'https:' &&
           !!url.hostname && !url.hash && value.indexOf('#') < 0;
    } catch (e: any) {
      log.debug("Caught in EntityStatement.isEndpointUrl(): " +
                ((e && e.message) || e));
      ok = false;
    }
    log.debug("Leaving EntityStatement.isEndpointUrl(). " + ok);
    return ok;
  }

  // The configuration endpoint of an Entity Identifier (9): a trailing "/"
  // removed, then `/.well-known/openid-federation` appended.
  static configurationUrlOf(entityId: string): string {
    log.debug("Entering EntityStatement.configurationUrlOf().");
    const out = String(entityId).replace(/\/$/, '') +
                '/.well-known/openid-federation';
    log.debug("Leaving EntityStatement.configurationUrlOf().");
    return out;
  }

  // -------------------------------------------------------------------------
  // READ A COMPACT JWS WITHOUT VERIFYING IT: its header and claims, or why
  // it cannot be read. The first step of every verification, and the whole
  // of what a chain needs to learn WHICH key to verify a statement against
  // (its `iss`) before it can verify it.
  // -------------------------------------------------------------------------
  static decode(jwt: Json): Read {
    log.debug("Entering EntityStatement.decode().");
    const parts = typeof jwt === 'string' ? jwt.split('.') : [];
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
      log.debug("Leaving EntityStatement.decode(). Not a compact JWS.");
      return EntityStatement.refuse(CODE_UNREADABLE,
        'this is not a signed JWT (three dot-separated parts).');
    }
    let header: Json;
    let claims: Json;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url')
        .toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1], 'base64url')
        .toString('utf8'));
    } catch (e: any) {
      log.debug("Caught in EntityStatement.decode(): " +
                ((e && e.message) || e));
      log.debug("Leaving EntityStatement.decode(). Not JSON.");
      return EntityStatement.refuse(CODE_UNREADABLE,
        'the JWT header or claims are not base64url JSON.');
    }
    if (!header || typeof header !== 'object' || Array.isArray(header) ||
        !claims || typeof claims !== 'object' || Array.isArray(claims)) {
      log.debug("Leaving EntityStatement.decode(). Not objects.");
      return EntityStatement.refuse(CODE_UNREADABLE,
        'the JWT header and claims must be JSON objects.');
    }
    log.debug("Leaving EntityStatement.decode(). typ=" + header.typ);
    return { ok: true, header: header, claims: claims };
  }

  // Is this a JWK Set with a unique, non-empty `kid` on every key (3.1.1)?
  static jwksProblem(jwks: Json): string {
    log.debug("Entering EntityStatement.jwksProblem().");
    let problem = '';
    if (!jwks || typeof jwks !== 'object' || !Array.isArray(jwks.keys) ||
        !jwks.keys.length) {
      problem = 'is not a JWK Set with at least one key';
    } else {
      const kids: string[] = [];
      for (let i = 0; i < jwks.keys.length && !problem; i++) {
        const key = jwks.keys[i];
        if (!key || typeof key !== 'object' || typeof key.kty !== 'string') {
          problem = 'holds a member that is not a JWK';
        } else if (typeof key.kid !== 'string' || !key.kid) {
          problem = 'holds a key without a kid';
        } else if (kids.indexOf(key.kid) >= 0) {
          problem = 'holds two keys with the kid "' + key.kid + '"';
        } else if (key.d !== undefined || key.p !== undefined ||
                   key.priv !== undefined || key.k !== undefined) {
          problem = 'holds private or symmetric key material';
        } else {
          kids.push(key.kid);
        }
      }
    }
    log.debug("Leaving EntityStatement.jwksProblem(). " + (problem || 'fine'));
    return problem;
  }

  // -------------------------------------------------------------------------
  // VERIFY A TYPED JWT AGAINST A JWK SET: the `typ` exactly `typ`, the
  // algorithm asymmetric, the `kid` a non-empty string naming EXACTLY one
  // key of the set (3.2 — no fallback to "try every key", which would let a
  // statement name no key and still verify), and the signature
  // `crypto.js`'s. Answers `{ ok, header, claims, key }`.
  // -------------------------------------------------------------------------
  static verify(jwt: Json, jwks: Json, typ: string): Read {
    log.debug("Entering EntityStatement.verify(). typ=" + typ);
    const read = EntityStatement.decode(jwt);
    if (!read.ok) {
      log.debug("Leaving EntityStatement.verify(). Unreadable.");
      return read;
    }
    const header = read.header;
    if (header.typ !== typ) {
      log.debug("Leaving EntityStatement.verify(). Wrong typ.");
      return EntityStatement.refuse(CODE_TYP, 'the JWT is typed "' +
        (header.typ === undefined ? '(none)' : header.typ) + '" and must ' +
        'be "' + typ + '".');
    }
    const accepted = EntityStatement.acceptedAlgorithms();
    if (typeof header.alg !== 'string' || accepted.indexOf(header.alg) < 0) {
      log.debug("Leaving EntityStatement.verify(). Unacceptable alg.");
      return EntityStatement.refuse(CODE_ALG, 'the JWT is signed with "' +
        header.alg + '", which is not an asymmetric algorithm this ' +
        'service verifies.');
    }
    if (typeof header.kid !== 'string' || !header.kid) {
      log.debug("Leaving EntityStatement.verify(). No kid.");
      return EntityStatement.refuse(CODE_KID,
        'the JWT names no kid, which a federation JWT must.');
    }
    const keys = (jwks && Array.isArray(jwks.keys)) ? jwks.keys : [];
    const named = keys.filter(function (one: Json): boolean {
      return one && one.kid === header.kid;
    });
    if (named.length !== 1) {
      log.debug("Leaving EntityStatement.verify(). The kid names no key.");
      return EntityStatement.refuse(CODE_KID, 'the kid "' + header.kid +
        '" names ' + (named.length ? 'more than one key' : 'no key') +
        ' of the issuer\'s JWK Set.');
    }
    const key = named[0];
    try {
      stsCrypto.verifyCompactJws(jwt, key, { algorithms: [header.alg] });
    } catch (e: any) {
      log.debug("Caught in EntityStatement.verify(): " +
                ((e && e.message) || e));
      log.debug("Leaving EntityStatement.verify(). The signature.");
      return EntityStatement.refuse(CODE_SIGNATURE, 'the signature does ' +
        'not verify with the key "' + header.kid + '": ' +
        ((e && e.message) || e));
    }
    log.debug("Leaving EntityStatement.verify(). Verified, kid=" +
              header.kid);
    return { ok: true, header: header, claims: read.claims, key: key };
  }

  // The times of a claim set: `iat` not in the future and `exp` not in the
  // past, each with `skewSec` of leeway (3.2). `exp` optional where
  // `expOptional` (a Trust Mark, 7.1). '' when both hold.
  static timeProblem(claims: Json, nowSec: number, skewSec: number,
                     expOptional?: boolean): string {
    log.debug("Entering EntityStatement.timeProblem().");
    let problem = '';
    if (!Number.isFinite(claims.iat)) {
      problem = 'iat is missing or not a number';
    } else if (claims.iat > nowSec + skewSec) {
      problem = 'iat is in the future';
    } else if (claims.exp === undefined && expOptional) {
      problem = '';
    } else if (!Number.isFinite(claims.exp)) {
      problem = 'exp is missing or not a number';
    } else if (claims.exp <= nowSec - skewSec) {
      problem = 'it expired at ' + new Date(claims.exp * 1000).toISOString();
    }
    log.debug("Leaving EntityStatement.timeProblem(). " + (problem || 'fine'));
    return problem;
  }

  // The syntax of a `metadata` claim (5, 3.2): an object of objects, keyed
  // by entity type, whose top-level members are never `null`, with no JWK
  // Set parameter under `federation_entity` and every federation endpoint
  // there an https URL without a fragment. '' when it is well formed.
  static metadataProblem(metadata: Json): string {
    log.debug("Entering EntityStatement.metadataProblem().");
    let problem = '';
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
      problem = 'metadata is not a JSON object';
    } else {
      const types = Object.keys(metadata);
      for (let i = 0; i < types.length && !problem; i++) {
        const value = metadata[types[i]];
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
          problem = 'metadata.' + types[i] + ' is not a JSON object';
          continue;
        }
        const names = Object.keys(value);
        for (let j = 0; j < names.length && !problem; j++) {
          if (value[names[j]] === null) {
            problem = 'metadata.' + types[i] + '.' + names[j] + ' is null ' +
                      '(5)';
          }
        }
        if (!problem && types[i] === 'federation_entity') {
          const fe = value;
          NO_JWKS_IN_FEDERATION_ENTITY.forEach(function (name: string) {
            if (!problem && fe[name] !== undefined) {
              problem = 'federation_entity metadata may not carry ' + name +
                        ' (5.2.1)';
            }
          });
          Object.keys(fe).filter(function (name: string): boolean {
            return /^federation_.*_endpoint$/.test(name);
          }).forEach(function (name: string): void {
            if (!problem && !EntityStatement.isEndpointUrl(fe[name])) {
              problem = 'federation_entity.' + name + ' is not an https URL ' +
                        'without a fragment (5.1.1)';
            }
          });
        }
      }
    }
    log.debug("Leaving EntityStatement.metadataProblem(). " +
              (problem || 'fine'));
    return problem;
  }

  // The syntax of `trust_marks` (3.1.2, 3.2): objects whose
  // `trust_mark_type` equals the `trust_mark_type` claim of the Trust Mark
  // JWT they carry. Whether the mark is TRUSTED is 7.3's, and separate.
  static trustMarksProblem(marks: Json): string {
    log.debug("Entering EntityStatement.trustMarksProblem().");
    let problem = '';
    if (!Array.isArray(marks)) {
      problem = 'trust_marks is not an array';
    } else {
      for (let i = 0; i < marks.length && !problem; i++) {
        const one = marks[i];
        if (!one || typeof one.trust_mark_type !== 'string' ||
            !one.trust_mark_type || typeof one.trust_mark !== 'string') {
          problem = 'trust_marks[' + i + '] needs a trust_mark_type and a ' +
                    'trust_mark';
          continue;
        }
        const read = EntityStatement.decode(one.trust_mark);
        if (!read.ok || read.claims.trust_mark_type !== one.trust_mark_type) {
          problem = 'trust_marks[' + i + ']\'s trust_mark_type is not the ' +
                    'one its Trust Mark carries';
        }
      }
    }
    log.debug("Leaving EntityStatement.trustMarksProblem(). " +
              (problem || 'fine'));
    return problem;
  }

  // -------------------------------------------------------------------------
  // THE CLAIMS OF AN ENTITY STATEMENT, ON THEIR OWN (3.1, 3.2). `options`:
  //   nowSec, skewSec    the clock and its leeway
  //   understood         claim names this reader processes beyond 3.1's,
  //                      so a `crit` naming one of them is accepted
  //   audience           set only for an EXPLICIT REGISTRATION REQUEST
  //                      (OpenID Federation for OpenID Connect 1.1, 3.1.1,
  //                      12.2.1): the OP's Entity Identifier, which `aud`
  //                      must be and nothing else. Anywhere else an `aud`
  //                      is refused, and a `trust_anchor` always is (3.2 of
  //                      that specification: they belong to the registration
  //                      request and response and to no other statement)
  // The KIND follows from the claims: `iss == sub` is an Entity
  // Configuration, anything else a Subordinate Statement. Answers
  // `{ ok, claims }` or the first problem found.
  // -------------------------------------------------------------------------
  static validateClaims(claims: Json, options: Json): Read {
    log.debug("Entering EntityStatement.validateClaims().");
    const o = options || {};
    const fail = function (code: string, why: string): Read {
      log.debug("Entering fail(). " + code);
      log.debug("Leaving fail().");
      log.debug("Leaving EntityStatement.validateClaims(). " + code);
      return EntityStatement.refuse(code, why);
    };
    if (!EntityStatement.isEntityId(claims.iss)) {
      return fail('STS-OIDFED-0015',
                  'iss is not an Entity Identifier (an https ' +
                  'URL with no query or fragment).');
    }
    if (!EntityStatement.isEntityId(claims.sub)) {
      return fail('STS-OIDFED-0015', 'sub is not an Entity Identifier.');
    }
    const configuration = claims.iss === claims.sub;
    if (claims.aud !== undefined || o.audience !== undefined) {
      const aud = Array.isArray(claims.aud) && claims.aud.length === 1
        ? claims.aud[0] : claims.aud;
      if (o.audience === undefined) {
        return fail('STS-OIDFED-0051', 'aud appears only in an Explicit ' +
                    'Registration request or response (Connect 1.1, 3.2).');
      }
      if (aud !== o.audience) {
        return fail('STS-OIDFED-0051', 'aud must be ' + o.audience +
                    ' and nothing else (Connect 1.1, 3.1.1).');
      }
    }
    if (claims.trust_anchor !== undefined) {
      return fail('STS-OIDFED-0051', 'trust_anchor appears only in an ' +
                  'Explicit Registration response (Connect 1.1, 3.2).');
    }
    const time = EntityStatement.timeProblem(claims, Number(o.nowSec),
                                             Number(o.skewSec) || 0);
    if (time) {
      return fail('STS-OIDFED-0016',
                  'the statement ' + claims.iss + ' made about ' +
                  claims.sub + ': ' + time + ' (3.2).');
    }
    const jwksProblem = EntityStatement.jwksProblem(claims.jwks);
    if (jwksProblem) {
      return fail('STS-OIDFED-0015', 'jwks ' + jwksProblem + ' (3.1.1).');
    }
    if (claims.crit !== undefined) {
      const understood = (o.understood || []).map(String);
      if (!Array.isArray(claims.crit) || !claims.crit.length) {
        return fail('STS-OIDFED-0017',
                    'crit must be a non-empty array (13.4).');
      }
      for (let i = 0; i < claims.crit.length; i++) {
        const name = claims.crit[i];
        if (typeof name !== 'string' || DEFINED_CLAIMS.indexOf(name) >= 0 ||
            claims[name] === undefined || understood.indexOf(name) < 0) {
          return fail('STS-OIDFED-0017',
                      'crit names "' + name + '", which is ' +
                      (DEFINED_CLAIMS.indexOf(name) >= 0
                        ? 'a claim this specification defines'
                        : claims[name] === undefined
                          ? 'not a claim of the statement'
                          : 'a claim this service does not understand') +
                      ' (3.2, 13.4).');
        }
      }
    }
    const misplaced = (configuration ? SUBORDINATE_ONLY : CONFIGURATION_ONLY)
      .filter(function (name: string): boolean {
        return claims[name] !== undefined;
      });
    if (misplaced.length) {
      return fail('STS-OIDFED-0018',
                  misplaced.join(', ') + ' may appear only ' +
                  'in ' + (configuration ? 'a Subordinate Statement'
                                          : 'an Entity Configuration') +
                  ' (3.1.2, 3.1.3).');
    }
    const hintsOf = function (name: string): string {
      log.debug("Entering hintsOf(). " + name);
      const v = claims[name];
      if (v === undefined) {
        log.debug("Leaving hintsOf(). Absent.");
        return '';
      }
      if (!Array.isArray(v) || !v.length ||
          !v.every(EntityStatement.isEntityId)) {
        log.debug("Leaving hintsOf(). Malformed.");
        return name + ' must be a non-empty array of Entity Identifiers ' +
               '(3.1.2)';
      }
      log.debug("Leaving hintsOf().");
      return '';
    };
    const hints = hintsOf('authority_hints') ||
                  hintsOf('trust_anchor_hints');
    if (hints) {
      return fail('STS-OIDFED-0015', hints + '.');
    }
    if (claims.metadata !== undefined) {
      const problem = EntityStatement.metadataProblem(claims.metadata);
      if (problem) {
        return fail('STS-OIDFED-0019', problem + '.');
      }
    }
    if (claims.trust_marks !== undefined) {
      const problem = EntityStatement.trustMarksProblem(claims.trust_marks);
      if (problem) {
        return fail('STS-OIDFED-0015', problem + ' (3.2).');
      }
    }
    if (claims.trust_mark_issuers !== undefined) {
      const tmi = claims.trust_mark_issuers;
      const bad = !tmi || typeof tmi !== 'object' || Array.isArray(tmi) ||
        Object.keys(tmi).some(function (k: string): boolean {
          return !Array.isArray(tmi[k]) ||
                 !tmi[k].every(EntityStatement.isEntityId);
        });
      if (bad) {
        return fail('STS-OIDFED-0015',
                    'trust_mark_issuers must map Trust Mark ' +
                    'types to arrays of Entity Identifiers (3.2).');
      }
    }
    if (claims.trust_mark_owners !== undefined) {
      const tmo = claims.trust_mark_owners;
      const bad = !tmo || typeof tmo !== 'object' || Array.isArray(tmo) ||
        Object.keys(tmo).some(function (k: string): boolean {
          return !tmo[k] || !EntityStatement.isEntityId(tmo[k].sub) ||
                 !!EntityStatement.jwksProblem(tmo[k].jwks);
        });
      if (bad) {
        return fail('STS-OIDFED-0015',
                    'trust_mark_owners must map Trust Mark ' +
                    'types to objects with a sub and a jwks (3.2).');
      }
    }
    if (claims.constraints !== undefined) {
      const problem = MetadataPolicy.constraintsProblem(claims.constraints);
      if (problem) {
        return fail('STS-OIDFED-0015', problem + ' (6.2).');
      }
    }
    if (claims.metadata_policy !== undefined) {
      // The STRUCTURE only: whether a critical operator is understood, and
      // whether the policy merges with its superiors', is the chain's
      // resolution (6.1.4.1), which knows the whole chain's criticals.
      const valid = MetadataPolicy.validate(claims.metadata_policy,
        Array.isArray(claims.metadata_policy_crit)
          ? claims.metadata_policy_crit : []);
      if (!valid.ok) {
        // error-code: none — the policy library's own code, in valid.code
        return fail(valid.code || CODE_METADATA, String(valid.why));
      }
    }
    if (claims.metadata_policy_crit !== undefined) {
      const crit = claims.metadata_policy_crit;
      if (!Array.isArray(crit) || !crit.length ||
          !crit.every(function (one: Json): boolean {
            return typeof one === 'string' &&
                   MetadataPolicy.OPERATORS.indexOf(one) < 0;
          })) {
        return fail('STS-OIDFED-0015',
                    'metadata_policy_crit must be a non-empty ' +
                    'array of operators other than the standard ones (3.1.3).');
      }
    }
    if (claims.source_endpoint !== undefined &&
        !EntityStatement.isEndpointUrl(claims.source_endpoint)) {
      return fail('STS-OIDFED-0015',
                  'source_endpoint is not an https URL (3.2).');
    }
    log.debug("Leaving EntityStatement.validateClaims(). " +
              (configuration ? 'An Entity Configuration.'
                             : 'A Subordinate Statement.'));
    return { ok: true, claims: claims };
  }

  // -------------------------------------------------------------------------
  // SIGN A TYPED FEDERATION JWT with a Federation Entity Key. `payload` is
  // signed as given — the caller sets `iat` and `exp` — and the header is
  // `typ`, the signer's algorithm and its `kid`, which 3, 7, 8.3.2, 8.4.2
  // and 8.7.2 each require. A federation JWT never carries `x5c` or `x5t`:
  // its key is trusted through the chain of statements above it.
  // -------------------------------------------------------------------------
  static sign(payload: Json, typ: string, signer: Signer): string {
    log.debug("Entering EntityStatement.sign(). typ=" + typ + ", alg=" +
              signer.alg);
    // certificate-header: none — a federation JWT's key is trusted through
    // the Subordinate Statements above it (section 4), never an X.509 path.
    const out = stsCrypto.signJws(payload, signer.key,
      { algorithm: signer.alg, keyid: signer.kid, header: { typ: typ } });
    log.debug("Leaving EntityStatement.sign(). " + out.length +
              " characters.");
    return out;
  }
}

export = EntityStatement;
