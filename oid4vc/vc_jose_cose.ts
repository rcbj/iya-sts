'use strict';
//
// File: vc_jose_cose.ts
//
// ---------------------------------------------------------------------------
// SECURING VERIFIABLE CREDENTIALS USING JOSE AND COSE (#198, 2026-09-26) —
// the W3C Recommendation's ENVELOPING mechanisms, for credentials and
// presentations in the VC Data Model 2.0: `vc+jwt` / `vp+jwt` (section 3.1,
// a JWS whose payload IS the credential), `vc+sd-jwt` / `vp+sd-jwt`
// (section 3.2, an SD-JWT, RFC 9901, over the same), and `vc+cose` /
// `vp+cose` (section 3.3, a COSE_Sign1, RFC 9052).
//
// This issuer's `jwt_vc_json` is the OLDER model — a VCDM 1.1 credential in
// a `vc` claim of a JWT (OpenID4VCI Appendix A.1) — and this specification
// says a VCDM 2.0 credential secured this way carries NEITHER a `vc` nor a
// `vp` claim (section 3.1.1): the payload is the document. So nothing here
// replaces or reads `jwt_vc_json`; the two are different formats and each
// verifier keeps its own.
//
// WHAT A VERIFICATION REFUSES, each a sentence of the Recommendation or of
// the RFCs it builds on:
//
//   * a media type that is not this mechanism's — `typ` `vc+jwt` (JWT),
//     `vc+sd-jwt` (SD-JWT), protected header 16 `application/vc+cose` and 3
//     `application/vc` (COSE), and the `vp` forms for a presentation;
//   * a signature that does not verify, or an algorithm outside the list
//     (`ALGORITHMS`: the asymmetric ones this service holds keys of);
//   * a `vc` or `vp` claim (3.1.1), and a payload that is not a conforming
//     credential or presentation (`vc_data_model.ts`);
//   * an `exp` passed or an `nbf` not reached (RFC 7519 sections 4.1.4 and
//     4.1.5 — MUSTs), with the clock allowance every JWT here gets;
//   * for an SD-JWT, every step of RFC 9901 section 7.1: `_sd_alg` one this
//     verifier supports (sha-256), each Disclosure well formed and
//     referenced exactly once, no digest twice, no Disclosure naming `_sd`
//     or `...` or a claim already present;
//   * for a presentation, any enveloped credential inside it that fails the
//     same checks.
//
// `iat` IS NOT A VALIDITY CLAIM, and a malformed one is a warning, not a
// refusal: RFC 7519 section 4.1.6 says what it must be and asks nothing of a
// verifier about it, and the W3C suite's own credential fixtures carry an
// XML Schema date there.
//
// THE KEY. A caller may name the verification method (a public JWK, the
// VC-API adapter's `options.verificationMethod`, refused if it carries a
// private member); otherwise the `kid` must be a did:key or did:jwk URL,
// resolved from the identifier with nothing fetched — which is what this
// service's own envelopes carry (`realmKeyFor()`'s verification method).
//
// A LIBRARY (rule 3): no route. JWS is `common/crypto.js`'s, COSE_Sign1 and
// CBOR `vc_status_codec.ts`'s.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');
import codec = require('./vc_status_codec');
import vcDataModel = require('./vc_data_model');
import vcDataIntegrity = require('./vc_data_integrity');

interface VcJoseCoseDeps {
  log: typeof helpers.log;
  stsCrypto: typeof stsCrypto;
  codec: typeof codec;
  model: typeof vcDataModel;
  resolveVerificationMethod: (vm: string) => { jwk: any; controller: string };
  now: () => number;
  clockSkewS: () => number;
}

// The asymmetric algorithms a signature here may be made with.
const ALGORITHMS = ['ES256', 'ES384', 'ES512', 'EdDSA', 'PS256', 'PS384',
                    'PS512', 'RS256', 'RS384', 'RS512'];

const MEDIA = {
  vc: { jwt: 'vc+jwt', sdjwt: 'vc+sd-jwt', cose: 'application/vc+cose',
        content: 'application/vc', cty: 'vc',
        envelope: 'EnvelopedVerifiableCredential' },
  vp: { jwt: 'vp+jwt', sdjwt: 'vp+sd-jwt', cose: 'application/vp+cose',
        content: 'application/vp', cty: 'vp',
        envelope: 'EnvelopedVerifiablePresentation' }
};

// The data: URL media types an envelope's id may carry, and the form each
// is. `application/jwt` is accepted as the legacy spelling of vc+jwt that
// the VC Data Model's own examples used.
const DATA_TYPES: Record<string, { form: string; kind: string }> = {
  'application/vc+jwt': { form: 'jwt', kind: 'vc' },
  'application/vp+jwt': { form: 'jwt', kind: 'vp' },
  'application/vc+sd-jwt': { form: 'sdjwt', kind: 'vc' },
  'application/vp+sd-jwt': { form: 'sdjwt', kind: 'vp' },
  'application/vc+cose': { form: 'cose', kind: 'vc' },
  'application/vp+cose': { form: 'cose', kind: 'vp' }
};

const V2 = 'https://www.w3.org/ns/credentials/v2';

class VcJoseCose {
  static readonly ALGORITHMS = ALGORITHMS;
  static readonly MEDIA = MEDIA;

  constructor(private readonly deps: VcJoseCoseDeps) {
    deps.log.debug("Entering VcJoseCose.constructor().");
    deps.log.debug("Leaving VcJoseCose.constructor().");
  }

  static defaultDeps(): VcJoseCoseDeps {
    helpers.log.debug("Entering VcJoseCose.defaultDeps().");
    helpers.log.debug("Leaving VcJoseCose.defaultDeps().");
    return {
      log: helpers.log,
      stsCrypto: stsCrypto,
      codec: codec,
      model: vcDataModel,
      resolveVerificationMethod: function resolveVerificationMethod(
        vm: string): { jwk: any; controller: string } {
        helpers.log.debug("Entering resolveVerificationMethod().");
        helpers.log.debug("Leaving resolveVerificationMethod().");
        return vcDataIntegrity.resolveVerificationMethod(vm);
      },
      now: function now(): number {
        helpers.log.debug("Entering now().");
        helpers.log.debug("Leaving now().");
        return Date.now();
      },
      clockSkewS: function clockSkewS(): number {
        helpers.log.debug("Entering clockSkewS().");
        helpers.log.debug("Leaving clockSkewS().");
        return Number(stsCrypto.tokenClockSkew()) || 0;
      }
    };
  }

  // The JWS algorithm a key signs with.
  algFor(jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.algFor().");
    const k = jwk || {};
    const alg = k.kty === 'OKP' ? 'EdDSA'
      : (k.crv === 'P-384' ? 'ES384' : (k.crv === 'P-521' ? 'ES512'
      : 'ES256'));
    log.debug("Leaving VcJoseCose.algFor(). " + alg);
    return alg;
  }

  // ---------------------------------------------------------------------------
  // SECURING. `signer`: { privateKey, publicJwk, kid } — the kid a
  // verification method URL.
  // ---------------------------------------------------------------------------
  async secureJwt(document: any, kind: 'vc' | 'vp', signer: any):
    Promise<string> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcJoseCose.secureJwt(). " + kind);
    const alg = this.algFor(signer.publicJwk);
    const token = await stsCrypto.signJwsAsync(document, signer.privateKey, {
      algorithm: alg,
      header: { alg: alg, kid: signer.kid, typ: MEDIA[kind].jwt,
                cty: MEDIA[kind].cty } });
    log.debug("Leaving VcJoseCose.secureJwt().");
    return token;
  }

  async secureCose(document: any, kind: 'vc' | 'vp', signer: any):
    Promise<Buffer> {
    const { log, codec } = this.deps;
    log.debug("Entering VcJoseCose.secureCose(). " + kind);
    const alg = this.algFor(signer.publicJwk);
    const out = await codec.coseSign1SignAsync({
      alg: alg, key: signer.privateKey,
      payload: Buffer.from(JSON.stringify(document), 'utf8'),
      protectedHeader: new Map<number, unknown>([
        [3, MEDIA[kind].content],
        [4, Buffer.from(String(signer.kid), 'utf8')],
        [16, MEDIA[kind].cose]]) } as any);
    log.debug("Leaving VcJoseCose.secureCose().");
    return out;
  }

  // A disclosure path, `a.b[2].c`, as segments.
  parsePath(path: unknown): (string | number)[] {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.parsePath().");
    const text = String(path || '');
    const out: (string | number)[] = [];
    const re = /([^.[\]]+)|\[(\d+)\]/g;
    let m: RegExpExecArray;
    while ((m = re.exec(text)) !== null) {
      out.push(m[2] !== undefined ? parseInt(m[2], 10) : m[1]);
    }
    if (!out.length) {
      log.debug("Leaving VcJoseCose.parsePath(). Empty.");
      throw new Error('"' + text + '" is not a disclosure path.');
    }
    log.debug("Leaving VcJoseCose.parsePath().");
    return out;
  }

  private digestOf(disclosure: string): string {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.digestOf().");
    log.debug("Leaving VcJoseCose.digestOf().");
    return crypto.createHash('sha256').update(disclosure, 'ascii')
      .digest('base64url');
  }

  // ---------------------------------------------------------------------------
  // AN SD-JWT OVER THE DOCUMENT (RFC 9901 section 4), each path in `paths`
  // made selectively disclosable: an object member becomes a digest in its
  // parent's `_sd`, an array element an `{"...": digest}`. Deeper paths
  // first, so a member of a disclosed object is itself disclosable.
  // ---------------------------------------------------------------------------
  async secureSdJwt(document: any, kind: 'vc' | 'vp', signer: any,
                    paths: string[]): Promise<string> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcJoseCose.secureSdJwt(). " + kind + ", " +
              (paths || []).length + " path(s).");
    const payload = JSON.parse(JSON.stringify(document));
    const parsed = (paths || []).map((p) => this.parsePath(p));
    parsed.sort(function (a, b) {
      return b.length - a.length;
    });
    const disclosures: string[] = [];
    for (const segments of parsed) {
      let parent: any = payload;
      for (let i = 0; i < segments.length - 1; i++) {
        parent = parent === null || parent === undefined ? undefined
                                                         : parent[segments[i]];
      }
      const last = segments[segments.length - 1];
      if (!parent || typeof parent !== 'object' ||
          parent[last] === undefined) {
        log.debug("Leaving VcJoseCose.secureSdJwt(). No such member.");
        throw new Error('the disclosure path "' + segments.join('.') +
                        '" names nothing in the document.');
      }
      if (parent === payload && ['@context', 'type', 'issuer']
          .indexOf(String(last)) >= 0 && kind === 'vc') {
        log.debug("Leaving VcJoseCose.secureSdJwt(). Mandatory member.");
        throw new Error('"' + last + '" is mandatory to disclose ' +
                        '(VC-JOSE-COSE section 3.2.1).');
      }
      const salt = crypto.randomBytes(16).toString('base64url');
      if (typeof last === 'number') {
        if (!Array.isArray(parent)) {
          throw new Error('"' + segments.join('.') + '" indexes a ' +
                          'non-array.');
        }
        const d = Buffer.from(JSON.stringify([salt, parent[last]]), 'utf8')
          .toString('base64url');
        disclosures.push(d);
        parent[last] = { '...': this.digestOf(d) };
      } else {
        const d = Buffer.from(JSON.stringify([salt, last, parent[last]]),
                              'utf8').toString('base64url');
        disclosures.push(d);
        delete parent[last];
        parent._sd = (parent._sd || []).concat([this.digestOf(d)]).sort();
      }
    }
    payload._sd_alg = 'sha-256';
    const alg = this.algFor(signer.publicJwk);
    const jwt = await stsCrypto.signJwsAsync(payload, signer.privateKey, {
      algorithm: alg,
      header: { alg: alg, kid: signer.kid, typ: MEDIA[kind].sdjwt,
                cty: MEDIA[kind].cty } });
    log.debug("Leaving VcJoseCose.secureSdJwt(). " + disclosures.length +
              " disclosure(s).");
    return [jwt].concat(disclosures).join('~') + '~';
  }

  // The enveloped form (VCDM 2.0 section 4.13) of a secured value.
  envelope(form: string, kind: 'vc' | 'vp', secured: string | Buffer): any {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.envelope(). " + form + " " + kind);
    const type = form === 'cose' ? MEDIA[kind].cose
      : 'application/' + (form === 'jwt' ? MEDIA[kind].jwt
                                         : MEDIA[kind].sdjwt);
    const data = Buffer.isBuffer(secured)
      ? ';base64,' + secured.toString('base64') : ',' + secured;
    log.debug("Leaving VcJoseCose.envelope().");
    return { '@context': V2, id: 'data:' + type + data,
             type: MEDIA[kind].envelope };
  }

  // ---------------------------------------------------------------------------
  // THE KEY a signature is checked with (see the header).
  // ---------------------------------------------------------------------------
  private keyFor(kid: unknown, opts: any): any {
    const { log, resolveVerificationMethod } = this.deps;
    log.debug("Entering VcJoseCose.keyFor().");
    const given = opts && opts.verificationMethod;
    if (given) {
      const jwk = given.publicKeyJwk || given;
      if (!jwk || typeof jwk !== 'object' || jwk.d !== undefined ||
          jwk.priv !== undefined || given.secretKeyJwk !== undefined ||
          given.privateKeyJwk !== undefined) {
        log.debug("Leaving VcJoseCose.keyFor(). A private member.");
        throw new Error('the verification method named carries a private ' +
                        'key, or no public JWK; this verifier takes public ' +
                        'keys only.');
      }
      log.debug("Leaving VcJoseCose.keyFor(). Named by the caller.");
      return jwk;
    }
    const text = String(kid || '');
    if (!/^did:(key|jwk):/.test(text)) {
      log.debug("Leaving VcJoseCose.keyFor(). Unresolvable.");
      throw new Error('the kid "' + text + '" is not a did:key or did:jwk ' +
                      'URL, and no verification method was named; this ' +
                      'verifier fetches no key.');
    }
    const resolved = resolveVerificationMethod(text);
    log.debug("Leaving VcJoseCose.keyFor(). Resolved from the kid.");
    return resolved.jwk;
  }

  // RFC 7519's time claims: exp and nbf refuse; a malformed iat warns.
  private timeClaims(claims: any, errors: string[], warnings: string[]):
    void {
    const { log, now, clockSkewS } = this.deps;
    log.debug("Entering VcJoseCose.timeClaims().");
    const t = Math.floor(now() / 1000);
    const skew = clockSkewS();
    ['exp', 'nbf'].forEach(function (name) {
      if (claims[name] === undefined) {
        return;
      }
      if (typeof claims[name] !== 'number' || !isFinite(claims[name])) {
        errors.push(name + ' is not a NumericDate (RFC 7519 section 2).');
      } else if (name === 'exp' && t > claims.exp + skew) {
        errors.push('it expired at ' + new Date(claims.exp * 1000)
          .toISOString() + ' (exp, RFC 7519 section 4.1.4).');
      } else if (name === 'nbf' && t + skew < claims.nbf) {
        errors.push('it is not valid before ' + new Date(claims.nbf * 1000)
          .toISOString() + ' (nbf, RFC 7519 section 4.1.5).');
      }
    });
    if (claims.iat !== undefined && typeof claims.iat !== 'number') {
      warnings.push('iat is ' + JSON.stringify(claims.iat) + ', not a ' +
                    'NumericDate (RFC 7519 section 4.1.6); it was ignored.');
    }
    log.debug("Leaving VcJoseCose.timeClaims().");
  }

  // ---------------------------------------------------------------------------
  // RFC 9901 SECTION 7.1: the Disclosures processed into the payload.
  // ---------------------------------------------------------------------------
  processDisclosures(payload: any, disclosures: string[]): any {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.processDisclosures(). " +
              disclosures.length + " disclosure(s).");
    if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') {
      log.debug("Leaving VcJoseCose.processDisclosures(). _sd_alg.");
      throw new Error('_sd_alg "' + payload._sd_alg + '" is not one this ' +
                      'verifier supports (sha-256).');
    }
    const byDigest = new Map<string, any[]>();
    disclosures.forEach((d) => {
      if (!/^[A-Za-z0-9_-]+$/.test(d)) {
        throw new Error('a Disclosure is not base64url.');
      }
      let parsed: any;
      try {
        parsed = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
      } catch (e) {
        log.debug("Caught in VcJoseCose.processDisclosures(): " +
                  ((e && e.message) || e));
        throw new Error('a Disclosure is not JSON.');
      }
      if (!Array.isArray(parsed) || (parsed.length !== 2 &&
          parsed.length !== 3) || typeof parsed[0] !== 'string' ||
          (parsed.length === 3 && typeof parsed[1] !== 'string')) {
        throw new Error('a Disclosure is [salt, name, value] or [salt, ' +
                        'value].');
      }
      if (parsed.length === 3 && (parsed[1] === '_sd' ||
                                  parsed[1] === '...')) {
        throw new Error('a Disclosure may not name "' + parsed[1] + '".');
      }
      const digest = this.digestOf(d);
      if (byDigest.has(digest)) {
        throw new Error('a Disclosure was presented twice.');
      }
      byDigest.set(digest, parsed);
    });
    const used = new Set<string>();
    const seen = new Set<string>();
    const walk = (node: any): any => {
      if (Array.isArray(node)) {
        const out: any[] = [];
        node.forEach((element) => {
          if (element && typeof element === 'object' &&
              !Array.isArray(element) && Object.keys(element).length === 1 &&
              typeof element['...'] === 'string') {
            const digest = element['...'];
            if (seen.has(digest)) {
              throw new Error('the digest ' + digest + ' appears twice.');
            }
            seen.add(digest);
            const d = byDigest.get(digest);
            if (d) {
              if (d.length !== 2) {
                throw new Error('an array element\'s Disclosure names a ' +
                                'claim.');
              }
              used.add(digest);
              out.push(walk(d[1]));
            }
            return;
          }
          out.push(walk(element));
        });
        return out;
      }
      if (!node || typeof node !== 'object') {
        return node;
      }
      const out: any = {};
      Object.keys(node).forEach(function (k) {
        if (k !== '_sd' && k !== '_sd_alg') {
          out[k] = node[k];
        }
      });
      Object.keys(out).forEach(function (k) {
        out[k] = walk(out[k]);
      });
      if (node._sd !== undefined) {
        if (!Array.isArray(node._sd)) {
          throw new Error('_sd is an array of digests.');
        }
        node._sd.forEach((digest: any) => {
          if (typeof digest !== 'string') {
            throw new Error('a digest in _sd is not a string.');
          }
          if (seen.has(digest)) {
            throw new Error('the digest ' + digest + ' appears twice.');
          }
          seen.add(digest);
          const d = byDigest.get(digest);
          if (!d) {
            return;
          }
          if (d.length !== 3) {
            throw new Error('an object member\'s Disclosure names no claim.');
          }
          if (Object.prototype.hasOwnProperty.call(out, d[1])) {
            throw new Error('the Disclosure of "' + d[1] + '" names a ' +
                            'claim already present.');
          }
          used.add(digest);
          out[d[1]] = walk(d[2]);
        });
      }
      return out;
    };
    const processed = walk(payload);
    if (used.size !== byDigest.size) {
      log.debug("Leaving VcJoseCose.processDisclosures(). Unreferenced.");
      throw new Error((byDigest.size - used.size) + ' Disclosure(s) hash to ' +
                      'no digest in the signed payload.');
    }
    log.debug("Leaving VcJoseCose.processDisclosures().");
    return processed;
  }

  // ---------------------------------------------------------------------------
  // VERIFY ONE SECURED VALUE. `form` 'jwt' | 'sdjwt' | 'cose'; `kind` the
  // kind the caller expects ('vc' | 'vp'), or '' for either. `opts`:
  // { verificationMethod }. Answers `{ ok, kind, document, errors,
  // warnings }`; throws for nothing.
  // ---------------------------------------------------------------------------
  async verify(form: string, secured: string | Buffer, kind: string,
               opts: any): Promise<any> {
    const { log, stsCrypto, codec } = this.deps;
    log.debug("Entering VcJoseCose.verify(). " + form + " " + kind);
    const errors: string[] = [];
    const warnings: string[] = [];
    let document: any = null;
    let found = '';
    try {
      if (form === 'jwt' || form === 'sdjwt') {
        const text = String(secured || '').trim();
        const parts = form === 'sdjwt' ? text.split('~') : [text];
        const jws = parts[0];
        const header = JSON.parse(Buffer.from(jws.split('.')[0] || '',
                                              'base64url').toString('utf8'));
        const want = form === 'jwt' ? 'jwt' : 'sdjwt';
        found = this.kindOf(header.typ, MEDIA.vc[want], MEDIA.vp[want],
                            kind);
        if (header.cty !== undefined && header.cty !== MEDIA[found].cty) {
          throw new Error('its cty is ' + JSON.stringify(header.cty) +
                          ', not ' + MEDIA[found].cty + '.');
        }
        const key = this.keyFor(header.kid, opts);
        const verified = stsCrypto.verifyCompactJws(jws, key,
                                                    { algorithms: ALGORITHMS });
        let payload = verified.claims;
        if (form === 'sdjwt') {
          if (parts.length < 2) {
            throw new Error('an SD-JWT ends with "~" (RFC 9901 section 4).');
          }
          const kb = parts[parts.length - 1];
          if (kb) {
            warnings.push('a Key Binding JWT was presented and not ' +
                          'checked: this verifier asked for none.');
          }
          payload = this.processDisclosures(payload,
            parts.slice(1, parts.length - 1).filter(function (d) {
              return d.length > 0;
            }));
        }
        this.timeClaims(payload, errors, warnings);
        document = payload;
      } else if (form === 'cose') {
        const bytes = Buffer.isBuffer(secured) ? secured
          : this.base64Strict(String(secured || ''));
        const peek = codec.cborDecode(bytes);
        const protectedHeader = peek && peek.value && Buffer.isBuffer(
          peek.value[0]) ? codec.cborDecode(peek.value[0]) : new Map();
        if (!(protectedHeader instanceof Map)) {
          throw new Error('not a COSE_Sign1 with a protected header map.');
        }
        found = this.kindOf(protectedHeader.get(16), MEDIA.vc.cose,
                            MEDIA.vp.cose, kind);
        const content = protectedHeader.get(3);
        if (content !== undefined && content !== MEDIA[found].content) {
          throw new Error('its content type (header 3) is ' +
                          JSON.stringify(content) + ', not ' +
                          MEDIA[found].content + '.');
        }
        const kidBytes = protectedHeader.get(4);
        const key = this.keyFor(Buffer.isBuffer(kidBytes)
          ? kidBytes.toString('utf8') : kidBytes, opts);
        const verified = await codec.coseSign1VerifyAsync(bytes, key,
          { algorithms: ALGORITHMS });
        document = JSON.parse(Buffer.from(verified.payload).toString('utf8'));
      } else {
        throw new Error('"' + form + '" is not a securing mechanism here.');
      }
      if (kind && found !== kind) {
        throw new Error('this is a ' + (found === 'vc' ? 'credential' :
                        'presentation') + ' where a ' + (kind === 'vc' ?
                        'credential' : 'presentation') + ' was expected.');
      }
      if (!document || typeof document !== 'object' ||
          Array.isArray(document)) {
        throw new Error('the payload is not a JSON object.');
      }
      if (document.vc !== undefined || document.vp !== undefined) {
        errors.push('the payload carries a "vc" or "vp" claim, which a ' +
                    'VCDM 2.0 envelope MUST NOT (VC-JOSE-COSE section ' +
                    '3.1.1).');
      }
    } catch (e) {
      log.debug("Caught in VcJoseCose.verify(): " + ((e && e.message) || e));
      errors.push(String((e && e.message) || e));
    }
    log.debug("Leaving VcJoseCose.verify(). " + errors.length +
              " error(s).");
    return { ok: !errors.length, kind: found, document: document,
             errors: errors, warnings: warnings };
  }

  // THE KIND A TYPE HEADER SAYS, against the kind expected. `typ` (JOSE)
  // and header 16 (COSE) are SHOULDs (VC-JOSE-COSE sections 3.1.1, 3.2.1,
  // 3.3.1), so an ABSENT one leaves the expected kind — the media type the
  // envelope's data: URL named — standing; a PRESENT one that names neither
  // this mechanism's credential nor its presentation type contradicts it,
  // and is refused.
  private kindOf(typ: unknown, vcType: string, vpType: string,
                 expected: string): string {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.kindOf().");
    if (typ === undefined) {
      if (!expected) {
        log.debug("Leaving VcJoseCose.kindOf(). Nothing says.");
        throw new Error('it carries no type header, and nothing else says ' +
                        'whether it is a credential or a presentation.');
      }
      log.debug("Leaving VcJoseCose.kindOf(). As expected.");
      return expected;
    }
    const found = typ === vcType ? 'vc' : (typ === vpType ? 'vp' : '');
    if (!found) {
      log.debug("Leaving VcJoseCose.kindOf(). Another type.");
      throw new Error('its type header is ' + JSON.stringify(typ) + '; ' +
                      'this mechanism is ' + vcType + ' or ' + vpType +
                      ' (VC-JOSE-COSE section 3).');
    }
    log.debug("Leaving VcJoseCose.kindOf(). " + found);
    return found;
  }

  // Strict base64 (or base64url): a string of anything else is refused
  // rather than decoded around, which is what `Buffer.from()` would do.
  private base64Strict(text: string): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.base64Strict().");
    const clean = text.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(clean) || clean.length % 4 === 1) {
      log.debug("Leaving VcJoseCose.base64Strict(). Not base64.");
      throw new Error('the COSE value is not base64.');
    }
    log.debug("Leaving VcJoseCose.base64Strict().");
    return Buffer.from(clean.replace(/-/g, '+').replace(/_/g, '/'),
                       'base64');
  }

  // ---------------------------------------------------------------------------
  // AN ENVELOPE (VCDM 2.0 section 4.13): the data: URL read — its media
  // type, and base64 or not — and the value inside verified.
  // ---------------------------------------------------------------------------
  async verifyEnvelope(envelope: any, kind: 'vc' | 'vp', opts: any):
    Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcJoseCose.verifyEnvelope(). " + kind);
    const m = /^data:([^,;]*)(;base64)?,(.*)$/s.exec(
      String(envelope && envelope.id || ''));
    if (!m) {
      log.debug("Leaving VcJoseCose.verifyEnvelope(). Not a data: URL.");
      return { ok: false, errors: ['the envelope\'s id is not a data: URL ' +
               '(RFC 2397).'], warnings: [], document: null };
    }
    const type = m[1] === 'application/jwt' ? 'application/' +
      MEDIA[kind].jwt : m[1];
    const known = DATA_TYPES[type];
    if (!known || known.kind !== kind) {
      log.debug("Leaving VcJoseCose.verifyEnvelope(). Unknown type.");
      return { ok: false, errors: ['the envelope\'s media type "' + m[1] +
               '" is not a ' + (kind === 'vc' ? 'credential' :
               'presentation') + ' securing mechanism this verifier reads.'],
               warnings: [], document: null };
    }
    // A COSE value goes on as TEXT (base64 in the URL, or percent-encoded
    // bytes without `;base64`), decoded strictly by `verify()`; a JWT form
    // is text either way.
    let body: string | Buffer = m[3];
    if (known.form === 'cose' && !m[2]) {
      body = Buffer.from(decodeURIComponent(m[3]), 'latin1');
    } else if (known.form !== 'cose' && m[2]) {
      body = this.base64Strict(m[3]).toString('utf8');
    }
    const out = await this.verify(known.form, body, kind, opts);
    log.debug("Leaving VcJoseCose.verifyEnvelope(). " + out.ok);
    return out;
  }
}

const slot = new InstanceSlot<VcJoseCose>(
  'oid4vc/vc_jose_cose',
  () => new VcJoseCose(VcJoseCose.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  VcJoseCose: VcJoseCose,
  installInstance: (instance: VcJoseCose): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ALGORITHMS: ALGORITHMS,
  MEDIA: MEDIA,
  algFor: slot.forward('algFor'),
  secureJwt: slot.forward('secureJwt'),
  secureCose: slot.forward('secureCose'),
  secureSdJwt: slot.forward('secureSdJwt'),
  envelope: slot.forward('envelope'),
  parsePath: slot.forward('parsePath'),
  processDisclosures: slot.forward('processDisclosures'),
  verify: slot.forward('verify'),
  verifyEnvelope: slot.forward('verifyEnvelope')
};
