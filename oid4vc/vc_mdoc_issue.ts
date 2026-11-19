// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_mdoc_issue.ts
//
// ---------------------------------------------------------------------------
// AN ISO mdoc, ISSUED (#1862, ISO/IEC 18013-5 section 9.1.2).
//
// What leaves this issuer is one IssuerSigned, base64url, not a
// DeviceResponse. The wallet builds the DeviceResponse when it presents.
// The Mobile Security Object is COSE_Sign1, untagged, signed by this
// realm's document signer (`mdoc_authority.ts`). The chain in `x5chain`
// (header 33) is that one certificate.
//
// The maps are inserted in RFC 8949 section 4.2.1's order — shorter
// encoded key first, then bytewise — because `vc_status_codec.ts`'s
// encoder writes a Map in insertion order and does not sort. Changing
// that encoder would rewrite every status list. The digest of an
// IssuerSignedItem is SHA-256 of the tag-24 bytes as they are encoded
// here, which is the same bytes a presentation must carry.
//
// Digest identifiers are random and not 0, 1, 2. A test that builds its
// own mdoc may use those, and an mdoc this service issues must not be
// mistaken for one.
//
// Proof of the holder stays a JWT (`proof_types_supported.jwt`). The
// credential is signed with COSE. Only a P-256 holder key is accepted:
// the proof algorithms advertised for this configuration are ES256, so
// a wallet that followed the metadata sends a P-256 key.
//
// A LIBRARY (rule 3). It does not require the issuer or the status
// module. The caller allocates the status index and passes `{idx, uri}`.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');
import codec = require('./vc_status_codec');
import nodeCrypto = require('crypto');

const { Tagged } = codec;

const TAG_TDATE = 0;
const TAG_FULL_DATE = 1004;
const TAG_ENCODED_CBOR = 24;
const X5CHAIN = 33;
const SIGNING_ALGS = ['-7', '-9'];

const ELEMENT_LABELS: Record<string, string> = {
  given_name: 'Given name',
  family_name: 'Family name',
  birth_date: 'Date of birth',
  issue_date: 'Date of issue',
  expiry_date: 'Date of expiry',
  issuing_country: 'Issuing country',
  issuing_authority: 'Issuing authority',
  document_number: 'Document number'
};

const OID_TO_ELEMENT: Record<string, string> = {
  given_name: 'given_name',
  family_name: 'family_name',
  birthdate: 'birth_date',
  document_number: 'document_number'
};

interface VcMdocIssueDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  codec: typeof codec;
}

/**
 * What one issuance is built from.
 */
interface MdocIssueInput {
  holderJwk: any;
  elements: Array<{ name: string; value: unknown }>;
  doctype: string;
  namespace: string;
  validFromMs: number;
  validUntilMs: number;
  signedMs: number;
  dsKey: any;
  dsDer: Buffer;
  coseAlg: number;
  status?: { idx: number; uri: string } | null;
}

/**
 * Issues ISO/IEC 18013-5 mdocs (`mso_mdoc`) for OpenID4VCI.
 */
class VcMdocIssue {
  /**
   * Builds an issuer with the dependencies it reads.
   *
   * @param deps - the logger, settings, error codes, crypto and codec
   */
  constructor(private readonly deps: VcMdocIssueDeps) {
  }

  /**
   * The dependencies a process without the composition root builds with.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcMdocIssueDeps {
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      stsCrypto: stsCrypto,
      codec: codec
    };
  }

  /**
   * The COSE algorithm identifiers an mdoc credential is signed with,
   * as strings so an offer's `signingAlg` can name one.
   *
   * @returns `['-7', '-9']`
   */
  static signingAlgs(): string[] {
    helpers.log.debug("Entering VcMdocIssue.signingAlgs().");
    helpers.log.debug("Leaving VcMdocIssue.signingAlgs().");
    return SIGNING_ALGS.slice();
  }

  /**
   * The element names this issuer can put in an mdoc, including the
   * configured `age_over_NN` thresholds.
   *
   * @returns the names
   */
  elementNames(): string[] {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.elementNames().");
    const names = ['given_name', 'family_name', 'birth_date',
                   'issue_date', 'expiry_date', 'issuing_country',
                   'issuing_authority', 'document_number'];
    this.thresholds().forEach(function (n) {
      names.push('age_over_' + n);
    });
    log.debug("Leaving VcMdocIssue.elementNames(). " + names.length);
    return names;
  }

  /**
   * The claims paths the metadata and the authorization endpoint share:
   * `[namespace, element]`.
   *
   * @returns the claims description objects
   */
  claimPaths(): Array<{ path: string[]; display: any[] }> {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.claimPaths().");
    const ns = this.namespace();
    const out = this.elementNames().map((name) => {
      return { path: [ns, name],
               display: [{ locale: 'en-US',
                           name: ELEMENT_LABELS[name] || name }] };
    });
    log.debug("Leaving VcMdocIssue.claimPaths(). " + out.length);
    return out;
  }

  /**
   * The claims path of one element.
   *
   * @param name - the element identifier
   * @returns `[namespace, element]`
   */
  pathFor(name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.pathFor(). " + name);
    log.debug("Leaving VcMdocIssue.pathFor().");
    return [this.namespace(), name];
  }

  /**
   * The mdoc element a directory claim maps to, or `''`.
   *
   * @param claim - the catalogue claim path
   * @returns the element identifier, or `''`
   */
  elementForOidc(claim: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.elementForOidc().");
    const parts = [].concat(claim || []).map(String);
    const key = parts[parts.length - 1] || '';
    const out = OID_TO_ELEMENT[key] || '';
    log.debug("Leaving VcMdocIssue.elementForOidc(). " + (out || "None."));
    return out;
  }

  /**
   * The elements of one person's mdoc. Issue and expiry dates, the
   * country and the authority are always present. Names, the birth
   * date, the document number and `age_over_NN` are present only when
   * the directory holds what they are computed from.
   *
   * @param subjectClaims - the issuer's subject claims
   * @param validFromMs - the MSO's validFrom
   * @param validUntilMs - the MSO's validUntil
   * @returns `{ name, value }` in the order they are issued
   */
  elementsOf(subjectClaims: any, validFromMs: number,
             validUntilMs: number): Array<{ name: string; value: unknown }> {
    const { log, config } = this.deps;
    log.debug("Entering VcMdocIssue.elementsOf().");
    const claims = subjectClaims || {};
    const out: Array<{ name: string; value: unknown }> = [];
    this.copyText(out, 'given_name', claims.given_name);
    this.copyText(out, 'family_name', claims.family_name);
    const birth = this.fullDateText(claims.birthdate);
    if (birth) {
      out.push({ name: 'birth_date',
                 value: new Tagged(TAG_FULL_DATE, birth) });
      this.ageOver(out, birth);
    }
    out.push({ name: 'issue_date',
               value: new Tagged(TAG_FULL_DATE,
                                 this.dayOf(validFromMs)) });
    out.push({ name: 'expiry_date',
               value: new Tagged(TAG_FULL_DATE,
                                 this.dayOf(validUntilMs)) });
    out.push({ name: 'issuing_country',
               value: String(config.value(
                 'oid4vci.mdocIssuingCountry') || 'US') });
    out.push({ name: 'issuing_authority',
               value: String(config.value(
                 'oid4vci.mdocIssuingAuthority') || 'Iya STS') });
    this.copyText(out, 'document_number', claims.document_number);
    log.debug("Leaving VcMdocIssue.elementsOf(). " + out.length);
    return out;
  }

  /**
   * Builds one IssuerSigned mdoc.
   *
   * @param input - the holder key, the elements, the document signer
   *   and the validity window
   * @returns the wallet's credential and the register's key
   */
  async issue(input: MdocIssueInput): Promise<any> {
    const { log, codec, stsCrypto } = this.deps;
    log.debug("Entering VcMdocIssue.issue().");
    const alg = Number(input.coseAlg);
    if (alg !== -7 && alg !== -9) {
      log.debug("Leaving VcMdocIssue.issue(). Not a P-256 COSE alg.");
      throw this.fail('the mdoc is signed with COSE -7 or -9, not ' +
                      input.coseAlg + '.');
    }
    const deviceKey = this.coseKey(input.holderJwk);
    const namespace = String(input.namespace || '');
    const doctype = String(input.doctype || '');
    if (!namespace || !doctype) {
      log.debug("Leaving VcMdocIssue.issue(). No doctype.");
      throw this.fail('an mdoc needs a docType and a namespace.');
    }
    const elements = [].concat(input.elements || []);
    if (!elements.length) {
      log.debug("Leaving VcMdocIssue.issue(). No elements.");
      throw this.fail('an mdoc with no elements is not a document.');
    }
    const ids = this.digestIds(elements.length);
    const digests = new Map();
    const items: any[] = [];
    elements.forEach((element: any, i: number) => {
      const salt = nodeCrypto.randomBytes(16);
      const item = new Map<string, unknown>([
        ['random', salt],
        ['digestID', ids[i]],
        ['elementValue', element.value],
        ['elementIdentifier', String(element.name)]
      ]);
      const tagged = new Tagged(TAG_ENCODED_CBOR, codec.cborEncode(item));
      const bytes = codec.cborEncode(tagged);
      digests.set(ids[i], nodeCrypto.createHash('sha256')
        .update(bytes).digest());
      items.push(tagged);
    });
    const digestMap = new Map();
    ids.slice().sort(function (a, b) {
      return Buffer.compare(codec.cborEncode(a), codec.cborEncode(b));
    }).forEach(function (id) {
      digestMap.set(id, digests.get(id));
    });
    const validity = new Map<string, unknown>([
      ['signed', this.tdate(input.signedMs)],
      ['validFrom', this.tdate(input.validFromMs)],
      ['validUntil', this.tdate(input.validUntilMs)]
    ]);
    const deviceKeyInfo = new Map<string, unknown>([
      ['deviceKey', deviceKey]
    ]);
    const valueDigests = new Map<string, unknown>([
      [namespace, digestMap]
    ]);
    const mso = new Map<string, unknown>();
    const status = input.status;
    if (status && Number.isInteger(Number(status.idx)) && status.uri) {
      mso.set('status', codec.coseStatus({ idx: Number(status.idx),
                                           uri: String(status.uri) }));
    }
    mso.set('docType', doctype);
    mso.set('version', '1.0');
    mso.set('validityInfo', validity);
    mso.set('valueDigests', valueDigests);
    mso.set('deviceKeyInfo', deviceKeyInfo);
    mso.set('digestAlgorithm', 'SHA-256');
    const payload = codec.cborEncode(new Tagged(TAG_ENCODED_CBOR,
                                                codec.cborEncode(mso)));
    const protectedBytes = codec.cborEncode(new Map([[1, alg]]));
    let signature: Buffer;
    try {
      signature = await stsCrypto.coseSign1SignAsync(alg, input.dsKey,
        protectedBytes, payload);
    } catch (e) {
      log.debug("Caught in VcMdocIssue.issue(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcMdocIssue.issue(). The signer refused.");
      throw this.fail('the document signer could not sign the Mobile ' +
                      'Security Object: ' + ((e && e.message) || e));
    }
    const issuerAuth = [protectedBytes,
                        new Map([[X5CHAIN, input.dsDer]]),
                        payload, signature];
    const issuerSigned = new Map<string, unknown>([
      ['nameSpaces', new Map([[namespace, items]])],
      ['issuerAuth', issuerAuth]
    ]);
    const credential = codec.cborEncode(issuerSigned)
      .toString('base64url');
    const exp = Math.floor(Number(input.validUntilMs) / 1000);
    log.debug("Leaving VcMdocIssue.issue(). " + elements.length +
              " element(s).");
    return {
      credential: credential,
      recordCredential: payload.toString('base64url'),
      disclosures: [],
      payload: { exp: exp },
      expiresAt: Number(input.validUntilMs) || 0,
      validFrom: new Date(input.validFromMs).toISOString(),
      validUntil: new Date(input.validUntilMs).toISOString(),
      deviceKeyJwk: this.publicJwk(input.holderJwk)
    };
  }

  private namespace(): string {
    const { log, config } = this.deps;
    log.debug("Entering VcMdocIssue.namespace().");
    const ns = String(config.value('oid4vci.mdocNamespace') ||
                      'urn:iya:sts:mdoc');
    log.debug("Leaving VcMdocIssue.namespace().");
    return ns;
  }

  private thresholds(): number[] {
    const { log, config } = this.deps;
    log.debug("Entering VcMdocIssue.thresholds().");
    const raw = [].concat(config.value('oid4vci.mdocAgeThresholds') ||
                          []);
    const out: number[] = [];
    raw.forEach(function (one) {
      const n = Number(String(one).trim());
      if (Number.isInteger(n) && n >= 0 && n <= 150 &&
          out.indexOf(n) < 0) {
        out.push(n);
      }
    });
    log.debug("Leaving VcMdocIssue.thresholds(). " + out.join(','));
    return out;
  }

  private copyText(out: Array<{ name: string; value: unknown }>,
                   name: string, value: unknown): void {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.copyText(). " + name);
    const text = value === undefined || value === null ? ''
      : String(value);
    if (text) {
      out.push({ name: name, value: text });
    }
    log.debug("Leaving VcMdocIssue.copyText().");
  }

  private fullDateText(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.fullDateText().");
    const text = String(value || '');
    const day = /^\d{4}-\d{2}-\d{2}/.exec(text);
    log.debug("Leaving VcMdocIssue.fullDateText(). " +
              (day ? "A date." : "None."));
    return day ? day[0] : '';
  }

  private dayOf(ms: number): string {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.dayOf().");
    log.debug("Leaving VcMdocIssue.dayOf().");
    return new Date(ms).toISOString().slice(0, 10);
  }

  private ageOver(out: Array<{ name: string; value: unknown }>,
                  birth: string): void {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.ageOver().");
    const parts = birth.split('-').map(Number);
    const now = Date.now();
    this.thresholds().forEach(function (years) {
      const anniversary = Date.UTC(parts[0] + years, parts[1] - 1,
                                   parts[2]);
      out.push({ name: 'age_over_' + years,
                 value: now >= anniversary });
    });
    log.debug("Leaving VcMdocIssue.ageOver().");
  }

  private tdate(ms: number): any {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.tdate().");
    const text = new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
    log.debug("Leaving VcMdocIssue.tdate().");
    return new Tagged(TAG_TDATE, text);
  }

  // Random, unique, and never the 0, 1, 2 a hand-built test mdoc uses.
  private digestIds(count: number): number[] {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.digestIds(). " + count);
    const ids: number[] = [];
    const seen = new Set<number>();
    while (ids.length < count) {
      const n = nodeCrypto.randomInt(24, 0x7fffffff);
      if (!seen.has(n)) {
        seen.add(n);
        ids.push(n);
      }
    }
    log.debug("Leaving VcMdocIssue.digestIds().");
    return ids;
  }

  private publicJwk(jwk: any): any {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.publicJwk().");
    const out = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    log.debug("Leaving VcMdocIssue.publicJwk().");
    return out;
  }

  private coseKey(jwk: any): Map<number, unknown> {
    const { log } = this.deps;
    log.debug("Entering VcMdocIssue.coseKey().");
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
        !jwk.x || !jwk.y) {
      log.debug("Leaving VcMdocIssue.coseKey(). Not P-256.");
      throw this.fail('an mdoc\'s holder key must be P-256 (COSE ' +
                      'ES256); this proof named ' +
                      ((jwk && jwk.kty) || 'no key') +
                      (jwk && jwk.crv ? ' ' + jwk.crv : '') + '.');
    }
    const x = Buffer.from(String(jwk.x), 'base64url');
    const y = Buffer.from(String(jwk.y), 'base64url');
    if (x.length !== 32 || y.length !== 32) {
      log.debug("Leaving VcMdocIssue.coseKey(). Bad coordinates.");
      throw this.fail('an mdoc\'s P-256 holder key has coordinates ' +
                      'that are not 32 bytes.');
    }
    log.debug("Leaving VcMdocIssue.coseKey().");
    return new Map<number, unknown>([[1, 2], [-1, 1], [-2, x],
                                     [-3, y]]);
  }

  private fail(message: string): Error {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcMdocIssue.fail().");
    log.error(errorCodes.tag('STS-VC-0187') + 'vc_mdoc_issue: ' +
              message);
    const err: any = new Error(message);
    err.code = 'STS-VC-0187';
    errorCodes.mark(err, 'STS-VC-0187');
    log.debug("Leaving VcMdocIssue.fail().");
    return err;
  }
}

const slot = new InstanceSlot<VcMdocIssue>(
  'oid4vc/vc_mdoc_issue',
  () => new VcMdocIssue(VcMdocIssue.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * ISO/IEC 18013-5 mdoc issuance for OpenID4VCI.
 *
 * @namespace
 */
export = {
  VcMdocIssue: VcMdocIssue,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcMdocIssue): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  SIGNING_ALGS: SIGNING_ALGS,
  issue: slot.forward('issue'),
  elementsOf: slot.forward('elementsOf'),
  elementNames: slot.forward('elementNames'),
  claimPaths: slot.forward('claimPaths'),
  pathFor: slot.forward('pathFor'),
  elementForOidc: slot.forward('elementForOidc')
};
