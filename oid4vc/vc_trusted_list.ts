// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_trusted_list.ts
//
// ---------------------------------------------------------------------------
// THIS ISSUER'S TRUST ANCHOR, AS A LIST OF TRUSTED ENTITIES (ETSI TS 119 602
// V1.1.1), at `GET /oid4vci/trusted-list` (rcbj, 2026-10-17).
//
// A credential and its Token Status List Token carry their chain in `x5c`
// (`oid4vci.credentialCertificateHeader`), and the chain ends under the
// service Root, which `/pki/ca/default/root` serves. What a wallet in the
// EUDI ecosystem pulls its anchors FROM is neither of those but a signed List
// of Trusted Entities: eudi-dev, among others, reads one by URL and anchors a
// credential whose chain ends in a certificate of the list's ISSUANCE service,
// and a status list whose chain ends in one of its REVOCATION service (Table
// D.3's arrangement). This is that list, in the standard's own JSON binding
// and nothing wallet-specific, so any wallet that reads a LoTE can use it:
//
//   * one trusted entity, this credential issuer, named by
//     `oid4vci.issuerDisplayName` and reached at its base URL;
//   * an issuance and a revocation service, each listing the service Root —
//     the one certificate both chains end under;
//   * the scheme's URIs (the list type, the status determination approach,
//     the community rules, the service types) under THIS list's own URL. ETSI
//     TS 119 602 defines list types for PID, wallet, access- and
//     registration-certificate and public-body EAA providers (Annexes D to
//     H), and a credential issuer of this service is none of them, so the
//     list is scheme explicit and says so rather than borrowing a type. The
//     service types end in `/Issuance` and `/Revocation`, the suffixes a
//     reader tells the two kinds apart by;
//   * `ListIssueDateTime`, `NextUpdate` (`oid4vci.trustedListLifetimeH` on),
//     `DistributionPoints` and a pointer to the list itself, which Tables D.1
//     to G.1 require of their lists.
//
// **SIGNED AS JAdES DOES IT** (the standard's Annexes D.4 to H.4): a compact
// JWS whose `x5c` carries the signer's chain — ES256 where this realm's P-256
// key is certified, which is the baseline every reader verifies, else RS256 —
// with `x5t#S256` and `iat`. A wallet accepts the list only when that chain
// ends under a list-operator CA it was configured with: the service Root,
// given once. That one step cannot be a URL, and should not be — a list that
// anybody could fetch and believe would anchor nothing.
//
// **KEPT, NOT REBUILT PER REQUEST** (rcbj, 2026-10-17: lists are maintained
// as you go). One row per realm (`vc_trusted_list.state`) holds the signed
// list, the digest of what it says and its sequence number. A request whose
// content digest matches, before `NextUpdate` draws near, is answered from
// the row; otherwise the list is signed again with the next
// `LoTESequenceNumber` (§6.3.2: it grows with every issue).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import errorCodes = require('../common/error_codes');

type Json = any;

// Where the list is served, under the realm's prefix.
const PATH = '/oid4vci/trusted-list';

// How close to `NextUpdate` a list is signed again: an hour, or a tenth of
// its lifetime when that is shorter.
const REFRESH_MARGIN_MS = 60 * 60 * 1000;

// The algorithms the list is signed with, in preference order: the first
// whose key carries a certificate chain.
const SIGNING_ALGS = ['ES256', 'RS256'];

interface Store {
  get(key: string): any;
  set(key: string, value: any): unknown;
}

interface VcTrustedListDeps {
  log: { debug(message: string): void; error(message: string): void };
  config: { value(key: string): any };
  baseUrlOf(req: any): string;
  serviceRoot(): any;
  signingKeyForAsync(alg: string, useCase?: string): Promise<any>;
  certificateHeaderFor(useCase: string, alg: string, kid: string): Json;
  publishedKidFor(kid: string): string;
  stsKid(): string;
  stsPrivateKey(): any;
  signJwsAsync(payload: Json, key: any, opts: Json): Promise<string>;
  digest(alg: string, data: any, enc: string): string;
  errorCodes: typeof errorCodes;
  now(): number;
  state: Store;
}

// realm -> { list: { token, digest, sequence, issuedAt, nextUpdate } }
const state = realms.map({ persist: 'vc_trusted_list.state' });

/**
 * This issuer's List of Trusted Entities (ETSI TS 119 602): the service Root
 * as the anchor of its credentials and its status lists, signed and kept.
 */
class VcTrustedList {
  /**
   * Builds the list over its dependencies.
   *
   * @param deps - the modules it reads and signs through
   */
  constructor(private readonly deps: VcTrustedListDeps) {
    deps.log.debug("Entering VcTrustedList.constructor().");
    deps.log.debug("Leaving VcTrustedList.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcTrustedListDeps {
    helpers.log.debug("Entering VcTrustedList.defaultDeps().");
    helpers.log.debug("Leaving VcTrustedList.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      baseUrlOf: helpers.baseUrlOf,
      serviceRoot: pki.serviceRoot,
      signingKeyForAsync: helpers.signingKeyForAsync,
      certificateHeaderFor: helpers.certificateHeaderFor,
      publishedKidFor: helpers.publishedKidFor,
      stsKid: function (): string {
        return helpers.stsKeysFor().kid;
      },
      stsPrivateKey: function (): any {
        return helpers.stsKeysFor().privateKey;
      },
      signJwsAsync: stsCrypto.signJwsAsync,
      digest: stsCrypto.digest,
      errorCodes: errorCodes,
      now: function (): number {
        return Date.now();
      },
      state: state
    };
  }

  /**
   * The list's own address, for a request.
   *
   * @param req - the request
   * @returns the URL
   */
  listUrl(req: any): string {
    return this.deps.baseUrlOf(req) + PATH;
  }

  // The service Root, base64 DER, or '' where there is none.
  private rootB64(): string {
    const root = this.deps.serviceRoot();
    return root && root.certificatePem
      ? String(root.certificatePem).replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, '') : '';
  }

  // What the list says, without its times and sequence number: what its
  // digest is taken over.
  private content(req: any, rootB64: string, signerB64: string): Json {
    const { config } = this.deps;
    const base = this.deps.baseUrlOf(req);
    const url = base + PATH;
    const operator = String(config.value('oid4vci.issuerDisplayName') ||
                            base);
    const territory = String(config.value('oid4vci.trustedListTerritory') ||
                             '');
    const metadata = base + '/.well-known/openid-credential-issuer';
    const en = function (value: string): Json {
      return { lang: 'en', value: value };
    };
    const uri = function (value: string): Json {
      return { lang: 'en', uriValue: value };
    };
    const service = function (kind: string, name: string): Json {
      return { ServiceInformation: {
        ServiceTypeIdentifier: url + '/SvcType/CredentialIssuer/' + kind,
        ServiceName: [en(name)],
        ServiceDigitalIdentity: { X509Certificates: [{ val: rootB64 }] } } };
    };
    const scheme: Json = {
      LoTEVersionIdentifier: 1,
      LoTEType: url + '/LoTEType/CredentialIssuersList',
      SchemeOperatorName: [en(operator)],
      SchemeOperatorAddress: {
        SchemeOperatorElectronicAddress: [uri(base)] },
      SchemeName: [en(operator + ': OpenID4VCI credential issuer')],
      SchemeInformationURI: [uri(metadata)],
      StatusDeterminationApproach: url + '/StatusDetn',
      SchemeTypeCommunityRules: [uri(url + '/schemerules')],
      PolicyOrLegalNotice: [{ LoTELegalNotice: 'The credential issuer ' +
        operator + ' runs, and the certificate authority its credentials ' +
        'and their Token Status List Tokens chain to.' }],
      DistributionPoints: [url],
      PointersToOtherLoTE: [{
        LoTELocation: url,
        ServiceDigitalIdentities: [{ X509Certificates: [{ val: signerB64 }] }],
        LoTEQualifiers: [{ LoTEType: url + '/LoTEType/CredentialIssuersList',
                           SchemeOperatorName: [en(operator)],
                           MimeType: 'application/jwt' }] }]
    };
    if (territory) {
      scheme.SchemeTerritory = territory;
      scheme.PointersToOtherLoTE[0].LoTEQualifiers[0].SchemeTerritory =
        territory;
    }
    return {
      ListAndSchemeInformation: scheme,
      TrustedEntitiesList: [{
        TrustedEntityInformation: {
          TEName: [en(operator)],
          TEAddress: { TEElectronicAddress: [uri(base)] },
          TEInformationURI: [uri(metadata)] },
        TrustedEntityServices: [
          service('Issuance', operator + ' credential issuance'),
          service('Revocation', operator + ' credential status lists')] }]
    };
  }

  // The key the list is signed with and its chain: the first of
  // SIGNING_ALGS whose key carries one.
  private async signer(): Promise<Json> {
    const { log, signingKeyForAsync, certificateHeaderFor, stsKid,
            stsPrivateKey } = this.deps;
    for (let i = 0; i < SIGNING_ALGS.length; i++) {
      const alg = SIGNING_ALGS[i];
      try {
        const key = alg === 'RS256'
          ? { key: stsPrivateKey(), kid: stsKid() }
          : await signingKeyForAsync(alg, 'vci-trusted-list');
        const header = certificateHeaderFor('vci-trusted-list', alg, key.kid);
        if (header && Array.isArray(header.x5c) && header.x5c.length) {
          return { alg: alg, key: key.key, kid: key.kid, x5c: header.x5c };
        }
      } catch (e) {
        log.debug("Caught in VcTrustedList.signer(): " +
                  ((e && e.message) || e));
        // The next algorithm, then.
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // THE LIST FOR A REQUEST: the kept one while it still says what this realm
  // would say and is not near its NextUpdate, otherwise signed again with the
  // next sequence number. Null where there is no Root or no certified key.
  // ---------------------------------------------------------------------------
  /**
   * Returns the realm's signed list, kept or signed again.
   *
   * @param req - the request (its base URL names the list)
   * @returns `{ token, sequence, nextUpdate }`, or null
   */
  async listFor(req: any): Promise<Json> {
    const { log, config, state, digest, now, publishedKidFor,
            certificateHeaderFor } = this.deps;
    log.debug("Entering VcTrustedList.listFor().");
    const rootB64 = this.rootB64();
    const signer = rootB64 ? await this.signer() : null;
    if (!signer) {
      log.debug("Leaving VcTrustedList.listFor(). No Root or no certified " +
                "key.");
      return null;
    }
    const lote = this.content(req, rootB64, signer.x5c[0]);
    const contentDigest = digest('sha256', JSON.stringify(lote) + '|' +
                                 signer.alg + '|' + signer.x5c.join(','),
                                 'base64url');
    const at = now();
    const lifetimeMs = Math.max(1, Number(
      config.value('oid4vci.trustedListLifetimeH')) || 24) * 3600 * 1000;
    const margin = Math.min(REFRESH_MARGIN_MS, lifetimeMs / 10);
    const kept = state.get('list');
    if (kept && kept.digest === contentDigest && kept.token &&
        Number(kept.nextUpdate) - margin > at) {
      log.debug("Leaving VcTrustedList.listFor(). Kept, sequence " +
                kept.sequence + ".");
      return kept;
    }
    const sequence = (kept ? Number(kept.sequence) || 0 : 0) + 1;
    const issued = new Date(Math.floor(at / 1000) * 1000);
    const nextUpdate = new Date(issued.getTime() + lifetimeMs);
    const scheme = lote.ListAndSchemeInformation;
    scheme.LoTESequenceNumber = sequence;
    scheme.ListIssueDateTime = issued.toISOString();
    scheme.NextUpdate = nextUpdate.toISOString();
    const signerDer = Buffer.from(signer.x5c[0], 'base64');
    const token = await this.deps.signJwsAsync({ LoTE: lote }, signer.key, {
      algorithm: signer.alg,
      header: { alg: signer.alg, typ: 'JWT', kid: publishedKidFor(signer.kid),
                x5c: certificateHeaderFor('vci-trusted-list', signer.alg,
                                          signer.kid).x5c,
                'x5t#S256': digest('sha256', signerDer, 'base64url'),
                iat: Math.floor(issued.getTime() / 1000) } });
    const row = { token: token, digest: contentDigest, sequence: sequence,
                  issuedAt: issued.getTime(),
                  nextUpdate: nextUpdate.getTime() };
    // THROUGH THE STORE, whole, so the journal carries it.
    state.set('list', row);
    log.debug("Leaving VcTrustedList.listFor(). Signed, sequence " +
              sequence + ".");
    return row;
  }

  /**
   * Registers `GET /oid4vci/trusted-list`.
   *
   * @param app - the express app
   * @returns nothing
   */
  registerRoutes(app: any): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering VcTrustedList.registerRoutes().");
    app.get(PATH, function (req: any, res: any) {
      self.listFor(req).then(function (row: Json) {
        if (!row) {
          self.deps.errorCodes.mark(res, 'STS-VC-0124');
          res.status(503).type('text/plain')
            .send('This service has no Root certificate authority, or no ' +
                  'key certified under it, to sign its trusted list with.');
          return;
        }
        const etag = '"' + self.deps.digest('sha256', row.token,
                                            'base64url') + '"';
        if (String(req.headers['if-none-match'] || '') === etag) {
          res.status(304).set('ETag', etag).end();
          return;
        }
        // Revalidated, as `/pki/ca/` is: the list changes when the Root or
        // the signing chain does, and a conditional request costs a
        // client nothing when it has not.
        res.status(200).type('application/jwt')
          .set('Cache-Control', 'no-cache').set('ETag', etag)
          .send(row.token);
      }, function (e: any) {
        log.error(self.deps.errorCodes.tag('STS-VC-0125') +
                  'vc_trusted_list: the trusted list could not be signed: ' +
                  ((e && e.message) || e));
        self.deps.errorCodes.mark(res, 'STS-VC-0125');
        res.status(500).type('text/plain')
          .send('The trusted list could not be signed.');
      });
    });
    log.debug("Leaving VcTrustedList.registerRoutes().");
  }
}

const slot = new InstanceSlot<VcTrustedList>(
  'oid4vc/vc_trusted_list',
  () => new VcTrustedList(VcTrustedList.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * This issuer's List of Trusted Entities (ETSI TS 119 602).
 *
 * @namespace
 */
export = {
  VcTrustedList: VcTrustedList,
  PATH: PATH,
  /**
   * Installs the instance the composition root built.
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcTrustedList): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  listFor: slot.forward('listFor'),
  listUrl: slot.forward('listUrl')
};
