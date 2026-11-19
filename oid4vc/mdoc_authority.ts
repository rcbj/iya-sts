// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mdoc_authority.ts
//
// ---------------------------------------------------------------------------
// THE ECDSA ISSUING AUTHORITY AN mdoc IS SIGNED UNDER (#1862).
//
// ISO/IEC 18013-5 Annex B: an Issuing Authority CA (IACA) and a document
// signer (DS) beneath it, both P-256, both ECDSA. This is a hierarchy of
// its own. It is not the service's RSA Root, and it is not a JOSE
// credential signer (`common/credential_signer.js`, `documentSigning`):
// those certificates carry a different extended key usage, and a wallet
// that checks `1.0.18013.5.1.2` would refuse them.
//
// The two certificates live on the realm's key set as credential-signer
// rows, group `mdoc`, slots `mdoc-iaca` and `mdoc-ds`, kid prefix
// `sts-mdoc-`. `credential_signer.js` publishes only the `vc-issuer`
// group, so these rows are stored beside those keys and left out of the
// JWKS. Product mode keeps them with the key set; development mode
// regenerates signing keys on every start, and these follow that set.
//
// Minted on the first issuance and on the first read of the public
// certificate, under one cluster claim, and never at require time.
// `VcMdoc.verify()` does not mint either: a verifier whose anchors are
// empty trusts nobody, and a test that never asks for a certificate
// must still find none.
//
// A LIBRARY (rule 3). It registers nothing. Every hash, key and random
// value is `common/crypto.js`'s (rule 3r), and both certificates are
// issued through `common/pki.js`'s `issueOutsideHierarchy()` (3w).
// `common/keystore.js`, `pki.js` and the cluster claim are required
// inside the methods that use them, so loading this module moves no
// route and closes no cycle with the issuer or the status list.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import stsCrypto = require('../common/crypto');

const GROUP = 'mdoc';
const IACA_SLOT = 'mdoc-iaca';
const DS_SLOT = 'mdoc-ds';
const IACA_KID = 'sts-mdoc-iaca';
const DS_KID = 'sts-mdoc-ds';
const MINT_SCOPE = 'keys.mdoc-authority-mint';
const MINT_WAIT_MS = 15000;
const MINT_POLL_MS = 100;
const HOUR_MS = 3600000;
const YEAR_MS = 365 * 86400000;
const DS_EKU = '1.0.18013.5.1.2';

interface MdocAuthorityDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  helpers: typeof helpers;
  stsCrypto: typeof stsCrypto;
}

/**
 * One minted authority: the IACA the verifier trusts, and the document
 * signer an issuance signs with.
 */
interface MdocPair {
  iacaPem: string;
  dsPem: string;
  dsDer: Buffer;
  dsKey: any;
  dsKid: string;
}

/**
 * The realm's mdoc Issuing Authority CA and document signer (#1862).
 */
class MdocAuthority {
  /**
   * Builds an authority with the dependencies it reads.
   *
   * @param deps - the logger, settings, error codes, helpers and
   *   `common/crypto.js`
   */
  constructor(private readonly deps: MdocAuthorityDeps) {
  }

  // The mint this process has in flight, per realm and key set.
  private readonly inFlight = new Map<string, Promise<MdocPair>>();

  /**
   * The dependencies a process without the composition root builds with.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): MdocAuthorityDeps {
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      helpers: helpers,
      stsCrypto: stsCrypto
    };
  }

  /**
   * The IACA certificate PEM when one has already been minted, or `''`.
   * Does not mint.
   *
   * @param realmId - a named realm, or the ambient one when omitted
   * @returns the PEM, or `''`
   */
  currentPem(realmId?: string): string {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.currentPem().");
    try {
      const keys = this.keysFor(realmId);
      const live = this.slotOf(keys, IACA_SLOT);
      if (live && live.certPem) {
        log.debug("Leaving MdocAuthority.currentPem(). Held.");
        return String(live.certPem);
      }
      const held = this.heldCert(keys, realmId, IACA_SLOT);
      log.debug("Leaving MdocAuthority.currentPem(). " +
                (held ? "Shared." : "None."));
      return held;
    } catch (e) {
      log.debug("Caught in MdocAuthority.currentPem(): " +
                ((e && e.message) || e));
      // A realm with no key set has minted nothing. The verifier then
      // trusts only the anchors it was configured with.
      log.debug("Leaving MdocAuthority.currentPem(). No key set.");
      return '';
    }
  }

  /**
   * The authority for `keys`, minted on the first call and kept after.
   *
   * @param keys - the realm's key set
   * @param issuerUri - the credential issuer URI the IACA names
   * @returns the IACA, the document signer and its key
   */
  async ensure(keys: any, issuerUri: string): Promise<MdocPair> {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.ensure().");
    const held = this.pairFrom(keys);
    if (held) {
      log.debug("Leaving MdocAuthority.ensure(). Held.");
      return held;
    }
    const issuer = String(issuerUri || '').replace(/\/+$/, '');
    if (!issuer) {
      log.debug("Leaving MdocAuthority.ensure(). No issuer URI.");
      throw this.fail('the mdoc authority needs the credential ' +
                      'issuer URI and none was given.');
    }
    // ONE MINT PER REALM PER PROCESS AT A TIME (CI run #532). Every
    // concurrent request used to ask the cluster claim for itself, and
    // each one that lost waited out the whole bound on its own. The
    // requests of one process now share one promise, as
    // `credential_signer.js`'s `memberForAsync()` does.
    const flightKey = keys && keys.realm !== undefined
      ? String(keys.realm) + ' ' + String(keys.kid || '') : '';
    const flying = flightKey ? this.inFlight.get(flightKey) : undefined;
    if (flying) {
      log.debug("Leaving MdocAuthority.ensure(). One is in flight.");
      return flying;
    }
    const running = this.claimAndMint(keys, issuer);
    if (flightKey) {
      this.inFlight.set(flightKey, running);
      const release = (): void => {
        log.debug("Entering release().");
        if (this.inFlight.get(flightKey) === running) {
          this.inFlight.delete(flightKey);
        }
        log.debug("Leaving release().");
      };
      running.then(release, function (e: any) {
        log.debug("Caught in MdocAuthority.ensure(): " +
                  ((e && e.message) || e));
        // The caller awaiting `running` is the one told; this handler
        // only frees the slot so the next request may try again.
        release();
      });
    }
    log.debug("Leaving MdocAuthority.ensure(). Minting.");
    return running;
  }

  // The claim, then either the pair another process made or one made here.
  private async claimAndMint(keys: any, issuer: string): Promise<MdocPair> {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.claimAndMint().");
    await this.claimMint(keys);
    const raced = this.pairFrom(keys);
    if (raced) {
      log.debug("Leaving MdocAuthority.claimAndMint(). Minted elsewhere.");
      return raced;
    }
    const made = await this.mint(keys, issuer);
    log.debug("Leaving MdocAuthority.claimAndMint(). Minted.");
    return made;
  }

  // The ambient key set, or a named realm's. Throws when the set cannot
  // be read, which `currentPem()` turns into "none minted".
  private keysFor(realmId?: string): any {
    const { log, helpers } = this.deps;
    log.debug("Entering MdocAuthority.keysFor().");
    const keys = realmId === undefined ? helpers.stsKeysFor()
      : helpers.stsKeysFor.of(String(realmId));
    log.debug("Leaving MdocAuthority.keysFor().");
    return keys;
  }

  private slotOf(keys: any, slot: string): any {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.slotOf(). " + slot);
    const rows = (keys && keys.credentialSigners) || [];
    const found = rows.filter(function (one: any) {
      return one && one.slot === slot;
    })[0] || null;
    log.debug("Leaving MdocAuthority.slotOf(). " +
              (found ? "Held." : "None."));
    return found;
  }

  private heldCert(keys: any, realmId: string | undefined,
                   slot: string): string {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.heldCert(). " + slot);
    const id = keys && keys.realm !== undefined ? String(keys.realm)
      : String(realmId || '');
    const keystore = require('../common/keystore');
    const rows = keystore.credentialSignersHeldFor(id) || [];
    const pub = rows.filter(function (one: any) {
      return one && one.slot === slot && one.certPem;
    })[0];
    log.debug("Leaving MdocAuthority.heldCert(). " +
              (pub ? "Held." : "None."));
    return pub ? String(pub.certPem) : '';
  }

  private privateOf(row: any, realmId: string): any {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.privateOf().");
    if (row) {
      try {
        if (row.privateKey) {
          log.debug("Leaving MdocAuthority.privateOf(). On the row.");
          return row.privateKey;
        }
      } catch (e) {
        log.debug("Caught in MdocAuthority.privateOf(): " +
                  ((e && e.message) || e));
        // The row's getter throws when the keystore cannot decrypt.
        // The caller mints again rather than signing with nothing.
      }
    }
    const kid = row && row.publicJwk && row.publicJwk.kid;
    if (!realmId || !kid) {
      log.debug("Leaving MdocAuthority.privateOf(). None.");
      return null;
    }
    const keystore = require('../common/keystore');
    const key = keystore.credentialSignerPrivateFor(realmId, kid);
    log.debug("Leaving MdocAuthority.privateOf(). " +
              (key ? "From the keystore." : "None."));
    return key || null;
  }

  private derOf(pem: string): Buffer {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.derOf().");
    const body = String(pem || '').replace(/-----[^-]+-----|\s+/g, '');
    log.debug("Leaving MdocAuthority.derOf().");
    return Buffer.from(body, 'base64');
  }

  // Both certificates and the document signer's key, or null: the pair
  // this key set carries, and otherwise the pair the keystore holds for
  // the realm — the store's row or a sibling's shared blob.
  //
  // **THE SECOND HALF IS WHAT A LOST CLAIM WAITS FOR (CI run #532).** It
  // read the certificates from the keystore and the private key through
  // the kid of THIS key set's own document-signer row, so a process whose
  // set had no such row — every process but the one that minted — never
  // found the pair however long it waited. In the cluster, cells and
  // MariaDB modes each request that lost the claim waited the whole
  // MINT_WAIT_MS and then minted an authority of its own.
  private pairFrom(keys: any): MdocPair | null {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.pairFrom().");
    const realmId = keys && keys.realm !== undefined
      ? String(keys.realm) : '';
    const own = this.pairOf(this.slotOf(keys, IACA_SLOT),
                            this.slotOf(keys, DS_SLOT), realmId);
    if (own) {
      log.debug("Leaving MdocAuthority.pairFrom(). On the key set.");
      return own;
    }
    if (!realmId) {
      log.debug("Leaving MdocAuthority.pairFrom(). Incomplete.");
      return null;
    }
    const keystore = require('../common/keystore');
    const rows = keystore.credentialSignersHeldFor(realmId) || [];
    const heldRow = function (slot: string): any {
      return rows.filter(function (one: any) {
        return one && one.slot === slot && one.certPem;
      })[0] || null;
    };
    const held = this.pairOf(heldRow(IACA_SLOT), heldRow(DS_SLOT),
                             realmId);
    log.debug("Leaving MdocAuthority.pairFrom(). " +
              (held ? "Held for the realm." : "Incomplete."));
    return held;
  }

  // The pair two rows make, or null where either certificate or the
  // document signer's private key is missing.
  private pairOf(iaca: any, ds: any, realmId: string): MdocPair | null {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.pairOf().");
    const iacaPem = iaca && iaca.certPem;
    const dsPem = ds && ds.certPem;
    if (!iacaPem || !dsPem) {
      log.debug("Leaving MdocAuthority.pairOf(). A certificate is missing.");
      return null;
    }
    const dsKey = this.privateOf(ds, realmId);
    if (!dsKey) {
      log.debug("Leaving MdocAuthority.pairOf(). No private key.");
      return null;
    }
    const kid = (ds.publicJwk && ds.publicJwk.kid) || DS_KID;
    log.debug("Leaving MdocAuthority.pairOf().");
    return { iacaPem: String(iacaPem), dsPem: String(dsPem),
             dsDer: this.derOf(String(dsPem)), dsKey: dsKey,
             dsKid: String(kid) };
  }

  // One claim for the realm. A lost claim waits, then mints here, which
  // is what a credential signer does when the winner never arrives. NOT
  // named `claim`: its body calls `claims.claim()`, and a method whose body
  // names itself beside a `setTimeout` is what tests/no_periodic_timers.js
  // reads as a timer chain. The wait below is one bounded operation.
  private async claimMint(keys: any): Promise<void> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering MdocAuthority.claimMint().");
    if (!keys || keys.realm === undefined) {
      log.debug("Leaving MdocAuthority.claimMint(). No realm.");
      return;
    }
    let claimed: any = { ok: true, reason: '' };
    try {
      const claims = require('../cluster/cluster_claims');
      claimed = await claims.claim({
        scope: MINT_SCOPE,
        value: String(keys.realm) + ':' + String(keys.kid || '') +
               ':mdoc',
        realm: String(keys.realm), ttlMs: 60000 });
    } catch (e) {
      log.debug("Caught in MdocAuthority.claimMint(): " +
                ((e && e.message) || e));
      // No claim service in this process: minting here is the only
      // copy there will be.
      claimed = { ok: true, reason: '' };
    }
    if (claimed.ok || claimed.reason !== 'used') {
      log.debug("Leaving MdocAuthority.claimMint(). This process.");
      return;
    }
    const deadline = Date.now() + MINT_WAIT_MS;
    while (Date.now() < deadline) {
      if (this.pairFrom(keys)) {
        log.debug("Leaving MdocAuthority.claimMint(). Arrived.");
        return;
      }
      // A per-operation poll inside one bounded wait, not periodic work.
      await new Promise(function (resolve) {
        setTimeout(resolve, MINT_POLL_MS);
      });
    }
    log.warn(errorCodes.tag('STS-PKI-0288') + 'mdoc_authority: another ' +
             'process claimed the "' + keys.realm + '" realm\'s mdoc ' +
             'authority and it did not arrive within ' + MINT_WAIT_MS +
             'ms; it is made here.');
    log.debug("Leaving MdocAuthority.claimMint(). Timed out.");
  }

  private async mint(keys: any, issuer: string): Promise<MdocPair> {
    const { log, config, stsCrypto } = this.deps;
    log.debug("Entering MdocAuthority.mint().");
    const country = this.country();
    const authority = String(config.value(
      'oid4vci.mdocIssuingAuthority') || 'Iya STS');
    const pki = require('../common/pki');
    const keyMaterial = require('../common/crypto_impl/key_material');
    const now = Date.now();
    const notBefore = new Date(now - HOUR_MS).toISOString();
    let caPair: any;
    let dsPair: any;
    let ca: any;
    let ds: any;
    try {
      caPair = await keyMaterial.generateKeyPair('ec-p256');
      ca = await pki.issueOutsideHierarchy({
        subject: [{ name: 'C', value: country },
                  { name: 'CN', value: authority + ' IACA' }],
        subjectPublicKey: caPair.publicPem,
        issuerPrivateKey: caPair.privatePem,
        signatureAlg: 'sha256-ecdsa',
        serial: stsCrypto.randomBytes(8).toString('hex'),
        notBefore: notBefore,
        notAfter: new Date(now + 10 * YEAR_MS).toISOString(),
        extensions: {
          basicConstraints: { present: true, critical: true, ca: true,
                              pathLen: 0 },
          keyUsage: { present: true, critical: true,
                      usages: ['keyCertSign', 'cRLSign'] },
          subjectKeyIdentifier: { present: true },
          issuerAltName: { present: true,
                           names: [{ kind: 'uri', value: issuer }] },
          cRLDistributionPoints: { present: true,
                                   urls: [issuer + '/oid4vci/mdoc-crl'] }
        }
      });
      dsPair = await keyMaterial.generateKeyPair('ec-p256');
      ds = await pki.issueOutsideHierarchy({
        subject: [{ name: 'C', value: country },
                  { name: 'CN', value: authority + ' document signer' }],
        subjectPublicKey: dsPair.publicPem,
        issuer: { certificatePem: ca.pem,
                  privateKeyPem: caPair.privatePem,
                  keyAlg: 'ec-p256' },
        signatureAlg: 'sha256-ecdsa',
        serial: stsCrypto.randomBytes(8).toString('hex'),
        notBefore: notBefore,
        notAfter: new Date(now + 2 * YEAR_MS).toISOString(),
        extensions: {
          keyUsage: { present: true, critical: true,
                      usages: ['digitalSignature'] },
          extKeyUsage: { present: true, critical: true,
                         usages: [DS_EKU] },
          subjectKeyIdentifier: { present: true },
          authorityKeyIdentifier: { present: true }
        }
      });
    } catch (e) {
      log.debug("Caught in MdocAuthority.mint(): " +
                ((e && e.message) || e));
      log.debug("Leaving MdocAuthority.mint(). The certificates failed.");
      throw this.fail('the mdoc IACA or document signer could not ' +
                      'be minted: ' + ((e && e.message) || e));
    }
    const iacaRow = this.row(IACA_SLOT, DS_SLOT, IACA_KID,
                             caPair.privatePem, ca.pem);
    const dsRow = this.row(DS_SLOT, IACA_SLOT, DS_KID,
                           dsPair.privatePem, ds.pem);
    this.keep(keys, [iacaRow, dsRow]);
    log.debug("Leaving MdocAuthority.mint(). " + DS_KID);
    return { iacaPem: ca.pem, dsPem: ds.pem,
             dsDer: Buffer.from(ds.der),
             dsKey: stsCrypto.privateKeyFrom(dsPair.privatePem),
             dsKid: DS_KID };
  }

  private country(): string {
    const { log, config } = this.deps;
    log.debug("Entering MdocAuthority.country().");
    const raw = String(config.value('oid4vci.mdocIssuingCountry') ||
                       'US').trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(raw)) {
      log.debug("Leaving MdocAuthority.country(). Not an alpha-2.");
      throw this.fail('oid4vci.mdocIssuingCountry must be an ISO ' +
                      '3166-1 alpha-2 country code.');
    }
    log.debug("Leaving MdocAuthority.country(). " + raw);
    return raw;
  }

  private row(slot: string, paired: string, kid: string,
              privatePem: string, certPem: string): any {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering MdocAuthority.row(). " + slot);
    const jwk: any = stsCrypto.publicKeyOf(privatePem)
      .export({ format: 'jwk' });
    jwk.kid = kid;
    jwk.alg = 'ES256';
    jwk.use = 'sig';
    delete jwk.d;
    log.debug("Leaving MdocAuthority.row().");
    return {
      group: GROUP, slot: slot, alg: 'ES256', kind: 'ec',
      pairedSlot: paired, publicJwk: jwk,
      privateKey: stsCrypto.privateKeyFrom(privatePem),
      certPem: certPem
    };
  }

  private keep(keys: any, made: any[]): void {
    const { log } = this.deps;
    log.debug("Entering MdocAuthority.keep().");
    const kept = ((keys && keys.credentialSigners) || [])
      .filter(function (one: any) {
        return one && one.slot !== IACA_SLOT && one.slot !== DS_SLOT;
      });
    keys.credentialSigners = kept.concat(made);
    if (keys && keys.realm !== undefined) {
      const keystore = require('../common/keystore');
      keystore.remember(String(keys.realm), keys);
      keystore.publishShared(String(keys.realm), keys);
    }
    log.debug("Leaving MdocAuthority.keep().");
  }

  private fail(message: string): Error {
    const { log, errorCodes } = this.deps;
    log.debug("Entering MdocAuthority.fail().");
    log.error(errorCodes.tag('STS-PKI-0288') + 'mdoc_authority: ' +
              message);
    const err: any = new Error(message);
    err.code = 'STS-PKI-0288';
    errorCodes.mark(err, 'STS-PKI-0288');
    log.debug("Leaving MdocAuthority.fail().");
    return err;
  }
}

const slot = new InstanceSlot<MdocAuthority>(
  'oid4vc/mdoc_authority',
  () => new MdocAuthority(MdocAuthority.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The realm's mdoc Issuing Authority CA and document signer.
 *
 * @namespace
 */
export = {
  MdocAuthority: MdocAuthority,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: MdocAuthority): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  ensure: slot.forward('ensure'),
  currentPem: slot.forward('currentPem')
};
