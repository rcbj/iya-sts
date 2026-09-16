'use strict';
//
// File: scep_ra.ts
//
// ===========================================================================
// THE SCEP REGISTRATION AUTHORITY CERTIFICATE, PER TRUST REALM (2026-09-13).
//
// RFC 8894 section 2.5.1 lets a CA delegate to an RA, and every SCEP client
// then does two things with the RA certificate it finds in GetCACert: it
// ENCRYPTS its request to it (the pkcsPKIEnvelope, RSA key transport), and it
// VERIFIES the CertRep's signature against it. So the RA key pair is an RSA
// key whatever the SCEP Issuing CA is, it carries `digitalSignature` and
// `keyEncipherment`, and it is ours — this is the one private key in the SCEP
// family, and it never leaves this module except into the CMS code that
// decrypts and signs with it.
//
// **IT IS A LEAF OF THE REALM'S SCEP ISSUING CA, ISSUED THROUGH `pki.certify()`
// UNDER THE SLOT `scep-ra`, `pinned`.** Three consequences, each the reason it
// is done that way rather than with a store of this module's own:
//
//   * the private key lives in the realm's PKI row, sealed under the
//     key-encryption key in product mode with the rest of the hierarchy — a
//     second place to keep a private key is the one nobody seals or rotates
//     (`common/CLAUDE.md` 3w's placement argument);
//   * `certify()` RECORDS it, so the SCEP Issuing CA's OCSP responder answers
//     `good` about it and its CRL can list it;
//   * a realm removed takes it with it, because the row goes.
//
// **IT IS RE-ISSUED ON DEMAND, NOT ON A TIMER**: when it is missing, when it
// expires within thirty days, when its key is not the size
// `scep.raKeyAlgorithm` names, or when it no longer chains to the SCEP Issuing
// CA the realm now has (a rebuilt branch). The certificate it replaces is put
// on the Issuing CA's list as `superseded`, which is `pki.js`'s own rule for a
// slot that is reissued.
//
// **THE RACE ACROSS PROCESSES WAS STATED RATHER THAN SOLVED, AND ACROSS NODES
// IT STOPPED BEING A RACE (fixed 2026-09-14, #46).** Two processes that both
// found the RA stale both issued one, and the PKI row was last write wins — so
// a client that fetched one node's RA in GetCACert and sent PKIOperation to
// another was answered FAILURE badMessageCheck (`STS-SCEP-0027`) on EVERY
// alternation, not in a window: each container issued its own lazily. Now,
// where the store arbitrates, one process in the cluster issues it
// (`pki.oneBuildInTheCluster()`, under a claim of its own), the row is read
// from the store before deciding and again once the claim is held, and a
// certificate slot is first writer wins in the row's merge — so a node that
// issued one at the same moment as another takes the other's. Inside one
// process the re-issue is still serialised per realm below; where nothing
// arbitrates this is what it was.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScepRa` takes the modules it uses through its constructor
// (`ScepRaDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `ScepRa` is exported beside them for the
// composition root.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');

import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import pki = require('../common/pki');
import core = require('../common/cert_enrollment');
// The table active-active mode is held to, for the row this file provides.
import capabilities = require('../cluster/cluster_capabilities');

const SLOT = 'scep-ra';

// An RA certificate this close to expiry is replaced before it is served: a
// client that fetched it today must still be able to encrypt to it tomorrow.
const RENEW_WITHIN_MS = 30 * 86400000;

// The one re-issue per realm in flight in this process.
const building = new Map();

// A freshly generated key pair, both halves PEM.
interface KeyPairPem {
  publicKeyPem: string;
  privateKeyPem: string;
}

// What `ScepRa` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface ScepRaDeps {
  nodeCrypto: typeof nodeCrypto;
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  pki: typeof pki;
  core: typeof core;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadPkiRevocation(): typeof import('../common/pki_revocation');
}

class ScepRa {
  constructor(private readonly deps: ScepRaDeps) {
    deps.log.debug("Entering ScepRa.constructor().");
    deps.log.debug("Leaving ScepRa.constructor().");
  }

  wantedBits() {
    const { log, config } = this.deps;
    log.debug("Entering ScepRa.wantedBits().");
    const alg = String(config.value('scep.raKeyAlgorithm') || 'rsa-2048');
    const match = /^rsa-(2048|3072|4096)$/.exec(alg);
    log.debug("Leaving ScepRa.wantedBits().");
    return match ? Number(match[1]) : 2048;
  }

  recordOf(realmId) {
    const { log, pki } = this.deps;
    log.debug("Entering ScepRa.recordOf().");
    let held = null;
    try {
      held = pki.certificateFor(realmId, 'scep', SLOT);
    } catch (e) {
      log.debug("Caught in ScepRa.recordOf(): " + ((e && e.message) || e));
      held = null;
    }
    log.debug("Leaving ScepRa.recordOf().");
    return held;
  }

  // Why the held RA certificate would not be served, or '' when it would.
  staleness(realmId, held) {
    const { log, nodeCrypto, core } = this.deps;
    log.debug("Entering ScepRa.staleness().");
    if (!held || !held.certificatePem || !held.privateKeyPem) {
      log.debug("Leaving ScepRa.staleness(). Missing.");
      return 'missing';
    }
    if (new Date(held.notAfter).getTime() - Date.now() < RENEW_WITHIN_MS) {
      log.debug("Leaving ScepRa.staleness(). Expiring.");
      return 'expiring';
    }
    let bits = 0;
    try {
      const key = new nodeCrypto.X509Certificate(held.certificatePem).publicKey;
      bits = key.asymmetricKeyType === 'rsa'
        ? key.asymmetricKeyDetails.modulusLength : 0;
    } catch (e) {
      log.debug("Caught in ScepRa.staleness(): " + ((e && e.message) || e));
      bits = 0;
    }
    if (bits !== this.wantedBits()) {
      log.debug("Leaving ScepRa.staleness(). Algorithm.");
      return 'algorithm';
    }
    const chain = core.caChainOf('scep');
    if (!chain.ok || (held.chainPem || [])[0] !== chain.issuingPem) {
      log.debug("Leaving ScepRa.staleness(). A different Issuing CA.");
      return 'issuer';
    }
    log.debug("Leaving ScepRa.staleness(). Current.");
    return '';
  }

  async issue(realmId, previous, reason) {
    const { log, nodeCrypto, pki, errorCodes, core,
            loadPkiRevocation } = this.deps;
    log.debug("Entering ScepRa.issue(). reason=" + reason);
    const bits = this.wantedBits();
    const pair = await new Promise<KeyPairPem>(function (resolve, reject) {
      nodeCrypto.generateKeyPair('rsa', {
        modulusLength: bits,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }, function (err, publicKey, privateKey) {
        if (err) {
          reject(err);
          return;
        }
        resolve({ publicKeyPem: publicKey, privateKeyPem: privateKey });
      });
    });
    const made = await pki.certify(realmId, 'scep', {
      slot: SLOT,
      label: 'SCEP RA',
      commonName: 'SCEP RA',
      keyAlg: 'rsa-' + bits,
      publicKeyPem: pair.publicKeyPem,
      privateKeyPem: pair.privateKeyPem,
      pinned: true,
      profile: 'digital-signature',
      keyUsage: ['digitalSignature', 'keyEncipherment']
    });
    if (!made.ok) {
      log.error(errorCodes.tag('STS-SCEP-0006') + 'scep: the RA certificate ' +
                'for realm "' + realmId + '" could not be issued: ' +
                (made.errors || []).join(' '));
      log.debug("Leaving ScepRa.issue(). certify() refused.");
      return errorCodes.mark({ ok: false, errors: ['The SCEP RA certificate ' +
        'could not be issued: ' + (made.errors || []).join(' ')] },
                             'STS-SCEP-0006');
    }
    if (previous && previous.serialHex &&
        core.normalSerial(previous.serialHex) !==
        core.normalSerial(made.record.serialHex)) {
      try {
        loadPkiRevocation().revoke(realmId, 'scep', {
          serialHex: previous.serialHex, reason: 'superseded',
          subject: previous.subject,
          note: 'the SCEP RA certificate was re-issued (' + reason + ')' });
      } catch (e) {
        log.debug("Caught in ScepRa.issue(): " + ((e && e.message) || e));
        // The new certificate is in place and serving; a CRL entry that could
        // not be written leaves the old one merely unlisted, which is logged.
        log.warn(errorCodes.tag('STS-SCEP-0006') + 'scep: the replaced RA ' +
                 'certificate could not be marked superseded: ' +
                 ((e && e.message) || e));
      }
    }
    log.info('scep: an RSA-' + bits + ' RA certificate was issued in realm "' +
             realmId + '" (' + reason + '), serial ' + made.record.serialHex +
             ', expires ' + made.record.notAfter + '.');
    log.debug("Leaving ScepRa.issue().");
    return { ok: true, record: this.recordOf(realmId) };
  }

  // ---------------------------------------------------------------------------
  // ONE RA CERTIFICATE FOR THE CLUSTER. The row is read from the store first —
  // another node may already have issued a current one — and the issue runs
  // under a claim of its own (`scep-ra:<realm>`, never the branch's:
  // `certify()` may repair the branch under that). `force` is the console's
  // Reissue, which replaces a current certificate and so has no "already there"
  // answer.
  // ---------------------------------------------------------------------------
  issueInTheCluster(realmId, held, why, force) {
    const { log, pki } = this.deps;
    const self = this;
    log.debug("Entering ScepRa.issueInTheCluster().");
    const existing = force ? null : function () {
      log.debug("Entering existing().");
      const now = self.recordOf(realmId);
      log.debug("Leaving existing().");
      return now && !self.staleness(realmId, now) ? { ok: true, record: now } :
             null;
    };
    log.debug("Leaving ScepRa.issueInTheCluster().");
    return pki.oneBuildInTheCluster(realmId, 'certs.scep:' + SLOT, existing,
      function () {
        // THE RECORD BEING REPLACED IS READ AGAIN: the row may have come from
        // the store since `ensure()` looked.
        const current = self.recordOf(realmId) || held;
        return self.issue(realmId, current, why);
      },
      { claim: 'scep-ra:' + String(realmId),
        label: 'the SCEP RA certificate of realm "' + (realmId || 'default') +
               '"' });
  }

  // The RA to use now: `{ ok, certificatePem, privateKeyPem, record }`, issuing
  // one first when the held one is stale. `options.force` re-issues regardless.
  async ensure(realmId, options?) {
    const { log, core, errorCodes } = this.deps;
    log.debug("Entering ScepRa.ensure(). realm=" + realmId);
    const opts = options || {};
    const chain = await core.ensureAuthority('scep');
    if (!chain.ok) {
      log.debug("Leaving ScepRa.ensure(). No SCEP Issuing CA.");
      return errorCodes.mark({ ok: false, errors: ['This realm has no ' +
        'certificate authority yet, so it has no SCEP Issuing CA and no RA ' +
        'certificate. Build the hierarchy on /admin/pki.'] }, 'STS-SCEP-0005');
    }
    const held = this.recordOf(realmId);
    const why = opts.force ? 'requested' : this.staleness(realmId, held);
    if (!why) {
      log.debug("Leaving ScepRa.ensure(). Current.");
      return { ok: true, certificatePem: held.certificatePem,
               privateKeyPem: held.privateKeyPem, record: held };
    }
    const key = String(realmId);
    if (!building.has(key)) {
      building.set(key, this.issueInTheCluster(realmId, held, why, !!opts.force)
        .finally(function () {
          building.delete(key);
        }));
    }
    const made = await building.get(key);
    if (!made.ok) {
      log.debug("Leaving ScepRa.ensure(). Not issued.");
      return made;
    }
    log.debug("Leaving ScepRa.ensure(). Issued.");
    return { ok: true, certificatePem: made.record.certificatePem,
             privateKeyPem: made.record.privateKeyPem, record: made.record,
             reissued: why };
  }

  // What a page and /admin-api show, and no private key.
  describe(realmId) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering ScepRa.describe().");
    const held = this.recordOf(realmId);
    if (!held) {
      log.debug("Leaving ScepRa.describe(). None.");
      return { present: false, status: 'missing', keyAlgorithm:
               'rsa-' + this.wantedBits() };
    }
    let keyAlg = '';
    try {
      const key = new nodeCrypto.X509Certificate(held.certificatePem).publicKey;
      keyAlg = 'rsa-' + key.asymmetricKeyDetails.modulusLength;
    } catch (e) {
      log.debug("Caught in ScepRa.describe(): " + ((e && e.message) || e));
      keyAlg = '';
    }
    const why = this.staleness(realmId, held);
    log.debug("Leaving ScepRa.describe().");
    return {
      present: true,
      status: why || 'current',
      subject: held.subject,
      serialHex: held.serialHex,
      keyAlgorithm: keyAlg,
      wantedKeyAlgorithm: 'rsa-' + this.wantedBits(),
      notBefore: held.notBefore,
      notAfter: held.notAfter,
      thumbprint: held.thumbprint,
      certificatePem: held.certificatePem
    };
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const scepRa = new ScepRa({
  nodeCrypto: nodeCrypto,
  log: log,
  config: config,
  errorCodes: errorCodes,
  pki: pki,
  core: core,
  loadPkiRevocation: function () {
    return require('../common/pki_revocation');
  }
});

// DECLARED AT REQUIRE TIME (cluster/CLAUDE.md): every node presents the RA
// certificate one node issued — `issueInTheCluster()` above.
capabilities.provide('scep.ra-agreement');

export = {
  ScepRa: ScepRa,
  SLOT: SLOT,
  RENEW_WITHIN_MS: RENEW_WITHIN_MS,
  ensure: scepRa.ensure.bind(scepRa) as ScepRa['ensure'],
  describe: scepRa.describe.bind(scepRa) as ScepRa['describe'],
  staleness: scepRa.staleness.bind(scepRa) as ScepRa['staleness']
};
