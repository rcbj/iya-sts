'use strict';
//
// File: scep_ra.js
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
// **THE ONE RACE IS ACROSS PROCESSES AND IT IS STATED RATHER THAN SOLVED.** In
// `dispatch` mode two workers that both find the RA stale may both issue one;
// the PKI row is last-write-wins over the keystore's channel, so a client that
// fetched the loser's certificate encrypts to a key nobody holds and is
// answered FAILURE badMessageCheck (`STS-SCEP-0027`) — GetCACert again fixes
// it. Inside one process the re-issue is serialised per realm below.
// ===========================================================================

const nodeCrypto = require('crypto');

const { log } = require('../common/helpers');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const pki = require('../common/pki');
const core = require('../common/cert_enrollment');

const SLOT = 'scep-ra';

// An RA certificate this close to expiry is replaced before it is served: a
// client that fetched it today must still be able to encrypt to it tomorrow.
const RENEW_WITHIN_MS = 30 * 86400000;

// The one re-issue per realm in flight in this process.
const building = new Map();

function wantedBits() {
  log.debug("Entering wantedBits().");
  const alg = String(config.value('scep.raKeyAlgorithm') || 'rsa-2048');
  const match = /^rsa-(2048|3072|4096)$/.exec(alg);
  log.debug("Leaving wantedBits().");
  return match ? Number(match[1]) : 2048;
}

function recordOf(realmId) {
  log.debug("Entering recordOf().");
  let held = null;
  try {
    held = pki.certificateFor(realmId, 'scep', SLOT);
  } catch (e) {
    log.debug("Caught in recordOf(): " + ((e && e.message) || e));
    held = null;
  }
  log.debug("Leaving recordOf().");
  return held;
}

// Why the held RA certificate would not be served, or '' when it would.
function staleness(realmId, held) {
  log.debug("Entering staleness().");
  if (!held || !held.certificatePem || !held.privateKeyPem) {
    log.debug("Leaving staleness(). Missing.");
    return 'missing';
  }
  if (new Date(held.notAfter).getTime() - Date.now() < RENEW_WITHIN_MS) {
    log.debug("Leaving staleness(). Expiring.");
    return 'expiring';
  }
  let bits = 0;
  try {
    const key = new nodeCrypto.X509Certificate(held.certificatePem).publicKey;
    bits = key.asymmetricKeyType === 'rsa'
      ? key.asymmetricKeyDetails.modulusLength : 0;
  } catch (e) {
    log.debug("Caught in staleness(): " + ((e && e.message) || e));
    bits = 0;
  }
  if (bits !== wantedBits()) {
    log.debug("Leaving staleness(). Algorithm.");
    return 'algorithm';
  }
  const chain = core.caChainOf('scep');
  if (!chain.ok || (held.chainPem || [])[0] !== chain.issuingPem) {
    log.debug("Leaving staleness(). A different Issuing CA.");
    return 'issuer';
  }
  log.debug("Leaving staleness(). Current.");
  return '';
}

async function issue(realmId, previous, reason) {
  log.debug("Entering issue(). reason=" + reason);
  const bits = wantedBits();
  const pair = await new Promise(function (resolve, reject) {
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
    log.debug("Leaving issue(). certify() refused.");
    return errorCodes.mark({ ok: false, errors: ['The SCEP RA certificate ' +
      'could not be issued: ' + (made.errors || []).join(' ')] },
                           'STS-SCEP-0006');
  }
  if (previous && previous.serialHex &&
      core.normalSerial(previous.serialHex) !==
      core.normalSerial(made.record.serialHex)) {
    try {
      require('../common/pki_revocation').revoke(realmId, 'scep', {
        serialHex: previous.serialHex, reason: 'superseded',
        subject: previous.subject,
        note: 'the SCEP RA certificate was re-issued (' + reason + ')' });
    } catch (e) {
      log.debug("Caught in issue(): " + ((e && e.message) || e));
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
  log.debug("Leaving issue().");
  return { ok: true, record: recordOf(realmId) };
}

// The RA to use now: `{ ok, certificatePem, privateKeyPem, record }`, issuing
// one first when the held one is stale. `options.force` re-issues regardless.
async function ensure(realmId, options) {
  log.debug("Entering ensure(). realm=" + realmId);
  const opts = options || {};
  const chain = await core.ensureAuthority('scep');
  if (!chain.ok) {
    log.debug("Leaving ensure(). No SCEP Issuing CA.");
    return errorCodes.mark({ ok: false, errors: ['This realm has no ' +
      'certificate authority yet, so it has no SCEP Issuing CA and no RA ' +
      'certificate. Build the hierarchy on /admin/pki.'] }, 'STS-SCEP-0005');
  }
  const held = recordOf(realmId);
  const why = opts.force ? 'requested' : staleness(realmId, held);
  if (!why) {
    log.debug("Leaving ensure(). Current.");
    return { ok: true, certificatePem: held.certificatePem,
             privateKeyPem: held.privateKeyPem, record: held };
  }
  const key = String(realmId);
  if (!building.has(key)) {
    building.set(key, issue(realmId, held, why).finally(function () {
      building.delete(key);
    }));
  }
  const made = await building.get(key);
  if (!made.ok) {
    log.debug("Leaving ensure(). Not issued.");
    return made;
  }
  log.debug("Leaving ensure(). Issued.");
  return { ok: true, certificatePem: made.record.certificatePem,
           privateKeyPem: made.record.privateKeyPem, record: made.record,
           reissued: why };
}

// What a page and /admin-api show, and no private key.
function describe(realmId) {
  log.debug("Entering describe().");
  const held = recordOf(realmId);
  if (!held) {
    log.debug("Leaving describe(). None.");
    return { present: false, status: 'missing', keyAlgorithm:
             'rsa-' + wantedBits() };
  }
  let keyAlg = '';
  try {
    const key = new nodeCrypto.X509Certificate(held.certificatePem).publicKey;
    keyAlg = 'rsa-' + key.asymmetricKeyDetails.modulusLength;
  } catch (e) {
    log.debug("Caught in describe(): " + ((e && e.message) || e));
    keyAlg = '';
  }
  const why = staleness(realmId, held);
  log.debug("Leaving describe().");
  return {
    present: true,
    status: why || 'current',
    subject: held.subject,
    serialHex: held.serialHex,
    keyAlgorithm: keyAlg,
    wantedKeyAlgorithm: 'rsa-' + wantedBits(),
    notBefore: held.notBefore,
    notAfter: held.notAfter,
    thumbprint: held.thumbprint,
    certificatePem: held.certificatePem
  };
}

module.exports = {
  SLOT: SLOT,
  RENEW_WITHIN_MS: RENEW_WITHIN_MS,
  ensure: ensure,
  describe: describe,
  staleness: staleness
};
