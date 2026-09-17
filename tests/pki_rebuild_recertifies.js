'use strict';
//
// File: pki_rebuild_recertifies.js
//
// ===========================================================================
// A BRANCH REBUILT UNDER A REALM'S SIGNING KEYS LEAVES THEM PUBLISHING
// CERTIFICATES FROM THE NEW BRANCH, NOT THE ONE IT REPLACED (2026-09-15, #46).
//
// `tests/vendored/sts_pki_distribution_points.js` found it over HTTP: a realm
// created and then rebuilt with `POST /admin-api/pki/build` published its
// signing keys' certificates from the SUPERSEDED Issuing CAs, with the old
// Intermediate in their chain, so `intermediate.crl` was named by the
// certificates of two authorities. Two holes made it and this file holds each
// shut:
//
//   A. **THE BUILD ACTION DID NOT RE-MINT.** `pki_admin.ts`'s `build` — the
//      action `/admin-api/pki/build` reaches — rebuilt the branch and left the
//      row's recorded certificates where they were, which `build-scope` and a
//      Root replacement never did. It was hidden by WHEN a runtime realm's
//      keys were made (after the rebuild, until `app.js` began making them
//      before the handler), so the assertion here certifies the keys FIRST,
//      which is the order the service now runs in every time.
//   B. **A CERTIFICATION IN FLIGHT ACROSS THE REBUILD.** The realm watcher
//      certifies a new realm's keys in the same moment the rebuild runs, and
//      a certificate signed by the old authority and recorded after the new
//      one was stored would never be re-minted by A. `certify()` now signs it
//      again from the authority the row holds when it records it. Driven
//      deterministically: the encoder is wrapped so that the authority is
//      replaced between the signature and the record.
//
// Mutation-checked by hand on the day: removing the re-mint in A, and the
// signing-again branch in B, each turns its section red.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const helpers = require('../common/helpers');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const x509 = require('../common/vendored/x509');
const pkiAdmin = require('../admin-ui/pki_admin');

const log = require('bunyan').createLogger({ name: 'pki_rebuild_recertifies',
  level: process.env.LOG_LEVEL || 'info' });

const REALM_BUILD = 'rebuild-remint-' + nodeCrypto.randomBytes(3)
  .toString('hex');
const REALM_FLIGHT = 'rebuild-flight-' + nodeCrypto.randomBytes(3)
  .toString('hex');

function issuedBy(certificatePem, caPem) {
  log.debug("Entering issuedBy().");
  const leaf = new nodeCrypto.X509Certificate(certificatePem);
  const ca = new nodeCrypto.X509Certificate(caPem);
  log.debug("Leaving issuedBy().");
  return leaf.issuer === ca.subject && leaf.verify(ca.publicKey);
}

// Every recorded certificate of one use case whose chain does not start with
// the Issuing CA the row holds now.
function staleSlots(realmId, useCaseId) {
  log.debug("Entering staleSlots().");
  const row = keystore.pkiFor(realmId);
  const now = row.issuing[useCaseId].certificatePem;
  log.debug("Leaving staleSlots().");
  return pki.certificatesFor(realmId, useCaseId).filter(function (one) {
    return (one.chainPem || [])[0] !== now ||
           !issuedBy(one.certificatePem, now);
  }).map(function (one) {
    return useCaseId + ':' + one.slot;
  });
}

async function sectionBuildAction(t) {
  log.debug("Entering sectionBuildAction().");
  t.log.info('=== A. the build action re-mints what the old branch had ' +
             'certified for the realm\'s own keys ===');
  const realm = realms.get(REALM_BUILD);
  const built = await pki.ensureScope(REALM_BUILD);
  t.check(built.ok, 'the realm has a branch', JSON.stringify(built.errors));
  const keys = helpers.stsKeysFor.of(REALM_BUILD);
  t.equal(keys.realm, REALM_BUILD, 'the key set is this realm\'s own');
  const first = await pki.certifyKeySet(REALM_BUILD, keys);
  t.check(first.ok && first.certified > 0,
          'its keys are certified from the branch BEFORE the rebuild — the ' +
          'order a runtime realm now runs in',
          JSON.stringify(first.failed || []));
  const oldIntermediate = keystore.pkiFor(REALM_BUILD).intermediate
    .certificatePem;

  const answer = await realms.run(realm, function () {
    return pkiAdmin.pkiAction({ action: 'build',
                                organisation: 'Rebuild Remint',
                                country: 'US' });
  });
  t.check(answer.ok, 'the build action answers ok',
          (answer.errors || []).join(' '));
  const row = keystore.pkiFor(REALM_BUILD);
  t.check(row.intermediate.certificatePem !== oldIntermediate,
          'and it really replaced the Intermediate');
  const stale = staleSlots(REALM_BUILD, 'jose')
    .concat(staleSlots(REALM_BUILD, 'xml'));
  t.equal(stale.join(', '), '',
          'NO JOSE OR XML CERTIFICATE THE REALM RECORDS IS STILL FROM THE ' +
          'SUPERSEDED ISSUING CAs — each was re-minted from the new one');
  t.check(issuedBy(keys.certPem, row.issuing.jose.certificatePem),
          'the certificate the key set PUBLISHES is issued by the new JOSE ' +
          'Issuing CA', new nodeCrypto.X509Certificate(keys.certPem).issuer);
  t.equal(keys.certChainPem[1], row.intermediate.certificatePem,
          'and the chain it publishes under it names the NEW Intermediate, ' +
          'so the old one\'s revocation address is named by nothing it sends');
  t.check(/re-minted/.test(String(answer.why || '')),
          'the answer says certificates were re-minted', answer.why);
  log.debug("Leaving sectionBuildAction().");
}

async function sectionInFlight(t) {
  log.debug("Entering sectionInFlight().");
  t.log.info('=== B. a certificate signed by an authority replaced while it ' +
             'was being signed is signed again ===');
  const built = await pki.ensureScope(REALM_FLIGHT);
  t.check(built.ok, 'the realm has a branch', JSON.stringify(built.errors));
  const pair = nodeCrypto.generateKeyPairSync('ec',
                                              { namedCurve: 'prime256v1' });
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const original = x509.issueCertificate;
  let replacements = 0;
  let replaceEvery = false;
  let busy = false;
  x509.issueCertificate = async function (opts) {
    const out = await original.apply(this, arguments);
    const leaf = opts && opts.profile === 'digital-signature';
    if (leaf && !busy && (replaceEvery || replacements === 0)) {
      busy = true;
      try {
        // THE REPLACEMENT LANDS BETWEEN THE SIGNATURE AND THE RECORD, which
        // is the window a rebuild racing the realm watcher hits.
        const again = await pki.reissueUseCase(REALM_FLIGHT, 'jose');
        replacements += again.ok ? 1 : 0;
      } finally {
        busy = false;
      }
    }
    return out;
  };
  let once;
  let joseAfterOnce = '';
  let publishedAfterOnce = null;
  let always;
  try {
    once = await pki.certify(REALM_FLIGHT, 'jose', {
      slot: 'inflight-probe', alg: 'ES256', label: 'in-flight probe',
      commonName: 'in-flight probe', publicKeyPem: publicKeyPem });
    // Read NOW: the second probe below replaces the authority again.
    joseAfterOnce = keystore.pkiFor(REALM_FLIGHT).issuing.jose.certificatePem;
    publishedAfterOnce = pki.certificateFor(REALM_FLIGHT, 'jose',
                                            'inflight-probe');
    replaceEvery = true;
    always = await pki.certify(REALM_FLIGHT, 'jose', {
      slot: 'moving-probe', alg: 'ES256', label: 'moving probe',
      commonName: 'moving probe', publicKeyPem: publicKeyPem });
  } finally {
    x509.issueCertificate = original;
  }
  t.check(once.ok, 'the certification answers ok',
          (once.errors || []).join(' '));
  t.check(replacements >= 1, 'the JOSE Issuing CA really was replaced ' +
          'during the signature', String(replacements));
  t.equal((once.record.chainPem || [])[0], joseAfterOnce,
          'THE RECORDED CERTIFICATE NAMES THE AUTHORITY THE ROW HOLDS NOW, ' +
          'not the one it was first signed by');
  t.check(issuedBy(once.record.certificatePem, joseAfterOnce),
          'and is really signed by it');
  t.check(!!publishedAfterOnce &&
          publishedAfterOnce.certificatePem === once.record.certificatePem,
          'and that is the certificate the slot publishes');
  t.check(!always.ok &&
          errorCodes.codeOf(always) === 'STS-PKI-0186',
          'an authority replaced on EVERY signature is a bounded refusal ' +
          'with its own code rather than a loop',
          errorCodes.codeOf(always) + ' ' + (always.errors || []).join(' '));
  t.check(!pki.certificateFor(REALM_FLIGHT, 'jose', 'moving-probe'),
          'and nothing was recorded for that slot');
  log.debug("Leaving sectionInFlight().");
}

async function run(t) {
  log.debug("Entering run().");
  const hadRoot = !!keystore.pkiFor(pki.SERVICE_SCOPE);
  [REALM_BUILD, REALM_FLIGHT].forEach(function (id) {
    if (!realms.get(id)) {
      realms.create({ id: id, name: id });
    }
  });
  try {
    await sectionBuildAction(t);
    await sectionInFlight(t);
  } finally {
    // Whatever this file made, it removes: `run.js` runs every file in one
    // process, and a Root left behind is the Root `tests/pki.js` meets.
    [REALM_BUILD, REALM_FLIGHT].forEach(function (id) {
      keystore.attachPki(id, null);
      if (realms.get(id)) {
        realms.remove(id);
      }
    });
    if (!hadRoot && keystore.pkiFor(pki.SERVICE_SCOPE)) {
      keystore.attachPki(pki.SERVICE_SCOPE, null);
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_rebuild_recertifies',
  describe: 'A realm branch rebuilt with the build action re-mints its ' +
            'signing keys\' certificates from the new authorities, and a ' +
            'certificate whose Issuing CA was replaced while it was being ' +
            'signed is signed again — or refused, bounded, with STS-PKI-0186.',
  run: run
};
