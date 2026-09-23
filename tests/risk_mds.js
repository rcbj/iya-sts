'use strict';
//
// File: risk_mds.js
//
// ===========================================================================
// THE FIDO METADATA SERVICE (#62 P5, 2026-09-22), in process, on the memory
// store, with a SYNTHETIC BLOB: a root and a signing certificate minted here,
// and entries invented here. No FIDO data is in this repository (the licence
// review on #62: MDS3 is contractual metadata, not open data).
//
//   A. AN ENTRY AS ROWS: one per key the model is listed under; the latest
//      status by date; compromised if any report ever said so; the
//      certification level; the icon dropped.
//   B. THE BLOB VERIFIED (`pki.verifyFidoMdsBlob()`, MDS3 section 3.1.8): a
//      good one; a changed payload; no x5c; a chain to somebody else's root.
//   C. IMPORTED: verified, activated, one row per key.
//   D. NOT NEWER IS REFUSED — a rollback (STS-RISK-0024).
//   E. THE LATEST ONLY: a newer BLOB is active and the older one's rows are
//      gone at once.
//   F. LOOKED UP by AAGUID: a revoked model is compromised; a model not
//      listed and the all-zero AAGUID are unknown, which decides nothing.
//   G. STALE past `nextUpdate` and the grace: nothing is known.
//   H. SCORED: a sign-in with a key whose model is revoked carries
//      `authenticator-compromised` and is HIGH.
//   I. A BLOB SIGNED UNDER ANOTHER ROOT is refused (STS-RISK-0022) and
//      recorded as a refused version.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const pki = require('../common/pki');
const x509 = require('../common/vendored/x509');
const keyMaterial = require('../common/vendored/key_material');
const riskStore = require('../risk/risk_store');
const riskDatasets = require('../risk/risk_datasets');
const riskTerms = require('../risk/risk_terms');
const riskEngine = require('../risk/risk_engine');

const log = require('bunyan').createLogger({ name: 'risk_mds',
  level: process.env.LOG_LEVEL || 'info' });

const REVOKED = '11111111-2222-4333-8444-555555555555';
const CERTIFIED = '66666666-7777-4888-9999-aaaaaaaaaaaa';
const DAY = 86400000;

// A root and a signing certificate under it, as FIDO's chain is shaped.
async function hierarchy(name) {
  log.debug("Entering hierarchy().");
  const rootPair = await keyMaterial.generateKeyPair('rsa-2048');
  const root = await x509.issueCertificate({
    subject: [{ name: 'CN', value: name + ' Root' }],
    subjectPublicKey: rootPair.publicPem, signatureAlg: 'sha256-rsa',
    profile: 'root-ca',
    issuer: { privateKeyPem: rootPair.privatePem, keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] } } });
  const signerPair = await keyMaterial.generateKeyPair('rsa-2048');
  const signer = await x509.issueCertificate({
    subject: [{ name: 'CN', value: name + ' MDS signer' }],
    subjectPublicKey: signerPair.publicPem, signatureAlg: 'sha256-rsa',
    profile: 'digital-signature',
    issuer: { certificatePem: root.pem, privateKeyPem: rootPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ['digitalSignature'] } } });
  log.debug("Leaving hierarchy().");
  return { rootPem: root.pem, signerPem: signer.pem,
           signerKey: signerPair.privatePem };
}

function derOf(pem) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

// A BLOB: an RS256 JWS over the payload, the chain in x5c.
function blobOf(h, payload) {
  log.debug("Entering blobOf().");
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT',
    x5c: [derOf(h.signerPem), derOf(h.rootPem)] })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = nodeCrypto.sign('sha256', Buffer.from(header + '.' +
                                                          body),
                                    h.signerKey).toString('base64url');
  log.debug("Leaving blobOf().");
  return header + '.' + body + '.' + signature;
}

function payloadOf(no, nextUpdateMs) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return {
    legalHeader: 'A synthetic BLOB for a test.', no: no,
    nextUpdate: new Date(nextUpdateMs).toISOString().slice(0, 10),
    entries: [
      { aaguid: REVOKED,
        metadataStatement: { description: 'Synthetic key, since revoked',
                             protocolFamily: 'fido2', icon: 'data:,x' },
        statusReports: [
          { status: 'FIDO_CERTIFIED_L1', effectiveDate: '2021-01-01' },
          { status: 'REVOKED', effectiveDate: '2025-06-01' }] },
      { aaguid: CERTIFIED,
        attestationCertificateKeyIdentifiers: ['ab01', 'AB02'],
        metadataStatement: { description: 'Synthetic key, certified',
                             protocolFamily: 'fido2' },
        statusReports: [
          { status: 'FIDO_CERTIFIED_L2', effectiveDate: '2022-01-01' }] }
    ] };
}

async function run(t) {
  log.debug("Entering run().");
  riskStore.reset();
  riskDatasets.forget();
  const now = Date.now();

  // --- A. an entry as rows ------------------------------------------------
  const rows = riskDatasets.mdsRowsOf(payloadOf(1, now).entries[0]);
  const certifiedRows = riskDatasets.mdsRowsOf(payloadOf(1, now).entries[1]);
  t.check(rows.length === 1 && rows[0].compromised === true &&
          rows[0].latestStatus === 'REVOKED' &&
          rows[0].certificationLevel === 'FIDO_CERTIFIED_L1' &&
          !rows[0].metadataStatement.icon,
          'A1. a revoked model: compromised, its latest status REVOKED, its ' +
          'certification kept, and no icon', JSON.stringify(rows[0]));
  t.check(certifiedRows.length === 3 &&
          certifiedRows.map(function (r) { return r.keyKind; }).join() ===
            'aaguid,acki,acki' && certifiedRows[2].key === 'ab02' &&
          certifiedRows[0].compromised === false,
          'A2. one row per key a model is listed under, keys lower-cased',
          JSON.stringify(certifiedRows.map(function (r) {
            return r.keyKind + ':' + r.key;
          })));

  // --- B. the BLOB verified ------------------------------------------------
  const fido = await hierarchy('Synthetic FIDO');
  const other = await hierarchy('Somebody Else');
  const good = blobOf(fido, payloadOf(5, now + 30 * DAY));
  const ok = await pki.verifyFidoMdsBlob(good, { anchorsPem: fido.rootPem });
  t.check(ok.ok && ok.payload.no === 5 && ok.chainPems.length === 2,
          'B1. a BLOB signed under the anchor verifies', ok.reason);
  const parts = good.split('.');
  const tampered = parts[0] + '.' + Buffer.from(JSON.stringify(
    payloadOf(99, now))).toString('base64url') + '.' + parts[2];
  const bad = await pki.verifyFidoMdsBlob(tampered,
                                          { anchorsPem: fido.rootPem });
  t.check(!bad.ok && /signature/.test(bad.reason),
          'B2. a changed payload does not', bad.reason);
  const bare = Buffer.from(JSON.stringify({ alg: 'RS256' }))
    .toString('base64url') + '.' + parts[1] + '.' + parts[2];
  const noChain = await pki.verifyFidoMdsBlob(bare,
                                              { anchorsPem: fido.rootPem });
  t.check(!noChain.ok && /x5c/.test(noChain.reason),
          'B3. nor one with no x5c', noChain.reason);
  const elsewhere = await pki.verifyFidoMdsBlob(
    blobOf(other, payloadOf(5, now)), { anchorsPem: fido.rootPem });
  t.check(!elsewhere.ok && /chain/.test(elsewhere.reason),
          'B4. nor one whose chain ends at somebody else\'s root',
          elsewhere.reason);

  // --- C. imported ----------------------------------------------------------
  config.setOverride('risk.mdsTrustAnchors', fido.rootPem);
  await riskTerms.accept({ provider: 'fido-mds3', acceptedBy: 'a test',
                           via: 'upload' });
  const first = await riskDatasets.importVersion({ dataset: 'fido.mds3',
    format: 'fido-mds3-jwt', content: good, source: 'upload' });
  t.check(first.ok && first.activated && first.rows === 4 &&
          first.serial === 5 && first.version === 'no-5',
          'C1. the BLOB is verified, loaded (four keys) and active',
          JSON.stringify(first));

  // --- D. not newer --------------------------------------------------------
  const older = await riskDatasets.importVersion({ dataset: 'fido.mds3',
    format: 'fido-mds3-jwt',
    content: blobOf(fido, payloadOf(4, now + 30 * DAY)), source: 'upload' });
  t.check(!older.ok && /serial number is 4/.test(older.errors[0]),
          'D1. an older BLOB is refused as a rollback (STS-RISK-0024)',
          JSON.stringify(older.errors));

  // --- E. the latest only --------------------------------------------------
  const newer = await riskDatasets.importVersion({ dataset: 'fido.mds3',
    format: 'fido-mds3-jwt',
    content: blobOf(fido, payloadOf(6, now + 30 * DAY)), source: 'upload' });
  const oldRow = await riskStore.lookupFido('fido.mds3', 'no-5', 'aaguid',
                                            REVOKED);
  t.check(newer.ok && newer.activated && oldRow === null,
          'E1. a newer BLOB is active, and the older one\'s rows are gone ' +
          'at once — FIDO\'s terms keep nothing to roll back to',
          JSON.stringify(newer));

  // --- F. looked up --------------------------------------------------------
  const revoked = await riskDatasets.lookupAuthenticator(REVOKED);
  const unlisted = await riskDatasets.lookupAuthenticator(
    '00000000-1111-4222-8333-444444444444');
  const zero = await riskDatasets.lookupAuthenticator(
    '00000000-0000-0000-0000-000000000000');
  t.check(revoked && revoked.model.compromised === true &&
          revoked.version === 'no-6' && unlisted === null && zero === null,
          'F1. a revoked model is compromised; an unlisted model and the ' +
          'all-zero AAGUID are unknown', JSON.stringify(revoked));

  // --- G. stale -------------------------------------------------------------
  const due = await riskDatasets.importVersion({ dataset: 'fido.mds3',
    format: 'fido-mds3-jwt',
    content: blobOf(fido, payloadOf(7, now - 2 * DAY)), source: 'upload' });
  config.setOverride('risk.mdsStaleGraceDays', 7);
  const withinGrace = await riskDatasets.lookupAuthenticator(REVOKED);
  config.setOverride('risk.mdsStaleGraceDays', 0);
  const pastGrace = await riskDatasets.lookupAuthenticator(REVOKED);
  config.setOverride('risk.mdsStaleGraceDays', 7);
  t.check(due.ok && withinGrace !== null && pastGrace === null,
          'G1. a BLOB past its nextUpdate answers within the grace, and ' +
          'says nothing after it');

  // --- H. scored -----------------------------------------------------------
  const assessed = await riskEngine.assess({ realm: '', subject:
    'urn:uuid:00000000-0000-4000-8000-0000000000f1', sessionId: '',
    door: 'a test', clientId: '',
    context: { address: '192.0.2.44', uaFingerprint: 'fp',
               credential: { kind: 'webauthn', aaguid: REVOKED } },
    userAgent: '' });
  t.check(assessed && assessed.level === 'HIGH' &&
          assessed.signals.some(function (s) {
            return s.signal === 'authenticator-compromised';
          }) && assessed.authenticatorCert === 'FIDO_CERTIFIED_L1' &&
          assessed.datasets['fido.mds3'] === 'no-7',
          'H1. a sign-in with a key whose model is revoked is HIGH, and the ' +
          'assessment records the BLOB that said so',
          JSON.stringify(assessed && { level: assessed.level,
                                       signals: assessed.signals }));

  // --- I. another root -----------------------------------------------------
  const foreign = await riskDatasets.importVersion({ dataset: 'fido.mds3',
    format: 'fido-mds3-jwt', content: blobOf(other, payloadOf(8, now)),
    source: 'upload' });
  const recorded = (await riskStore.listVersions('', 'fido.mds3'))
    .filter(function (v) { return v.state === 'refused'; });
  t.check(!foreign.ok && /does not verify/.test(foreign.errors[0]) &&
          recorded.length >= 2,
          'I1. a BLOB signed under another root is refused (STS-RISK-0022), ' +
          'and recorded as a refused version, as the rollback was',
          JSON.stringify(foreign.errors));

  config.clearOverride('risk.mdsTrustAnchors');
  config.clearOverride('risk.mdsStaleGraceDays');
  riskStore.reset();
  riskDatasets.forget();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_mds',
  describe: 'the FIDO Metadata Service (#62 P5) with a synthetic BLOB: an ' +
            'entry as rows, the signature and chain verified, a rollback ' +
            'refused, the latest only, a revoked model found by AAGUID, ' +
            'staleness past nextUpdate, and a sign-in with such a key HIGH',
  run: run
};
