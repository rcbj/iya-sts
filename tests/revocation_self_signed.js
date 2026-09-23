'use strict';
//
// File: revocation_self_signed.js
//
// A SELF-SIGNED END-ENTITY CERTIFICATE IS ITS OWN ANCHOR UNDER PRODUCT MODE'S
// HARD-FAIL (2026-09-23).
//
// `common/revocation_status.js`'s `selfSigned()` asked OpenSSL's
// `checkIssued()`, which also requires the issuer to allow keyCertSign. A
// self-signed certificate whose key usage is digitalSignature alone — what a
// pinned issuer certificate in `oid4vp.trustedIssuerCertificates` commonly is
// — therefore read as issued by an authority nobody holds, and once #174 made
// product refuse a certificate nobody can revoke, the Verifier refused every
// credential it signed (`sts_oid4vp_status_reference`, memory mode, run on
// 1b0f8b2). A self-signed certificate has no issuer to revoke it.
//
// Asserted in product mode, with a CONTROL beside it: a CA-issued leaf that
// names no list is still refused, so the acceptance is the self-signed rule
// and not a policy that stopped refusing. The certificates are made by the
// openssl binary here, at run time; nothing is committed.
//
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

let t;
const log = require('bunyan').createLogger({ name: 'revocation_self_signed',
  level: process.env.LOG_LEVEL || 'info' });

function openssl(args) {
  log.debug("Entering openssl().");
  childProcess.execFileSync('openssl', args, { stdio: 'ignore' });
  log.debug("Leaving openssl().");
}

// A self-signed P-256 certificate whose key usage is digitalSignature alone,
// and a CA with a leaf under it that names no CRL and no responder.
function makeCertificates(dir) {
  log.debug("Entering makeCertificates().");
  const f = function (name) {
    return path.join(dir, name);
  };
  openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
           'ec_paramgen_curve:P-256', '-nodes', '-keyout', f('self.key'),
           '-out', f('self.pem'), '-days', '2', '-subj',
           '/CN=self-signed-issuer.example',
           '-addext', 'basicConstraints=critical,CA:FALSE',
           '-addext', 'keyUsage=critical,digitalSignature']);
  openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
           'ec_paramgen_curve:P-256', '-nodes', '-keyout', f('ca.key'),
           '-out', f('ca.pem'), '-days', '2', '-subj',
           '/CN=foreign-ca.example',
           '-addext', 'basicConstraints=critical,CA:TRUE',
           '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
  openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt',
           'ec_paramgen_curve:P-256', '-nodes', '-keyout', f('leaf.key'),
           '-out', f('leaf.csr'), '-subj', '/CN=foreign-leaf.example']);
  fs.writeFileSync(f('leaf.ext'),
                   'basicConstraints=critical,CA:FALSE\n' +
                   'keyUsage=critical,digitalSignature\n');
  openssl(['x509', '-req', '-in', f('leaf.csr'), '-CA', f('ca.pem'),
           '-CAkey', f('ca.key'), '-CAcreateserial', '-out', f('leaf.pem'),
           '-days', '2', '-extfile', f('leaf.ext')]);
  log.debug("Leaving makeCertificates().");
  return {
    self: fs.readFileSync(f('self.pem'), 'utf8'),
    ca: fs.readFileSync(f('ca.pem'), 'utf8'),
    leaf: fs.readFileSync(f('leaf.pem'), 'utf8')
  };
}

async function run(harness) {
  log.debug("Entering run().");
  t = harness;
  delete process.env.CONFIG_FILE;
  const config = require('../common/config');
  const revocation = require('../common/revocation_status');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rev-self-'));
  try {
    const certs = makeCertificates(dir);
    config.setOverride('global.mode', 'product');
    const policy = revocation.policy();
    t.check(policy.requireDistributionPoint === true,
            'A0. product mode requires a distribution point (#174), so the ' +
            'checks below are under the policy that refused',
            JSON.stringify(policy));
    const self = await revocation.registeredVerdictFor({
      certificate: certs.self, source: 'a pinned issuer certificate' });
    t.check(self && self.refused !== true && self.status !== 'unknown',
            'A1. a self-signed end-entity certificate (no keyCertSign) is ' +
            'its own anchor and is not refused', JSON.stringify(self));
    const leaf = await revocation.registeredVerdictFor({
      certificate: certs.leaf, chain: certs.ca,
      source: 'a CA-issued certificate' });
    t.check(leaf && leaf.refused === true,
            'A2. the control: a CA-issued leaf naming no list is still ' +
            'refused in product', JSON.stringify(leaf));
  } finally {
    config.clearOverride('global.mode');
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'revocation_self_signed',
  describe: 'a self-signed end-entity certificate is its own anchor under ' +
            'product mode\'s hard-fail, and a CA-issued one naming no list ' +
            'is still refused',
  run: run
};
