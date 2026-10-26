// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// RFC 4998 passkey evidence (#947): an initial RFC 3161 ArchiveTimeStamp,
// verification of its token against a configured TSA trust anchor, and a
// timestamp renewal chained to the previous token. The local TSA is a test
// fixture made with OpenSSL; no public TSA or real authenticator is used.

const fs = require('fs');
const os = require('os');
const path = require('path');
const child = require('child_process');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
require('../common/crypto');
const config = require('../common/config');
const Evidence = require('../common/passkey_evidence').PasskeyEvidence;
const log = require('bunyan').createLogger({
  name: 'passkey_evidence', level: process.env.LOG_LEVEL || 'info' });

function command(file, args) {
  log.debug('Entering command(). ' + file);
  const out = child.spawnSync(file, args, { encoding: 'utf8' });
  if (out.status !== 0) {
    throw new Error(file + ' failed: ' + (out.stderr || out.stdout));
  }
  log.debug('Leaving command().');
  return out.stdout;
}

function asBuffer(value) {
  const out = Buffer.from(value);
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
}

function sequenceLength(record) {
  const parsed = asn1js.fromBER(asBuffer(Buffer.from(
    record.evidenceRecord, 'base64')));
  if (parsed.offset < 0) {
    return -1;
  }
  const seq = parsed.result.valueBlock.value[2];
  const chain = seq.valueBlock.value[0];
  return chain.valueBlock.value.length;
}

module.exports = {
  name: 'passkey_evidence',
  describe: 'RFC 4998 evidence creation and timestamp renewal (#947), ' +
            'with a local RFC 3161 TSA fixture',
  run: async function (t) {
    log.debug('Entering run().');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iya-passkey-evidence-'));
    const caKey = path.join(dir, 'ca.key');
    const caCert = path.join(dir, 'ca.crt');
    const key = path.join(dir, 'tsa.key');
    const cert = path.join(dir, 'tsa.crt');
    const csr = path.join(dir, 'tsa.csr');
    const ext = path.join(dir, 'tsa.ext');
    const chain = path.join(dir, 'chain.pem');
    const serial = path.join(dir, 'tsa.serial');
    const request = path.join(dir, 'request.der');
    const response = path.join(dir, 'response.der');
    const configFile = path.join(dir, 'tsa.cnf');
    try {
      // OpenSSL 3.5 refuses a TSA signer whose keyUsage includes
      // keyCertSign. pkijs, with checkChain, refuses a signer that is
      // not under a CA. The fixture is a CA plus a time-stamping leaf.
      command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', caKey, '-out', caCert, '-days', '2', '-subj',
        '/CN=IYA Synthetic Test TSA CA', '-addext',
        'basicConstraints=critical,CA:TRUE', '-addext',
        'keyUsage=critical,keyCertSign,cRLSign']);
      command('openssl', ['req', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key, '-out', csr, '-subj',
        '/CN=IYA Synthetic Test TSA']);
      fs.writeFileSync(ext, [
        'basicConstraints=CA:FALSE',
        'keyUsage=critical,digitalSignature',
        'extendedKeyUsage=critical,timeStamping', ''
      ].join('\n'));
      command('openssl', ['x509', '-req', '-in', csr, '-CA', caCert,
        '-CAkey', caKey, '-CAcreateserial', '-out', cert, '-days', '2',
        '-extfile', ext]);
      fs.writeFileSync(chain, fs.readFileSync(cert, 'utf8') +
                              fs.readFileSync(caCert, 'utf8'));
      fs.writeFileSync(serial, '01\n');
      fs.writeFileSync(configFile, [
        '[ tsa ]', 'default_tsa = tsa_config1', '', '[ tsa_config1 ]',
        'serial = ' + serial, 'crypto_device = builtin',
        'signer_cert = ' + cert, 'certs = ' + chain,
        'signer_key = ' + key, 'signer_digest = sha256',
        'default_policy = 1.2.3.4.1', 'other_policies = 1.2.3.4.5',
        'digests = sha256, sha512', 'accuracy = secs:1', 'ordering = yes',
        'tsa_name = yes', 'ess_cert_id_chain = no',
        'ess_cert_id_alg = sha256', ''
      ].join('\n'));
      config.setOverride('webauthn.attestationEvidenceTsaUrl',
                         'https://tsa.example.test/');
      config.setOverride('webauthn.attestationEvidenceTsaTrustAnchors',
                         fs.readFileSync(caCert, 'utf8'));
      const tsaFetch = async function (_url, options) {
        fs.writeFileSync(request, Buffer.from(options.body));
        command('openssl', ['ts', '-reply', '-queryfile', request,
          '-config', configFile, '-out', response]);
        const body = fs.readFileSync(response);
        return { ok: true, status: 200,
          arrayBuffer: async function () { return asBuffer(body); } };
      };
      const evidence = new Evidence(tsaFetch);
      const source = Buffer.from('verified classical attestation fixture');
      const first = await evidence.create(source);
      t.check(first.syntax === 'RFC4998' && first.version === 1 &&
              Buffer.from(first.object, 'base64').equals(source) &&
              first.objectDigest === require('crypto').createHash('sha256')
                .update(source).digest('hex') &&
              sequenceLength(first) === 1 && first.timestamps.length === 1,
              'A. the verified evidence object is hashed and receives an ' +
              'RFC 4998 ArchiveTimeStamp with a trusted RFC 3161 token',
              JSON.stringify({ syntax: first.syntax,
                timestamps: first.timestamps.length,
                chain: sequenceLength(first) }));
      const renewed = await evidence.renew(first, first.renewAfter);
      t.check(renewed.timestamps.length === 2 && sequenceLength(renewed) === 2 &&
              renewed.objectDigest === first.objectDigest &&
              renewed.renewedAt >= first.renewedAt,
              'B. renewal appends a TSA token over the previous token in the ' +
              'same ArchiveTimeStampChain',
              JSON.stringify({ timestamps: renewed.timestamps.length,
                chain: sequenceLength(renewed) }));
      const parsed = asn1js.fromBER(asBuffer(Buffer.from(
        renewed.timestamps[0], 'base64')));
      const token = new pkijs.ContentInfo({ schema: parsed.result });
      t.check(token.contentType === pkijs.id_ContentType_SignedData,
              'C. the archived timestamps are CMS ContentInfo tokens');
      const migrated = await evidence.renewHashTree(renewed, 'sha512');
      const migratedDer = asn1js.fromBER(asBuffer(Buffer.from(
        migrated.evidenceRecord, 'base64')));
      const chains = migratedDer.result.valueBlock.value[2].valueBlock.value;
      const algorithms = migratedDer.result.valueBlock.value[1].valueBlock.value;
      t.check(chains.length === 2 &&
              chains[1].valueBlock.value[0].valueBlock.value.length === 3 &&
              algorithms.some(function (one) {
                // asn1js keeps an OID as sid components. The dotted
                // form is toString(), not value.
                return one.valueBlock.value[0].valueBlock.toString() ===
                  '2.16.840.1.101.3.4.2.3';
              }) && migrated.hashAlgorithm === 'sha512',
              'D. hash-tree renewal adds a SHA-512 reduced tree and a new ' +
              'ArchiveTimeStampChain over the object and prior sequence');
    } finally {
      config.clearOverride('webauthn.attestationEvidenceTsaUrl');
      config.clearOverride('webauthn.attestationEvidenceTsaTrustAnchors');
      fs.rmSync(dir, { recursive: true, force: true });
    }
    log.debug('Leaving run().');
  }
};
