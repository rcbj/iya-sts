// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: signature_doors.js
//
// ---------------------------------------------------------------------------
// THE DOORS SITES MOVED ONTO, AND THAT THE MOVE CHANGED NO BYTE (#1368, phase
// 2).
//
// The risk in moving a signature onto a new door is a value that quietly
// differs: a `kid` is published, a JWKS modulus is what a client verifies with,
// and a Sig_structure one byte off verifies nothing. So each door is held to
// what it replaced, computed here the old way: node-forge for the digest and
// the modulus, the codec's own CBOR for the Sig_structure. The tests are not
// walked by tests/crypto_centralised.js, so they may still hold both libraries.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const forge = require('node-forge');

module.exports = {
  name: 'signature_doors',
  run: async function run(t) {
    const stsCrypto = require('../common/crypto');
    const pqJose = require('../common/pq_jose');
    const codec = require('../oid4vc/vc_status_codec');

    // ---- A kid, digested as it always was. -------------------------------
    ['MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A', '["P-256","abc","def"]']
      .forEach(function (material) {
        t.check(stsCrypto.sha256Hex(Buffer.from(material)) ===
          forge.md.sha256.create().update(material).digest().toHex(),
        'the kid digest is the one forge made, so no published kid moves',
        material);
      });

    // ---- A published RSA modulus, read as it always was. ------------------
    const rsa = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    const certificate = forge.pki.createCertificate();
    certificate.publicKey = rsa.publicKey;
    certificate.serialNumber = '01';
    certificate.validity.notBefore = new Date(0);
    certificate.validity.notAfter = new Date(4102444800000);
    certificate.setSubject([{ name: 'commonName', value: 'door' }]);
    certificate.setIssuer([{ name: 'commonName', value: 'door' }]);
    certificate.sign(rsa.privateKey, forge.md.sha256.create());
    const pem = forge.pki.certificateToPem(certificate);
    const oldB64u = function (big) {
      const hex = big.toString(16);
      return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex')
        .toString('base64url');
    };
    const read = stsCrypto.rsaPublicJwkOf(pem);
    t.check(read.n === oldB64u(rsa.publicKey.n) &&
      read.e === oldB64u(rsa.publicKey.e),
    'rsaPublicJwkOf() is the n and e the JWKS and DID document published');

    // ---- decodeJws: what it reads, and that it reads nothing loose. --------
    const b64u = function (value) {
      return Buffer.from(JSON.stringify(value)).toString('base64url');
    };
    const token = b64u({ alg: 'RS256' }) + '.' + b64u({ sub: 'x' }) + '.c2ln';
    t.check(stsCrypto.decodeJws(token).sub === 'x', 'it reads the claims');
    const complete = stsCrypto.decodeJws(token, { complete: true });
    t.check(complete.header.alg === 'RS256' && complete.payload.sub === 'x' &&
      complete.signature === 'c2ln', 'and with complete, all three parts');
    ['', 'a.b', 'not.a.token', 'a.b.c.d', undefined,
     token.replace(/^./, '+')].forEach(function (bad) {
      t.check(stsCrypto.decodeJws(bad) === null,
        'what is not a compact JWS is null, never a throw', String(bad));
    });

    // ---- The Sig_structure is the codec's, byte for byte. ------------------
    const protectedBytes = codec.cborEncode(new Map([[1, -7]]));
    const longPayload = Buffer.alloc(70000, 7);
    [Buffer.from('short'), Buffer.alloc(30, 1), Buffer.alloc(300, 2),
     longPayload].forEach(function (payload) {
      const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'prime256v1' });
      const signature = stsCrypto.coseSign1Sign(-7, privateKey, protectedBytes,
                                                payload);
      const theirs = codec.cborEncode(['Signature1', protectedBytes,
                                       Buffer.alloc(0), payload]);
      t.check(nodeCrypto.verify('sha256', theirs,
        { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature),
      'the door signs the Sig_structure the codec encodes, at ' +
      payload.length + ' bytes');
      t.check(stsCrypto.coseSign1Verify(-7, publicKey, protectedBytes, payload,
                                        signature),
      'and verifies what it signed');
      t.check(!stsCrypto.coseSign1Verify(-7, publicKey, protectedBytes,
        Buffer.concat([payload, Buffer.from([0])]), signature),
      'and not a changed payload');
      t.check(!stsCrypto.coseSign1Verify(-7, publicKey, protectedBytes, payload,
        signature, { external: Buffer.from('aad') }),
      'and not under different external data');
    });

    // ---- Every family the door signs, through the codec above it. ---------
    const families = [
      ['ES256', nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'prime256v1' })],
      ['ES384', nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'secp384r1' })],
      ['EdDSA', nodeCrypto.generateKeyPairSync('ed25519')],
      ['PS256', nodeCrypto.generateKeyPairSync('rsa',
        { modulusLength: 2048 })],
      ['RS256', nodeCrypto.generateKeyPairSync('rsa',
        { modulusLength: 2048 })]
    ];
    const pq = pqJose.generate('ML-DSA-44');
    families.push(['ML-DSA-44', { privateKey: pq.priv, publicKey: pq.pub }]);
    for (let i = 0; i < families.length; i++) {
      const alg = families[i][0];
      const pair = families[i][1];
      const input = { protectedHeader: [], unprotectedHeader: [],
                      payload: Buffer.from('p'), key: pair.privateKey,
                      alg: alg };
      const sync = codec.coseSign1Verify(codec.coseSign1Sign(input),
        pair.publicKey, { algorithms: [alg] });
      t.check(sync.alg === alg, alg + ' signs and verifies through the codec');
      const signed = await codec.coseSign1SignAsync(input);
      const later = await codec.coseSign1VerifyAsync(signed, pair.publicKey,
                                                     { algorithms: [alg] });
      t.check(later.alg === alg, alg + ' does so asynchronously too');
      const bad = Buffer.from(signed);
      bad[bad.length - 1] ^= 1;
      let refused = false;
      try {
        await codec.coseSign1VerifyAsync(bad, pair.publicKey,
                                         { algorithms: [alg] });
      } catch (e) {
        refused = /does not verify/.test(e.message);
      }
      t.check(refused, alg + ': a changed signature does not verify');
    }
    t.check((function () {
      try {
        stsCrypto.coseSign1Sign(-65535, 'k', Buffer.alloc(0), Buffer.alloc(0));
      } catch (e) {
        return /does not sign/.test(e.message);
      }
      return false;
    })(), 'the door never signs with a broken algorithm');

    // ---- The raw post-quantum door. ----------------------------------------
    const data = Buffer.from('data');
    const made = await stsCrypto.signRawSignatureAsync(
      { family: 'pq', alg: 'ML-DSA-44' }, pq.priv, data);
    t.check(pqJose.verify('ML-DSA-44', pq.pub, data, made) === true,
      'signRawSignatureAsync() makes an ML-DSA signature');
    t.check(await stsCrypto.verifyRawSignature(
      { family: 'pq', alg: 'ML-DSA-44' }, pq.pub, data, made),
    'verifyRawSignature() checks one from its raw key');
    t.check(!(await stsCrypto.verifyRawSignature(
      { family: 'pq', alg: 'ML-DSA-44' }, pq.pub, Buffer.from('other'), made)),
    'and refuses it over other data');

    // ---- The BBS door. ---------------------------------------------------
    t.check(stsCrypto.bbs.CRYPTOSUITE === 'bbs-2023',
      'the BBS suite is reached through crypto.js');
  }
};
