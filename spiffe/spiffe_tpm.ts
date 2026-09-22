'use strict';
//
// File: spiffe_tpm.ts
//
// ---------------------------------------------------------------------------
// TPM 2.0 STRUCTURES AND CREDENTIAL ACTIVATION, FOR THE `tpm_devid` NODE
// ATTESTOR (#40, 2026-09-21).
//
// `tpm_devid` proves three things about a node — that it holds a DevID key
// with a certificate from a trusted DevID CA, that the DevID key lives in the
// same TPM as an attestation key (AK), and that the AK lives in a TPM whose
// endorsement key (EK) a trusted manufacturer certified. SPIRE does it with
// `github.com/google/go-tpm/legacy/tpm2`; this is the part of that package
// the server needs, from TPM 2.0 Library Part 2 (structures) and Part 1
// section 24 (credential protection):
//
//   * `decodePublic()` — TPMT_PUBLIC (RSA and ECC objects), and `name()`,
//     nameAlg ‖ H_nameAlg(TPMT_PUBLIC), which is how one structure names
//     another;
//   * `decodeCertifyName()` — TPMS_ATTEST, of which only TPM2_Certify's
//     form is read, and `checkSignature()` over a TPMT_SIGNATURE;
//   * `makeCredential()` — TPM2_MakeCredential for an EK and an AK: this file
//     reads the EK's parameters and `common/crypto.js`'s
//     `tpmMakeCredential()` computes the credential — a seed encrypted to the
//     EK (RSA-OAEP, label "IDENTITY"), KDFa keys from the AK's Name, the
//     secret under AES-CFB and an integrity HMAC. Only a TPM holding the EK's
//     private key, activating FOR that AK, gets the secret back.
//
// THIS FILE IS A CODEC. Every signature it needs checked and every key it
// needs derived is `common/crypto.js`'s (rcbj, 2026-09-21); what is here is
// the TPM's byte layout.
//
// A public area may arrive with or without its TPM2B size prefix: SPIRE's
// agent sends TPMT_PUBLIC for the EK and AK, and a DevID public read from a
// tpm2-tools file carries TPM2B_PUBLIC's. `decodePublic()` accepts both.
//
// TPM 2.0 has no post-quantum algorithm; a TPM is RSA or ECC, and so is this.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;
// The signature check and the credential are crypto, and live where every
// other signature and cipher here does (rcbj, 2026-09-21).
import stsCrypto = require('../common/crypto');

// TPM_ALG_ID values used here (Part 2, table 9).
const ALG = {
  RSA: 0x0001, SHA1: 0x0004, AES: 0x0006, SHA256: 0x000b, SHA384: 0x000c,
  SHA512: 0x000d, NULL: 0x0010, RSASSA: 0x0014, RSAPSS: 0x0016,
  ECDSA: 0x0018, ECC: 0x0023, CFB: 0x0043
};
const HASHES = { 0x0004: 'sha1', 0x000b: 'sha256', 0x000c: 'sha384',
                 0x000d: 'sha512' };
// TPM_ECC_CURVE (Part 2, table 10) to a JWK curve.
const CURVES = { 0x0003: { crv: 'P-256', bytes: 32 },
                 0x0004: { crv: 'P-384', bytes: 48 },
                 0x0005: { crv: 'P-521', bytes: 66 } };
// TPMA_OBJECT sign (bit 18).
const ATTRIBUTE_SIGN = 0x00040000;
// TPM_GENERATED_VALUE and TPM_ST_ATTEST_CERTIFY.
const GENERATED = 0xff544347;
const ST_ATTEST_CERTIFY = 0x8017;

class Reader {
  private at = 0;

  constructor(private readonly bytes: Buffer) {
    log.debug("Entering Reader.constructor().");
    log.debug("Leaving Reader.constructor().");
  }

  take(n: number): Buffer {
    log.debug("Entering Reader.take().");
    if (n < 0 || this.at + n > this.bytes.length) {
      log.debug("Leaving Reader.take(). Short.");
      // error-code: none — a parse failure, refused by the attestor under
      // its own code
      throw new Error('the TPM structure is truncated');
    }
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    log.debug("Leaving Reader.take().");
    return out;
  }

  u8(): number {
    log.debug("Entering Reader.u8().");
    log.debug("Leaving Reader.u8().");
    return this.take(1)[0];
  }

  u16(): number {
    log.debug("Entering Reader.u16().");
    log.debug("Leaving Reader.u16().");
    return this.take(2).readUInt16BE(0);
  }

  u32(): number {
    log.debug("Entering Reader.u32().");
    log.debug("Leaving Reader.u32().");
    return this.take(4).readUInt32BE(0);
  }

  // A TPM2B: a 16-bit size and that many bytes.
  sized(): Buffer {
    log.debug("Entering Reader.sized().");
    log.debug("Leaving Reader.sized().");
    return this.take(this.u16());
  }

  position(): number {
    log.debug("Entering Reader.position().");
    log.debug("Leaving Reader.position().");
    return this.at;
  }

  left(): number {
    log.debug("Entering Reader.left().");
    log.debug("Leaving Reader.left().");
    return this.bytes.length - this.at;
  }
}

interface TpmPublic {
  type: number;
  nameAlg: number;
  attributes: number;
  // The TPMT_PUBLIC bytes, without a size prefix: what a Name hashes.
  raw: Buffer;
  // RSA
  symmetric?: { alg: number; keyBits: number; mode: number };
  scheme?: { alg: number; hash: number };
  keyBits?: number;
  exponent?: number;
  modulus?: Buffer;
  // ECC
  curve?: number;
  x?: Buffer;
  y?: Buffer;
}

interface TpmDeps {
  log: typeof log;
  crypto: typeof nodeCrypto;
  stsCrypto: typeof stsCrypto;
}

class Tpm {
  constructor(private readonly deps: TpmDeps) {
    deps.log.debug("Entering Tpm.constructor().");
    deps.log.debug("Leaving Tpm.constructor().");
  }

  static defaultDeps(): TpmDeps {
    helpers.log.debug("Entering Tpm.defaultDeps().");
    helpers.log.debug("Leaving Tpm.defaultDeps().");
    return { log: log, crypto: nodeCrypto, stsCrypto: stsCrypto };
  }

  hashName(alg: number): string {
    const { log } = this.deps;
    log.debug("Entering Tpm.hashName().");
    const name = HASHES[alg];
    if (!name) {
      log.debug("Leaving Tpm.hashName(). Unknown.");
      // error-code: none — see Reader.take()
      throw new Error('the TPM hash algorithm 0x' + alg.toString(16) +
                      ' is not supported');
    }
    log.debug("Leaving Tpm.hashName().");
    return name;
  }

  // TPMT_SYM_DEF_OBJECT.
  symmetric(reader: Reader): { alg: number; keyBits: number; mode: number } {
    const { log } = this.deps;
    log.debug("Entering Tpm.symmetric().");
    const alg = reader.u16();
    if (alg === ALG.NULL) {
      log.debug("Leaving Tpm.symmetric(). NULL.");
      return { alg: alg, keyBits: 0, mode: 0 };
    }
    const keyBits = reader.u16();
    const mode = reader.u16();
    log.debug("Leaving Tpm.symmetric().");
    return { alg: alg, keyBits: keyBits, mode: mode };
  }

  // A scheme: an algorithm and, unless it is NULL, a hash.
  scheme(reader: Reader): { alg: number; hash: number } {
    const { log } = this.deps;
    log.debug("Entering Tpm.scheme().");
    const alg = reader.u16();
    log.debug("Leaving Tpm.scheme().");
    return { alg: alg, hash: alg === ALG.NULL ? 0 : reader.u16() };
  }

  // TPMT_PUBLIC, or TPM2B_PUBLIC around one.
  decodePublic(bytes: Buffer): TpmPublic {
    const { log } = this.deps;
    log.debug("Entering Tpm.decodePublic().");
    const input = Buffer.from(bytes || []);
    try {
      const plain = this.decodeTpmtPublic(input);
      log.debug("Leaving Tpm.decodePublic(). TPMT_PUBLIC.");
      return plain;
    } catch (e) {
      log.debug("Caught in Tpm.decodePublic(): " + ((e && e.message) || e));
      if (input.length >= 2 && input.readUInt16BE(0) === input.length - 2) {
        log.debug("Leaving Tpm.decodePublic(). TPM2B_PUBLIC.");
        return this.decodeTpmtPublic(input.subarray(2));
      }
      log.debug("Leaving Tpm.decodePublic(). Neither.");
      throw e;
    }
  }

  decodeTpmtPublic(bytes: Buffer): TpmPublic {
    const { log } = this.deps;
    log.debug("Entering Tpm.decodeTpmtPublic().");
    const reader = new Reader(bytes);
    const out: TpmPublic = { type: reader.u16(), nameAlg: reader.u16(),
                             attributes: reader.u32(), raw: null };
    reader.sized();
    if (out.type === ALG.RSA) {
      out.symmetric = this.symmetric(reader);
      out.scheme = this.scheme(reader);
      out.keyBits = reader.u16();
      out.exponent = reader.u32();
      out.modulus = reader.sized();
    } else if (out.type === ALG.ECC) {
      out.symmetric = this.symmetric(reader);
      out.scheme = this.scheme(reader);
      out.curve = reader.u16();
      this.scheme(reader);
      out.x = reader.sized();
      out.y = reader.sized();
    } else {
      log.debug("Leaving Tpm.decodeTpmtPublic(). Unsupported type.");
      // error-code: none — see Reader.take()
      throw new Error('the TPM object type 0x' + out.type.toString(16) +
                      ' is not supported (RSA and ECC are)');
    }
    if (reader.left()) {
      log.debug("Leaving Tpm.decodeTpmtPublic(). Trailing bytes.");
      // error-code: none — see Reader.take()
      throw new Error('trailing bytes after TPMT_PUBLIC');
    }
    out.raw = Buffer.from(bytes);
    log.debug("Leaving Tpm.decodeTpmtPublic().");
    return out;
  }

  // The public key of a TPM object, as node key material.
  keyOf(pub: TpmPublic): nodeCrypto.KeyObject {
    const { log, crypto } = this.deps;
    log.debug("Entering Tpm.keyOf().");
    if (pub.type === ALG.RSA) {
      const e = Buffer.alloc(4);
      e.writeUInt32BE(pub.exponent || 65537, 0);
      let start = 0;
      while (start < 3 && e[start] === 0) start++;
      log.debug("Leaving Tpm.keyOf(). RSA.");
      return crypto.createPublicKey({ format: 'jwk', key: {
        kty: 'RSA', n: pub.modulus.toString('base64url'),
        e: e.subarray(start).toString('base64url') } as any });
    }
    const curve = CURVES[pub.curve];
    if (!curve) {
      log.debug("Leaving Tpm.keyOf(). Unsupported curve.");
      // error-code: none — see Reader.take()
      throw new Error('the TPM curve 0x' + Number(pub.curve).toString(16) +
                      ' is not supported');
    }
    const pad = Buffer.alloc(curve.bytes);
    log.debug("Leaving Tpm.keyOf(). ECC.");
    return crypto.createPublicKey({ format: 'jwk', key: {
      kty: 'EC', crv: curve.crv,
      x: Buffer.concat([pad, pub.x]).subarray(-curve.bytes)
        .toString('base64url'),
      y: Buffer.concat([pad, pub.y]).subarray(-curve.bytes)
        .toString('base64url') } as any });
  }

  // TPM2B_NAME's contents for an object: nameAlg ‖ H_nameAlg(TPMT_PUBLIC).
  name(pub: TpmPublic): Buffer {
    const { log, crypto } = this.deps;
    log.debug("Entering Tpm.name().");
    const alg = Buffer.alloc(2);
    alg.writeUInt16BE(pub.nameAlg, 0);
    log.debug("Leaving Tpm.name().");
    return Buffer.concat([alg, crypto.createHash(this.hashName(pub.nameAlg))
      .update(pub.raw).digest()]);
  }

  // Does `name` (a TPM2B_NAME's contents) name `pub`? Computed with the
  // name's own algorithm, as go-tpm's `MatchesPublic()` does.
  nameMatches(name: Buffer, pub: TpmPublic): boolean {
    const { log, crypto } = this.deps;
    log.debug("Entering Tpm.nameMatches().");
    if (!name || name.length < 2) {
      log.debug("Leaving Tpm.nameMatches(). Not a digest name.");
      return false;
    }
    const alg = name.readUInt16BE(0);
    let digest = null;
    try {
      digest = crypto.createHash(this.hashName(alg)).update(pub.raw).digest();
    } catch (e) {
      log.debug("Caught in Tpm.nameMatches(): " + ((e && e.message) || e));
      log.debug("Leaving Tpm.nameMatches(). Unknown algorithm.");
      return false;
    }
    const ok = digest.equals(name.subarray(2));
    log.debug("Leaving Tpm.nameMatches(). " + ok);
    return ok;
  }

  // TPMS_ATTEST from TPM2_Certify: the certified object's Name, or an error.
  decodeCertifyName(bytes: Buffer): Buffer {
    const { log } = this.deps;
    log.debug("Entering Tpm.decodeCertifyName().");
    const reader = new Reader(Buffer.from(bytes || []));
    if (reader.u32() !== GENERATED) {
      log.debug("Leaving Tpm.decodeCertifyName(). Not TPM-generated.");
      // error-code: none — see Reader.take()
      throw new Error('the attestation was not generated by a TPM ' +
                      '(magic is not TPM_GENERATED_VALUE)');
    }
    const type = reader.u16();
    reader.sized();
    reader.sized();
    reader.take(8 + 4 + 4 + 1);
    reader.take(8);
    if (type !== ST_ATTEST_CERTIFY) {
      log.debug("Leaving Tpm.decodeCertifyName(). Not a certify.");
      // error-code: none — see Reader.take()
      throw new Error('missing certify info');
    }
    const name = reader.sized();
    reader.sized();
    log.debug("Leaving Tpm.decodeCertifyName().");
    return Buffer.from(name);
  }

  // Did the AK sign `data` with `signature` (TPMT_SIGNATURE)? SPIRE's
  // `checkSignature()`: the AK must be a signing RSA key, and the signature
  // PKCS#1 v1.5 with the hash its scheme names. The structure is read here;
  // the signature is `common/crypto.js`'s to check. Resolves '' or why not.
  async checkSignature(ak: TpmPublic, data: Buffer, signature: Buffer):
      Promise<string> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Tpm.checkSignature().");
    if (!(ak.attributes & ATTRIBUTE_SIGN)) {
      log.debug("Leaving Tpm.checkSignature(). Not a signing key.");
      return 'not a signing key';
    }
    if (ak.type !== ALG.RSA) {
      log.debug("Leaving Tpm.checkSignature(). Not RSA.");
      return 'only RSA keys are supported';
    }
    try {
      const hash = this.hashName(ak.scheme.hash);
      const reader = new Reader(Buffer.from(signature || []));
      const sigAlg = reader.u16();
      if (sigAlg !== ALG.RSASSA && sigAlg !== ALG.RSAPSS) {
        log.debug("Leaving Tpm.checkSignature(). Not an RSA signature.");
        return 'the certification signature is not an RSA signature';
      }
      reader.u16();
      const raw = reader.sized();
      const ok = await stsCrypto.verifyRawSignature(
        { family: 'rsa-pkcs1', hash: hash }, this.keyOf(ak), data, raw);
      log.debug("Leaving Tpm.checkSignature(). " + ok);
      return ok ? '' : 'crypto/rsa: verification error';
    } catch (e) {
      log.debug("Caught in Tpm.checkSignature(): " + ((e && e.message) || e));
      log.debug("Leaving Tpm.checkSignature(). Threw.");
      return String((e && e.message) || e);
    }
  }

  // TPM2_MakeCredential for this EK and AK: the EK's parameters are read
  // here, and the credential is built by `common/crypto.js`'s
  // `tpmMakeCredential()` — go-tpm's `credactivation.Generate()`, which
  // SPIRE calls. Throws for an EK that is not RSA with an AES-CFB scheme.
  makeCredential(akName: Buffer, ek: TpmPublic, secret: Buffer):
      { credential: Buffer; secret: Buffer } {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Tpm.makeCredential().");
    if (ek.type !== ALG.RSA || !ek.symmetric || ek.symmetric.alg !== ALG.AES ||
        ek.symmetric.mode !== ALG.CFB) {
      log.debug("Leaving Tpm.makeCredential(). Unsupported EK.");
      // error-code: none — reported by the attestor under its own code
      throw new Error('unsupported algorithm: the EK must be an RSA key ' +
                      'with an AES-CFB symmetric scheme');
    }
    log.debug("Leaving Tpm.makeCredential().");
    return stsCrypto.tpmMakeCredential(akName, this.keyOf(ek),
                                       ek.symmetric.keyBits / 8, secret,
                                       this.hashName(akName.readUInt16BE(0)));
  }
}

const shared = new Tpm(Tpm.defaultDeps());

export = {
  Tpm: Tpm,
  ALG: ALG,
  hashName: (alg: number) => shared.hashName(alg),
  decodePublic: (bytes: Buffer) => shared.decodePublic(bytes),
  keyOf: (pub: any) => shared.keyOf(pub),
  name: (pub: any) => shared.name(pub),
  nameMatches: (name: Buffer, pub: any) => shared.nameMatches(name, pub),
  decodeCertifyName: (bytes: Buffer) => shared.decodeCertifyName(bytes),
  checkSignature: (ak: any, data: Buffer, sig: Buffer) =>
    shared.checkSignature(ak, data, sig),
  makeCredential: (akName: Buffer, ek: any, secret: Buffer) =>
    shared.makeCredential(akName, ek, secret)
};
