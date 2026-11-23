// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// File: openpgp_pqc.js
//
// ---------------------------------------------------------------------------
// RFC 9980 IN OpenPGP, READ HERE BECAUSE openpgp.js 6.3.2 CANNOT.
//
// openpgp.js's public-key enum stops at Ed448 (algorithm 28). A v6 key
// whose algorithm octet is 30 (ML-DSA-65+Ed25519), 31 (ML-DSA-87+Ed448),
// 35 (ML-KEM-768+X25519) or 36 (ML-KEM-1024+X448) throws inside the
// library before `crypto.js`'s allow list ever sees it. This module is
// that reader: the packets, the v6 fingerprint, both halves of a
// composite signature, and the RFC 9980 key combiner. `common/crypto.js`
// section 19 is still the policy — which of these names a realm accepts
// — and is the only file of this service that requires this one
// (`tests/crypto_centralised.js`).
//
// **SLH-DSA (algorithms 32, 33 and 34) IS REFUSED, NAMED.** RFC 9980
// makes those three MAY. Nothing here parses them, so a key that uses
// one is "not accepted" rather than a fingerprint this service invented.
//
// **A COMPOSITE SIGNATURE IS VALID ONLY WHEN BOTH HALVES ARE.** The
// Ed25519 or Ed448 half is checked here, over the OpenPGP dataDigest
// (RFC 9580 section 5.2.4), which both EdDSA and ML-DSA hash internally.
// The ML-DSA half goes through `pqc.js`, which is node's OpenSSL. A
// runtime that cannot verify ML-DSA (node before 24) reports the half
// unchecked; `readPublicKey()` then refuses the key rather than storing
// a self-signature it could not check.
//
// **THE PUBLISHED LINE A PEER MUST PARSE IS NOT INVENTED HERE.** This
// file verifies and, when ML-KEM is available, encrypts. It does not
// mint a key. Encryption is a v6 PKESK (RFC 9580 section 5.1.2 plus
// RFC 9980 section 4.3.1) in front of a v2 SEIPD (RFC 9580 section
// 5.13.2, AES-256 with OCB). The obsolete SEIPD type 9 is never written.
//
// A leaf: node `crypto`, and `@noble/curves` plus `pqc.js` only when a
// signature or an encapsulation is actually checked.
// ---------------------------------------------------------------------------

'use strict';

const crypto = require('crypto');
const bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'openpgp_pqc',
  level: process.env.STS_LOG_LEVEL || 'info'
});

// RFC 9980 tables 4, 5, 6 and 7. Lengths are octets. The secret-key
// columns are the seed forms (ML-DSA xi is 32, ML-KEM d||z is 64); this
// reader never stores a secret, and uses the lengths only to refuse a
// secret packet that was pasted by mistake.
const ALGS = Object.freeze({
  30: { name: 'ML-DSA-65+Ed25519', use: 'sign',
        ecc: 'ed25519', pq: 'ML-DSA-65',
        eccPub: 32, pqPub: 1952, eccSig: 64, pqSig: 3309,
        eccSecret: 32, pqSecret: 32 },
  31: { name: 'ML-DSA-87+Ed448', use: 'sign',
        ecc: 'ed448', pq: 'ML-DSA-87',
        eccPub: 57, pqPub: 2592, eccSig: 114, pqSig: 4627,
        eccSecret: 57, pqSecret: 32 },
  35: { name: 'ML-KEM-768+X25519', use: 'encrypt',
        ecc: 'x25519', pq: 'ML-KEM-768',
        eccPub: 32, pqPub: 1184, eccCt: 32, pqCt: 1088,
        eccSecret: 32, pqSecret: 64 },
  36: { name: 'ML-KEM-1024+X448', use: 'encrypt',
        ecc: 'x448', pq: 'ML-KEM-1024',
        eccPub: 56, pqPub: 1568, eccCt: 56, pqCt: 1568,
        eccSecret: 56, pqSecret: 64 }
});

const SIGNING_NAMES = Object.freeze(['ML-DSA-65+Ed25519', 'ML-DSA-87+Ed448']);
const ENCRYPTION_NAMES = Object.freeze(['ML-KEM-768+X25519',
                                        'ML-KEM-1024+X448']);

// OpenPGP hash algorithm ids (RFC 9580 section 9.5) and the v6 salt
// each one takes (Table 23). A composite signature must use a digest of
// at least 256 bits (RFC 9980 section 5.3.1); SHA-1 and the rest are
// absent on purpose.
const HASHES = Object.freeze({
  8: { name: 'sha256', salt: 16 },
  9: { name: 'sha384', salt: 24 },
  10: { name: 'sha512', salt: 32 },
  12: { name: 'sha3-256', salt: 16 },
  14: { name: 'sha3-512', salt: 32 }
});

const DOMSEP = Buffer.from('OpenPGPCompositeKDFv1', 'utf8');

// Key flags (RFC 9580 section 5.2.3.29).
const FLAG_CERTIFY = 0x01;
const FLAG_SIGN = 0x02;
const FLAG_ENCRYPT_COMMS = 0x04;
const FLAG_ENCRYPT_STORAGE = 0x08;

// No Entering/Leaving pair: readScalar() is the packet parser's inner
// read, once per field of every packet, and a debug line per call would
// drown the log of every key this module reads.
function readScalar(buf, offset, octets) {
  if (offset + octets > buf.length) {
    throw new Error('a packet ended early');
  }
  let n = 0;
  for (let i = 0; i < octets; i++) {
    n = (n * 256) + buf[offset + i];
  }
  return { value: n, next: offset + octets };
}

// No Entering/Leaving pair: the new-format length is read once per
// packet and once per subpacket, and logging it would drown a key.
function readNewLength(buf, offset) {
  if (offset >= buf.length) {
    throw new Error('a packet length ended early');
  }
  const first = buf[offset];
  if (first < 192) {
    return { length: first, next: offset + 1, partial: false };
  }
  if (first < 224) {
    if (offset + 1 >= buf.length) {
      throw new Error('a two-octet length ended early');
    }
    return { length: ((first - 192) << 8) + buf[offset + 1] + 192,
             next: offset + 2, partial: false };
  }
  if (first === 255) {
    const n = readScalar(buf, offset + 1, 4);
    return { length: n.value, next: n.next, partial: false };
  }
  return { length: 1 << (first & 0x1f), next: offset + 1, partial: true };
}

/**
 * The packets of an OpenPGP binary stream.
 *
 * @param buf - the bytes
 * @returns `[{ tag, body }]`
 */
function readPackets(buf) {
  log.debug("Entering readPackets().");
  const packets = [];
  let i = 0;
  while (i < buf.length) {
    const tagByte = buf[i];
    if ((tagByte & 0x80) === 0) {
      throw new Error('byte ' + i + ' is not an OpenPGP packet');
    }
    let tag;
    if (tagByte & 0x40) {
      tag = tagByte & 0x3f;
      const parts = [];
      let at = i + 1;
      let partial = true;
      while (partial) {
        const len = readNewLength(buf, at);
        at = len.next;
        if (at + len.length > buf.length) {
          throw new Error('packet ' + tag + ' runs past the end');
        }
        parts.push(buf.subarray(at, at + len.length));
        at += len.length;
        partial = len.partial;
      }
      packets.push({ tag: tag, body: Buffer.concat(parts) });
      i = at;
    } else {
      tag = (tagByte >> 2) & 0x0f;
      const lentype = tagByte & 0x03;
      if (lentype === 3) {
        throw new Error('an indeterminate packet length is not read');
      }
      const octets = lentype === 0 ? 1 : (lentype === 1 ? 2 : 4);
      const n = readScalar(buf, i + 1, octets);
      if (n.next + n.value > buf.length) {
        throw new Error('packet ' + tag + ' runs past the end');
      }
      packets.push({ tag: tag,
                     body: Buffer.from(buf.subarray(n.next,
                                                   n.next + n.value)) });
      i = n.next + n.value;
    }
  }
  log.debug("Leaving readPackets(). " + packets.length);
  return packets;
}

/**
 * Armor to bytes. A CRC24 footer is ignored: RFC 9580 section 6.1 says
 * a consumer must not reject a block whose footer is absent or wrong,
 * and a v6 key must not carry one.
 *
 * @param text - the armored text
 * @returns the bytes
 */
function dearmor(text) {
  log.debug("Entering dearmor().");
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  let i = 0;
  while (i < lines.length && lines[i].indexOf('-----BEGIN') !== 0) {
    i += 1;
  }
  if (i >= lines.length) {
    log.debug("Leaving dearmor(). No header.");
    throw new Error('no ASCII armor header');
  }
  const kind = lines[i];
  i += 1;
  while (i < lines.length && lines[i] !== '') {
    i += 1;
  }
  i += 1;
  const b64 = [];
  while (i < lines.length && lines[i].indexOf('-----END') !== 0) {
    if (lines[i] && lines[i][0] !== '=') {
      b64.push(lines[i].trim());
    }
    i += 1;
  }
  const out = Buffer.from(b64.join(''), 'base64');
  log.debug("Leaving dearmor(). " + out.length + " from " + kind);
  return out;
}

/**
 * Bytes of an armored block or of a binary packet stream.
 *
 * @param input - either
 * @returns the bytes
 */
function bytesOf(input) {
  log.debug("Entering bytesOf().");
  let buf = null;
  if (Buffer.isBuffer(input)) {
    buf = input;
  } else if (input instanceof Uint8Array) {
    buf = Buffer.from(input);
  }
  if (buf) {
    // A file read is a Buffer. Armor starts with '-', and a packet
    // stream's first byte always has the high bit set (RFC 9580
    // section 4.2), so a Buffer of armor is still armor.
    if (buf.length && (buf[0] & 0x80) === 0) {
      const text = buf.toString('utf8');
      if (text.indexOf('-----BEGIN') >= 0) {
        const out = dearmor(text);
        log.debug("Leaving bytesOf(). Armor bytes.");
        return out;
      }
      log.debug("Leaving bytesOf(). Not a packet.");
      throw new Error('not an OpenPGP block');
    }
    log.debug("Leaving bytesOf(). Binary.");
    return Buffer.from(buf);
  }
  const text = String(input || '');
  if (text.indexOf('-----BEGIN') >= 0) {
    const out = dearmor(text);
    log.debug("Leaving bytesOf(). Armor.");
    return out;
  }
  log.debug("Leaving bytesOf(). Not armor.");
  throw new Error('not an OpenPGP block');
}

/**
 * A v4 or v6 public-key packet body.
 *
 * @param body - the packet body
 * @returns `{ version, created, algorithm, material, spec }`
 */
function parsePublicKey(body) {
  log.debug("Entering parsePublicKey().");
  if (body.length < 6) {
    throw new Error('a public-key packet is too short');
  }
  const version = body[0];
  const created = body.readUInt32BE(1);
  const algorithm = body[5];
  let material;
  if (version >= 5) {
    if (body.length < 10) {
      throw new Error('a v6 public-key packet is too short');
    }
    const mlen = body.readUInt32BE(6);
    material = body.subarray(10, 10 + mlen);
    if (material.length !== mlen) {
      throw new Error('a v6 key material length does not match');
    }
  } else {
    material = body.subarray(6);
  }
  const spec = ALGS[algorithm] || null;
  log.debug("Leaving parsePublicKey(). v" + version + " alg " + algorithm);
  return { version: version, created: created, algorithm: algorithm,
           material: Buffer.from(material), spec: spec, body: body };
}

/**
 * The fingerprint of a key packet body (RFC 9580 section 5.5.4). v6 is
 * SHA-256 of `0x9B || uint32(body) || body`.
 *
 * @param body - the packet body
 * @returns the lowercase hex fingerprint
 */
function fingerprintOf(body) {
  log.debug("Entering fingerprintOf().");
  const version = body[0];
  const prefixLen = version >= 5 ? 4 : 2;
  const prefix = Buffer.alloc(1 + prefixLen);
  prefix[0] = 0x95 + version;
  if (version >= 5) {
    prefix.writeUInt32BE(body.length, 1);
  } else {
    prefix.writeUInt16BE(body.length, 1);
  }
  const name = version >= 5 ? 'sha256' : 'sha1';
  const out = crypto.createHash(name).update(prefix).update(body)
    .digest('hex');
  log.debug("Leaving fingerprintOf().");
  return out;
}

/**
 * What a signature hashes a key as: the same octet string as the
 * fingerprint, which for a v6 signature is `0x9B || uint32 || body`.
 *
 * @param body - the key packet body
 * @param sigVersion - the signature version
 * @returns the bytes
 */
function keyForHash(body, sigVersion) {
  log.debug("Entering keyForHash().");
  const prefixLen = sigVersion >= 5 ? 4 : 2;
  const prefix = Buffer.alloc(1 + prefixLen);
  prefix[0] = 0x95 + sigVersion;
  if (sigVersion >= 5) {
    prefix.writeUInt32BE(body.length, 1);
  } else {
    prefix.writeUInt16BE(body.length, 1);
  }
  log.debug("Leaving keyForHash().");
  return Buffer.concat([prefix, body]);
}

// No Entering/Leaving pair: one call per subpacket of every signature.
function parseSubpackets(buf) {
  const out = [];
  let i = 0;
  while (i < buf.length) {
    const len = readNewLength(buf, i);
    if (len.partial) {
      throw new Error('a subpacket length is partial');
    }
    if (len.length < 1 || len.next + len.length > buf.length) {
      throw new Error('a subpacket runs past its area');
    }
    const type = buf[len.next] & 0x7f;
    const data = Buffer.from(buf.subarray(len.next + 1,
                                          len.next + len.length));
    out.push({ type: type, data: data });
    i = len.next + len.length;
  }
  return out;
}

/**
 * A v4 or v6 signature packet body.
 *
 * @param body - the packet body
 * @returns the parsed signature
 */
function parseSignature(body) {
  log.debug("Entering parseSignature().");
  let i = 0;
  const version = body[i];
  i += 1;
  if (version !== 4 && version !== 6) {
    throw new Error('signature version ' + version + ' is not read');
  }
  const type = body[i];
  i += 1;
  const pubAlg = body[i];
  i += 1;
  const hashAlg = body[i];
  i += 1;
  const lenOctets = version === 6 ? 4 : 2;
  const hashedLen = readScalar(body, i, lenOctets);
  i = hashedLen.next;
  const hashed = body.subarray(i, i + hashedLen.value);
  i += hashedLen.value;
  const signatureData = Buffer.from(body.subarray(0, i));
  const unhashedLen = readScalar(body, i, lenOctets);
  i = unhashedLen.next + unhashedLen.value;
  const left = Buffer.from(body.subarray(i, i + 2));
  i += 2;
  let salt = Buffer.alloc(0);
  if (version === 6) {
    const saltLen = body[i];
    i += 1;
    salt = Buffer.from(body.subarray(i, i + saltLen));
    i += saltLen;
  }
  const params = Buffer.from(body.subarray(i));
  const sub = parseSubpackets(hashed);
  let created = 0;
  let keyExpires = null;
  let flags = null;
  sub.forEach(function (s) {
    if (s.type === 2 && s.data.length === 4) {
      created = s.data.readUInt32BE(0);
    } else if (s.type === 9 && s.data.length === 4) {
      keyExpires = s.data.readUInt32BE(0);
    } else if (s.type === 27 && s.data.length) {
      flags = s.data[0];
    }
  });
  log.debug("Leaving parseSignature(). type " + type);
  return { version: version, type: type, pubAlg: pubAlg, hashAlg: hashAlg,
           signatureData: signatureData, salt: salt, left: left,
           params: params, created: created, keyExpires: keyExpires,
           flags: flags };
}

/**
 * The dataDigest a composite signature is made over (RFC 9580 section
 * 5.2.4): hash(salt || toSign || signatureData || trailer).
 *
 * @param sig - a parsed signature
 * @param toSign - the signed material
 * @returns the digest
 */
function dataDigest(sig, toSign) {
  log.debug("Entering dataDigest().");
  const hash = HASHES[sig.hashAlg];
  if (!hash) {
    log.debug("Leaving dataDigest(). Unknown hash.");
    throw new Error('hash algorithm ' + sig.hashAlg +
                    ' is not accepted for a composite signature');
  }
  if (sig.version === 6 && sig.salt.length !== hash.salt) {
    log.debug("Leaving dataDigest(). Salt.");
    throw new Error('a v6 signature salt is ' + sig.salt.length +
                    ' octets, not ' + hash.salt);
  }
  const trailer = Buffer.alloc(6);
  trailer[0] = sig.version;
  trailer[1] = 0xff;
  trailer.writeUInt32BE(sig.signatureData.length, 2);
  const digest = crypto.createHash(hash.name);
  digest.update(sig.salt);
  digest.update(toSign);
  digest.update(sig.signatureData);
  digest.update(trailer);
  const out = digest.digest();
  log.debug("Leaving dataDigest().");
  return out;
}

/**
 * The two public halves of a composite key.
 *
 * @param material - the algorithm-specific public key
 * @param spec - the algorithm
 * @returns `{ ecc, pq }`
 */
function splitPublic(material, spec) {
  log.debug("Entering splitPublic().");
  const need = spec.eccPub + spec.pqPub;
  if (material.length !== need) {
    log.debug("Leaving splitPublic(). Length.");
    throw new Error(spec.name + ' public key is ' + material.length +
                    ' octets, not ' + need);
  }
  log.debug("Leaving splitPublic().");
  return { ecc: material.subarray(0, spec.eccPub),
           pq: material.subarray(spec.eccPub) };
}

/**
 * The two signature halves.
 *
 * @param params - the algorithm-specific signature
 * @param spec - the algorithm
 * @returns `{ ecc, pq }`
 */
function splitSignature(params, spec) {
  log.debug("Entering splitSignature().");
  const need = spec.eccSig + spec.pqSig;
  if (params.length !== need) {
    log.debug("Leaving splitSignature(). Length.");
    throw new Error(spec.name + ' signature is ' + params.length +
                    ' octets, not ' + need);
  }
  log.debug("Leaving splitSignature().");
  return { ecc: params.subarray(0, spec.eccSig),
           pq: params.subarray(spec.eccSig) };
}

/**
 * The EdDSA half of a composite signature, over the dataDigest.
 *
 * @param spec - the algorithm
 * @param eccPub - the EdDSA public key
 * @param eccSig - the EdDSA signature
 * @param digest - the dataDigest
 * @returns true when it verifies
 */
function verifyEddsa(spec, eccPub, eccSig, digest) {
  log.debug("Entering verifyEddsa().");
  let ok = false;
  if (spec.ecc === 'ed25519') {
    const ed25519 = require('@noble/curves/ed25519').ed25519;
    ok = ed25519.verify(eccSig, digest, eccPub);
  } else if (spec.ecc === 'ed448') {
    const ed448 = require('@noble/curves/ed448').ed448;
    ok = ed448.verify(eccSig, digest, eccPub);
  }
  log.debug("Leaving verifyEddsa(). " + ok);
  return ok === true;
}

/**
 * The ML-DSA half. `'unavailable'` when this runtime has no ML-DSA,
 * which is a refusal at registration rather than a pass.
 *
 * @param spec - the algorithm
 * @param pqPub - the ML-DSA public key
 * @param pqSig - the ML-DSA signature
 * @param digest - the dataDigest
 * @returns true, false, or `'unavailable'`
 */
function verifyMlDsa(spec, pqPub, pqSig, digest) {
  log.debug("Entering verifyMlDsa().");
  let out = false;
  try {
    const pqc = require('./pqc');
    out = pqc.verifyWithPub(spec.pq, pqSig, digest, pqPub) === true;
  } catch (e) {
    log.debug("Caught in verifyMlDsa(): " + ((e && e.message) || e));
    // Node before 24 is linked to an OpenSSL with no ML-DSA. The half
    // was not checked; the caller must not treat that as success.
    out = 'unavailable';
  }
  log.debug("Leaving verifyMlDsa(). " + out);
  return out;
}

/**
 * Both halves of one composite signature over `toSign`.
 *
 * @param sig - a parsed signature
 * @param toSign - the signed material
 * @param key - `{ spec, material }`
 * @returns `{ ok, eddsa, mldsa, digest, leftMatches, created }`
 */
function verifyComposite(sig, toSign, key) {
  log.debug("Entering verifyComposite().");
  const spec = key.spec;
  if (!spec || spec.use !== 'sign' || sig.pubAlg !== key.algorithm) {
    log.debug("Leaving verifyComposite(). Algorithm.");
    return { ok: false, eddsa: false, mldsa: false, leftMatches: false,
             why: 'the signature algorithm is not this key\'s' };
  }
  const digest = dataDigest(sig, toSign);
  const leftMatches = digest[0] === sig.left[0] && digest[1] === sig.left[1];
  const pubs = splitPublic(key.material, spec);
  const sigs = splitSignature(sig.params, spec);
  const eddsa = leftMatches && verifyEddsa(spec, pubs.ecc, sigs.ecc, digest);
  const mldsa = eddsa ? verifyMlDsa(spec, pubs.pq, sigs.pq, digest) : false;
  const ok = eddsa === true && mldsa === true;
  log.debug("Leaving verifyComposite(). " + ok);
  return { ok: ok, eddsa: eddsa, mldsa: mldsa, digest: digest,
           leftMatches: leftMatches, created: sig.created,
           why: ok ? '' : (mldsa === 'unavailable'
             ? 'ML-DSA could not be verified on this runtime'
             : 'a composite signature did not verify') };
}

/**
 * The material a signature of `type` is computed over.
 *
 * @param type - the signature type
 * @param primaryBody - the primary key packet body
 * @param subject - a user-id body, a subkey body, or message bytes
 * @param sigVersion - the signature version
 * @returns the bytes
 */
function toSign(type, primaryBody, subject, sigVersion) {
  log.debug("Entering toSign(). " + type);
  const keyBytes = keyForHash(primaryBody, sigVersion);
  let out = keyBytes;
  if (type === 0x00) {
    out = Buffer.from(subject || []);
  } else if (type === 0x01) {
    out = Buffer.from(String(subject || '')
      .replace(/\r\n/g, '\n').replace(/\n/g, '\r\n'));
  } else if (type === 0x10 || type === 0x11 || type === 0x12 ||
             type === 0x13 || type === 0x30) {
    const uid = Buffer.from(subject || []);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(uid.length, 0);
    out = Buffer.concat([keyBytes, Buffer.from([0xb4]), len, uid]);
  } else if (type === 0x18 || type === 0x19 || type === 0x28) {
    out = Buffer.concat([keyBytes, keyForHash(subject, sigVersion)]);
  } else if (type === 0x1f || type === 0x20) {
    out = keyBytes;
  } else {
    throw new Error('signature type ' + type + ' is not read');
  }
  log.debug("Leaving toSign().");
  return out;
}

/**
 * What a key packet's algorithm is, in the shape `describeKey()` uses.
 *
 * @param spec - the algorithm, or null
 * @param algorithm - the octet
 * @returns `{ algorithm, curve, bits }`
 */
function algorithmInfo(spec, algorithm) {
  log.debug("Entering algorithmInfo().");
  log.debug("Leaving algorithmInfo().");
  return { algorithm: spec ? spec.name : ('algorithm ' + algorithm),
           curve: '', bits: 0 };
}

/**
 * Reads one transferable public key that uses an RFC 9980 algorithm.
 *
 * @param input - armored or binary
 * @param at - the instant, as a Date
 * @returns `{ ok: true, description, binary, armored, key }` or
 *   `{ ok: false, reason, why }`
 */
function readPublicKey(input, at) {
  log.debug("Entering readPublicKey().");
  const when = at instanceof Date ? at : new Date();
  let binary;
  try {
    binary = bytesOf(input);
  } catch (e) {
    log.debug("Caught in readPublicKey(): " + ((e && e.message) || e));
    log.debug("Leaving readPublicKey(). Unreadable.");
    return { ok: false, reason: 'unreadable',
             why: String((e && e.message) || e) };
  }
  let packets;
  try {
    packets = readPackets(binary);
  } catch (e) {
    log.debug("Caught in readPublicKey(): " + ((e && e.message) || e));
    log.debug("Leaving readPublicKey(). Packets.");
    return { ok: false, reason: 'unreadable',
             why: String((e && e.message) || e) };
  }
  const tags = packets.map(function (p) {
    return p.tag;
  });
  if (tags.indexOf(5) >= 0 || tags.indexOf(7) >= 0) {
    log.debug("Leaving readPublicKey(). Secret.");
    return { ok: false, reason: 'secret', why: 'a secret key' };
  }
  const primaries = packets.filter(function (p) {
    return p.tag === 6;
  });
  if (primaries.length !== 1) {
    log.debug("Leaving readPublicKey(). " + primaries.length + " primaries.");
    return { ok: false, reason: primaries.length ? 'several' : 'not-pqc',
             why: primaries.length + ' primary keys' };
  }
  let primary;
  try {
    primary = parsePublicKey(primaries[0].body);
  } catch (e) {
    log.debug("Caught in readPublicKey(): " + ((e && e.message) || e));
    log.debug("Leaving readPublicKey(). Primary.");
    return { ok: false, reason: 'unreadable',
             why: String((e && e.message) || e) };
  }
  if (!primary.spec) {
    log.debug("Leaving readPublicKey(). Not a PQ algorithm.");
    return { ok: false, reason: 'not-pqc',
             why: 'algorithm ' + primary.algorithm +
                  ' is not an RFC 9980 algorithm this reader accepts' };
  }
  if (primary.spec.use !== 'sign') {
    log.debug("Leaving readPublicKey(). Encryption primary.");
    return { ok: false, reason: 'unreadable',
             why: 'the primary key is an encryption algorithm' };
  }
  const fp = fingerprintOf(primary.body);
  const subkeys = [];
  const userRecords = [];
  const directs = [];
  let lastSub = null;
  let lastUser = null;
  let revoked = false;
  let unchecked = '';
  const primaryKey = { spec: primary.spec, material: primary.material,
                       algorithm: primary.algorithm };
  // EVERY SELF-SIGNATURE IS CHECKED BEFORE ANYTHING IT SAYS IS BELIEVED.
  // A packet a third party appended to a published key — a subkey with no
  // binding, a revocation, a direct-key signature with an expiry — costs
  // that party nothing, so what a signature asserts (flags, expiry,
  // revocation, which subkey is bound) is read only from one that
  // verified by the primary key. A signature this runtime cannot check
  // makes the whole key `unchecked` rather than half-believed.
  const checked = function (sig, over) {
    const v = verifyComposite(sig, over, primaryKey);
    if (v.mldsa === 'unavailable') {
      unchecked = v.why;
    }
    return v;
  };
  packets.forEach(function (p) {
    if (p.tag === 13) {
      lastUser = { body: p.body, certs: [], revocations: [] };
      userRecords.push(lastUser);
      lastSub = null;
    } else if (p.tag === 17) {
      // A user attribute: its signatures follow it and bind no address.
      lastUser = null;
      lastSub = null;
    } else if (p.tag === 14) {
      lastSub = parsePublicKey(p.body);
      lastSub.bindings = [];
      lastSub.revocations = [];
      lastSub.pending = [];
      subkeys.push(lastSub);
      lastUser = null;
    } else if (p.tag === 2) {
      const sig = parseSignature(p.body);
      if (sig.type === 0x1f) {
        sig.verified = checked(sig, toSign(0x1f, primary.body, null,
                                           sig.version));
        directs.push(sig);
      } else if (sig.type === 0x20) {
        const v = checked(sig, toSign(0x20, primary.body, null,
                                      sig.version));
        if (v.ok) {
          revoked = true;
        }
      } else if ((sig.type === 0x10 || sig.type === 0x11 ||
                  sig.type === 0x12 || sig.type === 0x13 ||
                  sig.type === 0x30) && lastUser) {
        const v = checked(sig, toSign(sig.type, primary.body, lastUser.body,
                                      sig.version));
        if (v.ok) {
          (sig.type === 0x30 ? lastUser.revocations : lastUser.certs)
            .push(sig);
        }
        lastUser.last = v;
      } else if ((sig.type === 0x18 || sig.type === 0x28) && lastSub) {
        // A subkey is usable only with a binding signature the primary
        // made (RFC 9580 section 5.2.1), and not after a subkey
        // revocation (0x28) the primary made. Neither is believed
        // unverified.
        const v = checked(sig, toSign(sig.type, primary.body, lastSub.body,
                                      sig.version));
        if (v.ok) {
          (sig.type === 0x28 ? lastSub.revocations : lastSub.bindings)
            .push(sig);
        } else if (sig.type === 0x18 && v.eddsa === true &&
                   v.mldsa === 'unavailable') {
          // Only for the description of a key refused as unchecked: the
          // reader answers ok: false whenever this list is used.
          lastSub.pending.push(sig);
        }
      }
    }
  });
  const newest = function (list) {
    return list.slice().sort(function (a, b) {
      return b.created - a.created;
    })[0] || null;
  };
  // A user id is valid while its newest verified certification is newer
  // than every verified certification revocation (0x30) of it.
  const users = userRecords.map(function (u) {
    const cert = newest(u.certs);
    const revocation = newest(u.revocations);
    const valid = !!cert && (!revocation || cert.created > revocation.created);
    const text = u.body.toString('utf8');
    const email = (text.match(/<([^>]+)>/) || [])[1] || '';
    return { text: text, email: email, valid: valid, cert: cert,
             revokedCertification: !!revocation && !valid && !!cert };
  });
  // The primary key's expiry and flags come from its newest VERIFIED
  // direct-key signature, else from the newest valid user id
  // certification. An unverified one says nothing.
  const direct = newest(directs.filter(function (one) {
    return one.verified && one.verified.ok;
  }));
  const selfSig = direct || newest(users.filter(function (u) {
    return u.valid;
  }).map(function (u) {
    return u.cert;
  }));
  let expiresAt = '';
  let expired = false;
  if (selfSig && selfSig.keyExpires) {
    const exp = (primary.created + selfSig.keyExpires) * 1000;
    expiresAt = new Date(exp).toISOString();
    expired = exp <= when.getTime();
  }
  const primaryFlags = selfSig ? selfSig.flags : null;
  const subDescribed = [];
  let encryption = null;
  let encryptionCreated = -1;
  const encryptionKeys = [];
  subkeys.forEach(function (sub) {
    const info = Object.assign({
      fingerprint: fingerprintOf(sub.body) },
      algorithmInfo(sub.spec, sub.algorithm));
    const binding = newest(sub.bindings) ||
      (unchecked ? newest(sub.pending) : null);
    const subRevoked = sub.revocations.length > 0;
    const subExpired = !!(binding && binding.keyExpires &&
      (sub.created + binding.keyExpires) * 1000 <= when.getTime());
    // KEY FLAGS (RFC 9580 section 5.2.3.29): a binding that states them
    // must name an encryption use for the subkey to be encrypted to.
    const flagsAllow = !binding || binding.flags === null ||
      (binding.flags & (FLAG_ENCRYPT_COMMS | FLAG_ENCRYPT_STORAGE)) !== 0;
    sub.usable = !!binding && !subRevoked && !subExpired && flagsAllow &&
      sub.created * 1000 <= when.getTime() + 60000 &&
      !!sub.spec && sub.spec.use === 'encrypt';
    sub.fingerprint = info.fingerprint;
    subDescribed.push(Object.assign({ bound: !!binding,
                                      revoked: subRevoked }, info));
    if (sub.usable) {
      encryptionKeys.push(info);
    }
    // The newest usable subkey is the one mail is encrypted to, and the
    // one `encryptTo()` encrypts to (it reads this choice, never its own).
    if (sub.usable && sub.created > encryptionCreated) {
      encryption = Object.assign({ keyId: info.fingerprint.slice(0, 16) },
                                 info);
      encryptionCreated = sub.created;
    }
  });
  // The primary signs only when its newest verified self-signature lets it
  // (a stated key-flags subpacket without the sign flag means it does not);
  // this reader knows no signing subkey, so then the key has none.
  const signing = primaryFlags !== null && primaryFlags !== undefined &&
    (primaryFlags & FLAG_SIGN) === 0 ? null : {
      fingerprint: fp, keyId: fp.slice(0, 16),
      algorithm: primary.spec.name, curve: '', bits: 0
    };
  const description = {
    fingerprint: fp,
    keyId: fp.slice(0, 16),
    version: primary.version,
    created: new Date(primary.created * 1000).toISOString(),
    primary: algorithmInfo(primary.spec, primary.algorithm),
    subkeys: subDescribed,
    signing: signing,
    encryption: encryption,
    signingKeys: signing ? [signing] : [],
    encryptionKeys: encryptionKeys,
    users: users.map(function (u) {
      return { text: u.text, email: u.email, valid: u.valid };
    }),
    revoked: revoked,
    expiresAt: expiresAt,
    expired: expired,
    pqc: true
  };
  const key = { pqc: true, binary: binary, description: description,
                primary: primary, subkeys: subkeys, direct: direct,
                signing: !!signing };
  if (unchecked && !revoked) {
    log.debug("Leaving readPublicKey(). Unchecked.");
    return { ok: false, reason: 'unchecked', why: unchecked,
             description: description, binary: binary, key: key };
  }
  const certified = users.some(function (u) {
    return u.valid;
  });
  if (!direct && !certified) {
    log.debug("Leaving readPublicKey(). No self-signature.");
    return { ok: false, reason: 'bad-signature',
             why: 'no composite self-signature verified',
             description: description };
  }
  log.debug("Leaving readPublicKey(). " + fp);
  return { ok: true, key: key, description: description, binary: binary,
           armored: armorPublic(binary) };
}

/**
 * Armors a binary transferable public key. v6 keys carry no CRC24
 * footer (RFC 9580 section 6.1).
 *
 * @param binary - the bytes
 * @returns the armor
 */
function armorPublic(binary) {
  log.debug("Entering armorPublic().");
  const b64 = Buffer.from(binary).toString('base64');
  const lines = b64.match(/.{1,64}/g) || [];
  log.debug("Leaving armorPublic().");
  return '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n' +
    lines.join('\n') + '\n-----END PGP PUBLIC KEY BLOCK-----\n';
}

/**
 * Verifies a detached signature (`-----BEGIN PGP SIGNATURE-----`) over
 * the given bytes. Text signatures are canonicalised to CRLF first when
 * `text` is true; otherwise the bytes are hashed as a binary document
 * or as the signature's own type says.
 *
 * @param signature - the armored or binary signature
 * @param message - the signed bytes, or a string
 * @param key - a key `readPublicKey()` answered, or its description's
 *   source key object
 * @returns `{ ok, eddsa, mldsa, created, type }`
 */
function verifyDetached(signature, message, key) {
  log.debug("Entering verifyDetached().");
  const source = key && key.primary ? key : (key && key.key ? key.key : null);
  if (!source || !source.primary) {
    log.debug("Leaving verifyDetached(). No key.");
    return { ok: false, reason: 'other-key', why: 'no post-quantum key' };
  }
  let packets;
  try {
    packets = readPackets(bytesOf(signature));
  } catch (e) {
    log.debug("Caught in verifyDetached(): " + ((e && e.message) || e));
    log.debug("Leaving verifyDetached(). Unreadable.");
    return { ok: false, reason: 'unreadable',
             why: String((e && e.message) || e) };
  }
  const packet = packets.filter(function (p) {
    return p.tag === 2;
  })[0];
  if (!packet) {
    log.debug("Leaving verifyDetached(). No signature.");
    return { ok: false, reason: 'unsigned', why: 'no signature packet' };
  }
  const sig = parseSignature(packet.body);
  const raw = Buffer.isBuffer(message) ? message : Buffer.from(String(
    message == null ? '' : message));
  const subject = sig.type === 0x01 ? raw.toString('utf8') : raw;
  let over;
  try {
    over = toSign(sig.type, source.primary.body, subject, sig.version);
  } catch (e) {
    log.debug("Caught in verifyDetached(): " + ((e && e.message) || e));
    log.debug("Leaving verifyDetached(). Type.");
    return { ok: false, reason: 'unreadable',
             why: String((e && e.message) || e) };
  }
  const v = verifyComposite(sig, over, source.primary);
  log.debug("Leaving verifyDetached(). " + v.ok);
  return Object.assign({ type: sig.type, reason: v.ok ? '' : 'bad-signature' },
                       v);
}

/**
 * The RFC 9980 section 4.2.1 combiner. SHA3-256 of the two shares, the
 * ECDH ciphertext, the recipient's ECDH public key, the algorithm id
 * and the domain separator.
 *
 * @param mlkemShare - the ML-KEM shared secret
 * @param ecdhShare - the X25519 or X448 shared secret
 * @param ecdhCipherText - the ephemeral public key
 * @param ecdhPublicKey - the recipient's ECDH public key
 * @param algId - 35 or 36
 * @returns the 32-octet KEK
 */
function multiKeyCombine(mlkemShare, ecdhShare, ecdhCipherText,
                         ecdhPublicKey, algId) {
  log.debug("Entering multiKeyCombine().");
  const hash = crypto.createHash('sha3-256');
  hash.update(Buffer.from(mlkemShare));
  hash.update(Buffer.from(ecdhShare));
  hash.update(Buffer.from(ecdhCipherText));
  hash.update(Buffer.from(ecdhPublicKey));
  hash.update(Buffer.from([algId & 0xff]));
  hash.update(DOMSEP);
  hash.update(Buffer.from([DOMSEP.length]));
  const out = hash.digest();
  log.debug("Leaving multiKeyCombine().");
  return out;
}

/**
 * A v6 PKESK's composite fields (RFC 9580 section 5.1.2, RFC 9980
 * section 4.3.1).
 *
 * @param body - the packet body
 * @returns the parsed packet
 */
function parsePkesk(body) {
  log.debug("Entering parsePkesk().");
  let i = 0;
  const version = body[i];
  i += 1;
  if (version !== 6) {
    throw new Error('PKESK version ' + version + ' is not read');
  }
  const fpField = body[i];
  i += 1;
  let keyVersion = 0;
  let fingerprint = Buffer.alloc(0);
  if (fpField) {
    keyVersion = body[i];
    i += 1;
    fingerprint = Buffer.from(body.subarray(i, i + fpField - 1));
    i += fpField - 1;
  }
  const algorithm = body[i];
  i += 1;
  const spec = ALGS[algorithm];
  if (!spec || spec.use !== 'encrypt') {
    throw new Error('PKESK algorithm ' + algorithm + ' is not a composite KEM');
  }
  const ecdhCipherText = Buffer.from(body.subarray(i, i + spec.eccCt));
  i += spec.eccCt;
  const mlkemCipherText = Buffer.from(body.subarray(i, i + spec.pqCt));
  i += spec.pqCt;
  const restLen = body[i];
  i += 1;
  const wrapped = Buffer.from(body.subarray(i, i + restLen));
  log.debug("Leaving parsePkesk().");
  return { version: version, keyVersion: keyVersion,
           fingerprint: fingerprint.toString('hex'), algorithm: algorithm,
           spec: spec, ecdhCipherText: ecdhCipherText,
           mlkemCipherText: mlkemCipherText, wrapped: wrapped };
}

/**
 * Unwraps a session key with the published shares. The shares are the
 * test vector's; a live decrypt derives them with X25519 and ML-KEM.
 *
 * @param pkesk - `parsePkesk()`'s answer
 * @param ecdhPublicKey - the recipient's ECDH public key
 * @param mlkemShare - the ML-KEM shared secret
 * @param ecdhShare - the ECDH shared secret
 * @returns the session key
 */
function unwrapSessionKey(pkesk, ecdhPublicKey, mlkemShare, ecdhShare) {
  log.debug("Entering unwrapSessionKey().");
  const kek = multiKeyCombine(mlkemShare, ecdhShare, pkesk.ecdhCipherText,
                              ecdhPublicKey, pkesk.algorithm);
  const decipher = crypto.createDecipheriv('id-aes256-wrap', kek,
                                           Buffer.alloc(8, 0xa6));
  const session = Buffer.concat([decipher.update(pkesk.wrapped),
                                 decipher.final()]);
  log.debug("Leaving unwrapSessionKey().");
  return { kek: kek, sessionKey: session };
}

/**
 * Decrypts a v2 SEIPD body with a session key (RFC 9580 section 5.13.2).
 * AES-256 with OCB is what this service writes and what it reads here;
 * EAX and GCM are refused by name rather than guessed.
 *
 * @param body - the packet body
 * @param sessionKey - the unwrapped session key
 * @returns the plaintext packets' bytes
 */
function decryptSeipd(body, sessionKey) {
  log.debug("Entering decryptSeipd().");
  if (body[0] !== 2) {
    throw new Error('SEIPD version ' + body[0] + ' is not read');
  }
  const cipher = body[1];
  const aead = body[2];
  const chunkOctet = body[3];
  if (cipher !== 9 || aead !== 2) {
    throw new Error('SEIPD cipher ' + cipher + ' AEAD ' + aead +
                    ' is not AES-256-OCB');
  }
  if (chunkOctet > 16) {
    throw new Error('SEIPD chunk size octet ' + chunkOctet + ' is too large');
  }
  const salt = body.subarray(4, 36);
  const encrypted = body.subarray(36);
  const info = Buffer.from([0xd2, 0x02, cipher, aead, chunkOctet]);
  const derived = Buffer.from(crypto.hkdfSync('sha256', sessionKey, salt,
                                              info, 39));
  const messageKey = derived.subarray(0, 32);
  const ivPrefix = derived.subarray(32);
  const chunkSize = 1 << (chunkOctet + 6);
  const parts = [];
  let offset = 0;
  let index = 0;
  while (encrypted.length - offset > 16) {
    const last = encrypted.length - offset <= chunkSize + 32;
    const take = last ? encrypted.length - offset - 16 : chunkSize + 16;
    const piece = encrypted.subarray(offset, offset + take);
    const nonce = Buffer.alloc(15);
    ivPrefix.copy(nonce, 0);
    nonce.writeBigUInt64BE(BigInt(index), 7);
    const decipher = crypto.createDecipheriv('aes-256-ocb', messageKey,
                                             nonce, { authTagLength: 16 });
    decipher.setAAD(info);
    decipher.setAuthTag(piece.subarray(piece.length - 16));
    parts.push(Buffer.concat([
      decipher.update(piece.subarray(0, piece.length - 16)),
      decipher.final()]));
    offset += take;
    index += 1;
    if (last) {
      break;
    }
  }
  const plain = Buffer.concat(parts);
  const finalNonce = Buffer.alloc(15);
  ivPrefix.copy(finalNonce, 0);
  finalNonce.writeBigUInt64BE(BigInt(index), 7);
  const finalAad = Buffer.alloc(13);
  info.copy(finalAad, 0);
  finalAad.writeBigUInt64BE(BigInt(plain.length), 5);
  const finalTag = encrypted.subarray(encrypted.length - 16);
  const check = crypto.createDecipheriv('aes-256-ocb', messageKey,
                                        finalNonce, { authTagLength: 16 });
  check.setAAD(finalAad);
  check.setAuthTag(finalTag);
  check.update(Buffer.alloc(0));
  check.final();
  log.debug("Leaving decryptSeipd(). " + plain.length);
  return plain;
}

/**
 * The message packets of an encrypted message, given the published KEM
 * shares. Used to prove a vector; a live recipient derives the shares.
 *
 * @param input - the armored message
 * @param ecdhPublicKey - the recipient subkey's ECDH public key
 * @param mlkemShare - the ML-KEM shared secret
 * @param ecdhShare - the ECDH shared secret
 * @returns `{ kek, sessionKey, plaintext }`
 */
function decryptWithShares(input, ecdhPublicKey, mlkemShare, ecdhShare) {
  log.debug("Entering decryptWithShares().");
  const packets = readPackets(bytesOf(input));
  const pkeskPacket = packets.filter(function (p) {
    return p.tag === 1;
  })[0];
  const seipd = packets.filter(function (p) {
    return p.tag === 18;
  })[0];
  if (!pkeskPacket || !seipd) {
    throw new Error('the message has no v6 PKESK and v2 SEIPD');
  }
  const pkesk = parsePkesk(pkeskPacket.body);
  const unwrapped = unwrapSessionKey(pkesk, ecdhPublicKey, mlkemShare,
                                     ecdhShare);
  const plaintext = decryptSeipd(seipd.body, unwrapped.sessionKey);
  log.debug("Leaving decryptWithShares().");
  return { kek: unwrapped.kek, sessionKey: unwrapped.sessionKey,
           plaintext: plaintext, pkesk: pkesk };
}

/**
 * Verifies a cleartext signature (`gpg --clearsign`) by a key this reader
 * holds. The signature packet decides the hash; the Hash: armor header is
 * not trusted.
 *
 * @param signedText - the whole cleartext message
 * @param key - a key `readPublicKey()` answered
 * @returns the engine's shape: `{ ok, text, signer, created }` or
 *   `{ ok: false, reason, why }`
 */
function verifyCleartext(signedText, key) {
  log.debug("Entering verifyCleartext().");
  const text = String(signedText || '').replace(/\r\n?/g, '\n');
  const begin = text.indexOf('-----BEGIN PGP SIGNED MESSAGE-----');
  const sigAt = text.indexOf('-----BEGIN PGP SIGNATURE-----');
  if (begin < 0 || sigAt < 0) {
    log.debug("Leaving verifyCleartext(). Not cleartext.");
    return { ok: false, reason: 'unreadable',
             why: 'not a cleartext signed message' };
  }
  const head = text.slice(begin, sigAt).split('\n');
  let i = 1;
  while (i < head.length && head[i] !== '') {
    i += 1;
  }
  i += 1;
  const lines = [];
  for (; i < head.length; i++) {
    let line = head[i];
    if (line.indexOf('- ') === 0) {
      line = line.slice(2);
    }
    lines.push(line);
  }
  while (lines.length && lines[lines.length - 1] === '') {
    lines.pop();
  }
  const message = lines.join('\n');
  // A PROOF OF POSSESSION CARRIES EXACTLY ONE SIGNATURE. With several, which
  // one made the proof — and whose creation time is judged — would be a
  // choice among signatures a caller supplied.
  let count = 0;
  try {
    count = readPackets(bytesOf(text.slice(sigAt))).filter(function (p) {
      return p.tag === 2;
    }).length;
  } catch (e) {
    log.debug("Caught in verifyCleartext(): " + ((e && e.message) || e));
    log.debug("Leaving verifyCleartext(). Unreadable signature.");
    return { ok: false, reason: 'unreadable',
             why: String((e && e.message) || e) };
  }
  if (count !== 1) {
    log.debug("Leaving verifyCleartext(). " + count + " signatures.");
    return { ok: false, reason: count ? 'several' : 'unsigned',
             why: count ? 'the message carries ' + count + ' signatures; ' +
               'a proof of possession carries exactly one'
               : 'no signature packet' };
  }
  const source = key && key.primary ? key : (key && key.key ? key.key : null);
  if (source && source.signing === false) {
    log.debug("Leaving verifyCleartext(). The key does not sign.");
    return { ok: false, reason: 'other-key',
             why: 'made by a key whose self-signature does not let it sign' };
  }
  const verified = verifyDetached(text.slice(sigAt), message + '\n', key);
  if (!verified.ok && verified.eddsa !== true) {
    const again = verifyDetached(text.slice(sigAt), message, key);
    if (!again.ok && again.eddsa !== true) {
      log.debug("Leaving verifyCleartext(). " + verified.why);
      return { ok: false,
               reason: verified.reason || 'bad-signature',
               why: verified.why || 'the signature does not verify' };
    }
    log.debug("Leaving verifyCleartext(). Verified without a final LF.");
    return cleartextAnswer(key, message, again);
  }
  if (!verified.ok) {
    log.debug("Leaving verifyCleartext(). " + verified.why);
    return { ok: false,
             reason: verified.mldsa === 'unavailable' ? 'unchecked'
                                                      : 'bad-signature',
             why: verified.why, eddsa: verified.eddsa, mldsa: verified.mldsa };
  }
  log.debug("Leaving verifyCleartext(). Verified.");
  return cleartextAnswer(key, message, verified);
}

/**
 * The answer `verifyCleartext()` gives a signature that checked.
 *
 * @param key - the key
 * @param message - the cleartext
 * @param verified - the detached result
 * @returns `{ ok: true, text, signer, created }`
 */
function cleartextAnswer(key, message, verified) {
  log.debug("Entering cleartextAnswer().");
  const d = key.description || {};
  const signer = d.signing || d.primary || {};
  const created = verified.created
    ? new Date(verified.created * 1000).toISOString() : '';
  log.debug("Leaving cleartextAnswer().");
  return { ok: true, text: message,
           signer: { fingerprint: signer.fingerprint || d.fingerprint || '',
                     keyId: signer.keyId || d.keyId || '',
                     algorithm: signer.algorithm || '',
                     curve: signer.curve || '', bits: signer.bits || 0 },
           created: created };
}

// No Entering/Leaving pair: writePacket() is the encoder's inner write,
// once per packet of a message, and a debug line per call would drown an
// encryption.
function writePacket(tag, body) {
  const n = body.length;
  let len;
  if (n < 192) {
    len = Buffer.from([n]);
  } else if (n < 8384) {
    const v = n - 192;
    len = Buffer.from([192 + (v >> 8), v & 0xff]);
  } else {
    len = Buffer.alloc(5);
    len[0] = 255;
    len.writeUInt32BE(n, 1);
  }
  return Buffer.concat([Buffer.from([0xc0 | tag]), len, body]);
}

/**
 * A v2 SEIPD body, AES-256-OCB (RFC 9580 section 5.13.2). The chunk size
 * octet is 6 (4096-octet chunks).
 *
 * @param plaintext - the packets to encrypt
 * @param sessionKey - the 32-octet session key
 * @returns the packet body
 */
function encryptSeipd(plaintext, sessionKey) {
  log.debug("Entering encryptSeipd().");
  const cipherId = 9;
  const aead = 2;
  const chunkOctet = 6;
  const salt = crypto.randomBytes(32);
  const info = Buffer.from([0xd2, 0x02, cipherId, aead, chunkOctet]);
  const derived = Buffer.from(crypto.hkdfSync('sha256', sessionKey, salt,
                                              info, 39));
  const messageKey = derived.subarray(0, 32);
  const ivPrefix = derived.subarray(32);
  const chunkSize = 1 << (chunkOctet + 6);
  const plain = Buffer.from(plaintext);
  const chunks = [];
  let index = 0;
  let off = 0;
  do {
    const piece = plain.subarray(off, Math.min(plain.length, off + chunkSize));
    const nonce = Buffer.alloc(15);
    ivPrefix.copy(nonce, 0);
    nonce.writeBigUInt64BE(BigInt(index), 7);
    const enc = crypto.createCipheriv('aes-256-ocb', messageKey, nonce,
                                      { authTagLength: 16 });
    enc.setAAD(info);
    chunks.push(Buffer.concat([enc.update(piece), enc.final(),
                               enc.getAuthTag()]));
    index += 1;
    off += chunkSize;
  } while (off < plain.length);
  const finalNonce = Buffer.alloc(15);
  ivPrefix.copy(finalNonce, 0);
  finalNonce.writeBigUInt64BE(BigInt(index), 7);
  const finalAad = Buffer.alloc(13);
  info.copy(finalAad, 0);
  finalAad.writeBigUInt64BE(BigInt(plain.length), 5);
  const fin = crypto.createCipheriv('aes-256-ocb', messageKey, finalNonce,
                                    { authTagLength: 16 });
  fin.setAAD(finalAad);
  fin.update(Buffer.alloc(0));
  fin.final();
  const body = Buffer.concat([
    Buffer.from([2, cipherId, aead, chunkOctet]), salt,
    Buffer.concat(chunks), fin.getAuthTag()]);
  log.debug("Leaving encryptSeipd().");
  return body;
}

/**
 * A literal data packet (tag 11) holding `data` as binary.
 *
 * @param data - the bytes
 * @returns the packet
 */
function literalPacket(data) {
  log.debug("Entering literalPacket().");
  const date = Buffer.alloc(4);
  date.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  const body = Buffer.concat([Buffer.from([0x62, 0]), date, Buffer.from(data)]);
  log.debug("Leaving literalPacket().");
  return writePacket(11, body);
}

/**
 * The subkey a message to this key is encrypted to: the one
 * `readPublicKey()` chose as `description.encryption` — bound by a
 * verified binding signature, not revoked, not expired, its flags naming
 * an encryption use — and never merely the first subkey of an encryption
 * algorithm, which anybody can append to a published key.
 *
 * @param key - a key `readPublicKey()` answered
 * @returns the subkey, or null
 */
function encryptionSubkeyOf(key) {
  log.debug("Entering encryptionSubkeyOf().");
  const chosen = key && key.description && key.description.encryption;
  const wanted = chosen ? String(chosen.fingerprint || '') : '';
  const sub = wanted ? (key.subkeys || []).filter(function (s) {
    return s.usable === true && s.fingerprint === wanted;
  })[0] || null : null;
  log.debug("Leaving encryptionSubkeyOf(). " + (sub ? wanted : 'None.'));
  return sub;
}

/**
 * Encrypts bytes to a composite encryption subkey. ML-KEM encapsulation
 * needs node's OpenSSL 3.5; when it is absent this throws, and the
 * caller records its own code.
 *
 * @param data - the plaintext
 * @param key - a key `readPublicKey()` answered
 * @returns the armored message
 */
function encryptTo(data, key) {
  log.debug("Entering encryptTo().");
  const sub = encryptionSubkeyOf(key);
  if (!sub) {
    log.debug("Leaving encryptTo(). No encryption key.");
    throw new Error('the key has no bound, unrevoked composite ' +
                    'encryption subkey');
  }
  const pubs = splitPublic(sub.material, sub.spec);
  const x = sub.spec.ecc === 'x448'
    ? require('@noble/curves/ed448').x448
    : require('@noble/curves/ed25519').x25519;
  const eph = crypto.randomBytes(sub.spec.eccPub);
  const ecdhCipherText = Buffer.from(x.getPublicKey(eph));
  const ecdhShare = Buffer.from(x.getSharedSecret(eph, pubs.ecc));
  let kem;
  try {
    kem = require('./pqc').kemAlg(sub.spec.pq).encapsulate(pubs.pq);
  } catch (e) {
    log.debug("Caught in encryptTo(): " + ((e && e.message) || e));
    log.debug("Leaving encryptTo(). No ML-KEM.");
    throw new Error('ML-KEM is not available on this runtime (' +
                    ((e && e.message) || e) + ')');
  }
  const sessionKey = crypto.randomBytes(32);
  const kek = multiKeyCombine(kem.sharedSecret, ecdhShare, ecdhCipherText,
                              pubs.ecc, sub.algorithm);
  const wrap = crypto.createCipheriv('id-aes256-wrap', kek,
                                     Buffer.alloc(8, 0xa6));
  const wrapped = Buffer.concat([wrap.update(sessionKey), wrap.final()]);
  const fp = Buffer.from(fingerprintOf(sub.body), 'hex');
  const pkeskBody = Buffer.concat([
    Buffer.from([6, fp.length + 1, sub.version]), fp,
    Buffer.from([sub.algorithm]), ecdhCipherText,
    Buffer.from(kem.cipherText), Buffer.from([wrapped.length]), wrapped]);
  const seipdBody = encryptSeipd(literalPacket(data), sessionKey);
  const binary = Buffer.concat([writePacket(1, pkeskBody),
                                writePacket(18, seipdBody)]);
  const b64 = binary.toString('base64').match(/.{1,64}/g) || [];
  log.debug("Leaving encryptTo().");
  return '-----BEGIN PGP MESSAGE-----\n\n' + b64.join('\n') +
    '\n-----END PGP MESSAGE-----\n';
}

module.exports = {
  ALGS: ALGS,
  SIGNING_NAMES: SIGNING_NAMES,
  ENCRYPTION_NAMES: ENCRYPTION_NAMES,
  dearmor: dearmor,
  readPackets: readPackets,
  parsePublicKey: parsePublicKey,
  fingerprintOf: fingerprintOf,
  parseSignature: parseSignature,
  dataDigest: dataDigest,
  verifyComposite: verifyComposite,
  readPublicKey: readPublicKey,
  verifyDetached: verifyDetached,
  verifyCleartext: verifyCleartext,
  multiKeyCombine: multiKeyCombine,
  parsePkesk: parsePkesk,
  unwrapSessionKey: unwrapSessionKey,
  decryptSeipd: decryptSeipd,
  decryptWithShares: decryptWithShares,
  encryptSeipd: encryptSeipd,
  encryptTo: encryptTo,
  encryptionSubkeyOf: encryptionSubkeyOf,
  toSign: toSign,
  armorPublic: armorPublic
};
