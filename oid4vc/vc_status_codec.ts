'use strict';
//
// File: vc_status_codec.ts
//
// ---------------------------------------------------------------------------
// THE ENCODING HALF OF TWO STATUS MECHANISMS (#38 follow-ups, 2026-09-17).
//
//   * IETF Token Status List, draft-ietf-oauth-status-list-21 — the status of
//     a JOSE or COSE token (an SD-JWT VC, a CWT, an mdoc) as a compressed
//     array of 1, 2, 4 or 8 bits per token, published as a signed Status
//     List Token in JWT (`application/statuslist+jwt`) or CWT
//     (`application/statuslist+cwt`) form.
//   * W3C Bitstring Status List v1.0 — the same idea for a VCDM credential
//     (`jwt_vc_json`, `ldp_vc`), with a different bit order, a different
//     compression container and a different envelope.
//
// **WHAT THIS FILE IS NOT.** It allocates no index, keeps no list, serves no
// route and decides nothing about which credential is revoked: that is the
// status module's, which calls this one. What is here is the part two
// specifications fix to the bit, where a mistake does not fail loudly — a
// list packed in the wrong bit order still decodes, and says the wrong token
// is revoked. So it is a library with test vectors, kept apart from anything
// that has a store.
//
// **THE TWO BIT ORDERS ARE OPPOSITE, AND THAT IS THE EASY THING TO GET
// WRONG.** The draft (section 4.1) packs index 0 into the LEAST significant
// bit of byte 0; Bitstring Status List (section 2.2) puts index 0 at the
// LEFT-MOST, most significant, bit. One helper for both would be a helper
// that is wrong for one of them. `packTsl()` and `packBitstring()` are two
// functions on purpose, and `tests/vc_status_codec.js` holds each to its own
// specification's vectors.
//
// **THE COMPRESSION CONTAINERS DIFFER TOO**: ZLIB (RFC 1950) for the draft,
// GZIP (RFC 1952) for the W3C list, and a multibase `u` prefix on the latter.
// Decompression is BOUNDED in both directions (`maxOutputLength`): a status
// list comes from whoever the credential names, and a hundred kilobytes of
// zlib can be gigabytes of zeros.
//
// **CBOR AND COSE ARE WRITTEN HERE** because nothing in this service's
// dependencies speaks them, and what a Status List Token needs is small:
// the major types of RFC 8949 section 3, tags, and COSE_Sign1 (RFC 9052
// section 4.2). Maps keep INSERTION order rather than RFC 8949 section
// 4.2.1's bytewise order, because the draft's own examples (section 4.3,
// "bits" before "lst") are in insertion order and a verifier signs over the
// bytes it was given, not over a re-encoding.
//
// **POST-QUANTUM.** COSE carries ML-DSA-44/65/87 as -48/-49/-50
// (draft-ietf-cose-dilithium). The signature itself is `common/pq_jose.js`'s
// — the same code, and the same key shape (the 32-byte seed of RFC 9964), the
// JOSE side uses — with the `*Async` variants handing the work to the worker
// pool exactly as `common/crypto.js`'s `signJwsAsync()` does.
//
// A LIBRARY (rule 3): it registers no route and requires only `common/`
// leaves (`helpers` for the logger, `crypto`, `pq_jose`, `instance_slot`), so
// the issuer, the Verifier and the status module can all require it.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import zlib = require('zlib');
import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import pqJose = require('../common/pq_jose');
import InstanceSlot = require('../common/instance_slot');

// Section 7.1's registered values.
const TSL_STATUS = { VALID: 0, INVALID: 1, SUSPENDED: 2 };

// Section 4.1: the only permitted widths.
const TSL_BITS = [1, 2, 4, 8];

// Section 5.2's type, and the section 14.7 media types.
const CWT_TYPE = 'application/statuslist+cwt';
const JWT_TYPE = 'statuslist+jwt';

// W3C Bitstring Status List section 2.2 and 3.2: the smallest list a
// verifier accepts, in ENTRIES.
const BITSTRING_MIN_ENTRIES = 131072;
const BITSTRING_PURPOSES = ['refresh', 'revocation', 'suspension', 'message'];

// A status list is small; one that inflates past this is refused. 2^20
// tokens at eight bits is one mebibyte, so this leaves a wide margin and is
// still nothing like what a bomb expands to.
const DEFAULT_MAX_INFLATED = 32 * 1024 * 1024;

// How deep a CBOR item may nest before the decoder refuses it. A Status List
// Token nests four deep; this is generous and still stops a stack overflow.
const CBOR_MAX_DEPTH = 64;

// COSE algorithm identifiers (IANA "COSE Algorithms"), by JOSE name. The
// ML-DSA rows are draft-ietf-cose-dilithium's.
const COSE_ALGS: Record<string, number> = {
  ES256: -7, ES384: -35, ES512: -36, EdDSA: -8, ES256K: -47,
  PS256: -37, PS384: -38, PS512: -39,
  RS256: -257, RS384: -258, RS512: -259,
  'ML-DSA-44': -48, 'ML-DSA-65': -49, 'ML-DSA-87': -50
};
const COSE_ALG_NAMES: Record<string, string> = {};
Object.keys(COSE_ALGS).forEach(function (name) {
  COSE_ALG_NAMES[String(COSE_ALGS[name])] = name;
});

// A CBOR tag (RFC 8949 section 3.4): a number and the item it qualifies.
class Tagged {
  constructor(readonly tag: number, readonly value: unknown) {
  }
}

interface VcStatusCodecDeps {
  log: typeof helpers.log;
  stsCrypto: typeof stsCrypto;
  pqJose: typeof pqJose;
}

interface StatusListParts {
  bits: number;
  bytes: Buffer;
  aggregationUri?: string;
}

interface CoseSignInput {
  protectedHeader: Map<number, unknown>;
  unprotectedHeader?: Map<number, unknown>;
  payload: Buffer;
  key: any;
  alg: string;
}

interface CwtInput {
  sub: string;
  iat: number;
  exp?: number;
  ttl?: number;
  bits: number;
  bytes: Buffer;
  aggregationUri?: string;
  key: any;
  alg: string;
  kid?: string;
}

class VcStatusCodec {
  static readonly TSL_STATUS = TSL_STATUS;
  static readonly TSL_BITS = TSL_BITS;
  static readonly COSE_ALGS = COSE_ALGS;
  static readonly CWT_TYPE = CWT_TYPE;
  static readonly JWT_TYPE = JWT_TYPE;
  static readonly BITSTRING_MIN_ENTRIES = BITSTRING_MIN_ENTRIES;
  static readonly BITSTRING_PURPOSES = BITSTRING_PURPOSES;
  static readonly Tagged = Tagged;

  constructor(private readonly deps: VcStatusCodecDeps) {
    deps.log.debug("Entering VcStatusCodec.constructor().");
    deps.log.debug("Leaving VcStatusCodec.constructor().");
  }

  static defaultDeps(): VcStatusCodecDeps {
    helpers.log.debug("Entering VcStatusCodec.defaultDeps().");
    helpers.log.debug("Leaving VcStatusCodec.defaultDeps().");
    return { log: helpers.log, stsCrypto: stsCrypto, pqJose: pqJose };
  }

  private checkBits(bits: unknown): number {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.checkBits().");
    if (TSL_BITS.indexOf(Number(bits)) < 0 || !Number.isInteger(bits)) {
      log.debug("Leaving VcStatusCodec.checkBits(). Refused.");
      throw new Error('a Token Status List has 1, 2, 4 or 8 bits per ' +
                      'token (section 4.1); this one says ' + String(bits) +
                      '.');
    }
    log.debug("Leaving VcStatusCodec.checkBits().");
    return Number(bits);
  }

  private checkIndex(idx: unknown): number {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.checkIndex().");
    if (!Number.isSafeInteger(idx) || Number(idx) < 0) {
      log.debug("Leaving VcStatusCodec.checkIndex(). Refused.");
      throw new Error('a status list index is a non-negative integer; this ' +
                      'is ' + JSON.stringify(idx) + '.');
    }
    log.debug("Leaving VcStatusCodec.checkIndex().");
    return Number(idx);
  }

  // ---------------------------------------------------------------------------
  // TOKEN STATUS LIST, THE BYTE ARRAY (section 4.1). `values` is index ->
  // status, as a (possibly sparse) array or a Map; `size` is how many tokens
  // the list covers. Index 0 is the least significant bit(s) of byte 0.
  // ---------------------------------------------------------------------------
  packTsl(values: number[] | Map<number, number>, bits: number,
          size: number): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.packTsl(). bits=" + bits + ", size=" +
              size);
    const width = this.checkBits(bits);
    const count = this.checkIndex(size);
    const out = Buffer.alloc(Math.ceil(count * width / 8));
    const max = (1 << width) - 1;
    const put = (idx: number, value: number) => {
      if (!value) {
        return;
      }
      if (idx >= count) {
        throw new Error('index ' + idx + ' is outside a list of ' + count +
                        ' tokens.');
      }
      if (!Number.isInteger(value) || value < 0 || value > max) {
        throw new Error('status ' + value + ' does not fit in ' + width +
                        ' bit(s).');
      }
      const bit = idx * width;
      out[bit >> 3] |= value << (bit & 7);
    };
    if (values instanceof Map) {
      values.forEach(function (value, idx) {
        put(Number(idx), Number(value));
      });
    } else {
      (values || []).forEach(function (value, idx) {
        put(idx, Number(value));
      });
    }
    log.debug("Leaving VcStatusCodec.packTsl(). " + out.length + " byte(s).");
    return out;
  }

  unpackTslValue(bytes: Buffer, bits: number, idx: number): number {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.unpackTslValue(). idx=" + idx);
    const width = this.checkBits(bits);
    const at = this.checkIndex(idx) * width;
    // Section 8.3 step 6: an index past the end says nothing, and the
    // referenced token MUST be rejected — so this throws rather than
    // answering VALID for bits that do not exist.
    if (at + width > bytes.length * 8) {
      log.debug("Leaving VcStatusCodec.unpackTslValue(). Out of bounds.");
      throw new Error('index ' + idx + ' is outside this status list (' +
                      Math.floor(bytes.length * 8 / width) + ' tokens).');
    }
    const value = (bytes[at >> 3] >> (at & 7)) & ((1 << width) - 1);
    log.debug("Leaving VcStatusCodec.unpackTslValue(). " + value);
    return value;
  }

  // ZLIB, at the highest level (section 4.1 step 4).
  compress(bytes: Buffer): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.compress().");
    const out = zlib.deflateSync(bytes, { level: 9 });
    log.debug("Leaving VcStatusCodec.compress(). " + out.length + " byte(s).");
    return out;
  }

  decompress(bytes: Buffer, maxOutputLength?: number): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.decompress().");
    let out: Buffer;
    try {
      out = zlib.inflateSync(bytes, {
        maxOutputLength: maxOutputLength || DEFAULT_MAX_INFLATED });
    } catch (e) {
      log.debug("Caught in VcStatusCodec.decompress(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcStatusCodec.decompress(). Refused.");
      throw new Error('the status list is not a ZLIB stream this service ' +
                      'will inflate (' + ((e && e.message) || e) + ').');
    }
    log.debug("Leaving VcStatusCodec.decompress(). " + out.length +
              " byte(s).");
    return out;
  }

  // Section 4.2.
  tslJson(parts: StatusListParts): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.tslJson().");
    const out: any = {
      bits: this.checkBits(parts.bits),
      lst: this.compress(parts.bytes).toString('base64url')
    };
    if (parts.aggregationUri) {
      out.aggregation_uri = String(parts.aggregationUri);
    }
    log.debug("Leaving VcStatusCodec.tslJson().");
    return out;
  }

  tslFromJson(obj: any, maxOutputLength?: number): StatusListParts {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.tslFromJson().");
    if (!obj || typeof obj !== 'object' || typeof obj.lst !== 'string' ||
        !/^[A-Za-z0-9_-]+$/.test(obj.lst)) {
      log.debug("Leaving VcStatusCodec.tslFromJson(). Malformed.");
      throw new Error('a status_list is an object with bits and a base64url ' +
                      'lst (section 4.2).');
    }
    const bits = this.checkBits(obj.bits);
    if (obj.aggregation_uri !== undefined &&
        typeof obj.aggregation_uri !== 'string') {
      log.debug("Leaving VcStatusCodec.tslFromJson(). Bad aggregation_uri.");
      throw new Error('aggregation_uri is a string (section 4.2).');
    }
    const bytes = this.decompress(Buffer.from(obj.lst, 'base64url'),
                                  maxOutputLength);
    log.debug("Leaving VcStatusCodec.tslFromJson().");
    return { bits: bits, bytes: bytes,
             aggregationUri: obj.aggregation_uri };
  }

  // Section 4.3.
  tslCborMap(parts: StatusListParts): Map<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.tslCborMap().");
    const map = new Map<string, unknown>();
    map.set('bits', this.checkBits(parts.bits));
    map.set('lst', this.compress(parts.bytes));
    if (parts.aggregationUri) {
      map.set('aggregation_uri', String(parts.aggregationUri));
    }
    log.debug("Leaving VcStatusCodec.tslCborMap().");
    return map;
  }

  tslCbor(parts: StatusListParts): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.tslCbor().");
    const out = this.cborEncode(this.tslCborMap(parts));
    log.debug("Leaving VcStatusCodec.tslCbor().");
    return out;
  }

  tslFromCborMap(map: unknown, maxOutputLength?: number): StatusListParts {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.tslFromCborMap().");
    if (!(map instanceof Map) || !Buffer.isBuffer(map.get('lst'))) {
      log.debug("Leaving VcStatusCodec.tslFromCborMap(). Malformed.");
      throw new Error('a StatusList is a CBOR map with bits and a byte ' +
                      'string lst (section 4.3).');
    }
    const agg = map.get('aggregation_uri');
    if (agg !== undefined && typeof agg !== 'string') {
      log.debug("Leaving VcStatusCodec.tslFromCborMap(). Bad " +
                "aggregation_uri.");
      throw new Error('aggregation_uri is a text string (section 4.3).');
    }
    const out = { bits: this.checkBits(map.get('bits')),
                  bytes: this.decompress(map.get('lst') as Buffer,
                                         maxOutputLength),
                  aggregationUri: agg as string };
    log.debug("Leaving VcStatusCodec.tslFromCborMap().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // CBOR (RFC 8949). The encoder writes the shortest head for every length
  // and integer (section 4.2.1's first rule); maps keep the order they were
  // given, for the reason in the header.
  // ---------------------------------------------------------------------------
  private cborHead(major: number, value: number | bigint): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.cborHead().");
    const big = BigInt(value);
    let out: Buffer;
    if (big < BigInt(24)) {
      out = Buffer.from([(major << 5) | Number(big)]);
    } else if (big < BigInt(0x100)) {
      out = Buffer.from([(major << 5) | 24, Number(big)]);
    } else if (big < BigInt(0x10000)) {
      out = Buffer.alloc(3);
      out[0] = (major << 5) | 25;
      out.writeUInt16BE(Number(big), 1);
    } else if (big < BigInt(0x100000000)) {
      out = Buffer.alloc(5);
      out[0] = (major << 5) | 26;
      out.writeUInt32BE(Number(big), 1);
    } else {
      out = Buffer.alloc(9);
      out[0] = (major << 5) | 27;
      out.writeBigUInt64BE(big, 1);
    }
    log.debug("Leaving VcStatusCodec.cborHead().");
    return out;
  }

  cborEncode(value: unknown): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.cborEncode().");
    const parts: Buffer[] = [];
    const self = this;
    // Recursive and called per item, so no Entering/Leaving pair — the
    // hot-path exception the code style allows, stated as it requires.
    const walk = function (item: unknown, depth: number): void {
      if (depth > CBOR_MAX_DEPTH) {
        throw new Error('CBOR: nested deeper than ' + CBOR_MAX_DEPTH + '.');
      }
      if (item === false || item === true) {
        parts.push(Buffer.from([item ? 0xf5 : 0xf4]));
      } else if (item === null || item === undefined) {
        parts.push(Buffer.from([item === null ? 0xf6 : 0xf7]));
      } else if (typeof item === 'number' || typeof item === 'bigint') {
        const isInt = typeof item === 'bigint' || Number.isInteger(item);
        if (!isInt) {
          const f = Buffer.alloc(9);
          f[0] = 0xfb;
          f.writeDoubleBE(item as number, 1);
          parts.push(f);
        } else {
          if (typeof item === 'number' && !Number.isSafeInteger(item)) {
            throw new Error('CBOR: ' + item + ' is not a safe integer; ' +
                            'pass a bigint.');
          }
          const big = BigInt(item);
          if (big >= BigInt(0)) {
            parts.push(self.cborHead(0, big));
          } else {
            parts.push(self.cborHead(1, -BigInt(1) - big));
          }
        }
      } else if (Buffer.isBuffer(item) || item instanceof Uint8Array) {
        parts.push(self.cborHead(2, item.length), Buffer.from(item));
      } else if (typeof item === 'string') {
        const text = Buffer.from(item, 'utf8');
        parts.push(self.cborHead(3, text.length), text);
      } else if (Array.isArray(item)) {
        parts.push(self.cborHead(4, item.length));
        item.forEach(function (one) {
          walk(one, depth + 1);
        });
      } else if (item instanceof Map) {
        parts.push(self.cborHead(5, item.size));
        item.forEach(function (v, k) {
          walk(k, depth + 1);
          walk(v, depth + 1);
        });
      } else if (item instanceof Tagged) {
        parts.push(self.cborHead(6, item.tag));
        walk(item.value, depth + 1);
      } else if (typeof item === 'object') {
        const keys = Object.keys(item as object);
        parts.push(self.cborHead(5, keys.length));
        keys.forEach(function (k) {
          walk(k, depth + 1);
          walk((item as any)[k], depth + 1);
        });
      } else {
        throw new Error('CBOR: cannot encode a ' + typeof item + '.');
      }
    };
    walk(value, 0);
    const out = Buffer.concat(parts);
    log.debug("Leaving VcStatusCodec.cborEncode(). " + out.length +
              " byte(s).");
    return out;
  }

  cborDecode(input: Buffer | Uint8Array): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.cborDecode(). " + input.length +
              " byte(s).");
    const buf = Buffer.from(input);
    let pos = 0;
    const need = function (n: number): void {
      if (pos + n > buf.length) {
        throw new Error('CBOR: truncated at byte ' + pos + '.');
      }
    };
    // Reads one head; answers the major type and the argument (or the
    // simple/float marker for major type 7).
    const head = function (): { major: number; info: number;
                                arg: number } {
      need(1);
      const first = buf[pos++];
      const major = first >> 5;
      const info = first & 31;
      let arg = info;
      if (info === 24) {
        need(1);
        arg = buf[pos];
        pos += 1;
      } else if (info === 25) {
        need(2);
        arg = buf.readUInt16BE(pos);
        pos += 2;
      } else if (info === 26) {
        need(4);
        arg = buf.readUInt32BE(pos);
        pos += 4;
      } else if (info === 27) {
        need(8);
        const big = buf.readBigUInt64BE(pos);
        pos += 8;
        if (major !== 7 && big > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new Error('CBOR: an argument larger than ' +
                          Number.MAX_SAFE_INTEGER + ' is not accepted.');
        }
        arg = major === 7 ? 0 : Number(big);
        if (major === 7) {
          pos -= 8;
        }
      } else if (info > 27) {
        throw new Error('CBOR: indefinite lengths and reserved values are ' +
                        'not accepted (info ' + info + ').');
      }
      return { major: major, info: info, arg: arg };
    };
    // Recursive, so no Entering/Leaving pair (the hot-path exception).
    const item = function (depth: number): any {
      if (depth > CBOR_MAX_DEPTH) {
        throw new Error('CBOR: nested deeper than ' + CBOR_MAX_DEPTH + '.');
      }
      const h = head();
      switch (h.major) {
        case 0: {
          return h.arg;
        }
        case 1: {
          return -1 - h.arg;
        }
        case 2: {
          need(h.arg);
          const bytes = Buffer.from(buf.subarray(pos, pos + h.arg));
          pos += h.arg;
          return bytes;
        }
        case 3: {
          need(h.arg);
          const text = buf.subarray(pos, pos + h.arg).toString('utf8');
          pos += h.arg;
          return text;
        }
        case 4: {
          // Every item is at least one byte, so a count past the bytes left
          // is refused before anything is allocated for it.
          need(h.arg);
          const arr = [];
          for (let i = 0; i < h.arg; i++) {
            arr.push(item(depth + 1));
          }
          return arr;
        }
        case 5: {
          need(h.arg * 2);
          const map = new Map();
          for (let i = 0; i < h.arg; i++) {
            const k = item(depth + 1);
            if (map.has(k)) {
              throw new Error('CBOR: a map repeats the key ' +
                              JSON.stringify(k) + '.');
            }
            map.set(k, item(depth + 1));
          }
          return map;
        }
        case 6: {
          return new Tagged(h.arg, item(depth + 1));
        }
        default: {
          if (h.info === 20) {
            return false;
          }
          if (h.info === 21) {
            return true;
          }
          if (h.info === 22) {
            return null;
          }
          if (h.info === 23) {
            return undefined;
          }
          if (h.info === 25) {
            pos -= 2;
            need(2);
            const half = buf.readUInt16BE(pos);
            pos += 2;
            const exp = (half >> 10) & 0x1f;
            const mant = half & 0x3ff;
            const sign = half & 0x8000 ? -1 : 1;
            return sign * (exp === 0 ? mant * Math.pow(2, -14)
              : exp === 31 ? (mant ? NaN : Infinity)
                : (mant + 1024) * Math.pow(2, exp - 25));
          }
          if (h.info === 26) {
            pos -= 4;
            const f = buf.readFloatBE(pos);
            pos += 4;
            return f;
          }
          if (h.info === 27) {
            need(8);
            const d = buf.readDoubleBE(pos);
            pos += 8;
            return d;
          }
          throw new Error('CBOR: simple value ' + h.arg + ' is not ' +
                          'accepted.');
        }
      }
    };
    const out = item(0);
    if (pos !== buf.length) {
      log.debug("Leaving VcStatusCodec.cborDecode(). Trailing bytes.");
      throw new Error('CBOR: ' + (buf.length - pos) + ' byte(s) follow the ' +
                      'item.');
    }
    log.debug("Leaving VcStatusCodec.cborDecode().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // COSE_Sign1 (RFC 9052 section 4.2 and 4.4).
  // ---------------------------------------------------------------------------
  private sigStructure(protectedBytes: Buffer, payload: Buffer): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.sigStructure().");
    const out = this.cborEncode(['Signature1', protectedBytes,
                                 Buffer.alloc(0), payload]);
    log.debug("Leaving VcStatusCodec.sigStructure().");
    return out;
  }

  private algOf(alg: unknown): { name: string; id: number; spec: any } {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcStatusCodec.algOf(). " + String(alg));
    const name = typeof alg === 'number' ? COSE_ALG_NAMES[String(alg)]
                                         : String(alg || '');
    if (!name || COSE_ALGS[name] === undefined) {
      log.debug("Leaving VcStatusCodec.algOf(). Unknown.");
      throw new Error('COSE: algorithm ' + String(alg) + ' is not one this ' +
                      'service signs or verifies (' +
                      Object.keys(COSE_ALGS).join(', ') + ').');
    }
    log.debug("Leaving VcStatusCodec.algOf().");
    return { name: name, id: COSE_ALGS[name],
             spec: stsCrypto.jwsSpec(name) };
  }

  // A post-quantum private key is the seed bytes, or an AKP JWK carrying
  // them in `priv`, as `common/crypto.js`'s signer takes.
  private pqPrivate(key: any): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.pqPrivate().");
    log.debug("Leaving VcStatusCodec.pqPrivate().");
    return (key && key.priv) ? Buffer.from(key.priv, 'base64url')
                             : Buffer.from(key);
  }

  private pqPublic(key: any): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.pqPublic().");
    log.debug("Leaving VcStatusCodec.pqPublic().");
    return (key && key.pub) ? Buffer.from(key.pub, 'base64url')
      : (typeof key === 'string' ? Buffer.from(key, 'base64url')
                                 : Buffer.from(key));
  }

  private nodeParams(spec: any, key: any, isPrivate: boolean): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.nodeParams().");
    const keyObject = (key && (key.type === 'private' ||
                               key.type === 'public'))
      ? key
      : (isPrivate
          ? nodeCrypto.createPrivateKey(
              (key && key.kty) ? { key: key, format: 'jwk' } : key)
          : nodeCrypto.createPublicKey(
              (key && key.kty) ? { key: key, format: 'jwk' } : key));
    const params: any = { key: keyObject };
    if (spec.padding !== undefined) {
      params.padding = spec.padding;
      params.saltLength = spec.saltLength;
    }
    if (spec.family === 'ec') {
      params.dsaEncoding = 'ieee-p1363';
    }
    log.debug("Leaving VcStatusCodec.nodeParams().");
    return params;
  }

  private coseSetup(input: CoseSignInput): { alg: any; protectedBytes: Buffer;
                                             toBeSigned: Buffer } {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.coseSetup().");
    const alg = this.algOf(input.alg);
    const header = new Map<number, unknown>(input.protectedHeader || []);
    header.set(1, alg.id);
    // The algorithm first, as every example in RFC 9052 and the draft has it.
    const ordered = new Map<number, unknown>([[1, alg.id]]);
    header.forEach(function (v, k) {
      if (k !== 1) {
        ordered.set(k, v);
      }
    });
    const protectedBytes = this.cborEncode(ordered);
    const toBeSigned = this.sigStructure(protectedBytes,
                                         Buffer.from(input.payload));
    log.debug("Leaving VcStatusCodec.coseSetup().");
    return { alg: alg, protectedBytes: protectedBytes,
             toBeSigned: toBeSigned };
  }

  private coseAssemble(input: CoseSignInput, protectedBytes: Buffer,
                       signature: Buffer): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.coseAssemble().");
    const out = this.cborEncode(new Tagged(18, [
      protectedBytes,
      new Map(input.unprotectedHeader || []),
      Buffer.from(input.payload),
      signature
    ]));
    log.debug("Leaving VcStatusCodec.coseAssemble(). " + out.length +
              " byte(s).");
    return out;
  }

  coseSign1Sign(input: CoseSignInput): Buffer {
    const { log, pqJose } = this.deps;
    log.debug("Entering VcStatusCodec.coseSign1Sign(). alg=" + input.alg);
    const setup = this.coseSetup(input);
    const spec = setup.alg.spec;
    const signature = spec.family === 'pq'
      ? Buffer.from(pqJose.sign(setup.alg.name, this.pqPrivate(input.key),
                                setup.toBeSigned))
      : nodeCrypto.sign(spec.hash, setup.toBeSigned,
                        this.nodeParams(spec, input.key, true));
    const out = this.coseAssemble(input, setup.protectedBytes, signature);
    log.debug("Leaving VcStatusCodec.coseSign1Sign().");
    return out;
  }

  // The same, with a post-quantum signature made in the worker pool.
  async coseSign1SignAsync(input: CoseSignInput): Promise<Buffer> {
    const { log, pqJose } = this.deps;
    log.debug("Entering VcStatusCodec.coseSign1SignAsync(). alg=" +
              input.alg);
    const setup = this.coseSetup(input);
    if (setup.alg.spec.family !== 'pq') {
      log.debug("Leaving VcStatusCodec.coseSign1SignAsync(). In process.");
      return this.coseSign1Sign(input);
    }
    const signature = await pqJose.signAsync(setup.alg.name,
      this.pqPrivate(input.key), setup.toBeSigned, {});
    log.debug("Leaving VcStatusCodec.coseSign1SignAsync(). Pooled.");
    return this.coseAssemble(input, setup.protectedBytes,
                             Buffer.from(signature));
  }

  // Parses a COSE_Sign1 and checks everything but the signature itself, in
  // the order `common/crypto.js` refuses a JWS: shape, then the algorithm
  // against the caller's list, and only then the signature.
  private coseParse(buf: Buffer, opts: { algorithms?: string[] }): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.coseParse().");
    const decoded = this.cborDecode(buf);
    if (!(decoded instanceof Tagged) || decoded.tag !== 18 ||
        !Array.isArray(decoded.value) || decoded.value.length !== 4) {
      log.debug("Leaving VcStatusCodec.coseParse(). Not COSE_Sign1_Tagged.");
      throw new Error('COSE: not a COSE_Sign1_Tagged (tag 18) structure.');
    }
    const [protectedBytes, unprotectedHeader, payload, signature] =
      decoded.value as any[];
    if (!Buffer.isBuffer(protectedBytes) || !Buffer.isBuffer(payload) ||
        !Buffer.isBuffer(signature) || !(unprotectedHeader instanceof Map)) {
      log.debug("Leaving VcStatusCodec.coseParse(). Malformed members.");
      throw new Error('COSE: a COSE_Sign1 is [bstr, map, bstr, bstr].');
    }
    const protectedHeader = protectedBytes.length
      ? this.cborDecode(protectedBytes) : new Map();
    if (!(protectedHeader instanceof Map)) {
      log.debug("Leaving VcStatusCodec.coseParse(). Bad protected header.");
      throw new Error('COSE: the protected header is not a map.');
    }
    const allowed = opts && opts.algorithms;
    if (!Array.isArray(allowed) || !allowed.length) {
      log.debug("Leaving VcStatusCodec.coseParse(). No algorithm list.");
      throw new Error('COSE: the caller must name the acceptable ' +
                      'algorithms (RFC 8725 section 3.1, read for COSE).');
    }
    if (unprotectedHeader.has(1)) {
      log.debug("Leaving VcStatusCodec.coseParse(). Unprotected alg.");
      throw new Error('COSE: the algorithm must be in the protected header.');
    }
    const alg = this.algOf(protectedHeader.get(1));
    if (allowed.indexOf(alg.name) < 0) {
      log.debug("Leaving VcStatusCodec.coseParse(). Algorithm refused.");
      throw new Error('COSE: signed with ' + alg.name + ', and only ' +
                      allowed.join(', ') + ' accepted here.');
    }
    if (alg.spec.family === 'ec' && alg.spec.sigBytes &&
        signature.length !== alg.spec.sigBytes) {
      log.debug("Leaving VcStatusCodec.coseParse(). Wrong signature size.");
      throw new Error('COSE: an ' + alg.name + ' signature is ' +
                      alg.spec.sigBytes + ' bytes; this is ' +
                      signature.length + '.');
    }
    log.debug("Leaving VcStatusCodec.coseParse(). alg=" + alg.name);
    return {
      alg: alg, protectedHeader: protectedHeader,
      unprotectedHeader: unprotectedHeader, payload: payload,
      signature: signature,
      toBeSigned: this.sigStructure(protectedBytes, payload)
    };
  }

  private coseFinish(parsed: any, ok: boolean): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.coseFinish(). ok=" + ok);
    if (!ok) {
      log.debug("Leaving VcStatusCodec.coseFinish(). Refused.");
      throw new Error('COSE: the ' + parsed.alg.name + ' signature does not ' +
                      'verify.');
    }
    log.debug("Leaving VcStatusCodec.coseFinish().");
    return { alg: parsed.alg.name, protectedHeader: parsed.protectedHeader,
             unprotectedHeader: parsed.unprotectedHeader,
             payload: parsed.payload };
  }

  coseSign1Verify(buf: Buffer, key: any,
                  opts: { algorithms: string[] }): any {
    const { log, pqJose } = this.deps;
    log.debug("Entering VcStatusCodec.coseSign1Verify().");
    const parsed = this.coseParse(buf, opts);
    const spec = parsed.alg.spec;
    const ok = spec.family === 'pq'
      ? !!pqJose.verify(parsed.alg.name, this.pqPublic(key),
                        parsed.toBeSigned, parsed.signature)
      : nodeCrypto.verify(spec.hash, parsed.toBeSigned,
                          this.nodeParams(spec, key, false),
                          parsed.signature);
    const out = this.coseFinish(parsed, ok);
    log.debug("Leaving VcStatusCodec.coseSign1Verify().");
    return out;
  }

  async coseSign1VerifyAsync(buf: Buffer, key: any,
                             opts: { algorithms: string[] }): Promise<any> {
    const { log, pqJose } = this.deps;
    log.debug("Entering VcStatusCodec.coseSign1VerifyAsync().");
    const parsed = this.coseParse(buf, opts);
    if (parsed.alg.spec.family !== 'pq') {
      log.debug("Leaving VcStatusCodec.coseSign1VerifyAsync(). In process.");
      return this.coseSign1Verify(buf, key, opts);
    }
    const ok = await pqJose.verifyAsync(parsed.alg.name, this.pqPublic(key),
      parsed.toBeSigned, parsed.signature, {});
    log.debug("Leaving VcStatusCodec.coseSign1VerifyAsync(). Pooled.");
    return this.coseFinish(parsed, !!ok);
  }

  // ---------------------------------------------------------------------------
  // THE STATUS LIST TOKEN, CWT FORM (section 5.2). Not CWT-tagged; the
  // COSE_Sign1 is tagged 18; the type goes in protected header 16.
  // ---------------------------------------------------------------------------
  private cwtInput(input: CwtInput): CoseSignInput {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.cwtInput().");
    if (!input.sub || !Number.isInteger(input.iat)) {
      log.debug("Leaving VcStatusCodec.cwtInput(). Missing claims.");
      throw new Error('a Status List Token needs sub and iat (section 5.2).');
    }
    const claims = new Map<number, unknown>();
    claims.set(2, String(input.sub));
    claims.set(6, input.iat);
    if (input.exp !== undefined) {
      claims.set(4, input.exp);
    }
    if (input.ttl !== undefined) {
      if (!(Number(input.ttl) > 0)) {
        throw new Error('ttl is a positive number (section 5.2).');
      }
      claims.set(65534, input.ttl);
    }
    claims.set(65533, this.tslCborMap(input));
    const unprotectedHeader = new Map<number, unknown>();
    if (input.kid) {
      unprotectedHeader.set(4, Buffer.from(String(input.kid), 'utf8'));
    }
    log.debug("Leaving VcStatusCodec.cwtInput().");
    return {
      protectedHeader: new Map<number, unknown>([[16, CWT_TYPE]]),
      unprotectedHeader: unprotectedHeader,
      payload: this.cborEncode(claims),
      key: input.key,
      alg: input.alg
    };
  }

  statusListCwt(input: CwtInput): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.statusListCwt().");
    const out = this.coseSign1Sign(this.cwtInput(input));
    log.debug("Leaving VcStatusCodec.statusListCwt().");
    return out;
  }

  async statusListCwtAsync(input: CwtInput): Promise<Buffer> {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.statusListCwtAsync().");
    const out = await this.coseSign1SignAsync(this.cwtInput(input));
    log.debug("Leaving VcStatusCodec.statusListCwtAsync().");
    return out;
  }

  // The claims of a verified CWT, checked per section 8.3 steps 3 and 4.
  private cwtClaims(verified: any, opts: any): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.cwtClaims().");
    if (verified.protectedHeader.get(16) !== CWT_TYPE) {
      log.debug("Leaving VcStatusCodec.cwtClaims(). Wrong type.");
      throw new Error('a Status List Token in CWT form carries type ' +
                      CWT_TYPE + ' in protected header 16 (section 5.2).');
    }
    const claims = this.cborDecode(verified.payload);
    if (claims instanceof Tagged) {
      log.debug("Leaving VcStatusCodec.cwtClaims(). CWT-tagged.");
      throw new Error('a Status List Token MUST NOT be CWT-tagged ' +
                      '(section 5.2).');
    }
    if (!(claims instanceof Map)) {
      log.debug("Leaving VcStatusCodec.cwtClaims(). Not a map.");
      throw new Error('the CWT claims set is not a map.');
    }
    const sub = claims.get(2);
    const iat = claims.get(6);
    const exp = claims.get(4);
    const ttl = claims.get(65534);
    if (typeof sub !== 'string' || !sub || typeof iat !== 'number') {
      log.debug("Leaving VcStatusCodec.cwtClaims(). Missing sub or iat.");
      throw new Error('a Status List Token carries subject (2) and issued ' +
                      'at (6) (section 5.2).');
    }
    const now = opts && opts.now !== undefined ? opts.now
                                               : Math.floor(Date.now() / 1000);
    if (exp !== undefined && (typeof exp !== 'number' || exp <= now)) {
      log.debug("Leaving VcStatusCodec.cwtClaims(). Expired.");
      throw new Error('the Status List Token has expired (section 8.3 step ' +
                      '4c).');
    }
    if (ttl !== undefined && !(typeof ttl === 'number' && ttl > 0)) {
      log.debug("Leaving VcStatusCodec.cwtClaims(). Bad ttl.");
      throw new Error('ttl (65534) is a positive number (section 5.2).');
    }
    const list = this.tslFromCborMap(claims.get(65533),
                                     opts && opts.maxOutputLength);
    log.debug("Leaving VcStatusCodec.cwtClaims().");
    return { sub: sub, iat: iat, exp: exp, ttl: ttl, bits: list.bits,
             bytes: list.bytes, aggregationUri: list.aggregationUri,
             alg: verified.alg };
  }

  readStatusListCwt(buf: Buffer, key: any,
                    opts: { algorithms: string[]; now?: number;
                            maxOutputLength?: number }): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.readStatusListCwt().");
    const out = this.cwtClaims(this.coseSign1Verify(buf, key, opts), opts);
    log.debug("Leaving VcStatusCodec.readStatusListCwt().");
    return out;
  }

  async readStatusListCwtAsync(buf: Buffer, key: any,
                               opts: { algorithms: string[]; now?: number;
                                       maxOutputLength?: number }):
      Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.readStatusListCwtAsync().");
    const verified = await this.coseSign1VerifyAsync(buf, key, opts);
    log.debug("Leaving VcStatusCodec.readStatusListCwtAsync().");
    return this.cwtClaims(verified, opts);
  }

  // ---------------------------------------------------------------------------
  // THE STATUS LIST TOKEN, JWT FORM (section 5.1). The caller signs, with
  // `typ: statuslist+jwt`, through `common/crypto.js`, and hands the verified
  // header and claims back here.
  // ---------------------------------------------------------------------------
  statusListJwtPayload(input: { sub: string; iat: number; exp?: number;
                                ttl?: number; bits: number; bytes: Buffer;
                                aggregationUri?: string }): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.statusListJwtPayload().");
    if (!input.sub || !Number.isInteger(input.iat)) {
      log.debug("Leaving VcStatusCodec.statusListJwtPayload(). Missing.");
      throw new Error('a Status List Token needs sub and iat (section 5.1).');
    }
    const out: any = { sub: String(input.sub), iat: input.iat };
    if (input.exp !== undefined) {
      out.exp = input.exp;
    }
    if (input.ttl !== undefined) {
      if (!(Number(input.ttl) > 0)) {
        throw new Error('ttl is a positive number (section 5.1).');
      }
      out.ttl = input.ttl;
    }
    out.status_list = this.tslJson(input);
    log.debug("Leaving VcStatusCodec.statusListJwtPayload().");
    return out;
  }

  readStatusListJwtPayload(header: any, claims: any,
                           opts?: { now?: number;
                                    maxOutputLength?: number }): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.readStatusListJwtPayload().");
    if (!header || header.typ !== JWT_TYPE) {
      log.debug("Leaving VcStatusCodec.readStatusListJwtPayload(). typ.");
      throw new Error('a Status List Token in JWT form has typ ' + JWT_TYPE +
                      ' (section 5.1).');
    }
    const c = claims || {};
    if (typeof c.sub !== 'string' || !c.sub || typeof c.iat !== 'number') {
      log.debug("Leaving VcStatusCodec.readStatusListJwtPayload(). Claims.");
      throw new Error('a Status List Token carries sub and iat (section ' +
                      '5.1).');
    }
    const now = opts && opts.now !== undefined ? opts.now
                                               : Math.floor(Date.now() / 1000);
    if (c.exp !== undefined && (typeof c.exp !== 'number' || c.exp <= now)) {
      log.debug("Leaving VcStatusCodec.readStatusListJwtPayload(). Expired.");
      throw new Error('the Status List Token has expired (section 8.3 step ' +
                      '4c).');
    }
    if (c.ttl !== undefined && !(typeof c.ttl === 'number' && c.ttl > 0)) {
      log.debug("Leaving VcStatusCodec.readStatusListJwtPayload(). ttl.");
      throw new Error('ttl is a positive number (section 5.1).');
    }
    const list = this.tslFromJson(c.status_list,
                                  opts && opts.maxOutputLength);
    log.debug("Leaving VcStatusCodec.readStatusListJwtPayload().");
    return { sub: c.sub, iat: c.iat, exp: c.exp, ttl: c.ttl,
             bits: list.bits, bytes: list.bytes,
             aggregationUri: list.aggregationUri };
  }

  // ---------------------------------------------------------------------------
  // THE REFERENCE IN A REFERENCED TOKEN (sections 6.2 and 6.3). `null` when
  // the token carries no status_list at all; a malformed one THROWS, because
  // section 8.3 step 1 says a token whose reference is wrong is rejected,
  // not treated as one without a reference.
  // ---------------------------------------------------------------------------
  private checkReference(idx: unknown, uri: unknown): { idx: number;
                                                         uri: string } {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.checkReference().");
    if (!Number.isSafeInteger(idx) || Number(idx) < 0 ||
        typeof uri !== 'string' || !/^[A-Za-z][A-Za-z0-9+.-]*:\S+$/
          .test(uri)) {
      log.debug("Leaving VcStatusCodec.checkReference(). Malformed.");
      throw new Error('a status_list reference is a non-negative integer ' +
                      'idx and a URI (section 6.2).');
    }
    log.debug("Leaving VcStatusCodec.checkReference().");
    return { idx: Number(idx), uri: uri };
  }

  referenceOf(payload: any): { idx: number; uri: string } | null {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.referenceOf().");
    const status = payload && payload.status;
    if (status === undefined) {
      log.debug("Leaving VcStatusCodec.referenceOf(). No status claim.");
      return null;
    }
    if (!status || typeof status !== 'object' || Array.isArray(status)) {
      log.debug("Leaving VcStatusCodec.referenceOf(). Malformed status.");
      throw new Error('the status claim is a JSON object (section 6.2).');
    }
    if (status.status_list === undefined) {
      log.debug("Leaving VcStatusCodec.referenceOf(). Another mechanism.");
      return null;
    }
    const list = status.status_list || {};
    const out = this.checkReference(list.idx, list.uri);
    log.debug("Leaving VcStatusCodec.referenceOf(). idx=" + out.idx);
    return out;
  }

  // A COSE referenced token's Status structure (claim 65535 of a CWT, or
  // the equivalent element of an mdoc), as decoded here: a Map.
  referenceOfCose(status: unknown): { idx: number; uri: string } | null {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.referenceOfCose().");
    if (status === undefined) {
      log.debug("Leaving VcStatusCodec.referenceOfCose(). None.");
      return null;
    }
    if (!(status instanceof Map)) {
      log.debug("Leaving VcStatusCodec.referenceOfCose(). Malformed.");
      throw new Error('the Status structure is a CBOR map (section 6.3).');
    }
    const list = status.get('status_list');
    if (list === undefined) {
      log.debug("Leaving VcStatusCodec.referenceOfCose(). Another " +
                "mechanism.");
      return null;
    }
    if (!(list instanceof Map)) {
      log.debug("Leaving VcStatusCodec.referenceOfCose(). Bad info.");
      throw new Error('StatusListInfo is a CBOR map (section 6.3).');
    }
    const out = this.checkReference(list.get('idx'), list.get('uri'));
    log.debug("Leaving VcStatusCodec.referenceOfCose().");
    return out;
  }

  // The Status structure for a COSE referenced token.
  coseStatus(ref: { idx: number; uri: string }): Map<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.coseStatus().");
    const checked = this.checkReference(ref.idx, ref.uri);
    const info = new Map<string, unknown>([['idx', checked.idx],
                                           ['uri', checked.uri]]);
    log.debug("Leaving VcStatusCodec.coseStatus().");
    return new Map<string, unknown>([['status_list', info]]);
  }

  // ---------------------------------------------------------------------------
  // W3C BITSTRING STATUS LIST. Index 0 is the LEFT-MOST bit (section 2.2);
  // `size` is in ENTRIES and must be at least 131,072 (section 3.2).
  // `values` is a list of indexes whose status is 1, or a Map index -> value
  // for a `statusSize` above one.
  // ---------------------------------------------------------------------------
  packBitstring(values: number[] | Map<number, number>, size: number,
                statusSize?: number): Buffer {
    const { log } = this.deps;
    const width = statusSize === undefined ? 1 : Number(statusSize);
    log.debug("Entering VcStatusCodec.packBitstring(). size=" + size +
              ", statusSize=" + width);
    if (!Number.isInteger(width) || width < 1 || width > 8) {
      log.debug("Leaving VcStatusCodec.packBitstring(). statusSize.");
      throw new Error('statusSize is an integer from 1 to 8 here.');
    }
    const count = this.checkIndex(size);
    if (count < BITSTRING_MIN_ENTRIES) {
      log.debug("Leaving VcStatusCodec.packBitstring(). Too short.");
      throw new Error('a Bitstring Status List has at least ' +
                      BITSTRING_MIN_ENTRIES + ' entries (section 3.2).');
    }
    const out = Buffer.alloc(Math.ceil(count * width / 8));
    const max = (1 << width) - 1;
    const put = (idx: number, value: number) => {
      if (!value) {
        return;
      }
      if (!Number.isSafeInteger(idx) || idx < 0 || idx >= count) {
        throw new Error('index ' + idx + ' is outside a list of ' + count +
                        ' entries.');
      }
      if (!Number.isInteger(value) || value < 0 || value > max) {
        throw new Error('status ' + value + ' does not fit in ' + width +
                        ' bit(s).');
      }
      // Most significant bit of the entry first, left to right.
      for (let b = 0; b < width; b++) {
        if ((value >> (width - 1 - b)) & 1) {
          const bit = idx * width + b;
          out[bit >> 3] |= 0x80 >> (bit & 7);
        }
      }
    };
    if (values instanceof Map) {
      values.forEach(function (value, idx) {
        put(Number(idx), Number(value));
      });
    } else {
      (values || []).forEach(function (idx) {
        put(Number(idx), 1);
      });
    }
    log.debug("Leaving VcStatusCodec.packBitstring(). " + out.length +
              " byte(s).");
    return out;
  }

  bitstringValue(bytes: Buffer, idx: number, statusSize?: number): number {
    const { log } = this.deps;
    const width = statusSize === undefined ? 1 : Number(statusSize);
    log.debug("Entering VcStatusCodec.bitstringValue(). idx=" + idx);
    const at = this.checkIndex(idx) * width;
    // Section 3.2: a position outside the bitstring is a RANGE_ERROR.
    if (!Number.isInteger(width) || width < 1 || width > 8 ||
        at + width > bytes.length * 8) {
      log.debug("Leaving VcStatusCodec.bitstringValue(). RANGE_ERROR.");
      throw new Error('RANGE_ERROR: index ' + idx + ' is outside this ' +
                      'status list.');
    }
    let value = 0;
    for (let b = 0; b < width; b++) {
      const bit = at + b;
      value = (value << 1) | ((bytes[bit >> 3] >> (7 - (bit & 7))) & 1);
    }
    log.debug("Leaving VcStatusCodec.bitstringValue(). " + value);
    return value;
  }

  // Multibase base64url, no padding, of the GZIP stream (section 2.2).
  encodedList(bytes: Buffer): string {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.encodedList().");
    const out = 'u' + zlib.gzipSync(bytes, { level: 9 })
      .toString('base64url');
    log.debug("Leaving VcStatusCodec.encodedList().");
    return out;
  }

  decodeEncodedList(text: unknown, maxOutputLength?: number): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.decodeEncodedList().");
    const value = String(text || '');
    if (!/^u[A-Za-z0-9_-]+$/.test(value)) {
      log.debug("Leaving VcStatusCodec.decodeEncodedList(). Not multibase u.");
      throw new Error('encodedList is multibase base64url with no padding ' +
                      '(the "u" prefix, section 2.2).');
    }
    let out: Buffer;
    try {
      out = zlib.gunzipSync(Buffer.from(value.slice(1), 'base64url'), {
        maxOutputLength: maxOutputLength || DEFAULT_MAX_INFLATED });
    } catch (e) {
      log.debug("Caught in VcStatusCodec.decodeEncodedList(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcStatusCodec.decodeEncodedList(). Refused.");
      throw new Error('encodedList is not a GZIP stream this service will ' +
                      'expand (' + ((e && e.message) || e) + ').');
    }
    log.debug("Leaving VcStatusCodec.decodeEncodedList(). " + out.length +
              " byte(s).");
    return out;
  }

  bitstringEntry(input: { id?: string; statusPurpose: string;
                          statusListIndex: number;
                          statusListCredential: string;
                          statusSize?: number;
                          statusMessage?: any[] }): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.bitstringEntry().");
    const entry: any = {};
    if (input.id) {
      entry.id = String(input.id);
    }
    entry.type = 'BitstringStatusListEntry';
    entry.statusPurpose = String(input.statusPurpose);
    entry.statusListIndex = String(this.checkIndex(input.statusListIndex));
    entry.statusListCredential = String(input.statusListCredential);
    if (input.statusSize !== undefined) {
      entry.statusSize = input.statusSize;
    }
    if (input.statusMessage !== undefined) {
      entry.statusMessage = input.statusMessage;
    }
    log.debug("Leaving VcStatusCodec.bitstringEntry().");
    return this.readBitstringEntry(entry) && entry;
  }

  bitstringStatusListSubject(input: { id: string; statusPurpose: string;
                                      encodedList: string;
                                      ttl?: number }): any {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.bitstringStatusListSubject().");
    const out: any = {
      id: String(input.id),
      type: 'BitstringStatusList',
      statusPurpose: String(input.statusPurpose),
      encodedList: String(input.encodedList)
    };
    if (input.ttl !== undefined) {
      // Milliseconds, per section 2.2 — the draft's ttl is seconds.
      out.ttl = input.ttl;
    }
    log.debug("Leaving VcStatusCodec.bitstringStatusListSubject().");
    return out;
  }

  // A presented credential's entry, validated per section 2.1 — a
  // MALFORMED_VALUE_ERROR throws.
  readBitstringEntry(entry: any): { statusPurpose: string; index: number;
                                    credential: string; statusSize: number;
                                    statusMessage: any[] | null } {
    const { log } = this.deps;
    log.debug("Entering VcStatusCodec.readBitstringEntry().");
    const e = entry || {};
    const fail = (why: string) => {
      log.debug("Leaving VcStatusCodec.readBitstringEntry(). " + why);
      return new Error('MALFORMED_VALUE_ERROR: ' + why);
    };
    if (e.type !== 'BitstringStatusListEntry') {
      throw fail('the entry type is not BitstringStatusListEntry.');
    }
    if (BITSTRING_PURPOSES.indexOf(e.statusPurpose) < 0) {
      throw fail('statusPurpose "' + e.statusPurpose + '" is not one of ' +
                 BITSTRING_PURPOSES.join(', ') + '.');
    }
    if (typeof e.statusListIndex !== 'string' ||
        !/^(0|[1-9][0-9]*)$/.test(e.statusListIndex) ||
        !Number.isSafeInteger(Number(e.statusListIndex))) {
      throw fail('statusListIndex is a base-10 integer in a string.');
    }
    if (typeof e.statusListCredential !== 'string' ||
        !/^[A-Za-z][A-Za-z0-9+.-]*:\S+$/.test(e.statusListCredential)) {
      throw fail('statusListCredential is a URL.');
    }
    const size = e.statusSize === undefined ? 1 : e.statusSize;
    if (!Number.isInteger(size) || size < 1) {
      throw fail('statusSize is an integer greater than zero.');
    }
    if (e.statusMessage !== undefined &&
        (!Array.isArray(e.statusMessage) ||
         e.statusMessage.length !== Math.pow(2, size))) {
      throw fail('statusMessage has 2^statusSize elements.');
    }
    if (size > 1 && e.statusMessage === undefined) {
      throw fail('statusMessage is required when statusSize is above one.');
    }
    log.debug("Leaving VcStatusCodec.readBitstringEntry().");
    return { statusPurpose: e.statusPurpose,
             index: Number(e.statusListIndex),
             credential: e.statusListCredential, statusSize: size,
             statusMessage: e.statusMessage || null };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — `vc_issued.ts`'s
// arrangement: the exports are FACADES forwarding to the instance the root
// installs, and a process without the root builds a default at load.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcStatusCodec>(
  'oid4vc/vc_status_codec',
  () => new VcStatusCodec(VcStatusCodec.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading any module on the pattern does.
slot.buildNowUnlessDeferred();

export = {
  VcStatusCodec: VcStatusCodec,
  installInstance: (instance: VcStatusCodec): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  Tagged: Tagged,
  TSL_STATUS: TSL_STATUS,
  TSL_BITS: TSL_BITS,
  COSE_ALGS: COSE_ALGS,
  CWT_TYPE: CWT_TYPE,
  JWT_TYPE: JWT_TYPE,
  BITSTRING_MIN_ENTRIES: BITSTRING_MIN_ENTRIES,
  BITSTRING_PURPOSES: BITSTRING_PURPOSES,
  packTsl: slot.forward('packTsl'),
  unpackTslValue: slot.forward('unpackTslValue'),
  compress: slot.forward('compress'),
  decompress: slot.forward('decompress'),
  tslJson: slot.forward('tslJson'),
  tslFromJson: slot.forward('tslFromJson'),
  tslCborMap: slot.forward('tslCborMap'),
  tslCbor: slot.forward('tslCbor'),
  tslFromCborMap: slot.forward('tslFromCborMap'),
  cborEncode: slot.forward('cborEncode'),
  cborDecode: slot.forward('cborDecode'),
  coseSign1Sign: slot.forward('coseSign1Sign'),
  coseSign1SignAsync: slot.forward('coseSign1SignAsync'),
  coseSign1Verify: slot.forward('coseSign1Verify'),
  coseSign1VerifyAsync: slot.forward('coseSign1VerifyAsync'),
  statusListCwt: slot.forward('statusListCwt'),
  statusListCwtAsync: slot.forward('statusListCwtAsync'),
  readStatusListCwt: slot.forward('readStatusListCwt'),
  readStatusListCwtAsync: slot.forward('readStatusListCwtAsync'),
  statusListJwtPayload: slot.forward('statusListJwtPayload'),
  readStatusListJwtPayload: slot.forward('readStatusListJwtPayload'),
  referenceOf: slot.forward('referenceOf'),
  referenceOfCose: slot.forward('referenceOfCose'),
  coseStatus: slot.forward('coseStatus'),
  packBitstring: slot.forward('packBitstring'),
  bitstringValue: slot.forward('bitstringValue'),
  encodedList: slot.forward('encodedList'),
  decodeEncodedList: slot.forward('decodeEncodedList'),
  bitstringEntry: slot.forward('bitstringEntry'),
  bitstringStatusListSubject: slot.forward('bitstringStatusListSubject'),
  readBitstringEntry: slot.forward('readBitstringEntry')
};
