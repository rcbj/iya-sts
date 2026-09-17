'use strict';

// ===========================================================================
// tests/vc_status_codec.js — THE STATUS LIST ENCODINGS, HELD TO THEIR
// SPECIFICATIONS' OWN VECTORS (#38 follow-ups, 2026-09-17).
//
// `oid4vc/vc_status_codec.ts` is the part of two status mechanisms that is
// fixed to the bit: IETF draft-ietf-oauth-status-list-21 (Token Status List)
// and W3C Bitstring Status List v1.0. A mistake there does not fail loudly —
// a list packed in the wrong bit order decodes, and names the wrong token —
// so each claim below is checked against a value the SPECIFICATION printed,
// never only against a round trip through this file:
//
//   1. the draft's section 4.1 examples (bits 1 and 2), its section 4.2 JSON
//      and section 4.3 CBOR example, and Appendix C.1-C.3 in both
//      encodings, decoded here and read at every index the appendix lists;
//   2. CBOR round-trips at every head boundary, refuses trailing bytes, a
//      truncated item, a repeated map key and a runaway nesting;
//   3. a Status List Token in CWT form (section 5.2) signs and verifies with
//      ES256, EdDSA, RS256, PS256, ES256K and — post-quantum — ML-DSA-44
//      (also through the worker-pool path); a tampered one, one of the wrong
//      type, an expired one and one outside the caller's algorithm list are
//      refused; the draft's own section 5.2 example parses to the structure
//      it annotates; the JWT form's claims check typ, sub, iat and exp;
//   4. a referenced token's status_list reference is read, absent is null,
//      malformed throws (section 8.3 step 1);
//   5. Bitstring Status List: index 0 is the left-most bit, the W3C
//      example's encodedList expands to 131,072 zero bits, a list below the
//      minimum is refused, `u` is the only multibase accepted, and a GZIP
//      bomb is refused; an entry is validated per section 2.1.
//
// In process: the module is a library that registers nothing.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const zlib = require('zlib');
const codec = require('../oid4vc/vc_status_codec');
const pqJose = require('../common/pq_jose');

const log = require('bunyan').createLogger({
  name: 'vc_status_codec',
  level: process.env.LOG_LEVEL || 'info' });

const APPENDIX_C_LST = [
  'eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAA' +
    'AAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'XG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAAA7KpLAAAAAAAAAAAA' +
    'AAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb',
  'eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGVIAAAAAABAbiEBAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9SwIAAAAAAAAA' +
    'AAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw',
  'eNrt0EENgDAQADAIHwImkIIEJEwCUpCEBBQRHOy35Li1EjoOQGabAgAAAAAAAAAA' +
    'AAAAAAAAACC1SQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADrsCAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADoxaEA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIIoCgAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACArpwKAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAGhqVkAzlwIAAAAAiGVRAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAABx3AoAgLpVAQAAAAAAAAAAAAAAwM89rwMAAAAAAAAA' +
    'AAjsA9xMBMA'
];
const APPENDIX_C_CBOR = [
  'a2646269747301636c737458bd78daeddc010dc0200c0041a88249400ad2903e' +
    '0f4bba00bd93f002beb7a2a2010000a91e090000000000000000000000000000' +
    '0080729604000000000000000000000000000000000000000000000000000000' +
    '000000000000000000000000005c6f4800000000000000fc2c24000000000000' +
    '0000000000be1b12000000000000000000ecaa4b000000000000000000000000' +
    '000000009b0b0900000000000000000038de9400000000000000002a30cc0100' +
    '00000080642f0bd8011b',
  'a2646269747302636c737459013d78daeddb310d00211000412ea1a04004fe55' +
    '20ed357c28c81d3312b6df68bc65480000000000406e21010000000000000000' +
    '000000000000000000000000000000000000000000000040795b020000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '000000000000000000000080f4ba0400000000000000000000000000406d764a' +
    '000000000000000000000000000000000000000000e092210100000000000000' +
    '0000000000000000000000fc1312000000000000000000000000000000000000' +
    '00000000000000000000000000c0912e01000000000000000000000000000000' +
    '000000c07d4b02000000000000000000000000000000a8614a00000000000000' +
    '00000000406a1fcd60010c',
  'a2646269747304636c737459024878daedd0410d8030100030081f0226908204' +
    '244c025290840414111cecb7e4b8b5123a0e40669b0200000000000000000000' +
    '000000000020b549010000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '000000000000000000000000000000000000000000400ebb0200000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000e8c5a1000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000082280a00000000000000000000000000000000000000' +
    '00000000000000000000000000000000000000000000000080ae9c0a00000000' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '00686a5640339702000000008865510000000000000000000000000000000000' +
    '00000000000000000000000000000071dc0a0080ba5501000000000000000000' +
    '0000c0cf3daf03000000000000000008ec03dc4c04c0'
];

// The indexes Appendix C.1-C.3 list, with their values.
const APPENDIX_C_STATUS = [
  { bits: 1, values: { 0: 1, 1993: 1, 25460: 1, 159495: 1, 495669: 1,
                       554353: 1, 645645: 1, 723232: 1, 854545: 1,
                       934534: 1, 1000345: 1 } },
  { bits: 2, values: { 0: 1, 1993: 2, 25460: 1, 159495: 3, 495669: 1,
                       554353: 1, 645645: 2, 723232: 1, 854545: 1,
                       934534: 2, 1000345: 3 } },
  { bits: 4, values: { 0: 1, 1993: 2, 35460: 3, 459495: 4, 595669: 5,
                       754353: 6, 845645: 7, 923232: 8, 924445: 9,
                       934534: 10, 1004534: 11, 1000345: 12, 1030203: 13,
                       1030204: 14, 1030205: 15 } }
];

// Section 4.3's example, and section 5.2's example CWT.
const SECTION_4_3 = 'a2646269747301636c73744a78dadbb918000217015d';
const SECTION_5_2 =
  'd2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b63' +
  '7774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f73' +
  '74617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2' +
  '646269747301636c73744a78dadbb918000217015d584093fa4d01032b18c35e2fe1' +
  '101b77fd6cc9440022caa4694450c4e4e9feab4e99d1fa6d9772ce2bf3a12e0323de' +
  'd7c982c5e101a5e67f0cbc1e2b6f57ce99c279';

function throws(fn, pattern) {
  log.debug("Entering throws().");
  try {
    fn();
  } catch (e) {
    log.debug("Caught in throws(): " + ((e && e.message) || e));
    log.debug("Leaving throws(). It threw.");
    return !pattern || pattern.test(String(e && e.message));
  }
  log.debug("Leaving throws(). It did not throw.");
  return false;
}

async function rejects(promise, pattern) {
  log.debug("Entering rejects().");
  try {
    await promise;
  } catch (e) {
    log.debug("Caught in rejects(): " + ((e && e.message) || e));
    log.debug("Leaving rejects(). It rejected.");
    return !pattern || pattern.test(String(e && e.message));
  }
  log.debug("Leaving rejects(). It resolved.");
  return false;
}

function hex(buf) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Buffer.from(buf).toString('hex');
}

// ---------------------------------------------------------------------------
// 1. THE DRAFT'S BYTE ARRAYS AND VECTORS
// ---------------------------------------------------------------------------
function claimOne(t) {
  log.debug("Entering claimOne().");
  const one = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
  const packed1 = codec.packTsl(one, 1, 16);
  t.check(hex(packed1) === 'b9a3',
          '1a. section 4.1, bits 1: sixteen statuses pack to b9 a3',
          hex(packed1));
  const two = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
  const packed2 = codec.packTsl(two, 2, 12);
  t.check(hex(packed2) === 'c944f9',
          '1b. section 4.1, bits 2: twelve statuses pack to c9 44 f9',
          hex(packed2));
  t.check(two.every(function (v, i) {
    return codec.unpackTslValue(packed2, 2, i) === v;
  }) && one.every(function (v, i) {
    return codec.unpackTslValue(packed1, 1, i) === v;
  }), '1c. and every status reads back at its own index');
  t.check(hex(codec.decompress(Buffer.from('78dadbb918000217015d', 'hex')))
          === 'b9a3' &&
          hex(codec.decompress(Buffer.from('78da3be9f2130003df0207', 'hex')))
          === 'c944f9',
          '1d. the draft\'s two compressed arrays inflate to those bytes');
  const json1 = codec.tslFromJson({ bits: 1, lst: 'eNrbuRgAAhcBXQ' });
  const json2 = codec.tslFromJson({ bits: 2, lst: 'eNo76fITAAPfAgc' });
  t.check(json1.bits === 1 && hex(json1.bytes) === 'b9a3' &&
          json2.bits === 2 && hex(json2.bytes) === 'c944f9',
          '1e. section 4.2\'s JSON examples decode');
  const round = codec.tslFromJson(codec.tslJson({ bits: 2, bytes: packed2 }));
  t.check(round.bits === 2 && hex(round.bytes) === 'c944f9',
          '1f. tslJson() round-trips');
  const ex43 = codec.cborDecode(Buffer.from(SECTION_4_3, 'hex'));
  const read43 = codec.tslFromCborMap(ex43);
  t.check(read43.bits === 1 && hex(read43.bytes) === 'b9a3' &&
          hex(ex43.get('lst')) === '78dadbb918000217015d',
          '1g. section 4.3\'s CBOR example decodes to bits 1 and b9 a3');
  const ours43 = codec.tslCbor({ bits: 1, bytes: packed1 });
  const oursRead = codec.tslFromCborMap(codec.cborDecode(ours43));
  t.check(oursRead.bits === 1 && hex(oursRead.bytes) === 'b9a3' &&
          hex(ours43).indexOf('a2646269747301636c7374') === 0,
          '1h. tslCbor() writes bits before lst, as the example does, and ' +
          'round-trips', hex(ours43));
  t.check(throws(function () {
    codec.unpackTslValue(packed1, 1, 16);
  }, /outside/), '1i. an index past the end throws (section 8.3 step 6)');
  t.check(throws(function () {
    codec.packTsl([4], 2, 4);
  }) && throws(function () {
    codec.packTsl([], 3, 4);
  }, /1, 2, 4 or 8/) && throws(function () {
    codec.tslFromJson({ bits: 5, lst: 'eNrbuRgAAhcBXQ' });
  }), '1j. a value too wide and a width outside 1/2/4/8 are refused');

  APPENDIX_C_STATUS.forEach(function (vector, i) {
    const fromJson = codec.tslFromJson({ bits: vector.bits,
                                         lst: APPENDIX_C_LST[i] });
    const fromCbor = codec.tslFromCborMap(
      codec.cborDecode(Buffer.from(APPENDIX_C_CBOR[i], 'hex')));
    const size = Math.pow(2, 20);
    const expectedBytes = size * vector.bits / 8;
    const listed = Object.keys(vector.values);
    const agrees = function (bytes) {
      return listed.every(function (idx) {
        return codec.unpackTslValue(bytes, vector.bits, Number(idx)) ===
               vector.values[idx];
      });
    };
    // Every index not listed is VALID: the whole array sums to the listed
    // values' bit counts only if nothing else is set.
    let others = 0;
    for (let b = 0; b < fromJson.bytes.length; b++) {
      if (fromJson.bytes[b]) {
        others += 1;
      }
    }
    const rebuilt = codec.packTsl(new Map(listed.map(function (k) {
      return [Number(k), vector.values[k]];
    })), vector.bits, size);
    t.check(fromJson.bytes.length === expectedBytes &&
            fromCbor.bits === vector.bits &&
            fromJson.bytes.equals(fromCbor.bytes) &&
            agrees(fromJson.bytes) && others <= listed.length &&
            rebuilt.equals(fromJson.bytes),
            '1k. Appendix C.' + (i + 1) + ' (' + vector.bits + '-bit): the ' +
            'JSON and CBOR encodings decode to the same 2^20-entry array, ' +
            'every listed index reads its value, and packTsl() rebuilds it ' +
            'byte for byte', fromJson.bytes.length + ' bytes');
  });
  log.debug("Leaving claimOne().");
}

// ---------------------------------------------------------------------------
// 2. CBOR
// ---------------------------------------------------------------------------
function claimTwo(t) {
  log.debug("Entering claimTwo().");
  const ints = [0, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296,
                Number.MAX_SAFE_INTEGER, -1, -24, -25, -256, -257,
                -4294967296, -4294967297];
  const heads = { 0: '00', 23: '17', 24: '1818', 255: '18ff', 256: '190100',
                  65535: '19ffff', 65536: '1a00010000',
                  4294967296: '1b0000000100000000', '-1': '20',
                  '-24': '37', '-25': '3818', '-4294967296': '3affffffff' };
  const intsOk = ints.every(function (n) {
    return codec.cborDecode(codec.cborEncode(n)) === n;
  }) && Object.keys(heads).every(function (k) {
    return hex(codec.cborEncode(Number(k))) === heads[k];
  });
  t.check(intsOk, '2a. integers round-trip at every head boundary, in the ' +
          'shortest head (RFC 8949 section 4.2.1)');
  const nested = new Map([[1, 'text é'], ['k', [Buffer.from('0102', 'hex'),
    new Map([[-7, true]]), null, false, 1.5]],
    [65535, new codec.Tagged(18, [])]]);
  const back = codec.cborDecode(codec.cborEncode(nested));
  t.check(back.get(1) === 'text é' &&
          hex(back.get('k')[0]) === '0102' &&
          back.get('k')[1].get(-7) === true && back.get('k')[2] === null &&
          back.get('k')[3] === false && back.get('k')[4] === 1.5 &&
          back.get(65535) instanceof codec.Tagged &&
          back.get(65535).tag === 18 &&
          JSON.stringify(Array.from(back.keys())) ===
            JSON.stringify([1, 'k', 65535]),
          '2b. strings, byte strings, arrays, nested maps (order kept), ' +
          'tags, simple values and floats round-trip');
  t.check(codec.cborDecode(Buffer.from('f93400', 'hex')) === 0.25 &&
          codec.cborDecode(Buffer.from('f93e00', 'hex')) === 1.5,
          '2c. half-precision floats decode (RFC 8949 Appendix D)');
  t.check(throws(function () {
    codec.cborDecode(Buffer.from('0000', 'hex'));
  }, /follow/), '2d. trailing bytes are refused');
  t.check(throws(function () {
    codec.cborDecode(Buffer.from('45010203', 'hex'));
  }, /truncated/) && throws(function () {
    codec.cborDecode(Buffer.from('9affffffff', 'hex'));
  }, /truncated/), '2e. a truncated item, and a count past the bytes left, ' +
          'are refused before anything is allocated');
  t.check(throws(function () {
    codec.cborDecode(Buffer.from('a201020103', 'hex'));
  }, /repeats/), '2f. a repeated map key is refused');
  t.check(throws(function () {
    codec.cborDecode(Buffer.alloc(200, 0x81));
  }, /nested/) && throws(function () {
    codec.cborDecode(Buffer.from('5f', 'hex'));
  }, /indefinite/), '2g. runaway nesting and indefinite lengths are refused');
  t.check(throws(function () {
    codec.cborDecode(Buffer.from('1b0020000000000000', 'hex'));
  }, /larger/), '2h. an integer above 2^53 - 1 is refused rather than ' +
          'rounded');
  log.debug("Leaving claimTwo().");
}

// ---------------------------------------------------------------------------
// 3. THE STATUS LIST TOKEN
// ---------------------------------------------------------------------------
function keysFor(alg) {
  log.debug("Entering keysFor(). " + alg);
  let pair;
  if (alg === 'ML-DSA-44') {
    const generated = pqJose.generate(alg);
    const pub = pqJose.akpPublicJwk(alg, generated.pub);
    log.debug("Leaving keysFor(). AKP.");
    return { privateKey: Object.assign({ priv:
             Buffer.from(generated.priv).toString('base64url') }, pub),
             publicKey: pub };
  }
  if (alg === 'EdDSA') {
    pair = nodeCrypto.generateKeyPairSync('ed25519');
  } else if (alg === 'ES256') {
    pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  } else if (alg === 'ES256K') {
    pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  } else {
    pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  }
  log.debug("Leaving keysFor().");
  // The public half as a JWK, the way a verifier is handed one.
  return { privateKey: pair.privateKey,
           publicKey: pair.publicKey.export({ format: 'jwk' }) };
}

async function claimThree(t) {
  log.debug("Entering claimThree().");
  const now = Math.floor(Date.now() / 1000);
  const bytes = codec.packTsl(new Map([[0, 1], [5, 2]]), 2, 4096);
  const uri = 'https://sts.example/oid4vci/status/tsl/1';
  for (const alg of ['ES256', 'EdDSA', 'RS256', 'PS256', 'ES256K',
                     'ML-DSA-44']) {
    const keys = keysFor(alg);
    const cwt = codec.statusListCwt({ sub: uri, iat: now, exp: now + 600,
      ttl: 300, bits: 2, bytes: bytes, key: keys.privateKey, alg: alg,
      kid: 'k1' });
    const read = codec.readStatusListCwt(cwt, keys.publicKey,
                                         { algorithms: [alg] });
    const decoded = codec.cborDecode(cwt);
    const prot = codec.cborDecode(decoded.value[0]);
    t.check(read.sub === uri && read.iat === now && read.exp === now + 600 &&
            read.ttl === 300 && read.bits === 2 &&
            codec.unpackTslValue(read.bytes, 2, 5) === 2 &&
            decoded instanceof codec.Tagged && decoded.tag === 18 &&
            prot.get(1) === codec.COSE_ALGS[alg] &&
            prot.get(16) === 'application/statuslist+cwt' &&
            decoded.value[1].get(4).toString() === 'k1',
            '3a. a ' + alg + ' Status List Token in CWT form signs and ' +
            'verifies, tag 18 and not CWT-tagged, with type and kid in place');
    const tampered = Buffer.from(cwt);
    tampered[tampered.length - 70] ^= 1;
    t.check(throws(function () {
      codec.readStatusListCwt(tampered, keys.publicKey,
                              { algorithms: [alg] });
    }), '3b. a ' + alg + ' token with one byte changed is refused');
    const pooled = await codec.statusListCwtAsync({ sub: uri, iat: now,
      bits: 2, bytes: bytes, key: keys.privateKey, alg: alg });
    const pooledRead = await codec.readStatusListCwtAsync(pooled,
      keys.publicKey, { algorithms: [alg] });
    t.check(pooledRead.sub === uri && pooledRead.exp === undefined,
            '3c. the ' + alg + ' pooled path signs and verifies the same');
  }
  const keys = keysFor('ES256');
  const good = { sub: uri, iat: now, bits: 2, bytes: bytes,
                 key: keys.privateKey, alg: 'ES256' };
  t.check(throws(function () {
    codec.readStatusListCwt(codec.statusListCwt(good), keys.publicKey,
                            { algorithms: ['RS256'] });
  }, /only RS256/), '3d. an algorithm outside the caller\'s list is ' +
          'refused before the signature is looked at');
  t.check(throws(function () {
    codec.readStatusListCwt(codec.statusListCwt(Object.assign({}, good,
      { exp: now - 5 })), keys.publicKey, { algorithms: ['ES256'] });
  }, /expired/), '3e. an expired token is refused (section 8.3 step 4c)');
  const wrongType = codec.coseSign1Sign({
    protectedHeader: new Map([[16, 'application/cwt']]),
    unprotectedHeader: new Map(),
    payload: codec.cborEncode(new Map([[2, uri], [6, now],
      [65533, codec.tslCborMap({ bits: 2, bytes: bytes })]])),
    key: keys.privateKey, alg: 'ES256' });
  t.check(throws(function () {
    codec.readStatusListCwt(wrongType, keys.publicKey,
                            { algorithms: ['ES256'] });
  }, /type/), '3f. the wrong type header is refused');
  const noSub = codec.coseSign1Sign({
    protectedHeader: new Map([[16, codec.CWT_TYPE]]),
    payload: codec.cborEncode(new Map([[6, now],
      [65533, codec.tslCborMap({ bits: 2, bytes: bytes })]])),
    key: keys.privateKey, alg: 'ES256' });
  t.check(throws(function () {
    codec.readStatusListCwt(noSub, keys.publicKey, { algorithms: ['ES256'] });
  }, /subject/), '3g. a token without a subject is refused');
  const other = keysFor('ES256');
  t.check(throws(function () {
    codec.readStatusListCwt(codec.statusListCwt(good), other.publicKey,
                            { algorithms: ['ES256'] });
  }, /does not verify/), '3h. another key does not verify it');

  const example = codec.cborDecode(Buffer.from(SECTION_5_2, 'hex'));
  const exProt = codec.cborDecode(example.value[0]);
  const exClaims = codec.cborDecode(example.value[2]);
  const exList = codec.tslFromCborMap(exClaims.get(65533));
  t.check(example instanceof codec.Tagged && example.tag === 18 &&
          exProt.get(1) === -7 &&
          exProt.get(16) === 'application/statuslist+cwt' &&
          example.value[1].get(4).toString() === '12' &&
          exClaims.get(2) === 'https://example.com/statuslists/1' &&
          exClaims.get(6) === 1686920170 && exClaims.get(4) === 2291720170 &&
          exClaims.get(65534) === 43200 && exList.bits === 1 &&
          hex(exList.bytes) === 'b9a3' && example.value[3].length === 64,
          '3i. the draft\'s section 5.2 example parses to the structure it ' +
          'annotates (its signature needs a key the draft does not give)');

  const payload = codec.statusListJwtPayload({ sub: uri, iat: now,
    exp: now + 60, ttl: 30, bits: 2, bytes: bytes,
    aggregationUri: 'https://sts.example/agg' });
  const readJwt = codec.readStatusListJwtPayload(
    { alg: 'ES256', typ: 'statuslist+jwt' }, payload);
  t.check(payload.status_list.bits === 2 &&
          payload.status_list.aggregation_uri === 'https://sts.example/agg' &&
          readJwt.sub === uri && readJwt.ttl === 30 &&
          readJwt.bytes.equals(bytes),
          '3j. the JWT form\'s claims (section 5.1) round-trip');
  t.check(throws(function () {
    codec.readStatusListJwtPayload({ typ: 'JWT' }, payload);
  }, /typ/) && throws(function () {
    codec.readStatusListJwtPayload({ typ: 'statuslist+jwt' },
      Object.assign({}, payload, { exp: now - 1 }));
  }, /expired/) && throws(function () {
    codec.readStatusListJwtPayload({ typ: 'statuslist+jwt' },
      Object.assign({}, payload, { sub: undefined }));
  }) && throws(function () {
    codec.readStatusListJwtPayload({ typ: 'statuslist+jwt' },
      Object.assign({}, payload, { ttl: -1 }));
  }), '3k. the JWT form refuses the wrong typ, an expired token, a ' +
          'missing sub and a non-positive ttl');
  t.check(await rejects(codec.readStatusListCwtAsync(Buffer.from('00', 'hex'),
    keys.publicKey, { algorithms: ['ES256'] }), /COSE_Sign1/),
          '3l. something that is not COSE_Sign1 is refused as such');
  log.debug("Leaving claimThree().");
}

// ---------------------------------------------------------------------------
// 4. THE REFERENCE
// ---------------------------------------------------------------------------
function claimFour(t) {
  log.debug("Entering claimFour().");
  const ref = codec.referenceOf({ status: { status_list: {
    idx: 7, uri: 'https://example.com/statuslists/1' } } });
  t.check(ref && ref.idx === 7 &&
          ref.uri === 'https://example.com/statuslists/1',
          '4a. a JOSE token\'s status_list reference is read');
  t.check(codec.referenceOf({}) === null &&
          codec.referenceOf({ status: { other: {} } }) === null,
          '4b. no status claim, or another mechanism only, is null');
  t.check(throws(function () {
    codec.referenceOf({ status: { status_list: { idx: -1, uri: 'x:y' } } });
  }) && throws(function () {
    codec.referenceOf({ status: { status_list: { idx: 1.5, uri: 'x:y' } } });
  }) && throws(function () {
    codec.referenceOf({ status: { status_list: { idx: 1 } } });
  }) && throws(function () {
    codec.referenceOf({ status: 'revoked' });
  }), '4c. a malformed reference throws (section 8.3 step 1)');
  const cose = codec.coseStatus({ idx: 3, uri: 'https://e.example/s/1' });
  const back = codec.referenceOfCose(
    codec.cborDecode(codec.cborEncode(cose)));
  t.check(back.idx === 3 && back.uri === 'https://e.example/s/1' &&
          codec.referenceOfCose(undefined) === null &&
          throws(function () {
            codec.referenceOfCose(new Map([['status_list', 5]]));
          }),
          '4d. a COSE Status structure (section 6.3) round-trips');
  log.debug("Leaving claimFour().");
}

// ---------------------------------------------------------------------------
// 5. BITSTRING STATUS LIST
// ---------------------------------------------------------------------------
function claimFive(t) {
  log.debug("Entering claimFive().");
  const size = codec.BITSTRING_MIN_ENTRIES;
  const packed = codec.packBitstring([0, 9, size - 1], size);
  t.check(packed.length === 16384 && packed[0] === 0x80 &&
          packed[1] === 0x40 && packed[16383] === 0x01,
          '5a. index 0 is the left-most bit of byte 0 (section 2.2), and ' +
          'the last index the right-most bit of the last byte',
          hex(packed.subarray(0, 2)));
  t.check(codec.bitstringValue(packed, 0) === 1 &&
          codec.bitstringValue(packed, 1) === 0 &&
          codec.bitstringValue(packed, 9) === 1 &&
          codec.bitstringValue(packed, size - 1) === 1 &&
          throws(function () {
            codec.bitstringValue(packed, size);
          }, /RANGE_ERROR/),
          '5b. values read back, and a position past the end is a ' +
          'RANGE_ERROR');
  const encoded = codec.encodedList(packed);
  t.check(/^u[A-Za-z0-9_-]+$/.test(encoded) &&
          codec.decodeEncodedList(encoded).equals(packed),
          '5c. a 131,072-entry list round-trips through encodedList');
  const w3c = codec.decodeEncodedList(
    'uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA');
  t.check(w3c.length === 16384 && w3c.every(function (b) {
    return b === 0;
  }), '5d. the specification\'s example encodedList expands to 131,072 ' +
          'zero bits');
  t.check(throws(function () {
    codec.packBitstring([], size - 1);
  }, /at least/), '5e. a list below 131,072 entries is refused');
  const two = codec.packBitstring(new Map([[1, 2], [2, 3]]), size, 2);
  t.check(two[0] === 0x2c && codec.bitstringValue(two, 1, 2) === 2 &&
          codec.bitstringValue(two, 2, 2) === 3,
          '5f. a statusSize of 2 packs most significant bit first',
          hex(two.subarray(0, 1)));
  t.check(throws(function () {
    codec.decodeEncodedList('z' + encoded.slice(1));
  }, /multibase/) && throws(function () {
    codec.decodeEncodedList(encoded.slice(1));
  }, /multibase/), '5g. only the multibase "u" prefix is accepted');
  const bomb = 'u' + zlib.gzipSync(Buffer.alloc(40 * 1024 * 1024))
    .toString('base64url');
  t.check(throws(function () {
    codec.decodeEncodedList(bomb);
  }, /expand/) && throws(function () {
    codec.decompress(zlib.deflateSync(Buffer.alloc(40 * 1024 * 1024)));
  }, /inflate/) && throws(function () {
    codec.decodeEncodedList(encoded, 1000);
  }), '5h. a GZIP or ZLIB bomb is refused, and a caller\'s bound is ' +
          'honoured');
  const entry = codec.bitstringEntry({ id: 'https://sts.example/s#94567',
    statusPurpose: 'revocation', statusListIndex: 94567,
    statusListCredential: 'https://sts.example/status/revocation/1' });
  t.check(entry.type === 'BitstringStatusListEntry' &&
          entry.statusListIndex === '94567' &&
          codec.readBitstringEntry(entry).index === 94567,
          '5i. an entry is written with its index as a base-10 string, and ' +
          'reads back');
  const bad = function (changes) {
    return throws(function () {
      codec.readBitstringEntry(Object.assign({}, entry, changes));
    }, /MALFORMED_VALUE_ERROR/);
  };
  t.check(bad({ type: 'StatusList2021Entry' }) &&
          bad({ statusPurpose: 'expiry' }) &&
          bad({ statusListIndex: 94567 }) &&
          bad({ statusListIndex: '01' }) &&
          bad({ statusListCredential: 'not a url' }) &&
          bad({ statusSize: 2 }) &&
          bad({ statusSize: 1, statusMessage: [{}] }),
          '5j. a wrong type, purpose, index, credential URL, a statusSize ' +
          'without its messages and a message list of the wrong length are ' +
          'each a MALFORMED_VALUE_ERROR');
  const subject = codec.bitstringStatusListSubject({
    id: 'https://sts.example/status/revocation/1#list',
    statusPurpose: 'revocation', encodedList: encoded, ttl: 300000 });
  t.check(subject.type === 'BitstringStatusList' &&
          subject.encodedList === encoded && subject.ttl === 300000,
          '5k. the list credential\'s subject has the section 2.2 members');
  log.debug("Leaving claimFive().");
}

async function run(t) {
  log.debug("Entering run().");
  claimOne(t);
  claimTwo(t);
  await claimThree(t);
  claimFour(t);
  claimFive(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_status_codec',
  describe: 'the Token Status List and Bitstring Status List encodings, ' +
            'held to the specifications\' own vectors: bit order, ' +
            'compression, CBOR, COSE_Sign1 (post-quantum included) and the ' +
            'references a credential carries',
  run: run
};
