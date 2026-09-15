'use strict';
//
// File: gnap_httpsig.js
//
// ===========================================================================
// GNAP'S `httpsig` PROOF, HELD TO THE PUBLISHED VECTORS: RFC 9421 (HTTP MESSAGE
// SIGNATURES), RFC 9530 (CONTENT-DIGEST) AND RFC 8941 (STRUCTURED FIELDS).
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// `gnap/gnap_sf.js` and `gnap/gnap_httpsig.js` are route-free libraries, and
// every claim worth making about them is a comparison with an answer somebody
// ELSE published:
//
//   * **A SIGNATURE BASE IS A STRING NEITHER PARTY SENDS.** Over HTTP the only
//     observable is that a signature verified — and a signer and verifier
//     built from ONE implementation agree with each other whatever that
//     implementation does to a folded header or a default port. The RFC's
//     Appendix B prints the bases, so they are compared here byte for byte.
//     That is `assertion_grant.js`'s PBES2 lesson: a derivation that agrees
//     only with itself has been shown to agree with nothing.
//   * **THE DETERMINISTIC ALGORITHMS REPRODUCE EXACT BYTES.** hmac-sha256,
//     ed25519 and rsa-v1_5-sha256 are deterministic, so the published
//     signature is not only verified — it is PRODUCED, which is the check that
//     catches a signer hashing the wrong thing in a way its own verifier
//     shares. RSA-PSS and ECDSA are randomized and are verified only.
//   * **THE REFUSALS NEED MESSAGES NO CLIENT WOULD SEND ON PURPOSE**: a label
//     in one field and not the other, a component listed twice, a Signature
//     member that is a Token. Choosing the message is the whole test.
//
// The GNAP policy over these libraries — which components a grant request
// must cover, which key a `keyid` names — is `gnap/gnap_proof.js`'s and is not
// asserted here.
// ---------------------------------------------------------------------------
// THREE THINGS THE RFCs THEMSELVES GET WRONG, recorded where they are asserted
// so that a later reader does not "fix" the implementation to match the text:
//
//   * RFC 9530 section 2's two-member example pairs a sha-512 digest of
//     `{"hello": "world"}` + LF with a sha-256 digest of something else
//     (it is not that body, not without the LF, and not the Brotli bytes of
//     B.4). Under "every accepted algorithm present must match" it is REFUSED.
//   * RFC 9530 Appendix B.5 and B.6 print `...FabDg==:`, which is over-padded
//     base64 (43 characters and two `=`). RFC 8941 section 4.2.7 says a
//     decoding failure fails the parse, so it is refused as malformed.
//   * RFC 9635 section 7.3.1.1's rotation example signs the new key's base
//     over an old-key Signature of `YdDJ…` while the message carries `vN4I…`.
//     Both are valid ECDSA signatures of the same base — randomized — so the
//     example's new-key signature cannot verify against the message shown.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const errorCodes = require('../common/error_codes');
const sf = require('../gnap/gnap_sf');
const httpsig = require('../gnap/gnap_httpsig');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'gnap_httpsig',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// RFC 9421 APPENDIX B.1: THE TEST KEYS, verbatim.
// ---------------------------------------------------------------------------
const RSA_PUBLIC_PEM = [
  '-----BEGIN RSA PUBLIC KEY-----',
  'MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw',
  'WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq',
  'MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg',
  'kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P',
  'uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ',
  'PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB',
  '-----END RSA PUBLIC KEY-----'].join('\n');

const RSA_PRIVATE_PEM = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP',
  'BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd',
  'JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75',
  'jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI',
  'lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ',
  'SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56',
  'vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE',
  'CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW',
  '+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA',
  'yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR',
  'Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J',
  'YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM',
  'cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw',
  'DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1',
  'mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT',
  'qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67',
  'B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv',
  '9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn',
  'f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo',
  '81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa',
  '/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG',
  'IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m',
  'qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P',
  'WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ',
  'EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=',
  '-----END RSA PRIVATE KEY-----'].join('\n');

const RSA_PSS_PUBLIC_PEM = [
  '-----BEGIN PUBLIC KEY-----',
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2',
  '+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+',
  'oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq',
  'gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W',
  'Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4',
  'aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI',
  '2wIDAQAB',
  '-----END PUBLIC KEY-----'].join('\n');

const RSA_PSS_PRIVATE_PEM = [
  '-----BEGIN PRIVATE KEY-----',
  'MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv',
  'P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5',
  '3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr',
  'FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA',
  'AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw',
  '9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy',
  'c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq',
  'pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X',
  'aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4',
  'XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ',
  'HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD',
  '2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N',
  'RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx',
  'DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6',
  'vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm',
  'rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi',
  '4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL',
  'FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/',
  'OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx',
  'NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR',
  'NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ',
  '3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE',
  't2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND',
  'dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF',
  'S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR',
  'rOjr9w349JooGXhOxbu8nOxX',
  '-----END PRIVATE KEY-----'].join('\n');

const ECC_P256_PUBLIC_PEM = [
  '-----BEGIN PUBLIC KEY-----',
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf',
  'w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==',
  '-----END PUBLIC KEY-----'].join('\n');

const ECC_P256_PRIVATE_PEM = [
  '-----BEGIN EC PRIVATE KEY-----',
  'MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49',
  'AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM',
  '4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==',
  '-----END EC PRIVATE KEY-----'].join('\n');

const ED25519_PUBLIC_PEM = [
  '-----BEGIN PUBLIC KEY-----',
  'MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=',
  '-----END PUBLIC KEY-----'].join('\n');

const ED25519_PRIVATE_PEM = [
  '-----BEGIN PRIVATE KEY-----',
  'MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF',
  '-----END PRIVATE KEY-----'].join('\n');

const SHARED_SECRET = Buffer.from('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==', 'base64');

const KEYS = {
  rsaPublic: nodeCrypto.createPublicKey({ key: RSA_PUBLIC_PEM, format: 'pem',
                                          type: 'pkcs1' }),
  rsaPrivate: nodeCrypto.createPrivateKey(RSA_PRIVATE_PEM),
  pssPublic: nodeCrypto.createPublicKey(RSA_PSS_PUBLIC_PEM),
  pssPrivate: nodeCrypto.createPrivateKey(RSA_PSS_PRIVATE_PEM),
  eccPublic: nodeCrypto.createPublicKey(ECC_P256_PUBLIC_PEM),
  eccPrivate: nodeCrypto.createPrivateKey(ECC_P256_PRIVATE_PEM),
  edPublic: nodeCrypto.createPublicKey(ED25519_PUBLIC_PEM),
  edPrivate: nodeCrypto.createPrivateKey(ED25519_PRIVATE_PEM)
};

// ---------------------------------------------------------------------------
// RFC 9421 APPENDIX B.2's test-request and test-response.
// ---------------------------------------------------------------------------
const REQUEST_DIGEST = 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:';
const RESPONSE_DIGEST = 'sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:';

function testRequest(extra) {
  log.debug("Entering testRequest().");
  log.debug("Leaving testRequest().");
  return {
    method: 'POST',
    targetUri: 'https://example.com/foo?param=Value&Pet=dog',
    headers: Object.assign({
      host: 'example.com',
      date: 'Tue, 20 Apr 2021 02:07:55 GMT',
      'content-type': 'application/json',
      'content-digest': REQUEST_DIGEST,
      'content-length': '18'
    }, extra || {})
  };
}

function testResponse(extra) {
  log.debug("Entering testResponse().");
  log.debug("Leaving testResponse().");
  return {
    status: 200,
    headers: Object.assign({
      date: 'Tue, 20 Apr 2021 02:07:56 GMT',
      'content-type': 'application/json',
      'content-digest': RESPONSE_DIGEST,
      'content-length': '23'
    }, extra || {})
  };
}

function withSignature(message, signatureInput, signature) {
  log.debug("Entering withSignature().");
  const headers = Object.assign({}, message.headers, {
    'signature-input': signatureInput,
    signature: signature
  });
  log.debug("Leaving withSignature().");
  return Object.assign({}, message, { headers: headers });
}

function keyed(key, algorithm) {
  log.debug("Entering keyed().");
  log.debug("Leaving keyed().");
  return function () {
    return { key: key, algorithm: algorithm };
  };
}

// A refusal is right only when it is a refusal, carries the code, and is MARKED
// with it — the mark is what the call-log funnel reads, and a refusal with the
// code in its body and none under the Symbol would be recorded as uncoded.
function refused(t, result, code, what) {
  log.debug("Entering refused().");
  const ok = !!result && result.ok === false && result.errorCode === code &&
             errorCodes.codeOf(result) === code &&
             typeof result.why === 'string' &&
             result.why.length > 0;
  log.debug("Leaving refused().");
  return t.check(ok, what + ' — refused ' + code,
                 'got ' +
                 JSON.stringify(result &&
                                { ok: result.ok, errorCode: result.errorCode,
                                                     why: result.why }));
}

function throwsParse(t, fn, what) {
  log.debug("Entering throwsParse().");
  let threw = null;
  try {
    fn();
  } catch (e) {
    threw = e;
  }
  log.debug("Leaving throwsParse().");
  return t.check(threw instanceof Error && /^RFC 8941: /.test(threw.message),
                 what + ' — fails', threw ? threw.message : 'it did not throw');
}

// ===========================================================================
// 1. RFC 8941.
// ===========================================================================
function structuredFields(t) {
  log.debug("Entering structuredFields().");
  t.log.info('=== RFC 8941: every type, both directions, and the inputs that ' +
             'must fail ===');

  // Section 3.1, 3.1.1, 3.1.2 examples: parse, then re-serialize strictly.
  const lists = [
    ['sugar, tea, rum', 'sugar, tea, rum'],
    ['("foo" "bar"), ("baz"), ("bat" "one"), ()', '("foo" "bar"), ("baz"), ' +
                                                  '("bat" "one"), ()'],
    ['("foo"; a=1;b=2);lvl=5, ("bar" "baz");lvl=1', '("foo";a=1;b=2);lvl=5, ' +
                                                    '("bar" "baz");lvl=1'],
    ['abc;a=1;b=2; cde_456, (ghi;jk=4 l);q="9";r=w', 'abc;a=1;b=2;cde_456, ' +
                                                     '(ghi;jk=4 l);q="9";r=w'],
    ['  a,b,\tc  ', 'a, b, c'],
    ['', '']
  ];
  lists.forEach(function (row) {
    let out = null;
    try {
      out = sf.serializeList(sf.parseList(row[0]));
    } catch (e) {
      out = 'threw: ' + e.message;
    }
    t.equal(out, row[1], 'List ' + JSON.stringify(row[0]) + ' round-trips ' +
        'strictly');
  });
  // The fourth row is worth reading twice: `; cde_456` is a PARAMETER of `abc`
  // (a space is allowed after ";"), not a second member.
  const abc = sf.parseList('abc;a=1;b=2; cde_456, (ghi;jk=4 l);q="9";r=w');
  t.equal(abc.length, 2, 'section 3.1.2: "; cde_456" is a parameter, so the ' +
                         'List has two members');
  t.equal(sf.paramValue(abc[0].params, 'cde_456'), true, 'a parameter with ' +
      'no value is Boolean true');
  t.equal(abc[1].type, 'innerList', 'the second member is an Inner List');
  t.equal(sf.param(abc[1].params, 'r').type, 'token', 'r=w is a Token, not a ' +
                                                      'String');
  t.equal(sf.param(abc[1].params, 'q').type, 'string', 'q="9" is a String, ' +
                                                       'not an Integer');

  const one = sf.parseItem('1; a; b=?0');
  t.check(one.type === 'integer' && one.value === 1 &&
          sf.paramValue(one.params, 'a') === true &&
          sf.paramValue(one.params, 'b') === false,
          'section 3.1.2: "1; a; b=?0" is an Integer with a true and a false ' +
          'parameter');
  t.equal(sf.serializeItem(one), '1;a;b=?0', 'Boolean true is serialized as ' +
                                             'the key alone');

  const dicts = [
    ['en="Applepie", da=:w4ZibGV0w6ZydGU=:', 'en="Applepie", ' +
                                             'da=:w4ZibGV0w6ZydGU=:'],
    ['a=?0, b, c; foo=bar', 'a=?0, b, c;foo=bar'],
    ['rating=1.5, feelings=(joy sadness)',
     'rating=1.5, feelings=(joy sadness)'],
    ['a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid', 'a=(1 2), b=3, c=4;aa=bb, ' +
                                               'd=(5 6);valid'],
    ['a=1,    b=2;x=1;y=2,   c=(a   b   c)', 'a=1, b=2;x=1;y=2, c=(a b c)'],
    ['a=1, b=2, a=3', 'a=3, b=2']
  ];
  dicts.forEach(function (row) {
    let out = null;
    try {
      out = sf.serializeDictionary(sf.parseDictionary(row[0]));
    } catch (e) {
      out = 'threw: ' + e.message;
    }
    t.equal(out, row[1], 'Dictionary ' + JSON.stringify(row[0]) + ' ' +
        'round-trips strictly');
  });
  const da = sf.member(sf.parseDictionary('en="Applepie", da=:w4ZibGV0w6ZydGU=:'), 'da');
  t.check(da.type === 'bytes' && Buffer.isBuffer(da.value) &&
          da.value.toString('utf8') === '\u00c6blet\u00e6rte',
          'a Byte Sequence parses to a Buffer of the decoded octets',
          da.value.toString('hex'));
  const dup = sf.parseDictionary('a=1, b=2, a=3');
  t.check(dup[0][0] === 'a' && dup[0][1].value === 3 && dup.length === 2,
          'section 4.2.2: a duplicate key overwrites the VALUE in the FIRST ' +
          'position',
          JSON.stringify(dup.map(function (p) { return [p[0], p[1].value]; })));
  let seen = null;
  sf.parseDictionary('a=1, a=2', { onDuplicate: function (key) {
    log.debug("Entering onDuplicate().");
    seen = key;
    log.debug("Leaving onDuplicate().");
  } });
  t.equal(seen, 'a', 'the onDuplicate hook is told about a repeated key');
  t.equal(sf.serializeItem(sf.parseItem('x;a=1;a=2')), 'x;a=2',
          'section 4.2.3.2: a duplicate parameter is last-wins');

  // Every bare type, explicitly.
  const types = [
    ['42', 'integer', 42], ['-999999999999999', 'integer', -999999999999999],
    ['4.5', 'decimal', 4.5], ['-0.001', 'decimal', -0.001],
    ['"hello world"', 'string', 'hello world'],
    ['"a\\"b\\\\c"', 'string', 'a"b\\c'],
    ['foo123/456', 'token', 'foo123/456'], ['*foo:bar', 'token', '*foo:bar'],
    ['?1', 'boolean', true], ['?0', 'boolean', false]
  ];
  types.forEach(function (row) {
    const item = sf.parseItem(row[0]);
    t.check(item.type === row[1] && item.value === row[2],
            row[1] + ' ' + row[0] + ' parses', JSON.stringify(item));
    t.equal(sf.serializeItem(item), row[0], row[1] + ' ' + row[0] + ' ' +
        'serializes back');
  });
  const bytes = sf.parseItem(':cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:');
  t.equal(bytes.value.toString('utf8'), 'pretend this is binary content.',
          'section 3.3.5\'s Byte Sequence example decodes');
  t.equal(sf.parseItem(':YQ:').value.toString('utf8'), 'a',
          'section 4.2.7: missing padding is decoded, as parsers SHOULD NOT ' +
          'fail on it');
  t.equal(sf.serializeItem(sf.parseItem(':YQ:')), ':YQ==:', 'a Byte Sequence ' +
      'is serialized padded');

  // Decimal serialization, section 4.1.5: three places, half to even.
  t.equal(sf.serializeBareItem({ type: 'decimal', value: 0.0005 }), '0.0',
          'decimal ' +
      '0.0005 rounds half to even -> 0.0');
  t.equal(sf.serializeBareItem({ type: 'decimal', value: 0.0015 }), '0.002',
          'decimal ' +
      '0.0015 rounds half to even -> 0.002');
  t.equal(sf.serializeBareItem({ type: 'decimal', value: 2 }), '2.0', 'a ' +
      'whole Decimal keeps ".0"');
  t.equal(sf.serializeBareItem({ type: 'decimal', value: -1.25 }), '-1.25',
          'a ' +
      'negative Decimal keeps its sign');

  const mustFail = [
    ['list', 'a, b,', 'a trailing comma'],
    ['list', '\ta', 'a leading tab (only SP is discarded at the top)'],
    ['list', 'a b', 'two items with no comma'],
    ['item', '1234567890123456', 'a sixteen-digit Integer'],
    ['item', '1234567890123.5', 'a Decimal with thirteen integer digits'],
    ['item', '1.1234', 'a Decimal with four fractional digits'],
    ['item', '1.', 'a Decimal ending in "."'],
    ['item', '-', 'a bare minus sign'],
    ['item', '"a\\x"', 'an escape other than \\" or \\\\'],
    ['item', '"unterminated', 'an unterminated String'],
    ['item', '"tab\there"', 'a tab inside a String'],
    ['item', '"café"', 'a non-ASCII character'],
    ['item', '?2', 'a Boolean that is neither ?0 nor ?1'],
    ['item', ':YQ=:', 'base64 with padding that completes no group'],
    ['item', ':ab=c:', 'base64 with "=" in the middle'],
    ['item', ':a-b_:', 'base64url characters in a Byte Sequence'],
    ['item', ':YQ==', 'an unterminated Byte Sequence'],
    ['item', '#x', 'no Item type begins with "#"'],
    ['dictionary', 'A=1', 'an uppercase Dictionary key'],
    ['dictionary', 'a=1,', 'a trailing comma in a Dictionary'],
    ['dictionary', 'a=(1 2', 'an unterminated Inner List'],
    ['list', '(1,2)', 'an Inner List separated by a comma']
  ];
  mustFail.forEach(function (row) {
    throwsParse(t, function () {
      if (row[0] === 'list') {
        sf.parseList(row[1]);
      } else if (row[0] === 'item') {
        sf.parseItem(row[1]);
      } else {
        sf.parseDictionary(row[1]);
      }
    }, 'parsing ' + JSON.stringify(row[1]) + ' (' + row[2] + ')');
  });
  const serializeMustFail = [
    [function () { sf.serializeBareItem({ type: 'integer', value: 1e15 }); },
     'an ' +
        'Integer of sixteen digits'],
    [function () { sf.serializeBareItem({ type: 'integer', value: 1.5 }); },
     'a ' +
        'fractional Integer'],
    [function () {
      sf.serializeBareItem({ type: 'decimal', value: 1234567890123 });
    }, 'a ' +
        'Decimal of thirteen integer digits'],
    [function () {
      sf.serializeBareItem({ type: 'string', value: 'line\nbreak' });
    }, 'a ' +
        'String with a newline'],
    [function () { sf.serializeBareItem({ type: 'token', value: '1abc' }); },
     'a ' +
        'Token starting with a digit'],
    [function () { sf.serializeBareItem({ type: 'token', value: 'a b' }); },
     'a ' +
        'Token with a space'],
    [function () { sf.serializeKey('Foo'); }, 'an uppercase key'],
    [function () {
      sf.serializeBareItem({ type: 'bytes', value: 'not a buffer' });
    }, 'a ' +
        'Byte Sequence that is not a Buffer'],
    [function () { sf.serializeBareItem({ type: 'boolean', value: 1 }); },
     'a ' +
        'Boolean that is a number']
  ];
  serializeMustFail.forEach(function (row) {
    throwsParse(t, row[0], 'serializing ' + row[1]);
  });
  log.debug("Leaving structuredFields().");
}

// ===========================================================================
// 2. RFC 9530.
// ===========================================================================
function contentDigests(t) {
  log.debug("Entering contentDigests().");
  t.log.info('=== RFC 9530: Content-Digest vectors, and "every accepted ' +
             'algorithm must match" ===');
  const hello = '{"hello": "world"}';
  const helloLf = hello + '\n';
  t.equal(httpsig.contentDigest(hello, 'sha-512'), REQUEST_DIGEST,
          'RFC 9421 B.2 test-request Content-Digest (sha-512 of {"hello": ' +
          '"world"})');
  t.equal(httpsig.contentDigest(Buffer.from('{"message": "good dog"}'),
                                'sha-512'), RESPONSE_DIGEST,
          'RFC 9421 B.2 test-response Content-Digest (sha-512)');
  t.equal(httpsig.contentDigest(helloLf),
          'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:',
          'RFC 9530 B.1: sha-256 is the default, over the body with its LF');
  t.equal(httpsig.contentDigest(''),
          'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
          'RFC 9530 B.2: empty content');
  t.equal(httpsig.contentDigest('"world"}\n'),
          'sha-256=:jjcgBDWNAtbYUXI37CVG3gRuGOAjaaDRGpIUFsdyepQ=:',
          'RFC 9530 B.3: partial content');
  t.equal(httpsig.contentDigest(helloLf, 'sha-512'),
          'sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:',
          'RFC 9530 section 2: the single sha-512 example');
  const both = httpsig.contentDigest(helloLf, ['sha-256', 'sha-512']);
  t.check(/^sha-256=:RK\/0[^:]+:, sha-512=:YMAam[^:]+:$/.test(both),
          'several algorithms serialize as one Dictionary, in the order asked',
          both);

  let thrown = null;
  try {
    httpsig.contentDigest(hello, 'md5');
  } catch (e) {
    thrown = e;
  }
  t.check(thrown && thrown.errorCode === 'STS-GNAP-0200' &&
          errorCodes.codeOf(thrown) === 'STS-GNAP-0200',
          'a Deprecated algorithm cannot be computed, and the throw carries ' +
          'STS-GNAP-0200',
          thrown ? thrown.message : 'no throw');

  const good = httpsig.verifyContentDigest('sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:', helloLf);
  t.check(good.ok && good.algorithms.join() === 'sha-256', 'B.1 verifies',
          JSON.stringify(good));
  refused(t,
          httpsig.verifyContentDigest('sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:',
                                         '{"hello": "WORLD"}\n'),
          'STS-GNAP-0204', 'a tampered body');
  refused(t, httpsig.verifyContentDigest(undefined, helloLf), 'STS-GNAP-0201',
          'no ' +
      'Content-Digest at all');
  refused(t, httpsig.verifyContentDigest('sha-256=:@@@:', helloLf),
          'STS-GNAP-0202', 'a ' +
      'malformed Dictionary');
  refused(t, httpsig.verifyContentDigest('sha-256=RK', helloLf),
          'STS-GNAP-0203', 'a ' +
      'member that is a Token');
  refused(t,
          httpsig.verifyContentDigest('md5=:XrY7u+Ae7tCTyyK7j1rNww==:',
                                      helloLf), 'STS-GNAP-0205',
          'only an unknown algorithm present');
  refused(t,
          httpsig.verifyContentDigest('sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:', helloLf,
                                         { accepted: ['md5'] }),
          'STS-GNAP-0200',
          'a verifier configured with an unsupported algorithm');
  const ignored = httpsig.verifyContentDigest(
    'md5=:XrY7u+Ae7tCTyyK7j1rNww==:, ' +
    'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:', helloLf);
  t.check(ignored.ok && ignored.algorithms.join() === 'sha-256',
          'an unknown algorithm beside an accepted one is ignored',
          JSON.stringify(ignored));

  // RFC 9530 section 2's two-member example. Its sha-512 member IS the body
  // with an LF; its sha-256 member is not — so with both accepted it is
  // refused, and with sha-512 alone it verifies. The refusal is the property.
  const section2 = 'sha-256=:d435Qo+nKZ+gLcUHn7GQtQ72hiBVAgqoLsZnZPiTGPk=:, ' +
    'sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:';
  refused(t, httpsig.verifyContentDigest(section2, helloLf), 'STS-GNAP-0204',
          'RFC 9530 section 2\'s two-member example with both accepted (its ' +
          'sha-256 does not match)');
  t.check(httpsig.verifyContentDigest(section2, helloLf,
                                      { accepted: ['sha-512'] }).ok,
          'the same example with only sha-512 accepted verifies');
  refused(t,
          httpsig.verifyContentDigest('sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg==:', helloLf),
          'STS-GNAP-0202', 'RFC 9530 B.5\'s over-padded value is malformed ' +
                           'base64');
  log.debug("Leaving contentDigests().");
}

// ===========================================================================
// 3. RFC 9421 section 2: component values.
// ===========================================================================
function value(message, component, options) {
  log.debug("Entering value().");
  const result = httpsig.componentValue(message, component, options);
  log.debug("Leaving value().");
  return result.ok ? result.value : result;
}

function componentValues(t) {
  log.debug("Entering componentValues().");
  t.log.info('=== RFC 9421 section 2: every component the examples define ===');
  const fields = {
    method: 'GET',
    targetUri: 'https://www.example.com/',
    headers: {
      Host: 'www.example.com',
      date: 'Tue, 20 Apr 2021 02:07:56 GMT',
      'x-ows-header': '   Leading and trailing whitespace.',
      'x-obs-fold-header': 'Obsolete\r\n    line folding.',
      'cache-control': ['max-age=60', '   must-revalidate'],
      'example-dict': ' a=1,    b=2;x=1;y=2,   c=(a   b   c)',
      'x-empty-header': ' '
    }
  };
  t.equal(value(fields, 'host'), 'www.example.com', '2.1: a field name is ' +
                                                    'matched ' +
                                                    'case-insensitively and ' +
                                                    'used lowercased');
  t.equal(value(fields, 'x-ows-header'), 'Leading and trailing whitespace.',
          '2.1: ' +
      'leading and trailing whitespace is stripped');
  t.equal(value(fields, 'x-obs-fold-header'), 'Obsolete line folding.',
          '2.1: ' +
      'obsolete line folding becomes one space');
  t.equal(value(fields, 'cache-control'), 'max-age=60, must-revalidate',
          '2.1: ' +
      'field lines combine with ", "');
  t.equal(value(fields, 'example-dict'), 'a=1,    b=2;x=1;y=2,   c=(a   b   c)',
          '2.1: ' +
      'internal whitespace is kept without ;sf');
  t.equal(value(fields, 'x-empty-header'), '', '2.1: an empty field is the ' +
                                               'empty string');
  const types = { fieldTypes: { 'example-dict': 'dictionary' } };
  t.equal(value(fields, '"example-dict";sf', types), 'a=1, b=2;x=1;y=2, c=(a ' +
                                                     'b ' +
                                                     'c)', '2.1.1: ' +
      ';sf re-serializes strictly');
  const keyed2 = { method: 'GET', targetUri: 'https://x.example/',
                   headers: { 'example-dict': 'a=1, ' +
      'b=2;x=1;y=2, c=(a   b    c), d' } };
  [['a', '1'], ['d', '?1'], ['b', '2;x=1;y=2'], ['c', '(a b c)']].forEach(
      function (row) {
    t.equal(value(keyed2, { name: 'example-dict', params: { key: row[0] } },
                  types), row[1],
            '2.1.2: "example-dict";key="' + row[0] + '"');
  });
  const bs = { method: 'GET', targetUri: 'https://x.example/',
               headers: { 'example-header': ['value, ' +
      'with, lots', 'of, ' +
      'commas'] } };
  t.equal(value(bs, '"example-header";bs'), ':dmFsdWUsIHdpdGgsIGxvdHM=:, ' +
                                            ':b2YsIGNvbW1hcw==:', '2.1.3: ' +
      ';bs wraps each field line');
  bs.headers['example-header'] = 'value, with, lots, of, commas';
  t.equal(value(bs, '"example-header";bs'),
          ':dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:', '2.1.3: ' +
      ';bs on one line');

  const post = { method: 'POST',
                 targetUri: 'https://www.example.com/path?param=value',
                 headers: { host: 'www.example.com' } };
  t.equal(value(post, '@method'), 'POST', '2.2.1: @method');
  t.equal(value(post, '@target-uri'),
          'https://www.example.com/path?param=value', '2.2.2: ' +
      '@target-uri');
  t.equal(value(post, '@authority'), 'www.example.com', '2.2.3: @authority');
  t.equal(value({ method: 'POST',
                  targetUri: 'http://www.example.com/path?param=value' },
                '@scheme'), 'http', '2.2.4: ' +
      '@scheme');
  t.equal(value(post, '@request-target'), '/path?param=value', '2.2.5: ' +
      '@request-target, origin form');
  t.equal(value({ method: 'OPTIONS', targetUri: 'https://www.example.com/',
                  requestTarget: '*' }, '@request-target'), '*',
          '2.2.5: @request-target, asterisk form, when the caller supplies it');
  t.equal(value(post, '@path'), '/path', '2.2.6: @path');
  t.equal(value({ method: 'GET', targetUri: 'https://www.example.com' },
                '@path'), '/', '2.2.6: ' +
      'an empty path is "/"');
  t.equal(value({ method: 'GET',
                  targetUri: 'https://www.example.com/path?param=value&foo=bar&baz=bat%2Dman' }, '@query'),
          '?param=value&foo=bar&baz=bat%2Dman', '2.2.7: @query keeps ' +
                                                'percent-encoding');
  t.equal(value({ method: 'POST',
                  targetUri: 'https://www.example.com/path?queryString' },
                '@query'), '?queryString', '2.2.7: ' +
      '@query without "="');
  t.equal(value({ method: 'GET', targetUri: 'https://www.example.com/path' },
                '@query'), '?', '2.2.7: ' +
      'an absent query is "?"');
  t.equal(value({ method: 'GET',
                  targetUri: 'HTTPS://WWW.Example.COM:443/Path#frag' },
                '@authority'), 'www.example.com',
          '2.2.3: the host is lowercased and the default port omitted');
  t.equal(value({ method: 'GET',
                  targetUri: 'HTTPS://WWW.Example.COM:443/Path#frag' },
                '@scheme'), 'https', '2.2.4: ' +
      'the scheme is lowercased');
  t.equal(value({ method: 'GET',
                  targetUri: 'HTTPS://WWW.Example.COM:443/Path#frag' },
                '@path'), '/Path', '2.2.6: ' +
      'the path is NOT lowercased');
  t.equal(value({ method: 'GET', targetUri: 'http://example.com:8080/' },
                '@authority'), 'example.com:8080', '2.2.3: ' +
      'a non-default port is kept');
  t.equal(value({ method: 'get', targetUri: 'http://example.com/' }, '@method'),
          'get', '2.2.1: ' +
      'the method is case-sensitive and not uppercased');
  const qp = { method: 'GET',
               targetUri: 'https://www.example.com/path?param=value&foo=bar&baz=batman&qux=' };
  t.equal(value(qp, '"@query-param";name="baz"'), 'batman', '2.2.8: ' +
      '@query-param baz');
  t.equal(value(qp, '"@query-param";name="qux"'), '', '2.2.8: @query-param ' +
                                                      'qux (empty)');
  t.equal(value(qp, '"@query-param";name="param"'), 'value', '2.2.8: ' +
      '@query-param param');
  const enc = { method: 'GET',
                targetUri: 'https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something' };
  t.equal(value(enc, '"@query-param";name="var"'),
          'this%20is%20a%20big%0Amultiline%20value', '2.2.8: ' +
      'a newline stays encoded');
  t.equal(value(enc, '"@query-param";name="bar"'), 'with%20plus%20whitespace',
          '2.2.8: ' +
      '"+" is decoded and re-encoded as %20');
  t.equal(value(enc, '"@query-param";name="fa%C3%A7ade%22%3A%20"'), 'something',
          '2.2.8: ' +
      'the NAME is matched in its encoded form');
  t.equal(value(testResponse(), '@status'), '200', '2.2.9: @status on a ' +
                                                   'response');

  refused(t, httpsig.componentValue(post, '@status'), 'STS-GNAP-0210',
          '@status ' +
      'on a request');
  refused(t, httpsig.componentValue(testResponse(), '@method'), 'STS-GNAP-0210',
          'a ' +
      'request component on a response');
  refused(t, httpsig.componentValue(post, '@nonsense'), 'STS-GNAP-0209', 'an ' +
      'unknown derived component');
  refused(t, httpsig.componentValue(post, '"@method";req'), 'STS-GNAP-0208',
          ';req ' +
      'on a request');
  refused(t, httpsig.componentValue(post, '"host";tr'), 'STS-GNAP-0214', ';tr');
  refused(t, httpsig.componentValue(fields, '"example-dict";bs;sf', types),
          'STS-GNAP-0215', ';bs ' +
      'with ;sf');
  refused(t, httpsig.componentValue(post, 'x-missing'), 'STS-GNAP-0216', 'a ' +
      'covered field that is absent');
  refused(t, httpsig.componentValue(fields, '"x-ows-header";sf'),
          'STS-GNAP-0217', ';sf ' +
      'on a field of unknown type');
  refused(t, httpsig.componentValue(keyed2, '"example-dict";key="zz"', types),
          'STS-GNAP-0218', 'a ' +
      ';key member that is absent');
  refused(t,
          httpsig.componentValue({ method: 'GET',
                                   targetUri: 'https://x.example/',
                                   headers: { 'example-dict': 'a=(' } },
                                    '"example-dict";sf', types),
          'STS-GNAP-0219', ';sf ' +
                                        'over a malformed value');
  refused(t, httpsig.componentValue(post, '@signature-params'), 'STS-GNAP-0220',
          '@signature-params ' +
      'as a component');
  refused(t,
          httpsig.componentValue({ method: 'GET',
                                   targetUri: 'https://x.example/',
                                   headers: { 'x-name': 'café' } }, 'x-name'),
          'STS-GNAP-0221', 'a field value outside ASCII without ;bs');
  refused(t, httpsig.componentValue(post, 'Content-Type'), 'STS-GNAP-0206',
          'a ' +
      'field name that is not lowercased');
  refused(t, httpsig.componentValue(post, '"host";foo'), 'STS-GNAP-0207', 'a ' +
      'parameter nobody defined');
  refused(t, httpsig.componentValue(post, '"host";sf=?0'), 'STS-GNAP-0207',
          'a ' +
      'flag parameter set to false');
  refused(t,
          httpsig.componentValue({ method: 'GET',
                                   targetUri: 'https://x.example/?a=1&a=2' },
                                 '"@query-param";name="a"'),
          'STS-GNAP-0213', 'a query parameter that occurs twice');
  refused(t, httpsig.componentValue(qp, '"@query-param";name="nope"'),
          'STS-GNAP-0212', 'a ' +
      'query parameter that is absent');
  refused(t,
          httpsig.componentValue({ method: 'GET', targetUri: '/relative' },
                                 '@path'), 'STS-GNAP-0211', 'a ' +
      'target URI that is not absolute');
  log.debug("Leaving componentValues().");
}

// ===========================================================================
// 4. RFC 9421 Appendix B.2, section 2.5, B.3 and B.4: bases and signatures.
// ===========================================================================
const B21 = withSignature(testRequest(),
  'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";' +
  'nonce="b3k2pp5k7z-50gnwp.yemd"',
  'sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:');

const B22 = withSignature(testRequest(),
  'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");' +
  'created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
  'sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:');

const B23 = withSignature(testRequest(),
  'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" ' +
  '"content-digest" ' +
  '"content-length");created=1618884473;keyid="test-key-rsa-pss"',
  'sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:');

const B24 = withSignature(testResponse(),
  'sig-b24=("@status" "content-type" "content-digest" ' +
  '"content-length");created=1618884473;keyid="test-key-ecc-p256"',
  'sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:');

const B25 = withSignature(testRequest(),
  'sig-b25=("date" "@authority" ' +
  '"content-type");created=1618884473;keyid="test-shared-secret"',
  'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:');

const B26 = withSignature(testRequest(),
  'sig-b26=("date" "@method" "@path" "@authority" "content-type" ' +
  '"content-length");created=1618884473;keyid="test-key-ed25519"',
  'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:');

function publishedBase(message, label) {
  log.debug("Entering publishedBase().");
  const parsed = httpsig.parseSignatures(message);
  if (!parsed.ok) {
    log.debug("Leaving publishedBase().");
    return parsed;
  }
  const entry = parsed.signatures.filter(function (
      s) { return s.label === label; })[0];
  const built = httpsig.signatureBase(message, entry.components,
                                      entry.paramList);
  log.debug("Leaving publishedBase().");
  return built.ok ? built.base : built;
}

function appendixB(t) {
  log.debug("Entering appendixB().");
  t.log.info('=== RFC 9421 Appendix B.2: the six test cases, base and ' +
             'signature ===');
  const bases = {
    'sig-b21': [B21, '"@signature-params": ();created=1618884473;' +
                     'keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"'],
    'sig-b22': [B22, [
      '"@authority": example.com',
      '"content-digest": ' + REQUEST_DIGEST,
      '"@query-param";name="Pet": dog',
      '"@signature-params": ("@authority" "content-digest" "@query-param";' +
      'name="Pet");created=1618884473;keyid="test-key-rsa-pss";' +
      'tag="header-example"'
    ].join('\n')],
    'sig-b23': [B23, [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@method": POST',
      '"@path": /foo',
      '"@query": ?param=Value&Pet=dog',
      '"@authority": example.com',
      '"content-type": application/json',
      '"content-digest": ' + REQUEST_DIGEST,
      '"content-length": 18',
      '"@signature-params": ("date" "@method" "@path" "@query" "@authority" ' +
      '"content-type" "content-digest" ' +
      '"content-length");created=1618884473;keyid="test-key-rsa-pss"'
    ].join('\n')],
    'sig-b24': [B24, [
      '"@status": 200',
      '"content-type": application/json',
      '"content-digest": ' + RESPONSE_DIGEST,
      '"content-length": 23',
      '"@signature-params": ("@status" "content-type" "content-digest" ' +
      '"content-length");created=1618884473;keyid="test-key-ecc-p256"'
    ].join('\n')],
    'sig-b25': [B25, [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@authority": example.com',
      '"content-type": application/json',
      '"@signature-params": ("date" "@authority" ' +
      '"content-type");created=1618884473;keyid="test-shared-secret"'
    ].join('\n')],
    'sig-b26': [B26, [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@method": POST',
      '"@path": /foo',
      '"@authority": example.com',
      '"content-type": application/json',
      '"content-length": 18',
      '"@signature-params": ("date" "@method" "@path" "@authority" ' +
      '"content-type" ' +
      '"content-length");created=1618884473;keyid="test-key-ed25519"'
    ].join('\n')]
  };
  Object.keys(bases).forEach(function (label) {
    t.equal(publishedBase(bases[label][0], label), bases[label][1],
            'B.2 ' + label + ': ' +
        'the signature base is the published one');
  });

  const cases = [
    ['sig-b21', B21, KEYS.pssPublic, 'rsa-pss-sha512'],
    ['sig-b22', B22, KEYS.pssPublic, 'rsa-pss-sha512'],
    ['sig-b23', B23, KEYS.pssPublic, 'rsa-pss-sha512'],
    ['sig-b24', B24, KEYS.eccPublic, 'ecdsa-p256-sha256'],
    ['sig-b25', B25, SHARED_SECRET, 'hmac-sha256'],
    ['sig-b26', B26, KEYS.edPublic, 'ed25519']
  ];
  cases.forEach(function (row) {
    const result = httpsig.verify(row[1],
                                  { keyFor: keyed(row[2], row[3]),
                                    now: 1618884473, maxAgeS: 60 });
    t.check(result.ok && result.verified.length === 1 &&
            result.verified[0].label === row[0],
            'B.2 ' + row[0] + ' (' + row[3] + ') verifies with the published ' +
                                              'key', JSON.stringify(result));
  });
  // The deterministic two are PRODUCED, not only checked.
  const hmac = httpsig.sign(testRequest(), {
    label: 'sig-b25', components: ['date', '@authority', 'content-type'],
    params: { created: 1618884473, keyid: 'test-shared-secret' },
    key: SHARED_SECRET, algorithm: 'hmac-sha256'
  });
  t.equal(hmac.signature, B25.headers.signature, 'B.2.5: signing reproduces ' +
                                                 'the published HMAC exactly');
  // The negative an HMAC verifier most needs, because a comparison that always
  // answers true passes every positive vector above.
  const otherSecret = Buffer.from(SHARED_SECRET);
  otherSecret[63] ^= 0x01;
  refused(t, httpsig.verify(B25, { keyFor: keyed(otherSecret, 'hmac-sha256') }),
          'STS-GNAP-0246',
          'B.2.5 under a secret differing in its last bit');
  refused(t, httpsig.verify(withSignature(testRequest({ date: 'Tue, 20 Apr ' +
      '2021 02:07:56 GMT' }),
                                          B25.headers['signature-input'],
                                          B25.headers.signature),
                            { keyFor: keyed(SHARED_SECRET, 'hmac-sha256') }),
          'STS-GNAP-0246',
          'B.2.5 with its covered Date header changed by one second');
  refused(t,
          httpsig.verify(withSignature(testRequest(),
                                       B25.headers['signature-input'],
                                       'sig-b25=:pxcQw6G3AjtMBQjwo8Xzkg==:'),
                            { keyFor: keyed(SHARED_SECRET,
                                            'hmac-sha256') }), 'STS-GNAP-0246',
          'B.2.5 with a truncated MAC');
  t.equal(hmac.signatureInput, B25.headers['signature-input'], 'B.2.5: ' +
      'signing reproduces the published Signature-Input');
  const ed = httpsig.sign(testRequest(), {
    label: 'sig-b26',
    components: ['date', '@method', '@path', '@authority', 'content-type',
                 'content-length'],
    params: { created: 1618884473,
              keyid: 'test-key-ed25519' }, key: KEYS.edPrivate,
    algorithm: 'ed25519'
  });
  t.equal(ed.signature, B26.headers.signature, 'B.2.6: signing reproduces ' +
                                               'the published Ed25519 ' +
                                               'signature exactly');

  // Section 2.5 Figure 1 / section 3.2's worked example: same message, rsa-pss.
  const fig = withSignature(testRequest(),
    'sig1=("@method" "@authority" "@path" "content-digest" "content-length" ' +
    '"content-type");created=1618884473;keyid="test-key-rsa-pss"',
    'sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:');
  t.equal(publishedBase(fig, 'sig1'), [
    '"@method": POST',
    '"@authority": example.com',
    '"@path": /foo',
    '"content-digest": ' + REQUEST_DIGEST,
    '"content-length": 18',
    '"content-type": application/json',
    '"@signature-params": ("@method" "@authority" "@path" "content-digest" ' +
    '"content-length" ' +
    '"content-type");created=1618884473;keyid="test-key-rsa-pss"'
  ].join('\n'), 'section 2.5 Figure 1: the signature base');
  t.check(httpsig.verify(fig, {
    keyFor: keyed(KEYS.pssPublic, 'rsa-pss-sha512'),
    requireComponents: ['@method', '@authority', '@path', 'content-digest',
                        'content-length', 'content-type']
  }).ok, 'section 3.2: the Figure 2 signature verifies with its required ' +
         'components');

  // Section 4.3: a proxy's rsa-v1_5-sha256 signature beside the client's.
  const proxied = {
    method: 'POST',
    targetUri: 'https://origin.host.internal.example/foo?param=Value&Pet=dog',
    headers: {
      host: 'origin.host.internal.example', date: 'Tue, 20 Apr 2021 02:07:56 ' +
                                                  'GMT',
      'content-type': 'application/json', 'content-length': '18',
      forwarded: 'for=192.0.2.123;host=example.com;proto=https',
      'content-digest': REQUEST_DIGEST,
      'signature-input': 'sig1=("@method" "@authority" "@path" ' +
        '"content-digest" "content-type" ' +
        '"content-length");created=1618884475;keyid="test-key-ecc-p256", ' +
        'proxy_sig=("@method" "@authority" "@path" "content-digest" ' +
        '"content-type" "content-length" "forwarded");created=1618884480;' +
        'keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
      signature: 'sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, ' +
        'proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:'
    }
  };
  const proxyResult = httpsig.verify(proxied,
                                     { label: 'proxy_sig', now: 1618884500,
                                       keyFor: keyed(KEYS.rsaPublic) });
  t.check(proxyResult.ok &&
          proxyResult.verified[0].algorithm === 'rsa-v1_5-sha256',
          'section 4.3: proxy_sig verifies, the algorithm taken from its alg ' +
          'parameter', JSON.stringify(proxyResult));
  refused(t,
          httpsig.verify(proxied,
                         { label: 'proxy_sig', now: 1618884540,
                           keyFor: keyed(KEYS.rsaPublic) }),
          'STS-GNAP-0242', 'section 4.3: proxy_sig at its expires instant');
  const proxySigned = httpsig.sign(proxied, {
    label: 'proxy_sig',
    components: ['@method', '@authority', '@path', 'content-digest',
                 'content-type', 'content-length', 'forwarded'],
    params: [['created', 1618884480], ['keyid', 'test-key-rsa'],
             ['alg', 'rsa-v1_5-sha256'], ['expires', 1618884540]],
    key: KEYS.rsaPrivate
  });
  t.check(proxySigned.ok &&
          proxied.headers.signature.indexOf(proxySigned.signature) >= 0,
          'section 4.3: PKCS#1 v1.5 is deterministic, and signing reproduces ' +
          'proxy_sig exactly',
          proxySigned.signature && proxySigned.signature.slice(0, 40));
  const clientOriginal = Object.assign({}, proxied,
                                       { targetUri: 'https://example.com/foo?param=Value&Pet=dog' });
  t.check(httpsig.verify(clientOriginal,
                         { label: 'sig1',
                           keyFor: keyed(KEYS.eccPublic,
                                         'ecdsa-p256-sha256') }).ok,
          'section 4.3: the client\'s sig1 verifies over the message as the ' +
          'client sent it');
  refused(t,
          httpsig.verify(proxied,
                         { label: 'sig1',
                           keyFor: keyed(KEYS.eccPublic,
                                         'ecdsa-p256-sha256') }),
          'STS-GNAP-0246', 'section 4.3: sig1 after the proxy changed ' +
                           '@authority');

  // B.3: the TLS-terminating proxy's signature over Client-Cert.
  const clientCert = ':MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:';
  const ttrp = {
    method: 'POST',
    targetUri: 'https://service.internal.example/foo?param=Value&Pet=dog',
    headers: {
      host: 'service.internal.example', date: 'Tue, 20 Apr 2021 02:07:55 GMT',
      'content-type': 'application/json',
      'content-length': '18', 'client-cert': clientCert,
      'signature-input': 'ttrp=("@path" "@query" "@method" "@authority" ' +
                         '"client-cert");created=1618884473;' +
                         'keyid="test-key-ecc-p256"',
      signature: 'ttrp=:xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==:'
    }
  };
  t.equal(publishedBase(ttrp, 'ttrp'), [
    '"@path": /foo', '"@query": ?param=Value&Pet=dog', '"@method": POST',
    '"@authority": service.internal.example',
    '"client-cert": ' + clientCert,
    '"@signature-params": ("@path" "@query" "@method" "@authority" ' +
    '"client-cert");created=1618884473;keyid="test-key-ecc-p256"'
  ].join('\n'), 'B.3: the TLS-terminating proxy\'s signature base');
  t.check(httpsig.verify(ttrp,
                         { keyFor: keyed(KEYS.eccPublic,
                                         'ecdsa-p256-sha256') }).ok, 'B.3: ' +
      'ttrp verifies');

  // B.4: which transformations a signature survives.
  const sigInput = 'transform=("@method" "@path" "@authority" ' +
                   '"accept");created=1618884473;keyid="test-key-ed25519"';
  const sigValue = 'transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:';
  function transform(method, uri, headers) {
    log.debug("Entering transform().");
    log.debug("Leaving transform().");
    return { method: method, targetUri: uri,
             headers: Object.assign({ 'signature-input': sigInput,
                                      signature: sigValue }, headers) };
  }
  const edKey = { keyFor: keyed(KEYS.edPublic, 'ed25519') };
  const original = transform('GET',
                             'https://example.org/demo?name1=Value1&Name2=value2',
                             { host: 'example.org', date: 'Fri, 15 Jul 2022 ' +
                                 '14:24:55 ' +
                                 'GMT', accept: ['application/json', '*/*'] });
  t.equal(publishedBase(original, 'transform'), [
    '"@method": GET', '"@path": /demo', '"@authority": example.org',
    '"accept": application/json, */*',
    '"@signature-params": ("@method" "@path" "@authority" ' +
    '"accept");created=1618884473;keyid="test-key-ed25519"'
  ].join('\n'), 'B.4: the signature base');
  t.check(httpsig.verify(original, edKey).ok, 'B.4: the original message ' +
                                              'verifies');
  t.check(httpsig.verify(transform('GET',
    'https://example.org/demo?name1=Value1&Name2=value2&param=added',
    { host: 'example.org', date: 'Fri, 15 Jul 2022 14:24:55 GMT',
      accept: ['application/json', '*/*'],
      'accept-language': 'en-US,en;q=0.5' }), edKey).ok, 'B.4: an added ' +
          'header and query parameter do not break it');
  t.check(httpsig.verify(transform('GET',
    'https://example.org/demo?name1=Value1&Name2=value2',
    { host: 'example.org', referer: 'https://developer.example.org/demo',
      accept: 'application/json, ' +
        '*/*' }), edKey).ok,
    'B.4: Date removed and Accept collapsed onto one line do not break it');
  refused(t,
    httpsig.verify(transform('POST',
    'https://example.com/demo?name1=Value1&Name2=value2',
    { host: 'example.com', date: 'Fri, 15 Jul 2022 14:24:55 GMT',
      accept: ['application/json', '*/*'] }), edKey),
    'STS-GNAP-0246', 'B.4: a changed method and authority');
  refused(t,
    httpsig.verify(transform('GET',
    'https://example.org/demo?name1=Value1&Name2=value2',
    { host: 'example.org', date: 'Fri, 15 Jul 2022 14:24:55 GMT',
      accept: ['*/*', 'application/json'] }), edKey),
    'STS-GNAP-0246', 'B.4: the two Accept lines reordered');

  // Section 2.4's response examples use ;req, which this verifier refuses.
  refused(t, httpsig.verify({
    status: 503,
    headers: {
      'content-type': 'application/json',
      'signature-input': 'reqres=("@status" "@method";req);' +
                         'created=1618884479;keyid="test-key-ecc-p256"',
      signature: 'reqres=:dMT/A/76ehrdBTD/2Xx8QuKV6FoyzEP/I9hdzKN8LQJLNgzU4W767HK05rx1i8meNQQgQPgQp8wq2ive3tV5Ag==:'
    }
  }, { keyFor: keyed(KEYS.eccPublic, 'ecdsa-p256-sha256') }), 'STS-GNAP-0208',
          'section ' +
      '2.4: a ;req component');

  // RFC 9635 section 7.3.1's own example, a PS512 JWK named by its alg.
  const gnapKey = nodeCrypto.createPublicKey({ format: 'jwk',
                                               key: { kty: 'RSA', e: 'AQAB',
    n: 'hYOJ-XOKISdMMShn_G4W9m20mT0VWtQBsmBBkI2cmRt4Ai8BfYdHsFzAtYKOjpBR1RpKpJmVKxIGNy0g6Z3ad2XYsh8KowlyVy8IkZ8NMwSrcUIBZGYXjHpwjzvfGvXH_5KJlnR3_uRUp4Z4Ujk2bCaKegDn11V2vxE41hqaPUnhRZxe0jRETddzsE3mu1SK8dTCROjwUl14mUNo8iTrTm4n0qDadz8BkPo-uv4BC0bunS0K3bA_3UgVp7zBlQFoFnLTO2uWp_muLEWGl67gBq9MO3brKXfGhi3kOzywzwPTuq-cVQDyEN7aL0SxCb3Hc4IdqDaMg8qHUyObpPitDQ' } });
  const gnapRequest = {
    method: 'POST',
    targetUri: 'https://server.example.com/gnap',
    headers: {
      host: 'server.example.com', 'content-type': 'application/json',
      'content-length': '988',
      'content-digest':
        'sha-256=:q2XBmzRDCREcS2nWo/6LYwYyjrlN1bRfv+HKLbeGAGg=:',
      'signature-input': 'sig1=("@method" "@target-uri" "content-digest" ' +
        '"content-length" "content-type");created=1618884473;' +
        'keyid="gnap-rsa";nonce="NAOEJF12ER2";tag="gnap"',
      signature: 'sig1=:c2uwTa6ok3iHZsaRKl1ediKlgd5cCAYztbym68XgX8gSOgK0Bt+zLJ19oGjSAHDjJxX2gXP2iR6lh9bLMTfPzbFVn4Eh+5UlceP+0Z5mES7v0R1+eHeOqBl0YlYKaSQ11YT7n+cwPnCSdv/6+62m5zwXEEftnBeA1ECorfTuPtau/yrTYEvD9A/JqR2h9VzAE17kSlSSsDHYA6ohsFqcRJavX29duPZDfYgkZa76u7hJ23yVxoUpu2J+7VUdedN/72N3u3/z2dC8vQXbzCPTOiLru12lb6vnBZoDbUGsRR/zHPauxhj9T+218o5+tgwYXw17othJSxIIOZ9PkIgz4g==:'
    }
  };
  const gnapResult = httpsig.verify(gnapRequest, {
    keyFor: keyed(gnapKey, 'PS512'), requireTag: 'gnap', forbidAlgParam: true,
    requireComponents: ['@method', '@target-uri', 'content-digest'],
    now: 1618884480, maxAgeS: 60
  });
  t.check(gnapResult.ok && gnapResult.verified[0].algorithm === 'PS512',
          'RFC 9635 section 7.3.1: the example request verifies under the ' +
          'JWK\'s PS512', JSON.stringify(gnapResult));
  refused(t, httpsig.verify(gnapRequest, { keyFor: keyed(gnapKey, 'PS256') }),
          'STS-GNAP-0246',
          'the same request under PS256 (salt length and hash both wrong)');
  log.debug("Leaving appendixB().");
}

// ===========================================================================
// 5. Signing with every algorithm, and the byte-level shape of each output.
// ===========================================================================
function everyAlgorithm(t) {
  log.debug("Entering everyAlgorithm().");
  t.log.info('=== every algorithm signs and verifies, and emits the ' +
             'representation its RFC names ===');
  const rsa = KEYS.rsaPrivate;
  const p384 = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const p521 = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-521' });
  const ed448 = nodeCrypto.generateKeyPairSync('ed448');
  const rows = [
    ['rsa-pss-sha512', KEYS.pssPrivate, KEYS.pssPublic, 256],
    ['rsa-v1_5-sha256', rsa, KEYS.rsaPublic, 256],
    ['hmac-sha256', SHARED_SECRET, SHARED_SECRET, 32],
    ['ecdsa-p256-sha256', KEYS.eccPrivate, KEYS.eccPublic, 64],
    ['ecdsa-p384-sha384', p384.privateKey, p384.publicKey, 96],
    ['ed25519', KEYS.edPrivate, KEYS.edPublic, 64],
    ['RS256', rsa, KEYS.rsaPublic, 256], ['RS384', rsa, KEYS.rsaPublic, 256],
    ['RS512', rsa, KEYS.rsaPublic, 256],
    ['PS256', rsa, KEYS.rsaPublic, 256], ['PS384', rsa, KEYS.rsaPublic, 256],
    ['PS512', rsa, KEYS.rsaPublic, 256],
    ['ES256', KEYS.eccPrivate, KEYS.eccPublic, 64],
    ['ES384', p384.privateKey, p384.publicKey, 96],
    ['ES512', p521.privateKey, p521.publicKey, 132],
    ['EdDSA', KEYS.edPrivate, KEYS.edPublic, 64],
    ['EdDSA', ed448.privateKey, ed448.publicKey, 114],
    ['HS256', SHARED_SECRET, SHARED_SECRET, 32],
    ['HS384', SHARED_SECRET, SHARED_SECRET, 48],
    ['HS512', SHARED_SECRET, SHARED_SECRET, 64]
  ];
  rows.forEach(function (row) {
    const signed = httpsig.sign(testRequest(), {
      label: 'sig', components: ['@method', '@target-uri', 'content-digest'],
      params: { created: 1700000000, keyid: 'k', tag: 'gnap' }, key: row[1],
      algorithm: row[0]
    });
    if (!t.check(signed.ok, row[0] + ' signs', JSON.stringify(signed))) {
      return;
    }
    t.equal(signed.signatureBytes.length, row[3],
            row[0] + ' produces ' + row[3] + ' ' +
        'octets' +
            (/ecdsa|ES/.test(row[0]) ? ' (raw r||s, not DER)' : ''));
    const message = withSignature(testRequest(), signed.signatureInput,
                                  signed.signature);
    const verified = httpsig.verify(message,
                                    { keyFor: keyed(row[2], row[0]),
                                      requireTag: 'gnap',
                                      forbidAlgParam: true });
    t.check(verified.ok, row[0] + ' verifies what it signed',
            JSON.stringify(verified));
  });

  // The salt length is the HASH length, asserted with node directly rather
  // than through the module that chose it — a signer and verifier that shared
  // a wrong salt length would agree with each other above.
  [['PS256', 'sha256', 32], ['PS384', 'sha384', 48], ['PS512', 'sha512', 64],
   ['rsa-pss-sha512', 'sha512', 64]].forEach(function (row) {
    const signed = httpsig.sign(testRequest(),
                                { label: 's', components: ['@method'],
      params: {},
      key: row[0] === 'rsa-pss-sha512' ? KEYS.pssPrivate :
           rsa, algorithm: row[0] });
    const pub = row[0] === 'rsa-pss-sha512' ? KEYS.pssPublic : KEYS.rsaPublic;
    const data = Buffer.from(signed.base, 'ascii');
    const exact = nodeCrypto.verify(row[1], data,
                                    { key: pub, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
                                                    saltLength: row[2] },
                                    signed.signatureBytes);
    const other = nodeCrypto.verify(row[1], data,
                                    { key: pub, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
                                                    saltLength: row[2] === 32 ?
                                                        64 : 32 },
                                    signed.signatureBytes);
    t.check(exact && !other,
            row[0] + ' uses a salt of exactly ' + row[2] + ' ' +
        'octets', 'exact=' + exact + ' ' +
        'other=' + other);
  });
  // And ECDSA is IEEE P1363, checked by node with the encoding named.
  const es = httpsig.sign(testRequest(),
                          { label: 's', components: ['@method'], params: {},
                            key: KEYS.eccPrivate, algorithm: 'ES256' });
  t.check(nodeCrypto.verify('sha256', Buffer.from(es.base, 'ascii'),
                            { key: KEYS.eccPublic, dsaEncoding: 'ieee-p1363' },
                            es.signatureBytes),
          'ES256 output verifies as IEEE P1363 r||s under node directly');
  const der = nodeCrypto.sign('sha256', Buffer.from(es.base, 'ascii'),
                              KEYS.eccPrivate);
  const derMessage = withSignature(testRequest(), es.signatureInput,
                                   's=:' + der.toString('base64') + ':');
  refused(t,
          httpsig.verify(derMessage,
                         { keyFor: keyed(KEYS.eccPublic, 'ES256') }),
          'STS-GNAP-0246',
          'a DER-encoded ECDSA signature of the right base');
  log.debug("Leaving everyAlgorithm().");
}

// ===========================================================================
// 6. Refusals on signing and verifying.
// ===========================================================================
function refusals(t) {
  log.debug("Entering refusals().");
  t.log.info('=== the refusals, one at a time ===');
  const base = testRequest();
  const good = httpsig.sign(base,
                            { label: 'sig1',
    components: ['@method', '@target-uri', 'content-digest'],
    params: { created: 1700000000, keyid: 'test-key-ecc-p256',
              tag: 'gnap' }, key: KEYS.eccPrivate, algorithm:
                                                     'ecdsa-p256-sha256' });
  const signed = withSignature(base, good.signatureInput, good.signature);
  const eccKey = keyed(KEYS.eccPublic, 'ecdsa-p256-sha256');
  t.check(httpsig.verify(signed,
                         { keyFor: eccKey, now: 1700000010, maxAgeS: 300,
                                   requireTag: 'gnap',
                                   requireComponents: ['@method', '@target-uri',
                                                       'content-digest'] }).ok,
          'the control: the untampered message verifies under every ' +
          'requirement below');

  // Body tampering: the SIGNATURE still verifies (it covers the header), and
  // the Content-Digest check is what catches it — the two checks are separate
  // on purpose, and GNAP requires both.
  t.check(httpsig.verify(signed, { keyFor: eccKey }).ok, 'a tampered body ' +
      'leaves the signature over the header valid');
  refused(t,
          httpsig.verifyContentDigest(signed.headers['content-digest'],
                                      '{"hello": ' +
      '"mallory"}'), 'STS-GNAP-0204',
          'a tampered body fails its Content-Digest');

  refused(t,
          httpsig.verify(signed,
                         { keyFor: eccKey,
                           requireComponents: ['authorization'] }),
          'STS-GNAP-0243',
          'a required component the signature does not cover');
  refused(t,
          httpsig.verify(signed,
                         { keyFor: eccKey,
                           requireComponents: ['"content-digest";sf'] }),
          'STS-GNAP-0243',
          'a required component that differs only by a parameter');
  refused(t,
          httpsig.verify(signed,
                         { keyFor: eccKey, now: 1700000301, maxAgeS: 300 }),
          'STS-GNAP-0240', 'a ' +
      'stale created');
  refused(t,
          httpsig.verify(signed,
                         { keyFor: eccKey, now: 1699999000, maxAgeS: 300 }),
          'STS-GNAP-0241', 'a ' +
      'created too far in the future');
  refused(t,
          httpsig.verify(signed,
                         { keyFor: eccKey, label: 'sig1',
                           requireTag: 'gnap-rotate' }), 'STS-GNAP-0237',
          'the ' +
      'wrong tag on a labelled signature');
  refused(t, httpsig.verify(signed, { keyFor: eccKey, requireTag: 'other' }),
          'STS-GNAP-0237', 'no ' +
      'signature with the required tag');
  refused(t,
          httpsig.verify(signed,
                         { keyFor: keyed(
                             nodeCrypto.generateKeyPairSync('ec',
                                                            { namedCurve: 'P-256' }).publicKey,
                                                    'ecdsa-p256-sha256') }),
          'STS-GNAP-0246', 'the ' +
                                                        'wrong key of the ' +
                                                        'right type');
  refused(t,
          httpsig.verify(signed,
                         { keyFor: keyed(KEYS.edPublic, 'ecdsa-p256-sha256') }),
          'STS-GNAP-0224', 'a ' +
      'key of the wrong type');
  refused(t, httpsig.verify(signed, { keyFor: function () {
    log.debug("Entering keyFor().");
    log.debug("Leaving keyFor().");
    return null;
  } }), 'STS-GNAP-0244', 'no key for the signature');
  refused(t, httpsig.verify(signed, { keyFor: function () {
    log.debug("Entering keyFor().");
    log.debug("Leaving keyFor().");
    throw new Error('boom');
  } }), 'STS-GNAP-0244', 'a key lookup that throws');
  refused(t, httpsig.verify(signed, {}), 'STS-GNAP-0244', 'no keyFor at all');
  refused(t, httpsig.verify(signed, { keyFor: keyed(KEYS.eccPublic) }),
          'STS-GNAP-0226', 'no ' +
      'algorithm from the key or the parameters');
  refused(t,
          httpsig.verify(signed,
                         { keyFor: eccKey, allowedAlgorithms: ['ed25519'] }),
          'STS-GNAP-0245', 'an ' +
      'algorithm policy does not allow');
  refused(t, httpsig.verify(signed, { keyFor: keyed(KEYS.eccPublic, 'ES999') }),
          'STS-GNAP-0227', 'an ' +
      'unknown algorithm');
  refused(t, httpsig.verify(signed, { keyFor: eccKey, label: 'nope' }),
          'STS-GNAP-0236', 'a ' +
      'label the message does not carry');
  const expiring = httpsig.sign(base,
                                { label: 'e', components: ['@method'],
    params: { created: 1700000000, expires: 1700000060 },
    key: KEYS.eccPrivate, algorithm: 'ES256' });
  const expiringMessage = withSignature(base, expiring.signatureInput,
                                        expiring.signature);
  t.check(httpsig.verify(expiringMessage,
                         { keyFor: keyed(KEYS.eccPublic, 'ES256'),
                           now: 1700000059 }).ok,
          'a signature one second before its expires verifies');
  refused(t,
          httpsig.verify(expiringMessage,
                         { keyFor: keyed(KEYS.eccPublic, 'ES256'),
                           now: 1700000060 }), 'STS-GNAP-0242',
          'a signature at its expires');
  refused(t,
          httpsig.verify(withSignature(base, 'n=("@method")', 'n=:AAAA:'),
                         { keyFor: eccKey, requireCreated: true }),
          'STS-GNAP-0239', 'requireCreated with no created');

  // Duplicate components: on signing, and in a received Signature-Input.
  refused(t,
          httpsig.sign(base,
                       { label: 'd', components: ['@method', '@method'],
                                  params: {}, key: KEYS.eccPrivate,
                                  algorithm:
                                    'ES256' }), 'STS-GNAP-0223', 'signing ' +
                                      'with a component listed twice');
  refused(t,
          httpsig.sign(base,
                       { label: 'd',
                                  components: ['"content-digest";sf;' +
                                               'key="sha-512"',
                                               '"content-digest";' +
                                                   'key="sha-512";sf'],
                                  params: {}, key: KEYS.eccPrivate,
                                  algorithm: 'ES256' }),
          'STS-GNAP-0223', 'two identifiers equal but for parameter order');
  refused(t, httpsig.verify(withSignature(base, 'sig1=("@method" ' +
                                                '"@method");created=1700000000',
                                          good.signature),
                            { keyFor: eccKey }), 'STS-GNAP-0223', 'a ' +
                                'received Signature-Input listing a ' +
                                'component twice');

  // Label and field shapes.
  refused(t,
          httpsig.verify(withSignature(base, good.signatureInput,
                                       'other=:AAAA:'), { keyFor: eccKey }),
          'STS-GNAP-0234', 'a label in Signature-Input and not in Signature');
  refused(t, httpsig.verify(withSignature(base, good.signatureInput + ', ' +
      'sig1=()', good.signature), { keyFor: eccKey }),
          'STS-GNAP-0232', 'a label used twice');
  refused(t,
          httpsig.verify(withSignature(base, [good.signatureInput, 'sig1=()'],
                                       good.signature), { keyFor: eccKey }),
          'STS-GNAP-0232', 'a label used again on a second field line');
  refused(t,
          httpsig.verify(withSignature(base, 'sig1=("@method" oops',
                                       good.signature), { keyFor: eccKey }),
          'STS-GNAP-0231', 'a Signature-Input that is not a Dictionary');
  refused(t,
          httpsig.verify(withSignature(base, 'sig1=token', good.signature),
                         { keyFor: eccKey }),
          'STS-GNAP-0235',
          'a Signature-Input member that is not an Inner List');
  refused(t,
          httpsig.verify(withSignature(base, 'sig1=(method authority)',
                                       good.signature), { keyFor: eccKey }),
          'STS-GNAP-0235',
          'component identifiers that are Tokens, not Strings');
  refused(t,
          httpsig.verify(withSignature(base, good.signatureInput, 'sig1="abc"'),
                         { keyFor: eccKey }),
          'STS-GNAP-0235', 'a Signature member that is not a Byte Sequence');
  refused(t, httpsig.verify(base, { keyFor: eccKey }), 'STS-GNAP-0233', 'a ' +
      'message with no signature');
  refused(t,
          httpsig.verify(withSignature(base, 'sig1=();created="1700000000"',
                                       'sig1=:AAAA:'), { keyFor: eccKey }),
          'STS-GNAP-0222', 'a created parameter that is a String');
  refused(t,
          httpsig.verify(withSignature(base, 'sig1=("@method");keyid="k"',
                                       'sig1=:AAAA:'),
                         { keyFor: eccKey, maxAgeS: 60 }),
          'STS-GNAP-0239', 'no created when the age is checked');
  refused(t,
          httpsig.verify(withSignature(base,
                                       'sig1=("@signature-params");created=1',
                                       'sig1=:AAAA:'), { keyFor: eccKey }),
          'STS-GNAP-0220', '@signature-params listed as a covered component');

  // alg: forbidden, conflicting, and a JWS name where only the registry may go.
  const withAlg = httpsig.sign(base,
                               { label: 'a', components: ['@method'],
    params: { created: 1700000000, alg: 'ecdsa-p256-sha256' },
    key: KEYS.eccPrivate, algorithm: 'ecdsa-p256-sha256' });
  const withAlgMessage = withSignature(base, withAlg.signatureInput,
                                       withAlg.signature);
  t.check(httpsig.verify(withAlgMessage, { keyFor: keyed(KEYS.eccPublic) }).ok,
          'an ' +
      'alg parameter alone names the algorithm');
  refused(t,
          httpsig.verify(withAlgMessage,
                         { keyFor: eccKey, forbidAlgParam: true }),
          'STS-GNAP-0238', 'an ' +
      'alg parameter when it is forbidden');
  refused(t,
          httpsig.verify(withAlgMessage,
                         { keyFor: keyed(KEYS.eccPublic, 'ES256') }),
          'STS-GNAP-0228', 'an ' +
      'alg parameter disagreeing with the key');
  refused(t,
          httpsig.sign(base,
                       { label: 'a', components: [], params: { alg: 'ES256' },
                         key: KEYS.eccPrivate, algorithm: 'ES256' }),
          'STS-GNAP-0228', 'signing a JWS algorithm with an alg parameter');
  refused(t,
          httpsig.sign(base,
                       { label: 'a', components: [],
                                  params: { alg: 'rsa-v1_5-sha256' },
                                  key: KEYS.eccPrivate,
                                  algorithm: 'ecdsa-p256-sha256' }),
          'STS-GNAP-0228', 'signing ' +
                                      'with an alg parameter naming another ' +
                                      'algorithm');
  refused(t,
          httpsig.verify(withSignature(base, 'a=("@method");alg="ES256"',
                                       withAlg.signature),
                            { keyFor: keyed(KEYS.eccPublic) }), 'STS-GNAP-0227',
          'a ' +
                                'JWS name carried as the alg parameter');

  // Sign-side input problems.
  refused(t,
          httpsig.sign(base,
                       { label: 'Bad Label', components: [], params: {},
                         key: SHARED_SECRET, algorithm: 'hmac-sha256' }),
          'STS-GNAP-0225', 'a label that is not a Dictionary key');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: {},
                         key: SHARED_SECRET }), 'STS-GNAP-0226', 'no ' +
      'algorithm named');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: {},
                         key: SHARED_SECRET, algorithm: 'none' }),
          'STS-GNAP-0227', 'the JWS "none" algorithm');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: {},
                         key: SHARED_SECRET.slice(0, 16),
                         algorithm: 'hmac-sha256' }),
          'STS-GNAP-0224', 'an HMAC secret shorter than its hash');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: {},
                         key: KEYS.eccPublic, algorithm: 'ES256' }),
          'STS-GNAP-0224', 'signing with a public key');
  const small = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: {},
                         key: small.privateKey, algorithm: 'RS256' }),
          'STS-GNAP-0224', 'an RSA key under 2048 bits');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: {},
                         key: KEYS.pssPrivate, algorithm: 'rsa-v1_5-sha256' }),
          'STS-GNAP-0224', 'an RSASSA-PSS-only key under PKCS#1 v1.5');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: { created: 1.5 },
                         key: SHARED_SECRET, algorithm: 'hmac-sha256' }),
          'STS-GNAP-0222', 'a created that is not an Integer');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [], params: { nonce: {} },
                         key: SHARED_SECRET, algorithm: 'hmac-sha256' }),
          'STS-GNAP-0222', 'a parameter value that is not a bare item');
  refused(t,
          httpsig.sign(base,
                       { label: 'x', components: [42], params: {},
                         key: SHARED_SECRET, algorithm: 'hmac-sha256' }),
          'STS-GNAP-0206', 'a component that is not an identifier');

  // 'all' against 'any' when one of two signatures is bad.
  const second = httpsig.sign(base,
                              { label: 'sig2', components: ['@method'],
    params: { created: 1700000000, tag: 'gnap' },
    key: KEYS.edPrivate, algorithm: 'ed25519' });
  const two = httpsig.appendSignature(signed, second).message;
  const onlyEcc = function (parsed) {
    log.debug("Entering onlyEcc().");
    log.debug("Leaving onlyEcc().");
    return parsed.label === 'sig1' ?
           { key: KEYS.eccPublic, algorithm: 'ecdsa-p256-sha256' } : null;
  };
  refused(t, httpsig.verify(two, { keyFor: onlyEcc, requireTag: 'gnap' }),
          'STS-GNAP-0244', "require " +
      "'all' (the default) with one unverifiable signature");
  const anyResult = httpsig.verify(two,
                                   { keyFor: onlyEcc, requireTag: 'gnap',
                                     require: 'any' });
  t.check(anyResult.ok && anyResult.verified.length === 1 &&
          anyResult.verified[0].label === 'sig1',
          "require 'any' accepts the one that verifies", JSON.stringify(
              anyResult));
  refused(t, httpsig.appendSignature(two, second), 'STS-GNAP-0230',
          'appending ' +
      'a label already in the message');
  refused(t, httpsig.appendSignature(base, { ok: false }), 'STS-GNAP-0230',
          'appending ' +
      'something that is not a signature');
  log.debug("Leaving refusals().");
}

// ===========================================================================
// 7. RFC 9635 section 7.3.1.1: key rotation, two signatures, one covering the
//    other.
// ===========================================================================
function rotation(t) {
  log.debug("Entering rotation().");
  t.log.info('=== RFC 9635 7.3.1.1: rotation signs the old signature with ' +
             'the new key ===');
  const body = '{"key": {"proof": "httpsig", "jwk": {"kty": "RSA", "kid": ' +
               '"xyz-2", "alg": "RS256"}}}';
  const request = {
    method: 'POST',
    targetUri: 'https://server.example.com/token/PRY5NM33',
    headers: {
      host: 'server.example.com',
      authorization: 'GNAP 4398.34-12-asvDa.a',
      'content-digest': httpsig.contentDigest(body, 'sha-512')
    }
  };
  const oldSig = httpsig.sign(request, {
    label: 'old-key',
    components: ['@method', '@target-uri', 'content-digest', 'authorization'],
    params: { created: 1618884475, keyid: 'test-key-ecc-p256',
              tag: 'gnap' }, key: KEYS.eccPrivate,
    algorithm: 'ecdsa-p256-sha256'
  });
  const afterOld = httpsig.appendSignature(request, oldSig);
  t.check(afterOld.ok, 'the old key\'s signature is appended');
  t.check(request.headers['signature-input'] === undefined, 'appendSignature ' +
      'returns a new message and leaves the old one alone');
  const newSig = httpsig.sign(afterOld.message, {
    label: 'new-key',
    components: ['@method', '@target-uri', 'content-digest', 'authorization',
                 { name: 'signature', params: { key: 'old-key' } },
                 { name: 'signature-input', params: { key: 'old-key' } }],
    params: { created: 1618884480, keyid: 'xyz-2', tag: 'gnap-rotate' },
    key: KEYS.rsaPrivate, algorithm: 'RS256'
  });
  t.check(newSig.ok, 'the new key signs over the old signature',
          JSON.stringify(newSig.why));
  const lines = newSig.base.split('\n');
  t.equal(lines[4],
          '"signature";key="old-key": ' +
          oldSig.signature.slice('old-key='.length),
          'the base carries "signature";key="old-key" as the Byte Sequence ' +
          'member');
  t.equal(lines[5], '"signature-input";key="old-key": ("@method" ' +
          '"@target-uri" "content-digest" "authorization");' +
          'created=1618884475;keyid="test-key-ecc-p256";tag="gnap"',
          'the base carries "signature-input";key="old-key" in RFC 9635\'s ' +
          'own spelling');
  const rotated = httpsig.appendSignature(afterOld.message, newSig).message;
  t.check(/^old-key=\([^)]*\);[^,]*, new-key=\(/.test(
      rotated.headers['signature-input']) &&
          /^old-key=:[^:]+:, new-key=:[^:]+:$/.test(rotated.headers.signature),
          'both fields now hold both members, old first',
          rotated.headers.signature.slice(0, 30));

  const keyFor = function (parsed) {
    log.debug("Entering keyFor().");
    log.debug("Leaving keyFor().");
    return parsed.params.keyid === 'xyz-2' ?
           { key: KEYS.rsaPublic, algorithm: 'RS256' }
                                           : { key: KEYS.eccPublic,
                                               algorithm: 'ecdsa-p256-sha256' };
  };
  const common = ['@method', '@target-uri', 'content-digest', 'authorization'];
  t.check(httpsig.verify(rotated,
                         { label: 'old-key', requireTag: 'gnap', keyFor: keyFor,
                                    forbidAlgParam: true,
                                    requireComponents: common, now: 1618884490,
                                    maxAgeS: 60 }).ok,
          'the old-key signature verifies under tag gnap');
  t.check(httpsig.verify(rotated,
                         { label: 'new-key', requireTag: 'gnap-rotate',
    keyFor: keyFor, forbidAlgParam: true,
    requireComponents: common.concat(['"signature";key="old-key"',
                                      '"signature-input";key="old-key"']),
    now: 1618884490, maxAgeS: 60 }).ok,
          'the new-key signature verifies under tag gnap-rotate, covering ' +
          'the old one');
  const both = httpsig.verify(rotated, { keyFor: keyFor });
  t.check(both.ok &&
          both.verified.map(function (v) { return v.label; })
                       .join() === 'old-key,new-key',
          'with no label, BOTH are verified, in Signature-Input order',
          JSON.stringify(both.verified && both.verified.length));

  // Replace the old signature with another VALID ECDSA signature of the same
  // base: old-key still verifies, and new-key must not, because what it signed
  // was the other bytes.
  const resigned = httpsig.sign(request, {
    label: 'old-key',
    components: ['@method', '@target-uri', 'content-digest', 'authorization'],
    params: { created: 1618884475, keyid: 'test-key-ecc-p256',
              tag: 'gnap' }, key: KEYS.eccPrivate,
    algorithm: 'ecdsa-p256-sha256'
  });
  const swapped = Object.assign({}, rotated,
                                { headers: Object.assign({}, rotated.headers, {
    signature: rotated.headers.signature.replace(/^old-key=:[^:]+:/,
                                                 resigned.signature)
  }) });
  t.check(httpsig.verify(swapped, { label: 'old-key', keyFor: keyFor }).ok,
          'a re-made old-key signature is still a valid old-key signature');
  refused(t, httpsig.verify(swapped, { label: 'new-key', keyFor: keyFor }),
          'STS-GNAP-0246',
          'the new-key signature no longer verifies once the old signature ' +
          'it covered is swapped');
  refused(t,
          httpsig.verify(rotated,
                         { label: 'new-key', requireTag: 'gnap',
                           keyFor: keyFor }), 'STS-GNAP-0237',
          'the rotation signature does not pass as an ordinary gnap signature');
  const noOld = Object.assign({}, rotated,
                              { headers: Object.assign({}, rotated.headers, {
    'signature-input': rotated.headers['signature-input'].replace(
        /^old-key=\([^)]*\)[^,]*, /, 'renamed=(), ')
  }) });
  refused(t, httpsig.verify(noOld, { label: 'new-key', keyFor: keyFor }),
          'STS-GNAP-0234',
          'renaming the old signature in one field only is a label mismatch');

  // RFC 9635's printed example: both printed old-key values verify under the
  // test key, which is the evidence for the erratum recorded above.
  const printed = {
    method: 'POST', targetUri: 'https://server.example.com/token/PRY5NM33',
    headers: {
      host: 'server.example.com', authorization: 'GNAP 4398.34-12-asvDa.a',
      'content-digest': 'sha-512=:Fb/A5vnawhuuJ5xk2RjGrbbxr6cvinZqd4+JPY85u/JNyTlmRmCOtyVhZ1Oz/cSS4tsYen6fzpCwizy6UQxNBQ==:',
      'signature-input': 'old-key=("@method" "@target-uri" "content-digest" ' +
        '"authorization");created=1618884475;keyid="test-key-ecc-p256";' +
        'tag="gnap"'
    }
  };
  ['vN4IKYsJl2RLFe+tYEm4dHM4R4BToqx5D2FfH4ge5WOkgxodI2QRrjB8rysvoSEGvAfiVJOWsGcPD1lU639Amw==',
   'YdDJjDn2Sq8FR82e5IcOLWmmf6wILoswlnRcz+nM+e8xjFDpWS2YmiMYDqUdri2UiJsZx63T1z7As9Kl6HTGkQ=='].forEach(function (value, k) {
    const message = Object.assign({}, printed,
                                  { headers: Object.assign({}, printed.headers,
                                                           { signature: 'old-key=:' + value + ':' }) });
    t.check(httpsig.verify(message,
                           { keyFor: keyed(KEYS.eccPublic, 'ecdsa-p256-sha256'),
                             requireTag: 'gnap' }).ok,
            'RFC 9635 7.3.1.1: printed old-key value ' + (k + 1) + ' of 2 ' +
                'verifies under test-key-ecc-p256');
  });
  log.debug("Leaving rotation().");
}

function run(t) {
  log.debug("Entering run().");
  structuredFields(t);
  contentDigests(t);
  componentValues(t);
  appendixB(t);
  everyAlgorithm(t);
  refusals(t);
  rotation(t);
  // A FLOOR on the check count, for sts_admin_console.js's reason: a section
  // that stops being called takes its assertions with it and the run still
  // says "passed".
  t.check(t.passed() >= 300, 'the file made at least 300 passing checks',
          'made ' + t.passed());
  log.debug("Leaving run().");
}

module.exports = {
  name: 'gnap_httpsig',
  describe: 'GNAP httpsig: RFC 9421 Appendix B vectors, RFC 9530 digests, ' +
            'RFC 8941 parsing, refusals and key rotation',
  run: run
};
