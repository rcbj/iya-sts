'use strict';
//
// File: assertion_grant.js
//
// ===========================================================================
// RFC 7521 AND RFC 7523: THE ENCRYPTION MATRIX, AND THE TWO CLAIMS THAT LOOK
// ALIKE AND ARE NOT.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The whole flow is asserted over HTTP by
// `tests/vendored/sts_jwt_bearer_grant.js` — a real assertion at a real token
// endpoint, the refusals included. What is HERE is what that job cannot ask.
//
//   * **THE ENCRYPTION MATRIX.** RFC 7523 section 3 claim 10 lets an assertion
//     be encrypted, and this service decrypts sixteen key management
//     algorithms against six content encryption ones. Ninety-six combinations
//     is ninety-six token requests over HTTP; here it is a loop, and what is
//     being checked is `crypto.js`'s two halves agreeing rather than anything
//     about a request. **A wrap and an unwrap that disagree produce a
//     ciphertext that parses perfectly and an authentication tag that does not
//     verify** — the failure this file exists to make loud.
//
//   * **`PROTOCOL_CLAIMS` IS A LIST AND NOT A BEHAVIOUR.** What must never
//     reach an issued token from an assertion is a list of twelve names, and
//     the assertion that it holds all twelve is about the list. Over HTTP the
//     only observable is that a particular claim did not appear, which is one
//     name at a time and is satisfied by a token with no claims on it at all.
//
//   * **THE TWO DOORS ARE ONE READER.** `client_auth.js` (section 2.2) and
//     this module (section 2.1) read the same registered key material and
//     unwrap the same encryption. That they call ONE function rather than
//     holding two copies is a property of the modules; over HTTP two copies
//     that agree today are indistinguishable from one.
//
// **NEITHER FILE IMPLIES THE OTHER**, which is the split `tests/totp.js` and
// `sts_portal_totp.js` already have: this one says the arithmetic is right and
// that one says the doors are wired up.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const stsCrypto = require('../common/crypto');
const assertionGrant = require('../oauth-oidc/assertion_grant');
const pki = require('../common/pki');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'assertion_grant',
  level: process.env.LOG_LEVEL || 'info' });

const ENCS = ['A128GCM', 'A192GCM', 'A256GCM',
              'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'];

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the JWE tables say what this service can actually do ===');

  // The metadata is built from these lists, so a list that promised an
  // algorithm the code cannot perform would be the worst shape a metadata
  // member can have — a client author reads it as a capability. The tables are
  // asserted against RFC 7518 section 4's own membership rather than against
  // themselves.
  const wanted = ['RSA-OAEP-256', 'RSA-OAEP', 'ECDH-ES', 'ECDH-ES+A128KW',
                  'ECDH-ES+A192KW', 'ECDH-ES+A256KW', 'A128KW', 'A192KW',
                  'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'dir',
                  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW',
                  'PBES2-HS512+A256KW'];
  wanted.forEach(function (alg) {
    t.check(stsCrypto.JWE_ALGS.indexOf(alg) >= 0 &&
            stsCrypto.JWE_DECRYPT_ALGS.indexOf(alg) >= 0,
            alg + ' is in BOTH the encrypt and the decrypt table');
  });
  t.check(stsCrypto.JWE_ALGS.indexOf('RSA1_5') < 0,
          'RSA1_5 IS NOT, and that is a decision rather than a gap: RFC 8017 ' +
          'deprecated PKCS#1 v1.5 encryption, and implementing it safely ' +
          'means making an unwrap failure indistinguishable from every later ' +
          'failure — a property of a whole code path rather than of one ' +
          'function');
  t.check(stsCrypto.JWE_ASYMMETRIC_ALGS.every(function (alg) {
            return stsCrypto.JWE_SYMMETRIC_ALGS.indexOf(alg) < 0;
          }),
          'the asymmetric and symmetric lists do not overlap — which is what ' +
          'lets a caller narrow to the family it holds a key for');
  t.equal(stsCrypto.JWE_ASYMMETRIC_ALGS.length +
          stsCrypto.JWE_SYMMETRIC_ALGS.length,
          stsCrypto.JWE_ALGS.length,
          'and between them they are the whole table, so a third family ' +
          'added later cannot be silently absent from both');

  t.log.info('=== every algorithm against every enc, both ways ===');
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const PLAINTEXT = '{"probe":"an assertion would be here"}';
  let combinations = 0;
  ENCS.forEach(function (enc) {
    const spec = stsCrypto.JWE_ENCS[enc];
    stsCrypto.JWE_ALGS.forEach(function (alg) {
      let encOpts;
      let decOpts;
      if (stsCrypto.JWE_RSA_ALGS.indexOf(alg) >= 0) {
        encOpts = { jwk: rsa.publicKey.export({ format: 'jwk' }) };
        decOpts = { privateKey: rsa.privateKey };
      } else if (stsCrypto.JWE_ECDH_ALGS.indexOf(alg) >= 0) {
        encOpts = { jwk: ec.publicKey.export({ format: 'jwk' }) };
        decOpts = { privateKey: ec.privateKey };
      } else if (alg === 'dir') {
        // The shared key IS the content encryption key, so its length is
        // decided by `enc` — 32 bytes for A128CBC-HS256, because a CBC-HMAC
        // CEK is twice the AES key size.
        const key = nodeCrypto.randomBytes(spec.cekBytes);
        encOpts = { secret: key };
        decOpts = { secret: key };
      } else if (/^PBES2/.test(alg)) {
        // A PASSWORD, whose UTF-8 octets are the input. Not base64-decoded on
        // the way in however much it looks like base64 — RFC 7518 section 4.8
        // is explicit, and guessing there produces a key that is wrong and
        // plausible.
        encOpts = { secret: 'correct horse battery staple' };
        decOpts = { secret: 'correct horse battery staple' };
      } else {
        const bits = Number(alg.match(/A(\d+)/)[1]);
        const key = nodeCrypto.randomBytes(bits / 8);
        encOpts = { secret: key };
        decOpts = { secret: key };
      }
      const compact = stsCrypto.encryptJweCompact(PLAINTEXT,
        Object.assign({ alg: alg, enc: enc }, encOpts));
      const back = stsCrypto.decryptJweCompact(compact,
        Object.assign({ allowedEnc: [enc] }, decOpts));
      if (back.plaintext !== PLAINTEXT) {
        throw new Error(alg + '/' + enc + ' did not round-trip');
      }
      combinations += 1;
    });
  });
  t.equal(combinations, stsCrypto.JWE_ALGS.length * ENCS.length,
          'every key management algorithm round-trips against every content ' +
          'encryption algorithm — ' + combinations + ' combinations, which ' +
          'is the whole table and not a sample');

  t.log.info('=== the three refusals a wrong key produces ===');
  const gcmkw = stsCrypto.encryptJweCompact(PLAINTEXT,
    { alg: 'A256GCMKW', enc: 'A256GCM', secret: nodeCrypto.randomBytes(32) });
  try {
    stsCrypto.decryptJweCompact(gcmkw, { allowedEnc: ['A256GCM'],
                                         secret: nodeCrypto.randomBytes(32) });
    t.check(false, 'a wrong AES-GCM key should not unwrap');
  } catch (e) {
    t.check(/could not be unwrapped/.test(e.message),
            'a wrong key for an AES-GCM key wrap is refused by the ' +
            'authentication tag rather than yielding plausible garbage',
            e.message.slice(0, 90));
  }
  try {
    stsCrypto.decryptJweCompact(gcmkw, { allowedEnc: ['A256GCM'] });
    t.check(false, 'a symmetric alg with no secret should be refused');
  } catch (e) {
    t.check(/SHARED SECRET/.test(e.message),
            'and a symmetric algorithm with NO secret is told which kind of ' +
            'key it needed, rather than being handed a private key that ' +
            'cannot possibly work', e.message.slice(0, 90));
  }
  try {
    stsCrypto.decryptJweCompact(
      Buffer.from(JSON.stringify({ alg: 'RSA1_5', enc: 'A128GCM' }))
        .toString('base64url') + '.a.b.c.d',
      { allowedEnc: ['A128GCM'], privateKey: rsa.privateKey });
    t.check(false, 'RSA1_5 should be refused');
  } catch (e) {
    t.check(/deliberately/.test(e.message),
            'RSA1_5 is refused BY NAME with the reason, rather than falling ' +
            'off the end of the table — a caller that sent one has an ' +
            'implementation that offers it and needs to know this is a ' +
            'refusal and not an omission', e.message.slice(0, 90));
  }

  t.log.info('=== PBES2 against RFC 7517 Appendix C\'s published vector ===');
  // **THE ROUND TRIP ABOVE CANNOT SEE THIS AND THAT IS THE POINT.** The wrap
  // and the unwrap derive their key through ONE function, so they agree with
  // each other whatever the salt is built from — a mutant that dropped the
  // algorithm name from the salt input passed every one of the ninety-six
  // combinations above. RFC 7518 section 4.8.1.1 says the salt is
  // `alg || 0x00 || p2s`, and leaving the alg out makes ONE PASSWORD PRODUCE
  // THE SAME KEY FOR THREE DIFFERENT KEY SIZES.
  //
  // So this is checked against an EXTERNAL answer: the vector in RFC 7517
  // Appendix C, which is the same kind of evidence `tests/totp.js` uses and is
  // the only kind that means anything about a derivation.
  const vector = stsCrypto.pbes2Key('PBES2-HS256+A128KW',
    'Thus from my lips, by yours, my sin is purged.',
    Buffer.from('2WCTcJZ1Rvd_CJuJripQ1w', 'base64url'), 4096);
  t.equal(JSON.stringify(Array.from(vector)),
          JSON.stringify([110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116,
                          233, 170, 14, 24, 75]),
          'the derived key is RFC 7517 Appendix C\'s sixteen bytes exactly');
  const other = stsCrypto.pbes2Key('PBES2-HS384+A192KW',
    'Thus from my lips, by yours, my sin is purged.',
    Buffer.from('2WCTcJZ1Rvd_CJuJripQ1w', 'base64url'), 4096);
  t.check(Buffer.compare(vector, other.subarray(0, 16)) !== 0,
          'and the SAME password under a different PBES2 algorithm derives a ' +
          'different key, which is what the algorithm name in the salt is for');

  t.log.info('=== a PBES2 iteration count a caller chose is bounded ===');
  const pbes = stsCrypto.encryptJweCompact(PLAINTEXT,
    { alg: 'PBES2-HS256+A128KW', enc: 'A128GCM', secret: 'pw' });
  const header = JSON.parse(Buffer.from(pbes.split('.')[0], 'base64url')
    .toString('utf8'));
  t.check(header.p2s && header.p2c > 0,
          'a PBES2 JWE carries its salt and iteration count in the header ' +
          '(RFC 7518 section 4.8.1.1)', 'p2c=' + header.p2c);
  // ONE ABOVE THE CEILING rather than two billion. The assertion is the same
  // and the mutation round is what decides the number: with the ceiling
  // removed, a two-billion-iteration derivation does not fail the test, it
  // hangs the run — and a mutant that cannot be run is a mutant that has not
  // been checked.
  const greedy = [Buffer.from(JSON.stringify(
    Object.assign({}, header, { p2c: 1000001 })), 'utf8').toString('base64url')]
    .concat(pbes.split('.').slice(1)).join('.');
  try {
    stsCrypto.decryptJweCompact(greedy, { allowedEnc: ['A128GCM'],
                                          secret: 'pw' });
    t.check(false, 'two billion iterations should be refused');
  } catch (e) {
    t.check(/at most/.test(e.message),
            'and a count above the ceiling is REFUSED rather than performed. ' +
            'RFC 7518 section 4.8.1.2 leaves the ceiling to the recipient, ' +
            'and a caller choosing this number is a caller choosing how long ' +
            'this process blocks', e.message.slice(0, 90));
  }

  t.log.info('=== an assertion may be encrypted, and cty is checked ===');
  // A REAL JWS SHAPE and not three random strings joined by dots. Whether the
  // plaintext of a nested JWT is signed is decided by the protected header
  // parsing as JSON with an `alg` in it — RFC 7515 section 3.1 — because a
  // JSON claims object carrying two dotted values splits into exactly three
  // parts and would otherwise be read as a JWS. The signature is not verified
  // here; `unwrapAssertion()`'s job ends at "this is a signed document", and
  // `verify()` is what checks it.
  const inner = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' }),
                            'utf8').toString('base64url') + '.' +
                Buffer.from(JSON.stringify({ iss: 'https://a.example' }),
                            'utf8').toString('base64url') + '.' +
                nodeCrypto.randomBytes(32).toString('base64url');
  const nested = stsCrypto.encryptJweCompact(inner,
    { alg: 'A256KW', enc: 'A256GCM', secret: Buffer.alloc(32, 7), cty: 'JWT' });
  const opened = assertionGrant.unwrapAssertion(nested,
                                                { secret: Buffer.alloc(32,
                                                                       7) });
  t.check(opened.ok && opened.encrypted && opened.jws === inner,
          'a five-part assertion is decrypted and the JWS inside it comes ' +
          'back', opened.description || '');
  t.equal(opened.encryption.alg, 'A256KW',
          'and the encryption is REPORTED, so the console and the delegation ' +
          'register can say the assertion arrived encrypted');

  const plain = assertionGrant.unwrapAssertion(inner, {});
  t.check(plain.ok && !plain.encrypted && plain.jws === inner,
          'a THREE-part assertion comes back untouched — every client that ' +
          'authenticated with one before encryption existed is on exactly ' +
          'the path it was');

  // **THE FIXTURE THAT MATTERS CARRIES DOTS**, because a plaintext with none
  // is refused by a dot count and this assertion has to be about more than
  // that: `{"iss":"https://issuer.example.test/x"}` splits into exactly three
  // parts, which is how the first version of this check read an unsigned
  // claims object as a JWS.
  const notJws = stsCrypto.encryptJweCompact(
    '{"iss":"https://issuer.example.test/x","sub":"alice"}',
    { alg: 'A256KW', enc: 'A256GCM', secret: Buffer.alloc(32, 7), cty: 'JWT' });
  const refused = assertionGrant.unwrapAssertion(notJws,
                                                 { secret: Buffer.alloc(32,
                                                                        7) });
  t.check(!refused.ok && /section 3 claim 9/.test(refused.description),
          'a JWE whose plaintext is NOT a signed JWT is refused citing the ' +
          'claim it breaks: encryption does not stand in for a signature, ' +
          'because an encrypted document says nothing about who wrote it',
          refused.description);

  const wrongCty = stsCrypto.encryptJweCompact(inner,
    { alg: 'A256KW', enc: 'A256GCM', secret: Buffer.alloc(32, 7),
      cty: 'application/json' });
  const ctyRefused = assertionGrant.unwrapAssertion(wrongCty,
    { secret: Buffer.alloc(32, 7) });
  t.check(!ctyRefused.ok && /cty/.test(ctyRefused.description),
          'and a nested JWT declaring a `cty` that is not JWT is refused ' +
          'rather than handed to a JWS parser that would report a base64 ' +
          'problem three frames away', ctyRefused.description);

  t.log.info('=== the claims that may never reach an issued token ===');
  ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'scope', 'cnf', 'typ',
   'azp', 'client_id'].forEach(function (name) {
    t.check(assertionGrant.PROTOCOL_CLAIMS.indexOf(name) >= 0,
            '`' + name + '` is stripped before an assertion\'s claims are ' +
            'copied onto a token');
  });
  const carried = assertionGrant.extraClaimsFrom({
    iss: 'x', sub: 'y', aud: 'z', exp: 1, nbf: 1, iat: 1, jti: 'j',
    scope: 'openid', cnf: {}, typ: 'JWT', azp: 'a', client_id: 'c',
    department: 'engineering', employee_number: 4711
  });
  t.equal(Object.keys(carried).sort().join(','),
          'department,employee_number',
          'so a statement a trusted party made about somebody is carried and ' +
          'the profile\'s own furniture is not — an `exp` copied off an ' +
          'assertion would be a token lifetime chosen by whoever signed it');

  t.log.info('=== the two doors are ONE reader ===');
  // `client_auth.js`'s `keysFrom()` DELEGATES to this one — it is a one-line
  // forward — so the two halves of RFC 7523 cannot come to hold two answers to
  // "which of this party's keys may sign". Asserted on the BEHAVIOUR of both
  // rather than on the identity of the function, because a delegation that
  // grew a branch would still be one function and would still be wrong.
  // The second key is UNREADABLE rather than merely odd: an EC key with no `y`
  // is a JWK node refuses outright. A `kty: 'RSA'` with a short modulus is NOT
  // — base64url decodes to bytes and node builds a key out of them — which is
  // how the first version of this assertion passed against a reader that
  // refused nothing.
  const jwks = JSON.stringify({ keys: [
    Object.assign(rsa.publicKey.export({ format: 'jwk' }), { kid: 'k1' }),
    { kty: 'EC', crv: 'P-256', x: 'AA', kid: 'broken' }
  ] });
  const read = assertionGrant.keysFrom(jwks);
  t.equal((read.keys || []).length, 1,
          'ONE UNREADABLE KEY DOES NOT SPOIL THE SET. A JWKS commonly ' +
          'carries a key this version of node cannot build beside ones it ' +
          'can, and refusing the whole document would make a party unable to ' +
          'sign with the key that was fine');
  t.check(assertionGrant.keysFrom('{ not json').error,
          'a JWKS that is not JSON is REFUSED rather than throwing — an ' +
          'exception here would surface at the token endpoint as a 500 with ' +
          'nothing in it about keys');
  t.check(assertionGrant.keysFrom('{"keys":[]}').error,
          'and so is one with no keys in it');
  const akp = assertionGrant.keysFrom(JSON.stringify({ keys: [
    { kty: 'AKP', alg: 'ML-DSA-44', pub: 'AAAA', kid: 'pq1' }] }));
  t.equal((akp.keys || []).length, 1,
          'AN RFC 9964 POST-QUANTUM KEY SURVIVES THE READ. node\'s ' +
          'createPublicKey() has no idea what an AKP is and must not be ' +
          'asked — the JWK travels WHOLE to the verifier, which routes it to ' +
          'pq_jose.js. Without that branch the eleven post-quantum ' +
          'algorithms this service advertises for assertions would be ' +
          'advertised and unverifiable');

  t.log.info('=== the settings, read where they are used ===');
  t.check(assertionGrant.enabled(),
          'the grant is ON by default — the metadata advertises it only ' +
          'while it is, because a grant_types_supported member is a promise');
  t.check(assertionGrant.requiresRegisteredIssuer(),
          'AND THE ISSUER MUST BE DECLARED, which is one of only two ' +
          'refusals in this service that default to on. An assertion IS the ' +
          'whole authorization for this grant: no browser, no password, no ' +
          'consent step, so accepting one from anybody would mean anybody ' +
          'who can reach this port getting an access token as anybody');
  t.check(assertionGrant.maxLifetimeSeconds() > 0,
          'and a lifetime ceiling is in force by default (RFC 7521 section ' +
          '5.2 leaves the number to the server)',
          String(assertionGrant.maxLifetimeSeconds()) + 's');

  t.log.info('=== a certificate this service did not issue is not evidence ' +
             '===');
  log.debug("Leaving run().");
  // The `x5c` path both halves of RFC 7523 share. Asserted here rather than
  // over HTTP because the interesting input is a certificate nobody can be
  // made to send: a perfectly valid self-signed one, presented as though it
  // were the whole story.
  //
  // **IT IS BUILT IN THE AMBIENT REALM AND CLEARED AGAIN**, which is forced
  // rather than convenient: `keyFromChain()` checks a path against the realm
  // the REQUEST arrived in — that is the whole point of a per-realm CA — so a
  // hierarchy built under a name of this file's own would be checked against
  // the default realm's, which has none. Cleared in a `finally` for this
  // directory's process-wide-state rule: `run.js` runs every file in one
  // process, and a CA left standing changes what a later file's realm holds.
  return (async function () {
    const built = await pki.buildChain(undefined, {});
    t.check(built.ok, 'a hierarchy exists to check a path against');
    const issued = await pki.issueSigningKeyPair(undefined,
                                                 { identifier: 'signer' });
    const good = await assertionGrant.keyFromChain(
      { x5c: issued.issued.publicJwk.x5c });
    t.check(good && good.key,
            'a chain this service ISSUED yields a key, which is the point of ' +
            'holding a certificate authority at all');

    const selfPair = nodeCrypto.generateKeyPairSync('rsa',
                                                    { modulusLength: 2048 });
    const self = stsCrypto.selfSignedRsaCertificate({
      privateKeyPem: selfPair.privateKey.export({ type: 'pkcs8',
                                                  format: 'pem' }),
      publicKeyPem: selfPair.publicKey.export({ type: 'spki', format: 'pem' }),
      subject: 'CN=forged'
    });
    const forged = await assertionGrant.keyFromChain({
      x5c: [stsCrypto.stripPem(self.certPem || self.pem || '')] });
    t.check(forged && forged.error,
            'AND A CERTIFICATE THAT ARRIVES WITH THE SIGNATURE DOES NOT. ' +
            'Taking a public key out of an unchecked x5c would be verifying ' +
            'a signature against a key the signature came with, which proves ' +
            'nothing at all', (forged || {}).error);
    t.check(/chain to this realm/.test((forged || {}).error || ''),
            'and the refusal says what was missing rather than reporting a ' +
            'bad signature', (forged || {}).error);

    const none = await assertionGrant.keyFromChain({});
    t.check(none === null,
            'a header with NO x5c answers null rather than an error — most ' +
            'assertions carry none, and an error there would make the ' +
            'ordinary case look like a refusal');
  })().finally(function () {
    // See the note above: the ambient realm is shared by every file in this
    // run, so what this section built has to go.
    pki.clearChain(undefined);
  });
}

module.exports = {
  name: 'assertion_grant',
  describe: 'RFC 7521 and RFC 7523: the whole JWE matrix round-tripped both ' +
            'ways, the PBES2 ceiling, the nested-JWT checks, the twelve ' +
            'claims that may never reach an issued token, one JWKS reader ' +
            'for both halves of the profile, and that a certificate ' +
            'presented WITH a signature is not evidence unless this service ' +
            'issued it',
  run: run
};
