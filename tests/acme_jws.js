'use strict';
//
// File: acme_jws.js
//
// ===========================================================================
// WHAT AN ACME REQUEST IS ON THE WIRE, AND WHERE ACME'S STATE LIVES — IN
// PROCESS (2026-09-13).
//
// `tests/vendored/sts_acme_enrollment.js` drives the ACME server over HTTPS
// with an independent client, and `tests/acme_protocol.js` drives its handlers
// in a child process. What is here is what neither can ask, because every
// request either of them sends is one a CONFORMING client builds:
//
//   * THE ENVELOPE'S REFUSALS ONE BY ONE — a flattened JWS with an unprotected
//     header, padding in base64url, a non-canonical encoding, `crit`, a private
//     member in `jwk`, a key that does not fit `alg`, an RSA key under 2048
//     bits — each by the ACME error type and the STS code it answers, since
//     over HTTP most of them are one `malformed`.
//   * TWO EXTERNAL ANSWERS, the only kind that mean anything about a
//     derivation: RFC 7638 section 3.1's thumbprint, which an ACME account IS,
//     and RFC 9773 section 4.1's certificate identifier.
//   * THE REPLAY-NONCE'S PROOF — a nonce from another realm, a flipped byte, a
//     wrong version, and an expired one, which needs a chosen instant no
//     request may name.
//   * THE EXTERNAL ACCOUNT BINDING'S FIVE SHAPES, and its MAC refused with a
//     wrong key — which over HTTP is indistinguishable from an unknown kid.
//   * REALM ISOLATION OF THE SEVEN STORES, both ways and across a purge,
//     against a realm created here and removed in a `finally`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const jws = require('../acme/acme_jws');
const store = require('../acme/acme_store');

const log = require('bunyan').createLogger({ name: 'acme_jws',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === 'string' ? value
                                               : JSON.stringify(value))
    .toString('base64url');
}

// A flattened JWS signed by node's crypto with `alg`, for the verifier.
function signed(alg, privateKey, header, payload) {
  log.debug("Entering signed(). alg=" + alg);
  const protectedB64 = b64u(header);
  const payloadB64 = payload === null ? '' : b64u(payload);
  const input = Buffer.from(protectedB64 + '.' + payloadB64, 'ascii');
  let signature = null;
  if (alg === 'EdDSA') {
    signature = nodeCrypto.sign(null, input, privateKey);
  } else if (/^ES/.test(alg)) {
    signature = nodeCrypto.sign('sha' + alg.slice(2), input,
      { key: privateKey, dsaEncoding: 'ieee-p1363' });
  } else if (/^PS/.test(alg)) {
    signature = nodeCrypto.sign('sha' + alg.slice(2), input,
      { key: privateKey, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: Number(alg.slice(2)) / 8 });
  } else {
    signature = nodeCrypto.sign('sha' + alg.slice(2), input, privateKey);
  }
  log.debug("Leaving signed().");
  return { protected: protectedB64, payload: payloadB64,
           signature: signature.toString('base64url') };
}

function publicJwk(publicKey) {
  log.debug("Entering publicJwk().");
  const full = publicKey.export({ format: 'jwk' });
  const out = { kty: full.kty };
  ['n', 'e', 'crv', 'x', 'y'].forEach(function (name) {
    if (full[name] !== undefined) {
      out[name] = full[name];
    }
  });
  log.debug("Leaving publicJwk().");
  return out;
}

// ---------------------------------------------------------------------------
function checkEnvelope(t) {
  log.debug("Entering checkEnvelope().");
  t.log.info('=== A. the flattened JWS and its members ===');
  t.check(jws.isJoseJson('application/jose+json'), 'the media type is ' +
          'accepted');
  t.check(jws.isJoseJson('Application/JOSE+JSON; charset=utf-8'),
          'with its parameters compared away and its case folded');
  t.check(!jws.isJoseJson('application/json') && !jws.isJoseJson(''),
          'and application/json or nothing is not it');

  t.check(jws.decodeB64url('QQ', false) !== null, 'strict base64url decodes');
  t.equal(jws.decodeB64url('QQ==', false), null, 'padding is refused');
  t.equal(jws.decodeB64url('Q+', false), null, 'the + alphabet is refused');
  t.equal(jws.decodeB64url('QQ QQ', false), null, 'whitespace is refused');
  t.equal(jws.decodeB64url('QR', false), null,
          'a NON-CANONICAL encoding (trailing bits set) is refused, so one ' +
          'value has one spelling');
  t.equal(jws.decodeB64url('', false), null, 'an empty value is refused ' +
          'where one is required');
  t.check(Buffer.isBuffer(jws.decodeB64url('', true)), 'and allowed for a ' +
          'payload');

  const ok = jws.parseBody(JSON.stringify({ protected: b64u({ a: 1 }),
                                            payload: '', signature: 'AAAA' }));
  t.check(ok.ok, 'a flattened JWS with an empty payload parses',
          JSON.stringify(ok).slice(0, 200));
  const cases = [
    ['not JSON', 'nope', 'STS-ACME-0012'],
    ['an array', '[]', 'STS-ACME-0012'],
    ['an unprotected header', JSON.stringify({ protected: b64u({}),
      payload: '', signature: 'AAAA', header: {} }), 'STS-ACME-0012'],
    ['the general serialization', JSON.stringify({ payload: '',
      signatures: [] }), 'STS-ACME-0012'],
    ['a polluting key', '{"protected":"e30","payload":"","signature":"AAAA",' +
      '"__proto__":{"x":1}}', 'STS-ACME-0012'],
    ['padded base64url', JSON.stringify({ protected: b64u({}) + '=',
      payload: '', signature: 'AAAA' }), 'STS-ACME-0013']
  ];
  cases.forEach(function (one) {
    const refused = jws.parseBody(one[1]);
    t.check(!refused.ok && refused.type === 'malformed' &&
            refused.code === one[2], 'a body that is ' + one[0] + ' is ' +
            'refused malformed with ' + one[2],
            JSON.stringify(refused).slice(0, 200));
  });

  const header = function (value) {
    return jws.parseProtectedHeader({ headerBytes: Buffer.from(
      JSON.stringify(value)) });
  };
  t.check(header({ alg: 'RS256', nonce: 'x', url: 'https://a/b' }).ok,
          'a protected header with alg, nonce and url parses');
  ['crit', 'b64', 'jku', 'x5u', 'x5c'].forEach(function (member) {
    const value = { alg: 'RS256', nonce: 'x', url: 'https://a/b' };
    value[member] = member === 'b64' ? false : ['x'];
    const refused = header(value);
    t.check(!refused.ok && refused.code === 'STS-ACME-0014',
            'a header carrying "' + member + '" is refused');
  });
  t.check(header({ alg: 'RS256', nonce: 'x' }).code === 'STS-ACME-0014',
          'a header with no url is refused');

  ['none', 'HS256', 'ES256K', 'ML-DSA-44', 'RS1'].forEach(function (alg) {
    const refused = jws.checkAlgorithm(alg);
    t.check(!refused.ok && refused.type === 'badSignatureAlgorithm' &&
            Array.isArray(refused.algorithms) &&
            refused.algorithms.indexOf('RS256') >= 0,
            '"' + alg + '" is badSignatureAlgorithm, with the supported list ' +
            '(RFC 8555 section 6.2)');
  });
  jws.ACCOUNT_ALGS.forEach(function (alg) {
    t.check(jws.checkAlgorithm(alg).ok, alg + ' is accepted');
  });
  log.debug("Leaving checkEnvelope().");
}

// ---------------------------------------------------------------------------
function checkKeysAndSignatures(t) {
  log.debug("Entering checkKeysAndSignatures().");
  t.log.info('=== B. account keys, RFC 7638, and the signature ===');
  // RFC 7638 section 3.1.
  const rfcKey = { kty: 'RSA', e: 'AQAB', alg: 'RS256', kid: '2011-04-29',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw' };
  const described = jws.checkAccountKey(rfcKey, 'RS256');
  t.check(described.ok, 'RFC 7638\'s example key is an acceptable account key',
          JSON.stringify(described).slice(0, 200));
  t.equal(described.thumbprint, 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
          'and its thumbprint is RFC 7638 section 3.1\'s published value');
  t.check(!described.jwk.alg && !described.jwk.kid,
          'the stored key keeps only the required public members');

  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const small = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  const withPrivate = rsa.privateKey.export({ format: 'jwk' });
  const refusedPrivate = jws.checkAccountKey(withPrivate, 'RS256');
  t.check(!refusedPrivate.ok && refusedPrivate.type === 'badPublicKey' &&
          /"d"/.test(refusedPrivate.detail),
          'a jwk carrying the private exponent is badPublicKey, naming "d"');
  t.check(jws.checkAccountKey(publicJwk(small.publicKey), 'RS256').type ===
          'badPublicKey', 'an RSA key of 1024 bits is badPublicKey');
  t.check(!jws.checkAccountKey(publicJwk(ec.publicKey), 'ES384').ok,
          'a P-256 key does not fit ES384');
  t.check(!jws.checkAccountKey(publicJwk(ec.publicKey), 'RS256').ok,
          'an EC key does not fit RS256');
  t.check(jws.checkAccountKey(publicJwk(ed.publicKey), 'EdDSA').ok,
          'an Ed25519 key fits EdDSA');
  const offCurve = Object.assign({}, publicJwk(ec.publicKey),
    { y: publicJwk(ec.publicKey).x });
  t.check(!jws.checkAccountKey(offCurve, 'ES256').ok,
          'an EC point that is not on its curve does not load');
  t.check(jws.algorithmFitsKey('PS256', publicJwk(rsa.publicKey)) &&
          !jws.algorithmFitsKey('ES256', publicJwk(rsa.publicKey)) &&
          jws.algorithmFitsKey('ES256', publicJwk(ec.publicKey)) &&
          !jws.algorithmFitsKey('ES512', publicJwk(ec.publicKey)),
          'a kid request\'s alg is held to the stored key\'s type and curve');

  const url = 'https://acme.test/enroll/acme/new-order';
  [['RS256', rsa], ['PS256', rsa], ['ES256', ec], ['EdDSA', ed]].forEach(
    function (pair) {
      const alg = pair[0];
      const flat = signed(alg, pair[1].privateKey, { alg: alg, url: url },
                          { identifiers: [] });
      const parts = jws.parseBody(JSON.stringify(flat));
      t.check(parts.ok && jws.verifyFlattened(parts, publicJwk(
        pair[1].publicKey), alg).ok, 'an ' + alg + ' flattened JWS verifies');
      const tampered = Object.assign({}, flat,
        { payload: b64u({ identifiers: [1] }) });
      const tParts = jws.parseBody(JSON.stringify(tampered));
      const refused = jws.verifyFlattened(tParts, publicJwk(
        pair[1].publicKey), alg);
      t.check(!refused.ok && refused.code === 'STS-ACME-0024',
              'and with its payload changed it is refused STS-ACME-0024');
    });
  const getFlat = signed('ES256', ec.privateKey, { alg: 'ES256', url: url },
                         null);
  const getParts = jws.parseBody(JSON.stringify(getFlat));
  t.check(jws.verifyFlattened(getParts, publicJwk(ec.publicKey), 'ES256').ok,
          'a POST-as-GET (empty payload) verifies like any other JWS');
  t.equal(jws.readPayload(getParts).value, null, 'and reads as a null payload');
  // The one line common/crypto.js grew for it must not reach anybody else.
  const stsCrypto = require('../common/crypto');
  let refusedEmpty = false;
  try {
    stsCrypto.verifyCompactJws(getFlat.protected + '..' + getFlat.signature,
                               publicJwk(ec.publicKey),
                               { algorithms: ['ES256'] });
  } catch (e) {
    log.debug("Caught in checkKeysAndSignatures(): " +
              ((e && e.message) || e));
    refusedEmpty = /payload/.test(e.message);
  }
  t.check(refusedEmpty, 'without emptyPayload, verifyCompactJws still ' +
          'refuses an empty payload, as it did before ACME needed one');
  const asRs = jws.verifyFlattened(getParts, publicJwk(ec.publicKey), 'RS256');
  t.check(!asRs.ok, 'an ES256 signature is not accepted under the name RS256');
  const arrayPayload = jws.parseBody(JSON.stringify(signed('ES256',
    ec.privateKey, { alg: 'ES256', url: url }, [1, 2])));
  t.check(jws.readPayload(arrayPayload).code === 'STS-ACME-0025',
          'a payload that is not a JSON object is refused STS-ACME-0025');
  log.debug("Leaving checkKeysAndSignatures().");
}

// ---------------------------------------------------------------------------
function checkNonces(t) {
  log.debug("Entering checkNonces().");
  t.log.info('=== C. the Replay-Nonce carries its own proof ===');
  const nonce = jws.mintNonce('realm-a-' + RUN, 300);
  const checked = jws.checkNonce(nonce, 'realm-a-' + RUN);
  t.check(checked.ok && /^[A-Za-z0-9_-]{22}$/.test(checked.id),
          'a nonce this service minted checks, and names its random part',
          JSON.stringify(checked));
  t.check(/^[A-Za-z0-9_-]+$/.test(nonce), 'and is base64url (section 6.5.1)');
  t.equal(jws.checkNonce(nonce, 'realm-b-' + RUN).reason, 'forged',
          'the same nonce presented to another realm is not one it issued');
  const bytes = Buffer.from(nonce, 'base64url');
  bytes[10] ^= 1;
  t.equal(jws.checkNonce(bytes.toString('base64url'), 'realm-a-' + RUN).reason,
          'forged', 'a nonce with one bit of its random part flipped is ' +
          'refused');
  const version = Buffer.from(nonce, 'base64url');
  version[0] = 2;
  t.equal(jws.checkNonce(version.toString('base64url'), 'realm-a-' + RUN)
          .reason, 'malformed', 'a nonce of another version is malformed');
  t.equal(jws.checkNonce(undefined, 'realm-a-' + RUN).reason, 'malformed',
          'no nonce is malformed');
  const short = jws.mintNonce('realm-a-' + RUN, 1);
  const realNow = Date.now;
  let expired = null;
  try {
    Date.now = function () { return realNow() + 5000; };
    expired = jws.checkNonce(short, 'realm-a-' + RUN);
  } finally {
    Date.now = realNow;
  }
  t.equal(expired && expired.reason, 'expired',
          'a nonce presented after its lifetime is expired, not forged');
  const before = process.env[jws.NONCE_SECRET_VAR];
  t.check(!!before && before.length >= 40, 'the MAC secret is in the ' +
          'environment, where a forked request worker inherits it');
  log.debug("Leaving checkNonces().");
}

// ---------------------------------------------------------------------------
function checkEab(t) {
  log.debug("Entering checkEab().");
  t.log.info('=== D. the External Account Binding (RFC 8555 7.3.4) ===');
  const account = nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'prime256v1' });
  const other = nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'prime256v1' });
  const jwk = publicJwk(account.publicKey);
  const thumbprint = jws.checkAccountKey(jwk, 'ES256').thumbprint;
  const url = 'https://acme.test/enroll/acme/new-account';
  const hmacKey = nodeCrypto.randomBytes(32);
  const mac = function (header, payload, key) {
    const p = b64u(header);
    const body = b64u(payload);
    return { protected: p, payload: body,
             signature: nodeCrypto.createHmac('sha256', key || hmacKey)
               .update(p + '.' + body).digest('base64url') };
  };
  const good = mac({ alg: 'HS256', kid: 'eab-kid', url: url }, jwk);
  const parsed = jws.parseEab(good, url, thumbprint);
  t.check(parsed.ok && parsed.kid === 'eab-kid', 'a well-formed binding ' +
          'parses and names its kid', JSON.stringify(parsed).slice(0, 200));
  t.check(jws.verifyEabMac(parsed, hmacKey), 'and its MAC verifies with the ' +
          'key issued under that kid');
  t.check(!jws.verifyEabMac(parsed, nodeCrypto.randomBytes(32)),
          'and not with any other key');
  const shapes = [
    ['a nonce in its header', mac({ alg: 'HS256', kid: 'k', url: url,
                                    nonce: 'n' }, jwk)],
    ['a url other than newAccount', mac({ alg: 'HS256', kid: 'k',
                                          url: url + 'x' }, jwk)],
    ['a signature algorithm in place of a MAC', mac({ alg: 'RS256', kid: 'k',
                                                      url: url }, jwk)],
    ['another key as its payload', mac({ alg: 'HS256', kid: 'k', url: url },
                                       publicJwk(other.publicKey))],
    ['no kid', mac({ alg: 'HS256', url: url }, jwk)]
  ];
  shapes.forEach(function (one) {
    const refused = jws.parseEab(one[1], url, thumbprint);
    t.check(!refused.ok && refused.code === 'STS-ACME-0032',
            'a binding with ' + one[0] + ' is refused STS-ACME-0032',
            JSON.stringify(refused).slice(0, 200));
  });
  t.check(!jws.parseEab('a string', url, thumbprint).ok,
          'a binding that is not an object is refused');

  t.check(jws.checkContacts(['mailto:admin@example.com']).ok,
          'a mailto: contact is accepted');
  t.equal(jws.checkContacts(['https://example.com']).type,
          'unsupportedContact', 'an https: contact is unsupportedContact');
  t.equal(jws.checkContacts(['mailto:a@example.com?subject=x']).type,
          'invalidContact', 'a mailto: with header fields is invalidContact');
  t.equal(jws.checkContacts(['mailto:a@example.com,b@example.com']).type,
          'invalidContact', 'a mailto: with two recipients is invalidContact');
  log.debug("Leaving checkEab().");
}

// ---------------------------------------------------------------------------
function checkIdentifiers(t) {
  log.debug("Entering checkIdentifiers().");
  t.log.info('=== E. RFC 9773 certificate identifiers, identifier values ===');
  // RFC 9773 section 4.1's worked example.
  const aki = Buffer.from('69885B6B87464041E1B37B847BA0AE2CDE01C8D4', 'hex');
  t.equal(jws.certIdOf(aki, '87654321'), 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE',
          'the certificate identifier is RFC 9773 section 4.1\'s example, ' +
          'with the serial\'s leading zero octet because its high bit is set');
  t.equal(jws.certIdOf(aki, '0087654321'),
          'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE',
          'however the serial was written');
  const parsed = jws.parseCertId('aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
  t.check(parsed && parsed.serialHex === '87654321' &&
          parsed.aki.equals(aki), 'and parses back to the AKI and the serial');
  t.equal(jws.parseCertId('aYhba4dGQEHhs3uEe6CuLN4ByNQ'), null,
          'an identifier with no dot is refused');
  t.equal(jws.parseCertId('a=.b'), null, 'and one that is not base64url');

  t.equal(jws.normalIdentifier('dns', 'WWW.Example.COM'), 'www.example.com',
          'a dns identifier is lower-cased');
  t.equal(jws.normalIdentifier('dns', '*.example.com'), '*.example.com',
          'a wildcard is kept as written');
  t.equal(jws.normalIdentifier('dns', '10.0.0.1'), '',
          'an address is not a dns identifier (RFC 8738 section 3)');
  t.equal(jws.normalIdentifier('ip', '2001:DB8::1'), '2001:db8::1',
          'an IPv6 address is an ip identifier');
  t.equal(jws.normalIdentifier('ip', 'example.com'), '',
          'a name is not an ip identifier');
  t.equal(jws.normalIdentifier('email', 'Alice <a@example.com>'), '',
          'an email identifier is an addr-spec with no display name ' +
          '(RFC 8823 section 3.1)');
  t.equal(jws.normalIdentifier('permanent-identifier', 'ok\x00no'), '',
          'a permanent-identifier with a control character is refused');
  log.debug("Leaving checkIdentifiers().");
}

// ---------------------------------------------------------------------------
function checkRealmIsolation(t) {
  log.debug("Entering checkRealmIsolation().");
  t.log.info('=== F. ACME\'s stores are per realm, and purged with it ===');
  const id = 'acmejws-' + RUN;
  realms.create({ id: id, name: 'ACME store isolation' });
  let made = null;
  try {
    realms.run(realms.get(id), function () {
      made = store.createAccount({ jwk: { kty: 'EC' }, thumbprint: 'tp-' + RUN,
                                   entry: { kind: 'person', id: 'x' } });
      const authz = store.createAuthorization({ accountId: made.id });
      const order = store.createOrder(made, { authorizationIds: [authz.id],
        expires: new Date(Date.now() + 60000).toISOString() });
      store.recordCertificate({ accountId: made.id, orderId: order.id,
                                serialHex: 'abc' + RUN, certId: 'cid-' + RUN,
                                entry: { kind: 'person', id: 'x' } });
      t.check(store.spendNonce('nonce-' + RUN, 9999999999), 'a nonce is ' +
              'spent once in the realm');
      t.check(!store.spendNonce('nonce-' + RUN, 9999999999), 'and refused ' +
              'the second time there');
      made.order = order.id;
      made.authz = authz.id;
    });
    t.check(!store.getAccount(made.id) && !store.accountByThumbprint('tp-' +
            RUN), 'the account is invisible in the default realm, by id and ' +
            'by key');
    t.check(!store.getOrder(made.order) && !store.getAuthorization(made.authz),
            'and so are its order and authorization');
    t.check(!store.certificateByCertId('cid-' + RUN) &&
            !store.certificateBySerial('abc' + RUN),
            'and its certificate, by renewal identifier and by serial');
    t.check(store.spendNonce('nonce-' + RUN, 9999999999),
            'and a nonce spent in the realm is still unspent here');
    realms.run(realms.get(id), function () {
      t.check(!!store.getAccount(made.id) && !!store.getOrder(made.order),
              'while the realm still holds all of it');
    });
  } finally {
    realms.remove(id);
  }
  realms.create({ id: id, name: 'ACME store isolation, again' });
  try {
    realms.run(realms.get(id), function () {
      t.check(!store.getAccount(made.id) && !store.getOrder(made.order) &&
              !store.certificateByCertId('cid-' + RUN) &&
              store.spendNonce('nonce-' + RUN, 9999999999),
              'a realm re-created with the same id inherits none of it');
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving checkRealmIsolation().");
}

// ---------------------------------------------------------------------------
// THE NONCE SECRET IS IN THE ENVIRONMENT BEFORE ANY WORKER IS FORKED
// (2026-09-13). `common/request_pool.js` forks EAGERLY, before the listener
// binds, and a forked worker inherits the environment it was forked with — so a
// secret generated on the first nonce would be one each worker generated for
// itself, and a nonce issued by one worker would be refused as forged by the
// next. A CHILD PROCESS with the variable removed, because in this process some
// earlier section has already generated one and the assertion would pass
// against the lazy version.
// ---------------------------------------------------------------------------
function checkSecretAtRequire(t) {
  log.debug("Entering checkSecretAtRequire().");
  const env = Object.assign({}, process.env);
  delete env.STS_ACME_NONCE_SECRET;
  delete env.CONFIG_FILE;
  env.STS_LOG_LEVEL = 'fatal';
  const out = require('child_process').spawnSync(process.execPath, ['-e',
    "require('./acme/acme_jws');" +
    "process.stdout.write('SECRET=' + (process.env.STS_ACME_NONCE_SECRET ? " +
    "'set' : 'unset'));process.exit(0);"],
    { cwd: require('path').join(__dirname, '..'), env: env,
      encoding: 'utf8', timeout: 60000 });
  t.check(/SECRET=set/.test(String(out.stdout)),
          'requiring acme/acme_jws.js puts the nonce secret into the ' +
          'environment, before any request and so before any worker is forked',
          String(out.stdout).slice(-200) + String(out.stderr).slice(-300));
  log.debug("Leaving checkSecretAtRequire().");
}

async function run(t) {
  log.debug("Entering run().");
  checkSecretAtRequire(t);
  checkEnvelope(t);
  checkKeysAndSignatures(t);
  checkNonces(t);
  checkEab(t);
  checkIdentifiers(t);
  checkRealmIsolation(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'acme_jws',
  describe: 'the ACME envelope read strictly — flattened JWS, headers, ' +
            'account keys against RFC 7638, the Replay-Nonce\'s MAC, the ' +
            'External Account Binding, RFC 9773 identifiers — and ACME\'s ' +
            'stores per realm',
  run: run
};
