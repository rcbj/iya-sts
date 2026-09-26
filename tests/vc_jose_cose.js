'use strict';
// ===========================================================================
// tests/vc_jose_cose.js — VC-JOSE-COSE ENVELOPES (#198, 2026-09-26).
//
// oid4vc/vc_jose_cose.ts secures and verifies credentials and presentations
// as vc+jwt / vp+jwt, vc+sd-jwt / vp+sd-jwt and vc+cose / vp+cose. Claims:
//
//   A. every form round-trips through its envelope, for a credential and a
//      presentation, with a P-256 key named by its did:key kid, and with a
//      caller-named public key.
//   B. the refusals, each a clause: a contradicting type header, a `vc` or
//      `vp` claim, an exp passed, a signature by another key, a private key
//      named as the verification method, a COSE value that is not base64,
//      an unknown data: media type. A missing typ is NOT a refusal (it is a
//      SHOULD); a string iat is a warning.
//   C. RFC 9901 section 7.1: nested and array-element Disclosures
//      reconstructed; an unreferenced Disclosure, a digest twice, a
//      Disclosure naming `_sd`, a claim already present and an unsupported
//      _sd_alg each refused.
// ===========================================================================

const crypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'vc_jose_cose_test',
  level: process.env.LOG_LEVEL || 'info' });

const V2 = 'https://www.w3.org/ns/credentials/v2';

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === 'string' ? value
                                               : JSON.stringify(value))
    .toString('base64url');
}

function digest(disclosure) {
  log.debug("Entering digest().");
  log.debug("Leaving digest().");
  return crypto.createHash('sha256').update(disclosure, 'ascii')
    .digest('base64url');
}

async function run(t) {
  log.debug("Entering run().");
  const jose = require('../oid4vc/vc_jose_cose');
  const di = require('../oid4vc/vc_data_integrity');
  const made = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicJwk = made.publicKey.export({ format: 'jwk' });
  const did = di.didKeyOf(publicJwk);
  const signer = { privateKey: made.privateKey, publicJwk: publicJwk,
                   kid: did + '#' + did.slice('did:key:'.length) };
  const vc = { '@context': [V2], type: ['VerifiableCredential'], issuer: did,
               credentialSubject: { id: 'did:example:subject',
                                    address: { street: '1 Main', city: 'X' },
                                    phones: ['1', '2'] } };
  const vp = { '@context': [V2], type: ['VerifiablePresentation'],
               holder: did };

  t.log.info('=== A. round trips ===');
  const forms = [['jwt', function (doc, kind) {
    return jose.secureJwt(doc, kind, signer);
  }], ['sdjwt', function (doc, kind) {
    return jose.secureSdJwt(doc, kind, signer,
      kind === 'vc' ? ['credentialSubject.address.street',
                       'credentialSubject.phones[1]'] : ['holder']);
  }], ['cose', function (doc, kind) {
    return jose.secureCose(doc, kind, signer);
  }]];
  for (const form of forms) {
    for (const kind of ['vc', 'vp']) {
      const secured = await form[1](kind === 'vc' ? vc : vp, kind);
      const env = jose.envelope(form[0], kind, secured);
      const r = await jose.verifyEnvelope(env, kind, {});
      t.check(r.ok && r.kind === kind,
              'A1. ' + form[0] + ' ' + kind + ' round-trips by its kid',
              JSON.stringify(r.errors));
      const named = await jose.verifyEnvelope(env, kind,
        { verificationMethod: { publicKeyJwk: publicJwk } });
      t.check(named.ok, 'A2. ' + form[0] + ' ' + kind + ' verifies by a ' +
              'caller-named public key');
      if (form[0] === 'sdjwt' && kind === 'vc') {
        t.check(r.document.credentialSubject.address.street === '1 Main' &&
                r.document.credentialSubject.phones[1] === '2' &&
                r.document._sd_alg === undefined,
                'A3. the disclosed members are back where they were');
      }
    }
  }

  t.log.info('=== B. refusals ===');
  const token = await jose.secureJwt(vc, 'vc', signer);
  const reheader = function reheader(header, payload) {
    log.debug("Entering reheader().");
    const input = b64u(header) + '.' + b64u(payload);
    const sig = crypto.sign('sha256', Buffer.from(input), {
      key: made.privateKey, dsaEncoding: 'ieee-p1363' });
    log.debug("Leaving reheader().");
    return input + '.' + sig.toString('base64url');
  };
  const bad = await jose.verify('jwt', reheader({ alg: 'ES256',
    kid: signer.kid, typ: 'bad+typ' }, vc), 'vc', {});
  t.check(!bad.ok, 'B1. a contradicting typ is refused', bad.errors[0]);
  const noTyp = await jose.verify('jwt', reheader({ alg: 'ES256',
    kid: signer.kid }, vc), 'vc', {});
  t.check(noTyp.ok, 'B2. a missing typ (a SHOULD) is not refused',
          JSON.stringify(noTyp.errors));
  const claims = await jose.verify('jwt', reheader({ alg: 'ES256',
    kid: signer.kid, typ: 'vc+jwt' }, Object.assign({ vc: {} }, vc)), 'vc',
    {});
  t.check(!claims.ok && /MUST NOT/.test(claims.errors.join(' ')),
          'B3. a vc claim is refused');
  const expired = await jose.verify('jwt', reheader({ alg: 'ES256',
    kid: signer.kid, typ: 'vc+jwt' }, Object.assign({ exp: 1734397450 }, vc)),
    'vc', {});
  t.check(!expired.ok && /expired/.test(expired.errors.join(' ')),
          'B4. an exp passed is refused');
  const iat = await jose.verify('jwt', reheader({ alg: 'ES256',
    kid: signer.kid, typ: 'vc+jwt' }, Object.assign({ iat: '2010-01-01' },
                                                    vc)), 'vc', {});
  t.check(iat.ok && /iat/.test(iat.warnings.join(' ')),
          'B5. a string iat is a warning, not a refusal');
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .publicKey.export({ format: 'jwk' });
  const wrongKey = await jose.verify('jwt', token, 'vc',
    { verificationMethod: { publicKeyJwk: other } });
  t.check(!wrongKey.ok, 'B6. a signature by another key is refused');
  const priv = await jose.verify('jwt', token, 'vc', { verificationMethod:
    { publicKeyJwk: made.privateKey.export({ format: 'jwk' }) } });
  t.check(!priv.ok && /private/.test(priv.errors.join(' ')),
          'B7. a private key named as the verification method is refused');
  const cose = await jose.verify('cose', 'd2845856a40126036e', 'vc', {});
  t.check(!cose.ok, 'B8. a COSE value that is hex, not base64, is refused');
  const unknown = await jose.verifyEnvelope({ '@context': V2,
    type: 'EnvelopedVerifiableCredential', id: 'data:text/plain,hello' },
    'vc', {});
  t.check(!unknown.ok, 'B9. an unknown data: media type is refused');
  const asVp = await jose.verify('jwt', token, 'vp', {});
  t.check(!asVp.ok, 'B10. a credential offered as a presentation is ' +
          'refused');

  t.log.info('=== C. RFC 9901 section 7.1 ===');
  const d1 = b64u(['salt1', 'name', 'Alice']);
  const d2 = b64u(['salt2', 'second']);
  const payload = { _sd: [digest(d1)], list: ['first', { '...': digest(d2) }],
                    _sd_alg: 'sha-256' };
  const done = jose.processDisclosures(payload, [d1, d2]);
  t.check(done.name === 'Alice' && done.list.join(',') === 'first,second' &&
          done._sd === undefined,
          'C1. an object member and an array element are reconstructed');
  const withheld = jose.processDisclosures(payload, [d1]);
  t.check(withheld.list.length === 1,
          'C2. an array element not disclosed is removed');
  const throws = function throws(fn) {
    log.debug("Entering throws().");
    try {
      fn();
    } catch (e) {
      log.debug("Caught in throws(): " + ((e && e.message) || e));
      log.debug("Leaving throws(). It threw.");
      return true;
    }
    log.debug("Leaving throws(). It did not.");
    return false;
  };
  t.check(throws(function () {
    return jose.processDisclosures({ _sd: [] }, [d1]);
  }), 'C3. a Disclosure no digest references is refused');
  t.check(throws(function () {
    return jose.processDisclosures({ _sd: [digest(d1)], again: {
      _sd: [digest(d1)] } }, [d1]);
  }), 'C4. a digest appearing twice is refused');
  const sdName = b64u(['salt3', '_sd', 'x']);
  t.check(throws(function () {
    return jose.processDisclosures({ _sd: [digest(sdName)] }, [sdName]);
  }), 'C5. a Disclosure naming _sd is refused');
  t.check(throws(function () {
    return jose.processDisclosures({ name: 'Bob', _sd: [digest(d1)] }, [d1]);
  }), 'C6. a Disclosure of a claim already present is refused');
  t.check(throws(function () {
    return jose.processDisclosures({ _sd_alg: 'sha-512' }, []);
  }), 'C7. an unsupported _sd_alg is refused');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_jose_cose',
  describe: 'VC-JOSE-COSE: vc+jwt, vc+sd-jwt and vc+cose and the vp forms ' +
            'round-trip; the type, claim, time, key and encoding refusals; ' +
            'RFC 9901 section 7.1 in full',
  run: run
};
