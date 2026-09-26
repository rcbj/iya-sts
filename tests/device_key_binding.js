'use strict';
//
// File: device_key_binding.js
//
// ===========================================================================
// RFC 8628 AND OPENID CONNECT KEY BINDING (#150, 2026-09-26), in process.
//
//   1. the device codes: a user code normalised, pending then slow_down with
//      the interval grown by five, answered once, redeemed once, another
//      client's poll finding nothing, expiry, and the sweep;
//   2. DPoP: an ML-DSA-44 proof verified and bound to its AKP thumbprint, an
//      SLH-DSA proof refused, an AKP key carrying `priv` refused, and an AKP
//      key naming another parameter set refused;
//   3. Key Binding: c_s256 required where bound_key was granted and ignored
//      where it was not, and a bound ID Token presented without a proof from
//      its key refused.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const config = require('../common/config');
const stsCrypto = require('../common/crypto');
const device = require('../oauth-oidc/device_authorization');
const dpop = require('../oauth-oidc/dpop');
const oauth2 = require('../oauth-oidc/oauth2');

const log = require('bunyan').createLogger({ name: 'device_key_binding',
  level: process.env.LOG_LEVEL || 'info' });

const HTU = 'https://sts.test/oauth2/token';

// A DeviceAuthorization with the test's clock and a claim that is once.
function instance(clock) {
  log.debug("Entering instance().");
  const taken = new Set();
  const deps = Object.assign(device.DeviceAuthorization.defaultDeps(), {
    now: function () {
      return clock.now;
    },
    claims: {
      claim: function (opts) {
        const ok = !taken.has(opts.value);
        taken.add(opts.value);
        return Promise.resolve(ok ? { ok: true } :
                                    { ok: false, reason: 'taken' });
      }
    }
  });
  log.debug("Leaving instance().");
  return new device.DeviceAuthorization(deps);
}

function proof(alg, extra, jwkOver) {
  log.debug("Entering proof().");
  const pq = /^(ML|SLH)-DSA/.test(alg);
  const pair = pq ? null :
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  let jwk;
  let sign;
  if (/^ML-DSA/.test(alg)) {
    const k = crypto.generateKeyPairSync(alg.toLowerCase());
    jwk = { kty: 'AKP', alg: alg, pub: k.publicKey.export({ format: 'jwk' })
      .pub };
    sign = function (input) {
      return crypto.sign(null, input, k.privateKey);
    };
  } else if (pq) {
    jwk = { kty: 'AKP', alg: alg, pub: 'AAAA' };
    sign = function () {
      return Buffer.alloc(32);
    };
  } else {
    const j = pair.publicKey.export({ format: 'jwk' });
    jwk = { kty: 'EC', crv: j.crv, x: j.x, y: j.y };
    sign = function (input) {
      return crypto.sign('sha256', input, { key: pair.privateKey,
                                            dsaEncoding: 'ieee-p1363' });
    };
  }
  jwk = Object.assign(jwk, jwkOver || {});
  const header = { typ: 'dpop+jwt', alg: alg, jwk: jwk };
  const payload = Object.assign({ jti: crypto.randomBytes(12)
    .toString('base64url'), htm: 'POST', htu: HTU,
    iat: Math.floor(Date.now() / 1000) }, extra || {});
  const input = Buffer.from(JSON.stringify(header)).toString('base64url') +
    '.' + Buffer.from(JSON.stringify(payload)).toString('base64url');
  log.debug("Leaving proof().");
  return { jwt: input + '.' + sign(Buffer.from(input, 'ascii'))
    .toString('base64url'), jwk: jwk };
}

async function run(t) {
  log.debug("Entering run().");
  config.setOverride('oauth2.deviceAuthorization', true);
  try {
    await body(t);
  } finally {
    config.clearOverride('oauth2.deviceAuthorization');
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  t.log.info('=== 1. the device codes ===');
  const clock = { now: 1000000000000 };
  const d = instance(clock);
  const made = d.create('dev-client', 'The Television', 'openid', '');
  const typed = made.userCode.slice(0, 4).toLowerCase() + ' - ' +
    made.userCode.slice(4);
  t.check(/^[A-Z]{8}$/.test(made.userCode) &&
          /^[A-Za-z0-9_-]{43}$/.test(made.deviceCode) &&
          d.byUserCode(typed) && d.byUserCode(typed).deviceCode ===
            made.deviceCode,
          '1a. a 256-bit device code and an eight-letter user code, found ' +
          'however it is typed (section 6.1)');
  const initial = Number(made.interval);
  const first = d.poll(made.deviceCode, 'dev-client');
  const fast = d.poll(made.deviceCode, 'dev-client');
  t.check(first.state === 'pending' && fast.state === 'slow_down' &&
          fast.record.interval === initial + 5 &&
          d.poll(made.deviceCode, 'another').state === 'unknown',
          '1b. pending, then slow_down with the interval grown by five; ' +
          'another client finds nothing', JSON.stringify(fast.record));
  const answered = d.answer(typed, 'dev-alice', true,
    { acr: 'pwd', amr: ['pwd'], authTime: 12345, sessionId: 'sid-1' });
  t.check(answered.ok && answered.record.approval.sessionId === 'sid-1' &&
          !d.answer(typed, 'dev-alice', true, {}).ok &&
          !d.byUserCode(typed),
          '1c. approved with what the session proved, and once');
  const approved = d.poll(made.deviceCode, 'dev-client');
  t.check(approved.state === 'approved' &&
          await d.redeem(approved.record) &&
          !(await d.redeem(approved.record)) &&
          d.poll(made.deviceCode, 'dev-client').state === 'redeemed',
          '1d. approved, redeemed once');
  const late = d.create('dev-client', '', 'openid', '');
  clock.now += 3600 * 1000;
  t.check(d.poll(late.deviceCode, 'dev-client').state === 'expired' &&
          !d.byUserCode(late.userCode),
          '1e. past its lifetime, expired');
  clock.now += 3 * 3600 * 1000;
  const swept = d.sweep();
  t.check(d.poll(made.deviceCode, 'dev-client').state === 'unknown' &&
          /removed/.test(swept.summary),
          '1f. the sweep removes what finished long ago', swept.summary);

  t.log.info('=== 2. DPoP keys ===');
  const ml = proof('ML-DSA-44');
  const mlChecked = dpop.verifyProof(ml.jwt, { htm: 'POST', htu: HTU });
  t.check(mlChecked.ok && mlChecked.jkt === stsCrypto.jwkThumbprint(ml.jwk) &&
          dpop.SIGNING_ALGS.indexOf('ML-DSA-87') >= 0,
          '2a. an ML-DSA-44 proof verifies and binds to its AKP thumbprint',
          JSON.stringify(mlChecked).slice(0, 300));
  const slh = dpop.verifyProof(proof('SLH-DSA-SHA2-128s').jwt,
                               { htm: 'POST', htu: HTU });
  t.check(!slh.ok && dpop.SIGNING_ALGS.indexOf('SLH-DSA-SHA2-128s') < 0,
          '2b. SLH-DSA is not a DPoP algorithm');
  const priv = dpop.verifyProof(proof('ML-DSA-44', null, { priv: 'AAAA' })
    .jwt, { htm: 'POST', htu: HTU });
  const other = dpop.verifyProof(proof('ML-DSA-44', null,
                                       { alg: 'ML-DSA-65' }).jwt,
                                 { htm: 'POST', htu: HTU });
  t.check(!priv.ok && priv.errorCode === 'STS-OAUTH-0101' &&
          !other.ok && other.errorCode === 'STS-OAUTH-0102',
          '2c. an AKP key with priv, or naming another parameter set, is ' +
          'refused', JSON.stringify([priv.errorCode, other.errorCode]));

  t.log.info('=== 3. Key Binding ===');
  const code = 'a-code-' + crypto.randomBytes(8).toString('hex');
  const hash = crypto.createHash('sha256').update(code, 'ascii')
    .digest('base64url');
  const withHash = { claims: { c_s256: hash } };
  const wrongHash = { claims: { c_s256: 'nope' } };
  const server = oauth2;
  const refusal = function (scope, pr) {
    return server.boundKeyProofRefusal(scope, code, pr);
  };
  t.check(refusal('openid', null) === null &&
          refusal('openid bound_key', withHash) === null &&
          refusal('openid bound_key', null).code === 'STS-OAUTH-0702' &&
          refusal('openid bound_key', wrongHash).code === 'STS-OAUTH-0703',
          '3a. c_s256 is required and checked where bound_key was granted');
  const jwk = ml.jwk;
  const jkt = stsCrypto.jwkThumbprint(jwk);
  const bound = { sub: 'x', cnf: { jwk: jwk } };
  t.check(server.boundIdTokenRefusal({ sub: 'x' }, '') === null &&
          server.boundIdTokenRefusal(bound, jkt) === null &&
          server.boundIdTokenRefusal(bound, '').code === 'STS-OAUTH-0707' &&
          server.boundIdTokenRefusal(bound, 'another').code ===
            'STS-OAUTH-0707',
          '3b. a bound ID Token needs a proof from the key it names');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'device_key_binding',
  describe: 'RFC 8628 device codes and OpenID Connect Key Binding (#150): ' +
            'the codes\' life, ML-DSA DPoP keys, c_s256 and section 7',
  run: run
};
