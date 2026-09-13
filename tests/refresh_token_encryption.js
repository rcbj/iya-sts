'use strict';
//
// File: refresh_token_encryption.js
//
// ===========================================================================
// EVERY REFRESH TOKEN IS A SIGNED JWT ENCRYPTED TO ITS OWN REALM (2026-09-12).
//
// `oauth-oidc/refresh_token_crypto.js` argues the design. What is held here:
//
//   1. the settings table's enum lists ARE `common/crypto.js`'s JWE tables —
//      `config.js` cannot require that module, so they are written out twice
//      and this is what stops the copy drifting;
//   2. every (alg, enc) pair the JWE module implements seals and opens —
//      sixteen key management algorithms by six content encryptions — as a
//      nested JWT naming the realm key it used;
//   3. the refusals, each with its code: an unencrypted refresh token, a
//      tampered one, one sealed under ANOTHER realm's keys, and a JWE whose
//      content is not a signed JWT;
//   4. a change of algorithm strands no token already issued;
//   5. the keys travel: serialised and restored with the key set, counted by
//      the enrichment rule, and backfilled into a set written before them;
//   6. THE ENDPOINTS, in a child process on an ephemeral port: the token
//      endpoint hands out a JWE, the refresh grant redeems it, introspection
//      and revocation read it, the SIGNED JWT inside it is refused on its own
//      at both, and a token minted in one realm is refused in another.
//
// **SECTION 6 IS IN A CHILD** for `tests/oauth_oid4vc_hardcoded.js`'s reason:
// loading the whole protocol stack into `run.js`'s one process builds a
// certificate authority and registers every route on the shared app, which
// changes what later files see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const ROOT = path.join(__dirname, '..');

const config = require('../common/config');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const realms = require('../common/realms');
const helpers = require('../common/helpers');
const keystore = require('../common/keystore');
const rt = require('../oauth-oidc/refresh_token_crypto');

// A structurally valid JWS — the module encrypts and decrypts bytes and never
// verifies, so a real signature is not what these sections are about.
const INNER = [Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url'),
               Buffer.from('{"jti":"rt-probe","typ":"Refresh"}').toString('base64url'),
               'c2lnbmF0dXJl'].join('.');

function headerOf(compact) {
  return JSON.parse(Buffer.from(String(compact).split('.')[0], 'base64url').toString('utf8'));
}

function codeThrown(fn) {
  try {
    fn();
    return '(nothing thrown)';
  } catch (e) {
    return errorCodes.codeOf(e) || ('(uncoded: ' + e.message + ')');
  }
}

function settingRow(key) {
  return config.SETTINGS.filter(function (row) {
    return row.key === key;
  })[0] || null;
}

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RT_ROOT;
  const OUT = process.env.RT_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail === undefined ? '' : String(detail) });
  }
  function post(port, urlPath, form) {
    return new Promise(function (resolve) {
      const body = new URLSearchParams(form).toString();
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath, method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(body) } }, function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // Not JSON; the raw text is kept for the detail.
            json = null;
          }
          resolve({ status: res.statusCode, text: text, json: json });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realmsMod = require(ROOT_DIR + '/common/realms');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const client = { client_id: 'rt-client', client_secret: 'rt-client-secret-0123456789' };
    const registration = { identifier: 'rt-client', protocols: ['oauth2'],
      fields: { oauthClientId: 'rt-client', oauthClientSecret: client.client_secret,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password', 'refresh_token'] } };
    ldap.createUser('rt-alice', { invent: false });
    applications.createApplication(registration);
    realmsMod.create({ id: 'rtrealm' });
    realmsMod.run(realmsMod.get('rtrealm'), function () {
      ldap.createUser('rt-alice', { invent: false });
      applications.createApplication(registration);
    });

    const issue = function (prefix) {
      return post(port, prefix + '/oauth2/token', Object.assign({
        grant_type: 'password', username: 'rt-alice', password: 'anything',
        scope: 'openid offline_access' }, client));
    };

    let r = await issue('');
    const refresh = r.json && r.json.refresh_token;
    note(r.status === 200 && typeof refresh === 'string' &&
         refresh.split('.').length === 5,
         '6a. the token endpoint hands out a refresh token that is a five-part JWE',
         r.status + ' ' + String(refresh).split('.').length + ' part(s)');
    note(r.json && String(r.json.access_token || '').split('.').length === 3,
         '6b. and the access token beside it is still a plain JWS',
         String(r.json && r.json.access_token).split('.').length);

    const ins = await post(port, '/oauth2/introspect', { token: refresh });
    note(ins.json && ins.json.active === true && ins.json.token_type === 'refresh_token' &&
         ins.json.username === 'rt-alice',
         '6c. introspection opens it: active, a refresh_token, for the right person',
         ins.text.slice(0, 200));

    const inner = require(ROOT_DIR + '/oauth-oidc/refresh_token_crypto').open(refresh);
    const plain = await post(port, '/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: inner }, client));
    note(plain.status === 400 && plain.json && plain.json.error === 'invalid_grant',
         '6d. the SIGNED JWT inside it, presented on its own, is refused as invalid_grant',
         plain.status + ' ' + plain.text.slice(0, 200));
    const plainIns = await post(port, '/oauth2/introspect', { token: inner });
    note(plainIns.json && plainIns.json.active === false,
         '6e. and introspection calls that unencrypted refresh token inactive',
         plainIns.text.slice(0, 120));

    const redeemed = await post(port, '/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: refresh }, client));
    const next = redeemed.json && redeemed.json.refresh_token;
    note(redeemed.status === 200 && redeemed.json && redeemed.json.access_token,
         '6f. the refresh grant decrypts it and issues', redeemed.status + ' ' +
         redeemed.text.slice(0, 160));
    note(typeof next === 'string' && next.split('.').length === 5 && next !== refresh,
         '6g. and the refresh token it hands back is encrypted too',
         String(next).split('.').length + ' part(s)');

    const tampered = refresh.split('.');
    tampered[3] = Buffer.from('not the ciphertext at all').toString('base64url');
    const bad = await post(port, '/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: tampered.join('.') }, client));
    note(bad.status === 400 && bad.json && bad.json.error === 'invalid_grant',
         '6h. a tampered refresh token is invalid_grant', bad.status + ' ' + bad.text.slice(0, 160));

    const other = await issue('/realm/rtrealm');
    const otherRefresh = other.json && other.json.refresh_token;
    const across = await post(port, '/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: otherRefresh }, client));
    note(other.status === 200 && typeof otherRefresh === 'string' && across.status === 400 &&
         across.json && across.json.error === 'invalid_grant',
         '6i. a refresh token minted in another realm does not open in this one',
         other.status + ' / ' + across.status + ' ' + across.text.slice(0, 160));
    const home = await post(port, '/realm/rtrealm/oauth2/token', Object.assign({
      grant_type: 'refresh_token', refresh_token: otherRefresh }, client));
    note(home.status === 200, '6j. while it redeems in the realm that minted it',
         home.status + ' ' + home.text.slice(0, 160));

    if (next) {
      await post(port, '/oauth2/revoke', { token: next });
      const revoked = await post(port, '/oauth2/token', Object.assign({
        grant_type: 'refresh_token', refresh_token: next }, client));
      note(revoked.status === 400,
           '6k. revocation reads an encrypted refresh token: once revoked it no longer redeems',
           revoked.status + ' ' + revoked.text.slice(0, 160));
    }

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the endpoint half threw', detail: e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  // -------------------------------------------------------------------------
  t.log.info('=== 1. the settings table is the JWE module\'s table ===');
  const algRow = settingRow('oauth2.refreshTokenEncryptionAlg');
  const encRow = settingRow('oauth2.refreshTokenEncryptionEnc');
  t.check(!!algRow && JSON.stringify((algRow.enumValues || []).slice().sort()) ===
          JSON.stringify(stsCrypto.JWE_ALGS.slice().sort()),
          'oauth2.refreshTokenEncryptionAlg offers exactly common/crypto.js\'s JWE_ALGS',
          JSON.stringify(algRow && algRow.enumValues));
  t.check(!!encRow && JSON.stringify((encRow.enumValues || []).slice().sort()) ===
          JSON.stringify(Object.keys(stsCrypto.JWE_ENCS).sort()),
          'oauth2.refreshTokenEncryptionEnc offers exactly common/crypto.js\'s JWE_ENCS',
          JSON.stringify(encRow && encRow.enumValues));

  // -------------------------------------------------------------------------
  t.log.info('=== 2. every algorithm pair seals and opens ===');
  const keys = helpers.refreshTokenKeysFor();
  const failures = [];
  const kidsWrong = [];
  stsCrypto.JWE_ALGS.forEach(function (alg) {
    Object.keys(stsCrypto.JWE_ENCS).forEach(function (enc) {
      try {
        const sealed = rt.seal(INNER, null, { alg: alg, enc: enc });
        const header = headerOf(sealed);
        const kind = rt.kindOf(alg);
        const expectedKid = kind === 'secret' ? keys.secretKid : keys[kind].publicJwk.kid;
        if (header.alg !== alg || header.enc !== enc || header.cty !== 'JWT' ||
            header.kid !== expectedKid) {
          kidsWrong.push(alg + '/' + enc + ' ' + JSON.stringify(header));
        }
        if (rt.open(sealed) !== INNER) {
          failures.push(alg + '/' + enc + ' opened to something else');
        }
      } catch (e) {
        failures.push(alg + '/' + enc + ': ' + e.message);
      }
    });
  });
  t.check(!failures.length, 'all ' + stsCrypto.JWE_ALGS.length * 6 + ' (alg, enc) ' +
          'pairs round-trip', failures.slice(0, 8).join('; '));
  t.check(!kidsWrong.length, 'and every JWE is a nested JWT (cty JWT) naming the realm ' +
          'key of the right kind', kidsWrong.slice(0, 4).join('; '));
  t.check(rt.symmetricBytes('A128KW', 'A256GCM') === 16 &&
          rt.symmetricBytes('A256GCMKW', 'A128GCM') === 32 &&
          rt.symmetricBytes('dir', 'A256CBC-HS512') === 64 &&
          rt.symmetricBytes('dir', 'A128GCM') === 16,
          'a symmetric key is derived at exactly the size its algorithm needs');
  // NO TWO ALGORITHMS SHARE KEY BYTES — and the pairs chosen are the ones that
  // would: HKDF's output at 16 bytes is the PREFIX of its output at 32 under
  // the same info, so a derivation that left the algorithm out of `info` would
  // hand A128KW the first half of A256KW's key. It survived a mutation round
  // before this assertion existed.
  const k = function (alg, enc) {
    return rt.symmetricKeyFor(keys.secret, alg, enc).toString('hex');
  };
  t.check(k('A128KW', 'A128GCM') !== k('A128GCMKW', 'A128GCM') &&
          k('A128KW', 'A128GCM') !== k('dir', 'A128GCM') &&
          k('A256KW', 'A256GCM').indexOf(k('A128KW', 'A256GCM')) !== 0 &&
          k('A256KW', 'A128GCM') !== k('A256KW', 'A256GCM'),
          'no two (alg, enc) pairs derive the same key, or one key the prefix of another');

  // -------------------------------------------------------------------------
  t.log.info('=== 3. the refusals ===');
  t.equal(codeThrown(function () { rt.open(INNER); }), 'STS-OAUTH-0237',
          'an unencrypted refresh token is refused');
  t.equal(codeThrown(function () { rt.open('not.a.token.at.all.really'); }), 'STS-OAUTH-0238',
          'something that is not a JWE is refused');
  const sealed = rt.seal(INNER);
  const parts = sealed.split('.');
  parts[3] = Buffer.from('tampered ciphertext').toString('base64url');
  t.equal(codeThrown(function () { rt.open(parts.join('.')); }), 'STS-OAUTH-0238',
          'a tampered refresh token is refused');
  const notJwt = stsCrypto.encryptJweCompact('just some text', {
    alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT', jwk: keys.rsa.publicJwk });
  t.equal(codeThrown(function () { rt.open(notJwt); }), 'STS-OAUTH-0239',
          'a JWE whose content is not a signed JWT is refused');

  const realmA = 'rt-a-' + Date.now().toString(36);
  const realmB = 'rt-b-' + Date.now().toString(36);
  realms.create({ id: realmA });
  realms.create({ id: realmB });
  try {
    const setA = helpers.stsKeysFor.of(realmA);
    const setB = helpers.stsKeysFor.of(realmB);
    const kA = helpers.refreshTokenKeysFor(setA);
    const kB = helpers.refreshTokenKeysFor(setB);
    t.check(kA.rsa.publicJwk.kid !== kB.rsa.publicJwk.kid &&
            kA.ec.publicJwk.kid !== kB.ec.publicJwk.kid &&
            kA.secretKid !== kB.secretKid &&
            !Buffer.from(kA.secret).equals(Buffer.from(kB.secret)),
            'two realms hold different RSA keys, EC keys and secrets',
            [kA.rsa.publicJwk.kid, kB.rsa.publicJwk.kid].join(' / '));
    ['RSA-OAEP-256', 'ECDH-ES+A256KW', 'A256GCMKW', 'dir', 'PBES2-HS256+A128KW']
      .forEach(function (alg) {
        const inA = rt.seal(INNER, setA, { alg: alg, enc: 'A256GCM' });
        t.equal(codeThrown(function () { rt.open(inA, setB); }), 'STS-OAUTH-0238',
                alg + ': a token sealed in one realm does not open in another');
        t.check(rt.open(inA, setA) === INNER, alg + ': and opens in its own');
      });

    // -----------------------------------------------------------------------
    t.log.info('=== 5. the keys travel with the set ===');
    const blob = keystore.serialise(setA);
    t.check(!!(blob.refreshTokenEncKeys && blob.refreshTokenEncKeys.rsa &&
               /PRIVATE KEY/.test(blob.refreshTokenEncKeys.rsa.privateKeyPem) &&
               blob.refreshTokenEncKeys.secret),
            'the serialised set carries the refresh-token keys, secret included');
    const restored = keystore.deserialise(JSON.parse(JSON.stringify(blob)), require('crypto'));
    t.check(!!restored.refreshTokenEncKeys &&
            restored.refreshTokenEncKeys.rsa.publicJwk.kid === kA.rsa.publicJwk.kid &&
            Buffer.from(restored.refreshTokenEncKeys.secret).equals(Buffer.from(kA.secret)),
            'and come back through JSON with the same kid and the same secret bytes');
    const viaRestored = rt.seal(INNER, setA, { alg: 'A128KW', enc: 'A128CBC-HS256' });
    t.check(rt.open(viaRestored, { realm: realmA, refreshTokenEncKeys: restored.refreshTokenEncKeys }) === INNER,
            'a token sealed before a restore opens with the restored keys');
    const without = Object.assign({}, blob, { refreshTokenEncKeys: null });
    t.check(keystore.enriches(blob, without) === true && keystore.enriches(without, blob) === false,
            'the enrichment rule counts the refresh-token keys: a set gaining them enriches, ' +
            'losing them does not');
    // A realm NOBODY has made keys for, so the backfill takes its generating
    // branch rather than finding keys a process already holds — the first
    // version used realmB and passed with the assignment deleted.
    const legacy = { realm: 'rt-never-' + Date.now().toString(36), certB64: 'x' };
    const backfilled = helpers.refreshTokenKeysFor(legacy);
    t.check(!!(backfilled && backfilled.rsa && legacy.refreshTokenEncKeys === backfilled),
            'a key set written before the keys existed is backfilled');
  } finally {
    realms.remove(realmA);
    realms.remove(realmB);
  }

  // -------------------------------------------------------------------------
  t.log.info('=== 4. a change of algorithm strands nothing ===');
  const before = rt.seal(INNER);
  config.setOverride('oauth2.refreshTokenEncryptionAlg', 'A256KW');
  config.setOverride('oauth2.refreshTokenEncryptionEnc', 'A128CBC-HS256');
  try {
    const after = rt.seal(INNER);
    t.equal(headerOf(after).alg + '/' + headerOf(after).enc, 'A256KW/A128CBC-HS256',
            'a new token is sealed under the new setting');
    t.check(rt.open(before) === INNER,
            'and a token sealed under the old one still opens');
  } finally {
    config.clearOverride('oauth2.refreshTokenEncryptionAlg');
    config.clearOverride('oauth2.refreshTokenEncryptionEnc');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== 6. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'rt-enc-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', RT_ROOT: ROOT, RT_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its findings',
               'exit ' + result.status + ' ' + String(result.stderr || '').slice(-800))) {
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
}

module.exports = {
  name: 'refresh_token_encryption',
  describe: 'refresh tokens are signed JWTs encrypted to their own realm, under every ' +
            'JWE algorithm, and every reader decrypts first',
  run: run
};
