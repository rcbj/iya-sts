// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/token_exchange_assertions.js
//
// ===========================================================================
// AN ASSERTION FROM A DECLARED ISSUER, EXCHANGED (#114).
//
// RFC 8693 section 3 names `jwt`, `saml2` and `saml1` as token types, and
// `oauth-oidc/exchange_assertions.ts` accepts an RFC 7523 JWT, an RFC 7522
// SAML 2.0 assertion or a SAML 1.1 assertion signed by an issuer this realm
// DECLARED as a subject_token or an actor_token — verified by the assertion
// grant's own code, spent in the grant's own one-use history.
//
// Asserted at a real token endpoint, in a CHILD PROCESS (it flips
// `global.mode`, `public_clients_product.js`'s reason), in PRODUCT unless
// said:
//   1. a JWT from a declared issuer is exchanged, about the person it names;
//      one from an undeclared issuer is refused;
//   2. a SAML 2.0 assertion signed with the declared issuer's certificate is
//      exchanged; one signed with a certificate this realm's CA issued to
//      somebody else — which CHAINS — is refused;
//   3. a SAML 1.1 assertion is exchanged as `saml1`, and a SAML 2.0 one
//      declared as `saml1` is refused (STS-OAUTH-0797);
//   4. the audience: under `authorization-server` (the default) an assertion
//      addressed to a relying party registered here is refused (0796); under
//      `any-declared-relying-party` it is exchanged and the act says it was
//      FORWARDED; an unregistered audience is refused under both;
//   5. the SAML Recipient: under forwarding, a Recipient that is the
//      exchanging client's registered ACS is accepted, any other refused;
//   6. ONE HISTORY: a JWT spent at the jwt-bearer grant is refused at the
//      exchange, and an assertion spent at the exchange is refused there
//      again;
//   7. an assertion naming nobody the directory holds is refused (0798);
//   8. a PERSON as issuer exchanges an assertion about themselves and not
//      about somebody else;
//   9. an assertion as the actor_token: `act.sub` is the person it names;
//  10. DEVELOPMENT: an undeclared JWT is still exchanged unverified, as it
//      always was, while an undeclared SAML assertion is refused (there is
//      no unverified reading of XML to fall back on).
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'token_exchange_assertions',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.TEA_ROOT;
  const OUT = process.env.TEA_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const request = function (port, method, where, form) {
    return new Promise(function (resolve) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const req = http.request({ host: '127.0.0.1', port: port, path: where,
        method: method,
        headers: form ? { 'content-type': 'application/x-www-form-urlencoded',
                          'content-length': Buffer.byteLength(body) } : {} },
      function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = {};
          try {
            json = JSON.parse(text);
          } catch (e) {
            json = { parseError: e.message };
          }
          resolve({ status: res.statusCode, json: json, text: text });
        });
      });
      req.end(body);
    });
  };
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  };
  const claimsOf = function (jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                            .toString('utf8'));
  };
  const signJwt = function (claims, key, kid) {
    const input = b64u({ alg: 'RS256', typ: 'JWT', kid: kid }) + '.' +
                  b64u(claims);
    return input + '.' + crypto.sign('sha256', Buffer.from(input), key)
      .toString('base64url');
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const audit = require(ROOT + '/common/audit');
    const helpers = require(ROOT + '/common/helpers');
    const pki = require(ROOT + '/common/pki');
    const roles = require(ROOT + '/common/roles');
    const delegation = require(ROOT + '/common/delegation');
    const personAssertions = require(ROOT + '/common/person_assertions');
    const dir = require(ROOT + '/ldap/ldap_server');
    const signer = require(ROOT + '/tests/vendored/saml_xmldsig.js');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    // Where this server says its token endpoint and issuer are — an
    // assertion addressed to this authorization server names one of them.
    const discovery = await request(port, 'GET',
                                    '/.well-known/openid-configuration');
    const TOKEN = String(discovery.json.token_endpoint || '');
    const ISSUER = String(discovery.json.issuer || '');
    note(TOKEN && ISSUER, 'precondition: discovery names the token endpoint ' +
         'and the issuer', TOKEN + ' ' + ISSUER);

    const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    const T = { jwt: 'urn:ietf:params:oauth:token-type:jwt',
                saml2: 'urn:ietf:params:oauth:token-type:saml2',
                saml1: 'urn:ietf:params:oauth:token-type:saml1',
                access: 'urn:ietf:params:oauth:token-type:access_token' };
    const FRONT = 'https://tea-front.example';
    const FRONT_ACS = 'https://tea-front.example/saml/acs';
    const BACK = 'https://tea-back.example';
    const JWT_ISS = 'https://tea-jwt-idp.example';
    const SAML_ISS = 'https://tea-saml-idp.example';

    // --- the fixtures, made in DEVELOPMENT: product mode creates nothing
    // because it was named.
    if (!pki.hasChain()) {
      await pki.start({});
    }
    ['tea-alice', 'tea-carol', 'tea-dave'].forEach(function (name) {
      dir.createUser(name, { invent: false });
    });
    const confidential = function (identifier, fields) {
      return applications.createApplication({ identifier: identifier,
        protocols: ['oauth2', 'oidc'],
        fields: Object.assign({ oauthClientId: identifier,
          oauthClientSecret: identifier + '-secret-0123456789abcdef0123',
          oauthTokenEndpointAuthMethod: 'client_secret_post',
          oauthGrantType: ['client_credentials', EXCHANGE, JWT_BEARER],
          oauthAllowedScope: ['openid', 'api'] }, fields || {}) });
    };
    // The exchanging client, S for an assertion addressed to this server;
    // it delegates to R, which a person acting needs as well (#186).
    confidential('tea-client', { appAllowedToDelegateTo: ['tea-back'] });
    // A relying party an assertion can be FORWARDED from: it exchanges what
    // it was handed, and its ACS is a Recipient it may present.
    confidential('tea-front', { oauthAudience: [FRONT],
      samlAssertionConsumerService: [FRONT_ACS] });
    // R, which accepts dave as an actor (a person holding the actor role).
    confidential('tea-back', { oauthAudience: [BACK],
                               appAllowedToActOnBehalfOf: ['tea-dave'] });
    roles.write(String(config.value('delegation.actorRole')),
                { users: ['tea-dave'], groups: [] });

    // The declared JWT issuer: a key by value.
    const jwtKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = Object.assign(jwtKey.publicKey.export({ format: 'jwk' }),
                              { kid: 'tea-jwt-1', alg: 'RS256', use: 'sig' });
    applications.createApplication({ identifier: 'tea-jwt-idp',
      protocols: ['oauth2'],
      fields: { oauthAssertionIssuer: [JWT_ISS],
                oauthAssertionJwks: JSON.stringify({ keys: [jwk] }) } });
    // The declared SAML issuer: a certificate by value, issued by this
    // realm's CA so that the stranger below is a fair comparison.
    const samlPair = await pki.issueSigningKeyPair(undefined,
      { identifier: 'tea-saml-idp', purpose: 'saml' });
    const otherPair = await pki.issueSigningKeyPair(undefined,
      { identifier: 'tea-other', purpose: 'saml' });
    note(samlPair.ok && otherPair.ok, 'precondition: two RFC 7522 key ' +
         'pairs issued by this realm\'s CA',
         JSON.stringify([samlPair.errors, otherPair.errors]));
    applications.createApplication({ identifier: 'tea-saml-idp',
      protocols: ['oauth2'],
      fields: { oauthSamlAssertionIssuer: [SAML_ISS],
                oauthSamlAssertionSigningCertificate:
                  samlPair.issued.certificatePem } });
    // A PERSON who holds an RFC 7523 key pair of their own.
    const carolPair = await pki.issueSigningKeyPair(undefined,
      { identifier: 'tea-carol', purpose: 'jwt', subjectKind: 'person' });
    const carolWritten = carolPair.ok
      ? personAssertions.write('tea-carol', carolPair.issued, {})
      : { ok: false };
    note(carolWritten.ok, 'precondition: tea-carol holds an RFC 7523 key ' +
         'pair', JSON.stringify(carolWritten.errors || carolPair.errors));

    const aliceSub = helpers.subjectForName('tea-alice');
    const daveSub = helpers.subjectForName('tea-dave');
    const now = function () {
      return Math.floor(Date.now() / 1000);
    };
    const jti = function () {
      return 'tea-' + crypto.randomBytes(8).toString('hex');
    };
    const jwtAbout = function (sub, extra) {
      return signJwt(Object.assign({ iss: JWT_ISS, sub: sub, aud: TOKEN,
        iat: now(), exp: now() + 120, jti: jti() }, extra || {}),
      jwtKey.privateKey, 'tea-jwt-1');
    };
    const saml2About = function (subject, o, pair) {
      const options = o || {};
      const built = signer.buildAssertion(Object.assign({ issuer: SAML_ISS,
        subject: subject, audience: TOKEN, recipient: TOKEN }, options));
      const p = (pair || samlPair).issued;
      return signer.b64u(signer.sign(built, p.privateKeyPem,
                                     p.certificatePem));
    };
    const saml1About = function (subject, o) {
      const built = signer.buildAssertion11(Object.assign({ issuer: SAML_ISS,
        subject: subject, audience: TOKEN }, o || {}));
      return signer.b64u(signer.sign(built, samlPair.issued.privateKeyPem,
        samlPair.issued.certificatePem, { at: 'end' }));
    };
    const as = function (identifier) {
      return { client_id: identifier,
               client_secret: identifier + '-secret-0123456789abcdef0123' };
    };
    const exchange = function (client, token, type, extra) {
      return request(port, 'POST', '/oauth2/token', Object.assign({
        grant_type: EXCHANGE, subject_token: token, subject_token_type: type
      }, as(client), extra || {}));
    };
    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    const refused = function (r, code) {
      return r.status === 400 && r.json.error === 'invalid_request' &&
             !r.json.access_token && (!code || codeRecorded(code));
    };
    const show = function (r) {
      return r.status + ' ' + r.text.slice(0, 400);
    };
    const subOf = function (r) {
      return r.json.access_token ? claimsOf(r.json.access_token).sub : '';
    };
    const lastExchange = function () {
      return delegation.list().filter(function (row) {
        return /^oauth-/.test(row.type);
      })[0] || null;
    };

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('global.mode', 'product');
    try {
      // 1. JWT.
      let r = await exchange('tea-client', jwtAbout('tea-alice'), T.jwt);
      note(r.status === 200 && subOf(r) === aliceSub,
           '1a. a JWT from a DECLARED issuer is exchanged, about the person ' +
           'it names', show(r));
      const unknownKey = crypto.generateKeyPairSync('rsa',
                                                    { modulusLength: 2048 });
      r = await exchange('tea-client', signJwt({ iss: 'https://nobody.example',
        sub: 'tea-alice', aud: TOKEN, iat: now(), exp: now() + 120,
        jti: jti() }, unknownKey.privateKey, 'x'), T.jwt);
      note(refused(r), '1b. a JWT from an issuer nobody declared is refused ' +
           'invalid_request', show(r));

      // 2. SAML 2.0.
      r = await exchange('tea-client', saml2About('tea-alice'), T.saml2);
      const row = lastExchange();
      note(r.status === 200 && subOf(r) === aliceSub && row &&
           /SAML 2\.0 assertion/.test(JSON.stringify(row.consumed)),
           '2a. a SAML 2.0 assertion from the declared issuer is exchanged, ' +
           'and the act says what it consumed', show(r) + ' ' +
           JSON.stringify(row && row.consumed));
      r = await exchange('tea-client', saml2About('tea-alice', {}, otherPair),
                         T.saml2);
      note(refused(r), '2b. one signed with a certificate this realm\'s CA ' +
           'issued to SOMEBODY ELSE — it chains — is refused', show(r));

      // 3. SAML 1.1.
      r = await exchange('tea-client', saml1About('tea-alice'), T.saml1);
      note(r.status === 200 && subOf(r) === aliceSub,
           '3a. a SAML 1.1 assertion is exchanged as saml1', show(r));
      r = await exchange('tea-client', saml2About('tea-alice'), T.saml1);
      note(refused(r, 'STS-OAUTH-0797'), '3b. a SAML 2.0 assertion declared ' +
           'as saml1 is refused (0797)', show(r));
      r = await exchange('tea-client', saml1About('tea-alice', {
        method: 'urn:oasis:names:tc:SAML:1.0:cm:holder-of-key' }), T.saml1);
      note(refused(r) && /SAML:1\.0:cm:bearer/.test(r.text),
           '3c. a SAML 1.1 assertion with no bearer confirmation is refused, ' +
           'naming SAML 1.1\'s bearer method', show(r));

      // 4. The audience.
      r = await exchange('tea-front', jwtAbout('tea-alice', { aud: FRONT }),
                         T.jwt);
      note(refused(r, 'STS-OAUTH-0796'), '4a. authorization-server (the ' +
           'default): an assertion addressed to a relying party registered ' +
           'here is refused (0796)', show(r));
      config.setOverride('oauth2.tokenExchangeAudience',
                         'any-declared-relying-party');
      r = await exchange('tea-front', jwtAbout('tea-alice', { aud: FRONT }),
                         T.jwt);
      const forwarded = lastExchange();
      note(r.status === 200 && subOf(r) === aliceSub && forwarded &&
           /FORWARDED/.test(JSON.stringify(forwarded.consumed)),
           [].concat(claimsOf(r.json.access_token).aud).indexOf(FRONT) >= 0,
           '4b. any-declared-relying-party: the same assertion is exchanged ' +
           'by that relying party, for its own audience, and the act says ' +
           'it was FORWARDED',
           show(r) + ' ' + JSON.stringify(forwarded && forwarded.consumed));
      r = await exchange('tea-front', jwtAbout('tea-alice',
        { aud: 'https://unregistered.example' }), T.jwt);
      note(refused(r, 'STS-OAUTH-0796'), '4c. an audience nobody registered ' +
           'is refused under forwarding too', show(r));

      // 5. The SAML Recipient, under forwarding.
      r = await exchange('tea-front', saml2About('tea-alice',
        { audience: FRONT, recipient: FRONT_ACS }), T.saml2);
      note(r.status === 200, '5a. a forwarded SAML 2.0 assertion whose ' +
           'Recipient is the exchanging client\'s registered ACS is ' +
           'exchanged', show(r));
      r = await exchange('tea-front', saml2About('tea-alice',
        { audience: FRONT, recipient: 'https://elsewhere.example/acs' }),
      T.saml2);
      note(refused(r), '5b. and one whose Recipient is somebody else\'s is ' +
           'refused', show(r));
      config.clearOverride('oauth2.tokenExchangeAudience');
      r = await exchange('tea-front', saml2About('tea-alice',
        { recipient: FRONT_ACS }), T.saml2);
      note(refused(r), '5c. under authorization-server the ACS is not a ' +
           'Recipient this server accepts', show(r));

      // 6. One history.
      const once = jwtAbout('tea-alice');
      r = await request(port, 'POST', '/oauth2/token', Object.assign({
        grant_type: JWT_BEARER, assertion: once }, as('tea-client')));
      note(r.status === 200, 'precondition: the jwt-bearer grant spends a ' +
           'declared JWT', show(r));
      r = await exchange('tea-client', once, T.jwt);
      note(refused(r) && /used/.test(r.json.error_description || ''),
           '6a. ONE HISTORY: that JWT is refused at the exchange', show(r));
      const twice = saml2About('tea-alice');
      r = await exchange('tea-client', twice, T.saml2);
      const second = await exchange('tea-client', twice, T.saml2);
      note(r.status === 200 && refused(second),
           '6b. a SAML assertion is exchanged once and refused the second ' +
           'time', show(second));

      // 7. Nobody.
      r = await exchange('tea-client', jwtAbout('tea-nobody-' + jti()), T.jwt);
      note(r.status === 400 && !r.json.access_token,
           '7. an assertion naming somebody the directory does not hold ' +
           'is refused in product', show(r) + ' 0798=' +
           codeRecorded('STS-OAUTH-0798'));

      // 8. A person as issuer.
      const carol = carolPair.issued;
      const carolKey = crypto.createPrivateKey(carol.privateKeyPem);
      r = await exchange('tea-client', signJwt({ iss: 'tea-carol',
        sub: 'tea-carol', aud: TOKEN, iat: now(), exp: now() + 120,
        jti: jti() }, carolKey, carol.kid), T.jwt);
      note(r.status === 200 && subOf(r) === helpers.subjectForName('tea-carol'),
           '8a. a PERSON holding a key pair exchanges an assertion about ' +
           'themselves', show(r));
      r = await exchange('tea-client', signJwt({ iss: 'tea-carol',
        sub: 'tea-alice', aud: TOKEN, iat: now(), exp: now() + 120,
        jti: jti() }, carolKey, carol.kid), T.jwt);
      note(refused(r), '8b. and not one about somebody else', show(r));

      // 9. The actor.
      r = await exchange('tea-client', saml2About('tea-alice'), T.saml2, {
        audience: BACK, actor_token: jwtAbout('tea-dave'),
        actor_token_type: T.jwt });
      const act = r.json.access_token ? claimsOf(r.json.access_token).act
                                      : null;
      note(r.status === 200 && act && act.sub === daveSub &&
           subOf(r) === aliceSub,
           '9a. an assertion as the actor_token: act.sub is the person it ' +
           'names, the subject the SAML assertion\'s', show(r));
      r = await exchange('tea-client', saml2About('tea-alice'), T.saml2, {
        audience: BACK, actor_token: signJwt({ iss: 'https://nobody.example',
          sub: 'tea-dave', aud: TOKEN, iat: now(), exp: now() + 120,
          jti: jti() }, unknownKey.privateKey, 'x'),
        actor_token_type: T.jwt });
      note(refused(r), '9b. an actor_token from an undeclared issuer is ' +
           'refused', show(r));
    } finally {
      config.clearOverride('global.mode');
      config.clearOverride('oauth2.tokenExchangeAudience');
    }

    // 10. Development.
    const forged = b64u({ alg: 'none', typ: 'JWT' }) + '.' + b64u({
      iss: 'https://nobody.example', sub: 'tea-alice', username: 'tea-alice',
      iat: now(), exp: now() + 120, jti: jti() }) + '.';
    let d = await exchange('tea-client', forged, T.jwt);
    note(d.status === 200 && d.json.access_token,
         '10a. DEVELOPMENT: an undeclared, unsigned JWT is still exchanged ' +
         'unverified, as it always was', show(d));
    d = await exchange('tea-client', saml2About('tea-alice', {}, otherPair),
                       T.saml2);
    note(refused(d), '10b. DEVELOPMENT: a SAML assertion that does not ' +
         'verify is refused — there is no unverified reading to fall back ' +
         'on', show(d));
    d = await exchange('tea-client', saml1About('tea-alice'), T.saml1);
    note(d.status === 200 && subOf(d) === aliceSub,
         '10c. DEVELOPMENT: a declared SAML 1.1 assertion is exchanged',
         show(d));
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-tea-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { TEA_OUT: out, TEA_ROOT: ROOT,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'token_exchange_assertions',
  describe: 'RFC 7523, RFC 7522 and SAML 1.1 assertions from declared ' +
            'issuers as RFC 8693 subject and actor tokens (#114)',
  run: run
};
