'use strict';
//
// File: tests/token_exchange_product.js
//
// ===========================================================================
// PRODUCT MODE EXCHANGES ONLY A TOKEN IT CAN VERIFY (2026-09-21).
//
// RFC 8693's token exchange took a `subject_token`, tried to verify it, and
// — when that failed — read the name out of it unverified and EXCHANGED IT
// ANYWAY, in every mode. That is development's intent (a client under test
// drives the grant with a token from any issuer), and product had no check of
// its own: any client that could authenticate could write
// `{"sub": <anybody>}` into a JWT signed with nothing and be handed a token
// this realm signed for that person. The `actor_token` was never verified at
// all, so the `act` claim in the token that came out could name anybody too.
// `common/mode.js`'s `exchangesUnverifiedTokens()` is the switch now, and
// `oauth-oidc/oauth2.ts`'s exchange branch asks it.
//
// Asserted, in a CHILD PROCESS (it flips `global.mode` for the process,
// `public_clients_product.js`'s reason):
//   1. PRODUCT: a subject_token this realm signed is exchanged — the control,
//      without which every refusal below could be a grant that never works;
//   2. PRODUCT: an UNSIGNED (`alg: none`) subject_token naming somebody else
//      is refused invalid_request with STS-OAUTH-0555, and no token issued;
//   3. PRODUCT: one SIGNED WITH ANOTHER KEY is refused the same way;
//   4. PRODUCT: a subject_token this realm REVOKED is refused (0557);
//   5. PRODUCT: a verified subject with a FORGED actor_token is refused
//      (0556), and with a verified one the `act` claim is the actor's sub;
//   6. DEVELOPMENT is unchanged: the forged token is still exchanged, and
//      says whose it claimed to be — the behaviour a client under test uses.
//
// AND WHO MAY ACT FOR WHOM (#108, 2026-09-23), at the endpoint:
//   7. PRODUCT: an impersonation by a client with no delegation attributes is
//      invalid_request (STS-OAUTH-0618); a delegation to a target nothing
//      allows is invalid_target (0619); both are refused acts on
//      /admin/delegation; with appTrustedToImpersonate and
//      appAllowedToDelegateTo it is issued and the act names the attribute;
//      a subject_token whose may_act names somebody else is refused (0620),
//      and one naming the client stands in for the flag; `act` NESTS a prior
//      actor (RFC 8693 section 4.1); a scope wider than the subject_token's
//      is invalid_scope (0621); stsMayAct puts may_act on the token issued.
//   8. DEVELOPMENT: the same impersonation is issued and the act says it
//      WOULD have been refused; may_act is refused all the same; a wider
//      scope is issued.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'token_exchange_product',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.TXP_ROOT;
  const OUT = process.env.TXP_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const post = function (port, form) {
    return new Promise(function (resolve) {
      const body = new URLSearchParams(form).toString();
      const req = http.request({ host: '127.0.0.1', port: port,
        path: '/oauth2/token', method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(body) } },
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

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const stats = require(ROOT + '/common/admin_stats');
    const audit = require(ROOT + '/common/audit');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const SECRET = 'txp-confidential-secret-0123456789abcdef';
    const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    const ACCESS = 'urn:ietf:params:oauth:token-type:access_token';
    // Made in DEVELOPMENT, because product mode creates nothing because it
    // was named — the fixture has to exist before the mode is switched.
    applications.createApplication({ identifier: 'txp-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'txp-client', oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['client_credentials', EXCHANGE] } });
    const auth = { client_id: 'txp-client', client_secret: SECRET };
    const exchange = function (subjectToken, extra) {
      return post(port, Object.assign({ grant_type: EXCHANGE,
        subject_token: subjectToken, subject_token_type: ACCESS }, auth,
      extra || {}));
    };
    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    // Somebody the forger would like to be.
    const forgedClaims = { iss: 'https://127.0.0.1:' + port,
      sub: 'urn:uuid:00000000-0000-4000-8000-00000000a11c',
      username: 'txp-admin', scope: 'openid',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
      jti: 'txp-forged-' + crypto.randomBytes(6).toString('hex') };
    const unsigned = b64u({ alg: 'none', typ: 'JWT' }) + '.' +
                     b64u(forgedClaims) + '.';
    const stranger = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const signingInput = b64u({ alg: 'RS256', typ: 'JWT' }) + '.' +
                         b64u(forgedClaims);
    const foreignSigned = signingInput + '.' +
      crypto.sign('sha256', Buffer.from(signingInput), stranger.privateKey)
        .toString('base64url');

    // --- #108's fixtures, made in DEVELOPMENT for the reason above ---------
    const helpers = require(ROOT + '/common/helpers');
    const dir = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const delegation = require(ROOT + '/common/delegation');
    const MID_SECRET = 'txp-mid-secret-0123456789abcdef0123';
    dir.createUser('txp-alice', { invent: false });
    const aliceSub = helpers.subjectForName('txp-alice');
    applications.createApplication({ identifier: 'txp-back',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'txp-back',
                oauthAudience: ['https://txp-back.example'],
                appAllowedToActOnBehalfOf: ['txp-client'] } });
    applications.createApplication({ identifier: 'txp-mid',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'txp-mid', oauthClientSecret: MID_SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['client_credentials', EXCHANGE],
                oauthAllowedScope: ['openid', 'api'],
                appAllowedToDelegateTo: ['txp-back'],
                appTrustedToImpersonate: 'TRUE' } });
    const midAuth = { client_id: 'txp-mid', client_secret: MID_SECRET };
    // A token this realm signed about txp-alice, as another client's grant
    // would have produced it; `extra` adds `act`, `may_act`, a scope.
    const aliceToken = function (extra) {
      const now = Math.floor(Date.now() / 1000);
      return helpers.signJwt(Object.assign({
        iss: 'https://127.0.0.1:' + port, sub: aliceSub,
        username: 'txp-alice', client_id: 'txp-elsewhere', typ: 'Bearer',
        aud: 'https://127.0.0.1:' + port, scope: 'api',
        iat: now, nbf: now, exp: now + 600,
        jti: 'txp-alice-' + crypto.randomBytes(6).toString('hex') },
      extra || {}));
    };
    // The newest act of a type: `delegation.list()` is newest first.
    const lastAct = function (type) {
      return delegation.list().filter(function (row) {
        return row.type === type;
      })[0] || null;
    };
    const policyChecks = async function (m) {
      const product = m === 'product';
      const P = product ? '7' : '8';
      // An impersonation by a client with neither flag.
      let r = await exchange(aliceToken(),
                             { audience: 'https://txp-back.example' });
      if (product) {
        note(r.status === 400 && r.json.error === 'invalid_request' &&
             codeRecorded('STS-OAUTH-0618'),
             P + 'a. an IMPERSONATION by a client without ' +
             'appTrustedToImpersonate is invalid_request (0618)',
             r.status + ' ' + r.text.slice(0, 300));
        const row = lastAct('oauth-impersonation');
        note(row && row.outcome === 'refused' &&
             /appTrustedToImpersonate/.test(row.reason),
             P + 'b. and it is a REFUSED act on /admin/delegation, naming ' +
             'the missing flag', JSON.stringify(row && [row.outcome, row.reason]));
      } else {
        const row = lastAct('oauth-impersonation');
        note(r.status === 200 && row && row.outcome === 'issued' &&
             /WOULD HAVE BEEN REFUSED/.test(row.authorizedBy),
             P + 'a. DEVELOPMENT issues it, and the act says it WOULD have ' +
             'been refused in product', r.status + ' ' +
             JSON.stringify(row && row.authorizedBy));
      }
      // A delegation to a target nothing allows.
      const cc = await post(port, Object.assign(
        { grant_type: 'client_credentials' }, auth));
      r = await exchange(aliceToken(), {
        actor_token: String(cc.json.access_token || ''),
        actor_token_type: ACCESS, audience: 'https://elsewhere.example' });
      note(product ? (r.status === 400 && r.json.error === 'invalid_target' &&
                      codeRecorded('STS-OAUTH-0619'))
                   : r.status === 200,
           P + 'c. a DELEGATION to a target no attribute allows is ' +
           (product ? 'invalid_target (0619)' : 'issued in development'),
           r.status + ' ' + r.text.slice(0, 300));
      // The same client, allowed by the TARGET's attribute.
      r = await exchange(aliceToken(), {
        actor_token: String(cc.json.access_token || ''),
        actor_token_type: ACCESS, audience: 'https://txp-back.example' });
      const viaRbcd = lastAct('oauth-delegation');
      note(r.status === 200 && viaRbcd &&
           /appAllowedToActOnBehalfOf/.test(viaRbcd.authorizedBy),
           P + 'd. appAllowedToActOnBehalfOf on the target allows it, and ' +
           'the act says so', r.status + ' ' +
           JSON.stringify(viaRbcd && viaRbcd.authorizedBy));
      // A trusted intermediary impersonating.
      const post2 = function (subjectToken, extra) {
        return post(port, Object.assign({ grant_type: EXCHANGE,
          subject_token: subjectToken, subject_token_type: ACCESS }, midAuth,
        extra || {}));
      };
      r = await post2(aliceToken(), { audience: 'https://txp-back.example' });
      const imp = lastAct('oauth-impersonation');
      note(r.status === 200 && imp && imp.outcome === 'issued' &&
           /appTrustedToImpersonate/.test(imp.authorizedBy) &&
           /appAllowedToDelegateTo/.test(imp.authorizedBy),
           P + 'e. with appTrustedToImpersonate and appAllowedToDelegateTo ' +
           'the impersonation is issued, and the act names both',
           r.status + ' ' + JSON.stringify(imp && imp.authorizedBy));
      // may_act naming somebody else — every mode.
      r = await post2(aliceToken({ may_act: { sub: 'somebody-else' } }),
                      { audience: 'https://txp-back.example' });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           codeRecorded('STS-OAUTH-0620'),
           P + 'f. a subject_token whose may_act names somebody else is ' +
           'refused (0620) in ' + m, r.status + ' ' + r.text.slice(0, 300));
      // may_act naming the client stands in for the flag.
      r = await exchange(aliceToken({ may_act: { sub: 'txp-client' } }),
                         { audience: 'https://txp-back.example' });
      note(r.status === 200,
           P + 'g. one naming the client itself stands in for ' +
           'appTrustedToImpersonate', r.status + ' ' + r.text.slice(0, 300));
      // act nests.
      const midCc = await post(port, Object.assign(
        { grant_type: 'client_credentials' }, midAuth));
      r = await post2(aliceToken({ act: { sub: 'txp-prior-actor' } }), {
        actor_token: String(midCc.json.access_token || ''),
        actor_token_type: ACCESS, audience: 'https://txp-back.example' });
      const nested = r.json.access_token ? claimsOf(r.json.access_token).act
                                         : null;
      note(r.status === 200 && nested && nested.act &&
           nested.act.sub === 'txp-prior-actor' &&
           nested.sub === claimsOf(String(midCc.json.access_token)).sub,
           P + 'h. `act` NESTS: the new actor outermost, the ' +
           'subject_token\'s actor beneath it (RFC 8693 section 4.1)',
           r.status + ' ' + JSON.stringify(nested));
      // A wider scope.
      r = await post2(aliceToken({ scope: 'api' }),
                      { audience: 'https://txp-back.example',
                        scope: 'api openid' });
      note(product ? (r.status === 400 && r.json.error === 'invalid_scope' &&
                      codeRecorded('STS-OAUTH-0621'))
                   : r.status === 200,
           P + 'i. a scope WIDER than the subject_token\'s is ' +
           (product ? 'invalid_scope (0621)' : 'issued in development'),
           r.status + ' ' + r.text.slice(0, 300));
      r = await post2(aliceToken({ scope: 'api openid' }),
                      { audience: 'https://txp-back.example', scope: 'api' });
      note(r.status === 200, P + 'j. and a narrower one is issued',
           r.status + ' ' + r.text.slice(0, 300));
      // stsMayAct puts may_act on what is issued about her.
      credentials.setMayAct('txp-alice', applications.get('txp-mid').dn);
      r = await post2(aliceToken(), { audience: 'https://txp-back.example' });
      const claim = r.json.access_token
        ? claimsOf(r.json.access_token).may_act : null;
      credentials.setMayAct('txp-alice', '');
      note(r.status === 200 && claim && claim.sub === 'txp-mid',
           P + 'k. stsMayAct on the person puts may_act naming that party on ' +
           'the access token issued about them', r.status + ' ' +
           JSON.stringify(claim));
      return true;
    };

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('global.mode', 'product');
    try {
      // 1. The control: a token this realm signed.
      const cc = await post(port, Object.assign(
        { grant_type: 'client_credentials' }, auth));
      note(cc.status === 200 && cc.json.access_token,
           'precondition: product mode issues the client a token by ' +
           'client_credentials', cc.status + ' ' + cc.text.slice(0, 200));
      const real = String(cc.json.access_token || '');
      let r = await exchange(real);
      note(r.status === 200 && r.json.access_token,
           '1. PRODUCT: a subject_token this realm signed IS exchanged — the ' +
           'control that makes every refusal below mean something',
           r.status + ' ' + r.text.slice(0, 200));

      // 2. Unsigned.
      r = await exchange(unsigned);
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           !r.json.access_token,
           '2a. PRODUCT: an UNSIGNED subject_token naming somebody else is ' +
           'refused invalid_request and NOTHING is issued — it was ' +
           'exchanged for a token this realm signed for that person',
           r.status + ' ' + r.text.slice(0, 200));
      note(codeRecorded('STS-OAUTH-0555'), '2b. with STS-OAUTH-0555');

      // 3. Signed by a stranger.
      r = await exchange(foreignSigned);
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           !r.json.access_token,
           '3. PRODUCT: a subject_token SIGNED WITH ANOTHER KEY is refused ' +
           'the same way', r.status + ' ' + r.text.slice(0, 200));

      // 4. Revoked.
      const again = await post(port, Object.assign(
        { grant_type: 'client_credentials' }, auth));
      const revoked = String(again.json.access_token || '');
      stats.revoke(claimsOf(revoked).jti, 'token_exchange_product fixture');
      r = await exchange(revoked);
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           codeRecorded('STS-OAUTH-0557'),
           '4. PRODUCT: a subject_token this realm REVOKED is refused, with ' +
           'STS-OAUTH-0557', r.status + ' ' + r.text.slice(0, 200));

      // 5. The actor.
      r = await exchange(real, { actor_token: unsigned,
                                 actor_token_type: ACCESS });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           codeRecorded('STS-OAUTH-0556'),
           '5a. PRODUCT: a verified subject with a FORGED actor_token is ' +
           'refused with STS-OAUTH-0556 — the actor was never verified in ' +
           'any mode, so `act` could name anybody',
           r.status + ' ' + r.text.slice(0, 200));
      r = await exchange(real, { actor_token: real,
                                 actor_token_type: ACCESS });
      const act = r.json.access_token ? claimsOf(r.json.access_token).act
                                       : null;
      note(r.status === 200 && act && act.sub === claimsOf(real).sub,
           '5b. and with a VERIFIED actor_token the exchange succeeds and ' +
           '`act.sub` is the actor\'s own sub',
           r.status + ' ' + JSON.stringify(act));

      // 7. The delegation policy (#108).
      const policyIssued = await policyChecks('product');
      note(policyIssued, '7. PRODUCT: the delegation policy checks ran');
    } finally {
      config.clearOverride('global.mode');
    }
    const devRan = await policyChecks('development');
    note(devRan, '8. DEVELOPMENT: the delegation policy checks ran');

    // 6. Development is what it was.
    const dev = await exchange(unsigned);
    note(dev.status === 200 && dev.json.access_token &&
         claimsOf(dev.json.access_token).sub === forgedClaims.sub,
         '6. DEVELOPMENT is unchanged: the unsigned token is still exchanged ' +
         'and the result names whom it claimed — the behaviour a client ' +
         'under test drives the grant with',
         dev.status + ' ' + dev.text.slice(0, 200));
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
  const out = path.join(os.tmpdir(), 'sts-txp-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { TXP_OUT: out, TXP_ROOT: ROOT,
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
  name: 'token_exchange_product',
  describe: 'product mode exchanges only a subject_token and actor_token ' +
            'this realm can verify',
  run: run
};
