'use strict';
//
// File: rfc7009_revocation.js
//
// ===========================================================================
// RFC 7009 — TOKEN REVOCATION, AS IT HAS BEEN SINCE #102 (2026-09-22).
//
// `oauth-oidc/oauth2.ts` above `revokeEndpoint()` argues the design. Until
// that day `/oauth2/revoke` revoked the jti of any JWS this realm had signed,
// for anybody holding the string, in every mode. What is held here:
//
//   1. THE PREDICATE: `mode.opensRevocation()` is open in development and
//      closed in product, and `/admin/mode`'s table has its row.
//   2. THE ENDPOINT, in a child process on an ephemeral loopback port, in
//      DEVELOPMENT: an anonymous caller still revokes; a presented credential
//      that fails is 401 `invalid_client`; one that verifies is held to
//      section 2.1's ownership (`invalid_grant` for another client's token,
//      nothing revoked); an unregistered client_id with a secret has nothing
//      to fail against and goes on unidentified; an ID Token is
//      `unsupported_token_type`; no token is `invalid_request`; an unknown
//      `token_type_hint` is ignored; an invalid token is still 200; and a
//      refresh token takes its whole grant with it — the refresh token it
//      was refreshed from and BOTH access tokens, read back at introspection
//      and at the refresh grant, in a chain that does not rotate.
//   3. And in PRODUCT: no credential is 401 and revokes nothing; a wrong
//      secret is 401 with the Basic challenge; another client's token is
//      `invalid_grant` and stays active; a client revokes its own access
//      token (and only that token); a PUBLIC client revokes its own token
//      with its client_id alone and is refused another's; an unknown
//      client_id is 401; the ID Token, missing token and unknown hint rows
//      again; a refresh token in a ROTATING chain takes the rotated one's
//      access token and its own with it; the audit row naming both clients;
//      and a named authorization server narrowing
//      `revocation_endpoint_auth_methods_supported`.
//   4. DISCOVERY: `revocation_endpoint_auth_methods_supported` is exactly
//      introspection's list, with `none` in it.
//
// **THE CHILD IS NOT FASTIDIOUSNESS**, for `tests/rfc9068_access_tokens.js`'s
// reason: loading the protocol stack into `run.js`'s one process builds a
// certificate authority and registers every route on the shared app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'rfc7009_revocation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const mode = require('../common/mode');
const config = require('../common/config');

// ---------------------------------------------------------------------------
// 1. THE PREDICATE.
// ---------------------------------------------------------------------------
function predicate(t) {
  log.debug("Entering predicate().");
  t.log.info('=== 1. mode.opensRevocation() ===');
  config.clearOverride('global.mode');
  t.equal(mode.opensRevocation(), true,
          '1a. development: revocation is open to an anonymous caller');
  config.setOverride('global.mode', 'product');
  try {
    t.equal(mode.opensRevocation(), false,
            '1b. product: every revocation request comes from a client');
  } finally {
    config.clearOverride('global.mode');
  }
  const row = mode.REQUIREMENTS.filter(function (one) {
    return one.id === 'revocation';
  })[0];
  t.check(row && /invalid_grant/.test(row.product) &&
          /401 invalid_client/.test(row.development) &&
          /oauth2\.ts/.test(row.where),
          '1c. /admin/mode describes both modes, the refusals and where',
          JSON.stringify(row || null).slice(0, 200));
  log.debug("Leaving predicate().");
}

// ---------------------------------------------------------------------------
// 2-4. THE ENDPOINT, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.R79_ROOT;
  const OUT = process.env.R79_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.form ? new URLSearchParams(o.form).toString() : '';
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (chunk) { text += chunk; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // An empty 200 is not JSON. No logger in a `node -e` child, so
            // the reason travels on the result.
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  function claimsOf(token) {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url')
                            .toString('utf8'));
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const servers = require(ROOT + '/oauth-oidc/authorization_servers');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', false);
    const SECRET_A = 'r79-client-a-secret-0123456789abcdef';
    const SECRET_B = 'r79-client-b-secret-0123456789abcdef';
    const confidential = function (id, secret) {
      applications.createApplication({ identifier: id, protocols: ['oauth2'],
        fields: { oauthClientId: id, oauthClientSecret: secret,
                  oauthTokenEndpointAuthMethod: 'client_secret_post',
                  oauthAllowedScope: ['openid', 'offline_access'],
                  oauthGrantType: ['password', 'refresh_token',
                                   'client_credentials'] } });
    };
    confidential('r79-a', SECRET_A);
    confidential('r79-b', SECRET_B);
    applications.createApplication({ identifier: 'r79-pub',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'r79-pub',
                oauthTokenEndpointAuthMethod: 'none',
                oauthAllowedScope: ['openid', 'offline_access'],
                oauthGrantType: ['password', 'refresh_token'] } });
    const ALICE = 'r79-alice';
    ldap.createUser(ALICE, { invent: false });

    const A = { client_id: 'r79-a', client_secret: SECRET_A };
    const B = { client_id: 'r79-b', client_secret: SECRET_B };
    const PUB = { client_id: 'r79-pub' };
    const WRONG_A = { client_id: 'r79-a', client_secret: 'not-the-secret' };
    const basicWrong = 'Basic ' + Buffer.from('r79-a:not-the-secret')
      .toString('base64');

    // A token set by the password grant — development only, which is why
    // every set the product half uses is minted before the switch.
    const grant = async function (client) {
      const got = await request(port, 'POST', '/oauth2/token', {
        form: Object.assign({ grant_type: 'password', username: ALICE,
                              password: 'anything',
                              scope: 'openid offline_access' }, client) });
      return got.json || {};
    };
    const refresh = async function (client, refreshToken) {
      return request(port, 'POST', '/oauth2/token', {
        form: Object.assign({ grant_type: 'refresh_token',
                              refresh_token: refreshToken }, client) });
    };
    const revoke = function (form, headers, urlPath) {
      return request(port, 'POST', urlPath || '/oauth2/revoke',
                     { form: form, headers: headers || {} });
    };
    // Introspection as the token's own client, which product requires and
    // RFC 9701 section 5's intended-for rule allows for its own token.
    const active = async function (token, client) {
      const r = await request(port, 'POST', '/oauth2/introspect',
        { form: Object.assign({ token: token }, client || A) });
      return r.status === 200 && r.json && r.json.active === true;
    };
    // Where a public client's access token is USED: UserInfo refuses a
    // revoked one. It cannot introspect, having no credential.
    const usable = async function (token) {
      const r = await request(port, 'GET', '/oauth2/userinfo',
        { headers: { authorization: 'Bearer ' + token } });
      return r.status === 200;
    };
    const lastRevokeRow = function () {
      const rows = audit.list().filter(function (row) {
        return row.action === 'oauth.token.revoke';
      });
      return rows.length ? rows[0] : null;
    };

    // --- minted in development, for both halves ------------------------------
    const d1 = await grant(A);
    note(d1.access_token && d1.refresh_token && d1.id_token,
         '2a. (a control: the password grant issues an access token, a ' +
         'refresh token and an ID Token)', JSON.stringify(Object.keys(d1)));
    const d2 = await grant(A);
    const d3 = await grant(A);
    const p1 = await grant(A);
    const p2 = await grant(A);
    const p3 = await grant(A);
    const pPub = await grant(PUB);
    const pPub2 = await grant(PUB);

    // --- 2. development ----------------------------------------------------
    let r = await revoke({ token: d1.access_token });
    note(r.status === 200 && !(await active(d1.access_token)),
         '2b. development: an anonymous caller still revokes an access token',
         r.status + ' ' + r.text.slice(0, 160));
    r = await revoke(Object.assign({ token: d2.access_token }, WRONG_A));
    note(r.status === 401 && r.json.error === 'invalid_client' &&
         (await active(d2.access_token)),
         '2c. development: a presented secret that does not verify is 401 ' +
         'invalid_client, and nothing is revoked',
         r.status + ' ' + r.text.slice(0, 200));
    r = await revoke({ token: d2.access_token },
                     { authorization: basicWrong });
    note(r.status === 401 &&
         /^Basic realm=/.test(String(r.headers['www-authenticate'] || '')),
         '2d. and a wrong Basic credential gets the challenge',
         r.status + ' ' + r.headers['www-authenticate']);
    r = await revoke(Object.assign({ token: d2.access_token }, B));
    note(r.status === 400 && r.json.error === 'invalid_grant' &&
         (await active(d2.access_token)),
         '2e. development: an authenticated client revoking another ' +
         'client\'s token is refused invalid_grant, and it stays active',
         r.status + ' ' + r.text.slice(0, 200));
    r = await revoke({ token: d2.access_token, client_id: 'r79-nobody',
                       client_secret: 'whatever' });
    note(r.status === 200 && !(await active(d2.access_token)),
         '2f. development: an unregistered client_id has nothing to fail ' +
         'against, so it goes on unidentified and revokes',
         r.status + ' ' + r.text.slice(0, 200));
    r = await revoke({ token: d1.id_token });
    note(r.status === 400 && r.json.error === 'unsupported_token_type',
         '2g. development: an ID Token is unsupported_token_type',
         r.status + ' ' + r.text.slice(0, 200));
    r = await revoke({});
    note(r.status === 400 && r.json.error === 'invalid_request' &&
         /REQUIRED/.test(r.json.error_description || ''),
         '2h. development: a request with no token is invalid_request',
         r.status + ' ' + r.text.slice(0, 200));
    r = await revoke(Object.assign({ token: d3.access_token,
                                     token_type_hint: 'no_such_hint' }, A));
    note(r.status === 200 && !(await active(d3.access_token)),
         '2i. development: an unknown token_type_hint is ignored, not ' +
         'refused (RFC 7009 section 2.1)', r.status + ' ' +
         r.text.slice(0, 200));
    r = await revoke({ token: 'not-a-token' });
    note(r.status === 200, '2j. an invalid token is still 200 (section 2.2)',
         r.status);

    // The grant: RT1 refreshed (no rotation here) into AT2/RT2; revoking RT2
    // takes RT1, AT1 and AT2 with it.
    const chain = await grant(A);
    const second = await refresh(A, chain.refresh_token);
    const next = second.json || {};
    note(second.status === 200 && next.access_token && next.refresh_token &&
         (await active(chain.refresh_token)),
         '2k. (a control: a refresh outside RFC 9700 mode leaves the first ' +
         'refresh token working)', second.status + ' ' +
         second.text.slice(0, 160));
    r = await revoke(Object.assign({ token: next.refresh_token,
                                     token_type_hint: 'refresh_token' }, A));
    const gone = [await active(chain.access_token),
                  await active(chain.refresh_token),
                  await active(next.access_token),
                  await active(next.refresh_token)];
    note(r.status === 200 && gone.join(',') === 'false,false,false,false',
         '2l. revoking a refresh token revokes its grant: the refresh token ' +
         'it came from and both access tokens (section 2.1)',
         r.status + ' ' + gone.join(','));
    const redeemed = await refresh(A, chain.refresh_token);
    note(redeemed.status === 400 && redeemed.json.error === 'invalid_grant',
         '2m. and the first refresh token no longer refreshes',
         redeemed.status + ' ' + redeemed.text.slice(0, 160));

    // --- 4. discovery -------------------------------------------------------
    const meta = (await request(port, 'GET',
      '/.well-known/oauth-authorization-server')).json || {};
    note(JSON.stringify(meta.revocation_endpoint_auth_methods_supported) ===
           JSON.stringify(meta.introspection_endpoint_auth_methods_supported) &&
         meta.revocation_endpoint_auth_methods_supported.indexOf('none') >= 0 &&
         meta.revocation_endpoint_auth_methods_supported
           .indexOf('client_secret_jwt') >= 0,
         '4a. revocation_endpoint_auth_methods_supported is introspection\'s ' +
         'list, none included',
         JSON.stringify(meta.revocation_endpoint_auth_methods_supported));

    // --- 3. product ---------------------------------------------------------
    config.setOverride('global.mode', 'product');
    try {
      r = await revoke({ token: p1.access_token });
      note(r.status === 401 && r.json.error === 'invalid_client' &&
           (await active(p1.access_token)),
           '3a. product: no credential is 401 invalid_client and revokes ' +
           'nothing', r.status + ' ' + r.text.slice(0, 200));
      r = await revoke({ token: p1.access_token },
                       { authorization: basicWrong });
      note(r.status === 401 && r.json.error === 'invalid_client' &&
           /^Basic realm=/.test(String(r.headers['www-authenticate'] || '')) &&
           (await active(p1.access_token)),
           '3b. product: a wrong secret is 401 with the Basic challenge',
           r.status + ' ' + r.text.slice(0, 200));
      r = await revoke(Object.assign({ token: p1.access_token }, B));
      note(r.status === 400 && r.json.error === 'invalid_grant' &&
           (await active(p1.access_token)),
           '3c. product: another client\'s token is invalid_grant and stays ' +
           'active', r.status + ' ' + r.text.slice(0, 200));
      const row = lastRevokeRow();
      note(row && row.errorCode === 'STS-OAUTH-0612' &&
           row.actor === 'r79-b' && /r79-a/.test(JSON.stringify(row)),
           '3d. the audit row names the caller and the owner',
           JSON.stringify(row || null).slice(0, 300));
      r = await revoke(Object.assign({ token: p1.access_token }, A));
      note(r.status === 200 && !(await active(p1.access_token)) &&
           (await active(p1.refresh_token)),
           '3e. product: a client revokes its own access token — and only ' +
           'that token, its refresh token stays', r.status + ' ' +
           r.text.slice(0, 200));
      const usableBefore = await usable(pPub.access_token);
      r = await revoke(Object.assign({ token: pPub.access_token }, PUB));
      note(usableBefore && r.status === 200 &&
           !(await usable(pPub.access_token)),
           '3f. product: a PUBLIC client revokes its own token with its ' +
           'client_id alone', r.status + ' ' + r.text.slice(0, 200));
      r = await revoke(Object.assign({ token: p2.access_token }, PUB));
      note(r.status === 400 && r.json.error === 'invalid_grant' &&
           (await active(p2.access_token)),
           '3g. and is refused another client\'s', r.status + ' ' +
           r.text.slice(0, 200));
      r = await revoke({ token: p2.access_token, client_id: 'r79-nobody' });
      note(r.status === 401 && r.json.error === 'invalid_client',
           '3h. product: a client_id nobody registered is 401',
           r.status + ' ' + r.text.slice(0, 200));
      r = await revoke({ token: pPub2.access_token, client_id: 'r79-nobody',
                         client_secret: 'whatever' });
      note(r.status === 401 && (await usable(pPub2.access_token)),
           '3i. and so is one presenting a secret, which development let ' +
           'through unidentified', r.status + ' ' + r.text.slice(0, 200));
      r = await revoke(Object.assign({ token: p2.id_token }, A));
      note(r.status === 400 && r.json.error === 'unsupported_token_type',
           '3j. product: an ID Token is unsupported_token_type',
           r.status + ' ' + r.text.slice(0, 200));
      r = await revoke(Object.assign({}, A));
      note(r.status === 400 && r.json.error === 'invalid_request',
           '3k. product: no token is invalid_request', r.status + ' ' +
           r.text.slice(0, 200));
      r = await revoke(Object.assign({ token: p2.access_token,
                                       token_type_hint: 'urn:example:x' }, A));
      note(r.status === 200 && !(await active(p2.access_token)),
           '3l. product: an unknown hint is ignored', r.status + ' ' +
           r.text.slice(0, 200));

      // A ROTATING chain (product implies RFC 9700 mode): P3's refresh token
      // redeemed into Q; revoking Q's refresh token takes P3's access token
      // (minted beside the rotated one) and Q's.
      const rotated = await refresh(A, p3.refresh_token);
      const q = rotated.json || {};
      note(rotated.status === 200 && q.refresh_token &&
           !(await active(p3.refresh_token)),
           '3m. (a control: in product the refresh rotates, retiring the ' +
           'presented token)', rotated.status + ' ' +
           rotated.text.slice(0, 160));
      r = await revoke(Object.assign({ token: q.refresh_token }, A));
      const after = [await active(p3.access_token),
                     await active(q.access_token),
                     await active(q.refresh_token)];
      note(r.status === 200 && after.join(',') === 'false,false,false',
           '3n. product: revoking the rotated chain\'s refresh token revokes ' +
           'every access token of the grant', r.status + ' ' +
           after.join(','));
      const again = await refresh(A, q.refresh_token);
      note(again.status === 400 && again.json.error === 'invalid_grant',
           '3o. and the refresh token is refused at the token endpoint',
           again.status + ' ' + again.text.slice(0, 160));

      // A named authorization server narrowing the member.
      await request(port, 'GET',
                    '/.well-known/oauth-authorization-server/r79narrow');
      servers.setMember('r79narrow',
                        'revocation_endpoint_auth_methods_supported',
                        '["private_key_jwt"]');
      r = await revoke(Object.assign({ token: p2.refresh_token }, A),
                       {}, '/r79narrow/oauth2/revoke');
      note(r.status === 401 && r.json.error === 'invalid_client' &&
           /private_key_jwt/.test(r.json.error_description || '') &&
           (await active(p2.refresh_token)),
           '3p. a profile advertising only private_key_jwt refuses a ' +
           'client_secret_post client before its secret is read',
           r.status + ' ' + r.text.slice(0, 200));
      const narrowed = (await request(port, 'GET',
        '/.well-known/oauth-authorization-server/r79narrow')).json || {};
      note(JSON.stringify(narrowed
             .revocation_endpoint_auth_methods_supported) ===
             '["private_key_jwt"]',
           '3q. and its document says so',
           JSON.stringify(narrowed.revocation_endpoint_auth_methods_supported));
      note(claimsOf(p2.access_token).client_id === 'r79-a',
           '3r. (a control: the tokens name their client)');
    } finally {
      config.clearOverride('global.mode');
    }

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 2-4. the endpoint, in a child process ===');
  const out = path.join(os.tmpdir(), 'rfc7009-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', R79_ROOT: ROOT, R79_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  predicate(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc7009 revocation',
  describe: 'the revocation endpoint: client authentication by mode, a ' +
            'token issued to another client, the token types, the hint, ' +
            'and a refresh token taking its grant with it',
  run: run
};
