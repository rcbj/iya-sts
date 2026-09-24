'use strict';
//
// File: refresh_rotation_policy.js
//
// ===========================================================================
// WHAT MAKES A REFRESH TOKEN ROTATE, AND WHOSE CHAIN IT IS (#34, 2026-09-15).
//
// OAuth 2.1 section 4.3.1 asks a public client's refresh token to be
// sender-constrained OR rotated with replay detection. This service takes the
// second, and until 2026-09-15 it took it only inside a compliance mode. Two
// claims follow and both are held here:
//
//   1. ROTATION IS OFF THE MODE SWITCH. `oauth2.refreshTokenRotation` rotates
//      with neither mode on, a replayed token is refused, and the family
//      descended from the original grant is revoked — while the RFC 9700
//      rules that sit BESIDE rotation (the idle timeout, a refresh naming no
//      client) stay behind the mode, because an operator asking for rotation
//      did not ask for those. The scope narrowing and a DIFFERENT client's
//      token are RFC 6749 section 6's own and refused in every mode (#187).
//   2. AN UNKNOWN CLIENT IS REFUSED RATHER THAN ROTATED. Rotation is
//      bookkeeping about a chain belonging to a client, so OAuth 2.1 mode
//      refuses a grant made in a client's own name with no client_id at all,
//      refuses an assertion grant naming an undeclared client, and answers a
//      clientless assertion grant with an access token and NO refresh token.
//
// Section 3 is in a child process for `tests/refresh_token_encryption.js`'s
// reason: the whole protocol stack in `run.js`'s process would build a
// certificate authority and register every route on the shared app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'refresh_rotation_policy',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const realms = require('../common/realms');
const oauth21 = require('../oauth-oidc/oauth21');
const bcp = require('../oauth-oidc/oauth2_bcp');

// See tests/sender_constraints.js: a throwaway realm left standing in the
// in-process run is a failure in a later file.
const MADE = [];

function throwaway(id, overrides) {
  log.debug("Entering throwaway(). id=" + id);
  if (!realms.get(id)) {
    realms.create({ id: id, label: id });
    MADE.push(id);
  }
  Object.keys(overrides || {}).forEach(function (key) {
    realms.setOverride(id, key, String(overrides[key]));
  });
  log.debug("Leaving throwaway().");
  return realms.get(id);
}

function inRealm(id, fn) {
  log.debug("Entering inRealm().");
  const answer = realms.run(realms.get(id), fn);
  log.debug("Leaving inRealm().");
  return answer;
}

// ---------------------------------------------------------------------------
// 1. ROTATION, AND WHAT DOES NOT COME WITH IT.
// ---------------------------------------------------------------------------
function checkRotationIsItsOwnSwitch(t) {
  log.debug("Entering checkRotationIsItsOwnSwitch().");
  t.log.info('=== 1. rotation is its own switch ===');

  throwaway('rrp-rotation', { 'oauth2.refreshTokenRotation': 'true' });
  throwaway('rrp-plain', {});

  t.equal(inRealm('rrp-rotation', bcp.rotationRequired), true,
          '1a. the setting alone makes refresh tokens rotate');
  t.equal(inRealm('rrp-rotation', bcp.enabled), false,
          '1b. WITHOUT turning RFC 9700 mode on — which is the whole point: ' +
          'the mode refuses two dozen other things');

  // The replay refusal comes WITH rotation, because rotation without replay
  // detection is bookkeeping nobody reads.
  const replay = inRealm('rrp-rotation', function () {
    // A token this realm believes it rotated already. `checkRefreshRequest()`
    // reads its own store, so the record has to be there — it is put there by
    // noteRefreshIssued()/noteRefreshRotated(), which the grant calls.
    bcp.noteRefreshIssued('rrp-jti-1', '', 'rrp-client', '');
    bcp.noteRefreshRotated('rrp-jti-1');
    return bcp.checkRefreshRequest({
      claims: { jti: 'rrp-jti-1', client_id: 'rrp-client' },
      clientId: 'rrp-client', body: {} });
  });
  t.equal(replay && replay.ok, false,
          '1c. and a replayed refresh token is refused with the setting on ' +
          'and both modes off');
  t.equal(replay && replay.errorCode, 'STS-OAUTH-0138',
          '1d. as a detected replay');
  t.check(Array.isArray(replay && replay.revoke),
          '1e. carrying the family to revoke, not just the token replayed',
          JSON.stringify(replay && replay.revoke));

  // What does NOT come with it. The client binding is RFC 6749 section 6 as
  // RFC 9700 mode reads it, and an operator who asked for rotation did not ask
  // to have their unnamed-client refresh requests refused.
  const noClient = inRealm('rrp-rotation', function () {
    return bcp.checkRefreshRequest({ claims: { jti: 'rrp-jti-2' },
                                     clientId: '', body: {} });
  });
  t.equal(noClient && noClient.ok, true,
          '1f. the client binding stays behind the mode: rotation alone does ' +
          'not start refusing a refresh with no client_id');

  const widened = inRealm('rrp-rotation', function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'rrp-jti-3', scope: 'openid' },
      clientId: 'rrp-client', body: { scope: 'openid admin:write' } });
  });
  // Since #187 the scope check is RFC 6749 section 6's own MUST and holds in
  // every mode (tests/oidcc_conformance_findings.js carries the rest).
  t.equal(widened && widened.errorCode, 'STS-OAUTH-0142',
          '1g. but the scope check does NOT stay behind it: RFC 6749 section ' +
          '6 refuses a widened refresh in every mode (#187)');

  // In the mode, both of those refuse — the same two calls, one realm along.
  throwaway('rrp-mode', { 'oauth2.rfc9700': 'true' });
  const noClientInMode = inRealm('rrp-mode', function () {
    return bcp.checkRefreshRequest({ claims: { jti: 'rrp-jti-4' },
                                     clientId: '', body: {} });
  });
  t.equal(noClientInMode && noClientInMode.errorCode, 'STS-OAUTH-0140',
          '1h. and in RFC 9700 mode the same request IS refused, which is ' +
          'what makes this a split rather than a move');

  t.equal(inRealm('rrp-plain', function () {
    return bcp.checkRefreshRequest({ claims: { jti: 'rrp-jti-5' },
                                     clientId: '', body: {} }).ok;
  }), true, '1i. and a realm with neither refuses nothing at all');
  log.debug("Leaving checkRotationIsItsOwnSwitch().");
}

// ---------------------------------------------------------------------------
// 2. THE UNKNOWN CLIENT.
// ---------------------------------------------------------------------------
function checkTheUnknownClient(t) {
  log.debug("Entering checkTheUnknownClient().");
  t.log.info('=== 2. an unknown client is refused rather than rotated ===');

  throwaway('rrp-21', { 'oauth2.oauth21': 'true' });
  throwaway('rrp-off', {});

  const unnamed = inRealm('rrp-21', function () {
    return oauth21.tokenClientDeclarationRefusal({
      grant: 'refresh_token', clientId: '', registered: { declared: false } });
  });
  t.equal(unnamed && unnamed.errorCode, 'STS-OAUTH-0297',
          '2a. a refresh request naming no client at all is refused in ' +
          'OAuth 2.1 mode — it used to skip the check entirely');
  t.equal(unnamed && unnamed.error, 'invalid_client', '2b. as invalid_client');

  t.equal(inRealm('rrp-off', function () {
    return oauth21.tokenClientDeclarationRefusal({
      grant: 'refresh_token', clientId: '', registered: { declared: false } });
  }), null, '2c. and nothing changes with the mode off');

  const declared = inRealm('rrp-21', function () {
    return oauth21.tokenClientDeclarationRefusal({
      grant: 'refresh_token', clientId: 'rrp-client',
      registered: { declared: true, known: true } });
  });
  t.equal(declared, null, '2d. a declared client is unaffected');

  // The two assertion grants: they may arrive with no client by design, so
  // they are not on the registered-client list — but one that NAMES a client
  // still has to name one this server knows.
  const assertion = inRealm('rrp-21', function () {
    return oauth21.assertionClientRefusal({
      grant: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      clientId: 'rrp-stranger', registered: { declared: false, known: false } });
  });
  t.equal(assertion && assertion.errorCode, 'STS-OAUTH-0299',
          '2e. an assertion grant naming an undeclared client is refused');
  t.equal(inRealm('rrp-21', function () {
    return oauth21.assertionClientRefusal({
      grant: 'urn:ietf:params:oauth:grant-type:jwt-bearer', clientId: '',
      registered: {} });
  }), null, '2f. and one naming NO client is not refused — the assertion ' +
            'speaks for the subject, which is that grant\'s design');

  t.equal(inRealm('rrp-21', function () {
    return oauth21.withholdsRefreshToken({
      grant: 'urn:ietf:params:oauth:grant-type:saml2-bearer', clientId: '' });
  }), true, '2g. it is answered with NO REFRESH TOKEN instead: a chain ' +
            'belonging to nobody could not be checked against the client ' +
            'redeeming it');
  t.equal(inRealm('rrp-21', function () {
    return oauth21.withholdsRefreshToken({
      grant: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
      clientId: 'rrp-client' });
  }), false, '2h. while one that names a declared client keeps its refresh ' +
             'token');
  t.equal(inRealm('rrp-21', function () {
    return oauth21.withholdsRefreshToken({ grant: 'authorization_code',
                                           clientId: '' });
  }), false, '2i. and no other grant is touched by that rule');
  t.equal(inRealm('rrp-off', function () {
    return oauth21.withholdsRefreshToken({
      grant: 'urn:ietf:params:oauth:grant-type:jwt-bearer', clientId: '' });
  }), false, '2j. with the mode off, nothing is withheld');

  // The report says so, which is what a client author reads.
  const row = inRealm('rrp-21', function () {
    return oauth21.state().requirements.filter(function (one) {
      return one.id === 'refresh-public-rotation';
    })[0];
  });
  t.check(!!row, '2k. section 4.3.1 has a row of its own on GET ' +
                 '/oauth2/oauth21', row && row.section);
  // `state()` prefixes the draft's name to every section, so that a reader of
  // the report knows WHICH 4.3.1 — the draft moves.
  t.equal(row && row.section, oauth21.DRAFT + ' 4.3.1',
          '2l. citing the section this issue was opened about, and the ' +
          'revision it is a section of');
  t.check(/CHOICE OF TWO/.test(String(row && row.note)),
          '2m. and saying it is a choice of two rather than a DPoP ' +
          'requirement', String(row && row.note).slice(0, 120));
  log.debug("Leaving checkTheUnknownClient().");
}

// ---------------------------------------------------------------------------
// 3. ROTATION AT THE DOOR, in a child process.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RRP_ROOT;
  const OUT = process.env.RRP_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function post(port, urlPath, form) {
    return new Promise(function (resolve) {
      const body = new URLSearchParams(form).toString();
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(body) } },
        function (res) {
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              // Not JSON; the raw text is what the finding carries. No logger
              // exists in a `node -e` child.
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
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const client = { client_id: 'rrp-client',
                     client_secret: 'rrp-client-secret-0123456789' };
    ldap.createUser('rrp-alice', { invent: false });
    applications.createApplication({ identifier: 'rrp-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'rrp-client',
                oauthClientSecret: client.client_secret,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password', 'refresh_token'] } });
    const issue = function () {
      return post(port, '/oauth2/token', Object.assign({
        grant_type: 'password', username: 'rrp-alice', password: 'anything',
        scope: 'openid offline_access' }, client));
    };
    const refresh = function (token) {
      return post(port, '/oauth2/token', Object.assign({
        grant_type: 'refresh_token', refresh_token: token }, client));
    };

    // --- with everything off: a refresh token is reusable ------------------
    let r = await issue();
    const reusable = (r.json && r.json.refresh_token) || '';
    r = await refresh(reusable);
    note(r.status === 200, '3a. with rotation off a refresh token is spent ' +
                           'and still works', r.status);
    r = await refresh(reusable);
    note(r.status === 200,
         '3b. AND WORKS AGAIN — which is the state OAuth 2.1 section 4.3.1 ' +
         'is about, and what this service does when nobody has asked for ' +
         'anything else', r.status);

    // --- with the setting on: rotated, and a replay refused ---------------
    config.setOverride('oauth2.refreshTokenRotation', 'true');
    r = await issue();
    const first = (r.json && r.json.refresh_token) || '';
    r = await refresh(first);
    const second = (r.json && r.json.refresh_token) || '';
    note(r.status === 200 && second && second !== first,
         '3c. with oauth2.refreshTokenRotation on, a refresh hands back a ' +
         'NEW refresh token', r.status);
    // THE REDEEMED TOKEN IS RETIRED, not merely refused on its next use: the
    // rotation step revokes it, so it introspects as inactive. Until
    // 2026-09-16 that step asked `enabled()` rather than `rotationRequired()`
    // and this answered `active: true` with the setting on and no mode.
    r = await post(port, '/oauth2/introspect', Object.assign({
      token: first, token_type_hint: 'refresh_token' }, client));
    note(r.status === 200 && r.json && r.json.active === false,
         '3c2. and the one it replaced introspects as inactive at once',
         r.status + ' ' + r.text.slice(0, 200));
    r = await refresh(first);
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '3d. and presenting the spent one again is refused',
         r.status + ' ' + (r.json && r.json.error));
    note(r.text.indexOf('STS-OAUTH-') < 0,
         '3e. with no error code on the wire', r.text.slice(0, 200));
    r = await refresh(second);
    note(r.status === 400,
         '3f. and the replay revoked the whole family, so its sibling is ' +
         'refused too — a replayed chain has been copied and this server ' +
         'cannot tell the holders apart', r.status);
    config.setOverride('oauth2.refreshTokenRotation', 'false');

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    try {
      require('fs').writeFileSync(OUT, JSON.stringify(findings.concat([{
        ok: false, what: 'the child ran to the end',
        detail: (e && e.stack) || String(e) }])));
    } catch (inner) {
      console.error('refresh_rotation_policy child: ' + inner.message);
    }
    process.exit(1);
  });
}

function checkTheDoor(t) {
  log.debug("Entering checkTheDoor().");
  t.log.info('=== 3. rotation at the door, in a child process ===');
  const out = path.join(os.tmpdir(), 'rrp-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RRP_ROOT: ROOT, RRP_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in checkTheDoor(): " + ((e && e.message) || e));
    // The child died before writing a report; the check below says so.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in checkTheDoor(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving checkTheDoor(). No report.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving checkTheDoor().");
}

function removeRealms() {
  log.debug("Entering removeRealms().");
  MADE.splice(0).forEach(function (id) {
    realms.remove(id);
  });
  log.debug("Leaving removeRealms().");
}

function run(t) {
  log.debug("Entering run().");
  try {
    checkRotationIsItsOwnSwitch(t);
    checkTheUnknownClient(t);
    checkTheDoor(t);
  } finally {
    removeRealms();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'refresh_rotation_policy',
  describe: 'refresh token rotation on a switch of its own, the RFC 9700 ' +
            'rules that stay behind the mode, and the unknown client OAuth ' +
            '2.1 mode refuses rather than rotates',
  run: run
};
