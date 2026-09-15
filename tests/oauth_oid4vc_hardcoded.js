'use strict';
//
// File: oauth_oid4vc_hardcoded.js
//
// ===========================================================================
// THE 2026-09-12 HARD-CODED-VALUE SWEEP OF oauth-oidc/ AND oid4vc/.
//
// An audit found literals at call sites in both directories that product mode
// shipped unchanged — a password grant that checked no password, persona
// values in signed credentials, a Math.random() Transaction Code, replay
// caches that forgot live entries, an ungated process-wide DPoP switch, open
// dynamic registration, a did:web that ignored the trust realm. This file pins
// every refusal and every bug fix that came out of it.
//
// ---------------------------------------------------------------------------
// TWO HALVES, AND WHY THE SECOND RUNS IN A CHILD PROCESS.
//
// The LIBRARY half — the replay cache, the client assertion `exp` and
// lifetime rules, the persona gate in `vc_claims.js`,
// the DPoP windows — is asserted in process against the functions themselves,
// restoring every setting with `clearOverride()` (tests/CLAUDE.md: restore with
// reset, never by writing the old value back).
//
// The ENDPOINT half cannot be: the password grant, the ID Token and UserInfo
// claims, `/dpop/nonce-mode`, `/oauth2/register`, the Transaction Code attempt
// limit, `/issuer/offer`'s sign-in requirement and `/realm/<id>/did.json` are
// all behaviour of ROUTES, and requiring the whole protocol stack into
// `run.js`'s one process would register every route on the shared app ahead of
// every later file — a test whose side effects land on somebody else's file,
// which tests/CLAUDE.md records happening twice. So a child loads
// `common/protocol_stack.js`, serves it on an ephemeral loopback port, drives
// it over real HTTP, and hands back a list of findings this file asserts. That
// is `kerberos_product_mode.js`'s shape, for the same reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'oauth_oid4vc_hardcoded',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// THE CHILD. Written as a function so it is syntax-checked with this file, and
// shipped to `node -e` as its own source. It requires nothing from the parent's
// scope: everything it needs arrives as the two environment variables below.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.HC_ROOT;
  const OUT = process.env.HC_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json)
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET') {
        headers['content-type'] = o.json !== undefined ? 'application/json'
          : 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          let parseError = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // Not JSON — an HTML page or plain text; the raw body is kept, and
            // so is the reason it did not parse. This runs in a `node -e`
            // child with no logger, so the reason travels on the result.
            parseError = e.message;
            parsed = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed,
                    parseError: parseError });
        });
      });
      req.end(body);
    });
  }

  function payloadOf(jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                            .toString('utf8'));
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const applications = require(ROOT + '/common/applications');
    const offers = require(ROOT + '/oid4vc/vc_offers');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const SECRET = 'hc-client-secret-0123456789abcdef';
    const PASSWORD = 'correct-horse-battery-staple-hc';
    const client = { client_id: 'hc-client', client_secret: SECRET };

    // --- fixtures, made in development ------------------------------------
    ldap.createUser('hc-alice', { invent: false, attributes: {
      cn: 'Alice Liddell', givenName: 'Alice', sn: 'Liddell',
      mail: 'alice@hc.example' } });
    ldap.createUser('hc-bare', { invent: false });
    credentials.setPassword('hc-alice', PASSWORD);
    credentials.setPassword('hc-bare', PASSWORD);
    applications.createApplication({ identifier: 'hc-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'hc-client', oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password',
                                 'urn:ietf:params:oauth:grant-type:pre-authorized_code'] } });
    realms.create({ id: 'hcrealm' });

    // ======================================================================
    // 1. THE PASSWORD GRANT
    // ======================================================================
    let r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
      grant_type: 'password', username: 'hc-alice',
      password: 'not-the-password' }, client) });
    note(r.status === 200, '1a. development: the password grant still ' +
                           'accepts ANY password',
         r.status + ' ' + r.text.slice(0, 120));
    r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
      grant_type: 'password', username: 'hc-alice',
      password: 'invalid' }, client) });
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '1b. development: the reserved password "invalid" is still refused',
         r.status);

    config.setOverride('global.mode', 'product');
    r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
      grant_type: 'password', username: 'hc-alice',
      password: 'not-the-password' }, client) });
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '1c. PRODUCT: a wrong password is refused invalid_grant',
         r.status + ' ' + r.text.slice(0, 160));
    note(r.json &&
         /Authentication failed for user hc-alice\.$/.test(
             r.json.error_description || ''),
         '1d. and the description is the one protocol answer, naming no ' +
         'reason (no enumeration)',
         r.json && r.json.error_description);

    r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
      grant_type: 'password', username: 'hc-alice', password: PASSWORD,
      scope: 'openid profile email' }, client) });
    note(r.status === 200 && r.json && r.json.access_token,
         '1e. PRODUCT: the right password is issued tokens',
         r.status + ' ' + r.text.slice(0, 160));

    // ======================================================================
    // 2. THE PROFILE CLAIMS COME FROM THE DIRECTORY, AND NOTHING IS INVENTED
    // ======================================================================
    if (r.json && r.json.id_token) {
      const idt = payloadOf(r.json.id_token);
      note(idt.name === 'Alice Liddell' && idt.given_name === 'Alice' &&
           idt.family_name === 'Liddell' && idt.email === 'alice@hc.example',
           '2a. PRODUCT: the ID Token\'s name, given_name, family_name and ' +
           'email are the person\'s own cn, givenName, sn and ' +
           'mail', JSON.stringify(idt));
      note(!('email_verified' in idt),
           '2b. and it asserts NO email_verified, because nothing verified ' +
           'that mailbox',
           idt.email_verified);
      // The person's own subject, from the directory (2026-09-14): the
      // entry's `entryUUID`, the same in product mode as in development.
      note(idt.sub === require(ROOT + '/common/helpers')
                         .subjectForName('hc-alice') &&
           /^urn:uuid:/.test(idt.sub),
           '2c. and sub is the person\'s urn:uuid:<entryUUID>', idt.sub);
    } else {
      note(false, '2a. PRODUCT: an ID Token came back to inspect',
           r.text.slice(0, 160));
    }
    if (r.json && r.json.access_token) {
      const info = await request(port, 'GET', '/oauth2/userinfo',
        { headers: { authorization: 'Bearer ' + r.json.access_token } });
      note(info.status === 200 && info.json &&
           info.json.family_name === 'Liddell' &&
           info.json.email === 'alice@hc.example' &&
           !('email_verified' in info.json),
           '2d. PRODUCT: UserInfo answers profile and email from the ' +
           'directory, without ' +
           'email_verified', info.status + ' ' + info.text.slice(0, 200));
    }
    r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
      grant_type: 'password', username: 'hc-bare', password: PASSWORD,
      scope: 'openid profile email' }, client) });
    if (r.json && r.json.id_token) {
      const bare = payloadOf(r.json.id_token);
      const invented = ['name', 'given_name', 'family_name', 'email',
                        'email_verified']
        .filter(function (k) { return k in bare; });
      note(invented.length === 0,
           '2e. PRODUCT: a person whose entry holds none of them gets NO ' +
           'profile claims — absent rather than invented, and never ' +
           '"undefined"', JSON.stringify(bare));
    } else {
      note(false, '2e. PRODUCT: a token for the bare person came back',
           r.text.slice(0, 160));
    }

    // 1f. A SECOND FACTOR CANNOT BE BYPASSED THROUGH THE PASSWORD GRANT.
    const realMechanisms = credentials.mechanismsFor;
    credentials.mechanismsFor = function (name) {
      const out = realMechanisms(name);
      return Object.assign({}, out,
                           { mfaRequired: true, secondFactor: 'totp' });
    };
    r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
      grant_type: 'password', username: 'hc-alice',
      password: PASSWORD }, client) });
    credentials.mechanismsFor = realMechanisms;
    note(r.status === 400 &&
         /second factor/.test((r.json || {}).error_description || ''),
         '1f. PRODUCT: a person holding a second factor is refused the ' +
         'password grant, with the door that does ask for it ' +
         'named', r.status + ' ' + r.text.slice(0, 200));

    // ======================================================================
    // 3. POST /dpop/nonce-mode — PRODUCT REFUSES, DEVELOPMENT IS PER REALM
    // ======================================================================
    r = await request(port, 'POST', '/dpop/nonce-mode',
                      { json: { required: true } });
    note(r.status === 403 && /oauth2\.dpopNonceRequired/.test(r.text),
         '3a. PRODUCT: POST /dpop/nonce-mode is refused and names the ' +
         'setting to use instead',
         r.status + ' ' + r.text.slice(0, 160));
    config.clearOverride('global.mode');

    r = await request(port, 'POST', '/realm/hcrealm/dpop/nonce-mode',
                      { json: { required: true } });
    const inRealm = await request(port, 'GET',
                                  '/realm/hcrealm/dpop/nonce-mode');
    const inDefault = await request(port, 'GET', '/dpop/nonce-mode');
    note(r.status === 200 && inRealm.json &&
         inRealm.json.nonces_required === true,
         '3b. development: the switch turns nonces on in the realm it was ' +
         'reached in',
         inRealm.text.slice(0, 120));
    note(inDefault.json && inDefault.json.nonces_required === false,
         '3c. and NOT in the default realm — it was one switch for the whole ' +
         'process',
         inDefault.text.slice(0, 120));
    await request(port, 'POST', '/realm/hcrealm/dpop/nonce-mode',
                  { json: { required: false } });

    // ======================================================================
    // 4. RFC 7591 REGISTRATION
    // ======================================================================
    config.setOverride('oauth2.registeredClientIdPrefix', 'hc-dyn-');
    config.setOverride('oauth2.registeredSecretLifetimeS', 3600);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://rp.hc.example/cb'] } });
    note(r.status === 201 && r.json && /^hc-dyn-/.test(r.json.client_id),
         '4a. development: registration is open and the client_id takes the ' +
         'configured prefix',
         r.status + ' ' + (r.json && r.json.client_id));
    note(r.json &&
         r.json.client_secret_expires_at > Math.floor(Date.now() / 1000),
         '4b. and client_secret_expires_at follows ' +
         'oauth2.registeredSecretLifetimeS',
         r.json && r.json.client_secret_expires_at);
    const registered = r.json || {};
    config.clearOverride('oauth2.registeredClientIdPrefix');
    config.clearOverride('oauth2.registeredSecretLifetimeS');

    const readNoToken = await request(port, 'GET', '/oauth2/register/' +
      encodeURIComponent(registered.client_id || 'x'));
    note(readNoToken.status === 401,
         '4c. an RFC 7592 read with no registration access token is refused',
         readNoToken.status);

    config.setOverride('global.mode', 'product');
    // A TRUSTED SOFTWARE STATEMENT IS THE SECOND DOOR THROUGH A CLOSED
    // ENDPOINT (2026-09-13), and while it may open one the endpoint stays
    // advertised — so the closed-and-unadvertised claim below is made with
    // that door shut. tests/software_statement.js holds the open door.
    config.setOverride('oauth2.softwareStatementOpensRegistration', false);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://rp.hc.example/cb'] } });
    note(r.status === 403 && /oauth2\.openRegistration/.test(r.text),
         '4d. PRODUCT: registration is refused and names ' +
         'oauth2.openRegistration',
         r.status + ' ' + r.text.slice(0, 160));
    let meta = await request(port, 'GET',
                             '/.well-known/oauth-authorization-server');
    note(meta.json && !('registration_endpoint' in meta.json),
         '4e. PRODUCT: and registration_endpoint is not advertised',
         meta.json && meta.json.registration_endpoint);
    config.setOverride('oauth2.openRegistration', true);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://rp.hc.example/cb'],
                token_endpoint_auth_method: 'client_secret_basic' } });
    meta = await request(port, 'GET',
                         '/.well-known/oauth-authorization-server');
    note(r.status === 201 && meta.json && meta.json.registration_endpoint,
         '4f. PRODUCT with oauth2.openRegistration on: registration answers ' +
         'and is advertised',
         r.status + ' ' + r.text.slice(0, 120));
    config.clearOverride('oauth2.openRegistration');
    config.clearOverride('oauth2.softwareStatementOpensRegistration');
    config.clearOverride('global.mode');

    // ======================================================================
    // 5. THE TRANSACTION CODE
    // ======================================================================
    const fakeReq = { protocol: 'http', headers: { host: '127.0.0.1:' + port },
                      get: function (n) {
                        return String(n).toLowerCase() === 'host' ?
                               '127.0.0.1:' + port : undefined;
                      } };
    config.setOverride('oid4vci.txCodeLength', 8);
    let built = offers.buildCredentialOffer(fakeReq, ['IdentityCredential'],
                                            'cross-device');
    config.clearOverride('oid4vci.txCodeLength');
    note(/^[1-9][0-9]{7}$/.test(built.txCode),
         '5a. the Transaction Code has oid4vci.txCodeLength digits and no ' +
         'leading zero', built.txCode);
    const wrongOnce = async function (code) {
      return request(port, 'POST', '/oauth2/token', { form: Object.assign({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code, tx_code: '00000000' }, client) });
    };
    for (let i = 0; i < 6; i++) {
      await wrongOnce(built.preAuthorizedCode);
    }
    note(!!offers.preAuthorizedCodes.get(built.preAuthorizedCode),
         '5b. development: six wrong codes do NOT spend the pre-authorized ' +
         'code');

    config.setOverride('global.mode', 'product');
    config.setOverride('oid4vci.txCodeMaxAttempts', 3);
    built = offers.buildCredentialOffer(fakeReq, ['IdentityCredential'],
                                        'cross-device');
    const first = await wrongOnce(built.preAuthorizedCode);
    note(first.status === 400 && /2 attempt\(s\) remain/.test(first.text),
         '5c. PRODUCT: a wrong code says how many attempts remain',
         first.text.slice(0, 200));
    await wrongOnce(built.preAuthorizedCode);
    const third = await wrongOnce(built.preAuthorizedCode);
    note(/has been spent/.test(third.text) &&
         !offers.preAuthorizedCodes.get(built.preAuthorizedCode),
         '5d. PRODUCT: the wrong code that reaches oid4vci.txCodeMaxAttempts ' +
         'SPENDS the code',
         third.text.slice(0, 200));
    const afterSpent = await request(port, 'POST', '/oauth2/token',
                                     { form: Object.assign({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': built.preAuthorizedCode,
      tx_code: built.txCode }, client) });
    note(afterSpent.status === 400,
         '5e. and the RIGHT code afterwards is refused, because the code no ' +
         'longer exists',
         afterSpent.status + ' ' + afterSpent.text.slice(0, 120));
    config.clearOverride('oid4vci.txCodeMaxAttempts');

    // ======================================================================
    // 6. /issuer/offer
    // ======================================================================
    r = await request(port, 'GET', '/issuer/offer?mode=cross-device');
    note(r.status === 302 && /\/authn\//.test(String(r.headers.location || '')),
         '6a. PRODUCT: a pre-authorized offer page with no session sends the ' +
         'browser to sign in',
         r.status + ' ' + r.headers.location);
    r = await request(port, 'GET',
                      '/issuer/offer?wallet=' +
                      encodeURIComponent('https://evil.hc.example'));
    note(r.status === 400 && /oid4vci\.allowedWalletUrls/.test(r.text),
         '6b. PRODUCT: an unregistered wallet URL is refused as an open ' +
         'redirect', r.status + ' ' + r.text.slice(0, 160));
    config.setOverride('oid4vci.allowedWalletUrls', 'https://evil.hc.example');
    r = await request(port, 'GET',
                      '/issuer/offer?wallet=' +
                      encodeURIComponent('https://evil.hc.example'));
    config.clearOverride('oid4vci.allowedWalletUrls');
    note(r.status === 302 &&
         /^https:\/\/evil\.hc\.example\/vc-issuance-1\.html\?/.test(
             String(r.headers.location)),
         '6c. PRODUCT: a wallet URL listed in oid4vci.allowedWalletUrls is ' +
         'accepted', r.headers.location);
    r = await request(port, 'GET',
                      '/oid4vp/start?wallet=' +
                      encodeURIComponent('https://evil.hc.example'));
    note(r.status === 400 && /oid4vp\.allowedWalletUrls/.test(r.text),
         '6d. PRODUCT: the Verifier refuses an unregistered wallet URL too',
         r.status + ' ' + r.text.slice(0, 160));
    config.clearOverride('global.mode');
    r = await request(port, 'GET',
                      '/issuer/offer?wallet=' +
                      encodeURIComponent('https://evil.hc.example'));
    note(r.status === 302 &&
         /^https:\/\/evil\.hc\.example\//.test(String(r.headers.location)),
         '6e. development: any wallet URL is still accepted', r.status + ' ' +
             r.headers.location);
    r = await request(port, 'GET', '/issuer/offer?mode=cross-device');
    note(r.status === 200 && /tx_code/.test(r.text),
         '6f. development: the cross-device offer page still needs no sign-in',
         r.status);

    // ======================================================================
    // 7. did:web FOLLOWS THE REALM
    // ======================================================================
    const plain = await request(port, 'GET', '/.well-known/did.json');
    note(plain.json && plain.json.id === 'did:web:127.0.0.1%3A' + port,
         '7a. the default realm\'s DID is byte-for-byte the Host-header form ' +
         'it always was',
         plain.json && plain.json.id);
    const realmDoc = await request(port, 'GET',
                                   '/realm/hcrealm/.well-known/did.json');
    note(realmDoc.json &&
         realmDoc.json.id === 'did:web:127.0.0.1%3A' + port + ':realm:hcrealm',
         '7b. a realm\'s DID carries the realm path as did:web components',
         realmDoc.json && realmDoc.json.id);
    const pathForm = await request(port, 'GET', '/realm/hcrealm/did.json');
    note(pathForm.status === 200 && pathForm.json &&
         pathForm.json.id === (realmDoc.json || {}).id,
         '7c. and resolves at <base>/did.json, where the did:web method ' +
         'looks for it',
         pathForm.status);
    const bareForm = await request(port, 'GET', '/did.json');
    note(bareForm.status === 404,
         '7d. a DID with no path is NOT also served at /did.json',
         bareForm.status);

    // ======================================================================
    // 8. THE AUTHORIZATION GRANT'S `iat` HOLE — in the child rather than in
    //    process because it builds a certificate authority, and the hierarchy
    //    is shared with every later file in `run.js`'s one process
    //    (`tests/pki.js` asserts the Root it builds itself).
    // ======================================================================
    const pki = require(ROOT + '/common/pki');
    const assertionGrant = require(ROOT + '/oauth-oidc/assertion_grant');
    const nodeCrypto = require('crypto');
    const ISS = 'https://hc-broker.example/iss';
    const AUD = 'https://localhost:8081/oauth2/token';
    applications.createApplication({ identifier: 'hc-broker',
                                     protocols: ['oauth2'] });
    applications.updateApplication('hc-broker',
                                   { attribute: 'oauthAssertionIssuer',
                                                  mode: 'add', value: ISS });
    const hierarchy = pki.hasChain() ? { ok: true } : await pki.start({});
    const issued = hierarchy.ok
      ? await pki.issueSigningKeyPair(undefined,
                                      { identifier: 'hc-broker',
                                        purpose: 'jwt' })
      : null;
    if (!issued || !issued.issued) {
      note(false, '8. a broker signing key pair was issued',
           JSON.stringify(hierarchy.errors || issued));
    } else {
      applications.updateApplication('hc-broker',
                                     { attribute: 'oauthAssertionJwks',
                                                    mode: 'set',
                                                    value: JSON.stringify(
                                                        issued.issued.jwks) });
      const sign = function (payload) {
        const alg = issued.issued.jwsAlg;
        const head = Buffer.from(JSON.stringify({ alg: alg, typ: 'JWT',
                                                  kid: issued.issued.kid }))
          .toString('base64url');
        const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const digest = /384/.test(alg) ? 'sha384' :
                       (/512/.test(alg) ? 'sha512' : 'sha256');
        const options = /^ES/.test(alg)
          ? { key: issued.issued.privateKeyPem, dsaEncoding: 'ieee-p1363' }
          : issued.issued.privateKeyPem;
        return head + '.' + body + '.' +
          nodeCrypto.sign(digest, Buffer.from(head + '.' + body), options)
                    .toString('base64url');
      };
      const now = Math.floor(Date.now() / 1000);
      const noIat = await assertionGrant.verify({ audiences: [AUD],
                                                  assertion: sign({
        iss: ISS, sub: 'hc-someone', aud: AUD, exp: now + 86000,
        jti: 'hc-noiat' }) });
      note(!noIat.ok &&
           /oauth2\.jwtBearerMaxLifetimeS/.test(noIat.description || ''),
           '8a. a day-long grant assertion with NO iat is refused by the ' +
           'ceiling (it used to skip it entirely)', noIat.description);
      const shortNoIat = await assertionGrant.verify(
          { audiences: [AUD], assertion: sign({
        iss: ISS, sub: 'hc-someone', aud: AUD, exp: now + 60,
        jti: 'hc-short' }) });
      note(shortNoIat.ok, '8b. while a short one with no iat is accepted — ' +
                          'the control',
           shortNoIat.description);
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
  t.log.info('=== the endpoint half, in a child process ===');
  const out = path.join(os.tmpdir(), 'oauth-oid4vc-hc-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', HC_ROOT: ROOT, HC_OUT: out }),
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
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

// ---------------------------------------------------------------------------
// THE LIBRARY HALF.
// ---------------------------------------------------------------------------
function hs256(secret, payload) {
  log.debug("Entering hs256().");
  const head = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
                     .toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = nodeCrypto.createHmac('sha256', secret).update(head + '.' + body)
    .digest('base64url');
  log.debug("Leaving hs256().");
  return head + '.' + body + '.' + sig;
}

async function clientAssertions(t) {
  log.debug("Entering clientAssertions().");
  t.log.info('=== client assertions: exp, the lifetime ceiling, a full ' +
             'replay cache ===');
  const config = require('../common/config');
  const clientAuth = require('../oauth-oidc/client_auth');
  const AUD = 'https://hc.example/oauth2/token';
  const SECRET = 'hc-client-assertion-secret-0123456789';
  const now = Math.floor(Date.now() / 1000);
  let n = 0;
  const verify = function (claims) {
    log.debug("Entering verify().");
    n += 1;
    log.debug("Leaving verify().");
    return clientAuth.verify({
      method: 'client_secret_jwt', clientId: 'hc-assert', clientSecret: SECRET,
      assertionType: clientAuth.ASSERTION_TYPE, audiences: [AUD],
      assertion: hs256(SECRET,
                       Object.assign({ iss: 'hc-assert', sub: 'hc-assert',
                                               aud: AUD,
                                               jti: 'hc-' + process.pid + '-' +
                                                    n }, claims))
    });
  };
  try {
    let v = await verify({ iat: now });
    t.check(v.ok, 'development: a client assertion with NO exp is still ' +
                  'accepted', v.description);
    v = await verify({ iat: now, exp: now + 3600 });
    t.check(v.ok, 'development: an hour-long client assertion is still ' +
            'accepted — the parent suite signs its post-quantum ones for an ' +
            'hour', v.description);

    config.setOverride('global.mode', 'product');
    v = await verify({ iat: now });
    t.check(!v.ok && /MUST carry an `exp`/.test(v.description || ''),
            'PRODUCT: a client assertion with no exp is refused (RFC 7523 ' +
            'section 3 claim 4)',
            v.description);
    v = await verify({ iat: now, exp: now + 3600 });
    t.check(!v.ok && /oauth2\.jwtBearerMaxLifetimeS/.test(v.description || ''),
            'PRODUCT: a client assertion longer than ' +
            'oauth2.jwtBearerMaxLifetimeS is refused',
            v.description);
    v = await verify({ exp: now + 3600 });
    t.check(!v.ok && /oauth2\.jwtBearerMaxLifetimeS/.test(v.description || ''),
            'PRODUCT: and leaving out iat does not get round the ceiling — ' +
            'it is measured from now',
            v.description);
    v = await verify({ iat: now, exp: now + 60 });
    t.check(v.ok, 'PRODUCT: a short-lived client assertion is accepted',
            v.description);
    config.clearOverride('global.mode');

    // THE REPLAY CACHE REFUSES WHEN FULL OF LIVE ENTRIES. Filled to the floor
    // of the setting in a fresh realm-less partition; every entry is live.
    config.setOverride('oauth2.assertionReplayCacheSize', 10);
    let lastOk = null;
    let refused = null;
    for (let i = 0; i < 40 && !refused; i++) {
      const got = await verify({ iat: now, exp: now + 120 });
      if (got.ok) {
        lastOk = got;
      } else {
        refused = got;
      }
    }
    t.check(lastOk !== null && refused !== null &&
            /oauth2\.assertionReplayCacheSize/.test(refused.description || ''),
            'a replay cache full of UNEXPIRED client assertions refuses the ' +
            'next one rather than forgetting a live ' +
            'one', refused && refused.description);
  } finally {
    config.clearOverride('oauth2.assertionReplayCacheSize');
    config.clearOverride('global.mode');
  }
  log.debug("Leaving clientAssertions().");
}

function personaGate(t) {
  log.debug("Entering personaGate().");
  t.log.info('=== vc_claims: the persona is a development-mode source ===');
  const config = require('../common/config');
  const vcClaims = require('../oid4vc/vc_claims');
  const nobody = 'hc-no-entry-' + process.pid;
  try {
    const dev = vcClaims.subjectClaimsFor(nobody, {});
    t.check(dev.report.some(function (row) {
      return row.source === 'generated';
    }),
            'development: a person with no entry is given generated claim ' +
            'values',
            dev.report.length + ' row(s)');
    config.setOverride('global.mode', 'product');
    const product = vcClaims.subjectClaimsFor(nobody, {});
    t.equal(product.report.filter(function (row) {
      return row.source === 'generated';
    }).length, 0,
            'PRODUCT: no claim value is generated for a signed credential');
    t.equal(Object.keys(vcClaims.generatedFor(nobody)).length, 0,
            'PRODUCT: and the populate sweep is handed nothing to write onto ' +
            'an entry');
  } finally {
    config.clearOverride('global.mode');
  }
  log.debug("Leaving personaGate().");
}

function dpopWindows(t) {
  log.debug("Entering dpopWindows().");
  t.log.info('=== DPoP: the windows are settings, and the export stays the ' +
             'default ===');
  const config = require('../common/config');
  const dpop = require('../oauth-oidc/dpop');
  try {
    t.equal(dpop.IAT_SKEW_SECONDS, 300,
            'the old export still names the default');
    config.setOverride('oauth2.dpopIatSkewS', 42);
    t.equal(dpop.state().iat_skew_seconds, 42, 'the live window follows ' +
                                               'oauth2.dpopIatSkewS');
  } finally {
    config.clearOverride('oauth2.dpopIatSkewS');
  }
  log.debug("Leaving dpopWindows().");
}

function didParts(t) {
  log.debug("Entering didParts().");
  t.log.info('=== did:web parts of a base URL ===');
  const vcDid = require('../oid4vc/vc_did');
  const bare = vcDid.didWebPartsOf('http://localhost:8081');
  t.equal(bare.host + '|' + bare.segments.join('/'), 'localhost:8081|',
          'a bare origin has a host and no segments');
  const deep = vcDid.didWebPartsOf('https://idp.example.com/sts/realm/acme');
  t.equal(deep.host + '|' + deep.segments.join('/'),
          'idp.example.com|sts/realm/acme',
          'a pinned base with a path contributes every segment');
  log.debug("Leaving didParts().");
}

async function run(t) {
  log.debug("Entering run().");
  personaGate(t);
  dpopWindows(t);
  didParts(t);
  await clientAssertions(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oauth + oid4vc hard-coded sweep',
  describe: 'the 2026-09-12 sweep: password grant, directory profile claims, ' +
            'Transaction Code, replay caches, DPoP switch, registration, ' +
            'did:web',
  run: run
};
