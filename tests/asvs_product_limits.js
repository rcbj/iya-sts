// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/asvs_product_limits.js
// ===========================================================================
// WHAT PRODUCT MODE LIMITS FOR ASVS 5.0.0 LEVEL 1 (#1453, #1455, #1456, #1457).
//
// The whole stack in a child process, switched to product by its setting:
//
//   1. GRANTS: a client that declares none is held to the code flow, and an
//      operator's opt-out lifts it.
//   2. SCEP: answers 503 until an operator opts in.
//   3. XML: AES-CBC cannot be chosen and is not read; AES-GCM still is.
//   4. KERBEROS: 17 and 18 are read out of the list until an operator opts in.
//   5. THE MAIN PORT: product with HTTPS off is a reason not to start.
//   6. THE CERTIFICATE: a self-minted one is reported, and stops nothing.
//   7. DEVELOPMENT is unchanged.
//   8. SCIM AND SHARED SIGNALS: a scheme with no scope needs a console role.
//   9. GNAP: no grace on an expired assertion unless an operator set one.
//  10. RESPONSE TYPES: a client that declares none has the code flow.
//  11. CA FILES: confined to `security.fileRoots`, links followed.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'asvs_product_limits',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.PL_ROOT;
  const OUT = process.env.PL_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const mode = require(ROOT_DIR + '/common/mode');
    const crypto = require(ROOT_DIR + '/common/crypto');
    const applications = require(ROOT_DIR + '/common/applications');

    const CLIENT = 'pl-no-grants';
    const SECRET = 'a-long-enough-client-secret-for-this-probe';
    const REDIRECT = 'https://rp.pl.example/cb';
    applications.createApplication({ identifier: CLIENT, protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    app.get('/pl-spnego-redirect', function (req, res) {
      res.redirect('/authn/spnego?authn=the-step');
    });
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const ask = function (method, p, headers, body) {
      return new Promise(function (resolve, reject) {
        const req = http.request({ port: port, host: '127.0.0.1', agent: false,
          method: method, path: p, headers: headers || {} }, function (res) {
          let text = '';
          res.on('data', function (d) {
            text += d;
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, text: text,
                      headers: res.headers });
          });
        });
        req.on('error', reject);
        req.end(body || undefined);
      });
    };
    const grant = function (type) {
      return ask('POST', '/oauth2/token', {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' +
          Buffer.from(CLIENT + ':' + SECRET).toString('base64') },
      'grant_type=' + type);
    };
    const scep = function () {
      return ask('GET', '/enroll/scep?operation=GetCACaps');
    };
    const refusedGrant = function (r) {
      return r.status === 400 && /declares no grant_types/.test(r.text);
    };
    const keys = crypto.selfSignedRsaCertificate(
      { commonName: 'sts-test', serialNumber: '02' });
    const plain = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
      'assertion" ID="_e1"><saml:Subject/></saml:Assertion>';
    const seal = function (algorithm) {
      return crypto.encryptElement(plain, keys.certPem,
        { algorithm: algorithm });
    };

    // --- 7. development first -----------------------------------------------
    let r = await grant('client_credentials');
    note(!refusedGrant(r), 'development: no list, any grant',
         r.status + ' ' + r.text.slice(0, 120));
    r = await scep();
    note(r.status !== 503, 'development: SCEP answers', r.status);
    note(crypto.decryptElement(seal('aes256-cbc'), keys.privateKeyPem).ok,
         'development: AES-CBC is read');
    note(mode.valueInForce('krb5.enctypes').indexOf('18') >= 0,
         'development: enctype 18 is in force');
    note(mode.cleartextStartupProblem(false) === '',
         'development: cleartext may start');

    config.setOverride('global.mode', 'product');

    // --- 1. grants ----------------------------------------------------------
    r = await grant('client_credentials');
    note(refusedGrant(r), 'product: no list, no client_credentials',
         r.status + ' ' + r.text.slice(0, 200));
    r = await grant('refresh_token');
    note(!refusedGrant(r), 'refresh_token gets past this check', r.status);
    r = await grant('authorization_code');
    note(!refusedGrant(r), 'and so does the code flow', r.status);
    config.setOverride('oauth2.allowUndeclaredGrants', 'true');
    r = await grant('client_credentials');
    note(!refusedGrant(r), 'the opt-out lifts it', r.status);
    config.clearOverride('oauth2.allowUndeclaredGrants');

    // --- 1a. response types, at the authorization endpoint (#1479) ----------
    const authorize = function (type) {
      return ask('GET', '/oauth2/authorize?client_id=' + CLIENT +
        '&redirect_uri=' + encodeURIComponent(REDIRECT) + '&scope=openid' +
        '&nonce=n&state=s&response_type=' + encodeURIComponent(type));
    };
    const noResponseTypes = function (r) {
      return /unauthorized_client|declares(?:\+|%20| )no(?:\+|%20| )response/
        .test(String((r.headers || {}).location || '') + r.text);
    };
    r = await authorize('id_token');
    note(noResponseTypes(r), 'product: no list, no implicit flow',
         r.status + ' ' + String((r.headers || {}).location || r.text)
           .slice(0, 200));
    r = await authorize('code id_token');
    note(noResponseTypes(r), 'and no hybrid flow', r.status);
    r = await authorize('code');
    note(!noResponseTypes(r), 'the code flow gets past this check', r.status);
    config.setOverride('oauth2.allowUndeclaredGrants', 'true');
    r = await authorize('id_token');
    note(!noResponseTypes(r), 'the opt-out lifts it', r.status);
    config.clearOverride('oauth2.allowUndeclaredGrants');

    // --- 2. SCEP ------------------------------------------------------------
    r = await scep();
    note(r.status === 503, 'product: SCEP answers 503', r.status);
    note(!/STS-[A-Z]+-\d{4}/.test(r.text), 'and sends no error code', r.text);
    config.setOverride('scep.allowInProduct', 'true');
    r = await scep();
    note(r.status !== 503, 'until an operator opts in', r.status);
    config.clearOverride('scep.allowInProduct');

    // --- 3. XML encryption --------------------------------------------------
    const cbc = crypto.decryptElement(seal('aes256-cbc'), keys.privateKeyPem);
    note(!cbc.ok && cbc.refused, 'product: AES-CBC is not read',
         JSON.stringify(cbc));
    note(crypto.decryptElement(seal('aes256-gcm'), keys.privateKeyPem).ok,
         'AES-GCM still is');
    note(!mode.allowsValue('saml2.encryptionAlgorithm', 'aes256-cbc'),
         'and AES-CBC cannot be chosen');
    note(mode.allowsValue('saml2.encryptionAlgorithm', 'aes128-gcm'),
         'while AES-128-GCM can');

    // --- 3b. disallowed hashes (#1469) ---------------------------------------
    const mgf1 = crypto.encryptElement(plain, keys.certPem,
      { algorithm: 'aes256-gcm', keyTransport: 'rsa-oaep-mgf1p' });
    note(/rsa-oaep"|xmlenc11#rsa-oaep/.test(mgf1) &&
         !/rsa-oaep-mgf1p/.test(mgf1),
         'product: OAEP over SHA-1 is not chosen, even when asked for');
    note(crypto.decryptElement(mgf1, keys.privateKeyPem).ok,
         'and what it wrote instead opens');
    const allowingLegacy = function (run) {
      const realValue = config.value;
      config.value = function (key) {
        return key === 'crypto.allowLegacyHashes' ? true : realValue(key);
      };
      const out = run();
      config.value = realValue;
      return out;
    };
    const legacy = allowingLegacy(function () {
      return crypto.encryptElement(plain, keys.certPem,
        { algorithm: 'aes256-gcm', keyTransport: 'rsa-oaep-mgf1p' });
    });
    note(/rsa-oaep-mgf1p/.test(legacy), 'the flag keeps the capability');
    const refusedOaep = crypto.decryptElement(legacy, keys.privateKeyPem);
    note(!refusedOaep.ok && refusedOaep.refused, 'off, it is not unwrapped',
         JSON.stringify(refusedOaep));
    note(allowingLegacy(function () {
      return crypto.decryptElement(legacy, keys.privateKeyPem).ok;
    }), 'on, it is');
    const sources = ['kerberos/krb5_kdc.js', 'kerberos/krb5_pkinit.ts'].map(
      function (name) {
        return fs.readFileSync(ROOT_DIR + '/' + name, 'utf8');
      });
    note(sources.every(function (text) {
      return /allowsLegacyHashes\(\)/.test(text);
    }), 'S4U2Self and the PKINIT KDF ask the flag');

    // --- 4. Kerberos --------------------------------------------------------
    const types = function () {
      return mode.valueInForce('krb5.enctypes').join(',');
    };
    note(types() === '20,19', 'product: only RFC 8009 enctypes', types());
    note(!mode.allowsValue('krb5.enctypes', ['18']), 'and 18 is not allowed');
    // The setting takes effect at a restart, so it cannot be overridden here.
    const realValue = config.value;
    config.value = function (key) {
      return key === 'krb5.allowSha1Enctypes' ? true : realValue(key);
    };
    note(types() === '18,17,20,19',
         'the opt-in brings 17 and 18 back, never 23', types());
    config.value = realValue;

    // --- 8. no default administrator name (#1447) ---------------------------
    const names = require(ROOT_DIR + '/common/bootstrap_name');
    const generated = names.current();
    note(/^admin-[0-9a-f]{16}$/.test(generated),
         'product: admin gives way to a generated name', generated);
    note(names.current() === generated, 'and it is the same name every time');
    const valueFor = function (over, run) {
      const realValue = config.value;
      config.value = function (key) {
        return Object.prototype.hasOwnProperty.call(over, key) ? over[key]
          : realValue(key);
      };
      const out = run();
      config.value = realValue;
      return out;
    };
    ['root', 'SA', 'Administrator', ''].forEach(function (name) {
      note(valueFor({ 'admin.bootstrapUsername': name }, names.current) ===
           generated, 'so does ' + (name || 'no name'));
    });
    note(valueFor({ 'admin.bootstrapUsername': 'pat' }, names.current) ===
         'pat', 'an operator\'s own name is used');
    note(valueFor({ 'admin.allowDefaultUsername': true }, names.current) ===
         'admin', 'and the opt-out keeps admin');

    // --- 9. the directory withholds every credential (#1452) ----------------
    const list = JSON.stringify(JSON.parse(fs.readFileSync(ROOT_DIR +
      '/models/generated/directory.names.json', 'utf8')).secret)
      .replace(/"/g, "'");
    ['userpassword', 'ststotpcredential', 'stsbackupcodes',
      'stsactivationtoken', 'stspasswordresettoken', 'oauthclientsecret',
      'stsassertionprivatekey', 'stsenrolledprivatekey'].forEach(
      function (name) {
        note(list.indexOf("'" + name + "'") >= 0,
             name + ' is withheld from every LDAP reader');
      });
    // The SCIM mapping is the model's since #1579.
    const scimMap = fs.readFileSync(ROOT_DIR + '/models/scim/scim.tsp',
                                    'utf8');
    note(/ldap:\s*"uid"/.test(scimMap) &&
         !/ldap:\s*"(stsTotp|stsBackup|oauthClientSecret|stsActivation)/i
           .test(scimMap), 'and SCIM maps none of them');

    // --- 10. a person with no scope needs a role (#1473) --------------------
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const scimAs = function (who, pass) {
      return ask('GET', '/scim/v2/Users', { authorization: 'Basic ' +
        Buffer.from(who + ':' + pass).toString('base64'),
        accept: 'application/scim+json' });
    };
    const PASS = 'A-long-enough-probe-passphrase-77';
    // These rows are about the role, not the second factor (#1490).
    config.setOverride('authn.allowOptionalSecondFactor', 'true');
    ['pl-plain', 'pl-reader', 'pl-writer'].forEach(function (name) {
      // Product's attribute policy (#396) requires these of every person.
      ldap.createUser(name, { invent: false, attributes: { cn: name,
        givenName: 'Probe', sn: name, mail: name + '@example.test' } });
      const set = credentials.setPassword(name, PASS);
      note(set.ok, name + ' has a password', JSON.stringify(set.errors || []));
    });
    rbac.grant('pl-reader', 'read', { via: 'test' });
    rbac.grant('pl-writer', 'write', { via: 'test' });
    r = await scimAs('pl-plain', PASS);
    note(r.status === 403, 'product: a password with no role is refused at SCIM',
         r.status + ' ' + r.text.slice(0, 160));
    r = await scimAs('pl-reader', PASS);
    note(r.status === 200, 'Admin Read may read', r.status + ' ' +
         r.text.slice(0, 160));
    const writeAs = function (who) {
      return ask('POST', '/scim/v2/Users', { authorization: 'Basic ' +
        Buffer.from(who + ':' + PASS).toString('base64'),
        'content-type': 'application/scim+json' },
      JSON.stringify({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                       userName: 'pl-made-' + who }));
    };
    r = await writeAs('pl-reader');
    note(r.status === 403, 'but not write', r.status);
    const ssfAs = function (who) {
      return ask('GET', '/ssf/stream', { authorization: 'Basic ' +
        Buffer.from(who + ':' + PASS).toString('base64') });
    };
    r = await ssfAs('pl-plain');
    note(r.status === 403, 'product: a password with no role is refused at SSF',
         r.status + ' ' + r.text.slice(0, 160));
    r = await ssfAs('pl-reader');
    note(r.status === 403, 'and Admin Read is not enough, Basic grants write',
         r.status + ' ' + r.text.slice(0, 160));
    r = await ssfAs('pl-writer');
    note(r.status !== 403 && r.status !== 401, 'Admin Write may',
         r.status + ' ' + r.text.slice(0, 160));
    r = await writeAs('pl-writer');
    note(r.status !== 403 && r.status !== 401, 'Admin Write may',
         r.status + ' ' + r.text.slice(0, 160));
    const realAllow = config.value;
    config.value = function (key) {
      return key === 'security.allowUnscopedPeople' ? true : realAllow(key);
    };
    r = await scimAs('pl-plain', PASS);
    note(r.status === 200, 'the opt-out lifts it', r.status);
    config.value = realAllow;

    // --- 12. a CA file an administrator names (#1481) ------------------------
    const outbound = require(ROOT_DIR + '/common/outbound_tls');
    const scratch = fs.mkdtempSync(require('os').tmpdir() + '/pl-ca-');
    fs.mkdirSync(scratch + '/certs');
    fs.writeFileSync(scratch + '/certs/good.pem', 'x');
    fs.writeFileSync(scratch + '/outside.pem', 'x');
    fs.symlinkSync(scratch + '/outside.pem', scratch + '/certs/link.pem');
    const realCaValue = config.value;
    config.value = function (key) {
      return key === 'security.fileRoots' ? scratch + '/certs'
        : realCaValue(key);
    };
    note(outbound.namedFileAllowed(scratch + '/certs/good.pem'),
         'product: a CA file inside a listed directory may be read');
    note(!outbound.namedFileAllowed(scratch + '/outside.pem'),
         'one outside them may not');
    note(!outbound.namedFileAllowed(scratch + '/certs/link.pem'),
         'nor a symbolic link out of them');
    note(!outbound.namedFileAllowed(scratch + '/certs/../outside.pem'),
         'nor a path that climbs out');
    note(!outbound.namedFileAllowed('certs/good.pem'), 'nor a relative path');
    note(!outbound.namedFileAllowed(scratch + '/certs/none.pem'),
         'and one that does not exist answers the same');
    note(/fileRoots/.test(String(outbound.caFilePems('/etc/passwd'))) &&
         String(outbound.caFilePems('/etc/passwd')).indexOf('passwd') < 0,
         'the sentence names the setting and not the file');
    config.value = realCaValue;

    // --- 14. JWE content encryption (#1486) ---------------------------------
    r = await ask('GET', '/.well-known/openid-configuration');
    const discovered = JSON.parse(r.text);
    note(['id_token_encryption_enc_values_supported',
      'userinfo_encryption_enc_values_supported',
      'authorization_encryption_enc_values_supported',
      'request_object_encryption_enc_values_supported'
    ].every(function (member) {
      return Array.isArray(discovered[member]) && discovered[member].length &&
        !discovered[member].some(function (one) {
          return /CBC/.test(one);
        });
    }), 'product: discovery offers no CBC-HMAC content encryption',
    String(discovered.id_token_encryption_enc_values_supported));
    note(applications.defaultJweEnc() === 'A256GCM',
         'a client naming no enc is answered in AES-GCM');
    let cbcRefusal = '';
    try {
      crypto.encryptJweCompact('payload',
                               { enc: 'A128CBC-HS256', alg: 'RSA-OAEP-256' });
    } catch (e) {
      cbcRefusal = String(e && e.message);
    }
    note(/allowCbcJwe/.test(cbcRefusal), 'and the door refuses to encrypt with it',
         cbcRefusal);
    config.setOverride('crypto.allowCbcJwe', 'true');
    note(applications.defaultJweEnc() === 'A128CBC-HS256' &&
         applications.permittedEncs(['A256GCM', 'A128CBC-HS256']).length === 2,
         'the opt-out restores them');
    config.clearOverride('crypto.allowCbcJwe');

    // --- 15. the SPNEGO step leaves the address (#1487) ----------------------
    r = await ask('GET', '/pl-spnego-redirect');
    note(r.headers.location === '/authn/spnego' &&
         /sts_signin_step=the-step/.test(String(r.headers['set-cookie'])),
         'product: the SPNEGO step goes by cookie, not by address',
         String(r.headers.location) + ' ' + String(r.headers['set-cookie']));
    const stepper = require(ROOT_DIR + '/common/step_address');
    note(stepper.stepOfCookie({ headers: {
      cookie: 'a=b; sts_signin_step=the-step' } }) === 'the-step',
         'and the door reads it back');

    // --- 16. every named file goes through the rule (#1481) -------------------
    let namedRefusal = '';
    try {
      outbound.assertNamedFile('/etc/passwd');
    } catch (e) {
      namedRefusal = String(e && e.message);
    }
    note(/fileRoots/.test(namedRefusal) && namedRefusal.indexOf('passwd') < 0,
         'product: a named file outside the directories is refused, and the ' +
         'sentence does not repeat the path', namedRefusal);
    ['spiffe/spiffe_sigstore.ts', 'spiffe/spiffe_sigstore_tuf.ts',
      'spiffe/spiffe_attestor_k8s_psat.ts',
      'spiffe/spiffe_workload_attestor_k8s.ts',
      'spiffe/spiffe_attestor_azure_imds.ts',
      'spiffe/spiffe_attestor_gcp_iit.ts', 'common/mail_transports.ts',
      'common/revocation_status.js'].forEach(function (file) {
      note(fs.readFileSync(ROOT_DIR + '/' + file, 'utf8')
        .indexOf('assertNamedFile') >= 0, file + ' asks the rule');
    });

    // --- 17. L2: the push dialer, the issuance gate, PKCE, LDAP (#1492-#1496) -
    const ssfHttp = require(ROOT_DIR + '/ssf/ssf_http');
    r = await ssfHttp.pushSet('https://127.0.0.1:9/set', 'token', {});
    note(!r.ok && /internal|private|loopback|reserved/i.test(String(r.why)),
         'product: a push to an internal address is refused', JSON.stringify(r));
    const gate = require(ROOT_DIR + '/common/issuance_gate');
    gate.setDecider(function () {
      throw new Error('planted');
    });
    let gated = gate.check({ kind: gate.KINDS ? Object.values(gate.KINDS)[0] : '',
                             application: CLIENT, subject: { name: 'x' } });
    note(gated.allowed === false,
         'product: an issuance decider that throws issues nothing',
         JSON.stringify(gated));
    gate.setDecider(function () {
      return null;
    });
    gated = gate.check({ kind: gate.KINDS ? Object.values(gate.KINDS)[0] : '',
                         application: CLIENT, subject: { name: 'x' } });
    note(gated.allowed === false, 'nor one that answers nothing',
         JSON.stringify(gated));
    gate.setDecider(null);
    const asked = await ask('GET', '/oauth2/authorize?client_id=' + CLIENT +
      '&redirect_uri=' + encodeURIComponent(REDIRECT) +
      '&scope=openid&nonce=n&state=s&response_type=code');
    note(/invalid_request|PKCE/.test(String((asked.headers || {}).location || '') +
                                     asked.text),
         'product: a confidential client with no code_challenge is refused',
         asked.status + ' ' + String((asked.headers || {}).location || ''));
    note(config.value('ldap.plainListener') === false,
         'product: the plain LDAP listener is off by default');
    note(config.value('authn.sessionIdleTimeoutS') === 1800,
         'product: sessions have a 30-minute idle timeout by default');
    note(config.value('pki.keyAlgorithm') === 'rsa-3072' &&
         config.value('tls.selfSignedKeyBits') === 3072 &&
         mode.defaultRsaBits() === 3072, 'product: new RSA keys are 3072 bits');
    const bootDir = fs.mkdtempSync(require('os').tmpdir() + '/pl-boot-');
    const bootValue = config.value;
    let bootLog = false;
    config.value = function (key) {
      return key === 'persistence.dataDir' ? bootDir
        : (key === 'admin.logBootstrapPassword' ? bootLog : bootValue(key));
    };
    const bootCreds = require(ROOT_DIR + '/common/credentials');
    const held = bootCreds.writeBootstrapPassword('first-admin', 'the-secret');
    note(held === bootDir + '/bootstrap-admin-password' &&
         (fs.statSync(held).mode & 0o777) === 0o600 &&
         fs.readFileSync(held, 'utf8') === 'first-admin:the-secret\n',
         'the bootstrap password goes to a file only this service can read',
         held);
    bootLog = true;
    note(bootCreds.writeBootstrapPassword('a', 'b') === '',
         'and the opt-out returns to the log');
    config.value = bootValue;

    // --- 18. a second factor for everybody, and the doors that cannot ask ----
    // An app password needs no second factor there, deliberately (#1490).
    config.clearOverride('authn.allowOptionalSecondFactor');
    const appPass = credentials.createAppPassword('pl-plain', {
      name: 'a job', doors: ['scim'], createdBy: 'pl-plain' });
    note(appPass.ok, 'an app password can be made with no second factor held',
         JSON.stringify(appPass.errors || []));
    const own = credentials.verify('pl-plain', PASS,
                                   { via: 'test', door: 'scim' });
    note(own.ok === false && own.reason === 'second-factor-required',
         'product: the person\'s own password is refused at a password-only door',
         JSON.stringify(own));
    const viaApp = credentials.verify('pl-plain', appPass.password,
                                      { via: 'test', door: 'scim' });
    note(viaApp.ok === true,
         'and an app password works there with no second factor',
         JSON.stringify(viaApp).slice(0, 200));

    // --- 13. a certificate sign-in from a browser (#1484) --------------------
    const signIn = function (site, dest, fetched) {
      return ask('GET', '/tls/sign-in', site === undefined ? {}
        : { 'sec-fetch-site': site, 'sec-fetch-dest': dest,
            'sec-fetch-mode': fetched });
    };
    r = await signIn('cross-site', 'document', 'navigate');
    note(r.status === 403, 'product: a link from another site starts nothing',
         r.status);
    r = await signIn('same-origin', 'image', 'no-cors');
    note(r.status === 403, 'nor does an image on this origin', r.status);
    r = await signIn('same-origin', 'iframe', 'navigate');
    note(r.status === 403, 'nor a frame', r.status);
    r = await signIn('none', 'document', 'navigate');
    note(r.status === 200, 'an address the person typed is answered', r.status);
    r = await signIn('same-origin', 'document', 'navigate');
    note(r.status === 200, 'and a link on this origin', r.status);
    r = await signIn(undefined);
    note(r.status === 200, 'and a program, which sends none of them', r.status);

    // --- 11. the GNAP grace --------------------------------------------------
    note(mode.expiredAssertionGraceS() === 0,
         'product: an expired GNAP assertion gets no grace by default');
    const realSource = config.sourceOf;
    config.sourceOf = function (key) {
      return key === 'gnap.assertionMaxAgeS' ? 'env' : realSource(key);
    };
    note(mode.expiredAssertionGraceS() > 0,
         'and an operator who set one gets it');
    config.sourceOf = realSource;

    // --- 5. the main port ---------------------------------------------------
    note(/global\.https/.test(mode.cleartextStartupProblem(false)),
         'product: cleartext is a reason not to start');
    note(mode.cleartextStartupProblem(true) === '', 'TLS is not');
    note(/cleartextStartupProblem\(useHttps\)[\s\S]{0,200}process\.exit\(1\)/
      .test(fs.readFileSync(ROOT_DIR + '/server.js', 'utf8')),
         'and server.js acts on it');

    // --- 6. the certificate -------------------------------------------------
    const row = function () {
      return mode.report().requirements.filter(function (one) {
        return one.id === 'public-certificate';
      })[0];
    };
    note(row() && row().waived && row().waived.length === 1,
         'product: a self-minted certificate is reported on /admin/mode',
         JSON.stringify(row()));
    ['main-port-https', 'legacy-ciphers', 'declared-grants'].forEach(
      function (id) {
        note(mode.REQUIREMENTS.some(function (one) {
          return one.id === id;
        }), id + ' is described on /admin/mode');
      });
    config.clearOverride('global.mode');

    fs.writeFileSync(OUT, JSON.stringify(findings));
    server.close();
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the probe ran', (e && e.stack) || e);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports what it found.
 *
 * @param {object} t - the runner's checker
 * @returns {Promise<void>}
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'pl-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  PL_ROOT: ROOT, PL_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'asvs_product_limits',
  describe: 'what product mode limits for ASVS 5.0.0 Level 1: grants a ' +
            'client did not declare, SCEP, XML AES-CBC, Kerberos SHA-1, ' +
            'a cleartext main port and a self-minted certificate',
  run: run
};
