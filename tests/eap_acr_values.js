// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/eap_acr_values.js
//
// ===========================================================================
// OPENID CONNECT EAP ACR VALUES 1.0: `phr` AND `phrh`, REQUESTED, EARNED FROM
// EVIDENCE AND ASSERTED (#723).
//
// A relying party asks for a phishing-resistant sign-in with
// `acr_values=phr` (or `phrh`, the key hardware-protected) and reads the
// answer in the ID Token's `acr`. `common/phishing_resistance.ts` says what
// earns which; `oauth-oidc/step_up.ts` honours the request; the issuance
// policy sees it as `urn:sts:xacml:phishing-resistance`. These are the
// claims about that:
//
//   A. THE EVIDENCE (in this process, the libraries): a WebAuthn assertion
//      and a client certificate earn `phr`; an assertion by a key whose
//      attestation is trusted and whose BE flag is clear earns `phrh`; a
//      synced or unattested key `phr` only; a key enrolled in the same act,
//      a password, a one-time code, an emailed code, a recovery code, a
//      wallet and a Kerberos ticket earn nothing; a federation partner's
//      `phr` / `phrh` is carried; a session is its latest event.
//   B. WHAT MEETS WHAT: a session by its evidence, a token by its own `acr`
//      (`phrh` states `phr`); `amr` `hwk` with `mfa` no longer meets `phr`;
//      neither class is a rung; `hwk` is unchanged.
//   C. THE SCREEN AND THE REFUSALS: `phr`/`phrh` alone demand a key, alone
//      or after a password; an unmet request is STS-OAUTH-0970, and `phrh`
//      on a `phr` sign-in STS-OAUTH-0971 saying why; a detail type's
//      required `phr` is carried by the token.
//   D. THE ISSUANCE POLICY: the template's two options add a Deny each,
//      empty adds none, and the PDP refuses `none` (and `phr` where `phrh` is
//      required) for the listed application only.
//   E. OVER HTTP, in a CHILD PROCESS serving the stack on a loopback port
//      with a software authenticator (`passkey_backup_eligible.js`'s):
//        1. discovery publishes `phr` and `phrh`;
//        2. a passkey sign-in with no acr_values carries `acr` "1", as before;
//        3. `acr_values=phr` and `phrh` on a passkey with a trusted
//           attestation and BE clear carry `phr` and `phrh`;
//        4. a password with that person's security key as the step carries
//           `phr`;
//        5. a synced passkey carries `phr`, and under `phrh` is refused
//           unmet_authentication_requirements naming the backup flag;
//        6. a password-only person under `phr` is not let through on the
//           password — the screen demands a key — and a password session
//           returning under the round-trip marker is refused
//           unmet_authentication_requirements;
//        7. the issuance policy's `requirePhishingResistant` refuses a
//           password sign-in to the application it lists and admits a
//           passkey one.
//
// The attestation record written for the trusted keys is a FIXTURE invented
// here (`{ trusted: true, format: 'packed', ... }`): the stored shape
// `webauthn_attestation.ts` writes, without the certificate chain that would
// have earned it, which this file does not exercise.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'eap_acr_values',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// An authentication event as `authn.authenticationEvent()` records one.
function event(fields) {
  log.debug("Entering event().");
  const f = fields || {};
  log.debug("Leaving event().");
  return { at: 1000, amr: f.amr || [], acr: f.acr || '1',
           authenticated: f.authenticated !== false,
           authority: { kind: f.authority || 'local' },
           context: { credential: f.credential || {} } };
}

// ---------------------------------------------------------------------------
// A. THE EVIDENCE.
// ---------------------------------------------------------------------------
function evidence(t) {
  log.debug("Entering evidence().");
  t.log.info('=== A. the evidence ===');
  const pr = require('../common/phishing_resistance');
  const of = function of(fields) {
    log.debug("Entering of().");
    log.debug("Leaving of().");
    return pr.ofEvent(event(fields)).join(' ');
  };
  const hardware = { kind: 'webauthn', ceremony: 'assertion',
                     attestationTrusted: true, backupEligible: false };
  t.check(of({ amr: ['hwk'], credential: hardware }) === 'phr phrh',
          'A1. an assertion by a key with a trusted attestation and BE clear ' +
          'earns phr and phrh', of({ credential: hardware }));
  t.check(of({ credential: Object.assign({}, hardware,
                                         { backupEligible: true }) }) ===
          'phr' &&
          of({ credential: Object.assign({}, hardware,
                                         { attestationTrusted: false }) }) ===
          'phr' &&
          of({ credential: { kind: 'webauthn', ceremony: 'assertion' } }) ===
          'phr',
          'A2. a synced key, an unattested key, and one whose flags were not ' +
          'reported earn phr and never phrh');
  t.check(of({ credential: Object.assign({}, hardware,
                                         { ceremony: 'registration' }) }) ===
          '',
          'A3. a key REGISTERED in the same act earns nothing (EAP section ' +
          '4: provisioned on the strength of what came before it)');
  t.check(of({ amr: ['swk'], credential: { kind: 'certificate' } }) === 'phr',
          'A4. a TLS client certificate earns phr, and not phrh');
  const nothing = ['password', 'totp', 'email-code', 'email-link',
                   'backup-code', 'wallet'].filter(function (kind) {
    return of({ amr: ['hwk', 'pwd'], acr: 'mfa',
                credential: { kind: kind } }) !== '';
  });
  t.check(!nothing.length &&
          of({ authority: 'kerberos', amr: ['hwk'],
               credential: { kind: 'kerberos' } }) === '' &&
          of({ authenticated: false, credential: hardware }) === '',
          'A5. a password, a one-time code, an emailed code or link, a ' +
          'recovery code, a wallet, a Kerberos ticket and an anonymous ' +
          'session earn nothing, whatever amr says', nothing.join(', '));
  t.check(of({ authority: 'federation', acr: 'phrh' }) === 'phr phrh' &&
          of({ authority: 'federation', acr: 'phr' }) === 'phr' &&
          of({ authority: 'federation', acr: 'mfa', amr: ['hwk'] }) === '',
          'A6. a federation partner\'s phr / phrh is carried as it said it');
  const session = { acr: '1', events: [
    event({ credential: hardware }),
    event({ amr: ['pwd'], credential: { kind: 'password' } })] };
  t.check(pr.ofSession(session).length === 0 &&
          pr.ofSession({ events: session.events.slice(0, 1) }).length === 2,
          'A7. a session is its LATEST authenticated event: a password after ' +
          'a passkey leaves nothing');
  t.check(pr.factOf([]).join() === 'none' &&
          pr.factOf(['phr']).join() === 'phr',
          'A8. the XACML fact is never empty: none when nothing was earned');
  log.debug("Leaving evidence().");
}

// ---------------------------------------------------------------------------
// B, C. WHAT MEETS WHAT, THE SCREEN AND THE REFUSALS.
// ---------------------------------------------------------------------------
function meetsAndRefusals(t) {
  log.debug("Entering meetsAndRefusals().");
  t.log.info('=== B. what meets what; C. the screen and the refusals ===');
  const stepUp = require('../oauth-oidc/step_up');
  const errorCodes = require('../common/error_codes');
  const passkey = { acr: '1', amr: ['hwk'], events: [event({ amr: ['hwk'],
    credential: { kind: 'webauthn', ceremony: 'assertion',
                  attestationTrusted: false, backupEligible: true } })] };
  const hardware = { acr: '1', amr: ['hwk'], events: [event({ amr: ['hwk'],
    credential: { kind: 'webauthn', ceremony: 'assertion',
                  attestationTrusted: true, backupEligible: false } })] };
  const totp = { acr: 'mfa', amr: ['pwd', 'otp'], events: [event({
    acr: 'mfa', amr: ['pwd', 'otp'], credential: { kind: 'totp' } })] };
  t.check(stepUp.meets('phr', passkey) && !stepUp.meets('phrh', passkey) &&
          stepUp.meets('phrh', hardware) && stepUp.meets('phr', hardware) &&
          !stepUp.meets('phr', totp) && !stepUp.meets('mfa', passkey) &&
          stepUp.meets('1', passkey),
          'B1. a session meets phr / phrh by its evidence, and they are not ' +
          'rungs: a passkey is not mfa, two factors without a key are not phr');
  t.check(stepUp.meets('phr', { acr: 'phr' }) &&
          stepUp.meets('phr', { acr: 'phrh' }) &&
          !stepUp.meets('phrh', { acr: 'phr' }) &&
          stepUp.meets('1', { acr: 'phr' }) &&
          !stepUp.meets('mfa', { acr: 'phrh' }) &&
          !stepUp.meets('phr', { acr: 'mfa', amr: ['pwd', 'hwk'] }),
          'B2. a token meets them only by its own acr (phrh states phr, ' +
          'either meets 1); mfa with amr hwk no longer meets phr');
  t.check(stepUp.meets('hwk', { acr: 'mfa', amr: ['pwd', 'hwk'] }) &&
          JSON.stringify(stepUp.screenDemandFor(['hwk'])) ===
          '{"forceMfa":true,"forceKey":true}',
          'B3. hwk is unchanged: a password with a key, and both demanded');
  t.check(JSON.stringify(stepUp.screenDemandFor(['phr'])) ===
          '{"forceMfa":false,"forceKey":true}' &&
          JSON.stringify(stepUp.screenDemandFor(['phrh', 'phr'])) ===
          '{"forceMfa":false,"forceKey":true}' &&
          JSON.stringify(stepUp.screenDemandFor(['phr', 'mfa'])) ===
          '{"forceMfa":false,"forceKey":false}' &&
          !stepUp.demandsSecondFactor(['phr']),
          'C1. phr / phrh alone demand a key (alone or after a password) and ' +
          'not a second factor; phr mfa demands neither');
  t.check(stepUp.SUPPORTED.indexOf('phr') === 3 &&
          stepUp.SUPPORTED.indexOf('phrh') === 4,
          'C2. both are published after the ladder',
          JSON.stringify(stepUp.SUPPORTED));
  const need = function need(values) {
    log.debug("Entering need().");
    log.debug("Leaving need().");
    return { acrValues: values, maxAge: null, present: true };
  };
  let assessed = stepUp.assessSession(need(['phr']), totp,
                                      { honoured: true });
  let refusal = stepUp.unmetRefusal(need(['phr']), assessed, false);
  t.check(!assessed.met && refusal.error ===
          'unmet_authentication_requirements' &&
          errorCodes.codeOf(refusal) === 'STS-OAUTH-0970',
          'C3. phr unmet on the return leg is unmet_authentication_' +
          'requirements, STS-OAUTH-0970', JSON.stringify(refusal));
  assessed = stepUp.assessSession(need(['phrh']), passkey,
                                  { honoured: true });
  refusal = stepUp.unmetRefusal(need(['phrh']), assessed, false);
  t.check(!assessed.met && errorCodes.codeOf(refusal) === 'STS-OAUTH-0971' &&
          /backup-eligible/.test(refusal.description),
          'C4. phrh on a synced passkey is STS-OAUTH-0971, saying the key ' +
          'is backup-eligible', refusal.description);
  assessed = stepUp.assessSession(need(['phr']), passkey, {});
  t.check(assessed.met && assessed.acr === 'phr',
          'C5. met, the token carries the value requested',
          JSON.stringify(assessed));
  assessed = stepUp.assessSession({ acrValues: [], maxAge: null }, passkey,
                                  { required: ['phr'] });
  t.check(assessed.met && assessed.acr === 'phr',
          'C6. a detail type\'s required phr is carried as the token\'s acr, ' +
          'so the token endpoint\'s check meets it', JSON.stringify(assessed));
  assessed = stepUp.assessSession({ acrValues: [], maxAge: null }, passkey,
                                  {});
  t.check(assessed.met && assessed.acr === '1',
          'C7. nothing requested: the session\'s own acr, as before');
  log.debug("Leaving meetsAndRefusals().");
}

// ---------------------------------------------------------------------------
// D. THE ISSUANCE POLICY.
// ---------------------------------------------------------------------------
function issuancePolicy(t) {
  log.debug("Entering issuancePolicy().");
  t.log.info('=== D. the issuance policy ===');
  const templates = require('../xacml/xacml_templates');
  const pdp = require('../xacml/xacml_pdp');
  const rolePep = require('../xacml/xacml_role_pep');
  const AUTHN = templates.AUTHN_ATTRIBUTE;
  const ruleIds = function ruleIds(built) {
    log.debug("Entering ruleIds().");
    log.debug("Leaving ruleIds().");
    return built.policy.rules.map(function (r) {
      return String(r.id).replace(/^.*:rule:/, '');
    });
  };
  const plain = templates.build('role-issuance', {},
                                { name: 'role-issuance' });
  t.check(plain.ok && ruleIds(plain).indexOf('phishing-resistant') < 0 &&
          ruleIds(plain).indexOf('hardware-protected') < 0,
          'D1. the built-in policy carries neither rule by default');
  const strict = templates.build('role-issuance', {
    requirePhishingResistant: 'eap-phr',
    requireHardwareProtected: 'eap-phrh' }, { name: 'role-issuance' });
  t.check(strict.ok && ruleIds(strict).indexOf('phishing-resistant') >= 0 &&
          ruleIds(strict).indexOf('hardware-protected') >= 0,
          'D2. the two options add one each', JSON.stringify(strict.why));
  const decide = function decide(application, fact) {
    log.debug("Entering decide().");
    const request = rolePep.buildRequest({
      application: application, kind: 'start-session',
      subject: { kind: 'user', name: 'someone', authenticated: true },
      authentication: { amr: ['pwd'], acr: '1', kinds: ['password'] },
      phishingResistance: fact }, ['EVERYBODY'], [], ['EVERYBODY']);
    const answer = pdp.evaluate(strict.policy, request, {});
    const authn = (answer.obligations || []).some(function (o) {
      return o.id === AUTHN.OBLIGATION;
    });
    log.debug("Leaving decide().");
    return answer.decision + (authn ? '+authn' : '');
  };
  const seen = [decide('eap-phr', ['none']), decide('eap-phr', ['phr']),
                decide('other', ['none']), decide('eap-phrh', ['phr']),
                decide('eap-phrh', ['phr', 'phrh']), decide('eap-phrh', null),
                decide('eap-phr', null)];
  t.check(seen.join(' ') ===
          'Deny+authn Permit Permit Deny+authn Permit Permit Permit',
          'D3. the PDP refuses none for the phr application, phr for the ' +
          'phrh one, with the authentication obligation — and nothing for ' +
          'another application or an issuance the gate did not describe',
          seen.join(' '));
  log.debug("Leaving issuancePolicy().");
}

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.EAP_ROOT;
  const OUT = process.env.EAP_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = {};
        if (Object.keys(jar).length && !o.noCookies) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              json = null;
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: json });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }

  // A SOFTWARE AUTHENTICATOR — `passkey_backup_eligible.js`'s, assertions
  // only: the keys are written to the directory with `addKey()`, so what a
  // key's row says about its attestation is the test's to choose.
  const sha256 = function (buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
  };
  const makeAuthenticator = function (rpId, origin, backup) {
    const backupBits = backup === 'synced' ? 0x18 : 0;
    const pair = nodeCrypto.generateKeyPairSync('ec',
                                                { namedCurve: 'prime256v1' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const credentialId = nodeCrypto.randomBytes(32);
    let signCount = 0;
    let userHandle = '';
    return {
      credentialId: credentialId.toString('base64url'),
      jwk: jwk,
      setHandle: function (h) { userHandle = h; },
      assert: function (challenge) {
        signCount += 1;
        const count = Buffer.alloc(4);
        count.writeUInt32BE(signCount >>> 0, 0);
        const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
                                    Buffer.from([0x05 | backupBits]), count]);
        const cdj = Buffer.from(JSON.stringify({ type: 'webauthn.get',
          challenge: challenge, origin: origin, crossOrigin: false }),
                                'utf8');
        const signature = nodeCrypto.sign(
          'sha256', Buffer.concat([data, sha256(cdj)]), pair.privateKey);
        return { id: credentialId.toString('base64url'),
                 rawId: credentialId.toString('base64url'),
                 type: 'public-key',
                 response: {
                   authenticatorData: data.toString('base64url'),
                   clientDataJSON: cdj.toString('base64url'),
                   signature: signature.toString('base64url'),
                   userHandle: userHandle || null } };
      }
    };
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const templates = require(ROOT + '/xacml/xacml_templates');
    const xml = require(ROOT + '/xacml/xacml_xml');
    const xacmlStore = require(ROOT + '/xacml/xacml_store');
    const rolePep = require(ROOT + '/xacml/xacml_role_pep');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.eap.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-eap-7!';
    const VERIFIER = nodeCrypto.randomBytes(32).toString('base64url');
    const CHALLENGE = nodeCrypto.createHash('sha256').update(VERIFIER)
      .digest('base64url');
    config.setOverride('oauth2.consentRequired', false);

    ['eap-rp', 'eap-strict'].forEach(function (id) {
      applications.createApplication({ identifier: id,
        protocols: ['oauth2'],
        fields: { oauthClientId: id, oauthClientSecret: '',
                  oauthRedirectUri: [REDIRECT],
                  oauthTokenEndpointAuthMethod: 'none',
                  oauthGrantType: ['authorization_code'] } });
    });
    ['eap-erin', 'eap-dave', 'eap-carol', 'eap-bob'].forEach(
      function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });
    // The stored shape of a trusted statement — a FIXTURE (the header).
    const TRUSTED = { format: 'packed', type: 'basic', verified: true,
                      trusted: true, anchor: 'eap-test-anchor', why: '' };
    const keyFor = function (name, role, backup, attestation) {
      const key = makeAuthenticator(RPID, ORIGIN, backup);
      const handle = credentials.userHandleOf(name, { mint: true });
      key.setHandle(handle);
      const added = credentials.addKey(name, {
        credentialId: key.credentialId, publicKeyJwk: key.jwk,
        userHandle: handle, backupEligible: backup === 'synced',
        backupState: backup === 'synced',
        attestation: attestation || null }, role);
      note(added.ok, '(a ' + role + ' key for ' + name + ': ' +
           (backup || 'device-bound') + ', ' +
           (attestation ? 'trusted' : 'unattested') + ')',
           JSON.stringify(added.errors || []));
      return key;
    };
    const erinKey = keyFor('eap-erin', 'primary', 'device-bound', TRUSTED);
    const daveKey = keyFor('eap-dave', 'mfa', 'device-bound', null);
    const carolKey = keyFor('eap-carol', 'primary', 'synced', null);

    const claimsOf = function (jwt) {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    };
    const authorize = function (b, client, extra) {
      return b.go('GET', '/oauth2/authorize?' + new URLSearchParams(
        Object.assign({ client_id: client, response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: CHALLENGE, code_challenge_method: 'S256' },
        extra || {})).toString());
    };
    const atRedirect = function (r) {
      const loc = String((r && r.headers && r.headers.location) || '');
      return (r.status === 302 || r.status === 303) &&
        loc.indexOf(REDIRECT) === 0 ? new URL(loc).searchParams : null;
    };
    const redeem = async function (b, client, params) {
      const r = await b.go('POST', '/oauth2/token', { noCookies: true,
        form: { grant_type: 'authorization_code', code: params.get('code'),
                redirect_uri: REDIRECT, client_id: client,
                code_verifier: VERIFIER } });
      return r.json && r.json.id_token ? claimsOf(r.json.id_token) : null;
    };
    // A sign-in through the screen: the request, the password step
    // (`webauthn_only` for a passkey alone), and the passkey step where one
    // follows; then the return leg. Answers every hop.
    const signIn = async function (client, name, how, key, extra) {
      const b = browser(port);
      const first = await authorize(b, client, extra);
      const at = String(first.headers.location || '');
      if (!/\/authn\/login\?authn=/.test(at)) {
        return { first: first, final: first };
      }
      const page = await authnScreen.open({ port: port, jar: b.jar, at: at });
      const posted = await authnScreen.follow({ port: port, jar: b.jar,
        opened: page, fields: { action: 'login', username: name,
          password: how === 'passkey' ? '' : PASSWORD,
          webauthn_only: how === 'passkey' ? '1' : '' } });
      let answer = posted.answer || posted;
      if (key && posted.answer && posted.answer.next === 'mfa') {
        answer = (await authnScreen.passkeyStep({ port: port, jar: b.jar,
          opened: posted }, function (c) {
          return key.assert(c.challenge);
        })).answer;
      }
      const back = String((answer.headers || {}).location ||
                          answer.location || '');
      const final = /\/oauth2\/authorize\?/.test(back)
        ? await b.go('GET', back) : answer;
      const params = atRedirect(final);
      const claims = params && params.get('code')
        ? await redeem(b, client, params) : null;
      return { b: b, first: first, page: page, posted: posted,
               answer: answer, final: final, params: params,
               claims: claims };
    };

    // 1. Discovery.
    const anon = browser(port);
    const doc = await anon.go('GET', '/.well-known/openid-configuration');
    const supported = (doc.json || {}).acr_values_supported || [];
    note(supported.indexOf('phr') >= 0 && supported.indexOf('phrh') >= 0,
         'E1. discovery publishes phr and phrh in acr_values_supported',
         JSON.stringify(supported));

    // 2. Nothing asked: nothing changes.
    let r = await signIn('eap-rp', 'eap-erin', 'passkey', erinKey);
    note(r.claims && r.claims.acr === '1',
         'E2. a passkey sign-in that asks for nothing carries acr "1", as ' +
         'before', JSON.stringify(r.claims || r.final.headers));

    // 3. phr and phrh on a hardware-attested, device-bound passkey.
    r = await signIn('eap-rp', 'eap-erin', 'passkey', erinKey,
                     { acr_values: 'phr' });
    note(r.page.view && r.page.view.demands && r.page.view.demands.key ===
         true && r.claims && r.claims.acr === 'phr',
         'E3a. acr_values=phr: the screen demands a key, and the passkey ' +
         'sign-in\'s ID Token carries acr "phr"',
         JSON.stringify((r.page.view || {}).demands) + ' ' +
         JSON.stringify(r.claims || r.final.headers));
    r = await signIn('eap-rp', 'eap-erin', 'passkey', erinKey,
                     { acr_values: 'phrh' });
    note(r.claims && r.claims.acr === 'phrh',
         'E3b. acr_values=phrh on a key with a trusted attestation and BE ' +
         'clear carries acr "phrh"',
         JSON.stringify(r.claims || r.final.headers));

    // 4. A password and the security key as the step.
    r = await signIn('eap-rp', 'eap-dave', 'password', daveKey,
                     { acr_values: 'phr' });
    note(r.claims && r.claims.acr === 'phr' &&
         (r.claims.amr || []).indexOf('pwd') >= 0,
         'E4. a password with a security key as the step carries acr "phr"',
         JSON.stringify(r.claims || r.final.headers));

    // 5. A synced passkey: phr yes, phrh no.
    r = await signIn('eap-rp', 'eap-carol', 'passkey', carolKey,
                     { acr_values: 'phr' });
    note(r.claims && r.claims.acr === 'phr',
         'E5a. a synced passkey carries acr "phr"',
         JSON.stringify(r.claims || r.final.headers));
    r = await signIn('eap-rp', 'eap-carol', 'passkey', carolKey,
                     { acr_values: 'phrh' });
    note(r.params && r.params.get('error') ===
         'unmet_authentication_requirements' &&
         /backup-eligible/.test(String(r.params.get('error_description'))) &&
         !r.params.get('code'),
         'E5b. under phrh it is refused unmet_authentication_requirements, ' +
         'naming the backup flag (STS-OAUTH-0971)',
         r.final.status + ' ' + String(r.final.headers.location || ''));

    // 6. A password-only person.
    r = await signIn('eap-rp', 'eap-bob', 'password', null,
                     { acr_values: 'phr' });
    note(r.page.view && r.page.view.demands && r.page.view.demands.key ===
         true && !(r.params && r.params.get('code')),
         'E6a. under phr a password alone is not let through: the screen ' +
         'demands a key, and no code is issued on the password',
         JSON.stringify((r.page.view || {}).demands) + ' next=' +
         String((r.posted.answer || r.posted).next || ''));
    const bob = await signIn('eap-rp', 'eap-bob', 'password', null);
    note(bob.claims && bob.claims.acr === '1',
         '(a password session for bob, asking for nothing)',
         JSON.stringify(bob.claims || bob.final.headers));
    const again = await authorize(bob.b, 'eap-rp',
                                  { acr_values: 'phr', step_up_honoured: '1' });
    const refused = atRedirect(again);
    note(refused && refused.get('error') ===
         'unmet_authentication_requirements' &&
         /phishing-resistant/.test(String(refused.get('error_description'))),
         'E6b. that session returning under the round-trip marker is ' +
         'refused unmet_authentication_requirements (STS-OAUTH-0970)',
         again.status + ' ' + String(again.headers.location || ''));

    // 7. The issuance policy's floor for one application.
    r = await signIn('eap-strict', 'eap-bob', 'password', null);
    note(r.claims && r.claims.acr === '1',
         '(before the rule, a password sign-in to eap-strict is issued)',
         JSON.stringify(r.claims || r.final.headers));
    const name = rolePep.issuancePolicyName();
    const built = templates.build('role-issuance',
      { requirePhishingResistant: 'eap-strict' }, { name: name });
    const written = xacmlStore.write(name, xml.writePolicy(built.policy),
                                     { enabled: true });
    note(built.ok && written && written.ok,
         '(the issuance policy requires phr for eap-strict)',
         JSON.stringify((written && written.why) || built.why || ''));
    r = await signIn('eap-strict', 'eap-bob', 'password', null);
    note(r.params && r.params.get('error') === 'access_denied' &&
         !r.params.get('code') &&
         /requires a phishing-resistant authentication/.test(
           String(r.params.get('error_description'))),
         'E7a. requirePhishingResistant refuses a password sign-in to the ' +
         'application it lists, saying what the authentication lacked',
         r.final.status + ' ' + String(r.final.headers.location || '') +
         ' ' + String(r.final.text || '').slice(0, 200));
    r = await signIn('eap-strict', 'eap-erin', 'passkey', erinKey);
    note(r.claims && r.claims.acr === '1',
         'E7b. and admits a passkey sign-in (which asked for no acr, so its ' +
         'token says "1")', JSON.stringify(r.claims || r.final.headers));
    r = await signIn('eap-rp', 'eap-bob', 'password', null);
    note(r.claims && r.claims.acr === '1',
         'E7c. and leaves another application alone',
         JSON.stringify(r.claims || r.final.headers));
    xacmlStore.remove(name);
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function overHttp(t) {
  log.debug("Entering overHttp().");
  t.log.info('=== E. over HTTP ===');
  const out = path.join(os.tmpdir(), 'sts-eap-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { EAP_OUT: out, EAP_ROOT: ROOT,
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
    log.debug("Caught in overHttp(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in overHttp(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving overHttp().");
}

module.exports = {
  name: 'eap_acr_values',
  describe: 'OpenID Connect EAP ACR Values 1.0 (#723): phr and phrh earned ' +
            'from evidence, requested through RFC 9470, asserted in the ID ' +
            'Token, published, and required by the issuance policy',
  run: async function (t) {
    log.debug("Entering run().");
    evidence(t);
    meetsAndRefusals(t);
    issuancePolicy(t);
    overHttp(t);
    log.debug("Leaving run().");
  }
};
