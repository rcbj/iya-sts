'use strict';
//
// File: tests/public_clients_product.js
//
// ===========================================================================
// PUBLIC CLIENTS IN PRODUCT MODE (2026-09-17).
//
// Product mode used to refuse any client that did not authenticate, so there
// were no public clients in it and this service could not exercise the single
// commonest kind of OAuth client there is: a browser or native application
// that cannot keep a secret. It allows one now, and what makes that safe
// rather than merely permissive is the other half of the change — PRODUCT MODE
// IMPLIES RFC 9700 MODE (`common/mode.js`, `enforcesOauthSecurityBcp()`), so
// what a confidential client proves with a credential a public client proves
// with PKCE, an exactly matched redirect URI and a refresh token that rotates.
//
// Both halves are asserted here, because either one alone is a defect: the
// capability without the rules is a downgrade, and the rules without the
// capability are what it did before.
//
//   1. A PUBLIC CLIENT COMPLETES THE CODE FLOW and is issued tokens.
//   2. WITHOUT PKCE IT IS REFUSED — RFC 9700 section 2.1.1, enforced here
//      with `oauth2.rfc9700` OFF, which is the whole point of the implication.
//   3. THE CLIENT CREDENTIALS GRANT IS REFUSED to it (RFC 6749 section 4.4),
//      at the token endpoint and at registration.
//   4. A CONFIDENTIAL CLIENT IS UNCHANGED: no credential is still 401.
//   5. REFRESH TOKENS ROTATE, which is what RFC 9700 section 4.14.2 and
//      OAuth 2.1 section 4.3.1 ask of a public client's.
//   6. THE ID TOKEN'S CLAIMS COME FROM THE DIRECTORY and nothing is invented —
//      the assertions that used to ride the password grant in
//      `oauth_oid4vc_hardcoded.js`, which product mode no longer offers
//      (RFC 9700 section 2.4).
//
// IN A CHILD PROCESS, for `admin_bootstrap.js`'s reason: it flips
// `global.mode` for the whole process, and product mode now changes the OAuth
// stack's behaviour for every realm — a mode left on, or a realm seeded under
// it, would change what every other file in `run.js`'s one process means.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'public_clients_product',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.PCP_ROOT;
  const OUT = process.env.PCP_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  let jar = {};
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.form ? new URLSearchParams(o.form).toString() : '';
      const headers = Object.assign({}, o.headers || {});
      if (o.cookies && Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
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
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const helpers = require(ROOT + '/common/helpers');
    const bcp = require(ROOT + '/oauth-oidc/oauth2_bcp');
    const senderConstraints = require(ROOT + '/oauth-oidc/sender_constraints');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const REDIRECT = 'https://rp.pcp.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pcp-7!';
    const SECRET = 'pcp-confidential-secret-0123456789abcdef';
    // A FRESH VERIFIER AND NONCE PER FLOW. RFC 9700 section 2.1.1's
    // transaction-specific rule refuses a `code_challenge` or `nonce`
    // presented again after a code was issued for it, and product mode
    // enforces it — so the first draft of this file, which reused one
    // challenge, got a code for its first flow and nothing for the rest. That
    // is the service being right and the test being wrong, and it is worth a
    // comment because the symptom is an empty `code` several assertions later.
    const freshPkce = function () {
      const verifier = 'pcp-' + crypto.randomBytes(32).toString('base64url');
      return { verifier: verifier,
               challenge: crypto.createHash('sha256').update(verifier)
                 .digest('base64url') };
    };

    config.setOverride('oauth2.consentRequired', false);

    // The fixtures are made in DEVELOPMENT, because product mode creates
    // nothing because it was named — which is the rule this test then relies
    // on when it asks for a client_id nobody registered.
    ldap.createUser('pcp-alice', { invent: false, attributes: {
      cn: 'Alice Public', givenName: 'Alice', sn: 'Public',
      mail: 'alice@pcp.example' } });
    ldap.createUser('pcp-bare', { invent: false });
    credentials.setPassword('pcp-alice', PASSWORD);
    credentials.setPassword('pcp-bare', PASSWORD);
    applications.createApplication({ identifier: 'pcp-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pcp-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code', 'refresh_token',
                                 'client_credentials'] } });
    applications.updateApplication('pcp-public', {
      attribute: 'oauthClientSecret', mode: 'set', value: '' });
    applications.createApplication({ identifier: 'pcp-confidential',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pcp-confidential', oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['authorization_code', 'refresh_token'] } });

    const payloadOf = function (jwt) {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                              .toString('utf8'));
    };
    const authorize = function (query) {
      return request(port, 'GET', '/oauth2/authorize?' +
                     new URLSearchParams(query).toString(), { cookies: true });
    };
    // The sign-in round trip: the screen, the form it drew, and back to the
    // authorization endpoint with a session.
    const signIn = async function (first, username) {
      const location = String(first.headers.location || '');
      if (first.status !== 302 || !/\/authn\/login/.test(location)) {
        return first;
      }
      const page = await request(port, 'GET', location, { cookies: true });
      const form = {};
      (page.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
        function (tag) {
          const name = /name="([^"]+)"/.exec(tag);
          const value = /value="([^"]*)"/.exec(tag);
          if (name) {
            form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
          }
        });
      form.username = username;
      form.password = PASSWORD;
      form.action = 'login';
      const screen = location.split('?')[0].replace(/^https?:\/\/[^/]+/, '');
      const posted = await request(port, 'POST', screen,
                                   { form: form, cookies: true });
      const back = String(posted.headers.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      return back ? await request(port, 'GET', back, { cookies: true })
                  : posted;
    };
    const codeOf = function (r) {
      const loc = String((r && r.headers && r.headers.location) || '');
      if (!r || r.status !== 302 || loc.indexOf(REDIRECT) !== 0) {
        return null;
      }
      return new URL(loc).searchParams.get('code');
    };
    const codeFlow = async function (clientId, username, extra) {
      jar = {};
      const pkce = freshPkce();
      const first = await authorize(Object.assign(
        { client_id: clientId, response_type: 'code', redirect_uri: REDIRECT,
          scope: 'openid profile email', state: 'st',
          nonce: 'n-' + crypto.randomBytes(8).toString('hex'),
          code_challenge: pkce.challenge, code_challenge_method: 'S256' },
        extra || {}));
      const done = await signIn(first, username);
      return { first: first, final: done, code: codeOf(done),
               verifier: pkce.verifier };
    };

    config.setOverride('global.mode', 'product');
    try {
      // =====================================================================
      // 0. THE PREMISE: the BCP is on with its own settings off.
      // =====================================================================
      note(bcp.enabled() && !config.value('oauth2.rfc9700') &&
           !config.value('oauth2.oauth21'),
           '0a. product mode enforces RFC 9700 with oauth2.rfc9700 and ' +
           'oauth2.oauth21 both OFF — the implication, which everything ' +
           'below rests on',
           JSON.stringify({ enabled: bcp.enabled(),
                            rfc9700: config.value('oauth2.rfc9700'),
                            oauth21: config.value('oauth2.oauth21') }));
      // THE DISTINCTION THIS WHOLE CHANGE TURNS ON, and the assertion that
      // caught the first version of it: `declaredPublic()` reads RFC 7591
      // section 2's default and `isConfidential()` deliberately does not, so
      // a client that declared NO method is public to neither question —
      // PKCE is required of it AND a credential is required of it. Asking
      // `!isConfidential()` at the product-mode gate would have let it
      // through with neither.
      note(bcp.declaredPublic({ known: true,
                                token_endpoint_auth_method: 'none' }) === true
           && bcp.declaredPublic({ known: true,
                                   token_endpoint_auth_method: '' }) === false
           && bcp.declaredPublic({ known: true }) === false
           && bcp.declaredPublic({ known: false,
                                   token_endpoint_auth_method: 'none' })
                === false,
           '0b. only an EXPLICIT token_endpoint_auth_method="none" on a ' +
           'REGISTERED client is public; an omitted one is ' +
           'client_secret_basic (RFC 7591 section 2) and still needs a ' +
           'credential',
           JSON.stringify({
             none: bcp.declaredPublic({ known: true,
                                        token_endpoint_auth_method: 'none' }),
             empty: bcp.declaredPublic({ known: true,
                                         token_endpoint_auth_method: '' }),
             absent: bcp.declaredPublic({ known: true }),
             unknown: bcp.declaredPublic({ known: false,
                                           token_endpoint_auth_method: 'none' })
           }));
      note(bcp.isConfidential({ known: true,
                                token_endpoint_auth_method: '' }) === false,
           '0c. and isConfidential() still answers NO for that client, so ' +
           'RFC 9700 section 2.1.1 requires PKCE of it — the two functions ' +
           'read the undeclared case differently on purpose');
      note(senderConstraints.rotationRequired(),
           '0d. and refresh tokens rotate, which is what RFC 9700 section ' +
           '4.14.2 asks of a public client\'s',
           senderConstraints.rotationSource());

      // =====================================================================
      // 1. A PUBLIC CLIENT IS ISSUED TOKENS.
      // =====================================================================
      let flow = await codeFlow('pcp-public', 'pcp-alice');
      note(!!flow.code, '1a. a PUBLIC client reaches a code in product mode',
           flow.first.status + ' ' +
           String(flow.final.headers.location || '').slice(0, 120));
      let r = await request(port, 'POST', '/oauth2/token', { form: {
        grant_type: 'authorization_code', code: flow.code || '',
        redirect_uri: REDIRECT, client_id: 'pcp-public',
        code_verifier: flow.verifier } });
      note(r.status === 200 && r.json && r.json.access_token && r.json.id_token,
           '1b. and redeems it at the token endpoint presenting NO ' +
           'credential — which product mode refused outright until 2026-09-17',
           r.status + ' ' + r.text.slice(0, 200));
      const issued = r.json || {};

      // =====================================================================
      // 6. THE CLAIMS ARE THE DIRECTORY'S. (Here because it needs 1b's token.)
      // =====================================================================
      if (issued.id_token) {
        const idt = payloadOf(issued.id_token);
        note(idt.name === 'Alice Public' && idt.given_name === 'Alice' &&
             idt.family_name === 'Public' && idt.email === 'alice@pcp.example',
             '6a. PRODUCT: the ID Token\'s name, given_name, family_name and ' +
             'email are the person\'s own cn, givenName, sn and mail',
             JSON.stringify(idt));
        note(!('email_verified' in idt),
             '6b. and it asserts NO email_verified, because nothing verified ' +
             'that mailbox', idt.email_verified);
        note(idt.sub === helpers.subjectForName('pcp-alice') &&
             /^urn:uuid:/.test(idt.sub),
             '6c. and sub is the person\'s urn:uuid:<entryUUID>', idt.sub);
      } else {
        note(false, '6a. PRODUCT: an ID Token came back to inspect',
             r.text.slice(0, 200));
      }
      if (issued.access_token) {
        const info = await request(port, 'GET', '/oauth2/userinfo',
          { headers: { authorization: 'Bearer ' + issued.access_token } });
        note(info.status === 200 && info.json &&
             info.json.family_name === 'Public' &&
             info.json.email === 'alice@pcp.example' &&
             !('email_verified' in info.json),
             '6d. PRODUCT: UserInfo answers profile and email from the ' +
             'directory, without email_verified',
             info.status + ' ' + info.text.slice(0, 200));
      }
      flow = await codeFlow('pcp-public', 'pcp-bare');
      r = await request(port, 'POST', '/oauth2/token', { form: {
        grant_type: 'authorization_code', code: flow.code || '',
        redirect_uri: REDIRECT, client_id: 'pcp-public',
        code_verifier: flow.verifier } });
      if (r.json && r.json.id_token) {
        const bare = payloadOf(r.json.id_token);
        const invented = ['name', 'given_name', 'family_name', 'email',
                          'email_verified']
          .filter(function (k) { return k in bare; });
        note(invented.length === 0,
             '6e. PRODUCT: a person whose entry holds none of them gets NO ' +
             'profile claims — absent rather than invented',
             JSON.stringify(bare));
      } else {
        note(false, '6e. PRODUCT: a token for the bare person came back',
             r.text.slice(0, 200));
      }

      // =====================================================================
      // 5. THE REFRESH TOKEN ROTATES.
      // =====================================================================
      if (issued.refresh_token) {
        const once = await request(port, 'POST', '/oauth2/token', { form: {
          grant_type: 'refresh_token', refresh_token: issued.refresh_token,
          client_id: 'pcp-public' } });
        note(once.status === 200 && once.json && once.json.refresh_token &&
             once.json.refresh_token !== issued.refresh_token,
             '5a. a public client\'s refresh returns a NEW refresh token',
             once.status + ' ' + once.text.slice(0, 160));
        const twice = await request(port, 'POST', '/oauth2/token', { form: {
          grant_type: 'refresh_token', refresh_token: issued.refresh_token,
          client_id: 'pcp-public' } });
        note(twice.status === 400 && twice.json &&
             twice.json.error === 'invalid_grant',
             '5b. and the SPENT one is refused — one-time use, which is the ' +
             'limb of RFC 9700 section 4.14.2 that asks nothing of a client ' +
             'that cannot keep a secret',
             twice.status + ' ' + twice.text.slice(0, 160));
      } else {
        note(false, '5a. a refresh token came back to rotate',
             JSON.stringify(Object.keys(issued)));
      }

      // =====================================================================
      // 2. WITHOUT PKCE IT IS REFUSED.
      // =====================================================================
      jar = {};
      r = await authorize({ client_id: 'pcp-public', response_type: 'code',
                            redirect_uri: REDIRECT, scope: 'openid',
                            state: 'st' });
      note(r.status === 400 && /PKCE|code_challenge/.test(r.text),
           '2a. the same public client with NO code_challenge is refused — ' +
           'RFC 9700 section 2.1.1, enforced with oauth2.rfc9700 off',
           r.status + ' ' + r.text.slice(0, 200));
      jar = {};
      r = await authorize({ client_id: 'pcp-public', response_type: 'code',
                            redirect_uri: REDIRECT, scope: 'openid',
                            state: 'st',
                            code_challenge: freshPkce().verifier,
                            code_challenge_method: 'plain' });
      note(r.status === 400 && /S256/.test(r.text),
           '2b. and code_challenge_method=plain is refused: S256 only',
           r.status + ' ' + r.text.slice(0, 200));

      // =====================================================================
      // 3. THE CLIENT CREDENTIALS GRANT IS NOT A PUBLIC CLIENT'S.
      // =====================================================================
      r = await request(port, 'POST', '/oauth2/token', { form: {
        grant_type: 'client_credentials', client_id: 'pcp-public',
        scope: 'openid' } });
      note(r.status === 400 && r.json &&
           r.json.error === 'unauthorized_client' &&
           /4\.4|public/i.test(r.json.error_description || ''),
           '3a. the client credentials grant is refused to a public client ' +
           '(RFC 6749 section 4.4), as unauthorized_client and not ' +
           'invalid_client — the client is known, the GRANT is refused',
           r.status + ' ' + r.text.slice(0, 220));
      const refusal = bcp.checkClientRegistration({
        token_endpoint_auth_method: 'none',
        grant_types: ['client_credentials'],
        redirect_uris: [REDIRECT] });
      note(refusal && refusal.ok === false &&
           refusal.requirement === 'client-credentials-confidential-only',
           '3b. and REGISTERING that combination is refused too, so the two ' +
           'doors agree',
           JSON.stringify(refusal && refusal.requirement));

      // =====================================================================
      // 4. A CONFIDENTIAL CLIENT IS UNCHANGED.
      // =====================================================================
      flow = await codeFlow('pcp-confidential', 'pcp-alice');
      r = await request(port, 'POST', '/oauth2/token', { form: {
        grant_type: 'authorization_code', code: flow.code || '',
        redirect_uri: REDIRECT, client_id: 'pcp-confidential',
        code_verifier: flow.verifier } });
      note(r.status === 401 && r.json && r.json.error === 'invalid_client',
           '4a. a CONFIDENTIAL client that presents no credential is still ' +
           'refused 401 — the half of product mode that was doing the ' +
           'security work is unchanged',
           r.status + ' ' + r.text.slice(0, 220));
      flow = await codeFlow('pcp-confidential', 'pcp-alice');
      r = await request(port, 'POST', '/oauth2/token', { form: {
        grant_type: 'authorization_code', code: flow.code || '',
        redirect_uri: REDIRECT, client_id: 'pcp-confidential',
        client_secret: SECRET, code_verifier: flow.verifier } });
      note(r.status === 200 && r.json && r.json.access_token,
           '4b. and presenting it is issued tokens',
           r.status + ' ' + r.text.slice(0, 200));
    } finally {
      // In a `finally` so that a throw above cannot leave product mode on for
      // whatever runs next in this process.
      config.clearOverride('global.mode');
      config.clearOverride('oauth2.consentRequired');
    }

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  }()).catch(function (e) {
    console.error(e && e.stack ? e.stack : e);
    process.exit(1);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'public-clients-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'error',
                           PCP_ROOT: ROOT, PCP_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one, reported below with its
    // exit status and stderr.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
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
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'public clients in product mode',
  describe: 'product mode allows a public client and enforces RFC 9700 ' +
            'instead of a credential: PKCE, rotation, no client credentials ' +
            'grant, and a confidential client still authenticating',
  run: run
};
