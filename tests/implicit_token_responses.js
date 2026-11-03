// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/implicit_token_responses.js
//
// ===========================================================================
// RFC 9700 SECTION 2.1.2 WAIVED BY AN ADMINISTRATOR, AND THE IMPLICIT GRANT
// BESIDE id_token (#1295).
//
// rcbj, 2026-11-03: "ease off the strictness of our product mode so that we
// get certified with these features. It should require an admin to turn on
// these restricted flow / grant types". Held here:
//
//   A. THE DEFECT, with the setting OFF: `id_token` and `code id_token`
//      register with `grant_types: ["implicit"]` (RFC 7591 section 2.1) in
//      RFC 9700 mode and in product mode; `implicit` with only `code`, with
//      nothing, or beside a token response type is still STS-OAUTH-0133; and
//      the metadata keeps `implicit` beside the token-free id_token types.
//   B. THE SETTING, in product mode and in RFC 9700 mode: each of the four
//      token response types refused (0126 at the authorization endpoint,
//      0134 at registration) with it off and accepted with it on; the
//      metadata advertising them only with it on.
//   C. OAUTH 2.1 MODE AND FAPI STILL REFUSE with the setting on, and their
//      metadata does not advertise the token types.
//   D. THE REPORT: GET /oauth2/rfc9700's `no-implicit` row reads `waived`
//      with the setting named, `waived` lists it, every other row is
//      unchanged, and `mode.report()`'s BCP row carries it for /admin/mode.
//   E. OVER HTTP: both discovery documents of a realm, a registration and an
//      authorization request, each way.
//
// In a child process, because product mode is set on the realms here and the
// HTTP half loads the whole stack and serves it (`flow_type_choices.js`'s
// arrangement).
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'implicit_token_responses',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.ITR_ROOT;
  const OUT = process.env.ITR_OUT;
  const fs = require('fs');
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function send(port, method, urlPath, body) {
    return new Promise(function (resolve) {
      const data = body === undefined ? '' : JSON.stringify(body);
      const req = http.request({ host: '127.0.0.1', port: port,
        method: method, path: urlPath,
        headers: data ? { 'content-type': 'application/json',
                          'content-length': Buffer.byteLength(data) } : {} },
      function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = null;
          }
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text, json: parsed });
        });
      });
      req.end(data);
    });
  }
  const TOKEN_TYPES = ['token', 'id_token token', 'code token',
                       'code id_token token'];
  const ALL_TYPES = ['code', 'token', 'id_token', 'code token',
                     'code id_token', 'id_token token',
                     'code id_token token', 'none'];
  const ALL_GRANTS = ['authorization_code', 'implicit', 'refresh_token',
                      'client_credentials', 'password'];
  const codeOf = function (answer) {
    return answer && !answer.ok ? answer.errorCode : 'ok';
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const bcp = require(ROOT + '/oauth-oidc/oauth2_bcp');
    const mode = require(ROOT + '/common/mode');
    const stamp = String(Date.now()).slice(-6) + '-' +
      require('crypto').randomBytes(2).toString('hex');
    const KEY = 'oauth2.allowImplicitTokenResponses';
    const specs = {
      BCP: { 'oauth2.rfc9700': true },
      BCP_ON: { 'oauth2.rfc9700': true, [KEY]: true },
      PROD: { 'global.mode': 'product' },
      PROD_ON: { 'global.mode': 'product', [KEY]: true },
      V21_ON: { 'oauth2.oauth21': true, [KEY]: true },
      FAPI_ON: { 'oauth2.fapi': '1-baseline', [KEY]: true },
      FAPI2_ON: { 'oauth2.fapi': '2-security', [KEY]: true },
      OFF_ON: { [KEY]: true }
    };
    const made = {};
    Object.keys(specs).forEach(function (name) {
      const id = 'itr-' + name.toLowerCase().replace(/_/g, '') + '-' + stamp;
      const result = realms.create({ id: id, name: id,
        description: 'Created by tests/implicit_token_responses.js',
        overrides: specs[name] });
      note(result.ok, 'the realm ' + name + ' is created',
           JSON.stringify(result.errors || []));
      made[name] = result.ok ? result.realm : null;
    });
    const inRealm = function (name, fn) {
      return realms.run(realms.get(made[name].id), fn);
    };
    const authorize = function (types) {
      return bcp.checkAuthorizationRequest({
        query: { scope: 'openid', nonce: 'n-1', state: 's-1',
                 code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                 code_challenge_method: 'S256' },
        types: types.split(' '),
        client: { known: true, token_endpoint_auth_method: 'none' } });
    };
    const register = function (grants, types) {
      const meta = { redirect_uris: ['https://rp.example/cb'],
                     token_endpoint_auth_method: 'client_secret_basic' };
      if (grants) {
        meta.grant_types = grants;
      }
      if (types) {
        meta.response_types = types;
      }
      return bcp.checkClientRegistration(meta);
    };
    const narrowed = function () {
      return bcp.applyToMetadata({
        response_types_supported: ALL_TYPES.slice(0),
        grant_types_supported: ALL_GRANTS.slice(0) });
    };

    // --- A. The defect, the setting off ---------------------------------
    ['BCP', 'PROD'].forEach(function (name) {
      inRealm(name, function () {
        note(bcp.enabled() && !bcp.implicitWaived(),
             'A0. ' + name + ': the mode is on and nothing is waived');
        note(codeOf(register(['implicit'], ['id_token'])) === 'ok',
             'A1. ' + name + ': implicit beside id_token registers',
             codeOf(register(['implicit'], ['id_token'])));
        const hybrid = register(['authorization_code', 'implicit'],
                                ['code id_token']);
        note(codeOf(hybrid) === 'ok',
             'A2. ' + name + ': implicit beside code id_token registers',
             codeOf(hybrid));
        const both = register(['authorization_code', 'implicit'],
                              ['code', 'id_token', 'code id_token']);
        note(codeOf(both) === 'ok',
             'A3. ' + name + ': and beside code, id_token and code id_token',
             codeOf(both));
        note(codeOf(register(['authorization_code', 'implicit'],
                             ['code'])) === 'STS-OAUTH-0133',
             'A4. ' + name + ': implicit with only code is STS-OAUTH-0133');
        note(codeOf(register(['implicit'], null)) === 'STS-OAUTH-0133',
             'A5. ' + name + ': implicit with no response types (code by ' +
             'default) is STS-OAUTH-0133');
        note(codeOf(register(['implicit'],
                             ['id_token', 'id_token token'])) ===
               'STS-OAUTH-0133',
             'A6. ' + name + ': implicit beside a token response type is ' +
             'STS-OAUTH-0133 even with id_token registered too');
        note(authorize('id_token').ok && authorize('code id_token').ok,
             'A7. ' + name + ': the authorization endpoint still answers ' +
             'id_token and code id_token');
        const meta = narrowed();
        note(meta.grant_types_supported.indexOf('implicit') >= 0 &&
             meta.grant_types_supported.indexOf('password') < 0 &&
             JSON.stringify(meta.response_types_supported) ===
               JSON.stringify(['code', 'id_token', 'code id_token', 'none']),
             'A8. ' + name + ': the metadata drops the token types and ' +
             'password and keeps implicit beside id_token',
             JSON.stringify(meta));
      });
    });
    note(bcp.impliesImplicitGrant(['code', 'none']) === false &&
         bcp.impliesImplicitGrant(['code id_token']) === true &&
         bcp.impliesImplicitGrant(['token']) === true,
         'A9. impliesImplicitGrant() reads id_token and token, not code');

    // --- B. The setting -------------------------------------------------
    [['BCP', 'BCP_ON'], ['PROD', 'PROD_ON']].forEach(function (pair) {
      const off = pair[0];
      const on = pair[1];
      TOKEN_TYPES.forEach(function (type) {
        inRealm(off, function () {
          note(codeOf(authorize(type)) === 'STS-OAUTH-0126',
               'B1. ' + off + ': response_type=' + type + ' is ' +
               'STS-OAUTH-0126 with the setting off', codeOf(authorize(type)));
          const grants = type.indexOf('code') >= 0
            ? ['authorization_code', 'implicit'] : ['implicit'];
          const refused = register(grants, [type]);
          note(codeOf(refused) === 'STS-OAUTH-0133',
               'B2. ' + off + ': registering ' + type + ' with ' +
               JSON.stringify(grants) + ' is STS-OAUTH-0133',
               codeOf(refused));
          note(codeOf(register(null, [type])) === 'STS-OAUTH-0134',
               'B3. ' + off + ': registering ' + type + ' alone is ' +
               'STS-OAUTH-0134');
        });
        inRealm(on, function () {
          note(authorize(type).ok,
               'B4. ' + on + ': response_type=' + type + ' is accepted with ' +
               'the setting on', codeOf(authorize(type)));
          const grants = type.indexOf('code') >= 0
            ? ['authorization_code', 'implicit'] : ['implicit'];
          note(codeOf(register(grants, [type])) === 'ok',
               'B5. ' + on + ': registering ' + type + ' with ' +
               JSON.stringify(grants) + ' is accepted',
               codeOf(register(grants, [type])));
        });
      });
      inRealm(on, function () {
        note(bcp.enabled() && bcp.implicitWaived(),
             'B6. ' + on + ': the mode is still on, and the waiver in force');
        const meta = narrowed();
        note(JSON.stringify(meta.response_types_supported) ===
               JSON.stringify(ALL_TYPES) &&
             meta.grant_types_supported.indexOf('implicit') >= 0 &&
             meta.grant_types_supported.indexOf('password') < 0 &&
             JSON.stringify(meta.code_challenge_methods_supported) ===
               '["S256"]',
             'B7. ' + on + ': the metadata advertises every response type ' +
             'and implicit, and still narrows password and PKCE',
             JSON.stringify(meta));
        const pkce = bcp.checkAuthorizationRequest({
          query: { scope: 'openid', nonce: 'n-2' }, types: ['code'],
          client: { known: true, token_endpoint_auth_method: 'none' } });
        note(!pkce.ok && pkce.errorCode === 'STS-OAUTH-0127',
             'B8. ' + on + ': every other requirement holds — a public ' +
             'client with no PKCE is still refused', codeOf(pkce));
        note(codeOf(bcp.checkGrantType('password')) === 'STS-OAUTH-0131',
             'B9. ' + on + ': and the password grant');
        const noNonce = bcp.checkAuthorizationRequest({
          query: { scope: 'openid',
                   code_challenge:
                     'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                   code_challenge_method: 'S256' },
          types: ['id_token', 'token'],
          client: { known: true, token_endpoint_auth_method: 'none' } });
        note(!noNonce.ok && noNonce.requirement === 'nonce-required',
             'B10. ' + on + ': and id_token token with no nonce is still ' +
             'refused (nonce-required)', JSON.stringify(noNonce));
      });
    });
    inRealm('OFF_ON', function () {
      note(!bcp.enabled() && authorize('token').ok &&
           codeOf(register(['implicit'], ['token'])) === 'ok',
           'B11. outside the mode the setting changes nothing: everything ' +
           'is answered, as before');
      note(bcp.waivers().length === 0,
           'B12. and nothing is reported waived where the mode is off');
    });

    // --- C. OAuth 2.1 and FAPI ignore it -------------------------------
    ['V21_ON', 'FAPI_ON', 'FAPI2_ON'].forEach(function (name) {
      inRealm(name, function () {
        note(bcp.enabled() && !bcp.implicitWaived(),
             'C1. ' + name + ': the setting is stored and not in force');
        TOKEN_TYPES.forEach(function (type) {
          note(codeOf(authorize(type)) === 'STS-OAUTH-0126',
               'C2. ' + name + ': response_type=' + type + ' is still ' +
               'STS-OAUTH-0126', codeOf(authorize(type)));
          note(codeOf(register(null, [type])) !== 'ok',
               'C3. ' + name + ': registering ' + type + ' is still refused',
               codeOf(register(null, [type])));
        });
        const meta = narrowed();
        const fapi = require(ROOT + '/oauth-oidc/fapi');
        fapi.applyToMetadata(meta);
        note(meta.response_types_supported.every(function (one) {
          return one.split(' ').indexOf('token') < 0;
        }), 'C4. ' + name + ': the metadata advertises no token type',
             JSON.stringify(meta.response_types_supported));
        const row = bcp.state().requirements.filter(function (one) {
          return one.id === 'no-implicit';
        })[0];
        note(row && row.enforced === 'yes' &&
             bcp.state().waived.length === 0,
             'C5. ' + name + ': the report says enforced, nothing waived',
             JSON.stringify(row && row.enforced));
      });
    });
    inRealm('FAPI2_ON', function () {
      const meta = narrowed();
      require(ROOT + '/oauth-oidc/fapi').applyToMetadata(meta);
      note(JSON.stringify(meta.response_types_supported) === '["code"]' &&
           meta.grant_types_supported.indexOf('implicit') < 0,
           'C6. FAPI 2.0: code alone, so the implicit grant goes with the ' +
           'id_token types', JSON.stringify(meta));
    });

    // --- D. The report ----------------------------------------------------
    inRealm('PROD_ON', function () {
      const state = bcp.state();
      const rowOf = function (id) {
        return state.requirements.filter(function (one) {
          return one.id === id;
        })[0] || {};
      };
      note(rowOf('no-implicit').enforced === 'waived' &&
           String(rowOf('no-implicit').note).indexOf(KEY) >= 0 &&
           /ADMINISTRATOR/.test(String(rowOf('no-implicit').note)),
           'D1. GET /oauth2/rfc9700: no-implicit is waived by an ' +
           'administrator, naming the setting',
           JSON.stringify(rowOf('no-implicit')));
      note(rowOf('prefer-code').enforced === 'waived',
           'D2. and prefer-code, what is left once no-implicit refused, ' +
           'with it');
      note(JSON.stringify(state.waived) === JSON.stringify([{
             requirement: 'no-implicit', section: 'RFC 9700 2.1.2',
             level: 'SHOULD NOT', setting: KEY }]) &&
           state.settings[KEY] === true,
           'D3. `waived` lists it, and `settings` carries the value',
           JSON.stringify([state.waived, state.settings[KEY]]));
      const others = state.requirements.filter(function (one) {
        return one.enforced === 'waived' && one.id !== 'no-implicit' &&
               one.id !== 'prefer-code';
      });
      note(others.length === 0,
           'D4. nothing else is waived', JSON.stringify(others));
      const report = mode.report();
      const bcpRow = report.requirements.filter(function (one) {
        return one.id === 'oauth-security-bcp';
      })[0] || {};
      note(JSON.stringify(bcpRow.waived) === JSON.stringify(state.waived),
           'D5. /admin/mode: the BCP row carries the waiver',
           JSON.stringify(bcpRow.waived));
      const page = require(ROOT + '/admin-ui/web_mode');
      const drawn = page.render(JSON.parse(JSON.stringify(report)));
      note(drawn.indexOf('waived-oauth-security-bcp-no-implicit') >= 0 &&
           drawn.indexOf(KEY) >= 0 &&
           /WAIVED IN THIS REALM BY AN ADMINISTRATOR/.test(drawn),
           'D6. and the page draws it under the row, naming the setting');
    });
    inRealm('PROD', function () {
      const bcpRow = mode.report().requirements.filter(function (one) {
        return one.id === 'oauth-security-bcp';
      })[0] || {};
      const row = bcp.state().requirements.filter(function (one) {
        return one.id === 'no-implicit';
      })[0] || {};
      note(bcpRow.waived === undefined && row.enforced === 'yes' &&
           bcp.state().waived.length === 0,
           'D7. with the setting off nothing is waived anywhere',
           JSON.stringify([bcpRow.waived, row.enforced]));
    });

    // --- E. Over HTTP -----------------------------------------------------
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    for (const name of ['BCP', 'BCP_ON', 'PROD', 'PROD_ON', 'V21_ON']) {
      const at = '/realm/' + made[name].id;
      const waived = name === 'BCP_ON' || name === 'PROD_ON';
      for (const doc of ['/.well-known/openid-configuration',
                         '/.well-known/oauth-authorization-server']) {
        const r = await send(port, 'GET', at + doc);
        const types = (r.json && r.json.response_types_supported) || [];
        const grants = (r.json && r.json.grant_types_supported) || [];
        const advertised = TOKEN_TYPES.every(function (one) {
          return types.indexOf(one) >= 0;
        });
        const none = TOKEN_TYPES.every(function (one) {
          return types.indexOf(one) < 0;
        });
        note(r.status === 200 && (waived ? advertised : none) &&
             grants.indexOf('implicit') >= 0 &&
             types.indexOf('id_token') >= 0,
             'E1. ' + name + ' ' + doc + ': the token types are ' +
             (waived ? '' : 'not ') + 'advertised, and implicit is, beside ' +
             'id_token', JSON.stringify([r.status, types, grants]));
      }
    }
    const registerOver = async function (name, body) {
      return send(port, 'POST', '/realm/' + made[name].id +
                  '/oauth2/register', Object.assign({
        redirect_uris: ['https://rp.example/cb'],
        token_endpoint_auth_method: 'client_secret_basic',
        client_name: 'itr ' + name }, body));
    };
    const idOnly = await registerOver('BCP', { grant_types: ['implicit'],
                                               response_types: ['id_token'] });
    note(idOnly.status === 201,
         'E2. BCP: POST /oauth2/register for id_token with implicit is 201',
         idOnly.status + ' ' + idOnly.text.slice(0, 300));
    const codeOnly = await registerOver('BCP', {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code'] });
    note(codeOnly.status === 400 && codeOnly.json &&
         codeOnly.json.error === 'invalid_client_metadata',
         'E3. BCP: and for code alone with implicit, 400 ' +
         'invalid_client_metadata', codeOnly.status + ' ' +
         codeOnly.text.slice(0, 300));
    const tokenOff = await registerOver('BCP', {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code id_token token'] });
    note(tokenOff.status === 400,
         'E4. BCP: code id_token token is refused at registration',
         tokenOff.status + ' ' + tokenOff.text.slice(0, 300));
    const tokenOn = await registerOver('BCP_ON', {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code', 'code id_token token', 'id_token token',
                       'code token'] });
    note(tokenOn.status === 201,
         'E5. BCP_ON: and accepted with the setting on',
         tokenOn.status + ' ' + tokenOn.text.slice(0, 300));
    const askFor = async function (name, client, type) {
      const q = new URLSearchParams({ response_type: type,
        client_id: client, redirect_uri: 'https://rp.example/cb',
        scope: 'openid', nonce: 'n-' + type.length, state: 'st',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256' });
      return send(port, 'GET', '/realm/' + made[name].id +
                  '/oauth2/authorize?' + q.toString());
    };
    if (tokenOn.json && tokenOn.json.client_id) {
      const on = await askFor('BCP_ON', tokenOn.json.client_id,
                              'id_token token');
      note(on.status < 500 &&
           (on.text + String(on.headers.location || ''))
             .indexOf('unsupported_response_type') < 0,
           'E6. BCP_ON: GET /oauth2/authorize?response_type=id_token token ' +
           'is not refused for its response type',
           on.status + ' ' + String(on.headers.location || '') + ' ' +
           on.text.slice(0, 200));
    }
    if (idOnly.json && idOnly.json.client_id) {
      const off = await askFor('BCP', idOnly.json.client_id, 'id_token token');
      note((off.text + String(off.headers.location || ''))
             .indexOf('unsupported_response_type') >= 0,
           'E7. BCP: and refused unsupported_response_type with it off',
           off.status + ' ' + String(off.headers.location || '') + ' ' +
           off.text.slice(0, 200));
    }

    server.close();
    Object.keys(made).forEach(function (name) {
      if (made[name]) {
        realms.remove(made[name].id);
      }
    });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'implicit-token-responses-' +
                        process.pid + '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', ITR_ROOT: ROOT, ITR_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one, reported below with its
    // exit status and stderr.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
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
  name: 'implicit_token_responses',
  describe: 'RFC 9700 section 2.1.2 waived per realm by ' +
            'oauth2.allowImplicitTokenResponses, OAuth 2.1 and FAPI ' +
            'ignoring it, and the implicit grant registering beside ' +
            'id_token (#1295)',
  run: run
};
