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
// And #1296 — the realm makes the token response types POSSIBLE, and each
// application has to have one ENABLED (`oauthAllowedTokenResponseTypes`):
//
//   F. THE AUTHORIZATION ENDPOINT, realm off/on × application off/on for
//      each token type: 0126 where the realm does not allow it, whatever the
//      application lists; 0998 (unauthorized_client) where it does and the
//      application does not list that exact type; accepted where both.
//   G. DYNAMIC REGISTRATION: with
//      `oauth2.dynamicRegistrationTokenResponseTypes` empty every token
//      type is 0999; listed ones register and others are
//      0999; over HTTP a registration records them on the attribute, the
//      client may then use them, and an RFC 7592 update is held to the list
//      and replaces the attribute.
//   H. THE ADMINISTRATOR'S WRITE: a create or an add refused STS-REG-0364
//      while the realm does not allow the types (mode on and not waived,
//      OAuth 2.1, FAPI), allowed where it does or where the mode is off;
//      stored in canonical order, a value outside the four refused
//      STS-REG-0203, and a remove never refused.
//   I. OAUTH 2.1 AND FAPI with every switch on — the waiver, the dynamic
//      list, the application listing the type — still refuse 0126 and 0134.
//   J. THE OWNER (in this process, `owner_administration.js`'s arrangement):
//      the access-control policy lets an application's owner write
//      `oauthAllowedTokenResponseTypes` and refuses a person who is not an
//      owner, and one holding no owner role.
//   K. THE REPORT AND THE PAGES: `waived` says the waiver is per application
//      and carries the dynamic-registration setting with its value;
//      /admin/mode draws both; the console's application view carries the
//      enabled types and whether the realm honours them, and the OAuth block
//      draws them with section 2.1.2's warning.
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
  function send(port, method, urlPath, body, extra) {
    return new Promise(function (resolve) {
      const data = body === undefined ? '' : JSON.stringify(body);
      const req = http.request({ host: '127.0.0.1', port: port,
        method: method, path: urlPath,
        headers: Object.assign(data
          ? { 'content-type': 'application/json',
              'content-length': Buffer.byteLength(data) } : {},
          extra || {}) },
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
    const DYN = 'oauth2.dynamicRegistrationTokenResponseTypes';
    const ALL_FOUR = 'token,code token,id_token token,code id_token token';
    const applications = require(ROOT + '/common/applications');
    const errorCodes = require(ROOT + '/common/error_codes');
    const specs = {
      // #1296: the waiver with the dynamic-registration list, all four or
      // one; a realm flipped off after its applications were written.
      BCP_DYN: { 'oauth2.rfc9700': true, [KEY]: true, [DYN]: ALL_FOUR },
      BCP_DYN1: { 'oauth2.rfc9700': true, [KEY]: true,
                  [DYN]: 'id_token token' },
      PROD_DYN: { 'global.mode': 'product', [KEY]: true,
                  [DYN]: 'id_token token' },
      SWITCH: { 'oauth2.rfc9700': true, [KEY]: true },
      V21_ALL: { 'oauth2.oauth21': true, [KEY]: true, [DYN]: ALL_FOUR },
      FAPI_ALL: { 'oauth2.fapi': '1-baseline', [KEY]: true,
                  [DYN]: ALL_FOUR },
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
    const authorize = function (types, clientId) {
      return bcp.checkAuthorizationRequest({
        query: { scope: 'openid', nonce: 'n-1', state: 's-1',
                 client_id: clientId || 'itr-nobody',
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
    // An application in the ambient realm listing `types` (#1296).
    const makeApp = function (id, types) {
      const fields = { oauthClientId: id,
                       oauthRedirectUri: ['https://rp.example/cb'],
                       oauthTokenEndpointAuthMethod: ['none'] };
      if (types) {
        fields.oauthAllowedTokenResponseTypes = types;
      }
      return applications.createApplication({ identifier: id,
        protocols: ['oauth2', 'oidc'], fields: fields });
    };
    const listed = function (id) {
      return applications.allowedTokenResponseTypesOf(id);
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
          // Since #1296 the setting makes the type possible and the
          // application has to have it enabled: F holds both halves.
          const id = 'itr-b4-' + on.toLowerCase().replace(/_/g, '') + '-' +
            type.replace(/ /g, '-');
          const app = makeApp(id, [type]);
          note(app.ok && authorize(type, id).ok,
               'B4. ' + on + ': response_type=' + type + ' is accepted with ' +
               'the setting on, for an application that enables it',
               JSON.stringify([app.errors, codeOf(authorize(type, id))]));
          const grants = type.indexOf('code') >= 0
            ? ['authorization_code', 'implicit'] : ['implicit'];
          note(codeOf(register(grants, [type])) === 'STS-OAUTH-0999',
               'B5. ' + on + ': registering ' + type + ' with ' +
               JSON.stringify(grants) + ' is past 0133 and 0134, and is ' +
               'STS-OAUTH-0999 with the dynamic-registration list empty',
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
        // The client B4 enabled id_token token on, so that the nonce is
        // what is left to refuse (#1296).
        const noNonce = bcp.checkAuthorizationRequest({
          query: { scope: 'openid',
                   client_id: 'itr-b4-' + on.toLowerCase().replace(/_/g, '') +
                     '-id_token-token',
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
             level: 'SHOULD NOT', setting: KEY, perApplication: true,
             attribute: 'oauthAllowedTokenResponseTypes',
             dynamicRegistration: { setting: DYN, value: [] } }]) &&
           state.settings[KEY] === true &&
           JSON.stringify(state.settings[DYN]) === '[]',
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
      note(/PER APPLICATION/.test(drawn) &&
           drawn.indexOf('oauthAllowedTokenResponseTypes') >= 0 &&
           drawn.indexOf(DYN) >= 0 && /is empty/.test(drawn),
           'K1. /admin/mode says the waiver is per application, names the ' +
           'attribute and the dynamic-registration setting, and that it is ' +
           'empty', drawn.slice(drawn.indexOf('PER APPLICATION'),
                                drawn.indexOf('PER APPLICATION') + 400));
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

    // --- F. The authorization endpoint, realm × application (#1296) -----
    inRealm('SWITCH', function () {
      TOKEN_TYPES.forEach(function (type) {
        const slug = type.replace(/ /g, '-');
        const made = makeApp('itr-f-on-' + slug, [type]);
        note(made.ok, 'F0. SWITCH: an application enabling ' + type + ' is ' +
             'created while the realm allows it', JSON.stringify(made));
        makeApp('itr-f-off-' + slug, null);
      });
      // One application listing every OTHER type, so "lists something" is
      // not mistaken for "lists this".
      TOKEN_TYPES.forEach(function (type) {
        const slug = type.replace(/ /g, '-');
        makeApp('itr-f-other-' + slug, TOKEN_TYPES.filter(function (one) {
          return one !== type;
        }));
      });
      TOKEN_TYPES.forEach(function (type) {
        const slug = type.replace(/ /g, '-');
        note(authorize(type, 'itr-f-on-' + slug).ok,
             'F1. realm on, application on: ' + type + ' is accepted',
             codeOf(authorize(type, 'itr-f-on-' + slug)));
        const off = authorize(type, 'itr-f-off-' + slug);
        note(!off.ok && off.errorCode === 'STS-OAUTH-0998' &&
             off.error === 'unauthorized_client' &&
             off.description.indexOf('oauthAllowedTokenResponseTypes') >= 0,
             'F2. realm on, application off: ' + type + ' is ' +
             'unauthorized_client, STS-OAUTH-0998, naming the attribute',
             JSON.stringify(off));
        note(codeOf(authorize(type, 'itr-f-other-' + slug)) ===
               'STS-OAUTH-0998',
             'F3. realm on, application listing every other type: ' + type +
             ' is still 0998', codeOf(authorize(type, 'itr-f-other-' +
                                                         slug)));
        note(codeOf(authorize(type.split(' ').reverse().join(' '),
                              'itr-f-on-' + slug)) === 'ok',
             'F4. the words of ' + type + ' in another order are the same ' +
             'response type');
      });
      note(authorize('code id_token', 'itr-f-off-token').ok &&
           authorize('code', 'itr-f-off-token').ok,
           'F5. a token-free response type needs nothing enabled');
      const flipped = realms.setOverride(made.SWITCH.id, KEY, false);
      note(flipped.ok, 'F6. the realm\'s waiver is turned off',
           JSON.stringify(flipped));
    });
    inRealm('SWITCH', function () {
      TOKEN_TYPES.forEach(function (type) {
        const slug = type.replace(/ /g, '-');
        note(listed('itr-f-on-' + slug).indexOf(type) >= 0 &&
             codeOf(authorize(type, 'itr-f-on-' + slug)) === 'STS-OAUTH-0126',
             'F7. realm off, application on: ' + type + ' is ' +
             'unsupported_response_type, STS-OAUTH-0126',
             codeOf(authorize(type, 'itr-f-on-' + slug)));
        note(codeOf(authorize(type, 'itr-f-off-' + slug)) ===
               'STS-OAUTH-0126',
             'F8. realm off, application off: ' + type + ' is 0126');
      });
      // --- H, the realm not allowing them -----------------------------
      const create = makeApp('itr-h-create', ['token']);
      note(!create.ok && errorCodes.codeOf(create) === 'STS-REG-0364' &&
           JSON.stringify(create.errors).indexOf(
             'oauthAllowedTokenResponseTypes') >= 0 &&
           JSON.stringify(create.errors).indexOf(KEY) >= 0,
           'H1. a create listing a token type while the realm does not ' +
           'allow them is STS-REG-0364, naming the attribute and the setting',
           JSON.stringify(create));
      const add = applications.updateApplication('itr-f-off-token',
        { attribute: 'oauthAllowedTokenResponseTypes', mode: 'add',
          value: 'token' });
      note(!add.ok && errorCodes.codeOf(add) === 'STS-REG-0364',
           'H2. and so is an add', JSON.stringify(add));
      const remove = applications.updateApplication('itr-f-on-token',
        { attribute: 'oauthAllowedTokenResponseTypes', mode: 'remove',
          value: 'token' });
      note(remove.ok && listed('itr-f-on-token').length === 0,
           'H3. a remove is never refused, so a withdrawn waiver can be ' +
           'tidied up', JSON.stringify([remove, listed('itr-f-on-token')]));
      const plain = makeApp('itr-h-plain', null);
      note(plain.ok, 'H4. an application listing nothing is created as ' +
           'before', JSON.stringify(plain));
    });
    inRealm('BCP_ON', function () {
      makeApp('itr-h-on', null);
      const add = applications.updateApplication('itr-h-on',
        { attribute: 'oauthAllowedTokenResponseTypes', mode: 'add',
          value: 'token  id_token' });
      note(add.ok && JSON.stringify(listed('itr-h-on')) ===
             '["id_token token"]',
           'H5. where the realm allows them an add is stored, its words ' +
           'sorted', JSON.stringify([add, listed('itr-h-on')]));
      const wrong = applications.updateApplication('itr-h-on',
        { attribute: 'oauthAllowedTokenResponseTypes', mode: 'add',
          value: 'code id_token' });
      note(!wrong.ok && errorCodes.codeOf(wrong) === 'STS-REG-0203',
           'H6. a response type that is not one of the four is STS-REG-0203',
           JSON.stringify(wrong));
      const row = applications.applicationFields().filter(function (one) {
        return one.attribute === 'oauthAllowedTokenResponseTypes';
      })[0] || {};
      note(row.type === 'array' && JSON.stringify(row.choices) ===
             JSON.stringify(applications.TOKEN_RESPONSE_TYPES) &&
           row.editable === 'multi',
           'H7. the field grid offers a checkbox for each of the four',
           JSON.stringify(row));
    });
    inRealm('BCP', function () {
      const create = makeApp('itr-h-bcp', ['id_token token']);
      note(!create.ok && errorCodes.codeOf(create) === 'STS-REG-0364',
           'H8. BCP with the waiver off: a create is STS-REG-0364',
           JSON.stringify(create));
    });
    inRealm('OFF_ON', function () {
      const create = makeApp('itr-h-off', ['token']);
      note(create.ok && authorize('token', 'itr-h-nobody').ok,
           'H9. outside RFC 9700 mode the attribute may be written, and ' +
           'narrows nothing', JSON.stringify(create));
    });

    // --- G. Dynamic registration, in process -------------------------------
    inRealm('PROD_DYN', function () {
      note(JSON.stringify(bcp.dynamicRegistrationTokenResponseTypes()) ===
             '["id_token token"]',
           'G1. PROD_DYN: the realm lists id_token token');
      note(codeOf(register(['implicit'], ['id_token token'])) === 'ok',
           'G2. PROD_DYN: registering id_token token is accepted',
           codeOf(register(['implicit'], ['id_token token'])));
      note(codeOf(register(['implicit'], ['token id_token'])) === 'ok',
           'G3. in either word order');
      const outside = register(['authorization_code', 'implicit'],
                               ['code', 'code token']);
      note(!outside.ok && outside.errorCode === 'STS-OAUTH-0999' &&
           outside.error === 'invalid_client_metadata' &&
           outside.description.indexOf(DYN) >= 0,
           'G4. PROD_DYN: code token, not on the list, is ' +
           'invalid_client_metadata, STS-OAUTH-0999, naming the setting',
           JSON.stringify(outside));
    });
    inRealm('BCP_DYN', function () {
      TOKEN_TYPES.forEach(function (type) {
        const grants = type.indexOf('code') >= 0
          ? ['authorization_code', 'implicit'] : ['implicit'];
        note(codeOf(register(grants, [type])) === 'ok',
             'G5. BCP_DYN: registering ' + type + ' is accepted with all ' +
             'four listed', codeOf(register(grants, [type])));
      });
    });

    // --- I. OAuth 2.1 and FAPI with every switch on -------------------------
    ['V21_ALL', 'FAPI_ALL'].forEach(function (name) {
      inRealm(name, function () {
        const made2 = makeApp('itr-i-' + name.toLowerCase().replace(/_/g, ''),
                              ['token']);
        note(!made2.ok && errorCodes.codeOf(made2) === 'STS-REG-0364',
             'I1. ' + name + ': an application cannot even list a token type',
             JSON.stringify(made2));
        TOKEN_TYPES.forEach(function (type) {
          note(codeOf(authorize(type, 'itr-i-any')) === 'STS-OAUTH-0126',
               'I2. ' + name + ': ' + type + ' is still 0126 with the ' +
               'waiver and the dynamic list on');
          note(codeOf(register(null, [type])) === 'STS-OAUTH-0134',
               'I3. ' + name + ': and registering it is still 0134',
               codeOf(register(null, [type])));
        });
      });
    });

    // --- K. The console's application view ----------------------------------
    inRealm('BCP_ON', function () {
      const views = require(ROOT + '/admin-core/admin_views');
      const viewsOf = views.instance || views;
      const state = (viewsOf.applicationObservedState
        ? viewsOf : new views.AdminViews(views.AdminViews.defaultDeps()))
        .applicationObservedState(applications.get('itr-h-on').fields,
                                  'itr-h-on');
      const tokens = state.oauthAllowedTokenResponseTypes || {};
      note(JSON.stringify(tokens.enabled) === '["id_token token"]' &&
           tokens.enforced === true && tokens.waived === true,
           'K2. the application view carries the enabled types and that ' +
           'the realm honours them', JSON.stringify(tokens));
      const page = require(ROOT + '/admin-ui/web_applications');
      const t = require(ROOT + '/admin-ui/web_kit').context
        ? require(ROOT + '/admin-ui/web_kit').context({}).t : null;
      if (t) {
        const row = { page: { config: { observed: state } } };
        const line = page.tokenResponseTypesLine(row, t);
        note(line.indexOf('cfg-token-response-types') >= 0 &&
             line.indexOf('id_token token') >= 0 &&
             /SHOULD NOT/.test(line) && /2\.1\.2/.test(line),
             'K3. the OAuth block draws them with section 2.1.2\'s warning',
             line.slice(0, 600));
        const none = page.tokenResponseTypesLine({ page: { config: {
          observed: { oauthAllowedTokenResponseTypes: { enabled: [],
            enforced: true, waived: false } } } } }, t);
        note(none === '', 'K4. and nothing where none is enabled and the ' +
             'realm does not waive the section');
        const notHonoured = page.tokenResponseTypesLine({ page: { config: {
          observed: { oauthAllowedTokenResponseTypes: {
            enabled: ['token'], enforced: true, waived: false } } } } }, t);
        note(/Not honoured/.test(notHonoured),
             'K5. a value the realm does not honour says so',
             notHonoured.slice(0, 400));
      } else {
        note(false, 'K3. the console kit offers a translator');
      }
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
    const tokenEmpty = await registerOver('BCP_ON', {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code', 'code id_token token'] });
    note(tokenEmpty.status === 400 && tokenEmpty.json &&
         tokenEmpty.json.error === 'invalid_client_metadata',
         'G6. BCP_ON: with the dynamic-registration list empty a token type ' +
         'is refused invalid_client_metadata over HTTP',
         tokenEmpty.status + ' ' + tokenEmpty.text.slice(0, 300));
    const tokenOn = await registerOver('BCP_DYN', {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code', 'code id_token token', 'id_token token',
                       'code token'] });
    note(tokenOn.status === 201,
         'E5. BCP_DYN: and accepted with the setting on and the types ' +
         'listed for self-registration',
         tokenOn.status + ' ' + tokenOn.text.slice(0, 300));
    if (tokenOn.json && tokenOn.json.client_id) {
      const held = realms.run(realms.get(made.BCP_DYN.id), function () {
        return listed(tokenOn.json.client_id);
      });
      note(JSON.stringify(held.slice(0).sort()) === JSON.stringify(
             ['code id_token token', 'code token', 'id_token token']),
           'G7. the registration records its token types on ' +
           'oauthAllowedTokenResponseTypes, and only those',
           JSON.stringify(held));
    }
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
      const on = await askFor('BCP_DYN', tokenOn.json.client_id,
                              'id_token token');
      note(on.status < 500 &&
           !/unsupported_response_type|unauthorized_client/.test(
             on.text + String(on.headers.location || '')),
           'E6. BCP_DYN: GET /oauth2/authorize?response_type=id_token token ' +
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

    // F over HTTP: an administered application in a waived realm that does
    // not enable the type is answered unauthorized_client at its redirect.
    realms.run(realms.get(made.BCP_ON.id), function () {
      makeApp('itr-e-plain', null);
    });
    const plainAsk = await askFor('BCP_ON', 'itr-e-plain', 'code token');
    note(/unauthorized_client/.test(String(plainAsk.headers.location || '') +
                                    plainAsk.text),
         'F9. BCP_ON over HTTP: an application without code token enabled ' +
         'is answered unauthorized_client',
         plainAsk.status + ' ' + String(plainAsk.headers.location || '') +
         ' ' + plainAsk.text.slice(0, 200));

    // G over HTTP: RFC 7592's update is held to the list and replaces the
    // attribute.
    const one = await registerOver('BCP_DYN1', {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code', 'id_token token'] });
    const recorded = one.json && one.json.client_id
      ? realms.run(realms.get(made.BCP_DYN1.id), function () {
        return listed(one.json.client_id);
      }) : null;
    note(one.status === 201 &&
         JSON.stringify(recorded) === '["id_token token"]',
         'G8. BCP_DYN1: registering id_token token, the one listed, is 201 ' +
         'and records it', one.status + ' ' + JSON.stringify(recorded) + ' ' +
         one.text.slice(0, 300));
    if (one.json && one.json.registration_access_token) {
      const where = '/realm/' + made.BCP_DYN1.id + '/oauth2/register/' +
        encodeURIComponent(one.json.client_id);
      const bearer = { authorization: 'Bearer ' +
                                      one.json.registration_access_token };
      const base = { client_id: one.json.client_id,
                     redirect_uris: ['https://rp.example/cb'],
                     token_endpoint_auth_method: 'client_secret_basic',
                     client_name: 'itr BCP_DYN1' };
      const wider = await send(port, 'PUT', where, Object.assign({
        grant_types: ['authorization_code', 'implicit'],
        response_types: ['code', 'id_token token', 'code token'] }, base),
        bearer);
      note(wider.status === 400 && wider.json &&
           wider.json.error === 'invalid_client_metadata',
           'G9. an RFC 7592 update asking for code token, not listed, is ' +
           'invalid_client_metadata', wider.status + ' ' +
           wider.text.slice(0, 300));
      const narrower = await send(port, 'PUT', where, Object.assign({
        grant_types: ['authorization_code'], response_types: ['code'] },
        base), bearer);
      const after = realms.run(realms.get(made.BCP_DYN1.id), function () {
        return listed(one.json.client_id);
      });
      note(narrower.status === 200 && after.length === 0,
           'G10. and an update to code alone replaces the attribute with ' +
           'nothing', narrower.status + ' ' + JSON.stringify(after) + ' ' +
           narrower.text.slice(0, 200));
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

// ---------------------------------------------------------------------------
// J. THE OWNER (#1296, rcbj's decision 1), asked of the access-control
// policy the way the management API's gate asks it on an owner's token —
// `owner_administration.js`'s arrangement, with the ownership register a
// stub so the decision depends on the policy alone.
// ---------------------------------------------------------------------------
const OWNER_DN = 'uid=olive,ou=users,dc=example,dc=com';
const OTHER_DN = 'uid=mallory,ou=users,dc=example,dc=com';

function ownerPep() {
  log.debug("Entering ownerPep().");
  const accessPep = require('../xacml/xacml_access_pep');
  const pipModule = require('../xacml/xacml_pip');
  const templates = require('../xacml/xacml_templates');
  const objects = { 'application/itr-owned': { owners: [OWNER_DN],
                                               protected: false } };
  const pip = new pipModule.XacmlPip(Object.assign(
    pipModule.XacmlPip.defaultDeps(), {
      ownership: function () {
        return {
          objectOf: function (kind, name) {
            log.debug("Entering objectOf().");
            const found = objects[kind + '/' + name];
            log.debug("Leaving objectOf().");
            return found ? Object.assign({ found: true, kind: kind,
                                           name: name }, found)
              : { found: false, kind: kind, name: name, owners: [],
                  protected: false, reasons: [] };
          },
          identityOf: function (person) {
            log.debug("Entering identityOf().");
            log.debug("Leaving identityOf().");
            return { keys: person === 'olive' ? [OWNER_DN.toLowerCase()]
                                              : [OTHER_DN.toLowerCase()] };
          }
        };
      } }));
  const pep = new accessPep.XacmlAccessPep(Object.assign(
    accessPep.XacmlAccessPep.defaultDeps(), { pip: pip }));
  // The template's DEFAULTS, which is the claim: an owner may write the
  // attribute without anybody editing the policy.
  const built = templates.build('access-control', {},
                                { idBase: 'urn:sts:test:access-control' });
  pep.accessPolicy = function () {
    return { policy: built.policy, name: 'test', builtIn: true };
  };
  log.debug("Leaving ownerPep().");
  return pep;
}

function ownerWrite(person, roles, attributes) {
  log.debug("Entering ownerWrite().");
  log.debug("Leaving ownerWrite().");
  return {
    resource: 'management-api', action: 'write',
    requiredRoles: ['ADMIN_WRITE'],
    subject: { name: 'sts-user-portal', authenticated: true, roles: roles,
               sessionId: null },
    ownedObject: { kind: 'application', id: 'itr-owned', action: 'add',
                   attributes: attributes, requiredRole: 'OWNER_WRITE',
                   person: person }
  };
}

function theOwner(t) {
  log.debug("Entering theOwner().");
  t.log.info('=== J. the owner may enable a token response type ===');
  const pep = ownerPep();
  const allowed = function (question) {
    return pep.decide(question).allowed;
  };
  const attr = ['oauthAllowedTokenResponseTypes'];
  t.equal(allowed(ownerWrite('olive', ['OWNER_READ', 'OWNER_WRITE'], attr)),
          true, 'J1. the application\'s owner may add to ' +
          'oauthAllowedTokenResponseTypes under the template\'s defaults');
  t.equal(allowed(ownerWrite('mallory', ['OWNER_READ', 'OWNER_WRITE'],
                             attr)), false,
          'J2. a person who is not its owner may not');
  t.equal(allowed(ownerWrite('olive', [], attr)), false,
          'J3. nor may one holding no owner role and no administrator role');
  t.equal(allowed(ownerWrite('olive', ['OWNER_READ'], attr)), false,
          'J4. nor the owner on a read-only token');
  t.equal(allowed(ownerWrite('olive', ['OWNER_READ', 'OWNER_WRITE'],
                             ['oauthAllowedTokenResponseTypes',
                              'oauthGrantType'])), false,
          'J5. and the grant types beside it are still not an owner\'s');
  const portal = fs.readFileSync(path.join(ROOT, 'portal', 'web_owned.ts'),
                                 'utf8');
  const api = fs.readFileSync(path.join(ROOT, 'mgmt-api', 'admin_api.ts'),
                              'utf8');
  t.check(/name: 'oauthAllowedTokenResponseTypes', lines: true/.test(portal),
          'J6. the portal\'s owned-application page draws a field for it');
  t.check(/OWNER_APPLICATION_FIELDS = \[[^\]]*'oauthAllowedTokenResponseTypes'/
            .test(api),
          'J7. and the management API answers it on an owner\'s read');
  log.debug("Leaving theOwner().");
}

async function run(t) {
  log.debug("Entering run().");
  theOwner(t);
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
      // Fourteen realms and the default one: over realms.maxCount's ten.
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', ITR_ROOT: ROOT, ITR_OUT: out,
                           STS_REALMS_MAX_COUNT: '30' }),
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
            'id_token (#1295); each token response type enabled per ' +
            'application by oauthAllowedTokenResponseTypes, by an ' +
            'administrator, the owner or a dynamic registration within ' +
            'oauth2.dynamicRegistrationTokenResponseTypes (#1296)',
  run: run
};
