// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/flow_type_choices.js
//
// ---------------------------------------------------------------------------
// THE DECLARED FLOW LISTS AS CHECKBOXES, AND WHAT WAS SEEN DRAWN READ-ONLY
// (#706).
//
// rcbj: `oauthGrantType` and `oauthResponseType` are a checkbox per value
// rather than free text, and `oauthGrantTypeObserved` and
// `oauthResponseTypeObserved` are shown at the head of the application's
// OAuth 2.0 / OpenID Connect sub-tab, one line each, every value with a check
// mark, and never as something to edit. What is held:
//
//   A. the two declared lists are closed sets — `applications.FLOW_*` —
//      and the observed lists are no field of the grid;
//   B. the closed sets are what the metadata promises with every switch on:
//      `grant_types_supported` and `response_types_supported`, as sets;
//   C. a console or API write outside a set is refused (STS-REG-0203), a
//      response type is stored with its words sorted, and a remove in another
//      word order still removes;
//   D. the sub-tab: the observed lines come first, carry a check mark per
//      value and no control, and the declared lists are checkboxes, ticked
//      as the entry holds them, with no text box.
//
// And #708 — every other sighting, beside what it shadows:
//
//   E. the OAuth block's five lines in order, a value outside a declared
//      list marked with a warning instead of a check, and a line cut at ten
//      values with "+N more" to the Directory entry tab; a scope a delegated
//      permission grant declares counts as on the list, and the
//      oauthAllowedScope cell draws it read-only with a tooltip (#1141);
//   F. a URN choice is labelled by its last two sections, its full value and
//      meaning in the tooltip, and still posts the full value;
//   G. the SAML panels: SAML 2.0's lists, its last AuthnRequest and the
//      observed certificate by subject and thumbprint; SAML 1.1's lists and
//      the note that the profiles share them;
//   H. the Overview's four counters, and `oauthScope` refused at a set or an
//      add (STS-REG-0361) while a remove still works.
//
// In a child process, because it loads the whole stack and serves it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'flow_type_choices',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.FT_ROOT;
  const OUT = process.env.FT_OUT;
  const fs = require('fs');
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function get(port, urlPath) {
    return new Promise(function (resolve) {
      http.get({ host: '127.0.0.1', port: port, path: urlPath },
               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, json: parsed });
        });
      });
    });
  }
  const sorted = function (list) {
    return JSON.stringify([].concat(list || []).slice(0).sort());
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const views = require(ROOT + '/admin-core/admin_views');
    const page = require(ROOT + '/admin-ui/web_applications');
    const WebKit = require(ROOT + '/admin-ui/web_kit');
    const errorCodes = require(ROOT + '/common/error_codes');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const stamp = String(Date.now()).slice(-6);
    // Every switch that adds a grant to the metadata, on.
    const realm = realms.create({ id: 'ft-' + stamp, name: 'ft',
      overrides: { 'oauth2.jwtBearerGrant': true,
                   'oauth2.saml2BearerGrant': true, 'oauth2.ciba': true,
                   'oauth2.deviceAuthorization': true } }).realm;

    // --- A. The fields -------------------------------------------------
    const rows = applications.applicationFields();
    const rowOf = function (name) {
      return rows.filter(function (one) {
        return one.attribute === name;
      })[0] || null;
    };
    const grants = rowOf('oauthGrantType');
    const responses = rowOf('oauthResponseType');
    note(!!grants && grants.type === 'array' &&
         sorted(grants.choices) === sorted(applications.FLOW_GRANT_TYPES) &&
         !!responses && responses.type === 'array' &&
         sorted(responses.choices) ===
           sorted(applications.FLOW_RESPONSE_TYPES),
         'A1. oauthGrantType and oauthResponseType are lists from a closed ' +
         'set', JSON.stringify([grants && grants.choices,
                                responses && responses.choices]));
    note(!rowOf('oauthGrantTypeObserved') &&
         !rowOf('oauthResponseTypeObserved'),
         'A2. the observed lists are no field of the grid');

    // --- B. The metadata, every switch on ------------------------------
    const meta = await get(port, '/realm/' + realm.id +
                           '/.well-known/openid-configuration');
    note(meta.status === 200 &&
         sorted(meta.json.grant_types_supported) ===
           sorted(applications.FLOW_GRANT_TYPES),
         'B1. the grant choices are grant_types_supported with every ' +
         'switch on', JSON.stringify(meta.json.grant_types_supported));
    note(meta.status === 200 &&
         sorted(meta.json.response_types_supported) ===
           sorted(applications.FLOW_RESPONSE_TYPES),
         'B2. the response type choices are response_types_supported',
         JSON.stringify(meta.json.response_types_supported));
    note(applications.FLOW_RESPONSE_TYPES.every(function (one) {
      return applications.canonicalResponseType(one) === one;
    }), 'B3. every response type choice is written in canonical order');

    await realms.run(realm, async function () {
      // --- C. The writes -------------------------------------------------
      const made = applications.createApplication({ identifier: 'ft-web',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'ft-web',
                  oauthGrantType: ['authorization_code', 'refresh_token'],
                  oauthResponseType: ['id_token code', 'code'] } });
      const held = function (name) {
        return [].concat(applications.get('ft-web').fields[name] || [])
          .map(String);
      };
      note(made.ok && sorted(held('oauthResponseType')) ===
             sorted(['code', 'code id_token']),
           'C1. a create stores a response type with its words sorted',
           JSON.stringify([made.errors, held('oauthResponseType')]));
      const badCreate = applications.createApplication({
        identifier: 'ft-bad', protocols: ['oauth2'],
        fields: { oauthGrantType: ['urn:example:not-a-grant'] } });
      note(!badCreate.ok && errorCodes.codeOf(badCreate) === 'STS-REG-0203',
           'C2. a create naming a grant this service does not implement is ' +
           'refused, STS-REG-0203', JSON.stringify(badCreate));
      const badAdd = applications.updateApplication('ft-web',
        { attribute: 'oauthGrantType', mode: 'add',
          value: 'authorisation_code' });
      const badType = applications.updateApplication('ft-web',
        { attribute: 'oauthResponseType', mode: 'add',
          value: 'code code_token' });
      note(!badAdd.ok && errorCodes.codeOf(badAdd) === 'STS-REG-0203' &&
           !badType.ok && errorCodes.codeOf(badType) === 'STS-REG-0203',
           'C3. an add outside either set is refused, STS-REG-0203',
           JSON.stringify([badAdd, badType]));
      const add = applications.updateApplication('ft-web',
        { attribute: 'oauthResponseType', mode: 'add',
          value: 'token  id_token code' });
      note(add.ok && held('oauthResponseType')
             .indexOf('code id_token token') >= 0,
           'C4. an add stores its response type with its words sorted',
           JSON.stringify([add.errors, held('oauthResponseType')]));
      const remove = applications.updateApplication('ft-web',
        { attribute: 'oauthResponseType', mode: 'remove',
          value: 'token code id_token' });
      note(remove.ok && held('oauthResponseType')
             .indexOf('code id_token token') < 0,
           'C5. a remove in another word order still removes it',
           JSON.stringify([remove.errors, held('oauthResponseType')]));

      // --- D. The sub-tab --------------------------------------------------
      applications.seen({ identifier: 'ft-web', kind: 'oauth2-client',
        protocol: 'OAuth 2.0 / OIDC', counts: false, note: 'a test sighting',
        fields: { oauthClientId: 'ft-web',
                  oauthGrantTypeObserved: 'refresh_token',
                  oauthResponseTypeObserved: 'code' } });
      const request = { query: {}, headers: { host: 'localhost:8081' },
                        protocol: 'https', get: function () { return ''; } };
      const json = views.applicationDetailJson(request, 'ft-web').json;
      const observed = json.page.config.observed;
      const valuesOf = function (list) {
        return [].concat(list || []).map(function (one) {
          return one.value;
        });
      };
      note(sorted(valuesOf(observed.oauthGrantTypeObserved)) ===
             sorted(['refresh_token']) &&
           sorted(valuesOf(observed.oauthResponseTypeObserved)) ===
             sorted(['code']) &&
           observed.oauthGrantTypeObserved[0].declared === true,
           'D1. the answer carries what was seen, read off the entry',
           JSON.stringify(observed));
      const section = page.applicationFieldsSection(WebKit.context({}, true),
                                                    json, '');
      const oauth = section.indexOf('id="cfg-oauth"');
      const at = section.indexOf('id="cfg-oauth-observed"');
      const form = section.indexOf('<form', oauth);
      const block = at < 0 ? '' : section.slice(at, section.indexOf(
        '</div></div>', at) + 12);
      note(oauth >= 0 && at > oauth && form > at,
           'D2. the observed lines are at the head of the OAuth sub-tab, ' +
           'above its form', JSON.stringify({ oauth: oauth, at: at,
                                              form: form }));
      note(/<code>oauthGrantTypeObserved<\/code><span class="fg-seen"[^>]*><svg[^]*?<\/svg>refresh_token<\/span>/
             .test(block) &&
           /<code>oauthResponseTypeObserved<\/code><span class="fg-seen"><svg[^]*?<\/svg>code<\/span>/
             .test(block) &&
           !/<input|<textarea|<select|<button|<form/.test(block),
           'D3. one line each: the name, then each value with a check ' +
           'mark, and no control', block.slice(0, 600));
      const cellOf = function (name) {
        const start = section.indexOf('id="fgc-' + name + '"');
        return start < 0 ? '' : section.slice(start,
          section.indexOf('id="fgc-', start + 5) > 0
            ? section.indexOf('id="fgc-', start + 5) : undefined);
      };
      const grantCell = cellOf('oauthGrantType');
      const typeCell = cellOf('oauthResponseType');
      const boxes = function (cell) {
        return (cell.match(/<input type="checkbox"/g) || []).length;
      };
      note(boxes(grantCell) === applications.FLOW_GRANT_TYPES.length &&
           boxes(typeCell) === applications.FLOW_RESPONSE_TYPES.length &&
           !/type="text"/.test(grantCell) && !/type="text"/.test(typeCell),
           'D4. the declared lists are a checkbox per value and no text box',
           JSON.stringify([boxes(grantCell), boxes(typeCell)]));
      note(/value="authorization_code" checked/.test(grantCell) &&
           /value="refresh_token" checked/.test(grantCell) &&
           /value="client_credentials">/.test(grantCell) &&
           /value="code id_token" checked/.test(typeCell),
           'D5. ticked as the entry holds them', grantCell.slice(0, 400));
      note(section.indexOf('id="fgc-oauthGrantTypeObserved"') < 0 &&
           section.indexOf('id="fgc-oauthResponseTypeObserved"') < 0 &&
           section.indexOf('name="field.oauthGrantTypeObserved') < 0,
           'D6. no pane offers the observed lists as a field');
      note(page.applicationObservedFlows({ page: { config: {} } },
                                         WebKit.context({}, true).t) === '',
           'D7. an answer without the member draws nothing');

      // --- E. The OAuth block, #708 ----------------------------------------
      const ctx = WebKit.context({}, true);
      applications.updateApplication('ft-web', { attribute: 'oauthRedirectUri',
        mode: 'add', value: 'https://ft.example/cb' });
      applications.updateApplication('ft-web', {
        attribute: 'oauthAllowedScope', mode: 'add', value: 'openid' });
      const scopes = ['openid'];
      for (let i = 1; i <= 12; i++) {
        scopes.push('ft-scope-' + i);
      }
      applications.seen({ identifier: 'ft-web', kind: 'oauth2-client',
        protocol: 'OAuth 2.0 / OIDC', counts: false, note: 'a test sighting',
        fields: { oauthClientId: 'ft-web',
                  oauthGrantTypeObserved: 'client_credentials',
                  appRedirectUriObserved: ['https://ft.example/cb',
                                           'https://ft.example/other'],
                  oauthScope: scopes,
                  appAuthorizationServer: 'default' } });
      const json2 = views.applicationDetailJson(request, 'ft-web').json;
      const oauthHtml = page.applicationObservedFlows(json2, ctx.t);
      const lineOf = function (html, name) {
        const at = html.indexOf('<code>' + name + '</code>');
        return at < 0 ? '' : html.slice(at, html.indexOf('</div>', at));
      };
      const order = ['oauthGrantTypeObserved', 'oauthResponseTypeObserved',
                     'appRedirectUriObserved', 'oauthScope',
                     'appAuthorizationServer'].map(function (name) {
        return oauthHtml.indexOf('<code>' + name + '</code>');
      });
      note(order.every(function (at, i) {
        return at >= 0 && (i === 0 || at > order[i - 1]);
      }), 'E1. the OAuth block draws its five lines in order',
           JSON.stringify(order));
      const redirectLine = lineOf(oauthHtml, 'appRedirectUriObserved');
      const grantLine = lineOf(oauthHtml, 'oauthGrantTypeObserved');
      note(/fg-undeclared"[^>]*><svg[^]*?<\/svg>https:\/\/ft\.example\/other</
             .test(redirectLine) &&
           /<span class="fg-seen"[^>]*><svg[^]*?<\/svg>https:\/\/ft\.example\/cb</
             .test(redirectLine) &&
           /fg-undeclared"[^>]*><svg[^]*?<\/svg>client_credentials</
             .test(grantLine) &&
           !/fg-undeclared"[^>]*><svg[^]*?<\/svg>refresh_token</
             .test(grantLine),
           'E2. a value outside the declared list is marked with a warning, ' +
           'one on it with a check', redirectLine + ' | ' + grantLine);
      const scopeLine = lineOf(oauthHtml, 'oauthScope');
      const spans = (scopeLine.match(/class="fg-seen/g) || []).length;
      note(spans === 10 && /href="#tab-entry">\+3 more</.test(scopeLine) &&
           /fg-undeclared"[^>]*><svg[^]*?<\/svg>ft-scope-1</
             .test(scopeLine) &&
           /<span class="fg-seen"[^>]*><svg[^]*?<\/svg>openid</
             .test(scopeLine),
           'E3. ten values, then "+3 more" to the Directory entry tab; a ' +
           'scope outside oauthAllowedScope is marked', scopeLine);
      // E4 (#1141): a scope a delegated permission grant declares is on the
      // list — the bare word of one of this service's APIs, and the
      // permission identifier — and one with no grant is still marked.
      const granted = applications.updateApplication('ft-web', {
        attribute: 'oauthDelegatedPermission', mode: 'add',
        value: 'urn:sts:admin-api:admin:read' });
      applications.seen({ identifier: 'ft-web', kind: 'oauth2-client',
        protocol: 'OAuth 2.0 / OIDC', counts: false, note: 'a test sighting',
        fields: { oauthClientId: 'ft-web',
                  oauthScope: ['admin:read', 'admin:write',
                               'urn:sts:admin-api:admin:read'] } });
      const seenScopes = views.applicationDetailJson(request, 'ft-web').json
        .page.config.observed.oauthScope;
      const declaredOf = function (value) {
        const hit = seenScopes.filter(function (one) {
          return one.value === value;
        })[0];
        return hit ? hit.declared : null;
      };
      note(granted && granted.ok && declaredOf('admin:read') === true &&
           declaredOf('urn:sts:admin-api:admin:read') === true &&
           declaredOf('admin:write') === false,
           'E4. a scope a delegated permission grant declares is not marked, ' +
           'as its bare word or its identifier; one without is (#1141)',
           JSON.stringify([granted && granted.errors, seenScopes]));
      // E5 (#1141): the oauthAllowedScope cell draws it read-only — the key,
      // the details in a tooltip, a link to the Permissions tab — and never
      // as an input, so a save neither posts nor stores it.
      const json3 = views.applicationDetailJson(request, 'ft-web').json;
      const derived = (json3.page.config.derived || {}).oauthAllowedScope ||
        [];
      const cellHtml = page.applicationFieldsSection(ctx, json3, '');
      const cellAt = cellHtml.indexOf('id="fgc-oauthAllowedScope"');
      const cell = cellAt < 0 ? '' : cellHtml.slice(cellAt,
        cellHtml.indexOf('class="fg-grow"', cellAt));
      note(derived.length === 1 && derived[0].value === 'admin:read' &&
           derived[0].api === 'sts-management-api' &&
           derived[0].permission === 'urn:sts:admin-api:admin:read' &&
           /class="fg-item fg-derived"><span class="fg-derived-value"[^>]*title="[^"]*urn:sts:admin-api:admin:read[^"]*"[^>]*><svg[^]*?<\/svg>admin:read<\/span><a class="fg-derived-link" href="#tab-permissions">/
             .test(cell) &&
           !/value="admin:read"/.test(cell),
           'E5. the oauthAllowedScope cell draws a delegated permission ' +
           'grant\'s scope read-only, with its details as a tooltip and a ' +
           'link to the Permissions tab, and no input (#1141)',
           JSON.stringify(derived) + ' | ' + cell.slice(0, 600));

      // --- F. URN choices by their last two sections ---------------------
      const section2 = page.applicationFieldsSection(ctx, json2, '');
      const exchange = 'urn:ietf:params:oauth:grant-type:token-exchange';
      const labelAt = section2.indexOf('value="' + exchange + '"');
      const label = labelAt < 0 ? '' : section2.slice(
        section2.lastIndexOf('<label', labelAt),
        section2.indexOf('</label>', labelAt));
      note(/>grant-type:token-exchange$/.test(label) &&
           label.indexOf('title="' + exchange + ' — ') >= 0 &&
           /RFC 8693/.test(label) &&
           /value="urn:openid:params:grant-type:ciba"[^>]*>grant-type:ciba/
             .test(section2) &&
           /value="authorization_code"[^>]*>authorization_code/
             .test(section2),
           'F1. a URN grant is labelled by its last two sections, with its ' +
           'full value and meaning in the tooltip; a plain one as it is',
           label.slice(0, 400));

      // --- G. The SAML panels ----------------------------------------------
      const cert = require(ROOT + '/common/crypto')
        .selfSignedRsaCertificate({ commonName: 'ft-sp-signer', bits: 2048 });
      applications.createApplication({ identifier: 'ft-sp',
        protocols: ['saml2', 'saml11'],
        fields: { samlEntityId: 'https://ft-sp.example/metadata' } });
      applications.seen({ identifier: 'ft-sp', kind: 'saml2-service-provider',
        protocol: 'SAML 2.0', counts: false, note: 'a test sighting',
        fields: { samlNameIdFormat:
                    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                  samlResponseBinding:
                    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                  samlAuthnRequestSigned: 'TRUE',
                  samlAuthnRequestVerification:
                    'verified HTTP-Redirect rsa-sha256',
                  samlObservedSigningCertificate: cert.certB64 } });
      const spJson = views.applicationDetailJson(request, 'ft-sp').json;
      const saml2 = page.applicationObservedSaml(spJson, ctx.t, 'saml2');
      const saml11 = page.applicationObservedSaml(spJson, ctx.t, 'saml11');
      const thumb = require(ROOT + '/common/crypto').certificateThumbprint(
        cert.certB64, { format: 'colon-hex' });
      note(/id="cfg-saml2-observed"/.test(saml2) &&
           />nameid-format:persistent</.test(saml2) &&
           />bindings:HTTP-POST</.test(saml2) &&
           /Last AuthnRequest<\/code><span>signed<\/span><span class="state-valid">verified<\/span><code>HTTP-Redirect<\/code><code>rsa-sha256<\/code>/
             .test(saml2) &&
           saml2.indexOf(thumb) >= 0 && /ft-sp-signer/.test(saml2) &&
           !/<input|<textarea|<select|<button|<form/.test(saml2),
           'G1. SAML 2.0: the lists, the last AuthnRequest with its badge, ' +
           'and the observed certificate by subject and thumbprint, no ' +
           'control', saml2.slice(0, 900));
      note(/id="cfg-saml11-observed"/.test(saml11) &&
           />nameid-format:persistent</.test(saml11) &&
           /record these two lists in the same attributes/.test(saml11) &&
           !/Last AuthnRequest/.test(saml11),
           'G2. SAML 1.1: the shared lists and the note', saml11.slice(0, 600));
      const spSection = page.applicationFieldsSection(ctx, spJson, '');
      const s2 = spSection.indexOf('id="cfg-saml2-observed"');
      const s11 = spSection.indexOf('id="cfg-saml11-observed"');
      note(s2 > 0 && s11 > s2 &&
           spSection.indexOf('<form', s2) > s2,
           'G3. each panel draws its block above its form',
           JSON.stringify([s2, s11]));

      // --- H. The Overview and oauthScope ----------------------------------
      const detail = page.detail(ctx, Object.assign({}, json2,
                                                    { state: {} }));
      note(/<td>Authentications<\/td><td><code>\d+<\/code>/.test(detail) &&
           /<td>Sessions<\/td><td><code>\d+<\/code>/.test(detail) &&
           /<td>People<\/td><td><code>\d+<\/code>/.test(detail) &&
           /<td>Last person<\/td>/.test(detail) &&
           detail.indexOf('<td>Last seen') < detail.indexOf(
             '<td>Authentications'),
           'H1. the Overview carries the four counters after Last seen');
      const scopeAdd = applications.updateApplication('ft-web',
        { attribute: 'oauthScope', mode: 'add', value: 'email' });
      const scopeSet = applications.updateApplication('ft-web',
        { attribute: 'oauthScope', mode: 'set', value: 'email' });
      const scopeRemove = applications.updateApplication('ft-web',
        { attribute: 'oauthScope', mode: 'remove', value: 'ft-scope-1' });
      // A set of any list is refused before this (STS-REG-0008), so the
      // add is the door #708 closes.
      note(!scopeAdd.ok && errorCodes.codeOf(scopeAdd) === 'STS-REG-0361' &&
           !scopeSet.ok && scopeRemove.ok,
           'H2. oauthScope is refused at an add, STS-REG-0361, and at a ' +
           'set; a remove still works',
           JSON.stringify([scopeAdd, scopeSet, scopeRemove.errors]));
    });
    server.close();
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
  const out = path.join(os.tmpdir(), 'flow-type-choices-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
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
                         { LOG_LEVEL: 'fatal', FT_ROOT: ROOT, FT_OUT: out }),
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
  name: 'declared flow types as checkboxes',
  describe: 'oauthGrantType and oauthResponseType are closed sets matching ' +
            'the metadata, writes outside them are refused, and every ' +
            'observed attribute is drawn read-only beside what it shadows, ' +
            'a value outside its declared twin marked (#706, #708)',
  run: run
};
