'use strict';
//
// File: rfc9396_authorization_details.js
//
// ===========================================================================
// RFC 9396 — RICH AUTHORIZATION REQUESTS, EVERY FEATURE, POSITIVE AND NEGATIVE
// (2026-09-13).
//
// `oauth-oidc/authorization_details.ts` argues the design. What is held here:
//
//   1. THE REGISTRY: a resource's type definition
//      (`authorizationDetailsTypeOf`) in every shape it may and may not take,
//      and a client's registered `authorization_details_types` at
//      registration and on the console.
//   2. THE LIBRARY, with no directory: the parser's refusals in order, the
//      built-in hand-off, section 6's coverage rule and the narrowing it
//      allows, the consent digest, the one-time Allow, and the audience plan's
//      three new decisions in `jwt_access_token.audiencePlan()`.
//   3. THE ENDPOINTS, in a child process on an ephemeral loopback port:
//        a. the metadata, per realm, and a named authorization server's list;
//        b. an authorization request with details → the consent screen that
//           draws them → a code → a token whose claim, audience and response
//           carry them → introspection;
//        c. section 6 at the token endpoint: a subset of a code and of a
//           refresh token, a widening refused, the refresh token keeping the
//           whole grant;
//        d. consent asked EVERY time, Deny, prompt=none;
//        e. every refusal: unknown type, schema, locations, two resources, a
//           resource or scope naming another API, a client's registered types,
//           a named server's list, malformed JSON;
//        f. the direct grants (client_credentials), a request object (RFC
//           9101) carrying details, a pushed request (RFC 9126) with an
//           unknown type refused at the push;
//        g. openid_credential unchanged: no forced consent, identifiers added;
//        h. registration, RFC 7592 read-back, the console's writes, and the
//           RFC 9728 import's plan.
//
// **THE CHILD** is `tests/rfc9068_access_tokens.js`'s reason: the protocol
// stack registers every route on the shared app and builds a CA.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'rfc9396_authorization_details',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const applications = require('../common/applications');
const details = require('../oauth-oidc/authorization_details');
const jwtAccessToken = require('../oauth-oidc/jwt_access_token');
const errorCodes = require('../common/error_codes');

// ---------------------------------------------------------------------------
// 1. THE REGISTRY.
// ---------------------------------------------------------------------------
function registry(t) {
  log.debug("Entering registry().");
  t.log.info('=== 1. type definitions and registered types ===');
  const of = applications.authorizationDetailsTypeOf;
  const bare = of('account_information');
  t.check(!bare.problem && bare.type === 'account_information' &&
          !bare.validate && bare.locations.length === 0,
          '1a. a bare type name is a definition', JSON.stringify(bare));
  const full = of(JSON.stringify({
    type: 'payment_initiation', description: 'Pay somebody',
    locations: ['https://pay.example/'],
    schema: { type: 'object', required: ['instructedAmount'] } }));
  t.check(!full.problem && full.description === 'Pay somebody' &&
          full.locations[0] === 'https://pay.example/' &&
          typeof full.validate === 'function' &&
          full.validate({ type: 'payment_initiation', instructedAmount: 1 }) &&
          !full.validate({ type: 'payment_initiation' }),
          '1b. a JSON definition carries a description, locations and a ' +
          'schema that compiles and validates', full.problem);
  t.check(/stray|carries colour/.test(of('{"type":"x","colour":"red"}')
            .problem) && /colour/.test(of('{"type":"x","colour":"red"}')
            .problem),
          '1c. a member a definition does not hold is refused, not ignored');
  t.check(/not readable JSON/.test(of('{"type":').problem),
          '1d. a definition that starts with { and is not JSON is refused');
  t.check(/built in|no application may declare/.test(
            of('openid_credential').problem),
          '1e. openid_credential is built in and may not be declared');
  t.check(/does not compile/.test(of(JSON.stringify(
            { type: 'x', schema: { type: 'not-a-type' } })).problem),
          '1f. a schema that does not compile is refused');
  t.check(/fragment/.test(of(JSON.stringify(
            { type: 'x', locations: ['https://a.example/#f'] })).problem) &&
          /absolute URI/.test(of(JSON.stringify(
            { type: 'x', locations: ['relative/path'] })).problem),
          '1g. a location with a fragment or not absolute is refused');
  t.check(/not a type name/.test(of('two words').problem) &&
          /not a type name/.test(of('x'.repeat(513)).problem) &&
          /description must be a string/.test(of(JSON.stringify(
            { type: 'x', description: 3 })).problem),
          '1h. a name with a space, an overlong name and a non-string ' +
          'description are refused');

  const meta = applications.authorizationDetailsMetadataProblem;
  t.equal(meta({ authorization_details_types: ['a', 'b:c'] }), null,
          '1i. registration: an array of type names is accepted');
  const notArray = meta({ authorization_details_types: 'a' });
  t.check(notArray && notArray.error === 'invalid_client_metadata' &&
          notArray.errorCode === 'STS-REG-0110',
          '1j. registration: a string is refused STS-REG-0110');
  t.check(/not a non-empty string/.test((meta({
            authorization_details_types: [''] }) || {}).description),
          '1k. registration: an empty name is refused');
  const attr = applications.authorizationDetailsAttributeProblem;
  t.check((attr('oauthAuthorizationDetailsTypes', 'bad name') || {}).code ===
            'STS-REG-0111' &&
          (attr('oauthAuthorizationDetailsType', '{"type":1}') || {}).code ===
            'STS-REG-0112' &&
          attr('oauthAuthorizationDetailsType', '') === null &&
          attr('oauthAuthorizationDetailsTypes', 'ok') === null,
          '1l. the console writes: a bad name REG-0111, a bad definition ' +
          'REG-0112, a clear and a good value accepted');
  log.debug("Leaving registry().");
}

// ---------------------------------------------------------------------------
// 2. THE LIBRARY.
// ---------------------------------------------------------------------------
function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 2. parse, coverage, digest, consent, audience ===');
  const codeOf = function (r) {
    return errorCodes.codeOf(r) || '';
  };
  let r = details.parse(undefined);
  t.check(r.ok && r.details === null, '2a. nothing sent is no details');
  r = details.parse('[]');
  t.check(r.ok && r.details === null, '2b. an empty array authorizes nothing');
  r = details.parse('{not json');
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0450',
          '2c. unreadable JSON is 0450', r.error);
  r = details.parse('{"type":"x"}');
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0450' && /array/.test(r.error),
          '2d. an object where an array belongs is 0450');
  r = details.parse(JSON.stringify(new Array(21).fill({ type: 'x' })));
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0450' &&
          /authorizationDetailsMaxEntries/.test(r.error),
          '2e. more than oauth2.authorizationDetailsMaxEntries is 0450');
  r = details.parse('[3]');
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0451',
          '2f. an entry that is not an object is 0451');
  r = details.parse('[{"type": 1}]');
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0451' && /no `type`/.test(r.error),
          '2g. an entry with no string type is 0451');
  [['locations', ['https://a.example/#x']], ['actions', 'read'],
   ['datatypes', []], ['privileges', [1]], ['identifier', 7]]
    .forEach(function (pair, i) {
      const one = { type: 'x' };
      one[pair[0]] = pair[1];
      const answer = details.parse([one]);
      t.check(!answer.ok && codeOf(answer) === 'STS-OAUTH-0452' &&
              answer.error.indexOf(pair[0]) >= 0,
              '2h' + i + '. section 2.2: a malformed ' + pair[0] + ' is 0452',
              answer.error);
    });
  r = details.parse('[{"type":"nobody_declares_this"}]');
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0453' &&
          /openid_credential/.test(r.error),
          '2i. section 5: an unknown type is 0453, naming what is supported',
          r.error);
  r = details.parse('[{"type":"openid_credential"}]',
                    { clientTypes: ['account_information'] });
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0454',
          '2j. section 10: a type outside the client\'s registered list is ' +
          '0454');
  r = details.parse('[{"type":"openid_credential"}]',
                    { profileTypes: ['account_information'] });
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0455',
          '2k. a type outside the authorization server\'s list is 0455');
  let seen = null;
  r = details.parse('[{"type":"openid_credential","x":1}]', {
    builtIn: function (d) {
      seen = d;
      return { entry: { type: 'openid_credential', normalised: true } };
    } });
  t.check(r.ok && seen && seen.x === 1 && r.details[0].normalised === true &&
          r.resolved[0].definition === null,
          '2l. the built-in type is handed to builtIn, and its entry kept');
  r = details.parse('[{"type":"openid_credential"}]', {
    builtIn: function () {
      return errorCodes.mark({ error: 'no such configuration' },
                             'STS-OAUTH-0153');
    } });
  t.check(!r.ok && codeOf(r) === 'STS-OAUTH-0153' &&
          r.error === 'no such configuration',
          '2m. a built-in refusal keeps its sentence and code');

  const granted = [{ type: 'account_information',
                     actions: ['list_accounts', 'read_balances'],
                     locations: ['https://a.example/', 'https://b.example/'],
                     identifier: 'acct-1', extra: { deep: [1, 2] } }];
  t.equal(details.coveredProblem([{ type: 'account_information',
    actions: ['read_balances'], locations: ['https://b.example/'] }], granted),
          '', '2n. section 6: a subset of actions and locations is covered');
  t.equal(details.coveredProblem([{ type: 'account_information',
    identifier: 'acct-1', extra: { deep: [1, 2] } }], granted), '',
          '2o. an identical non-array member is covered, and absent arrays ' +
          'mean "as granted"');
  t.check(/not covered/.test(details.coveredProblem([{
            type: 'account_information', actions: ['transfer'] }], granted)),
          '2p. an action the grant did not carry is not covered');
  t.check(/not covered/.test(details.coveredProblem([{
            type: 'account_information', identifier: 'acct-2' }], granted)) &&
          /not covered/.test(details.coveredProblem([{
            type: 'account_information', extra: { deep: [2, 1] } }],
                                                    granted)),
          '2q. a different identifier, or a member with different content, ' +
          'is not covered');
  t.check(/not covered/.test(details.coveredProblem([{ type: 'other' }],
                                                    granted)) &&
          /no authorization_details/.test(details.coveredProblem(
            [{ type: 'x' }], null)),
          '2r. another type, or a grant with no details, covers nothing');
  t.check(/not covered/.test(details.coveredProblem([{
            type: 'account_information', datatypes: ['balances'] }], granted)),
          '2s. a common array the grant lacks entirely is a widening');
  const enriched = [{ type: 'openid_credential',
                      credential_configuration_id: 'c1',
                      credential_identifiers: ['c1:abc'] }];
  const narrowed = details.narrow([{ type: 'openid_credential',
                                     credential_configuration_id: 'c1' }],
                                  enriched);
  t.check(details.coveredProblem([{ type: 'openid_credential',
            credential_configuration_id: 'c1' }], enriched) === '' &&
          narrowed[0].credential_identifiers[0] === 'c1:abc',
          '2t. section 7: an enriched grant covers the plain request, and ' +
          'narrow() keeps what the server added to a built-in detail');
  t.check(details.narrow([granted[0]], granted)[0] === granted[0] &&
          details.narrow([{ type: 'account_information',
                            actions: ['read_balances'] }], granted)[0]
            .actions.length === 1,
          '2u. narrow() hands a declared type\'s request on as asked');

  const digestA = details.digestOf([{ type: 'p',
    amount: { value: '1', currency: 'EUR' } }]);
  const digestB = details.digestOf([{ amount: { currency: 'EUR', value: '1' },
                                      type: 'p' }]);
  const digestC = details.digestOf([{ type: 'p',
    amount: { value: '2', currency: 'EUR' } }]);
  t.check(digestA === digestB && digestA !== digestC,
          '2v. the consent digest ignores member order and not content');
  t.check(details.needsConsent([{ type: 'payment_initiation' }]) &&
          !details.needsConsent([{ type: 'openid_credential' }]) &&
          !details.needsConsent(null),
          '2w. a declared type needs consent; openid_credential does not');
  t.check(!details.consumeConsented('r96-alice', 'c', digestA),
          '2x. nothing is consented before Allow');
  details.noteConsented('r96-alice', 'c', digestA);
  t.check(!details.consumeConsented('r96-bob', 'c', digestA) &&
          !details.consumeConsented('r96-alice', 'c', digestC) &&
          details.consumeConsented('r96-alice', 'c', digestA) &&
          !details.consumeConsented('r96-alice', 'c', digestA),
          '2y. an Allow is for one person, one array, and is spent once');

  const own = 'https://sts.example/resource';
  const plan = function (extra) {
    return jwtAccessToken.audiencePlan(Object.assign({
      ownResource: own, explicit: [], scopes: [] }, extra));
  };
  const bank = { resources: ['bank'], audiences: ['https://pay.bank/'],
                 identifiers: ['https://bank/', 'https://pay.bank/'] };
  let p = plan({ details: { resources: ['bank', 'shop'],
                            audiences: ['https://bank/', 'https://shop/'],
                            identifiers: [] } });
  t.check(p.refusal && p.refusal.error === 'invalid_authorization_details' &&
          errorCodes.codeOf(p.refusal) === 'STS-OAUTH-0459',
          '2z. details of two resource servers are refused 0459');
  p = plan({ details: bank, scopes: [{ value: 'https://shop/read',
                                        kind: 'permission', name: 'read',
                                        audience: 'https://shop/' }] });
  t.check(p.refusal && p.refusal.error === 'invalid_scope' &&
          errorCodes.codeOf(p.refusal) === 'STS-OAUTH-0460',
          '2aa. a scope naming another API beside the details is 0460');
  p = plan({ details: bank, explicit: ['https://shop/'] });
  t.check(p.refusal && p.refusal.error === 'invalid_target' &&
          errorCodes.codeOf(p.refusal) === 'STS-OAUTH-0460',
          '2ab. a resource naming another API beside the details is 0460');
  p = plan({ details: bank, scopes: [{ value: 'payments', kind: 'ordinary' },
                                      { value: 'openid', kind: 'oidc' }] });
  t.check(!p.refusal && JSON.stringify(p.audiences) ===
            '["https://pay.bank/"]' && p.scope === 'payments' &&
          p.stripped[0] === 'openid',
          '2ac. the details decide the audience, an ordinary scope stays, ' +
          'an OIDC scope comes off', JSON.stringify(p));
  p = plan({ details: { resources: ['bank'],
                        audiences: ['https://pay.bank/', 'https://bank/'],
                        identifiers: bank.identifiers },
             scopes: [{ value: 'payments', kind: 'ordinary' }],
             explicit: [] });
  t.check(!p.refusal && p.audiences.length === 2 && p.scope === 'payments',
          '2ad. several locations of ONE resource are not "several ' +
          'resources": an ordinary scope is not ambiguous');
  p = plan({ details: bank, explicit: ['https://bank/'] });
  t.check(!p.refusal && p.audiences[0] === 'https://bank/',
          '2ae. a resource the details\' resource answers to is accepted and ' +
          'wins');
  p = plan({ scopes: [{ value: 'payments', kind: 'ordinary' }] });
  t.check(!p.refusal && p.audiences[0] === own,
          '2af. no details: the plan is what it was');
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.R96_ROOT;
  const OUT = process.env.R96_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const b64 = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };
  const payloadOf = function (jwt) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    } catch (e) {
      return { parseError: e.message };
    }
  };

  let jar = {};
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.form ? new URLSearchParams(o.form).toString()
        : (o.json !== undefined ? JSON.stringify(o.json) : '');
      const headers = Object.assign({}, o.headers || {});
      if (o.cookies && Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = o.json !== undefined ? 'application/json'
          : 'application/x-www-form-urlencoded';
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
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const servers = require(ROOT + '/oauth-oidc/authorization_servers');
    const prm = require(ROOT + '/oauth-oidc/protected_resource_metadata');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const SECRET = 'r96-client-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.r96.example/cb';
    const BASIC = 'Basic ' + Buffer.from('r96:' + SECRET).toString('base64');

    const withoutNulls = function (all) {
      Object.keys(all).forEach(function (k) {
        if (all[k] === null) {
          delete all[k];
        }
      });
      return all;
    };
    const create = function (id, fields) {
      return applications.createApplication({ identifier: id,
        protocols: ['oauth2'], fields: withoutNulls(fields) });
    };
    const PAYMENT = {
      type: 'payment_initiation',
      description: 'Initiate a payment from your account',
      locations: ['https://pay.bank.r96.example/'],
      schema: { type: 'object', required: ['instructedAmount'],
                properties: { instructedAmount: { type: 'object',
                  required: ['currency', 'amount'],
                  properties: { currency: { type: 'string' },
                                amount: { type: 'string' } } } } }
    };
    let made = create('r96-bank', {
      oauthClientId: 'r96-bank',
      oauthPermissionBaseUri: 'https://bank.r96.example/',
      oauthPermission: ['read'],
      oauthAudience: ['https://api.bank.r96.example'],
      oauthAuthorizationDetailsType: [JSON.stringify(PAYMENT),
                                      'account_information'] });
    note(made.ok, '3a0. a resource declaring two types is created',
         JSON.stringify(made.errors));
    create('r96-shop', { oauthClientId: 'r96-shop',
      oauthPermissionBaseUri: 'https://shop.r96.example/',
      oauthPermission: ['orders'],
      oauthAuthorizationDetailsType: ['order_access'] });
    create('r96-zdup', { oauthClientId: 'r96-zdup',
      oauthAuthorizationDetailsType: ['account_information'] });
    create('r96', { oauthClientId: 'r96', oauthClientSecret: SECRET,
      oauthRedirectUri: [REDIRECT],
      oauthTokenEndpointAuthMethod: 'client_secret_basic' });
    create('r96-limited', { oauthClientId: 'r96-limited',
      oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
      oauthTokenEndpointAuthMethod: 'client_secret_basic',
      oauthAuthorizationDetailsTypes: ['account_information'] });

    const payment = function (amount, extra) {
      return Object.assign({ type: 'payment_initiation',
        locations: ['https://pay.bank.r96.example/'],
        actions: ['initiate', 'status'],
        instructedAmount: { currency: 'EUR', amount: amount } }, extra || {});
    };
    const authorize = function (query, prefix, keepCookies) {
      if (!keepCookies) {
        jar = {};
      }
      return request(port, 'GET', (prefix || '') + '/oauth2/authorize?' +
        new URLSearchParams(Object.assign({ response_type: 'code',
          client_id: 'r96', redirect_uri: REDIRECT, scope: 'openid',
          state: 'st-' + crypto.randomBytes(4).toString('hex') }, query))
          .toString(), { cookies: true });
    };
    const local = function (location) {
      return String(location || '').replace(/^https?:\/\/[^/]+/, '');
    };
    const hidden = function (text) {
      const form = {};
      (text.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
        const name = /name="([^"]+)"/.exec(tag);
        const value = /value="([^"]*)"/.exec(tag);
        if (name) {
          form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
        }
      });
      return form;
    };
    // Follow sign-in and consent until the client's redirect_uri (or an
    // error page), answering consent with `answer`. Every page on the way is
    // kept for the assertions.
    const drive = async function (first, answer) {
      let r = first;
      const pages = { consent: null, consentCount: 0 };
      for (let hop = 0; hop < 12; hop++) {
        const where = String(r.headers.location || '');
        if (r.status !== 302 && r.status !== 303) {
          break;
        }
        if (where.indexOf(REDIRECT) === 0) {
          break;
        }
        if (/\/authn\/login/.test(where)) {
          const page = await request(port, 'GET', local(where),
                                     { cookies: true });
          const form = hidden(page.text);
          form.username = 'r96-alice';
          form.password = 'anything';
          form.action = 'login';
          r = await request(port, 'POST', '/authn/login',
                            { form: form, cookies: true });
          continue;
        }
        if (/\/oauth2\/consent/.test(where)) {
          const page = await request(port, 'GET', local(where),
                                     { cookies: true });
          pages.consent = page;
          pages.consentCount += 1;
          const form = hidden(page.text);
          form.action = answer || 'allow';
          r = await request(port, 'POST', '/oauth2/consent',
                            { form: form, cookies: true });
          continue;
        }
        r = await request(port, 'GET', local(where), { cookies: true });
      }
      const location = String(r.headers.location || '');
      const query = location.indexOf('?') >= 0
        ? new URLSearchParams(location.split('?')[1]) : new URLSearchParams();
      return { final: r, location: location, query: query, pages: pages };
    };
    const token = function (form, auth) {
      return request(port, 'POST', '/oauth2/token', { form: form,
        headers: { authorization: auth || BASIC } });
    };

    // --- a. metadata --------------------------------------------------------
    let meta = (await request(port, 'GET',
                              '/.well-known/openid-configuration')).json;
    const types = meta.authorization_details_types_supported || [];
    note(JSON.stringify(types.filter(function (one) {
      return /^(openid_credential|payment_initiation|account_information|order_access)$/
        .test(one);
    })) === '["account_information","openid_credential","order_access",' +
            '"payment_initiation"]' &&
         JSON.stringify(types) === JSON.stringify(types.slice(0).sort()),
         '3a. authorization_details_types_supported is openid_credential ' +
         'and every declared type, sorted', JSON.stringify(types));
    realms.create({ id: 'r96other' });
    const otherMeta = (await request(port, 'GET',
      '/realm/r96other/.well-known/openid-configuration')).json;
    note(otherMeta.authorization_details_types_supported &&
         otherMeta.authorization_details_types_supported
           .indexOf('payment_initiation') < 0 &&
         otherMeta.authorization_details_types_supported
           .indexOf('openid_credential') >= 0,
         '3a2. another realm does not support this realm\'s declared types',
         JSON.stringify(otherMeta.authorization_details_types_supported));

    // --- b. the whole flow ---------------------------------------------------
    const firstDetails = [payment('12.50')];
    let flow = await drive(await authorize({
      authorization_details: JSON.stringify(firstDetails) }));
    const code = flow.query.get('code');
    const consentText = flow.pages.consent ? flow.pages.consent.text : '';
    note(flow.pages.consentCount === 1 &&
         /payment_initiation/.test(consentText) &&
         /Initiate a payment from your account/.test(consentText) &&
         /12\.50/.test(consentText) &&
         /pay\.bank\.r96\.example/.test(consentText) &&
         /r96-bank/.test(consentText),
         '3b. section 11.2: the consent screen draws the detail — type, the ' +
         'resource\'s description, the amount, the resource and the audience',
         consentText.slice(0, 200));
    note(!!code, '3c. Allow leads to a code', flow.location);
    let r = await token({ grant_type: 'authorization_code', code: code,
                          redirect_uri: REDIRECT });
    const at = payloadOf(r.json.access_token);
    note(r.status === 200 && Array.isArray(r.json.authorization_details) &&
         r.json.authorization_details[0].instructedAmount.amount === '12.50',
         '3d. section 7: the token response carries authorization_details',
         r.text.slice(0, 300));
    note(Array.isArray(at.authorization_details) &&
         at.authorization_details[0].type === 'payment_initiation' &&
         at.aud === 'https://pay.bank.r96.example/',
         '3e. section 9.1: the access token carries the claim, and is ' +
         'addressed to the detail\'s location', JSON.stringify(at));
    const intro = await request(port, 'POST', '/oauth2/introspect',
      { form: { token: r.json.access_token },
        headers: { authorization: BASIC } });
    note(intro.json.active === true &&
         Array.isArray(intro.json.authorization_details) &&
         intro.json.authorization_details[0].actions.length === 2,
         '3f. section 9.2: introspection returns authorization_details',
         intro.text.slice(0, 300));
    const refresh = r.json.refresh_token;

    // --- c. section 6 at the token endpoint ----------------------------------
    r = await token({ grant_type: 'refresh_token', refresh_token: refresh,
      authorization_details: JSON.stringify([payment('12.50',
        { actions: ['status'] })]) });
    note(r.status === 200 &&
         JSON.stringify(payloadOf(r.json.access_token).authorization_details[0]
           .actions) === '["status"]',
         '3g. section 6: a refresh narrows the details to a subset',
         r.text.slice(0, 300));
    const rotated = r.json.refresh_token;
    r = await token({ grant_type: 'refresh_token', refresh_token: rotated,
      authorization_details: JSON.stringify(firstDetails) });
    note(r.status === 200 &&
         payloadOf(r.json.access_token).authorization_details[0].actions
           .length === 2,
         '3h. and the rotated refresh token kept the WHOLE grant, so the ' +
         'next refresh may ask for all of it again', r.text.slice(0, 300));
    const rotated2 = r.json.refresh_token;
    r = await token({ grant_type: 'refresh_token', refresh_token: rotated2,
      authorization_details: JSON.stringify([payment('12.50',
        { actions: ['initiate', 'refund'] })]) });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details' &&
         /not covered/.test(r.json.error_description),
         '3i. a refresh asking for an action the grant lacks is refused',
         r.text.slice(0, 200));
    r = await token({ grant_type: 'refresh_token', refresh_token: rotated2,
      authorization_details: JSON.stringify([payment('99.00')]) });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3j. a refresh asking for a different amount is refused',
         r.text.slice(0, 200));
    r = await token({ grant_type: 'refresh_token', refresh_token: rotated2 });
    note(r.status === 200 &&
         payloadOf(r.json.access_token).authorization_details[0]
           .instructedAmount.amount === '12.50',
         '3k. a refresh naming no details carries the grant\'s',
         r.text.slice(0, 200));

    flow = await drive(await authorize({
      authorization_details: JSON.stringify(firstDetails) }, '', true));
    note(flow.pages.consentCount === 1 && !!flow.query.get('code'),
         '3l. the same details again, same person, same client: consent is ' +
         'asked AGAIN', 'consent pages: ' + flow.pages.consentCount);
    r = await token({ grant_type: 'authorization_code',
      code: flow.query.get('code'), redirect_uri: REDIRECT,
      authorization_details: JSON.stringify([payment('12.50',
        { actions: ['initiate'] })]) });
    note(r.status === 200 &&
         JSON.stringify(payloadOf(r.json.access_token).authorization_details[0]
           .actions) === '["initiate"]',
         '3m. section 6: a code redeemed with a subset of its details',
         r.text.slice(0, 300));
    const refreshFromNarrowCode = r.json.refresh_token;
    r = await token({ grant_type: 'refresh_token',
      refresh_token: refreshFromNarrowCode,
      authorization_details: JSON.stringify(firstDetails) });
    note(r.status === 200,
         '3n. and its refresh token still carries the whole grant',
         r.text.slice(0, 200));
    flow = await drive(await authorize({
      authorization_details: JSON.stringify(firstDetails) }, '', true));
    r = await token({ grant_type: 'authorization_code',
      code: flow.query.get('code'), redirect_uri: REDIRECT,
      authorization_details: JSON.stringify([payment('13.00')]) });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3o. a code redeemed with details it did not authorize is refused',
         r.text.slice(0, 200));

    // --- d. consent ----------------------------------------------------------
    flow = await drive(await authorize({
      authorization_details: JSON.stringify(firstDetails) }, '', true), 'deny');
    note(flow.query.get('error') === 'access_denied',
         '3p. Deny on details answers access_denied', flow.location);
    r = await authorize({ authorization_details: JSON.stringify(firstDetails),
                          prompt: 'none' }, '', true);
    note(/error=consent_required/.test(String(r.headers.location || '')) &&
         /authorization_details/.test(decodeURIComponent(
           String(r.headers.location || ''))),
         '3q. prompt=none with details answers consent_required',
         r.headers.location);

    // --- e. refusals ---------------------------------------------------------
    const refusedWith = async function (query, error, pattern, prefix,
                                        clientId) {
      const q = Object.assign({}, query);
      if (clientId) {
        q.client_id = clientId;
      }
      const f = await drive(await authorize(q, prefix, true));
      return { ok: f.query.get('error') === error &&
                   (!pattern ||
                    pattern.test(f.query.get('error_description') || '')),
               detail: f.location + ' consent=' + f.pages.consentCount,
               consent: f.pages.consentCount };
    };
    let x = await refusedWith({ authorization_details:
      '[{"type":"not_declared_anywhere"}]' }, 'invalid_authorization_details',
      /no application in this realm declares/);
    note(x.ok && x.consent === 0,
         '3r. an unknown type is refused, and never asked about', x.detail);
    x = await refusedWith({ authorization_details: JSON.stringify([{
      type: 'payment_initiation', locations: PAYMENT.locations }]) },
      'invalid_authorization_details', /instructedAmount/);
    note(x.ok, '3s. section 5: a detail failing its type\'s schema is refused',
         x.detail);
    x = await refusedWith({ authorization_details: JSON.stringify([
      payment('1', { locations: ['https://evil.r96.example/'] })]) },
      'invalid_authorization_details', /evil\.r96\.example/);
    note(x.ok, '3t. a location the resource does not declare is refused',
         x.detail);
    // account_information is declared by two applications; the first answers.
    flow = await drive(await authorize({ authorization_details:
      JSON.stringify([{ type: 'account_information',
                        actions: ['list_accounts'] }]) }, '', true));
    r = await token({ grant_type: 'authorization_code',
                      code: flow.query.get('code'), redirect_uri: REDIRECT });
    note(r.status === 200 && payloadOf(r.json.access_token).aud ===
           'https://bank.r96.example/',
         '3u. a detail with no locations is addressed to its resource\'s ' +
         'permission base, and a type two applications declare belongs to ' +
         'the first', JSON.stringify(payloadOf(r.json.access_token).aud));
    x = await refusedWith({ authorization_details: JSON.stringify([
      payment('1'), { type: 'order_access' }]) },
      'invalid_authorization_details', /more than one resource server/);
    note(x.ok && x.consent === 0,
         '3v. RFC 9068: details of two resource servers are refused, and ' +
         'never asked about', x.detail);
    x = await refusedWith({ authorization_details: JSON.stringify([
      payment('1')]), resource: 'https://shop.r96.example/' },
      'invalid_target', /resource parameter/);
    note(x.ok, '3w. a resource naming another API beside the details is ' +
         'invalid_target', x.detail);
    x = await refusedWith({ authorization_details: JSON.stringify([
      payment('1')]), scope: 'openid https://shop.r96.example/orders' },
      'invalid_scope', /another resource server/);
    note(x.ok, '3x. a scope naming another API\'s permission beside the ' +
         'details is invalid_scope', x.detail);
    flow = await drive(await authorize({ authorization_details:
      JSON.stringify([payment('3')]),
      resource: 'https://api.bank.r96.example' }, '', true));
    r = await token({ grant_type: 'authorization_code',
                      code: flow.query.get('code'), redirect_uri: REDIRECT });
    note(r.status === 200 && payloadOf(r.json.access_token).aud ===
           'https://api.bank.r96.example',
         '3y. a resource the details\' resource answers to is accepted and ' +
         'becomes the audience', r.text.slice(0, 200));
    x = await refusedWith({ authorization_details: JSON.stringify([
      payment('1')]) }, 'invalid_authorization_details',
      /registered authorization_details_types/, '', 'r96-limited');
    note(x.ok, '3z. section 10: a type outside the client\'s registered ' +
         'types is refused', x.detail);
    x = await refusedWith({ authorization_details: '[{"type":' },
      'invalid_authorization_details', /not readable JSON/);
    note(x.ok, '3aa. unreadable JSON is refused', x.detail);
    await request(port, 'GET', '/.well-known/oauth-authorization-server/r96as');
    servers.setMember('r96as', 'authorization_details_types_supported',
                      '["account_information"]');
    x = await refusedWith({ authorization_details: JSON.stringify([
      payment('1')]) }, 'invalid_authorization_details',
      /publishes authorization_details_types_supported/, '/r96as');
    const narrowedDoc = (await request(port, 'GET',
      '/.well-known/oauth-authorization-server/r96as')).json;
    note(x.ok && JSON.stringify(
           narrowedDoc.authorization_details_types_supported) ===
           '["account_information"]',
         '3ab. a named authorization server publishing a narrower list ' +
         'refuses a type outside it, and its document says so', x.detail);
    servers.removeMember('r96as', 'authorization_details_types_supported');

    // --- f. direct grants, request objects, pushed requests ------------------
    r = await token({ grant_type: 'client_credentials', scope: 'payments',
      authorization_details: JSON.stringify([payment('5')]) });
    const cc = payloadOf(r.json.access_token);
    note(r.status === 200 && cc.authorization_details &&
         cc.authorization_details[0].instructedAmount.amount === '5' &&
         cc.aud === 'https://pay.bank.r96.example/' &&
         Array.isArray(r.json.authorization_details),
         '3ac. client_credentials with details: granted, carried and ' +
         'addressed to the location', r.text.slice(0, 300));
    r = await token({ grant_type: 'client_credentials',
      authorization_details: '[{"type":"not_declared_anywhere"}]' });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3ad. the token endpoint refuses an unknown type',
         r.text.slice(0, 200));
    r = await token({ grant_type: 'client_credentials',
      authorization_details: JSON.stringify([payment('5'),
                                             { type: 'order_access' }]) });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3ae. and details of two APIs', r.text.slice(0, 200));
    r = await token({ grant_type: 'client_credentials',
      authorization_details: JSON.stringify([payment('5')]),
      resource: 'https://shop.r96.example/' });
    note(r.status === 400 && r.json.error === 'invalid_target',
         '3af. and a resource naming another API', r.text.slice(0, 200));
    r = await token({ grant_type: 'client_credentials',
      authorization_details: JSON.stringify([payment('5')]) },
      'Basic ' + Buffer.from('r96-limited:' + SECRET).toString('base64'));
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3ag. and a type outside the client\'s registered types',
         r.text.slice(0, 200));

    const claims = { iss: 'r96', aud: BASE, client_id: 'r96',
      response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
      state: 'jar', exp: Math.floor(Date.now() / 1000) + 300,
      authorization_details: [payment('7.00')] };
    const unsigned = b64({ alg: 'none' }) + '.' + b64(claims) + '.';
    flow = await drive(await request(port, 'GET', '/oauth2/authorize?' +
      new URLSearchParams({ client_id: 'r96', request: unsigned }).toString(),
      { cookies: true }));
    r = await token({ grant_type: 'authorization_code',
                      code: flow.query.get('code'), redirect_uri: REDIRECT });
    note(flow.pages.consentCount === 1 && r.status === 200 &&
         payloadOf(r.json.access_token).authorization_details[0]
           .instructedAmount.amount === '7.00',
         '3ah. RFC 9101: details as a JSON array inside a request object are ' +
         'consented and granted', flow.location + ' ' + r.text.slice(0, 200));
    r = await request(port, 'POST', '/oauth2/par', { form: {
      client_id: 'r96', response_type: 'code', redirect_uri: REDIRECT,
      scope: 'openid', authorization_details: '[{"type":"nope_nope"}]' },
      headers: { authorization: BASIC } });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3ai. RFC 9126: a pushed request with an unknown type is refused at ' +
         'the push', r.status + ' ' + r.text.slice(0, 200));

    // --- g. openid_credential unchanged --------------------------------------
    flow = await drive(await authorize({ authorization_details:
      '[{"type":"openid_credential"}]' }, '', true));
    r = await token({ grant_type: 'authorization_code',
                      code: flow.query.get('code'), redirect_uri: REDIRECT });
    note(flow.pages.consentCount === 0 && r.status === 200 &&
         r.json.authorization_details &&
         Array.isArray(r.json.authorization_details[0].credential_identifiers),
         '3aj. openid_credential is not forced through consent and still ' +
         'gets its credential_identifiers', flow.location + ' ' +
         r.text.slice(0, 200));

    // --- h. registration, the console, the import ----------------------------
    r = await request(port, 'POST', '/oauth2/register', { json: {
      client_name: 'r96 registered', redirect_uris: [REDIRECT],
      authorization_details_types: ['account_information'] } });
    const reg = r.json || {};
    const read = reg.client_id ? await request(port, 'GET',
      '/oauth2/register/' + reg.client_id, { headers: { authorization:
        'Bearer ' + reg.registration_access_token } }) : { json: {} };
    note((r.status === 201 || r.status === 200) &&
         JSON.stringify(reg.authorization_details_types) ===
           '["account_information"]' &&
         JSON.stringify(read.json.authorization_details_types) ===
           '["account_information"]' &&
         JSON.stringify(applications.clientConfigOf(reg.client_id)
           .authorization_details_types) === '["account_information"]',
         '3ak. RFC 7591 and 7592: authorization_details_types registered, ' +
         'held and read back', r.text.slice(0, 200));
    r = await request(port, 'POST', '/oauth2/register', { json: {
      client_name: 'r96 bad', redirect_uris: [REDIRECT],
      authorization_details_types: 'account_information' } });
    note(r.status === 400 && r.json.error === 'invalid_client_metadata',
         '3al. a registration with a non-array authorization_details_types ' +
         'is refused', r.text.slice(0, 200));
    let u = applications.updateApplication('r96-bank', {
      attribute: 'oauthAuthorizationDetailsType', mode: 'add',
      value: '{"type":"x","schema":{"type":"nope"}}' });
    note(!u.ok && /does not compile/.test(JSON.stringify(u.errors)),
         '3am. the console refuses a definition whose schema does not ' +
         'compile', JSON.stringify(u.errors));
    u = applications.updateApplication('r96', {
      attribute: 'oauthAuthorizationDetailsTypes', mode: 'add',
      value: 'has space' });
    note(!u.ok, '3an. and a client type name with a space',
         JSON.stringify(u.errors));
    u = applications.updateApplication('r96-shop', {
      attribute: 'oauthAuthorizationDetailsType', mode: 'add',
      value: 'refund_request' });
    meta = (await request(port, 'GET', '/.well-known/openid-configuration'))
      .json;
    note(u.ok && meta.authorization_details_types_supported
           .indexOf('refund_request') >= 0,
         '3ao. a type added on the console is supported at once',
         JSON.stringify(u.errors));
    const plan = prm.planFor({ resource: 'https://new.r96.example/',
      authorization_details_types_supported: ['invoice_access',
        'openid_credential', 'order_access', 'two words'] });
    note(JSON.stringify(plan.detailsTypeLines) === '["invoice_access"]' &&
         plan.warnings.some(function (one) {
           return /order_access.*already declared/.test(one);
         }) &&
         plan.warnings.some(function (one) {
           return /openid_credential/.test(one);
         }),
         '3ap. the RFC 9728 import proposes the resource\'s types, leaving ' +
         'out the built-in type, a bad name and one already declared',
         JSON.stringify(plan.detailsTypeLines) + ' ' +
         JSON.stringify(plan.warnings));

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
  t.log.info('=== 3. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'rfc9396-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', R96_ROOT: ROOT, R96_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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

async function run(t) {
  log.debug("Entering run().");
  registry(t);
  library(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc9396 authorization details',
  describe: 'rich authorization requests: type definitions, parsing, ' +
            'consent, audience, section 6 narrowing, metadata and ' +
            'registration',
  run: run
};
