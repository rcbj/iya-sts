// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/gnap_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT THE GNAP ENDPOINTS ANSWER, HELD BYTE FOR BYTE (#1579 item 6).
//
// The documents a GNAP client instance and resource server send, the
// members of every answer, the discovery documents and the error codes come
// from `models/gnap/gnap.tsp` since #1579. Before the switch the JSON
// Schemas were written by hand in `gnap/gnap_schemas.ts`, and the switch was
// to change NOTHING a client or a resource server sees: the model describes
// and validates the wire, it does not reshape it. So this records what the
// hand-written version answered, in `tests/gnap_model_wire.snapshot.json`,
// and holds every later build to it: a scripted conversation with every
// endpoint — discovery, the grant endpoint's pending and issued answers and
// its refusals (the schema's, the walker's, the engine's), continuation,
// modification and revocation, token management, introspection, resource
// registration, the start modes and `/gnap-api` — in development and in
// product mode.
//
// What is recorded of each answer: the status, every header but the ones
// that are about the connection, the body (parsed when it is JSON), and the
// STS error code the response was marked with (read off the response
// object, never the wire). Values that differ from run to run — a key's
// material, a handle, a token, a nonce, an instant — are replaced by a
// placeholder; the comparison is of everything else, exactly.
//
// `GNAP_WIRE_PRINT=1 node tests/gnap_model_wire.js` prints the snapshot
// instead of comparing it; that is how the file was written, from the image
// of the tree before the switch, and how it is rewritten when the wire is
// MEANT to change.
//
// A CHILD PROCESS, as tests/oauth_model_wire.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'gnap_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'gnap_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.GW_ROOT;
  const OUT = process.env.GW_OUT;
  const http = require('http');
  const record = { wire: [], problems: [] };

  const SKIPPED_HEADERS = ['date', 'connection', 'keep-alive',
                           'content-length', 'etag', 'transfer-encoding'];

  function kept(headers) {
    const out = {};
    Object.keys(headers || {}).sort().forEach(function (name) {
      if (SKIPPED_HEADERS.indexOf(name) < 0) {
        out[name] = headers[name];
      }
    });
    return out;
  }

  function parsed(type, text) {
    if (/json/.test(String(type || '')) && text) {
      try {
        return JSON.parse(text);
      } catch (e) {
        return { unparsed: text };
      }
    }
    return text;
  }

  // An unsigned request: a browser, or a client that proves nothing.
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const headers = Object.assign({}, o.headers || {});
      let body = '';
      if (o.json !== undefined) {
        body = typeof o.json === 'string' ? o.json : JSON.stringify(o.json);
        headers['content-type'] = headers['content-type'] ||
          'application/json';
      }
      if (body) {
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed(res.headers['content-type'], text) });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, headers: {}, text: String(e && e.message),
                  json: null });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const errorCodes = require(ROOT + '/common/error_codes');
    const applications = require(ROOT + '/common/applications');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const gnap = require(ROOT + '/tests/protocol/gnap_client.js');

    const marks = [];
    const server = http.createServer(function (req, res) {
      res.on('finish', function () {
        marks.push(errorCodes.codeOf(res) || '');
      });
      app(req, res);
    });
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    config.setOverride('gnap.continueWaitS', 0);

    const MODES = [{ name: 'development', product: false },
                   { name: 'product', product: true }];

    for (let m = 0; m < MODES.length; m++) {
      const mode = MODES[m];
      if (mode.product) {
        config.setOverride('global.mode', 'product');
      } else {
        config.clearOverride('global.mode');
      }
      const tag = mode.name.slice(0, 3);
      const RS_URI = 'https://rs-' + tag + '.gw.test/api';
      const FINISH = 'https://client-' + tag + '.gw.test/finish';
      const TYPE = 'gw-' + tag + '-read';
      const keys = {};
      const made = [];
      const client = function (id, fields) {
        keys[id] = new gnap.Client({ key: gnap.newKey('ES256', 'kid-' + id) });
        made.push(applications.createApplication({ identifier: id,
          kind: 'gnap-client', protocols: ['gnap'],
          fields: Object.assign({
            gnapKey: JSON.stringify(keys[id].keyObject()) }, fields || {}) }));
      };
      const rsApp = function (id, fields) {
        keys[id] = new gnap.Client({ key: gnap.newKey('ES256', 'kid-' + id) });
        made.push(applications.createApplication({ identifier: id,
          kind: 'gnap-resource-server', protocols: ['gnap'],
          fields: Object.assign({
            gnapKey: JSON.stringify(keys[id].keyObject()),
            gnapResourceServerUri: RS_URI }, fields || {}) }));
      };
      ldap.createUser('gw-' + tag + '-user', { invent: false });
      rsApp('gw-' + tag + '-rs', {
        oauthAuthorizationDetailsType: [JSON.stringify({ type: TYPE,
          actions: ['read', 'write'] })] });
      client('gw-' + tag + '-web', { gnapFinishUri: [FINISH] });
      client('gw-' + tag + '-trusted', { gnapSkipInteraction: 'TRUE' });
      if (!made.every(function (one) {
        return one && one.ok;
      })) {
        record.problems.push(mode.name + ': fixtures ' + JSON.stringify(made));
      }
      const web = keys['gw-' + tag + '-web'];
      const trusted = keys['gw-' + tag + '-trusted'];
      const rs = keys['gw-' + tag + '-rs'];
      const right = function (extra) {
        return Object.assign({ type: TYPE, actions: ['read'],
                               locations: [RS_URI] }, extra || {});
      };

      const remember = function (name, method, p, r) {
        record.wire.push({ mode: mode.name, step: name, method: method,
                           path: p, status: r.status,
                           headers: kept(r.headers),
                           body: r.json !== null && r.json !== undefined
                             ? r.json : r.text,
                           code: marks[marks.length - 1] || '' });
        return r;
      };
      const plain = async function (name, method, p, opts) {
        const r = await request(port, method, p, opts);
        return remember(name, method, p, r);
      };
      const signed = async function (name, who, method, p, opts) {
        let r;
        try {
          r = await who.send(method, base + p, opts || {});
          r.json = parsed(r.headers['content-type'], r.text);
        } catch (e) {
          r = { status: 0, headers: {}, text: String(e && e.message),
                json: null };
        }
        return remember(name, method, p, r);
      };
      const pathOf = function (uri) {
        return uri ? new URL(uri).pathname : '/nowhere';
      };

      // DISCOVERY.
      await plain('discovery', 'OPTIONS', '/gnap');
      await plain('rs discovery', 'GET', '/.well-known/gnap-as-rs');
      await plain('keys', 'GET', '/gnap/keys');
      await plain('zcap controller', 'GET', '/gnap/zcap/controller');
      await plain('biscuit revocations', 'GET', '/gnap/biscuit/revocations');
      await plain('discovery, a named server', 'OPTIONS', '/gw-as/gnap');
      await plain('rs discovery, a named server', 'GET',
                  '/.well-known/gnap-as-rs/gw-as');
      await plain('discovery, a bad server name', 'OPTIONS',
                  '/' + encodeURIComponent('a b') + '/gnap');

      // THE GRANT ENDPOINT: REFUSALS.
      const webKey = { key: web.keyObject() };
      await plain('grant, not JSON', 'POST', '/gnap',
                  { json: 'not json',
                    headers: { 'content-type': 'text/plain' } });
      await plain('grant, unsigned', 'POST', '/gnap',
                  { json: { client: webKey,
                            access_token: { access: [right()] } } });
      await signed('grant, an array', web, 'POST', '/gnap', { json: [1] });
      await signed('grant, a control character', web, 'POST', '/gnap',
                   { json: { client: { key: web.keyObject(),
                                       display: { name: 'a\u0001b' } },
                             access_token: { access: [right()] },
                             interact: { start: ['redirect'] } } });
      await signed('grant, a wrong type', web, 'POST', '/gnap',
                   { json: { client: webKey, access_token: { access: 'x' },
                             interact: { start: ['redirect'] } } });
      await signed('grant, an overlong label', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()],
                                             label: 'x'.repeat(300) },
                             interact: { start: ['redirect'] } } });
      await signed('grant, a finish member nobody defines', web, 'POST',
                   '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()] },
                             interact: { start: ['redirect'],
                                         finish: { method: 'redirect',
                                                   uri: FINISH,
                                                   nonce: 'n-1',
                                                   extra: 1 } } } });
      await signed('grant, a finish uri that is not a URI', web, 'POST',
                   '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()] },
                             interact: { start: ['redirect'],
                                         finish: { method: 'redirect',
                                                   uri: 'not a uri',
                                                   nonce: 'n-1' } } } });
      await signed('grant, no client', web, 'POST', '/gnap',
                   { json: { access_token: { access: [right()] } } });
      await signed('grant, the durable flag', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()],
                                             flags: ['durable'] },
                             interact: { start: ['redirect'] } } });
      await signed('grant, an unknown start mode', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()] },
                             interact: { start: ['telepathy'] } } });
      await signed('grant, an unknown finish method', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()] },
                             interact: { start: ['redirect'],
                                         finish: { method: 'carrier-pigeon',
                                                   uri: FINISH,
                                                   nonce: 'n-1' } } } });
      await signed('grant, an interaction reference', web, 'POST', '/gnap',
                   { json: { client: webKey, interact_ref: 'abc',
                             access_token: { access: [right()] } } });
      await signed('grant, two tokens without labels', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             access_token: [{ access: [right()] },
                                            { access: [right()] }],
                             interact: { start: ['redirect'] } } });
      await signed('grant, a location nobody registered', web, 'POST',
                   '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right({
                               locations: ['https://nobody.gw.test/'] })] },
                             interact: { start: ['redirect'] } } });
      await signed('grant, no resource server at all', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             access_token: { access: ['gw-just-a-string'] },
                             interact: { start: ['redirect'] } } });
      await signed('grant, an unknown sub_id format', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             subject: { sub_id_formats: ['telepathy'] },
                             interact: { start: ['redirect'] } } });
      await signed('grant, an unknown key', new gnap.Client({
        key: gnap.newKey('ES256', 'kid-gw-stranger') }), 'POST', '/gnap',
                   { json: { client: { key: { proof: 'httpsig',
                                              jwk: gnap.newKey('ES256',
                                                'kid-gw-other').publicJwk } },
                             access_token: { access: [right()] },
                             interact: { start: ['redirect'] } } });
      const stranger = new gnap.Client({ key: gnap.newKey('ES256',
                                                          'kid-gw-new') });
      await signed('grant, a key nobody registered', stranger, 'POST',
                   '/gnap',
                   { json: { client: { key: stranger.keyObject() },
                             access_token: { access: [right()] },
                             interact: { start: ['redirect'] } } });
      await signed('grant, nothing to interact with', web, 'POST', '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()] } } });

      // THE GRANT ENDPOINT: PENDING AND ISSUED.
      let r = await signed('grant, pending with redirect and finish', web,
                           'POST', '/gnap',
                           { json: { client: webKey,
                                     access_token: { access: [right()] },
                                     subject: { sub_id_formats: ['opaque'] },
                                     interact: { start: ['redirect'],
                                                 finish: {
                                                   method: 'redirect',
                                                   uri: FINISH,
                                                   nonce: 'gw-nonce-1' } } } });
      const pending = (r.json && r.json.continue) ? r.json : null;
      r = await signed('grant, pending with a user code', web, 'POST',
                       '/gnap',
                       { json: { client: webKey,
                                 access_token: { access: [right()],
                                                 label: 'one' },
                                 interact: { start: ['user_code',
                                                     'user_code_uri',
                                                     'app'] } } });
      const coded = (r.json && r.json.continue) ? r.json : null;
      r = await signed('grant, issued to a trusted client', trusted, 'POST',
                       '/gnap',
                       { json: { client: { key: trusted.keyObject() },
                                 access_token: { access: [right()] } } });
      const issued = (r.json && r.json.access_token) ? r.json : null;
      await signed('grant, two labelled tokens', trusted, 'POST', '/gnap',
                   { json: { client: { key: trusted.keyObject() },
                             access_token: [{ access: [right()],
                                              label: 'a' },
                                            { access: [right({
                                              actions: ['write'] })],
                                              label: 'b' }] } });
      await signed('grant, the bearer flag', trusted, 'POST', '/gnap',
                   { json: { client: { key: trusted.keyObject() },
                             access_token: { access: [right()],
                                             flags: ['bearer'] } } });

      // CONTINUATION.
      const cont = pending && pending.continue;
      const contPath = cont ? pathOf(cont.uri) : '/gnap/continue/none';
      const contToken = cont && cont.access_token
        ? cont.access_token.value : 'none';
      await signed('continue, no token', web, 'POST', contPath, {});
      await signed('continue, a bad grant path', web, 'POST',
                   '/gnap/continue/' + encodeURIComponent('a b'),
                   { token: contToken });
      await signed('continue, an unknown token', web, 'POST', contPath,
                   { token: 'gw-unknown-token' });
      await signed('continue, a body member nobody defines', web, 'POST',
                   contPath, { token: contToken, json: { unexpected: 1 } });
      r = await signed('continue, an interaction reference out of turn',
                       web, 'POST', contPath,
                       { token: contToken,
                         json: { interact_ref: 'gw-ref' } });
      const turned = r.json && r.json.continue && r.json.continue.access_token
        ? r.json.continue.access_token.value : contToken;
      r = await signed('continue, a poll', web, 'POST', contPath,
                       { token: turned });
      let next = r.json && r.json.continue && r.json.continue.access_token
        ? r.json.continue.access_token.value : turned;
      r = await signed('continue, a modification', web, 'PATCH', contPath,
                       { token: next,
                         json: { access_token: { access: [right({
                           actions: ['read', 'write'] })] },
                                 interact: { start: ['redirect'] } } });
      next = r.json && r.json.continue && r.json.continue.access_token
        ? r.json.continue.access_token.value : next;
      await signed('continue, a modification with a wrong type', web,
                   'PATCH', contPath,
                   { token: next, json: { access_token: 5 } });
      await signed('continue, revoked', web, 'DELETE', contPath,
                   { token: next });
      await signed('continue, after the revocation', web, 'POST', contPath,
                   { token: next });

      // THE START MODES AND /gnap-api.
      const start = coded && coded.interact;
      await plain('start, the app link', 'GET',
                  start && start.app ? pathOf(start.app) : '/gnap/app/x');
      await plain('start, an unknown link', 'GET', '/gnap/interact/gw-none');
      await plain('start, the user code page', 'GET', '/gnap/code');
      await plain('gnap-api, the index', 'GET', '/gnap-api');
      await plain('gnap-api, the code view', 'GET', '/gnap-api/code');
      await plain('gnap-api, a code act unbound', 'POST', '/gnap-api/code',
                  { json: { code: 'nothing' } });
      await plain('gnap-api, an approval view of nothing', 'GET',
                  '/gnap-api/approve/gw-none');
      await plain('gnap-api, an approval act unbound', 'POST',
                  '/gnap-api/approve/gw-none', { json: { decision: 'deny' } });

      // TOKEN MANAGEMENT.
      const tokenObject = issued && issued.access_token;
      const tokenValue = tokenObject ? tokenObject.value : 'gw-no-token';
      const manage = tokenObject && tokenObject.manage;
      const managePath = manage ? pathOf(manage.uri) : '/gnap/token/none';
      const manageToken = manage && manage.access_token
        ? manage.access_token.value : 'none';
      await signed('manage, a bad handle', trusted, 'POST',
                   '/gnap/token/' + encodeURIComponent('a b'),
                   { token: manageToken });
      await signed('manage, an unknown token', trusted, 'POST', managePath,
                   { token: 'gw-unknown' });

      // INTROSPECTION AND REGISTRATION (RFC 9767).
      const rsKey = { key: rs.keyObject() };
      await plain('introspect, unsigned', 'POST', '/gnap/introspect',
                  { json: { access_token: tokenValue,
                            resource_server: rsKey } });
      await signed('introspect, a live token', rs, 'POST',
                   '/gnap/introspect',
                   { json: { access_token: tokenValue,
                             resource_server: rsKey } });
      await signed('introspect, an unknown token', rs, 'POST',
                   '/gnap/introspect',
                   { json: { access_token: 'gw-not-a-token',
                             resource_server: rsKey } });
      await signed('introspect, a malformed token', rs, 'POST',
                   '/gnap/introspect',
                   { json: { access_token: 'not a token',
                             resource_server: rsKey } });
      await signed('introspect, no resource server', rs, 'POST',
                   '/gnap/introspect',
                   { json: { access_token: tokenValue } });
      await signed('register, a resource set', rs, 'POST', '/gnap/resource',
                   { json: { access: [right()], resource_server: rsKey,
                             token_formats_supported: ['jwt-signed'],
                             token_introspection_required: true } });
      await signed('register, owners of no identifier', rs, 'POST',
                   '/gnap/resource',
                   { json: { access: [right({ identifier: 'gw-thing' })],
                             resource_server: rsKey,
                             resource_owners: { 'gw-other': 'cn=x' } } });
      await signed('register, a wrong type', rs, 'POST', '/gnap/resource',
                   { json: { access: [right()], resource_server: rsKey,
                             token_introspection_required: 'yes' } });

      // ROTATION AND REVOCATION OF THE ISSUED TOKEN, last: the token is
      // gone after them.
      const fresh = new gnap.Client({ key: gnap.newKey('ES256',
                                                       'kid-gw-fresh') });
      r = await signed('manage, a rotation', trusted, 'POST', managePath,
                       { token: manageToken });
      const rotated = r.json && r.json.access_token
        ? r.json.access_token : null;
      const rotatedPath = rotated && rotated.manage
        ? pathOf(rotated.manage.uri) : managePath;
      const rotatedToken = rotated && rotated.manage &&
        rotated.manage.access_token ? rotated.manage.access_token.value
        : manageToken;
      await signed('manage, a key rotation body nobody defines', trusted,
                   'POST', rotatedPath,
                   { token: rotatedToken, json: { key: fresh.keyObject(),
                                                  extra: 1, more: 2,
                                                  again: 3, last: 4 } });
      await signed('manage, revoked', trusted, 'DELETE', rotatedPath,
                   { token: rotatedToken });
      await signed('manage, after the revocation', trusted, 'POST',
                   rotatedPath, { token: rotatedToken });
    }
    config.clearOverride('global.mode');
    config.clearOverride('gnap.continueWaitS');
    // Every answer above was held to the model as it was sent (#1579); a
    // gap is recorded there, and none may have been.
    try {
      record.gaps = require(ROOT + '/gnap/gnap_model').gaps();
    } catch (e) {
      record.gaps = ['the model could not be asked: ' + (e && e.message)];
    }
    server.close();
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push('the child failed: ' + (e && e.stack || e));
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// Member names whose value differs from run to run.
const VOLATILE_MEMBERS = ['value', 'nonce', 'jti', 'instance_id', 'x', 'y',
  'n', 'e', 'kid', 'x5c', 'publicKeyMultibase', 'publicKeyJwk', 'id', 'iat',
  'exp', 'nbf', 'created', 'user_code', 'code', 'interact_ref', 'csrf',
  'root_public_key', 'root_public_keys', 'revocation_ids', 'hash',
  'controller', 'verificationMethod', 'capabilityDelegation',
  'capabilityInvocation', 'assertionMethod', 'authentication', 'sub',
  'cnf', 'jkt', 'expires_in', 'wait', 'status_list', 'resource_reference'];

// Members whose string value is a random token the record keeps as
// `<random>` (#1579). The text pattern below found them only while the
// value happened to hold a capital and a digit, and a grant_id or a finish
// nonce that drew neither failed the record under load; by name, it cannot.
const RANDOM_MEMBERS = ['grant_id', 'finish'];

// Walks a value: a volatile member's value is replaced by its name, and a
// URL's handle segment by a placeholder.
function scrub(value, name) {
  log.debug("Entering scrub().");
  if (name && VOLATILE_MEMBERS.indexOf(name) >= 0 && value !== undefined &&
      value !== null && value !== '' && name !== 'code') {
    log.debug("Leaving scrub(). A volatile member.");
    return '<' + name + '>';
  }
  if (name && RANDOM_MEMBERS.indexOf(name) >= 0 &&
      typeof value === 'string' && value !== '') {
    log.debug("Leaving scrub(). A random member.");
    return '<random>';
  }
  if (Array.isArray(value)) {
    const list = value.map(function (one) {
      return scrub(one, name);
    });
    log.debug("Leaving scrub().");
    return list;
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = scrub(value[key], key);
    });
    log.debug("Leaving scrub().");
    return out;
  }
  if (name === 'set-cookie' && typeof value === 'string') {
    log.debug("Leaving scrub(). A cookie.");
    return value.replace(/=[^;]*/, '=<cookie>');
  }
  if (typeof value === 'number' && value >= 1.7e9 && value < 2.2e9) {
    log.debug("Leaving scrub(). An instant.");
    return '<epoch>';
  }
  log.debug("Leaving scrub().");
  return value;
}

// The run-to-run values left in text, each replaced by a placeholder.
function normalise(record) {
  log.debug("Entering normalise().");
  // An error code's own member is held: the scrub above spares `code`
  // only where it names a GNAP error (a short word); a user code is
  // replaced below by its shape.
  const PATTERNS = [
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['httpdate', /[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    ['uptime', /up \d+ second\(s\)/g],
    // The build's version, whose fourth part is the build instant.
    ['version', /\b\d+\.\d+\.\d+\.\d{14}\b/g],
    ['build', /\b20\d{12}\b/g],
    // A handle in a GNAP path: the grant's, the token's, a start link's.
    ['handle', /(\/gnap\/(?:continue|token|interact|app|approve)\/)[A-Za-z0-9_.~-]+/g],
    ['usercode', /"code": "[A-Z0-9]{4}-?[A-Z0-9]{4}"/g],
    ['thumbprint', /urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]+/g],
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}/g],
    // A long random value that happened to draw no digit, or no capital
    // (#1579: an interact `finish` nonce escaped the rule above once). At
    // 32 characters and over, only a random value holds a capital or a
    // digit; the snake_case member names that long hold neither.
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z0-9])[A-Za-z0-9_-]{32,}/g]
  ];
  const text = JSON.stringify(scrub(record), null, 1);
  let out = text;
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], function (value, prefix) {
      if (pair[0] === 'handle') {
        return prefix + '<handle>';
      }
      if (pair[0] === 'usercode') {
        return '"code": "<usercode>"';
      }
      return '<' + pair[0] + '>';
    });
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'gnap-model-wire-' + process.pid +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|GNAP_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', GW_ROOT: ROOT, GW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return normalise(record);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + '.' + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ': ' + JSON.stringify(b).slice(0, 300) + ' where ' +
    JSON.stringify(a).slice(0, 300) + ' was recorded';
}

function run(t) {
  log.debug("Entering run().");
  const now = capture();
  if (!t.check(!!now, 'the child process reported')) {
    log.debug("Leaving run().");
    return;
  }
  t.check(now.problems.length === 0, 'the child ran to the end',
          now.problems.join('\n'));
  t.check(Array.isArray(now.gaps) && now.gaps.length === 0,
          'every answer of the conversation is its model\'s ' +
          '(models/gnap/gnap.tsp; none recorded under STS-GNAP-0910/0911)',
          JSON.stringify(now.gaps).slice(0, 2000));
  let recorded = null;
  try {
    recorded = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    recorded = null;
  }
  if (!t.check(!!recorded, 'the recorded wire is in the tree', SNAPSHOT)) {
    log.debug("Leaving run().");
    return;
  }
  t.check(recorded.wire.length === now.wire.length,
          'the conversation has as many steps as recorded',
          now.wire.length + ' vs ' + recorded.wire.length);
  recorded.wire.forEach(function (one, i) {
    t.check(firstDifference(one, now.wire[i], 'wire') === null,
            one.mode + ', ' + one.step + ': ' + one.method +
            ' answers as recorded (' + one.status + ')',
            firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.GNAP_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'gnap_model_wire',
  describe: 'what the GNAP endpoints answer, byte for byte, against the ' +
            'record made before their documents, answers, discovery ' +
            'members and error codes came from the model (#1579): ' +
            'discovery, the grant endpoint\'s answers and refusals, ' +
            'continuation, token management, introspection, registration ' +
            'and /gnap-api, in development and product mode',
  run: run
};
