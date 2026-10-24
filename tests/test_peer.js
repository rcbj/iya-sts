// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: test_peer.js
//
// ===========================================================================
// THE TEST PEER, AGAINST A FAKE AUTHORIZATION SERVER (#586).
//
// `tests/peer/` is the far party the protocol jobs talk to in every mode
// (tests/CLAUDE.md, *THE TEST PEER*). Its roles are only worth something if
// each REFUSES what a real party would, so this file starts the peer in
// process on a free port and stands up, beside it, the smallest thing that
// plays the realm: RFC 8414 metadata and a key set, an SSF configuration, a
// GNAP introspection endpoint answering from a table this file fills, and
// SAML 2.0 metadata. Then, per role:
//
//   A. THE RFC 9470 RESOURCE SERVER: the challenge in exactly the shape
//      `sts_step_up.js` asserts (`Bearer error="insufficient_user_
//      authentication"`, then error_description, `acr_values` and `max_age`
//      last), a met requirement answered 200 with what it decided on, and
//      the refusals before any step-up question — no token, another audience,
//      another typ, another issuer, a resource nobody configured.
//   B. THE GNAP RESOURCE SERVER, with proofs made by `tests/protocol/
//      gnap_client.js` — the jobs' own independent client — so the two
//      implementations of RFC 9421 and the GNAP JWS proofs are held to each
//      other: httpsig, jwsd and jws accepted; another key, no proof, the
//      wrong scheme and an inactive token refused; write refused on a read
//      right; mutual TLS on the peer's TLS listener; the RS-first challenge;
//      and the spend arithmetic `sts_gnap_limits.js` asserts (20, refused,
//      refunded, 10 to exactly 30, a cent more, another currency).
//   C. THE SSF RECEIVER over TLS, trusting the peer's CA: a signed SET
//      accepted 202, and the refusals RFC 8935 names.
//   D. THE SAML 2.0 SERVICE PROVIDER: its signed redirect AuthnRequest, a
//      signed Response consumed, and the same Response with its NameID
//      changed refused.
//   E. THE READBACK: per role, and after a sequence number.
//   F. THE SAML 1.1 RELYING PARTY AND THE WS-FEDERATION ONE: a Browser/POST
//      Response verified through ResponseID and AssertionID, the same with
//      InResponseTo (which that profile forbids) refused; an artifact the
//      peer resolves at the responder with a request its key signs; a
//      WS-Federation token for the right realm accepted and one for another
//      realm refused.
//   G. THE OPENID PROVIDER COMMANDS RELYING PARTY (#596) over TLS: a
//      Command Token signed by the realm's key answered per section 6's
//      table (metadata, activate, incompatible_state), an `_async` result
//      POSTed to the callback the metadata named with the callback_token as
//      Bearer, a tenant stream dropped by `?drop=1` and resumed with
//      Last-Event-ID, a 503 for `?fail=1` once, and the refusals section 9
//      names — another issuer, another typ, a nonce, a replayed jti, a
//      signature that does not verify, a symmetric alg.
//   H. THE BACK-CHANNEL LOGOUT RELYING PARTY (#293) over TLS: a Logout
//      Token signed by the realm's key accepted 200 no-store, and the
//      refusals OpenID Connect Back-Channel Logout 1.0 section 2.6 asks of a
//      relying party — a replayed jti, another typ, a nonce, another aud or
//      issuer, no event, neither sub nor sid, a bad signature, an encrypted
//      token it holds no key for, a body that is not a form.
//
// IN PROCESS rather than a protocol job, because none of it is the service:
// it is a test fixture's own correctness, and a stack is not needed to show
// it.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const nodeCrypto = require('crypto');
const { SignedXml } = require('xml-crypto');
const peer = require('./peer/peer.js');
const pki = require('./peer/peer_pki.js');
const gnapPeer = require('./peer/peer_gnap.js');
const gnap = require('./protocol/gnap_client.js');

const log = require('bunyan').createLogger({ name: 'test_peer',
  level: process.env.LOG_LEVEL || 'info' });

const TYPE = 'urn:test:peer:type';

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(value).toString('base64url');
}

// A compact JWS by `key` (an RSA KeyObject) with `header` and `claims`.
function jws(key, header, claims) {
  log.debug("Entering jws().");
  const input = b64u(JSON.stringify(header)) + '.' +
                b64u(JSON.stringify(claims));
  const signature = nodeCrypto.sign('sha256', Buffer.from(input), key);
  log.debug("Leaving jws().");
  return input + '.' + b64u(signature);
}

// ---------------------------------------------------------------------------
// THE FAKE REALM. `introspection` maps a token value to its answer; every
// introspection request must carry an HTTP message signature, or the fake
// answers 400 as the service does (`invalid_resource_server`).
// ---------------------------------------------------------------------------
function fakeRealm(state) {
  log.debug("Entering fakeRealm().");
  log.debug("Leaving fakeRealm().");
  return http.createServer(function (req, res) {
    const chunks = [];
    req.on('data', function (c) {
      chunks.push(c);
    });
    req.on('end', function () {
      const body = Buffer.concat(chunks).toString('utf8');
      const json = function (status, value) {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(value));
      };
      if (req.url === '/.well-known/oauth-authorization-server' ||
          req.url === '/.well-known/openid-configuration') {
        json(200, { issuer: state.base, jwks_uri: state.base + '/jwks' });
      } else if (req.url === '/.well-known/ssf-configuration') {
        json(200, { issuer: state.base, jwks_uri: state.base + '/jwks' });
      } else if (req.url === '/jwks') {
        json(200, { keys: [state.jwk] });
      } else if (req.url === '/gnap/introspect') {
        state.introspections += 1;
        if (!req.headers['signature-input'] || !req.headers.signature) {
          json(400, { error: 'invalid_resource_server' });
          return;
        }
        const asked = JSON.parse(body);
        json(200, state.introspection[asked.access_token] ||
                  { active: false });
      } else if (req.url === '/oauth2/commands/callback') {
        state.callbacks.push({ authorization: req.headers.authorization,
                              body: body });
        res.writeHead(204);
        res.end();
      } else if (req.url === '/gnap/resource') {
        json(200, { resource_reference: 'ref-peer-1' });
      } else if (req.url === '/saml11/responder') {
        // The responder: what was asked, and the artifact profile's answer
        // to it — or a refusal when the request is not signed.
        state.saml11Requests.push(body);
        const requestId = (/RequestID="([^"]+)"/.exec(body) || [])[1];
        res.writeHead(200, { 'Content-Type': 'text/xml' });
        res.end('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/' +
                'soap/envelope/"><soap:Body>' +
                state.saml11Response(requestId) +
                '</soap:Body></soap:Envelope>');
      } else if (req.url === '/saml2/metadata' ||
                 req.url === '/saml11/metadata' ||
                 req.url === '/FederationMetadata/2007-06/' +
                             'FederationMetadata.xml') {
        res.writeHead(200, { 'Content-Type': 'application/xml' });
        res.end('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:' +
                '2.0:metadata" entityID="' + state.base + '/saml2"><md:' +
                'IDPSSODescriptor><md:KeyDescriptor use="signing"><ds:' +
                'KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:' +
                'X509Data><ds:X509Certificate>' + state.idp.certB64 +
                '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:' +
                'KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>');
      } else {
        json(404, { error: 'no ' + req.url });
      }
    });
  });
}

function call(url, options) {
  log.debug("Entering call(). " + url);
  log.debug("Leaving call().");
  return fetch(url, Object.assign({ redirect: 'manual' }, options || {}))
    .then(async function (r) {
      const text = await r.text();
      let json = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch (e) {
        log.debug("Caught in call(): " + ((e && e.message) || e));
        // Not JSON; `text` carries it.
        json = null;
      }
      return { status: r.status, text: text, json: json,
               headers: r.headers };
    });
}

// A request over the peer's TLS listener, trusting its CA, optionally with
// a client certificate.
function overTls(port, ca, method, p, headers, body, client) {
  log.debug("Entering overTls(). " + method + " " + p);
  log.debug("Leaving overTls().");
  return new Promise(function (resolve, reject) {
    const options = { host: 'localhost', port: port, path: p,
                      method: method, headers: headers || {}, ca: ca,
                      agent: false };
    if (client) {
      options.cert = client.cert;
      options.key = client.key;
    }
    const req = https.request(options, function (res) {
      const chunks = [];
      res.on('data', function (c) {
        chunks.push(c);
      });
      res.on('end', function () {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch (e) {
          log.debug("Caught in overTls(): " + ((e && e.message) || e));
          // Not JSON; `text` carries it.
          json = null;
        }
        resolve({ status: res.statusCode, text: text, json: json,
                  headers: res.headers });
      });
    });
    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

async function stepUpSection(t, state, peerBase, tenant) {
  log.debug("Entering stepUpSection().");
  const now = Math.floor(Date.now() / 1000);
  const token = function (claims, header) {
    log.debug("Entering token().");
    log.debug("Leaving token().");
    return jws(state.key, Object.assign({ alg: 'RS256', kid: 'k1',
                                          typ: 'at+jwt' }, header || {}),
               Object.assign({ iss: state.base, aud: ['https://api.test/'],
                               exp: now + 300, iat: now, client_id: 'c1',
                               sub: 'urn:uuid:x', auth_time: now - 10,
                               acr: '1' }, claims || {}));
  };
  const at = function (name, value) {
    log.debug("Entering at().");
    log.debug("Leaving at().");
    return call(peerBase + '/t/' + tenant + '/step-up/' + name,
                { headers: value ? { Authorization: 'Bearer ' + value }
                                 : {} });
  };
  let r = await at('api', token());
  const challenge = r.headers.get('www-authenticate') || '';
  t.check(r.status === 401 &&
          /^Bearer error="insufficient_user_authentication"/
            .test(challenge) &&
          /, acr_values="mfa"(,|$)/.test(challenge) &&
          /, max_age="600"$/.test(challenge) &&
          /error_description="[^"]+"/.test(challenge) &&
          r.json.error === 'insufficient_user_authentication',
          'A. an acr "1" token is challenged in section 3\'s shape',
          r.status + ' ' + challenge);
  r = await at('api', token({ acr: 'mfa' }));
  t.check(r.status === 200 && r.json.met === true &&
          r.json.resource === 'api' && r.json.token.acr === 'mfa' &&
          r.json.token.client_id === 'c1' &&
          /^bearer$/i.test(r.json.token.scheme) &&
          r.json.requirement.acr_values === 'mfa' &&
          r.json.requirement.max_age === 600,
          'A. an mfa token within max_age is answered 200, met',
          r.status + ' ' + r.text.slice(0, 300));
  r = await at('api', token({ acr: 'mfa', auth_time: now - 4000 }));
  t.check(r.status === 401 && /max_age="600"$/.test(
    r.headers.get('www-authenticate') || ''),
          'A. an mfa token older than max_age is challenged',
          String(r.status));
  r = await at('api', null);
  t.check(r.status === 401 && r.json.error === 'invalid_token' &&
          !/acr_values=/.test(r.headers.get('www-authenticate') || ''),
          'A. no token is invalid_token, with no step-up auth-params',
          String(r.status));
  r = await at('api', token({ aud: ['https://other.test/'], acr: 'mfa' }));
  t.check(r.status === 401 && r.json.error === 'invalid_token' &&
          r.text.indexOf('api') >= 0,
          'A. another audience is invalid_token, naming the resource',
          r.text.slice(0, 200));
  r = await at('api', token({ acr: 'mfa' }, { typ: 'JWT' }));
  t.check(r.status === 401 && r.json.error === 'invalid_token',
          'A. a token not typed at+jwt is refused (RFC 9068 section 4)',
          String(r.status));
  r = await at('api', token({ acr: 'mfa', iss: 'https://elsewhere.test' }));
  t.check(r.status === 401 && r.json.error === 'invalid_token',
          'A. another issuer is refused', String(r.status));
  r = await at('api', token({ acr: 'mfa', cnf: { jkt: 'x' } }));
  t.check(r.status === 401,
          'A. a sender-constrained token is refused: no proof is checked',
          String(r.status));
  const forged = token({ acr: 'mfa' }).split('.');
  forged[1] = b64u(JSON.stringify({ iss: state.base, acr: 'mfa',
                                    aud: ['https://api.test/'],
                                    exp: now + 300 }));
  r = await at('api', forged.join('.'));
  t.check(r.status === 401, 'A. a payload that is not the signed one is ' +
          'refused', String(r.status));
  r = await at('nobody', token({ acr: 'mfa' }));
  t.check(r.status === 404, 'A. a resource nobody configured is 404',
          String(r.status));
  log.debug("Leaving stepUpSection().");
}

async function gnapSection(t, state, peerBase, port, ca, view) {
  log.debug("Entering gnapSection().");
  const resource = view.gnap.resource;
  const spendUrl = view.gnap.spend;
  const es = new gnap.Client({ key: gnap.newKey('ES256') });
  const limited = { type: TYPE, actions: ['read', 'spend'],
                    limits: { amount: '30', currency: 'EUR', count: 5 } };
  state.introspection.bound = { active: true, key: es.keyObject(),
    access: [{ type: TYPE, actions: ['read', 'write'] }],
    format: 'jwt-signed', grant_id: 'g-bound', sub: 'urn:uuid:p' };
  state.introspection.readOnly = { active: true, key: es.keyObject(),
    access: [{ type: TYPE, actions: ['read'] }], format: 'macaroon' };
  state.introspection.spender = { active: true, key: es.keyObject(),
    access: [limited], format: 'jwt-signed', grant_id: 'g-spend' };
  state.introspection.carry = { active: true, flags: ['bearer'],
    access: [{ type: TYPE, actions: ['read'] }], format: 'biscuit' };

  let r = await gnap.rawRequest('GET', resource, {});
  const first = String(r.headers['www-authenticate'] || '');
  t.check(r.status === 401 && /^GNAP as_uri="/.test(first) &&
          first.indexOf('as_uri="' + state.base + '/gnap"') >= 0 &&
          first.indexOf('access="ref-peer-1"') >= 0 &&
          !/error=/.test(first),
          'B. no token: the RS-first challenge (RFC 9635 9.1) with the ' +
          'registered reference and no error', first);
  r = await es.send('GET', resource, { token: 'bound' });
  t.check(r.status === 200 && r.json.method === 'httpsig' &&
          r.json.format === 'jwt-signed' && r.json.action === 'read' &&
          r.json.token.cnf.jkt === gnapPeer.thumbprint(es.key.publicJwk) &&
          r.json.token.grant_id === 'g-bound',
          'B. a bound token proved by gnap_client.js\'s HTTP signature is ' +
          'accepted, and the confirmation is the key\'s RFC 7638 ' +
          'thumbprint', r.status + ' ' + r.text.slice(0, 300));
  r = await es.send('POST', resource, { token: 'bound', json: { x: 1 } });
  t.check(r.status === 200 && r.json.action === 'write',
          'B. and for write, with a body and its Content-Digest',
          r.status + ' ' + r.text.slice(0, 200));
  r = await es.send('POST', resource, { token: 'bound', json: { x: 1 },
    mutate: function (message) {
      return { body: Buffer.from(JSON.stringify({ x: 2 })) };
    } });
  t.check(r.status === 401,
          'B. a body changed after it was signed is refused (the digest)',
          r.status + ' ' + r.text.slice(0, 200));
  const thief = new gnap.Client({ key: gnap.newKey('ES256') });
  r = await thief.send('GET', resource, { token: 'bound' });
  t.check(r.status === 401, 'B. the same token proved by another key is ' +
          'refused', String(r.status));
  r = await es.send('GET', resource, { token: 'bound', sign: false });
  t.check(r.status === 401, 'B. the bound token with no proof is refused',
          String(r.status));
  r = await gnap.rawRequest('GET', resource,
                            { Authorization: 'Bearer bound' });
  t.check(r.status === 401, 'B. the bound token with the Bearer scheme is ' +
          'refused', String(r.status));
  r = await es.send('GET', resource, { token: 'gone' });
  t.check(r.status === 401 && r.json.error === 'invalid_token' &&
          /error="invalid_token"/.test(r.headers['www-authenticate']),
          'B. a token introspection calls inactive is refused',
          String(r.status));
  r = await es.send('POST', resource, { token: 'readOnly', json: {} });
  t.check(r.status === 403 && r.json.error === 'insufficient_scope' &&
          /insufficient_scope/.test(r.headers['www-authenticate']),
          'B. write on a read-only right is 403 insufficient_scope',
          String(r.status));
  r = await gnap.rawRequest('GET', resource,
                            { Authorization: 'Bearer carry' });
  t.check(r.status === 200 && r.json.method === 'bearer' &&
          r.json.token.cnf === null && r.json.format === 'biscuit',
          'B. a bearer token with the Bearer scheme and no proof is ' +
          'accepted', r.status + ' ' + r.text.slice(0, 200));
  r = await es.send('GET', resource, { token: 'carry' });
  t.check(r.status === 401, 'B. and refused with the GNAP scheme',
          String(r.status));

  for (const proof of ['jwsd', 'jws']) {
    const signer = new gnap.Client({ key: gnap.newKey(
      proof === 'jws' ? 'EdDSA' : 'RS256'), proof: proof });
    state.introspection[proof] = { active: true, key: signer.keyObject(),
      access: [{ type: TYPE, actions: ['read', 'write'] }],
      format: 'jwt-signed' };
    r = await signer.send('GET', resource, { token: proof });
    t.check(r.status === 200 && r.json.method === proof,
            'B. ' + proof + ': a GET proved by gnap_client.js is accepted',
            r.status + ' ' + r.text.slice(0, 200));
    r = await signer.send('POST', resource, { token: proof,
                                              json: { y: 1 } });
    t.check(r.status === 200 && r.json.action === 'write',
            'B. ' + proof + ': and a POST with a body',
            r.status + ' ' + r.text.slice(0, 200));
  }

  // MUTUAL TLS, on the peer's TLS listener (7.3.2).
  const clientCert = pki.signingCertificate('gnap-mtls-client');
  const otherCert = pki.signingCertificate('gnap-mtls-thief');
  state.introspection.mtls = { active: true,
    key: { proof: 'mtls', cert: clientCert.certB64 },
    access: [{ type: TYPE, actions: ['read'] }], format: 'jwt-signed' };
  const tlsPath = '/t/' + view.tenant + '/gnap/resource';
  r = await overTls(port, ca, 'GET', tlsPath,
                    { Authorization: 'GNAP mtls' }, null,
                    { cert: clientCert.certPem,
                      key: clientCert.privateKeyPem });
  t.check(r.status === 200 && r.json.method === 'mtls' &&
          r.json.token.cnf['x5t#S256'],
          'B. mtls: the token\'s certificate on the connection is accepted',
          r.status + ' ' + r.text.slice(0, 200));
  r = await overTls(port, ca, 'GET', tlsPath,
                    { Authorization: 'GNAP mtls' }, null, null);
  t.check(r.status === 401, 'B. mtls: with no client certificate, refused',
          String(r.status));
  r = await overTls(port, ca, 'GET', tlsPath,
                    { Authorization: 'GNAP mtls' }, null,
                    { cert: otherCert.certPem,
                      key: otherCert.privateKeyPem });
  t.check(r.status === 401, 'B. mtls: with another certificate, refused',
          String(r.status));

  // THE SPEND, as sts_gnap_limits.js section 3 drives it.
  const spend = function (json) {
    log.debug("Entering spend().");
    log.debug("Leaving spend().");
    return es.send('POST', spendUrl, { token: 'spender', json: json });
  };
  r = await spend({ amount: '20', currency: 'EUR' });
  t.check(r.status === 200 && r.json.remaining.amount === '10' &&
          r.json.grant_id === 'g-spend' && r.json.totals.amount === '20',
          'B. spend 20 EUR of 30: 10 left, counted against the grant',
          r.status + ' ' + r.text.slice(0, 300));
  r = await spend({ amount: '20', currency: 'EUR' });
  t.check(r.status === 403 && r.json.error === 'insufficient_scope' &&
          /insufficient_scope/.test(r.headers['www-authenticate']),
          'B. 20 more passes the limit: 403 insufficient_scope',
          r.status + ' ' + r.text.slice(0, 200));
  r = await spend({ amount: '10', currency: 'EUR', simulateFailure: true });
  t.check(r.status === 502 && r.json.refunded === true,
          'B. a failed operation is refunded', r.text.slice(0, 200));
  r = await spend({ amount: '10', currency: 'EUR' });
  t.check(r.status === 200 && r.json.totals.amount === '30' &&
          r.json.remaining.amount === '0',
          'B. so 10 more is exactly the limit', r.text.slice(0, 200));
  r = await spend({ amount: '0.01', currency: 'EUR' });
  t.check(r.status === 403, 'B. and a cent more is refused',
          String(r.status));
  r = await spend({ amount: '1', currency: 'USD' });
  t.check(r.status === 403 && /EUR/.test(r.json.error_description),
          'B. another currency is refused, naming the allowed one',
          r.text.slice(0, 200));
  r = await gnap.rawRequest('POST', spendUrl,
                            { 'Content-Type': 'application/json' },
                            Buffer.from('{"amount":"1"}'));
  t.check(r.status === 401, 'B. a spend with no token: the challenge',
          String(r.status));
  t.equal(gnapPeer.fromUnits(gnapPeer.toUnits('0.1') +
                             gnapPeer.toUnits('0.2')), '0.3',
          'B. the arithmetic is decimal: 0.1 + 0.2 is 0.3');
  t.check(state.introspections > 10,
          'B. every presentation was introspected, signed by the peer\'s ' +
          'key', String(state.introspections));
  log.debug("Leaving gnapSection().");
}

async function ssfSection(t, state, port, ca, view) {
  log.debug("Entering ssfSection().");
  const pushPath = new URL(view.ssf.pushUrl).pathname;
  const now = Math.floor(Date.now() / 1000);
  const verification = 'https://schemas.openid.net/secevent/ssf/' +
                       'event-type/verification';
  const set = function (header, claims) {
    log.debug("Entering set().");
    const events = {};
    events[verification] = { state: 's1' };
    log.debug("Leaving set().");
    return jws(state.key, Object.assign({ alg: 'RS256', kid: 'k1',
                                          typ: 'secevent+jwt' }, header),
               Object.assign({ iss: state.base, aud: 'receiver-1', iat: now,
                               jti: 'j' + nodeCrypto.randomBytes(6)
                                 .toString('hex'),
                               events: events }, claims));
  };
  const push = function (body, auth, type) {
    log.debug("Entering push().");
    log.debug("Leaving push().");
    return overTls(port, ca, 'POST', pushPath, {
      'Content-Type': type || 'application/secevent+jwt',
      Authorization: auth === undefined ? 'Bearer push-secret' : auth },
      Buffer.from(body), null);
  };
  let r = await push(set({}, {}));
  t.check(r.status === 202 && r.text === '',
          'C. a signed SET from the realm is accepted, 202 and empty',
          r.status + ' ' + r.text);
  r = await push(set({}, {}), 'Bearer wrong');
  t.check(r.status === 401 && r.json.err === 'authentication_failed',
          'C. another Authorization is authentication_failed', r.text);
  r = await push(set({ typ: 'JWT' }, {}));
  t.check(r.status === 400 && r.json.err === 'invalid_request',
          'C. a SET not typed secevent+jwt is refused', r.text);
  r = await push(set({}, { iss: 'https://other.test' }));
  t.check(r.status === 400 && r.json.err === 'invalid_issuer',
          'C. another issuer is invalid_issuer', r.text);
  r = await push(set({}, { aud: 'somebody-else' }));
  t.check(r.status === 400 && r.json.err === 'invalid_audience',
          'C. another audience is invalid_audience', r.text);
  const tampered = set({}, {}).split('.');
  tampered[1] = b64u(JSON.stringify({ iss: state.base, aud: 'receiver-1' }));
  r = await push(tampered.join('.'));
  t.check(r.status === 400 && r.json.err === 'invalid_key',
          'C. a SET whose signature does not verify is invalid_key', r.text);
  r = await push(set({}, {}), undefined, 'application/json');
  t.check(r.status === 400, 'C. a body that is not application/' +
          'secevent+jwt is refused', String(r.status));
  log.debug("Leaving ssfSection().");
}

async function samlSection(t, state, peerBase, view) {
  log.debug("Entering samlSection().");
  let r = await call(view.urls.saml2Login + '?binding=post&relay=rs1');
  const location = r.headers.get('location') || '';
  const u = new URL(location);
  const xml = zlib.inflateRawSync(Buffer.from(
    u.searchParams.get('SAMLRequest'), 'base64')).toString('utf8');
  const signed = location.slice(location.indexOf('?') + 1)
    .split('&Signature=')[0];
  const verified = nodeCrypto.verify('RSA-SHA256', Buffer.from(signed),
    view.saml.certPem, Buffer.from(u.searchParams.get('Signature'),
                                   'base64'));
  const id = (/ ID="([^"]+)"/.exec(xml) || [])[1];
  t.check(r.status === 302 && u.pathname === '/saml2/sso' && verified &&
          xml.indexOf('<saml:Issuer>' + view.saml.entityId) >= 0 &&
          xml.indexOf('AssertionConsumerServiceURL="' +
                      view.urls.saml2Acs + '"') >= 0 && !!id,
          'D. the SP-initiated start: a redirect AuthnRequest signed by the ' +
          'tenant\'s registered key', r.status + ' ' + xml.slice(0, 200));
  const now = new Date();
  const later = new Date(Date.now() + 300000).toISOString();
  const assertionId = '_a' + nodeCrypto.randomBytes(8).toString('hex');
  const assertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:' +
    '2.0:assertion" ID="' + assertionId + '" Version="2.0" IssueInstant="' +
    now.toISOString() + '"><saml:Issuer>' + state.base + '/saml2</saml:' +
    'Issuer><saml:Subject><saml:NameID>alice</saml:NameID><saml:' +
    'SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    '<saml:SubjectConfirmationData InResponseTo="' + id + '" Recipient="' +
    view.urls.saml2Acs + '" NotOnOrAfter="' + later + '"/></saml:' +
    'SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="' +
    later + '"><saml:AudienceRestriction><saml:Audience>' +
    view.saml.entityId + '</saml:Audience></saml:AudienceRestriction>' +
    '</saml:Conditions><saml:AttributeStatement><saml:Attribute Name="' +
    'mail"><saml:AttributeValue>alice@test</saml:AttributeValue></saml:' +
    'Attribute></saml:AttributeStatement></saml:Assertion>';
  const response = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:' +
    '2.0:protocol" ID="_r1" Version="2.0" IssueInstant="' +
    now.toISOString() + '" Destination="' + view.urls.saml2Acs +
    '" InResponseTo="' + id + '"><samlp:Status><samlp:StatusCode Value="' +
    'urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    assertion + '</samlp:Response>';
  const sig = new SignedXml({ privateKey: state.idp.privateKeyPem,
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256' });
  sig.computeSignature(response, { location: {
    reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
    action: 'after' } });
  const signedResponse = sig.getSignedXml();
  const tampered = signedResponse.replace('<saml:NameID>alice<',
                                          '<saml:NameID>mallory<');
  const post = function (xmlText) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return call(view.urls.saml2Acs, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ SAMLResponse: Buffer.from(xmlText)
        .toString('base64'), RelayState: 'rs1' }).toString() });
  };
  r = await post(tampered);
  t.check(r.status === 400 && !r.json.ok,
          'D. the Response with its NameID changed under the signature is ' +
          'refused', r.text.slice(0, 300));
  r = await post(signedResponse);
  t.check(r.status === 200 && r.json.ok && r.json.nameId === 'alice' &&
          r.json.solicited === true && r.json.assertionSignatureValid &&
          r.json.attributes.mail[0] === 'alice@test',
          'D. the signed Response to its own request is consumed',
          r.text.slice(0, 400));
  r = await post(signedResponse);
  t.check(r.status === 400 && /InResponseTo/.test(r.text),
          'D. and the same Response again is refused: its request was ' +
          'answered', r.text.slice(0, 300));
  log.debug("Leaving samlSection().");
}

// A SAML 1.1 assertion, signed through AssertionID by the fake identity
// provider.
function saml11Assertion(state, audience, method, subject) {
  log.debug("Entering saml11Assertion().");
  const now = new Date();
  const later = new Date(Date.now() + 300000).toISOString();
  const id = '_a' + nodeCrypto.randomBytes(8).toString('hex');
  const xml = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:' +
    'assertion" AssertionID="' + id + '" MajorVersion="1" MinorVersion="1" ' +
    'Issuer="' + state.base + '" IssueInstant="' + now.toISOString() + '">' +
    '<saml:Conditions NotBefore="' + now.toISOString() + '" NotOnOrAfter="' +
    later + '"><saml:AudienceRestrictionCondition><saml:Audience>' +
    audience + '</saml:Audience></saml:AudienceRestrictionCondition></saml:' +
    'Conditions><saml:AuthenticationStatement AuthenticationMethod="urn:' +
    'oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="' +
    now.toISOString() + '"><saml:Subject><saml:NameIdentifier>' + subject +
    '</saml:NameIdentifier><saml:SubjectConfirmation><saml:' +
    'ConfirmationMethod>' + method + '</saml:ConfirmationMethod></saml:' +
    'SubjectConfirmation></saml:Subject></saml:AuthenticationStatement>' +
    '</saml:Assertion>';
  log.debug("Leaving saml11Assertion().");
  return signXml(state, xml, 'Assertion', 'AssertionID', 'append');
}

// An enveloped signature by the fake identity provider on `localName`,
// through `idAttribute`.
function signXml(state, xml, localName, idAttribute, action) {
  log.debug("Entering signXml(). " + localName);
  const where = "//*[local-name(.)='" + localName + "']";
  const sig = new SignedXml({ privateKey: state.idp.privateKeyPem,
    idAttribute: idAttribute,
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' });
  sig.addReference({
    xpath: where,
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256' });
  sig.computeSignature(xml, { location: { reference: where,
                                          action: action } });
  log.debug("Leaving signXml().");
  return sig.getSignedXml();
}

async function saml11Section(t, state, view) {
  log.debug("Entering saml11Section().");
  const acs = view.urls.saml11Acs;
  const responseFor = function (inResponseTo, method, subject) {
    log.debug("Entering responseFor().");
    const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:' +
      'protocol" ResponseID="_r' + nodeCrypto.randomBytes(8).toString('hex') +
      '" MajorVersion="1" MinorVersion="1" IssueInstant="' +
      new Date().toISOString() + '" Recipient="' + acs + '"' +
      (inResponseTo ? ' InResponseTo="' + inResponseTo + '"' : '') +
      '><samlp:Status><samlp:StatusCode Value="samlp:Success"/></samlp:' +
      'Status>' + saml11Assertion(state, view.saml.entityId, method,
                                   subject) + '</samlp:Response>';
    log.debug("Leaving responseFor().");
    return signXml(state, xml, 'Response', 'ResponseID', 'prepend');
  };
  const post = function (xml) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return call(acs, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ SAMLResponse: Buffer.from(xml)
        .toString('base64'), TARGET: 'https://app.test/x' }).toString() });
  };
  const bearer = 'urn:oasis:names:tc:SAML:1.0:cm:bearer';
  let r = await post(responseFor(null, bearer, 'bob'));
  t.check(r.status === 200 && r.json.ok && r.json.nameIdentifier === 'bob' &&
          r.json.responseSignatureValid && r.json.assertionSignatureValid &&
          r.json.target === 'https://app.test/x',
          'F. a Browser/POST Response, signed twice, verifies through ' +
          'ResponseID and AssertionID', r.text.slice(0, 400));
  r = await post(responseFor('_nobody', bearer, 'bob'));
  t.check(r.status === 400 && /InResponseTo/.test(r.text),
          'F. one carrying InResponseTo, on a profile with no request, is ' +
          'refused', r.text.slice(0, 300));
  r = await post(responseFor(null, 'urn:oasis:names:tc:SAML:1.0:cm:' +
                                   'artifact', 'bob'));
  t.check(r.status === 400 && /confirmation method/.test(r.text),
          'F. one whose confirmation method is cm:artifact is refused on ' +
          'Browser/POST', r.text.slice(0, 300));
  state.saml11Response = function (requestId) {
    log.debug("Entering saml11Response().");
    log.debug("Leaving saml11Response().");
    return '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:' +
      'protocol" ResponseID="_r2" MajorVersion="1" MinorVersion="1" ' +
      'IssueInstant="' + new Date().toISOString() + '" InResponseTo="' +
      requestId + '"><samlp:Status><samlp:StatusCode Value="samlp:' +
      'Success"/></samlp:Status>' + saml11Assertion(state,
        view.saml.entityId, 'urn:oasis:names:tc:SAML:1.0:cm:artifact',
        'carol') + '</samlp:Response>';
  };
  r = await call(acs + '?SAMLart=' + encodeURIComponent('AAEartifact') +
                 '&TARGET=x');
  const asked = state.saml11Requests[state.saml11Requests.length - 1] || '';
  t.check(r.status === 200 && r.json.ok && r.json.nameIdentifier === 'carol' &&
          /<samlp:AssertionArtifact>AAEartifact</.test(asked) &&
          /Signature/.test(asked) &&
          verifiesUnder(asked, view.saml.certPem),
          'F. an artifact is resolved at the responder with a request the ' +
          'tenant\'s registered key signed, and its cm:artifact assertion ' +
          'accepted', r.text.slice(0, 300));
  log.debug("Leaving saml11Section().");
}

// Whether the samlp:Request in a SOAP body verifies under `certPem`.
function verifiesUnder(soapBody, certPem) {
  log.debug("Entering verifiesUnder().");
  const { DOMParser } = require('@xmldom/xmldom');
  const doc = new DOMParser().parseFromString(soapBody, 'text/xml');
  const request = doc.getElementsByTagNameNS('*', 'Request')[0];
  const signature = request &&
    request.getElementsByTagNameNS('*', 'Signature')[0];
  if (!signature) {
    log.debug("Leaving verifiesUnder(). Unsigned.");
    return false;
  }
  const sig = new SignedXml({ publicCert: certPem,
                              idAttribute: 'RequestID' });
  sig.loadSignature(signature);
  log.debug("Leaving verifiesUnder().");
  return sig.checkSignature(soapBody);
}

async function wsfedSection(t, state, view) {
  log.debug("Entering wsfedSection().");
  const rstr = function (audience) {
    log.debug("Entering rstr().");
    log.debug("Leaving rstr().");
    return '<t:RequestSecurityTokenResponse xmlns:t="http://schemas.' +
      'xmlsoap.org/ws/2005/02/trust"><wsp:AppliesTo xmlns:wsp="http://' +
      'schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference ' +
      'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
      audience + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
      '<t:RequestedSecurityToken>' + saml11Assertion(state, audience,
        'urn:oasis:names:tc:SAML:1.0:cm:bearer', 'dave') +
      '</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>';
  };
  const post = function (wresult) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return call(view.urls.wsfedReply, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ wa: 'wsignin1.0', wresult: wresult,
                                  wctx: 'ctx-1' }).toString() });
  };
  let r = await post(rstr('urn:test:wsfed:one'));
  t.check(r.status === 200 && r.json.ok && r.json.subject === 'dave' &&
          r.json.signatureValid && r.json.wctx === 'ctx-1' &&
          r.json.tokenType === 'saml11',
          'F. a WS-Federation sign-in response for this realm is accepted',
          r.text.slice(0, 300));
  r = await post(rstr('urn:test:wsfed:another'));
  t.check(r.status === 400 && /audience/.test(r.text),
          'F. one whose token is for another realm is refused',
          r.text.slice(0, 300));
  r = await post(rstr('urn:test:wsfed:one').replace('>dave<', '>eve<'));
  t.check(r.status === 400 && !r.json.ok,
          'F. one whose subject was changed under the signature is refused',
          r.text.slice(0, 300));
  log.debug("Leaving wsfedSection().");
}

// G. The Provider Commands relying party.
async function commandsSection(t, state, port, ca, view) {
  log.debug("Entering commandsSection().");
  const at = new URL(view.commands.endpoint).pathname;
  const now = Math.floor(Date.now() / 1000);
  const token = function (header, claims) {
    log.debug("Entering token().");
    log.debug("Leaving token().");
    return jws(state.key, Object.assign({ alg: 'RS256', kid: 'k1',
                                          typ: 'command+jwt' }, header),
               Object.assign({ iss: state.base, aud: 'rp-1',
                               client_id: 'rp-1', iat: now, exp: now + 60,
                               jti: 'c' + nodeCrypto.randomBytes(6)
                                 .toString('hex'),
                               tenant: 'realm-1' }, claims));
  };
  const send = function (compact, query, headers) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return overTls(port, ca, 'POST', at + (query || ''), Object.assign({
      'Content-Type': 'application/x-www-form-urlencoded' }, headers || {}),
      Buffer.from('command_token=' + encodeURIComponent(compact)), null);
  };
  let r = await send(token({}, { command: 'metadata',
    metadata: { callback_endpoint: state.base +
                                   '/oauth2/commands/callback' } }),
                     '?audsub=1');
  t.check(r.status === 200 &&
          r.json.commands_supported.indexOf('suspend_async') >= 0 &&
          r.json.commands_supported.indexOf('audit_tenant') >= 0 &&
          r.json.aud_sub_required === true && r.json.roles.length === 2,
          'G. metadata answers what the relying party supports',
          r.text.slice(0, 300));
  r = await send(token({}, { command: 'activate', sub: 'alice',
                             email: 'alice@example.test' }));
  t.check(r.status === 200 && r.json.account_state === 'active' &&
          /^rp-/.test(r.json.aud_sub),
          'G. activate makes the account active, with an aud_sub', r.text);
  r = await send(token({}, { command: 'activate', sub: 'alice' }));
  t.check(r.status === 409 && r.json.error === 'incompatible_state' &&
          r.json.account_state === 'active',
          'G. activating an active account is incompatible_state', r.text);
  r = await send(token({}, { command: 'suspend_async', sub: 'alice',
                             callback_token: 'cb-1' }));
  t.check(r.status === 202, 'G. an _async command is answered 202',
          String(r.status));
  for (let i = 0; i < 40 && !state.callbacks.length; i++) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 50);
    });
  }
  const back = state.callbacks[0] || {};
  t.check(back.authorization === 'Bearer cb-1' &&
          JSON.parse(back.body || '{}').account_state === 'suspended' &&
          JSON.parse(back.body || '{}').sub === 'alice',
          'G. and its result is POSTed to the metadata\'s callback with ' +
          'the callback_token', JSON.stringify(back));
  await send(token({}, { command: 'reactivate', sub: 'alice' }));
  await send(token({}, { command: 'activate', sub: 'bob' }));
  r = await send(token({}, { command: 'audit_tenant' }), '?drop=1');
  t.check(r.status === 200 && /^id: 1\nevent: account-state/.test(r.text) &&
          !/command-complete/.test(r.text),
          'G. ?drop=1 closes the tenant stream after one event', r.text);
  const again = token({}, { command: 'audit_tenant' });
  r = await send(again, '?drop=1', { 'Last-Event-ID': '1' });
  t.check(r.status === 200 && /^id: 2\nevent: account-state/.test(r.text) &&
          /id: 3\nevent: command-complete/.test(r.text),
          'G. and a resumption with Last-Event-ID completes it', r.text);
  r = await send(token({}, { command: 'metadata', metadata: {} }),
                 '?fail=1');
  const second = await send(token({}, { command: 'metadata',
                                        metadata: {} }), '?fail=1');
  t.check(r.status === 503 && second.status === 200,
          'G. ?fail=1 answers 503 once, then the command', r.status + ' ' +
          second.status);
  r = await send(token({}, { command: 'audit', sub: 'alice',
                             iss: 'https://other.test' }));
  t.check(r.status === 401 && r.json.error === 'unrecognized_provider',
          'G. another issuer is unrecognized_provider', r.text);
  r = await send(token({ typ: 'JWT' }, { command: 'audit', sub: 'alice' }));
  t.check(r.status === 400 && r.json.error === 'invalid_request',
          'G. a token not typed command+jwt is refused', r.text);
  r = await send(token({}, { command: 'audit', sub: 'alice', nonce: 'n' }));
  t.check(r.status === 400, 'G. a Command Token with a nonce is refused',
          r.text);
  const once = token({}, { command: 'audit', sub: 'alice' });
  await send(once);
  r = await send(once);
  t.check(r.status === 400 && /already used/.test(r.json.error_description),
          'G. a replayed jti is refused', r.text);
  const tampered = token({}, { command: 'audit', sub: 'alice' }).split('.');
  tampered[1] = b64u(JSON.stringify({ iss: state.base, command: 'delete' }));
  r = await send(tampered.join('.'));
  t.check(r.status === 400 && /does not verify/.test(
    r.json.error_description),
          'G. a token whose signature does not verify is refused', r.text);
  r = await send(token({ alg: 'HS256' }, { command: 'audit',
                                           sub: 'alice' }));
  t.check(r.status === 400 && /asymmetric/.test(r.json.error_description),
          'G. a symmetric alg is refused before any key', r.text);
  r = await call('http://localhost:' + port + at + '?client_id=rp-1');
  t.check(r.status === 200 && r.json.accounts.length === 2 &&
          r.json.accounts.every(function (one) {
            return one.state === 'active';
          }), 'G. the accounts it holds are read back', r.text);
  log.debug("Leaving commandsSection().");
}

// H. THE BACK-CHANNEL LOGOUT RELYING PARTY (#293): a Logout Token signed by
// the realm's key accepted, and the refusals section 2.6 asks of a relying
// party, each by its own fault.
async function bclSection(t, state, port, ca, view) {
  log.debug("Entering bclSection().");
  const at = new URL(view.bcl.endpoint).pathname;
  const now = Math.floor(Date.now() / 1000);
  const EVENT = 'http://schemas.openid.net/event/backchannel-logout';
  const token = function (header, claims) {
    log.debug("Entering token().");
    const events = {};
    events[EVENT] = {};
    log.debug("Leaving token().");
    return jws(state.key, Object.assign({ alg: 'RS256', kid: 'k1',
                                          typ: 'logout+jwt' }, header),
               Object.assign({ iss: state.base, aud: 'rp-bcl', iat: now,
                               jti: 'l' + nodeCrypto.randomBytes(6)
                                 .toString('hex'),
                               sub: 'alice', sid: 's-1', events: events },
                             claims));
  };
  const send = function (compact, type) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return overTls(port, ca, 'POST', at, {
      'Content-Type': type || 'application/x-www-form-urlencoded' },
      Buffer.from('logout_token=' + encodeURIComponent(compact)), null);
  };
  const good = token({}, {});
  let r = await send(good);
  t.check(r.status === 200 &&
          /no-store/.test(String(r.headers['cache-control'])),
          'H. a Logout Token from the realm is accepted, 200 and no-store',
          r.status + ' ' + r.text);
  r = await send(good);
  t.check(r.status === 400 && /seen before/.test(r.text),
          'H. the same jti again is refused as a replay', r.text);
  const refusals = [
    ['a token not typed logout+jwt', token({ typ: 'JWT' }, {}), /typ/],
    ['a token carrying a nonce', token({}, { nonce: 'n' }), /nonce/],
    ['a token for another client', token({}, { aud: 'someone-else' }),
     /aud/],
    ['a token from another issuer', token({}, { iss: 'https://other.test' }),
     /iss/],
    ['a token without the event', token({}, { events: {} }), /events/],
    ['a token naming neither sub nor sid',
     token({}, { sub: undefined, sid: undefined }), /neither sub nor sid/]
  ];
  for (const [what, compact, why] of refusals) {
    r = await send(compact);
    t.check(r.status === 400 && r.json && r.json.error === 'invalid_request' &&
            why.test(r.json.error_description || ''),
            'H. ' + what + ' is refused', r.text);
  }
  const tampered = token({}, {}).split('.');
  tampered[1] = b64u(JSON.stringify({ iss: state.base, aud: 'rp-bcl' }));
  r = await send(tampered.join('.'));
  t.check(r.status === 400 && /signature/.test(r.text),
          'H. a token whose signature does not verify is refused', r.text);
  r = await send('a.b.c.d.e');
  t.check(r.status === 400 && /encrypted/.test(r.text),
          'H. an encrypted token, which the peer cannot open, is refused',
          r.text);
  r = await send(token({}, {}), 'application/json');
  t.check(r.status === 400 && /not a form/.test(r.text),
          'H. a body that is not a form is refused', r.text);
  log.debug("Leaving bclSection().");
}

async function run(t) {
  log.debug("Entering run().");
  const caDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-peer-'));
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const state = { key: pair.privateKey,
                  jwk: Object.assign(pair.publicKey.export({ format: 'jwk' }),
                                     { kid: 'k1', alg: 'RS256', use: 'sig' }),
                  introspection: {}, introspections: 0,
                  saml11Requests: [], callbacks: [],
                  // Replaced by section F before the responder is asked.
                  saml11Response: function () {
                    log.debug("Entering saml11Response().");
                    log.debug("Leaving saml11Response().");
                    return '';
                  },
                  idp: pki.signingCertificate('fake idp') };
  const realm = fakeRealm(state);
  await new Promise(function (resolve) {
    realm.listen(0, '127.0.0.1', resolve);
  });
  state.base = 'http://127.0.0.1:' + realm.address().port;
  const running = await peer.start({ port: 0, host: 'localhost',
                                     caDir: caDir });
  const peerBase = 'http://localhost:' + running.port;
  try {
    const ca = fs.readFileSync(path.join(caDir, 'ca.crt'), 'utf8');
    t.check(/BEGIN CERTIFICATE/.test(ca), 'the peer wrote its CA ' +
            'certificate, and nothing else', fs.readdirSync(caDir).join());
    const r = await call(peerBase + '/peer/tenants/one', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        realmBase: state.base,
        stepUp: { resources: { api: { audience: 'https://api.test/',
                                      acr_values: 'mfa', max_age: 600 } } },
        gnap: { type: TYPE },
        wsfed: { realm: 'urn:test:wsfed:one' },
        ssf: { authorizationHeader: 'Bearer push-secret',
               audience: 'receiver-1' },
        bcl: { clientId: 'rp-bcl' } }) });
    const view = r.json;
    t.check(r.status === 200 && view.ok && view.gnap.key.jwk &&
            !view.gnap.key.jwk.d && /BEGIN CERTIFICATE/.test(
              view.saml.certPem) && /^https:/.test(view.ssf.pushUrl),
            'a tenant is configured, and its view carries public keys only',
            r.text.slice(0, 300));
    await stepUpSection(t, state, peerBase, 'one');
    await gnapSection(t, state, peerBase, running.port, ca, view);
    await ssfSection(t, state, running.port, ca, view);
    await samlSection(t, state, peerBase, view);
    await saml11Section(t, state, view);
    await wsfedSection(t, state, view);
    await commandsSection(t, state, running.port, ca, view);
    await bclSection(t, state, running.port, ca, view);
    let back = await call(peerBase + '/peer/tenants/one/received?role=ssf');
    t.check(back.status === 200 && back.json.events.length >= 7 &&
            back.json.events.every(function (row) {
              return row.role === 'ssf';
            }) && back.json.events[0].ok === true &&
            back.json.events[0].eventTypes.length === 1,
            'E. the readback answers one role\'s records',
            back.text.slice(0, 300));
    const last = back.json.last;
    back = await call(peerBase + '/peer/tenants/one/received?since=' + last);
    t.check(back.status === 200 && back.json.events.length === 0,
            'E. and nothing after the last sequence number',
            back.text.slice(0, 200));
    back = await call(peerBase + '/peer/tenants/nobody/received');
    t.check(back.status === 404, 'E. a tenant nobody configured is 404',
            String(back.status));
  } finally {
    await running.close();
    await new Promise(function (resolve) {
      realm.close(resolve);
    });
    fs.rmSync(caDir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'test_peer',
  describe: 'the test peer (#586) against a fake realm: the RFC 9470 and ' +
            'GNAP resource servers, the SSF receiver, the SAML 2.0 ' +
            'service provider, the Provider Commands relying party and ' +
            'the Back-Channel Logout relying party, ' +
            'each refusing what a real party would',
  run: run
};
