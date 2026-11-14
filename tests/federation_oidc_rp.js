// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/federation_oidc_rp.js
// ===========================================================================
// AN INBOUND OPENID CONNECT RELATIONSHIP AS THE CONFORMANCE SUITE'S RELYING
// PARTY PLANS HOLD IT (#930), IN PROCESS. The whole stack in a child process
// over HTTP on 127.0.0.1, and beside it a small OpenID Provider written
// here (plain http, which development mode's federation.outboundAllowHttp
// admits for a loopback partner) whose answers each case chooses:
//   1. the code flow: a good ID Token signs in and UserInfo is asked; an ID
//      Token with no sub (STS-FED-0195), no iat (0196), a foreign azp
//      (0197), no nonce (0198), another nonce (0039) or an algorithm other
//      than the registered one (0208), or issued before the sign-in began
//      or in the future (0253), is refused before UserInfo is asked;
//      UserInfo answering for another sub is refused (0202); the
//      administrator's check-partner reads the key set;
//   2. the hybrid `code id_token` type: PKCE beside it, the front ID
//      Token's c_hash checked BEFORE the code is redeemed (0199: the token
//      endpoint is never called), and the two ID Tokens held to one
//      subject (0201);
//   3. the implicit `id_token token` type in the fragment mode: no
//      response_mode asked, the bare GET answered with the page and its one
//      script under `script-src 'self'` with `frame-ancestors` kept, the
//      script served, a wrong at_hash refused (0200) and a right one asking
//      UserInfo with the front access token; `query` with that type is not
//      ready;
//   4. discovery: the endpoints read from {fedPeer}/.well-known/
//      openid-configuration at the sign-in, and a document naming another
//      issuer refused (0204);
//   5. the login initiation endpoint: off refuses (0205), another iss
//      refuses (0206), the right one starts the sign-in with the
//      login_hint passed on;
//   7. self-registration (fedRegister) and Request Objects by reference:
//      the registration's metadata and one public key, the client kept,
//      the object verifying with that key and answered once (0218), no
//      second registration for the same issuer, register-partner, alg none;
//   8. WebFinger: off refuses (0215), the form, an address looked up as
//      acct: with nothing continuing by itself, continuing registering at
//      the found issuer, and an issuer outside fedPeer refused (0217);
//   6. refresh tokens (fedRefreshTokens): a held token refreshed when due
//      and UserInfo asked with the new access token; a refreshed ID Token
//      naming another iss (0211) and a refused refresh (0210) end the
//      session; an ended session's token is gone.
//   10. a FAPI client (#931): 2-security pushes, then redeems with
//      private_key_jwt and DPoP and asks UserInfo as DPoP; discovery off,
//      or a document with no PAR endpoint, refuses (0243); 1-advanced puts
//      a PS256 request object on the browser URL and redeems with
//      private_key_jwt and no DPoP; message signing puts that object in the
//      push, not on the URL, and opens a JARM response before redeeming.
//      A push the partner refuses stays 502 (0244) and does not redirect.
//      A JARM response signed by another key, or one with no state, is
//      refused (0246) without redeeming; one that carries the partner's
//      error is that error (0025), and the same sign-in then redeems a
//      good response. The first push answered use_dpop_nonce is retried
//      with that nonce. Registration sends private_key_jwt and PS256, and
//      DPoP or JARM where the profile uses them. beginConnect will not
//      start a FAPI sign-in (0184). A 2.x refresh proves DPoP with the
//      sign-in's key; 1-advanced refreshes with the assertion alone.
//      What the answer is held to (#931's review): 1-advanced's front ID
//      Token without s_hash, or with another state's, is refused (0248);
//      a 2.x answer naming no issuer is refused (0249) and one naming
//      another still is (0238); a JARM response with no exp is refused
//      (0250); a 2.x token response, or refresh, whose token_type is not
//      DPoP is refused or ends the session (0251), and `dpop` in lower
//      case is accepted. None of these redeems a code.
//      1-advanced over mutual TLS (rcbj's decision of 2026-11-13, 10ad-
//      10al), against the partner on a listener that asks for a client
//      certificate and binds the token it issues to it: the relationship's
//      clientAuth certificate is presented at the token endpoint and at
//      UserInfo, which answers the bound token only over it; tls_client_auth
//      sends the client_id and nothing else, and is not ready without
//      1-advanced; a certificate whose key will not open is STS-FED-0252
//      with nothing dialled; the renewal job keeps the subject; a
//      registration says tls_client_auth with the subject DN, and the
//      discovery document's mtls_endpoint_aliases are dialled.
//      Every request signed afresh (#931's first run, 10am, 10an): a
//      partner that demands its DPoP nonce at the push, the token endpoint
//      and the refresh, and a UserInfo that demands one of its own in
//      WWW-Authenticate: each is answered once more, no client assertion
//      or request object jti is ever sent twice, and the authorization
//      server's nonce and UserInfo's are never sent to each other.
// The conformance suite's relying-party plans drive the same code over the
// wire (`tests/protocol/sts_oidcc_rp_conformance.js`); this pins each
// refusal's code and that nothing is dialled after it.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'federation_oidc_rp',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack and the partner, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.FRP_ROOT;
  const OUT = process.env.FRP_OUT;
  const http = require('http');
  const fs = require('fs');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function b64u(value) {
    return Buffer.from(typeof value === 'string' ? value
                                                 : JSON.stringify(value))
      .toString('base64url');
  }
  function halfHash(value) {
    const digest = nodeCrypto.createHash('sha256').update(String(value))
      .digest();
    return digest.subarray(0, digest.length / 2).toString('base64url');
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const audit = require(ROOT_DIR + '/common/audit');
    const federation = require(ROOT_DIR + '/federation/federation');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    // --- the partner -------------------------------------------------------
    const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    jwk.kid = 'frp-1';
    jwk.use = 'sig';
    jwk.alg = 'RS256';
    const op = { calls: [], scenario: {}, byToken: {}, bound: {}, jtis: [] };
    // A JWT's claims, unverified: what the partner reads a jti or a DPoP
    // nonce from. null for anything that is not three base64url parts.
    const jwtClaimsOf = function (token) {
      const parts = String(token || '').split('.');
      if (parts.length !== 3) {
        return null;
      }
      try {
        return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      } catch (e) {
        // Not a JWT the partner can read: no jti and no nonce, which every
        // check below reads as missing.
        op.unreadable = String((e && e.message) || e);
        return null;
      }
    };
    const sign = function (claims) {
      const input = b64u({ alg: 'RS256', kid: 'frp-1', typ: 'JWT' }) + '.' +
                    b64u(claims);
      return input + '.' + nodeCrypto.sign('sha256', Buffer.from(input),
                                           pair.privateKey)
        .toString('base64url');
    };
    const partner = http.createServer(function (req, res) {
      let body = '';
      req.on('data', function (c) {
        body += c;
      });
      req.on('end', function () {
        const url = new URL(req.url, 'http://x');
        // THE CLIENT CERTIFICATE PRESENTED (#931): its x5t#S256 on the
        // mutual-TLS listener, '' on the others and when none was sent.
        const peer = req.socket &&
          typeof req.socket.getPeerCertificate === 'function'
          ? req.socket.getPeerCertificate() : null;
        const cert = peer && peer.raw
          ? nodeCrypto.createHash('sha256').update(peer.raw)
              .digest('base64url') : '';
        op.calls.push({ path: url.pathname, body: body,
                        auth: String(req.headers.authorization || ''),
                        dpop: String(req.headers.dpop || ''), cert: cert });
        // EVERY jti A CLIENT ASSERTION OR A REQUEST OBJECT CARRIES (#931's
        // first run), across the whole child: the suite refuses a second
        // sight of either (CheckForClientAssertionJtiReuse,
        // ValidateRequestObjectJti).
        const sentForm = new URLSearchParams(body);
        ['client_assertion', 'request'].forEach(function (name) {
          const sentJwt = jwtClaimsOf(sentForm.get(name));
          if (sentJwt) {
            op.jtis.push({ path: url.pathname, kind: name,
                           jti: String(sentJwt.jti || '') });
          }
        });
        // A PARTNER THAT DEMANDS DPoP NONCES (#931's first run): the
        // authorization server's at the push and the token endpoint, in
        // the body (RFC 9449 section 8), and UserInfo's own, in
        // WWW-Authenticate with the scheme spelt as the suite's
        // rs-dpop-auth-scheme-case-insensitivity module spells it
        // (section 9). `demand.rt` limits the refresh check to this case's
        // token, and UserInfo's to the tokens it issues.
        const demand = op.scenario.demand;
        const sentProof = jwtClaimsOf(req.headers.dpop) || {};
        const proofNonce = String(sentProof.nonce || '');
        const sentRt = sentForm.get('refresh_token');
        const asDemanded = demand &&
          (/\/par$/.test(url.pathname) ||
           (/\/token$/.test(url.pathname) &&
            (!sentRt || sentRt === demand.rt)));
        if (asDemanded && proofNonce !== demand.as) {
          res.writeHead(400, { 'Content-Type': 'application/json',
                               'DPoP-Nonce': demand.as });
          res.end(JSON.stringify({ error: 'use_dpop_nonce' }));
          return;
        }
        const presentedAt = String(req.headers.authorization || '')
          .replace(/^(Bearer|DPoP) /, '');
        if (demand && /\/userinfo$/.test(url.pathname) &&
            (presentedAt === 'at-back' ||
             presentedAt === 'at-' + demand.rt) &&
            proofNonce !== demand.rs) {
          res.writeHead(401, {
            'WWW-Authenticate': 'dPoP error="use_dpop_nonce", ' +
              'error_description="Resource server requires nonce in DPoP ' +
              'proof"',
            'DPoP-Nonce': demand.rs });
          res.end();
          return;
        }
        const send = function (status, json) {
          res.writeHead(status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(json));
        };
        const s = op.scenario;
        if (/openid-configuration$/.test(url.pathname)) {
          return send(200, Object.assign({
            issuer: s.issuer,
            registration_endpoint: s.base + 'register',
            authorization_endpoint: s.base + 'disco-authorize',
            token_endpoint: s.base + 'token', jwks_uri: s.base + 'jwks',
            userinfo_endpoint: s.base + 'userinfo' }, s.discovery || {}));
        }
        if (url.pathname === '/.well-known/webfinger') {
          op.webfinger = url.searchParams.get('resource');
          return send(200, { subject: op.webfinger, links: [
            { rel: 'http://openid.net/specs/connect/1.0/issuer',
              href: s.webfingerIssuer } ] });
        }
        if (/\/register$/.test(url.pathname)) {
          op.registered = JSON.parse(body || '{}');
          op.registrations = (op.registrations || 0) + 1;
          return send(201, Object.assign({}, op.registered,
            // A SECRET WITH WHAT FORM-ENCODING CHANGES (#930), as the
            // suite's registrations hand out: 7g decodes the Basic header
            // a token request carries against it.
            { client_id: 'dyn-' + op.registrations,
              client_secret: 'dyn %+:<\u00e9/secret-' +
                             op.registrations }));
        }
        if (/\/jwks$/.test(url.pathname)) {
          return send(200, { keys: [jwk] });
        }
        if (/\/par$/.test(url.pathname)) {
          op.par = new URLSearchParams(body);
          // The call was recorded above, so the first push of a cleared
          // list is posts === 1. A nonce answer cannot use send(): that
          // helper sets only Content-Type, and the retry reads DPoP-Nonce.
          const posts = op.calls.filter(function (c) {
            return /\/par$/.test(c.path);
          }).length;
          if (s.parNonce && posts === 1) {
            res.writeHead(400, { 'Content-Type': 'application/json',
                                 'DPoP-Nonce': String(s.parNonce) });
            res.end(JSON.stringify({ error: 'use_dpop_nonce' }));
            return;
          }
          if (s.parRefuse) {
            return send(400, { error: 'invalid_request' });
          }
          return send(200, { request_uri: s.base + 'pushed',
                             expires_in: 90 });
        }
        if (/\/token$/.test(url.pathname)) {
          // A token request carrying a DPoP proof is answered as a bound
          // token (RFC 9449 section 5) unless a case chooses the type.
          const boundType = req.headers.dpop ? 'DPoP' : 'Bearer';
          // A refresh answers by the token it was sent, so each held
          // session keeps its own case whatever order they are refreshed in.
          if (/grant_type=refresh_token/.test(body)) {
            const rt = new URLSearchParams(body).get('refresh_token');
            const how = op.byToken[rt] || {};
            return how.refuse
              ? send(400, { error: 'invalid_grant' })
              : send(200, { access_token: 'at-' + rt,
                            token_type: how.tokenType || boundType,
                            refresh_token: rt,
                            id_token: sign(how.claims()) });
          }
          // A CERTIFICATE-BOUND TOKEN (RFC 8705 section 3, #931): a token
          // requested over mutual TLS is bound to that certificate, and
          // UserInfo answers it only over the same one.
          let issued = 'at-back';
          if (s.bindMtls && cert) {
            op.boundCount = (op.boundCount || 0) + 1;
            issued = 'at-mtls-' + op.boundCount;
            op.bound[issued] = cert;
          }
          return send(200, { access_token: issued,
                             token_type: s.tokenType || boundType,
                             refresh_token: s.rt || 'rt-none',
                             id_token: sign(s.backClaims()) });
        }
        if (/\/userinfo$/.test(url.pathname)) {
          op.bearer = String(req.headers.authorization || '');
          const presented = op.bearer.replace(/^(Bearer|DPoP) /, '');
          if (op.bound[presented] !== undefined &&
              op.bound[presented] !== cert) {
            op.boundRefused = (op.boundRefused || 0) + 1;
            return send(401, { error: 'invalid_token' });
          }
          if (op.bound[presented] !== undefined) {
            op.boundAnswered = (op.boundAnswered || 0) + 1;
          }
          return send(200, Object.assign({ sub: 'frp-person' },
                                         s.userinfo || {}));
        }
        return send(404, { error: 'not_found' });
      });
    });
    await new Promise(function (r) {
      partner.listen(0, '127.0.0.1', r);
    });
    const opBase = 'http://127.0.0.1:' + partner.address().port + '/op/';
    // THE SAME PARTNER OVER TLS, for WebFinger, which is https only: a
    // certificate made here (verification is off for it below, as
    // development's federation.outboundSkipTlsVerification allows).
    const x509 = require(ROOT_DIR + '/common/crypto_impl/x509');
    const keyMaterial = require(ROOT_DIR + '/common/crypto_impl/key_material');
    const tlsPair = await keyMaterial.generateKeyPair('ec-p256');
    const tlsCert = await x509.issueCertificate({
      subject: [{ name: 'CN', value: '127.0.0.1' }],
      subjectPublicKey: tlsPair.publicPem,
      issuerPrivateKey: tlsPair.privatePem, signatureAlg: 'sha256-ecdsa',
      serial: nodeCrypto.randomBytes(8).toString('hex'),
      notBefore: new Date(Date.now() - 60000).toISOString(),
      notAfter: new Date(Date.now() + 3600000).toISOString(),
      extensions: { basicConstraints: { present: true, critical: true,
                                        ca: false } } });
    const tlsPartner = require('https').createServer(
      { key: tlsPair.privatePem, cert: tlsCert.pem },
      partner.listeners('request')[0]);
    await new Promise(function (r) {
      tlsPartner.listen(0, '127.0.0.1', r);
    });
    const tlsHost = '127.0.0.1:' + tlsPartner.address().port;
    // AND OVER MUTUAL TLS (#931): the same partner asking for a client
    // certificate, as a FAPI 1.0 Advanced authorization server's token and
    // UserInfo endpoints do. It verifies nothing about the chain itself:
    // what it records is which certificate came, which is the claim.
    const mtlsPartner = require('https').createServer(
      { key: tlsPair.privatePem, cert: tlsCert.pem, requestCert: true,
        rejectUnauthorized: false },
      partner.listeners('request')[0]);
    await new Promise(function (r) {
      mtlsPartner.listen(0, '127.0.0.1', r);
    });
    const mtlsBase = 'https://127.0.0.1:' + mtlsPartner.address().port +
                     '/op/';

    // --- the service ---------------------------------------------------------
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const call = function (method, p, form, jar) {
      const body = form ? new URLSearchParams(form).toString() : undefined;
      return screen.call({ port: port, jar: jar || {}, method: method,
        path: p, body: body,
        headers: form ? { 'content-type':
                          'application/x-www-form-urlencoded' } : {} });
    };
    const coded = function (code) {
      return audit.list().filter(function (row) {
        return row.errorCode === code;
      }).length;
    };
    config.setOverride('federation.enabled', 'true');
    config.setOverride('federation.outboundAllowHttp', 'true');
    config.setOverride('federation.outboundSkipTlsVerification', 'true');
    const stamp = String(Date.now()).slice(-6);
    const make = function (id, fields) {
      const made = federation.create({ fedId: id, fedRole: 'service-provider',
                                       fedProtocol: 'oidc', fedPeer: opBase });
      const all = Object.assign({ fedPeer: opBase, fedClientId: 'frp-client',
        fedClientSecret: 'frp-secret-' + stamp, fedAutocreateUsers: 'TRUE',
        fedSsoUrl: opBase + 'authorize', fedTokenUrl: opBase + 'token',
        fedJwksUri: opBase + 'jwks', fedUserinfoUrl: opBase + 'userinfo',
        fedScope: 'openid profile email' }, fields || {});
      const results = [made];
      Object.keys(all).forEach(function (field) {
        if (all[field] === null) {
          return;
        }
        results.push(federation.update(id, { field: field,
                                             value: String(all[field]) }));
      });
      results.push(federation.update(id, { field: 'fedEnabled',
                                           value: 'TRUE' }));
      return results.every(function (one) {
        return one && one.ok;
      }) ? id : JSON.stringify(results.filter(function (one) {
        return !one || !one.ok;
      }));
    };
    // The authorization request the login endpoint sends the browser with.
    const begin = async function (id, jar) {
      const r = await call('GET', '/federation/login/' + id, null, jar);
      const at = new URL(String(r.headers.location || 'http://x/'));
      return { status: r.status, location: String(r.headers.location || ''),
               params: at.searchParams };
    };
    const claims = function (started, extra) {
      const now = Math.floor(Date.now() / 1000);
      return Object.assign({ iss: opBase, sub: 'frp-person',
        aud: 'frp-client', iat: now, exp: now + 300,
        nonce: started.params.get('nonce') }, extra || {});
    };
    const without = function (object, name) {
      const out = Object.assign({}, object);
      delete out[name];
      return out;
    };

    // --- 1. the code flow ----------------------------------------------------
    const CODE = make('frp-code-' + stamp);
    note(CODE === 'frp-code-' + stamp, '0. a code-flow relationship', CODE);
    const codeCase = async function (what, back, userinfo, code) {
      const jar = {};
      const started = await begin(CODE, jar);
      op.calls = [];
      op.scenario = { backClaims: function () {
        return back(started);
      }, userinfo: userinfo };
      const before = code ? coded(code) : 0;
      const r = await call('GET', '/federation/acs/' + CODE + '?state=' +
        encodeURIComponent(started.params.get('state')) + '&code=c-1', null,
        jar);
      const asked = op.calls.map(function (c) {
        return c.path;
      });
      return { r: r, asked: asked, coded: code ? coded(code) - before : 0,
               started: started };
    };
    let got = await codeCase('good', function (s) {
      return claims(s);
    });
    note(got.r.status < 400 && got.asked.indexOf('/op/userinfo') >= 0 &&
         got.started.params.get('code_challenge'),
         '1a. a good ID Token signs in, and UserInfo is asked',
         got.r.status + ' ' + JSON.stringify(got.asked) + ' ' +
         got.r.text.slice(0, 300));
    const refusals = [
      ['1b. no sub', function (s) {
        return without(claims(s), 'sub');
      }, 'STS-FED-0195'],
      ['1c. no iat', function (s) {
        return without(claims(s), 'iat');
      }, 'STS-FED-0196'],
      ['1d. an azp that is not this client', function (s) {
        return claims(s, { azp: 'somebody-else' });
      }, 'STS-FED-0197'],
      ['1e. two audiences and no azp', function (s) {
        return claims(s, { aud: ['frp-client', 'another'] });
      }, 'STS-FED-0197'],
      ['1f. no nonce', function (s) {
        return without(claims(s), 'nonce');
      }, 'STS-FED-0198'],
      ['1g. another nonce', function (s) {
        return claims(s, { nonce: 'n-not-this-one' });
      }, 'STS-FED-0039'],
      // OpenID Connect Core 3.1.3.7 step 10 (#931's first run: the FAPI
      // 1.0 Advanced plan's iat-is-week-in-past module).
      ['1h. issued a week before the sign-in began', function (s) {
        return claims(s, { iat: Math.floor(Date.now() / 1000) - 604800 });
      }, 'STS-FED-0253'],
      ['1i. issued an hour in the future', function (s) {
        return claims(s, { iat: Math.floor(Date.now() / 1000) + 3600 });
      }, 'STS-FED-0253']
    ];
    for (const one of refusals) {
      got = await codeCase(one[0], one[1], null, one[2]);
      note(got.r.status === 401 && got.coded === 1 &&
           got.asked.indexOf('/op/userinfo') < 0,
           one[0] + ': refused (' + one[2] + ') and UserInfo never asked',
           got.r.status + ' ' + got.coded + ' ' + JSON.stringify(got.asked) +
           ' ' + got.r.text.slice(0, 200));
    }
    got = await codeCase('userinfo', function (s) {
      return claims(s);
    }, { sub: 'somebody-else' }, 'STS-FED-0202');
    note(got.r.status === 401 && got.coded === 1,
         '1h. UserInfo answering for another sub is refused (STS-FED-0202)',
         got.r.status + ' ' + got.coded);

    federation.update(CODE, { field: 'fedIdTokenSignedResponseAlg',
                              value: 'ES256' });
    got = await codeCase('registered alg', function (s) {
      return claims(s);
    }, null, 'STS-FED-0208');
    note(got.r.status === 401 && got.coded === 1 &&
         got.asked.indexOf('/op/userinfo') < 0,
         '1i. an ID Token under another algorithm than ' +
         'fedIdTokenSignedResponseAlg is refused (STS-FED-0208)',
         got.r.status + ' ' + got.coded);
    federation.update(CODE, { field: 'fedIdTokenSignedResponseAlg',
                              value: 'RS256' });
    got = await codeCase('registered alg', function (s) {
      return claims(s);
    });
    note(got.r.status < 400, '1j. and accepted under the registered one',
         got.r.status);
    const actions = require(ROOT_DIR + '/admin-core/admin_actions');
    op.scenario = {};
    const checked = await actions.federationAction(
      { action: 'check-partner', id: CODE });
    note(checked.ok && checked.keys === 1 && checked.readable === 1 &&
         checked.discovered === false &&
         !('errorCode' in checked) &&
         checked.endpoints.jwks_uri === opBase + 'jwks',
         '1k. check-partner reads the partner\'s key set and reports it',
         JSON.stringify(checked));

    // --- 2. hybrid -----------------------------------------------------------
    const HYBRID = make('frp-hyb-' + stamp,
                        { fedResponseType: 'code id_token' });
    const hybridCase = async function (front, back, code) {
      const jar = {};
      const started = await begin(HYBRID, jar);
      op.calls = [];
      op.scenario = { backClaims: function () {
        return back(started);
      } };
      const before = code ? coded(code) : 0;
      const r = await call('POST', '/federation/acs/' + HYBRID, {
        state: started.params.get('state'), code: 'c-hybrid',
        id_token: sign(front(started)) }, jar);
      return { r: r, started: started,
               coded: code ? coded(code) - before : 0,
               asked: op.calls.map(function (c) {
                 return c.path;
               }) };
    };
    got = await hybridCase(function (s) {
      return claims(s, { c_hash: halfHash('c-hybrid') });
    }, function (s) {
      return claims(s);
    });
    note(got.r.status < 400 && got.asked.indexOf('/op/token') >= 0 &&
         got.started.params.get('response_type') === 'code id_token' &&
         got.started.params.get('response_mode') === 'form_post' &&
         got.started.params.get('code_challenge_method') === 'S256',
         '2a. code id_token: PKCE and form_post asked, a good c_hash ' +
         'signs in after the code is redeemed',
         got.r.status + ' ' + got.started.location + ' ' +
         JSON.stringify(got.asked) + ' ' + got.r.text.slice(0, 200));
    got = await hybridCase(function (s) {
      return claims(s);
    }, function (s) {
      return claims(s);
    }, 'STS-FED-0199');
    note(got.r.status === 401 && got.coded === 1 &&
         got.asked.indexOf('/op/token') < 0,
         '2b. no c_hash: refused (STS-FED-0199) and the code never redeemed',
         got.r.status + ' ' + got.coded + ' ' + JSON.stringify(got.asked));
    got = await hybridCase(function (s) {
      return claims(s, { c_hash: halfHash('another code') });
    }, function (s) {
      return claims(s);
    }, 'STS-FED-0199');
    note(got.r.status === 401 && got.coded === 1,
         '2c. a c_hash of another code: refused (STS-FED-0199)',
         got.r.status + ' ' + got.coded);
    got = await hybridCase(function (s) {
      return claims(s, { c_hash: halfHash('c-hybrid') });
    }, function (s) {
      return claims(s, { sub: 'somebody-else' });
    }, 'STS-FED-0201');
    note(got.r.status === 401 && got.coded === 1,
         '2d. the token endpoint\'s ID Token naming another sub: refused ' +
         '(STS-FED-0201)', got.r.status + ' ' + got.coded);

    // --- 3. implicit, in the fragment mode -----------------------------------
    const IMPLICIT = make('frp-imp-' + stamp,
                          { fedResponseType: 'id_token token',
                            fedResponseMode: 'fragment' });
    let r = await call('GET', '/federation/acs/' + IMPLICIT);
    const csp = String(r.headers['content-security-policy'] || '');
    note(r.status === 200 &&
         r.text.indexOf('<script src="/federation/fragment.js"></script>') >
           0 && r.text.indexOf('id="fed-fragment"') > 0 &&
         /script-src 'self'/.test(csp) && /frame-ancestors/.test(csp) &&
         /no-store/.test(String(r.headers['cache-control'])),
         '3a. the bare GET is answered with the fragment page and its one ' +
         'script', r.status + ' ' + csp + ' ' + r.text.slice(0, 300));
    r = await call('GET', '/federation/fragment.js');
    note(r.status === 200 &&
         /javascript/.test(String(r.headers['content-type'])) &&
         r.text.indexOf('fed-fragment') > 0 &&
         r.text.indexOf('replaceState') > 0,
         '3b. the script is served', r.status);
    r = await call('GET', '/federation/acs/' + CODE);
    note(r.status !== 200 || r.text.indexOf('fragment.js') < 0,
         '3c. a relationship that did not choose the fragment mode never ' +
         'answers with the page', r.status);
    const implicitCase = async function (front, access, code) {
      const jar = {};
      const started = await begin(IMPLICIT, jar);
      op.calls = [];
      op.bearer = '';
      op.scenario = {};
      const before = code ? coded(code) : 0;
      const resp = await call('POST', '/federation/acs/' + IMPLICIT, {
        state: started.params.get('state'), access_token: access,
        token_type: 'Bearer', id_token: sign(front(started)) }, jar);
      return { r: resp, started: started,
               coded: code ? coded(code) - before : 0,
               asked: op.calls.map(function (c) {
                 return c.path;
               }) };
    };
    got = await implicitCase(function (s) {
      return claims(s, { at_hash: halfHash('another token') });
    }, 'at-front', 'STS-FED-0200');
    note(got.r.status === 401 && got.coded === 1 &&
         got.started.params.get('response_mode') === null &&
         got.asked.indexOf('/op/userinfo') < 0,
         '3d. id_token token by fragment: no response_mode asked, and a ' +
         'wrong at_hash refused (STS-FED-0200) before UserInfo',
         got.r.status + ' ' + got.coded + ' ' + got.started.location);
    got = await implicitCase(function (s) {
      return without(claims(s), 'nonce');
    }, 'at-front', 'STS-FED-0198');
    note(got.r.status === 401 && got.coded === 1,
         '3e. a front-channel ID Token with no nonce: refused (STS-FED-0198)',
         got.r.status + ' ' + got.coded);
    got = await implicitCase(function (s) {
      return claims(s, { at_hash: halfHash('at-front') });
    }, 'at-front');
    note(got.r.status < 400 && op.bearer === 'Bearer at-front',
         '3f. a right at_hash signs in, asking UserInfo with the front ' +
         'access token', got.r.status + ' ' + op.bearer + ' ' +
         got.r.text.slice(0, 200));
    const QUERY = make('frp-query-' + stamp,
                       { fedResponseType: 'id_token token',
                         fedResponseMode: 'query' });
    const ready = federation.readinessOf(federation.get(QUERY));
    note(!ready.ready && ready.missing.some(function (one) {
      return /fedResponseMode/.test(one);
    }), '3g. id_token token with fedResponseMode=query is not ready',
         JSON.stringify(ready));

    // --- 4. discovery --------------------------------------------------------
    const DISCO = make('frp-disco-' + stamp,
                       { fedDiscovery: 'TRUE', fedSsoUrl: null,
                         fedTokenUrl: null, fedJwksUri: null,
                         fedUserinfoUrl: null });
    note(federation.readinessOf(federation.get(DISCO)).ready,
         '4a. a discovering relationship is ready with no endpoint written',
         JSON.stringify(federation.readinessOf(federation.get(DISCO))));
    op.calls = [];
    op.scenario = { issuer: opBase, base: opBase };
    let started = await begin(DISCO, {});
    note(started.status === 302 &&
         started.location.indexOf(opBase + 'disco-authorize?') === 0 &&
         op.calls.some(function (c) {
           return c.path === '/op/.well-known/openid-configuration';
         }),
         '4b. the sign-in reads the discovery document and goes to the ' +
         'authorization endpoint it names', started.status + ' ' +
         started.location);
    op.scenario = { issuer: opBase + 'someone-else/', base: opBase };
    let before = coded('STS-FED-0204');
    started = await begin(DISCO, {});
    note(started.status === 502 && coded('STS-FED-0204') === before + 1,
         '4c. a document naming another issuer is refused (STS-FED-0204)',
         started.status);

    // --- 6. refresh tokens ---------------------------------------------------
    const fedSp = require(ROOT_DIR + '/federation/federation_sp');
    const REFRESH = make('frp-ref-' + stamp, { fedRefreshTokens: 'TRUE',
                                               fedRefreshEverySeconds: '1' });
    const fresh = function () {
      const now = Math.floor(Date.now() / 1000);
      return { iss: opBase, sub: 'frp-person', aud: 'frp-client', iat: now,
               exp: now + 300 };
    };
    const refreshCase = async function (rt, how) {
      const jar = {};
      const started = await begin(REFRESH, jar);
      op.byToken[rt] = how;
      op.scenario = { rt: rt, backClaims: function () {
        return claims(started);
      } };
      await call('GET', '/federation/acs/' + REFRESH + '?state=' +
        encodeURIComponent(started.params.get('state')) + '&code=c-r', null,
        jar);
      op.calls = [];
      return fedSp.refreshDue(Date.now() + 5000);
    };
    const bearers = function () {
      return op.calls.filter(function (c) {
        return c.path === '/op/userinfo';
      }).map(function (c) {
        return c.auth;
      });
    };
    let counts = await refreshCase('rt-good', { claims: fresh });
    note(counts.refreshed === 1 && counts.ended === 0 &&
         bearers().indexOf('Bearer at-rt-good') >= 0,
         '6a. a held refresh token is refreshed when due, and UserInfo asked ' +
         'with the new access token', JSON.stringify(counts) + ' ' +
         JSON.stringify(bearers()));
    before = coded('STS-FED-0211');
    counts = await refreshCase('rt-iss', { claims: function () {
      return Object.assign(fresh(), { iss: 'https://another.example/' });
    } });
    note(counts.ended === 1 && coded('STS-FED-0211') === before + 1 &&
         bearers().indexOf('Bearer at-rt-iss') < 0,
         '6b. a refreshed ID Token naming another iss ends the session ' +
         '(STS-FED-0211), and UserInfo is not asked for it',
         JSON.stringify(counts) + ' ' + JSON.stringify(bearers()));
    before = coded('STS-FED-0210');
    counts = await refreshCase('rt-refused', { refuse: true });
    note(counts.ended === 1 && coded('STS-FED-0210') === before + 1,
         '6c. a refresh the partner refuses ends the session (STS-FED-0210)',
         JSON.stringify(counts));
    counts = await fedSp.refreshDue(Date.now() + 5000);
    note(counts.refreshed === 1 && counts.ended === 0,
         '6d. an ended session\'s token is gone: only the live one is ' +
         'refreshed again', JSON.stringify(counts));

    // --- 7. self-registration and Request Objects -------------------------
    const stateOf = function (text) {
      const m = /<html[^>]* data-sts-state="([^"]*)"/.exec(String(text || ''));
      return m ? JSON.parse(m[1].replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')) : null;
    };
    const DYN = make('frp-dyn-' + stamp, { fedDiscovery: 'TRUE',
      fedRegister: 'TRUE', fedRequestObject: 'request_uri',
      fedRequestObjectSigningAlg: 'RS256', fedClientId: null,
      fedClientSecret: null, fedSsoUrl: null, fedTokenUrl: null,
      fedJwksUri: null, fedUserinfoUrl: null });
    note(federation.readinessOf(federation.get(DYN)).ready,
         '7a. a registering relationship is ready with no client written',
         JSON.stringify(federation.readinessOf(federation.get(DYN))));
    op.scenario = { issuer: opBase, base: opBase };
    started = await begin(DYN, {});
    const dyn = federation.get(DYN);
    const md = op.registered || {};
    const registeredKey = ((md.jwks || {}).keys || [])[0] || {};
    note(started.status === 302 && dyn.fedClientId === 'dyn-1' &&
         dyn.fedRegisteredIssuer === opBase &&
         started.params.get('client_id') === 'dyn-1' &&
         md.request_object_signing_alg === 'RS256' &&
         registeredKey.kty === 'RSA' && !registeredKey.d &&
         (md.redirect_uris || [])[0] ===
           'http://127.0.0.1:' + port + '/federation/acs/' + DYN,
         '7b. the sign-in registers the relationship at the partner, keeps ' +
         'the client it is given, and registers one public RSA key',
         started.status + ' ' + dyn.fedClientId + ' ' +
         JSON.stringify(md).slice(0, 400));
    const requestUri = String(started.params.get('request_uri') || '');
    r = await call('GET', requestUri);
    const parts = r.text.split('.');
    const claimsOf = parts.length === 3
      ? JSON.parse(Buffer.from(parts[1], 'base64url').toString()) : {};
    const verifies = parts.length === 3 && nodeCrypto.verify('sha256',
      Buffer.from(parts[0] + '.' + parts[1]),
      nodeCrypto.createPublicKey({ key: registeredKey, format: 'jwk' }),
      Buffer.from(parts[2], 'base64url'));
    note(r.status === 200 &&
         /oauth-authz-req\+jwt/.test(String(r.headers['content-type'])) &&
         verifies && claimsOf.iss === 'dyn-1' && claimsOf.aud === opBase &&
         claimsOf.client_id === 'dyn-1' &&
         claimsOf.state === started.params.get('state') &&
         claimsOf.nonce === started.params.get('nonce'),
         '7c. the Request Object at request_uri carries the request, ' +
         'verifies with the registered key, iss the client and aud the ' +
         'partner', r.status + ' ' + JSON.stringify(claimsOf).slice(0, 300));
    before = coded('STS-FED-0218');
    r = await call('GET', requestUri);
    note(r.status === 404 && coded('STS-FED-0218') === before + 1,
         '7d. a Request Object is answered once (STS-FED-0218)', r.status);
    started = await begin(DYN, {});
    note(op.registrations === 1,
         '7e. a relationship already registered with this issuer does not ' +
         'register again', String(op.registrations));
    federation.update(DYN, { field: 'fedRequestObjectSigningAlg',
                             value: 'none' });
    const rereg = await actions.federationAction(
      { action: 'register-partner', id: DYN,
        base: 'http://127.0.0.1:' + port });
    started = await begin(DYN, {});
    r = await call('GET', String(started.params.get('request_uri') || ''));
    note(rereg.ok && op.registrations === 2 &&
         op.registered.request_object_signing_alg === 'none' &&
         !op.registered.jwks && /\.$/.test(r.text) &&
         JSON.parse(Buffer.from(r.text.split('.')[0], 'base64url')
           .toString()).alg === 'none',
         '7f. register-partner registers again; an unsigned Request Object ' +
         'registers no key and is sent alg none',
         JSON.stringify(rereg) + ' ' + r.text.slice(0, 80));

    // --- 7g. the registered client's Basic credentials --------------------
    // RFC 6749 section 2.3.1: id and secret each form-urlencoded, then
    // joined and base64-encoded. Sent raw, the suite's URLDecoder refused
    // a secret holding `%` ("Incomplete trailing escape") and its
    // ValidateClientIdAndSecret failed the rest (2026-11-03).
    const regd = federation.get(DYN);
    const issued = federation.clientSecretOf(regd);
    const callsBefore = op.calls.length;
    await require(ROOT_DIR + '/federation/federation_http').fetchJson(
      Object.assign({}, regd, { fedTokenUrl: opBase + 'basic-probe' }),
      'fedTokenUrl', { method: 'POST', form: { grant_type: 'probe' },
                       basic: { user: regd.fedClientId, pass: issued } });
    const probe = op.calls.slice(callsBefore).filter(function (c) {
      return /basic-probe$/.test(c.path);
    })[0] || { auth: '' };
    const joined = Buffer.from(probe.auth.replace(/^Basic /, ''), 'base64')
      .toString('utf8');
    const colon = joined.indexOf(':');
    const formDecoded = function (v) {
      return decodeURIComponent(String(v).replace(/\+/g, ' '));
    };
    let decodedId = '';
    let decodedSecret = '';
    try {
      decodedId = formDecoded(joined.slice(0, colon));
      decodedSecret = formDecoded(joined.slice(colon + 1));
    } catch (e) {
      decodedSecret = 'undecodable: ' + ((e && e.message) || e);
    }
    note(/[%+:<\u00e9 ]/.test(issued) && colon > 0 &&
         decodedId === regd.fedClientId && decodedSecret === issued &&
         joined.slice(colon + 1).indexOf(':') < 0,
         '7g. a registered client\'s Basic header form-urlencodes the id and ' +
         'the secret (RFC 6749 section 2.3.1), so a secret holding % + : < ' +
         'and a space decodes to itself',
         JSON.stringify({ issued: issued, joined: joined,
                          decoded: [decodedId, decodedSecret] }));

    // --- 8. WebFinger from a typed identifier --------------------------------
    before = coded('STS-FED-0215');
    r = await call('GET', '/federation/webfinger/' + DYN + '?resource=' +
                   encodeURIComponent('acct:a@' + tlsHost));
    note(r.status === 403 && coded('STS-FED-0215') === before + 1,
         '8a. off by default: refused (STS-FED-0215)', r.status);
    federation.update(DYN, { field: 'fedWebFinger', value: 'TRUE' });
    r = await call('GET', '/federation/webfinger/' + DYN);
    let view = (stateOf(r.text) || {}).view || {};
    note(r.status === 200 && view.kind === 'webfinger' &&
         view.step === 'ask',
         '8b. the page asks for an identifier', r.status + ' ' +
         JSON.stringify(view));
    op.scenario = { issuer: opBase + 'tenant7', base: opBase,
                    webfingerIssuer: opBase + 'tenant7' };
    op.calls = [];
    r = await call('GET', '/federation/webfinger/' + DYN + '?resource=' +
                   encodeURIComponent('a@' + tlsHost));
    view = (stateOf(r.text) || {}).view || {};
    note(r.status === 200 && view.step === 'found' &&
         view.issuer === opBase + 'tenant7' &&
         op.webfinger === 'acct:a@' + tlsHost &&
         op.calls.some(function (c) {
           return c.path === '/op/tenant7/.well-known/openid-configuration';
         }) && !op.calls.some(function (c) {
           return /authorize|register/.test(c.path);
         }),
         '8c. an address is looked up as acct:, the issuer found and its ' +
         'discovery document read, and nothing goes on by itself',
         r.status + ' ' + JSON.stringify(view));
    const registeredBefore = op.registrations;
    r = await call('GET', String(view.continueHref || ''));
    note(r.status === 302 &&
         String(r.headers.location).indexOf(opBase + 'disco-authorize') ===
           0 && op.registrations === registeredBefore + 1 &&
         federation.get(DYN).fedRegisteredIssuer === opBase + 'tenant7',
         '8d. continuing signs in at that issuer, registering there first',
         r.status + ' ' + r.headers.location);
    op.scenario.webfingerIssuer = 'https://elsewhere.example/';
    before = coded('STS-FED-0217');
    r = await call('GET', '/federation/webfinger/' + DYN + '?resource=' +
                   encodeURIComponent('https://' + tlsHost + '/x'));
    note(r.status === 403 && coded('STS-FED-0217') === before + 1,
         '8e. an issuer outside fedPeer is refused (STS-FED-0217)',
         r.status);

    // --- 9. the WebFinger bound is parsed, never a string prefix ----------
    const within = require(ROOT_DIR + '/federation/federation_sp')
      .issuerWithin;
    const bounds = [
      ['https://op.example', 'https://op.example', true],
      ['https://op.example', 'https://op.example/', true],
      ['https://op.example', 'https://OP.example/tenant/a', true],
      ['https://op.example', 'https://op.example:443/x', true],
      ['https://op.example/tenant', 'https://op.example/tenant', true],
      ['https://op.example/tenant/', 'https://op.example/tenant/7', true],
      ['https://op.example', 'https://op.example.evil.com', false],
      ['https://op.example', 'https://op.example:8443', false],
      ['https://op.example', 'https://op.example@evil.com', false],
      ['https://op.example', 'https://u:p@op.example/x', false],
      ['https://op.example/tenant', 'https://op.example/tenant2', false],
      ['https://op.example/tenant', 'https://op.example/tenant/../x', false],
      ['https://op.example', 'http://op.example', false],
      ['https://op.example', 'https://op.example/x?a=1', false],
      ['https://op.example', 'https://op.example/x#f', false],
      ['https://op.example', 'not a url', false]];
    bounds.forEach(function (one) {
      note(within(one[1], one[0]) === one[2],
           '9. ' + one[1] + ' is ' + (one[2] ? '' : 'NOT ') + 'within ' +
           one[0], String(within(one[1], one[0])));
    });
    // And through the endpoint: fedPeer `http://127.0.0.1` and an issuer on
    // another port of that host, which a string prefix admits — a real
    // partner answering there, so only the bound can refuse it.
    const BOUND = make('frp-bound-' + stamp, { fedDiscovery: 'TRUE',
      fedWebFinger: 'TRUE', fedPeer: 'http://127.0.0.1', fedSsoUrl: null,
      fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null });
    op.scenario = { webfingerIssuer: opBase, issuer: opBase, base: opBase };
    before = coded('STS-FED-0217');
    r = await call('GET', '/federation/webfinger/' + BOUND + '?resource=' +
                   encodeURIComponent('a@' + tlsHost));
    note(BOUND === 'frp-bound-' + stamp &&
         federation.get(BOUND).fedPeer === 'http://127.0.0.1' &&
         r.status === 403 && coded('STS-FED-0217') === before + 1,
         '9b. an issuer on another port of fedPeer\'s host is refused ' +
         '(STS-FED-0217)', r.status + ' ' + BOUND + ' ' +
         federation.get(BOUND).fedPeer);

    // --- 5. the login initiation endpoint ------------------------------------
    before = coded('STS-FED-0205');
    r = await call('GET', '/federation/initiate-login/' + CODE + '?iss=' +
                   encodeURIComponent(opBase));
    note(r.status === 403 && coded('STS-FED-0205') === before + 1,
         '5a. off by default: refused (STS-FED-0205)', r.status);
    federation.update(CODE, { field: 'fedInitiateLogin', value: 'TRUE' });
    before = coded('STS-FED-0206');
    r = await call('GET', '/federation/initiate-login/' + CODE + '?iss=' +
                   encodeURIComponent('https://another.example/'));
    note(r.status === 400 && coded('STS-FED-0206') === before + 1,
         '5b. another issuer: refused (STS-FED-0206)', r.status);
    r = await call('POST', '/federation/initiate-login/' + CODE, {
      iss: opBase, login_hint: 'frp@example.org',
      target_link_uri: 'https://elsewhere.example/steal' });
    const sent = new URL(String(r.headers.location || 'http://x/'));
    note(r.status === 302 &&
         String(r.headers.location).indexOf(opBase + 'authorize?') === 0 &&
         sent.searchParams.get('login_hint') === 'frp@example.org',
         '5c. the partner\'s own issuer starts the sign-in, its login_hint ' +
         'passed on and a foreign target dropped', r.status + ' ' +
         r.headers.location);

    // --- 10. a FAPI client (#931) ------------------------------------------
    const jwtParts = function (token) {
      const parts = String(token || '').split('.');
      if (parts.length !== 3) {
        return null;
      }
      return {
        header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
        claims: JSON.parse(Buffer.from(parts[1], 'base64url').toString())
      };
    };
    const parClaims = function () {
      const now = Math.floor(Date.now() / 1000);
      return { iss: opBase, sub: 'frp-person', aud: 'frp-client', iat: now,
               exp: now + 300, nonce: op.par.get('nonce') };
    };
    const SEC = make('frp-fapi2-' + stamp, { fedFapi: '2-security',
      fedDiscovery: 'TRUE', fedSsoUrl: null, fedTokenUrl: null,
      fedJwksUri: null, fedUserinfoUrl: null });
    note(SEC === 'frp-fapi2-' + stamp &&
         federation.readinessOf(federation.get(SEC)).ready,
         '10a. a 2-security relationship is ready with no endpoint written',
         SEC);
    op.calls = [];
    op.par = null;
    op.scenario = { issuer: opBase, base: opBase, discovery: {
      pushed_authorization_request_endpoint: opBase + 'par' },
      backClaims: parClaims };
    const secJar = {};
    started = await begin(SEC, secJar);
    const secKeys = Array.from(started.params.keys()).sort().join(',');
    const secPar = op.par || new URLSearchParams();
    const secAssert = jwtParts(secPar.get('client_assertion'));
    const secProof = jwtParts((op.calls.filter(function (c) {
      return /\/par$/.test(c.path);
    })[0] || {}).dpop);
    note(started.status === 302 && secKeys === 'client_id,request_uri' &&
         started.params.get('client_id') === 'frp-client' &&
         started.params.get('request_uri') === opBase + 'pushed' &&
         secPar.get('response_type') === 'code' &&
         secPar.get('code_challenge_method') === 'S256' &&
         !secPar.get('request') &&
         secAssert && secAssert.header.alg === 'PS256' &&
         secAssert.claims.aud === opBase &&
         secAssert.claims.iss === 'frp-client' &&
         secProof && secProof.header.typ === 'dpop+jwt' &&
         secProof.claims.htm === 'POST',
         '10b. 2-security pushes the request and sends the browser only ' +
         'client_id and request_uri',
         started.status + ' ' + started.location + ' ' + secPar.toString()
           .slice(0, 400));
    op.calls = [];
    r = await call('GET', '/federation/acs/' + SEC + '?state=' +
      encodeURIComponent(secPar.get('state')) + '&code=c-fapi2&iss=' +
      encodeURIComponent(opBase), null, secJar);
    const secToken = op.calls.filter(function (c) {
      return /\/token$/.test(c.path);
    })[0] || { body: '', dpop: '', auth: '' };
    const secForm = new URLSearchParams(secToken.body);
    const secUser = op.calls.filter(function (c) {
      return /\/userinfo$/.test(c.path);
    })[0] || { auth: '' };
    note(r.status < 400 && secForm.get('client_assertion') &&
         !secForm.get('client_secret') && secToken.dpop &&
         secUser.auth.indexOf('DPoP ') === 0,
         '10c. the code is redeemed with private_key_jwt and DPoP, and ' +
         'UserInfo is asked as DPoP',
         r.status + ' ' + secUser.auth + ' ' + secToken.body.slice(0, 240));

    const NODISCO = make('frp-fapi2-off-' + stamp,
                         { fedFapi: '2-security' });
    before = coded('STS-FED-0243');
    op.calls = [];
    started = await begin(NODISCO, {});
    note(NODISCO === 'frp-fapi2-off-' + stamp && started.status === 502 &&
         coded('STS-FED-0243') === before + 1 &&
         !op.calls.some(function (c) {
           return /openid-configuration|\/par$/.test(c.path);
         }),
         '10d. 2-security with fedDiscovery off is refused (STS-FED-0243) ' +
         'and nothing is dialled', started.status + ' ' + NODISCO);

    const NOPAR = make('frp-fapi2-nopar-' + stamp, { fedFapi: '2-security',
      fedDiscovery: 'TRUE', fedSsoUrl: null, fedTokenUrl: null,
      fedJwksUri: null, fedUserinfoUrl: null });
    before = coded('STS-FED-0243');
    op.scenario = { issuer: opBase, base: opBase };
    started = await begin(NOPAR, {});
    note(started.status === 502 && coded('STS-FED-0243') === before + 1,
         '10e. a discovery document with no PAR endpoint is refused ' +
         '(STS-FED-0243)', started.status);

    // --- 10x-10ab. what a 2.x answer is held to (#931's review) -----------
    // The accepted path is 10c: an answer naming the partner's issuer, and
    // a token response the partner answered as DPoP-bound.
    const secStart = async function (extra) {
      const jar = {};
      op.calls = [];
      op.par = null;
      op.scenario = Object.assign({ issuer: opBase, base: opBase,
        discovery: { pushed_authorization_request_endpoint: opBase + 'par' },
        backClaims: parClaims }, extra || {});
      await begin(SEC, jar);
      return { jar: jar,
               state: (op.par || new URLSearchParams()).get('state') };
    };
    const secAnswer = function (flow, query) {
      op.calls = [];
      return call('GET', '/federation/acs/' + SEC + '?state=' +
        encodeURIComponent(flow.state) + '&code=c-sec' + query, null,
        flow.jar);
    };
    const dialled = function (pattern) {
      return op.calls.some(function (c) {
        return pattern.test(c.path);
      });
    };
    let flow = await secStart();
    before = coded('STS-FED-0249');
    r = await secAnswer(flow, '');
    note(flow.state && r.status === 401 &&
         coded('STS-FED-0249') === before + 1 && !dialled(/\/token$/),
         '10x. a 2-security answer naming no issuer is refused ' +
         '(STS-FED-0249) and the code is not redeemed',
         r.status + ' ' + r.text.slice(0, 200));
    flow = await secStart();
    before = coded('STS-FED-0238');
    r = await secAnswer(flow, '&iss=' +
                        encodeURIComponent(opBase + 'someone-else/'));
    note(r.status === 401 && coded('STS-FED-0238') === before + 1 &&
         !dialled(/\/token$/),
         '10y. a 2-security answer naming another issuer is still ' +
         'refused (STS-FED-0238)', r.status);
    flow = await secStart({ tokenType: 'Bearer' });
    before = coded('STS-FED-0251');
    r = await secAnswer(flow, '&iss=' + encodeURIComponent(opBase));
    note(r.status === 502 && coded('STS-FED-0251') === before + 1 &&
         dialled(/\/token$/) && !dialled(/\/userinfo$/),
         '10aa. a 2-security token response answered Bearer is refused ' +
         '(STS-FED-0251) and UserInfo is never asked with it',
         r.status + ' ' + r.text.slice(0, 200));
    flow = await secStart({ tokenType: 'dpop' });
    r = await secAnswer(flow, '&iss=' + encodeURIComponent(opBase));
    const lowerUser = op.calls.filter(function (c) {
      return /\/userinfo$/.test(c.path);
    })[0] || { auth: '' };
    note(r.status < 400 && lowerUser.auth.indexOf('DPoP ') === 0,
         '10ab. token_type is compared without case: dpop signs in and ' +
         'UserInfo is asked as DPoP', r.status + ' ' + lowerUser.auth);

    const ADV = make('frp-fapi1-' + stamp, { fedFapi: '1-advanced' });
    op.calls = [];
    op.par = null;
    const advJar = {};
    started = await begin(ADV, advJar);
    const advReq = jwtParts(started.params.get('request'));
    note(started.status === 302 &&
         started.params.get('response_type') === 'code id_token' &&
         started.params.get('response_mode') === 'form_post' &&
         started.params.get('code_challenge_method') === 'S256' &&
         advReq && advReq.header.alg === 'PS256' &&
         advReq.header.typ === 'oauth-authz-req+jwt' &&
         advReq.claims.response_type === 'code id_token' &&
         !op.calls.some(function (c) {
           return /\/par$/.test(c.path);
         }),
         '10f. 1-advanced puts a PS256 request object on the browser URL ' +
         'and does not push',
         started.status + ' ' + started.location.slice(0, 240));
    op.calls = [];
    op.scenario = { backClaims: function () {
      return claims(started);
    } };
    r = await call('POST', '/federation/acs/' + ADV, {
      state: started.params.get('state'), code: 'c-adv',
      id_token: sign(claims(started, { c_hash: halfHash('c-adv'),
        s_hash: halfHash(started.params.get('state')) }))
    }, advJar);
    const advToken = op.calls.filter(function (c) {
      return /\/token$/.test(c.path);
    })[0] || { body: '', dpop: 'none', auth: '' };
    const advForm = new URLSearchParams(advToken.body);
    const advUser = op.calls.filter(function (c) {
      return /\/userinfo$/.test(c.path);
    })[0] || { auth: '' };
    note(r.status < 400 && advForm.get('client_assertion') &&
         !advToken.dpop && advUser.auth.indexOf('Bearer ') === 0,
         '10g. 1-advanced with the right s_hash redeems with ' +
         'private_key_jwt and no DPoP, and UserInfo stays bearer',
         r.status + ' ' + advUser.auth + ' dpop=' + advToken.dpop);

    // --- 10v, 10w. 1-advanced's s_hash (#931's review) --------------------
    // The accepted path is 10g. Case 2a is the control: a plain hybrid
    // relationship sends no s_hash and still signs in.
    const advHash = async function (extra) {
      const jar = {};
      const begun = await begin(ADV, jar);
      op.calls = [];
      op.scenario = { backClaims: function () {
        return claims(begun);
      } };
      const was = coded('STS-FED-0248');
      const resp = await call('POST', '/federation/acs/' + ADV, {
        state: begun.params.get('state'), code: 'c-adv-h',
        id_token: sign(claims(begun, Object.assign(
          { c_hash: halfHash('c-adv-h') }, extra))) }, jar);
      return { r: resp, coded: coded('STS-FED-0248') - was,
               redeemed: op.calls.some(function (c) {
                 return /\/token$/.test(c.path);
               }) };
    };
    got = await advHash({});
    note(got.r.status === 401 && got.coded === 1 && !got.redeemed,
         '10v. 1-advanced: a front ID Token with no s_hash is refused ' +
         '(STS-FED-0248) and the code is not redeemed',
         got.r.status + ' ' + got.coded + ' ' + got.r.text.slice(0, 200));
    got = await advHash({ s_hash: halfHash('another state') });
    note(got.r.status === 401 && got.coded === 1 && !got.redeemed,
         '10w. 1-advanced: an s_hash of another state is refused ' +
         '(STS-FED-0248)', got.r.status + ' ' + got.coded);

    const MS = make('frp-fapi2ms-' + stamp, {
      fedFapi: '2-message-signing', fedDiscovery: 'TRUE', fedSsoUrl: null,
      fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null });
    op.calls = [];
    op.par = null;
    op.scenario = { issuer: opBase, base: opBase, discovery: {
      pushed_authorization_request_endpoint: opBase + 'par' },
      backClaims: parClaims };
    const msJar = {};
    started = await begin(MS, msJar);
    const msPar = op.par || new URLSearchParams();
    const msReq = jwtParts(msPar.get('request'));
    note(MS === 'frp-fapi2ms-' + stamp && started.status === 302 &&
         started.location.indexOf('request=') < 0 &&
         msReq && msReq.header.alg === 'PS256' &&
         msReq.header.typ === 'oauth-authz-req+jwt' &&
         msReq.claims.response_mode === 'jwt' &&
         msReq.claims.response_type === 'code',
         '10h. message signing puts the request object in the push, not ' +
         'on the browser URL',
         started.status + ' ' + started.location);
    const jarm = sign({ iss: opBase, aud: 'frp-client',
      state: msPar.get('state'), code: 'c-jarm',
      exp: Math.floor(Date.now() / 1000) + 300 });
    op.calls = [];
    r = await call('GET', '/federation/acs/' + MS + '?response=' +
      encodeURIComponent(jarm), null, msJar);
    const msToken = op.calls.filter(function (c) {
      return /\/token$/.test(c.path);
    })[0] || { body: '', dpop: '' };
    const msUser = op.calls.filter(function (c) {
      return /\/userinfo$/.test(c.path);
    })[0] || { auth: '' };
    note(r.status < 400 && /code=c-jarm/.test(msToken.body) &&
         msToken.dpop && msUser.auth.indexOf('DPoP ') === 0,
         '10i. a JARM response is opened and the code inside it redeemed ' +
         'with DPoP',
         r.status + ' ' + msUser.auth + ' ' + msToken.body.slice(0, 200));

    // --- 10j. a push the partner refuses ------------------------------------
    const PARNO = make('frp-fapi-par-' + stamp, {
      fedFapi: '2-security', fedDiscovery: 'TRUE', fedSsoUrl: null,
      fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null });
    before = coded('STS-FED-0244');
    op.calls = [];
    op.scenario = { issuer: opBase, base: opBase, discovery: {
      pushed_authorization_request_endpoint: opBase + 'par' },
      parRefuse: true };
    started = await begin(PARNO, {});
    const refusedPushes = op.calls.filter(function (c) {
      return /\/par$/.test(c.path);
    }).length;
    note(PARNO === 'frp-fapi-par-' + stamp && started.status === 502 &&
         coded('STS-FED-0244') === before + 1 &&
         started.location.indexOf('request_uri') < 0 &&
         refusedPushes === 1,
         '10j. a push the partner refuses stays 502 (STS-FED-0244) and ' +
         'the browser is not redirected',
         started.status + ' ' + started.location + ' pushes=' +
         refusedPushes);

    // --- 10k. DPoP-Nonce on the wire ----------------------------------------
    // withNonce is unit-tested. This is the push: the first answer carries
    // the header, and only the second proof claims that nonce.
    const NONCE = make('frp-fapi-nonce-' + stamp, {
      fedFapi: '2-security', fedDiscovery: 'TRUE', fedSsoUrl: null,
      fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null });
    op.calls = [];
    op.scenario = { issuer: opBase, base: opBase, discovery: {
      pushed_authorization_request_endpoint: opBase + 'par' },
      parNonce: 'nonce-from-the-partner' };
    started = await begin(NONCE, {});
    const noncePushes = op.calls.filter(function (c) {
      return /\/par$/.test(c.path);
    });
    const firstProof = jwtParts(noncePushes[0] && noncePushes[0].dpop);
    const secondProof = jwtParts(noncePushes[1] && noncePushes[1].dpop);
    note(NONCE === 'frp-fapi-nonce-' + stamp && noncePushes.length === 2 &&
         started.status === 302 &&
         started.location.indexOf('request_uri=') >= 0 &&
         firstProof && !firstProof.claims.nonce &&
         secondProof &&
         secondProof.claims.nonce === 'nonce-from-the-partner',
         '10k. the first push is answered use_dpop_nonce, and the second ' +
         'carries that nonce and is the one that redirects',
         started.status + ' ' + noncePushes.length + ' ' +
         JSON.stringify(secondProof && secondProof.claims));

    // --- 10l, 10m. what a FAPI profile registers ----------------------------
    const regBits = function (id, profile, fields) {
      return make(id, Object.assign({
        fedFapi: profile, fedDiscovery: 'TRUE', fedRegister: 'TRUE',
        fedClientId: null, fedClientSecret: null, fedSsoUrl: null,
        fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null
      }, fields || {}));
    };
    const REGMS = regBits('frp-fapi-regms-' + stamp, '2-message-signing');
    const regsBefore = op.registrations || 0;
    op.scenario = { issuer: opBase, base: opBase, discovery: {
      pushed_authorization_request_endpoint: opBase + 'par' } };
    started = await begin(REGMS, {});
    let reg = op.registered || {};
    let regKey = ((reg.jwks || {}).keys || [])[0] || {};
    note(REGMS === 'frp-fapi-regms-' + stamp && started.status === 302 &&
         op.registrations === regsBefore + 1 &&
         reg.token_endpoint_auth_method === 'private_key_jwt' &&
         reg.token_endpoint_auth_signing_alg === 'PS256' &&
         reg.dpop_bound_access_tokens === true &&
         reg.authorization_signed_response_alg === 'PS256' &&
         reg.request_object_signing_alg === 'PS256' &&
         reg.require_pushed_authorization_requests === true &&
         JSON.stringify(reg.response_types) === '["code"]' &&
         (reg.grant_types || []).indexOf('implicit') < 0 &&
         regKey.kty === 'RSA' && !regKey.d,
         '10l. message signing registers private_key_jwt, PS256, DPoP ' +
         'and a signed authorization response',
         started.status + ' ' + JSON.stringify(reg).slice(0, 500));
    const REGADV = regBits('frp-fapi-regadv-' + stamp, '1-advanced');
    op.scenario = { issuer: opBase, base: opBase };
    started = await begin(REGADV, {});
    reg = op.registered || {};
    regKey = ((reg.jwks || {}).keys || [])[0] || {};
    note(started.status === 302 &&
         reg.token_endpoint_auth_method === 'private_key_jwt' &&
         reg.token_endpoint_auth_signing_alg === 'PS256' &&
         reg.request_object_signing_alg === 'PS256' &&
         JSON.stringify(reg.response_types) === '["code id_token"]' &&
         (reg.grant_types || []).indexOf('authorization_code') >= 0 &&
         (reg.grant_types || []).indexOf('implicit') >= 0 &&
         reg.dpop_bound_access_tokens !== true &&
         !reg.authorization_signed_response_alg &&
         !reg.require_pushed_authorization_requests &&
         regKey.kty === 'RSA' && !regKey.d,
         '10m. 1-advanced registers the request object and the hybrid ' +
         'response, and not DPoP, JARM or a pushed request',
         started.status + ' ' + JSON.stringify(reg).slice(0, 500));

    // --- 10n, 10o. account linking ------------------------------------------
    // An enterprise relationship is also 0184, so the control is a consumer
    // provider that connects, and the same relationship with a profile set
    // that does not. fedProvider is applied only at create.
    config.setOverride('federation.consumerProviders', 'true');
    const LINK = 'frp-link-' + stamp;
    const linkMade = federation.create({
      fedId: LINK, fedRole: 'service-provider', fedProtocol: 'oidc',
      fedPeer: opBase, fedProvider: 'generic-oidc' });
    const linkFields = {
      fedClientId: 'frp-client', fedClientSecret: 'frp-secret-' + stamp,
      fedSsoUrl: opBase + 'authorize', fedTokenUrl: opBase + 'token',
      fedJwksUri: opBase + 'jwks', fedUserinfoUrl: opBase + 'userinfo',
      fedEnabled: 'TRUE' };
    const linkWrites = [linkMade];
    Object.keys(linkFields).forEach(function (field) {
      linkWrites.push(federation.update(LINK, { field: field,
        value: String(linkFields[field]) }));
    });
    const linkReady = linkWrites.every(function (one) {
      return one && one.ok;
    });
    const linkRecord = federation.get(LINK) || {};
    const callsAtLink = op.calls.length;
    const opened = fedSp.beginConnect({}, { relationship: LINK,
                                            username: 'ada' });
    note(linkReady && linkRecord.fedProvider === 'generic-oidc' &&
         opened.ok === true &&
         String(opened.location || '').indexOf(opBase + 'authorize?') ===
           0 && op.calls.length === callsAtLink,
         '10n. a consumer relationship can be connected, and that door ' +
         'dials nothing',
         JSON.stringify({ ok: opened.ok, location: opened.location,
           ready: federation.readinessOf(linkRecord) }).slice(0, 400));
    const profiles = ['2-security', '1-advanced', '2-message-signing'];
    const linkRefusals = profiles.map(function (profile) {
      federation.update(LINK, { field: 'fedFapi', value: profile });
      return fedSp.beginConnect({}, { relationship: LINK,
                                      username: 'ada' });
    });
    note(linkRefusals.every(function (one) {
      return one && one.ok === false && one.code === 'STS-FED-0184';
    }) && op.calls.length === callsAtLink,
         '10o. beginConnect will not start a FAPI sign-in (STS-FED-0184)',
         JSON.stringify(linkRefusals.map(function (one) {
           return one && one.code;
         })));

    // --- 10p-10s. JARM refusals, then the same sign-in still redeems -------
    // A discovering relationship stores no jwks URI. A response with no
    // state has no context to take the discovered URI from, so the partner
    // key is pasted: otherwise 0246 is "no keys" and never "no state".
    // The wrong key is signed as kid frp-1, so that key is selected and
    // the signature is what fails.
    const JARM = make('frp-fapi-jarm-' + stamp, {
      fedFapi: '2-message-signing', fedDiscovery: 'TRUE', fedSsoUrl: null,
      fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null });
    const pastedKeys = federation.update(JARM, { field: 'fedJwks',
      value: JSON.stringify({ keys: [jwk] }) });
    const otherPair = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 2048 });
    const signOther = function (claims) {
      const input = b64u({ alg: 'RS256', kid: 'frp-1', typ: 'JWT' }) + '.' +
                    b64u(claims);
      return input + '.' + nodeCrypto.sign('sha256', Buffer.from(input),
                                           otherPair.privateKey)
        .toString('base64url');
    };
    const jarmExp = function () {
      return Math.floor(Date.now() / 1000) + 300;
    };
    op.calls = [];
    op.par = null;
    op.scenario = { issuer: opBase, base: opBase, discovery: {
      pushed_authorization_request_endpoint: opBase + 'par' },
      backClaims: function () {
        return parClaims();
      } };
    const jarmJar = {};
    started = await begin(JARM, jarmJar);
    const jState = (op.par || new URLSearchParams()).get('state');
    const jarmGet = function (token) {
      op.calls = [];
      return call('GET', '/federation/acs/' + JARM + '?response=' +
        encodeURIComponent(token), null, jarmJar);
    };
    const noToken = function () {
      return !op.calls.some(function (c) {
        return /\/token$/.test(c.path);
      });
    };
    before = coded('STS-FED-0246');
    r = await jarmGet(signOther({ iss: opBase, aud: 'frp-client',
      state: jState, code: 'c-stolen', exp: jarmExp() }));
    note(pastedKeys && pastedKeys.ok && jState && r.status === 401 &&
         coded('STS-FED-0246') === before + 1 && noToken() &&
         r.text.indexOf('did not verify') >= 0,
         '10p. a JARM response signed by another key is refused ' +
         '(STS-FED-0246) and the code is not redeemed',
         r.status + ' ' + r.text.slice(0, 300));
    before = coded('STS-FED-0246');
    r = await jarmGet(sign({ iss: opBase, aud: 'frp-client',
      code: 'c-nostate', exp: jarmExp() }));
    note(r.status === 401 && coded('STS-FED-0246') === before + 1 &&
         noToken() && r.text.indexOf('no state') >= 0,
         '10q. a JARM response with no state is refused (STS-FED-0246) ' +
         'and the code is not redeemed',
         r.status + ' ' + r.text.slice(0, 300));
    before = coded('STS-FED-0025');
    const jarmCodes = coded('STS-FED-0246');
    r = await jarmGet(sign({ iss: opBase, aud: 'frp-client', state: jState,
      error: 'access_denied', exp: jarmExp() }));
    note(r.status === 400 && coded('STS-FED-0025') === before + 1 &&
         coded('STS-FED-0246') === jarmCodes && noToken() &&
         r.text.indexOf('access_denied') >= 0,
         '10r. a JARM response carrying the partner\'s error is that ' +
         'error (STS-FED-0025) and does not redeem a code',
         r.status + ' ' + r.text.slice(0, 300));
    before = coded('STS-FED-0250');
    r = await jarmGet(sign({ iss: opBase, aud: 'frp-client', state: jState,
      code: 'c-noexp' }));
    note(r.status === 401 && coded('STS-FED-0250') === before + 1 &&
         noToken() && r.text.indexOf('no exp') >= 0,
         '10z. a JARM response with no exp is refused (STS-FED-0250) and ' +
         'the code is not redeemed', r.status + ' ' + r.text.slice(0, 300));
    r = await jarmGet(sign({ iss: opBase, aud: 'frp-client', state: jState,
      code: 'c-jarm-kept', exp: jarmExp() }));
    const keptToken = op.calls.filter(function (c) {
      return /\/token$/.test(c.path);
    })[0] || { body: '' };
    note(r.status < 400 && /code=c-jarm-kept/.test(keptToken.body),
         '10s. the same sign-in still redeems a good JARM response',
         r.status + ' ' + keptToken.body.slice(0, 200));

    // --- 10t, 10u. refresh ---------------------------------------------------
    // sealPartnerToken is the clear value when this process holds no
    // durable key-encryption key, so the sealed blob is not what shows the
    // key survived. The public jwk in the two DPoP proofs is. refreshDue
    // also refreshes the still-live session from case 6, so the assertion
    // is this refresh_token, not the count.
    const proofX = function (header) {
      const parsed = jwtParts(header);
      return parsed && parsed.header.jwk && parsed.header.jwk.x;
    };
    const FREF = make('frp-fapi-ref-' + stamp, {
      fedFapi: '2-security', fedDiscovery: 'TRUE',
      fedRefreshTokens: 'TRUE', fedRefreshEverySeconds: '1',
      fedSsoUrl: null, fedTokenUrl: null, fedJwksUri: null,
      fedUserinfoUrl: null });
    const frefJar = {};
    op.calls = [];
    op.par = null;
    op.scenario = { issuer: opBase, base: opBase, rt: 'rt-fapi2',
      discovery: { pushed_authorization_request_endpoint: opBase + 'par' },
      backClaims: function () {
        return parClaims();
      } };
    started = await begin(FREF, frefJar);
    await call('GET', '/federation/acs/' + FREF + '?state=' +
      encodeURIComponent((op.par || new URLSearchParams()).get('state')) +
      '&code=c-fref&iss=' + encodeURIComponent(opBase), null, frefJar);
    const signInX = proofX((op.calls.filter(function (c) {
      return /\/token$/.test(c.path);
    })[0] || {}).dpop);
    op.byToken['rt-fapi2'] = { claims: function () {
      const now = Math.floor(Date.now() / 1000);
      return { iss: opBase, sub: 'frp-person', aud: 'frp-client', iat: now,
               exp: now + 300 };
    } };
    op.calls = [];
    await fedSp.refreshDue(Date.now() + 5000);
    const frefCall = op.calls.filter(function (c) {
      return /\/token$/.test(c.path) &&
             /refresh_token=rt-fapi2/.test(c.body);
    })[0] || { body: '', dpop: '' };
    const frefForm = new URLSearchParams(frefCall.body);
    const frefUser = op.calls.filter(function (c) {
      return /\/userinfo$/.test(c.path) && c.auth === 'DPoP at-rt-fapi2';
    })[0];
    note(FREF === 'frp-fapi-ref-' + stamp && signInX &&
         proofX(frefCall.dpop) === signInX &&
         frefForm.get('client_assertion') && !frefForm.get('client_secret') &&
         !!frefUser,
         '10t. a 2.x refresh sends private_key_jwt and a DPoP proof from ' +
         'the sign-in key, and UserInfo is asked as DPoP',
         'x=' + signInX + ' again=' + proofX(frefCall.dpop) + ' ' +
         frefCall.body.slice(0, 180));
    const AREF = make('frp-fapi1-ref-' + stamp, {
      fedFapi: '1-advanced', fedRefreshTokens: 'TRUE',
      fedRefreshEverySeconds: '1' });
    const arefJar = {};
    op.calls = [];
    op.scenario = { rt: 'rt-fapi1' };
    started = await begin(AREF, arefJar);
    // The token endpoint is the callback's, so the ID Token is this
    // sign-in's nonce and not the previous case's.
    op.scenario.backClaims = function () {
      return claims(started);
    };
    await call('POST', '/federation/acs/' + AREF, {
      state: started.params.get('state'), code: 'c-aref',
      id_token: sign(claims(started, { c_hash: halfHash('c-aref'),
        s_hash: halfHash(started.params.get('state')) }))
    }, arefJar);
    op.byToken['rt-fapi1'] = { claims: function () {
      const now = Math.floor(Date.now() / 1000);
      return { iss: opBase, sub: 'frp-person', aud: 'frp-client', iat: now,
               exp: now + 300 };
    } };
    op.calls = [];
    await fedSp.refreshDue(Date.now() + 5000);
    const arefCall = op.calls.filter(function (c) {
      return /\/token$/.test(c.path) &&
             /refresh_token=rt-fapi1/.test(c.body);
    })[0] || { body: '', dpop: 'none' };
    const arefForm = new URLSearchParams(arefCall.body);
    const arefUser = op.calls.filter(function (c) {
      return /\/userinfo$/.test(c.path) &&
             c.auth === 'Bearer at-rt-fapi1';
    })[0];
    note(arefForm.get('client_assertion') && !arefCall.dpop && !!arefUser,
         '10u. a 1-advanced refresh sends the assertion and no DPoP ' +
         'proof, and UserInfo stays bearer',
         'dpop=' + arefCall.dpop + ' ' + arefCall.body.slice(0, 180));

    // --- 10ac. a 2.x refresh answered Bearer ends the session ------------
    op.byToken['rt-fapi2'].tokenType = 'Bearer';
    before = coded('STS-FED-0251');
    op.calls = [];
    await fedSp.refreshDue(Date.now() + 120000);
    const bearerRefresh = op.calls.some(function (c) {
      return /\/token$/.test(c.path) &&
             /refresh_token=rt-fapi2/.test(c.body);
    });
    note(bearerRefresh && coded('STS-FED-0251') === before + 1 &&
         !op.calls.some(function (c) {
           return /\/userinfo$/.test(c.path) &&
                  /at-rt-fapi2/.test(c.auth);
         }),
         '10ac. a 2-security refresh answered Bearer ends the session ' +
         '(STS-FED-0251) and UserInfo is not asked',
         bearerRefresh + ' ' + (coded('STS-FED-0251') - before));

    // --- 10am, 10an. every request signed afresh (#931's first run) -------
    // The conformance suite's FAPI 2 plans failed every module on
    // CheckForClientAssertionJtiReuse: the use_dpop_nonce retry at the push
    // and at the token endpoint sent the first attempt's client assertion
    // again. And UserInfo's nonce challenge, in WWW-Authenticate, was never
    // answered, so every module that waits for UserInfo timed out. Here the
    // partner demands its nonce at the push, the token endpoint and the
    // refresh, and UserInfo demands one of its own: no jti may be seen
    // twice, UserInfo is asked again with its own nonce, and the two
    // servers' nonces are never sent to each other.
    const NJTI = make('frp-fapi-jti-' + stamp, {
      fedFapi: '2-security', fedDiscovery: 'TRUE',
      fedRefreshTokens: 'TRUE', fedRefreshEverySeconds: '1',
      fedSsoUrl: null, fedTokenUrl: null, fedJwksUri: null,
      fedUserinfoUrl: null });
    const njtiJar = {};
    op.calls = [];
    op.jtis = [];
    op.par = null;
    op.scenario = { issuer: opBase, base: opBase, rt: 'rt-nonce',
      demand: { as: 'as-nonce-1', rs: 'rs-nonce-1', rt: 'rt-nonce' },
      discovery: { pushed_authorization_request_endpoint: opBase + 'par' },
      backClaims: function () {
        return parClaims();
      } };
    started = await begin(NJTI, njtiJar);
    // The push's nonce is held for the token request; the partner moves
    // on before the code comes back, so that request is challenged too.
    op.scenario.demand.as = 'as-nonce-1b';
    r = await call('GET', '/federation/acs/' + NJTI + '?state=' +
      encodeURIComponent((op.par || new URLSearchParams()).get('state')) +
      '&code=c-njti&iss=' + encodeURIComponent(opBase), null, njtiJar);
    const proofNonceOf = function (c) {
      const parsed = jwtParts(c && c.dpop);
      return parsed ? String(parsed.claims.nonce || '') : 'no proof';
    };
    const njtiOf = function (re) {
      return op.calls.filter(function (c) {
        return re.test(c.path);
      });
    };
    const njtiPar = njtiOf(/\/par$/);
    const njtiToken = njtiOf(/\/token$/);
    const njtiUser = njtiOf(/\/userinfo$/);
    op.byToken['rt-nonce'] = { claims: function () {
      const now = Math.floor(Date.now() / 1000);
      return { iss: opBase, sub: 'frp-person', aud: 'frp-client', iat: now,
               exp: now + 300 };
    } };
    // Both servers move their nonce on, so the refresh meets a challenge
    // at each and answers it.
    op.scenario.demand = { as: 'as-nonce-2', rs: 'rs-nonce-2',
                           rt: 'rt-nonce' };
    const signInCalls = op.calls.length;
    await fedSp.refreshDue(Date.now() + 5000);
    const njtiRefresh = op.calls.slice(signInCalls).filter(function (c) {
      return /\/token$/.test(c.path) && /refresh_token=rt-nonce/.test(c.body);
    });
    const njtiRefreshUser = op.calls.slice(signInCalls).filter(function (c) {
      return /\/userinfo$/.test(c.path) && c.auth === 'DPoP at-rt-nonce';
    });
    const assertionJtis = op.jtis.filter(function (one) {
      return one.kind === 'client_assertion';
    }).map(function (one) {
      return one.jti;
    });
    const distinct = function (list) {
      return list.every(function (one, i) {
        return one && list.indexOf(one) === i;
      });
    };
    // This case's six requests, each with an assertion; the refresh also
    // renews the other cases' held sessions, whose jtis are in the list
    // too and must be just as distinct.
    const mine = njtiPar.concat(njtiToken, njtiRefresh).map(function (c) {
      const sent = jwtParts(new URLSearchParams(c.body)
        .get('client_assertion'));
      return sent ? String(sent.claims.jti || '') : '';
    });
    note(NJTI === 'frp-fapi-jti-' + stamp && njtiPar.length === 2 &&
         njtiToken.length === 2 && njtiRefresh.length === 2 &&
         mine.length === 6 && distinct(mine) && distinct(assertionJtis),
         '10am. the push, the token request and the refresh are each ' +
         'answered use_dpop_nonce and sent again, and no client assertion ' +
         'jti is seen twice',
         njtiPar.length + ' ' + njtiToken.length + ' ' + njtiRefresh.length +
         ' ' + JSON.stringify(assertionJtis));
    note(r.status < 400 && njtiUser.length === 2 &&
         proofNonceOf(njtiUser[0]) === '' &&
         proofNonceOf(njtiUser[1]) === 'rs-nonce-1' &&
         proofNonceOf(njtiPar[0]) === '' &&
         proofNonceOf(njtiPar[1]) === 'as-nonce-1' &&
         proofNonceOf(njtiToken[0]) === 'as-nonce-1' &&
         proofNonceOf(njtiToken[1]) === 'as-nonce-1b' &&
         njtiRefresh.length === 2 &&
         proofNonceOf(njtiRefresh[0]) === 'as-nonce-1b' &&
         proofNonceOf(njtiRefresh[1]) === 'as-nonce-2' &&
         njtiRefreshUser.length === 2 &&
         proofNonceOf(njtiRefreshUser[0]) === 'rs-nonce-1' &&
         proofNonceOf(njtiRefreshUser[1]) === 'rs-nonce-2',
         '10am. UserInfo\'s challenge in WWW-Authenticate (scheme dPoP) is ' +
         'answered with its own nonce, at the sign-in and the refresh, and ' +
         'neither server is sent the other\'s nonce',
         r.status + ' par=' + njtiPar.map(proofNonceOf).join(',') +
         ' user=' + njtiUser.map(proofNonceOf).join(',') +
         ' token=' + njtiToken.map(proofNonceOf).join(',') +
         ' refresh=' + njtiRefresh.map(proofNonceOf).join(',') +
         ' refreshUser=' + njtiRefreshUser.map(proofNonceOf).join(','));
    const NRO = make('frp-fapi-jtims-' + stamp, {
      fedFapi: '2-message-signing', fedDiscovery: 'TRUE', fedSsoUrl: null,
      fedTokenUrl: null, fedJwksUri: null, fedUserinfoUrl: null });
    op.calls = [];
    op.jtis = [];
    op.scenario = { issuer: opBase, base: opBase,
      demand: { as: 'as-nonce-ms', rs: 'rs-nonce-ms', rt: '' },
      discovery: { pushed_authorization_request_endpoint: opBase + 'par' } };
    started = await begin(NRO, {});
    const msPushes = njtiOf(/\/par$/);
    const kinds = function (kind) {
      return op.jtis.filter(function (one) {
        return one.kind === kind;
      }).map(function (one) {
        return one.jti;
      });
    };
    note(NRO === 'frp-fapi-jtims-' + stamp && started.status === 302 &&
         msPushes.length === 2 && kinds('request').length === 2 &&
         distinct(kinds('request')) &&
         kinds('client_assertion').length === 2 &&
         distinct(kinds('client_assertion')),
         '10an. message signing\'s retried push carries a new request ' +
         'object and a new client assertion, each with a jti of its own',
         started.status + ' ' + msPushes.length + ' ' +
         JSON.stringify(op.jtis));
    op.scenario = {};

    // --- 10ad-10ak. 1-advanced over mutual TLS (#931, rcbj 2026-11-13) ----
    const fedClientCert = require(ROOT_DIR +
                                  '/federation/federation_client_certificate');
    const mtlsSignIn = async function (id, extraScenario) {
      const jar = {};
      const begun = await begin(id, jar);
      op.calls = [];
      op.scenario = Object.assign({ bindMtls: true,
        backClaims: function () {
          return claims(begun);
        } }, extraScenario || {});
      const resp = await call('POST', '/federation/acs/' + id, {
        state: begun.params.get('state'), code: 'c-mtls',
        id_token: sign(claims(begun, { c_hash: halfHash('c-mtls'),
          s_hash: halfHash(begun.params.get('state')) }))
      }, jar);
      return {
        r: resp,
        token: op.calls.filter(function (c) {
          return /\/token$/.test(c.path);
        })[0] || { body: '', cert: '', dpop: '' },
        userinfo: op.calls.filter(function (c) {
          return /\/userinfo$/.test(c.path);
        })[0] || { cert: '', auth: '' }
      };
    };
    const MTLS = make('frp-fapi1-mtls-' + stamp, { fedFapi: '1-advanced',
      fedTokenUrl: mtlsBase + 'token', fedUserinfoUrl: mtlsBase + 'userinfo' });
    op.boundAnswered = 0;
    got = await mtlsSignIn(MTLS);
    const mtlsView = fedClientCert.viewOf(federation.get(MTLS)) || {};
    const mtlsForm = new URLSearchParams(got.token.body);
    note(MTLS === 'frp-fapi1-mtls-' + stamp && got.r.status < 400 &&
         mtlsView.held && got.token.cert &&
         got.token.cert === mtlsView.x5tS256 &&
         mtlsForm.get('client_assertion') && !got.token.dpop,
         '10ad. 1-advanced presents the relationship\'s client certificate ' +
         'at the token endpoint, beside private_key_jwt and no DPoP',
         got.r.status + ' presented=' + got.token.cert + ' held=' +
         mtlsView.x5tS256);
    note(got.userinfo.cert === mtlsView.x5tS256 &&
         op.boundAnswered === 1 && !op.boundRefused,
         '10ae. UserInfo is asked over the same certificate, so the ' +
         'certificate-bound token is answered',
         'userinfo cert=' + got.userinfo.cert + ' answered=' +
         op.boundAnswered + ' refused=' + (op.boundRefused || 0));
    const mtlsPem = mtlsView.certificatePem || '';
    let mtlsParsed = null;
    try {
      mtlsParsed = new nodeCrypto.X509Certificate(mtlsPem);
    } catch (e) {
      // No certificate published is what the note below reports.
      note(false, '10af-. the published certificate parses',
           String((e && e.message) || e));
      mtlsParsed = null;
    }
    note(!!mtlsParsed &&
         /(^|,)CN=federation frp-fapi1-mtls-/.test(mtlsView.subject) &&
         mtlsParsed.fingerprint256.replace(/:/g, '').toLowerCase() ===
           Buffer.from(mtlsView.x5tS256, 'base64url').toString('hex') &&
         (mtlsView.chainPem || []).length >= 2 &&
         (mtlsParsed.keyUsage || []).indexOf('1.3.6.1.5.5.7.3.2') >= 0 &&
         JSON.stringify(mtlsView).indexOf('PRIVATE KEY') < 0,
         '10af. the certificate is a clientAuth leaf under the realm\'s ' +
         'chain, its x5t#S256 and subject published and no private key',
         mtlsView.subject + ' ' + JSON.stringify(
           mtlsParsed ? mtlsParsed.keyUsage : null) + ' ' +
         (JSON.stringify(mtlsView).indexOf('PRIVATE KEY') < 0));
    // tls_client_auth: the certificate authenticates, nothing else does.
    federation.update(MTLS, { field: 'fedTokenAuth',
                              value: 'tls_client_auth' });
    got = await mtlsSignIn(MTLS);
    const tcaForm = new URLSearchParams(got.token.body);
    note(federation.readinessOf(federation.get(MTLS)).ready &&
         got.r.status < 400 && got.token.cert === mtlsView.x5tS256 &&
         tcaForm.get('client_id') === 'frp-client' &&
         !tcaForm.get('client_assertion') && !tcaForm.get('client_secret') &&
         !/^Basic /.test(got.token.auth || ''),
         '10ag. tls_client_auth sends the client_id over the certificate and ' +
         'no assertion, secret or Basic header',
         got.r.status + ' ' + got.token.body.slice(0, 160));
    const TCA = make('frp-tca-plain-' + stamp, {
      fedTokenAuth: 'tls_client_auth' });
    note(!federation.readinessOf(federation.get(TCA)).ready &&
         federation.readinessOf(federation.get(TCA)).missing.some(
           function (m) {
             return /^fedFapi=1-advanced/.test(m);
           }),
         '10ah. tls_client_auth without 1-advanced is not ready',
         JSON.stringify(federation.readinessOf(federation.get(TCA))));
    // A certificate whose key will not open refuses the sign-in.
    const heldRow = federation.clientCertificateOf(federation.get(MTLS));
    federation.writeClientCertificate(MTLS, Object.assign({}, heldRow,
      { sealed: true, privateKey: 'not-a-sealed-value' }), 'a test');
    before = coded('STS-FED-0252');
    got = await mtlsSignIn(MTLS);
    note(got.r.status === 500 && coded('STS-FED-0252') === before + 1 &&
         !op.calls.some(function (c) {
           return /\/token$/.test(c.path);
         }),
         '10ai. a client certificate that will not open refuses the ' +
         'sign-in (STS-FED-0252) and nothing is dialled',
         got.r.status + ' ' + (coded('STS-FED-0252') - before));
    // The job renews within federation.clientCertificateRenewDays, same
    // subject, new serial; and a relationship with none gets one.
    federation.writeClientCertificate(MTLS, heldRow, 'a test');
    const renewed = await fedClientCert.renewDue(
      new Date(heldRow.notAfter).getTime() - 86400000);
    const afterRow = federation.clientCertificateOf(federation.get(MTLS)) ||
                     {};
    note(renewed.issued >= 1 && afterRow.serialHex &&
         afterRow.serialHex !== heldRow.serialHex &&
         afterRow.subject === heldRow.subject &&
         !fedClientCert.due(federation.get(MTLS)),
         '10aj. the renewal job issues a new certificate with the same ' +
         'subject inside federation.clientCertificateRenewDays',
         JSON.stringify(renewed) + ' ' + heldRow.serialHex + ' -> ' +
         afterRow.serialHex);
    // Discovery's mtls_endpoint_aliases, and a registration that says
    // tls_client_auth with the certificate's subject.
    const ALIAS = make('frp-fapi1-alias-' + stamp, { fedFapi: '1-advanced',
      fedDiscovery: 'TRUE', fedRegister: 'TRUE', fedClientId: null,
      fedClientSecret: null, fedTokenAuth: 'tls_client_auth',
      fedSsoUrl: null, fedTokenUrl: null, fedJwksUri: null,
      fedUserinfoUrl: null });
    op.registered = null;
    op.scenario = { issuer: opBase, base: opBase, discovery: {
      mtls_endpoint_aliases: { token_endpoint: mtlsBase + 'token',
                               userinfo_endpoint: mtlsBase + 'userinfo' } } };
    const aliasJar = {};
    started = await begin(ALIAS, aliasJar);
    const aliasReg = op.registered || {};
    const aliasView = fedClientCert.viewOf(federation.get(ALIAS)) || {};
    op.calls = [];
    op.scenario.bindMtls = true;
    op.scenario.backClaims = function () {
      return Object.assign(claims(started), { aud: aliasReg.client_id ||
        federation.get(ALIAS).fedClientId });
    };
    r = await call('POST', '/federation/acs/' + ALIAS, {
      state: started.params.get('state'), code: 'c-alias',
      id_token: sign(Object.assign(claims(started, {
        c_hash: halfHash('c-alias'),
        s_hash: halfHash(started.params.get('state')) }),
        { aud: federation.get(ALIAS).fedClientId }))
    }, aliasJar);
    const aliasToken = op.calls.filter(function (c) {
      return /\/token$/.test(c.path);
    })[0] || { cert: '' };
    note(aliasReg.token_endpoint_auth_method === 'tls_client_auth' &&
         aliasReg.tls_client_auth_subject_dn === aliasView.subject &&
         aliasReg.tls_client_certificate_bound_access_tokens === true &&
         !aliasReg.token_endpoint_auth_signing_alg,
         '10ak. 1-advanced registers tls_client_auth with the certificate\'s ' +
         'subject DN and certificate-bound access tokens',
         JSON.stringify(aliasReg).slice(0, 400));
    note(r.status < 400 && aliasToken.cert &&
         aliasToken.cert === aliasView.x5tS256,
         '10al. the token request goes to the discovery document\'s ' +
         'mtls_endpoint_aliases with the client certificate',
         r.status + ' cert=' + aliasToken.cert + ' ' +
         String(r.text || '').slice(0, 200));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    server.close();
    partner.close();
    tlsPartner.close();
    mtlsPartner.close();
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child process threw',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'frp-' + process.pid + '-' +
                        Date.now() + '.json');
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
                                  FRP_ROOT: ROOT, FRP_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
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
  name: 'federation_oidc_rp',
  describe: 'an inbound OpenID Connect relationship holds the ID Token, ' +
            'UserInfo, hybrid, fragment, discovery and login-initiation ' +
            'rules the conformance suite\'s relying-party plans test (#930)',
  run: run
};
