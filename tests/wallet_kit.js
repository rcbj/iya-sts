// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wallet_kit.js
//
// ===========================================================================
// A WALLET WRITTEN FOR THE TESTS, AND THE STACK IT TALKS TO (#38's
// follow-ups). NOT A TEST: `run.js` skips it by name.
//
// The wallet sign-in tests — `oid4vp_sign_in.js`, `oid4vp_sign_in_formats.js`,
// `oid4vp_dc_api.js`, `vc_status_list.js` and `oid4vp_wallet_mfa.js` — each
// run in a CHILD PROCESS (`admin_credential_controls.js`'s reason: they load
// the whole protocol stack and flip settings every other file in `run.js`'s
// one process would see), and each needs the same things: the stack on an
// ephemeral loopback port, a cookie jar per browser, an OID4VCI issuance done
// the way a wallet does it, and a presentation in each of the three formats.
// Those live here, once, so the five files differ only in what they assert.
//
// `inAChild(t, childMain, name)` is the parent half: it serialises the child
// function, runs it with a clean environment, and reports its findings.
// `boot()` is the child half's start.
//
// The wallet is deliberately NOT the service's own code: its proofs, Key
// Binding JWTs and VP JWTs are signed here with node's crypto (and
// `common/pq_jose.js` for ML-DSA, which has no other implementation in this
// tree). The two exceptions are said where they are made: the BBS derived
// proof uses the same `@digitalbazaar/bbs-signatures` library the issuer
// uses — there is no second BBS implementation here — and the ldp_vc holder
// proof uses `oid4vc/vc_data_integrity.ts`, whose own test holds it to the
// W3C's published vectors.
//
// STYLE: everything inside `boot()` runs only in the `node -e` child a test
// file starts, and follows the root CLAUDE.md's exemption for such code —
// the two exported functions log their entry and exit.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'wallet_kit',
  level: process.env.LOG_LEVEL || 'info' });

const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const QUERY_IDS = {
  'dc+sd-jwt': 'identity_credential',
  'jwt_vc_json': 'identity_credential_jwt_vc',
  'ldp_vc': 'identity_credential_ldp_vc'
};
const CONFIG_FOR = {
  'dc+sd-jwt': 'IdentityCredential',
  'jwt_vc_json': 'IdentityCredentialJwtVcJson',
  'ldp_vc': 'IdentityCredentialLdpVc'
};

// ---------------------------------------------------------------------------
// THE PARENT HALF.
// ---------------------------------------------------------------------------
function inAChild(t, childMain, name, extraEnv) {
  log.debug("Entering inAChild(). " + name);
  const out = path.join(os.tmpdir(), name + '-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', WSI_ROOT: ROOT,
                                  WSI_OUT: out }, extraEnv || {}),
      encoding: 'utf8', timeout: 480000, cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024
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
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving inAChild(). No findings.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

// ---------------------------------------------------------------------------
// THE CHILD HALF.
// ---------------------------------------------------------------------------
async function boot() {
  log.debug("Entering boot().");
  const http = require('http');
  const nodeCrypto = require('crypto');
  require(ROOT + '/common/protocol_stack');
  const m = {
    app: require(ROOT + '/common/app'),
    config: require(ROOT + '/common/config'),
    realms: require(ROOT + '/common/realms'),
    helpers: require(ROOT + '/common/helpers'),
    errorCodes: require(ROOT + '/common/error_codes'),
    gate: require(ROOT + '/common/issuance_gate'),
    ldap: require(ROOT + '/ldap/ldap_server'),
    applications: require(ROOT + '/common/applications'),
    offers: require(ROOT + '/oid4vc/vc_offers'),
    verifier: require(ROOT + '/oid4vc/vc_verifier'),
    issuer: require(ROOT + '/oid4vc/vc_issuer'),
    issued: require(ROOT + '/oid4vc/vc_issued'),
    status: require(ROOT + '/oid4vc/vc_status'),
    codec: require(ROOT + '/oid4vc/vc_status_codec'),
    di: require(ROOT + '/oid4vc/vc_data_integrity'),
    vcConfigs: require(ROOT + '/oid4vc/vc_configs'),
    authn: require(ROOT + '/authn/authn'),
    logout: require(ROOT + '/logout/logout'),
    stats: require(ROOT + '/common/admin_stats'),
    stsCrypto: require(ROOT + '/common/crypto'),
    pqJose: require(ROOT + '/common/pq_jose'),
    bbs2023: require(ROOT + '/common/crypto_impl/bbs2023.js'),
    cacheRegistry: require(ROOT + '/common/cache_registry')
  };
  const DEFAULT = m.realms.DEFAULT_REALM;
  const findings = [];
  const marks = [];

  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }

  const server = http.createServer(function (req, res) {
    res.on('finish', function () {
      marks.push(m.errorCodes.codeOf(res));
    });
    m.app(req, res);
  });
  await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;
  const origin = base;

  function b64u(input) {
    return Buffer.from(input).toString('base64url');
  }

  function decode(jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
      .toString('utf8'));
  }

  function browser() {
    return { cookies: {} };
  }

  function request(method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      let body = o.raw || '';
      const headers = Object.assign({}, o.headers || {});
      if (o.json !== undefined) {
        body = JSON.stringify(o.json);
        headers['content-type'] = 'application/json';
      } else if (o.form) {
        body = new URLSearchParams(o.form).toString();
        headers['content-type'] = 'application/x-www-form-urlencoded';
      }
      if (method !== 'GET') {
        headers['content-length'] = Buffer.byteLength(body);
      }
      if (o.browser) {
        const jar = o.browser.cookies;
        const line = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
        if (line) {
          headers.cookie = line;
        }
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        const chunks = [];
        res.on('data', function (c) { chunks.push(c); });
        res.on('end', function () {
          const buf = Buffer.concat(chunks);
          const text = buf.toString('utf8');
          const set = [].concat(res.headers['set-cookie'] || []);
          if (o.browser) {
            set.forEach(function (one) {
              const pair = one.split(';')[0];
              const eq = pair.indexOf('=');
              const name = pair.slice(0, eq);
              const value = pair.slice(eq + 1);
              if (/Max-Age=0/.test(one) || value === '') {
                delete o.browser.cookies[name];
              } else {
                o.browser.cookies[name] = value;
              }
            });
          }
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // A page, not JSON; the text is what is read.
            parsed = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    buffer: buf, json: parsed, setCookie: set,
                    code: marks.length ? marks[marks.length - 1] : '' });
        });
      });
      req.end(body);
    });
  }

  function pathOf(url) {
    const u = new URL(url, 'http://127.0.0.1');
    return u.pathname + u.search;
  }

  function unescapeHtml(text) {
    return String(text).replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }

  const SECRET = 'wsi-client-secret-0123456789abcdef';
  const client = { client_id: 'wsi-wallet', client_secret: SECRET };
  function provision() {
    try {
      m.applications.createApplication({ identifier: 'wsi-wallet',
        protocols: ['oauth2', 'oid4vci'],
        fields: { oauthClientId: 'wsi-wallet', oauthClientSecret: SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_post',
                  oauthGrantType: [PRE_AUTH] } });
    } catch (e) {
      // Already there, from an earlier section in the same realm.
      log.debug("Caught in provision(): " + ((e && e.message) || e));
    }
  }

  // ---------------------------------------------------------------------
  // A HOLDER KEY: `{ alg, jwk, privateKey }` for ES256 (the default),
  // ES384, EdDSA (Ed25519) or ML-DSA-44.
  // ---------------------------------------------------------------------
  function holderKey(alg) {
    const wanted = alg || 'ES256';
    if (wanted === 'ML-DSA-44') {
      const pair = m.pqJose.generate('ML-DSA-44');
      const jwk = m.pqJose.akpPublicJwk('ML-DSA-44', pair.pub);
      delete jwk.use;
      return { alg: wanted, jwk: jwk, privateKey: pair.priv,
               privateJwk: Object.assign({}, jwk,
                 { priv: Buffer.from(pair.priv).toString('base64url') }) };
    }
    const pair = wanted === 'EdDSA'
      ? nodeCrypto.generateKeyPairSync('ed25519')
      : nodeCrypto.generateKeyPairSync('ec', { namedCurve:
          wanted === 'ES384' ? 'P-384' : 'P-256' });
    return { alg: wanted, jwk: pair.publicKey.export({ format: 'jwk' }),
             privateKey: pair.privateKey,
             privateJwk: pair.privateKey.export({ format: 'jwk' }) };
  }

  // A compact JWS by the holder, in any of those algorithms.
  // `noTimestamp` is deliberately NOT passed: jsonwebtoken DELETES a
  // payload's own `iat` under it, and every proof here carries one.
  function jws(header, payload, holder) {
    return m.stsCrypto.signJws(payload, holder.privateKey, {
      algorithm: header.alg,
      header: header
    });
  }

  // A pre-authorized code, redeemed for an access token, for `username`.
  async function accessTokenFor(username, opts) {
    const o = opts || {};
    const prefix = o.prefix || '';
    const configId = o.configId || 'IdentityCredential';
    const built = await m.realms.run(o.realm || DEFAULT, function () {
      return m.offers.buildCredentialOffer(fakeReq(prefix), [configId],
        'cross-device', { user: m.helpers.userFor(username) });
    });
    const redeemed = await request('POST', prefix + '/oauth2/token',
      { form: Object.assign({ grant_type: PRE_AUTH,
        'pre-authorized_code': built.preAuthorizedCode,
        tx_code: built.txCode }, client) });
    return redeemed.json && redeemed.json.access_token
      ? { token: redeemed.json.access_token }
      : { error: 'token ' + redeemed.status + ' ' +
                 redeemed.text.slice(0, 200) };
  }

  function fakeReq(prefix) {
    return { protocol: 'http', originalUrl: (prefix || '') + '/',
             headers: { host: '127.0.0.1:' + port },
             get: function (n) {
               return String(n).toLowerCase() === 'host' ?
                 '127.0.0.1:' + port : undefined;
             } };
  }

  // THE CLIENT IDENTIFIER A SIGN-IN'S REQUEST IS SIGNED UNDER, and so the
  // audience a holder proves for (2026-10-12): `oid4vp.signInClientIdPrefix`,
  // x509_hash by default — the SHA-256 of the Verifier's certificate, made
  // here first if no sign-in has made it yet, exactly as a start does.
  async function signInAudience(opts) {
    const o = opts || {};
    return m.realms.run(o.realm || DEFAULT, async function () {
      const req = fakeReq(o.prefix || '');
      const prefix = m.verifier.signInClientIdPrefix();
      await m.verifier.prepareSignedClientId(req, prefix);
      return m.verifier.signedClientId(req, prefix).clientId;
    });
  }

  // ---------------------------------------------------------------------
  // THE ISSUANCE, as a wallet does it. `opts.format` picks the
  // configuration; `opts.token` overrides the access token; `opts.attestation`
  // is a key attestation JWT for the proof header; `opts.proofType`
  // `attestation` sends it as the proof itself; `opts.holders` sends a proof
  // for each of several holder keys, a batch. `opts.kid` (a DID URL, or a
  // function of the holder answering one) names the key by `kid` instead of
  // `jwk` (#693); `opts.keepJwk` sends both.
  // ---------------------------------------------------------------------
  async function issue(username, holder, opts) {
    const o = opts || {};
    const prefix = o.prefix || '';
    const configId = o.configId || CONFIG_FOR[o.format || 'dc+sd-jwt'];
    let accessToken = o.token;
    if (!accessToken) {
      const got = await accessTokenFor(username,
        { prefix: prefix, realm: o.realm, configId: configId });
      if (got.error) {
        return { error: got.error };
      }
      accessToken = got.token;
    }
    const nonce = await request('POST', prefix + '/oid4vci/nonce',
                                { form: {} });
    const cNonce = nonce.json && nonce.json.c_nonce;
    let proofs;
    if (o.proofType === 'attestation') {
      proofs = { attestation: [o.attestation(cNonce)] };
    } else {
      const header = { alg: holder.alg, typ: 'openid4vci-proof+jwt',
                       jwk: holder.jwk };
      if (o.attestation) {
        header.key_attestation = o.attestation(cNonce);
      }
      // A BATCH (#670): `opts.holders`, one proof per key, all quoting the
      // one c_nonce, as OpenID4VCI 1.0 section 8.2's `proofs.jwt` does.
      const keys = o.holders || [holder];
      proofs = { jwt: keys.map(function (one) {
        const h = Object.assign({}, header, { alg: one.alg, jwk: one.jwk });
        if (o.kid) {
          h.kid = typeof o.kid === 'function' ? o.kid(one) : o.kid;
          if (!o.keepJwk) {
            delete h.jwk;
          }
        }
        return jws(h,
          { aud: base + prefix, iat: Math.floor(Date.now() / 1000),
            nonce: cNonce }, one);
      }) };
    }
    const got = await request('POST', prefix + '/oid4vci/credential', {
      headers: { authorization: 'Bearer ' + accessToken },
      json: { credential_configuration_id: configId, proofs: proofs } });
    const credential = got.json && got.json.credentials &&
                       got.json.credentials[0] &&
                       got.json.credentials[0].credential;
    if (!credential) {
      return { error: 'credential ' + got.status + ' ' +
                      got.text.slice(0, 300), response: got,
               accessToken: accessToken };
    }
    return { credential: credential, accessToken: accessToken,
             credentials: got.json.credentials.map(function (c) {
               return c.credential;
             }), response: got };
  }

  // ---------------------------------------------------------------------
  // PRESENTATIONS, one per format. `o.noProof` leaves the holder proof off;
  // `o.iat` sets its time; `o.key` signs with another key than the bound one.
  // ---------------------------------------------------------------------
  function presentSdJwt(credential, holder, nonce, aud, opts) {
    const o = opts || {};
    const withoutKb = String(credential).split('~')[0] + '~';
    if (o.noProof) {
      return withoutKb;
    }
    const signer = o.key || holder;
    const sdHash = nodeCrypto.createHash('sha256')
      .update(withoutKb, 'ascii').digest('base64url');
    return withoutKb + jws({ alg: signer.alg, typ: 'kb+jwt' },
      { iat: o.iat || Math.floor(Date.now() / 1000), nonce: nonce, aud: aud,
        sd_hash: sdHash }, signer);
  }

  function presentJwtVc(credential, holder, nonce, aud, opts) {
    const o = opts || {};
    const payload = {
      iss: o.iss || 'urn:ietf:params:oauth:jwk-thumbprint:holder',
      aud: aud, nonce: nonce,
      iat: o.iat || Math.floor(Date.now() / 1000),
      vp: { '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiablePresentation'],
            verifiableCredential: [credential] }
    };
    if (o.noProof) {
      return b64u(JSON.stringify({ alg: 'none', typ: 'JWT' })) + '.' +
        b64u(JSON.stringify(payload)) + '.';
    }
    const signer = o.key || holder;
    return jws({ alg: signer.alg, typ: 'JWT' }, payload, signer);
  }

  // The disclosed statements a sign-in asks for: the subject, the issuer,
  // the validity window and the status entries — or, with `o.pick`, the ones
  // that function chooses.
  async function presentLdp(credential, holder, nonce, domain, opts) {
    const o = opts || {};
    const lib = await import('@digitalbazaar/bbs-signatures');
    const suite = lib.CIPHERSUITES.BLS12381_SHA256;
    const keys = await m.helpers.bbsKeyPair();
    const doc = Object.assign({}, credential);
    delete doc.proof;
    const statements = await m.bbs2023.canonicalizedStatements(doc);
    const proofOptions = Object.assign({ '@context': credential['@context'] },
                                       credential.proof);
    delete proofOptions.proofValue;
    const header = await m.bbs2023.headerFor(proofOptions);
    const signature = m.bbs2023.multibaseToBytes(credential.proof.proofValue);
    const wanted = o.pick || function (line) {
      return /credentials#credentialSubject> <did:jwk:/.test(line) ||
             /credentials#issuer>/.test(line) ||
             /credentials#validFrom>/.test(line) ||
             /credentials#validUntil>/.test(line) ||
             /ns\/credentials\/status#/.test(line) ||
             /BitstringStatusListEntry/.test(line);
    };
    const indexes = [];
    statements.forEach(function (line, i) {
      if (wanted(line)) {
        indexes.push(i);
      }
    });
    const te = function (s) { return new TextEncoder().encode(s); };
    const proof = await lib.deriveProof({
      publicKey: keys.publicKey, signature: signature, header: header,
      messages: statements.map(te),
      presentationHeader: te(String(o.bbsNonce || nonce)),
      disclosedMessageIndexes: indexes, ciphersuite: suite });
    const envelope = {
      cryptosuite: 'bbs-2023',
      proof: Buffer.from(proof).toString('base64url'),
      disclosedIndexes: indexes,
      disclosedStatements: indexes.map(function (i) {
        return statements[i];
      }),
      proofOptions: proofOptions
    };
    if (o.bare) {
      return JSON.stringify(envelope);
    }
    const signer = o.key || holder;
    const vp = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: m.di.didJwkOf(holder.jwk),
      verifiableCredential: [envelope]
    };
    if (o.noProof) {
      return JSON.stringify(vp);
    }
    const signed = await m.di.signPresentation(vp, {
      privateKey: signer.alg === 'ML-DSA-44' ? signer.privateJwk
                                             : signer.privateKey,
      publicJwk: signer.jwk, challenge: o.challenge || nonce,
      domain: domain, created: o.created,
      verificationMethod: m.di.didJwkOf(signer.jwk) + '#0' });
    if (o.key) {
      // Claim the bound holder while signing with another key.
      signed.holder = m.di.didJwkOf(holder.jwk);
    }
    return JSON.stringify(signed);
  }

  async function present(format, credential, holder, nonce, aud, opts) {
    if (format === 'jwt_vc_json') {
      return presentJwtVc(credential, holder, nonce, aud, opts);
    }
    if (format === 'ldp_vc') {
      return presentLdp(credential, holder, nonce, aud, opts);
    }
    return presentSdJwt(credential, holder, nonce, aud, opts);
  }

  // ---------------------------------------------------------------------
  // THE SIGN-IN, as a browser drives it.
  // ---------------------------------------------------------------------
  function pendingSignIn(opts) {
    const o = opts || {};
    return m.realms.run(o.realm || DEFAULT, function () {
      const to = m.authn.beginAuthentication(Object.assign({
        returnTo: '/wsi/after', protocol: 'wsi-probe', application: '' },
        o.begin || {}));
      return new URL(to, 'http://x').searchParams.get('authn');
    });
  }

  // ---------------------------------------------------------------------
  // THE SIGN-IN SURFACE'S WALLET PAGES (#574): the shells, the views and
  // the acts at `/authn-api/wallet`, bound as the page binds them — JSON,
  // this service's Origin, and the X-CSRF-Token of the browser's
  // `sts_session` cookie, which the shell mints where the browser has none.
  //
  // `formLike()` reads an act's JSON answer as the page it replaced was
  // read: an answer naming an address (`redirect`, `mfa`) is the 303 it
  // was, `headers.location` that address; anything else keeps its status.
  // `code` is the code the response was marked with, as before.
  // ---------------------------------------------------------------------
  function formLike(r) {
    const j = r.json || {};
    const where = j.location || (j.ok && j.go) || '';
    if (j.ok && where) {
      return Object.assign({}, r, { status: 303, answer: r,
        headers: Object.assign({}, r.headers, { location: where }) });
    }
    return Object.assign({}, r, { answer: r });
  }

  function act(who, urlPath, body, opts) {
    const o = opts || {};
    const headers = { accept: 'application/json' };
    if (o.origin !== null) {
      headers.origin = o.origin === undefined ? origin : o.origin;
    }
    const csrf = o.csrf !== undefined ? o.csrf : (who && who.csrf) || '';
    if (csrf) {
      headers['x-csrf-token'] = csrf;
    }
    return request('POST', urlPath, { browser: who, headers: headers,
                                      json: body });
  }

  // A VERIFICATION, STARTED AS `POST /admin-api/verifications/start`
  // STARTS ONE (#594): through the Verifier's own `startVerification()`, in
  // the realm `o.realm` names. The demonstration's `/oid4vp/start`, which
  // these jobs drove until then, left for the development companion. The
  // answer is read as that page's 302 was: `headers.location` the wallet's
  // address. `query` is the start's names (`by`, `format`, …) as a query
  // string or an object.
  async function verificationStart(query, opts) {
    const o = opts || {};
    const asked = {};
    new URLSearchParams(typeof query === 'string'
      ? query.replace(/^[^?]*\?/, '') : query || {})
      .forEach(function (value, name) {
        asked[name] = value;
      });
    const started = await m.realms.run(o.realm || DEFAULT, function () {
      return m.verifier.startVerification(fakeReq(o.prefix || ''), asked,
                                          'body');
    });
    if (!started.ok) {
      return { status: started.status, json: started, headers: {} };
    }
    return { status: 302, json: started,
             headers: { location: started.walletUrl } };
  }

  // The start, as the start page runs it: its shell (the arrival cookie),
  // its view (the CSRF token), and `POST /authn-api/wallet`; then the wait
  // page's view. `o.mfa` starts it as a second factor; `o.query` adds
  // `siop`, `enrol` or `wallet`.
  async function start(who, authnId, opts) {
    const o = opts || {};
    const p = o.prefix || '';
    const fields = Object.assign(o.mfa ? { mfa: o.mfa } : { authn: authnId },
                                 o.query || {});
    const q = new URLSearchParams(fields).toString();
    const shell = await request('GET', p + '/authn/wallet?' + q,
                                { browser: who });
    const opened = await request('GET', p + '/authn-api/wallet?' + q,
                                 { browser: who });
    if (opened.status !== 200 || !opened.json || !opened.json.ok) {
      return { started: formLike(opened), shell: shell, opened: opened };
    }
    who.csrf = opened.json.csrf;
    const startedRaw = await act(who, p + '/authn-api/wallet', fields);
    const started = formLike(startedRaw);
    if (started.status !== 303) {
      return { started: started, shell: shell, opened: opened };
    }
    const state = startedRaw.json.state;
    const waitPath = p + startedRaw.json.go;
    const waiting = await request('GET', p + '/authn-api/wallet/' +
                                  encodeURIComponent(state), { browser: who });
    const view = (waiting.json && waiting.json.view) || null;
    const walletUrl = view && view.sameDevice ? new URL(view.sameDevice)
                                              : null;
    let requestObject = null;
    if (walletUrl) {
      const ro = await request('GET',
        pathOf(walletUrl.searchParams.get('request_uri')));
      requestObject = decode(ro.text);
    }
    const dcRequest = view ? view.dcRequest : null;
    const u = new URL(waitPath, 'http://x');
    return { started: started, shell: shell, opened: opened,
             waitPath: waitPath, waiting: waiting, view: view,
             walletUrl: walletUrl, requestObject: requestObject,
             dcRequest: dcRequest,
             dcPayload: dcRequest ? decode(dcRequest.data.request) : null,
             authn: u.searchParams.get('authn'),
             mfa: u.searchParams.get('mfa') || '',
             enrol: u.searchParams.get('enrol') || '',
             state: state, prefix: p };
  }

  // A FRESH CSRF TOKEN for a browser whose session changed under it — a
  // sign-in replaces the arrival session, and the token is derived from the
  // session the cookie names: the start view of a new pending sign-in
  // answers the token of the cookie the browser holds now.
  async function refreshCsrf(who, opts) {
    const o = opts || {};
    const id = await pendingSignIn({ realm: o.realm });
    const opened = await request('GET', (o.prefix || '') +
      '/authn-api/wallet?authn=' + encodeURIComponent(id), { browser: who });
    who.csrf = (opened.json && opened.json.csrf) || '';
    return who.csrf;
  }

  // The ids an act on the transaction names beside it.
  function idsOf(s) {
    const out = { authn: s.authn };
    if (s.mfa) {
      out.mfa = s.mfa;
    }
    if (s.enrol) {
      out.enrol = '1';
    }
    return out;
  }

  // THE COLLECTION, as the wait page's poll (and a same-device return)
  // asks for it: `POST …/status`. `o.responseCode` is the code a
  // same-device wallet sent the person back with.
  async function collect(who, s, opts) {
    const o = opts || {};
    const body = idsOf(s);
    if (o.responseCode !== undefined) {
      body.response_code = o.responseCode;
    }
    return formLike(await act(who, s.prefix + '/authn-api/wallet/' +
      encodeURIComponent(s.state) + '/status', body, o));
  }

  // The `response_code` in a wallet's redirect back to the wait page.
  function responseCodeOf(redirect) {
    const m = /[?&]response_code=([^&#]+)/.exec(String(redirect || ''));
    return m ? decodeURIComponent(m[1]) : undefined;
  }

  function vpToken(format, presentation) {
    return JSON.stringify({ [QUERY_IDS[format || 'dc+sd-jwt']]:
                              [presentation] });
  }

  // THE WALLET'S `direct_post`, or — where the request asked for
  // `direct_post.jwt`, as a sign-in does by default since 2026-10-12
  // (`oid4vp.signInResponseMode`) — the same answer ENCRYPTED to the
  // request's ECDH-ES key, as a HAIP wallet sends it. `o.plain` sends it in
  // the clear whatever was asked, which the Response URI refuses.
  async function respond(s, presentation, opts) {
    const o = opts || {};
    const vp = o.raw || vpToken(o.format, presentation);
    return request('POST', (o.prefix || '') + '/oid4vp/response', {
      form: encryptedForm(s.requestObject, { state: s.requestObject.state,
                                             vp_token: vp }, o) });
  }

  // What a wallet posts for `fields` under the request's response mode:
  // the fields themselves for `direct_post`, `{ response }` — a JWE to the
  // request's key, `o.keyAlg` (ECDH-ES by default), with `vp_token` parsed
  // back into the object it is — for `direct_post.jwt`.
  function encryptedForm(requestObject, fields, opts) {
    const o = opts || {};
    const ro = requestObject || {};
    if (ro.response_mode !== 'direct_post.jwt' || o.plain) {
      return fields;
    }
    const payload = Object.assign({}, fields);
    delete payload.state;
    if (typeof payload.vp_token === 'string') {
      try {
        payload.vp_token = JSON.parse(payload.vp_token);
      } catch (e) {
        // A malformed vp_token a test sends on purpose travels as it is.
        payload.vp_token = String(payload.vp_token);
      }
    }
    const keyAlg = o.keyAlg || 'ECDH-ES';
    const key = ((ro.client_metadata || {}).jwks || { keys: [] }).keys
      .filter(function (k) {
        return k.alg === keyAlg;
      })[0];
    return { response: m.stsCrypto.encryptJweCompact(JSON.stringify(payload),
      { alg: keyAlg, enc: 'A128GCM', jwk: key }) };
  }

  // The Digital Credentials API answer, as the page's script posts it.
  // `o.encrypt` (default true where the request asked for dc_api.jwt)
  // encrypts the vp_token to the request's key.
  async function answerDcApi(who, s, dataOrPresentation, opts) {
    const o = opts || {};
    let data = dataOrPresentation;
    if (typeof dataOrPresentation === 'string') {
      const payload = { vp_token: JSON.parse(vpToken(o.format,
                                                     dataOrPresentation)) };
      const jwks = s.dcPayload.client_metadata.jwks;
      if (s.dcPayload.response_mode === 'dc_api.jwt' && o.encrypt !== false) {
        // The request offers a key per alg (#82: the X-Wing hybrid first,
        // ECDH-ES second); `o.keyAlg` picks one, ECDH-ES by default.
        const keyAlg = o.keyAlg || 'ECDH-ES';
        const key = jwks.keys.filter(function (k) {
          return k.alg === keyAlg;
        })[0];
        const jwe = m.stsCrypto.encryptJweCompact(JSON.stringify(payload), {
          alg: keyAlg, enc: 'A128GCM', jwk: o.jwk || key
        });
        data = { response: jwe };
      } else {
        data = payload;
      }
    }
    const response = o.noResponse ? '' : JSON.stringify({
      protocol: o.protocol || s.dcRequest.protocol, data: data });
    // The wait page's runtime sends it to `POST …/dc-api` (#574).
    return formLike(await act(who, s.prefix + '/authn-api/wallet/' +
      encodeURIComponent(s.state) + '/dc-api',
      Object.assign(idsOf(s), { response: response }), o));
  }

  function sessionCookie(r) {
    return r.setCookie.some(function (c) {
      return /^sts_session=[^;]+/.test(c) && !/Max-Age=0/.test(c);
    });
  }

  function sessionOf(who, realm) {
    return m.realms.run(realm || DEFAULT, function () {
      const found = who.cookies.sts_session && m.authn.cookieSession(
        { headers: { cookie: 'sts_session=' + who.cookies.sts_session } },
        m.authn.SESSION_COOKIE);
      // AN ARRIVAL SESSION IS NOBODY'S (`authn.ts`, `startArrivalSession()`):
      // the sign-in screen's shell mints one for a browser without a cookie
      // since #571, and it holds no principal, so it is no sign-in.
      return (found && found.session && found.session.chosen !== false)
        ? found.session : null;
    });
  }

  function inRealm(fn, realm) {
    return m.realms.run(realm || DEFAULT, fn);
  }

  async function finish(outPath) {
    server.close();
    fs.writeFileSync(outPath, JSON.stringify(findings));
  }

  log.debug("Leaving boot().");
  return {
    m: m, DEFAULT: DEFAULT, port: port, base: base, origin: origin,
    note: note, findings: findings, marks: marks, b64u: b64u,
    decode: decode, browser: browser, request: request, pathOf: pathOf,
    unescapeHtml: unescapeHtml, provision: provision, holderKey: holderKey,
    jws: jws, accessTokenFor: accessTokenFor, fakeReq: fakeReq,
    signInAudience: signInAudience,
    issue: issue, presentSdJwt: presentSdJwt, presentJwtVc: presentJwtVc,
    presentLdp: presentLdp, present: present, pendingSignIn: pendingSignIn,
    start: start, collect: collect, act: act, formLike: formLike,
    verificationStart: verificationStart,
    refreshCsrf: refreshCsrf,
    responseCodeOf: responseCodeOf, idsOf: idsOf,
    vpToken: vpToken, respond: respond, encryptedForm: encryptedForm,
    answerDcApi: answerDcApi, sessionCookie: sessionCookie,
    sessionOf: sessionOf, inRealm: inRealm, finish: finish,
    QUERY_IDS: QUERY_IDS, CONFIG_FOR: CONFIG_FOR, client: client
  };
}

module.exports = {
  inAChild: inAChild,
  boot: boot,
  QUERY_IDS: QUERY_IDS,
  CONFIG_FOR: CONFIG_FOR
};
