'use strict';
//
// File: rfc9101_request_object_jti.js
//
// ===========================================================================
// AN RFC 9101 REQUEST OBJECT'S `jti` IS ACCEPTED ONCE (#35, 2026-09-17).
//
// `oauth-oidc/request_object.ts`'s header argues the design: the `jti` is
// LOOKED AT on every pass through the authorization endpoint and SPENT only
// where something is issued on the object, or where the pushed authorization
// request endpoint keeps it. What is held here:
//
//   1. THE LIBRARY, in this process: what an object is remembered by
//      (`onceOf()` — with `exp`, without it, without a `jti`, switched off),
//      the spend and its refusal, `used_assertions.peek()`, and the
//      `keepBelow` line that lets a redirect keep a claim.
//   2. THE ENDPOINT, in a child process on an ephemeral loopback port, for
//      `tests/rfc9101_request_objects.js`'s reason (the protocol stack
//      registers every route on the shared app and builds a CA):
//        a. the passes before the sign-in screen, after it and after the
//           consent screen are ONE use, and a replay afterwards is refused
//           before anybody is asked to sign in;
//        b. a flow started before the object was spent is refused on its
//           return;
//        c. a refused request spends nothing;
//        d. an object with no `jti` is not remembered, another client's
//           `jti` is another document, and the switch turns it all off;
//        e. by reference, the same;
//        f. a pushed object is spent at the push — its URN issues a code,
//           and the object is refused at a second push and by value;
//        g. the used-assertion history lists the spent objects.
//
// **MUTATION RECORD** (2026-09-17; each made in the tree, the tests image
// rebuilt and this file run, the change put back — four mutants, all
// caught):
//
//   * the spend in `issueAuthorizationResponse()` removed: 2c, 2c2, 2d, 2j,
//     2m, 2r, 2s;
//   * `resolve()` never looking (`replayed = null`): 2c, 2c2, 2j, 2m, 2q —
//     and 2d still PASSES, which is the design showing: the spend refuses
//     the late flow on its own, so the look is a courtesy and not the
//     guard;
//   * the spend at the push removed: 2p, 2q, 2r, 2s;
//   * `keepBelow` dropped in `claim()`: 1j, and 2c, 2c2, 2d, 2j, 2m, 2r, 2s
//     with it, because every redirect released its claim.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const events = require('events');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'rfc9101_request_object_jti',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const ro = require('../oauth-oidc/request_object');
const config = require('../common/config');
const usedAssertions = require('../common/used_assertions');

// A response double that emits `finish` with the status it is given.
function finishedWith(status) {
  log.debug("Entering finishedWith().");
  const res = new events.EventEmitter();
  res.statusCode = status;
  log.debug("Leaving finishedWith().");
  return { res: res };
}

// ---------------------------------------------------------------------------
// 1. THE LIBRARY.
// ---------------------------------------------------------------------------
async function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. onceOf, spend, peek and keepBelow ===');
  const skew = Number(config.value('oauth2.clientAssertionSkewS'));
  const exp = Math.floor(Date.now() / 1000) + 120;
  const once = ro.onceOf({ jti: 'j-1', exp: exp }, 'lib-client');
  t.check(once && once.issuer === 'lib-client' && once.identifier === 'j-1' &&
          once.expiresAt === (exp + skew) * 1000,
          '1a. an object with exp is remembered by its client and jti until ' +
          'exp plus the skew', JSON.stringify(once));
  const before = Date.now();
  const open = ro.onceOf({ jti: 'j-2' }, 'lib-client');
  const retention = Number(config.value('oauth2.requestObjectJtiRetentionS'));
  t.check(open && open.expiresAt >= before + retention * 1000 &&
          open.expiresAt <= Date.now() + retention * 1000,
          '1b. one without exp is remembered for ' +
          'oauth2.requestObjectJtiRetentionS', JSON.stringify(open));
  t.equal(ro.onceOf({ exp: exp }, 'lib-client'), null,
          '1c. one without a jti is not remembered at all');
  t.equal(ro.onceOf({ jti: '' }, 'lib-client'), null,
          '1d. nor one with an empty jti');
  config.setOverride('oauth2.requestObjectJtiOnce', false);
  try {
    t.equal(ro.onceOf({ jti: 'j-3', exp: exp }, 'lib-client'), null,
            '1e. oauth2.requestObjectJtiOnce off remembers nothing');
  } finally {
    config.clearOverride('oauth2.requestObjectJtiOnce');
  }

  t.equal(await ro.lookUp(once), null, '1f. a jti nobody has spent is looked ' +
          'at and let through');
  const first = await ro.spend({ once: once });
  t.check(first.ok, '1g. and spent', JSON.stringify(first));
  const looked = await ro.lookUp(once);
  t.check(looked && looked.error === 'invalid_request_object' &&
          /used already — as an RFC 9101 request object/.test(
            looked.description),
          '1h. once spent, a look refuses it with invalid_request_object and ' +
          'says what it was spent as', JSON.stringify(looked));
  const second = await ro.spend({ once: once });
  t.check(!second.ok && second.status === 400 &&
          second.error === 'invalid_request_object',
          '1i. and a second spend is refused, 400', JSON.stringify(second));
  t.check((await ro.spend({ once: null })).ok,
          '1i2. an object with nothing to remember spends nothing and passes');

  const kept = { issuer: 'lib-client', identifier: 'j-redirect',
                 expiresAt: Date.now() + 60000 };
  const redirect = finishedWith(302);
  t.check((await ro.spend({ once: kept, request: redirect,
                            keepBelow: 400 })).ok, '1j0. a claim bound to a ' +
          'response');
  redirect.res.emit('finish');
  t.check((await usedAssertions.peek({ format: 'jwt', issuer: 'lib-client',
                                        identifier: 'j-redirect' })).used,
          '1j. keepBelow 400: a 302 keeps the claim');
  const plain = { issuer: 'lib-client', identifier: 'j-plain',
                  expiresAt: Date.now() + 60000 };
  const other = finishedWith(302);
  await ro.spend({ once: plain, request: other });
  other.res.emit('finish');
  t.check(!(await usedAssertions.peek({ format: 'jwt', issuer: 'lib-client',
                                         identifier: 'j-plain' })).used,
          '1k. without it the 2xx rule stands, and a 302 releases the claim');
  const failed = { issuer: 'lib-client', identifier: 'j-failed',
                   expiresAt: Date.now() + 60000 };
  const broken = finishedWith(500);
  await ro.spend({ once: failed, request: broken, keepBelow: 400 });
  broken.res.emit('finish');
  t.check(!(await usedAssertions.peek({ format: 'jwt', issuer: 'lib-client',
                                         identifier: 'j-failed' })).used,
          '1l. and a 500 releases it under keepBelow too');
  t.check(!(await usedAssertions.peek({ format: 'jwt', issuer: 'lib-other',
                                         identifier: 'j-1' })).used,
          '1m. the key is the client and the jti: another client\'s j-1 is ' +
          'another document');
  const asAssertion = await usedAssertions.claim({
    format: 'jwt', use: 'client-authentication', issuer: 'lib-client',
    identifier: 'j-1', expiresAt: Date.now() + 60000 });
  t.check(!asAssertion.ok && asAssertion.reason === 'replay' &&
          asAssertion.existing.use === 'request-object',
          '1n. one namespace per issuer (RFC 7519 4.1.7): a client assertion ' +
          'with a spent request object\'s jti is a replay',
          JSON.stringify(asAssertion));
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE ENDPOINT, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.JTI_ROOT;
  const OUT = process.env.JTI_OUT;
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
  function sign(payload, key, kid) {
    const input = b64({ alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: kid }) +
                  '.' + b64(payload);
    const signature = crypto.sign('sha256', Buffer.from(input),
                                  { key: key, dsaEncoding: 'ieee-p1363' });
    return input + '.' + signature.toString('base64url');
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
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };
  const local = function (location) {
    return String(location || '').replace(/^https?:\/\/[^/]+/, '');
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const usedAssertions = require(ROOT + '/common/used_assertions');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;

    // The client's own host, for a request object by reference.
    const served = {};
    const roServer = http.createServer(function (req, res) {
      res.writeHead(200, { 'content-type': 'application/oauth-authz-req+jwt' });
      res.end(served[req.url] || '');
    });
    await new Promise(function (r) { roServer.listen(0, '127.0.0.1', r); });
    const RO = 'http://127.0.0.1:' + roServer.address().port;

    config.setOverride('oauth2.consentRequired', false);

    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const ecJwk = Object.assign(ec.publicKey.export({ format: 'jwk' }),
                                { kid: 'jti-ec', use: 'sig' });
    const SECRET = 'jti-client-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.jti.example/cb';
    const make = function (id) {
      applications.createApplication({ identifier: id, protocols: ['oauth2'],
        fields: { oauthClientId: id, oauthClientSecret: SECRET,
          oauthRedirectUri: [REDIRECT],
          oauthTokenEndpointAuthMethod: 'client_secret_basic',
          oauthRequestUri: [RO + '/ro/one'],
          oauthJwks: JSON.stringify({ keys: [ecJwk] }) } });
    };
    ['jti-a', 'jti-b', 'jti-consent'].forEach(make);

    let counter = 0;
    const objectFor = function (clientId, extra) {
      counter += 1;
      const claims = Object.assign({
        iss: clientId, aud: BASE, client_id: clientId,
        response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
        state: 'st-' + counter, nonce: 'n-' + crypto.randomBytes(6)
          .toString('hex'),
        exp: Math.floor(Date.now() / 1000) + 300,
        jti: 'jti-' + counter + '-' + crypto.randomBytes(4).toString('hex')
      }, extra || {});
      Object.keys(claims).forEach(function (k) {
        if (claims[k] === null) {
          delete claims[k];
        }
      });
      return { claims: claims, jwt: sign(claims, ec.privateKey, 'jti-ec') };
    };
    const authorize = function (query) {
      jar = {};
      return request(port, 'GET', '/oauth2/authorize?' +
                     new URLSearchParams(query).toString());
    };
    const byValue = function (clientId, object, extra) {
      return authorize(Object.assign({ client_id: clientId,
                                       request: object.jwt }, extra || {}));
    };
    const toSignIn = function (r) {
      return r.status === 302 &&
             /\/authn\/login/.test(String(r.headers.location || ''));
    };
    const refusedAsUsed = function (r) {
      return r.status === 400 && r.json &&
             r.json.error === 'invalid_request_object' &&
             /used already/.test(r.json.error_description || '');
    };
    const codeAt = function (r, state) {
      const loc = String((r && r.headers && r.headers.location) || '');
      return !!r && r.status === 302 && loc.indexOf(REDIRECT) === 0 &&
             /[?&]code=/.test(loc) &&
             (!state || loc.indexOf('state=' + state) >= 0);
    };
    // The sign-in screen, posted; answers the return URL and the response to
    // it WITHOUT following it, so a test can hold a flow half way.
    const signIn = async function (first, username) {
      const page = await request(port, 'GET', local(first.headers.location),
                                 { cookies: true });
      const form = hiddenFields(page.text);
      form.username = username || 'jti-alice';
      form.password = 'anything';
      form.action = 'login';
      const posted = await request(port, 'POST', '/authn/login',
                                   { form: form, cookies: true });
      return String(posted.headers.location || '');
    };
    const complete = async function (first, username) {
      const back = await signIn(first, username);
      return request(port, 'GET', local(back), { cookies: true });
    };
    const describe = function (r) {
      return r ? r.status + ' ' + (r.headers.location || '') + ' ' +
                 r.text.slice(0, 200) : '(none)';
    };

    // --- a. the passes are one use; a replay is refused before sign-in -------
    const one = objectFor('jti-a');
    let r = await byValue('jti-a', one);
    note(toSignIn(r), '2a. an object with a jti reaches the sign-in screen',
         describe(r));
    let final = await complete(r);
    note(codeAt(final, one.claims.state), '2b. and its second pass, after ' +
         'the sign-in, issues a code: the two passes are one use',
         describe(final));
    r = await byValue('jti-a', one);
    note(refusedAsUsed(r), '2c. the same object again is refused with ' +
         'invalid_request_object before the sign-in screen', describe(r));
    note(r.status === 400 && !/\/authn\/login/.test(r.headers.location || ''),
         '2c2. answered on this server, not by a redirect', describe(r));

    // --- b. a flow started before the spend is refused on its return --------
    const held = objectFor('jti-a');
    const firstFlow = await byValue('jti-a', held);
    const heldBack = await signIn(firstFlow);
    const heldJar = jar;
    const secondFlow = await byValue('jti-a', held);
    final = await complete(secondFlow);
    note(codeAt(final, held.claims.state), '2d0. a second flow on one object ' +
         'issues first', describe(final));
    jar = heldJar;
    r = await request(port, 'GET', local(heldBack), { cookies: true });
    note(refusedAsUsed(r), '2d. and the first flow, returning from its ' +
         'sign-in afterwards, is refused on that pass', describe(r));

    // --- c. a refused request spends nothing ---------------------------------
    const refused = objectFor('jti-a', { prompt: 'none' });
    r = await byValue('jti-a', refused);
    note(r.status === 302 && /error=login_required/.test(
           String(r.headers.location || '')),
         '2e. prompt=none with no session is answered login_required',
         describe(r));
    r = await byValue('jti-a', refused);
    note(!refusedAsUsed(r) && /error=login_required/.test(
           String(r.headers.location || '')),
         '2f. and the same object is not refused as used: an error ' +
         'response spent nothing', describe(r));

    // --- d. no jti, another client, the switch ----------------------------
    const bare = objectFor('jti-a', { jti: null });
    final = await complete(await byValue('jti-a', bare));
    const bareAgain = await complete(await byValue('jti-a', bare));
    note(codeAt(final, bare.claims.state) &&
         codeAt(bareAgain, bare.claims.state),
         '2g. an object with no jti issues a code every time it is sent',
         describe(bareAgain));
    const shared = objectFor('jti-a');
    final = await complete(await byValue('jti-a', shared));
    const sameJti = objectFor('jti-b', { jti: shared.claims.jti });
    r = await byValue('jti-b', sameJti);
    note(codeAt(final, shared.claims.state) && toSignIn(r),
         '2h. another client\'s object with the same jti is another document',
         describe(r));
    config.setOverride('oauth2.requestObjectJtiOnce', false);
    try {
      final = await complete(await byValue('jti-a', shared));
      note(codeAt(final, shared.claims.state),
           '2i. oauth2.requestObjectJtiOnce off: a spent object issues again, ' +
           'which is what this service did before #35', describe(final));
    } finally {
      config.clearOverride('oauth2.requestObjectJtiOnce');
    }
    r = await byValue('jti-a', shared);
    note(refusedAsUsed(r), '2j. and on again, it is refused again',
         describe(r));

    // --- d2. the consent screen is a third pass of the same use --------------
    config.setOverride('oauth2.consentRequired', true);
    try {
      const asked = objectFor('jti-consent', { scope: 'openid email' });
      r = await byValue('jti-consent', asked);
      const toConsent = await complete(r, 'jti-consenter');
      const consentPage = local(toConsent.headers.location);
      const drawn = await request(port, 'GET', consentPage, { cookies: true });
      const form = hiddenFields(drawn.text);
      form.action = 'allow';
      const allowed = await request(port, 'POST', '/oauth2/consent',
                                    { form: form, cookies: true });
      final = await request(port, 'GET', local(allowed.headers.location),
                            { cookies: true });
      note(/\/oauth2\/consent/.test(consentPage) &&
           codeAt(final, asked.claims.state),
           '2k. the passes before sign-in, after it and after the consent ' +
           'screen are one use, and the last issues a code',
           consentPage + ' -> ' + describe(allowed) + ' -> ' +
           describe(final));
    } finally {
      config.setOverride('oauth2.consentRequired', false);
    }

    // --- e. by reference -----------------------------------------------------
    const referenced = objectFor('jti-a');
    served['/ro/one'] = referenced.jwt;
    const byReference = { client_id: 'jti-a', request_uri: RO + '/ro/one' };
    final = await complete(await authorize(byReference));
    note(codeAt(final, referenced.claims.state),
         '2l. an object by reference issues a code', describe(final));
    r = await authorize(byReference);
    note(refusedAsUsed(r), '2m. and the same request_uri, answering the same ' +
         'object, is refused', describe(r));

    // --- f. a pushed object is spent at the push ------------------------------
    const basic = 'Basic ' + Buffer.from('jti-a:' + SECRET).toString('base64');
    const pushed = objectFor('jti-a');
    const push = function (object) {
      return request(port, 'POST', '/oauth2/par', {
        headers: { authorization: basic },
        form: { request: object.jwt }
      });
    };
    r = await push(pushed);
    note(r.status === 201 && r.json && r.json.request_uri,
         '2n. a pushed object with a jti is kept', describe(r));
    const urn = r.json && r.json.request_uri;
    const urnQuery = { client_id: 'jti-a', request_uri: urn };
    const viaUrn = await authorize(urnQuery);
    final = await complete(viaUrn);
    note(toSignIn(viaUrn) && codeAt(final, pushed.claims.state),
         '2o. its URN reaches the sign-in screen and issues a code: the URN ' +
         'spends nothing again', describe(viaUrn) + ' / ' + describe(final));
    r = await push(pushed);
    note(r.status === 400 && r.json &&
         r.json.error === 'invalid_request_object' &&
         /used already/.test(r.json.error_description || ''),
         '2p. the same object pushed again is refused', describe(r));
    r = await byValue('jti-a', pushed);
    note(refusedAsUsed(r), '2q. and so is the pushed object sent by value',
         describe(r));
    const spentFirst = objectFor('jti-a');
    await complete(await byValue('jti-a', spentFirst));
    r = await push(spentFirst);
    note(r.status === 400 && r.json &&
         r.json.error === 'invalid_request_object',
         '2r. an object spent at the authorization endpoint is refused at ' +
         'the push', describe(r));

    // --- g. the history lists them -------------------------------------------
    const listed = await usedAssertions.list({ use: 'request-object',
                                               limit: 100 });
    const ids = listed.rows.map(function (row) {
      return row.identifier;
    });
    note(ids.indexOf(one.claims.jti) >= 0 &&
         ids.indexOf(pushed.claims.jti) >= 0 &&
         ids.indexOf(bare.claims.jti) < 0 &&
         listed.rows.every(function (row) {
           return row.state === 'spent' && row.format === 'jwt';
         }),
         '2s. the used-assertion history lists each spent object as a ' +
         'spent request-object row, by its client and jti',
         JSON.stringify(listed.rows.slice(0, 3)));

    server.close();
    roServer.close();
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
  t.log.info('=== 2. the endpoint, in a child process ===');
  const out = path.join(os.tmpdir(), 'rfc9101-jti-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', JTI_ROOT: ROOT, JTI_OUT: out }),
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
  await library(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc9101 request object jti',
  describe: 'A request object\'s jti is accepted once: looked at on every ' +
            'pass, spent where something is issued or a push is kept',
  run: run
};
