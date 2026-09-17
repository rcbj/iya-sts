'use strict';
//
// File: jose_kid.js
//
// ===========================================================================
// A SIGNED TOKEN'S `kid` MAY BE THE KEY'S RFC 9278 THUMBPRINT URI (2026-09-13).
//
// `common/jose_kid.js` argues the design: `keys.kidFormat`, per realm,
// `internal` by default; the internal kid stays the key's name inside this
// service; the JWK Set lists every signing key under both names while the
// setting is on; a lookup here accepts either name whatever it says. Held:
//
//   A. THE PRIMITIVE. RFC 7638 section 3.1's own RSA example gives RFC 9278's
//      URI byte for byte, and an AKP key hashes exactly `alg`, `kty` and `pub`
//      (RFC 9964) — the members a post-quantum `kid` rests on.
//   B. THE SETTING AND THE LIBRARY. The row is an enum of exactly the
//      library's formats, defaults to `internal`, is runtime and not
//      per-process (so a realm may carry it), and sits in a group a console
//      page draws. `publishedKid()`, `names()` and the JWKS entries, with the
//      setting off and on, and a key with no thumbprint falling back to its
//      internal kid.
//   C. THE WHOLE PATH, IN A CHILD PROCESS on an ephemeral port: a token from
//      /oauth2/token carries the internal kid; with the setting on, its access
//      token and ID Token carry the thumbprint URI, the JWKS lists every
//      signing key twice with the RSA key still first and the second entries
//      before the encryption keys, the token verifies against the entry its
//      kid names, a token signed before the switch still finds its key, x5u is
//      unaffected, an ES256 and a post-quantum signature carry the URI, a
//      Security Event Token signed under the URI verifies here, GNAP's key
//      document names the same kid, turning it off restores both the header
//      and the set while a URI kid is still recognised here, and a realm's own
//      override reaches that realm and not the default one.
//
// **C IS IN A CHILD** for `tests/jose_certificate_header.js`'s reason: loading
// the whole protocol stack into `run.js`'s one process changes what later
// files see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'jose_kid_test',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// RFC 7638 section 3.1's example key and the thumbprint that section gives.
const RFC7638_N = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfA' +
  'AtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY' +
  '4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJ' +
  'ZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0' +
  'fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
const RFC7638_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.JKID_ROOT;
  const OUT = process.env.JKID_OUT;
  const fs = require('fs');
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function request(port, method, urlPath, form) {
    return new Promise(function (resolve, reject) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
        method: method, headers: form ? {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body) } : {} }, function (res) {
        const chunks = [];
        res.on('data', function (c) { chunks.push(c); });
        res.on('error', reject);
        res.on('end', function () {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          let parseError = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // The caller asserts on the status; the reason travels on the
            // result, because this runs in a `node -e` child with no logger.
            parseError = e.message;
            json = null;
          }
          resolve({ status: res.statusCode, text: text, json: json,
                    parseError: parseError });
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  }
  function headerOf(compact) {
    return JSON.parse(Buffer.from(String(compact).split('.')[0], 'base64url')
                            .toString('utf8'));
  }
  const PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';
  function isUri(kid) {
    return String(kid || '').indexOf(PREFIX) === 0;
  }
  // RS256 checked with node against the JWK itself, so nothing of this
  // service's verifies its own signature here.
  function verifiesWith(token, jwk) {
    const parts = String(token).split('.');
    return nodeCrypto.verify('sha256',
      Buffer.from(parts[0] + '.' + parts[1]),
      nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' }),
      Buffer.from(parts[2], 'base64url'));
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const ssfEvents = require(ROOT_DIR + '/ssf/ssf_events');

    const REALM = 'jkidrealm';
    const client = { client_id: 'jkid-client',
                     client_secret: 'jkid-client-secret-0123456789' };
    ldap.createUser('jkid-alice', { invent: false });
    applications.createApplication({ identifier: 'jkid-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'jkid-client',
                oauthClientSecret: client.client_secret,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password', 'refresh_token'] } });
    realms.create({ id: REALM });

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const issue = function () {
      return request(port, 'POST', '/oauth2/token', Object.assign({
        grant_type: 'password', username: 'jkid-alice', password: 'anything',
        scope: 'openid' }, client));
    };
    const jwks = async function (prefix) {
      const r = await request(port, 'GET', (prefix || '') + '/oauth2/jwks');
      return (r.json && Array.isArray(r.json.keys)) ? r.json.keys : [];
    };
    const internalKid = helpers.STS.kid;

    // ---- the default: the internal kid ----------------------------------
    let r = await issue();
    const before = r.json && r.json.access_token;
    note(r.status === 200 && before && headerOf(before).kid === internalKid,
         'C1. with nothing configured, an access token carries the internal ' +
         'kid', r.status + ' ' + (before ? headerOf(before).kid : r.text));
    let keys = await jwks('');
    note(keys.length > 0 && !keys.some(function (k) { return isUri(k.kid); }),
         'C2. and the JWKS names no key by a thumbprint URI',
         keys.map(function (k) { return k.kid; }).join(', '));
    const offCount = keys.length;
    // Fetched now, while the setting is off, so that the signed document is
    // CACHED under the internal kid when the setting changes below.
    const metadata = async function () {
      const m = await request(port, 'GET',
                              '/.well-known/oauth-authorization-server');
      return m.json && m.json.signed_metadata;
    };
    const metaBefore = await metadata();
    note(metaBefore && headerOf(metaBefore).kid === internalKid,
         'C1b. signed_metadata is signed under the internal kid too',
         metaBefore ? headerOf(metaBefore).kid : '(no signed_metadata)');

    // ---- on --------------------------------------------------------------
    config.setOverride('keys.kidFormat', 'jwk-thumbprint-uri');
    r = await issue();
    const access = r.json && r.json.access_token;
    const idToken = r.json && r.json.id_token;
    const rsaUri = stsCrypto.jwkThumbprintUri(
      nodeCrypto.createPublicKey(helpers.STS.certPem)
                .export({ format: 'jwk' }));
    note(r.status === 200 && access && headerOf(access).kid === rsaUri,
         'C3. with keys.kidFormat=jwk-thumbprint-uri the access token\'s kid ' +
         'is the RSA key\'s RFC 9278 URI', access ? headerOf(access).kid :
           r.text);
    note(idToken && headerOf(idToken).kid === rsaUri,
         'C4. and so is the ID Token\'s',
         idToken ? headerOf(idToken).kid : '(no id_token)');
    const metaAfter = await metadata();
    note(metaAfter && headerOf(metaAfter).kid === rsaUri,
         'C4b. and signed_metadata\'s at once, although a copy signed under ' +
         'the internal kid a moment ago is still inside its cache window',
         metaAfter ? headerOf(metaAfter).kid : '(no signed_metadata)');
    note(before && access &&
         (headerOf(before).x5u === undefined) ===
         (headerOf(access).x5u === undefined),
         'C5. the certificate header is unaffected — x5u is found by the ' +
         'internal kid either way',
         JSON.stringify([headerOf(before || '').x5u !== undefined,
                         headerOf(access || '').x5u !== undefined]));

    keys = await jwks('');
    const kids = keys.map(function (k) { return k.kid; });
    const signing = keys.filter(function (k) {
      return k.use !== 'enc' && !isUri(k.kid);
    });
    const uriEntries = keys.filter(function (k) { return isUri(k.kid); });
    note(keys.length && keys[0].kid === internalKid,
         'C6. the RSA key is still keys[0], under its internal kid', kids[0]);
    note(uriEntries.length === signing.length &&
         signing.every(function (k) {
           return kids.indexOf(stsCrypto.jwkThumbprintUri(k)) >= 0;
         }),
         'C7. every signing key is listed a second time under its own ' +
         'thumbprint URI', signing.length + ' signing, ' + uriEntries.length +
         ' URI entries');
    const firstUri = kids.findIndex(isUri);
    const lastSigning = keys.reduce(function (at, k, i) {
      return (k.use !== 'enc' && !isUri(k.kid)) ? i : at;
    }, -1);
    const lastUri = keys.reduce(function (at, k, i) {
      return isUri(k.kid) ? i : at;
    }, -1);
    const firstEnc = keys.findIndex(function (k) { return k.use === 'enc'; });
    note(firstUri > lastSigning && (firstEnc < 0 || firstEnc > lastUri),
         'C8. the second entries follow every signing key and precede the ' +
         'encryption keys', JSON.stringify({ firstUri: firstUri,
           lastSigning: lastSigning, firstEnc: firstEnc }));
    note(keys.length === offCount + uriEntries.length,
         'C9. nothing else in the set changed', offCount + ' -> ' +
         keys.length);
    const named = keys.filter(function (k) { return k.kid === rsaUri; })[0];
    note(named && access && verifiesWith(access, named),
         'C10. the token verifies against the JWKS entry its kid names',
         named ? named.kty : '(no entry)');
    const old = keys.filter(function (k) { return k.kid === internalKid; })[0];
    note(before && old && verifiesWith(before, old),
         'C11. a token signed before the switch still finds its key under ' +
         'the internal kid', old ? old.kid : '(no entry)');

    // ---- other keys ------------------------------------------------------
    const es = helpers.signJwtAs({ sub: 'x' }, 'ES256');
    const esEntry = keys.filter(function (k) {
      return k.kid === headerOf(es).kid;
    })[0];
    note(isUri(headerOf(es).kid) && esEntry && esEntry.crv === 'P-256',
         'C12. an ES256 signature carries its key\'s URI, and the JWKS lists ' +
         'that URI over the P-256 key', headerOf(es).kid);
    const pq = await helpers.signJwtAsAsync({ sub: 'x' }, 'ML-DSA-44');
    const pqKeys = await jwks('');
    const pqEntry = pqKeys.filter(function (k) {
      return k.kid === headerOf(pq).kid;
    })[0];
    note(isUri(headerOf(pq).kid) && pqEntry && pqEntry.kty === 'AKP' &&
         pqEntry.alg === 'ML-DSA-44',
         'C13. an ML-DSA-44 signature carries its AKP key\'s URI ' +
         '(RFC 9964\'s members), and the JWKS lists it', headerOf(pq).kid);

    // ---- verified here ---------------------------------------------------
    [['RS256', 'C14'], ['ES256', 'C15']].forEach(function (pair) {
      const set = ssfEvents.signSetSync({ iss: 'x', jti: 'jkid-' + pair[0],
                                          iat: 1, events: {} },
                                        { algorithm: pair[0] });
      const verdict = ssfEvents.verifySet(set, headerOf(set));
      note(isUri(headerOf(set).kid) && verdict.verified,
           pair[1] + '. a ' + pair[0] + ' Security Event Token signed under ' +
           'the URI kid is verified here against this service\'s own key',
           headerOf(set).kid + ' ' + verdict.note);
    });
    const gnap = await request(port, 'GET', '/gnap/keys');
    note(gnap.status !== 200 ||
         (gnap.json && gnap.json.jwt && gnap.json.jwt.kid === rsaUri),
         'C16. GNAP\'s key document names the kid its jwt-signed tokens carry',
         gnap.status + ' ' + (gnap.json && gnap.json.jwt &&
                              gnap.json.jwt.kid));

    // ---- off again -------------------------------------------------------
    config.clearOverride('keys.kidFormat');
    r = await issue();
    const after = r.json && r.json.access_token;
    keys = await jwks('');
    note(after && headerOf(after).kid === internalKid &&
         !keys.some(function (k) { return isUri(k.kid); }),
         'C18. turning it off restores the internal kid and drops the second ' +
         'entries', after ? headerOf(after).kid : r.text);
    note(helpers.kidNamesKey(rsaUri, internalKid) &&
         !helpers.kidNamesKey(headerOf(es).kid, internalKid),
         'C19. a URI kid is still recognised here as this key\'s — and ' +
         'another key\'s URI is not');

    // ---- one realm carrying it -------------------------------------------
    // A process-wide override reaches every realm, as any setting does; a
    // REALM's override reaches that realm alone.
    realms.run(realms.get(REALM), function () {
      config.setOverride('keys.kidFormat', 'jwk-thumbprint-uri');
    });
    const realmKid = realms.run(realms.get(REALM), function () {
      return [helpers.STS.kid, helpers.publishedKidFor(helpers.STS.kid)];
    });
    const realmKeys = await jwks('/realm/' + REALM);
    const defaultKeys = await jwks('');
    note(isUri(realmKid[1]) && realmKeys.some(function (k) {
      return k.kid === realmKid[1];
    }), 'C20. a realm carrying the setting signs under its own key\'s URI ' +
         'and lists it in its own JWKS', realmKid.join(' / '));
    note(helpers.publishedKidFor(helpers.STS.kid) === internalKid &&
         !defaultKeys.some(function (k) { return isUri(k.kid); }),
         'C21. while the default realm, which does not, keeps its internal ' +
         'kid and its JWKS', helpers.publishedKidFor(helpers.STS.kid));
    realms.run(realms.get(REALM), function () {
      config.clearOverride('keys.kidFormat');
    });

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw', detail: e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const stsCrypto = require('../common/crypto');
  const joseKid = require('../common/jose_kid');

  // -------------------------------------------------------------------------
  t.log.info('=== A. the primitive ===');
  t.equal(stsCrypto.jwkThumbprint({ kty: 'RSA', n: RFC7638_N, e: 'AQAB',
                                    alg: 'RS256', kid: '2011-04-29' }),
          RFC7638_THUMBPRINT,
          'RFC 7638 section 3.1\'s example key hashes to the thumbprint that ' +
          'section gives, its alg and kid ignored');
  t.equal(stsCrypto.jwkThumbprintUri({ kty: 'RSA', n: RFC7638_N, e: 'AQAB' }),
          'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' + RFC7638_THUMBPRINT,
          'and its RFC 9278 URI is that thumbprint under the sha-256 prefix');
  const akp = { kty: 'AKP', alg: 'ML-DSA-44', pub: 'cHVibGljLWJ5dGVz',
                use: 'sig', kid: 'ignored' };
  t.equal(stsCrypto.jwkThumbprint(akp),
          nodeCrypto.createHash('sha256')
            .update('{"alg":"ML-DSA-44","kty":"AKP","pub":"cHVibGljLWJ5dGVz"}')
            .digest('base64url'),
          'an AKP key hashes exactly alg, kty and pub, in that order');

  // -------------------------------------------------------------------------
  t.log.info('=== B. the setting and the library ===');
  const row = config.SETTINGS.filter(function (one) {
    return one.key === joseKid.SETTING;
  })[0] || {};
  t.equal(JSON.stringify({ type: row.type, values: row.enumValues,
                           dflt: row.dflt, runtime: row.runtime,
                           perProcess: !!row.perProcess }),
          JSON.stringify({ type: 'enum', values: joseKid.FORMATS,
                           dflt: 'internal', runtime: true,
                           perProcess: false }),
          'keys.kidFormat is an enum of exactly the library\'s formats, ' +
          'internal by default, runtime and not per-process');
  let admin = '';
  try {
    admin = fs.readFileSync(path.join(ROOT, 'admin-ui', 'admin.ts'), 'utf8');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    admin = '';
  }
  t.check(admin.indexOf("group: '" + row.group + "'") >= 0,
          'and its group is one SETTING_HOMES draws on a console page',
          row.group);

  const jwk = { kty: 'RSA', n: RFC7638_N, e: 'AQAB', use: 'sig',
                kid: 'jkid-unit-rsa' };
  const uri = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' +
              RFC7638_THUMBPRINT;
  try {
    t.equal(joseKid.publishedKid('jkid-unit-rsa', jwk), 'jkid-unit-rsa',
            'with the setting off, a header carries the internal kid');
    t.equal(joseKid.thumbprintUriEntries([jwk]).length, 0,
            'and a JWK Set gets no second entries');
    config.setOverride(joseKid.SETTING, 'jwk-thumbprint-uri');
    t.equal(joseKid.publishedKid('jkid-unit-rsa', function () {
      return jwk;
    }), uri, 'with it on, the thumbprint URI');
    const entries = joseKid.withThumbprintUriEntries([jwk]);
    t.equal(JSON.stringify(entries.map(function (k) { return k.kid; })),
            JSON.stringify(['jkid-unit-rsa', uri]),
            'the set keeps the entry and adds one under the URI');
    t.equal(entries[1].n, RFC7638_N, 'over the same key');
    t.equal(joseKid.publishedKid('jkid-unit-bad', { kty: 'nope' }),
            'jkid-unit-bad',
            'a key with no thumbprint falls back to its internal kid');
    t.equal(joseKid.thumbprintUriEntries([{ kty: 'nope',
                                            kid: 'jkid-unit-bad' }]).length,
            0, 'and gets no second entry, so the set and the tokens agree');
    config.clearOverride(joseKid.SETTING);
    t.check(joseKid.names(uri, 'jkid-unit-rsa', jwk) &&
            joseKid.names('jkid-unit-rsa', 'jkid-unit-rsa', jwk),
            'a lookup accepts either name with the setting off again');
    t.check(!joseKid.names(uri.slice(0, -1) + 'A', 'jkid-unit-rsa', jwk) &&
            !joseKid.names('sts-other', 'jkid-unit-rsa', jwk),
            'and neither another URI nor another internal kid');
  } finally {
    config.clearOverride(joseKid.SETTING);
  }

  // -------------------------------------------------------------------------
  t.log.info('=== C. the whole path, in a child process ===');
  const out = path.join(os.tmpdir(), 'jkid-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', JKID_ROOT: ROOT,
                           JKID_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
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
  name: 'jose_kid',
  describe: 'a signed token\'s kid may be its key\'s RFC 9278 JWK Thumbprint ' +
            'URI — keys.kidFormat, per realm, internal by default — with the ' +
            'JWKS listing every signing key under both names while it is on',
  run: run
};
