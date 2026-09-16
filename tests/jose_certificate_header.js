'use strict';
//
// File: jose_certificate_header.js
//
// ===========================================================================
// A SIGNED TOKEN NAMES THE CERTIFICATE CHAIN OF ITS KEY (2026-09-13).
//
// `common/jose_certificate_header.js` argues the design: every JWT this
// service signs with a certified key may carry `x5c` (the chain inline) or
// `x5u` (the address of the chain on this service), chosen per use case and
// per realm, `x5u` by default. What is held here:
//
//   A. THE TABLE AND THE SETTINGS AGREE. `config.js` cannot require that
//      module, so the twelve rows are written there and the list of use cases
//      here; each row exists, is an enum of exactly `MODES`, defaults to
//      `x5u`, is runtime (so a realm may carry it), sits in a group a console
//      page draws — and no `*CertificateHeader` row exists that the table does
//      not know.
//   B. EVERY SIGNER NAMES A USE CASE. A scan of the source for every call that
//      signs a JWS — `signJwt`, `signJwtAs`, `signJwtAsAsync`, `.signJws`,
//      `.signJwsAsync`, `signPublishedDocument` — outside the primitive itself.
//      Each must name one or carry `// certificate-header: none — <why>`. This
//      is what makes "anywhere a certified key signs" a property of the build
//      rather than of a reviewer's memory, and it is the only section that
//      fails when a NEW signer is added and forgotten. Every use-case id named
//      in the source must be one the table has, and every row must be named
//      somewhere.
//   C. THE WHOLE PATH, IN A CHILD PROCESS on an ephemeral port: a token from
//      /oauth2/token carries `x5u`; that address answers the PEM chain; the
//      chain links to the service Root; the token's signature verifies with the
//      key IN the leaf, which is the one thing that proves the certificate is
//      over the signing key; the leaf names its CRL and OCSP responder. Then
//      `x5c`, `both` and `none` (byte for byte what an untouched signer made);
//      one use case changed without moving another; a realm's override
//      reaching its own tokens and not the default realm's; the signed_metadata
//      cache seeing a changed setting at once; an ES256 key and an HMAC; no
//      `x5u` without a request or a pinned base; a pinned base naming the
//      origin; a register row over another key giving no header at all; the
//      refresh token's inner JWS; a Security Event Token; and the endpoint's
//      refusals.
//
// **C IS IN A CHILD** for `tests/refresh_token_encryption.js`'s reason: loading
// the whole protocol stack into `run.js`'s one process builds a certificate
// authority and registers every route on the shared app, which changes what
// later files see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'jose_certificate_header',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// B's scope. The PRIMITIVE is excluded — `common/crypto.js` takes a header as a
// parameter and decides nothing — and so is everything this repository may not
// edit or that is not the service.
// ---------------------------------------------------------------------------
const SKIP_DIRS = ['node_modules', 'node-ldapjs', 'tests', 'docs', '.git',
                   'vendored', 'coverage', '.claude'];
const SKIP_FILES = ['common/crypto.js'];

const SIGNING_CALL = /(?:\bsignJwt|\bsignJwtAs|\bsignJwtAsAsync|\.signJws|\.signJwsAsync|\bsignPublishedDocument)\(/g;

function jsFilesUnder(dir, out) {
  log.debug("Entering jsFilesUnder().");
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.indexOf(entry.name) < 0) {
        jsFilesUnder(path.join(dir, entry.name), out);
      }
      return;
    }
    if (/\.js$/.test(entry.name)) {
      out.push(path.join(dir, entry.name));
    }
  });
  log.debug("Leaving jsFilesUnder().");
  return out;
}

// The STATEMENT a call is in, read as text from the call to the first `;` —
// the style sweep broke long calls over several lines, so a line is not a
// statement, which is the lesson `tests/error_codes.js` records.
function statementFrom(text, index) {
  log.debug("Entering statementFrom().");
  const end = text.indexOf(';', index);
  log.debug("Leaving statementFrom().");
  return text.slice(index, end < 0 ? text.length : end + 1);
}

function lineOf(text, index) {
  log.debug("Entering lineOf().");
  log.debug("Leaving lineOf().");
  return text.slice(0, index).split('\n').length;
}

function scanSigners() {
  log.debug("Entering scanSigners().");
  const uncovered = [];
  const exemptWithoutReason = [];
  const named = [];
  jsFilesUnder(ROOT, []).forEach(function (file) {
    const rel = path.relative(ROOT, file).split(path.sep).join('/');
    if (SKIP_FILES.indexOf(rel) >= 0) {
      return;
    }
    const text = fs.readFileSync(file, 'utf8');
    const lines = text.split('\n');
    let match;
    SIGNING_CALL.lastIndex = 0;
    while ((match = SIGNING_CALL.exec(text)) !== null) {
      const lineNo = lineOf(text, match.index);
      const line = lines[lineNo - 1];
      const trimmed = line.trim();
      // A comment, a definition and a name quoted in a string — a log line, a
      // sentence on a page — are not calls.
      const column = match.index - text.lastIndexOf('\n', match.index) - 1;
      const before = line.slice(0, column);
      const unescaped = before.replace(/\\./g, '');
      const insideString = ['\'', '"', '`'].some(function (quote) {
        return (unescaped.split(quote).length - 1) % 2 === 1;
      });
      if (/^(\/\/|\*)/.test(trimmed) || before.indexOf('//') >= 0 ||
          /\bfunction\s*$/.test(before) || insideString) {
        continue;
      }
      const statement = statementFrom(text, match.index);
      const above = lines.slice(Math.max(0, lineNo - 4), lineNo).join('\n');
      if (/certificate-header: none/.test(above)) {
        if (!/certificate-header: none\s*—\s*\S/.test(above)) {
          exemptWithoutReason.push(rel + ':' + lineNo);
        }
        continue;
      }
      const ids = [];
      const idPattern =
        /certificateHeader(?:For)?\s*:?\s*\(?\s*'([a-z0-9-]+)'/g;
      let one;
      while ((one = idPattern.exec(statement)) !== null) {
        ids.push(one[1]);
      }
      const published = /'((?:oauth|vci)-signed-metadata)'/.exec(statement);
      if (published) {
        ids.push(published[1]);
      }
      ids.forEach(function (id) {
        named.push({ id: id, where: rel + ':' + lineNo });
      });
      if (!ids.length && !/[cC]ertificateHeader/.test(statement)) {
        uncovered.push(rel + ':' + lineNo + '  ' + trimmed.slice(0, 70));
      }
    }
  });
  log.debug("Leaving scanSigners(). " + uncovered.length + " uncovered.");
  return { uncovered: uncovered, exemptWithoutReason: exemptWithoutReason,
           named: named };
}

// ---------------------------------------------------------------------------
// C, in a child. Everything it needs is required inside, so the function can
// be shipped as source with `node -e`.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.JCH_ROOT;
  const OUT = process.env.JCH_OUT;
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
            // Not JSON — the chain endpoint answers PEM. The caller asserts on
            // the text; the reason travels on the result, because this runs in
            // a `node -e` child with no logger.
            parseError = e.message;
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: json, parseError: parseError });
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
  function pemsIn(text) {
    return String(text).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  }
  function b64Of(pem) {
    return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  }
  function pemOfB64(b64) {
    return '-----BEGIN CERTIFICATE-----\n' +
           b64.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
  }
  function sleep(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const pki = require(ROOT_DIR + '/common/pki');
    const certificateHeader = require(ROOT_DIR +
                                      '/common/jose_certificate_header');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const rtCrypto = require(ROOT_DIR + '/oauth-oidc/refresh_token_crypto');
    const ssfEvents = require(ROOT_DIR + '/ssf/ssf_events');
    const jwt = require('jsonwebtoken');

    const REALM = 'jchrealm';
    const client = { client_id: 'jch-client',
                     client_secret: 'jch-client-secret-0123456789' };
    const registration = { identifier: 'jch-client', protocols: ['oauth2'],
      fields: { oauthClientId: 'jch-client',
                oauthClientSecret: client.client_secret,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password', 'refresh_token'] } };
    ldap.createUser('jch-alice', { invent: false });
    applications.createApplication(registration);
    realms.create({ id: REALM });
    realms.run(realms.get(REALM), function () {
      ldap.createUser('jch-alice', { invent: false });
      applications.createApplication(registration);
    });
    await pki.ensureScope(REALM);

    // The keys of both realms, made and certified. Certification is
    // asynchronous after a key set is made, so this waits for the register.
    const defaultKid = helpers.STS.kid;
    const realmKid = realms.run(realms.get(REALM), function () {
      return helpers.STS.kid;
    });
    const certifiedIn = function (realmId, slot) {
      return !!pki.certificateFor(realmId, 'jose', slot);
    };
    const allCertified = function () {
      return certifiedIn('default', 'RS256') && certifiedIn(REALM, 'RS256') &&
             certifiedIn('default', 'ES256:P-256');
    };
    for (let i = 0; i < 30 && !allCertified(); i++) {
      await sleep(100);
    }
    // A realm's keys made before its branch existed were not certified by the
    // hook that runs when they are made, so ask once, as a restart would.
    if (!allCertified()) {
      await pki.certifyKeySet(REALM, helpers.stsKeysFor.of(REALM));
      await pki.certifyKeySet('default', helpers.stsKeysFor.of('default'));
    }
    for (let i = 0; i < 50 && !allCertified(); i++) {
      await sleep(100);
    }
    note(certifiedIn('default', 'RS256') && certifiedIn(REALM, 'RS256'),
         'C0. both realms\' RS256 keys are certified under their JOSE ' +
         'Issuing CAs — the precondition everything below rests on',
         defaultKid + ' / ' + realmKid);

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const origin = 'http://127.0.0.1:' + port;
    const issue = function (prefix) {
      return request(port, 'POST', prefix + '/oauth2/token', Object.assign({
        grant_type: 'password', username: 'jch-alice', password: 'anything',
        scope: 'openid' }, client));
    };

    // ---- the default: x5u ------------------------------------------------
    let r = await issue('');
    const access = r.json && r.json.access_token;
    const idToken = r.json && r.json.id_token;
    const aHeader = access ? headerOf(access) : {};
    note(r.status === 200 && typeof aHeader.x5u === 'string' &&
         aHeader.x5c === undefined,
         'C1. with nothing configured, an access token from /oauth2/token ' +
         'carries x5u and not x5c', r.status + ' ' + JSON.stringify(aHeader));
    const expectedPrefix = origin + '/pki/chain/default/';
    note(String(aHeader.x5u).indexOf(expectedPrefix) === 0 &&
         /\/[0-9a-f]{64}\.pem$/.test(String(aHeader.x5u)),
         'C2. and it names this service\'s own origin — the one the request ' +
         'arrived at — the default realm\'s scope and a SHA-256',
         aHeader.x5u);
    note(idToken && typeof headerOf(idToken).x5u === 'string',
         'C3. the ID Token beside it carries x5u too, under its own setting',
         idToken ? JSON.stringify(headerOf(idToken)) : '(no id_token)');

    const chainPath = String(aHeader.x5u).slice(origin.length);
    const fetched = await request(port, 'GET', chainPath);
    const pems = pemsIn(fetched.text);
    note(fetched.status === 200 &&
         /application\/pem-certificate-chain/.test(
           fetched.headers['content-type']) &&
         fetched.headers['cache-control'] === 'no-store',
         'C4. the x5u address answers the chain as ' +
         'application/pem-certificate-chain, no-store',
         fetched.status + ' ' + fetched.headers['content-type'] + ' ' +
         fetched.headers['cache-control']);
    const certs = pems.map(function (p) {
      return new nodeCrypto.X509Certificate(p);
    });
    let links = certs.length === 4;
    for (let i = 0; links && i < certs.length - 1; i++) {
      links = certs[i].issuer === certs[i + 1].subject &&
              certs[i].verify(certs[i + 1].publicKey);
    }
    const rootPem = pki.serviceRoot().certificatePem;
    note(links && b64Of(pems[3]) === b64Of(rootPem),
         'C5. it is the FULL chain — leaf, Issuing CA, Intermediate, Root — ' +
         'each link signed by the next, ending at this service\'s Root',
         certs.length + ' certificate(s): ' +
         certs.map(function (c) { return c.subject.split('\n').pop(); })
              .join(' <- '));
    let verified = false;
    try {
      jwt.verify(access, certs[0].publicKey.export({ type: 'spki',
                                                       format: 'pem' }),
                 { algorithms: ['RS256'] });
      verified = true;
    } catch (e) {
      verified = 'refused: ' + e.message;
    }
    note(verified === true,
         'C6. the token\'s signature verifies with the key IN THE LEAF — the ' +
         'certificate is over the key that signed, which RFC 7515 requires',
         verified);
    const leafDer = Buffer.from(b64Of(pems[0]), 'base64').toString('latin1');
    note(/OCSP/.test(String(certs[0].infoAccess)) &&
         leafDer.indexOf('/pki/crl/') >= 0,
         'C7. and the leaf names its OCSP responder and its CRL distribution ' +
         'point, which is what the header exists to carry',
         String(certs[0].infoAccess).replace(/\n/g, ' | '));

    let inner = null;
    try {
      inner = rtCrypto.open(String(r.json.refresh_token || ''));
    } catch (e) {
      inner = null;
      note(false, 'C8. the refresh token opens', e.message);
    }
    note(!!inner && typeof headerOf(inner).x5u === 'string',
         'C8. the signed JWT INSIDE the refresh token carries x5u',
         inner ? JSON.stringify(headerOf(inner)) : '(no refresh token)');

    // ---- x5c, both, none, per use case -----------------------------------
    config.setOverride('oauth2.accessTokenCertificateHeader', 'x5c');
    r = await issue('');
    const x5cHeader = headerOf(r.json.access_token);
    note(Array.isArray(x5cHeader.x5c) && x5cHeader.x5u === undefined &&
         x5cHeader.x5c.join(',') === pems.map(b64Of).join(','),
         'C9. set to x5c, the access token carries the SAME chain inline, ' +
         'base64 DER, and no x5u',
         JSON.stringify(Object.keys(x5cHeader)) + ' ' +
         (x5cHeader.x5c || []).length);
    note(typeof headerOf(r.json.id_token).x5u === 'string' &&
         headerOf(r.json.id_token).x5c === undefined,
         'C10. while the ID Token, whose setting was not touched, still ' +
         'carries x5u — one use case moves without another',
         JSON.stringify(Object.keys(headerOf(r.json.id_token))));
    config.setOverride('oauth2.accessTokenCertificateHeader', 'both');
    r = await issue('');
    const bothHeader = headerOf(r.json.access_token);
    note(Array.isArray(bothHeader.x5c) && typeof bothHeader.x5u === 'string',
         'C11. set to both, it carries both',
         JSON.stringify(Object.keys(bothHeader)));
    config.setOverride('oauth2.accessTokenCertificateHeader', 'none');
    r = await issue('');
    const noneHeader = headerOf(r.json.access_token);
    note(Object.keys(noneHeader).sort().join(',') === 'alg,kid,typ',
         'C12. set to none, the header is alg, typ and kid and nothing else',
         JSON.stringify(noneHeader));
    const fixed = { sub: 'byte-for-byte', iat: 1700000000 };
    const named = helpers.signJwtAs(fixed, 'RS256', null,
                                    { certificateHeader: 'access-token' });
    const unnamed = helpers.signJwtAs(fixed, 'RS256', null);
    note(named === unnamed,
         'C13. and a token signed under none is BYTE FOR BYTE the token a ' +
         'signer naming no use case makes', named.length + ' / ' +
         unnamed.length);
    config.clearOverride('oauth2.accessTokenCertificateHeader');

    // ---- a realm ---------------------------------------------------------
    realms.run(realms.get(REALM), function () {
      config.setOverride('oauth2.accessTokenCertificateHeader', 'x5c');
    });
    const inRealm = await issue('/realm/' + REALM);
    const realmHeader = inRealm.json ? headerOf(inRealm.json.access_token) : {};
    const realmIdHeader = inRealm.json ? headerOf(inRealm.json.id_token) : {};
    const realmLeaf = Array.isArray(realmHeader.x5c)
      ? new nodeCrypto.X509Certificate(pemOfB64(realmHeader.x5c[0])) : null;
    note(inRealm.status === 200 && realmLeaf &&
         realmHeader.x5c[0] !== pems.map(b64Of)[0] &&
         realmHeader.x5c[realmHeader.x5c.length - 1] === b64Of(rootPem),
         'C14. a realm carrying x5c gets its OWN leaf inline, under the same ' +
         'Root',
         inRealm.status + ' ' + JSON.stringify(Object.keys(realmHeader)));
    note(String(realmIdHeader.x5u).indexOf(origin + '/pki/chain/' + REALM +
                                          '/') === 0,
         'C15. and its ID Token\'s x5u names the realm\'s scope',
         realmIdHeader.x5u);
    r = await issue('');
    note(typeof headerOf(r.json.access_token).x5u === 'string' &&
         headerOf(r.json.access_token).x5c === undefined,
         'C16. while the DEFAULT realm\'s access token is still x5u — the ' +
         'realm\'s override stayed in the realm',
         JSON.stringify(Object.keys(headerOf(r.json.access_token))));
    const realmChain = await request(port, 'GET',
                                     String(realmIdHeader.x5u)
                                       .slice(origin.length));
    const realmThumb = /([0-9a-f]{64})\.pem$/.exec(String(realmIdHeader.x5u));
    const crossScope = realmThumb ? await request(port, 'GET',
      '/pki/chain/default/' + realmThumb[1] + '.pem') : { status: 0 };
    const notHex = await request(port, 'GET', '/pki/chain/default/zzz.pem');
    const unknown = await request(port, 'GET', '/pki/chain/default/' +
                                  'a'.repeat(64));
    note(realmChain.status === 200 && pemsIn(realmChain.text).length === 4 &&
         crossScope.status === 404 && notHex.status === 404 &&
         unknown.status === 404,
         'C17. the realm\'s chain answers in its own scope, and a 404 ' +
         'answers its certificate in another scope, a value that is not a ' +
         'SHA-256 and a SHA-256 of nothing',
         [realmChain.status, crossScope.status, notHex.status,
          unknown.status].join(' '));

    // ---- signed_metadata's cache sees the setting ------------------------
    const metaBefore = await request(port, 'GET',
                                     '/.well-known/oauth-authorization-server');
    config.setOverride('oauth2.signedMetadataCertificateHeader', 'x5c');
    const metaAfter = await request(port, 'GET',
                                    '/.well-known/oauth-authorization-server');
    config.clearOverride('oauth2.signedMetadataCertificateHeader');
    const smBefore = metaBefore.json && metaBefore.json.signed_metadata;
    const smAfter = metaAfter.json && metaAfter.json.signed_metadata;
    note(smBefore && typeof headerOf(smBefore).x5u === 'string' &&
         smAfter && Array.isArray(headerOf(smAfter).x5c),
         'C18. signed_metadata carries x5u, and a changed setting is seen ON ' +
         'THE NEXT FETCH — the cached signature is keyed by it',
         (smBefore ? JSON.stringify(Object.keys(headerOf(smBefore))) : '-') +
         ' then ' +
         (smAfter ? JSON.stringify(Object.keys(headerOf(smAfter))) : '-'));

    // ---- the helper directly, with no request ------------------------------
    config.setOverride('wstrust.jwtCertificateHeader', 'x5c');
    const es = helpers.signJwtAs({ sub: 'es' }, 'ES256', null,
                                 { certificateHeader: 'wstrust-jwt' });
    const esHeader = headerOf(es);
    let esVerified = false;
    try {
      const esLeaf = new nodeCrypto.X509Certificate(pemOfB64(esHeader.x5c[0]));
      jwt.verify(es, esLeaf.publicKey.export({ type: 'spki', format: 'pem' }),
                 { algorithms: ['ES256'] });
      esVerified = true;
    } catch (e) {
      esVerified = 'refused: ' + e.message;
    }
    note(esVerified === true,
         'C19. an ES256 signature names the P-256 key\'s OWN certificate, ' +
         'and verifies with the key in it', esVerified);
    const hs = helpers.signJwtAs({ sub: 'hs' }, 'HS256', 'a-client-secret',
                                 { certificateHeader: 'wstrust-jwt' });
    note(headerOf(hs).x5c === undefined && headerOf(hs).x5u === undefined,
         'C20. an HS256 signature carries neither — a client\'s secret has ' +
         'no certificate', JSON.stringify(headerOf(hs)));
    note(JSON.stringify(helpers.certificateHeaderFor('no-such-use-case',
                                                     'RS256', defaultKid)) ===
         '{}',
         'C21. a use case the table does not have gives nothing');
    config.setOverride('wstrust.jwtCertificateHeader', 'x5u');
    const bare = helpers.certificateHeaderFor('wstrust-jwt', 'RS256',
                                              defaultKid);
    note(bare.x5u === undefined,
         'C22. x5u with no request and no pinned base names nothing rather ' +
         'than guessing an origin', JSON.stringify(bare));
    const fakeReq = { protocol: 'https', headers: {},
                      get: function () { return 'sts.example.test:8443'; } };
    const ambient = certificateHeader.enterRequest(fakeReq, function () {
      return helpers.certificateHeaderFor('wstrust-jwt', 'RS256', defaultKid);
    });
    note(String(ambient.x5u).indexOf(
           'https://sts.example.test:8443/pki/chain/default/') === 0,
         'C23. inside a request, the origin is the request\'s own',
         ambient.x5u);
    config.setOverride('global.publicBaseUrl', 'https://idp.example.test');
    const pinned = certificateHeader.enterRequest(fakeReq, function () {
      return helpers.certificateHeaderFor('wstrust-jwt', 'RS256', defaultKid);
    });
    config.clearOverride('global.publicBaseUrl');
    note(String(pinned.x5u).indexOf(
           'https://idp.example.test/pki/chain/default/') === 0,
         'C24. and a pinned global.publicBaseUrl wins over the request\'s Host',
         pinned.x5u);

    // ---- a register row over a different key -----------------------------
    const record = pki.certificateFor('default', 'jose', 'RS256');
    const saved = { thumbprint: record.thumbprint,
                    subjectKeyFingerprint: record.subjectKeyFingerprint };
    record.thumbprint = 'f'.repeat(64);
    record.subjectKeyFingerprint = 'e'.repeat(64);
    config.setOverride('wstrust.jwtCertificateHeader', 'both');
    const mismatched = helpers.certificateHeaderFor('wstrust-jwt', 'RS256',
                                                    defaultKid);
    record.thumbprint = saved.thumbprint;
    record.subjectKeyFingerprint = saved.subjectKeyFingerprint;
    note(JSON.stringify(mismatched) === '{}',
         'C25. a certificate on record over a DIFFERENT key gives no header ' +
         'at all, rather than a certificate that does not hold the signing key',
         JSON.stringify(mismatched));
    config.clearOverride('wstrust.jwtCertificateHeader');

    // ---- a Security Event Token -------------------------------------------
    config.setOverride('ssf.setCertificateHeader', 'x5c');
    const set = ssfEvents.signSetSync({ iss: 'x', jti: 'set-1', iat: 1,
                                        events: {} }, { algorithm: 'RS256' });
    config.clearOverride('ssf.setCertificateHeader');
    note(Array.isArray(headerOf(set).x5c) &&
         headerOf(set).typ === 'secevent+jwt',
         'C26. a Security Event Token carries x5c under its own setting, and ' +
         'keeps the typ RFC 8417 gives it', JSON.stringify(
           Object.keys(headerOf(set))));

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
  const certificateHeader = require('../common/jose_certificate_header');

  // -------------------------------------------------------------------------
  t.log.info('=== A. the use-case table and the settings agree ===');
  const rows = {};
  config.SETTINGS.forEach(function (row) {
    rows[row.key] = row;
  });
  const bad = [];
  certificateHeader.USE_CASES.forEach(function (uc) {
    const row = rows[uc.setting];
    if (!row) {
      bad.push(uc.id + ': no row ' + uc.setting);
      return;
    }
    if (row.type !== 'enum' ||
        (row.enumValues || []).join(',') !==
        certificateHeader.MODES.join(',') ||
        row.dflt !== certificateHeader.DEFAULT_MODE || row.runtime !== true ||
        row.perProcess) {
      bad.push(uc.setting + ': ' + JSON.stringify({ type: row.type,
        values: row.enumValues, dflt: row.dflt, runtime: row.runtime }));
    }
  });
  t.equal(bad.join('; '), '',
          'every use case has its setting, an enum of exactly none/x5c/x5u/' +
          'both, defaulting to x5u, runtime and so settable per realm');
  t.equal(certificateHeader.DEFAULT_MODE, 'x5u', 'and the default is x5u');
  const strays = Object.keys(rows).filter(function (key) {
    return /CertificateHeader$/.test(key) &&
      !certificateHeader.USE_CASES.some(function (uc) {
        return uc.setting === key;
      });
  });
  t.equal(strays.join(', '), '',
          'no *CertificateHeader setting exists that the table does not know');
  const ids = certificateHeader.USE_CASE_IDS;
  t.equal(ids.length, new Set(ids).size, 'the use-case ids are unique');
  let admin = null;
  try {
    admin = fs.readFileSync(path.join(ROOT, 'admin-ui', 'admin.js'), 'utf8');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    admin = '';
  }
  const unhomed = certificateHeader.USE_CASES.filter(function (uc) {
    return admin.indexOf("group: '" + rows[uc.setting].group + "'") < 0;
  }).map(function (uc) { return rows[uc.setting].group; });
  t.equal(unhomed.join(', '), '',
          'each lives in a group SETTING_HOMES draws on a protocol page');

  // -------------------------------------------------------------------------
  t.log.info('=== B. every JWS signer outside the primitive names a use ' +
             'case ===');
  const scan = scanSigners();
  t.equal(scan.uncovered.join('\n'), '',
          'no signing call is left that names no certificate-header use case ' +
          'and carries no `// certificate-header: none — <why>`');
  t.equal(scan.exemptWithoutReason.join(', '), '',
          'and every exemption says why');
  const unknownIds = scan.named.filter(function (one) {
    return ids.indexOf(one.id) < 0;
  }).map(function (one) { return one.id + ' at ' + one.where; });
  t.equal(unknownIds.join(', '), '',
          'every use case named in the source is one the table has');
  const unused = ids.filter(function (id) {
    return !scan.named.some(function (one) { return one.id === id; });
  });
  t.equal(unused.join(', '), '',
          'and every row of the table is named by at least one signer — a ' +
          'setting nothing reads is a setting that lies');

  // -------------------------------------------------------------------------
  t.log.info('=== C. the whole path, in a child process ===');
  const out = path.join(os.tmpdir(), 'jch-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', JCH_ROOT: ROOT, JCH_OUT: out }),
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
  name: 'jose_certificate_header',
  describe: 'a JWT signed with a certified key names its certificate chain — ' +
            'x5u by default, x5c, both or none, per use case and per realm — ' +
            'and every signer in the source names which setting governs it',
  run: run
};
