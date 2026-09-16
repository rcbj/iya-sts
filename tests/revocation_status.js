'use strict';
//
// File: revocation_status.js
//
// ===========================================================================
// REVOCATION, CONSULTED: THE REGISTER, THE FOREIGN CRL, OCSP, DELTA AND
// INDIRECT CRLs, AND EVERY DOOR THAT ACCEPTS A PRESENTED CERTIFICATE
// (2026-09-12).
//
// **WHY HERE RATHER THAN OVER HTTP**, which is `tests/CLAUDE.md`'s first
// question. Three of the claims here cannot be reached over HTTP at all:
//
//   * **A FOREIGN CRL THAT IS UNREACHABLE, BADLY SIGNED, STALE, SLOW OR A
//     REDIRECT** — every one of those is a server somebody else runs, and the
//     only honest fixture is a server this file runs, on a port it chose, whose
//     hits it can count. The cache and the failure memory are claims about
//     requests NOT made, which only the server can see.
//   * **A WORKER'S VIEW OF A CLIENT CERTIFICATE** — `request_pool.peerOf()` on
//     a real TLS socket, decoded the way the worker decodes it. No endpoint
//     reports what a worker was handed.
//   * **A REVOKED CERTIFICATE AT `GET /tls/sign-in`** needs an HTTPS listener
//     asking for a client certificate and a truststore holding a CA minted for
//     the purpose, which is section 6 and 7's child process.
//
//     **THIS WAS THE 8443 AND 9443 LISTENERS UNTIL 2026-09-16, AND ONE CLAIM
//     DIED WITH THEM.** Section 6 asserted that the STRICT listener answered
//     403 for a chain that verified and a CRL that revoked it, and section 7
//     that the permissive one answered 200 and started no session. The strict
//     listener has no successor and the 403 is not coming back: refusing at
//     the handshake is a property of a SOCKET, and the socket that remains
//     carries every other protocol in the service. What is asserted instead is
//     the thing that actually mattered — that a revoked certificate whose
//     CHAIN VERIFIES starts NO SESSION and is reported refused on revocation,
//     while a good one from the same authority signs in. That is where the
//     refusal has to be made now, and it is the one place OpenSSL cannot make
//     it: OpenSSL built the chain and was satisfied.
//   * **AN OCSP RESPONDER THAT SIGNS WITH THE WRONG KEY, A DELEGATED RESPONDER
//     WITHOUT THE EKU, A STALE OR REPLAYED RESPONSE, A DELTA THAT REVOKES OR
//     REMOVES, AND AN INDIRECT CRL** — sections 8 to 11 — are documents a third
//     party signs, and the only honest fixture is one OPENSSL made: a real
//     `openssl ocsp` responder answering this file's HTTP server per request,
//     `openssl ca -gencrl` for every list it can write, and pkijs only for the
//     indirect CRL's certificateIssuer entries, which OpenSSL cannot write —
//     and which `openssl crl` is then asked to verify, so even that one is read
//     by an implementation other than the one under test.
//
// **MOSTLY NEGATIVES**, for `tests/sts_dpop.js`'s reason: a revocation check
// that answers `good` for a good certificate looks finished and is worth
// nothing. What it has to get right is `revoked` for a revoked one at every
// door, `unknown` — and a REFUSAL only under hard-fail — for a list it could
// not trust, and NOT dialling anything named by a chain that did not verify.
//
// It REVOKES AN ISSUING CA, which would poison anybody else's test sharing its
// process — one of the reasons every section runs in a child process of its
// own (see `spawnChild()`), so nothing here is left behind to remove.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'revocation_status',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_REVOCATION_STATUS_CHILD';

// ---------------------------------------------------------------------------
// A FOREIGN CERTIFICATE AUTHORITY, minted on the vendored engine the launchers
// mint a remote PEP's credential with, and a CRL signed by it with pkijs.
//
// **THE CRL IS BUILT BY THE SAME LIBRARY THE CHECK PARSES WITH**, which is the
// "implementation agreeing with itself" `tests/pki_revocation.js` warns about —
// so section 4 also reads one OpenSSL made (`openssl ca -gencrl`), which is the
// independent reading, wherever openssl is installed.
// ---------------------------------------------------------------------------
async function issue(spec) {
  log.debug("Entering issue().");
  const x509 = require('../common/vendored/x509');
  const keys = require('../common/vendored/key_material');
  const pair = await keys.generateKeyPair('rsa-2048');
  const now = Date.now();
  const extensions = {
    basicConstraints: { present: true, critical: true, ca: !!spec.ca,
                        pathLen: spec.ca ? (spec.pathLen || 0) : undefined },
    keyUsage: { present: true, critical: true,
                usages: spec.ca ? ['keyCertSign', 'cRLSign']
                                : ['digitalSignature', 'keyEncipherment'] },
    subjectKeyIdentifier: { present: true },
    authorityKeyIdentifier: { present: true }
  };
  if (!spec.ca) {
    extensions.extKeyUsage = { present: true, usages: ['clientAuth'] };
  }
  if (spec.crls && spec.crls.length) {
    extensions.cRLDistributionPoints = { present: true, critical: false,
                                         urls: spec.crls };
  }
  const issued = await x509.issueCertificate({
    subject: spec.subject,
    subjectPublicKey: pair.publicPem,
    signatureAlg: 'sha256-rsa',
    issuerPrivateKey: spec.issuer ? undefined : pair.privatePem,
    issuer: spec.issuer,
    notBefore: new Date(now - 60000).toISOString(),
    notAfter: new Date(now + 365 * 24 * 3600 * 1000).toISOString(),
    extensions: extensions
  });
  log.debug("Leaving issue().");
  return { pem: issued.pem, key: pair.privatePem, serialHex: issued.serialHex,
           subject: spec.subject };
}

function asIssuer(one) {
  log.debug("Entering asIssuer().");
  log.debug("Leaving asIssuer().");
  return { certificatePem: one.pem, privateKeyPem: one.key,
           keyAlg: 'rsa-2048' };
}

async function makeCrl(issuer, serials, options) {
  log.debug("Entering makeCrl().");
  const pkijs = require('pkijs');
  const asn1js = require('asn1js');
  // For its side effect: it installs the Web Crypto engine pkijs signs with.
  require('../common/pki_revocation');
  const opts = options || {};
  const der = function (pem) {
    log.debug("Entering der().");
    const buf = Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
    log.debug("Leaving der().");
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  };
  const issuerCert = pkijs.Certificate.fromBER(der(issuer.pem));
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;
  crl.issuer = issuerCert.subject;
  const now = Date.now();
  crl.thisUpdate = new pkijs.Time({ type: 0, value: new Date(now - 60000) });
  crl.nextUpdate = new pkijs.Time({ type: 0,
    value: new Date(opts.nextUpdateMs || now + 3600 * 1000) });
  if (serials.length) {
    crl.revokedCertificates = serials.map(function (serialHex) {
      let hex = String(serialHex).toLowerCase().replace(/^0+/, '');
      if (hex.length % 2) {
        hex = '0' + hex;
      }
      let bytes = Buffer.from(hex, 'hex');
      if (bytes[0] & 0x80) {
        bytes = Buffer.concat([Buffer.from([0]), bytes]);
      }
      const entry = new pkijs.RevokedCertificate();
      entry.userCertificate = new asn1js.Integer({
        valueHex: bytes.buffer.slice(bytes.byteOffset,
                                     bytes.byteOffset + bytes.byteLength) });
      entry.revocationDate = new pkijs.Time({ type: 0,
                                              value: new Date(now - 30000) });
      entry.crlEntryExtensions = new pkijs.Extensions({ extensions: [
        new pkijs.Extension({ extnID: '2.5.29.21', critical: false,
          extnValue: new asn1js.Enumerated({ value: 1 }).toBER(false) })
      ] });
      return entry;
    });
  }
  if (opts.criticalExtension) {
    // An OID nobody implements. It was the deltaCRLIndicator until delta CRLs
    // became understood, and a test of "an extension this file does not know"
    // must not quietly become a test of one it does.
    crl.crlExtensions = new pkijs.Extensions({ extensions: [
      new pkijs.Extension({ extnID: '1.3.6.1.4.1.55555.7.1', critical: true,
        extnValue: new asn1js.Integer({ value: 1 }).toBER(false) })
    ] });
  }
  const signer = opts.signWith || issuer;
  const key = await crypto.subtle.importKey('pkcs8', der(signer.key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  await crl.sign(key, 'SHA-256');
  log.debug("Leaving makeCrl().");
  return Buffer.from(crl.toSchema(true).toBER(false));
}

// A CRL AND OCSP server this file controls: a route table, a hit counter per
// path, three misbehaviours — a status, a delay and a redirect — and an `ocsp`
// route that hands the POSTed request to a real `openssl ocsp` responder and
// answers with what it signed.
function crlServer() {
  log.debug("Entering crlServer().");
  const routes = {};
  const hits = {};
  const server = http.createServer(function (req, res) {
    const chunks = [];
    req.on('data', function (chunk) { chunks.push(chunk); });
    req.on('end', function () {
      const route = routes[req.url];
      hits[req.url] = (hits[req.url] || 0) + 1;
      if (!route) {
        // error-code: none — a test fixture, not the service
        res.writeHead(404);
        res.end();
        return;
      }
      const send = function () {
        log.debug("Entering send().");
        if (route.redirect) {
          res.writeHead(302, { Location: route.redirect });
          res.end();
          log.debug("Leaving send().");
          return;
        }
        let body = route.body || '';
        // A responder takes a POST of the DER request (RFC 6960 appendix A.1).
        // Answering anything else was how a client sending GET-with-a-body
        // passed this file: node will send one, and no real responder reads it.
        if (route.ocsp && (req.method !== 'POST' ||
            req.headers['content-type'] !== 'application/ocsp-request')) {
          // error-code: none — a test fixture, not the service
          res.writeHead(405);
          res.end();
          log.debug("Leaving send().");
          return;
        }
        if (route.ocsp) {
          body = answerOcsp(route.ocsp, Buffer.concat(chunks));
        }
        res.writeHead(route.status || 200,
                      { 'Content-Type': route.contentType ||
                        (route.ocsp ? 'application/ocsp-response' :
                         'application/pkix-crl') });
        res.end(body);
        log.debug("Leaving send().");
      };
      if (route.delayMs) {
        setTimeout(send, route.delayMs);
      } else {
        send();
      }
    });
  });
  log.debug("Leaving crlServer().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      const base = 'http://127.0.0.1:' + server.address().port;
      resolve({ server: server, base: base, routes: routes, hits: hits });
    });
  });
}

async function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const config = require('../common/config');
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      const refused = config.setOverride(key, String(pairs[key]));
      if (refused && refused.ok === false) {
        throw new Error('could not set ' + key + ': ' +
                        JSON.stringify(refused));
      }
    });
    log.debug("Leaving withSettings().");
    return await fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function haveOpenSsl() {
  log.debug("Entering haveOpenSsl().");
  try {
    childProcess.execFileSync('openssl', ['version'], { stdio: 'pipe' });
    log.debug("Leaving haveOpenSsl().");
    return true;
  } catch (e) {
    log.debug("Caught in haveOpenSsl(): " + ((e && e.message) || e));
    log.debug("Leaving haveOpenSsl().");
    // No openssl on this machine. The one section that needs an independent
    // CRL writer says so and skips its assertion rather than passing it.
    return false;
  }
}

// ===========================================================================
// 1. THE POLICY.
// ===========================================================================
async function thePolicy(t) {
  log.debug("Entering thePolicy().");
  t.log.info('=== 1. the policy: auto chooses by mode, and a named value ' +
             'wins ===');
  const status = require('../common/revocation_status');
  const mode = require('../common/mode');
  t.equal(mode.isProduct(), false, 'this file starts in development mode');
  t.equal(status.policy().configured, 'auto', 'pki.revocationCheck defaults ' +
                                              'to auto');
  t.equal(status.policy().effective, 'soft-fail',
          'and auto is SOFT-FAIL in development — the register is consulted, ' +
          'an unreachable foreign list is not a refusal');
  await withSettings({ 'global.mode': 'product' }, async function () {
    t.equal(status.policy().effective, 'hard-fail',
            'and HARD-FAIL in product, through ' +
            'mode.refusesUnknownRevocationStatus()');
  });
  await withSettings({ 'pki.revocationCheck': 'off' }, async function () {
    t.equal(status.policy().effective, 'off',
            'a named value wins over the mode');
  });
  log.debug("Leaving thePolicy().");
}

// ===========================================================================
// 2 AND 3. THE REGISTER: an assertion's x5c through verifyLeaf(), and an
// X509-SVID through the SPIRE Server API's verifier.
// ===========================================================================
async function theRegister(t, realm, crlBase) {
  log.debug("Entering theRegister().");
  t.log.info('=== 2. the register: verifyLeaf() refuses what /admin/pki ' +
             'revoked ===');
  const pki = require('../common/pki');
  const revocation = require('../common/pki_revocation');
  const realms = require('../common/realms');
  const assertionGrant = require('../oauth-oidc/assertion_grant');
  const REALM = realm.id;

  const one = await pki.issueSigningKeyPair(REALM,
                                            { identifier: 'rev-app-one' });
  const two = await pki.issueSigningKeyPair(REALM,
                                            { identifier: 'rev-app-two' });
  const three = await pki.issueSigningKeyPair(REALM,
                                              { identifier: 'rev-app-three' });
  if (!one.ok || !two.ok || !three.ok) {
    throw new Error('key pairs could not be issued: ' +
                    JSON.stringify([one.errors, two.errors, three.errors]));
  }
  const leafOne = one.issued;
  const serialOf = function (pem) {
    log.debug("Entering serialOf().");
    log.debug("Leaving serialOf().");
    return new nodeCrypto.X509Certificate(pem).serialNumber;
  };

  const good = await pki.verifyLeaf(REALM, leafOne.certificatePem,
                                    leafOne.chainPem);
  t.check(good.ok && good.revocation && good.revocation.status === 'good',
          'a leaf this realm issued verifies, and the verdict says it was ' +
          'LOOKED UP rather than skipped',
          JSON.stringify(good.revocation ? good.revocation.status : good.why));
  t.check(good.revocation && good.revocation.links.some(function (link) {
            return link.source === 'register';
          }) && !good.revocation.links.some(function (link) {
            return link.source === 'crl';
          }),
          'and every link of a path this service issued is answered by the ' +
          'REGISTER — nothing is fetched for a certificate this service ' +
          'signed');

  revocation.revoke(REALM, 'assertions',
                    { serialHex: serialOf(leafOne.certificatePem),
                                            reason: 'keyCompromise' });
  const refused = await pki.verifyLeaf(REALM, leafOne.certificatePem,
                                       leafOne.chainPem);
  const errorCodes = require('../common/error_codes');
  t.check(!refused.ok && refused.revocation &&
          refused.revocation.status === 'revoked',
          'REVOKED ON /admin/pki IS REFUSED HERE — the sentence this whole ' +
          'change reverses', refused.why);
  t.equal(errorCodes.codeOf(refused), 'STS-PKI-0118',
          'and the refusal carries STS-PKI-0118, non-enumerably');
  t.check(/keyCompromise/.test(refused.why),
          'and says WHY, with the reason the register holds', refused.why);

  const viaGrant = await realms.run(realm, function () {
    return assertionGrant.keyFromChain({ x5c: [leafOne.certificatePem]
      .concat(leafOne.chainPem).map(function (pem) {
        return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      }) });
  });
  t.check(viaGrant && viaGrant.errorCode === 'STS-PKI-0118' && !viaGrant.key,
          'the RFC 7523 x5c door refuses it with the REVOCATION code rather ' +
          'than "does not chain here" — the certificate is ours and was ' +
          'withdrawn',
          JSON.stringify(viaGrant &&
                         { code: viaGrant.errorCode, error: viaGrant.error }));

  await withSettings({ 'pki.revocationCheck': 'off' }, async function () {
    const off = await pki.verifyLeaf(REALM, leafOne.certificatePem,
                                     leafOne.chainPem);
    t.check(off.ok && off.revocation.checked === false,
            'with pki.revocationCheck=off the same certificate is accepted ' +
            'and the verdict says nothing was consulted');
  });

  // A HOLD, AND THE RELEASE THAT MAKES IT GOOD AGAIN — through the synchronous
  // door with the LEAF ALONE, which is the half that proves the walk does not
  // need the client's chain.
  const status = require('../common/revocation_status');
  const leafTwo = two.issued;
  revocation.revoke(REALM, 'assertions',
                    { serialHex: serialOf(leafTwo.certificatePem),
                                            reason: 'certificateHold' });
  const held = status.localVerdictFor({ leaf: leafTwo.certificatePem, chain: [],
                                        verified: true });
  t.check(held.refused && held.status === 'revoked' &&
          held.revoked.reason === 'certificateHold',
          'a certificate on hold is refused, presented with no chain at all',
          held.why);
  revocation.release(REALM, 'assertions', serialOf(leafTwo.certificatePem));
  const released = status.localVerdictFor({ leaf: leafTwo.certificatePem,
                                            chain: [],
                                            verified: true });
  t.check(!released.refused && released.status === 'good',
          'and released, it is good again on the very next check — the ' +
          'register is read per certificate and never cached', released.why);

  // THE ISSUING CA REVOKED AT ITS INTERMEDIATE: every leaf under it is refused,
  // including one presented WITHOUT the Issuing CA's certificate.
  const issuingPem = pki.describeIssuer(REALM, 'assertions').certificatePem;
  revocation.revoke(REALM, 'intermediate', { serialHex: serialOf(issuingPem),
                                              reason: 'cACompromise' });
  const orphan = status.localVerdictFor({ leaf: three.issued.certificatePem,
                                          chain: [],
                                          verified: true });
  t.check(orphan.refused && orphan.revoked && orphan.revoked.depth === 1,
          'A REVOKED ISSUING CA REVOKES EVERY LEAF UNDER IT, found by ' +
          'walking UP through the tiers this service holds — the client did ' +
          'not send the Issuing CA, and not sending it must not be how that ' +
          'is got around',
          JSON.stringify(orphan.revoked));

  t.log.info('=== 3. the SPIRE Server API: an X509-SVID on hold is refused ' +
             '===');
  const ca = require('../spiffe/spiffe_ca');
  const spiffeAuth = require('../spiffe/spiffe_auth');
  const svid = await realms.run(realm, function () {
    return ca.mintX509Svid('spiffe://' + ca.trustDomain() +
                           '/ns/t/sa/revocation-probe');
  });
  const svidCert = new nodeCrypto.X509Certificate(svid.chainPem[0]);
  const id = 'spiffe://' +
             realms.run(realm, function () { return ca.trustDomain(); }) +
             '/ns/t/sa/revocation-probe';
  const before = realms.run(realm, function () {
    return spiffeAuth.verifyPresentedCertificate({ raw: svidCert.raw }, id);
  });
  t.check(before.ok && before.revocation && before.revocation.status === 'good',
          'a fresh SVID verifies and was looked up',
          JSON.stringify(before).slice(0, 300));
  revocation.revoke(REALM, 'spiffe', { serialHex: svidCert.serialNumber,
                                        reason: 'certificateHold' });
  const after = realms.run(realm, function () {
    return spiffeAuth.verifyPresentedCertificate({ raw: svidCert.raw }, id);
  });
  t.check(!after.ok && after.errorCode === 'STS-PKI-0118' &&
          /REVOCATION/.test(after.reason),
          'and on hold it is refused, with the revocation code the caller\'s ' +
          'audit row carries', JSON.stringify(after).slice(0, 300));
  revocation.release(REALM, 'spiffe', svidCert.serialNumber);

  // A FEDERATED-LOOKING CERTIFICATE THIS SERVICE DID NOT SIGN is never refused
  // at the synchronous door, whatever the policy: that door does not fetch.
  const foreignRoot = await issue({ subject: 'CN=rev foreign root', ca: true,
                                    pathLen: 1 });
  const foreignLeaf = await issue({ subject: 'CN=rev foreign leaf',
                                    crls: [crlBase + '/never-dialled.crl'],
                                    issuer: asIssuer(foreignRoot) });
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const local = status.localVerdictFor({ leaf: foreignLeaf.pem,
                                           chain: [foreignRoot.pem],
                                           verified: true });
    t.check(!local.refused && local.status === 'unknown' &&
            local.unknown.every(function (one) {
              return one.kind === 'not-consulted';
            }),
            'the register-only door answers a foreign certificate ' +
            'NOT-CONSULTED and does not refuse it even under ' +
            'hard-fail', local.why);
  });
  log.debug("Leaving theRegister().");
}

// ===========================================================================
// 4. THE FOREIGN CRL.
// ===========================================================================
async function theForeignCrl(t, fixture, realmId) {
  log.debug("Entering theForeignCrl().");
  t.log.info('=== 4. a foreign certificate against the CRL it names ===');
  const status = require('../common/revocation_status');
  const errorCodes = require('../common/error_codes');
  status.resetCache();
  const base = fixture.base;
  const routes = fixture.routes;
  const hits = fixture.hits;

  const root = await issue({ subject: 'CN=rev external root', ca: true,
                             pathLen: 1 });
  const issuing = await issue({ subject: 'CN=rev external issuing', ca: true,
                                crls: [base + '/root.crl'],
                                issuer: asIssuer(root) });
  const leafFor = function (name, urls) {
    log.debug("Entering leafFor().");
    log.debug("Leaving leafFor().");
    return issue({ subject: 'CN=' + name, crls: urls,
                   issuer: asIssuer(issuing) });
  };
  routes['/root.crl'] = { body: await makeCrl(root, []) };
  routes['/issuing.crl'] = { body: await makeCrl(issuing, []) };

  const good = await leafFor('rev good', [base + '/issuing.crl']);
  const input = function (leaf, verified) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: [issuing.pem, root.pem],
             verified: verified !== false };
  };

  const first = await status.verdictFor(input(good));
  t.check(first.status === 'good' && !first.refused,
          'a foreign leaf whose issuer\'s CRL does not list it is GOOD',
          first.why);
  t.check(hits['/issuing.crl'] === 1 && hits['/root.crl'] === 1,
          'and BOTH lists were fetched — the leaf\'s at the Issuing CA and ' +
          'the Issuing CA\'s at the Root', JSON.stringify(hits));
  await status.verdictFor(input(good));
  t.check(hits['/issuing.crl'] === 1 && hits['/root.crl'] === 1,
          'a second check is answered from the CACHE — no second request',
          JSON.stringify(hits));

  const revokedLeaf = await leafFor('rev revoked', [base + '/revoking.crl']);
  routes['/revoking.crl'] = { body: await makeCrl(issuing,
                                                  [revokedLeaf.serialHex]) };
  const revoked = await status.verdictFor(input(revokedLeaf));
  t.check(revoked.status === 'revoked' && revoked.refused &&
          revoked.revoked.reason === 'keyCompromise' &&
          revoked.revoked.source === 'crl',
          'a leaf its issuer\'s CRL lists is REVOKED, with the reason off ' +
          'the entry, and refused under soft-fail', revoked.why);
  t.equal(errorCodes.codeOf(revoked), 'STS-PKI-0118', 'carrying STS-PKI-0118');

  // UNREACHABLE: soft-fail accepts and reports, hard-fail refuses.
  const lost = await leafFor('rev unreachable', [base + '/missing.crl']);
  const soft = await status.verdictFor(input(lost));
  t.check(soft.status === 'unknown' && !soft.refused &&
          soft.unknown.some(function (one) {
            return one.kind === 'unreachable';
          }),
          'a list that answers 404 is UNKNOWN, and soft-fail accepts it',
          soft.why);
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const hard = await status.verdictFor(input(lost));
    t.check(hard.refused && errorCodes.codeOf(hard) === 'STS-PKI-0119',
            'and HARD-FAIL refuses the same certificate with STS-PKI-0119 — ' +
            'the attacker who can block a fetch does not get in', hard.why);
  });
  const lostHits = hits['/missing.crl'];
  await status.verdictFor(input(lost));
  t.equal(hits['/missing.crl'], lostHits,
          'and the FAILURE is remembered for pki.revocationFailureRetryS: a ' +
          'dead server costs one request per window, not one per certificate');
  status.resetCache();
  await withSettings({ 'pki.revocationFailureRetryS': 0 }, async function () {
    await status.verdictFor(input(lost));
    await status.verdictFor(input(lost));
  });
  t.equal(hits['/missing.crl'], lostHits + 2,
          'while a retry window of ZERO — a legal value — dials on every ' +
          'check');

  // A LIST SIGNED BY SOMEBODY ELSE, a stale one, and one with a critical
  // extension this service does not implement: all three are unusable.
  const stranger = await issue({ subject: 'CN=rev external issuing', ca: true,
                                 issuer: asIssuer(root) });
  const forged = await leafFor('rev forged', [base + '/forged.crl']);
  routes['/forged.crl'] = { body: await makeCrl(issuing, [],
                                                { signWith: stranger }) };
  const stale = await leafFor('rev stale', [base + '/stale.crl']);
  // Ten minutes past, which is beyond the default pki.revocationClockSkewS of
  // five: a list one second past its nextUpdate is inside the skew now.
  routes['/stale.crl'] = { body: await makeCrl(issuing, [],
                                               { nextUpdateMs: Date.now() -
                                                   600000 }) };
  const nearly = await leafFor('rev nearly stale', [base + '/nearly.crl']);
  routes['/nearly.crl'] = { body: await makeCrl(issuing, [],
                                                { nextUpdateMs: Date.now() -
                                                    60000 }) };
  const delta = await leafFor('rev delta', [base + '/delta.crl']);
  routes['/delta.crl'] = { body: await makeCrl(issuing, [],
                                               { criticalExtension: true }) };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const f = await status.verdictFor(input(forged));
    t.check(f.refused && /signature does not verify/.test(f.why),
            'a CRL whose SIGNATURE does not verify against the issuer is not ' +
            'a list about that issuer — refused under hard-fail, naming the ' +
            'signature',
            f.why);
    const s = await status.verdictFor(input(stale));
    t.check(s.refused && /STALE/.test(s.why),
            'a CRL past its nextUpdate is refused as STALE', s.why);
    const n = await status.verdictFor(input(nearly));
    t.check(!n.refused && n.status === 'good',
            'while one a minute past its nextUpdate is inside ' +
            'pki.revocationClockSkewS and still used', n.why);
    const d = await status.verdictFor(input(delta));
    t.check(d.refused && /critical extension/.test(d.why),
            'a CRL carrying a critical extension this service does not ' +
            'implement is unusable (RFC 5280 section 6.3.3)', d.why);
  });

  // SLOW, and a REDIRECT.
  const slow = await leafFor('rev slow', [base + '/slow.crl']);
  routes['/slow.crl'] = { body: await makeCrl(issuing, []), delayMs: 1500 };
  const moved = await leafFor('rev moved', [base + '/moved.crl']);
  routes['/moved.crl'] = { redirect: base + '/issuing.crl' };
  await withSettings({ 'pki.revocationCheck': 'hard-fail',
                       'pki.revocationFetchTimeoutMs': 200 },
                     async function () {
    const started = Date.now();
    const v = await status.verdictFor(input(slow));
    t.check(v.refused && /did not answer within 200ms/.test(v.why) &&
            Date.now() - started < 1400,
            'a CRL server slower than pki.revocationFetchTimeoutMs is ' +
            'abandoned at the timeout, not waited for', v.why);
    const r = await status.verdictFor(input(moved));
    t.check(r.refused && /redirect is not followed/.test(r.why),
            'a redirect is NOT FOLLOWED — the only address the issuer signed ' +
            'is the one in the certificate', r.why);
  });
  t.equal(hits['/issuing.crl'], 1,
          'and nothing reached the address the redirect pointed at');

  // AN UNVERIFIED CHAIN NAMES URLS ANYBODY COULD HAVE WRITTEN: nothing is
  // dialled.
  const bait = await leafFor('rev bait', [base + '/bait.crl']);
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const v = await status.verdictFor(input(bait, false));
    t.check(!v.refused && v.unknown.some(function (one) {
              return one.kind === 'unverified-chain';
            }),
            'a chain that did NOT VERIFY is not refused on revocation (it is ' +
            'refused, where it matters, for not verifying)', v.why);
  });
  t.equal(hits['/bait.crl'], undefined,
          'AND NOTHING IT NAMES IS DIALLED — the URL in a certificate nobody ' +
          'vouched for is a request-forwarder for whoever minted it');

  // NO DISTRIBUTION POINT, and one that is not http.
  const bare = await leafFor('rev bare', []);
  const ldapOnly = await leafFor('rev ldap',
                                 ['ldap://127.0.0.1:1/cn=x?certificateRevocationList;' +
                                  'binary']);
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const v = await status.verdictFor(input(bare));
    t.check(!v.refused && v.unknown.some(function (one) {
              return one.kind === 'no-distribution-point';
            }),
            'under hard-fail a certificate whose issuer names NO list is ' +
            'accepted — there is no fetch an attacker could block', v.why);
    const l = await status.verdictFor(input(ldapOnly));
    t.check(!l.refused && /does not dial/.test(l.why),
            'and one naming only an ldap: point is the same case: this ' +
            'service dials http and https and nothing else', l.why);
    await withSettings({ 'pki.revocationRequireDistributionPoint': true },
                       async function () {
      const strict = await status.verdictFor(input(bare));
      t.check(strict.refused,
              'unless pki.revocationRequireDistributionPoint is on',
              strict.why);
    });
  });

  // AN IMPOSTOR CARRYING THE NAME OF ONE OF THIS SERVICE'S OWN AUTHORITIES.
  // The issuer is found by NAME AND SIGNATURE, and this is the case the
  // signature half exists for: a foreign CA whose subject is, byte for byte,
  // this realm's JOSE Issuing CA's. Matched by name alone its leaf would be
  // answered from THIS service's register — which has never heard of it and
  // so says `good` — and the CRL that actually revokes it would never be read.
  const pkiModule = require('../common/pki');
  const joseCert = new nodeCrypto.X509Certificate(
    pkiModule.describeIssuer(realmId, 'jose').certificatePem);
  const impostor = await issue({ subject: joseCert.subject.split('\n')
    .join(','),
                                 ca: true, crls: [base + '/root.crl'],
                                 issuer: asIssuer(root) });
  const impostorLeaf = await issue({ subject: 'CN=rev impostor leaf',
                                     crls: [base + '/impostor.crl'],
                                     issuer: asIssuer(impostor) });
  routes['/impostor.crl'] = { body: await makeCrl(impostor,
                                                  [impostorLeaf.serialHex]) };
  t.equal(new nodeCrypto.X509Certificate(impostor.pem).subject,
          joseCert.subject,
          'the impostor CA really does carry the JOSE Issuing CA\'s subject');
  const fooled = await status.verdictFor({ leaf: impostorLeaf.pem,
                                           chain: [impostor.pem, root.pem],
                                           verified: true });
  t.check(fooled.status === 'revoked' && fooled.revoked.source === 'crl',
          'a leaf under a foreign CA NAMED like one of this service\'s ' +
          'authorities is answered from ITS OWN CRL, not from this ' +
          'service\'s register — the issuer is matched by signature, not by ' +
          'name', fooled.why);

  // THE INDEPENDENT READING: a CRL OpenSSL wrote.
  if (haveOpenSsl()) {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-revstat-'));
    try {
      const target = await leafFor('rev openssl', [base + '/openssl.crl']);
      fs.writeFileSync(path.join(scratch, 'ca.pem'), issuing.pem);
      fs.writeFileSync(path.join(scratch, 'ca.key'), issuing.key);
      const when = new Date(Date.now() - 60000).toISOString()
        .replace(/[-:T]/g, '').slice(2, 14) + 'Z';
      fs.writeFileSync(path.join(scratch, 'index.txt'),
        'R\t300101000000Z\t' + when + ',keyCompromise\t' +
        target.serialHex.toUpperCase() + '\tunknown\t/CN=rev openssl\n');
      fs.writeFileSync(path.join(scratch, 'crlnumber'), '01\n');
      fs.writeFileSync(path.join(scratch, 'ca.cnf'),
        '[ca]\ndefault_ca=d\n[d]\ndatabase=' + path.join(scratch, 'index.txt') +
        '\ncrlnumber=' + path.join(scratch, 'crlnumber') +
        '\ndefault_md=sha256\ndefault_crl_days=1\n');
      childProcess.execFileSync('openssl',
        ['ca', '-config', path.join(scratch, 'ca.cnf'),
        '-gencrl', '-keyfile', path.join(scratch, 'ca.key'), '-cert',
        path.join(scratch, 'ca.pem'), '-out', path.join(scratch, 'crl.pem')],
        { stdio: 'pipe' });
      // PEM, as `openssl ca` writes it — the check accepts both, and this is
      // the case that says so.
      routes['/openssl.crl'] = { body: fs.readFileSync(
          path.join(scratch, 'crl.pem')) };
      const v = await status.verdictFor(input(target));
      t.check(v.status === 'revoked' && v.revoked.reason === 'keyCompromise',
              'a CRL OPENSSL wrote, served as PEM, is read, verified and ' +
              'found to revoke the leaf — the reading that is not pkijs ' +
              'agreeing with itself',
              v.why);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  } else {
    t.log.warn('openssl is not installed; the independent CRL reading was ' +
               'not run');
  }
  log.debug("Leaving theForeignCrl().");
  return { root: root, issuing: issuing, good: good, revoked: revokedLeaf };
}

// ===========================================================================
// 8 TO 11. OCSP, DELTA CRLs, INDIRECT CRLs AND THE ISSUING DISTRIBUTION POINT,
// AGAINST DOCUMENTS OPENSSL SIGNED.
//
// Every certificate below is made by `openssl req`/`openssl x509`, every OCSP
// response by `openssl ocsp` answering the request THIS SERVICE built, and
// every CRL but the indirect ones by `openssl ca -gencrl`. EC P-256 keys
// throughout, because an RSA key per certificate is most of this file's running
// time and the verifier is not what the key type is testing.
// ===========================================================================
function openssl(args, cwd) {
  log.debug("Entering openssl().");
  log.debug("Leaving openssl().");
  return childProcess.execFileSync('openssl', args,
                                   { cwd: cwd, stdio: 'pipe' });
}

// The route handler an `ocsp` route runs: the request this service POSTed, put
// in front of `openssl ocsp` as a responder with the named signer.
function answerOcsp(spec, requestDer) {
  log.debug("Entering answerOcsp().");
  const stamp = nodeCrypto.randomBytes(6).toString('hex');
  const reqPath = path.join(spec.dir, 'req-' + stamp + '.der');
  const respPath = path.join(spec.dir, 'resp-' + stamp + '.der');
  fs.writeFileSync(reqPath, requestDer);
  try {
    openssl(['ocsp', '-index', spec.index, '-CA', spec.ca, '-rsigner',
             spec.signer,
             '-rkey', spec.key, '-reqin', reqPath, '-respout', respPath,
             '-ndays', '1'], spec.dir);
    log.debug("Leaving answerOcsp().");
    return spec.tamper ? tamperedSignature(fs.readFileSync(respPath))
                       : fs.readFileSync(respPath);
  } catch (e) {
    log.debug("Caught in answerOcsp(): " + ((e && e.message) || e));
    log.debug("Leaving answerOcsp().");
    // A request openssl would not answer. An empty body is what the service
    // then fails to parse, which is the assertion that would report it.
    return Buffer.alloc(0);
  }
}

// The same response with one bit of its SIGNATURE flipped: an ECDSA signature
// stays well-formed DER, so what fails is the verification and nothing before
// it.
function tamperedSignature(der) {
  log.debug("Entering tamperedSignature().");
  const pkijs = require('pkijs');
  const asn1js = require('asn1js');
  const plain = function (bytes) {
    log.debug("Entering plain().");
    log.debug("Leaving plain().");
    return bytes.buffer.slice(bytes.byteOffset,
                              bytes.byteOffset + bytes.byteLength);
  };
  const response = pkijs.OCSPResponse.fromBER(plain(der));
  const basic = pkijs.BasicOCSPResponse.fromBER(plain(Buffer.from(
    response.responseBytes.response.valueBlock.valueHexView)));
  const signature = Buffer.from(basic.signature.valueBlock.valueHexView);
  signature[signature.length - 1] ^= 0x01;
  basic.signature = new asn1js.BitString({ valueHex: plain(signature) });
  response.responseBytes.response = new asn1js.OctetString({
    valueHex: basic.toSchema().toBER(false) });
  log.debug("Leaving tamperedSignature().");
  return Buffer.from(response.toSchema().toBER(false));
}

function indexLine(serial, reason) {
  log.debug("Entering indexLine().");
  log.debug("Leaving indexLine().");
  return (reason ? 'R' : 'V') + '\t300101000000Z\t' +
         (reason ? '260101000000Z,' + reason : '') + '\t' + serial +
         '\tunknown\t/CN=s' + serial + '\n';
}

async function opensslFixture(dir, base) {
  log.debug("Entering opensslFixture().");
  const read = function (name) {
    log.debug("Entering read().");
    log.debug("Leaving read().");
    return fs.readFileSync(path.join(dir, name), 'utf8');
  };

  const url = function (route) {
    log.debug("Entering url().");
    log.debug("Leaving url().");
    return base + route;
  };
  const sections = [
    '[req]', 'distinguished_name=dn', 'prompt=no', '[dn]', 'CN=unused',
    '[root_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign,cRLSign', 'subjectKeyIdentifier=hash',
    '[issuing_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign,cRLSign', 'subjectKeyIdentifier=hash',
    'authorityKeyIdentifier=keyid',
    'crlDistributionPoints=URI:' + url('/o-root.crl'),
    '[responder_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=OCSPSigning',
    '[noeku_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    '[crl_issuer_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,cRLSign,digitalSignature', 'subjectKeyIdentifier=hash',
    '[impostor_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign,cRLSign,digitalSignature',
    '[nosign_issuer_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    '[nosign_ca_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign',
    'crlDistributionPoints=URI:' + url('/o-root.crl'),
    '[subca_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign,cRLSign',
    'crlDistributionPoints=URI:' + url('/s-onlyuser.crl')
  ];
  const leafSection = function (name, lines) {
    log.debug("Entering leafSection().");
    sections.push('[' + name + ']', 'basicConstraints=CA:FALSE',
                  'keyUsage=critical,digitalSignature',
                  'extendedKeyUsage=clientAuth');
    lines.forEach(function (line) { sections.push(line); });
    log.debug("Leaving leafSection().");
  };
  const LEAVES = [
    // 8. OCSP
    ['ocspGood', '1001',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/issuer')]],
    ['ocspRevoked', '1002',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/delegated'),
                             'crlDistributionPoints=URI:' +
                             url('/o-empty.crl')]],
    ['ocspUnknown', '1003',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/issuer'),
                             'crlDistributionPoints=URI:' +
                             url('/o-empty.crl')]],
    ['ocspUnknownCrlRevokes', '1004',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/issuer'),
                                       'crlDistributionPoints=URI:' +
                                       url('/o-revokes.crl')]],
    ['ocspWrongKey', '1005',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/impostor')]],
    ['ocspWrongKeyFallback', '100a',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/impostor'),
                                      'crlDistributionPoints=URI:' +
                                      url('/o-empty.crl')]],
    ['ocspNoEku', '1006',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/noeku')]],
    ['ocspStale', '1007',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/stale')]],
    ['ocspReplay', '1008',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/replay')]],
    ['ocspDedupe', '1009',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/dedupe')]],
    ['ocspTampered', '100b',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/tampered')]],
    ['ocspExpiredResponder', '100c',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/expired')]],
    ['ocspOtherCertificate', '100d',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/other')]],
    ['ocspTryLater', '100e',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/trylater')]],
    // 9. DELTA
    ['deltaRevokes', '2001',
     ['crlDistributionPoints=URI:' + url('/d-base.crl')]],
    ['deltaRemoves', '2002',
     ['crlDistributionPoints=URI:' + url('/d-base.crl')]],
    ['heldNoDelta', '2003',
     ['crlDistributionPoints=URI:' + url('/d4-base.crl')]],
    ['revokedNoDelta', '2004',
     ['crlDistributionPoints=URI:' + url('/d4-base.crl')]],
    ['deltaMismatch', '2005',
     ['crlDistributionPoints=URI:' + url('/d3-base.crl'),
                               'freshestCRL=URI:' + url('/d3-delta.crl')]],
    ['deltaAtPoint', '2006',
     ['crlDistributionPoints=URI:' + url('/d-delta.crl')]],
    ['deltaNotNewer', '2007',
     ['crlDistributionPoints=URI:' + url('/d5-base.crl')]],
    ['deltaComplete', '2008',
     ['crlDistributionPoints=URI:' + url('/d6-base.crl')]],
    ['deltaOtherScope', '2009',
     ['crlDistributionPoints=URI:' + url('/d7-base.crl')]],
    // 10. INDIRECT
    ['indirectRevoked', '3001', ['crlDistributionPoints=cdp_indirect']],
    ['indirectOtherIssuer', '3002', ['crlDistributionPoints=cdp_indirect']],
    ['indirectCarried', '3003', ['crlDistributionPoints=cdp_indirect']],
    ['indirectForged', '3004', ['crlDistributionPoints=cdp_forged']],
    ['indirectUnnamed', '3005',
     ['crlDistributionPoints=URI:' + url('/i-unnamed.crl')]],
    ['indirectFlat', '3006', ['crlDistributionPoints=cdp_flat']],
    ['directNamedEntry', '3007',
     ['crlDistributionPoints=URI:' + url('/i-direct-named.crl')]],
    ['indirectNoCrlSign', '3008', ['crlDistributionPoints=cdp_nosign']],
    // 11. SCOPE
    ['scopeOnlyCa', '4001',
     ['crlDistributionPoints=URI:' + url('/s-onlyca.crl')]],
    ['scopeOtherName', '4003',
     ['crlDistributionPoints=URI:' + url('/s-other.crl')]],
    ['scopePartial', '4004',
     ['crlDistributionPoints=URI:' + url('/s-key.crl')]],
    ['scopeComplete', '4005', ['crlDistributionPoints=cdp_key, cdp_rest']],
    ['scopePointReasons', '4006', ['crlDistributionPoints=cdp_point_reasons']]
  ];
  LEAVES.forEach(function (one) { leafSection(one[0] + '_ext', one[2]); });
  ['indirect', 'forged', 'flat'].forEach(function (name) {
    sections.push('[cdp_' + name + ']',
                  'fullname=URI:' + url('/i-' + name + '.crl'),
                  'CRLissuer=dirName:crl_issuer_dn');
  });
  sections.push('[cdp_nosign]', 'fullname=URI:' + url('/i-nosign.crl'),
                'CRLissuer=dirName:nosign_issuer_dn',
                '[nosign_issuer_dn]', 'CN=rev ossl crl issuer without crlsign');
  sections.push('[crl_issuer_dn]', 'CN=rev ossl crl issuer',
                '[cdp_key]', 'fullname=URI:' + url('/s-key.crl'),
                '[cdp_rest]', 'fullname=URI:' + url('/s-rest.crl'),
                '[cdp_point_reasons]', 'fullname=URI:' + url('/o-empty.crl'),
                'reasons=keyCompromise');
  fs.writeFileSync(path.join(dir, 'ext.cnf'), sections.join('\n') + '\n');

  const key = function (name) {
    log.debug("Entering key().");
    openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt',
             'ec_paramgen_curve:P-256',
             '-out', name + '.key'], dir);
    log.debug("Leaving key().");
  };

  const selfSigned = function (name, subject, extensions) {
    log.debug("Entering selfSigned().");
    key(name);
    openssl(['req', '-x509', '-new', '-config', 'ext.cnf', '-extensions',
             extensions,
             '-key', name +
                     '.key', '-subj', subject, '-days', '2', '-out',
             name + '.pem'], dir);
    log.debug("Leaving selfSigned().");
    return { name: name, pem: read(name + '.pem'), key: read(name + '.key'),
             path: path.join(dir, name + '.pem'),
             keyPath: path.join(dir, name + '.key') };
  };

  const issued = function (name, subject, issuer, serial, extensions) {
    log.debug("Entering issued().");
    key(name);
    openssl(['req', '-new', '-config', 'ext.cnf', '-key', name + '.key',
             '-subj', subject,
             '-out', name + '.csr'], dir);
    openssl(['x509', '-req', '-in', name + '.csr', '-CA', issuer + '.pem',
             '-CAkey',
             issuer + '.key', '-set_serial', '0x' +
                                             serial, '-days', '2', '-extfile',
             'ext.cnf', '-extensions', extensions, '-out', name + '.pem'], dir);
    log.debug("Leaving issued().");
    return { name: name, pem: read(name + '.pem'), key: read(name + '.key'),
             serial: serial,
             path: path.join(dir, name + '.pem'), keyPath: path.join(dir,
                                                                     name +
                                                                         '.key') };
  };

  const fx = { dir: dir, base: base };
  fx.root = selfSigned('root', '/CN=rev ossl root', 'root_ext');
  fx.issuing = issued('issuing', '/CN=rev ossl issuing', 'root', '0100',
                      'issuing_ext');
  fx.responder = issued('responder', '/CN=rev ossl responder', 'issuing',
                        '0200', 'responder_ext');
  fx.noEku = issued('noeku', '/CN=rev ossl responder without eku', 'issuing',
                    '0201', 'noeku_ext');
  // A self-signed certificate carrying the ISSUING CA'S OWN NAME and another
  // key.
  fx.impostor = selfSigned('impostor', '/CN=rev ossl issuing', 'impostor_ext');
  fx.crlIssuer = issued('crlissuer', '/CN=rev ossl crl issuer', 'root', '0300',
                        'crl_issuer_ext');
  // The same name again, self-signed: carries the right name and chains
  // nowhere.
  fx.crlIssuerImpostor = selfSigned('crlissuer-impostor', '/CN=rev ossl crl ' +
      'issuer',
                                    'impostor_ext');
  fx.subCa = issued('subca', '/CN=rev ossl sub ca', 'issuing', '4002',
                    'subca_ext');
  fx.crlIssuerNoSign = issued('crlissuer-nosign', '/CN=rev ossl crl issuer ' +
                                                  'without crlsign',
                              'root', '0301', 'nosign_issuer_ext');
  fx.noSignCa = issued('nosignca', '/CN=rev ossl ca without crlsign', 'root',
                       '0400',
                       'nosign_ca_ext');
  // A leaf under the CA that may not sign CRLs, whose own CRL that CA signs.
  sections.push('[nosign_leaf_ext]', 'basicConstraints=CA:FALSE',
                'keyUsage=critical,digitalSignature',
                'crlDistributionPoints=URI:' + url('/n-nosign.crl'));
  fs.writeFileSync(path.join(dir, 'ext.cnf'), sections.join('\n') + '\n');
  fx.noSignLeaf = issued('nosign-leaf', '/CN=rev ossl under a ca without ' +
                                        'crlsign',
                         'nosignca', '5001', 'nosign_leaf_ext');
  // A delegated responder whose certificate EXPIRED, issued with `openssl ca`,
  // the one OpenSSL 3.0 command that takes a start and an end date.
  key('expired-responder');
  openssl(['req', '-new', '-config', 'ext.cnf', '-key', 'expired-responder.key',
           '-subj',
           '/CN=rev ossl expired responder', '-out', 'expired-responder.csr'],
          dir);
  fs.writeFileSync(path.join(dir, 'issue-index.txt'), '');
  fs.writeFileSync(path.join(dir, 'issue-serial'), '0202\n');
  fs.writeFileSync(path.join(dir, 'issue.cnf'),
    '[ca]\ndefault_ca=d\n[d]\ndatabase=' + path.join(dir, 'issue-index.txt') +
    '\nnew_certs_dir=' + dir + '\nserial=' + path.join(dir, 'issue-serial') +
    '\ndefault_md=sha256\npolicy=any\nunique_subject=no\n[any]\ncommonName=supplied\n');
  openssl(['ca', '-batch', '-notext', '-config', 'issue.cnf', '-in',
           'expired-responder.csr',
           '-cert', 'issuing.pem', '-keyfile', 'issuing.key', '-startdate',
           '20200101000000Z',
           '-enddate', '20200102000000Z', '-extfile', 'ext.cnf', '-extensions',
           'responder_ext', '-out', 'expired-responder.pem'], dir);
  fx.expiredResponder = { name: 'expired-responder',
                          pem: read('expired-responder.pem'),
                          path: path.join(dir, 'expired-responder.pem'),
                          keyPath: path.join(dir, 'expired-responder.key') };
  fx.leaf = {};
  LEAVES.forEach(function (one) {
    fx.leaf[one[0]] = issued('leaf-' + one[0], '/CN=rev ossl ' + one[0],
                             'issuing', one[1],
                             one[0] + '_ext');
  });
  log.debug("Leaving opensslFixture().");
  return fx;
}

// A CRL by `openssl ca -gencrl`, with the index, the cRLNumber and the CRL
// extensions (plus any sections they reference) given. A `crlNumber` of null
// leaves the `crlnumber` line out, which is how OpenSSL writes a list with NO
// cRLNumber at all.
function opensslCrl(fx, signer, label, crlNumber, lines, extensionLines) {
  log.debug("Entering opensslCrl().");
  const d = path.join(fx.dir, 'crl-' + label);
  fs.mkdirSync(d);
  fs.writeFileSync(path.join(d, 'index.txt'), lines.join(''));
  if (crlNumber !== null) {
    fs.writeFileSync(path.join(d, 'crlnumber'), crlNumber + '\n');
  }
  fs.writeFileSync(path.join(d, 'ca.cnf'),
    '[ca]\ndefault_ca=d\n[d]\ndatabase=' + path.join(d, 'index.txt') +
    (crlNumber === null ? '' : '\ncrlnumber=' + path.join(d, 'crlnumber')) +
    '\ndefault_md=sha256\ndefault_crl_days=1\nunique_subject=no\n[x]\n' +
    (extensionLines || []).join('\n') + '\n');
  const args = ['ca', '-config', path.join(d, 'ca.cnf'), '-gencrl', '-keyfile',
                signer.keyPath, '-cert', signer.path, '-out',
                path.join(d, 'crl.pem')];
  if (extensionLines && extensionLines.length) {
    args.push('-crlexts', 'x');
  }
  openssl(args, fx.dir);
  log.debug("Leaving opensslCrl().");
  return fs.readFileSync(path.join(d, 'crl.pem'));
}

// AN INDIRECT CRL, which OpenSSL cannot write: pkijs builds it — an issuing
// distribution point naming the URL and indirectCRL, and entries each
// optionally preceded by a certificateIssuer — and the caller then has `openssl
// crl` verify it against its signer, so the document is read by something other
// than pkijs.
async function indirectCrl(signer, spec) {
  log.debug("Entering indirectCrl().");
  const pkijs = require('pkijs');
  const asn1js = require('asn1js');
  require('../common/pki_revocation');
  const buffer = function (text) {
    log.debug("Entering buffer().");
    const buf = Buffer.from(String(text).replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
    log.debug("Leaving buffer().");
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  };

  const plain = function (bytes) {
    log.debug("Entering plain().");
    log.debug("Leaving plain().");
    return bytes.buffer.slice(bytes.byteOffset,
                              bytes.byteOffset + bytes.byteLength);
  };

  const tagged = function (tag, value, constructed) {
    log.debug("Entering tagged().");
    log.debug("Leaving tagged().");
    return constructed
      ? new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: tag },
                                 value: value })
      : new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: tag },
                               valueHex: value });
  };
  const signerCert = pkijs.Certificate.fromBER(buffer(signer.pem));
  const idpFields = [tagged(0,
                            [tagged(0,
                                    [tagged(6, plain(Buffer.from(spec.url)))],
                                    true)], true)];
  if (spec.indirect !== false) {
    idpFields.push(tagged(4, plain(Buffer.from([0xff]))));
  }
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;
  crl.issuer = signerCert.subject;
  const now = Date.now();
  crl.thisUpdate = new pkijs.Time({ type: 0, value: new Date(now - 60000) });
  crl.nextUpdate = new pkijs.Time({ type: 0, value: new Date(now + 3600000) });
  const crlExtensions = [
    new pkijs.Extension({ extnID: '2.5.29.20', critical: false,
      extnValue: new asn1js.Integer({ value: 1 }).toBER(false) }),
    new pkijs.Extension({ extnID: '2.5.29.28', critical: true,
      extnValue: new asn1js.Sequence({ value: idpFields }).toBER(false) })
  ];
  // RFC 5280 section 5.2.7: where the list's own signer's certificate is.
  if (spec.caIssuers && spec.caIssuers.length) {
    crlExtensions.push(new pkijs.Extension({ extnID: '1.3.6.1.5.5.7.1.1',
      critical: false,
      extnValue: new pkijs.InfoAccess({ accessDescriptions: spec.caIssuers.map(
          function (url) {
        return new pkijs.AccessDescription({ accessMethod: '1.3.6.1.5.5.7.48.2',
          accessLocation: new pkijs.GeneralName({ type: 6, value: url }) });
      }) }).toSchema().toBER(false) }));
  }
  crl.crlExtensions = new pkijs.Extensions({ extensions: crlExtensions });
  crl.revokedCertificates = spec.entries.map(function (one) {
    const entry = new pkijs.RevokedCertificate();
    let bytes = Buffer.from(one.serial.length % 2 ? '0' + one.serial :
                            one.serial, 'hex');
    if (bytes[0] & 0x80) {
      bytes = Buffer.concat([Buffer.from([0]), bytes]);
    }
    entry.userCertificate = new asn1js.Integer({ valueHex: plain(bytes) });
    entry.revocationDate = new pkijs.Time({ type: 0,
                                            value: new Date(now - 30000) });
    const extensions = [new pkijs.Extension({ extnID: '2.5.29.21',
      critical: false,
      extnValue: new asn1js.Enumerated({ value: 1 }).toBER(false) })];
    if (one.certificateIssuerPem) {
      const named = pkijs.Certificate.fromBER(buffer(one.certificateIssuerPem));
      extensions.push(new pkijs.Extension({ extnID: '2.5.29.29', critical: true,
        extnValue: new pkijs.GeneralNames({ names: [
          new pkijs.GeneralName({ type: 4, value: named.subject })] })
          .toSchema().toBER(false) }));
    }
    entry.crlEntryExtensions = new pkijs.Extensions({ extensions: extensions });
    return entry;
  });
  // EC for the OpenSSL fixtures, RSA for this service's own authorities.
  const keyObject = nodeCrypto.createPrivateKey(signer.key);
  const pkcs8 = keyObject.export({ type: 'pkcs8', format: 'pem' });
  const privateKey = await crypto.subtle.importKey('pkcs8', buffer(pkcs8),
    keyObject.asymmetricKeyType === 'rsa'
      ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
      : { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  await crl.sign(privateKey, 'SHA-256');
  log.debug("Leaving indirectCrl().");
  return Buffer.from(crl.toSchema(true).toBER(false));
}

function chainOf(fx) {
  log.debug("Entering chainOf().");
  log.debug("Leaving chainOf().");
  return [fx.issuing.pem, fx.root.pem];
}

async function theOcsp(t, fx) {
  log.debug("Entering theOcsp().");
  t.log.info('=== 8. OCSP: good, revoked, unknown, the wrong key, no EKU, ' +
             'stale, replayed, and one request for two callers ===');
  const status = require('../common/revocation_status');
  const errorCodes = require('../common/error_codes');
  const routes = fx.routes;
  const hits = fx.hits;
  const index = path.join(fx.dir, 'ocsp-index.txt');
  fs.writeFileSync(index,
                   [indexLine('1001'), indexLine('1002', 'keyCompromise'),
                           indexLine('1005'), indexLine('100A'), indexLine(
                               '1006'),
                           indexLine('1007'), indexLine('1008'), indexLine(
                               '1009'),
                           indexLine('100B'), indexLine('100C'), indexLine(
                               '100D'),
                           indexLine('100E')].join(''));
  const responder = function (signer) {
    log.debug("Entering responder().");
    log.debug("Leaving responder().");
    return { ocsp: { dir: fx.dir, index: index, ca: fx.issuing.path,
                     signer: signer.path, key: signer.keyPath } };
  };
  routes['/ocsp/issuer'] = responder(fx.issuing);
  routes['/ocsp/delegated'] = responder(fx.responder);
  routes['/ocsp/impostor'] = responder(fx.impostor);
  routes['/ocsp/noeku'] = responder(fx.noEku);
  routes['/ocsp/dedupe'] = responder(fx.issuing);
  routes['/ocsp/tampered'] = responder(fx.responder);
  routes['/ocsp/tampered'].ocsp.tamper = true;
  routes['/ocsp/expired'] = responder(fx.expiredResponder);
  // tryLater (RFC 6960 section 4.2.1): an OCSPResponse with no responseBytes.
  routes['/ocsp/trylater'] = { body: Buffer.from('30030a0103', 'hex') };
  routes['/o-root.crl'] = { body: opensslCrl(fx, fx.root, 'root', '01', []) };
  routes['/o-empty.crl'] = { body: opensslCrl(fx, fx.issuing, 'empty', '01',
                                              []) };
  routes['/o-revokes.crl'] = { body: opensslCrl(fx, fx.issuing, 'revokes', '01',
                                                [indexLine('1004',
                                                           'keyCompromise')]) };
  const input = function (leaf) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: chainOf(fx), verified: true };
  };

  const good = await status.verdictFor(input(fx.leaf.ocspGood));
  const goodLink = good.links[0];
  t.check(good.status === 'good' && goodLink.answeredBy === 'ocsp' &&
          goodLink.ocspResponder === 'issuer' &&
          goodLink.ocspNonce === 'matched',
          'OCSP GOOD: a response openssl signed with the ISSUER\'s key, ' +
          'echoing the nonce this service sent, answers the leaf good',
          JSON.stringify({ status: good.status, link: goodLink }));

  const revoked = await status.verdictFor(input(fx.leaf.ocspRevoked));
  const revokedLink = revoked.links[0];
  t.check(revoked.status === 'revoked' && revoked.refused &&
          revokedLink.answeredBy === 'ocsp' &&
          revokedLink.ocspResponder === 'delegated' &&
          revoked.revoked.reason === 'keyCompromise' &&
          /OCSP responder/.test(revoked.why),
          'OCSP REVOKED, from a DELEGATED responder the issuer certified ' +
          'with id-kp-OCSPSigning: refused with the reason openssl put in ' +
          'the response',
          revoked.why);
  t.equal(errorCodes.codeOf(revoked), 'STS-PKI-0118', 'carrying STS-PKI-0118');
  t.equal(hits['/o-empty.crl'], undefined,
          'and the CRL the same certificate names was NOT fetched — OCSP ' +
          'answered first');

  const unknown = await status.verdictFor(input(fx.leaf.ocspUnknown));
  t.check(unknown.status === 'unknown' && !unknown.refused &&
          unknown.unknown.some(function (one) {
            return one.kind === 'responder-unknown';
          }),
          'OCSP UNKNOWN: a signed `unknown` is unknown, and soft-fail ' +
          'accepts it',
          unknown.why);
  t.check(hits['/o-empty.crl'] >= 1 && /does not list it/.test(unknown.why),
          'and it is NOT UPGRADED by the CRL that does not list the ' +
          'certificate — the CRL was read and the answer stayed ' +
          'unknown', unknown.why);
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const hard = await status.verdictFor(input(fx.leaf.ocspUnknown));
    t.check(hard.refused && errorCodes.codeOf(hard) === 'STS-PKI-0119',
            'while HARD-FAIL refuses a certificate the issuer\'s own ' +
            'responder does not know, with STS-PKI-0119', hard.why);
  });
  const outvoted = await status.verdictFor(input(
      fx.leaf.ocspUnknownCrlRevokes));
  t.check(outvoted.status === 'revoked' &&
          outvoted.links[0].answeredBy === 'crl',
          'and a CRL that LISTS the certificate still wins over a ' +
          'responder\'s unknown',
          outvoted.why);

  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const wrong = await status.verdictFor(input(fx.leaf.ocspWrongKey));
    t.check(wrong.refused && wrong.status === 'unknown' &&
            /issuer's key does not verify its signature/.test(wrong.why) &&
            /was not issued by the certificate's issuer/.test(wrong.why),
            'A RESPONDER SIGNING WITH THE WRONG KEY — a certificate carrying ' +
            'the issuer\'s own NAME over another key — is not believed, and ' +
            'hard-fail refuses', wrong.why);
    const noEku = await status.verdictFor(input(fx.leaf.ocspNoEku));
    t.check(noEku.refused && /carries no id-kp-OCSPSigning/.test(noEku.why),
            'A DELEGATED RESPONDER WITHOUT THE EKU — issued by the right CA, ' +
            'signing correctly — is not a responder, and hard-fail ' +
            'refuses', noEku.why);
    const tampered = await status.verdictFor(input(fx.leaf.ocspTampered));
    t.check(tampered.refused &&
            /key does not verify its signature/.test(tampered.why),
            'a delegated responder with the EKU whose response has one bit ' +
            'of its signature flipped is not believed', tampered.why);
    const expired = await status.verdictFor(input(
        fx.leaf.ocspExpiredResponder));
    t.check(expired.refused && /outside its validity period/.test(expired.why),
            'nor is a delegated responder whose certificate has EXPIRED',
            expired.why);
    const tryLater = await status.verdictFor(input(fx.leaf.ocspTryLater));
    t.check(tryLater.refused && /tryLater/.test(tryLater.why),
            'a responder answering tryLater gave no answer, and the policy ' +
            'decides',
            tryLater.why);
  });
  const fallback = await status.verdictFor(input(fx.leaf.ocspWrongKeyFallback));
  t.check(fallback.status === 'good' &&
          fallback.links[0].answeredBy === 'crl' &&
          /not signed by anybody the issuer authorised/.test(
              fallback.links[0].why),
          'and where the certificate also names a CRL, an untrustworthy ' +
          'responder is replaced by the list — with the responder\'s failure ' +
          'kept on the link',
          fallback.links[0].why);

  // A RESPONSE PRODUCED IN ADVANCE, the way RFC 5019 responders produce them:
  // no nonce, and no nextUpdate. It is served verbatim to every request.
  openssl(['ocsp', '-issuer', fx.issuing.path, '-cert', fx.leaf.ocspStale.path,
           '-no_nonce',
           '-reqout', 'stale-req.der'], fx.dir);
  openssl(['ocsp', '-index', index, '-CA', fx.issuing.path, '-rsigner',
           fx.issuing.path,
           '-rkey', fx.issuing.keyPath, '-reqin', 'stale-req.der', '-respout',
           'stale-resp.der'], fx.dir);
  routes['/ocsp/stale'] = { body: fs.readFileSync(
      path.join(fx.dir, 'stale-resp.der')),
                            contentType: 'application/ocsp-response' };
  // The same pre-produced response, served for a DIFFERENT certificate.
  routes['/ocsp/other'] = { body: fs.readFileSync(
      path.join(fx.dir, 'stale-resp.der')),
                            contentType: 'application/ocsp-response' };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const other = await status.verdictFor(input(fx.leaf.ocspOtherCertificate));
    t.check(other.refused &&
            /no single response names its issuer and serial/.test(other.why),
            'a valid, signed, nonce-less response ABOUT ANOTHER CERTIFICATE ' +
            'answers nothing about this one — the CertID must ' +
            'match', other.why);
  });
  const producedAt = Date.now();
  const noNonce = await status.verdictFor(input(fx.leaf.ocspStale));
  t.check(noNonce.status === 'good' && noNonce.links[0].ocspNonce === 'absent',
          'a response that echoes NO nonce is believed by default — the ' +
          'pre-produced responses of RFC 5019 cannot carry one', noNonce.why);
  status.resetCache();
  await withSettings({ 'pki.revocationCheck': 'hard-fail',
                       'pki.revocationOcspRequireNonce': true },
                     async function () {
    const strict = await status.verdictFor(input(fx.leaf.ocspStale));
    t.check(strict.refused && /echoes no nonce/.test(strict.why),
            'unless pki.revocationOcspRequireNonce, which refuses it',
            strict.why);
  });
  status.resetCache();
  await new Promise(function (resolve) {
    setTimeout(resolve, Math.max(0, 1300 - (Date.now() - producedAt)));
  });
  await withSettings({ 'pki.revocationCheck': 'hard-fail',
                       'pki.revocationOcspMaxAgeS': 1,
                       'pki.revocationClockSkewS': 0 }, async function () {
    const stale = await status.verdictFor(input(fx.leaf.ocspStale));
    t.check(stale.refused && /STALE/.test(stale.why) &&
            /no nextUpdate/.test(stale.why),
            'A STALE RESPONSE — no nextUpdate, and a thisUpdate older than ' +
            'pki.revocationOcspMaxAgeS — is refused under hard-fail',
            stale.why);
  });

  openssl(['ocsp', '-issuer', fx.issuing.path, '-cert', fx.leaf.ocspReplay.path,
           '-reqout', 'replay-req.der'], fx.dir);
  openssl(['ocsp', '-index', index, '-CA', fx.issuing.path, '-rsigner',
           fx.issuing.path,
           '-rkey', fx.issuing.keyPath, '-reqin', 'replay-req.der', '-respout',
           'replay-resp.der', '-ndays', '1'], fx.dir);
  routes['/ocsp/replay'] = { body: fs.readFileSync(
      path.join(fx.dir, 'replay-resp.der')),
                             contentType: 'application/ocsp-response' };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const replay = await status.verdictFor(input(fx.leaf.ocspReplay));
    t.check(replay.refused && /replay/.test(replay.why),
            'a response echoing SOMEBODY ELSE\'S NONCE is a replay and is ' +
            'refused, however valid its signature', replay.why);
  });

  // THE CLOCK, moved rather than waited for: a day and a half on, a response
  // whose nextUpdate was a day away is past it; an hour back, one produced now
  // is in the future.
  const realNow = Date.now;
  status.resetCache();
  try {
    Date.now = function () {
      log.debug("Entering now().");
      log.debug("Leaving now().");
      return realNow() + 36 * 3600 * 1000;
    };
    const late = await status.verdictFor(input(fx.leaf.ocspGood));
    t.check(late.links[0].status === 'unknown' &&
            /STALE — its nextUpdate was/.test(late.links[0].why),
            'a response PAST ITS nextUpdate is stale', late.links[0].why);
    status.resetCache();
    Date.now = function () {
      log.debug("Entering now().");
      log.debug("Leaving now().");
      return realNow() - 3600 * 1000;
    };
    const early = await status.verdictFor(input(fx.leaf.ocspGood));
    t.check(early.links[0].status === 'unknown' &&
            /in the future/.test(early.links[0].why),
            'and one whose thisUpdate is further in the future than ' +
            'pki.revocationClockSkewS is not believed either',
            early.links[0].why);
  } finally {
    Date.now = realNow;
  }
  status.resetCache();

  const both = await Promise.all([status.verdictFor(input(fx.leaf.ocspDedupe)),
                                  status.verdictFor(
                                      input(fx.leaf.ocspDedupe))]);
  t.check(both[0].status === 'good' && both[1].status === 'good' &&
          hits['/ocsp/dedupe'] === 1,
          'TWO CALLERS AT ONCE make ONE request to the responder',
          JSON.stringify(hits));
  await status.verdictFor(input(fx.leaf.ocspDedupe));
  t.equal(hits['/ocsp/dedupe'], 1,
          'and a third is answered from the cache, until the response\'s ' +
          'nextUpdate');

  const issuerHits = hits['/ocsp/issuer'];
  status.resetCache();
  await withSettings({ 'pki.revocationOcsp': 'after-crl' }, async function () {
    const later = await status.verdictFor(input(fx.leaf.ocspRevoked));
    t.check(later.status === 'good' && later.links[0].answeredBy === 'crl' &&
            hits['/ocsp/delegated'] === 1,
            'pki.revocationOcsp=after-crl asks the CRL FIRST, and a CRL that ' +
            'answers means the responder is never dialled', later.why);
    const onlyOcsp = await status.verdictFor(input(fx.leaf.ocspGood));
    t.check(onlyOcsp.status === 'good' &&
            onlyOcsp.links[0].answeredBy === 'ocsp',
            'while a certificate naming no CRL is still answered by its ' +
            'responder',
            onlyOcsp.why);
  });
  await withSettings({ 'pki.revocationOcsp': 'off' }, async function () {
    const off = await status.verdictFor(input(fx.leaf.ocspGood));
    t.check(off.status === 'unknown' &&
            hits['/ocsp/issuer'] === issuerHits + 1 &&
            off.unknown.some(function (one) {
              return one.kind === 'no-distribution-point';
            }),
            'and pki.revocationOcsp=off asks no responder at all', off.why);
  });
  log.debug("Leaving theOcsp().");
}

async function theDeltas(t, fx) {
  log.debug("Entering theDeltas().");
  t.log.info('=== 9. delta CRLs: one that revokes, one that removes, one ' +
             'built on another base, and one that cannot be reached ===');
  const status = require('../common/revocation_status');
  const routes = fx.routes;
  const input = function (leaf) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: chainOf(fx), verified: true };
  };
  // freshestCRL ON THE BASE CRL for this pair.
  routes['/d-base.crl'] = { body: opensslCrl(fx, fx.issuing, 'd-base', '0A',
    [indexLine('2002', 'certificateHold')],
    ['freshestCRL=URI:' + fx.base + '/d-delta.crl']) };
  routes['/d-delta.crl'] = { body: opensslCrl(fx, fx.issuing, 'd-delta', '0B',
    [indexLine('2001', 'keyCompromise'), indexLine('2002', 'removeFromCRL')],
    ['2.5.29.27=critical,ASN1:INTEGER:10']) };
  // freshestCRL ON THE CERTIFICATE for this one, and a delta built on number
  // 99.
  routes['/d3-base.crl'] = { body: opensslCrl(fx, fx.issuing, 'd3-base', '14',
                                              []) };
  routes['/d3-delta.crl'] = { body: opensslCrl(fx, fx.issuing, 'd3-delta', '15',
    [indexLine('2005', 'keyCompromise')],
    ['2.5.29.27=critical,ASN1:INTEGER:99']) };
  // A delta NOT NEWER than its base; a freshestCRL naming a COMPLETE list; and
  // a delta whose issuing distribution point is not its base's.
  routes['/d5-base.crl'] = { body: opensslCrl(fx, fx.issuing, 'd5-base', '28',
    [],
    ['freshestCRL=URI:' + fx.base + '/d5-delta.crl']) };
  routes['/d5-delta.crl'] = { body: opensslCrl(fx, fx.issuing, 'd5-delta', '27',
    [indexLine('2007', 'keyCompromise')],
    ['2.5.29.27=critical,ASN1:INTEGER:40']) };
  routes['/d6-base.crl'] = { body: opensslCrl(fx, fx.issuing, 'd6-base', '32',
    [],
    ['freshestCRL=URI:' + fx.base + '/o-empty.crl']) };
  routes['/d7-base.crl'] = { body: opensslCrl(fx, fx.issuing, 'd7-base', '3C',
    [],
    ['freshestCRL=URI:' + fx.base + '/d7-delta.crl',
     'issuingDistributionPoint=critical,@idp_d7', '[idp_d7]',
     'fullname=URI:' + fx.base + '/d7-base.crl']) };
  routes['/d7-delta.crl'] = { body: opensslCrl(fx, fx.issuing, 'd7-delta', '3D',
    [indexLine('2009', 'keyCompromise')],
    ['2.5.29.27=critical,ASN1:INTEGER:60']) };
  // A base whose delta is not there.
  routes['/d4-base.crl'] = { body: opensslCrl(fx, fx.issuing, 'd4-base', '1E',
    [indexLine('2003', 'certificateHold'), indexLine('2004', 'keyCompromise')],
    ['freshestCRL=URI:' + fx.base + '/d4-missing.crl']) };

  const revokes = await status.verdictFor(input(fx.leaf.deltaRevokes));
  t.check(revokes.status === 'revoked' &&
          /with its delta at/.test(revokes.links[0].why) &&
          /d-delta\.crl/.test(revokes.links[0].deltaUrl || ''),
          'A DELTA THAT REVOKES: the base CRL does not list the leaf, the ' +
          'delta its freshestCRL names does, and the merged answer is ' +
          'revoked', revokes.links[0].why);
  const removes = await status.verdictFor(input(fx.leaf.deltaRemoves));
  t.check(removes.status === 'good' &&
          /with its delta at/.test(removes.links[0].why),
          'A DELTA THAT REMOVES: the base lists the leaf on hold, the delta ' +
          'says removeFromCRL, and the merged answer is ' +
          'good', removes.links[0].why);
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const mismatch = await status.verdictFor(input(fx.leaf.deltaMismatch));
    t.check(mismatch.refused && mismatch.status === 'unknown' &&
            /BaseCRLNumber is 99/.test(mismatch.why),
            'A DELTA WITH A MISMATCHED BASE NUMBER — built on list 99 when ' +
            'the base here is 20 — is not merged; its revocation is not ' +
            'believed, and hard-fail refuses the certificate it would have ' +
            'been about', mismatch.why);
    const held = await status.verdictFor(input(fx.leaf.heldNoDelta));
    t.check(held.refused && held.status === 'unknown',
            'a base listing a certificate ON HOLD whose delta cannot be ' +
            'fetched is unknown — the hold is exactly what a delta may have ' +
            'released', held.why);
    const permanent = await status.verdictFor(input(fx.leaf.revokedNoDelta));
    t.check(permanent.status === 'revoked' &&
            permanent.revoked.reason === 'keyCompromise',
            'while a base\'s PERMANENT revocation stands without its delta — ' +
            'no newer list can un-revoke keyCompromise', permanent.why);
    const notNewer = await status.verdictFor(input(fx.leaf.deltaNotNewer));
    t.check(notNewer.refused && notNewer.status === 'unknown' &&
            /cRLNumber is not greater/.test(notNewer.why),
            'a delta whose own cRLNumber is not greater than its base\'s is ' +
            'not newer than the list it would update', notNewer.why);
    const complete = await status.verdictFor(input(fx.leaf.deltaComplete));
    t.check(complete.refused && /not a delta CRL/.test(complete.why),
            'a freshestCRL naming a COMPLETE list is not a delta to merge',
            complete.why);
    const otherScope = await status.verdictFor(input(fx.leaf.deltaOtherScope));
    t.check(otherScope.refused && otherScope.status === 'unknown' &&
            /different scope/.test(otherScope.why),
            'and a delta whose issuing distribution point is not its base\'s ' +
            'describes a different scope', otherScope.why);
    const atPoint = await status.verdictFor(input(fx.leaf.deltaAtPoint));
    t.check(atPoint.refused && /DELTA CRL/.test(atPoint.why),
            'and a delta served at a cRLDistributionPoint is not taken for ' +
            'the complete list', atPoint.why);
  });
  log.debug("Leaving theDeltas().");
}

async function theIndirect(t, fx) {
  log.debug("Entering theIndirect().");
  t.log.info('=== 10. indirect CRLs: a second CA revoking the leaf, entry ' +
             'attribution, and signers the certificate does not name ===');
  const status = require('../common/revocation_status');
  const routes = fx.routes;
  const input = function (leaf, extra) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: chainOf(fx).concat(extra || []),
             verified: true };
  };
  // Serial 3002 is listed FIRST with no certificateIssuer, so it belongs to the
  // CRL issuer — not to the leaf's issuer; 3001 names the leaf's issuer; 3003
  // follows it with none, so RFC 5280 section 5.3.3 carries that issuer
  // forward.
  const listed = await indirectCrl(fx.crlIssuer,
                                   { url: fx.base + '/i-indirect.crl',
                                     entries: [
    { serial: '3002' },
    { serial: '3001', certificateIssuerPem: fx.issuing.pem },
    { serial: '3003' }
  ] });
  fs.writeFileSync(path.join(fx.dir, 'indirect.crl'), listed);
  const openSslReads = String(childProcess.spawnSync('openssl',
    ['crl', '-inform', 'DER',
    '-in', path.join(fx.dir,
                     'indirect.crl'), '-CAfile', fx.crlIssuer.path, '-noout',
    '-text'],
    { encoding: 'utf8' }).stderr) + String(childProcess.spawnSync('openssl',
    ['crl', '-inform',
    'DER', '-in', path.join(fx.dir, 'indirect.crl'), '-noout', '-text'],
    { encoding: 'utf8' }).stdout);
  t.check(/verify OK/.test(openSslReads) &&
          /Certificate Issuer/.test(openSslReads) &&
          /Indirect CRL/.test(openSslReads),
          'the indirect CRL pkijs built is one OPENSSL reads, verifies ' +
          'against the CRL issuer and shows as indirect with a ' +
          'certificateIssuer entry',
          openSslReads.slice(0, 400));
  routes['/i-indirect.crl'] = { body: listed };
  routes['/i-forged.crl'] = { body: await indirectCrl(fx.crlIssuerImpostor, {
    url: fx.base + '/i-forged.crl',
    entries: [{ serial: '3004', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/i-unnamed.crl'] = { body: await indirectCrl(fx.crlIssuer, {
    url: fx.base + '/i-unnamed.crl',
    entries: [{ serial: '3005', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/i-flat.crl'] = { body: await indirectCrl(fx.crlIssuer, {
    url: fx.base + '/i-flat.crl', indirect: false, entries: [] }) };
  routes['/i-direct-named.crl'] = { body: await indirectCrl(fx.issuing, {
    url: fx.base + '/i-direct-named.crl', indirect: false,
    entries: [{ serial: '3007', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/i-nosign.crl'] = { body: await indirectCrl(fx.crlIssuerNoSign, {
    url: fx.base + '/i-nosign.crl',
    entries: [{ serial: '3008', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/n-nosign.crl'] = { body: opensslCrl(fx, fx.noSignCa, 'n-nosign',
                                               '01',
                                               [indexLine('5001',
                                                          'keyCompromise')]) };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const named = await status.verdictFor(input(fx.leaf.directNamedEntry));
    t.check(named.refused && named.status === 'unknown' &&
            /does not declare itself indirect in its issuing distribution point/.test(named.why),
            'an entry carrying a certificateIssuer in a list that is NOT ' +
            'declared indirect makes the list unusable rather than being ' +
            'read', named.why);
    const noSign = await status.verdictFor(input(fx.leaf.indirectNoCrlSign,
                                                 [fx.crlIssuerNoSign.pem]));
    t.check(noSign.refused && noSign.status === 'unknown' &&
            /may not sign CRLs/.test(noSign.why),
            'a CRL issuer whose certificate lacks cRLSign is not authorised, ' +
            'whatever the certificate names', noSign.why);
    const directNoSign = await status.verdictFor({ leaf: fx.noSignLeaf.pem,
      chain: [fx.noSignCa.pem, fx.root.pem], verified: true });
    t.check(directNoSign.refused &&
            /does not include cRLSign/.test(directNoSign.why),
            'nor is a DIRECT list signed by an issuer whose keyUsage leaves ' +
            'out cRLSign (RFC 5280 section 4.2.1.3)', directNoSign.why);
  });
  const issuersFile = path.join(fx.dir, 'crl-issuers.pem');
  fs.writeFileSync(issuersFile, fx.crlIssuer.pem + fx.crlIssuerImpostor.pem);

  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const nobody = await status.verdictFor(input(fx.leaf.indirectRevoked));
    t.check(nobody.refused && nobody.status === 'unknown' &&
            /no certificate for that name/.test(nobody.why),
            'with the CRL issuer\'s certificate nowhere to be found, an ' +
            'indirect list cannot be trusted and hard-fail ' +
            'refuses', nobody.why);
    const inChain = await status.verdictFor(input(fx.leaf.indirectRevoked,
                                                  [fx.crlIssuer.pem]));
    t.check(inChain.status === 'revoked' && inChain.links[0].indirect === true,
            'AN INDIRECT CRL REVOKING A CERTIFICATE FROM A SECOND CA: the ' +
            'leaf\'s cRLIssuer names it, its certificate came with the chain ' +
            'and chains to the same Root, and the entry that names the ' +
            'leaf\'s issuer revokes it', inChain.why);
  });
  await withSettings({ 'pki.revocationCrlIssuersFile': issuersFile },
                     async function () {
    const fromFile = await status.verdictFor(input(fx.leaf.indirectRevoked));
    t.check(fromFile.status === 'revoked',
            'and the same answer with the signer found in ' +
            'pki.revocationCrlIssuersFile',
            fromFile.why);
    const other = await status.verdictFor(input(fx.leaf.indirectOtherIssuer));
    t.check(other.status === 'good',
            'an entry with NO certificateIssuer before it belongs to the CRL ' +
            'issuer — the same serial under the leaf\'s own issuer is ' +
            'good', other.why);
    const carried = await status.verdictFor(input(fx.leaf.indirectCarried));
    t.check(carried.status === 'revoked',
            'while an entry AFTER a certificateIssuer belongs to that issuer ' +
            '(RFC 5280 section 5.3.3)', carried.why);
    await withSettings({ 'pki.revocationCheck': 'hard-fail' },
                       async function () {
      const forged = await status.verdictFor(input(fx.leaf.indirectForged));
      t.check(forged.refused && forged.status === 'unknown' &&
              forged.status !== 'revoked' &&
              /signature does not verify/.test(forged.why),
              'a list signed by a certificate that carries the named CRL ' +
              'issuer\'s NAME and chains nowhere is not believed — the real ' +
              'CRL issuer\'s key does not verify it, and the impostor is not ' +
              'a signer it may be checked against',
              forged.why);
      const unnamed = await status.verdictFor(input(fx.leaf.indirectUnnamed));
      t.check(unnamed.refused && unnamed.status === 'unknown' &&
              /names no separate CRL issuer/.test(unnamed.why),
              'AN INDIRECT CRL FROM A SIGNER THE CERTIFICATE DOES NOT NAME — ' +
              'a real, properly signed list revoking this very leaf, from a ' +
              'CRL issuer its distribution point never mentioned — revokes ' +
              'nothing, and hard-fail refuses', unnamed.why);
      const flat = await status.verdictFor(input(fx.leaf.indirectFlat));
      t.check(flat.refused && /does not declare itself indirect/.test(flat.why),
              'and a list at a cRLIssuer point that does not declare ' +
              'indirectCRL is not the list the certificate named', flat.why);
    });
  });
  const impostorOnly = path.join(fx.dir, 'crl-issuers-impostor.pem');
  fs.writeFileSync(impostorOnly, fx.crlIssuerImpostor.pem);
  status.resetCache();
  await withSettings({ 'pki.revocationCheck': 'hard-fail',
                       'pki.revocationCrlIssuersFile': impostorOnly },
                     async function () {
    const onlyImpostor = await status.verdictFor(input(fx.leaf.indirectForged));
    t.check(onlyImpostor.refused &&
            /do not chain to an authority/.test(onlyImpostor.why),
            'and with ONLY the impostor to go on — the right name, cRLSign, ' +
            'listed in the issuers file — no signer is authorised at all, ' +
            'because it does not chain to an authority the leaf\'s own path ' +
            'passes through', onlyImpostor.why);
  });
  log.debug("Leaving theIndirect().");
}

async function theScope(t, fx) {
  log.debug("Entering theScope().");
  t.log.info('=== 11. the issuing distribution point: onlyContainsCACerts, ' +
             'onlyContainsUserCerts, its name, and onlySomeReasons ===');
  const status = require('../common/revocation_status');
  const routes = fx.routes;
  const idp = function (label, lines) {
    log.debug("Entering idp().");
    log.debug("Leaving idp().");
    return ['issuingDistributionPoint=critical,@idp_' + label,
            '[idp_' + label + ']']
      .concat(lines);
  };
  const OTHERS = 'CACompromise,affiliationChanged,superseded,' +
                 'cessationOfOperation,certificateHold,privilegeWithdrawn,' +
                 'AACompromise';
  routes['/s-onlyca.crl'] = { body: opensslCrl(fx, fx.issuing, 's-onlyca', '01',
    [],
    idp('a', ['fullname=URI:' + fx.base + '/s-onlyca.crl', 'onlyCA=TRUE'])) };
  routes['/s-onlyuser.crl'] = { body: opensslCrl(fx, fx.issuing, 's-onlyuser',
    '01', [],
    idp('b',
        ['fullname=URI:' + fx.base + '/s-onlyuser.crl', 'onlyuser=TRUE'])) };
  routes['/s-other.crl'] = { body: opensslCrl(fx, fx.issuing, 's-other', '01',
    [],
    idp('c', ['fullname=URI:' + fx.base + '/somewhere-else.crl'])) };
  routes['/s-key.crl'] = { body: opensslCrl(fx, fx.issuing, 's-key', '01', [],
    idp('d',
        ['fullname=URI:' + fx.base + '/s-key.crl',
         'onlysomereasons=keyCompromise'])) };
  routes['/s-rest.crl'] = { body: opensslCrl(fx, fx.issuing, 's-rest', '01', [],
    idp('e',
        ['fullname=URI:' + fx.base + '/s-rest.crl',
         'onlysomereasons=' + OTHERS])) };
  const input = function (pem) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: pem, chain: chainOf(fx), verified: true };
  };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const onlyCa = await status.verdictFor(input(fx.leaf.scopeOnlyCa.pem));
    t.check(onlyCa.refused && /covers only CA certificates/.test(onlyCa.why),
            'a list with onlyContainsCACerts is not about an end-entity ' +
            'certificate',
            onlyCa.why);
    const onlyUser = await status.verdictFor(input(fx.subCa.pem));
    t.check(onlyUser.refused &&
            /covers only end-entity certificates/.test(onlyUser.why),
            'and one with onlyContainsUserCerts is not about a CA certificate',
            onlyUser.why);
    const otherName = await status.verdictFor(input(
        fx.leaf.scopeOtherName.pem));
    t.check(otherName.refused && /names a different list/.test(otherName.why),
            'a list whose issuing distribution point names ANOTHER list is ' +
            'not the one the certificate pointed at, whoever signed ' +
            'it', otherName.why);
    const partial = await status.verdictFor(input(fx.leaf.scopePartial.pem));
    t.check(partial.refused &&
            partial.unknown.some(function (one) {
              return one.kind === 'incomplete-reasons';
            }),
            'a list covering only keyCompromise (onlySomeReasons) does not ' +
            'make a certificate good — the other reasons are ' +
            'unanswered', partial.why);
    const pointReasons = await status.verdictFor(
        input(fx.leaf.scopePointReasons.pem));
    t.check(pointReasons.refused &&
            pointReasons.unknown.some(function (one) {
              return one.kind === 'incomplete-reasons';
            }),
            'and the same when the DISTRIBUTION POINT names only ' +
            'keyCompromise, over a list that covers ' +
            'everything', pointReasons.why);
    const complete = await status.verdictFor(input(fx.leaf.scopeComplete.pem));
    t.check(complete.status === 'good' && !complete.refused,
            'while two points whose lists cover keyCompromise and every ' +
            'other reason between them answer good', complete.why);
  });
  log.debug("Leaving theScope().");
}

// The OpenSSL half, in its own process.
async function extendedChildBody() {
  log.debug("Entering extendedChildBody().");
  const results = [];
  const t = recordingHarness(results);
  if (!haveOpenSsl()) {
    t.bad('openssl is required for sections 8 to 11 and is not installed',
          'install openssl; these documents must come from an implementation ' +
          'that is not the one under test');
    log.debug("Leaving extendedChildBody().");
    return { results: results };
  }
  const fixture = await crlServer();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-revstat-ossl-'));
  try {
    const fx = await opensslFixture(dir, fixture.base);
    fx.routes = fixture.routes;
    fx.hits = fixture.hits;
    await withSettings({ 'pki.revocationFailureRetryS': 0 }, async function () {
      await theOcsp(t, fx);
      await theDeltas(t, fx);
      await theIndirect(t, fx);
      await theScope(t, fx);
    });
  } finally {
    fixture.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving extendedChildBody().");
  return { results: results };
}

// ===========================================================================
// 12 TO 17. WHAT THE FIRST TWO PASSES LEFT OUT, AGAINST DOCUMENTS OPENSSL
// SIGNED AND A DIRECTORY LDAPJS SERVES.
//
// A delegated responder's own status, a list's signer fetched from the list's
// caIssuers address, ldap and ldaps distribution points (a real in-process
// ldapjs server on ephemeral ports, TLS on one of them), the two delta checks
// no fixture above could reach, and a REGISTERED certificate asked about with
// no chain presented. A fixture of its own rather than more rows in
// `opensslFixture()`: its CA names carry an O so that a name RELATIVE to an
// issuer is a DN a directory can be keyed by, and its certificates name ports
// that only exist once the directory is listening.
// ===========================================================================
async function closingFixture(dir, base, ldapsUrl, ldapUrl) {
  log.debug("Entering closingFixture().");
  const read = function (name) {
    log.debug("Entering read().");
    log.debug("Leaving read().");
    return fs.readFileSync(path.join(dir, name), 'utf8');
  };

  const url = function (route) {
    log.debug("Entering url().");
    log.debug("Leaving url().");
    return base + route;
  };
  const sections = [
    '[req]', 'distinguished_name=dn', 'prompt=no', '[dn]', 'CN=unused',
    '[root_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign,cRLSign', 'subjectKeyIdentifier=hash',
    '[issuing_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign,cRLSign', 'subjectKeyIdentifier=hash',
    'authorityKeyIdentifier=keyid',
    'crlDistributionPoints=URI:' + url('/c-root.crl'),
    'authorityInfoAccess=caIssuers;URI:' + url('/ca/root.cer'),
    '[crl_issuer_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,cRLSign,digitalSignature', 'subjectKeyIdentifier=hash',
    '[impostor_ext]', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,keyCertSign,cRLSign,digitalSignature',
    '[server_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=serverAuth', 'subjectAltName=IP:127.0.0.1',
    '[resp_nocheck_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=OCSPSigning', '1.3.6.1.5.5.7.48.1.5=ASN1:NULL',
    'crlDistributionPoints=URI:' + url('/r-responders.crl'),
    '[resp_revoked_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=OCSPSigning',
    'crlDistributionPoints=URI:' + url('/r-responders.crl'),
    '[resp_unknown_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=OCSPSigning',
    'crlDistributionPoints=URI:' + url('/r-missing.crl'),
    'authorityInfoAccess=OCSP;URI:' + url('/ocsp/self'),
    '[resp_good_ext]', 'basicConstraints=CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=OCSPSigning',
    'crlDistributionPoints=URI:' + url('/r-empty.crl'),
    '[cdp_cai]', 'fullname=URI:' + url('/c-indirect.crl'),
    'CRLissuer=dirName:crl_issuer_dn',
    '[cdp_p7]', 'fullname=URI:' + url('/c-pkcs7.crl'),
    'CRLissuer=dirName:crl_issuer_dn',
    '[cdp_cai2]', 'fullname=URI:' + url('/c-indirect2.crl'),
    'CRLissuer=dirName:crl_issuer_dn',
    '[cdp_imp]', 'fullname=URI:' + url('/c-impostor.crl'),
    'CRLissuer=dirName:crl_issuer_dn',
    '[cdp_ldapcai]', 'fullname=URI:' + url('/c-ldapcai.crl'),
    'CRLissuer=dirName:crl_issuer_dn',
    '[crl_issuer_dn]', 'O=revc', 'CN=revc crl issuer',
    '[cdp_rel]', 'relativename=rel_dn', '[rel_dn]', 'CN=ldaprel',
    '[cdp_relmulti]', 'relativename=relm_dn', '[relm_dn]', 'CN=ldaprel',
    '+OU=second ' +
        'value'
  ];
  // A comma inside a URI: value is openssl's list separator, so the DNs in the
  // LDAP addresses below are percent-encoded, as RFC 4516 allows.
  const LEAVES = [
    // 12. the delegated responder's own status
    ['rNocheck', '6001',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/nocheck')]],
    ['rRevoked', '6002',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/revoked')]],
    ['rUnknown', '6003',
     ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/unknown')]],
    ['rGood', '6004', ['authorityInfoAccess=OCSP;URI:' + url('/ocsp/good')]],
    // 13. the list's signer from its caIssuers address
    ['caiIndirect', '6101', ['crlDistributionPoints=cdp_cai']],
    ['caiPkcs7', '6102', ['crlDistributionPoints=cdp_p7']],
    ['caiSecondList', '6106', ['crlDistributionPoints=cdp_cai2']],
    ['caiImpostor', '6103', ['crlDistributionPoints=cdp_imp']],
    ['caiRollover', '6104',
     ['crlDistributionPoints=URI:' + url('/c-rollover.crl')]],
    ['caiRolloverNoAia', '6105',
     ['crlDistributionPoints=URI:' + url('/c-rollover-noaia.crl')]],
    // 14. ldap and ldaps
    ['lRevoked', '6201',
     ['crlDistributionPoints=URI:' + ldapsUrl + '/cn=ldapcrl%2Co=revc']],
    ['lPlain', '6202',
     ['crlDistributionPoints=URI:' + ldapUrl + '/cn=plaincrl%2Co=revc']],
    ['lReferral', '6203',
     ['crlDistributionPoints=URI:' + ldapsUrl + '/cn=referral%2Co=revc']],
    ['lHuge', '6204',
     ['crlDistributionPoints=URI:' + ldapsUrl + '/cn=huge%2Co=revc']],
    ['lSilent', '6205',
     ['crlDistributionPoints=URI:' + ldapsUrl + '/cn=silent%2Co=revc']],
    ['lCritical', '6206', ['crlDistributionPoints=URI:' + ldapsUrl +
                           '/cn=ldapcrl%2Co=revc????!x-unknown-extension']],
    ['lRelative', '6207', ['crlDistributionPoints=cdp_rel']],
    ['lTwins', '6208',
     ['crlDistributionPoints=URI:' + ldapsUrl + '/cn=twins%2Co=revc']],
    ['lCaIssuers', '6209', ['crlDistributionPoints=cdp_ldapcai']],
    ['lStray', '6210',
     ['crlDistributionPoints=URI:' + ldapsUrl +
      '/cn=ldapcrl%2Co=revc?userPassword']],
    ['lRelativeMulti', '6211', ['crlDistributionPoints=cdp_relmulti']],
    // 15. the two delta checks
    ['dOtherSigner', '6301',
     ['crlDistributionPoints=URI:' + url('/x-base.crl')]],
    ['dNoNumber', '6302', ['crlDistributionPoints=URI:' + url('/x-nonum.crl')]],
    ['dSameSigner', '6303', ['crlDistributionPoints=URI:' + url('/x-ok.crl')]],
    // 17. registered certificates, asked about with nothing presented
    ['gRevokedChain', '6401',
     ['crlDistributionPoints=URI:' + url('/g-revokes.crl')]],
    ['gRevokedAia', '6402',
     ['crlDistributionPoints=URI:' + url('/g-revokes.crl'),
                             'authorityInfoAccess=caIssuers;URI:' +
                             url('/ca/issuing.cer')]],
    ['gGoodAia', '6403', ['crlDistributionPoints=URI:' + url('/r-empty.crl'),
                          'authorityInfoAccess=caIssuers;URI:' +
                          url('/ca/issuing.cer')]],
    ['gNoAia', '6404', ['crlDistributionPoints=URI:' + url('/g-revokes.crl')]],
    ['gDeadAia', '6405', ['crlDistributionPoints=URI:' + url('/g-revokes.crl'),
                          'authorityInfoAccess=caIssuers;URI:' +
                          url('/ca/missing.cer')]],
    ['gWrongAia', '6406', ['crlDistributionPoints=URI:' + url('/g-revokes.crl'),
                           'authorityInfoAccess=caIssuers;URI:' +
                           url('/ca/crlissuer.cer')]]
  ];
  LEAVES.forEach(function (one) {
    sections.push('[' + one[0] + '_ext]', 'basicConstraints=CA:FALSE',
                  'keyUsage=critical,digitalSignature',
                  'extendedKeyUsage=clientAuth');
    one[2].forEach(function (line) { sections.push(line); });
  });
  fs.writeFileSync(path.join(dir, 'ext.cnf'), sections.join('\n') + '\n');

  const key = function (name) {
    log.debug("Entering key().");
    openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt',
             'ec_paramgen_curve:P-256',
             '-out', name + '.key'], dir);
    log.debug("Leaving key().");
  };

  const made = function (name) {
    log.debug("Entering made().");
    log.debug("Leaving made().");
    return { name: name, pem: read(name + '.pem'), key: read(name + '.key'),
             path: path.join(dir, name + '.pem'),
             keyPath: path.join(dir, name + '.key') };
  };

  const selfSigned = function (name, subject, extensions) {
    log.debug("Entering selfSigned().");
    key(name);
    openssl(['req', '-x509', '-new', '-config', 'ext.cnf', '-extensions',
             extensions,
             '-key', name +
                     '.key', '-subj', subject, '-days', '2', '-out',
             name + '.pem'], dir);
    log.debug("Leaving selfSigned().");
    return made(name);
  };

  const issued = function (name, subject, issuer, serial, extensions) {
    log.debug("Entering issued().");
    key(name);
    openssl(['req', '-new', '-config', 'ext.cnf', '-key', name + '.key',
             '-subj', subject,
             '-out', name + '.csr'], dir);
    openssl(['x509', '-req', '-in', name + '.csr', '-CA', issuer + '.pem',
             '-CAkey',
             issuer + '.key', '-set_serial', '0x' +
                                             serial, '-days', '2', '-extfile',
             'ext.cnf', '-extensions', extensions, '-out', name + '.pem'], dir);
    log.debug("Leaving issued().");
    return Object.assign(made(name), { serial: serial });
  };
  const fx = { dir: dir, base: base };
  fx.root = selfSigned('root', '/O=revc/CN=revc root', 'root_ext');
  fx.issuing = issued('issuing', '/O=revc/CN=revc issuing', 'root', '0100',
                      'issuing_ext');
  // THE SAME NAME, ANOTHER KEY, THE SAME ROOT: an issuer's rollover key, which
  // may sign its lists and never appears in a chain a client presents.
  fx.issuingNew = issued('issuing-new', '/O=revc/CN=revc issuing', 'root',
                         '0101', 'issuing_ext');
  fx.crlIssuer = issued('crlissuer', '/O=revc/CN=revc crl issuer', 'root',
                        '0300',
                        'crl_issuer_ext');
  fx.crlIssuerTwin = issued('crlissuer-twin', '/O=revc/CN=revc crl issuer',
                            'root', '0301',
                            'crl_issuer_ext');
  fx.crlIssuerImpostor = selfSigned('crlissuer-impostor', '/O=revc/CN=revc ' +
      'crl issuer',
                                    'impostor_ext');
  fx.server = issued('server', '/O=revc/CN=127.0.0.1', 'root', '0500',
                     'server_ext');
  fx.respNocheck = issued('resp-nocheck', '/O=revc/CN=revc responder nocheck',
                          'issuing',
                          '0200', 'resp_nocheck_ext');
  fx.respRevoked = issued('resp-revoked', '/O=revc/CN=revc responder revoked',
                          'issuing',
                          '0201', 'resp_revoked_ext');
  fx.respUnknown = issued('resp-unknown', '/O=revc/CN=revc responder unknown',
                          'issuing',
                          '0202', 'resp_unknown_ext');
  fx.respGood = issued('resp-good', '/O=revc/CN=revc responder good', 'issuing',
                       '0203',
                       'resp_good_ext');
  fx.leaf = {};
  LEAVES.forEach(function (one) {
    fx.leaf[one[0]] = issued('leaf-' + one[0], '/O=revc/CN=revc ' + one[0],
                             'issuing',
                             one[1], one[0] + '_ext');
  });
  const derOf = function (cert) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return new nodeCrypto.X509Certificate(cert.pem).raw;
  };
  fx.der = { root: derOf(fx.root), issuing: derOf(fx.issuing),
             issuingNew: derOf(fx.issuingNew), crlIssuer: derOf(fx.crlIssuer),
             crlIssuerTwin: derOf(fx.crlIssuerTwin),
             impostor: derOf(fx.crlIssuerImpostor) };
  openssl(['crl2pkcs7', '-nocrl', '-certfile', fx.crlIssuer.path, '-outform',
           'DER',
           '-out', 'crlissuer.p7c'], dir);
  fx.p7c = fs.readFileSync(path.join(dir, 'crlissuer.p7c'));
  log.debug("Leaving closingFixture().");
  return fx;
}

// A DIRECTORY this file controls, on an ephemeral port — TLS when a certificate
// is given — answering base-object searches under o=revc from a table: an
// attribute set, two entries, a referral, or nothing ever. Hits per DN.
function ldapDirectory(tlsMaterial, port) {
  log.debug("Entering ldapDirectory().");
  const ldap = require('ldapjs');
  const entries = {};
  const hits = {};
  const server = tlsMaterial
    ? ldap.createServer({ certificate: tlsMaterial.pem, key: tlsMaterial.key })
    : ldap.createServer();
  const keyOf = function (dn) {
    log.debug("Entering keyOf().");
    log.debug("Leaving keyOf().");
    return String(dn).toLowerCase().replace(/\s+/g, '');
  };

  const answer = function (req, res, next) {
    log.debug("Entering answer().");
    const key = keyOf(req.dn.toString());
    hits[key] = (hits[key] || 0) + 1;
    const entry = entries[key];
    if (!entry) {
      log.debug("Leaving answer().");
      return next(new ldap.NoSuchObjectError(req.dn.toString()));
    }
    if (entry.silent) {
      log.debug("Leaving answer().");
      // Never answered: the client's own deadline is what ends it.
      return undefined;
    }
    if (entry.referral) {
      res.send(res.createSearchReference(['ldaps://elsewhere.example/cn=x,' +
                                          'o=revc']));
      res.end();
      log.debug("Leaving answer().");
      return next();
    }
    // Every attribute is sent whatever was asked for: ldapjs's own server-side
    // filtering drops a requested `;binary` type it should have matched, and
    // what is under test is the client's reading, not that filter.
    res.attributes = [];
    (entry.many || [entry.attributes]).forEach(function (attributes) {
      res.send({ dn: req.dn.toString(), attributes: attributes });
    });
    res.end();
    log.debug("Leaving answer().");
    return next();
  };
  // Both spellings of the suffix: ldapjs routes by a case-sensitive attribute
  // type, and a DN built from a certificate's names is written `O=revc`.
  server.search('o=revc', answer);
  server.search('O=revc', answer);
  log.debug("Leaving ldapDirectory().");
  return new Promise(function (resolve) {
    server.listen(port || 0, '127.0.0.1', function () {
      resolve({ server: server, port: server.address().port, entries: entries,
                hits: hits,
                keyOf: keyOf });
    });
  });
}

async function theResponderStatus(t, fx) {
  log.debug("Entering theResponderStatus().");
  t.log.info('=== 12. a delegated OCSP responder\'s OWN status: nocheck, ' +
             'revoked, unknown and good, and never asked through OCSP ===');
  const status = require('../common/revocation_status');
  const routes = fx.routes;
  const hits = fx.hits;
  const index = path.join(fx.dir, 'ocsp-index-12.txt');
  fs.writeFileSync(index,
                   [indexLine('6001'), indexLine('6002'), indexLine('6003'),
                           indexLine('6004')].join(''));
  const responder = function (signer) {
    log.debug("Entering responder().");
    log.debug("Leaving responder().");
    return { ocsp: { dir: fx.dir, index: index, ca: fx.issuing.path,
                     signer: signer.path, key: signer.keyPath } };
  };
  routes['/ocsp/nocheck'] = responder(fx.respNocheck);
  routes['/ocsp/revoked'] = responder(fx.respRevoked);
  routes['/ocsp/unknown'] = responder(fx.respUnknown);
  routes['/ocsp/good'] = responder(fx.respGood);
  routes['/ocsp/self'] = responder(fx.respUnknown);
  routes['/r-responders.crl'] = { body: opensslCrl(fx, fx.issuing,
    'r-responders', '01',
    [indexLine('0200', 'keyCompromise'), indexLine('0201', 'keyCompromise')]) };
  routes['/r-empty.crl'] = { body: opensslCrl(fx, fx.issuing, 'r-empty', '01',
                                              []) };
  const input = function (leaf) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: [fx.issuing.pem, fx.root.pem],
             verified: true };
  };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const nocheck = await status.verdictFor(input(fx.leaf.rNocheck));
    t.check(nocheck.status === 'good' &&
            nocheck.links[0].ocspResponderStatus === 'not-checked' &&
            /id-pkix-ocsp-nocheck/.test(nocheck.links[0].why),
            'A RESPONDER CARRYING id-pkix-ocsp-nocheck IS NOT CHECKED, AND ' +
            'SAYS SO — even though the CRL its certificate names lists it: ' +
            'the issuer that put the extension there decided its revocation ' +
            'is not a question',
            JSON.stringify(nocheck.links[0]));
    t.check(!hits['/r-responders.crl'],
            'and that CRL was not fetched at all',
            JSON.stringify(hits['/r-responders.crl']));
    const good = await status.verdictFor(input(fx.leaf.rGood));
    t.check(good.status === 'good' &&
            good.links[0].ocspResponderStatus === 'good',
            'a responder whose own CRL does not list it is GOOD, and its ' +
            'answer is used',
            JSON.stringify(good.links[0]));
    const revoked = await status.verdictFor(input(fx.leaf.rRevoked));
    t.check(revoked.status !== 'good' && revoked.refused &&
            /itself REVOKED/.test(revoked.why),
            'A REVOKED RESPONDER\'S ANSWERS ARE UNUSABLE: its signed "good" ' +
            'is not believed, and with nothing else to go on hard-fail ' +
            'refuses', revoked.why);
    t.check(hits['/r-responders.crl'] > 0,
            'having fetched the responder\'s own CRL to find that out',
            JSON.stringify(hits['/r-responders.crl']));
    const unknown = await status.verdictFor(input(fx.leaf.rUnknown));
    t.check(unknown.refused && /could not be established/.test(unknown.why),
            'A RESPONDER WHOSE OWN STATUS IS UNKNOWN — its CRL is a 404 — IS ' +
            'NOT BELIEVED UNDER HARD-FAIL: the fetch an attacker blocks must ' +
            'not become the way a compromised responder is ' +
            'trusted', unknown.why);
    t.check(!hits['/ocsp/self'],
            'AND ITS STATUS IS NEVER ASKED THROUGH OCSP — its own ' +
            'certificate names a responder, and that responder is not dialled',
            JSON.stringify(hits['/ocsp/self']));
  });
  await withSettings({ 'pki.revocationCheck': 'soft-fail' }, async function () {
    const revoked = await status.verdictFor(input(fx.leaf.rRevoked));
    t.check(revoked.status !== 'good' && /itself REVOKED/.test(revoked.why),
            'a revoked responder is unusable under SOFT-FAIL too — a signed ' +
            'fact is not a status that could not be established', revoked.why);
    const unknown = await status.verdictFor(input(fx.leaf.rUnknown));
    t.check(unknown.status === 'good' && !unknown.refused &&
            unknown.links[0].ocspResponderStatus === 'unknown',
            'while soft-fail believes a responder whose status is unknown, ' +
            'and records that it did', JSON.stringify(unknown.links[0]));
  });
  log.debug("Leaving theResponderStatus().");
}

async function theCaIssuers(t, fx) {
  log.debug("Entering theCaIssuers().");
  t.log.info('=== 13. a list\'s signer fetched from its own caIssuers ' +
             'address: DER, PKCS#7, an impostor, and an issuer\'s rollover ' +
             'key ===');
  const status = require('../common/revocation_status');
  const routes = fx.routes;
  const hits = fx.hits;
  routes['/ca/crlissuer.cer'] = { body: fx.der.crlIssuer,
                                  contentType: 'application/pkix-cert' };
  routes['/ca/crlissuer.p7c'] = { body: fx.p7c,
                                  contentType: 'application/pkcs7-mime' };
  routes['/ca/impostor.cer'] = { body: fx.der.impostor,
                                 contentType: 'application/pkix-cert' };
  routes['/ca/issuing-new.cer'] = { body: fx.der.issuingNew,
                                    contentType: 'application/pkix-cert' };
  routes['/c-indirect.crl'] = { body: await indirectCrl(fx.crlIssuer, {
    url: fx.base + '/c-indirect.crl',
    caIssuers: [fx.base + '/ca/crlissuer.cer'],
    entries: [{ serial: '6101', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/c-indirect2.crl'] = { body: await indirectCrl(fx.crlIssuer, {
    url: fx.base + '/c-indirect2.crl',
    caIssuers: [fx.base + '/ca/crlissuer.cer'],
    entries: [{ serial: '6106', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/c-pkcs7.crl'] = { body: await indirectCrl(fx.crlIssuer, {
    url: fx.base + '/c-pkcs7.crl', caIssuers: [fx.base + '/ca/crlissuer.p7c'],
    entries: [{ serial: '6102', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/c-impostor.crl'] = { body: await indirectCrl(fx.crlIssuerImpostor, {
    url: fx.base + '/c-impostor.crl', caIssuers: [fx.base + '/ca/impostor.cer'],
    entries: [{ serial: '6103', certificateIssuerPem: fx.issuing.pem }] }) };
  routes['/c-rollover.crl'] = { body: opensslCrl(fx, fx.issuingNew,
    'c-rollover', '01',
    [indexLine('6104', 'keyCompromise')],
    ['authorityInfoAccess=caIssuers;URI:' + fx.base + '/ca/issuing-new.cer']) };
  routes['/c-rollover-noaia.crl'] = { body: opensslCrl(fx, fx.issuingNew,
    'c-rollover-noaia',
    '01', [indexLine('6105', 'keyCompromise')]) };
  const input = function (leaf) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: [fx.issuing.pem, fx.root.pem],
             verified: true };
  };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const der = await status.verdictFor(input(fx.leaf.caiIndirect));
    t.check(der.status === 'revoked' && der.links[0].indirect === true &&
            hits['/ca/crlissuer.cer'] > 0,
            'AN INDIRECT CRL WHOSE SIGNER IS NOWHERE HERE IS TRUSTED THROUGH ' +
            'THE caIssuers ADDRESS THE LIST ITSELF NAMES: the DER ' +
            'certificate there carries the name, cRLSign, chains to the ' +
            'leaf\'s Root, and revokes the leaf',
            der.why);
    const again = await status.verdictFor(input(fx.leaf.caiSecondList));
    t.check(again.status === 'revoked' && hits['/c-indirect2.crl'] === 1 &&
            hits['/ca/crlissuer.cer'] === 1,
            'and the fetched certificate is cached — a SECOND list naming ' +
            'the same caIssuers address is verified without that address ' +
            'being fetched again',
            JSON.stringify([hits['/c-indirect2.crl'],
                            hits['/ca/crlissuer.cer']]));
    const pkcs7 = await status.verdictFor(input(fx.leaf.caiPkcs7));
    t.check(pkcs7.status === 'revoked' && hits['/ca/crlissuer.p7c'] > 0,
            'and the same from a PKCS#7 certs-only bundle, the other form ' +
            'RFC 5280 section 4.2.2.1 names', pkcs7.why);
    const impostor = await status.verdictFor(input(fx.leaf.caiImpostor));
    t.check(impostor.refused && impostor.status === 'unknown' &&
            /caIssuers/.test(impostor.why),
            'A caIssuers ADDRESS SERVING AN IMPOSTOR — the right name, ' +
            'self-signed, signing the very list that points at it — is not ' +
            'believed: it chains to nothing the leaf\'s path passes ' +
            'through', impostor.why);
    const rollover = await status.verdictFor(input(fx.leaf.caiRollover));
    t.check(rollover.status === 'revoked' && hits['/ca/issuing-new.cer'] > 0,
            'A DIRECT LIST SIGNED WITH THE ISSUER\'S ROLLOVER KEY — the same ' +
            'name, a different key, the same Root — is verified through the ' +
            'certificate its caIssuers address serves, and revokes the ' +
            'leaf', rollover.why);
    const noAia = await status.verdictFor(input(fx.leaf.caiRolloverNoAia));
    t.check(noAia.refused && noAia.status === 'unknown' &&
            /names no caIssuers address/.test(noAia.why),
            'while the same list naming no caIssuers address cannot be ' +
            'verified, and says why', noAia.why);
  });
  log.debug("Leaving theCaIssuers().");
}

async function theLdap(t, fx, ldaps, plain) {
  log.debug("Entering theLdap().");
  t.log.info('=== 14. ldap and ldaps distribution points, against a real ' +
             'directory ===');
  const status = require('../common/revocation_status');
  const lcrl = opensslCrl(fx, fx.issuing, 'l-crl', '01',
    ['6201', '6202', '6203', '6204', '6205', '6206', '6207', '6208'].map(
        function (one) {
      return indexLine(one, 'keyCompromise');
    }));
  const lcrlDer = Buffer.from(String(lcrl).replace(/-----[^-]+-----/g, '')
                                          .replace(/\s+/g, ''),
                              'base64');
  const crlEntry = { attributes: { objectClass: 'cRLDistributionPoint',
                                   'certificateRevocationList;binary':
                                     lcrlDer } };
  ldaps.entries[ldaps.keyOf('cn=ldapcrl,o=revc')] = crlEntry;
  plain.entries[plain.keyOf('cn=plaincrl,o=revc')] = crlEntry;
  ldaps.entries[ldaps.keyOf('cn=referral,o=revc')] = { referral: true };
  ldaps.entries[ldaps.keyOf('cn=huge,o=revc')] = { attributes: {
    'certificateRevocationList;binary': nodeCrypto.randomBytes(64 * 1024) } };
  ldaps.entries[ldaps.keyOf('cn=silent,o=revc')] = { silent: true };
  ldaps.entries[ldaps.keyOf('cn=twins,o=revc')] = { many: [crlEntry.attributes,
                                                           crlEntry.attributes] };
  ldaps.entries[ldaps.keyOf('CN=ldaprel,CN=revc issuing,O=revc')] = crlEntry;
  ldaps.entries[ldaps.keyOf('cn=crlissuerldap,o=revc')] = { attributes: {
    'cACertificate;binary': fx.der.crlIssuerTwin } };
  fx.routes['/c-ldapcai.crl'] = { body: await indirectCrl(fx.crlIssuerTwin, {
    url: fx.base + '/c-ldapcai.crl',
    caIssuers: ['ldaps://127.0.0.1:' + ldaps.port +
                '/cn=crlissuerldap,o=revc?cACertificate;binary'],
    entries: [{ serial: '6209', certificateIssuerPem: fx.issuing.pem }] }) };
  const caFile = path.join(fx.dir, 'ldap-ca.pem');
  fs.writeFileSync(caFile, fx.root.pem);
  const input = function (leaf) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: [fx.issuing.pem, fx.root.pem],
             verified: true };
  };

  const hitsOf = function (dir, dn) {
    log.debug("Entering hitsOf().");
    log.debug("Leaving hitsOf().");
    return dir.hits[dir.keyOf(dn)] || 0;
  };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    status.resetCache();
    const noCa = await status.verdictFor(input(fx.leaf.lRevoked));
    t.check(noCa.refused && noCa.status === 'unknown' &&
            /connection failed/.test(noCa.why),
            'LDAPS VERIFIES THE DIRECTORY: with the directory\'s CA in ' +
            'neither node\'s store nor pki.revocationLdapCaFile, the TLS ' +
            'handshake fails and hard-fail refuses', noCa.why);
    await withSettings({ 'pki.revocationLdapCaFile': caFile },
                       async function () {
      status.resetCache();
      const revoked = await status.verdictFor(input(fx.leaf.lRevoked));
      t.check(revoked.status === 'revoked' &&
              hitsOf(ldaps, 'cn=ldapcrl,o=revc') > 0,
              'AN ldaps: DISTRIBUTION POINT IS FETCHED — ' +
              'certificateRevocationList;binary out of a base-object search ' +
              'on a directory whose certificate chains to ' +
              'pki.revocationLdapCaFile — and the list revokes the ' +
              'leaf', revoked.why);
      const plainDefault = await status.verdictFor(input(fx.leaf.lPlain));
      t.check(!plainDefault.refused && plainDefault.status === 'unknown' &&
              /plain ldap/.test(plainDefault.why) &&
              hitsOf(plain, 'cn=plaincrl,o=revc') === 0,
              'A PLAIN ldap: ADDRESS IS NOT DIALLED BY DEFAULT, and the ' +
              'certificate is answered as naming nothing this service dials ' +
              '— no fetch was blocked, so hard-fail does not refuse ' +
              'it', plainDefault.why);
      await withSettings({ 'pki.revocationLdap': 'ldaps-and-ldap' },
                         async function () {
        const plainOn = await status.verdictFor(input(fx.leaf.lPlain));
        t.check(plainOn.status === 'revoked' &&
                hitsOf(plain, 'cn=plaincrl,o=revc') > 0,
                'while pki.revocationLdap=ldaps-and-ldap dials it and the ' +
                'list revokes',
                plainOn.why);
      });
      await withSettings({ 'pki.revocationLdap': 'off' }, async function () {
        status.resetCache();
        const before = hitsOf(ldaps, 'cn=ldapcrl,o=revc');
        const off = await status.verdictFor(input(fx.leaf.lRevoked));
        t.check(!off.refused && off.status === 'unknown' &&
                hitsOf(ldaps, 'cn=ldapcrl,o=revc') === before,
                'and pki.revocationLdap=off dials neither', off.why);
      });
      const referral = await status.verdictFor(input(fx.leaf.lReferral));
      t.check(referral.refused && /referral is not followed/.test(referral.why),
              'A REFERRAL IS NOT FOLLOWED — the address the issuer signed is ' +
              'the only one',
              referral.why);
      const twins = await status.verdictFor(input(fx.leaf.lTwins));
      t.check(twins.refused && /2 entries where one was named/.test(twins.why),
              'and a directory answering a base-object search with two ' +
              'entries is not believed about either', twins.why);
      const critical = await status.verdictFor(input(fx.leaf.lCritical));
      t.check(!critical.refused && /critical extension/.test(critical.why),
              'AN LDAP URL CARRYING A CRITICAL EXTENSION IS NOT DIALLED (RFC ' +
              '4516 section 2.1), and is reported as such', critical.why);
      await withSettings({ 'pki.revocationMaxCrlBytes': 4096 },
                         async function () {
        const huge = await status.verdictFor(input(fx.leaf.lHuge));
        t.check(huge.refused && /more than 4096 bytes/.test(huge.why),
                'THE SIZE CAP HOLDS OVER LDAP: the connection\'s bytes are ' +
                'counted as they arrive and the socket destroyed at ' +
                'pki.revocationMaxCrlBytes', huge.why);
      });
      await withSettings({ 'pki.revocationFetchTimeoutMs': 400 },
                         async function () {
        const started = Date.now();
        const silent = await status.verdictFor(input(fx.leaf.lSilent));
        t.check(silent.refused &&
                /did not answer within 400ms/.test(silent.why) &&
                Date.now() - started < 3000,
                'AND SO DOES THE DEADLINE: a directory that never answers ' +
                'the search is given up on at ' +
                'pki.revocationFetchTimeoutMs', silent.why);
      });
      const relativeNone = await status.verdictFor(input(fx.leaf.lRelative));
      t.check(!relativeNone.refused &&
              /pki\.revocationLdapDirectory names none/.test(relativeNone.why),
              'A NAME RELATIVE TO ITS CRL ISSUER, WITH NO DIRECTORY ' +
              'CONFIGURED, IS REFUSED BY NAME — the certificate does not say ' +
              'which directory, and a guess is a request to a host nobody ' +
              'signed', relativeNone.why);
      await withSettings({ 'pki.revocationLdapDirectory': 'ldaps://127.0.0.1:' +
          ldaps.port },
        async function () {
          status.resetCache();
          const relative = await status.verdictFor(input(fx.leaf.lRelative));
          t.check(relative.status === 'revoked' &&
                  hitsOf(ldaps, 'CN=ldaprel,CN=revc issuing,O=revc') > 0,
                  'while with pki.revocationLdapDirectory set, the relative ' +
                  'name is joined to the issuer\'s — "CN=ldaprel,CN=revc ' +
                  'issuing,O=revc" — looked up there, and the list ' +
                  'revokes', relative.why);
        });
      const stray = await status.verdictFor(input(fx.leaf.lStray));
      t.check(stray.refused && /userPassword/.test(stray.why) &&
              /not an attribute a revocation list is kept in/.test(stray.why),
              'AN LDAP URL NAMING SOME OTHER ATTRIBUTE IS NOT READ — a ' +
              'distribution point is not a way to have this service fetch ' +
              'userPassword', stray.why);
      const multi = await status.verdictFor(input(fx.leaf.lRelativeMulti));
      t.check(!multi.refused && /multi-valued RDN/.test(multi.why),
              'A RELATIVE NAME THAT IS A MULTI-VALUED RDN IS REFUSED BY NAME ' +
              '— it has no one string a directory is sure to index it ' +
              'under', multi.why);
      await withSettings({ 'pki.revocationLdapDirectory':
                             'ldaps://127.0.0.1:1/extra' },
        async function () {
          const malformed = await status.verdictFor(input(fx.leaf.lRelative));
          t.check(!malformed.refused &&
                  /not an ldap:\/\/ or ldaps:\/\/ address/.test(malformed.why),
                  'and a directory setting with anything after the host is ' +
                  'refused rather than having a DN appended to ' +
                  'it', malformed.why);
        });
      const parsed = [status.parseLdapUrl('ldap:///cn=x'),
                      status.parseLdapUrl('ldaps://h/cn=x??one'),
                      status.parseLdapUrl('ldaps://h/cn=x????!bindname=cn%3Dy'),
                      status.parseLdapUrl('ldaps://h:1636/cn=a%2Co=b?cACertificate;' +
                                          'binary')];
      t.check(!parsed[0].ok && /names no host/.test(parsed[0].why) &&
              !parsed[1].ok && /base-object/.test(parsed[1].why) &&
              !parsed[2].ok && /critical extension/.test(parsed[2].why) &&
              parsed[3].ok && parsed[3].port === 1636 &&
              parsed[3].dn === 'cn=a,o=b' &&
              parsed[3].attributes[0] === 'cACertificate;binary',
              'RFC 4516, READ STRICTLY: no host is refused, a scope other ' +
              'than base is refused, a critical extension (!bindname) is ' +
              'refused, and a percent-encoded DN, a port and an attribute ' +
              'are read', JSON.stringify(parsed));
      const ldapCai = await status.verdictFor(input(fx.leaf.lCaIssuers));
      t.check(ldapCai.status === 'revoked' &&
              hitsOf(ldaps, 'cn=crlissuerldap,o=revc') > 0,
              'AND A caIssuers ADDRESS IN ldaps: — cACertificate;binary — ' +
              'supplies an indirect list\'s signer the same way http ' +
              'does', ldapCai.why);
    });
  });
  log.debug("Leaving theLdap().");
}

async function theDeltaSigners(t, fx) {
  log.debug("Entering theDeltaSigners().");
  t.log.info('=== 15. the two delta checks no earlier fixture reached: a ' +
             'delta signed by another authorised key, and a base with no ' +
             'cRLNumber ===');
  const status = require('../common/revocation_status');
  const routes = fx.routes;
  routes['/x-base.crl'] = { body: opensslCrl(fx, fx.issuing, 'x-base', '10', [],
    ['freshestCRL=URI:' + fx.base + '/x-delta.crl']) };
  routes['/x-delta.crl'] = { body: opensslCrl(fx, fx.issuingNew, 'x-delta',
    '11',
    [indexLine('6301', 'keyCompromise')],
    ['2.5.29.27=critical,ASN1:INTEGER:16',
     'authorityInfoAccess=caIssuers;URI:' + fx.base + '/ca/issuing-new.cer']) };
  routes['/x-nonum.crl'] = { body: opensslCrl(fx, fx.issuing, 'x-nonum', null,
    [],
    ['freshestCRL=URI:' + fx.base + '/x-nonum-delta.crl']) };
  routes['/x-nonum-delta.crl'] = { body: opensslCrl(fx, fx.issuing,
    'x-nonum-delta', '02',
    [indexLine('6302',
               'keyCompromise')], ['2.5.29.27=critical,ASN1:INTEGER:1']) };
  routes['/x-ok.crl'] = { body: opensslCrl(fx, fx.issuing, 'x-ok', '20', [],
    ['freshestCRL=URI:' + fx.base + '/x-ok-delta.crl']) };
  routes['/x-ok-delta.crl'] = { body: opensslCrl(fx, fx.issuing, 'x-ok-delta',
    '21',
    [indexLine('6303',
               'keyCompromise')], ['2.5.29.27=critical,ASN1:INTEGER:32']) };
  const openSslText = String(childProcess.spawnSync('openssl', ['crl', '-in',
    path.join(fx.dir, 'crl-x-nonum', 'crl.pem'), '-noout', '-text'],
                                                    { encoding:
                                                        'utf8' }).stdout);
  t.check(/Freshest CRL/.test(openSslText) && !/CRL Number/.test(openSslText),
          'the base list OpenSSL wrote carries a freshestCRL and NO ' +
          'cRLNumber, which is the fixture the base-number check ' +
          'needed', openSslText.slice(0, 300));
  const input = function (leaf) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: leaf.pem, chain: [fx.issuing.pem, fx.root.pem],
             verified: true };
  };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const same = await status.verdictFor(input(fx.leaf.dSameSigner));
    t.check(same.status === 'revoked' &&
            /with its delta at/.test(same.links[0].why),
            'the control: a base and a delta from the same issuer and key ' +
            'merge, and the delta revokes', same.links[0].why);
    const other = await status.verdictFor(input(fx.leaf.dOtherSigner));
    t.check(other.refused && other.status === 'unknown' &&
            /issued or signed by somebody other/.test(other.why),
            'A DELTA SIGNED BY ANOTHER AUTHORISED KEY THAN ITS BASE — the ' +
            'issuer\'s own rollover key, verified through its caIssuers ' +
            'address — is not merged: a delta updates the list its own ' +
            'signer wrote', other.why);
    const noNumber = await status.verdictFor(input(fx.leaf.dNoNumber));
    t.check(noNumber.refused && noNumber.status === 'unknown' &&
            /carries no cRLNumber/.test(noNumber.why),
            'AND A BASE CRL WITH NO cRLNumber CANNOT HAVE A DELTA APPLIED — ' +
            'there is nothing to check the delta\'s BaseCRLNumber ' +
            'against', noNumber.why);
  });
  log.debug("Leaving theDeltaSigners().");
}

async function theRegisteredApi(t, fx) {
  log.debug("Entering theRegisteredApi().");
  t.log.info('=== 17. a REGISTERED certificate: nothing presented, its ' +
             'issuer fetched from its caIssuers address, and a bare key ' +
             'reported as one ===');
  const status = require('../common/revocation_status');
  const errorCodes = require('../common/error_codes');
  const routes = fx.routes;
  const hits = fx.hits;
  routes['/ca/root.cer'] = { body: fx.der.root,
                             contentType: 'application/pkix-cert' };
  routes['/ca/issuing.cer'] = { body: fx.der.issuing,
                                contentType: 'application/pkix-cert' };
  routes['/g-revokes.crl'] = { body: opensslCrl(fx, fx.issuing, 'g-revokes',
    '01',
    ['6401', '6402', '6404', '6405', '6406'].map(function (one) {
      return indexLine(one, 'keyCompromise');
    })) };
  await withSettings({ 'pki.revocationCheck': 'hard-fail' }, async function () {
    const withChain = await status.registeredVerdictFor({
      certificate: fx.leaf.gRevokedChain.pem,
      chain: [fx.issuing.pem, fx.root.pem],
      source: 'a test registration' });
    t.check(withChain.refused && withChain.status === 'revoked' &&
            withChain.registered === true,
            'a registered certificate registered WITH its chain is looked up ' +
            'on the CRL it names, and a revoked one is refused', withChain.why);
    t.equal(errorCodes.codeOf(withChain), 'STS-PKI-0129',
            'carrying STS-PKI-0129 — the REGISTERED code, not the presented ' +
            'one');
    const alone = await status.registeredVerdictFor({
      certificate: String(fx.leaf.gRevokedAia.pem).replace(/-----[^-]+-----/g,
                                                           '')
        .replace(/\s+/g, ''), source: 'base64 DER, as fedSigningCertificate ' +
                                      'holds it' });
    t.check(alone.status === 'revoked' && hits['/ca/issuing.cer'] > 0 &&
            (alone.issuersFetched || []).length === 2,
            'A REGISTERED LEAF WITH NOTHING BESIDE IT: its issuer is fetched ' +
            'from its own caIssuers address, and that issuer\'s from its — ' +
            'up to a self-signed Root — and the CRL revokes ' +
            'it', JSON.stringify(alone.issuersFetched) + ' ' + alone.why);
    const good = await status.registeredVerdictFor(
        { certificate: fx.leaf.gGoodAia.pem,
                                                      source: 'a test ' +
                                                        'registration' });
    t.check(good.status === 'good' && !good.refused,
            'while a good one built the same way is good at every link',
            good.why);
    const noAia = await status.registeredVerdictFor(
        { certificate: fx.leaf.gNoAia.pem,
                                                       source: 'a test ' +
                                                        'registration' });
    t.check(!noAia.refused && noAia.status === 'unknown' &&
            noAia.unknown.some(function (one) {
              return one.kind === 'no-distribution-point';
            }),
            'A REGISTERED LEAF WHOSE ISSUER IS NOWHERE AND WHICH NAMES NO ' +
            'caIssuers ADDRESS gives an attacker nothing to block, so ' +
            'hard-fail does not refuse it',
            noAia.why);
    await withSettings({ 'pki.revocationRequireDistributionPoint': true },
                       async function () {
      const required = await status.registeredVerdictFor(
          { certificate: fx.leaf.gNoAia.pem,
                                                            source: 'a test ' +
                                                        'registration' });
      t.check(required.refused,
              'unless pki.revocationRequireDistributionPoint says it must',
              required.why);
    });
    const dead = await status.registeredVerdictFor(
        { certificate: fx.leaf.gDeadAia.pem,
                                                      source: 'a test ' +
                                                        'registration' });
    t.check(dead.refused && dead.unknown.some(function (one) {
              return one.kind === 'issuer-not-fetched';
            }),
            'WHILE ONE NAMING A caIssuers ADDRESS THAT DID NOT ANSWER IS ' +
            'REFUSED — that is the fetch an attacker blocks', dead.why);
    const wrong = await status.registeredVerdictFor(
        { certificate: fx.leaf.gWrongAia.pem,
                                                       source: 'a test ' +
                                                        'registration' });
    t.check(wrong.refused && wrong.unknown.some(function (one) {
              return one.kind === 'issuer-not-fetched';
            }) && /none of the 1 certificate/.test(wrong.why),
            'and so is one whose caIssuers address serves a certificate that ' +
            'did not sign it — what is fetched is believed only for its key ' +
            'verifying the one below',
            wrong.why);
    const bare = await status.registeredKeyVerdictFor(
        { kty: 'EC', crv: 'P-256', kid: 'k1',
      x: 'AAAA', y: 'AAAA' }, 'a bare JWK');
    t.check(bare.bare === true && bare.status === 'unchecked' &&
            !bare.refused &&
            /bare key/.test(bare.why),
            'A BARE JWK — no x5c — IS REPORTED AS NOTHING TO CHECK, never as ' +
            'good', bare.why);
    const x5c = await status.registeredKeyVerdictFor({ kty: 'EC', kid: 'k2',
      x5c: [String(fx.leaf.gRevokedChain.pem).replace(/-----[^-]+-----/g, '')
                                             .replace(/\s+/g, ''),
            String(fx.issuing.pem).replace(/-----[^-]+-----/g, '')
                                  .replace(/\s+/g, '')] },
      'a JWK with an x5c');
    t.check(x5c.refused && x5c.status === 'revoked',
            'while a JWK carrying an x5c is answered through that certificate',
            x5c.why);
  });
  await withSettings({ 'pki.revocationCheck': 'off' }, async function () {
    status.resetCache();
    const before = hits['/ca/issuing.cer'] || 0;
    const off = await status.registeredVerdictFor(
        { certificate: fx.leaf.gRevokedAia.pem,
                                                     source: 'a test ' +
                                                        'registration' });
    t.check(!off.refused && off.status === 'unchecked' &&
            (hits['/ca/issuing.cer'] || 0) === before,
            'and pki.revocationCheck=off consults nothing for a registered ' +
            'one either — not even its caIssuers address is fetched', off.why);
  });
  log.debug("Leaving theRegisteredApi().");
}

// The closing half, in its own process: OpenSSL documents, an http fixture and
// two directories.
async function closingChildBody() {
  log.debug("Entering closingChildBody().");
  const results = [];
  const t = recordingHarness(results);
  if (!haveOpenSsl()) {
    t.bad('openssl is required for sections 12 to 17 and is not installed',
          'install openssl; these documents must come from an implementation ' +
          'that is not the one under test');
    log.debug("Leaving closingChildBody().");
    return { results: results };
  }
  const fixture = await crlServer();
  const plain = await ldapDirectory(null);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-revstat-close-'));
  let ldaps = null;
  try {
    // The directory's certificate has to exist before it listens, and the
    // leaves have to name its port — so a throwaway socket reserves one.
    const ldapsPort = await new Promise(function (resolve) {
      const probe = require('net').createServer();
      probe.listen(0, '127.0.0.1', function () {
        const port = probe.address().port;
        probe.close(function () { resolve(port); });
      });
    });
    const fx = await closingFixture(dir, fixture.base,
                                    'ldaps://127.0.0.1:' + ldapsPort,
                                    'ldap://127.0.0.1:' + plain.port);
    fx.routes = fixture.routes;
    fx.hits = fixture.hits;
    fx.routes['/c-root.crl'] = { body: opensslCrl(fx, fx.root, 'c-root', '01',
                                                  []) };
    ldaps = await ldapDirectory({ pem: fx.server.pem, key: fx.server.key },
                                ldapsPort);
    await withSettings({ 'pki.revocationFailureRetryS': 0 }, async function () {
      await theResponderStatus(t, fx);
      await theCaIssuers(t, fx);
      await theLdap(t, fx, ldaps, plain);
      await theDeltaSigners(t, fx);
      await theRegisteredApi(t, fx);
    });
  } finally {
    fixture.server.close();
    plain.server.close();
    if (ldaps) {
      ldaps.server.close();
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving closingChildBody().");
  return { results: results };
}

// A compact JWS, signed here with node's own primitives so that no verifier
// under test also produced what it verifies.
function signCompact(header, claims, privateKeyPem) {
  log.debug("Entering signCompact().");
  const b64u = function (value) {
    log.debug("Entering b64u().");
    log.debug("Leaving b64u().");
    return Buffer.from(typeof value === 'string' ? value :
                       JSON.stringify(value))
      .toString('base64url');
  };
  const signing = b64u(header) + '.' + b64u(claims);
  const ec = /^ES/.test(header.alg);
  const signature = nodeCrypto.sign('sha' + String(header.alg).slice(2),
    Buffer.from(signing),
    ec ? { key: privateKeyPem, dsaEncoding: 'ieee-p1363' } : privateKeyPem);
  log.debug("Leaving signCompact().");
  return signing + '.' + signature.toString('base64url');
}

// A realm of its own for sections 16 and 18: section 2 revokes an Issuing CA
// in the first one, and everything issued under it after that is revoked.
async function secondRealm(label) {
  log.debug("Entering secondRealm().");
  const pki = require('../common/pki');
  const realms = require('../common/realms');
  const id = label + '-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    throw new Error('the realm could not be created: ' +
                    (made.errors || []).join(' '));
  }
  const branch = await pki.ensureScope(id);
  if (!branch.ok) {
    throw new Error('the realm branch could not be built: ' +
                    (branch.errors || []).join(' '));
  }
  log.debug("Leaving secondRealm().");
  return made.realm;
}

// The Issuing CA of `realmId` that signed `pem`, by name.
function useCaseOf(realmId, pem) {
  log.debug("Entering useCaseOf().");
  const pki = require('../common/pki');
  const issuer = new nodeCrypto.X509Certificate(pem).issuer;
  const row = pki.rawRowFor(realmId) || {};
  log.debug("Leaving useCaseOf().");
  return Object.keys(row.issuing || {}).filter(function (useCase) {
    return new nodeCrypto.X509Certificate(row.issuing[useCase].certificatePem).subject === issuer;
  })[0] || '';
}

async function theOwnIndirectSigner(t, fixture) {
  log.debug("Entering theOwnIndirectSigner().");
  t.log.info('=== 16. THIS SERVICE\'S OWN AUTHORITY as the signer of an ' +
             'indirect CRL about a certificate one of its authorities did ' +
             'not sign ===');
  if (!haveOpenSsl()) {
    t.bad('openssl is required for section 16 and is not installed',
          'install ' +
        'openssl');
    log.debug("Leaving theOwnIndirectSigner().");
    return;
  }
  const pki = require('../common/pki');
  const status = require('../common/revocation_status');
  const realm = await secondRealm('rev-own-signer');
  const row = pki.rawRowFor(realm.id);
  const jose = row.issuing.jose;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-revstat-own-'));
  try {
    fs.writeFileSync(path.join(dir, 'intermediate.pem'),
                     row.intermediate.certificatePem);
    fs.writeFileSync(path.join(dir, 'intermediate.key'),
                     row.intermediate.privateKeyPem);
    const joseSubject = new nodeCrypto.X509Certificate(
        jose.certificatePem).subject.split('\n');
    const url = fixture.base + '/own-indirect.crl';
    fs.writeFileSync(path.join(dir, 'ext.cnf'), [
      '[req]', 'distinguished_name=dn', 'prompt=no', '[dn]', 'CN=unused',
      '[subca_ext]', 'basicConstraints=critical,CA:TRUE',
      'keyUsage=critical,keyCertSign,cRLSign',
      '[leaf_ext]', 'basicConstraints=CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'crlDistributionPoints=cdp_own', '[cdp_own]', 'fullname=URI:' + url,
      'CRLissuer=dirName:jose_dn', '[jose_dn]'].concat(joseSubject).join('\n') +
                                                '\n');
    const issue = function (name, subject, issuer, serial, extensions) {
      log.debug("Entering issue().");
      openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt',
               'ec_paramgen_curve:P-256',
               '-out', name + '.key'], dir);
      openssl(['req', '-new', '-config', 'ext.cnf', '-key', name + '.key',
               '-subj', subject,
               '-out', name + '.csr'], dir);
      openssl(['x509', '-req', '-in', name + '.csr', '-CA', issuer + '.pem',
               '-CAkey',
               issuer + '.key', '-set_serial', '0x' +
                                               serial, '-days', '2', '-extfile',
               'ext.cnf', '-extensions', extensions, '-out', name +
                   '.pem'], dir);
      log.debug("Leaving issue().");
      return fs.readFileSync(path.join(dir, name + '.pem'), 'utf8');
    };
    const subCa = issue('subca', '/CN=rev own sub ca', 'intermediate', '7001',
                        'subca_ext');
    const leaf = issue('leaf', '/CN=rev own leaf', 'subca', '7002', 'leaf_ext');
    fixture.routes['/own-indirect.crl'] = { body: await indirectCrl(
      { pem: jose.certificatePem, key: jose.privateKeyPem },
      { url: url,
        entries: [{ serial: '7002', certificateIssuerPem: subCa }] }) };
    await withSettings({ 'pki.revocationCheck': 'hard-fail',
                         'pki.revocationFailureRetryS': 0 },
      async function () {
        status.resetCache();
        const verdict = await status.verdictFor({ leaf: leaf,
          chain: [subCa, row.intermediate.certificatePem], verified: true });
        t.check(verdict.status === 'revoked' &&
                verdict.links[0].indirect === true &&
                verdict.links[1] && verdict.links[1].source === 'register',
                'A CERTIFICATE UNDER A SUB-CA NOBODY HERE HOLDS, WHOSE ' +
                'cRLIssuer IS THIS REALM\'S OWN JOSE ISSUING CA, is revoked ' +
                'by the indirect list that authority signed — its ' +
                'certificate found among this service\'s own authorities, ' +
                'authorised because it chains to the realm Intermediate the ' +
                'sub-CA was issued by — while the sub-CA itself is answered ' +
                'by the register',
                verdict.why + ' ' +
                JSON.stringify(verdict.links.map(function (one) {
                  return one.source;
                })));
      });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving theOwnIndirectSigner().");
}

async function theRegisteredDoors(t) {
  log.debug("Entering theRegisteredDoors().");
  t.log.info('=== 18. the doors that USE a registered certificate: RFC 7523 ' +
             'grant and client authentication, RFC 7522, a federation ' +
             'partner, and OID4VP ===');
  const pki = require('../common/pki');
  const realms = require('../common/realms');
  const revocation = require('../common/pki_revocation');
  const applications = require('../common/applications');
  const errorCodes = require('../common/error_codes');
  const assertionGrant = require('../oauth-oidc/assertion_grant');
  const clientAuth = require('../oauth-oidc/client_auth');
  const samlGrant = require('../oauth-oidc/saml_assertion_grant');
  const signer = require('./vendored/saml_xmldsig.js');
  const federationSp = require('../federation/federation_sp');
  const vcVerifier = require('../oid4vc/vc_verifier');
  const realm = await secondRealm('rev-doors');
  const REALM = realm.id;
  const AUD = 'https://sts.example.test/oauth2/token';
  const revoke = function (pem) {
    log.debug("Entering revoke().");
    log.debug("Leaving revoke().");
    return revocation.revoke(REALM, useCaseOf(REALM, pem),
      { serialHex: new nodeCrypto.X509Certificate(pem).serialNumber,
        reason: 'keyCompromise' });
  };

  const b64Of = function (pem) {
    log.debug("Entering b64Of().");
    log.debug("Leaving b64Of().");
    return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  };
  let jti = 0;
  const claims = function (iss, sub) {
    log.debug("Entering claims().");
    jti += 1;
    const now = Math.floor(Date.now() / 1000);
    log.debug("Leaving claims().");
    return { iss: iss, sub: sub, aud: AUD, iat: now, exp: now + 120,
             jti: 'rev-door-' + jti };
  };
  await realms.run(realm, async function () {
    // --- RFC 7523 section 2.1 ---------------------------------------------
    const ISS = 'https://issuer.example.test/rev-grant';
    applications.createApplication({ identifier: 'rev-grant-app',
                                     protocols: ['oauth2'] });
    applications.updateApplication('rev-grant-app',
      { attribute: 'oauthAssertionIssuer', mode: 'add', value: ISS });
    const pair = (await pki.issueSigningKeyPair(REALM,
                                                { identifier: 'rev-grant-app',
                                                         purpose:
                                                           'jwt' })).issued;
    t.check(pair && pair.jwks && pair.jwks.keys[0] &&
            Array.isArray(pair.jwks.keys[0].x5c),
            'a key pair issued from /admin/pki carries its certificate in ' +
            'the JWKS it writes (x5c), which is what the check ' +
            'reads', JSON.stringify(pair.jwks).slice(0, 80));
    applications.updateApplication('rev-grant-app',
      { attribute: 'oauthAssertionJwks', mode: 'set',
        value: JSON.stringify(pair.jwks) });
    const sign = function (c) {
      log.debug("Entering sign().");
      log.debug("Leaving sign().");
      return signCompact({ alg: pair.jwsAlg, typ: 'JWT', kid: pair.kid }, c,
                         pair.privateKeyPem);
    };
    const good = await assertionGrant.verify({ assertion: sign(
        claims(ISS, 'alice')),
                                               audiences: [AUD] });
    t.check(good.ok && good.keyRevocation &&
            good.keyRevocation.status === 'good',
            'RFC 7523 GRANT: an assertion verified by a REGISTERED key ' +
            'reports the key\'s certificate as looked up and ' +
            'good', JSON.stringify(good.keyRevocation || good.description));
    revoke(pair.certificatePem);
    const refused = await assertionGrant.verify({
      assertion: sign(claims(ISS, 'alice')),
                                                  audiences: [AUD] });
    t.check(!refused.ok && refused.errorCode === 'STS-PKI-0129' &&
            refused.error === 'invalid_grant' &&
            /REVOKED/.test(refused.description),
            'AND ONCE /admin/pki REVOKES THAT CERTIFICATE, THE SAME ' +
            'REGISTERED KEY NO LONGER VERIFIES A GRANT — invalid_grant, ' +
            'STS-PKI-0129', refused.description);
    // A bare key: the same kind of key with its x5c taken off.
    const barePair = (await pki.issueSigningKeyPair(REALM,
                                                    { identifier:
                                                        'rev-bare-app',
                                                             purpose:
                                                               'jwt' })).issued;
    const bareJwks = { keys: barePair.jwks.keys.map(function (one) {
      const copy = Object.assign({}, one);
      delete copy.x5c;
      return copy;
    }) };
    const BARE = 'https://issuer.example.test/rev-bare';
    applications.createApplication({ identifier: 'rev-bare-app',
                                     protocols: ['oauth2'] });
    applications.updateApplication('rev-bare-app',
      { attribute: 'oauthAssertionIssuer', mode: 'add', value: BARE });
    applications.updateApplication('rev-bare-app',
      { attribute: 'oauthJwks', mode: 'set', value: JSON.stringify(bareJwks) });
    revoke(barePair.certificatePem);
    const bare = await assertionGrant.verify({
      assertion: signCompact({ alg: barePair.jwsAlg, typ: 'JWT',
                               kid: barePair.kid },
                             claims(BARE, 'alice'), barePair.privateKeyPem),
      audiences: [AUD] });
    t.check(bare.ok && bare.keyRevocation && bare.keyRevocation.bare === true &&
            bare.keyRevocation.status === 'unchecked',
            'A BARE REGISTERED JWK HAS NOTHING TO CHECK, AND THE RESULT SAYS ' +
            'SO — even with its certificate revoked elsewhere, a key ' +
            'registered without it names no ' +
            'issuer', JSON.stringify(bare.keyRevocation || bare.description));

    // --- RFC 7523 section 2.2, client authentication ------------------------
    const clientPair = (await pki.issueSigningKeyPair(REALM,
                                                      { identifier:
                                                          'rev-client',
                                                               purpose: 'jwt' })).issued;
    const clientAssertion = function () {
      log.debug("Entering clientAssertion().");
      log.debug("Leaving clientAssertion().");
      return signCompact({ alg: clientPair.jwsAlg, typ: 'JWT',
                           kid: clientPair.kid },
                         claims('rev-client',
                                'rev-client'), clientPair.privateKeyPem);
    };
    const authOk = await clientAuth.verify({ method: 'private_key_jwt',
      assertionType: clientAuth.ASSERTION_TYPE, assertion: clientAssertion(),
      clientId: 'rev-client', jwks: JSON.stringify(clientPair.jwks),
      audiences: [AUD] });
    t.check(authOk.ok, 'RFC 7523 CLIENT AUTHENTICATION with a registered key ' +
                       'succeeds',
            authOk.description);
    revoke(clientPair.certificatePem);
    const authRefused = await clientAuth.verify({ method: 'private_key_jwt',
      assertionType: clientAuth.ASSERTION_TYPE, assertion: clientAssertion(),
      clientId: 'rev-client', jwks: JSON.stringify(clientPair.jwks),
      audiences: [AUD] });
    t.check(!authRefused.ok && authRefused.errorCode === 'STS-PKI-0129',
            'and is refused once the registered key\'s certificate is ' +
            'revoked — the client is answered ' +
            'invalid_client', JSON.stringify(authRefused));

    // --- RFC 7522 ---------------------------------------------------------
    const samlPair = (await pki.issueSigningKeyPair(REALM,
                                                    { identifier: 'rev-saml',
                                                             purpose: 'saml' })).issued;
    const samlAssertion = function () {
      log.debug("Entering samlAssertion().");
      log.debug("Leaving samlAssertion().");
      return signer.b64u(signer.sign(signer.buildAssertion({ issuer: 'rev-saml',
        subject: 'rev-saml', audience: AUD, recipient: AUD }),
        samlPair.privateKeyPem, samlPair.certificatePem));
    };
    const samlOk = await samlGrant.verify({ assertion: samlAssertion(),
      clientId: 'rev-saml',
      registeredCertificate: samlPair.certificatePem, audiences: [AUD] });
    t.check(samlOk.ok && samlOk.certificateRevocation &&
            samlOk.certificateRevocation.status === 'good',
            'RFC 7522: the registered certificate that verified the ' +
            'assertion is looked up and ' +
            'good',
            JSON.stringify(samlOk.certificateRevocation || samlOk.description));
    revoke(samlPair.certificatePem);
    const samlRefused = await samlGrant.verify({ assertion: samlAssertion(),
      clientId: 'rev-saml', registeredCertificate: samlPair.certificatePem,
      audiences: [AUD] });
    t.check(!samlRefused.ok && samlRefused.errorCode === 'STS-PKI-0129' &&
            samlRefused.error === 'invalid_grant',
            'and refused once it is revoked', samlRefused.description);

    // --- a federation partner ---------------------------------------------
    const fedPair = (await pki.issueSigningKeyPair(REALM,
                                                   { identifier: 'rev-fed',
                                                            purpose:
                                                              'saml' })).issued;
    const fakeRes = function () {
      log.debug("Entering fakeRes().");
      log.debug("Leaving fakeRes().");
      return { statusCode: 200, headersSent: false, body: '',
               status: function (code) {
                 log.debug("Entering status().");
                 this.statusCode = code;
                 log.debug("Leaving status().");
                 return this;
               },
               type: function () {
                 log.debug("Entering type().");
                 log.debug("Leaving type().");
                 return this;
               }, set: function () {
                 log.debug("Entering set().");
                 log.debug("Leaving set().");
                 return this;
               },
               send: function (body) {
                 log.debug("Entering send().");
                 this.body = body;
                 this.headersSent = true;
                 log.debug("Leaving send().");
                 return this;
               } };
    };
    const record = { fedId: 'rev-fed-unregistered',
                     fedSigningCertificate: b64Of(fedPair.certificatePem) };
    let proceeded = 0;
    const proceed = function () {
      log.debug("Entering proceed().");
      proceeded += 1;
      log.debug("Leaving proceed().");
      return 'signed in';
    };
    const fedGood = await federationSp.signerStillAccepted({}, fakeRes(),
                                                           record, proceed);
    t.check(fedGood === 'signed in' && proceeded === 1,
            'FEDERATION: a response verified by a good fedSigningCertificate ' +
            'goes on to the sign-in', JSON.stringify(fedGood));
    revoke(fedPair.certificatePem);
    const res = fakeRes();
    await federationSp.signerStillAccepted({}, res, record, proceed);
    t.check(res.statusCode === 401 && proceeded === 1 &&
            errorCodes.codeOf(res) === 'STS-PKI-0129' &&
            /REVOKED/.test(res.body),
            'and once that certificate is revoked the sign-in is REFUSED ' +
            'with the reason on the page, STS-PKI-0129, and never ' +
            'started', res.statusCode + ' ' +
            String(res.body).slice(0, 200));
    const jwkRes = fakeRes();
    await federationSp.signerStillAccepted({}, jwkRes, record, proceed,
      { kty: 'RSA', kid: 'partner', x5c: [b64Of(fedPair.certificatePem)] });
    t.check(jwkRes.statusCode === 401 && proceeded === 1,
            'the same for an OIDC partner key whose x5c is that certificate',
            String(jwkRes.statusCode));
    const bareFed = await federationSp.signerStillAccepted({}, fakeRes(),
      record, proceed,
      { kty: 'RSA', kid: 'partner-bare', n: 'AQAB', e: 'AQAB' });
    t.check(bareFed === 'signed in' && proceeded === 2,
            'while a partner key with no certificate has nothing to check ' +
            'and the sign-in goes on', JSON.stringify(bareFed));

    // --- OID4VP -----------------------------------------------------------
    const vcPair = (await pki.issueSigningKeyPair(REALM, { identifier: 'rev-vc',
                                                           purpose:
                                                             'jwt' })).issued;
    const vcGood = await vcVerifier.issuerCertificateRevocation(
        { ok: true, checks: [],
      issuerCertificatePem: vcPair.certificatePem });
    t.check(vcGood.ok && vcGood.checks.length === 1 && vcGood.checks[0].ok,
            'OID4VP: a trusted issuer certificate that verified a credential ' +
            'is looked up and good, as a check ' +
            'row', JSON.stringify(vcGood.checks));
    revoke(vcPair.certificatePem);
    const vcRefused = await vcVerifier.issuerCertificateRevocation(
        { ok: true, checks: [],
      issuerCertificatePem: vcPair.certificatePem });
    t.check(!vcRefused.ok && vcRefused.revocationRefused === true &&
            !vcRefused.checks[0].ok,
            'and once it is revoked the presentation is refused on that check',
            JSON.stringify(vcRefused.checks));
  });

  // THE WIRING, READ OUT OF THE SOURCE — the helpers above are asked directly,
  // and what no in-process call reaches is that the consumer and the response
  // endpoint CALL them. A grep is the blunt instrument
  // `tests/saml_assertion_grant.js` uses for the same kind of claim: the
  // failure guarded against is a sign-in path added or edited to reach
  // completeSignIn() without the check.
  const fedSource = fs.readFileSync(path.join(ROOT, 'federation',
                                              'federation_sp.js'), 'utf8')
    .split('\n');
  const sites = [];
  fedSource.forEach(function (line, at) {
    if (/^\s*return completeSignIn\(/.test(line)) {
      const before = fedSource.slice(Math.max(0, at - 3), at).join('\n');
      sites.push({ line: at + 1, wrapped: /signerStillAccepted\(/.test(before),
                   opaque: /The profile endpoint answered/.test(before) });
    }
  });
  t.check(sites.length === 5 &&
          sites.filter(function (one) { return one.wrapped; }).length === 4 &&
          sites.filter(function (one) { return !one.wrapped; })
               .every(function (one) {
            return one.opaque;
          }),
          'EVERY FEDERATED SIGN-IN THAT RESTS ON A SIGNATURE REACHES ' +
          'completeSignIn() THROUGH signerStillAccepted() — SAML 2.0 and ' +
          '1.1, WS-Federation, OIDC and a JWT access token — and the one ' +
          'that does not is the opaque OAuth 2.0 token, where no signature ' +
          'was verified at all', JSON.stringify(sites));
  t.check(/verified: .*jwk: candidates\[i\]|jwk: candidates\[i\]/.test(
      fedSource.join('\n')) &&
          /\}, verified\.jwk\);/.test(fedSource.join('\n')),
          'and a partner JWT\'s check is handed the key that verified it',
          'verifyForeignJwt() returns jwk');
  const vpSource = fs.readFileSync(path.join(ROOT, 'oid4vc', 'vc_verifier.js'),
                                   'utf8');
  t.check(/verifyPresentation\(presentations\[0\], record\);\s*await issuerCertificateRevocation\(verified\);\s*record\.verdict = \{/
            .test(vpSource) && /pem: pem,/.test(vpSource) &&
          (vpSource.match(/result\.issuerCertificatePem = verifyIssuerSignature\(/g) || []).length === 2,
          'and the OID4VP response endpoint asks before it records a ' +
          'verdict, with the certificate both verifiers report having ' +
          'used', 'vc_verifier.js');
  log.debug("Leaving theRegisteredDoors().");
}

// ===========================================================================
// 5. THE MAIN PORT, AS A REAL HANDSHAKE, AND WHAT A WORKER IS HANDED.
// ===========================================================================
function handshake(port, client) {
  log.debug("Entering handshake().");
  log.debug("Leaving handshake().");
  return new Promise(function (resolve) {
    const req = https.request({ host: '127.0.0.1', port: port, path: '/',
      method: 'GET', cert: client.cert, key: client.key,
      rejectUnauthorized: false, agent: false }, function (res) {
      let text = '';
      res.on('data', function (c) { text += c; });
      res.on('end', function () {
        let body = null;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in handshake(): " +
                    ((e && e.message) || e));
          // Not JSON; the raw text is what gets reported.
          body = { raw: text };
        }
        resolve({ status: res.statusCode, body: body });
      });
    });
    req.on('error',
           function (e) {
             resolve({ status: 0, body: { error: e.message } });
           });
    req.end();
  });
}

async function theMainPort(t, minted) {
  log.debug("Entering theMainPort().");
  t.log.info('=== 5. the main port\'s doors, over a real handshake ===');
  const status = require('../common/revocation_status');
  const mtls = require('../oauth-oidc/mtls');
  const requestPool = require('../common/request_pool');
  const tls = require('../tls/tls_server');
  const server = https.createServer({
    cert: tls.serverCertificate().certPem,
    key: tls.serverCertificate().privateKeyPem,
    ca: [minted.root.pem], requestCert: true, rejectUnauthorized: false
  }, function (req, res) {
    status.annotateRequest(req).then(function () {
      const verified = mtls.peerVerified(req);
      // WHAT A WORKER IS HANDED, decoded the way `request_worker.js`'s
      // `decodePeer()` decodes it, and put on a shim socket the way that file
      // does — then asked the same question.
      const forwarded = requestPool.peerOf(req);
      const flat = forwarded
        ? JSON.parse(Buffer.from(forwarded.cert, 'base64').toString('utf8')) :
                   {};
      Object.keys(flat).forEach(function (name) {
        if (flat[name] && typeof flat[name].__buffer === 'string') {
          flat[name] = Buffer.from(flat[name].__buffer, 'base64');
        }
      });
      const shim = { authorized: forwarded ? forwarded.authorized : false,
                     getPeerCertificate: function () {
                       log.debug("Entering getPeerCertificate().");
                       log.debug("Leaving getPeerCertificate().");
                       return flat;
                     } };
      // AND THE OTHER TWO DOORS ON THIS PORT THAT READ THE ANNOTATION: SCIM's
      // client-certificate scheme, and RFC 8705 self-signed client
      // authentication with the thumbprint registered — which is the case the
      // revocation guard has to come BEFORE, since the thumbprint matches.
      const scim = require('../scim/scim_auth').authenticate(req, 'read');
      const clientAuth = require('../oauth-oidc/client_auth');
      Promise.all([
        status.verdictFor(status.fromSocket(shim)),
        clientAuth.verify({ method: 'self_signed_tls_client_auth', request: req,
                            clientId: 'rev-client',
                            certificateThumbprint: mtls.presentedThumbprint(
                                req) })
      ]).then(function (both) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          verified: verified.verified, error: verified.error || '',
          status: req.certificateRevocation && req.certificateRevocation.status,
          forwardedChain: (flat.issuerChain || []).length,
          workerStatus: both[0].status,
          scimScheme: scim && scim.ok ? scim.scheme : '',
          clientAuthOk: !!both[1].ok, clientAuthCode: both[1].errorCode || ''
        }));
      });
    });
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  try {
    const good = await handshake(port,
                                 { cert: minted.good.pem + minted.issuing.pem,
                                         key: minted.good.key });
    t.check(good.body.verified === true && good.body.status === 'good',
            'a good foreign client certificate VERIFIES through ' +
            'mtls.peerVerified(), with the annotation app.js ' +
            'makes', JSON.stringify(good.body));
    const bad = await handshake(port,
                                { cert: minted.revoked.pem + minted.issuing.pem,
                                        key: minted.revoked.key });
    t.check(bad.body.verified === false && bad.body.error === 'CERT_REVOKED',
            'a REVOKED one is NOT VERIFIED — which is how the remote XACML ' +
            'PEP and the XACML user chains refuse it without a new question',
            JSON.stringify(bad.body));
    t.check(good.body.forwardedChain >= 1 &&
            good.body.workerStatus === 'good' &&
            bad.body.workerStatus === 'revoked',
            'AND A REQUEST WORKER HANDED THE CERTIFICATE reaches the same ' +
            'verdict: peerOf() now carries the chain above the leaf, without ' +
            'which a worker has no issuer to verify a foreign CRL with',
            JSON.stringify({ good: good.body, bad: bad.body }));
    t.check(good.body.scimScheme === 'clientcert' &&
            bad.body.scimScheme !== 'clientcert',
            'SCIM\'s client-certificate scheme accepts the good certificate ' +
            'and does NOT accept the revoked one as a credential',
            JSON.stringify({ good: good.body.scimScheme,
                             bad: bad.body.scimScheme }));
    t.check(good.body.clientAuthOk === true &&
            bad.body.clientAuthOk === false &&
            bad.body.clientAuthCode === 'STS-PKI-0118',
            'and RFC 8705 client authentication refuses the revoked ' +
            'certificate with the revocation code even though its registered ' +
            'thumbprint MATCHES — a revoked certificate is a client secret ' +
            'its issuer withdrew',
            JSON.stringify({ good: good.body.clientAuthOk,
                             bad: bad.body.clientAuthCode }));
  } finally {
    await new Promise(function (resolve) { server.close(resolve); });
  }
  log.debug("Leaving theMainPort().");
}

// ===========================================================================
// 6 AND 7. GET /tls/sign-in AGAINST A REVOKED CERTIFICATE, IN A CHILD.
//
// It was the 8443 and 9443 listeners until 2026-09-16 (see the header). The
// child now builds the listener ITSELF — `requestCert: true,
// rejectUnauthorized: false` over `common/app`, which is the main port's
// posture in `server.js` — because this module binds nothing any more. It is
// still a child process: it adds a trust anchor, revokes a certificate and
// leaves both in module state.
// ===========================================================================
async function childBody() {
  log.debug("Entering childBody().");
  const out = {};
  const fixture = await crlServer();
  const root = await issue({ subject: 'CN=rev listener root', ca: true,
                             pathLen: 1 });
  const issuing = await issue({ subject: 'CN=rev listener issuing', ca: true,
                                crls: [fixture.base + '/r.crl'],
                                issuer: asIssuer(root) });
  fixture.routes['/r.crl'] = { body: await makeCrl(root, []) };
  const good = await issue({ subject: 'CN=rev-listener-good',
                             issuer: asIssuer(issuing),
                             crls: [fixture.base + '/l.crl'] });
  const bad = await issue({ subject: 'CN=rev-listener-bad',
                            issuer: asIssuer(issuing),
                            crls: [fixture.base + '/l.crl'] });
  fixture.routes['/l.crl'] = { body: await makeCrl(issuing, [bad.serialHex]) };
  const tls = require('../tls/tls_server');
  const app = require('../common/app');
  tls.truststore.add(root.pem, { by: 'revocation_status test' });
  // THE MAIN PORT'S POSTURE, BUILT HERE. A client certificate is asked for and
  // never required, so nothing is refused by the handshake and every refusal
  // below is one this service made after OpenSSL was satisfied — which is the
  // whole subject of these two sections.
  const serverCert = tls.serverCertificate();
  const listener = https.createServer(Object.assign({
    cert: serverCert.certPem, key: serverCert.privateKeyPem,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  tls.trustClientCertificatesOn(listener, 'the revocation_status test ' +
                                          'listener');
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;
  const ask = function (leaf) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return new Promise(function (resolve) {
      const req = https.request({ host: '127.0.0.1', port: port,
        path: '/tls/sign-in',
        method: 'GET', cert: leaf.pem + issuing.pem, key: leaf.key,
        rejectUnauthorized: false, agent: false }, function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let body = {};
          try {
            body = JSON.parse(text);
          } catch (e) {
            log.debug("Caught in a callback in ask(): " +
                      ((e && e.message) || e));
            // Reported as the raw text below.
            body = { raw: text.slice(0, 200) };
          }
          resolve({ status: res.statusCode, body: body });
        });
      });
      req.on('error',
             function (e) {
               resolve({ status: 0, body: { error: e.message } });
             });
      req.end();
    });
  };

  const summary = function (answer) {
    log.debug("Entering summary().");
    const cert = answer.body.clientCertificate || {};
    const session = answer.body.session || {};
    log.debug("Leaving summary().");
    return { status: answer.status, error: answer.body.error || answer.body.raw,
             verified: cert.verified,
             revocation: answer.body.revocation &&
                         answer.body.revocation.status,
             signedIn: answer.body.signedIn,
             refused: session.refusedOnRevocation,
             started: session.started, why: session.why };
  };
  out.revoked = summary(await ask(bad));
  out.good = summary(await ask(good));
  await new Promise(function (ok) {
    listener.close(ok);
  });
  fixture.server.close();
  log.debug("Leaving childBody().");
  return out;
}

// ---------------------------------------------------------------------------
// EVERY SECTION RUNS IN A CHILD PROCESS, AND THE FIRST VERSION DID NOT.
//
// `run.js` runs every file in ONE process, and the first version of this file
// ran sections 1 to 5 in it. It passed alone and failed under `npm test`. The
// cause that made it fail THEN — a realm branch built twice, the second build
// replacing the one a leaf had just been issued from — is fixed in `pki.js`
// (`oneBuildAtATime()`, pinned by `tests/pki_scope_builds.js`). What keeps this
// file in children is everything else it shares with a process: it sets
// `global.mode` and a dozen `pki.revocation*` settings, it revokes authorities
// in the KEYSTORE's rows, and it asserts on the module-wide CRL and OCSP caches
// and their failure memory — and every one of those is state another file may
// have left behind, or would inherit from this one.
//
// So the whole file runs in three fresh processes — the register-and-CRL half,
// the listener half (which adds a trust anchor and revokes a certificate, both
// of them module state) and the OpenSSL half — and this process only replays
// what they asserted.
// That is the arrangement `tests/tls_trust_anchor.js` and
// `tests/spiffe_authority.js` use for the same class of reason.
// ---------------------------------------------------------------------------
function spawnChild(which) {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = which;
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('REVOCATION-CHILD ') === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild().");
    return { error: 'the ' + which + ' child produced no result (exit ' +
                    result.status + '): ' +
                    String(result.stderr || '').slice(-1200) };
  }
  log.debug("Leaving spawnChild().");
  return JSON.parse(line.slice('REVOCATION-CHILD '.length));
}

function theListeners(t, got) {
  log.debug("Entering theListeners().");
  t.log.info('=== 6 and 7. GET /tls/sign-in starts no session for a revoked ' +
             'certificate ===');
  if (got.error) {
    t.bad('the listener child did not run', got.error);
    log.debug("Leaving theListeners().");
    return;
  }
  t.check(got.revoked.verified === true &&
          got.revoked.revocation === 'revoked',
          'A REVOKED CERTIFICATE WHOSE CHAIN VERIFIED is found revoked at ' +
          'the REQUEST, off its issuer\'s CRL — node\'s own `crl` option ' +
          'would have to refuse every issuer that publishes no list, so this ' +
          'is not a check a socket can make',
          JSON.stringify(got.revoked));
  t.check(got.revoked.signedIn === false && got.revoked.started === false &&
          got.revoked.refused === true,
          'and it SIGNS NOBODY IN, reported as refused on revocation. **The ' +
          'HANDSHAKE REFUSAL 9443 made has no successor and is not coming ' +
          'back** (2026-09-16): this port carries every other protocol, so a ' +
          'certificate that must not be an identity is refused where it is ' +
          'USED and the answer is a 200 saying so',
          JSON.stringify(got.revoked));
  t.check(got.good.status === 200 && got.good.revocation === 'good' &&
          got.good.signedIn === true && got.good.started === true,
          'while a good certificate from the SAME authority signs its holder ' +
          'in — without which the assertion above passes on a door that is ' +
          'simply shut', JSON.stringify(got.good));
  log.debug("Leaving theListeners().");
}

// The register-and-CRL half, in its own process. It records every assertion
// rather than logging it, and the parent replays them in order.
// A harness that RECORDS every assertion rather than logging it, for a child
// whose parent replays them in order.
function recordingHarness(results) {
  log.debug("Entering recordingHarness().");
  const t = {
    check: function (condition, what, detail) {
      log.debug("Entering check().");
      results.push({ ok: !!condition, what: what, detail: detail });
      log.debug("Leaving check().");
      return !!condition;
    },
    equal: function (actual, expected, what) {
      log.debug("Entering equal().");
      log.debug("Leaving equal().");
      return t.check(actual === expected, what,
                     'expected ' + JSON.stringify(expected) + ', got ' +
                     JSON.stringify(actual));
    },
    bad: function (what, detail) {
      log.debug("Entering bad().");
      results.push({ ok: false, what: what, detail: detail });
      log.debug("Leaving bad().");
    },
    log: {
      info: function (line) {
        log.debug("Entering info().");
        results.push({ info: line });
        log.debug("Leaving info().");
      },
      warn: function (line) {
        log.debug("Entering warn().");
        results.push({ info: 'warning: ' + line });
        log.debug("Leaving warn().");
      }
    }
  };
  log.debug("Leaving recordingHarness().");
  return t;
}

async function registerChildBody() {
  log.debug("Entering registerChildBody().");
  const results = [];
  const t = recordingHarness(results);
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const realms = require('../common/realms');
  require('../ldap/ldap_server');
  await keystore.start();
  const rooted = await pki.ensureRoot({});
  if (!rooted.ok) {
    throw new Error('the service Root CA could not be built: ' +
                    (rooted.errors || []).join(' '));
  }
  // A FRESH PROCESS HAS NO REALM WATCHER — nothing called `pki.start()` — so
  // this `ensureScope()` is the only build of the branch and the branch this
  // file issues from is the one it asked for.
  const id = 'rev-status-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    throw new Error('the realm could not be created: ' +
                    (made.errors || []).join(' '));
  }
  const fixture = await crlServer();
  try {
    const branch = await pki.ensureScope(id);
    if (!branch.ok) {
      throw new Error('the realm branch could not be built: ' +
                      (branch.errors || []).join(' '));
    }
    await thePolicy(t);
    await theRegister(t, made.realm, fixture.base);
    const minted = await theForeignCrl(t, fixture, made.realm.id);
    await theMainPort(t, minted);
    await theOwnIndirectSigner(t, fixture);
    await theRegisteredDoors(t);
  } finally {
    fixture.server.close();
  }
  log.debug("Leaving registerChildBody().");
  return { results: results };
}

// ===========================================================================

function replay(t, which, got) {
  log.debug("Entering replay().");
  if (got.error) {
    t.bad('the ' + which + ' child did not run', got.error);
    log.debug("Leaving replay().");
    return;
  }
  got.results.forEach(function (one) {
    if (one.info) {
      t.log.info(one.info);
      return;
    }
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving replay().");
}

async function run(t) {
  log.debug("Entering run().");
  replay(t, 'register-and-CRL', spawnChild('register'));
  theListeners(t, spawnChild('listeners'));
  replay(t, 'OpenSSL', spawnChild('openssl'));
  replay(t, 'closing', spawnChild('closing'));
  log.debug("Leaving run().");
}

const CHILD_BODIES = { register: registerChildBody, listeners: childBody,
                       openssl: extendedChildBody, closing: closingChildBody };

if (process.env[CHILD_FLAG]) {
  const body = CHILD_BODIES[process.env[CHILD_FLAG]];
  body().then(function (out) {
    process.stdout.write('REVOCATION-CHILD ' + JSON.stringify(out) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + (e && e.stack) + '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'revocation_status',
  describe: 'revocation CONSULTED: the policy by mode, the register at ' +
            'verifyLeaf and the SPIRE Server API (a hold, a release, a ' +
            'revoked Issuing CA refusing a leaf sent alone), a foreign CRL ' +
            '(good, cached, revoked, 404 soft and hard, failure memory, ' +
            'forged, stale, critical extension, timeout, redirect, ' +
            'unverified chain never dialled, no distribution point, an ' +
            'OpenSSL CRL), the main port\'s doors and a worker\'s view over ' +
            'a real handshake, GET /tls/sign-in refusing a revoked ' +
            'certificate a session and signing a good one\'s holder in, and ' +
            'against OpenSSL-signed ' +
            'documents: OCSP (good, revoked by a delegated responder, ' +
            'unknown, the wrong key, no EKU, stale, replayed, one request ' +
            'for two callers, the order setting), delta CRLs (revokes, ' +
            'removes, a mismatched base, an unreachable delta), indirect ' +
            'CRLs (a second CA revoking, entry attribution, an impostor ' +
            'signer, a signer the certificate does not name) and the issuing ' +
            'distribution point\'s scope and reasons; and a delegated ' +
            'responder\'s own status, a list\'s signer from its caIssuers ' +
            'address, ldap and ldaps against a real directory, the two ' +
            'unreached delta checks, this service\'s own authority as an ' +
            'indirect-CRL signer, and a REGISTERED certificate at every door ' +
            'that uses one',
  run: run
};
