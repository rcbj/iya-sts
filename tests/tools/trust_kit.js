// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/trust_kit.js
//
// ===========================================================================
// CERTIFICATES A VALIDATION TEST CHOOSES, AND THE STORES IT PUTS THEM IN
// (#1360). In `tools/` because `run.js` discovers `tests/*.js`, for
// `saml_signing_kit.js`'s reason, and one copy because three files mint the
// same fixtures: a CA, a leaf that breaks exactly one rule, and a CRL.
//
// `signerStoreDouble()` is the signer truststore's directory: a Map per realm,
// with the slot's own three functions, so a test asserts the store's rules and
// not the directory's.
// ===========================================================================

const http = require('http');
const x509 = require('../../common/crypto_impl/x509');
const keys = require('../../common/crypto_impl/key_material');

const log = require('bunyan').createLogger({ name: 'trust_kit',
  level: process.env.LOG_LEVEL || 'info' });

const DAY = 86400000;
// One key per run, shared by every certificate that does not ask for its own:
// RSA generation is the slow part, and no assertion here is about the key.
let shared = null;

async function keyPair() {
  log.debug("Entering keyPair().");
  if (!shared) {
    shared = await keys.generateKeyPair('rsa-2048');
  }
  log.debug("Leaving keyPair().");
  return shared;
}

// `DNS:host` as the engine's GeneralName.
function generalName(text) {
  log.debug("Entering generalName().");
  const at = String(text).indexOf(':');
  log.debug("Leaving generalName().");
  return { kind: String(text).slice(0, at).toLowerCase(),
           value: String(text).slice(at + 1) };
}

/**
 * Issues one certificate.
 *
 * @param spec - `{ cn, ca, pathLen, usages, eku, san, crls, notBefore,
 *   notAfter, issuer, selfSigned, signatureAlg, pair, critical (an OID),
 *   permittedDns, noKeyUsage, noEku }`; `issuer` omitted means self-signed
 * @returns a promise of `{ pem, key, keyAlg, serialHex, cn }`
 */
async function mint(spec) {
  log.debug("Entering mint(). " + spec.cn);
  const pair = spec.pair || await keyPair();
  const now = Date.now();
  const extensions = {
    basicConstraints: { present: true, critical: true, ca: !!spec.ca,
                        pathLen: spec.ca ? (spec.pathLen === undefined ? 1 :
                                            spec.pathLen) : undefined },
    subjectKeyIdentifier: { present: true },
    authorityKeyIdentifier: { present: !!spec.issuer }
  };
  if (!spec.noKeyUsage) {
    extensions.keyUsage = { present: true, critical: true,
      usages: spec.usages || (spec.ca ? ['keyCertSign', 'cRLSign'] :
                              ['digitalSignature']) };
  }
  if (spec.eku) {
    extensions.extKeyUsage = { present: true, usages: spec.eku };
  }
  if (spec.san) {
    extensions.subjectAltName = { present: true, critical: false,
                                  names: spec.san.map(generalName) };
  }
  if (spec.crls) {
    extensions.cRLDistributionPoints = { present: true, critical: false,
                                         urls: spec.crls };
  }
  if (spec.permittedDns) {
    extensions.nameConstraints = { present: true, critical: true,
                                   permitted: spec.permittedDns.map(
                                     function (d) {
                                       return generalName('DNS:' + d);
                                     }), excluded: [] };
  }
  if (spec.critical) {
    extensions.custom = [{ oid: spec.critical, critical: true,
                           value: Buffer.from('0500', 'hex')
                             .toString('base64') }];
  }
  const issued = await x509.issueCertificate({
    subject: [{ name: 'CN', value: spec.cn }],
    subjectPublicKey: pair.publicPem,
    signatureAlg: spec.signatureAlg || 'sha256-rsa',
    issuerPrivateKey: spec.issuer ? undefined : pair.privatePem,
    issuer: spec.issuer ? { certificatePem: spec.issuer.pem,
                            privateKeyPem: spec.issuer.key,
                            keyAlg: 'rsa-2048' } : undefined,
    notBefore: new Date(spec.notBefore || now - 60000).toISOString(),
    notAfter: new Date(spec.notAfter || now + 365 * DAY).toISOString(),
    extensions: extensions
  });
  log.debug("Leaving mint().");
  return { pem: issued.pem, key: pair.privatePem, serialHex: issued.serialHex,
           cn: spec.cn };
}

/**
 * A CRL signed by an issuer, listing these serials.
 *
 * @param issuer - what `mint()` answered for the CA
 * @param serials - the revoked serials, in hex
 * @returns a promise of the DER
 */
async function crlOf(issuer, serials) {
  log.debug("Entering crlOf().");
  const pkijs = require('pkijs');
  const asn1js = require('asn1js');
  // For its side effect: it installs the Web Crypto engine pkijs signs with.
  require('../../common/pki_revocation');
  const der = function (pem) {
    log.debug("Entering der().");
    const buf = Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
    log.debug("Leaving der().");
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  };
  const now = Date.now();
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;
  crl.issuer = pkijs.Certificate.fromBER(der(issuer.pem)).subject;
  crl.thisUpdate = new pkijs.Time({ type: 0, value: new Date(now - 60000) });
  crl.nextUpdate = new pkijs.Time({ type: 0, value: new Date(now + 3600000) });
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
      return entry;
    });
  }
  crl.crlExtensions = new pkijs.Extensions({ extensions: [
    new pkijs.Extension({ extnID: '2.5.29.20', critical: false,
      extnValue: new asn1js.Integer({ value: 1 }).toBER(false) })
  ] });
  const key = await crypto.subtle.importKey('pkcs8', der(issuer.key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  await crl.sign(key, 'SHA-256');
  log.debug("Leaving crlOf().");
  return Buffer.from(crl.toSchema(true).toBER(false));
}

/**
 * A plain-HTTP server of CRLs on a loopback port this file chose.
 *
 * @returns a promise of `{ base, routes, close() }`; a route is a path's bytes
 */
function crlServer() {
  log.debug("Entering crlServer().");
  const routes = {};
  const server = http.createServer(function (req, res) {
    const body = routes[req.url];
    if (!body) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/pkix-crl' });
    res.end(body);
  });
  log.debug("Leaving crlServer().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve({ base: 'http://127.0.0.1:' + server.address().port,
                routes: routes,
                close: function () {
                  return new Promise(function (done) {
                    server.close(done);
                  });
                } });
    });
  });
}

/**
 * The signer truststore's directory slot, as a Map per realm.
 *
 * @returns `{ list, put, remove, rows }`
 */
function signerStoreDouble() {
  log.debug("Entering signerStoreDouble().");
  const realmsSeen = new Map();
  const of = function (realmId) {
    log.debug("Entering of().");
    if (!realmsSeen.has(realmId)) {
      realmsSeen.set(realmId, new Map());
    }
    log.debug("Leaving of().");
    return realmsSeen.get(realmId);
  };
  log.debug("Leaving signerStoreDouble().");
  return {
    list: function (realmId) {
      return Array.from(of(realmId).values());
    },
    put: function (realmId, row) {
      of(realmId).set(row.fingerprint, Object.assign({}, row));
      return true;
    },
    remove: function (realmId, fingerprint) {
      return of(realmId).delete(fingerprint);
    },
    rows: of
  };
}

module.exports = { DAY: DAY, mint: mint, crlOf: crlOf, crlServer: crlServer,
                   signerStoreDouble: signerStoreDouble, keyPair: keyPair };
