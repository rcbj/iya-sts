'use strict';
//
// File: oid4vp_x509_client_id.js
//
// ===========================================================================
// THE x509_san_dns AND x509_hash CLIENT IDENTIFIER PREFIXES (OpenID4VP 1.0
// section 5.9.3, #230), in process, against the real certificate authority.
//
//   1. x509_san_dns: the Verifier is certified for the Response URI's host,
//      the Request Object carries the chain in `x5c` (leaf, Issuing CA,
//      Intermediate — no Root), is signed ES256 by the leaf's key, the
//      leaf's dNSName is the Client Identifier and it chains to the Root;
//   2. x509_hash: the same certificate, and the Client Identifier is the
//      base64url SHA-256 of its DER, computed here independently;
//   3. the prefix per request, over the realm's setting;
//   4. the certificate is issued once, and not over another key;
//   5. the refusals: a configured name that is not the Response URI's host,
//      an IP address, a wildcard, the per-realm limit, an algorithm the realm
//      holds no key for; x509_hash still answers where no name can be had;
//   6. product mode never certifies a Host header — and does certify
//      oid4vp.x509DnsName and a pinned global.publicBaseUrl;
//   7. a renewal of the JOSE Issuing CA's certificates keeps the name;
//   8. the Digital Credentials API request of a sign-in carries the same
//      x5c.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const pki = require('../common/pki');
const verifier = require('../oid4vc/vc_verifier');

const log = require('bunyan').createLogger({ name: 'oid4vp_x509_client_id',
  level: process.env.LOG_LEVEL || 'info' });

const HOST = 'sts.test';

function fakeReq(host) {
  log.debug("Entering fakeReq().");
  const name = host || HOST;
  log.debug("Leaving fakeReq().");
  return { protocol: 'https', headers: { host: name }, query: {},
           get: function (header) {
             return String(header).toLowerCase() === 'host' ? name : '';
           } };
}

function partOf(jwt, i) {
  log.debug("Entering partOf().");
  log.debug("Leaving partOf().");
  return JSON.parse(Buffer.from(String(jwt).split('.')[i], 'base64url')
    .toString('utf8'));
}

function pemOf(b64) {
  log.debug("Entering pemOf().");
  log.debug("Leaving pemOf().");
  return '-----BEGIN CERTIFICATE-----\n' +
    String(b64).match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
}

// THE WALLET'S CHECK, written from the specification rather than asked of
// the module under test: the signature by the leaf's key, the chain link by
// link to the Root this service publishes, and the Client Identifier against
// the leaf.
function walletCheck(jwt, clientId) {
  log.debug("Entering walletCheck().");
  const header = partOf(jwt, 0);
  const claims = partOf(jwt, 1);
  const certs = (header.x5c || []).map(function (one) {
    return new nodeCrypto.X509Certificate(pemOf(one));
  });
  const root = new nodeCrypto.X509Certificate(pki.serviceRoot()
    .certificatePem);
  const parts = String(jwt).split('.');
  const signatureOk = header.alg === 'ES256' && certs.length > 0 &&
    nodeCrypto.verify('sha256', Buffer.from(parts[0] + '.' + parts[1]),
                      { key: certs[0].publicKey, dsaEncoding: 'ieee-p1363' },
                      Buffer.from(parts[2], 'base64url'));
  let chainOk = certs.length === 3;
  for (let i = 0; chainOk && i < certs.length; i++) {
    const issuer = i + 1 < certs.length ? certs[i + 1] : root;
    chainOk = certs[i].checkIssued(issuer) &&
              certs[i].verify(issuer.publicKey) &&
              certs[i].fingerprint256 !== root.fingerprint256;
  }
  const leaf = certs[0];
  const dns = leaf ? String(leaf.subjectAltName || '').split(/,\s*/)
    .filter(function (one) {
      return one.indexOf('DNS:') === 0;
    }).map(function (one) {
      return one.slice(4);
    }) : [];
  const hash = leaf ? nodeCrypto.createHash('sha256').update(leaf.raw)
    .digest('base64url') : '';
  let idOk = false;
  if (/^x509_san_dns:/.test(clientId)) {
    const name = clientId.slice('x509_san_dns:'.length);
    idOk = dns.indexOf(name) >= 0 &&
           new URL(claims.response_uri).hostname === name;
  } else if (/^x509_hash:/.test(clientId)) {
    idOk = clientId === 'x509_hash:' + hash;
  }
  log.debug("Leaving walletCheck().");
  return { header: header, claims: claims, signatureOk: signatureOk,
           chainOk: chainOk, idOk: idOk && claims.client_id === clientId,
           dns: dns, hash: hash, leaf: leaf };
}

async function refusalOf(fn) {
  log.debug("Entering refusalOf().");
  try {
    await fn();
  } catch (e) {
    log.debug("Caught in refusalOf(): " + ((e && e.message) || e));
    log.debug("Leaving refusalOf(). Refused.");
    return e;
  }
  log.debug("Leaving refusalOf(). Not refused.");
  return null;
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await body(t);
  } finally {
    ['oid4vp.clientIdPrefix', 'oid4vp.x509DnsName', 'global.mode',
     'global.publicBaseUrl'].forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  t.log.info('=== 1. x509_san_dns ===');
  config.setOverride('oid4vp.clientIdPrefix', 'x509_san_dns');
  await verifier.prepareSignedClientId(fakeReq());
  const san = verifier.buildVpRequest(fakeReq(), { byReference: true });
  const sanCheck = walletCheck(san.requestObject, san.clientId);
  t.check(san.clientId === 'x509_san_dns:' + HOST,
          '1a. the Client Identifier is x509_san_dns: and the Response ' +
          'URI\'s host', san.clientId);
  t.check(sanCheck.header.typ === 'oauth-authz-req+jwt' &&
          sanCheck.header.x5c.length === 3 && !sanCheck.header.x5u &&
          sanCheck.signatureOk,
          '1b. the Request Object is ES256, typed, carries a three-' +
          'certificate x5c and no x5u, and verifies against the leaf',
          JSON.stringify(sanCheck.header).slice(0, 200));
  t.check(sanCheck.chainOk,
          '1c. the chain verifies link by link to the service Root, which ' +
          'it does not carry');
  t.check(sanCheck.idOk && sanCheck.dns.length === 1 &&
          sanCheck.claims.iss === san.clientId,
          '1d. the leaf\'s one dNSName is the Client Identifier and the ' +
          'Response URI\'s host', sanCheck.dns.join(','));
  t.check(!sanCheck.leaf.ca && /digital/i.test(JSON.stringify(
            sanCheck.leaf.keyUsage || ['digitalSignature'])) &&
          !(sanCheck.leaf.keyUsage || []).some(function (u) {
            return /serverAuth|1\.3\.6\.1\.5\.5\.7\.3\.1/.test(u);
          }),
          '1e. the leaf is no CA and carries no TLS server usage');

  t.log.info('=== 2. x509_hash ===');
  config.setOverride('oid4vp.clientIdPrefix', 'x509_hash');
  await verifier.prepareSignedClientId(fakeReq());
  const hashed = verifier.buildVpRequest(fakeReq(), { byReference: true });
  const hashCheck = walletCheck(hashed.requestObject, hashed.clientId);
  t.check(hashed.clientId === 'x509_hash:' + hashCheck.hash &&
          hashCheck.idOk && hashCheck.signatureOk && hashCheck.chainOk,
          '2a. x509_hash: the base64url SHA-256 of the leaf\'s DER, signed ' +
          'and chained as before', hashed.clientId);
  t.check(hashCheck.hash === sanCheck.hash,
          '2b. one certificate answers both prefixes for one name');

  t.log.info('=== 3. per request ===');
  config.setOverride('oid4vp.clientIdPrefix', 'pre-registered');
  const perRequest = verifier.buildVpRequest(fakeReq(),
    { byReference: true, clientIdPrefix: 'x509_san_dns' });
  const plain = verifier.buildVpRequest(fakeReq(), { byReference: true });
  t.check(perRequest.clientId === san.clientId &&
          partOf(perRequest.requestObject, 0).x5c &&
          plain.clientId === String(config.value('oid4vp.clientId')) &&
          !partOf(plain.requestObject, 0).x5c &&
          verifier.clientIdPrefixFor('no-such-prefix') === 'pre-registered',
          '3a. a request names its own prefix over the realm\'s; an unknown ' +
          'one is the realm\'s');

  t.log.info('=== 4. issued once, over this key ===');
  const again = await pki.certifyVerifierKey(undefined, {
    dnsName: HOST, alg: 'ES256',
    publicKeyPem: sanCheck.leaf.publicKey.export({ type: 'spki',
                                                   format: 'pem' }) });
  const stranger = nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'P-256' }).publicKey.export({ type: 'spki',
                                                format: 'pem' });
  t.check(again.ok && again.issued === false &&
          again.certificate.serialHex.toLowerCase() ===
            sanCheck.leaf.serialNumber.toLowerCase() &&
          pki.verifierCertificateFor(undefined, HOST, stranger) === null,
          '4a. asked again, the same certificate; asked for another key, ' +
          'none', JSON.stringify(again).slice(0, 200));

  t.log.info('=== 5. refusals ===');
  config.setOverride('oid4vp.x509DnsName', 'other.test');
  let refused = await refusalOf(function () {
    return verifier.prepareSignedClientId(fakeReq(), 'x509_san_dns');
  });
  t.check(refused && refused.code === 'STS-VC-0111',
          '5a. a configured name that is not the Response URI\'s host is ' +
          'refused before anything is certified',
          refused && refused.message);
  config.clearOverride('oid4vp.x509DnsName');
  refused = await refusalOf(function () {
    return verifier.prepareSignedClientId(fakeReq('127.0.0.1:8081'),
                                          'x509_san_dns');
  });
  await verifier.prepareSignedClientId(fakeReq('127.0.0.1:8081'),
                                       'x509_hash');
  const nameless = verifier.x509Material(fakeReq('127.0.0.1:8081'),
                                         'x509_hash');
  const namelessLeaf = new nodeCrypto.X509Certificate(
    nameless.certificate.certificatePem);
  t.check(refused && refused.code === 'STS-VC-0111' &&
          /^x509_hash:/.test(nameless.clientId) &&
          !namelessLeaf.subjectAltName && nameless.dnsName === '',
          '5b. reached by an IP address: no x509_san_dns, and x509_hash ' +
          'signs under a certificate with no name');
  const wildcard = await pki.certifyVerifierKey(undefined, {
    dnsName: '*.sts.test', alg: 'ES256', publicKeyPem: stranger });
  t.check(!wildcard.ok && /wildcard/.test((wildcard.errors || []).join(' ')),
          '5c. a wildcard is refused (STS-PKI-0204)', JSON.stringify(
            wildcard));
  const made = [];
  let limit = null;
  for (let i = 0; i <= pki.MAX_VERIFIER_CERTIFICATES; i++) {
    const one = await pki.certifyVerifierKey(undefined, {
      dnsName: 'n' + i + '.limit.test', alg: 'ES256',
      publicKeyPem: stranger });
    if (!one.ok) {
      limit = one;
      break;
    }
    made.push(one);
  }
  t.check(limit && /the most it keeps/.test((limit.errors || []).join(' ')) &&
          made.length < pki.MAX_VERIFIER_CERTIFICATES + 1,
          '5d. a realm keeps at most ' + pki.MAX_VERIFIER_CERTIFICATES +
          ' Verifier certificates (STS-PKI-0205)', made.length + ' made');
  // A realm with no key for the algorithm: every algorithm the setting may
  // name has a key in a realm's set, so the key lookup is what is replaced.
  const keyless = new verifier.VcVerifier(Object.assign(
    verifier.VcVerifier.defaultDeps(), {
      ownPublicKeyFor: function () {
        throw new Error('this realm holds no key for "ES256".');
      } }));
  refused = await refusalOf(function () {
    return keyless.prepareSignedClientId(fakeReq(), 'x509_hash');
  });
  t.check(refused && refused.code === 'STS-VC-0113',
          '5e. an algorithm the realm holds no key for signs nothing');

  t.log.info('=== 6. product mode ===');
  config.setOverride('global.mode', 'product');
  const fromHost = verifier.x509DnsNameFor(fakeReq());
  config.setOverride('oid4vp.x509DnsName', HOST);
  const configured = verifier.x509DnsNameFor(fakeReq());
  config.clearOverride('oid4vp.x509DnsName');
  config.setOverride('global.publicBaseUrl', 'https://' + HOST);
  const pinned = verifier.x509DnsNameFor(fakeReq('evil.test'));
  config.clearOverride('global.publicBaseUrl');
  config.clearOverride('global.mode');
  t.check(fromHost.code === 'STS-VC-0110' && !fromHost.name &&
          configured.name === HOST && pinned.name === HOST,
          '6a. product: never the Host header; the configured name, or ' +
          'the pinned base URL\'s host (whatever Host a request carried)',
          JSON.stringify([fromHost, configured, pinned]));

  t.log.info('=== 7. a renewal keeps the name ===');
  const before = pki.verifierCertificateFor(undefined, HOST);
  await pki.recertifyUseCase('', 'jose');
  const after = pki.verifierCertificateFor(undefined, HOST);
  const renewed = after ? new nodeCrypto.X509Certificate(
    after.certificatePem) : null;
  t.check(before && after && after.serialHex !== before.serialHex &&
          renewed && /DNS:sts\.test/.test(renewed.subjectAltName || ''),
          '7a. renewed by the JOSE Issuing CA, the certificate keeps its ' +
          'dNSName', renewed && renewed.subjectAltName);

  t.log.info('=== 8. the Digital Credentials API request ===');
  config.setOverride('oid4vp.clientIdPrefix', 'x509_san_dns');
  const signIn = verifier.buildVpRequest(fakeReq(), {
    signIn: { authnId: 'x509-test', bindingHash: 'h', completePath: '/x',
              ttlMs: 60000, crossDevice: false, issuerDids: [],
              dcApiOrigin: 'https://' + HOST } });
  const dcHeader = partOf(signIn.signIn.dcApi.request, 0);
  const dcClaims = partOf(signIn.signIn.dcApi.request, 1);
  t.check(dcHeader.x5c && dcHeader.x5c[0] ===
            partOf(signIn.requestObject, 0).x5c[0] &&
          dcClaims.client_id === 'x509_san_dns:' + HOST &&
          dcHeader.alg === 'ES256',
          '8a. the sign-in\'s DC API request is signed under the same ' +
          'certificate and Client Identifier');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'oid4vp_x509_client_id',
  describe: 'OpenID4VP x509_san_dns and x509_hash (#230): the Verifier\'s ' +
            'certificate, x5c, both Client Identifiers, per request, the ' +
            'refusals, product mode and renewal',
  run: run
};
