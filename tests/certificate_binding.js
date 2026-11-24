// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: certificate_binding.js
//
// ---------------------------------------------------------------------------
// PIV SIGN-IN (#2012), in process, over certificates made at run time:
//
//   1. THE PROFILES: `certSignIn.profiles` held to its shape; a name method
//      refused without `lowAffinity`.
//   2. THE STORED GRAMMAR: `stsCertificateBinding` values canonicalised.
//   3. THE PROFILE: covered by an issuer in the validated path; keyUsage,
//      extendedKeyUsage and the policies RFC 5280 policy processing carries
//      — a Federal-PKI-style MAPPING accepted, an unmapped policy (a card
//      authentication certificate's) refused.
//   4. THE BINDINGS: none, one, two methods disagreeing, one method naming
//      two people; a second certificate with the same UPN and no
//      high-affinity binding refused, and accepted only under a low-affinity
//      profile; renewal under the same key carries spki-sha256 and not
//      issuer-serial.
//   5. REVOCATION AT SIGN-IN: `certSignIn.requireRevocation`.
//   6. RFC 9440: the two headers parsed, the trusted proxy by certificate AND
//      address, the socket's view, the headers removed from anybody else;
//      and the proxy pinned by its KEY (`spki:<hex>`, rcbj 2026-11-23): a
//      renewal under the same key matching the key pin and not the
//      certificate pin, a malformed entry refused at the write
//      (STS-TLS-0077), and the pin inventory's rows.
//   7. THE HANDOFF: offered and reused, refused unknown or for another
//      browser, presented, consumed once, never for another browser.
//   8. THE DIRECTORY: `stsCertificateBinding` canonicalised and held unique
//      on every write, found by value and by UPN; a covered certificate
//      resolved end to end by `tls_client_certificates.storedIdentityOf()`;
//      a stored certificate whose card UUID another person holds refused.
//
// Over HTTP, with a real handshake and listener, is owed: nothing here
// binds a socket (tests/CLAUDE.md, *What has no test*).
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const config = require('../common/config');
const realms = require('../common/realms');
const pki = require('../common/pki');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
// The directory at load, as `tests/piv_attestation.js` requires it: loaded
// first from inside a run, its TLS module's startup check found
// `tls.createSecureContext` missing under the runner.
const ldap = require('../ldap/ldap_server');
const binding = require('../common/certificate_binding');
const forwarded = require('../common/forwarded_client_certificate');
const handoffModule = require('../tls/certificate_handoff');
const kit = require('./webauthn_attestation_kit');
const pkivia = require('./piv_attestation_kit');

const log = require('bunyan').createLogger({ name: 'certificate_binding',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const P_FED = '2.16.840.1.101.3.2.1.3.13';
const P_AGENCY = '1.3.6.1.4.1.67607.99.1.1';
const P_CARD_AUTH = '1.3.6.1.4.1.67607.99.1.2';
const P_OTHER = '1.3.6.1.4.1.67607.99.1.3';
const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
const OVERRIDDEN = ['certSignIn.profiles', 'certSignIn.requireRevocation',
                    'certSignIn.handoff', 'piv.externalIssuers'];

function code(answer) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return errorCodes.codeOf(answer) || '';
}

function ab(bytes) {
  log.debug("Entering ab().");
  log.debug("Leaving ab().");
  return Uint8Array.from(Buffer.from(bytes)).buffer;
}

function oidSequence(oids) {
  log.debug("Entering oidSequence().");
  log.debug("Leaving oidSequence().");
  return new asn1js.Sequence({ value: oids.map(function (oid) {
    return new asn1js.ObjectIdentifier({ value: oid });
  }) }).toBER(false);
}

function policies(oids) {
  log.debug("Entering policies().");
  log.debug("Leaving policies().");
  return kit.extension('2.5.29.32', false, new pkijs.CertificatePolicies({
    certificatePolicies: oids.map(function (oid) {
      return new pkijs.PolicyInformation({ policyIdentifier: oid });
    }) }).toSchema().toBER(false));
}

// A subjectAltName with a UPN (otherName) and an rfc822Name.
function names(upn, email) {
  log.debug("Entering names().");
  const value = [];
  if (upn) {
    value.push(new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 },
      value: [new asn1js.ObjectIdentifier({ value: '1.3.6.1.4.1.311.20.2.3' }),
              new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 },
                value: [new asn1js.Utf8String({ value: upn })] })] }));
  }
  if (email) {
    value.push(new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 1 },
                                      valueHex: ab(email) }));
  }
  log.debug("Leaving names().");
  return kit.extension('2.5.29.17', false,
                       new asn1js.Sequence({ value: value }).toBER(false));
}

// A path in the Federal PKI's shape: a root (the anchor), an intermediate
// asserting P_FED and mapping it to P_AGENCY, and leaves under the agency's
// policy.
async function hierarchy() {
  log.debug("Entering hierarchy().");
  const root = await kit.root('Test Federal ' + RUN, 'ec');
  const pair = await kit.keyPair('ec');
  const mapping = new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [
    new asn1js.ObjectIdentifier({ value: P_FED }),
    new asn1js.ObjectIdentifier({ value: P_AGENCY })] })] }).toBER(false);
  const intermediate = await kit.certificate({
    subject: [['2.5.4.3', 'Test Agency CA ' + RUN]],
    publicKey: pair.crypto.publicKey, issuer: root, ca: true,
    extensions: [policies([P_FED]),
                 kit.extension('2.5.29.33', false, mapping)] });
  intermediate.signingKey = pair.crypto.privateKey;
  log.debug("Leaving hierarchy().");
  return { root: root, intermediate: intermediate };
}

async function leaf(issuer, o) {
  log.debug("Entering leaf().");
  const pair = o.pair || await kit.keyPair('ec');
  const ext = [
    kit.extension('2.5.29.15', true, new asn1js.BitString({
      valueHex: new Uint8Array([0x80]).buffer, unusedBits: 7 }).toBER(false)),
    kit.extension('2.5.29.37', false, oidSequence(o.eku || [CLIENT_AUTH])),
    policies(o.policies || [P_AGENCY])
  ];
  // An empty subjectAltName is malformed (RFC 5280 4.2.1.6): none at all.
  if (o.upn || o.email) {
    ext.push(names(o.upn || '', o.email || ''));
  }
  if (o.ski !== false) {
    ext.push(kit.extension('2.5.29.14', false, new asn1js.OctetString({
      valueHex: ab(nodeCrypto.randomBytes(20)) }).toBER(false)));
  }
  const made = await kit.certificate({ subject: [['2.5.4.3', o.cn ||
    'SMITH.JANE.' + RUN]], publicKey: pair.crypto.publicKey, issuer: issuer,
                                       extensions: ext });
  made.pair = pair;
  log.debug("Leaving leaf().");
  return made;
}

// A CertificateBinding over a settings stub and a directory stub.
function boundOver(values, directory, product) {
  log.debug("Entering boundOver().");
  const deps = Object.assign(binding.CertificateBinding.defaultDeps(), {
    config: { value: function (key) {
      return values[key];
    } },
    mode: { refusesUnknownRevocationStatus: function () {
      return !!product;
    } },
    loadEnrollment: function () {
      return directory;
    }
  });
  log.debug("Leaving boundOver().");
  return new binding.CertificateBinding(deps);
}

function directoryStub() {
  log.debug("Entering directoryStub().");
  const byKey = new Map();
  const holder = function (id) {
    return { kind: 'person', id: id, dn: 'uid=' + id + ',ou=users,dc=t' };
  };
  const out = {
    hold: function (kind, value, id) {
      const k = kind + '|' + value;
      byKey.set(k, (byKey.get(k) || []).concat([holder(id)]));
    },
    certificateHolders: function (sha) {
      return byKey.get('stored|' + sha) || [];
    },
    pivCardHolders: function (uuid) {
      return byKey.get('card|' + uuid) || [];
    },
    certificateBindingHolders: function (kind, value) {
      return byKey.get(kind + '|' + value) || [];
    }
  };
  log.debug("Leaving directoryStub().");
  return out;
}

function checkProfiles(t) {
  log.debug("Entering checkProfiles().");
  t.log.info('=== 1. the profiles ===');
  const key = 'a'.repeat(64);
  t.check(binding.profilesProblem({}) !== '',
          '1a. a value that is not an array is refused');
  t.check(binding.profilesProblem([{ id: 'p', issuers: [key],
    bindings: ['upn'] }]).indexOf('lowAffinity') >= 0,
          '1b. a name method without lowAffinity is refused (rcbj\'s ' +
          'decision on #2012)');
  t.equal(binding.profilesProblem([{ id: 'p', issuers: [key],
    bindings: ['upn'], lowAffinity: true }]), '',
          '1c. with lowAffinity true it is taken');
  t.check(binding.profilesProblem([{ id: 'p', issuers: ['nope'] }]) !== '',
          '1d. an issuer that is not a SHA-256 is refused');
  t.check(binding.profilesProblem([{ id: 'p', issuers: [key],
    keyUsage: ['signEverything'] }]) !== '', '1e. an unknown keyUsage name ' +
          'is refused');
  t.check(binding.profilesProblem([{ id: 'p', issuers: [key] },
    { id: 'p', issuers: [key] }]) !== '', '1f. two profiles of one id are ' +
          'refused');
  const rule = binding.CertificateBinding.writeRule('certSignIn.profiles',
                                                    '[{"id":"x"}]');
  t.check(rule && rule.code === 'STS-TLS-0065',
          '1g. the write rule refuses a malformed value with STS-TLS-0065',
          JSON.stringify(rule));
  t.check(binding.CertificateBinding.writeRule('certSignIn.profiles', '') ===
          null, '1h. empty is the service as it was, and taken');
  log.debug("Leaving checkProfiles().");
}

function checkGrammar(t) {
  log.debug("Entering checkGrammar().");
  t.log.info('=== 2. the stored grammar ===');
  const key = 'AB'.repeat(32);
  t.equal(binding.bindingValueOf('Issuer-Serial:' + key + ':00:0A:1b'),
          'issuer-serial:' + 'ab'.repeat(32) + ':a1b',
          '2a. hex lower-cased, colons out of the serial, leading zeros off');
  t.equal(binding.bindingValueOf('subject:CN = Jane Smith , O=Agency'),
          'subject:cn=jane smith,o=agency', '2b. a DN trimmed and lower-cased');
  t.equal(binding.bindingValueOf('spki-sha256:' + key),
          'spki-sha256:' + 'ab'.repeat(32), '2c. a digest');
  t.equal(binding.bindingValueOf('upn:jane@example.com'), '',
          '2d. upn is not a stored method');
  t.equal(binding.bindingValueOf('issuer-ski:nothex:01'), '',
          '2e. an issuer that is not a digest is no binding');
  log.debug("Leaving checkGrammar().");
}

async function checkProfile(t, h) {
  log.debug("Entering checkProfile().");
  t.log.info('=== 3. the profile ===');
  const rootKey = stsCrypto.certificateFacts(h.root.der).spkiSha256;
  const chain = [h.intermediate.der, h.root.der];
  const profile = { id: 'fpki', issuers: [rootKey],
    keyUsage: ['digitalSignature'], extendedKeyUsage: [CLIENT_AUTH],
    policies: [P_FED], bindings: ['issuer-serial', 'spki-sha256'] };
  const b = boundOver({ 'certSignIn.profiles': JSON.stringify([profile]) },
                      directoryStub());
  const jane = await leaf(h.intermediate, { upn: 'jane@agency.test' });
  t.check(b.profileFor(chain) && b.profileFor(chain).id === 'fpki',
          '3a. a root in the validated path covers the certificate');
  const other = await kit.root('Unrelated ' + RUN, 'ec');
  t.check(b.profileFor([other.der]) === null,
          '3b. a path without a listed issuer is not covered');
  t.equal(b.profileRefusal(b.profileFor(chain), jane.der, chain), '',
          '3c. the agency policy MAPPED to P_FED is accepted (RFC 5280 ' +
          'section 6.1 policy mapping)');
  const card = await leaf(h.intermediate, { policies: [P_CARD_AUTH] });
  t.check(/RFC 5280/.test(b.profileRefusal(b.profileFor(chain), card.der,
                                           chain)),
          '3d. a certificate under an unmapped policy (a card authentication ' +
          'certificate\'s) is outside the profile');
  const strict = boundOver({ 'certSignIn.profiles': JSON.stringify([
    Object.assign({}, profile, { policies: [P_OTHER] })]) }, directoryStub());
  t.check(strict.profileRefusal(strict.profileFor(chain), jane.der, chain) !==
          '', '3e. a profile asking another policy refuses it');
  const eku = boundOver({ 'certSignIn.profiles': JSON.stringify([
    Object.assign({}, profile, { extendedKeyUsage: ['1.3.6.1.5.5.7.3.4'] })]) },
    directoryStub());
  t.check(/extendedKeyUsage/.test(eku.profileRefusal(eku.profileFor(chain),
                                                    jane.der, chain)),
          '3f. a profile asking another purpose refuses it');
  // A FORGED LINK (the #2012 review): a certificate carrying the agency CA's
  // subject over another key, sent after the leaf. Only what signed counts,
  // so the path ends at the leaf and no profile covers it.
  const forgedPair = await kit.keyPair('ec');
  const forged = await kit.certificate({
    subject: [['2.5.4.3', 'Test Agency CA ' + RUN]],
    publicKey: forgedPair.crypto.publicKey,
    signingKey: forgedPair.crypto.privateKey, ca: true });
  t.equal(b.signedPath(jane.der, [forged.der, h.root.der]).length, 0,
          '3h. a link that did not sign the leaf ends the path');
  t.check(b.identityOf(jane.der, [forged.der, h.root.der], 'default') ===
          null, '3i. a forged intermediate cannot bring a certificate under ' +
          'a profile');
  t.equal(b.signedPath(jane.der, chain).length, 2,
          '3j. the real path verifies link by link');
  const outside = b.identityOf(card.der, chain, 'default');
  t.check(outside && outside.error === 'NOT_STORED' && outside.outsideProfile,
          '3g. a covered certificate outside its profile names nobody',
          JSON.stringify(outside));
  log.debug("Leaving checkProfile().");
  return { profile: profile, chain: chain, jane: jane, rootKey: rootKey };
}

async function checkBindings(t, h, p) {
  log.debug("Entering checkBindings().");
  t.log.info('=== 4. the bindings ===');
  const issuerKey = stsCrypto.certificateFacts(h.intermediate.der)
    .spkiSha256;
  const facts = stsCrypto.certificateFacts(p.jane.der);
  const serialKey = binding.bindingValueOf('issuer-serial:' + issuerKey +
                                           ':' + facts.serialHex);
  const spkiKey = 'spki-sha256:' + facts.spkiSha256;
  const values = { 'certSignIn.profiles': JSON.stringify([p.profile]) };
  const dir = directoryStub();
  const b = boundOver(values, dir);
  t.equal(b.identityOf(p.jane.der, p.chain, 'default').error, 'NOT_STORED',
          '4a. bound to nobody');
  dir.hold('binding', serialKey, 'jane');
  const one = b.identityOf(p.jane.der, p.chain, 'default');
  t.check(one.accepted && one.username === 'jane' &&
          one.methods.join() === 'issuer-serial',
          '4b. issuer and serial bind the one person', JSON.stringify(one));
  dir.hold('binding', spkiKey, 'jane');
  t.check(b.identityOf(p.jane.der, p.chain, 'default').methods.join() ===
          'issuer-serial,spki-sha256', '4c. two methods agreeing are one ' +
          'person');
  const split = directoryStub();
  split.hold('binding', serialKey, 'jane');
  split.hold('binding', spkiKey, 'bob');
  t.equal(boundOver(values, split).identityOf(p.jane.der, p.chain,
                                              'default').error,
          'STORED_TWICE', '4d. two methods naming different people name ' +
          'nobody');
  const twice = directoryStub();
  twice.hold('binding', serialKey, 'jane');
  twice.hold('binding', serialKey, 'bob');
  t.equal(boundOver(values, twice).identityOf(p.jane.der, p.chain,
                                              'default').error,
          'STORED_TWICE', '4e. one method naming two people names nobody');
  // A second certificate from the same CA with the same UPN, no
  // high-affinity binding.
  const upnDir = directoryStub();
  upnDir.hold('binding', serialKey, 'jane');
  upnDir.hold('upn', 'jane@agency.test', 'jane');
  const second = await leaf(h.intermediate, { upn: 'jane@agency.test' });
  t.equal(boundOver(values, upnDir).identityOf(second.der, p.chain,
                                               'default').error,
          'NOT_STORED', '4f. under the default high-affinity profile a ' +
          'second certificate with the same UPN signs nobody in');
  const low = boundOver({ 'certSignIn.profiles': JSON.stringify([
    Object.assign({}, p.profile, { bindings: ['issuer-serial', 'upn'],
                                   lowAffinity: true })]) }, upnDir);
  t.equal(low.identityOf(second.der, p.chain, 'default').error, 'NOT_STORED',
          '4g. a name is never a fallback: where the profile also names a ' +
          'high-affinity method, a UPN match alone signs nobody in');
  const namesOnly = boundOver({ 'certSignIn.profiles': JSON.stringify([
    Object.assign({}, p.profile, { bindings: ['upn'], lowAffinity: true })]) },
    upnDir);
  const byName = namesOnly.identityOf(second.der, p.chain, 'default');
  t.check(byName.accepted && byName.username === 'jane' && byName.lowAffinity,
          '4g-ii. under a names-only opted-in profile the unique UPN binds',
          JSON.stringify(byName));
  const pending = new binding.CertificateBinding(Object.assign(
    binding.CertificateBinding.defaultDeps(), {
      config: { value: function (key) {
        return key === 'certSignIn.profiles' ? JSON.stringify([Object.assign(
          {}, p.profile, { bindings: ['upn'], lowAffinity: true })]) : '';
      } },
      loadEnrollment: function () {
        return upnDir;
      },
      upnKeysComplete: function () {
        return false;
      } }));
  t.equal(pending.identityOf(second.der, p.chain, 'default').error,
          'NOT_STORED', '4g-iii. until the index backfill has finished, ' +
          'upn matches nobody');
  // Renewal: a new certificate over the same key.
  const renewed = await leaf(h.intermediate, { pair: p.jane.pair,
                                               upn: 'jane@agency.test' });
  const renewDir = directoryStub();
  renewDir.hold('binding', serialKey, 'jane');
  t.equal(boundOver(values, renewDir).identityOf(renewed.der, p.chain,
                                                 'default').error,
          'NOT_STORED', '4h. a renewed certificate is a new serial: ' +
          'issuer-serial must be bound again');
  renewDir.hold('binding', spkiKey, 'jane');
  t.equal(boundOver(values, renewDir).identityOf(renewed.der, p.chain,
                                                 'default').username,
          'jane', '4i. and spki-sha256 carries over under the same key');
  const byDigest = directoryStub();
  byDigest.hold('binding', 'certificate-sha256:' +
                stsCrypto.digest('sha256', p.jane.der, 'hex'), 'jane');
  const digestOnly = boundOver({ 'certSignIn.profiles': JSON.stringify([
    Object.assign({}, p.profile, { bindings: ['certificate-sha256'] })]) },
    byDigest);
  t.equal(digestOnly.identityOf(p.jane.der, p.chain, 'default').username,
          'jane', '4j. certificate-sha256 finds a stored binding as well as ' +
          'userCertificate');
  log.debug("Leaving checkBindings().");
}

function checkRevocation(t) {
  log.debug("Entering checkRevocation().");
  t.log.info('=== 5. revocation at sign-in ===');
  const on = boundOver({ 'certSignIn.requireRevocation': 'on' },
                       directoryStub(), false);
  t.equal(on.revocationRefusal({ status: 'good' }), '',
          '5a. a verified status signs in');
  t.check(on.revocationRefusal({ status: 'unknown', why: 'no answer' }) !==
          '', '5b. on: an unknown status soft-fail accepted is refused');
  t.check(on.revocationRefusal({ status: 'unchecked' }) !== '',
          '5c. on: a status not consulted is refused');
  t.check(on.revocationRefusal(null) !== '', '5d. on: no verdict is refused');
  t.equal(on.revocationRefusal({ status: 'revoked', refused: true }), '',
          '5e. a refused verdict is the revocation refusal\'s to report');
  const dev = boundOver({ 'certSignIn.requireRevocation': 'auto' },
                        directoryStub(), false);
  t.equal(dev.revocationRefusal({ status: 'unknown' }), '',
          '5f. auto in development leaves it to the revocation policy');
  const product = boundOver({ 'certSignIn.requireRevocation': 'auto' },
                            directoryStub(), true);
  t.check(product.revocationRefusal({ status: 'unknown' }) !== '',
          '5g. auto in product requires a verified status');
  log.debug("Leaving checkRevocation().");
}

async function checkForwarded(t, h, p) {
  log.debug("Entering checkForwarded().");
  t.log.info('=== 6. RFC 9440 ===');
  const b64 = p.jane.der.toString('base64');
  const parsed = forwarded.parse({ 'client-cert': ':' + b64 + ':',
    'client-cert-chain': ':' + h.intermediate.der.toString('base64') + ':' });
  t.check(parsed.leaf && parsed.leaf.equals(p.jane.der) &&
          parsed.chain.length === 1, '6a. Client-Cert and Client-Cert-Chain ' +
          'are read as RFC 8941 byte sequences');
  t.check(!!forwarded.parse({ 'client-cert': b64 }).problem,
          '6b. a Client-Cert that is not a byte sequence is refused');
  const proxy = await leaf(h.intermediate, {});
  const proxySha = stsCrypto.digest('sha256', proxy.der, 'hex');
  const make = function (values) {
    return new forwarded.ForwardedClientCertificate(Object.assign(
      forwarded.ForwardedClientCertificate.defaultDeps(), {
        config: { value: function (key) {
          return values[key] || '';
        } },
        anchors: function () {
          return [stsCrypto.parseCertificate(h.root.der)];
        }
      }));
  };
  const socketOf = function (der, address) {
    return { authorized: true, remoteAddress: address,
             getPeerCertificate: function () {
               return { raw: der };
             } };
  };
  const both = make({ 'tls.trustedProxyCertificates': proxySha,
                      'tls.trustedProxyAddresses': '10.9.0.0/16' });
  t.check(both.fromTrustedProxy({ socket: socketOf(proxy.der, '10.9.1.2') }),
          '6c. the proxy\'s certificate from its address is trusted');
  t.check(!both.fromTrustedProxy({ socket: socketOf(proxy.der,
                                                    '192.0.2.7') }),
          '6d. the proxy\'s certificate from another address is not');
  t.check(!both.fromTrustedProxy({ socket: socketOf(p.jane.der,
                                                    '10.9.1.2') }),
          '6e. another certificate from the proxy\'s address is not');
  const half = make({ 'tls.trustedProxyCertificates': proxySha });
  t.check(!half.fromTrustedProxy({ socket: socketOf(proxy.der, '10.9.1.2') }),
          '6f. a certificate without an address range trusts nobody');
  // AN SPKI PIN (rcbj, 2026-11-23: "accept both"). The key's digest is
  // computed here with node's own X509Certificate, not through the module.
  const spkiHex = function (der) {
    return nodeCrypto.createHash('sha256').update(
      new nodeCrypto.X509Certificate(der).publicKey
        .export({ type: 'spki', format: 'der' })).digest('hex');
  };
  const renewed = await leaf(h.intermediate, { pair: proxy.pair });
  const byKey = make({ 'tls.trustedProxyCertificates':
                         'spki:' + spkiHex(proxy.der),
                       'tls.trustedProxyAddresses': '10.9.0.0/16' });
  t.check(byKey.fromTrustedProxy({ socket: socketOf(proxy.der, '10.9.1.2') }),
          '6k. an spki: pin trusts the proxy\'s certificate by its key');
  t.check(!renewed.der.equals(proxy.der) &&
          byKey.fromTrustedProxy({ socket: socketOf(renewed.der,
                                                    '10.9.1.2') }),
          '6l. a certificate renewed under the same key still matches the ' +
          'spki: pin');
  t.check(!both.fromTrustedProxy({ socket: socketOf(renewed.der,
                                                    '10.9.1.2') }),
          '6m. the renewed certificate no longer matches the certificate pin');
  t.check(!byKey.fromTrustedProxy({ socket: socketOf(p.jane.der,
                                                     '10.9.1.2') }),
          '6n. a certificate under another key does not match the spki: pin');
  const colons = spkiHex(proxy.der).toUpperCase().match(/../g).join(':');
  const mixed = make({ 'tls.trustedProxyCertificates': 'sha256:' + proxySha +
                         ', SPKI:' + colons,
                       'tls.trustedProxyAddresses': '10.9.0.0/16' });
  const both2 = mixed.configured();
  t.check(both2.fingerprints.length === 1 && both2.keys.length === 1 &&
          mixed.fromTrustedProxy({ socket: socketOf(renewed.der,
                                                    '10.9.1.2') }),
          '6o. a certificate pin and a key pin listed together, the key ' +
          'pin in colon-separated upper-case hex', JSON.stringify(both2));
  const pinCode = function (value) {
    return config.checkWriteCode('tls.trustedProxyCertificates', value,
                                 false);
  };
  t.check(!pinCode('spki:' + spkiHex(proxy.der) + ',' + proxySha) &&
          !config.checkWrite('tls.trustedProxyCertificates',
                             'sha256:' + proxySha, false),
          '6p. a write of certificate and spki: pins is taken');
  t.check(['spki:', 'spki:' + proxySha.slice(2), 'deadbeef',
           'sha1:' + proxySha, proxySha + ',x'].every(function (bad) {
    return pinCode(bad) === 'STS-TLS-0077';
  }), '6q. a malformed entry is refused at the write (STS-TLS-0077)');
  config.setOverride('tls.trustedProxyCertificates',
                     proxySha + ',spki:' + colons);
  OVERRIDDEN.push('tls.trustedProxyCertificates');
  const pins = require('../common/certificate_pins').fromTrustedProxies();
  config.clearOverride('tls.trustedProxyCertificates');
  t.check(pins.length === 2 && pins[0].thumbprint === proxySha &&
          !/\(key\)/.test(pins[0].where) &&
          pins[1].thumbprint === 'spki:' + spkiHex(proxy.der) &&
          /#2 \(key\)$/.test(pins[1].where),
          '6r. the pin inventory lists a certificate pin as written and a ' +
          'key pin as spki:<hex>, marked (key)', JSON.stringify(pins));
  const verdict = await both.verify(parsed);
  t.check(verdict.ok && verdict.path.length === 3,
          '6g. the forwarded chain verifies to the client truststore',
          JSON.stringify(verdict.why || ''));
  const view = forwarded.viewOf(socketOf(proxy.der, '10.9.1.2'),
                                verdict.path, '');
  t.check(view.authorized === true && view.getPeerCertificate().raw
    .equals(p.jane.der) && view.getPeerCertificate(true).issuerCertificate
    .raw.equals(h.intermediate.der) && view.remoteAddress === '10.9.1.2',
          '6h. the request\'s view answers the forwarded certificate and the ' +
          'real socket for the rest');
  const stranger = await kit.root('Stranger ' + RUN, 'ec');
  const strangeLeaf = await leaf(stranger, {});
  t.check(!(await both.verify({ leaf: strangeLeaf.der, chain: [] })).ok,
          '6g-ii. a forwarded certificate from a root the truststore does not ' +
          'hold is refused');
  const serverOnly = await leaf(h.intermediate, { eku: ['1.3.6.1.5.5.7.3.1'] });
  const serverVerdict = await both.verify({ leaf: serverOnly.der,
                                            chain: [h.intermediate.der] });
  t.check(!serverVerdict.ok && /TLS client/.test(serverVerdict.why),
          '6g-iii. a serverAuth-only leaf is refused as a TLS client ' +
          'certificate', JSON.stringify(serverVerdict));
  t.check(!!forwarded.parse({ 'client-cert': ':AAAA:',
                              'client-cert-chain': ':%%%:' }).problem,
          '6g-iv. malformed bytes in the chain are refused');
  const none = forwarded.viewOf(socketOf(proxy.der, '10.9.1.2'), [], 'x');
  t.check(none.authorized === false && !none.getPeerCertificate().raw,
          '6i. a request from the proxy with no usable Client-Cert presents ' +
          'no certificate, never the proxy\'s own');
  const req = { headers: { 'client-cert': ':' + b64 + ':' },
                socket: socketOf(p.jane.der, '198.51.100.4'), url: '/x' };
  await new Promise(function (resolve) {
    both.middleware()(req, {}, resolve);
  });
  t.check(req.headers['client-cert'] === undefined &&
          req.socket.getPeerCertificate().raw.equals(p.jane.der),
          '6j. from anybody else the headers are removed and the socket left ' +
          'alone');
  log.debug("Leaving checkForwarded().");
}

async function checkHandoff(t) {
  log.debug("Entering checkHandoff().");
  t.log.info('=== 7. the handoff ===');
  const store = new Map();
  let presented = { ok: true, username: 'jane', credentialId: 'f',
                    serial: '01', amr: ['hwk', 'sc'], revocationSaid: 'good',
                    verificationFacts: {} };
  const ho = new handoffModule.CertificateHandoff(Object.assign(
    handoffModule.CertificateHandoff.defaultDeps(), {
      store: store,
      config: { value: function (key) {
        return key === 'certSignIn.handoff';
      } },
      helpers: Object.assign({}, require('../common/helpers'), {
        urlOf: function (req, path) {
          return 'https://cert.example.test' + path;
        } }),
      loadAuthn: function () {
        return { SESSION_COOKIE: 'sts_session',
                 cookieSession: function (req) {
                   return req.sid ? { id: req.sid } : null;
                 } };
      },
      loadTlsServer: function () {
        return { screenCertificateHolder: function () {
          return Promise.resolve(presented);
        } };
      }
    }));
  const offer = ho.offer({ sid: 'S1' }, 'P1', '');
  t.check(offer && /\/authn\/certificate\/continue\?h=/.test(offer.href),
          '7a. the screen is offered a link to the certificate listener');
  t.equal(ho.offer({ sid: 'S1' }, 'P1', offer.id).id, offer.id,
          '7b. a live handoff for the same sign-in and browser is reused');
  t.check(ho.offer({}, 'P1', '') === null,
          '7c. a browser with no session is offered none');
  const answer = function () {
    const res = { headers: {}, statusCode: 200, body: '', where: '',
      status: function (s) {
        this.statusCode = s;
        return this;
      },
      type: function () {
        return this;
      },
      set: function (h) {
        Object.assign(this.headers, h);
        return this;
      },
      send: function (b) {
        this.body = b;
        return this;
      },
      redirect: function (s, w) {
        this.statusCode = s;
        this.where = w;
      } };
    return res;
  };
  const unknown = answer();
  await ho.continueHandoff({ query: { h: 'x'.repeat(43) }, sid: 'S1' },
                           unknown);
  t.check(unknown.statusCode === 400 && code(unknown) === 'STS-TLS-0074',
          '7d. an unknown handoff is refused 400 (STS-TLS-0074)');
  const stranger = answer();
  await ho.continueHandoff({ query: { h: offer.id }, sid: 'S2' }, stranger);
  t.check(stranger.statusCode === 403 && code(stranger) === 'STS-TLS-0075',
          '7e. another browser\'s request is refused 403 (STS-TLS-0075)');
  const good = answer();
  await ho.continueHandoff({ query: { h: offer.id }, sid: 'S1' }, good);
  t.check(good.statusCode === 303 && /\/authn\/login\?authn=P1$/
    .test(good.where), '7f. the certificate is presented and the browser ' +
          'sent back to the screen', good.where);
  t.check(ho.resultFor({ sid: 'S2' }, 'P1', offer.id, false) === null,
          '7g. another browser cannot read it');
  t.check(ho.resultFor({ sid: 'S1' }, 'P2', offer.id, false) === null,
          '7h. another sign-in cannot use it');
  const held = ho.resultFor({ sid: 'S1' }, 'P1', offer.id, true);
  t.check(held && held.ok && held.username === 'jane' &&
          held.amr.join() === 'hwk,sc' &&
          typeof held.recordVerification === 'function',
          '7i. the act takes the holder, with what the key earned');
  t.check(ho.resultFor({ sid: 'S1' }, 'P1', offer.id, true) === null,
          '7j. once');
  const again = answer();
  await ho.continueHandoff({ query: { h: offer.id }, sid: 'S1' }, again);
  t.equal(again.statusCode, 400, '7k. a used handoff is not presented again');
  presented = { ok: false, code: 'STS-AUTHN-0468', why: 'not stored' };
  const second = ho.offer({ sid: 'S1' }, 'P1', offer.id);
  const refused = answer();
  await ho.continueHandoff({ query: { h: second.id }, sid: 'S1' }, refused);
  const what = ho.resultFor({ sid: 'S1' }, 'P1', second.id, false);
  t.check(refused.statusCode === 303 && what && !what.ok &&
          what.code === 'STS-AUTHN-0468', '7l. a refused certificate goes ' +
          'back to the screen with its refusal');
  log.debug("Leaving checkHandoff().");
}

async function checkDirectory(t, h, p) {
  log.debug("Entering checkDirectory().");
  t.log.info('=== 8. the directory ===');
  const editor = require('../ldap/person_editor');
  const tlsClient = require('../common/tls_client_certificates');
  const codec = require('../persistence/directory_codec');
  const jane = 'bind-jane-' + RUN;
  const bob = 'bind-bob-' + RUN;
  ldap.createUser(jane, { invent: false, attributes: {} });
  ldap.createUser(bob, { invent: false, attributes: {} });
  // userPrincipalName written onto the entry the way an ldapmodify would
  // (`tests/piv_attestation.js`'s holdCardUuid()).
  const janeEntry = ldap.existingUserEntry(jane);
  (janeEntry.stored || janeEntry).attributes.userprincipalname =
    ['Jane.' + RUN + '@Agency.Test'];
  const issuerKey = stsCrypto.certificateFacts(h.intermediate.der)
    .spkiSha256;
  const facts = stsCrypto.certificateFacts(p.jane.der);
  const value = 'Issuer-Serial:' + issuerKey.toUpperCase() + ':00' +
    facts.serialHex;
  const set = editor.update(jane, { attribute: 'stsCertificateBinding',
    mode: 'set', value: value }, { actor: 'test', via: 'test' });
  const entry = ldap.existingUserEntry(jane);
  const held = (((entry && (entry.stored || entry)) || {}).attributes || {})
    .stscertificatebinding || [];
  const canonical = binding.bindingValueOf(value);
  t.check(set.ok && held.length === 1 && held[0] === canonical,
          '8a. the editor stores a binding canonicalised',
          JSON.stringify([set.errors, held]));
  t.equal(code(editor.update(bob, { attribute: 'stsCertificateBinding',
    mode: 'set', value: canonical }, { actor: 'test', via: 'test' })),
          'STS-TLS-0070', '8b. a second person given the same binding is ' +
          'refused');
  t.equal(code(editor.update(bob, { attribute: 'stsCertificateBinding',
    mode: 'set', value: 'serial:42' }, { actor: 'test', via: 'test' })),
          'STS-TLS-0069', '8c. a value outside the grammar is refused');
  const found = ldap.certificateBindingHolders('binding', canonical);
  t.check(found.length === 1 && found[0].id === jane,
          '8d. the binding finds its holder');
  const byUpn = ldap.certificateBindingHolders('upn',
                                               'jane.' + RUN + '@agency.test');
  t.check(byUpn.length === 1 && byUpn[0].id === jane,
          '8e. a UPN finds its holder ignoring case');
  const keys = codec.certificateBindingKeysOf({
    stscertificatebinding: [canonical], userprincipalname: ['A@B.C'] });
  t.check(keys.indexOf(canonical) >= 0 && keys.indexOf('upn:a@b.c') >= 0,
          '8f. the codec keys both under certificatebinding');
  config.setOverride('certSignIn.profiles', JSON.stringify([p.profile]));
  const resolved = tlsClient.storedIdentityOf(p.jane.der, realms.currentId(),
                                              p.chain);
  t.check(resolved.accepted && resolved.username === jane &&
          resolved.profile === 'fpki',
          '8g. a covered certificate resolves end to end through the ' +
          'directory', JSON.stringify(resolved));
  config.clearOverride('certSignIn.profiles');
  const legacy = tlsClient.storedIdentityOf(p.jane.der, realms.currentId(),
                                            p.chain);
  t.equal(legacy.error, 'NOT_STORED', '8h. with no profile the #1061 rule ' +
          'answers as before: not stored in userCertificate, nobody');
  // A certificate stored on one person whose card UUID another holds.
  const uuid = nodeCrypto.randomUUID();
  const card = await pkivia.outsideCard({ uuids: [uuid], policies: [P_FED],
                                          cn: bob });
  config.setOverride('piv.externalIssuers', card.issuerPem);
  ldap.changeStoredCertificate('person', jane, { add: card.leafDer });
  const bobEntry = ldap.existingUserEntry(bob);
  (bobEntry.stored || bobEntry).attributes.stspivcarduuid = [uuid];
  const split = tlsClient.storedIdentityOf(card.leafDer, realms.currentId());
  t.equal(split.error, 'STORED_TWICE', '8i. stored on one person and naming ' +
          'a card UUID another holds, it names nobody (#2012)');
  config.clearOverride('piv.externalIssuers');
  log.debug("Leaving checkDirectory().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    if (!pki.hasRoot()) {
      await pki.start({});
    }
    await pki.ensureScope(realms.currentId());
    checkProfiles(t);
    checkGrammar(t);
    const h = await hierarchy();
    const p = await checkProfile(t, h);
    await checkBindings(t, h, p);
    checkRevocation(t);
    await checkForwarded(t, h, p);
    await checkHandoff(t);
    await checkDirectory(t, h, p);
  } finally {
    OVERRIDDEN.forEach(function (k) {
      config.clearOverride(k);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'certificate_binding',
  describe: '#2012: certificate sign-in profiles and bindings, revocation ' +
            'at sign-in, RFC 9440 from a named proxy, the certificate ' +
            'handoff, and stsCertificateBinding in the directory',
  run: run
};
