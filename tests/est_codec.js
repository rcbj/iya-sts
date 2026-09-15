'use strict';
//
// File: est_codec.js
//
// ===========================================================================
// THE FOUR WIRE SHAPES EST ADDS, READ BACK BY A SECOND IMPLEMENTATION
// (2026-09-13).
//
// `est/est_codec.js` writes a request-body decoder, a certs-only CMS message, a
// CSR attributes document and a multipart/mixed response by hand, in DER it
// encodes itself. Every claim here is checked by READING what it wrote with
// pkijs/asn1js or by hand — never with the codec — because a writer and a
// reader that are one implementation agree with each other whatever the RFC
// says (`tests/crypto_module.js`'s argument).
//
// WHY IN PROCESS: every input is chosen — a body that is base64 but not
// canonical, a certificate whose bytes a re-encoding would change (an ML-DSA
// key), a boundary — and none of that needs a service. The protocol half is
// `tests/vendored/sts_est_enrollment.js`.
//
// **THE CERTIFICATES MUST SURVIVE BYTE FOR BYTE**, which is the decision the
// codec's header argues against pkijs's re-encoding, so it is asserted with an
// ML-DSA certificate as well as an EC one: a post-quantum key is the case a
// library reading the key as opaque is likeliest to re-encode differently.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const path = require('path');
const asn1js = require('asn1js');
const pkijs = require('pkijs');

const log = require('bunyan').createLogger({ name: 'est_codec',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function ab(buf) {
  log.debug("Entering ab().");
  const b = Buffer.from(buf);
  log.debug("Leaving ab().");
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function pemDer(pem) {
  log.debug("Entering pemDer().");
  log.debug("Leaving pemDer().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
}

async function certificatePem(x509, keys, alg, name) {
  log.debug("Entering certificatePem(). " + alg);
  const pair = await keys.generateKeyPair(alg);
  const cert = await x509.issueCertificate({
    subject: [{ name: 'CN', value: name }],
    subjectPublicKey: pair.publicPem,
    signatureAlg: x509.defaultSignatureAlgorithm(
      await keys.describePublicPem(pair.publicPem)),
    profile: 'root-ca',
    issuer: { privateKeyPem: pair.privatePem, keyAlg: alg },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] }
    }
  });
  log.debug("Leaving certificatePem().");
  return cert.pem;
}

async function run(t) {
  log.debug("Entering run().");
  const codec = require(path.join(ROOT, 'est', 'est_codec'));
  const x509 = require(path.join(ROOT, 'common', 'vendored', 'x509'));
  const keys = require(path.join(ROOT, 'common', 'vendored', 'key_material'));

  t.log.info('=== a request body (RFC 8951 section 3) ===');
  const der = nodeCrypto.randomBytes(200);
  const wrapped = der.toString('base64').replace(/(.{64})/g, '$1\r\n') +
                  '\r\n';
  const decoded = codec.decodeBody(Buffer.from(wrapped, 'latin1'));
  t.check(decoded.ok && decoded.der.equals(der),
          'base64 wrapped at 64 characters with CRLF decodes to the DER sent');
  const spaced = codec.decodeBody(Buffer.from(' ' + der.toString('base64')
    .split('').join('\t') + ' \n', 'latin1'));
  t.check(spaced.ok && spaced.der.equals(der),
          'spaces and tabs anywhere are tolerated');
  t.check(!codec.decodeBody(Buffer.from('QUJD@EFG', 'latin1')).ok,
          'a character outside the alphabet is refused',
          JSON.stringify(codec.decodeBody(Buffer.from('QUJD@EFG'))));
  t.check(!codec.decodeBody(Buffer.from('QUJDR', 'latin1')).ok,
          'a length that is not a multiple of four is refused');
  t.check(!codec.decodeBody(Buffer.from('QR==', 'latin1')).ok,
          'NON-CANONICAL base64 (non-zero bits before the padding) is refused',
          'QR== decodes leniently to "A"; only a strict reader refuses it');
  t.check(!codec.decodeBody(Buffer.from('-----BEGIN CERTIFICATE REQUEST-----' +
                                        '\nQUJD\n-----END CERTIFICATE ' +
                                        'REQUEST-----', 'latin1')).ok,
          'a PEM body is refused rather than having its headers skipped');
  t.check(!codec.decodeBody(Buffer.alloc(0)).ok &&
          !codec.decodeBody(Buffer.from(' \r\n')).ok,
          'an empty body, or one of whitespace only, is refused');

  t.log.info('=== OIDs ===');
  t.equal(codec.oid('1.2.840.113549.1.7.2').toString('hex'),
          '06092a864886f70d010702', 'id-signedData encodes as RFC 5652 lists');
  t.equal(codec.oid('2.16.840.1.101.3.4.3.17').toString('hex'),
          '06096086480165030403 11'.replace(/ /g, ''),
          'ML-DSA-44 encodes as its registry entry');

  t.log.info('=== a certs-only message (RFC 5652 section 5) ===');
  const ecPem = await certificatePem(x509, keys, 'ec-p256', 'EST codec EC');
  const pqPem = await certificatePem(x509, keys, 'ml-dsa-44',
                                     'EST codec ML-DSA');
  const message = codec.certsOnly([ecPem, pqPem]);
  const info = new pkijs.ContentInfo({ schema: asn1js.fromBER(ab(message))
    .result });
  t.equal(info.contentType, '1.2.840.113549.1.7.2',
          'the ContentInfo is id-signedData');
  const signed = new pkijs.SignedData({ schema: info.content });
  t.equal(signed.version, 1, 'SignedData version 1');
  t.equal(signed.encapContentInfo.eContentType, '1.2.840.113549.1.7.1',
          'the encapsulated content type is id-data, with no content');
  t.check(!signed.encapContentInfo.eContent,
          'and there is no content');
  t.equal(signed.signerInfos.length, 0, 'there is no signer (certs-only)');
  t.equal(signed.digestAlgorithms.length, 0, 'and no digest algorithm');
  t.equal(signed.certificates.length, 2, 'both certificates are carried');
  // The raw bytes of each certificate, taken from the SET by hand, not by
  // re-encoding a parsed Certificate.
  const outer = asn1js.fromBER(ab(message)).result;
  const signedSeq = outer.valueBlock.value[1].valueBlock.value[0];
  const certSet = signedSeq.valueBlock.value.filter(function (one) {
    return one.idBlock.tagClass === 3 && one.idBlock.tagNumber === 0;
  })[0];
  const raw = certSet.valueBlock.value.map(function (one) {
    return Buffer.from(one.valueBeforeDecodeView);
  });
  t.check(raw[0].equals(pemDer(ecPem)),
          'the EC certificate is carried BYTE FOR BYTE');
  t.check(raw[1].equals(pemDer(pqPem)),
          'the ML-DSA certificate is carried BYTE FOR BYTE');
  t.check(new nodeCrypto.X509Certificate(ecPem).verify(
    new nodeCrypto.X509Certificate(Buffer.concat([raw[0]])).publicKey),
          'the carried EC certificate still verifies');
  t.equal(codec.certsOnly([]).length > 0 &&
          new pkijs.SignedData({ schema: new pkijs.ContentInfo({
            schema: asn1js.fromBER(ab(codec.certsOnly([]))).result })
            .content }).certificates.length, 0,
          'an empty list is still a well-formed certs-only message');

  t.log.info('=== CSR attributes (RFC 7030 section 4.5.2) ===');
  const attrs = codec.csrAttrs([
    { oid: '1.2.840.10045.4.3.2' },
    { oid: codec.OIDS.extensionRequest },
    { type: codec.OIDS.extKeyUsage, values: [{ oid: '1.3.6.1.5.5.7.3.1' }] },
    { type: codec.OIDS.subjectAltName, values: [{ utf8: 'dNSName' }] }
  ]);
  const parsedAttrs = asn1js.fromBER(ab(attrs));
  t.equal(parsedAttrs.offset, attrs.length,
          'the document is one complete DER value');
  const items = parsedAttrs.result.valueBlock.value;
  t.equal(items.length, 4, 'SEQUENCE OF four AttrOrOID');
  t.check(items[0] instanceof asn1js.ObjectIdentifier &&
          items[0].valueBlock.toString() === '1.2.840.10045.4.3.2',
          'a bare OID is an OBJECT IDENTIFIER');
  t.check(items[2] instanceof asn1js.Sequence &&
          items[2].valueBlock.value[0].valueBlock.toString() ===
            '2.5.29.37' &&
          items[2].valueBlock.value[1] instanceof asn1js.Set &&
          items[2].valueBlock.value[1].valueBlock.value[0].valueBlock
            .toString() === '1.3.6.1.5.5.7.3.1',
          'an Attribute is SEQUENCE { type, SET OF values }');
  t.check(items[3].valueBlock.value[1].valueBlock.value[0] instanceof
            asn1js.Utf8String &&
          items[3].valueBlock.value[1].valueBlock.value[0].valueBlock.value ===
            'dNSName', 'a text value is a UTF8String');

  t.log.info('=== multipart/mixed (RFC 7030 section 4.4.2) ===');
  const keyDer = nodeCrypto.randomBytes(300);
  const certDer = nodeCrypto.randomBytes(500);
  const multi = codec.multipartMixed([
    { contentType: 'application/pkcs8', der: keyDer },
    { contentType: 'application/pkcs7-mime; smime-type=certs-only',
      der: certDer }
  ]);
  const text = multi.body.toString('latin1');
  const pieces = text.split('--' + multi.boundary);
  t.equal(pieces.length, 4, 'two parts and a closing delimiter');
  t.check(/^--\r\n$/.test(pieces[3]),
          'the closing delimiter is boundary--');
  const first = pieces[1];
  t.check(/Content-Type: application\/pkcs8\r\n/.test(first) &&
          /Content-Transfer-Encoding: base64\r\n\r\n/.test(first),
          'each part carries its own Content-Type and ' +
          'Content-Transfer-Encoding: base64');
  const firstBody = first.slice(first.indexOf('\r\n\r\n') + 4)
    .replace(/\s+/g, '');
  t.check(Buffer.from(firstBody, 'base64').equals(keyDer),
          'the first part decodes to the key bytes');
  const secondBody = pieces[2].slice(pieces[2].indexOf('\r\n\r\n') + 4)
    .replace(/\s+/g, '');
  t.check(Buffer.from(secondBody, 'base64').equals(certDer),
          'the second part decodes to the certificate bytes');
  t.check(text.split(/\r\n/).every(function (line) {
    return line.length <= 76;
  }), 'no line is longer than RFC 2045 allows');
  t.check(codec.multipartMixed([]).boundary !== multi.boundary,
          'the boundary is random per response');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'est_codec',
  describe: 'EST\'s request-body decoder, certs-only CMS message, CSR ' +
            'attributes and multipart response, read back independently',
  run: run
};
