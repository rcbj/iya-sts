// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml_inclusive_prefixes.js
//
// ===========================================================================
// AN ENVELOPED SIGNATURE WHOSE EXCLUSIVE CANONICALIZATION CARRIES AN
// InclusiveNamespaces PrefixList, VERIFIED AS ITS SIGNER MADE IT.
//
// A SAML partner commonly signs an Assertion inside a Response with
// exclusive c14n and a PrefixList naming the prefixes its attribute values
// use only in TEXT (`xsi:type="xs:string"`): Shibboleth's and
// SimpleSAMLphp's `xs`. Exclusive c14n renders a listed prefix that is IN
// SCOPE, and here `xs` is declared on the Response, an ANCESTOR of the
// signed Assertion. `crypto.verifyXmlSignature()` serialized the Signature
// and the signed element each on its own, which dropped that declaration,
// so the octets differed from the signer's and the signature was refused —
// the defect #1917's WSS4J round trip found in the WS-Security verifiers.
// Asserted, with documents signed by the vendored engine IN PLACE (so its
// octets are the signer's):
//
//   A. the Assertion inside the Response, the PrefixList on SignedInfo's
//      CanonicalizationMethod and on the Reference's transform, verifies;
//   B. on SignedInfo alone, and on the Reference alone, each verifies;
//   C. without a PrefixList (the control) it verifies, as it always did;
//   D. the declaration the PrefixList renders is signed: the same document
//      with the Response's `xs` namespace changed is refused;
//   E. the Response itself signed the same way (no ancestor) verifies.
//   F. PYSAML2'S SHAPE (run 45298800947): the XML Signature prefix (`ns2`)
//      declared on the signed root, not on the Signature, exclusive c14n
//      with no PrefixList, signed in place as xmlsec1 signs it — an
//      AuthnRequest, an ArtifactResolve, and the same with `ds` and a
//      default namespace. #2020 copied the root's declarations onto the
//      Signature with `setAttribute()`, the serializer declared `ns2`
//      again, and every one was refused as "Attribute xmlns:ns2
//      redefined". Each verifies, and a changed Issuer is still refused.
// ===========================================================================

const crypto = require('../common/crypto');
const xmldsig = require('../common/crypto_impl/xmldsig.js');

const log = require('bunyan').createLogger({
  name: 'saml_inclusive_prefixes',
  level: process.env.LOG_LEVEL || 'info' });

const SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const XS = 'http://www.w3.org/2001/XMLSchema';
const XSI = 'http://www.w3.org/2001/XMLSchema-instance';
const EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

// One key pair and a self-signed certificate, made here.
function keys() {
  log.debug("Entering keys().");
  const forge = xmldsig.forge;
  const pair = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  cert.setSubject([{ name: 'commonName', value: 'saml-prefixes' }]);
  cert.setIssuer([{ name: 'commonName', value: 'saml-prefixes' }]);
  cert.sign(pair.privateKey, xmldsig.forge.md.sha256.create());
  log.debug("Leaving keys().");
  return { keyPem: forge.pki.privateKeyToPem(pair.privateKey),
           certPem: forge.pki.certificateToPem(cert) };
}

const ASSERTION = '<saml:Assertion xmlns:saml="' + SAML +
  '" xmlns:xs="' + XS + '" xmlns:xsi="' + XSI + '" ID="_a" Version="2.0" ' +
  'IssueInstant="2026-11-23T00:00:00Z">' +
  '<saml:Issuer>https://partner.example</saml:Issuer>' +
  '<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>' +
  '<saml:AttributeStatement><saml:Attribute Name="mail">' +
  '<saml:AttributeValue xsi:type="xs:string">alice@example.com' +
  '</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>' +
  '</saml:Assertion>';

function responseOpen(xsNamespace) {
  log.debug("Entering responseOpen().");
  log.debug("Leaving responseOpen().");
  return '<samlp:Response xmlns:samlp="' + SAMLP + '" xmlns:saml="' + SAML +
    '" xmlns:xs="' + (xsNamespace || XS) + '" xmlns:xsi="' + XSI +
    '" ID="_r" Version="2.0" IssueInstant="2026-11-23T00:00:00Z">' +
    '<saml:Issuer>https://partner.example</saml:Issuer>';
}

// `xml` signed by the vendored engine in place, enveloped, its root,
// exclusive c14n with `onSignedInfo` / `onReference` as the PrefixList
// where given.
function signed(xml, pair, onSignedInfo, onReference) {
  log.debug("Entering signed().");
  const out = xmldsig.signXml(xml, {
    mode: 'enveloped', keyInfo: 'x509', placement: 'after-issuer',
    privateKeyPem: pair.keyPem, certPem: pair.certPem,
    c14nAlg: EXC, c14nPrefixList: onSignedInfo || undefined,
    transforms: [{ algorithm: xmldsig.TRANSFORM_ENVELOPED },
                 { algorithm: EXC, prefixList: onReference || undefined }] });
  log.debug("Leaving signed().");
  return typeof out === 'string' ? out : out.xml;
}

// THE PARTNER'S SHAPE: the Assertion signed on its own, with `xs` and
// `xsi` declared on itself, and then put inside a Response that declares
// them, the Assertion's own declarations taken off. Exclusive c14n renders
// a listed prefix that is in scope on the apex either way, so what was
// signed is unchanged; only a verifier that drops the ancestors' sees a
// difference.
function nested(pair, onSignedInfo, onReference, xsNamespace) {
  log.debug("Entering nested().");
  const assertion = signed(ASSERTION, pair, onSignedInfo, onReference)
    .replace(' xmlns:xs="' + XS + '"', '')
    .replace(' xmlns:xsi="' + XSI + '"', '')
    .replace(' xmlns:saml="' + SAML + '"', '');
  log.debug("Leaving nested().");
  return responseOpen(xsNamespace) + assertion + '</samlp:Response>';
}

// PYSAML2'S SHAPE, SIGNED AS xmlsec1 SIGNS IT: the Signature in place,
// after the Issuer, its prefix `prefix` (none: a default namespace on the
// Signature itself) declared wherever `xml` declares it; the Reference's
// digest over the root's exclusive canonical form, and SignedInfo
// canonicalized IN PLACE, where every declaration of the root is in scope.
// Written by hand rather than by the vendored signer, which puts its own
// `xmlns:ds` on the Signature and so never makes this document.
function pysaml2Signed(xml, pair, prefix, after) {
  log.debug("Entering pysaml2Signed().");
  const forge = xmldsig.forge;
  const p = prefix ? prefix + ':' : '';
  const tag = function (name, attrs, body) {
    return '<' + p + name + (attrs || '') +
      (body === undefined ? '/>' : '>' + body + '</' + p + name + '>');
  };
  const parse = function (text) {
    return new DOMParser().parseFromString(text, 'text/xml');
  };
  const root = parse(xml).documentElement;
  const md = forge.md.sha256.create();
  md.update(xmldsig.canonicalize(root, {}), 'utf8');
  const digest = forge.util.encode64(md.digest().getBytes());
  const certB64 = pair.certPem.replace(/-----[^-]+-----|\s/g, '');
  const signedInfo = tag('SignedInfo', '',
    tag('CanonicalizationMethod', ' Algorithm="' + EXC + '"') +
    tag('SignatureMethod', ' Algorithm="' + RSA_SHA256 + '"') +
    tag('Reference', ' URI="#' + root.getAttribute('ID') + '"',
        tag('Transforms', '',
            tag('Transform', ' Algorithm="' +
                xmldsig.TRANSFORM_ENVELOPED + '"') +
            tag('Transform', ' Algorithm="' + EXC + '"')) +
        tag('DigestMethod', ' Algorithm="' + SHA256 + '"') +
        tag('DigestValue', '', digest)));
  const signature = tag('Signature',
    prefix ? '' : ' xmlns="' + DS + '"',
    signedInfo + tag('SignatureValue', '', 'SIGNATURE-VALUE') +
    tag('KeyInfo', '', tag('X509Data', '',
                           tag('X509Certificate', '', certB64))));
  const placed = xml.replace(after, after + signature);
  const si = parse(placed).getElementsByTagNameNS(DS, 'SignedInfo')[0];
  const siMd = forge.md.sha256.create();
  siMd.update(xmldsig.canonicalize(si, {}), 'utf8');
  const value = forge.util.encode64(
    forge.pki.privateKeyFromPem(pair.keyPem).sign(siMd));
  log.debug("Leaving pysaml2Signed().");
  return placed.replace('SIGNATURE-VALUE', value);
}

// Section F's documents: pysaml2's AuthnRequest and ArtifactResolve, with
// `ns0`, `ns1` and `ns2` all on the root, and two spellings of the same
// request with a default namespace.
function pysaml2Cases(t, pair, verify) {
  log.debug("Entering pysaml2Cases().");
  const issuer = '<ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:' +
    'nameid-format:entity">http://saml-pysaml2:8000/sp</ns1:Issuer>';
  const head = ' xmlns:ns0="' + SAMLP + '" xmlns:ns1="' + SAML +
    '" xmlns:ns2="' + DS + '" Version="2.0" ' +
    'IssueInstant="2026-11-24T02:49:06Z"';
  const authn = pysaml2Signed('<ns0:AuthnRequest' + head +
    ' ID="id-authn" AssertionConsumerServiceURL=' +
    '"http://saml-pysaml2:8000/acs/post" ProtocolBinding=' +
    '"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">' + issuer +
    '<ns0:NameIDPolicy AllowCreate="false"/></ns0:AuthnRequest>',
    pair, 'ns2', issuer);
  t.check(/<ns2:Signature>/.test(authn) &&
          !/<ns2:Signature [^>]*xmlns/.test(authn),
          'precondition: the Signature declares nothing; ns2 is the ' +
          'AuthnRequest\'s', authn.slice(0, 400));
  let r = verify(authn, 'AuthnRequest');
  t.check(r.ok, 'F. a pysaml2 AuthnRequest, ns2 declared on the root, ' +
          'verifies', r.why);
  r = verify(authn.replace('http://saml-pysaml2:8000/sp',
                           'http://saml-pysaml2:8000/other'),
             'AuthnRequest');
  t.check(!r.ok, 'F. and the same AuthnRequest with its Issuer changed is ' +
          'refused', JSON.stringify(r).slice(0, 300));
  const resolve = pysaml2Signed('<ns0:ArtifactResolve' + head +
    ' ID="id-resolve">' + issuer + '<ns0:Artifact>AAQAAA==</ns0:Artifact>' +
    '</ns0:ArtifactResolve>', pair, 'ns2', issuer);
  r = verify(resolve, 'ArtifactResolve');
  t.check(r.ok, 'F. a pysaml2 ArtifactResolve, ns2 declared on the root, ' +
          'verifies', r.why);
  const dflt = '<AuthnRequest xmlns="' + SAMLP + '" xmlns:ns1="' + SAML +
    '"DS Version="2.0" IssueInstant="2026-11-24T02:49:06Z" ID="id-d">' +
    issuer + '</AuthnRequest>';
  r = verify(pysaml2Signed(dflt.replace('DS', ''), pair, '', issuer),
             'AuthnRequest');
  t.check(r.ok, 'F. a default-namespace AuthnRequest, the Signature ' +
          'declaring its own default namespace, verifies', r.why);
  r = verify(pysaml2Signed(dflt.replace('DS', ' xmlns:ds="' + DS + '"'),
                           pair, 'ds', issuer), 'AuthnRequest');
  t.check(r.ok, 'F. a default-namespace AuthnRequest, ds declared on the ' +
          'root, verifies', r.why);
  log.debug("Leaving pysaml2Cases().");
}

function run(t) {
  log.debug("Entering run().");
  const pair = keys();
  const verify = function (xml, element) {
    return crypto.verifyXmlSignature(xml, { element: element,
                                            certPem: pair.certPem });
  };
  const both = nested(pair, 'xs', 'xs');
  t.check(/PrefixList="xs"/.test(both) &&
          !/<saml:Assertion[^>]*xmlns:xs=/.test(both),
          'precondition: the signature carries the PrefixList, and xs is ' +
          'declared on the Response only', both.slice(0, 700));
  let r = verify(both, 'Assertion');
  t.check(r.ok, 'A. an Assertion signed with PrefixList "xs" on SignedInfo ' +
          'and on its Reference, xs declared on the Response, verifies',
          r.why);
  r = verify(nested(pair, 'xs', ''), 'Assertion');
  t.check(r.ok, 'B. the PrefixList on SignedInfo alone verifies', r.why);
  r = verify(nested(pair, '', 'xs'), 'Assertion');
  t.check(r.ok, 'B. the PrefixList on the Reference alone verifies', r.why);
  r = verify(nested(pair, '', ''), 'Assertion');
  t.check(r.ok, 'C. without a PrefixList it verifies, as it always did',
          r.why);
  r = verify(nested(pair, 'xs', 'xs', 'urn:not-the-schema'), 'Assertion');
  t.check(!r.ok, 'D. the declaration the PrefixList renders is signed: ' +
          'the Response\'s xs changed is refused',
          JSON.stringify(r).slice(0, 300));
  const root = signed(responseOpen() + '<saml:Assertion ID="_x" ' +
    'Version="2.0" IssueInstant="2026-11-23T00:00:00Z"><saml:Issuer>' +
    'https://partner.example</saml:Issuer></saml:Assertion>' +
    '<x:V xmlns:x="urn:x" xsi:type="xs:string">v</x:V>' +
    '</samlp:Response>', pair, 'xs', 'xs');
  r = verify(root, 'Response');
  t.check(r.ok, 'E. a Response signed at its root with PrefixList "xs", ' +
          'xs declared on the Response, verifies', r.why);
  pysaml2Cases(t, pair, verify);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_inclusive_prefixes',
  describe: 'crypto.verifyXmlSignature(): an enveloped signature whose ' +
            'exclusive c14n names an InclusiveNamespaces PrefixList, the ' +
            'listed prefix declared on an ancestor, verifies as signed; and ' +
            'pysaml2\'s signature prefix declared on the signed root',
  run: run
};
