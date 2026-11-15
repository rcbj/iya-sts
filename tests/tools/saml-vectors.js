// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/saml-vectors.js
//
// ---------------------------------------------------------------------------
// SAML 2.0 AS AN IDENTITY PROVIDER, AS NODE BUILDS AND READS IT (#444, phase
// 7, the `saml` slice): the vectors `rust/crates/sts-saml/tests/
// saml_vectors.rs` reads, run by `crypto-vectors.js` (`saml-node.json`) in a
// child of its own.
//
//   signer      the realm's XML signer (key, certificate, KeyInfo chain,
//               algorithms), so Rust signs with the same key;
//   assertions  buildSamlAssertion() unsigned over a range of options, with
//               the ID and instants Node wrote, and signAssertion() over
//               each — RSA, so the same BYTES;
//   responses   statusElement() and buildResponse(), signed and not;
//   bindings    decodeMessage(), the inflated redirect encoding,
//               withoutEnvelopedSignature(), redirectUrlFor(),
//               simpleSignFields(), postBindingPage() and page();
//   requests    readAuthnRequest() over requests well and badly formed;
//   artifacts   mintArtifact() (the handle read back), isForeignArtifact(),
//               the row key and the row stashArtifact() writes.
//
// And `checkRust()`: what Rust built and signed, verified and read by Node.
// A builder is a tool, not service code, and logs nothing.
// ---------------------------------------------------------------------------

const path = require('path');
const zlib = require('zlib');

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const SP = 'https://sp.vectors.example/saml';
const ACS = 'https://sp.vectors.example/acs';

// A fake translator: each key and its values, so the Rust side can write
// the same strings into the page.
const T = {
  html: function (key, vars) {
    return '[' + key + (vars ? ' ' + JSON.stringify(vars) : '') + ']';
  }
};

function instantsOf(xml) {
  const pick = function (re) {
    const m = re.exec(xml);
    return m ? m[1] : '';
  };
  return {
    id: pick(/<saml:Assertion[^>]* ID="([^"]+)"/),
    now: pick(/<saml:Assertion[^>]* IssueInstant="([^"]+)"/),
    notBefore: pick(/<saml:Conditions NotBefore="([^"]+)"/),
    notOnOrAfter: pick(/<saml:Conditions[^>]* NotOnOrAfter="([^"]+)"/)
  };
}

function build(ROOT) {
  const helpers = require(path.join(ROOT, 'common', 'helpers.js'));
  const stsCrypto = require(path.join(ROOT, 'common', 'crypto.js'));
  const app = require(path.join(ROOT, 'common', 'app'));
  const realms = require(path.join(ROOT, 'common', 'realms'));
  require(path.join(ROOT, 'ldap', 'ldap_server'));
  const saml2 = require(path.join(ROOT, 'saml', 'saml2'));
  const stats = require(path.join(ROOT, 'common', 'admin_stats'));
  const documentSettings = require(path.join(ROOT, 'saml',
                                             'document_settings'));
  const sso = require(path.join(ROOT, 'saml', 'saml2_sso'));
  sso.registerRoutes(app);
  const direct = new sso.Saml2Sso(sso.Saml2Sso.defaultDeps());
  const STS = helpers.STS;
  const how = documentSettings.signatureOptions();
  const signer = {
    privateKeyPem: STS.xmlSigner.privateKeyPem,
    certPem: STS.xmlSigner.certPem,
    chainPem: STS.xmlSigner.certChainPem || [],
    keyInfoXml: helpers.xmlSignerKeyInfo(STS.xmlSigner),
    sigAlg: how.sigAlg, c14nAlg: how.c14nAlg,
    policy: require('./wssec-vectors.js').policyNow(ROOT)
  };

  // THE ASSERTIONS.
  const assertions = [];
  const one = function (name, subject, audience, lifetime, opts) {
    const xml = saml2.buildSamlAssertion(subject, audience, lifetime,
      Object.assign({ sign: false, issuer: 'https://idp.vectors.example' },
                    opts || {}));
    // The configured custom attributes (`stats.samlAttributes()`), which
    // the builder appends: an input to the Rust builder.
    const custom = stats.samlAttributes('saml2', { subject: subject,
                                                   audience: audience });
    assertions.push({ name: name, subject: subject, audience: audience || '',
                      opts: opts || {}, instants: instantsOf(xml),
                      custom: JSON.parse(JSON.stringify(custom)),
                      unsigned: xml, signed: saml2.signAssertion(xml) });
  };
  one('the defaults', 'alice', null, 60, {});
  one('an audience', 'alice', SP, 5, {});
  one('escapes', 'a<b&"c\'', SP + '?a=1&b=2', 5,
      { nameIdValue: '<x&y>' });
  one('the Web SSO profile', 'alice', SP, 5, {
    nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    nameIdValue: '_t1', sessionIndex: '_s1',
    authnInstant: '2026-11-15T09:00:00.000Z',
    authnContextClassRef:
      'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    subjectConfirmation: { recipient: ACS, inResponseTo: '_req1' } });
  one('a confirmation with its own expiry', 'alice', SP, 5, {
    subjectConfirmation: { recipient: ACS, inResponseTo: '_r',
                           notOnOrAfter: '2030-01-01T00:00:00.000Z' } });
  one('attributes, multi-valued', 'alice', SP, 5, {
    attributes: [
      { name: 'urn:oid:0.9.2342.19200300.100.1.3', friendlyName: 'mail',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        value: 'alice@example.com' },
      { name: 'groups', values: ['a', 'b', 'c&d'] },
      { name: 'empty', value: null }] });
  one('delegates', 'alice', SP, 5, {
    delegates: [{ nameId: 'svc-a' },
                { nameId: 'svc-b', format: 'urn:x:fmt',
                  instant: '2026-11-15T09:00:00.000Z' }] });
  one('qualifiers and an attribute query', 'alice', SP, 5, {
    nameQualifier: 'https://idp.vectors.example', spNameQualifier: SP,
    attributeQuery: true });

  // THE RESPONSES.
  const responses = [];
  [['urn:oasis:names:tc:SAML:2.0:status:Success', '', ''],
   ['urn:oasis:names:tc:SAML:2.0:status:Requester',
    'urn:oasis:names:tc:SAML:2.0:status:NoPassive', 'a <reason> & more'],
   ['urn:oasis:names:tc:SAML:2.0:status:Responder', '', 'only a message']]
    .forEach(function (row) {
      responses.push({ kind: 'status', code: row[0], sub: row[1],
                       message: row[2],
                       xml: direct.statusElement(row[0], row[1], row[2]) });
    });
  const built = direct.buildResponse({
    destination: ACS, inResponseTo: '_req1',
    issuer: 'https://idp.vectors.example',
    status: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    assertion: assertions[3].signed, sp: SP });
  responses.push({ kind: 'response', signed: built.signed, xml: built.xml,
                   id: built.id,
                   issueInstant: /IssueInstant="([^"]+)"/.exec(built.xml)[1],
                   destination: ACS, inResponseTo: '_req1',
                   issuer: 'https://idp.vectors.example',
                   status: 'urn:oasis:names:tc:SAML:2.0:status:Success',
                   assertion: assertions[3].signed });

  // THE BINDINGS.
  const bindings = { decoded: [], stripped: [], redirects: [],
                     simpleSign: [], pages: [] };
  const request = '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="_q1" Version="2.0" ' +
    'IssueInstant="2026-11-15T10:00:00Z" Destination="https://idp/sso">' +
    '<saml:Issuer>' + SP + '</saml:Issuer></samlp:AuthnRequest>';
  [['plain base64', Buffer.from(request).toString('base64')],
   ['deflated', zlib.deflateRawSync(Buffer.from(request)).toString('base64')],
   ['url-safe alphabet', zlib.deflateRawSync(Buffer.from(request))
     .toString('base64').replace(/\+/g, '-').replace(/\//g, '_')],
   ['leading whitespace', Buffer.from('  ' + request).toString('base64')],
   ['not base64 or deflate', '!!!notbase64!!!'],
   ['empty', '']].forEach(function (row) {
    bindings.decoded.push({ name: row[0], encoded: row[1],
                            decoded: direct.decodeMessage(row[1]) });
  });
  const signedResponse = built.xml;
  [['a signed Response', signedResponse],
   ['a Response with no signature', '<samlp:Response xmlns:samlp="' +
     NS_SAMLP + '" ID="_x"><saml:Issuer xmlns:saml="' + NS_SAML + '">i' +
     '</saml:Issuer><samlp:Status/></samlp:Response>'],
   ['a signature first', '<r ID="_x"><ds:Signature>s</ds:Signature><a/></r>'],
   ['a declaration first', '<?xml version="1.0"?><r><Issuer>i</Issuer>' +
     '<Signature>s</Signature></r>'],
   ['the assertion\'s own signature left', assertions[3].signed]]
    .forEach(function (row) {
      bindings.stripped.push({ name: row[0], xml: row[1],
        stripped: direct.withoutEnvelopedSignature(row[1]) });
    });
  [['signed, with RelayState', 'rs&1', SP],
   ['signed, a destination with a query', '', SP]].forEach(function (row) {
    const dest = row[0].indexOf('query') >= 0 ? ACS + '?x=1' : ACS;
    const url = direct.redirectUrlFor(dest, 'SAMLResponse', signedResponse,
                                      row[1], row[2]);
    bindings.redirects.push({ name: row[0], destination: dest,
                              relayState: row[1], xml: signedResponse,
                              url: url });
  });
  const ss = direct.simpleSignFields('SAMLResponse', signedResponse, 'rs',
                                     SP);
  bindings.simpleSign.push({ xml: signedResponse, relayState: 'rs',
                             message: ss.message, extra: ss.extra });
  const note = { title: 'Signing <you> in', sub: 'to <b>x</b>', t: T };
  bindings.pages.push({
    destination: ACS + '?a=1&b="2"', field: 'SAMLResponse',
    message: 'PHg+', relayState: 'r<s', extra: [['SigAlg', 'a&b']],
    title: note.title, sub: note.sub,
    inner: direct.postBindingPage(ACS + '?a=1&b="2"', 'SAMLResponse', 'PHg+',
                                  'r<s', note, [['SigAlg', 'a&b']]),
    page: direct.page('A <title>', '<p>x</p>')
  });
  bindings.pages.push({
    destination: ACS, field: 'SAMLResponse', message: 'abc', relayState: '',
    extra: [], title: 't', sub: 's',
    inner: direct.postBindingPage(ACS, 'SAMLResponse', 'abc', '',
                                  { title: 't', sub: 's', t: T }),
    page: direct.page('t', '') });

  // THE REQUESTS.
  const requests = [];
  const authnRequest = function (attrs, inner) {
    return '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ' + attrs + '>' + inner +
      '</samlp:AuthnRequest>';
  };
  [['every attribute', authnRequest('ID="_a" Version="2.0" ' +
     'IssueInstant="2026-11-15T10:00:00Z" Destination="https://idp/sso" ' +
     'ForceAuthn="true" IsPassive="1" ProtocolBinding="urn:oasis:names:tc:' +
     'SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceIndex="2" ' +
     'AssertionConsumerServiceURL="' + ACS + '"',
     '<saml:Issuer> ' + SP + ' </saml:Issuer><samlp:NameIDPolicy ' +
     'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" ' +
     'AllowCreate=" true "/>')],
   ['a subject and contexts', authnRequest('ID="_b" Version="2.0"',
     '<saml:Issuer>' + SP + '</saml:Issuer><saml:Subject><saml:NameID ' +
     'Format="urn:x"> bob </saml:NameID></saml:Subject>' +
     '<samlp:RequestedAuthnContext Comparison="exact"><saml:' +
     'AuthnContextClassRef> urn:a </saml:AuthnContextClassRef><saml:' +
     'AuthnContextClassRef>urn:b</saml:AuthnContextClassRef></samlp:' +
     'RequestedAuthnContext>')],
   ['false booleans', authnRequest('ID="_c" ForceAuthn="false" ' +
     'IsPassive="yes"', '')],
   ['a signature', authnRequest('ID="_d"', '<saml:Issuer>i</saml:Issuer>' +
     '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>')],
   ['not an AuthnRequest', '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP +
     '" ID="_e"/>'],
   ['empty', '   '],
   ['malformed', '<samlp:AuthnRequest']].forEach(function (row) {
    const read = direct.readAuthnRequest(row[1]);
    requests.push({ name: row[0], xml: row[1],
                    read: JSON.parse(JSON.stringify(read)) });
  });

  // THE ARTIFACTS.
  const artifacts = { minted: [], foreign: [], keys: [], rows: [] };
  ['https://idp.vectors.example', direct.idpEntityId()].forEach(function (i) {
    [0, 1, 513].forEach(function (index) {
      artifacts.minted.push({ issuer: i, index: index,
                              artifact: direct.mintArtifact(i, index) });
    });
  });
  const own = direct.mintArtifact(direct.idpEntityId(), 0);
  [['its own', own],
   ['another issuer\'s', direct.mintArtifact('https://other.example', 0)],
   ['too short', Buffer.alloc(43).toString('base64')],
   ['another type', Buffer.concat([Buffer.from([0, 5, 0, 0]),
     Buffer.alloc(40)]).toString('base64')],
   ['not base64', '***']].forEach(function (row) {
    artifacts.foreign.push({ name: row[0], artifact: row[1],
                             issuer: direct.idpEntityId(),
                             foreign: direct.isForeignArtifact(row[1]) });
  });
  [own, 'AAAA', ''].forEach(function (a) {
    artifacts.keys.push({ artifact: a, key: stsCrypto.credentialDigest(a) });
  });
  const handle = realms.handleFor('saml2_sso.artifacts');
  const res = { set: function () { return res; },
                status: function () { return res; },
                type: function () { return res; },
                send: function () { return res; },
                redirect: function (a, b) {
                  res.location = b || a;
                  return res;
                } };
  direct.deliver(res, {
    binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
    destination: ACS, field: 'SAMLResponse', xml: signedResponse,
    relayState: '', issuer: direct.idpEntityId(), spEntityId: SP,
    inResponseTo: '_req1', note: { title: 't', sub: 's', t: T } });
  handle.dump(realms.DEFAULT_REALM.id).forEach(function (row) {
    artifacts.rows.push({ key: row.key, value: row.value });
  });
  artifacts.location = String(res.location || '');

  return { signer: signer, assertions: assertions, responses: responses,
           bindings: bindings, requests: requests, artifacts: artifacts,
           idpEntityId: direct.idpEntityId() };
}

// What Rust made, checked by Node: each assertion and Response Rust signed
// verifies here with the realm's certificate, and each artifact Rust minted
// is read as one of this issuer's.
function checkRust(ROOT, rows, check) {
  const stsCrypto = require(path.join(ROOT, 'common', 'crypto.js'));
  (rows.signed || []).forEach(function (row) {
    const v = stsCrypto.verifyXmlSignature(row.xml,
      { element: row.element, certPem: row.certPem });
    check(v.ok === true, 'saml: Node verifies the ' + row.element +
          ' Rust signed (' + row.name + ')', v.why || '');
  });
  (rows.keys || []).forEach(function (row) {
    check(stsCrypto.credentialDigest(row.artifact) === row.key,
          'saml: Node keys the artifact Rust keyed', row.key);
  });
  (rows.minted || []).forEach(function (row) {
    const bytes = Buffer.from(row.artifact, 'base64');
    check(bytes.length === 44 && bytes.readUInt16BE(0) === 4 &&
          bytes.readUInt16BE(2) === row.index &&
          stsCrypto.samlArtifactSourceId(row.issuer)
            .equals(bytes.subarray(4, 24)),
          'saml: Node reads the artifact Rust minted (' + row.issuer + ', ' +
          row.index + ')', row.artifact);
  });
}

module.exports = { build: build, checkRust: checkRust };
