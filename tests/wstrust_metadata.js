// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_metadata.js
//
// ===========================================================================
// GET /sts/metadata IS WSDL 1.1 WITH WS-SECURITYPOLICY (#958).
//
// The document is built from the model and from the flags the caller passes,
// so the four versions, the four operations and every credential can be
// asserted without the stack. send() is the route: the media type, no-store,
// and the same document the request's base would be given.
//
// What is refused on purpose: SAML 1.2, the internal label AQ-RES, an
// algorithm suite, and a Kerberos issued type while wstrust.issueKerberos
// is off. The RST address is /sts. This document's own URL is not one.
//
// V. EACH TRUST VERSION IS ITS OWN CONTRACT: a port type per version whose
//    messages are that version's elements (resolved through the prefixes
//    the document declares), whose operations are the ones it defines
//    (May 2004 has no Cancel), and whose actions are WS-Trust's input
//    action and the output action wstrust.ts writes; two SOAP ports each,
//    eight in all, at /sts. xmllint reads the whole document.
// C. THE TOKEN CAPABILITY EXTENSION: the document validates against its own
//    schema with xmllint; every input and output row, every pair, and the
//    pairs moving with the flags (Kerberos conditional only while issued,
//    unsupported from a disabled credential, the empty credential only in
//    development); the WSDL names it; the routes answer it.
// M. WS-METADATAEXCHANGE: a WS-Transfer Get and a GetMetadata in either
//    SOAP version and either addressing namespace, the three sections, a
//    Dialect narrowing, an unknown dialect answered empty, RelatesTo, and
//    the two faults with their codes.
// F. ALWAYS FORMATTED (rcbj, 2026-11-13): the WSDL is one element a line,
//    each two spaces deeper than its parent, and the text is the same
//    document with the indentation taken out; so is the WSDL in WS-MEX.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const helpers = require('../common/helpers');
const IssuerNames = require('../common/issuer_names');
const Krb5Tokens = require('../kerberos/krb5_tokens');
const WsModel = require('../ws-trust/ws_model');
const WsTrustMetadata = require('../ws-trust/wstrust_metadata');
const WsTrustCapabilities = require('../ws-trust/wstrust_capabilities');
const WsTrustMex = require('../ws-trust/wstrust_mex');
const childProcess = require('child_process');
const os = require('os');
const { DOMParser } = require('@xmldom/xmldom');

const log = require('bunyan').createLogger({ name: 'wstrust_metadata',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'https://sts.example';
const ISSUER = 'https://sts.example/issuer';

function flags(over) {
  log.debug("Entering flags().");
  const out = {
    acceptKerberos: true,
    issueKerberos: false,
    acceptClientCertificate: true,
    verifiesCredentials: false
  };
  Object.keys(over || {}).forEach(function (key) {
    out[key] = over[key];
  });
  log.debug("Leaving flags().");
  return out;
}

function documentOf(one, issuer) {
  log.debug("Entering documentOf().");
  const xml = WsTrustMetadata.document(BASE, issuer || ISSUER, one);
  log.debug("Leaving documentOf().");
  return xml;
}

// The next `<wsp:Policy` element. `<wsp:PolicyReference` starts with the
// same characters and is not an element this walk should descend into.
function nextPolicy(xml, from) {
  log.debug("Entering nextPolicy().");
  let at = from;
  while (at < xml.length) {
    const found = xml.indexOf('<wsp:Policy', at);
    if (found < 0) {
      log.debug("Leaving nextPolicy(). None.");
      return -1;
    }
    const after = xml.charAt(found + '<wsp:Policy'.length);
    if (after === '>' || after === ' ') {
      log.debug("Leaving nextPolicy().");
      return found;
    }
    at = found + 1;
  }
  log.debug("Leaving nextPolicy(). None.");
  return -1;
}

// A policy by wsu:Id, including the nested policies a token assertion
// carries. A slice that stops at the first close would end inside
// RequesterAuthentication's first token.
function slicePolicy(xml, id) {
  log.debug("Entering slicePolicy().");
  const marker = 'wsu:Id="' + id + '"';
  const at = xml.indexOf(marker);
  if (at < 0) {
    log.debug("Leaving slicePolicy(). Missing.");
    return '';
  }
  const open = xml.lastIndexOf('<wsp:Policy ', at);
  let i = xml.indexOf('>', at) + 1;
  let depth = 1;
  const closeLen = '</wsp:Policy>'.length;
  while (i < xml.length && depth > 0) {
    const nextOpen = nextPolicy(xml, i);
    const nextClose = xml.indexOf('</wsp:Policy>', i);
    if (nextClose < 0) {
      break;
    }
    if (nextOpen >= 0 && nextOpen < nextClose) {
      depth += 1;
      i = nextOpen + '<wsp:Policy'.length;
    } else {
      depth -= 1;
      if (depth === 0) {
        const out = xml.slice(open, nextClose + closeLen);
        log.debug("Leaving slicePolicy().");
        return out;
      }
      i = nextClose + closeLen;
    }
  }
  log.debug("Leaving slicePolicy(). Unclosed.");
  return '';
}

function contains(text, needle) {
  log.debug("Entering contains().");
  log.debug("Leaving contains().");
  return text.indexOf(needle) >= 0;
}

function run(t) {
  log.debug("Entering run().");
  const dev = documentOf(flags());
  const types = Krb5Tokens.VALUE_TYPES;
  const kerberos = [types.AP_REQ, types.GSS_AP_REQ, types.AP_REQ_1510,
                    types.GSS_AP_REQ_1510, types.AP_REQ_4120,
                    types.GSS_AP_REQ_4120];
  ['trust13', 'trust14', 'trust2005', 'trust2004'].forEach(function (term) {
    const uri = WsModel.term('wst.namespace', term);
    t.check(contains(dev, uri), 'the document names ' + term, uri);
  });
  ['Issue', 'Renew', 'Validate', 'Cancel'].forEach(function (name) {
    t.check(contains(dev, 'wsdl:operation name="' + name + '"'),
            'a port type offers ' + name);
  });
  versions(t, dev);
  capabilities(t);
  mex(t);
  formatted(t, dev);
  t.check(contains(dev, '2004/04 has no Cancel') &&
          contains(dev, 'wst:' + WsModel.term('wst.fault', 'InvalidRequest')),
          '2004/04 Cancel is refused as InvalidRequest');
  ['UsernameToken', 'SAML 2.0', 'SAML 1.1', 'JWT', 'X.509',
   'Kerberos', 'TLS client certificate'].forEach(function (name) {
    t.check(contains(dev, name), 'the documentation names ' + name);
  });
  kerberos.forEach(function (uri) {
    t.check(contains(dev, uri),
            'the documentation names every Kerberos ValueType', uri);
  });
  t.check(contains(dev, 'There is no SAML 1.2.') &&
          !contains(dev, 'AQ-RES') && !contains(dev, 'rfc:1510') &&
          !contains(dev, 'WssSamlV12'),
          'SAML 1.2 is denied, and AQ-RES and the SAML 1.1 Kerberos ' +
          'method are absent');
  t.check(!contains(dev, 'AlgorithmSuite') && !contains(dev, 'Basic256'),
          'no alternative names an algorithm suite');
  t.check(contains(dev, '<soap:address location="' + BASE + '/sts"/>') &&
          contains(dev, '<soap12:address location="' + BASE + '/sts"/>') &&
          !/address location="[^"]*\/sts\/(metadata|mex)/.test(dev),
          'every port addresses /sts, not a metadata document');

  const nasty = 'https://issuer.example/a<b>&c';
  const escaped = documentOf(flags(), nasty);
  t.check(contains(escaped, 'https://issuer.example/a&lt;b&gt;&amp;c') &&
          !contains(escaped, nasty),
          'an issuer is escaped inside the documentation');

  const requester = slicePolicy(dev, 'RequesterAuthentication');
  const issued = slicePolicy(dev, 'IssuedTokenTypes');
  t.check(contains(requester, 'sp:UsernameToken') &&
          contains(requester, 'sp:WssSamlV20Token11') &&
          contains(requester, 'sp:WssSamlV11Token11') &&
          contains(requester, 'sp:X509Token') &&
          contains(requester, 'sp:SignedParts') &&
          contains(requester, 'sp:KerberosToken') &&
          contains(requester, 'sp:HttpsToken') &&
          contains(requester, 'sp:RequireClientCertificate') &&
          contains(requester, '<wsp:All/>'),
          'development offers every input alternative, including none');
  kerberos.forEach(function (uri) {
    t.check(!contains(issued, uri),
            'Kerberos is not an issued type while issueKerberos is off',
            uri);
  });
  t.check(contains(issued, WsModel.term('wst.tokenType', 'saml2')) &&
          contains(issued, WsModel.term('wst.tokenType', 'saml11')) &&
          contains(issued, WsModel.term('wst.tokenType', 'jwt')),
          'SAML 2.0, SAML 1.1 and JWT are always issued types');

  const off = documentOf(flags({
    acceptKerberos: false,
    acceptClientCertificate: false,
    verifiesCredentials: true
  }));
  const offIn = slicePolicy(off, 'RequesterAuthentication');
  t.check(!contains(offIn, 'sp:KerberosToken') &&
          !contains(offIn, 'sp:HttpsToken') &&
          !contains(offIn, '<wsp:All/>') &&
          contains(off, kerberos[0]),
          'Kerberos, TLS and the empty alternative follow the flags, and ' +
          'the ValueTypes stay in the documentation');

  const on = documentOf(flags({
    issueKerberos: true,
    verifiesCredentials: true
  }));
  const onOut = slicePolicy(on, 'IssuedTokenTypes');
  kerberos.forEach(function (uri) {
    t.check(contains(onOut, uri),
            'each Kerberos ValueType is issued while the flag is on', uri);
  });
  t.check(!contains(on, '<wsp:All/>'),
          'product has no empty alternative');

  answered(t);
  const source = fs.readFileSync(path.join(__dirname, '..', 'ws-trust',
                                            'wstrust.ts'), 'utf8');
  t.check(contains(source, "'/sts/metadata'"),
          'wstrust.ts registers GET /sts/metadata');
  log.debug("Leaving run().");
}

// xmllint, which the tests image carries (tests/Dockerfile): the document
// alone, or against a schema. A missing xmllint fails, never skips.
function xmllint(xml, schema) {
  log.debug("Entering xmllint().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wstrust-md-'));
  try {
    const doc = path.join(dir, 'doc.xml');
    fs.writeFileSync(doc, xml);
    const args = ['--noout', '--nonet'];
    if (schema) {
      const xsd = path.join(dir, 'schema.xsd');
      fs.writeFileSync(xsd, schema);
      args.push('--schema', xsd);
    }
    args.push(doc);
    const run = childProcess.spawnSync('xmllint', args, { encoding: 'utf8' });
    const out = { ok: run.status === 0,
                  errors: String(run.stderr || (run.error &&
                                                run.error.message) || '') };
    log.debug("Leaving xmllint(). " + out.ok);
    return out;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function parse(xml) {
  log.debug("Entering parse().");
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  log.debug("Leaving parse().");
  return doc;
}

function elements(root, ns, name) {
  log.debug("Entering elements().");
  const out = [];
  const list = root.getElementsByTagNameNS(ns, name);
  for (let i = 0; i < list.length; i += 1) {
    out.push(list[i]);
  }
  log.debug("Leaving elements().");
  return out;
}

const WSDL = 'http://schemas.xmlsoap.org/wsdl/';
const WSAM = 'http://www.w3.org/2007/05/addressing/metadata';

function versions(t, xml) {
  log.debug("Entering versions().");
  const lint = xmllint(xml);
  t.check(lint.ok, 'xmllint reads the WSDL', lint.errors.slice(0, 300));
  const doc = parse(xml);
  const root = doc.documentElement;
  const ns = function (term) {
    return WsModel.term('wst.namespace', term);
  };
  const want = {
    TrustMay2004: { ns: ns('trust2004'), cancel: false, collection: false },
    TrustFeb2005: { ns: ns('trust2005'), cancel: true, collection: true },
    Trust13: { ns: ns('trust13'), cancel: true, collection: true },
    Trust14: { ns: ns('trust13'), cancel: true, collection: true }
  };
  const messages = {};
  elements(root, WSDL, 'message').forEach(function (one) {
    const part = elements(one, WSDL, 'part')[0];
    const qname = String(part.getAttribute('element'));
    const prefix = qname.split(':')[0];
    messages[one.getAttribute('name')] = {
      ns: root.lookupNamespaceURI(prefix), local: qname.split(':')[1] };
  });
  const portTypes = elements(root, WSDL, 'portType');
  t.equal(portTypes.map(function (one) {
    return one.getAttribute('name');
  }).join(' '), 'TrustMay2004 TrustFeb2005 Trust13 Trust14',
  'one port type per trust version, oldest first');
  portTypes.forEach(function (portType) {
    const name = portType.getAttribute('name');
    const v = want[name];
    const ops = elements(portType, WSDL, 'operation');
    const opNames = ops.map(function (one) {
      return one.getAttribute('name');
    });
    t.equal(opNames.join(' '), v.cancel ? 'Issue Renew Validate Cancel'
                                        : 'Issue Renew Validate',
            name + ' has the operations its version defines');
    ops.forEach(function (op) {
      const opName = op.getAttribute('name');
      const input = elements(op, WSDL, 'input')[0];
      const output = elements(op, WSDL, 'output')[0];
      const inMsg = messages[String(input.getAttribute('message'))
        .split(':')[1]];
      const outMsg = messages[String(output.getAttribute('message'))
        .split(':')[1]];
      t.check(inMsg && inMsg.ns === v.ns &&
              inMsg.local === 'RequestSecurityToken',
              name + ' ' + opName + ' reads its version\'s RST',
              JSON.stringify(inMsg));
      const outLocal = opName === 'Issue' && v.collection
        ? 'RequestSecurityTokenResponseCollection'
        : 'RequestSecurityTokenResponse';
      t.check(outMsg && outMsg.ns === v.ns && outMsg.local === outLocal,
              name + ' ' + opName + ' answers ' + outLocal + ' in its ' +
              'version', JSON.stringify(outMsg));
      t.equal(input.getAttributeNS(WSAM, 'Action'), v.ns + '/RST/' + opName,
              name + ' ' + opName + '\'s input action');
      let term = opName.toLowerCase() + 'Final';
      if (opName === 'Issue') {
        term = v.collection ? 'issueFinal' : 'issue';
      }
      t.equal(output.getAttributeNS(WSAM, 'Action'),
              WsModel.relative('wst.action', term, v.ns),
              name + ' ' + opName + '\'s output action is the one ' +
              'wstrust.ts writes');
    });
  });
  const ports = elements(root, WSDL, 'port');
  t.equal(ports.length, 8, 'eight ports: each version over SOAP 1.1 and 1.2');
  const schemas = elements(root, 'http://www.w3.org/2001/XMLSchema',
                           'schema').map(function (one) {
    return one.getAttribute('targetNamespace');
  });
  t.check([ns('trust2004'), ns('trust2005'), ns('trust13'),
           ns('trust14')].every(function (one) {
    return schemas.indexOf(one) >= 0;
  }), 'a schema per trust namespace, 1.4\'s for ActAs', schemas.join(' '));
  t.check(contains(xml, 'location="' + BASE +
                   '/sts/metadata/capabilities"') &&
          contains(xml, 'metadataExchange="' + BASE + '/sts/mex"') &&
          contains(xml, 'wsdl:required="false"'),
          'the WSDL names the capability document and WS-MEX, optionally');
  log.debug("Leaving versions().");
}

function pairOf(model, input, output) {
  log.debug("Entering pairOf().");
  const out = model.combinations.filter(function (one) {
    return one.input === input && one.output === output;
  })[0];
  log.debug("Leaving pairOf().");
  return out;
}

function capabilities(t) {
  log.debug("Entering capabilities().");
  const dev = flags();
  const model = WsTrustCapabilities.model(BASE, ISSUER, dev);
  const inputs = model.inputs.map(function (one) {
    return one.id;
  });
  t.equal(inputs.join(' '), 'x509-signature username-token saml2 saml11 ' +
          'jwt kerberos tls-client-certificate none',
          'every credential, in the order the endpoint reads them');
  t.equal(model.outputs.map(function (one) {
    return one.id;
  }).join(' '), 'saml2 saml11 jwt kerberos', 'every issued type');
  t.equal(model.combinations.length, inputs.length * 4,
          'every pair is written out');
  ['saml2', 'saml11', 'jwt'].forEach(function (output) {
    model.inputs.forEach(function (input) {
      t.equal(pairOf(model, input.id, output).support, 'supported',
              input.id + ' -> ' + output + ' is supported');
    });
  });
  t.equal(pairOf(model, 'username-token', 'kerberos').support,
          'unsupported', 'no Kerberos output while issueKerberos is off');
  const on = WsTrustCapabilities.model(BASE, ISSUER, flags({
    issueKerberos: true, acceptKerberos: false, verifiesCredentials: true,
    acceptClientCertificate: false }));
  const kerberos = pairOf(on, 'jwt', 'kerberos');
  t.check(kerberos.support === 'conditional' &&
          kerberos.conditions.map(function (one) {
            return one.kind;
          }).join(' ') === 'transport target',
          'Kerberos is conditional on TLS and a Kerberos target once ' +
          'issued', JSON.stringify(kerberos));
  t.check(['kerberos', 'tls-client-certificate', 'none']
    .every(function (id) {
      return on.combinations.filter(function (one) {
        return one.input === id;
      }).every(function (one) {
        return one.support === 'unsupported';
      });
    }), 'a disabled credential is unsupported for every output');
  t.equal(pairOf(on, 'kerberos', 'saml2').conditions[0].setting,
          'wstrust.acceptKerberos', 'and it names the setting that ' +
          'disables it');
  t.check(on.delegation.indexOf('kerberos') < 0 &&
          model.delegation.indexOf('kerberos') >= 0,
          'Kerberos inside OnBehalfOf/ActAs follows acceptKerberos');
  const kerberosOut = on.outputs.filter(function (one) {
    return one.id === 'kerberos';
  })[0];
  t.equal(kerberosOut.operations.join(' '), 'Issue Validate',
          'a Kerberos token is neither renewed nor cancelled');
  [dev, flags({ issueKerberos: true, verifiesCredentials: true })]
    .forEach(function (one, i) {
      const xml = WsTrustCapabilities.document(BASE, ISSUER, one);
      const lint = xmllint(xml, WsTrustCapabilities.schema());
      t.check(lint.ok, 'the capability document ' + i + ' validates ' +
              'against its schema', lint.errors.slice(0, 400));
    });
  const xml = WsTrustCapabilities.document(BASE, '<x&y>', dev);
  t.check(contains(xml, 'issuer="&lt;x&amp;y&gt;"'),
          'the issuer is escaped');
  const lintSchema = xmllint(WsTrustCapabilities.schema());
  t.check(lintSchema.ok, 'the schema itself is well-formed');
  const source = fs.readFileSync(path.join(__dirname, '..', 'ws-trust',
                                            'wstrust.ts'), 'utf8');
  t.check(contains(source, "'/sts/metadata/capabilities'") &&
          contains(source, "'/sts/metadata/capabilities.xsd'") &&
          contains(source, "'/sts/mex'"),
          'wstrust.ts registers the capability document, its schema and ' +
          'WS-MEX');
  log.debug("Leaving capabilities().");
}

function envelope(soapNs, wsaNs, action, body, messageId) {
  log.debug("Entering envelope().");
  const out = '<s:Envelope xmlns:s="' + soapNs + '" xmlns:a="' + wsaNs +
    '"><s:Header>' + (action ? '<a:Action>' + action + '</a:Action>' : '') +
    (messageId ? '<a:MessageID>' + messageId + '</a:MessageID>' : '') +
    '</s:Header><s:Body>' + (body || '') + '</s:Body></s:Envelope>';
  log.debug("Leaving envelope().");
  return out;
}

function mex(t) {
  log.debug("Entering mex().");
  const soap11 = WsModel.term('soap.namespace', 'soap11');
  const soap12 = WsModel.term('soap.namespace', 'soap12');
  const wsa10 = WsModel.term('wsa.namespace', 'addressing');
  const wsa04 = 'http://schemas.xmlsoap.org/ws/2004/08/addressing';
  const MEX = 'http://schemas.xmlsoap.org/ws/2004/09/mex';
  const get = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get';
  const getMetadata = MEX + '/GetMetadata/Request';
  const sectionsOf = function (body) {
    return elements(parse(body).documentElement, MEX,
                    'MetadataSection').map(function (one) {
      return one.getAttribute('Dialect');
    });
  };
  const all = WsTrustMex.answer(envelope(soap12, wsa10, get, '',
                                         'urn:uuid:1'), BASE, ISSUER,
                                flags());
  t.equal(all.status, 200, 'a WS-Transfer Get is answered');
  t.check(/^application\/soap\+xml/.test(all.type) &&
          contains(all.body, 'xmlns:soap="' + soap12 + '"'),
          'in SOAP 1.2 when asked in SOAP 1.2');
  t.check(contains(all.body, '/transfer/GetResponse</wsa:Action>') &&
          contains(all.body, '<wsa:RelatesTo>urn:uuid:1</wsa:RelatesTo>') &&
          contains(all.body, 'xmlns:wsa="' + wsa10 + '"'),
          'with GetResponse and RelatesTo, in the request\'s addressing');
  t.equal(sectionsOf(all.body).join(' '), WSDL + ' ' +
          WsTrustCapabilities.NAMESPACE +
          ' http://www.w3.org/2001/XMLSchema',
          'three sections: the WSDL, the capabilities and their schema');
  const lint = xmllint(all.body);
  t.check(lint.ok, 'xmllint reads the answer', lint.errors.slice(0, 300));
  const narrowed = WsTrustMex.answer(envelope(soap11, wsa04, getMetadata,
    '<m:GetMetadata xmlns:m="' + MEX + '"><m:Dialect>' + WSDL +
    '</m:Dialect></m:GetMetadata>'), BASE, ISSUER, flags());
  t.check(narrowed.status === 200 && /^text\/xml/.test(narrowed.type) &&
          contains(narrowed.body, 'xmlns:wsa="' + wsa04 + '"') &&
          contains(narrowed.body, '/GetMetadata/Response</wsa:Action>'),
          'a GetMetadata in SOAP 1.1 and 2004/08 addressing is answered so');
  t.equal(sectionsOf(narrowed.body).join(' '), WSDL,
          'a Dialect narrows it to the WSDL');
  const none = WsTrustMex.answer(envelope(soap11, wsa10, getMetadata,
    '<m:GetMetadata xmlns:m="' + MEX + '"><m:Dialect>urn:nothing' +
    '</m:Dialect></m:GetMetadata>'), BASE, ISSUER, flags());
  t.check(none.status === 200 && sectionsOf(none.body).length === 0,
          'an unknown dialect is an empty Metadata, not a fault');
  const notSoap = WsTrustMex.answer('<x/>', BASE, ISSUER, flags());
  t.check(notSoap.status === 500 && notSoap.errorCode ===
          'STS-WSTRUST-0072' && contains(notSoap.body, 'soap:Client') &&
          !contains(notSoap.body, 'STS-'),
          'a body that is not SOAP is a Client fault, the code not sent');
  const other = WsTrustMex.answer(envelope(soap12, wsa10,
    'urn:something-else', ''), BASE, ISSUER, flags());
  t.check(other.status === 500 && other.errorCode === 'STS-WSTRUST-0073' &&
          contains(other.body, 'soap:Sender') &&
          contains(other.body, '/fault</wsa:Action>'),
          'another action is a Sender fault in SOAP 1.2');
  log.debug("Leaving mex().");
}

function answered(t) {
  log.debug("Entering answered().");
  const req = {
    protocol: 'https',
    url: '/sts/metadata',
    originalUrl: '/sts/metadata',
    headers: {},
    get: function (name) {
      log.debug("Entering get().");
      const out = name === 'host' ? 'sts.example:8443' : undefined;
      log.debug("Leaving get().");
      return out;
    }
  };
  const headers = {};
  let status = 0;
  let body = '';
  const res = {
    status: function (code) {
      log.debug("Entering status().");
      status = code;
      log.debug("Leaving status().");
      return res;
    },
    set: function (name, value) {
      log.debug("Entering set().");
      headers[name] = value;
      log.debug("Leaving set().");
      return res;
    },
    send: function (text) {
      log.debug("Entering send().");
      body = text;
      log.debug("Leaving send().");
    }
  };
  WsTrustMetadata.send(req, res);
  const base = helpers.baseUrlOf(req);
  const want = WsTrustMetadata.document(base, IssuerNames.issuer(base),
                                         WsTrustMetadata.liveFlags());
  t.equal(status, 200, 'send answers 200');
  t.equal(headers['Content-Type'], 'application/wsdl+xml; charset=utf-8',
          'send names the WSDL media type');
  t.equal(headers['Cache-Control'], 'no-store',
          'send does not store the document');
  // A boolean, not t.equal(): the detail would be the whole document, and
  // a line that long was cut off in the run's output with what followed it.
  t.check(body === want, 'send is the document for the request base',
          String(body).length + ' characters, want ' + String(want).length);
  log.debug("Leaving answered().");
}

// F. The WSDL is indented, one element a line, and only whitespace between
// elements was added: the lines trimmed and joined, indented again, give the
// same text back, and that joined text parses to the same element tree.
function formatted(t, xml) {
  log.debug("Entering formatted().");
  const XmlFormat = require('../common/xml_format');
  const lines = xml.replace(/\n$/, '').split('\n');
  t.check(lines.length > 200,
          'F1. the WSDL is returned on many lines', lines.length + ' lines');
  const twoStarts = lines.filter(function (line) {
    return (line.match(/<[A-Za-z]/g) || []).length > 1;
  });
  t.check(twoStarts.length === 0,
          'F2. no line opens more than one element', twoStarts[0] || '');
  let depth = 0;
  const misplaced = [];
  lines.forEach(function (line) {
    const body = line.trim();
    if (/^<\//.test(body)) {
      depth--;
    }
    if (!/^<\?/.test(body) && line.length - body.length !== 2 * depth) {
      misplaced.push(line.slice(0, 80));
    }
    if (/^<[A-Za-z]/.test(body) && !/\/>$/.test(body) &&
        !/<\/[^>]+>$/.test(body)) {
      depth++;
    }
  });
  t.check(misplaced.length === 0 && depth === 0,
          'F3. each element is two spaces deeper than its parent',
          misplaced[0] || ('ended at depth ' + depth));
  const joined = lines.map(function (line) {
    return line.trim();
  }).join('');
  // A boolean, not t.equal(): the detail would be the whole document.
  t.check(XmlFormat.indent(joined, log) === xml,
          'F4. indenting the joined text again gives the same document');
  const tree = function (node) {
    const kids = [];
    for (let c = node.firstChild; c; c = c.nextSibling) {
      if (c.nodeType === 1) {
        kids.push(tree(c));
      } else if (c.nodeType === 3 && c.nodeValue.trim() !== '') {
        kids.push(c.nodeValue);
      }
    }
    return [node.namespaceURI, node.localName, kids];
  };
  t.check(JSON.stringify(tree(parse(xml).documentElement)) ===
          JSON.stringify(tree(parse(joined).documentElement)),
          'F5. and the indented document has the same elements and text');
  const answer = WsTrustMex.answer(envelope(
    WsModel.term('soap.namespace', 'soap11'),
    WsModel.term('wsa.namespace', 'addressing'),
    'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get', '',
    'urn:uuid:f'), BASE, ISSUER, flags());
  t.check(contains(answer.body, '\n  <wsdl:types>'),
          'F6. the WSDL in a WS-MEX answer is indented too');
  log.debug("Leaving formatted().");
}

module.exports = {
  name: 'wstrust_metadata',
  describe: 'GET /sts/metadata is WSDL 1.1 with WS-SecurityPolicy for the ' +
            'four trust versions and every credential WS-Trust accepts ' +
            '(#958)',
  run: run
};
