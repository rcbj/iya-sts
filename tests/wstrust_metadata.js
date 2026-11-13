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
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const helpers = require('../common/helpers');
const IssuerNames = require('../common/issuer_names');
const Krb5Tokens = require('../kerberos/krb5_tokens');
const WsModel = require('../ws-trust/ws_model');
const WsTrustMetadata = require('../ws-trust/wstrust_metadata');

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
            'the port type offers ' + name);
  });
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
          !contains(dev, BASE + '/sts/metadata'),
          'both ports address /sts, not this document');

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
  t.equal(body, want, 'send is the document for the request base');
  log.debug("Leaving answered().");
}

module.exports = {
  name: 'wstrust_metadata',
  describe: 'GET /sts/metadata is WSDL 1.1 with WS-SecurityPolicy for the ' +
            'four trust versions and every credential WS-Trust accepts ' +
            '(#958)',
  run: run
};
