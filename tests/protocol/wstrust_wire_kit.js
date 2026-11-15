// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: wstrust_wire_kit.js
//
// ===========================================================================
// THE PLUMBING OF THE D12 WS-TRUST JOBS (#444, phase 7) — A HELPER, NOT A
// JOB.
//
// `sts_wstrust_rules.js` and `sts_wstrust_requester_auth.js` carry the
// in-process WS-Trust files (`wstrust_fault_codes.js`, `wstrust_jwt_claims.js`,
// `wstrust_saml11.js`, `wstrust_token_claims.js`, `wstrust_scope_warnings.js`,
// `wstrust_client_certificate.js`, `wstrust_message_signature.js` and the
// WS-Trust half of `reserved_password_refusal.js`) over the wire. Each needs
// an RST in either SOAP version and any trust namespace, a fault read for
// WS-Trust 1.4 section 11's code where its SOAP version puts it, and the
// token an RSTR carries. They live here once, beside `oauth_wire_kit.js`,
// whose realm, application, person and audit helpers they use.
//
// Nothing here comes from the service's own code: every assertion a job
// presents is one the service ISSUED over `/sts` (a credential it did not
// sign would be refused before the check under test), altered here where
// the check is about the alteration.
//
// OWNED HERE (MANIFEST.js's LOCAL_HELPERS).
// ===========================================================================

const assert = require("assert");

const WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const WST_2004_04 = "http://schemas.xmlsoap.org/ws/2004/04/trust";
const WST_2005_02 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
const WST14 = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
const WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
             "wssecurity-secext-1.0.xsd";
const SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
const SAML2 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-" +
              "profile-1.1#SAMLV2.0";
const SAML11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-" +
               "profile-1.1#SAMLV1.1";
const SAML10 = "urn:oasis:names:tc:SAML:1.0:assertion";
const JWT = "urn:ietf:params:oauth:token-type:jwt";

function wsKit(K) {
  const log = K.log;
  log.debug("Entering wsKit().");

  function x(value) {
    log.debug("Entering x().");
    log.debug("Leaving x().");
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function usernameToken(user, pass) {
    log.debug("Entering usernameToken().");
    log.debug("Leaving usernameToken().");
    return "<wsse:UsernameToken><wsse:Username>" + x(user) +
      "</wsse:Username>" + (pass === null ? ""
        : "<wsse:Password>" + x(pass) + "</wsse:Password>") +
      "</wsse:UsernameToken>";
  }

  // A JWT in the security header or inside an element, as this STS answers
  // one (a BinarySecurityToken whose ValueType is the JWT token type).
  function jwtToken(jwt) {
    log.debug("Entering jwtToken().");
    log.debug("Leaving jwtToken().");
    return '<wsse:BinarySecurityToken ValueType="' + JWT + '" ' +
      'EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-' +
      'wss-soap-message-security-1.0#Base64Binary">' + jwt +
      "</wsse:BinarySecurityToken>";
  }

  function actAs(inner) {
    log.debug("Entering actAs().");
    log.debug("Leaving actAs().");
    return '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + inner +
      "</wst14:ActAs>";
  }

  function onBehalfOf(inner) {
    log.debug("Entering onBehalfOf().");
    log.debug("Leaving onBehalfOf().");
    return "<wst:OnBehalfOf>" + inner + "</wst:OnBehalfOf>";
  }

  // An RST: `o.soap11`, `o.trustNs` (1.3's by default), `o.security` (the
  // wsse:Security content), `o.op` (Issue), `o.tokenType`, `o.appliesTo`
  // and `o.body` (more of the RST).
  function rst(o) {
    log.debug("Entering rst().");
    const ns = o.trustNs || WST;
    log.debug("Leaving rst().");
    return '<s:Envelope xmlns:s="' + (o.soap11 ? SOAP11 : SOAP12) + '" ' +
      'xmlns:wsse="' + WSSE + '"><s:Header>' +
      (o.security ? "<wsse:Security>" + o.security + "</wsse:Security>"
                  : "") +
      '</s:Header><s:Body><wst:RequestSecurityToken xmlns:wst="' + ns +
      '"><wst:RequestType>' + ns + "/" + (o.op || "Issue") +
      "</wst:RequestType>" + (o.tokenType ? "<wst:TokenType>" +
        o.tokenType + "</wst:TokenType>" : "") + (o.appliesTo
        ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/' +
          '09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/' +
          '2005/08/addressing"><wsa:Address>' + x(o.appliesTo) +
          "</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>" : "") +
      (o.body || "") + "</wst:RequestSecurityToken></s:Body></s:Envelope>";
  }

  // POSTs an RST (or `o.raw`) to a realm's /sts, `o.query` appended.
  function post(id, o) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return K.send(K.rb(id) + "/sts" + (o.query || ""), {
      method: "POST", raw: o.raw !== undefined ? o.raw : rst(o),
      headers: Object.assign({ "Content-Type": o.soap11
        ? "text/xml; charset=utf-8" : "application/soap+xml" },
      o.headers || {}) });
  }

  // Where section 11's code sits in a fault of each SOAP version, qualified
  // with `ns`.
  function carries(body, soap11, code, ns) {
    log.debug("Entering carries().");
    const esc = function (s) {
      return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
    };
    const re = soap11
      ? new RegExp("<soap:Fault><faultcode xmlns:wst=\"" + esc(ns) +
                   "\">wst:" + code + "</faultcode>")
      : new RegExp("<soap:Code><soap:Value>soap:Sender</soap:Value>" +
                   "<soap:Subcode><soap:Value xmlns:wst=\"" + esc(ns) +
                   "\">wst:" + code + "</soap:Value></soap:Subcode>" +
                   "</soap:Code>");
    log.debug("Leaving carries().");
    return re.test(String(body));
  }

  // The token an RSTR carries: `{ rstr, inner, jwt?, assertion?, type }`,
  // asserting a 200.
  function tokenOf(r, what) {
    log.debug("Entering tokenOf().");
    assert.strictEqual(r.status, 200, what + " answered " + r.status +
      ": " + String(r.text).replace(/\s+/g, " ").slice(0, 600));
    const m = /<wst:RequestedSecurityToken>([\s\S]*?)<\/wst:RequestedSecurityToken>/
      .exec(r.text);
    assert.ok(m, what + ": no RequestedSecurityToken: " +
              r.text.slice(0, 400));
    const inner = m[1].trim();
    const type = (/<wst:TokenType>([^<]+)<\/wst:TokenType>/.exec(r.text) ||
                  [])[1] || "";
    const out = { rstr: r.text, inner: inner, type: type };
    const jwt = /^<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(inner);
    if (jwt) {
      out.jwt = jwt[1].trim();
    } else {
      out.assertion = inner;
    }
    log.debug("Leaving tokenOf().");
    return out;
  }

  // An Issue by UsernameToken, its token answered (asserted to be one).
  async function issue(id, user, pass, appliesTo, tokenType, more) {
    log.debug("Entering issue(). " + user + " for " + appliesTo);
    const r = await post(id, Object.assign({
      security: usernameToken(user, pass), appliesTo: appliesTo,
      tokenType: tokenType }, more || {}));
    log.debug("Leaving issue().");
    return tokenOf(r, user + "'s Issue for " + appliesTo);
  }

  // The assertion's (or a JWT's) Signature taken off: what an unsigned
  // assertion is, everything else as the service signed it.
  function unsigned(assertion) {
    log.debug("Entering unsigned().");
    log.debug("Leaving unsigned().");
    return String(assertion).replace(
      /<(ds:)?Signature[\s>][\s\S]*?<\/(ds:)?Signature>/, "");
  }

  function stripCertificates(xml) {
    log.debug("Entering stripCertificates().");
    log.debug("Leaving stripCertificates().");
    return String(xml).replace(
      /<(ds:)?X509Certificate>[^<]*<\/(ds:)?X509Certificate>/g, "");
  }

  log.debug("Leaving wsKit().");
  return { WST: WST, WST_2004_04: WST_2004_04, WST_2005_02: WST_2005_02,
           WST14: WST14, SAML2: SAML2, SAML11: SAML11, SAML10: SAML10,
           JWT: JWT, x: x, usernameToken: usernameToken, jwtToken: jwtToken,
           actAs: actAs, onBehalfOf: onBehalfOf, rst: rst, post: post,
           carries: carries, tokenOf: tokenOf, issue: issue,
           unsigned: unsigned, stripCertificates: stripCertificates };
}

module.exports = { wsKit: wsKit };
