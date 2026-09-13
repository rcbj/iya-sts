"use strict";
//
// File: saml_xmldsig.js
//
// ===========================================================================
// A SAML 2.0 ASSERTION AND AN XML SIGNATURE, BUILT BY THIS SUITE'S OWN CODE.
//
// `sts_dpop.js` writes its own DPoP client rather than importing the wallet's,
// and `sts_jwt_bearer_grant.js` writes its own thirty-line JWS signer rather
// than calling `common/crypto.js`. The reason applies here with more force
// than to either of them: **if both sides of the exchange came from one
// implementation, a shared misunderstanding would make the test pass and
// interoperate with nobody** — and XML Signature is the format where a shared
// misunderstanding is most likely, because exclusive canonicalization is where
// every XML Signature implementation ever written has had a bug.
//
// So this file signs with nothing but node's own `crypto` and string
// concatenation, and the service verifies with the parent project's vendored
// engine. A signature made here that verifies there is two implementations
// agreeing.
//
// ---------------------------------------------------------------------------
// **CANONICAL BY CONSTRUCTION, WHICH IS THE WHOLE TRICK.**
//
// Canonicalizing arbitrary XML is hundreds of lines and is exactly the code
// this file must not share with the thing under test. Emitting XML that is
// ALREADY in exclusive-canonical form is about forty, because the rules are
// mechanical when you control the document:
//
//   * one namespace prefix, declared on the root and never re-declared, so
//     "render a declaration only where it is visibly utilized and not already
//     rendered by an output ancestor" has one answer everywhere;
//   * attributes sorted by local name, since none of ours is in a namespace;
//   * no self-closing elements — canonical form writes `<a></a>`;
//   * no comments, no whitespace between elements, no XML declaration;
//   * `&`, `<` and `>` escaped in text, and `"` and the three control
//     characters escaped in attribute values.
//
// The `<ds:SignedInfo>` is built the same way and carries its own `xmlns:ds`,
// which is what exclusive c14n renders for it when it is canonicalized on its
// own as XMLDSIG requires. Declaring the prefix on both `<ds:Signature>` and
// `<ds:SignedInfo>` is redundant and legal and is what makes the bytes this
// file signs the bytes the verifier reconstructs.
//
// The enveloped-signature transform is what makes the reference digest
// computable at all: the digest is taken over the assertion BEFORE the
// signature is spliced in, which is precisely what that transform reproduces
// at verification time by removing it again.
//
// ---------------------------------------------------------------------------
// **IT DELIBERATELY BUILDS BROKEN ASSERTIONS TOO**, and that is most of its
// value. A file that could only produce a correct document would let a job
// assert that a good assertion is accepted, which is what a server with no
// checks in it does for everybody. Every option that omits a required element,
// moves an instant, names the wrong recipient or breaks the digest is here so
// that a REFUSAL can be asserted beside the acceptance — which is the only
// shape that tells a working gate from a service refusing for some other
// reason.
//
// A LOCAL HELPER (`MANIFEST.js`'s `LOCAL_HELPERS`): it is this repository's
// own and there is no copy in the parent to sync from.
// ===========================================================================

const nodeCrypto = require("crypto");

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'saml_xmldsig',
  level: process.env.LOG_LEVEL || 'info' });

const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

function esc(text) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Canonical XML escapes more in an attribute value than in text: the delimiter
// itself, and the three whitespace characters that an XML parser would
// otherwise normalise to a space — which would change the octets the verifier
// reconstructs and produce a digest mismatch with nothing saying why.
function escAttr(text) {
  log.debug("Entering escAttr().");
  log.debug("Leaving escAttr().");
  return esc(text).replace(/"/g, "&quot;").replace(/\r/g, "&#xD;")
    .replace(/\n/g, "&#xA;").replace(/\t/g, "&#x9;");
}

// Attributes in canonical order: sorted by local name, because none of ours is
// in a namespace. Sorted HERE rather than written in order by each caller, for
// the reason this file exists at all — an attribute in the wrong order is a
// digest that does not match, and nothing anywhere says which attribute.
function attrs(pairs) {
  log.debug("Entering attrs().");
  log.debug("Leaving attrs().");
  return Object.keys(pairs || {})
    .filter(function (k) {
      return pairs[k] !== undefined && pairs[k] !== null && pairs[k] !== "";
    })
    .sort()
    .map(function (k) { return " " + k + "=\"" + escAttr(pairs[k]) + "\""; })
    .join("");
}

// Never self-closing. `<a/>` and `<a></a>` are the same infoset and are NOT the
// same octets, and canonical form is the second.
function el(name, pairs, inner) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return "<" + name + attrs(pairs) + ">" + (inner || "") + "</" + name + ">";
}

// An xsd:dateTime with no fractional seconds, which is what every SAML
// implementation emits and what this suite's refusal assertions quote back.
function iso(offsetMs) {
  log.debug("Entering iso().");
  log.debug("Leaving iso().");
  return new Date(Date.now() + (offsetMs || 0)).toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}

function id() {
  log.debug("Entering id().");
  log.debug("Leaving id().");
  // A SAML ID is an xsd:ID and may not start with a digit. The leading
  // underscore is what every implementation uses for that reason.
  return "_" + nodeCrypto.randomBytes(16).toString("hex");
}

// ---------------------------------------------------------------------------
// THE ASSERTION. Every option that is not simply a value is a way of building
// something WRONG, and each is named after the rule it breaks:
//
//   omitConditions, omitSubject, omitNameId, omitConfirmationData
//   notBefore / notOnOrAfter / confirmationNotOnOrAfter — null removes the
//       attribute, a string sets it, absent means a sensible window
//   recipient — null removes it
//   method — a confirmation method that is not bearer
//   unknownCondition — a <Condition> type nothing understands (SAML core
//       section 2.5.1 makes the assertion Invalid, which is RFC 7522 item 11)
//   version — "1.1", to send the wrong specification's document
//   id — a fixed one, so a replay can be built deliberately
// ---------------------------------------------------------------------------
function buildAssertion(o) {
  log.debug("Entering buildAssertion().");
  const options = o || {};
  const assertionId = options.id || id();
  const scd = options.omitConfirmationData ? "" :
    el("saml:SubjectConfirmationData", {
      NotOnOrAfter: options.confirmationNotOnOrAfter === null ? "" :
        (options.confirmationNotOnOrAfter || iso(120000)),
      Recipient: options.recipient === null ? "" :
        (options.recipient || options.audience),
      Address: options.address
    });
  const confirmation = el("saml:SubjectConfirmation",
                          { Method: options.method || BEARER }, scd);
  const audiences = options.audiences ||
    (options.audience ? [options.audience] : []);
  const audienceEls = audiences.map(function (one) {
    return el("saml:Audience", {}, esc(one));
  }).join("");
  const conditionsInner =
    (audienceEls ? el("saml:AudienceRestriction", {}, audienceEls) : "") +
    (options.unknownCondition
      ? el("saml:" + options.unknownCondition, {}, "") : "");
  const conditions = options.omitConditions ? "" :
    el("saml:Conditions", {
      NotBefore: options.notBefore === null ? "" :
        (options.notBefore || iso(-60000)),
      NotOnOrAfter: options.notOnOrAfter === null ? "" :
        (options.notOnOrAfter || iso(120000))
    }, conditionsInner);
  const attributeEls = Object.keys(options.attributes || {})
    .map(function (name) {
      const values = [].concat(options.attributes[name]);
      return el("saml:Attribute", { Name: name },
        values.map(function (v) {
          return el("saml:AttributeValue", {}, esc(v));
        }).join(""));
    }).join("");
  // RFC 7522 section 3 item 7: an <AuthnStatement> where the issuer
  // authenticated the subject itself, and NONE where the client is acting
  // autonomously on their behalf. Both are conforming and the job asserts that
  // this service reports which.
  const authn = options.authnStatement
    ? el("saml:AuthnStatement", { AuthnInstant: iso(0) },
        el("saml:AuthnContext", {},
          el("saml:AuthnContextClassRef", {},
             "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")))
    : "";
  const subject = options.omitSubject ? "" :
    el("saml:Subject", {},
      (options.omitNameId ? "" :
        el("saml:NameID",
           { Format: options.nameIdFormat ||
                     "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified" },
           esc(options.subject))) + confirmation);
  const inner = el("saml:Issuer", {}, esc(options.issuer)) + subject +
    conditions + authn +
    (attributeEls ? el("saml:AttributeStatement", {}, attributeEls) : "");
  const xml = "<saml:Assertion xmlns:saml=\"" + SAML_NS + "\"" +
    attrs({ ID: assertionId,
            IssueInstant: options.issueInstant || iso(0),
            Version: options.version || "2.0" }) + ">" + inner +
    "</saml:Assertion>";
  log.debug("Leaving buildAssertion().");
  return { id: assertionId, xml: xml };
}

// ---------------------------------------------------------------------------
// SIGN IT. Digest the assertion as it stands, build a canonical
// <ds:SignedInfo> over that digest, sign THOSE octets, and splice the
// <ds:Signature> in after the <saml:Issuer> — which is where the SAML 2.0
// schema puts it and is the only place a conforming verifier looks.
//
// `breakDigest` writes a digest that is not the assertion's, which is the one
// refusal a test cannot get any other way: every other bad document is refused
// on a rule, and this one is refused because the cryptography says so.
// `certPem` may be empty, which produces a signature with no <ds:KeyInfo> —
// the ordinary case for a party whose certificate is already registered.
// ---------------------------------------------------------------------------
function sign(built, privateKeyPem, certPem, opts) {
  log.debug("Entering sign().");
  const options = opts || {};
  const digest = nodeCrypto.createHash("sha256")
    .update(Buffer.from(built.xml, "utf8")).digest("base64");
  const signedInfo = "<ds:SignedInfo xmlns:ds=\"" + DS_NS + "\">" +
    el("ds:CanonicalizationMethod", { Algorithm: EXC_C14N }, "") +
    el("ds:SignatureMethod", { Algorithm: RSA_SHA256 }, "") +
    el("ds:Reference", { URI: "#" + built.id },
      el("ds:Transforms", {},
        el("ds:Transform", { Algorithm: ENVELOPED }, "") +
        el("ds:Transform", { Algorithm: EXC_C14N }, "")) +
      el("ds:DigestMethod", { Algorithm: SHA256 }, "") +
      el("ds:DigestValue", {},
         options.breakDigest ? "TgqfFkPodWJqI2+1c2YHTQ==" : digest)) +
    "</ds:SignedInfo>";
  const value = nodeCrypto.sign("sha256", Buffer.from(signedInfo, "utf8"),
                                privateKeyPem).toString("base64");
  const keyInfo = certPem
    ? el("ds:KeyInfo", {},
        el("ds:X509Data", {},
          el("ds:X509Certificate", {},
             String(certPem).replace(/-----[^-]+-----/g, "")
               .replace(/\s+/g, ""))))
    : "";
  const signature = "<ds:Signature xmlns:ds=\"" + DS_NS + "\">" + signedInfo +
    el("ds:SignatureValue", {}, value) + keyInfo + "</ds:Signature>";
  const marker = "</saml:Issuer>";
  const at = built.xml.indexOf(marker) + marker.length;
  log.debug("Leaving sign().");
  return built.xml.slice(0, at) + signature + built.xml.slice(at);
}

// RFC 7522 section 2.1: "The SAML Assertion XML data MUST be encoded using
// base64url ... and where the padding bits are set to zero."
function b64u(text) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(text, "utf8").toString("base64url");
}

// The encoding the specification does NOT ask for, so that a job can assert
// what this service does with it. Several widely-deployed stacks send it.
function b64(text) {
  log.debug("Entering b64().");
  log.debug("Leaving b64().");
  return Buffer.from(text, "utf8").toString("base64");
}

module.exports = { buildAssertion: buildAssertion, sign: sign, b64u: b64u,
                   b64: b64, iso: iso, id: id, BEARER: BEARER };
