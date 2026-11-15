// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: saml_wire_kit.js
//
// ===========================================================================
// THE PLUMBING OF THE D12 SAML JOBS (#444, phase 7) — A HELPER, NOT A JOB.
//
// The in-process SAML files (`saml2_force_authn.js`, `saml_interop_findings.js`,
// `saml_request_signatures.js`, `saml_signature_algorithms.js`,
// `saml_metadata_lifecycle.js`, `saml_artifact_and_simplesign.js`, ...)
// build AuthnRequests and walk the stack in a child process. Their D12 jobs
// ask the same of a running service, and each needs the same few things,
// which live here once, beside `oauth_wire_kit.js` (whose realm, person,
// browser and audit helpers they use):
//
//   * A SERVICE PROVIDER'S KEY PAIR AND CERTIFICATE, made here (node-forge),
//     RSA or EC, registered on the application as `samlSigningCertificate`;
//   * AN AUTHNREQUEST (and a LogoutRequest), built here with every attribute
//     a check varies, on the HTTP-Redirect binding signed over the query
//     string with any SigAlg, or unsigned, or on HTTP-POST;
//   * THE BROWSER'S WALK of `/saml2/sso` → the sign-in screen over
//     `/authn-api` → back, counting the trips to the screen, with the screen
//     answered, cancelled, or skipped (the return address presented without
//     authenticating, as a browser that never signed in would);
//   * the Response read off the auto-post form: its status codes, message,
//     AuthnInstant, class reference and attributes.
//
// OWNED HERE (MANIFEST.js's LOCAL_HELPERS).
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const zlib = require("zlib");
const path = require("path");
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const authnSignin = require("./authn_signin");

const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

function samlKit(K) {
  const log = K.log;
  log.debug("Entering samlKit().");

  // A self-signed certificate for a service provider: `alg` rsa (the
  // default, RSA 2048) or ec (P-256), made with the X.509 engine this
  // repository ships, as `sts_certificate_holder_rename.js` makes its CSR.
  async function credential(cn, alg) {
    log.debug("Entering credential(). " + cn);
    const x509 = require(path.join(REPO, "common", "crypto_impl",
                                   "x509.js"));
    const pair = alg === "ec"
      ? nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      : nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privatePem = pair.privateKey.export({ type: "pkcs8",
                                                format: "pem" });
    const publicPem = pair.publicKey.export({ type: "spki", format: "pem" });
    const pem = await x509.selfSignedCertPem({ subject: "CN=" + cn,
      publicPem: publicPem, privatePem: privatePem,
      signatureAlg: alg === "ec" ? "sha256-ecdsa" : "sha256-rsa",
      serial: nodeCrypto.randomBytes(8).toString("hex") });
    log.debug("Leaving credential().");
    return { certificatePem: pem, privateKeyPem: privatePem,
             alg: alg === "ec" ? "ec" : "rsa" };
  }

  function b64cert(pem) {
    log.debug("Entering b64cert().");
    log.debug("Leaving b64cert().");
    return String(pem).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  }

  // An AuthnRequest's XML. `o.issuer`, `o.acs`, `o.destination`,
  // `o.force`, `o.passive`, `o.context` (class URIs), `o.version`,
  // `o.issueInstant`, `o.id`, `o.binding` (ProtocolBinding).
  function authnRequestXml(o) {
    log.debug("Entering authnRequestXml().");
    const id = o.id || ("_wk" + nodeCrypto.randomBytes(10).toString("hex"));
    const xml = '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="' +
      (o.version || "2.0") + '" IssueInstant="' +
      (o.issueInstant || new Date().toISOString()) + '"' +
      (o.destination ? ' Destination="' + o.destination + '"' : "") +
      (o.acs ? ' AssertionConsumerServiceURL="' + o.acs + '"' : "") +
      ' ProtocolBinding="' + (o.binding || BINDING_POST) + '"' +
      (o.force ? ' ForceAuthn="true"' : "") +
      (o.passive ? ' IsPassive="true"' : "") + ">" +
      "<saml:Issuer>" + o.issuer + "</saml:Issuer>" +
      (o.context ? '<samlp:RequestedAuthnContext Comparison="exact">' +
        [].concat(o.context).map(function (one) {
          return "<saml:AuthnContextClassRef>" + one +
            "</saml:AuthnContextClassRef>";
        }).join("") + "</samlp:RequestedAuthnContext>" : "") +
      "</samlp:AuthnRequest>";
    log.debug("Leaving authnRequestXml().");
    return { id: id, xml: xml };
  }

  // A message on the HTTP-Redirect binding to `endpoint`: `o.sign` a
  // credential to sign the query with (`o.sigAlg`, RSA-SHA256 by default;
  // `o.signWith` another key), `o.relayState`, `o.param` (SAMLRequest or
  // SAMLResponse).
  function redirect(endpoint, xml, o) {
    log.debug("Entering redirect().");
    const opts = o || {};
    const param = opts.param || "SAMLRequest";
    let q = param + "=" + encodeURIComponent(
      zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64"));
    if (opts.relayState !== undefined) {
      q += "&RelayState=" + encodeURIComponent(opts.relayState);
    }
    if (opts.sign) {
      const sigAlg = opts.sigAlg || (opts.sign.alg === "ec" ? ECDSA_SHA256
                                                            : RSA_SHA256);
      q += "&SigAlg=" + encodeURIComponent(sigAlg);
      const hash = /sha1$/.test(sigAlg) ? "sha1" : "sha256";
      const key = (opts.signWith || opts.sign).privateKeyPem;
      const sig = nodeCrypto.sign(hash, Buffer.from(q), opts.sign.alg ===
        "ec" ? { key: key, dsaEncoding: "der" } : key);
      q += "&Signature=" + encodeURIComponent(sig.toString("base64"));
    }
    log.debug("Leaving redirect().");
    return endpoint + (endpoint.indexOf("?") >= 0 ? "&" : "?") + q;
  }

  // The SAML message a self-submitting form carries, decoded.
  function messageOf(text, field) {
    log.debug("Entering messageOf().");
    const m = new RegExp('name="' + (field || "SAMLResponse") +
                         '" value="([^"]+)"').exec(String(text || ""));
    log.debug("Leaving messageOf().");
    return m ? Buffer.from(m[1].replace(/&#x2B;|&#43;/g, "+")
      .replace(/&#x3D;|&#61;/g, "=").replace(/&#x2F;|&#47;/g, "/"),
    "base64").toString("utf8") : "";
  }

  // What a Response says: its status codes (local names), message,
  // AuthnInstant, class reference, AuthenticationMethod (SAML 1.1).
  function responseOf(text) {
    log.debug("Entering responseOf().");
    const xml = messageOf(text);
    if (!xml) {
      log.debug("Leaving responseOf(). None.");
      return null;
    }
    const codes = [];
    const re = /StatusCode Value="([^"]+)"/g;
    let one = re.exec(xml);
    while (one) {
      codes.push(one[1].split(":").pop());
      one = re.exec(xml);
    }
    const pick = function (r) {
      const m = r.exec(xml);
      return m ? m[1] : "";
    };
    log.debug("Leaving responseOf().");
    return { xml: xml, codes: codes,
             authnInstant: pick(/AuthnInstant="([^"]+)"/),
             message: pick(/<samlp:StatusMessage>([^<]*)</),
             classRef: pick(/AuthnContextClassRef>([^<]*)</),
             method: pick(/AuthenticationMethod="([^"]+)"/),
             inResponseTo: pick(/<samlp:Response[^>]*InResponseTo="([^"]+)"/) };
  }

  function cookieOf(b) {
    log.debug("Entering cookieOf().");
    log.debug("Leaving cookieOf().");
    return Object.keys(b.jar).map(function (k) {
      return k + "=" + b.jar[k];
    }).join("; ");
  }

  function keep(b, lines) {
    log.debug("Entering keep().");
    (lines || []).forEach(function (line) {
      const pair = String(line).split(";")[0];
      const at = pair.indexOf("=");
      if (at > 0) {
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(line)) {
          delete b.jar[pair.slice(0, at)];
        } else {
          b.jar[pair.slice(0, at)] = value;
        }
      }
    });
    log.debug("Leaving keep().");
  }

  // THE WALK. `start` is a URL the browser `b` opens. At the sign-in screen
  // `o.at` decides: 'login' (`o.username`, `o.password`), 'cancel', or
  // 'skip' (the screen's own return address presented without signing in).
  // Consent is allowed. Answers the last answer, the trips to the screen,
  // the screen's view the first time, and the Response.
  async function drive(id, b, start, o) {
    log.debug("Entering drive().");
    const opts = Object.assign({ at: "login" }, o || {});
    const rb = K.rb(id);
    let r = await b.go(start);
    let screens = 0;
    let view = null;
    let action = opts.at;
    for (let hop = 0; hop < 14; hop += 1) {
      const loc = r.location || "";
      if ((r.status === 302 || r.status === 303) &&
          /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(loc)) {
        screens += 1;
        const at = /^https?:/.test(loc) ? loc : K.base + loc;
        const opened = await authnSignin.screen(rb, at,
                                                { cookie: cookieOf(b) });
        keep(b, opened.setCookies);
        if (!view) {
          view = opened.view || {};
        }
        if (action === "skip") {
          // THE RETURN ADDRESS WITHOUT SIGNING IN: the screen's view does
          // not carry it, so it is read off the Cancel answer — the held
          // request's `?rid=` — with the cancellation taken off, which is
          // what a browser that never authenticated would present.
          const cancelled = await authnSignin.submit(rb, at,
            { action: "cancel" }, { screen: opened, cookie: cookieOf(b) });
          keep(b, cancelled.setCookies);
          const u = new URL(cancelled.location || "/", K.base);
          u.searchParams.delete("authn_error");
          u.searchParams.delete("authn_error_description");
          assert.ok(/[?&](rid|fid)=/.test(u.search),
                    "the Cancel answer names no held request: " +
                    String(cancelled.location));
          action = "done";
          r = await b.go(u.toString());
          continue;
        }
        if (action === "done") {
          break;
        }
        const a = await authnSignin.submit(rb, at, action === "cancel"
          ? { action: "cancel" }
          : { action: "login", username: opts.username,
              password: opts.password || "anything" },
        { screen: opened, cookie: cookieOf(b) });
        keep(b, a.setCookies);
        action = "done";
        if (a.next !== "redirect" || !a.location) {
          log.debug("Leaving drive(). The screen answered " + a.next);
          return { final: r, screens: screens, view: view, answer: a,
                   response: null };
        }
        r = await b.go(a.location);
        continue;
      }
      if (authnSignin.isConsent(loc)) {
        const c = await K.consent(b, /^https?:/.test(loc) ? loc
                                                          : K.base + loc);
        r = c;
        continue;
      }
      if ((r.status === 302 || r.status === 303) && loc &&
          (/^\//.test(loc) || loc.indexOf(K.base) === 0)) {
        r = await b.go(loc);
        continue;
      }
      break;
    }
    log.debug("Leaving drive(). " + r.status + " after " + screens);
    return { final: r, screens: screens, view: view,
             response: responseOf(r.text) };
  }

  log.debug("Leaving samlKit().");
  return { NS_SAMLP: NS_SAMLP, NS_SAML: NS_SAML, BINDING_POST: BINDING_POST,
           RSA_SHA256: RSA_SHA256, RSA_SHA1: RSA_SHA1,
           ECDSA_SHA256: ECDSA_SHA256, credential: credential,
           b64cert: b64cert, authnRequestXml: authnRequestXml,
           redirect: redirect, messageOf: messageOf, responseOf: responseOf,
           drive: drive, cookieOf: cookieOf, keep: keep };
}

module.exports = { samlKit: samlKit };
