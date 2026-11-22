// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/pep_app_identity.js
//
// ===========================================================================
// WHAT `/pep-app` READS OF THE IDENTITY THE REMOTE PEP FORWARDS (#1760, D11).
//
// The proxy forwards the identity it established in one of three ways per
// route: headers it names, a JWT access token the service issued for the
// application (`Authorization: Bearer`), or a SAML 2.0 assertion the service
// issued for the application, which the proxy POSTs server-side to the
// application's ACS before forwarding the request with the cookie the ACS
// set. `pep_app.js` already echoes every header; this module adds the two
// things a plain echo cannot show:
//
//   * **A BEARER JWT, DECODED AND CHECKED.** Its header and payload as sent
//     (unverified), and `verified`: the signature against the realm's JWKS,
//     at the URL `/pep-app/saml/_setup` named (`jwksUrl`), or else the
//     token's own `iss` + `/oauth2/jwks`. RS, PS, ES and EdDSA, with node's
//     crypto. `expired` beside it. Nothing is refused here: the echo says
//     what it saw, and the job asserts it.
//   * **THE ACS**, `POST /pep-app/saml/acs`: the `SAMLResponse`'s XML
//     signature checked with the realm's signing certificate (read from the
//     IdP metadata URL `_setup` named, or the certificates it was handed),
//     the assertion taken from what the signature COVERS (not from the
//     document around it, so a wrapped assertion is not read), its audience
//     the configured SP entity and its conditions current. Accepted, it opens
//     a session behind a `pep_app_saml` cookie holding `{ nameId,
//     attributes, issuer, sessionIndex }`, and every echo carries `saml`
//     while the cookie names a live session.
//
// **`POST /pep-app/saml/_setup` IS UNAUTHENTICATED**, like everything else
// in this development-only container: `{ audience, metadataUrl?,
// certificates?, jwksUrl?, caPem? }`. The job calls it once it knows its
// realm, because the realm does not exist when the stack starts and no
// environment variable could name it.
//
// **WHAT THIS MODULE DIALS IS BOUNDED BY ITS CONFIGURATION, NOT BY THE
// CALLER (2026-11-20, CodeQL js/request-forgery).** A metadata URL, a JWKS
// URL and a token's own `iss` all arrive in a request, so each is dialled
// only when its origin is EXACTLY one of the origins the companion was
// started with (`COMPANION_STS_URL`, `COMPANION_STS_PUBLIC_URL`), and the
// request is built on that configured origin rather than on the text it
// was given. Anything else is refused before a socket is opened, and the
// refusal says which origins are allowed.
//
// **AND IT NEVER DIALS WITHOUT VERIFYING THE CERTIFICATE (CodeQL
// js/disabling-certificate-validation).** It used to follow
// `COMPANION_STS_TLS_INSECURE`, the demonstrations' switch, and turn the
// check off. Now the anchor is `COMPANION_STS_CA_FILE` when it is given,
// else the `caPem` `_setup` was handed (the job's own anchor for this run's
// service Root, which no image can hold), else node's own roots. A caller
// naming an anchor is no wider than what `_setup` already is: the same
// caller names the certificates the ACS trusts, and it cannot move the
// dial to another origin.
//
// xml-crypto and @xmldom/xmldom, pinned in the companion's own lockfile at
// the versions the service uses; required lazily. No timer: the JWKS cache
// and the sessions expire where they are read and are capped on insert.
// ===========================================================================

const crypto = require("crypto");
const http = require("http");
const https = require("https");
const fs = require("fs");
const util = require("./companion_util.js");

const log = util.logger("iya-sts-companion-pep-app-identity");

const COOKIE = "pep_app_saml";
const MAX_SESSIONS = 2000;
const SESSION_TTL_MS = 60 * 60 * 1000;
const JWKS_TTL_MS = 60 * 1000;
const FETCH_MAX_BYTES = 1024 * 1024;
const FETCH_TIMEOUT_MS = 10000;

/**
 * base64url (or base64) text as a Buffer.
 *
 * @param {string} text - the text
 * @returns {Buffer} the bytes
 */
function bytesOf(text) {
  log.debug("Entering bytesOf().");
  log.debug("Leaving bytesOf().");
  return Buffer.from(String(text || "").replace(/-/g, "+")
    .replace(/_/g, "/"), "base64");
}

/**
 * The parts of a compact JWS, decoded, or null when it is not one.
 *
 * @param {string} token - the token
 * @returns {object|null} `{ header, payload, signingInput, signature }`
 */
function jwsParts(token) {
  log.debug("Entering jwsParts().");
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    log.debug("Leaving jwsParts(). Not three parts.");
    return null;
  }
  try {
    const out = { header: JSON.parse(bytesOf(parts[0]).toString("utf8")),
                  payload: JSON.parse(bytesOf(parts[1]).toString("utf8")),
                  signingInput: parts[0] + "." + parts[1],
                  signature: bytesOf(parts[2]) };
    log.debug("Leaving jwsParts().");
    return out;
  } catch (e) {
    log.debug("Caught in jwsParts(): " + ((e && e.message) || e));
    log.debug("Leaving jwsParts(). Not JSON.");
    return null;
  }
}

/**
 * How node verifies a JWS algorithm.
 *
 * @param {string} alg - the `alg`
 * @returns {object|null} `{ hash, padding, saltLength, dsaEncoding }`
 */
function verifierFor(alg) {
  log.debug("Entering verifierFor(). " + alg);
  const m = /^(RS|PS|ES)(256|384|512)$/.exec(String(alg || ""));
  let out = null;
  if (alg === "EdDSA") {
    out = { hash: null };
  } else if (m) {
    const hash = "sha" + m[2];
    if (m[1] === "RS") {
      out = { hash: hash };
    } else if (m[1] === "PS") {
      out = { hash: hash, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
              saltLength: Number(m[2]) / 8 };
    } else {
      out = { hash: hash, dsaEncoding: "ieee-p1363" };
    }
  }
  log.debug("Leaving verifierFor().");
  return out;
}

/**
 * The origins a list of configured URLs names, each mapped to itself: the
 * value is what a request is built on, so the host dialled is always a
 * configured string. A URL that does not parse is left out.
 *
 * @param {string[]} [urls] - the configured URLs
 * @returns {Map<string, string>} origin -> origin
 */
function originsOf(urls) {
  log.debug("Entering originsOf().");
  const out = new Map();
  [].concat(urls || []).forEach(function (one) {
    try {
      const parsed = new URL(String(one || ""));
      if (parsed.protocol === "https:" || parsed.protocol === "http:") {
        out.set(parsed.origin, parsed.origin);
      }
    } catch (e) {
      log.debug("Caught in originsOf(): " + ((e && e.message) || e));
    }
  });
  log.debug("Leaving originsOf(). " + out.size);
  return out;
}

/**
 * The identity half of `/pep-app`.
 */
class PepAppIdentity {
  /**
   * @param {object} [opts] - `caFile` (the anchor for dialling the
   *   service) and `origins` (the service URLs the companion was started
   *   with; only their origins are ever dialled)
   */
  constructor(opts) {
    log.debug("Entering PepAppIdentity.constructor().");
    const o = opts || {};
    this.caFile = String(o.caFile || "");
    this.origins = originsOf(o.origins);
    this.config = { audience: "", certificates: [], jwksUrl: "",
                    caPem: "" };
    this.jwks = new Map();
    this.sessions = new Map();
    log.debug("Leaving PepAppIdentity.constructor().");
  }

  /**
   * One GET of a URL, as text, bounded in size and time.
   *
   * @param {string} url - the URL
   * @returns {Promise<string>} the body
   */
  fetchText(url) {
    log.debug("Entering PepAppIdentity.fetchText(). " + url);
    const why = this.refusalOf(url);
    if (why) {
      log.debug("Leaving PepAppIdentity.fetchText(). Refused.");
      return Promise.reject(new Error(why));
    }
    const asked = new URL(url);
    // Built on the CONFIGURED origin, never on the text the caller sent:
    // the comparison above made them equal, and this keeps the host this
    // dials one the companion was started with.
    const base = this.origins.get(asked.origin);
    const target = new URL(asked.pathname + asked.search, base);
    const secure = target.protocol === "https:";
    const options = { method: "GET", timeout: FETCH_TIMEOUT_MS };
    if (secure) {
      // Verification stays on whatever is given; only the anchor varies.
      if (this.caFile) {
        options.ca = fs.readFileSync(this.caFile);
      } else if (this.config.caPem) {
        options.ca = this.config.caPem;
      }
    }
    log.debug("Leaving PepAppIdentity.fetchText().");
    return new Promise(function (resolve, reject) {
      const request = (secure ? https : http).request(target, options,
                                                      function (res) {
        const chunks = [];
        let size = 0;
        res.on("data", function (chunk) {
          size += chunk.length;
          if (size > FETCH_MAX_BYTES) {
            request.destroy(new Error(url + " answered over 1 MiB"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", function () {
          if (res.statusCode !== 200) {
            reject(new Error(url + " answered " + res.statusCode));
            return;
          }
          resolve(Buffer.concat(chunks).toString("utf8"));
        });
      });
      request.on("timeout", function () {
        request.destroy(new Error(url + " did not answer in time"));
      });
      request.on("error", reject);
      request.end();
    });
  }

  /**
   * Why a URL may not be dialled, or '' when it may: it must parse, be
   * http or https, and have EXACTLY one of the configured origins. A
   * substring or prefix test would let `https://sts:8081.evil.test` or
   * `https://evil.test/?https://sts:8081` through; `URL.origin` cannot.
   *
   * @param {string} url - the URL a caller named
   * @returns {string} the refusal, or ''
   */
  refusalOf(url) {
    log.debug("Entering PepAppIdentity.refusalOf().");
    let parsed = null;
    try {
      parsed = new URL(String(url || ""));
    } catch (e) {
      log.debug("Caught in PepAppIdentity.refusalOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving PepAppIdentity.refusalOf(). Not a URL.");
      return "not an absolute URL: " + String(url || "");
    }
    if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
        !this.origins.has(parsed.origin)) {
      log.debug("Leaving PepAppIdentity.refusalOf(). Not allowed.");
      return "the companion dials only " +
             (Array.from(this.origins.keys()).join(", ") || "nothing") +
             " (COMPANION_STS_URL, COMPANION_STS_PUBLIC_URL), not " +
             parsed.origin;
    }
    log.debug("Leaving PepAppIdentity.refusalOf(). Allowed.");
    return "";
  }

  /**
   * `POST /pep-app/saml/_setup`: what the ACS and the JWT check trust.
   *
   * @param {object} body - `{ audience, metadataUrl?, certificates?,
   *   jwksUrl? }`
   * @returns {Promise<object>} what was taken
   */
  async setup(body) {
    log.debug("Entering PepAppIdentity.setup().");
    const b = body || {};
    const certificates = [].concat(b.certificates || [])
      .map(String).filter(Boolean);
    // Both URLs are checked before anything is dialled or kept, so a
    // refused setup leaves the previous one in force.
    const refused = [b.metadataUrl, b.jwksUrl].filter(Boolean)
      .map((one) => this.refusalOf(String(one))).filter(Boolean)[0];
    if (refused) {
      log.debug("Leaving PepAppIdentity.setup(). Refused.");
      return { ok: false, refused: true, why: refused };
    }
    const caPem = String(b.caPem || "");
    if (caPem && caPem.indexOf("-----BEGIN CERTIFICATE-----") < 0) {
      log.debug("Leaving PepAppIdentity.setup(). Not a PEM.");
      return { ok: false, refused: true,
               why: "caPem holds no PEM certificate" };
    }
    this.config.caPem = caPem;
    if (b.metadataUrl) {
      const xml = await this.fetchText(String(b.metadataUrl));
      const re = /<(?:[A-Za-z0-9_-]+:)?X509Certificate>([^<]+)</g;
      let m;
      while ((m = re.exec(xml)) !== null) {
        const b64 = m[1].replace(/\s+/g, "");
        certificates.push("-----BEGIN CERTIFICATE-----\n" +
          b64.replace(/(.{64})/g, "$1\n").replace(/\n$/, "") +
          "\n-----END CERTIFICATE-----\n");
      }
    }
    this.config = { audience: String(b.audience || ""),
                    certificates: certificates,
                    jwksUrl: String(b.jwksUrl || ""),
                    caPem: caPem };
    this.jwks.clear();
    log.info("pep-app: the ACS trusts " + certificates.length +
             " signing certificate(s) for audience " +
             (this.config.audience || "(none)") + "; JWTs are checked " +
             "against " + (this.config.jwksUrl || "their own iss"));
    log.debug("Leaving PepAppIdentity.setup().");
    return { ok: true, audience: this.config.audience,
             certificates: certificates.length,
             jwksUrl: this.config.jwksUrl };
  }

  /**
   * A JWKS's keys, cached for a minute where they are read.
   *
   * @param {string} url - the JWKS URL
   * @returns {Promise<object[]>} the keys
   */
  async keysAt(url) {
    log.debug("Entering PepAppIdentity.keysAt(). " + url);
    const held = this.jwks.get(url);
    if (held && held.expires > Date.now()) {
      log.debug("Leaving PepAppIdentity.keysAt(). Cached.");
      return held.keys;
    }
    const keys = (JSON.parse(await this.fetchText(url)).keys) || [];
    while (this.jwks.size >= 16) {
      this.jwks.delete(this.jwks.keys().next().value);
    }
    this.jwks.set(url, { keys: keys, expires: Date.now() + JWKS_TTL_MS });
    log.debug("Leaving PepAppIdentity.keysAt(). " + keys.length);
    return keys;
  }

  /**
   * An `Authorization: Bearer <JWT>` read and checked, or null when the
   * header carries no JWT.
   *
   * @param {string} authorization - the header
   * @returns {Promise<object|null>} `{ header, payload, verified, expired,
   *   why }`
   */
  async bearerJwt(authorization) {
    log.debug("Entering PepAppIdentity.bearerJwt().");
    const m = /^Bearer\s+(\S+)$/i.exec(String(authorization || ""));
    const parts = m ? jwsParts(m[1]) : null;
    if (!parts) {
      log.debug("Leaving PepAppIdentity.bearerJwt(). No JWT.");
      return null;
    }
    const out = { header: parts.header, payload: parts.payload,
                  verified: false, expired: typeof parts.payload.exp ===
                    "number" && parts.payload.exp * 1000 < Date.now(),
                  why: "" };
    const url = this.config.jwksUrl || (parts.payload.iss
      ? util.stripTrailingSlashes(String(parts.payload.iss)) + "/oauth2/jwks"
      : "");
    const how = verifierFor(parts.header.alg);
    if (!url || !how) {
      out.why = !url ? "no JWKS to check it against"
                     : "unsupported alg " + parts.header.alg;
      log.debug("Leaving PepAppIdentity.bearerJwt(). " + out.why);
      return out;
    }
    const refused = this.refusalOf(url);
    if (refused) {
      out.why = refused;
      log.debug("Leaving PepAppIdentity.bearerJwt(). " + out.why);
      return out;
    }
    try {
      const keys = await this.keysAt(url);
      const key = keys.filter(function (one) {
        return one.kid === parts.header.kid;
      })[0] || (keys.length === 1 ? keys[0] : null);
      if (!key) {
        out.why = "no key " + parts.header.kid + " at " + url;
      } else {
        const options = { key: crypto.createPublicKey({ key: key,
                                                        format: "jwk" }) };
        if (how.padding) {
          options.padding = how.padding;
          options.saltLength = how.saltLength;
        }
        if (how.dsaEncoding) {
          options.dsaEncoding = how.dsaEncoding;
        }
        out.verified = crypto.verify(how.hash,
                                     Buffer.from(parts.signingInput),
                                     options, parts.signature);
        out.why = out.verified ? "" : "the signature does not verify";
      }
    } catch (e) {
      log.debug("Caught in PepAppIdentity.bearerJwt(): " +
                ((e && e.message) || e));
      // A fixed sentence: the echo is a response, and what the error says
      // (and its stack) goes to the log, as everywhere in the companion.
      log.warn("pep-app: the JWKS at " + url + " could not be read: " +
               ((e && e.stack) || e));
      out.why = "could not check it: the JWKS at " + url + " could not be " +
                "read (the companion's log says why)";
    }
    log.debug("Leaving PepAppIdentity.bearerJwt(). " + out.verified);
    return out;
  }

  /**
   * A `SAMLResponse` checked, answering the assertion's facts or why not.
   *
   * @param {string} encoded - the form's `SAMLResponse`, base64
   * @returns {object} `{ ok, why?, nameId, attributes, issuer,
   *   sessionIndex, notOnOrAfter }`
   */
  checkResponse(encoded) {
    log.debug("Entering PepAppIdentity.checkResponse().");
    const { SignedXml } = require("xml-crypto");
    const { DOMParser } = require("@xmldom/xmldom");
    const refuse = function (why) {
      log.debug("Entering refuse().");
      log.debug("Leaving refuse().");
      return { ok: false, why: why };
    };
    if (!this.config.certificates.length) {
      log.debug("Leaving PepAppIdentity.checkResponse(). Not set up.");
      return refuse("no signing certificate: POST /pep-app/saml/_setup first");
    }
    const xml = Buffer.from(String(encoded || ""), "base64").toString("utf8");
    let doc;
    try {
      doc = new DOMParser().parseFromString(xml, "text/xml");
    } catch (e) {
      log.debug("Caught in PepAppIdentity.checkResponse(): " +
                ((e && e.message) || e));
      log.debug("Leaving PepAppIdentity.checkResponse(). Not XML.");
      return refuse("the SAMLResponse is not XML");
    }
    const signatures = Array.from(doc.getElementsByTagNameNS(
      "http://www.w3.org/2000/09/xmldsig#", "Signature"));
    let covered = null;
    for (const node of signatures) {
      for (const pem of this.config.certificates) {
        try {
          const sig = new SignedXml({ publicCert: pem });
          sig.loadSignature(node);
          if (sig.checkSignature(xml) &&
              typeof sig.getSignedReferences === "function") {
            const refs = sig.getSignedReferences();
            if (refs && refs.length) {
              covered = refs[0];
            }
          }
        } catch (e) {
          log.debug("Caught in PepAppIdentity.checkResponse(): " +
                    ((e && e.message) || e));
          // Not this certificate, or not a signature it can check.
        }
        if (covered) {
          break;
        }
      }
      if (covered) {
        break;
      }
    }
    if (!covered) {
      log.debug("Leaving PepAppIdentity.checkResponse(). Unsigned.");
      return refuse("no signature verifies under the realm's certificate");
    }
    // THE ASSERTION IS READ FROM WHAT THE SIGNATURE COVERS, never from the
    // document around it.
    const signed = new DOMParser().parseFromString(covered, "text/xml");
    const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    const root = signed.documentElement;
    const assertion = root && root.localName === "Assertion"
      ? root : signed.getElementsByTagNameNS(SAML, "Assertion")[0];
    if (!assertion) {
      log.debug("Leaving PepAppIdentity.checkResponse(). No assertion.");
      return refuse("the signed part holds no Assertion");
    }
    const textOf = function (parent, name) {
      log.debug("Entering textOf().");
      const el = parent.getElementsByTagNameNS(SAML, name)[0];
      log.debug("Leaving textOf().");
      return el ? String(el.textContent || "").trim() : "";
    };
    const audiences = Array.from(assertion.getElementsByTagNameNS(SAML,
      "Audience")).map(function (el) {
      return String(el.textContent || "").trim();
    });
    if (this.config.audience &&
        audiences.indexOf(this.config.audience) < 0) {
      log.debug("Leaving PepAppIdentity.checkResponse(). Audience.");
      return refuse("the assertion is for " + JSON.stringify(audiences) +
                    ", not " + this.config.audience);
    }
    const conditions = assertion.getElementsByTagNameNS(SAML,
                                                        "Conditions")[0];
    const notOnOrAfter = conditions
      ? String(conditions.getAttribute("NotOnOrAfter") || "") : "";
    const notBefore = conditions
      ? String(conditions.getAttribute("NotBefore") || "") : "";
    const now = Date.now();
    if (notOnOrAfter && Date.parse(notOnOrAfter) <= now) {
      log.debug("Leaving PepAppIdentity.checkResponse(). Expired.");
      return refuse("the assertion's conditions ended at " + notOnOrAfter);
    }
    if (notBefore && Date.parse(notBefore) > now + 60000) {
      log.debug("Leaving PepAppIdentity.checkResponse(). Not yet.");
      return refuse("the assertion's conditions begin at " + notBefore);
    }
    const attributes = {};
    Array.from(assertion.getElementsByTagNameNS(SAML, "Attribute"))
      .forEach(function (el) {
        const name = String(el.getAttribute("Name") || "");
        attributes[name] = Array.from(el.getElementsByTagNameNS(SAML,
          "AttributeValue")).map(function (v) {
          return String(v.textContent || "").trim();
        });
      });
    const statement = assertion.getElementsByTagNameNS(SAML,
                                                       "AuthnStatement")[0];
    const out = { ok: true, nameId: textOf(assertion, "NameID"),
                  attributes: attributes, issuer: textOf(assertion, "Issuer"),
                  sessionIndex: statement
                    ? String(statement.getAttribute("SessionIndex") || "")
                    : "",
                  notOnOrAfter: notOnOrAfter };
    log.debug("Leaving PepAppIdentity.checkResponse(). " + out.nameId);
    return out;
  }

  /**
   * `POST /pep-app/saml/acs`: the response checked and, accepted, a session
   * opened.
   *
   * @param {Buffer} bytes - the form body
   * @returns {object} `{ status, cookie?, saml?, why? }`
   */
  acs(bytes) {
    log.debug("Entering PepAppIdentity.acs().");
    const form = util.formOf(bytes || Buffer.alloc(0));
    const checked = this.checkResponse(form.SAMLResponse);
    if (!checked.ok) {
      log.info("pep-app: the ACS refused a SAMLResponse: " + checked.why);
      log.debug("Leaving PepAppIdentity.acs(). Refused.");
      return { status: 403, why: checked.why };
    }
    while (this.sessions.size >= MAX_SESSIONS) {
      this.sessions.delete(this.sessions.keys().next().value);
    }
    const id = crypto.randomBytes(24).toString("base64url");
    const until = Math.min(Date.now() + SESSION_TTL_MS,
                           checked.notOnOrAfter
                             ? Date.parse(checked.notOnOrAfter) + 3600000
                             : Infinity);
    const saml = { nameId: checked.nameId, attributes: checked.attributes,
                   issuer: checked.issuer,
                   sessionIndex: checked.sessionIndex };
    this.sessions.set(id, { saml: saml, expires: until });
    log.info("pep-app: the ACS accepted an assertion about " +
             checked.nameId + " from " + checked.issuer);
    log.debug("Leaving PepAppIdentity.acs(). Accepted.");
    return { status: 200, saml: saml,
             cookie: COOKIE + "=" + id + "; Path=/pep-app; HttpOnly; " +
                     "SameSite=Lax" };
  }

  /**
   * The SAML session a request's cookie names, or null.
   *
   * @param {object} req - the request
   * @returns {object|null} `{ nameId, attributes, issuer, sessionIndex }`
   */
  sessionOf(req) {
    log.debug("Entering PepAppIdentity.sessionOf().");
    const id = util.cookiesOf(req)[COOKIE] || "";
    const held = id ? this.sessions.get(id) : null;
    if (held && held.expires <= Date.now()) {
      this.sessions.delete(id);
      log.debug("Leaving PepAppIdentity.sessionOf(). Expired.");
      return null;
    }
    log.debug("Leaving PepAppIdentity.sessionOf().");
    return held ? held.saml : null;
  }
}

module.exports = { PepAppIdentity: PepAppIdentity, COOKIE: COOKIE,
                   jwsParts: jwsParts };
