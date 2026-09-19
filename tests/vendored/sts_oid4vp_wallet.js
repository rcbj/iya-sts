"use strict";
//
// File: sts_oid4vp_wallet.js
//
// ---------------------------------------------------------------------------
// OPENID4VP OVER THE NETWORK, WITH THIS FILE AS THE WALLET (2026-09-18).
//
// `/authn/wallet` (`oid4vc/vc_signin.ts`) turns a verified presentation into
// a session, and until this job every assertion about it was made IN PROCESS
// (`tests/oid4vp_sign_in.js` and its three siblings, on `tests/wallet_kit.js`)
// — against a stack on a loopback port, with settings flipped from inside and
// issuance done by minting a pre-authorized code with the service's own
// functions. That proves the logic. It cannot prove that a deployed service,
// behind a load balancer, several nodes answering one sign-in between them,
// in PRODUCT mode, does the same thing for a wallet that knows only what is
// on the wire. This job is that wallet, and it runs against whatever the
// service URL names — testidp's three active-active nodes as readily as a
// local development stack.
//
// WHAT IT DOES, IN ORDER:
//
//   0. It ASKS what the service is (`service_facts.js`): the mode, whether
//      `oid4vp.signIn` is on, and which formats a sign-in asks in. It changes
//      no setting — the owner's rule — and where the wallet sign-in is off it
//      asserts the documented refusal instead (the screen offers no wallet,
//      the door answers 403) and covers only what does not need the door.
//   1. EVERYTHING IT NEEDS IS CREATED BEFOREHAND through `/admin-api`: a
//      person with a real password and directory attributes, and a PUBLIC
//      wallet client registered for the authorization code grant, its
//      redirect URI and the credential scopes.
//   2. ISSUANCE, the way a wallet does it (OpenID4VCI): the person signs in
//      with their password through the authorization code flow with PKCE, the
//      code is redeemed for an access token THIS REALM ISSUED — a product-mode
//      credential endpoint refuses one it cannot verify (2026-09-18), and only
//      a credential issued on a verified token is recorded as one that may sign
//      anybody in (`vc_issued.ts`, rule 3ar) — then a c_nonce, a proof of
//      possession of a fresh holder key, and a HOLDER-BOUND `dc+sd-jwt` (and a
//      `jwt_vc_json`) credential naming the person's `urn:uuid:` subject.
//   3. THE SIGN-IN (OpenID4VP, `direct_post`): an OIDC authorization request
//      reaches the sign-in screen, the screen's wallet link starts a
//      transaction in one "browser" (a cookie jar), the wait page hands the
//      wallet a request by reference, the SIGNED request object is fetched and
//      its signature checked against the realm's published key, the wallet
//      POSTs a vp_token (the SD-JWT VC plus a Key Binding JWT carrying the
//      request's nonce, its client_id as audience and `sd_hash`), and the
//      browser collects with the `response_code` it is sent back with. The
//      result is checked THREE ways: the browser holds a session cookie; the
//      authorization request that was waiting completes, and its ID Token
//      names the credential's subject with `amr` "pop"; and `/admin-api/
//      sessions` lists one more wallet session for the person.
//   4. THE REFUSALS, each of which must sign NOBODY in — no session cookie, a
//      403 wait page with the reason on it, and no new session on
//      `/admin-api/sessions`: a Key Binding JWT for another nonce; for
//      another audience; none at all; one signed by a key the credential is
//      not bound to; a credential this realm never issued (signed by a key of
//      this file's own); a second `direct_post` to a transaction already
//      answered; the wait page asked by a browser that did not start the
//      sign-in, before and after the answer and WITH the response_code; a
//      wrong response_code; and a sign-in collected a second time. The
//      protocol's error is asserted where the protocol defines one — OpenID4VP
//      section 8.4's `invalid_request` from the response endpoint — and the
//      page's refusal where it is the browser's. (The `STS-VC-*` codes are an
//      operator's names and are never sent, so this job cannot see them; the
//      in-process files assert those.)
//   5. A SECOND FORMAT: a `jwt_vc_json` credential signs the same person in
//      with a VP JWT signed by its bound key, and a VP JWT for another nonce
//      does not. `ldp_vc` is NOT driven here — its presentation is a bbs-2023
//      derived proof, and the only BBS implementation in this tree is the
//      service's own, which an independent wallet may not borrow.
//   6. THE ACCESS TOKEN THE ISSUER WILL NOT BELIEVE: a token signed by a key
//      of this file's own. In product mode the credential endpoint refuses it
//      (`invalid_token`); in development it issues on it as it always has, and
//      that credential VERIFIES at the sign-in and signs nobody in.
//   7. THE VERIFIER AT `/oid4vp/start` (the bar door): a request by
//      reference for the configured claims, answered with the Disclosures it
//      asks for — accepted, reported on `/oid4vp/result`, and no session — and
//      the same answer for another nonce, refused.
//
// THE WALLET IS INDEPENDENT. Every key, signature, hash and Disclosure below
// is made with node's own `crypto`, and nothing is borrowed from the
// service's code or from the parent project's wallet: a wallet that shared the
// service's reading of the specification would agree with it where both are
// wrong and interoperate with nobody (`tests/wallet_kit.js` says the same).
//
// OWNED HERE (local: true): `/authn/wallet` is this repository's own door.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads,
  // for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_oid4vp_wallet",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

// The two credential configurations this job asks for, by the identifiers the
// issuer's metadata publishes. Overridable for a deployment that names them
// differently; each is checked against the metadata for its format below, so
// a wrong override fails as that rather than as a refused credential.
const SD_JWT_CONFIG = process.env.OID4VCI_SDJWT_CONFIG_ID ||
                      "IdentityCredential";
const JWT_VC_CONFIG = process.env.OID4VCI_JWT_CONFIG_ID ||
                      "IdentityCredentialJwtVcJson";

// The wallet client. Stable across runs, so a kept service does not collect
// one registry entry per run; `registry.provision()` reconciles it.
const CLIENT_ID = "sts-oid4vp-wallet-job";
const REDIRECT_URI = "https://wallet.sts-oid4vp-wallet-job.example.test/cb";

// The person, unique per run, so nothing another job does to its own people
// can reach this one and a leftover row names the file that made it.
const HOLDER = usernameFor("oid4vp-wallet");
const HOLDER_PASSWORD = "Oid4vp-wallet-" +
  crypto.randomBytes(9).toString("base64url") + "-Aa1!";

// What a session started by the wallet door calls itself on /admin-api/
// sessions (`vc_signin.ts`'s VIA). Matched loosely — the row is recognised by
// its `amr` as well — so a reworded label fails one check, not the job.
const WALLET_VIA = /OpenID4VP/;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// BYTES AND JOSE, with node's crypto and nothing else.
// ---------------------------------------------------------------------------
function b64u(input) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(input).toString("base64url");
}

function partOf(jwt, index) {
  log.debug("Entering partOf().");
  const segment = String(jwt || "").split(".")[index];
  log.debug("Leaving partOf().");
  return JSON.parse(Buffer.from(String(segment || ""), "base64url")
    .toString("utf8"));
}

function headerOf(jwt) {
  log.debug("Entering headerOf().");
  log.debug("Leaving headerOf().");
  return partOf(jwt, 0);
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return partOf(jwt, 1);
}

function sha256b64u(text) {
  log.debug("Entering sha256b64u().");
  log.debug("Leaving sha256b64u().");
  return crypto.createHash("sha256").update(String(text), "ascii")
    .digest("base64url");
}

// The hash and signature shape each JWS algorithm this job may meet uses.
// ES* signatures are the fixed-width r||s of RFC 7518 section 3.4, which node
// calls `ieee-p1363`; PS* are RSA-PSS with the digest-length salt.
function algorithmParams(alg) {
  log.debug("Entering algorithmParams(). " + alg);
  const bits = String(alg).slice(2);
  const hash = /^(256|384|512)$/.test(bits) ? "sha" + bits : null;
  let out = null;
  if (/^RS(256|384|512)$/.test(alg)) {
    out = { hash: hash, opts: {} };
  } else if (/^PS(256|384|512)$/.test(alg)) {
    out = { hash: hash, opts: {
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } };
  } else if (/^ES(256|384|512)$/.test(alg)) {
    out = { hash: hash, opts: { dsaEncoding: "ieee-p1363" } };
  } else if (alg === "EdDSA" || alg === "Ed25519") {
    out = { hash: null, opts: {} };
  }
  log.debug("Leaving algorithmParams().");
  return out;
}

// A compact JWS by one of this wallet's keys: `{ alg, privateKey }`.
function signJws(header, payload, key) {
  log.debug("Entering signJws(). " + header.alg);
  const input = b64u(JSON.stringify(header)) + "." +
                b64u(JSON.stringify(payload));
  const params = algorithmParams(header.alg);
  const signature = crypto.sign(params.hash, Buffer.from(input, "ascii"),
    Object.assign({ key: key.privateKey }, params.opts));
  log.debug("Leaving signJws().");
  return input + "." + signature.toString("base64url");
}

// Whether `jwt` was signed by `publicKey` under the algorithm its header
// names. False for an algorithm this wallet does not know, never a throw.
function verifyJws(jwt, publicKey) {
  log.debug("Entering verifyJws().");
  const parts = String(jwt || "").split(".");
  let ok = false;
  try {
    const params = algorithmParams(headerOf(jwt).alg);
    if (params && parts.length === 3) {
      ok = crypto.verify(params.hash,
        Buffer.from(parts[0] + "." + parts[1], "ascii"),
        Object.assign({ key: publicKey }, params.opts),
        Buffer.from(parts[2], "base64url"));
    }
  } catch (e) {
    log.debug("Caught in verifyJws(): " + ((e && e.message) || e));
    // A key or a signature node cannot read is a signature that did not
    // verify, which is the answer the caller asserts on.
    ok = false;
  }
  log.debug("Leaving verifyJws(). " + ok);
  return ok;
}

// A holder key: `{ alg, privateKey, jwk }`, P-256 for ES256 — the one
// algorithm every wallet and every verifier supports.
function holderKey() {
  log.debug("Entering holderKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  log.debug("Leaving holderKey().");
  return { alg: "ES256", privateKey: pair.privateKey, jwk: jwk };
}

// The public key the realm signs its request objects with, found the way a
// wallet finds it: by `kid` in the JWKS its OpenID Provider metadata names,
// or else the first certificate of the `x5u` chain the header points at
// (RFC 7515 section 4.1.5). Answers a KeyObject, or null.
async function realmKeyFor(jwt) {
  log.debug("Entering realmKeyFor().");
  const header = headerOf(jwt);
  const discovery = await (await fetch(base +
    "/.well-known/openid-configuration")).json();
  const jwks = await (await fetch(discovery.jwks_uri)).json();
  const found = (jwks.keys || []).find(function (k) {
    return header.kid && k.kid === header.kid;
  });
  if (found) {
    log.debug("Leaving realmKeyFor(). By kid in the JWKS.");
    return crypto.createPublicKey({ key: found, format: "jwk" });
  }
  if (header.x5u && String(header.x5u).indexOf("https://") === 0) {
    const pem = await (await fetch(header.x5u)).text();
    const PEM_CERT =
      /-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/;
    const first = (pem.match(PEM_CERT) || [])[0];
    if (first) {
      log.debug("Leaving realmKeyFor(). By the x5u chain.");
      return new crypto.X509Certificate(first).publicKey;
    }
  }
  log.debug("Leaving realmKeyFor(). None found.");
  return null;
}

// ---------------------------------------------------------------------------
// A BROWSER: a cookie jar, and requests that never follow a redirect on
// their own, because every hop here is something to look at.
// ---------------------------------------------------------------------------
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    cookies: cookies,
    header: function header() {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(cookies).map(function (k) {
        return k + "=" + cookies[k];
      }).join("; ");
    },
    take: function take(response) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[name];
        } else {
          cookies[name] = value;
        }
      });
      log.debug("Leaving take(). " + set.length + " cookie(s).");
      return set;
    }
  };
}

// One request. `who` is a jar or null (a party with no cookies — a wallet,
// or another browser). Answers { status, headers, text, json, location,
// setCookie }.
async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header()) {
    headers.cookie = who.header();
  }
  const r = await fetch(new URL(url, base).toString(),
                        { method: method, headers: headers, body: body,
                          redirect: "manual" });
  const setCookie = who ? who.take(r) :
    (typeof r.headers.getSetCookie === "function" ?
      r.headers.getSetCookie() : []);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    // A page, not JSON: `text` is what the caller reads.
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, headers: r.headers, text: text, json: json,
           location: location ? new URL(location, base).toString() : "",
           setCookie: setCookie };
}

function unescapeHtml(text) {
  log.debug("Entering unescapeHtml().");
  log.debug("Leaving unescapeHtml().");
  return String(text).replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

// Whether a response set a live session cookie.
function setsSession(r) {
  log.debug("Entering setsSession().");
  log.debug("Leaving setsSession().");
  return (r.setCookie || []).some(function (line) {
    return /^sts_session=[^;]+/.test(line) && !/Max-Age=0/i.test(line);
  });
}

// IS ANYBODY SIGNED IN IN THIS BROWSER? Asked by USING the session, the way
// `sts_global_logout.js` asks: an authorization request with `prompt=none`
// (OIDC Core section 3.1.2.1) comes back with a code for a signed-in session
// and `login_required` for anything else. The jar holding an `sts_session`
// cookie says nothing, because the authorization endpoint sets an ARRIVAL
// cookie before anybody signs in (`authn/CLAUDE.md`), and a refusal must
// leave exactly that: a cookie naming nobody. Answers where it landed.
async function sessionAnswer(who) {
  log.debug("Entering sessionAnswer().");
  const pair = pkce();
  const r = await hop(who, "GET", authorizeUrl("openid", pair, "probe") +
                      "&prompt=none");
  log.debug("Leaving sessionAnswer().");
  return r.location || ("HTTP " + r.status + " " +
                        r.text.replace(/\s+/g, " ").slice(0, 200));
}

function nobodyIn(landed) {
  log.debug("Entering nobodyIn().");
  log.debug("Leaving nobodyIn().");
  return /[?&]error=login_required/.test(landed) &&
         !/[?&]code=/.test(landed);
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = crypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: crypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// ---------------------------------------------------------------------------
// THE WALLET'S OAUTH HALF: an authorization request, and a code redeemed.
// ---------------------------------------------------------------------------
function authorizeUrl(scope, pair, state) {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return base + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: scope, state: state, nonce: "n-" + state,
    code_challenge: pair.challenge, code_challenge_method: "S256"
  }).toString();
}

async function redeem(code, verifier) {
  log.debug("Entering redeem().");
  const r = await hop(null, "POST", base + "/oauth2/token", { form: {
    grant_type: "authorization_code", code: code, redirect_uri: REDIRECT_URI,
    code_verifier: verifier, client_id: CLIENT_ID } });
  log.debug("Leaving redeem(). " + r.status);
  return r;
}

// ---------------------------------------------------------------------------
// THE WALLET'S OID4VCI HALF.
// ---------------------------------------------------------------------------
async function issuerMetadata() {
  log.debug("Entering issuerMetadata().");
  const r = await hop(null, "GET",
                      base + "/.well-known/openid-credential-issuer");
  log.debug("Leaving issuerMetadata(). " + r.status);
  return r.json;
}

// A credential for `holder` in configuration `configId`, on `accessToken`.
// Answers { status, credential, json, text }.
async function requestCredential(meta, configId, accessToken, holder) {
  log.debug("Entering requestCredential(). " + configId);
  const nonce = await hop(null, "POST", meta.nonce_endpoint, { form: {} });
  const cNonce = nonce.json && nonce.json.c_nonce;
  const proof = signJws({ alg: holder.alg, typ: "openid4vci-proof+jwt",
                          jwk: holder.jwk },
                        { iss: CLIENT_ID, aud: meta.credential_issuer,
                          iat: Math.floor(Date.now() / 1000),
                          nonce: cNonce }, holder);
  const r = await hop(null, "POST", meta.credential_endpoint, {
    headers: { authorization: "Bearer " + accessToken },
    json: { credential_configuration_id: configId,
            proofs: { jwt: [proof] } } });
  const credential = r.json && r.json.credentials && r.json.credentials[0] &&
                     r.json.credentials[0].credential;
  log.debug("Leaving requestCredential(). " + r.status);
  return { status: r.status, credential: credential || null, json: r.json,
           text: r.text, cNonce: cNonce };
}

// ---------------------------------------------------------------------------
// PRESENTATIONS.
// ---------------------------------------------------------------------------

// An SD-JWT VC as presented: the issuer-signed JWT, the Disclosures chosen,
// and a Key Binding JWT (SD-JWT section 4.3) over exactly those bytes.
// `o.disclose` picks Disclosures by claim name; `o.noKb` leaves the KB-JWT
// off; `o.key` signs it with another key than the bound one.
function presentSdJwt(credential, holder, nonce, aud, opts) {
  log.debug("Entering presentSdJwt().");
  const o = opts || {};
  const parts = String(credential).split("~");
  const wanted = o.disclose || [];
  const chosen = parts.slice(1).filter(function (d) {
    if (!d) {
      return false;
    }
    let decoded = null;
    try {
      decoded = JSON.parse(Buffer.from(d, "base64url").toString("utf8"));
    } catch (e) {
      log.debug("Caught in presentSdJwt(): " + ((e && e.message) || e));
      // The trailing KB-JWT slot of an issued credential is empty, and a
      // segment that is not a Disclosure is simply not chosen.
      decoded = null;
    }
    return Array.isArray(decoded) && decoded.length === 3 &&
           wanted.indexOf(decoded[1]) >= 0;
  });
  const withoutKb = [parts[0]].concat(chosen).join("~") + "~";
  if (o.noKb) {
    log.debug("Leaving presentSdJwt(). No KB-JWT.");
    return withoutKb;
  }
  const signer = o.key || holder;
  const kb = signJws({ alg: signer.alg, typ: "kb+jwt" },
                     { iat: Math.floor(Date.now() / 1000), nonce: nonce,
                       aud: aud, sd_hash: sha256b64u(withoutKb) }, signer);
  log.debug("Leaving presentSdJwt().");
  return withoutKb + kb;
}

// A W3C Verifiable Presentation as a JWT (OpenID4VP Appendix B.1.3.1.3's
// holder binding): the credential inside, signed by the holder key with the
// request's nonce and the verifier as audience.
function presentJwtVc(credential, holder, nonce, aud, opts) {
  log.debug("Entering presentJwtVc().");
  const o = opts || {};
  const signer = o.key || holder;
  const vp = signJws({ alg: signer.alg, typ: "JWT", jwk: holder.jwk }, {
    iss: "urn:ietf:params:oauth:jwk-thumbprint:holder",
    aud: aud, nonce: nonce, iat: Math.floor(Date.now() / 1000),
    vp: { "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiablePresentation"],
          verifiableCredential: [credential] } }, signer);
  log.debug("Leaving presentJwtVc().");
  return vp;
}

// The DCQL credential query id a request object asks `format` under.
function queryIdFor(requestObject, format) {
  log.debug("Entering queryIdFor(). " + format);
  const found = (((requestObject || {}).dcql_query || {}).credentials || [])
    .find(function (q) {
      return q.format === format;
    });
  log.debug("Leaving queryIdFor().");
  return found ? found.id : "";
}

// POST the wallet's answer to the request's response_uri (OpenID4VP section
// 8.2, `direct_post`). The wallet has no cookie for this service.
async function respond(requestObject, format, presentation) {
  log.debug("Entering respond(). " + format);
  const vpToken = {};
  vpToken[queryIdFor(requestObject, format)] = [presentation];
  const r = await hop(null, "POST", requestObject.response_uri, { form: {
    state: requestObject.state, vp_token: JSON.stringify(vpToken) } });
  log.debug("Leaving respond(). " + r.status);
  return r;
}

async function verdictOf(state) {
  log.debug("Entering verdictOf().");
  const r = await hop(null, "GET", base + "/oid4vp/result/" +
                      encodeURIComponent(state));
  log.debug("Leaving verdictOf(). " + r.status);
  return (r.json && r.json.verdict) || null;
}

// ---------------------------------------------------------------------------
// THE SIGN-IN, as a browser and a wallet drive it together.
// ---------------------------------------------------------------------------

// An OIDC authorization request reaches the sign-in screen, the screen's
// wallet link is followed, the wait page names the request, and the wallet
// fetches it. Answers everything a later step needs; `screen` and `door`
// are there for the switched-off case.
async function startSignIn(who) {
  log.debug("Entering startSignIn().");
  const pair = pkce();
  const state = "w-" + crypto.randomBytes(6).toString("hex");
  const authorized = await hop(who, "GET",
                               authorizeUrl("openid", pair, state));
  const authnId = new URL(authorized.location || base, base).searchParams
    .get("authn") || "";
  const screen = await hop(who, "GET", authorized.location || base);
  const link = /id="wallet-signin" href="([^"]+)"/.exec(screen.text);
  const out = { pair: pair, oauthState: state, authnId: authnId,
                authorized: authorized, screen: screen,
                walletLink: link ? unescapeHtml(link[1]) : "" };
  out.door = await hop(who, "GET", base + "/authn/wallet?authn=" +
                       encodeURIComponent(authnId));
  if (out.door.status !== 303) {
    log.debug("Leaving startSignIn(). The door did not open.");
    return out;
  }
  out.waitUrl = out.door.location;
  out.waiting = await hop(who, "GET", out.waitUrl);
  const open = /id="wallet-open" href="([^"]+)"/.exec(out.waiting.text);
  out.walletUrl = open ? new URL(unescapeHtml(open[1])) : null;
  out.requestUri = out.walletUrl ?
    out.walletUrl.searchParams.get("request_uri") : "";
  if (out.requestUri) {
    const ro = await hop(null, "GET", out.requestUri);
    out.requestObjectResponse = ro;
    out.requestObjectJwt = ro.text;
    out.requestObject = payloadOf(ro.text);
  }
  log.debug("Leaving startSignIn().");
  return out;
}

// From a wait-page redirect onwards: follow the browser back through the
// authorization request that was waiting (and its consent screen, if one is
// drawn) to the client's redirect URI, and redeem the code. Answers
// { code, tokens, idToken }.
async function finishAuthorization(who, location, pair) {
  log.debug("Entering finishAuthorization().");
  let at = location;
  for (let n = 0; n < 6 && at && at.indexOf(base) === 0 &&
                  !consentScreen.isConsentScreen(at); n += 1) {
    const r = await hop(who, "GET", at);
    at = r.location;
  }
  const settled = await consentScreen.settleAuthorization({
    base: base, location: at, cookie: who.header() });
  at = settled.location || at;
  const code = new URL(at || REDIRECT_URI).searchParams.get("code");
  const tokens = code ? await redeem(code, pair.verifier) : null;
  const idToken = tokens && tokens.json && tokens.json.id_token;
  log.debug("Leaving finishAuthorization(). code=" + !!code);
  return { landed: at, code: code, tokens: tokens,
           idToken: idToken ? payloadOf(idToken) : null };
}

// The wallet sessions /admin-api/sessions lists for the holder.
async function walletSessions() {
  log.debug("Entering walletSessions().");
  const r = await hop(null, "GET", api + "/sessions?per=500&q=" +
                      encodeURIComponent(HOLDER));
  const rows = (r.json && (r.json.sessions || r.json.rows)) || [];
  log.debug("Leaving walletSessions(). " + rows.length + " row(s).");
  return rows.filter(function (row) {
    return String(row.username || "").toLowerCase() ===
             HOLDER.toLowerCase() &&
           (WALLET_VIA.test(String(row.protocol || "")) ||
            (row.amr || []).indexOf("pop") >= 0);
  });
}

// One refused attempt, end to end, in a fresh browser: the presentation
// `build(requestObject)` makes is answered, the browser asks the wait page,
// and nothing may be signed in. `expect.verified` is what the verdict should
// say; `expect.response` the response endpoint's status.
async function refused(label, format, build, expect) {
  log.debug("Entering refused(). " + label);
  const who = jar();
  const s = await startSignIn(who);
  assert.ok(s.requestObject, label + ": the sign-in did not start: " +
            s.door.status + " " + s.door.text.slice(0, 200));
  const answered = await respond(s.requestObject, format,
                                 build(s.requestObject));
  const verdict = await verdictOf(s.requestObject.state);
  const page = await hop(who, "GET", s.waitUrl);
  const landed = await sessionAnswer(who);
  check(label, function () {
    assert.strictEqual(answered.status, expect.response,
      "the response endpoint answered " + answered.status + " " +
      answered.text.slice(0, 400));
    if (expect.response === 400) {
      assert.strictEqual(answered.json && answered.json.error,
        "invalid_request", "OpenID4VP section 8.4 names invalid_request " +
        "for a presentation that is refused: " + answered.text.slice(0, 300));
    }
    assert.strictEqual(!!(verdict && verdict.ok), expect.verified,
      "the verdict: " + JSON.stringify(verdict).slice(0, 600));
    assert.strictEqual(page.status, 403, "the wait page answered " +
      page.status + " " + page.text.replace(/\s+/g, " ").slice(0, 300));
    assert.ok(/id="wallet-reason"/.test(page.text),
      "and says why nobody was signed in");
    assert.ok(!setsSession(page), "the wait page set a session cookie");
    assert.ok(nobodyIn(landed), "and nobody is signed in in that " +
              "browser: prompt=none landed at " + landed);
  });
  log.debug("Leaving refused().");
}

// ---------------------------------------------------------------------------
// THE TEST.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Running the OpenID4VP wallet job against " + base + " as " +
           HOLDER);

  // ==== 0. WHAT THE SERVICE IS ============================================
  const product = await facts.isProduct(api);
  const signInSetting = await facts.setting(api, "oid4vp.signIn");
  const signInOn = !(signInSetting === false ||
                     String(signInSetting) === "false");
  const formats = [].concat(await facts.setting(api,
                                                "oid4vp.signInFormats") ||
                            []).map(String);
  log.info("mode=" + (product ? "product" : "development") +
           ", oid4vp.signIn=" + signInOn + ", oid4vp.signInFormats=" +
           JSON.stringify(formats));

  // ==== 1. WHAT IT NEEDS, CREATED BEFOREHAND ===============================
  log.info("=== 1. the wallet client and the person ===");
  const meta = await issuerMetadata();
  const configs = (meta && meta.credential_configurations_supported) || {};
  check("the issuer publishes a dc+sd-jwt configuration (" + SD_JWT_CONFIG +
        ") and a jwt_vc_json one (" + JWT_VC_CONFIG + "), each with a scope",
        function () {
          assert.ok(meta && meta.credential_endpoint && meta.nonce_endpoint,
                    "no issuer metadata: " + JSON.stringify(meta));
          assert.strictEqual((configs[SD_JWT_CONFIG] || {}).format,
                             "dc+sd-jwt");
          assert.strictEqual((configs[JWT_VC_CONFIG] || {}).format,
                             "jwt_vc_json");
          assert.ok(configs[SD_JWT_CONFIG].scope &&
                    configs[JWT_VC_CONFIG].scope);
        });
  const credentialScopes = [configs[SD_JWT_CONFIG].scope,
                            configs[JWT_VC_CONFIG].scope];
  // PUBLIC, like every wallet: no secret, PKCE, the authorization code grant
  // and nothing else, and the credential scopes it will ask for. Registering
  // the scopes is what a product-mode realm wants of a client that asks for
  // them; nothing about the realm is changed to let it.
  await registry.provision(base, {
    identifier: CLIENT_ID, name: "OpenID4VP wallet job",
    protocols: ["oauth2", "oid4vci"],
    fields: { oauthClientId: CLIENT_ID,
              oauthGrantType: ["authorization_code"],
              oauthTokenEndpointAuthMethod: "none",
              oauthConfidential: "FALSE",
              oauthRedirectUri: [REDIRECT_URI],
              oauthResponseType: ["code"],
              oauthScope: ["openid"].concat(credentialScopes) },
    why: "the wallet sts_oid4vp_wallet.js collects credentials with and " +
         "signs its holder in through"
  });
  await registry.ensurePerson(base, HOLDER, HOLDER_PASSWORD);

  // ==== 2. ISSUANCE ========================================================
  log.info("=== 2. an access token this realm issued, and two credentials " +
           "===");
  const granted = await registry.authorizationCode(base, {
    clientId: CLIENT_ID, redirectUri: REDIRECT_URI, username: HOLDER,
    password: HOLDER_PASSWORD,
    scope: ["openid"].concat(credentialScopes).join(" ") });
  const tokenSet = await redeem(granted.code, granted.verifier);
  const accessToken = tokenSet.json && tokenSet.json.access_token;
  const passwordIdToken = tokenSet.json && tokenSet.json.id_token ?
    payloadOf(tokenSet.json.id_token) : {};
  const holderSub = String(passwordIdToken.sub || "");
  check("the holder signs in with their password and the code redeems for " +
        "an access token granted the credential scopes, naming their " +
        "urn:uuid subject", function () {
          assert.strictEqual(tokenSet.status, 200, tokenSet.text);
          assert.ok(accessToken, "no access token: " + tokenSet.text);
          const granted_ = String(tokenSet.json.scope ||
                                  payloadOf(accessToken).scope || "");
          credentialScopes.forEach(function (one) {
            assert.ok(granted_.split(/\s+/).indexOf(one) >= 0,
                      "scope " + one + " was not granted: " + granted_);
          });
          assert.ok(/^urn:uuid:/i.test(holderSub),
                    "the ID Token's sub: " + holderSub);
        });

  const sdKey = holderKey();
  const sd = await requestCredential(meta, SD_JWT_CONFIG, accessToken, sdKey);
  const sdPayload = sd.credential ?
    payloadOf(String(sd.credential).split("~")[0]) : {};
  check("a holder-bound dc+sd-jwt credential is issued for the key the " +
        "wallet proved, naming the holder's subject", function () {
          assert.strictEqual(sd.status, 200, sd.text.slice(0, 400));
          assert.ok(typeof sd.credential === "string" &&
                    sd.credential.indexOf("~") > 0, sd.text.slice(0, 200));
          assert.strictEqual(sdPayload.sub, holderSub);
          assert.strictEqual(sdPayload.vct, configs[SD_JWT_CONFIG].vct);
          assert.deepStrictEqual(
            [sdPayload.cnf && sdPayload.cnf.jwk && sdPayload.cnf.jwk.x,
             sdPayload.cnf && sdPayload.cnf.jwk && sdPayload.cnf.jwk.y],
            [sdKey.jwk.x, sdKey.jwk.y], "cnf.jwk is the proved key");
        });
  const jwtKey = holderKey();
  const jwtVc = await requestCredential(meta, JWT_VC_CONFIG, accessToken,
                                        jwtKey);
  check("a holder-bound jwt_vc_json credential is issued the same way",
        function () {
          assert.strictEqual(jwtVc.status, 200, jwtVc.text.slice(0, 400));
          assert.ok(typeof jwtVc.credential === "string" &&
                    jwtVc.credential.split(".").length === 3,
                    jwtVc.text.slice(0, 200));
        });

  // ==== 3. THE SIGN-IN =====================================================
  if (!signInOn) {
    log.info("=== 3. oid4vp.signIn is OFF here: the documented refusal ===");
    const off = await startSignIn(jar());
    check("with the wallet sign-in switched off the screen offers no " +
          "wallet and /authn/wallet refuses with 403", function () {
            assert.strictEqual(off.walletLink, "", "the screen still " +
                               "offers " + off.walletLink);
            assert.strictEqual(off.door.status, 403, off.door.text.slice(0,
                                                                     300));
            assert.ok(!setsSession(off.door));
          });
  } else {
    await signInSections(formats, sdKey, sd, jwtKey, jwtVc, holderSub);
  }

  // ==== 6. THE ACCESS TOKEN THE ISSUER WILL NOT BELIEVE =====================
  log.info("=== 6. an access token this realm did not issue ===");
  const forger = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const forged = signJws({ alg: "ES256", typ: "at+jwt" }, {
    iss: base, sub: holderSub, aud: meta.credential_issuer,
    client_id: CLIENT_ID, scope: credentialScopes.join(" "),
    jti: crypto.randomUUID(), iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300 },
    { privateKey: forger.privateKey });
  const forgedKey = holderKey();
  const onForged = await requestCredential(meta, SD_JWT_CONFIG, forged,
                                           forgedKey);
  // PRODUCT MODE REFUSES THIS TOKEN AT THE CREDENTIAL ENDPOINT SINCE
  // 2026-09-18 (`vc_issuer.ts`'s `presentedIssuerToken()`,
  // `mode.acceptsUnverifiedIssuerTokens()`). Development issues on it, as it
  // always has — OID4VCI lets the authorization server be somebody else — and
  // there the property that matters to this job is asserted instead: the
  // credential VERIFIES at the sign-in and signs nobody in, because this realm
  // never recorded it as one that may (rule 3ar).
  if (product) {
    check("PRODUCT: the credential endpoint refuses an access token it " +
          "cannot verify, 401 invalid_token", function () {
            assert.strictEqual(onForged.status, 401, onForged.text);
            assert.strictEqual(onForged.json && onForged.json.error,
                               "invalid_token", onForged.text);
            assert.ok(!onForged.credential);
          });
  } else {
    check("development: the credential endpoint issues on it, as it always " +
          "has", function () {
            assert.strictEqual(onForged.status, 200, onForged.text);
            assert.ok(onForged.credential);
          });
    if (signInOn) {
      await refused("that credential VERIFIES at the sign-in and signs " +
                    "nobody in, because this realm never recorded it as " +
                    "one that may", "dc+sd-jwt",
                    function (ro) {
                      return presentSdJwt(onForged.credential, forgedKey,
                                          ro.nonce, ro.client_id);
                    }, { response: 200, verified: true });
    }
  }

  // ==== 7. THE VERIFIER (THE BAR DOOR) =====================================
  await barDoor(sd, sdKey);

  const floor = signInOn ? 30 : 9;
  assert.ok(checks >= floor, "only " + checks + " checks ran (the floor " +
            "is " + floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// Sections 3, 4 and 5: everything that needs the wallet door open.
async function signInSections(formats, sdKey, sd, jwtKey, jwtVc,
                              holderSub) {
  log.debug("Entering signInSections().");
  log.info("=== 3. a wallet signs the holder in ===");
  const before = await walletSessions();
  const browser = jar();
  const s = await startSignIn(browser);
  check("the sign-in screen offers the wallet for this pending " +
        "authorization request", function () {
          assert.ok(/\/authn\/login\?authn=/.test(s.authorized.location),
                    "the authorization request went to " +
                    s.authorized.location);
          assert.strictEqual(s.walletLink, "/authn/wallet?authn=" +
                             s.authnId);
        });
  check("the door sends the browser to the wait page and binds the " +
        "transaction to it with an HttpOnly cookie", function () {
          assert.strictEqual(s.door.status, 303, s.door.text.slice(0, 300));
          assert.ok(/\/authn\/wallet\/wait\?/.test(s.waitUrl), s.waitUrl);
          assert.ok(browser.cookies.sts_wallet_binding, "no binding cookie");
          assert.ok(/HttpOnly/i.test(s.door.setCookie.join(" ")),
                    s.door.setCookie.join(" "));
          assert.strictEqual(s.waiting.status, 200);
        });
  const roKey = s.requestObjectJwt ? await realmKeyFor(s.requestObjectJwt) :
    null;
  const ro = s.requestObject || {};
  const queries = ((ro.dcql_query || {}).credentials || []);
  check("the request is BY REFERENCE, a signed JWT that verifies against " +
        "the realm's published key", function () {
          assert.ok(s.requestUri, "the wait page names no request_uri");
          assert.strictEqual(s.requestObjectResponse.status, 200);
          assert.ok(/oauth-authz-req\+jwt/.test(String(
            s.requestObjectResponse.headers.get("content-type"))));
          assert.ok(explicitlyTyped(s.requestObjectJwt), "the Request " +
            "Object's JOSE header typ is " +
            JSON.stringify(headerOf(s.requestObjectJwt).typ) + ", not " +
            "oauth-authz-req+jwt (RFC 9101 section 10.8)");
          assert.ok(roKey, "no key for kid " +
                    headerOf(s.requestObjectJwt).kid);
          assert.ok(verifyJws(s.requestObjectJwt, roKey),
                    "the request object's signature does not verify");
        });
  check("it asks for a vp_token by direct_post to this service, with a " +
        "fresh nonce, the client_id the wallet link names, and a DCQL " +
        "query for this issuer's credential in the formats configured",
        function () {
          assert.strictEqual(ro.response_type, "vp_token");
          assert.strictEqual(ro.response_mode, "direct_post");
          assert.strictEqual(new URL(ro.response_uri).origin,
                             new URL(base).origin);
          assert.ok(ro.nonce && String(ro.nonce).length >= 16, ro.nonce);
          assert.ok(ro.state);
          assert.strictEqual(ro.client_id,
                             s.walletUrl.searchParams.get("client_id"));
          assert.deepStrictEqual(queries.map(function (q) {
            return q.format;
          }), formats);
          const sdQuery = queries.find(function (q) {
            return q.format === "dc+sd-jwt";
          });
          if (sdQuery) {
            assert.deepStrictEqual(sdQuery.meta.vct_values,
                                   [sdPayloadVct(sd)]);
          }
        });

  // Another browser, before any answer, is not this sign-in's.
  const stranger = jar();
  let r = await hop(stranger, "GET", s.waitUrl);
  check("another browser asking the wait page is refused, 403, and given " +
        "no session", function () {
          assert.strictEqual(r.status, 403, r.text.slice(0, 200));
          assert.ok(!setsSession(r));
        });

  r = await respond(ro, "dc+sd-jwt",
                    presentSdJwt(sd.credential, sdKey, ro.nonce,
                                 ro.client_id));
  const redirect = (r.json && r.json.redirect_uri) || "";
  check("the wallet's direct_post (SD-JWT VC + Key Binding JWT) is accepted " +
        "and the wallet is sent back to the wait page with a response_code",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 400));
          assert.ok(/\/authn\/wallet\/wait\?/.test(redirect), redirect);
          assert.ok(/[?&]response_code=/.test(redirect), redirect);
          assert.ok(!setsSession(r), "the wallet's request sets no session");
        });
  const verdict = await verdictOf(ro.state);
  check("the Verifier's verdict on it is ok", function () {
    assert.ok(verdict && verdict.ok, JSON.stringify(verdict));
  });

  r = await respond(ro, "dc+sd-jwt",
                    presentSdJwt(sd.credential, sdKey, ro.nonce,
                                 ro.client_id));
  check("a second direct_post to the same sign-in is refused, 400 " +
        "invalid_request", function () {
          assert.strictEqual(r.status, 400, r.text.slice(0, 300));
          assert.strictEqual(r.json && r.json.error, "invalid_request");
        });

  r = await hop(stranger, "GET", redirect);
  check("the response_code does not let another browser collect it: 403, " +
        "no session", function () {
          assert.strictEqual(r.status, 403, r.text.slice(0, 200));
          assert.ok(!setsSession(r) && !stranger.cookies.sts_session,
                    JSON.stringify(r.setCookie));
        });
  r = await hop(null, "GET", redirect);
  check("nor a request carrying no cookie at all", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 200));
    assert.ok(!setsSession(r));
  });
  r = await hop(browser, "GET", redirect.replace(/response_code=[^&]+/,
                                                 "response_code=wrong"));
  const stillNobody = await sessionAnswer(browser);
  check("a wrong response_code is refused in the right browser too, 403, " +
        "and that browser is still signed in as nobody", function () {
          assert.strictEqual(r.status, 403, r.text.slice(0, 200));
          assert.ok(!setsSession(r), JSON.stringify(r.setCookie));
          assert.ok(nobodyIn(stillNobody), "prompt=none landed at " +
                    stillNobody);
        });

  // The arrival cookie the authorization endpoint set, which a sign-in must
  // REPLACE rather than upgrade in place (session fixation, authn/CLAUDE.md).
  const arrival = browser.cookies.sts_session || "";
  r = await hop(browser, "GET", redirect);
  check("the browser that started it collects: a NEW session cookie, and " +
        "back to the authorization request that was waiting", function () {
          assert.strictEqual(r.status, 303, r.text.slice(0, 300));
          assert.ok(setsSession(r) && browser.cookies.sts_session &&
                    browser.cookies.sts_session !== arrival,
                    r.setCookie.join(" "));
          assert.ok(/\/oauth2\/authorize/.test(r.location), r.location);
        });
  const collected = r;
  const finished = await finishAuthorization(browser, collected.location,
                                             s.pair);
  check("that request completes with a code, and its ID Token names the " +
        "subject the credential was issued for, authenticated by proof of " +
        "possession (amr pop)", function () {
          assert.ok(finished.code, "ended at " + finished.landed);
          assert.strictEqual(finished.tokens.status, 200,
                             finished.tokens.text);
          assert.strictEqual(finished.idToken.sub, holderSub);
          assert.deepStrictEqual(finished.idToken.amr, ["pop"]);
        });
  r = await hop(browser, "GET", redirect);
  check("the sign-in is collected once: asked again it is refused, 400, " +
        "and starts no second session", function () {
          assert.strictEqual(r.status, 400, r.text.slice(0, 200));
          assert.ok(!setsSession(r));
        });
  const after = await walletSessions();
  check("/admin-api/sessions lists one more wallet session for the holder, " +
        "amr [\"pop\"]", function () {
          assert.strictEqual(after.length, before.length + 1,
            "before " + before.length + ", after " + after.length + ": " +
            JSON.stringify(after).slice(0, 600));
          assert.ok(after.some(function (row) {
            return JSON.stringify(row.amr) === "[\"pop\"]" &&
                   row.sub === holderSub;
          }), JSON.stringify(after).slice(0, 600));
        });

  // ==== 4. THE REFUSALS ====================================================
  log.info("=== 4. presentations that sign nobody in ===");
  const counted = after.length;
  await refused("a Key Binding JWT for ANOTHER NONCE: 400 invalid_request, " +
                "nobody signed in", "dc+sd-jwt", function (req) {
                  return presentSdJwt(sd.credential, sdKey,
                                      "not-" + req.nonce, req.client_id);
                }, { response: 400, verified: false });
  await refused("a Key Binding JWT for ANOTHER AUDIENCE: refused, nobody " +
                "signed in", "dc+sd-jwt", function (req) {
                  return presentSdJwt(sd.credential, sdKey, req.nonce,
                                      "https://somebody-else.example");
                }, { response: 400, verified: false });
  await refused("NO Key Binding JWT: refused, nobody signed in",
                "dc+sd-jwt", function () {
                  return presentSdJwt(sd.credential, sdKey, "", "",
                                      { noKb: true });
                }, { response: 400, verified: false });
  await refused("a Key Binding JWT signed by a key the credential is NOT " +
                "BOUND to: refused, nobody signed in", "dc+sd-jwt",
                function (req) {
                  return presentSdJwt(sd.credential, sdKey, req.nonce,
                                      req.client_id, { key: holderKey() });
                }, { response: 400, verified: false });
  // A credential shaped exactly like this realm's — its vct, the holder's
  // subject, bound to a key the wallet holds — signed by somebody else.
  const outsider = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const outsiderKey = holderKey();
  const now = Math.floor(Date.now() / 1000);
  const notIssued = signJws({ alg: "ES256", typ: "dc+sd-jwt" }, {
    iss: base, vct: sdPayloadVct(sd), sub: holderSub,
    cnf: { jwk: outsiderKey.jwk }, iat: now, nbf: now - 5, exp: now + 600,
    _sd_alg: "sha-256", _sd: [] }, { privateKey: outsider.privateKey }) + "~";
  await refused("a credential this realm DID NOT ISSUE (its issuer URL and " +
                "the holder's subject, signed by another key): refused, " +
                "nobody signed in", "dc+sd-jwt", function (req) {
                  return presentSdJwt(notIssued, outsiderKey, req.nonce,
                                      req.client_id);
                }, { response: 400, verified: false });
  const stillCounted = await walletSessions();
  check("and after all of them /admin-api/sessions lists no new wallet " +
        "session for the holder", function () {
          assert.strictEqual(stillCounted.length, counted,
            JSON.stringify(stillCounted).slice(0, 600));
        });
  r = await hop(null, "POST", base + "/oid4vp/response", { form: {
    state: "no-such-" + crypto.randomBytes(6).toString("hex"),
    vp_token: "{}" } });
  check("an answer to a state this Verifier never issued is refused, 400 " +
        "invalid_request", function () {
          assert.strictEqual(r.status, 400, r.text.slice(0, 200));
          assert.strictEqual(r.json && r.json.error, "invalid_request");
        });

  // ==== 5. A SECOND FORMAT =================================================
  if (formats.indexOf("jwt_vc_json") < 0) {
    log.info("=== 5. jwt_vc_json is not among oid4vp.signInFormats here; " +
             "skipped ===");
    log.debug("Leaving signInSections().");
    return;
  }
  log.info("=== 5. a jwt_vc_json credential signs the holder in too ===");
  const second = jar();
  const s2 = await startSignIn(second);
  const ro2 = s2.requestObject;
  r = await respond(ro2, "jwt_vc_json",
                    presentJwtVc(jwtVc.credential, jwtKey, ro2.nonce,
                                 ro2.client_id));
  const redirect2 = (r.json && r.json.redirect_uri) || "";
  check("a VP JWT around the jwt_vc_json credential, signed by its bound " +
        "key for this nonce and audience, is accepted", function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 400));
          assert.ok(/[?&]response_code=/.test(redirect2), redirect2);
        });
  r = await hop(second, "GET", redirect2);
  const finished2 = r.status === 303 ?
    await finishAuthorization(second, r.location, s2.pair) : null;
  check("and the browser that started it is signed in as the same person",
        function () {
          assert.strictEqual(r.status, 303, r.text.replace(/\s+/g, " ")
            .slice(0, 400));
          assert.ok(second.cookies.sts_session);
          assert.strictEqual(finished2.idToken.sub, holderSub);
          assert.deepStrictEqual(finished2.idToken.amr, ["pop"]);
        });
  await refused("a jwt_vc_json VP JWT for ANOTHER NONCE: refused, nobody " +
                "signed in", "jwt_vc_json", function (req) {
                  return presentJwtVc(jwtVc.credential, jwtKey,
                                      "not-" + req.nonce, req.client_id);
                }, { response: 400, verified: false });
  await refused("a jwt_vc_json VP JWT signed by a key the credential is " +
                "not bound to: refused, nobody signed in", "jwt_vc_json",
                function (req) {
                  return presentJwtVc(jwtVc.credential, jwtKey, req.nonce,
                                      req.client_id, { key: holderKey() });
                }, { response: 400, verified: false });
  log.debug("Leaving signInSections().");
}

// RFC 9101 section 10.8 types a Request Object explicitly with the JOSE
// header `typ: "oauth-authz-req+jwt"`, and that is where a strict wallet looks.
// This job found the service putting it only in the PAYLOAD (2026-09-18) —
// `vc_verifier.ts` handed `helpers.signJwt()` the member as a claim, and the
// header said `JWT` — and the service was fixed the same day, so the header
// is what is asserted.
function explicitlyTyped(jwt) {
  log.debug("Entering explicitlyTyped().");
  log.debug("Leaving explicitlyTyped().");
  return headerOf(jwt).typ === "oauth-authz-req+jwt";
}

function sdPayloadVct(sd) {
  log.debug("Entering sdPayloadVct().");
  log.debug("Leaving sdPayloadVct().");
  return payloadOf(String(sd.credential).split("~")[0]).vct;
}

// Section 7: the Verifier at /oid4vp/start, which asks for the configured
// claims and signs nobody in whatever it decides.
async function barDoor(sd, sdKey) {
  log.debug("Entering barDoor().");
  log.info("=== 7. the Verifier at /oid4vp/start ===");
  const visitor = jar();
  async function begin() {
    log.debug("Entering begin().");
    const started = await hop(visitor, "GET", base +
      "/oid4vp/start?by=reference&format=" + encodeURIComponent("dc+sd-jwt"));
    const walletUrl = started.location ? new URL(started.location) : null;
    const requestUri = walletUrl ? walletUrl.searchParams.get("request_uri") :
      "";
    const got = requestUri ? await hop(null, "GET", requestUri) : null;
    log.debug("Leaving begin().");
    return { started: started, jwt: got ? got.text : "",
             ro: got ? payloadOf(got.text) : null };
  }
  const one = await begin();
  const key = one.jwt ? await realmKeyFor(one.jwt) : null;
  const claimQuery = ((((one.ro || {}).dcql_query || {}).credentials ||
                       [])[0] || {});
  const asked = (claimQuery.claims || []).map(function (c) {
    return c.path[0];
  });
  check("a request by reference is handed to the wallet, signed by the " +
        "realm, asking for a dc+sd-jwt by direct_post", function () {
          assert.strictEqual(one.started.status, 302,
                             one.started.text.slice(0, 200));
          assert.ok(one.ro, "no request object");
          assert.ok(key && verifyJws(one.jwt, key), "signature");
          assert.strictEqual(one.ro.response_mode, "direct_post");
          assert.strictEqual(claimQuery.format, "dc+sd-jwt");
        });
  let r = await respond(one.ro, "dc+sd-jwt",
                        presentSdJwt(sd.credential, sdKey, one.ro.nonce,
                                     one.ro.client_id, { disclose: asked }));
  const verdict = await verdictOf(one.ro.state);
  check("the holder's credential, disclosing exactly the claims asked for (" +
        asked.join(", ") + "), is accepted and sent to the thank-you page, " +
        "and no session is started", function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 500));
          assert.ok(/\/oid4vp\/done\?/.test((r.json || {}).redirect_uri),
                    r.text);
          assert.ok(verdict && verdict.ok, JSON.stringify(verdict));
          asked.forEach(function (name) {
            assert.ok(verdict.claims && name in verdict.claims,
                      name + " was not disclosed: " +
                      JSON.stringify(verdict.claims));
          });
          assert.ok(!setsSession(r));
        });
  r = await hop(visitor, "GET", r.json.redirect_uri);
  check("and its thank-you page signs nobody in either", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/id="verdict"/.test(r.text));
    assert.ok(!setsSession(r) && !visitor.cookies.sts_session);
  });
  const two = await begin();
  r = await respond(two.ro, "dc+sd-jwt",
                    presentSdJwt(sd.credential, sdKey, "not-" + two.ro.nonce,
                                 two.ro.client_id, { disclose: asked }));
  const refusedVerdict = await verdictOf(two.ro.state);
  check("the same answer for another request's nonce is refused, 400 " +
        "invalid_request, and the verdict says so", function () {
          assert.strictEqual(r.status, 400, r.text.slice(0, 300));
          assert.strictEqual(r.json && r.json.error, "invalid_request");
          assert.ok(refusedVerdict && refusedVerdict.ok === false,
                    JSON.stringify(refusedVerdict));
        });
  log.debug("Leaving barDoor().");
}

const program = new Command();
program
  .name("sts_oid4vp_wallet")
  .description("OpenID4VP over the network with this job as the wallet: a " +
    "holder-bound credential issued on a real access token signs its " +
    "person in at /authn/wallet in the browser that asked, once; wrong " +
    "nonces, audiences, keys, issuers, browsers and replays sign nobody in; " +
    "and the Verifier at /oid4vp/start accepts and refuses.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
