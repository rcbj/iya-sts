// @ts-check
'use strict';
//
// File: client_auth.js
//
// ===========================================================================
// HOW A CLIENT PROVES WHO IT IS — all six methods, and four of them are new.
//
// RFC 9700 section 2.5 says an authorization server SHOULD enforce client
// authentication where a process for issuing credentials exists, and RECOMMENDS
// that the process be ASYMMETRIC. The difference it is pointing at:
//
//   a shared secret         both sides hold the same string, so a leak from
//                           either end forges the client, and the server is
//                           holding something worth stealing on behalf of every
//                           client that registered
//
//   asymmetric              the client signs with a private key the server never
//                           has; the server verifies with a public one that is
//                           worth nothing to an attacker
//
// This service enforced the first and merely ACCEPTED the second: a client that
// registered `private_key_jwt` sent an assertion and this server did not look
// at it. That is worse than not offering the method at all — a client author
// would have come away believing an assertion had been checked. Closing that is
// what this file is for.
//
// ---------------------------------------------------------------------------
// THE SIX METHODS, and which of them is real here — beside `none`, and
// `saml2_bearer` (RFC 7522 section 2.2, this service's own name; see
// `METHODS` below).
//
//   none                        public client; nothing to check
//   client_secret_basic         the secret, from an Authorization: Basic header
//   client_secret_post          the secret, from a form parameter
//   client_secret_jwt           an assertion signed HS256 with the secret
//   private_key_jwt             an assertion signed with the client's own key,
//                               verified against the JWKS it registered
//   tls_client_auth             a client certificate whose chain verified, and
//                               which this realm issued to this application or
//                               which carries the one subject it registered
//                               (RFC 8705 section 2.1)
//   self_signed_tls_client_auth the client certificate is the one registered,
//                               by thumbprint or in its jwks (section 2.2)
//   attest_jwt_client_auth      a Client Attestation a trusted attester
//                               signed, and a PoP from the key it binds
//                               (draft-ietf-oauth-attestation-based-client-
//                               auth-11, #229)
//   attest_jwt_client_auth_dpop the same attestation, proved by the DPoP
//                               proof (that draft's combined mode)
//
// All of them are verified. The two shared-secret ones compare in constant
// time; the two assertion ones do the full RFC 7523 section 3 check
// (`saml2_bearer` RFC 7522 section 3's, in `saml_assertion_grant.js`); the two
// certificate ones read the connection `mtls.js` already looks at.
//
// **RFC 8705 section 2 is client AUTHENTICATION and section 3 is token
// BINDING**, and they are different features that happen to read the same
// certificate. `mtls.js` does the binding — a token carries `cnf["x5t#S256"]`
// and a resource server checks it. This does the authentication — the
// certificate stands in for a secret at the token endpoint. A deployment may
// have either, both or neither.
//
// ---------------------------------------------------------------------------
// ~~`jwks_uri` IS DELIBERATELY NOT DEREFERENCED, and it is the same refusal
// WS-Federation's `wreqptr` gets.~~ — REVERSED BY #120 (2026-09-22, rcbj's
// decision). RFC 7591 lets a client register its keys by value (`jwks`) or
// by reference (`jwks_uri`), and OpenID Connect Registration expects the
// reference to be honoured. The SSRF argument that refused it is answered by
// the outbound policy it is fetched under (`federation_http.ts`: https, no
// redirect, a size cap, internal addresses refused in product mode) rather
// than by a refusal, and what `wreqptr` still gets is different: that URL is
// chosen by the REQUEST, this one was REGISTERED. `client_jwks.js` holds the
// fetch and its cache.
//
// ---------------------------------------------------------------------------
// It is a LIBRARY (rule 3): it registers no route and requires `common/`
// libraries, `mtls.js`, `assertion_grant.js` and `saml_assertion_grant.js` —
// none of which requires it back — so it cannot join a cycle. It holds NO state
// of its own since 2026-09-13: the assertion `jti` cache it kept became
// `common/used_assertions.js`, the one history every RFC 7523 and RFC 7522
// assertion is spent against, whatever it is presented as. A replayed assertion
// is a replayed credential, and RFC 7523 section 3 says so.
// ===========================================================================

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
// One signer and one verifier for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');
const { log } = require('../common/helpers');
const config = require('../common/config');
// THE MODE, for one question (2026-09-12): is a presented credential CHECKED
// strictly — `exp` required on a client assertion and its lifetime capped? A
// LEAF (rule 3), requiring only `config`, so it moves nothing and closes
// nothing.
const mode = require('../common/mode');
const mtls = require('./mtls');
// A library (rule 3): the revocation check a REGISTERED key's certificate gets
// when it verifies a client assertion.
const revocationStatus = require('../common/revocation_status');
// A LEAF (rule 3w): the chain check a REGISTERED key's certificate gets when it
// verifies a client assertion, and the error-code registry its refusal's code
// is read from. `assertion_grant.js` below already requires both.
const pki = require('../common/pki');
const errorCodes = require('../common/error_codes');
// RFC 7521 AND THE OTHER HALF OF RFC 7523. That module owns the assertion
// FORMAT — how a registered JWKS is read, and how an encrypted assertion is
// unwrapped — and this file takes both from it rather than keeping a second
// copy of either. The require runs one way only and its header says why.
const assertionGrant = require('./assertion_grant');
// RFC 7522's OTHER HALF. That module owns the SAML assertion format — how a
// registered certificate is read, how an <EncryptedAssertion> is opened, and
// every one of section 3's eleven items — and this file takes section 2.2 from
// it rather than keeping a second copy. The require runs ONE WAY, exactly as
// the one above does and for the same reason: section 2.2 needs the assertion
// format and that module owns it, and section 2.1 needs nothing at all from
// client authentication.
const samlAssertionGrant = require('./saml_assertion_grant');
// RFC 8705 section 2.1.2's five subject parameters, read and compared — the one
// reading the registration door in `common/applications.js` also asks. A leaf.
const certificateSubject = require('../common/certificate_subject');
// OAUTH 2.0 ATTESTATION-BASED CLIENT AUTHENTICATION (#229): the two methods
// whose credential rides in HTTP header fields rather than in the body.
// `client_attestation.ts` is required LAZILY, in `verify()`: this file is
// loaded before the composition root runs (`common/cors.js` reaches it through
// `oauth2_bcp.js`, from `app.js`), and a converted module required that early
// builds an instance of its own, which the root then cannot install (#50,
// R2). The two names are spelt here for the same reason.
const ATTESTATION_METHODS = ['attest_jwt_client_auth',
                             'attest_jwt_client_auth_dpop'];

// RFC 7523 section 2.2. One value, spelt once, because a client that sends the
// wrong one is told which is expected rather than being told its assertion is
// invalid.
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
// RFC 7522 section 2.2's value, spelt once for the same reason. The two
// profiles of RFC 7521 both put a document in `client_assertion` and the type
// is the only thing on the wire that says which document it is, so a client
// that sends the wrong one is told which is expected.
const SAML_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:saml2-bearer';

// The methods this file can actually verify.
// `token_endpoint_auth_methods_supported` is built from this in oauth2.js, so
// the metadata cannot advertise one that falls through to "not checked" — which
// is the state this file was written to end.
//
// ---------------------------------------------------------------------------
// **`saml2_bearer` IS THIS SERVICE'S OWN NAME AND NOT A REGISTERED ONE**, and
// that has to be said where the list is rather than in a document nobody
// reading this will open.
//
// The IANA "OAuth Token Endpoint Authentication Methods" registry holds seven
// values and RFC 7522 registers NONE of them: it defines a
// `client_assertion_type` and stops, because RFC 7521's framework is about the
// request parameters and OpenID Connect's registration metadata is where a
// method name would live. So a deployment that wants to say "this client
// authenticates with a SAML assertion" has no registered word for it, and
// every implementation that offers the feature invents one.
//
// The invention is PUBLISHED rather than documented — it appears in
// `token_endpoint_auth_methods_supported` like every other method here — so a
// client author discovers it from the metadata instead of from this comment.
// What is NOT invented is anything on the wire: the `client_assertion_type` is
// RFC 7522's URN exactly, and a client that sends that with its assertion is
// conforming whatever this service happens to call the method internally.
// ---------------------------------------------------------------------------
const SYMMETRIC_METHODS = ['client_secret_basic', 'client_secret_post',
                           'client_secret_jwt'];
// The two attestation methods (#229) are asymmetric twice over: the attester
// signs the attestation, and the client instance proves its own key.
const ASYMMETRIC_METHODS = ['private_key_jwt', 'saml2_bearer',
                            'tls_client_auth',
                            'self_signed_tls_client_auth'].concat(
                              ATTESTATION_METHODS);
const METHODS = ['none'].concat(SYMMETRIC_METHODS, ASYMMETRIC_METHODS);

// Which of them RFC 9700 section 2.5 is asking for. Read by the caller that
// logs the RECOMMENDED a client did not follow, so that the list and the advice
// cannot drift apart.
function isAsymmetric(method) {
  log.debug("Entering isAsymmetric().");
  log.debug("Leaving isAsymmetric().");
  return ASYMMETRIC_METHODS.indexOf(String(method)) >= 0;
}

// ---------------------------------------------------------------------------
// THE USED-ASSERTION HISTORY. RFC 7523 section 3: an authorization server MAY
// reject an assertion whose jti it has already seen, and OpenID Connect Core
// section 9 says the jti must be used only once. A signed assertion captured
// off the wire is a credential until it expires, so "may" is not the useful
// reading — it is remembered for as long as the assertion could still be valid
// and refused after that by `exp` instead.
//
// **THIS FILE KEPT ITS OWN CACHE UNTIL 2026-09-13 AND NOW SPENDS AGAINST
// `common/used_assertions.js`.** That module argues why: a cache here was
// forgotten at a restart in development, never held by the ldif store,
// converged rather than agreed across processes, and — the one that is this
// file's — was a different cache from `assertion_grant.js`'s, so one JWT could
// authenticate a client AND be spent as a grant. The rule that a FULL history
// refuses rather than forgets (`oauth2.assertionReplayCacheSize`, 2026-09-12)
// moved with it unchanged.
//
// **AND A CLIENT ASSERTION IS NOW VERIFIED ONCE PER REQUEST**, which is the
// half of this change that is a bug fix rather than a design. The token
// endpoint asks this file twice about one request: `oauth2_bcp.js`'s
// `checkClientAuthentication()` (the RFC 9700 policy) and then
// `observeClientAuthentication()` (the fact the role gate and product mode
// read). With a jti spent on the first call, the second was a REPLAY of the
// request's own assertion — so in RFC 9700 mode every `private_key_jwt`,
// `client_secret_jwt` and `saml2_bearer` client was observed as NOT
// authenticated, and in product mode on top of it was refused `invalid_client`
// having authenticated perfectly. `verify()` keeps the answer for an
// assertion on the request object, under a Symbol nothing serialises, and a
// second question about the same document on the same request gets the same
// answer. A different document on the same request is verified afresh.
// ---------------------------------------------------------------------------
const usedAssertions = require('../common/used_assertions');
// FAPI 2.0's "as a string" (#140). A leaf: it requires nothing here back.
const fapi = require('./fapi');
const VERIFIED_ON_REQUEST = Symbol('sts.clientAuth.verifiedAssertions');

// The lifetime ceiling a client assertion is held to, in seconds, or 0 for
// none. It is `oauth2.jwtBearerMaxLifetimeS` — the grant's own setting —
// because the question is the same one ("how long may a signed assertion stay
// a credential") and a deployment has one answer to it; and it applies ONLY
// WHERE CREDENTIALS ARE VERIFIED, because development has always accepted a
// long-lived client assertion and the parent project's suite signs its
// post-quantum ones for an hour so that a slow signature under coverage is not
// reported as the mock refusing it.
function assertionLifetimeCap() {
  log.debug("Entering assertionLifetimeCap().");
  if (!mode.verifiesCredentials()) {
    log.debug("Leaving assertionLifetimeCap().");
    return 0;
  }
  const seconds = Number(config.value('oauth2.jwtBearerMaxLifetimeS'));
  log.debug("Leaving assertionLifetimeCap().");
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0;
}

function clockSkewSeconds() {
  log.debug("Entering clockSkewSeconds().");
  log.debug("Leaving clockSkewSeconds().");
  return config.value('oauth2.clientAssertionSkewS');
}

// One of two copies of this until 2026-08-27; `scim/scim_auth.ts` had the
// other, and both existed because `crypto.timingSafeEqual()` THROWS on buffers
// of different lengths and every caller therefore has to write the same guard
// around it. The name stays here because "do these two client secrets match" is
// what this file is asking.
function secretsMatch(presented, expected) {
  log.debug("Entering secretsMatch().");
  log.debug("Leaving secretsMatch().");
  return stsCrypto.constantTimeEquals(presented, expected);
}

// A registered JWKS, as a list of node public keys.
//
// **IT MOVED TO `assertion_grant.js` ON 2026-09-10 AND THIS IS THE
// DELEGATION.** Both halves of RFC 7523 read the same registered key material,
// and two copies of this function would have been two answers to "which of
// this client's keys may sign" — which is exactly the shape of duplication
// `crypto.js` was written to end one layer down. The shape it returns is
// unchanged bar one added member (`jwk`, which the certificate-bound path
// needs), so every caller here is untouched.
function keysFrom(jwksText) {
  log.debug("Entering keysFrom().");
  log.debug("Leaving keysFrom().");
  return assertionGrant.keysFrom(jwksText);
}

// ---------------------------------------------------------------------------
// The assertion, checked the way RFC 7523 section 3 lists.
//
// The order matters in one place and only one: the SIGNATURE is verified before
// anything is believed about the claims. Reading `iss` out of an unverified
// assertion to decide which client this is would be reading a name an attacker
// wrote — which is why the client_id comes from the caller, and the assertion
// has to agree with it rather than establish it.
// ---------------------------------------------------------------------------
// ASYNCHRONOUS SINCE THE WORKER POOL EXISTED, and this is one of the three
// surfaces that take a JWS the CLIENT signed. All eleven post-quantum and
// composite algorithms are advertised in
// `token_endpoint_auth_signing_alg_values_supported`, and verifying a composite
// ML-DSA assertion took 17.8 and 23.3 seconds on 2026-08-29 — on the one thread
// that also answers the KDC. See common/worker.js.
//
// Nothing else about it changed: the order of the checks is the order it was,
// the signature is still verified BEFORE the claims for the reason stated
// below, and every algorithm that is not post-quantum is verified here in this
// process because a check that takes microseconds has nothing to gain from a
// child.
async function verifyAssertion(opts) {
  log.debug("Entering verifyAssertion(). method=" + opts.method);
  const clientId = String(opts.clientId || '');
  // ---------------------------------------------------------------------
  // RFC 7523 SECTION 3 CLAIM 10 — THE ASSERTION MAY BE ENCRYPTED (2026-09-10).
  //
  // It is the same nested JWT the AUTHORIZATION grant may arrive as, so it is
  // unwrapped by the same function: `assertion_grant.js` owns the format. The
  // client secret goes with it because a `client_secret_jwt` client's only
  // shared key IS its secret, and an RSA-OAEP assertion is decrypted with this
  // realm's own key whichever method the client declared.
  //
  // A plain three-part JWS comes back untouched, so every client that
  // authenticated with one before this existed is on exactly the path it was.
  // ---------------------------------------------------------------------
  const unwrapped = assertionGrant.unwrapAssertion(opts.assertion,
                                                   { secret:
                                                       opts.clientSecret });
  if (!unwrapped.ok) {
    log.debug("Leaving verifyAssertion(). It would not decrypt.");
    return { ok: false, errorCode: unwrapped.errorCode,
             description: unwrapped.description };
  }
  const assertion = unwrapped.jws;
  let header = null;
  try {
    header = JSON.parse(Buffer.from(assertion.split('.')[0], 'base64url')
                              .toString('utf8'));
  } catch (e) {
    log.debug("Leaving verifyAssertion(). The assertion is not a JWT.");
    return { ok: false, errorCode: 'STS-OAUTH-0001',
             description: 'client_assertion ' +
        'is not a JWT: ' + e.message };
  }
  const alg = String((header && header.alg) || '');

  // Which key verifies it, and the two methods diverge only here.
  let verifyWith = null;
  let verifyEntries = [];
  if (opts.method === 'client_secret_jwt') {
    if (!/^HS(256|384|512)$/.test(alg)) {
      log.debug("Leaving verifyAssertion(). client_secret_jwt with a " +
                "non-HMAC alg.");
      return { ok: false, errorCode: 'STS-OAUTH-0002',
               description: 'client_secret_jwt ' +
                                       'signs with an HMAC over the ' +
                                       'client_secret, so alg must be HS256, ' +
                                       'HS384 or HS512. This assertion says ' +
                                       '"' + alg + '".' };
    }
    if (!opts.clientSecret) {
      log.debug("Leaving verifyAssertion().");
      return { ok: false, errorCode: 'STS-OAUTH-0003', description: 'this ' +
                                       'client has no client_secret on its ' +
                                       'entry, so there is nothing to verify ' +
                                       'a client_secret_jwt assertion with.' };
    }
    verifyWith = opts.clientSecret;
  } else {
    if (/^HS/.test(alg) || alg === 'none') {
      // The alg-confusion refusal, and it is the reason the method decides the
      // family rather than the header: an assertion that nominated HS256 while
      // the client registered a public key would be verified with that PUBLIC
      // key as an HMAC secret — the classic JWT forgery, and it is a forgery
      // anybody can perform because the key is public.
      log.debug("Leaving verifyAssertion(). private_key_jwt with a symmetric " +
                "alg.");
      return { ok: false, errorCode: 'STS-OAUTH-0004',
               description: 'private_key_jwt ' +
                                       'is asymmetric, so alg must be an ' +
                                       'asymmetric one (RS256, PS256, ES256 ' +
                                       'and so on). This assertion says ' +
                                       '"' + alg + '", which ' +
                                       'would have this server verify a ' +
                                       'signature with a PUBLIC key used as ' +
                                       'an HMAC secret — a forgery anybody ' +
                                       'could produce, since the key is ' +
                                       'public.' };
    }
    // -------------------------------------------------------------------
    // THREE SOURCES OF KEY SINCE 2026-09-10, AND THEY ARE ORed.
    //
    //   `jwks`                what the client REGISTERED, by value. What this
    //                         has always read.
    //   `oauthAssertionJwks`  what THIS SERVICE ISSUED it from its own
    //                         certificate authority (`common/pki.js`).
    //   the assertion's `x5c` a certificate chain presented WITH the
    //                         signature — used only after it has been shown to
    //                         chain to this realm's own Root CA, because a key
    //                         that arrives with the signature proves nothing.
    //
    // `assertion_grant.js`'s `keysForParty()` reads the first two off an
    // entry; here they are read through `keysFrom()` once per attribute,
    // because this function is handed FIELDS by its caller rather than an
    // entry. Same table, same reader.
    // -------------------------------------------------------------------
    const found = [];
    let readingProblem = '';
    let readingProblemCode = '';
    [opts.jwks, opts.assertionJwks].forEach(function (text) {
      if (!text) {
        return;
      }
      const read = keysFrom(text);
      if (read.error) {
        readingProblem = read.error;
        readingProblemCode = read.errorCode;
        return;
      }
      read.keys.forEach(function (one) { found.push(one); });
    });
    // A CERTIFICATE PRESENTED WITH THE SIGNATURE, checked against this realm's
    // own certificate authority before a key is taken out of it. Tried
    // whatever the registry holds, because a certificate this service ISSUED
    // is evidence in its own right — that is the point of holding a CA — and
    // a client may present one without a JWKS having been written onto its
    // entry.
    const fromChain = await assertionGrant.keyFromChain(header);
    if (fromChain && fromChain.key) {
      found.push({ kid: header.kid ? String(header.kid) : '',
                   key: fromChain.key });
    } else if (fromChain && fromChain.error && !found.length) {
      log.debug("Leaving verifyAssertion(). The x5c does not chain here.");
      return { ok: false, errorCode: fromChain.errorCode,
               description: fromChain.error };
    }
    // A REGISTERED `jwks_uri`, FETCHED (#120) — only where nothing was
    // registered by value, under `federation_http.ts`'s outbound policy, and
    // cached by `client_jwks.js`; the header's `kid` fetches again when the
    // cached set lacks it (a client that rotated its keys).
    let fetchedWhy = '';
    if (!opts.jwks && opts.jwksUri) {
      const fetched = await assertionGrant.ensurePartyKeys(
        { oauthJwksUri: opts.jwksUri }, 'application', header && header.kid);
      fetchedWhy = (fetched && fetched.why) || '';
      assertionGrant.keysForParty({ oauthJwksUri: opts.jwksUri },
                                  'application')
        .keys.forEach(function (one) { found.push(one); });
    }
    if (!found.length && opts.jwksUri) {
      log.debug("Leaving verifyAssertion(). The jwks_uri gave no key.");
      return { ok: false, errorCode: 'STS-OAUTH-0005', description: 'this ' +
                                       'client registered a jwks_uri and its ' +
                                       'keys could not be fetched' +
                                       (fetchedWhy ? ': ' + fetchedWhy : '') +
                                       '.' };
    }
    if (!found.length && readingProblem) {
      log.debug("Leaving verifyAssertion().");
      return { ok: false, errorCode: readingProblemCode,
               description: readingProblem + '.' };
    }
    if (!found.length) {
      log.debug("Leaving verifyAssertion().");
      return { ok: false, errorCode: 'STS-OAUTH-0006', description: 'this ' +
                                       'client registered no keys, so a ' +
                                       'private_key_jwt assertion cannot be ' +
                                       'verified. Register a `jwks` — by ' +
                                       'value — on its entry, or have this ' +
                                       'service issue it a signing key pair ' +
                                       'from /admin/pki.' };
    }
    // The kid narrows the set when the assertion names one and the JWKS uses
    // them; otherwise every key is tried. Trying them all is correct rather
    // than lax — a signature either verifies under a key or it does not, and a
    // client that rotated without updating its kid is a client whose assertion
    // is still genuine.
    const candidates = header.kid
      ? found.filter(function (one) { return one.kid === String(header.kid); })
      : found;
    // The ENTRIES are kept beside the keys, because the one that verifies is
    // then checked for revocation through the certificate its JWK carries.
    verifyEntries = candidates.length ? candidates : found;
    verifyWith = verifyEntries.map(function (one) {
      return one.key;
    });
  }

  const audiences = opts.audiences || [];
  let claims = null;
  let lastError = '';
  let usedEntry = null;
  const attempts = Array.isArray(verifyWith) ? verifyWith : [verifyWith];
  for (let i = 0; i < attempts.length && !claims; i++) {
    try {
      // NOT one of our tokens: the key is the CLIENT'S and so is the algorithm.
      // Every option here is named, including the clock tolerance — which is
      // `oauth2.clientAssertionSkewS` and is a DIFFERENT setting from the one
      // the shared verifier defaults to. That one is about how strictly we read
      // back a token WE signed; this one is about how far a CLIENT'S clock may
      // be out. Collapsing them would be easy and wrong, which is why this call
      // passes its own rather than taking the default.
      claims = await stsCrypto.verifyJwsAsync(assertion, attempts[i], {
        algorithms: [alg],
        // The audience and the issuer are checked here rather than by hand
        // below, so that a library that knows the rules applies them: `aud` may
        // be an array and a single expected value must match ANY of its
        // members.
        audience: audiences,
        issuer: clientId || undefined,
        clockTolerance: clockSkewSeconds()
      });
      usedEntry = verifyEntries[i] || null;
    } catch (e) {
      lastError = e.message;
    }
  }
  if (!claims) {
    log.debug("Leaving verifyAssertion(). It did not verify.");
    return { ok: false, errorCode: 'STS-OAUTH-0007',
             description: 'the client_assertion did not verify: ' + lastError +
                          '. ' +
                          'It must be signed by a key this client ' +
                          'registered, name this client as both `iss` and ' +
                          '`sub`, name one of ' + audiences.join(' ' +
                              'or ') + ' ' +
                          'as `aud`, and be unexpired.' };
  }
  // THE ISSUER AS THE SOLE AUDIENCE, where the caller asks for it (OAuth 2.1
  // mode, 2026-09-13). OAuth 2.1 section 2.4 makes
  // draft-ietf-oauth-rfc7523bis-11 mandatory, and for CLIENT AUTHENTICATION
  // that draft says the `aud` "MUST use the issuer identifier of the
  // authorization server as its sole value", that the token endpoint URL
  // "MUST NOT be used", and that the server "MUST reject any JWT that does not
  // contain its issuer identifier as its sole audience value". The signature
  // above was checked against the LENIENT list on purpose, so a well-signed
  // assertion addressed to the token endpoint is refused for its AUDIENCE, by
  // name, rather than reported as a document that did not verify. Before the
  // chain, the revocation check and the used-assertion claim, so a refused
  // assertion is not also used up.
  if (opts.strictAudience) {
    const aud = claims.aud;
    const named = Array.isArray(aud) ? aud : [aud];
    if (named.length !== 1 ||
        String(named[0]) !== String(opts.strictAudience)) {
      log.debug("Leaving verifyAssertion(). The audience is not the issuer " +
                "alone.");
      return { ok: false, errorCode: 'STS-OAUTH-0283',
               description: 'the client_assertion must name this ' +
                            'authorization server\'s issuer identifier, "' +
                            opts.strictAudience + '", as its SOLE audience ' +
                            '(OAuth 2.1 section 2.4, ' +
                            'draft-ietf-oauth-rfc7523bis-11 section 4) — ' +
                            'the token endpoint URL may not be used — and ' +
                            'it names ' + JSON.stringify(aud) + '.' };
    }
    // FAPI 2.0 section 5.3.2.1 item 8 (#140): "as a string" — a one-element
    // array names the right audience in the wrong shape.
    if (fapi.strictAssertionAudience() && Array.isArray(aud)) {
      log.debug("Leaving verifyAssertion(). FAPI 2.0: aud is an array.");
      return { ok: false, errorCode: 'STS-OAUTH-0283',
               description: 'the client_assertion must name this ' +
                            'authorization server\'s issuer identifier as a ' +
                            'STRING in aud (FAPI 2.0 section 5.3.2.1 item ' +
                            '8), and it names an array.' };
    }
  }
  // THE REGISTERED KEY'S CHAIN, NOW THAT IT HAS VERIFIED SOMETHING
  // (2026-09-13). A key out of `jwks` or `oauthAssertionJwks` carrying an `x5c`
  // is believed only while that certificate's WHOLE chain holds — the
  // certificate holds this key, every link verifies and is in date, every
  // issuer may issue, and the path ends in this realm or at the self-signed
  // root registered with it. `assertion_grant.js` makes the same call for
  // section 2.1, through the same function, so the two halves of RFC 7523
  // cannot disagree about what a registered certificate is worth.
  if (usedEntry && usedEntry.jwk && Array.isArray(usedEntry.jwk.x5c) &&
      usedEntry.jwk.x5c.length) {
    const keyChain = await pki.verifySignerChain(undefined, {
      certificate: usedEntry.jwk.x5c[0], chain: usedEntry.jwk.x5c.slice(1),
      key: usedEntry.jwk,
      source: 'the key "' + (usedEntry.kid || '(no kid)') +
              '" registered for client "' + clientId + '"'
    });
    if (!keyChain.ok) {
      log.warn('client_auth: the registered key that verified client "' +
               clientId + '"\'s assertion has a chain that does not hold: ' +
               keyChain.why);
      log.debug("Leaving verifyAssertion(). The registered key's chain is " +
                "refused.");
      return { ok: false,
               errorCode: errorCodes.codeOf(keyChain) || 'STS-PKI-0157',
               description: 'the certificate of the key this client ' +
                            'registered, which verified the assertion, does ' +
                            'not have a valid trust chain: ' + keyChain.why };
    }
    log.debug('verifyAssertion(): ' + pki.signerChainSummary(keyChain) + '.');
  }
  // THE REGISTERED KEY'S CERTIFICATE, NOW THAT IT HAS VERIFIED SOMETHING. A key
  // out of `jwks` or `oauthAssertionJwks` that carries an `x5c` is checked for
  // revocation as a presented certificate is — before the jti is spent, so a
  // refused assertion is not also used up. A key out of the assertion's own
  // `x5c` has no registered entry (its chain was checked on the way in), and a
  // registered key with no certificate is a bare key with nothing to check,
  // which the verdict reports rather than calling good. Asynchronous, because
  // this function is.
  if (usedEntry && usedEntry.jwk) {
    const keyRevocation =
        await revocationStatus.registeredKeyVerdictFor(usedEntry.jwk,
      'the key "' + (usedEntry.kid || '(no kid)') +
      '" registered for client "' + clientId + '"');
    if (keyRevocation.refused) {
      log.warn('client_auth: the registered key that verified client "' +
               clientId +
               '"\'s assertion is refused: ' + keyRevocation.why);
      log.debug("Leaving verifyAssertion(). The registered key is revoked.");
      return { ok: false, errorCode: 'STS-PKI-0129',
               description: 'the key this client registered, which verified ' +
                            'the assertion, may no longer be ' +
                            'used: ' + keyRevocation.why };
    }
    log.debug('verifyAssertion(): ' +
              revocationStatus.registeredSummary(keyRevocation) + '.');
  }
  // RFC 7523 section 3: iss and sub are both the client. `iss` was checked
  // above by the library; `sub` is checked here because it is the one that says
  // WHO is being authenticated, and an assertion issued by the client ABOUT
  // somebody else is a different thing entirely.
  if (String(claims.sub || '') !== clientId) {
    log.debug("Leaving verifyAssertion(). The subject is not this client.");
    return { ok: false, errorCode: 'STS-OAUTH-0008', description: 'RFC 7523 ' +
                                     'section 3: a client assertion names ' +
                                     'the client as both `iss` and `sub`. ' +
                                     'This one has sub="' +
                                     (claims.sub || '') + '" where the ' +
                                         'client is "' + clientId +
                                     '" — an assertion a client made ABOUT ' +
                                     'somebody else is not that somebody ' +
                                     'authenticating.' };
  }
  // -------------------------------------------------------------------
  // `exp` AND THE LIFETIME CEILING (2026-09-12).
  //
  // RFC 7523 section 3 claim 4 says the JWT MUST contain an `exp`, and the
  // library only checks one that is present — so an assertion with none was
  // accepted, and its jti remembered for the clock skew alone (sixty seconds)
  // while the assertion itself stayed valid for ever. That is a bearer
  // credential that can be replayed a minute after it was first used.
  //
  // IN PRODUCT MODE it is refused, and the lifetime is capped at
  // `oauth2.jwtBearerMaxLifetimeS` — measured from `iat`, and FROM NOW when
  // there is no `iat`, so leaving the optional claim out cannot be the way
  // round the ceiling. In DEVELOPMENT neither refusal is made, which is what
  // this service always did; what changed there is the replay window below,
  // which now covers a no-`exp` assertion for the ceiling rather than for
  // sixty seconds.
  // -------------------------------------------------------------------
  const nowSeconds = Math.floor(Date.now() / 1000);
  const hasExp = claims.exp !== undefined && claims.exp !== null;
  if (!hasExp && mode.verifiesCredentials()) {
    log.debug("Leaving verifyAssertion(). No exp, and credentials are " +
              "verified here.");
    return { ok: false, errorCode: 'STS-OAUTH-0009', description: 'RFC 7523 ' +
                                     'section 3 claim 4: a client assertion ' +
                                     'MUST carry an `exp`. One without it ' +
                                     'never expires, so it is a credential ' +
                                     'anybody who captures it can use for ' +
                                     'ever.' };
  }
  const cap = assertionLifetimeCap();
  if (cap && hasExp) {
    const from = (claims.iat !== undefined && claims.iat !== null)
      ? Math.min(Number(claims.iat), nowSeconds) : nowSeconds;
    const lifetime = Number(claims.exp) - from;
    if (lifetime > cap + clockSkewSeconds()) {
      log.debug("Leaving verifyAssertion(). The assertion lives too long.");
      return { ok: false, errorCode: 'STS-OAUTH-0010', description: 'this ' +
          'client assertion is valid for ' + lifetime +
                                       ' seconds and this authorization ' +
                                       'server accepts at most ' +
                                       cap + ' ' +
                                       '(oauth2.jwtBearerMaxLifetimeS), ' +
                                       'measured from `iat` or, where there ' +
                                       'is none, from now. Mint a ' +
                                       'short-lived assertion per request.' };
    }
  }
  if (!claims.jti) {
    log.debug("Leaving verifyAssertion().");
    return { ok: false, errorCode: 'STS-OAUTH-0011', description: 'RFC 7523 ' +
                                     'section 3: a client assertion must ' +
                                     'carry a `jti`, so that this server can ' +
                                     'refuse a replay of it.' };
  }
  // Remembered until it expires — not for a fixed window — so the history and
  // the `exp` check cover exactly the same span between them, with no gap in
  // which a replay would be accepted because the row had been swept early. An
  // assertion with NO `exp` (development only, see above) is remembered for the
  // lifetime ceiling where there is one and for five minutes where there is not
  // — it stays presentable after that, which is the permissiveness development
  // mode has, stated here rather than pretended away.
  const remembered = hasExp
    ? Number(claims.exp) * 1000
    : Date.now() +
      (Number(config.value('oauth2.jwtBearerMaxLifetimeS')) || 300) * 1000;
  // The LAST check, after every refusal of the document itself, so that an
  // assertion refused for any other reason is not also used up.
  const spent = await usedAssertions.claim({
    format: 'jwt', use: 'client-authentication',
    issuer: clientId, identifier: String(claims.jti),
    clientId: clientId, subject: clientId,
    expiresAt: remembered + clockSkewSeconds() * 1000,
    request: opts.request
  });
  if (!spent.ok && spent.reason === 'replay') {
    log.warn('client_auth: client "' + clientId + '" replayed the assertion ' +
                                                  'jti ' + claims.jti +
             '. A signed assertion is a credential until it expires, so a ' +
             'second use of one is refused (RFC 7523 section 3).');
    log.debug("Leaving verifyAssertion(). The jti was replayed.");
    return { ok: false, errorCode: 'STS-OAUTH-0012', description: 'this ' +
                                     'client_assertion has been used ' +
                                     'already' +
                                     usedAssertions.usedAs(spent.existing) +
                                     '. Its `jti` is remembered until ' +
                                     'the assertion expires, because a ' +
                                     'signed assertion captured off the wire ' +
                                     'is a credential until then. Mint a ' +
                                     'fresh one per request.' };
  }
  if (!spent.ok && spent.reason === 'full') {
    log.warn('client_auth: the used-assertion history for this realm ' +
             'is full of unexpired rows (oauth2.assertionReplayCacheSize ' +
             '= ' + spent.cap +
             '), so a new assertion from "' + clientId + '" is REFUSED ' +
             'rather than a live one being forgotten.');
    log.debug("Leaving verifyAssertion(). The replay cache is full.");
    return { ok: false, errorCode: 'STS-OAUTH-0013', description: 'this ' +
                                     'authorization server is holding as ' +
                                     'many unexpired client assertions as it ' +
                                     'is configured to remember ' +
                                     '(oauth2.assertionReplayCacheSize), and ' +
                                     'it will not forget one that could ' +
                                     'still be replayed in order to accept ' +
                                     'yours. Retry shortly, with a ' +
                                     'short-lived assertion.' };
  }
  if (!spent.ok) {
    log.debug("Leaving verifyAssertion(). The history could not be asked.");
    // The store's own message goes to the log (used_assertions.js tags it)
    // and not to the client: it is a sentence about this service's database.
    return { ok: false, errorCode: 'STS-OAUTH-0243', description: 'this ' +
                                     'client assertion verified, and this ' +
                                     'authorization server could not record ' +
                                     'that it has been used, so it is ' +
                                     'refused rather than accepted ' +
                                     'unrecorded. Retry with a fresh ' +
                                     'assertion.' };
  }
  log.debug("Leaving verifyAssertion(). Verified. alg=" + alg + ", jti=" +
            claims.jti);
  return { ok: true, alg: alg, jti: String(claims.jti) };
}

// ---------------------------------------------------------------------------
// RFC 8705 section 2 — the certificate stands in for the secret.
//
// Two methods, and the difference is what the certificate has to match:
//
//   tls_client_auth              a certificate whose CHAIN VERIFIED against the
//                                client truststore, and which is either issued
//                                by this realm to THIS application (implicit)
//                                or carries the one subject the client
//                                registered (explicit, section 2.1.2)
//   self_signed_tls_client_auth  any certificate that is the one the client
//                                registered — by thumbprint, or as the x5c of
//                                a key in its jwks (section 2.2.2) — no CA
//                                involved, which is section 2.2's whole point
//
// **THE TWO MAPPINGS FOR `tls_client_auth` (2026-09-13), AND WHY BOTH.** The
// EXPLICIT one is the RFC's: exactly one of `tls_client_auth_subject_dn`,
// `_san_dns`, `_san_uri`, `_san_ip`, `_san_email`, compared by
// `common/certificate_subject.js` as a name rather than a string — and it is
// what an application holding a certificate from somebody else's authority
// uses, that authority's root installed at /tls/trust. The IMPLICIT one is
// this service's certificate-to-identity mapping, the one a person's TLS
// client certificate signs them in by, pointed at an application:
// `common/tls_client_certificates.js`'s `identityOf()` names the application a
// realm-issued certificate was issued to (its `urn:sts:application:`
// subjectAltName), and `stillHeld()` asks whether that application's record
// still lists it. Nothing needs registering for it, because issuing the
// certificate TO the application was the registration.
//
// **A CERTIFICATE THIS SERVICE ISSUED AS SOMEBODY ELSE'S IDENTITY NEVER
// AUTHENTICATES THIS CLIENT**, whatever subject the client registered. RFC 8705
// section 7.4 is the reason: a subject is only as good as the authority that
// put it in the certificate, and this realm's authority has already said whose
// certificate this is.
//
// **THE CHAIN IS VERIFIED FOR BOTH, AND IT WAS NOT.** Until 2026-09-13 this
// function compared the subject DN and logged that no chain had been checked,
// because the truststore started empty. It is the main port's verdict now —
// `mtls.peerVerified()`, which is the chain, revocation and the identity gate
// in one answer — and section 2.1 is the PKI method precisely because the
// subject is believed only from a certificate an anchor vouched for.
// `self_signed_tls_client_auth` is untouched by it: section 6.1 says that
// method does not verify the chain, and the proof is the handshake.
// ---------------------------------------------------------------------------
function subjectRfc4514(cert) {
  log.debug("Entering subjectRfc4514().");
  // The subject as RFC 4514 writes it, leaf first, off the DER — through
  // `common/certificate_subject.js`, which is also what compares a registered
  // DN with it, so the spelling a refusal quotes is the one that was compared.
  // node's `getPeerCertificate().subject` object was read here until
  // 2026-09-13, and it cannot say which attributes were one multi-valued RDN
  // or what order a repeated type came in.
  let text = '';
  try {
    text = certificateSubject.subjectOf(
      new crypto.X509Certificate(cert.raw)).text;
  } catch (e) {
    log.debug("Caught in subjectRfc4514(): " + ((e && e.message) || e));
    text = '';
  }
  log.debug("Leaving subjectRfc4514().");
  return text;
}

// The DER of every certificate a registered JWKS carries as a key's `x5c[0]`,
// for section 2.2.2's reading of `self_signed_tls_client_auth`. A JWKS that
// does not parse holds none, and the refusal says the thumbprint and the jwks
// were both looked at.
function registeredCertificatesOf(jwksText) {
  log.debug("Entering registeredCertificatesOf().");
  if (!jwksText) {
    log.debug("Leaving registeredCertificatesOf(). No jwks.");
    return [];
  }
  const read = keysFrom(jwksText);
  if (read.error) {
    log.debug("Leaving registeredCertificatesOf(). The jwks does not parse.");
    return [];
  }
  const out = [];
  read.keys.forEach(function (one) {
    const x5c = one.jwk && Array.isArray(one.jwk.x5c) ? one.jwk.x5c : [];
    if (typeof x5c[0] === 'string' && x5c[0]) {
      out.push(Buffer.from(x5c[0], 'base64'));
    }
  });
  log.debug("Leaving registeredCertificatesOf(). " + out.length + " held.");
  return out;
}

// The two identity questions `tls_client_certificates.js` answers — who a
// certificate was issued to, and whether that holder's record still lists it
// — are `mtls.issuedIdentityOf()` since #107 (2026-09-23), because GNAP's PKI
// trust model asks them of the same socket.
function verifyCertificate(opts) {
  log.debug("Entering verifyCertificate(). method=" + opts.method);
  const cert = mtls.peerCertificate(opts.request);
  if (!cert) {
    log.debug("Leaving verifyCertificate(). No certificate on this " +
              "connection.");
    return { ok: false, errorCode: 'STS-OAUTH-0014',
             description: 'RFC 8705 section 2: this client authenticates ' +
                          'with its TLS client certificate, and this request ' +
                          'arrived with none. The token endpoint has to be ' +
                          'reached over a TLS connection that asked for one ' +
                          '— set global.https, which RFC 9700 mode does by ' +
                          'default.' };
  }
  // REVOCATION, CONSULTED (2026-09-12), before either match, for BOTH methods.
  // The certificate here is standing in for a client secret, and a revoked one
  // is a secret its issuer withdrew. `common/app.js` computed the verdict
  // before any route. **An UNVERIFIED certificate is looked up too** — the
  // register needs no chain to say that this service revoked something it
  // issued — and what it never does for one is dial a URL the certificate
  // names, which is `common/revocation_status.js`'s rule. So
  // `self_signed_tls_client_auth` with a certificate nobody issued is
  // unaffected: there is nobody to revoke it.
  const revocation = opts.request && opts.request.certificateRevocation;
  if (revocation && revocation.refused) {
    log.debug("Leaving verifyCertificate(). Refused on revocation.");
    return { ok: false,
             // The verdict's own code — 0118 revoked, 0119 unestablished,
             // and since #174 0188 not dialled, 0189 an invalid noRevAvail,
             // 0190 a certificate nobody can revoke.
             errorCode: revocationStatus.codeOf(revocation),
             description: 'RFC 8705 section 2: the client certificate on ' +
                          'this connection was refused on revocation ' +
                          '(pki.revocationCheck is ' +
                          revocation.policy + '). ' + revocation.why };
  }
  const presentedThumbprint = mtls.thumbprintOf(cert);
  if (opts.method === 'self_signed_tls_client_auth') {
    const registered = String(opts.certificateThumbprint || '');
    const inJwks = registeredCertificatesOf(opts.jwks);
    if (!registered && !inJwks.length) {
      log.debug("Leaving verifyCertificate(). Nothing registered.");
      return { ok: false, errorCode: 'STS-OAUTH-0015',
               description: 'this client authenticates with a self-signed ' +
                            'certificate (RFC 8705 section 2.2) and has none ' +
                            'registered: no key in its jwks carries an x5c ' +
                            '(section 2.2.2), and there is no ' +
                            'oauthTlsClientCertificateThumbprint on its ' +
                            'entry.' };
    }
    const byThumbprint = !!registered && presentedThumbprint === registered;
    const byJwks = inJwks.some(function (der) {
      return Buffer.compare(der, Buffer.from(cert.raw)) === 0;
    });
    if (!byThumbprint && !byJwks) {
      log.debug("Leaving verifyCertificate(). Not the registered certificate.");
      return { ok: false, errorCode: 'STS-OAUTH-0016',
               description: 'RFC 8705 section 2.2: this connection was made ' +
                            'with the certificate whose SHA-256 thumbprint ' +
                            'is ' + presentedThumbprint + ', and it is ' +
                            'neither the x5c of a key in this client\'s jwks ' +
                            '(' + inJwks.length + ' registered) nor ' +
                            (registered ? 'the registered thumbprint ' +
                                          registered
                                        : 'a registered thumbprint') + '.' };
    }
    log.debug("Leaving verifyCertificate(). The registered certificate.");
    return { ok: true, subject: subjectRfc4514(cert),
             thumbprint: presentedThumbprint,
             mapping: byJwks ? 'jwks' : 'thumbprint' };
  }

  // ---------------------------------------------------------------------
  // tls_client_auth. THE CHAIN FIRST: nothing below is believed about a
  // certificate no anchor vouched for.
  // ---------------------------------------------------------------------
  const peer = mtls.peerVerified(opts.request);
  if (!peer.verified && peer.identity && peer.identity.issuedHere) {
    // A chain through this service's own Root that is not an identity here —
    // an RFC 7523 key pair, a person's certificate from another realm.
    log.debug("Leaving verifyCertificate(). Issued here, not an identity.");
    return { ok: false, errorCode: 'STS-OAUTH-0481',
             description: 'RFC 8705 section 2.1: the client certificate ' +
                          'chains to this service\'s own Root and is not a ' +
                          'TLS client identity in this realm: ' +
                          (peer.identity.why || peer.error || '') + '. Issue ' +
                          'this application a TLS client certificate from ' +
                          'its Credentials section.' };
  }
  if (!peer.verified) {
    log.debug("Leaving verifyCertificate(). The chain did not verify.");
    return { ok: false, errorCode: 'STS-OAUTH-0480',
             description: 'RFC 8705 section 2.1: tls_client_auth ' +
                          'authenticates a certificate whose chain is ' +
                          'validated against a trust anchor, and this one ' +
                          'did not verify' +
                          (peer.error ? ' (' + peer.error + ')' : '') + '. ' +
                          'Install the issuing authority\'s root at ' +
                          '/tls/trust, send the intermediates with the ' +
                          'certificate, or register the client for ' +
                          'self_signed_tls_client_auth instead.' };
  }
  const subjects = certificateSubject.registeredOf(opts.subjects);
  if (subjects.members.length > 1) {
    // `mtlsMetadataProblem()` and `mtlsAttributeProblem()` refuse this at
    // every write door; an `ldapmodify` is the way it arrives.
    log.debug("Leaving verifyCertificate(). Two subject parameters.");
    return { ok: false, errorCode: 'STS-OAUTH-0482',
             description: 'RFC 8705 section 2.1.2: this client\'s entry ' +
                          'registers ' + subjects.members.length + ' ' +
                          'certificate subject parameters (' +
                          subjects.members.join(', ') + ') where a client ' +
                          'uses exactly one, so there is no single subject ' +
                          'to expect. Clear all but one.' };
  }
  const issued = mtls.issuedIdentityOf(opts.request);
  const identity = issued.identity;
  if (identity.issuedHere && identity.accepted) {
    const mine = identity.kind === 'application' &&
      (identity.username === String(opts.applicationIdentifier || '') ||
       identity.username === String(opts.clientId || ''));
    if (!mine) {
      log.debug("Leaving verifyCertificate(). Somebody else's identity.");
      return { ok: false, errorCode: 'STS-OAUTH-0484',
               description: 'RFC 8705 section 2.1: the client certificate ' +
                            'was issued by this realm to the ' +
                            identity.kind + ' "' + identity.username + '", ' +
                            'and a certificate this service issued as ' +
                            'somebody\'s identity authenticates that holder ' +
                            'and nobody else — whatever subject this client ' +
                            'registered (section 7.4).' };
    }
    if (!issued.held) {
      log.debug("Leaving verifyCertificate(). No longer held.");
      return { ok: false, errorCode: 'STS-OAUTH-0483',
               description: 'RFC 8705 section 2.1: the client certificate ' +
                            'was issued to this application (serial ' +
                            identity.serialHex + '), and its record no ' +
                            'longer lists it — it was taken off or replaced. ' +
                            'A certificate the application\'s record does ' +
                            'not hold is not its credential.' };
    }
    log.info('RFC 8705 section 2.1: client "' + (opts.clientId || '') + '" ' +
             'authenticated with the TLS client certificate this realm ' +
             'issued to it (serial ' + identity.serialHex + ', ' +
             identity.why + ').');
    log.debug("Leaving verifyCertificate(). The implicit mapping.");
    return { ok: true, subject: subjectRfc4514(cert),
             thumbprint: presentedThumbprint, mapping: 'implicit',
             serialHex: identity.serialHex };
  }
  if (!subjects.member) {
    log.debug("Leaving verifyCertificate(). Nothing to match an external " +
              "certificate against.");
    return { ok: false, errorCode: 'STS-OAUTH-0486',
             description: 'RFC 8705 section 2.1: the client certificate ' +
                          'verified and was not issued by this realm to ' +
                          'this application, and the client registers no ' +
                          'certificate subject to match it against — one of ' +
                          'tls_client_auth_subject_dn, tls_client_auth_san_' +
                          'dns, _san_uri, _san_ip or _san_email.' };
  }
  const matched = certificateSubject.matches(subjects.member, subjects.value,
                                             cert.raw);
  if (!matched.ok) {
    log.debug("Leaving verifyCertificate(). The subject does not match.");
    return { ok: false, errorCode: 'STS-OAUTH-0485',
             description: 'RFC 8705 section 2.1.2: this client registered ' +
                          subjects.member + ' "' + subjects.value + '" and ' +
                          'the certificate on this connection carries ' +
                          (matched.presented.length
                            ? certificateSubject.MEMBERS[subjects.member]
                                .label + ' ' +
                              matched.presented.map(function (one) {
                                return '"' + one + '"';
                              }).join(', ')
                            : 'no ' + certificateSubject.MEMBERS[
                                subjects.member].label) + '.' };
  }
  log.info('RFC 8705 section 2.1: client "' + (opts.clientId || '') + '" ' +
           'authenticated by ' + subjects.member + ' on a certificate whose ' +
           'chain verified.');
  log.debug("Leaving verifyCertificate(). The explicit mapping.");
  return { ok: true, subject: subjectRfc4514(cert),
           thumbprint: presentedThumbprint, mapping: 'explicit',
           member: subjects.member };
}

// ---------------------------------------------------------------------------
// ONE VERIFICATION OF ONE ASSERTION PER REQUEST. See the header above
// `usedAssertions` for the double-spend this closes. Keyed by a digest of
// everything that decides the answer — the method, the client, the type, the
// document and, for a JWT, the audience policy — so a request presenting two
// different assertions verifies both, and one presenting the same one twice is
// answered once. The PROMISE is kept rather than the result, so a second caller
// that arrives while the first is still verifying waits for that verification
// instead of starting a second one that would find the first one's claim.
// ---------------------------------------------------------------------------
function verifiedOnce(request, parts, run) {
  log.debug("Entering verifiedOnce().");
  if (!request || typeof request !== 'object') {
    log.debug("Leaving verifiedOnce(). No request to remember it on.");
    return run();
  }
  let held = request[VERIFIED_ON_REQUEST];
  if (!held) {
    held = new Map();
    request[VERIFIED_ON_REQUEST] = held;
  }
  const key = crypto.createHash('sha256').update(parts.join('\n'))
    .digest('base64url');
  if (held.has(key)) {
    log.debug("Leaving verifiedOnce(). Answered already on this request.");
    return held.get(key);
  }
  const answer = run();
  held.set(key, answer);
  log.debug("Leaving verifiedOnce(). Verifying.");
  return answer;
}

// ---------------------------------------------------------------------------
// THE ONE ENTRY POINT. Given what the request presented and what the client's
// entry says, does this client authenticate?
//
// It decides nothing about whether authentication is REQUIRED — that is section
// 2.5's policy question and it lives in `oauth2_bcp.js`. This answers only
// "does what arrived prove this client", which is protocol.
// ---------------------------------------------------------------------------
//
// ASYNCHRONOUS BECAUSE verifyAssertion() IS. The four methods that are not an
// assertion — the two secret ones and the two RFC 8705 certificate ones —
// resolve without leaving this process; nothing about what any of them decides
// changed.
async function verify(opts) {
  log.debug("Entering verify().");
  const info = opts || {};
  const method = String(info.method || '');
  log.debug("Entering verify(). method=" + method + ", client=" +
            info.clientId);

  if (method === 'client_secret_basic' || method === 'client_secret_post') {
    if (!info.presentedSecret) {
      log.debug("Leaving verify(). No secret was presented.");
      log.debug("Leaving verify().");
      return { ok: false, errorCode: 'STS-OAUTH-0019', description: 'no ' +
          'client_secret was presented. Send it by ' +
                                       (method === 'client_secret_post'
                                         ? 'client_secret_post (a ' +
                                           'client_secret form parameter).'
                                         : 'client_secret_basic (an ' +
                                           'Authorization: Basic header).') };
    }
    // ROTATION AND EXPIRY (#49 P5), read off the client's own entry here
    // rather than threaded through every caller: the secret a rotation
    // replaced, accepted until its overlap ends, and when the current one
    // expires. The registry is required LAZILY — it is not one of this
    // file's dependencies and must not become a cycle.
    let entry = {};
    try {
      entry = require('../common/applications')
        .clientConfigOf(String(info.clientId || '')) || {};
    } catch (e) {
      log.debug("Caught in verify(): " + ((e && e.message) || e));
      entry = {};
    }
    const current = secretsMatch(info.presentedSecret, info.clientSecret);
    const previous = !current && !!entry.client_secret_previous &&
      Date.now() < Number(entry.client_secret_previous_until) &&
      secretsMatch(info.presentedSecret, entry.client_secret_previous);
    if (!current && !previous) {
      log.debug("Leaving verify(). The secret did not match.");
      log.debug("Leaving verify().");
      return { ok: false, errorCode: 'STS-OAUTH-0020', description: 'the ' +
                                       'client_secret presented is not the ' +
                                       'one on this client\'s entry in the ' +
                                       'application registry.' };
    }
    if (previous) {
      log.debug("Leaving verify(). The previous secret, inside its overlap.");
      log.debug("Leaving verify().");
      return { ok: true, method: method, previousSecret: true };
    }
    const expiresAt = Number(entry.client_secret_expires_at) || 0;
    if (expiresAt > 0 && Math.floor(Date.now() / 1000) >= expiresAt) {
      if (mode.refusesExpiredClientSecrets()) {
        log.debug("Leaving verify(). The secret has expired.");
        log.debug("Leaving verify().");
        return { ok: false, errorCode: 'STS-OAUTH-0558', description: 'the ' +
                 'client_secret presented expired at ' +
                 new Date(expiresAt * 1000).toISOString() +
                 ' (its client_secret_expires_at); ask this service\'s ' +
                 'administrator for a new one, or rotate it through RFC ' +
                 '7592 client registration management.' };
      }
      log.warn(errorCodes.tag('STS-OAUTH-0559') + 'client_auth: the ' +
               'client_secret of "' + String(info.clientId || '') +
               '" expired at ' + new Date(expiresAt * 1000).toISOString() +
               ' and was ACCEPTED, because this is a development-mode ' +
               'service (mode.refusesExpiredClientSecrets()).');
    }
    log.debug("Leaving verify(). The secret matched.");
    log.debug("Leaving verify().");
    return { ok: true, method: method };
  }

  if (method === 'client_secret_jwt' || method === 'private_key_jwt') {
    if (!info.assertion) {
      log.debug("Leaving verify(). No assertion was presented.");
      log.debug("Leaving verify().");
      return { ok: false, errorCode: 'STS-OAUTH-0021', description: 'this ' +
          'client authenticates with ' + method + ', ' +
                                       'so the request must carry ' +
                                       'client_assertion and ' +
                                       'client_assertion_type=' +
          ASSERTION_TYPE + '.' };
    }
    if (String(info.assertionType || '') !== ASSERTION_TYPE) {
      log.debug("Leaving verify(). The assertion type is wrong.");
      log.debug("Leaving verify().");
      return { ok: false, errorCode: 'STS-OAUTH-0022',
               description: 'client_assertion_type ' +
          'must be "' + ASSERTION_TYPE +
                                       '" (RFC 7523 section 2.2). This ' +
                                       'request says "' +
                                       (info.assertionType || '') + '".' };
    }
    // The AUDIENCE POLICY is part of the key (2026-09-13): two callers asking
    // about one document with two policies must not have the first answer
    // silently decide both. See verifiedOnce().
    const checked = await verifiedOnce(info.request,
      [method, info.clientId, info.assertionType, info.assertion,
       String(info.strictAudience || ''),
       (info.audiences || []).join(' ')],
      function () {
        return verifyAssertion({
          method: method, assertion: info.assertion, clientId: info.clientId,
          clientSecret: info.clientSecret, jwks: info.jwks,
          jwksUri: info.jwksUri,
          // The JWKS this service ISSUED to this client from its own
          // certificate authority, beside the one the client registered. Two
          // attributes and not one: a client that registered its own keys and
          // was later issued a pair by an operator has two ways to sign, both
          // of which somebody deliberately arranged.
          assertionJwks: info.assertionJwks,
          audiences: info.audiences,
          // OAuth 2.1 mode's issuer-as-sole-audience rule, or empty.
          strictAudience: info.strictAudience || '',
          // What binds the used-assertion claim to this response, so that an
          // assertion is spent only when tokens are issued.
          request: info.request
        });
      });
    if (!checked.ok) {
      log.debug("Leaving verify(). The assertion was refused.");
      log.debug("Leaving verify().");
      return checked;
    }
    log.debug("Leaving verify(). The assertion verified.");
    log.debug("Leaving verify().");
    return { ok: true, method: method, alg: checked.alg, jti: checked.jti };
  }

  // -------------------------------------------------------------------------
  // RFC 7522 SECTION 2.2 — A SAML 2.0 ASSERTION IN PLACE OF A CLIENT SECRET.
  //
  // A BRANCH OF ITS OWN rather than a third case on the one above, because
  // almost nothing is shared: there is no symmetric variant to tell apart (XML
  // Signature over a shared secret is not something any SAML stack emits, so
  // the alg-confusion refusal has nothing to refuse), the key material is a
  // certificate rather than a JWKS, and the checks are section 3's eleven
  // items rather than RFC 7523 section 3's ten claims.
  //
  // **THE CERTIFICATES ARE THE RFC 7522 ONES AND ONLY THOSE.** A client that
  // holds an RFC 7523 key pair and no SAML one cannot authenticate this way,
  // which is the separation the two attribute sets exist for and is stated at
  // the refusal rather than left to be discovered.
  // -------------------------------------------------------------------------
  if (method === 'saml2_bearer') {
    if (!info.assertion) {
      log.debug("Leaving verify(). No SAML assertion was presented.");
      return { ok: false, errorCode: 'STS-OAUTH-0023', description: 'this ' +
          'client authenticates with ' + method +
                                       ', so the request must carry ' +
                                       'client_assertion and ' +
                                       'client_assertion_type=' +
          SAML_ASSERTION_TYPE +
                                       ' (RFC 7522 section 2.2).' };
    }
    if (String(info.assertionType || '') !== SAML_ASSERTION_TYPE) {
      // NAMED, and the JWT type is named back where it is the one that
      // arrived: the two profiles put different documents in one parameter,
      // and "your assertion is invalid" for a client that sent a perfectly
      // good JWT under the wrong type is the least useful true sentence
      // available.
      log.debug("Leaving verify(). The SAML assertion type is wrong.");
      return { ok: false, errorCode: 'STS-OAUTH-0024',
               description: 'client_assertion_type ' +
          'must be "' +
                                       SAML_ASSERTION_TYPE + '" (RFC 7522 ' +
                                       'section 2.2). This request says ' +
                                       '"' + (info.assertionType || '') +
                                       '"' +
                                       (String(info.assertionType ||
                                               '') === ASSERTION_TYPE
                                         ? ', which is RFC 7523\'s JWT ' +
                                           'profile — this client is ' +
                                           'registered for the SAML 2.0 one'
                                         : '') + '.' };
    }
    const checked = await verifiedOnce(info.request,
      [method, info.clientId, info.assertionType, info.assertion],
      function () {
        return samlAssertionGrant.verify({
          assertion: info.assertion,
          clientId: info.clientId,
          // The two RFC 7522 attributes, handed over rather than looked up,
          // because this function is given FIELDS by its caller. Neither of
          // them is an `oauthAssertion*` one.
          registeredCertificate: info.samlSigningCertificate,
          issuedCertificate: info.samlAssertionCertificate,
          issuedCertificateChain: info.samlAssertionCertificateChain,
          audiences: info.audiences,
          request: info.request
        });
      });
    if (!checked.ok) {
      log.debug("Leaving verify(). The SAML assertion was refused.");
      return { ok: false, errorCode: checked.errorCode,
               description: checked.description };
    }
    log.debug("Leaving verify(). The SAML assertion verified.");
    return { ok: true, method: method, alg: checked.signatureMethod,
             jti: checked.id };
  }

  // -------------------------------------------------------------------------
  // OAUTH 2.0 ATTESTATION-BASED CLIENT AUTHENTICATION (#229,
  // draft-ietf-oauth-attestation-based-client-auth-11). Nothing in the body:
  // the attestation and its proof are HTTP header fields, which is why the
  // request is all this branch hands over. `client_attestation.ts` holds the
  // whole of sections 4 to 7 and answers once per request, for
  // `verifiedOnce()`'s reason. `info.issuer` is the audience a PoP must name.
  // -------------------------------------------------------------------------
  if (ATTESTATION_METHODS.indexOf(method) >= 0) {
    const clientAttestation = require('./client_attestation');
    const checked = await clientAttestation.verifyRequest(info.request, {
      method: method, clientId: info.clientId, issuer: info.issuer
    });
    if (!checked.ok) {
      log.debug("Leaving verify(). The client attestation was refused.");
      return checked;
    }
    log.debug("Leaving verify(). The client attestation verified.");
    return { ok: true, method: method, alg: checked.alg, jti: checked.jti };
  }

  if (method === 'tls_client_auth' ||
      method === 'self_signed_tls_client_auth') {
    const checked = verifyCertificate({
      method: method, request: info.request, clientId: info.clientId,
      // The five subject parameters, keyed by their registration member
      // names — `clientConfigOf()`'s object is passed whole — and the
      // entry's own identifier, which the implicit mapping compares with the
      // application a realm-issued certificate names.
      subjects: info.tlsSubjects ||
                { tls_client_auth_subject_dn: info.subjectDn },
      applicationIdentifier: info.applicationIdentifier,
      certificateThumbprint: info.certificateThumbprint,
      jwks: info.jwks
    });
    if (!checked.ok) {
      log.debug("Leaving verify(). The certificate was refused.");
      log.debug("Leaving verify().");
      return checked;
    }
    log.debug("Leaving verify(). The certificate matched.");
    log.debug("Leaving verify().");
    return { ok: true, method: method, subject: checked.subject,
             mapping: checked.mapping, thumbprint: checked.thumbprint };
  }

  // A method this file cannot verify. It is refused rather than waved through,
  // which is the whole change: `private_key_jwt` used to land here and be
  // ACCEPTED, so a client author came away believing an assertion had been
  // checked when nothing had looked at it.
  log.debug("Leaving verify(). Unknown method.");
  log.debug("Leaving verify().");
  return { ok: false, errorCode: 'STS-OAUTH-0025',
           description:
             'this client\'s entry says token_endpoint_auth_method="' + method +
                        '", which this server cannot verify. The ' +
                        METHODS.length +
                        ' it can are: ' + METHODS.join(', ') + '.' };
}

module.exports = {
  ASSERTION_TYPE: ASSERTION_TYPE,
  SAML_ASSERTION_TYPE: SAML_ASSERTION_TYPE,
  METHODS: METHODS,
  SYMMETRIC_METHODS: SYMMETRIC_METHODS,
  ASYMMETRIC_METHODS: ASYMMETRIC_METHODS,
  isAsymmetric: isAsymmetric,
  subjectRfc4514: subjectRfc4514,
  verify: verify,
  // For the pages that report how many assertions are being remembered. The
  // history is one per realm now, shared with both grant profiles, so this is
  // that history's count rather than a count of client assertions alone.
  assertionsRemembered: function () {
    log.debug("Entering assertionsRemembered().");
    log.debug("Leaving assertionsRemembered().");
    return usedAssertions.summary().live;
  }
};
