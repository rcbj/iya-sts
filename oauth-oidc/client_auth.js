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
// THE SIX METHODS, and which of them is real here.
//
//   none                        public client; nothing to check
//   client_secret_basic         the secret, from an Authorization: Basic header
//   client_secret_post          the secret, from a form parameter
//   client_secret_jwt           an assertion signed HS256 with the secret
//   private_key_jwt             an assertion signed with the client's own key,
//                               verified against the JWKS it registered
//   tls_client_auth             the client certificate's subject DN matches the
//                               one registered (RFC 8705 section 2.1)
//   self_signed_tls_client_auth the client certificate's thumbprint matches the
//                               one registered (RFC 8705 section 2.2)
//
// All of them are verified. The two shared-secret ones compare in constant
// time; the two assertion ones do the full RFC 7523 section 3 check; the two
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
// `jwks_uri` IS DELIBERATELY NOT DEREFERENCED, and it is the same refusal
// WS-Federation's `wreqptr` gets.
//
// RFC 7591 lets a client register its keys by value (`jwks`) or by reference
// (`jwks_uri`). Following the reference means this service making an outbound
// HTTP request to a URL somebody registered, which is a server-side request
// forgery with a specification citation attached — the identical shape
// `wsfed.js` refuses, and refusing it there while doing it here would be a
// position held in one file and not the other. A client that registers
// `jwks_uri` is told to register `jwks` instead, by name, at the moment it
// authenticates rather than as a silent failure to verify.
//
// ---------------------------------------------------------------------------
// It is a LIBRARY (rule 3): it registers no route and requires `helpers.js`,
// `config.js` and `mtls.js` — none of which requires it back — so it cannot
// join a cycle. It holds ONE piece of state, the assertion `jti` cache, for the
// same reason `dpop.js` holds one: a replayed assertion is a replayed
// credential, and RFC 7523 section 3 says so.
// ===========================================================================

const crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('../common/realms');
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
const ASYMMETRIC_METHODS = ['private_key_jwt', 'saml2_bearer',
                            'tls_client_auth',
                            'self_signed_tls_client_auth'];
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
// The assertion `jti` cache. RFC 7523 section 3: an authorization server MAY
// reject an assertion whose jti it has already seen, and OpenID Connect Core
// section 9 says the jti must be used only once. A signed assertion captured
// off the wire is a credential until it expires, so "may" is not the useful
// reading — it is remembered for as long as the assertion could still be valid
// and refused after that by `exp` instead.
//
// ~~Bounded like every other cache here. A forgotten jti is a check not made,
// never a false refusal, which is why eviction is by AGE and the cap only ever
// drops the oldest.~~
//
// **THAT PARAGRAPH HAD THE TRADE BACKWARDS FOR THIS CACHE, AND IT CHANGED ON
// 2026-09-12 IN EVERY MODE.** "A check not made" is harmless for a cache that
// protects against a client BUG; this one protects against a CAPTURED
// CREDENTIAL, and a forgotten live jti is that credential accepted a second
// time. Dropping the oldest meant a thousand fresh assertions from anybody
// bought a replay of any older one still inside its `exp`. So the cap is now
// `oauth2.assertionReplayCacheSize`, EXPIRED entries are swept first, and a
// cache still full of live entries REFUSES THE NEW ASSERTION — a false refusal
// of a fresh credential, which the client recovers from by retrying, instead
// of a replay nobody could detect. `MAX_ASSERTIONS` is the default, kept under
// its old name.
// ---------------------------------------------------------------------------
const MAX_ASSERTIONS = 1000;

function maxAssertions() {
  log.debug("Entering maxAssertions().");
  const count = Number(config.value('oauth2.assertionReplayCacheSize'));
  log.debug("Leaving maxAssertions().");
  return isFinite(count) && count > 0 ? Math.floor(count) : MAX_ASSERTIONS;
}
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// jti -> forget-at
const seenAssertions = realms.map({ persist: 'client_auth.seenAssertions' });

// Sweeps what has expired, and answers whether there is ROOM for one more.
// It never deletes an entry that has not expired — see the header above.
function forgetStaleAssertions() {
  log.debug("Entering forgetStaleAssertions().");
  const now = Date.now();
  seenAssertions.forEach(function (forgetAt, jti) {
    if (forgetAt < now) {
      seenAssertions.delete(jti);
    }
  });
  const room = seenAssertions.size < maxAssertions();
  log.debug("Leaving forgetStaleAssertions(). " + seenAssertions.size + " " +
      "live; " +
            (room ? "room for another." : "FULL."));
  return room;
}

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

// One of two copies of this until 2026-08-27; `scim/scim_auth.js` had the
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
    // The first two are read by `assertion_grant.js`'s `keysForParty()` ... no:
    // they are read here through `keysFrom()` twice, because this function is
    // handed FIELDS by its caller rather than an entry. Same table, same
    // reader, one call per attribute.
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
    if (!found.length && opts.jwksUri) {
      log.debug("Leaving verifyAssertion(). Only a jwks_uri is registered.");
      return { ok: false, errorCode: 'STS-OAUTH-0005', description: 'this ' +
                                       'client registered jwks_uri and no ' +
                                       'jwks. This service will NOT fetch a ' +
                                       'URL somebody registered in order to ' +
                                       'verify a credential — that is a ' +
                                       'server-side request forgery with a ' +
                                       'specification citation attached, and ' +
                                       'it is the same refusal ' +
                                       'WS-Federation\'s wreqptr gets here. ' +
                                       'Register the keys by value, as ' +
                                       '`jwks`.' };
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
  const room = forgetStaleAssertions();
  const key = clientId + ':' + String(claims.jti);
  if (seenAssertions.has(key)) {
    log.warn('client_auth: client "' + clientId + '" replayed the assertion ' +
                                                  'jti ' + claims.jti +
             '. A signed assertion is a credential until it expires, so a ' +
             'second use of one is refused (RFC 7523 section 3).');
    log.debug("Leaving verifyAssertion(). The jti was replayed.");
    return { ok: false, errorCode: 'STS-OAUTH-0012', description: 'this ' +
                                     'client_assertion has been used ' +
                                     'already. Its `jti` is remembered until ' +
                                     'the assertion expires, because a ' +
                                     'signed assertion captured off the wire ' +
                                     'is a credential until then. Mint a ' +
                                     'fresh one per request.' };
  }
  if (!room) {
    log.warn('client_auth: the client assertion replay cache for this realm ' +
             'is full of unexpired entries (oauth2.assertionReplayCacheSize ' +
             '= ' + maxAssertions() +
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
  // Remembered until it expires — not for a fixed window — so the cache and the
  // `exp` check cover exactly the same span between them, with no gap in which
  // a replay would be accepted because the entry had been swept early. An
  // assertion with NO `exp` (development only, see above) is remembered for the
  // lifetime ceiling where there is one and for five minutes where there is not
  // — it stays presentable after that, which is the permissiveness development
  // mode has, stated here rather than pretended away.
  const remembered = hasExp
    ? Number(claims.exp) * 1000
    : Date.now() +
      (Number(config.value('oauth2.jwtBearerMaxLifetimeS')) || 300) * 1000;
  seenAssertions.set(key, remembered + clockSkewSeconds() * 1000);
  log.debug("Leaving verifyAssertion(). Verified. alg=" + alg + ", jti=" +
            claims.jti);
  return { ok: true, alg: alg, jti: String(claims.jti) };
}

// ---------------------------------------------------------------------------
// RFC 8705 section 2 — the certificate stands in for the secret.
//
// Two methods, and the difference is what the certificate has to match:
//
//   tls_client_auth              a PKI-issued certificate whose SUBJECT DN is
//                                the one the client registered (section 2.1.2's
//                                `tls_client_auth_subject_dn`)
//   self_signed_tls_client_auth  any certificate whose THUMBPRINT is the one the
//                                client registered — no CA involved, which is
//                                section 2.2's whole point
//
// The subject is compared in RFC 4514 form, leaf first, which is the same
// spelling `tls_server.js` files a verified certificate under on /admin/users —
// one spelling for one DN across this service, rather than each surface picking
// its own and the two never matching.
// ---------------------------------------------------------------------------
function subjectRfc4514(cert) {
  log.debug("Entering subjectRfc4514().");
  // node hands back a subject object; the RDNs are ordered leaf-first when read
  // in reverse of the object's insertion order, which is how the TLS report
  // builds the same string.
  const subject = (cert && cert.subject) || {};
  const parts = [];
  Object.keys(subject).forEach(function (type) {
    const values = Array.isArray(subject[type]) ? subject[type] :
                   [subject[type]];
    values.forEach(function (value) {
      parts.push(type + '=' +
                 String(value).replace(/([,+="<>;\\\\])/g, '\\\\$1'));
    });
  });
  log.debug("Leaving subjectRfc4514().");
  return parts.reverse().join(',');
}

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
             errorCode: revocation.status === 'revoked' ? 'STS-PKI-0118' :
                        'STS-PKI-0119',
             description: 'RFC 8705 section 2: the client certificate on ' +
                          'this connection was refused on revocation ' +
                          '(pki.revocationCheck is ' +
                          revocation.policy + '). ' + revocation.why };
  }
  if (opts.method === 'self_signed_tls_client_auth') {
    const registered = String(opts.certificateThumbprint || '');
    if (!registered) {
      log.debug("Leaving verifyCertificate().");
      return { ok: false, errorCode: 'STS-OAUTH-0015',
               description: 'this client authenticates with a self-signed ' +
                            'certificate (RFC 8705 section 2.2) and has none ' +
                            'registered. Put its SHA-256 thumbprint on its ' +
                            'entry as oauthTlsClientCertificateThumbprint.' };
    }
    const presented = mtls.thumbprintOf(cert);
    if (presented !== registered) {
      log.debug("Leaving verifyCertificate(). The thumbprint does not match.");
      return { ok: false, errorCode: 'STS-OAUTH-0016',
               description: 'RFC 8705 section 2.2: this client registered ' +
                            'the certificate whose SHA-256 thumbprint ' +
                            'is ' + registered + ', and ' +
                            'this connection was made with the one whose ' +
                            'thumbprint is ' + presented + '.' };
    }
    log.debug("Leaving verifyCertificate(). The thumbprint matches.");
    return { ok: true, subject: subjectRfc4514(cert), thumbprint: presented };
  }
  const registeredDn = String(opts.subjectDn || '');
  if (!registeredDn) {
    log.debug("Leaving verifyCertificate().");
    return { ok: false, errorCode: 'STS-OAUTH-0017',
             description: 'this client authenticates with a PKI certificate ' +
                          '(RFC 8705 section 2.1) and has no subject DN ' +
                          'registered. Put it on its entry as ' +
                          'oauthTlsClientAuthSubjectDn, in RFC 4514 form — ' +
                          'the spelling /admin/users files a verified ' +
                          'certificate under.' };
  }
  const presentedDn = subjectRfc4514(cert);
  if (presentedDn !== registeredDn) {
    log.debug("Leaving verifyCertificate(). The subject DN does not match.");
    return { ok: false, errorCode: 'STS-OAUTH-0018',
             description: 'RFC 8705 section 2.1.2: this client registered ' +
                          'the subject DN "' +
                          registeredDn + '" and the certificate on this ' +
                                         'connection has "' +
                          presentedDn + '".' };
  }
  // NOT a check on the chain, and that is worth being explicit about rather
  // than leaving as an omission: section 2.1 expects a PKI-issued certificate
  // validated against a trust anchor, and this service's truststore is whatever
  // somebody POSTed to /tls/trust — empty at startup by design. So what is
  // verified here is possession of the private key for a certificate with the
  // registered subject, which the TLS handshake proves, and NOT that a CA
  // vouched for it. A real deployment must do both.
  log.warn('RFC 8705 section 2.1: client "' + (opts.clientId || '') + '" ' +
           'authenticated by its certificate subject DN. This service does ' +
           'NOT validate the certificate chain — the truststore at ' +
           '/tls/trust starts empty by design — so what was proved is ' +
           'possession of the key for a certificate carrying that subject, ' +
           'not that a CA issued it.');
  log.debug("Leaving verifyCertificate(). The subject DN matches.");
  return { ok: true, subject: presentedDn,
           thumbprint: mtls.thumbprintOf(cert) };
}

// ---------------------------------------------------------------------------
// THE ONE ENTRY POINT. Given what the request presented and what the client's
// entry says, does this client authenticate?
//
// It decides nothing about whether authentication is REQUIRED — that is section
// 2.5's policy question and it lives in `oauth2_bcp.js`. This answers only
// "does what arrived prove this client", which is protocol.
// ---------------------------------------------------------------------------
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
    if (!secretsMatch(info.presentedSecret, info.clientSecret)) {
      log.debug("Leaving verify(). The secret did not match.");
      log.debug("Leaving verify().");
      return { ok: false, errorCode: 'STS-OAUTH-0020', description: 'the ' +
                                       'client_secret presented is not the ' +
                                       'one on this client\'s entry in the ' +
                                       'application registry.' };
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
    const checked = await verifyAssertion({
      method: method, assertion: info.assertion, clientId: info.clientId,
      clientSecret: info.clientSecret, jwks: info.jwks, jwksUri: info.jwksUri,
      // The JWKS this service ISSUED to this client from its own certificate
      // authority, beside the one the client registered. Two attributes and
      // not one: a client that registered its own keys and was later issued a
      // pair by an operator has two ways to sign, both of which somebody
      // deliberately arranged.
      assertionJwks: info.assertionJwks,
      audiences: info.audiences
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
    const checked = await samlAssertionGrant.verify({
      assertion: info.assertion,
      clientId: info.clientId,
      // The two RFC 7522 attributes, handed over rather than looked up,
      // because this function is given FIELDS by its caller. Neither of them
      // is an `oauthAssertion*` one.
      registeredCertificate: info.samlSigningCertificate,
      issuedCertificate: info.samlAssertionCertificate,
      audiences: info.audiences
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

  if (method === 'tls_client_auth' ||
      method === 'self_signed_tls_client_auth') {
    const checked = verifyCertificate({
      method: method, request: info.request, clientId: info.clientId,
      subjectDn: info.subjectDn,
      certificateThumbprint: info.certificateThumbprint
    });
    if (!checked.ok) {
      log.debug("Leaving verify(). The certificate was refused.");
      log.debug("Leaving verify().");
      return checked;
    }
    log.debug("Leaving verify(). The certificate matched.");
    log.debug("Leaving verify().");
    return { ok: true, method: method, subject: checked.subject };
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
  // For the pages that report how many assertions are being remembered.
  assertionsRemembered: function () {
    log.debug("Entering assertionsRemembered().");
    log.debug("Leaving assertionsRemembered().");
    return seenAssertions.size;
  }
};
