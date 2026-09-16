'use strict';
//
// File: assertion_grant.js
//
// ===========================================================================
// RFC 7521 AND RFC 7523: AN ASSERTION INSTEAD OF A CREDENTIAL.
//
// **RFC 7521 IS A FRAMEWORK AND RFC 7523 IS THE ONLY PROFILE OF IT ANYBODY
// USES**, which is why one file holds both and why the header says so first. A
// reader looking for "the RFC 7521 code" will find nothing else: 7521 defines
// two request parameters, one error vocabulary and a list of checks, and 7523
// says the assertion is a JWT and names the claims. Neither is testable
// without the other — 7521 has no wire format at all — and `tests/` says the
// same thing where it would otherwise look like a coverage gap.
//
// ---------------------------------------------------------------------------
// TWO USES OF ONE FORMAT, AND THEY ARE NOT THE SAME FEATURE.
//
//   RFC 7523 section 2.2   CLIENT AUTHENTICATION. `client_assertion` +
//                          `client_assertion_type`. The assertion says WHO IS
//                          CALLING, and is a replacement for a client secret.
//                          `client_auth.js` has done this since 2026-08-26.
//
//   RFC 7523 section 2.1   AN AUTHORIZATION GRANT. `grant_type=…:jwt-bearer`
//                          + `assertion`. The assertion says WHO THE TOKEN IS
//                          FOR, and is a replacement for an authorization
//                          code. **This file is what was missing.**
//
// They share a format, a claim set and — since 2026-09-13 — one used-assertion
// history (`common/used_assertions.js`), and nothing else. In the
// first the `sub` MUST be the client; in the second the `sub` is a PERSON and
// being the client would be the degenerate case. Reading one file and
// concluding the other is covered is the mistake this paragraph exists to
// prevent — which is exactly the mistake this service had made: the metadata
// named RFC 7523, `client_auth.js` implemented section 2.2 completely, and
// section 2.1 did not exist.
//
// ---------------------------------------------------------------------------
// WHAT AN ASSERTION GRANT ACTUALLY IS, BECAUSE IT DECIDES THE REFUSAL.
//
// A trusted party signs a document saying *this person is alice, and I am
// giving you this so you will issue a token for her*, and this authorization
// server issues one. **There is no browser, no password and no consent step
// anywhere in it.** So the signature is the entire security of the grant, and
// the one thing this service must not do is accept an assertion from anybody.
//
// That puts this feature in the same category as FEDERATION rather than in the
// category everything else here is in: **there is no permissive answer
// available.** "Accept any signed assertion" means anybody who can reach this
// port gets an access token as anybody. So an assertion issuer must be
// CONFIGURED, `oauth2.jwtBearerRequireRegisteredIssuer` is on by default, and
// `federation/CLAUDE.md`'s argument is the argument here.
//
// **WHAT IS STILL PERMISSIVE IS EVERYTHING AROUND IT**, and that is the
// distinction `kerberos/CLAUDE.md` draws about SPNEGO. The `sub` need not be
// anybody this service has heard of — an assertion for a name nobody has ever
// used mints that person exactly as typing the name at the sign-in screen
// does. The scope is not checked against anything. What is real is that
// somebody who holds a private key this service was told to trust signed the
// document.
//
// ---------------------------------------------------------------------------
// THERE ARE TWO KINDS OF ISSUER SINCE 2026-09-11, AND THE SECOND HAS A RULE
// THE FIRST DOES NOT.
//
// An APPLICATION is the issuer this file was written for: an operator declares
// `oauthAssertionIssuer` on its entry, which is the operator saying *this party
// may speak about people*, and its assertion may name any `sub` at all. That is
// the delegated shape of section 2.1 — a trusted third party vouching for
// somebody.
//
// A PERSON may hold a signing key pair now (`common/person_assertions.js`,
// `stsAssertion*` on their own entry), and sign an assertion saying *this is
// me, issue a token for me*. **That is RFC 7523 read literally rather than
// extended**: section 3 claim 1 asks only that `iss` be "a unique identifier
// for the JWT issuer", and claim 2 says the `sub` of an authorization grant
// "typically identifies an authorized accessor or resource owner". A resource
// owner presenting a key of their own is the case the profile describes and the
// one a client author most often wants to run — no browser, no password, a
// signature and an access token.
//
// **AND A PERSON MAY ONLY ASSERT ABOUT THEMSELVES.** `iss` and `sub` must name
// the same person, checked below, because a person's key pair is a credential
// belonging to one person rather than an authority over the others — and
// without the rule, anybody handed a key on /admin/pki could obtain a token as
// anybody in the realm. The check is made TWICE, once for a key found on the
// entry and once for a certificate presented in an `x5c` that this service can
// see it issued to a person, because those are two ways in and the second does
// not go through the registry at all.
//
// ---------------------------------------------------------------------------
// EVERY OPTIONAL COMPONENT OF BOTH SPECIFICATIONS IS IMPLEMENTED, and the list
// is here because "optional" is where implementations quietly differ:
//
//   RFC 7523 section 3 claim 5   `nbf`   checked, with the configured skew
//   RFC 7523 section 3 claim 6   `iat`   checked, and it bounds the LIFETIME
//                                        (`oauth2.jwtBearerMaxLifetimeS`)
//   RFC 7523 section 3 claim 7   `jti`   spent once, ever, against the
//                                        used-assertion history, and
//                                        REQUIRED here — see below
//   RFC 7523 section 3 claim 8   other claims are carried onto the token
//   RFC 7523 section 3 claim 10  **the assertion may be ENCRYPTED** — a nested
//                                        JWT, JWE(JWS), in any algorithm this
//                                        service holds a key for
//   RFC 7521 section 4.1         `scope` on the request, narrowed against what
//                                        the assertion permits
//   RFC 7521 section 5.2 (5)     the assertion may name several audiences
//   RFC 7521 section 6.2         `client_id` may be OMITTED where the
//                                        assertion identifies the client
//   RFC 7521 section 6.3         the assertion may carry a `cnf` — reported,
//                                        not enforced; see below
//   RFC 7521 section 4.2         `error_description` and `error_uri` on every
//                                        refusal, which is most of this file
//
// **`jti` IS REQUIRED HERE AND THE RFC SAYS OPTIONAL**, which is section 3's
// own reading rather than a departure from it: the last paragraph of that
// section says an authorization server MAY reject a reused JWT, and a signed
// assertion captured off the wire is a CREDENTIAL until it expires. An
// assertion with no `jti` cannot be remembered, so accepting one would mean
// accepting a bearer credential this service has no way to spend. It is the
// same decision `client_auth.js` already made for section 2.2, and it is
// stated at the refusal rather than left to be discovered.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, so its position in the require
// order is not a position. It requires only `common/` libraries —
// `helpers.js`, `config.js`, `applications.js`, `crypto.js`, `pki.js`,
// `revocation_status.js`, `person_assertions.js`, `used_assertions.js` and
// `error_codes.js` — none of which requires it back. It is required by
// `oauth2.js` (9), by `request_object.js` and `software_statement.js` (for
// `keysForParty()` and `keyFromChain()`), and by `client_auth.js`, which takes
// its key reading and its JWE unwrap from here rather than keeping a second
// copy of either.
//
// **THE DEPENDENCY RUNS ONE WAY AND MUST**: `client_auth.js` requires THIS,
// never the reverse. Section 2.2 needs the assertion FORMAT and this file owns
// it; section 2.1 needs nothing at all from client authentication, because an
// assertion grant may arrive from a public client with no credential.
// ===========================================================================

const nodeCrypto = require('crypto');
const stsCrypto = require('../common/crypto');
const pki = require('../common/pki');
// A LEAF that requires nothing: the code a chain refusal carries is read off
// the verdict `pki.verifySignerChain()` returns.
const errorCodes = require('../common/error_codes');
// A library (rule 3) that registers no route: the revocation check a
// REGISTERED key's certificate gets when it verifies an assertion below.
const revocationStatus = require('../common/revocation_status');
const applications = require('../common/applications');
// THE PERSON-ASSERTION REGISTER (2026-09-11). A LIBRARY (rule 3) that holds no
// store — `ldap/ldap_server.js` fills its `setDirectory()` slot at 21, which is
// how this file reaches `ou=users` from position 9 without registering a single
// /ldap route. It is the SECOND kind of issuer this grant accepts, and the one
// refusal that comes with it is its own: a person's key signs an assertion
// about that person and about nobody else.
const personAssertions = require('../common/person_assertions');
const config = require('../common/config');
const { log, STS } = require('../common/helpers');

// RFC 7523 section 2.1. One value, spelt once.
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
// RFC 7521 section 4.2's error code for a bad assertion, which is
// `invalid_grant` for section 2.1 and `invalid_client` for section 2.2 — the
// same document refused for the same reason gets two codes depending on what
// it was being used AS, which is a thing implementations get wrong in both
// directions.
const GRANT_ERROR = 'invalid_grant';

// ---------------------------------------------------------------------------
// THE USED-ASSERTION HISTORY, AND IT IS NOT A SECOND CACHE ANY MORE
// (2026-09-13).
//
// This file kept a replay cache of its own beside `client_auth.js`'s and argued
// that was deliberate: a document used to authenticate a client and a document
// used to authorize an issuance were two credentials, keyed differently, and one
// cache would let an assertion presented as a client credential spend the jti
// of a grant from the same party. **The owner reversed that, and the argument
// did not survive being read against the rule it was for.** A jti is the
// ISSUER's name for one document (RFC 7519 section 4.1.7 requires it be
// unique to that issuer), so two documents from one party sharing one is
// already a broken issuer — and one document spent as a client assertion AND
// as a grant is a JWT used twice, which "once" forbids. Both now spend against
// `common/used_assertions.js`, keyed by issuer and jti whatever the document
// is presented as. That module argues the rest: why it persists in every store,
// why the claim is atomic across processes, and why an assertion is spent only
// when tokens are issued.
//
// **A FULL HISTORY REFUSES; IT NEVER FORGETS** — the 2026-09-12 rule, moved
// with it unchanged. `oauth2.assertionReplayCacheSize` is one count per realm
// now rather than one per cache.
// ---------------------------------------------------------------------------
const usedAssertions = require('../common/used_assertions');

function skewSeconds() {
  log.debug("Entering skewSeconds().");
  log.debug("Leaving skewSeconds().");
  // THE SAME SETTING SECTION 2.2 USES, deliberately. It answers "how far out
  // may somebody else's clock be", and this service has no reason to hold two
  // different opinions about that depending on which parameter the assertion
  // arrived in. Its description names both uses.
  return config.value('oauth2.clientAssertionSkewS');
}

function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return config.value('oauth2.jwtBearerGrant') !== false;
}

function requiresRegisteredIssuer() {
  log.debug("Entering requiresRegisteredIssuer().");
  log.debug("Leaving requiresRegisteredIssuer().");
  return config.value('oauth2.jwtBearerRequireRegisteredIssuer') !== false;
}

function maxLifetimeSeconds() {
  log.debug("Entering maxLifetimeSeconds().");
  const seconds = Number(config.value('oauth2.jwtBearerMaxLifetimeS'));
  log.debug("Leaving maxLifetimeSeconds().");
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0;
}

// ---------------------------------------------------------------------------
// A REGISTERED JWKS AS A LIST OF KEYS. **MOVED HERE FROM `client_auth.js`**,
// which now calls this one — the two sections read the same registered key
// material and a second copy of this function would be a second answer to
// "which of this client's keys may sign".
//
// It refuses rather than throwing: a client that registered a malformed key
// needs to be told which, and an exception here would surface at the token
// endpoint as a 500 with nothing in it about keys.
// ---------------------------------------------------------------------------
function keysFrom(jwksText) {
  log.debug('Entering keysFrom().');
  let document = null;
  try {
    document = typeof jwksText === 'string' ? JSON.parse(jwksText) : jwksText;
  } catch (e) {
    log.debug('Leaving keysFrom(). The registered JWKS is not JSON.');
    return { errorCode: 'STS-OAUTH-0026', error: 'the JWKS registered for ' +
                                                 'this party is not valid ' +
                                                 'JSON: ' +
                    e.message };
  }
  const jwks = (document && Array.isArray(document.keys)) ? document.keys : [];
  if (!jwks.length) {
    log.debug('Leaving keysFrom(). The registered JWKS has no keys.');
    return { errorCode: 'STS-OAUTH-0027', error: 'the JWKS registered for ' +
                                                 'this party contains no ' +
                                                 'keys' };
  }
  const keys = [];
  for (let i = 0; i < jwks.length; i++) {
    const jwk = jwks[i];
    try {
      if (jwk.kty === 'AKP') {
        // RFC 9964's post-quantum key type. node's createPublicKey() has no
        // idea what one is — and must not be asked, or the key is dropped as
        // unreadable and the caller is told none of its keys could be read,
        // which names nothing a person could act on. The JWK travels WHOLE to
        // stsCrypto.verifyCompactJws(), which routes an AKP to pq_jose.js.
        keys.push({ kid: jwk.kid ? String(jwk.kid) : '', jwk: jwk, key: jwk });
        continue;
      }
      keys.push({ kid: jwk.kid ? String(jwk.kid) : '', jwk: jwk,
                  key: nodeCrypto.createPublicKey(
                      { key: jwk, format: 'jwk' }) });
    } catch (e) {
      // One unreadable key does not spoil the set: a JWKS commonly carries a
      // key this version of node cannot build beside ones it can, and refusing
      // the whole document would make a party unable to present an assertion
      // signed with the key that was fine.
      log.warn('assertion_grant: a key in a registered JWKS could not be ' +
               'read and is ignored (' +
               (jwk && jwk.kid ? 'kid=' + jwk.kid : 'no kid') + '): ' +
               e.message);
    }
  }
  if (!keys.length) {
    log.debug('Leaving keysFrom(). None of the registered keys could be read.');
    return { errorCode: 'STS-OAUTH-0028', error: 'none of the keys in the ' +
                    'JWKS registered for this party could be read' };
  }
  log.debug('Leaving keysFrom(). ' + keys.length + ' usable key(s).');
  return { keys: keys };
}

// ---------------------------------------------------------------------------
// RFC 7523 SECTION 3 CLAIM 10 — THE ASSERTION MAY BE ENCRYPTED.
//
// A nested JWT: a JWE whose plaintext is the JWS. **Both parameters take one**
// — `assertion` and `client_assertion` alike — which is why this function is
// here rather than in either caller.
//
// **WHICH KEY OPENS IT DEPENDS ON WHAT THE SENDER COULD POSSIBLY HAVE HAD**,
// and that is the whole of the design:
//
//   an asymmetric alg   encrypted to THIS SERVICE'S published RSA or EC key,
//                       which anybody can fetch from the JWKS. Every party
//                       can do this and it is what a client should use.
//   a symmetric alg     encrypted under the CLIENT SECRET, which is the only
//                       shared key that exists between this service and a
//                       client. Available only where there is one, which is
//                       why `secret` is a parameter rather than a lookup.
//
// **THE `cty` IS CHECKED AND NOT ASSUMED.** RFC 7519 section 5.2 says a nested
// JWT carries `cty: "JWT"`, and a JWE whose plaintext is something else is a
// document this service should say it cannot read rather than hand to a JWS
// parser that will report a base64 problem three frames away. It is a WARNING
// rather than a refusal where the plaintext does parse as a JWS, because
// several stacks omit it and the specification's own word is "MUST" about
// emitting it rather than about refusing one without it.
// ---------------------------------------------------------------------------
function unwrapAssertion(presented, opts) {
  log.debug('Entering unwrapAssertion().');
  const options = opts || {};
  const compact = String(presented || '').trim();
  const parts = compact.split('.');
  if (parts.length !== 5) {
    // Three parts is an ordinary JWS and is the overwhelmingly common case;
    // anything else is left to the JWS reader to report, because it can say
    // more about a malformed token than a length check can.
    log.debug('Leaving unwrapAssertion(). Not encrypted.');
    return { ok: true, jws: compact, encrypted: false };
  }
  let header = null;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch (e) {
    log.debug('Leaving unwrapAssertion(). The JWE header is not JSON.');
    return { ok: false, errorCode: 'STS-OAUTH-0029', description: 'this ' +
             'assertion has five parts, so it is an encrypted JWT (RFC 7523 ' +
             'section 3, claim 10) — and its protected header is not valid ' +
             'base64url JSON: ' + e.message };
  }
  const alg = String((header && header.alg) || '');
  // -------------------------------------------------------------------------
  // WHICH OF THIS REALM'S PRIVATE KEYS OPENS IT, and it is decided by the
  // ALGORITHM FAMILY rather than by a single default.
  //
  // The first version of this function handed `STS.privateKey` — the RSA one —
  // to every asymmetric algorithm, so an ECDH-ES assertion encrypted to an EC
  // key this service PUBLISHES in its own JWKS was refused with "the content
  // encryption key could not be unwrapped". The metadata advertised the
  // algorithm and the endpoint could not perform it, which is the worst shape
  // a metadata member can have and is the reason this list is derived from the
  // key set rather than written down.
  //
  // `STS` is a proxy onto the AMBIENT realm's key set, so these are the keys of
  // the authorization server the request actually reached — which is what the
  // sender fetched from the JWKS at the path it posted to.
  // -------------------------------------------------------------------------
  const symmetric = stsCrypto.JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0;
  const candidates = [];
  if (symmetric) {
    candidates.push({ secret: options.secret });
  } else if (stsCrypto.JWE_ECDH_ALGS.indexOf(alg) >= 0) {
    // ECDH-ES agrees over a CURVE, so the key that opens it is the one whose
    // curve matches the sender's ephemeral key. Narrowed by the header's `kid`
    // where it names one; otherwise every EC key of that curve is tried, which
    // is the same rule `verify()` applies to signing keys and is correct for
    // the same reason — an agreement either produces the right secret or it
    // does not.
    const wanted = String((header.epk && header.epk.crv) || '');
    (STS.extraKeys || []).forEach(function (one) {
      const jwk = one.publicJwk || {};
      if (jwk.kty !== 'EC' || (wanted && jwk.crv !== wanted)) {
        return;
      }
      if (header.kid && String(header.kid) !== String(jwk.kid)) {
        return;
      }
      candidates.push({ privateKey: one.privateKey });
    });
  } else {
    candidates.push({ privateKey: STS.privateKey });
  }
  if (!candidates.length) {
    log.debug('Leaving unwrapAssertion(). No key of that kind.');
    return { ok: false, errorCode: 'STS-OAUTH-0030', description: 'this ' +
        'assertion is encrypted "' + alg +
             '" and this authorization server holds no key it could be ' +
             'encrypted to' +
             (header.epk && header.epk.crv
               ? ' over the curve "' + header.epk.crv + '"'
               : '') + (header.kid ? ' under kid "' + header.kid + '"' : '') +
             '. Its keys are published at /oauth2/jwks.' };
  }
  let opened = null;
  let lastError = '';
  for (let i = 0; i < candidates.length && !opened; i++) {
    try {
      opened = stsCrypto.decryptJweCompact(compact, Object.assign({
        // Every `enc` this service knows. Narrowing here would be this service
        // advertising a content encryption algorithm it then refused, and the
        // list it advertises is exactly this one.
        allowedEnc: Object.keys(stsCrypto.JWE_ENCS)
      }, candidates[i]));
    } catch (e) {
      lastError = e.message;
    }
  }
  if (!opened) {
    log.debug('Leaving unwrapAssertion(). It would not decrypt.');
    return { ok: false, errorCode: 'STS-OAUTH-0031', description: 'this ' +
             'assertion is encrypted and could not be ' +
             'decrypted: ' + lastError };
  }
  if (opened.header.cty && String(opened.header.cty).toUpperCase() !== 'JWT') {
    log.debug('Leaving unwrapAssertion(). The content type is not JWT.');
    return { ok: false, errorCode: 'STS-OAUTH-0032', description: 'this ' +
             'assertion is an encrypted JWT whose protected header says ' +
             'cty="' + opened.header.cty + '". ' +
             'An assertion is a signed JWT inside the encryption (RFC 7519 ' +
             'section 5.2), so cty must be "JWT" or absent.' };
  }
  const inner = String(opened.plaintext || '').trim();
  // ---------------------------------------------------------------------
  // **COUNTING DOTS IS NOT ENOUGH, AND THE FIRST VERSION OF THIS COUNTED
  // DOTS.** A JSON object carrying two dotted values — an `iss` of
  // `https://issuer.example.test/…` is the ordinary case — splits into
  // exactly three parts, so an unsigned claims object was read as a JWS and
  // the refusal a caller got named a base64 problem instead of the rule it
  // broke. `tests/vendored/sts_jwt_bearer_grant.js` sends precisely that.
  //
  // A JWS is three parts AND a protected header that is base64url JSON
  // carrying an `alg`, which is RFC 7515 section 3.1 read literally. Checked
  // here rather than left to `verify()`'s own header parse, because the
  // question at THIS point is what kind of document arrived.
  // ---------------------------------------------------------------------
  const looksSigned = (function () {
    const parts = inner.split('.');
    if (parts.length !== 3) {
      return false;
    }
    try {
      const head = JSON.parse(Buffer.from(parts[0], 'base64url')
        .toString('utf8'));
      return !!(head && head.alg);
    } catch (e) {
      log.debug("Caught in a callback in unwrapAssertion(): " +
                ((e && e.message) || e));
      // Not a protected header. Swallowed rather than reported, because the
      // answer to "is this a JWS" is simply no and the sentence below says
      // what that means.
      return false;
    }
  })();
  if (!looksSigned) {
    log.debug('Leaving unwrapAssertion(). The plaintext is not a JWS.');
    return { ok: false, errorCode: 'STS-OAUTH-0033', description: 'this ' +
             'assertion decrypted to something that is not a signed JWT. RFC ' +
             '7523 section 3 claim 9 requires the assertion to be signed or ' +
             'MACed, and encryption does not stand in for that: an encrypted ' +
             'document says nothing about who wrote it.' };
  }
  if (!opened.header.cty) {
    log.warn('assertion_grant: an encrypted assertion arrived without ' +
             'cty="JWT" in its protected header. RFC 7519 section 5.2 says a ' +
             'nested JWT carries one. It decrypted to a JWS, so it is ' +
             'accepted.');
  }
  log.debug('Leaving unwrapAssertion(). Decrypted. alg=' + alg);
  return { ok: true, jws: inner, encrypted: true,
           encryption: { alg: alg, enc: String(opened.header.enc || ''),
                         kid: opened.header.kid ? String(opened.header.kid) :
                              '',
                         cty: opened.header.cty ? String(opened.header.cty) :
                              '' } };
}

// ---------------------------------------------------------------------------
// WHICH KEYS MAY HAVE SIGNED AN ASSERTION FROM THIS PARTY.
//
// Two sources and they are ORed, which is a decision rather than an oversight:
//
//   `oauthJwks`           what the party REGISTERED, by value. RFC 7591's
//                         member, and what a party with a key of its own uses.
//   `oauthAssertionJwks`  what THIS SERVICE ISSUED to it from its own
//                         certificate authority (`common/pki.js`), public half
//                         only, carrying `x5c`.
//
// **THEY ARE TWO ATTRIBUTES AND NOT ONE, AND THE ISSUE PATH DOES NOT
// OVERWRITE.** A client that registered its own keys and is then issued a key
// pair by an operator has TWO ways to sign, both of which somebody
// deliberately arranged — and writing the issued JWKS over `oauthJwks` would
// silently end the first the moment somebody pressed a button on a page about
// the second.
//
// `jwks_uri` IS STILL NOT DEREFERENCED. Following a URL somebody registered in
// order to verify a credential is a server-side request forgery with a
// specification citation attached, and it is the same refusal WS-Federation's
// `wreqptr` gets. That position is `client_auth.js`'s, made once for both
// sections.
// ---------------------------------------------------------------------------
//
// **AND A PERSON'S KEY LIVES SOMEWHERE ELSE ENTIRELY**, which is why this
// function is told WHICH KIND of party it is reading rather than trying every
// name it knows. `stsAssertionJwks` is on a person's own entry and
// `oauthAssertionJwks` is on an application's; the store is schemaless, so a
// function that read both lists off whatever it was handed would accept an
// `oauthAssertionJwks` somebody put on a person — and that is precisely the
// crossing the two attribute sets exist to prevent, made once here instead of
// being hoped for.
function keysForParty(fields, kind) {
  log.debug('Entering keysForParty(). kind=' + (kind || 'application'));
  const found = [];
  const problems = [];
  const names = String(kind) === 'person'
    ? ['stsAssertionJwks']
    : ['oauthJwks', 'oauthAssertionJwks'];
  names.forEach(function (name) {
    const text = fields && fields[name];
    if (!text) {
      return;
    }
    const read = keysFrom(text);
    if (read.error) {
      problems.push(name + ': ' + read.error);
      return;
    }
    read.keys.forEach(function (one) {
      found.push(Object.assign({ source: name }, one));
    });
  });
  log.debug('Leaving keysForParty(). ' + found.length + ' key(s).');
  return { keys: found, problems: problems,
           // A PERSON CANNOT BE IN THIS STATE. `jwks_uri` is an application's
           // registration member and there is no person attribute that holds
           // one, so reporting it for a person would be a sentence about a
           // registration nobody made.
           jwksUriOnly: String(kind) !== 'person' &&
                        !!(fields && fields.oauthJwksUri && !fields.oauthJwks &&
                           !fields.oauthAssertionJwks) };
}

// The application entry that is allowed to issue assertions under this `iss`.
// `oauthAssertionIssuer` is the declaration; an application that declared none
// is found by its own identifier, because an assertion a CLIENT issues about
// itself names the client_id as `iss` and asking an operator to write the
// client_id down twice would be a configuration step with no decision in it.
function issuerEntry(iss) {
  log.debug('Entering issuerEntry(). iss=' + iss);
  const wanted = String(iss || '');
  if (!wanted) {
    log.debug('Leaving issuerEntry(). No issuer.');
    return null;
  }
  // `list()` answers VIEWS — `applications.view()` is not exported and takes a
  // record rather than an identifier — so `fields` is already here and there
  // is no second read per entry.
  const all = applications.list();
  for (let i = 0; i < all.length; i++) {
    const fields = all[i].fields || {};
    const declared = fields.oauthAssertionIssuer;
    const values = Array.isArray(declared) ? declared
      : (declared ? [String(declared)] : []);
    if (values.indexOf(wanted) >= 0) {
      log.debug('Leaving issuerEntry(). Declared by ' + all[i].identifier +
                '.');
      return { identifier: all[i].identifier, fields: fields, declared: true,
               kind: 'application' };
    }
  }
  // ---------------------------------------------------------------------
  // A PERSON, and it is asked AFTER every application declaration and
  // BEFORE an application's own identifier — which is the order the two
  // lookups are worth in this question.
  //
  // A DECLARATION is somebody saying *this name issues assertions*, and
  // `person_assertions.issuerFor()` answers a declared `stsAssertionIssuer`
  // first and a bare username second, exactly as this function does for an
  // application. So the sequence is: every declaration in the realm,
  // whoever wrote it, and then the two ways a party can be found by its own
  // name.
  //
  // **WHAT COMES BACK IS NOT AN APPLICATION AND MUST NOT BE TREATED AS
  // ONE.** `kind` travels with it, `keysForParty()` reads a different
  // attribute for it, and `verify()` refuses an assertion from it that
  // names anybody but the signer as `sub`. A caller that ignored `kind`
  // would be giving every person in the realm the authority an operator
  // grants by declaring `oauthAssertionIssuer` on an application.
  // ---------------------------------------------------------------------
  const person = personAssertions.issuerFor(wanted);
  if (person) {
    log.debug('Leaving issuerEntry(). A person: ' + person.identifier + '.');
    return { identifier: person.identifier,
             // The record's own attributes, in the spelling `keysForParty()`
             // reads. It is the same shape an application's `fields` is, so
             // that nothing below this line has to branch to find a key.
             fields: person.record,
             declared: person.declared,
             kind: 'person',
             person: person.record };
  }
  // NOT DECLARED, BUT KNOWN. An assertion a client issues ABOUT ITSELF names
  // its own client_id as `iss`, and asking an operator to write that down a
  // second time under another attribute would be a configuration step with no
  // decision in it. `declared: false` travels with the answer so that the
  // caller — and the console — can tell the two apart.
  const byClientId = applications.forClientId(wanted);
  if (byClientId) {
    log.debug('Leaving issuerEntry(). It is a client_id.');
    return { identifier: byClientId.identifier,
             fields: byClientId.fields || {}, declared: false,
             kind: 'application' };
  }
  const byIdentifier = applications.get(wanted);
  if (byIdentifier) {
    log.debug('Leaving issuerEntry(). It is an application identifier.');
    return { identifier: wanted, fields: byIdentifier.fields || {},
             declared: false, kind: 'application' };
  }
  log.debug('Leaving issuerEntry(). Nobody has declared it.');
  return null;
}

// ---------------------------------------------------------------------------
// THE `x5c` PATH, AND WHY IT IS CHECKED RATHER THAN READ.
//
// A JWS header may carry the signer's certificate chain (RFC 7515 section
// 4.1.6). Taking a public key out of one and verifying with it would be
// **verifying a signature against a key the signature came with**, which
// proves nothing at all — so an `x5c` is only ever used here after the chain
// has been shown to reach this realm's own Root CA.
//
// That is what makes the certificate authority worth having: a party issued a
// key pair by `/admin/pki` can present its certificate instead of registering
// a JWKS, and this service can tell that it issued it.
// ---------------------------------------------------------------------------
async function keyFromChain(header) {
  log.debug('Entering keyFromChain().');
  const chain = Array.isArray(header && header.x5c) ? header.x5c : [];
  if (!chain.length) {
    log.debug('Leaving keyFromChain(). No x5c.');
    return null;
  }
  const pem = function (b64) {
    log.debug("Entering pem().");
    log.debug("Leaving pem().");
    return '-----BEGIN CERTIFICATE-----\n' +
           String(b64).replace(/(.{64})/g, '$1\n').replace(/\n$/, '') +
           '\n-----END CERTIFICATE-----\n';
  };
  const leafPem = pem(chain[0]);
  const rest = chain.slice(1).map(pem);
  let checked;
  try {
    checked = await pki.verifyLeaf(undefined, leafPem, rest);
  } catch (e) {
    log.debug('Leaving keyFromChain(). The path would not build.');
    return { errorCode: 'STS-OAUTH-0034', error: 'the x5c chain could not be ' +
                                                 'checked: ' + e.message };
  }
  if (!checked.ok && checked.revocation && checked.revocation.refused) {
    // IT CHAINS HERE AND SOMETHING ON IT IS REVOKED (2026-09-12) — a different
    // condition from not chaining, with a different code, because the fix is
    // different: this certificate is ours and somebody withdrew it.
    log.debug('Leaving keyFromChain(). It chains here and is revoked.');
    return { errorCode: checked.revocation.status === 'revoked'
                          ? 'STS-PKI-0118' : 'STS-PKI-0119',
             error: 'the certificate in this assertion\'s x5c header chains ' +
                    'to this realm\'s certificate authority and was refused ' +
                    'on revocation: ' + checked.revocation.why };
  }
  const entitlement = errorCodes.codeOf(checked);
  if (!checked.ok && (entitlement === 'STS-PKI-0158' ||
                      entitlement === 'STS-PKI-0159')) {
    // IT CHAINS HERE AND A CERTIFICATE ON IT WAS NOT ENTITLED TO DO WHAT IT
    // DID (2026-09-13) — a certificate signed by one of this service's own
    // LEAVES, or a CA's certificate presented as the signer. "It does not chain
    // here" would be false about it, and the fix is not the same: nothing is
    // wrong with the anchor, somebody built a link that was never theirs to.
    log.debug('Leaving keyFromChain(). It chains here through a link that ' +
              'may not sign.');
    return { errorCode: entitlement,
             error: 'the certificate path in this assertion\'s x5c header ' +
                    'ends at this realm\'s certificate authority and was ' +
                    'refused: ' + checked.why };
  }
  if (!checked.ok) {
    log.debug('Leaving keyFromChain(). It does not chain here.');
    return { errorCode: 'STS-OAUTH-0035', error: 'the certificate in this ' +
                    'assertion\'s x5c header does not chain to this realm\'s ' +
                    'own certificate authority: ' +
                    checked.why + ' A certificate that arrives WITH the ' +
                    'signature proves nothing on its own, so this service ' +
                    'uses one only when it can see that it issued it.' };
  }
  let key;
  try {
    key = new nodeCrypto.X509Certificate(leafPem).publicKey;
  } catch (e) {
    log.debug("Leaving keyFromChain().");
    return { errorCode: 'STS-OAUTH-0036', error: 'the certificate in this ' +
                    'assertion\'s x5c header could not be read: ' + e.message };
  }
  // ---------------------------------------------------------------------
  // AND WHO IT WAS ISSUED TO, WHICH IS A CHECK THIS PATH DID NOT USED TO
  // NEED (2026-09-11).
  //
  // Until a PERSON could hold a key pair, every leaf this hierarchy issued
  // belonged to an application — a party an operator registered — so "it
  // chains here" and "it may assert about somebody" were the same sentence.
  // They are not any more: a person's leaf chains just as well, and reading
  // it as an authority over other people would hand everybody who is given a
  // key on /admin/pki a token as anybody in the realm.
  //
  // `common/pki.js` puts the answer IN the certificate for exactly this — a
  // URI subjectAltName of `urn:sts:person:<name>` or
  // `urn:sts:application:<identifier>` — so it is read here rather than
  // guessed from which attribute the certificate was found in, which is an
  // answer nobody holding a PEM file can get to. Node's own parse hands the
  // SAN over as a comma-separated string of `URI:…` members.
  // ---------------------------------------------------------------------
  const leaf = new nodeCrypto.X509Certificate(leafPem);
  const sans = String(leaf.subjectAltName || '').split(',')
    .map(function (one) { return one.trim(); });
  let subjectKind = '';
  let subjectName = '';
  sans.forEach(function (one) {
    const match = /^URI:urn:sts:(application|person):(.+)$/.exec(one);
    if (match) {
      subjectKind = match[1];
      subjectName = match[2];
    }
  });
  log.debug('Leaving keyFromChain(). It chains here, issued to ' +
            (subjectKind || 'something this service cannot name') + ' "' +
            subjectName + '".');
  return { key: key, subject: leaf.subject,
           subjectKind: subjectKind, subjectName: subjectName,
           thumbprint: stsCrypto.certificateThumbprint(leafPem,
                                                       { format:
                                                           'base64url' }) };
}

// ---------------------------------------------------------------------------
// THE CHECKS, IN RFC 7521 SECTION 5.2'S ORDER, WITH ONE THING FIRST.
//
// **THE SIGNATURE IS VERIFIED BEFORE ANY CLAIM IS BELIEVED**, which is not the
// order section 5.2 lists them in and is the order they have to run in. That
// section's checks are about `iss`, `sub` and `aud`, and reading any of those
// out of an unverified document is reading a name an attacker wrote. So the
// issuer is resolved from the unverified `iss` ONLY to find candidate keys,
// nothing is decided on it, and every check below runs on claims that a
// signature has already vouched for.
// ---------------------------------------------------------------------------
async function verify(opts) {
  log.debug('Entering verify().');
  const options = opts || {};
  const audiences = options.audiences || [];

  if (!enabled()) {
    log.debug('Leaving verify(). The grant is switched off.');
    return { ok: false, errorCode: 'STS-OAUTH-0037',
             error: 'unsupported_grant_type',
             description: 'This authorization server does not perform the ' +
                          'JWT bearer grant (RFC 7523 section 2.1). ' +
                          'oauth2.jwtBearerGrant is off.' };
  }
  const presented = String(options.assertion || '');
  if (!presented) {
    log.debug('Leaving verify(). No assertion.');
    return { ok: false, errorCode: 'STS-OAUTH-0038', error: 'invalid_request',
             description: 'grant_type="' + GRANT_TYPE + '" takes the ' +
                          'assertion in an `assertion` parameter (RFC 7521 ' +
                          'section 4.1). This request carried none.' };
  }

  // --- RFC 7523 section 3 claim 10: it may be encrypted ---------------------
  const unwrapped = unwrapAssertion(presented,
                                    { secret: options.clientSecret });
  if (!unwrapped.ok) {
    log.debug('Leaving verify(). It would not decrypt.');
    return { ok: false, errorCode: unwrapped.errorCode, error: GRANT_ERROR,
             description: unwrapped.description };
  }
  const jws = unwrapped.jws;

  let header = null;
  let unverified = null;
  try {
    const parts = jws.split('.');
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    unverified = JSON.parse(Buffer.from(parts[1], 'base64url')
                                  .toString('utf8'));
  } catch (e) {
    log.debug('Leaving verify(). It is not a JWT.');
    return { ok: false, errorCode: 'STS-OAUTH-0039', error: GRANT_ERROR,
             description: 'the assertion is not a JWT: ' + e.message };
  }
  const alg = String((header && header.alg) || '');
  if (alg === 'none') {
    // RFC 7523 section 3 claim 9. Named rather than left to fall out of the
    // algorithm table, because `alg: "none"` is the forgery every JWT
    // implementation has had at some point and a caller sending one deserves
    // to be told which rule it broke.
    log.debug('Leaving verify(). alg=none.');
    return { ok: false, errorCode: 'STS-OAUTH-0040', error: GRANT_ERROR,
             description: 'this assertion says alg="none". RFC 7523 section ' +
                          '3 claim 9 requires the assertion to be digitally ' +
                          'signed or MACed — an unsigned assertion is a ' +
                          'request to issue a token for anybody who asks.' };
  }
  if (stsCrypto.JWS_SIGNING_ALGS.indexOf(alg) < 0) {
    log.debug("Leaving verify().");
    return { ok: false, errorCode: 'STS-OAUTH-0041', error: GRANT_ERROR,
             description: 'this assertion is signed "' + alg + '" and this ' +
                          'service verifies ' +
                          stsCrypto.JWS_SIGNING_ALGS.join(', ') + '.' };
  }

  const iss = String((unverified && unverified.iss) || '');
  if (!iss) {
    log.debug("Leaving verify().");
    return { ok: false, errorCode: 'STS-OAUTH-0042', error: GRANT_ERROR,
             description: 'RFC 7523 section 3 claim 1: an assertion must ' +
                          'carry an `iss` naming the party that issued it.' };
  }

  // --- Which keys could have signed it -------------------------------------
  const party = issuerEntry(iss);
  const candidates = [];
  let issuerProblem = '';
  let issuerProblemCode = 'STS-OAUTH-0046';
  if (party) {
    const read = keysForParty(party.fields, party.kind);
    read.keys.forEach(function (one) { candidates.push(one); });
    if (read.jwksUriOnly) {
      issuerProblemCode = 'STS-OAUTH-0044';
      issuerProblem = 'the application registered for this issuer has a ' +
                      'jwks_uri and no jwks. This service will NOT fetch a ' +
                      'URL somebody registered in order to verify a ' +
                      'credential — that is a server-side request forgery ' +
                      'with a specification citation attached. Register the ' +
                      'keys by value, as `jwks`, or have this service issue ' +
                      'a key pair from /admin/pki.';
    } else if (read.problems.length) {
      issuerProblemCode = 'STS-OAUTH-0045';
      issuerProblem = read.problems.join('; ') + '.';
    }
  }
  // The `x5c` path is tried whatever the registry says, because a certificate
  // this service ISSUED is evidence in its own right — that is the point of
  // holding a certificate authority — and a party may present one without
  // having had a JWKS written onto its entry.
  const fromChain = await keyFromChain(header);
  if (fromChain && fromChain.error && !candidates.length) {
    log.debug('Leaving verify(). The x5c does not chain here.');
    return { ok: false, errorCode: fromChain.errorCode, error: GRANT_ERROR,
             description: fromChain.error };
  }
  if (fromChain && fromChain.key) {
    candidates.push({ kid: header.kid ? String(header.kid) : '',
                      key: fromChain.key, source: 'x5c',
                      // WHO THE CERTIFICATE SAYS IT IS FOR, carried on the
                      // candidate rather than on the request, because the
                      // check below is about the key that actually verified
                      // the signature — several may have been tried.
                      subjectKind: fromChain.subjectKind,
                      subjectName: fromChain.subjectName,
                      thumbprint: fromChain.thumbprint });
  }

  if (!party && requiresRegisteredIssuer() && !(fromChain && fromChain.key)) {
    // THE ONE REFUSAL THAT IS NOT ABOUT THE DOCUMENT. See the header: there is
    // no permissive answer available here, so the sentence explains the
    // position rather than merely reporting a lookup that failed.
    log.warn('assertion_grant: an assertion grant was presented for iss="' +
             iss + '", which no application in this realm has declared. ' +
             'Refused.');
    log.debug('Leaving verify(). Nobody has declared that issuer.');
    return { ok: false, errorCode: 'STS-OAUTH-0043', error: GRANT_ERROR,
             description: 'nothing in this realm is registered to issue ' +
                          'assertions as "' + iss + '" — no application ' +
                          'declares it and nobody in ou=users holds a ' +
                          'signing key pair under it. This is the one grant ' +
                          'here that cannot be permissive: an assertion IS ' +
                          'the whole authorization, so accepting one from ' +
                          'anybody would mean anybody who can reach this ' +
                          'port getting an access token as anybody. Declare ' +
                          'the issuer on an application entry as ' +
                          '`oauthAssertionIssuer`, and give it a `jwks` or a ' +
                          'key pair issued from /admin/pki — or, for a ' +
                          'person asserting about THEMSELVES, issue that ' +
                          'person a key pair from the same page, which ' +
                          'writes `stsAssertionJwks` onto their entry. ' +
                          '`oauth2.jwtBearerRequireRegisteredIssuer` turns ' +
                          'this refusal off, and reading what it says before ' +
                          'doing so is the point of it having a description.' };
  }
  if (!candidates.length) {
    log.debug('Leaving verify(). No key to try.');
    return { ok: false,
             errorCode: issuerProblem ? issuerProblemCode : 'STS-OAUTH-0046',
             error: GRANT_ERROR,
             description: issuerProblem ||
                          ('there is no key registered against "' + iss + '" ' +
                           'to verify this assertion with. Put a JWKS on the ' +
                           'application entry as `jwks`, or issue a signing ' +
                           'key pair from /admin/pki — to the application, ' +
                           'or to the person, depending on which of the two ' +
                           '"' + iss +
                           '" names.') };
  }

  // --- The signature -------------------------------------------------------
  // The kid narrows the set when the assertion names one; otherwise every
  // candidate is tried. Trying them all is correct rather than lax — a
  // signature either verifies under a key or it does not, and a party that
  // rotated without updating its kid is a party whose assertion is genuine.
  const narrowed = header.kid
    ? candidates.filter(function (one) {
      return one.kid === String(header.kid);
    })
    : candidates;
  const attempts = narrowed.length ? narrowed : candidates;
  let claims = null;
  let usedKey = null;
  let lastError = '';
  for (let i = 0; i < attempts.length && !claims; i++) {
    try {
      claims = await stsCrypto.verifyJwsAsync(jws, attempts[i].key, {
        algorithms: [alg],
        // `aud` and `iss` are checked by the library so that a library that
        // knows the rules applies them: RFC 7521 section 5.2 (5) allows `aud`
        // to be an array and a single expected value must match ANY member.
        audience: audiences,
        issuer: iss,
        clockTolerance: skewSeconds()
      });
      usedKey = attempts[i];
    } catch (e) {
      lastError = e.message;
    }
  }
  if (!claims) {
    log.debug('Leaving verify(). It did not verify.');
    return { ok: false, errorCode: 'STS-OAUTH-0047', error: GRANT_ERROR,
             description: 'the assertion did not verify: ' + lastError +
                          '. It must be signed by a key registered for "' +
                          iss +
                          '", name one of ' + audiences.join(' or ') +
                          ' as `aud`, and be unexpired.' };
  }

  // --- The registered key's CHAIN, now that it has been USED ---------------
  // (2026-09-13.) A key out of the party's JWKS that carries an `x5c` is
  // believed only while the WHOLE chain of that certificate holds: the
  // certificate must hold this key, every link must verify and be in date,
  // every issuer must be a CA permitted to sign, and the path must end in this
  // realm or at the self-signed root registered with it. Until this date the
  // chain was checked when it was registered and never again, so an expired
  // certificate, an expired intermediate or a replaced Root went on verifying
  // assertions. `pki.verifySignerChain()` argues the three anchors. A key from
  // the assertion's own `x5c` was path-checked by `keyFromChain()` on the way
  // in, and a bare key has no certificate to chain.
  let keyChain = null;
  const usedX5c = usedKey && usedKey.source !== 'x5c' && usedKey.jwk &&
                  Array.isArray(usedKey.jwk.x5c) ? usedKey.jwk.x5c : [];
  if (usedX5c.length) {
    keyChain = await pki.verifySignerChain(undefined, {
      certificate: usedX5c[0], chain: usedX5c.slice(1), key: usedKey.jwk,
      source: 'the key "' + (usedKey.kid || '(no kid)') + '" in ' +
              usedKey.source + ' for "' + iss + '"'
    });
    if (!keyChain.ok) {
      log.warn('assertion_grant: the registered key that verified an ' +
               'assertion from "' + iss + '" has a chain that does not ' +
               'hold: ' + keyChain.why);
      log.debug('Leaving verify(). The registered key\'s chain is refused.');
      return { ok: false,
               errorCode: errorCodes.codeOf(keyChain) || 'STS-PKI-0157',
               error: GRANT_ERROR,
               description: 'the certificate of the key registered for "' +
                            iss + '" that verified this assertion does not ' +
                            'have a valid trust chain: ' + keyChain.why };
    }
  }

  // --- The registered key's certificate, now that it has been USED ---------
  // A key out of the party's JWKS carries its certificate in `x5c` when it has
  // one; that certificate is checked for revocation exactly as a presented one
  // is, before any claim is believed and before the jti is spent. A key from
  // the assertion's own `x5c` was checked by `keyFromChain()` already, and a
  // bare key has nothing to check — the verdict says so rather than `good`.
  // ASYNCHRONOUS, because this whole function is: a foreign issuer's OCSP
  // responder or CRL may be dialled.
  let keyRevocation = null;
  if (usedKey && usedKey.source !== 'x5c') {
    keyRevocation = await revocationStatus.registeredKeyVerdictFor(usedKey.jwk,
      'the key "' + (usedKey.kid || '(no kid)') + '" in ' + usedKey.source +
          ' ' +
          'for "' + iss + '"');
    if (keyRevocation.refused) {
      log.warn('assertion_grant: the registered key that verified an ' +
               'assertion from "' + iss +
               '" is refused: ' + keyRevocation.why);
      log.debug('Leaving verify(). The registered key is revoked.');
      return { ok: false, errorCode: 'STS-PKI-0129', error: GRANT_ERROR,
               description: 'the key registered for "' + iss + '" that ' +
                            'verified this assertion may no longer be ' +
                            'used: ' + keyRevocation.why };
    }
  }

  // --- RFC 7523 section 3, claim by claim ----------------------------------
  const sub = String(claims.sub || '');
  if (!sub) {
    log.debug("Leaving verify().");
    return { ok: false, errorCode: 'STS-OAUTH-0048', error: GRANT_ERROR,
             description: 'RFC 7523 section 3 claim 2: an assertion used as ' +
                          'an authorization grant must carry a `sub` naming ' +
                          'the principal the token is for. An assertion with ' +
                          'an `iss` and no `sub` says who is asking and not ' +
                          'who they are asking about.' };
  }
  // -------------------------------------------------------------------------
  // THE ONE CHECK THAT IS ABOUT WHO THE ISSUER IS RATHER THAN WHAT THE
  // DOCUMENT SAYS (2026-09-11): **A PERSON MAY ONLY ASSERT ABOUT
  // THEMSELVES.**
  //
  // An APPLICATION that declares `oauthAssertionIssuer` is an operator saying
  // *this party may speak about people*, which is the whole content of the
  // declaration — so its assertion may name any `sub` and always could. A
  // PERSON's key pair is not that. It is a credential belonging to one person,
  // issued so that they can present themselves, and reading it as an authority
  // over others would mean anybody given a key on /admin/pki can get a token
  // as anybody in the realm. `common/person_assertions.js` argues it at
  // length; this is where it is enforced.
  //
  // **IT IS CHECKED IN TWO PLACES BECAUSE THERE ARE TWO WAYS IN**, and missing
  // the second would have left the refusal decorative: a key found on the
  // person's entry, and a certificate presented in the `x5c` that this service
  // can see it issued TO a person. The second is the one that is easy to
  // forget — the chain path does not go through the registry at all, which is
  // the whole point of it.
  //
  // It is below the signature and above every other claim check for the reason
  // the header gives about ordering: `sub` and `iss` are claims, and a claim is
  // worth nothing until something has vouched for it.
  // -------------------------------------------------------------------------
  const personName = (party && party.kind === 'person')
    ? party.person.username
    : ((usedKey && usedKey.source === 'x5c' && usedKey.subjectKind === 'person')
        ? usedKey.subjectName : '');
  // **THE CERTIFICATE'S OWN WORD IS ENOUGH, AND THE FALLBACK IS THE POINT OF
  // THIS LINE.** A leaf naming a person who has since been deleted from the
  // directory would otherwise find no record, and a check that is skipped when
  // the lookup fails is a check that is skipped exactly when somebody has
  // tidied the entry away. What this service issued the certificate to is a
  // fact about the certificate, so the name in it stands on its own.
  const signedByPerson = personName
    ? (personAssertions.recordFor(personName) ||
       { username: personName, effectiveIssuers: [personName] })
    : null;
  if (signedByPerson && !personAssertions.subjectIsSelf(signedByPerson, sub)) {
    log.warn('assertion_grant: "' + iss + '" is a person in this realm and ' +
             'the assertion they signed names "' + sub + '" as its subject. ' +
             'Refused: a person\'s signing key says who THEY are and is not ' +
             'an authority over anybody else.');
    log.debug('Leaving verify(). A person asserted about somebody else.');
    return { ok: false, errorCode: 'STS-OAUTH-0049', error: GRANT_ERROR,
             description: '"' + iss + '" is a PERSON in this realm, and a ' +
                          'person\'s assertion may only be about themselves ' +
                          '— this one names ' +
                          '"' + sub + '" as its `sub`. RFC ' +
                          '7523 section 3 claim 2 says the subject of an ' +
                          'authorization grant "typically identifies an ' +
                          'authorized accessor or resource owner", and a key ' +
                          'issued to one resource owner is that person\'s ' +
                          'credential rather than permission to speak for ' +
                          'the others. A party that may assert about other ' +
                          'people is an APPLICATION with the issuer declared ' +
                          'on it as `oauthAssertionIssuer` — which is a ' +
                          'thing an operator did, and is exactly the ' +
                          'difference.' };
  }
  if (claims.exp === undefined || claims.exp === null) {
    log.debug("Leaving verify().");
    // The library only checks an `exp` that is present. Section 3 claim 4
    // makes it REQUIRED, and an assertion with no expiry is a bearer
    // credential that never stops working.
    return { ok: false, errorCode: 'STS-OAUTH-0050', error: GRANT_ERROR,
             description: 'RFC 7523 section 3 claim 4: an assertion must ' +
                          'carry an `exp`. One without it never expires, ' +
                          'which makes it a credential anybody who captures ' +
                          'it can use for ever.' };
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (claims.iat !== undefined &&
      Number(claims.iat) > nowSeconds + skewSeconds()) {
    log.debug("Leaving verify().");
    // RFC 7523 section 3 claim 6 is OPTIONAL and says nothing about the
    // future. Refused anyway: an assertion issued in the future is a clock
    // that is wrong somewhere, and saying so is more useful than accepting it
    // and having the `exp` be wrong by the same amount.
    return { ok: false, errorCode: 'STS-OAUTH-0051', error: GRANT_ERROR,
             description: 'this assertion says it was issued at ' +
                          new Date(Number(claims.iat) * 1000).toISOString() +
                          ', which is in the future. One of the two clocks ' +
                          'involved is wrong, and this service allows ' +
                          skewSeconds() + ' seconds of difference ' +
                          '(oauth2.clientAssertionSkewS).' };
  }
  const cap = maxLifetimeSeconds();
  // MEASURED FROM `iat`, OR FROM NOW WHERE THERE IS NONE (2026-09-12, every
  // mode). This read `cap && claims.iat !== undefined && …`, so an assertion
  // that simply left out the OPTIONAL claim was not checked against the
  // ceiling at all — a day-long assertion was one omitted field away from
  // being accepted. `iat` is still honoured where it is present, and a future
  // one was refused above, so `from` is never meaningfully later than now.
  const hasIat = claims.iat !== undefined && claims.iat !== null;
  const from = hasIat ? Number(claims.iat) : nowSeconds;
  if (cap && Number(claims.exp) - from > cap) {
    log.debug("Leaving verify().");
    // RFC 7521 section 5.2 (6) invites an authorization server to reject an
    // assertion whose lifetime is unreasonable, and leaves "unreasonable" to
    // it. A short life is the whole difference between an assertion and a
    // long-lived credential somebody has to be able to revoke.
    return { ok: false, errorCode: 'STS-OAUTH-0052', error: GRANT_ERROR,
             description: 'this assertion is valid for ' +
                          (Number(claims.exp) - from) + ' seconds' +
                          (hasIat ? '' : ' from now (it carries no `iat`, so ' +
                                         'its lifetime is measured from when ' +
                                         'it arrived)') +
                          ' and this authorization server accepts at ' +
                          'most ' + cap + ' (oauth2.jwtBearerMaxLifetimeS). ' +
                          'RFC 7521 section 5.2 leaves the ceiling to the ' +
                          'server; an assertion is meant to be spent within ' +
                          'seconds of being minted.' };
  }
  if (!claims.jti) {
    log.debug("Leaving verify().");
    return { ok: false, errorCode: 'STS-OAUTH-0053', error: GRANT_ERROR,
             description: 'RFC 7523 section 3 claim 7 makes `jti` optional ' +
                          'and this authorization server requires one, which ' +
                          'is that section\'s last paragraph read literally: ' +
                          'it says a server MAY refuse a reused assertion, ' +
                          'and an assertion with no `jti` cannot be ' +
                          'remembered — so accepting one means accepting a ' +
                          'credential this service has no way to spend.' };
  }
  // Remembered until it EXPIRES rather than for a fixed window, so the history
  // and the `exp` check cover exactly the same span with no gap in which a
  // replay would be accepted because the row had been swept early. It is the
  // LAST refusal of the document itself — nothing below this line refuses — so
  // an assertion refused for any other reason is not also used up.
  const spent = await usedAssertions.claim({
    format: 'jwt', use: 'authorization-grant',
    issuer: iss, identifier: String(claims.jti),
    // The client making the token request, where it named itself. Recorded on
    // the row for the console; it is not part of what the history is keyed by.
    clientId: String(options.requestingClientId || ''), subject: sub,
    expiresAt: (Number(claims.exp) * 1000) + skewSeconds() * 1000,
    request: options.request
  });
  if (!spent.ok && spent.reason === 'replay') {
    log.warn('assertion_grant: "' + iss + '" replayed the assertion jti ' +
             claims.jti + '. A signed assertion is a credential until it ' +
             'expires, so a second use of one is refused.');
    log.debug('Leaving verify(). The jti was replayed.');
    return { ok: false, errorCode: 'STS-OAUTH-0054', error: GRANT_ERROR,
             description: 'this assertion has been used already' +
                          usedAssertions.usedAs(spent.existing) + '. Its ' +
                          '`jti` is remembered until the assertion expires, ' +
                          'because a signed assertion captured off the wire ' +
                          'is a credential until then. Mint a fresh one per ' +
                          'request.' };
  }
  if (!spent.ok && spent.reason === 'full') {
    log.warn('assertion_grant: the used-assertion history for this realm is ' +
             'full of unexpired rows (oauth2.assertionReplayCacheSize ' +
             '= ' + spent.cap + '), ' +
             'so a new grant from ' +
             '"' + iss + '" is REFUSED rather than a live ' +
             'one being forgotten.');
    log.debug('Leaving verify(). The replay cache is full.');
    return { ok: false, errorCode: 'STS-OAUTH-0055', error: GRANT_ERROR,
             description: 'this authorization server is holding as many ' +
                          'unexpired assertions as it is configured to ' +
                          'remember (oauth2.assertionReplayCacheSize), and ' +
                          'it will not forget one that could still be ' +
                          'replayed in order to accept yours. Retry shortly.' };
  }
  if (!spent.ok) {
    log.debug('Leaving verify(). The history could not be asked.');
    return { ok: false, errorCode: 'STS-OAUTH-0243', error: GRANT_ERROR,
             description: 'this assertion verified, and this authorization ' +
                          'server could not record that it has been used, ' +
                          'so it is refused rather than accepted ' +
                          'unrecorded. Retry with a fresh assertion.' };
  }

  // --- RFC 7521 section 4.1: the requested scope ---------------------------
  // **NARROWED AND NEVER WIDENED.** An assertion that names a `scope` is the
  // issuer saying what this grant is for; a request that asks for more than
  // that is asking the assertion to authorize something it did not. Where the
  // assertion names none, the request decides — which is section 4.1's own
  // reading: `scope` is a request parameter and the assertion claim is an
  // optional constraint on it.
  const assertedScope = String(claims.scope || '').split(/\s+/)
    .filter(Boolean);
  const requestedScope = String(options.scope || '').split(/\s+/)
    .filter(Boolean);
  let scope = requestedScope;
  let scopeNarrowed = [];
  if (assertedScope.length) {
    if (!requestedScope.length) {
      scope = assertedScope;
    } else {
      scopeNarrowed = requestedScope.filter(function (one) {
        return assertedScope.indexOf(one) < 0;
      });
      scope = requestedScope.filter(function (one) {
        return assertedScope.indexOf(one) >= 0;
      });
      if (scopeNarrowed.length) {
        log.warn('assertion_grant: "' + iss + '" presented an assertion ' +
                 'scoped "' + assertedScope.join(' ') + '" and the request ' +
                 'asked for "' + requestedScope.join(' ') + '". The values ' +
                 'the assertion does not carry were dropped: ' +
                 scopeNarrowed.join(' ') + '.');
      }
    }
  }

  // --- RFC 7521 section 6.3: a confirmation ---------------------------------
  // Carried and REPORTED and never enforced, which is the same position this
  // service takes on OIDC Core 5.5's `essential`: a `cnf` in an assertion is
  // the issuer saying the presenter should hold a key, and enforcing it means
  // demanding a proof this grant has no parameter to carry. It is put on the
  // result so that `/admin/delegation` can say it was there.
  const confirmation = claims.cnf && typeof claims.cnf === 'object'
    ? claims.cnf : null;
  if (confirmation) {
    log.warn('assertion_grant: the assertion from "' + iss + '" carries a ' +
             '`cnf` (RFC 7521 section 6.3). It is recorded and NOT enforced: ' +
             'this grant has no parameter in which a presenter could prove ' +
             'possession of the named key, so demanding one would refuse ' +
             'every conforming client.');
  }

  log.info('assertion_grant: an RFC 7523 section 2.1 assertion from "' + iss +
           '" for "' + sub + '" verified. alg=' + alg +
           (unwrapped.encrypted
             ? ', encrypted ' + unwrapped.encryption.alg + '/' +
               unwrapped.encryption.enc
             : '') +
           ', key from ' + (usedKey ? usedKey.source : 'unknown') +
           ', jti=' + claims.jti + '.');
  log.debug('Leaving verify(). Verified.');
  return {
    ok: true,
    issuer: iss,
    subject: sub,
    // Which application declared the issuer, where one did. Null for an
    // assertion accepted on its `x5c` alone, which is a legitimate state and
    // is reported as one rather than being turned into a lookup failure.
    application: (party && party.kind !== 'person') ? party.identifier : '',
    // WHICH KIND OF PARTY SIGNED IT, and the person's own name where one did.
    // `/admin/delegation` draws the intermediary of this act out of these, and
    // an assertion a person made about themselves drawn as an APPLICATION
    // speaking about a third party would be the register saying the opposite
    // of what happened.
    issuerKind: signedByPerson ? 'person'
                              : (party ? 'application'
                                       : (usedKey && usedKey.source === 'x5c'
                                           ? (usedKey.subjectKind || '')
                                           : '')),
    person: signedByPerson ? signedByPerson.username : '',
    declared: !!(party && party.declared),
    alg: alg,
    jti: String(claims.jti),
    scope: scope,
    scopeNarrowed: scopeNarrowed,
    audience: claims.aud,
    encrypted: !!unwrapped.encrypted,
    encryption: unwrapped.encryption || null,
    keySource: usedKey ? usedKey.source : '',
    // What the revocation check said about that key: null for a key out of the
    // assertion's own x5c (checked on the way in), `bare` for a JWK with no
    // certificate, and otherwise the verdict's status and policy.
    keyRevocation: keyRevocation
      ? { status: keyRevocation.status, bare: !!keyRevocation.bare,
          policy: keyRevocation.policy || '', why: keyRevocation.why }
      : null,
    // What the chain check said about that key's certificate: null where there
    // was no registered certificate to check (an `x5c` header, path-checked on
    // the way in, or a bare key), and otherwise the anchor it was validated to.
    keyChain: keyChain
      ? { anchor: keyChain.anchor, path: keyChain.path || [] }
      : null,
    confirmation: confirmation,
    expiresAt: Number(claims.exp) * 1000,
    // RFC 7523 section 3 claim 8: an assertion MAY carry other claims. They
    // are handed back WHOLE and it is the caller's business what to do with
    // them — `oauth2.js` puts the ones that are not protocol claims onto the
    // token, which is the only thing this grant can usefully do with a
    // statement a trusted party made about somebody.
    claims: claims
  };
}

// The claims this grant will not copy onto an issued token. Every one of them
// is either the assertion's own protocol furniture or something the token
// endpoint decides for itself — an `exp` copied off an assertion would produce
// a token that expires when the assertion did, which is a token lifetime set
// by whoever signed the assertion.
const PROTOCOL_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti',
                         'scope', 'cnf', 'typ', 'azp', 'client_id'];

function extraClaimsFrom(claims) {
  log.debug('Entering extraClaimsFrom().');
  const out = {};
  Object.keys(claims || {}).forEach(function (name) {
    if (PROTOCOL_CLAIMS.indexOf(name) < 0) {
      out[name] = claims[name];
    }
  });
  log.debug('Leaving extraClaimsFrom(). ' + Object.keys(out).length + ' ' +
      'claim(s).');
  return out;
}

module.exports = {
  GRANT_TYPE: GRANT_TYPE,
  PROTOCOL_CLAIMS: PROTOCOL_CLAIMS,
  enabled: enabled,
  requiresRegisteredIssuer: requiresRegisteredIssuer,
  maxLifetimeSeconds: maxLifetimeSeconds,
  // For client_auth.js, which takes both from here rather than keeping a
  // second copy of either. See the header on why the require runs this way.
  keysFrom: keysFrom,
  // For `software_statement.js` and `request_object.js` (2026-09-13), which
  // verify a statement or a request object from a party against the SAME keys
  // an assertion from it is verified against — a second reader of `oauthJwks`
  // and `oauthAssertionJwks` would be a second answer to "which of this party's
  // keys may sign".
  keysForParty: keysForParty,
  unwrapAssertion: unwrapAssertion,
  // The certificate-chain path, for section 2.2 as well. A client that was
  // issued a key pair from /admin/pki can present its certificate in the `x5c`
  // header instead of having a JWKS written onto its entry, and both halves of
  // RFC 7523 accept it on exactly the same terms: only after this service has
  // checked that it issued it.
  keyFromChain: keyFromChain,
  verify: verify,
  extraClaimsFrom: extraClaimsFrom,
  // For the pages that report how many assertions are being remembered: the
  // realm's used-assertion history, which this grant shares with client
  // authentication and with RFC 7522.
  assertionsRemembered: function () {
    log.debug("Entering assertionsRemembered().");
    log.debug("Leaving assertionsRemembered().");
    return usedAssertions.summary().live;
  }
};
