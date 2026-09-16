'use strict';
//
// File: mtls.js
//
// ===========================================================================
// RFC 8705 — CERTIFICATE-BOUND ACCESS TOKENS, the other half of RFC 9700's
// sender-constraining recommendation.
//
// Section 2.2 of the BCP names two mechanisms and this service had one of them.
// `dpop.js` binds a token to a KEY the client proves possession of per request;
// this binds it to the CLIENT CERTIFICATE the TLS connection was made with. The
// shapes are deliberately parallel and the reason to have both is that they
// fail differently: DPoP needs no PKI and works for a client that cannot hold a
// certificate, and mTLS needs no per-request signature and survives a client
// that cannot do JOSE.
//
// What a client sees:
//
//   token endpoint over mTLS       ->  cnf: { "x5t#S256": <thumbprint> }
//   resource endpoint over mTLS    ->  the presented certificate is thumbprinted
//                                      again and compared
//
// This is RFC 8705 section 3 (the confirmation method) and section 3.1 (the
// check). Section 2 — mutual-TLS CLIENT AUTHENTICATION, where the certificate
// replaces the client_secret — is `client_auth.js`'s `verifyCertificate()`,
// and this sentence said it was not implemented anywhere for three weeks after
// it was. What this file adds for it, since 2026-09-13, is the POLICY half the
// two sections share: `declaredRefusal()` (a client that DECLARED an RFC 8705
// method, or declared `tls_client_certificate_bound_access_tokens`, is held to
// it in every mode) and `refreshBindingApplies()` (section 7.1: a refresh token
// held by a client that authenticated by certificate is bound through that
// authentication, not to one certificate — so rotating the certificate does not
// strand the grant).
//
// ---------------------------------------------------------------------------
// IT ONLY WORKS WHERE THERE IS A CLIENT CERTIFICATE TO SEE, AND THAT IS A
// DEPLOYMENT FACT RATHER THAN A CHECK.
//
// The token endpoint has to be reached over a TLS connection that ASKED for a
// certificate. On this service that means `global.https` — which RFC 9700 mode
// turns on — because the main listener is where `/oauth2/token` lives, and
// `server.js` sets `requestCert: true, rejectUnauthorized: false` on it: asked
// for, never required, which since 2026-09-16 is this service's only
// posture — the 8443 and 9443 listeners are gone, and every client
// certificate arrives on the main port. A client that presents none gets an
// ordinary Bearer or DPoP-bound token and nothing about its behaviour
// changes, which is what keeps this invisible to every caller that does not
// use it.
//
// `rejectUnauthorized: false` is worth being precise about, because it looks
// like a hole and is not: a certificate that did not build a chain to a trusted
// anchor is still THUMBPRINTED and still binds the token. RFC 8705 section 3
// says the binding is to the certificate itself and explicitly permits a
// self-signed one — the proof is that the same key completed the handshake, not
// that a CA vouched for it. Refusing an unverified certificate here would break
// exactly the case the truststore at `/tls/trust` exists to make reachable.
//
// ---------------------------------------------------------------------------
// THE THUMBPRINT IS OF THE DER, AND THAT IS THE WHOLE OF THE INTEROPERABILITY.
//
// RFC 8705 section 3.1: `x5t#S256` is the base64url-encoded SHA-256 of the DER
// encoding of the X.509 certificate. Not of the PEM, not of the public key, not
// hex, and not base64 with padding. Every one of those produces a value that
// looks right in a log and matches nothing, so `thumbprintOf()` is the only
// place it is computed and both ends of the comparison go through it.
//
// ---------------------------------------------------------------------------
// It is a LIBRARY like `dpop.js` (rule 3): it registers no route and requires
// only `helpers.js`, `config.js` and `common/crypto.js` — plus
// `common/tls_client_certificates.js` lazily, in `peerVerified()` — so it
// cannot join a cycle and its position in the require order does not matter.
// `dpop.js` requires it, because `presentedAccessToken()` there is the single
// check every protected endpoint shares and a second one beside it would be
// another caller nobody updated.
// ===========================================================================

const crypto = require('crypto');
// One thumbprint computation for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');
const { log, b64u } = require('../common/helpers');
const config = require('../common/config');

// RFC 8705 section 3.1's confirmation member. Spelt out as a constant because
// the `#` in it is legal in a JSON member name and looks like a mistake every
// time somebody reads it.
const CONFIRMATION_MEMBER = 'x5t#S256';

// ---------------------------------------------------------------------------
// The certificate the TLS connection was made with, or null.
//
// node hands back an EMPTY OBJECT rather than null when no certificate was
// presented — `{}` — so the test is for the raw DER rather than for the object,
// which is the trap this function exists to hold in one place.
// ---------------------------------------------------------------------------
function peerCertificate(req) {
  log.debug("Entering peerCertificate().");
  const socket = req && req.socket;
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    // A plain HTTP connection. Not an error and not worth a log line per
    // request: it is the ordinary case whenever `global.https` is off.
    log.debug("Leaving peerCertificate().");
    return null;
  }
  const cert = socket.getPeerCertificate();
  if (!cert || !cert.raw || !cert.raw.length) {
    log.debug("Leaving peerCertificate().");
    return null;
  }
  log.debug("Leaving peerCertificate().");
  return cert;
}

// ---------------------------------------------------------------------------
// DID THAT CERTIFICATE VERIFY, AND AGAINST WHAT (2026-09-06).
//
// **PRESENTED AND VERIFIED ARE TWO DIFFERENT QUESTIONS AND THIS FILE ANSWERED
// ONLY THE FIRST ONE.** `peerCertificate()` above returns whatever arrived;
// until this function existed, every caller of it treated "a certificate is
// here" as "a certificate was accepted", because on this listener there was no
// third answer available — `server.js` passed no `ca`, so `socket.authorized`
// was false for every certificate ever presented and reading it would have been
// reading a constant.
//
// THAT IS NO LONGER TRUE. The main listener joined the client truststore that
// `POST /tls/trust` fills, so a certificate that chains to an anchor is now
// distinguishable from one that chains to nothing. RFC 8705 binding does not
// care about the difference — it binds to the certificate and section 3
// explicitly permits a self-signed one — but anything that RESOLVES a
// certificate to an identity does: a DN read off an unverified certificate is a
// name the caller chose for itself.
//
// `authorizationError` is node's own reason string
// (`UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, `CERT_HAS_EXPIRED`, …) and it is
// carried out whole rather than mapped, because it is the one string that tells
// somebody debugging a mutual-TLS deployment WHICH of a dozen things went
// wrong.
// ---------------------------------------------------------------------------
function peerVerified(req) {
  log.debug("Entering peerVerified().");
  const socket = req && req.socket;
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    log.debug("Leaving peerVerified(). Not a TLS connection.");
    return { verified: false, presented: false,
             why: 'This is a plain HTTP connection, which cannot carry a ' +
                  'client certificate at all.' };
  }
  if (!peerCertificate(req)) {
    log.debug("Leaving peerVerified(). Nothing presented.");
    return { verified: false, presented: false,
             why: 'No client certificate was presented. This listener asks ' +
                  'for one and never requires it, so the connection is ' +
                  'perfectly ordinary.' };
  }
  // REVOCATION, CONSULTED (2026-09-12). `common/app.js` put the verdict on the
  // request before any route, because a foreign CRL may need a fetch and this
  // function is synchronous. **A REVOKED CERTIFICATE IS NOT VERIFIED**, which
  // is what every validator that checks means by the word — so every caller
  // that resolves a certificate to an identity through here (the remote XACML
  // PEP chain, the XACML user chain and RFC 8705's `tls_client_auth` in
  // `client_auth.js`) refuses it without learning a new question. It is read
  // ONLY for a chain that verified: an unverified one is refused already, and
  // its reason is the more useful one to report. `revocation` is carried out
  // whole so a caller can mark the right code.
  const revocation = req.certificateRevocation || null;
  if (socket.authorized && revocation && revocation.refused) {
    log.debug("Leaving peerVerified(). Verified, and refused on revocation.");
    return {
      verified: false, presented: true, revocation: revocation,
      error: revocation.status === 'revoked' ? 'CERT_REVOKED'
                                             : 'REVOCATION_STATUS_UNKNOWN',
      why: 'The chain built to an anchor in this service\'s client ' +
           'truststore and was REFUSED ON REVOCATION (pki.revocationCheck is ' +
           revocation.policy + '): ' + revocation.why
    };
  }
  // A CHAIN THROUGH THIS SERVICE'S OWN ROOT IS NOT, ON ITS OWN, AN IDENTITY
  // (2026-09-13). The main port trusts that Root for client certificates
  // since the user portal started issuing TLS client certificates, and every
  // key pair this service ever issued chains to it — an application's RFC 7523
  // key pair included. `common/tls_client_certificates.js` is the gate: a
  // certificate this service issued verifies here only when it came from a TLS
  // client Issuing CA, with clientAuth, in THIS request's realm. Required
  // lazily: it reaches the certificate authority, and this module is on the
  // token endpoint's path with three requires and no reason to carry a fourth.
  if (socket.authorized) {
    let gate = null;
    try {
      gate = require('../common/tls_client_certificates').checkSocket(socket);
    } catch (e) {
      // No certificate authority in this process — `npm test`, a process
      // that never started one. Nothing here was issued by it, so there is
      // nothing for the gate to refuse.
      log.debug("Caught in peerVerified(): " + ((e && e.message) || e));
      gate = null;
    }
    if (gate && !gate.ok) {
      log.debug("Leaving peerVerified(). Verified, and not an identity.");
      return {
        verified: false, presented: true, revocation: revocation,
        identity: gate.identity, error: gate.error,
        why: 'The chain built to this service\'s own Root and is NOT ' +
             'accepted as an identity: ' + gate.why + '.'
      };
    }
  }
  if (socket.authorized) {
    log.debug("Leaving peerVerified(). Verified.");
    return { verified: true, presented: true, revocation: revocation,
             why: 'The chain built from what was presented to an anchor in ' +
                  'this service\'s client truststore' +
                  (revocation && revocation.checked
                    ? ', and its revocation was consulted: ' + revocation.why
                    : '. NO REVOCATION WAS CHECKED (pki.revocationCheck is ' +
                      'off) — a revoked certificate verifies here.') };
  }
  const error = socket.authorizationError
    ? String(socket.authorizationError) : '';
  log.debug("Leaving peerVerified(). Not verified: " + error);
  return {
    verified: false, presented: true, error: error,
    why: 'A client certificate was presented and it did NOT verify' +
         (error ? ' (' + error + ')' : '') + '. The commonest cause is that ' +
         'nothing in the truststore issued it — POST the issuing CA to ' +
         '/tls/trust — and the next commonest is a chain sent without its ' +
         'intermediates, which looks identical from the client side. The ' +
         'certificate is still thumbprinted and still binds a token: RFC ' +
         '8705 section 3 binds to the certificate rather than to anybody\'s ' +
         'opinion of it.'
  };
}

// RFC 8705 `x5t#S256`: SHA-256 over the DER, base64url. The same digest
// `tls/tls_server.js` prints as colon-hex and `spiffe/spiffe_ca.js` truncates
// as an authority id — three spellings of one computation, which is why the
// shared function takes a format and the three that each computed it are one.
function thumbprintOf(cert) {
  log.debug("Entering thumbprintOf().");
  if (!cert || !cert.raw) {
    log.debug("Leaving thumbprintOf().");
    return '';
  }
  log.debug("Leaving thumbprintOf().");
  return stsCrypto.certificateThumbprint(cert);
}

// The thumbprint of whatever certificate this request arrived with, or ''. The
// one function anything outside this file should need.
function presentedThumbprint(req) {
  log.debug("Entering presentedThumbprint().");
  log.debug("Leaving presentedThumbprint().");
  return thumbprintOf(peerCertificate(req));
}

// RFC 8705 section 3: the confirmation claim to put on an issued token, or
// undefined when there is nothing to bind to. Returned as the whole `cnf` value
// so the caller does not have to know the member's name — and MERGED with a
// DPoP `jkt` rather than replacing it, because a client that both presented a
// certificate and sent a proof has demonstrated both and a token that recorded
// one of them would be throwing away a check somebody performed.
function confirmationFor(req, existing) {
  log.debug("Entering confirmationFor().");
  const thumbprint = presentedThumbprint(req);
  if (!thumbprint) {
    log.debug("Leaving confirmationFor(). No client certificate on this " +
              "connection.");
    return existing;
  }
  const cnf = Object.assign({}, existing || {});
  cnf[CONFIRMATION_MEMBER] = thumbprint;
  log.info('RFC 8705: this token is bound to the client certificate the ' +
           'connection was made ' +
           'with. ' + CONFIRMATION_MEMBER + '=' + thumbprint +
           (existing && existing.jkt ?
            ', and to the DPoP key ' + existing.jkt + ' ' +
               'as well' : ''));
  log.debug("Leaving confirmationFor(). Bound.");
  return cnf;
}

// What a token says about its own certificate binding, or ''.
function boundThumbprintOf(claims) {
  log.debug("Entering boundThumbprintOf().");
  const cnf = claims && claims.cnf;
  if (!cnf || typeof cnf !== 'object') {
    log.debug("Leaving boundThumbprintOf().");
    return '';
  }
  const value = cnf[CONFIRMATION_MEMBER];
  log.debug("Leaving boundThumbprintOf().");
  return value ? String(value) : '';
}

// ---------------------------------------------------------------------------
// RFC 8705 section 3.1, the RESOURCE server's half: a certificate-bound token
// is only usable on a connection made with that certificate.
//
// Returns null when there is nothing to say and a refusal object otherwise. The
// two failures are told apart because they send a client to different places:
// no certificate at all is usually a client that did not configure one or a
// proxy that terminated TLS, and a DIFFERENT certificate is the case the
// binding exists to catch.
//
// A token this service did not issue is NOT checked, and that is the same
// judgement `presentedAccessToken()` makes about `cnf.jkt`: for a foreign token
// the confirmation claim is something anybody could have written, so enforcing
// it would be theatre performed on an unverified string.
// ---------------------------------------------------------------------------
function checkBinding(claims, req, verified, noun) {
  log.debug("Entering checkBinding().");
  // What to CALL the thing in the refusal. The refresh grant checks a refresh
  // token with this same function, and a message about "this access token" when
  // the client is holding a refresh token sends somebody looking at the wrong
  // credential.
  const what = noun || 'access token';
  const bound = boundThumbprintOf(claims);
  if (!bound) {
    log.debug("Leaving checkBinding(). This token is not certificate-bound.");
    return null;
  }
  if (!verified) {
    log.warn('RFC 8705: this access token carries a ' + CONFIRMATION_MEMBER +
             ' ' +
             'confirmation and was NOT issued by this service, so the ' +
             'binding is a claim anybody could have written and is not ' +
             'enforced. The same is true of cnf.jkt on a foreign token.');
    log.debug("Leaving checkBinding(). A foreign token's binding is not " +
              "enforced.");
    return null;
  }
  const presented = presentedThumbprint(req);
  if (!presented) {
    log.debug("Leaving checkBinding(). Bound, and no certificate on this " +
              "connection.");
    return {
      errorCode: 'STS-OAUTH-0091',
      error: 'invalid_token',
      description: 'RFC 8705 section 3.1: this ' + what + ' is bound to a ' +
                   'client certificate ' +
                   '(cnf["' + CONFIRMATION_MEMBER + '"]), so it may only be ' +
                   'used on a TLS connection made with that certificate. ' +
                   'This request arrived with no client certificate at all — ' +
                   'either none was configured, or something terminated TLS ' +
                   'in front of this service.'
    };
  }
  if (presented !== bound) {
    log.debug("Leaving checkBinding(). Bound to a different certificate.");
    return {
      errorCode: 'STS-OAUTH-0092',
      error: 'invalid_token',
      description: 'RFC 8705 section 3.1: this ' + what + ' is bound to the ' +
                   'client certificate whose SHA-256 thumbprint ' +
                   'is ' + bound + ', and this ' +
                   'connection was made with the one whose thumbprint ' +
                   'is ' + presented + '. A ' +
                   'certificate-bound token is usable only by the holder of ' +
                   'that certificate\'s private key, which is the whole of ' +
                   'what sender-constraining buys.'
    };
  }
  log.debug("Leaving checkBinding(). The certificate matches. thumbprint=" +
            presented);
  return null;
}

// The two RFC 8705 section 2 client authentication methods, spelt once.
const CERTIFICATE_METHODS = ['tls_client_auth', 'self_signed_tls_client_auth'];

// ---------------------------------------------------------------------------
// WHAT A CLIENT DECLARED, HELD TO IN EVERY MODE (2026-09-13).
//
// This service's standing rule is that a refusal waits for RFC 9700 mode, OAuth
// 2.1 mode or product mode, because a refusal that cannot be turned off removes
// a test case. These two are the exception, and they are the exception for one
// reason: the CLIENT asked for them. A client whose entry declares
// `tls_client_auth` has said its certificate is its credential, and a
// development-mode service that issued it tokens without one — which is what
// `observeClientAuthentication()` alone does outside those modes — would be
// telling it that its own mutual-TLS configuration works when it does not.
// Section 3.4 leaves the second to the authorization server's discretion, and
// the discretion is exercised the way the client declared.
//
// Answers null or `{ status, error, errorCode, description }`. It decides; the
// endpoint answers. It reads the observation the endpoint already made, so the
// certificate is verified once per request.
//
//   * a declared certificate method that did not authenticate — 401
//     `invalid_client`, section 2's own answer, carrying the code
//     `client_auth.js` gave the reason (no certificate, a chain that did not
//     verify, a subject that did not match …);
//   * `tls_client_certificate_bound_access_tokens` and no certificate on the
//     connection — 400 `invalid_request`, STS-OAUTH-0487: nothing about the
//     client failed to authenticate, the request simply cannot produce what the
//     client registered for.
// ---------------------------------------------------------------------------
function declaredRefusal(opts) {
  log.debug("Entering declaredRefusal().");
  const o = opts || {};
  const registered = o.registered;
  if (!registered || !registered.known) {
    log.debug("Leaving declaredRefusal(). No entry to have declared anything.");
    return null;
  }
  const method = String(registered.token_endpoint_auth_method || '').trim();
  const observation = o.observation || {};
  if (CERTIFICATE_METHODS.indexOf(method) >= 0 && !observation.authenticated) {
    log.debug("Leaving declaredRefusal(). The declared method did not " +
              "authenticate.");
    return { status: 401, error: 'invalid_client',
             errorCode: observation.errorCode || 'STS-OAUTH-0488',
             description: 'RFC 8705 section 2: this client\'s entry declares ' +
               'token_endpoint_auth_method=' + method + ', so its TLS client ' +
               'certificate is its credential, and it did not authenticate: ' +
               (observation.why || 'nothing was verified.') };
  }
  if (registered.tls_client_certificate_bound_access_tokens === true &&
      !presentedThumbprint(o.request)) {
    log.debug("Leaving declaredRefusal(). Bound tokens declared, no " +
              "certificate.");
    return { status: 400, error: 'invalid_request',
             errorCode: 'STS-OAUTH-0487',
             description: 'RFC 8705 section 3.4: this client registered ' +
               'tls_client_certificate_bound_access_tokens=true, and this ' +
               'request arrived on a connection with no client certificate, ' +
               'so there is nothing to bind a token to. It is refused rather ' +
               'than answered with an unbound token, which the client would ' +
               'present as if it were bound.' };
  }
  log.debug("Leaving declaredRefusal(). Nothing declared was broken.");
  return null;
}

// ---------------------------------------------------------------------------
// RFC 8705 SECTION 7.1: IS A REFRESH TOKEN'S CERTIFICATE BINDING CHECKED FOR
// THIS REQUEST (2026-09-13).
//
// "refresh tokens are indirectly certificate-bound by way of the client ID and
// the associated requirement for (certificate-based) authentication to the AS
// when issued to clients utilizing the tls_client_auth or
// self_signed_tls_client_auth methods." So for a client that AUTHENTICATED BY
// CERTIFICATE on this very request, the refresh token's own `x5t#S256` is not
// compared — which is what lets a client whose certificate expired present its
// new one and get tokens bound to it (section 6.3). Every other client —
// section 4's public client, a secret-authenticated one that happened to
// present a certificate — keeps the check, because for them the certificate is
// the only thing binding the refresh token to its holder.
// ---------------------------------------------------------------------------
//
// **AND ONLY FOR THE REFRESH TOKEN'S OWN CLIENT.** "By way of the client ID"
// is the whole of the indirect binding, and RFC 6749's check that a refresh
// token is redeemed by the client it was issued to is RFC 9700 mode's here —
// so outside that mode a client authenticated by its certificate presenting
// ANOTHER client's certificate-bound refresh token would otherwise be let past
// the one binding that refresh token has. `clientId` is compared with the
// token's `client_id` claim before the check is skipped.
function refreshBindingApplies(observation, claims, clientId) {
  log.debug("Entering refreshBindingApplies().");
  const o = observation || {};
  const byCertificate = !!o.authenticated &&
    CERTIFICATE_METHODS.indexOf(String(o.method || '')) >= 0;
  const ownToken = !!clientId && !!claims &&
    String(claims.client_id || '') === String(clientId);
  log.debug("Leaving refreshBindingApplies(). " +
            !(byCertificate && ownToken));
  return !(byCertificate && ownToken);
}

// Whether this deployment can bind a token at all, for the pages that report
// it. It is a property of the listener rather than of a request: `global.https`
// is what makes `server.js` ask for a client certificate, and without TLS there
// is no certificate to ask for.
function available() {
  log.debug("Entering available().");
  log.debug("Leaving available().");
  return !!config.value('global.https');
}

module.exports = {
  CONFIRMATION_MEMBER: CONFIRMATION_MEMBER,
  peerCertificate: peerCertificate,
  peerVerified: peerVerified,
  thumbprintOf: thumbprintOf,
  presentedThumbprint: presentedThumbprint,
  confirmationFor: confirmationFor,
  boundThumbprintOf: boundThumbprintOf,
  checkBinding: checkBinding,
  CERTIFICATE_METHODS: CERTIFICATE_METHODS,
  declaredRefusal: declaredRefusal,
  refreshBindingApplies: refreshBindingApplies,
  available: available
};
