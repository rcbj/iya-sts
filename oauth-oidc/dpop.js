// File: dpop.js
//
// ---------------------------------------------------------------------------
// The server's half of DPoP — RFC 9449, OAuth 2.0 Demonstrating Proof of
// Possession. This module is the checker; oauth2.js binds the tokens it issues
// and vc_issuer.js's protected endpoints demand a proof for them.
//
// Requiring this module registers nothing. It is a library, unlike the protocol
// modules beside it — there is no `app.get` here — so its position in
// server.js's require order does not matter. It requires helpers.js and nothing
// else, so it cannot be part of a cycle.
//
// What it is defending against. A Bearer access token (RFC 6750) is a password:
// anything that can read it can spend it, so a token leaked from a log, a
// proxy, a crash dump or an open redirect is a working credential until it
// expires. A DPoP-bound token carries `cnf.jkt`, the RFC 7638 thumbprint of a
// public key, and every request presenting it must also carry a fresh signature
// from the matching private key over that request's method and URI. The stolen
// bytes are then worthless without the key.
//
// RFC 9449 section 4.3 lists twelve checks a receiver MUST make. They are
// implemented here in that order and each is labelled with its number, because
// the ones that are easiest to leave out are the ones that quietly convert this
// from a proof of possession into a decoration:
//
//   * omit the SIGNATURE check (6) and any client can claim any key.
//   * omit `htm`/`htu` (8, 9) and one captured proof works at every endpoint —
//     including the token endpoint proof being replayed at the credential
//     endpoint.
//   * omit `ath` (12) and a proof captured with one token can be presented
//     with another, which is exactly the theft this is supposed to stop.
//   * omit the `cnf.jkt` comparison (12) and the token is not bound to
//     anything: the client simply presents its own key and is believed.
//   * omit `typ` (4) and some other JWT the client signed with the same key —
//     an OID4VCI credential proof of possession, say, which this very workflow
//     also signs — is accepted as a DPoP proof.
//
// Which is why tests/sts_dpop.js removes each of those checks in turn and
// requires that the suite notices.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('../common/realms');
// jsonwebtoken and the STS key arrived with presentedAccessToken() below: it
// verifies an access token this service issued before believing its cnf. Still
// a leaf — jsonwebtoken is an npm package and helpers.js is this module's only
// project dependency, so the no-cycle property is unchanged. One signer and one
// verifier for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');
const helpers = require('../common/helpers');
// The registry of error codes: a leaf. A refusal is MARKED on the response and
// named on the refusal object this module hands back; neither is serialised.
const errorCodes = require('../common/error_codes');
// RFC 8705 — the other sender constraint. A library like this one: it registers
// nothing and requires only helpers.js and config.js, so requiring it here
// cannot create a cycle. It is required HERE rather than at the four protected
// endpoints because presentedAccessToken() below is the single check they
// share.
const mtls = require('./mtls');
// For one decision: whether to REFUSE an access token in a query string rather
// than merely ignore it (RFC 9700 section 4.3.2). A library that registers no
// route and requires only helpers.js, config.js and client_auth.js, so
// requiring it here cannot create a cycle.
const bcp = require('./oauth2_bcp');
// For one value: `oauth2.clockSkewS`, the allowance applied to `exp` and `nbf`
// wherever this service reads back a token it signed. config.js requires
// NOTHING from this repository — it is the module helpers.js itself sits on top
// of — so this is still a leaf and the no-cycle property above is unchanged.
// It is read here rather than passed in because presentedAccessToken() is the
// single check the four protected endpoints share: a skew applied at three of
// them and not the fourth is a token that is alive at UserInfo and dead at the
// credential endpoint, which reads as a wallet bug from both sides.
const config = require('../common/config');
const log = helpers.log;
const b64u = helpers.b64u;
const jsonFromB64u = helpers.jsonFromB64u;
const nowSec = helpers.nowSec;
const randomId = helpers.randomId;
const STS = helpers.STS;
const vciError = helpers.vciError;
// The one decision about whether a forwarded header is believable, shared with
// baseUrlOf() so that two functions in this service cannot answer it two ways.
const forwardedFrom = helpers.forwardedFrom;

const PROOF_TYP = 'dpop+jwt';

// The algorithms this server will check a proof with. RFC 9449 check 5: a
// registered ASYMMETRIC signature algorithm, never `none` and never a MAC. The
// list is deliberately explicit rather than "whatever the JWT library accepts":
// an allow-list is the only thing that stops an `alg` the client chose from
// selecting a verification path the server did not intend.
// THE ALGORITHMS COME FROM `common/crypto.js` AND ARE NOT LISTED AGAIN HERE.
//
// This file used to carry its own nine-row table — the node hash name, key
// type, curve, PSS salt length and `dsaEncoding` for each — beside its own
// `crypto.verify()` call. It was a second implementation of "verify a compact
// JWS with a key somebody handed us", and the cost was not the duplicated
// lines: it was that DPoP silently accepted a DIFFERENT SET of algorithms from
// everything else in this service, so a client whose key was Ed25519 or
// secp256k1 could register it, sign an ID Token request with it, and then find
// its DPoP proof refused with no explanation that named the real reason.
//
// RFC 9449 section 4.2 requires an ASYMMETRIC algorithm — never a MAC, whose
// key both parties would have to know, and never `none` — which is exactly
// what `JWS_ASYMMETRIC_ALGS` is.
//
// NOT THE POST-QUANTUM ONES, and this exclusion is a SPECIFICATION limit
// rather than anything this service cannot do. DPoP binds a token to a key
// through `cnf.jkt`, which is the RFC 7638 JWK Thumbprint — and RFC 7638
// defines the required members for `RSA`, `EC`, `OKP` and `oct` and for
// nothing else. An ML-DSA or SLH-DSA key is `kty: "AKP"` (RFC 9964), for which
// no thumbprint is registered, so a proof signed with one would verify
// perfectly and bind to nothing. The debugger's own dpop.js excludes them for
// the same reason and says so in the same words.
const SIGNING_ALGS = stsCrypto.JWS_ASYMMETRIC_ALGS.filter(function (alg) {
  return stsCrypto.JWS_ALGS[alg].family !== 'pq';
});

// RFC 9449 section 11.1: the acceptable window for a proof's `iat`. Short,
// because the window is how long a captured proof stays useful for the same
// method and URI; the nonce mechanism below is what shortens it further when a
// deployment cares.
//
// A SETTING SINCE 2026-09-12 (`oauth2.dpopIatSkewS`), read per use for the
// rule `common/CLAUDE.md` gives: a runtime setting captured in a module-level
// const is the one thing a runtime override cannot reach. The export below
// keeps its old name and is now the DEFAULT, for any reader that wanted the
// number; `iatSkewSeconds()` is the live value.
const IAT_SKEW_SECONDS = 300;

function iatSkewSeconds() {
  log.debug("Entering iatSkewSeconds().");
  const seconds = Number(config.value('oauth2.dpopIatSkewS'));
  log.debug("Leaving iatSkewSeconds().");
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) :
         IAT_SKEW_SECONDS;
}

// Replay detection (section 11.1). A `jti` seen once is refused thereafter. In
// a real deployment this is a shared cache with an eviction policy; here it is
// a Map of jti -> the second it was seen, pruned on use, which is all a mock
// needs and is honest about being bounded by the same window as `iat`. PER
// TRUST REALM. `realms.map()` is a Map that holds a separate one for each realm
// and hands out the ambient realm's — so every reader below is unchanged and
// every one of them is now realm-correct. In the default realm, and in a
// service with no realms defined, there is exactly one partition and this
// behaves as the plain Map it replaced. See common/realms.js.
const seenJtis = realms.map({ persist: 'dpop.seenJtis' });

// Server-supplied nonces (sections 8 and 9). OFF by default: the mechanism is a
// second round trip on the first request of every session, so a deployment opts
// in. `requireNonces()` is read per request rather than captured at require
// time, so a test can turn it on and off without restarting the service.
// SHARED AND PERSISTED, NOT A MODULE VARIABLE (2026-09-08). It was
// `let nonceMode = false`, which is exactly as much state as it looks like and
// one process's worth of it. `POST /oauth2/dpop-nonce-mode` is the only thing
// that writes it, that path FANS OUT (it carries no session), and the request
// that arms nonce mode therefore armed ONE request worker — after which the
// server demanded a nonce from a third of the callers and accepted anything
// from the rest. `sts_dpop.js` reported it exactly: a nonce the server never
// issued was accepted 200, because the worker answering had never been told
// nonces were required at all.
//
// ~~`sharedMap` and not `realms.obj()`, which is per realm: this switch has
// been service-wide since it was written … and making it per-realm here would
// be a behaviour change smuggled in with a replication fix.~~
//
// **IT IS A SETTING NOW, PER REALM, AND THE PARAGRAPH ABOVE IS WHY IT WAS
// DONE AS ITS OWN CHANGE (2026-09-12).** A switch that one realm flips for
// every realm is a trust-realm leak in the same family as the stores
// `common/CLAUDE.md` lists: a test at /realm/acme/dpop/nonce-mode turned
// nonces on for the default realm's clients, which had asked for nothing. So
// the state is `oauth2.dpopNonceRequired` — a `config.js` row, which is per
// realm by construction (the override lands on the ambient realm), replicated
// to every request worker by the same change log a setting already rides, and
// reachable through /admin/oauth2 and POST /admin-api/config/set behind a
// credential. That last property is the one product mode needed: the
// endpoint that used to be the ONLY way to set it is an unauthenticated test
// control, and in product it refuses.
//
// The replication property the 2026-09-08 fix bought is kept rather than
// traded: a setting written through one worker is read by the others exactly
// as the shared map's row was.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const issuedNonces = realms.map({ persist: 'dpop.issuedNonces' });
// The default of `oauth2.dpopNonceTtlS`, kept under its old name for the same
// reason IAT_SKEW_SECONDS is.
const NONCE_TTL_SECONDS = 300;

function nonceTtlSeconds() {
  log.debug("Entering nonceTtlSeconds().");
  const seconds = Number(config.value('oauth2.dpopNonceTtlS'));
  log.debug("Leaving nonceTtlSeconds().");
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) :
         NONCE_TTL_SECONDS;
}

// WRITES THE SETTING, IN THE REALM IT IS CALLED IN. Returns what is now in
// force, or throws with the setting's own refusal — which cannot happen for a
// boolean on a runtime row, and is surfaced rather than swallowed because a
// switch that silently did not switch is the invisible failure the endpoint's
// own comment warns about.
//
// **TURNING IT BACK TO WHAT IT WOULD BE ANYWAY CLEARS THE OVERRIDE rather than
// writing one**, which is tests/CLAUDE.md's "restore with reset" rule applied
// inside the control: a test that turns nonces on and then off would otherwise
// leave the row reading `source: override` with the default's value, and the
// management API's own job asserts that a row nobody meant to override does not
// say that — so the failure would land on a different file.
function setNonceMode(on) {
  log.debug('Entering setNonceMode(). on=' + on);
  const wanted = on === true;
  config.clearOverride('oauth2.dpopNonceRequired');
  if (config.value('oauth2.dpopNonceRequired') !== wanted) {
    const written = config.setOverride('oauth2.dpopNonceRequired', wanted);
    if (written && written.ok === false) {
      log.debug('Leaving setNonceMode(). The setting refused the value.');
      throw new Error((written.errors || []).join(' '));
    }
  }
  log.debug('Leaving setNonceMode(). DPoP nonces are ' +
            (nonceModeOn() ? 'REQUIRED' : 'not required'));
  return nonceModeOn();
}

function nonceModeOn() {
  log.debug("Entering nonceModeOn().");
  log.debug("Leaving nonceModeOn().");
  return config.value('oauth2.dpopNonceRequired') === true;
}

function issueNonce() {
  log.debug('Entering issueNonce().');
  pruneNonces();
  const nonce = randomId(16);
  issuedNonces.set(nonce, nowSec());
  log.debug('Leaving issueNonce().');
  return nonce;
}

function pruneNonces() {
  log.debug("Entering pruneNonces().");
  const cutoff = nowSec() - nonceTtlSeconds();
  issuedNonces.forEach(function (issued, nonce) {
    if (issued < cutoff) issuedNonces.delete(nonce);
  });
  log.debug("Leaving pruneNonces().");
}

function nonceIsCurrent(nonce) {
  log.debug('Entering nonceIsCurrent().');
  pruneNonces();
  const ok = !!nonce && issuedNonces.has(String(nonce));
  log.debug('Leaving nonceIsCurrent(). ok=' + ok);
  return ok;
}

// ---------------------------------------------------------------------------
// The JWK Thumbprint, RFC 7638 — the value that becomes `cnf.jkt`.
//
// Built member by member in the specification's own order rather than by
// sorting the key's members, so a key carrying a `kid` or Web Crypto's
// `key_ops`/`ext` hashes to the same value as the same key without them. That
// is not tidiness: the wallet sends its key in every proof header, and if a
// stray member changed the digest the token would stop matching its own key.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE RFC 7638 MEMBER TABLE AND THE CANONICAL JSON MOVED TO `common/crypto.js`
// ON 2026-08-27, and the paragraph above is why they had to move rather than be
// tidied: there were THREE copies of this computation in the service, and the
// other two derived a `kid` with JSON.stringify over an object literal whose
// keys happened to be in lexicographic order. All three agreed. RFC 7638 exists
// so that two implementations agree, and three that agree by coincidence are
// two bugs waiting for somebody to add a member out of order.
//
// **THE `jkt` IS NEVER TRUNCATED AND THAT IS NOT A STYLE CHOICE.** The other
// two callers shorten theirs, because a `kid` only has to be unique within a
// JWKS and a short one is readable in a log. This one is compared BYTE FOR BYTE
// against a value the client computed from the same key, so a truncation here
// would be a binding that accepts a prefix collision.
// ---------------------------------------------------------------------------
function thumbprint(jwk) {
  log.debug('Entering thumbprint().');
  const jkt = stsCrypto.jwkThumbprint(jwk);
  log.debug('Leaving thumbprint(). jkt=' + jkt);
  return jkt;
}

// `ath`, RFC 9449 section 4.2: base64url(SHA-256(ASCII(access token))).
function athOf(accessToken) {
  log.debug("Entering athOf().");
  log.debug("Leaving athOf().");
  return b64u(crypto.createHash('sha256')
                    .update(String(accessToken), 'ascii')
                    .digest());
}

// ---------------------------------------------------------------------------
// `htu` — the request's own target URI, without query or fragment, normalized
// the way section 4.3 asks (RFC 3986 syntax- and scheme-based normalization).
//
// Behind a proxy this has to be the URI the CLIENT used, not the one the socket
// saw: with the api or a CORS proxy in front of this service, `req.protocol`
// and `req.get('host')` describe the last hop and every proof would be refused
// for naming the real endpoint.
//
// **THE FORWARDED HEADERS ARE HONOURED ONLY WHERE A PROXY IS TRUSTED**, and
// that is a change — this function used to believe them unconditionally, while
// `baseUrlOf()` in helpers.js ignored them, so two functions in one service
// disagreed about whether a forwarded header was believable. They share
// `forwardedFrom()` now and one setting decides.
//
// It is the htu check that makes the setting matter rather than the metadata.
// `htu` binds a proof to the endpoint it was made for, which is what stops a
// proof captured at one endpoint being replayed at another — and if a CLIENT
// can set the expected value with a header, it can name the endpoint it stole
// the proof from and the binding stops meaning anything. So with
// `global.trustProxy` off, what the socket saw is what a proof must name; the
// refusal in check 9 says so, and names the setting, because a proof refused
// for a reason nobody can see is an afternoon.
// ---------------------------------------------------------------------------
function htuOf(req) {
  log.debug('Entering htuOf().');
  const from = forwardedFrom(req);
  const proto = String(from.proto || 'http').toLowerCase();
  const host = String(from.host || '').trim().toLowerCase();
  // req.originalUrl carries the query; the path alone is what belongs here.
  const path = String(req.originalUrl || req.url || '/').split('?')[0].split(
      '#')[0];
  let hostname = host;
  let port = '';
  const colon = host.lastIndexOf(':');
  if (colon > -1 && host.indexOf(']') < colon) {
    hostname = host.slice(0, colon);
    port = host.slice(colon + 1);
  }
  if ((proto === 'https' && port === '443') || (proto === 'http' &&
                                                port === '80')) port = '';
  const htu = proto + '://' + hostname + (port ? ':' + port : '') + path;
  log.debug('Leaving htuOf(). htu=' + htu);
  return htu;
}

function normalizeHtu(value) {
  log.debug('Entering normalizeHtu(). value=' + value);
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch (e) {
    log.debug("Caught in normalizeHtu(): " + ((e && e.message) || e));
    // Unparseable, so it cannot match anything. Returned as-is so the caller's
    // comparison fails and says what arrived, rather than throwing.
    log.debug('Leaving normalizeHtu(). Not a URL.');
    return String(value || '');
  }
  const scheme = parsed.protocol.toLowerCase();
  let port = parsed.port;
  if ((scheme === 'https:' && port === '443') || (scheme === 'http:' &&
                                                  port === '80')) port = '';
  const out = scheme + '//' + parsed.hostname.toLowerCase() +
              (port ? ':' + port : '') +
              parsed.pathname;
  log.debug('Leaving normalizeHtu(). out=' + out);
  return out;
}

// ---------------------------------------------------------------------------
// The twelve checks.
//
// Returns { ok: true, jkt, jwk, claims } or { ok: false, error, description,
// needNonce }. It never sends a response: the caller decides the status code
// and the header shape, because an authorization server says `use_dpop_nonce`
// in a 400 JSON body while a resource server says it in a 401 WWW-Authenticate,
// and this module has no business knowing which of the two it is serving.
// ---------------------------------------------------------------------------
function verifyProof(rawHeader, opts) {
  log.debug('Entering verifyProof(). htm=' + (opts && opts.htm) + ', htu=' +
            (opts && opts.htu));
  const options = opts || {};
  // `code` names the condition for the caller that sends the response; it is
  // never serialised into one.
  const fail = function (code, description, extra) {
    log.debug("Entering fail().");
    log.debug('Leaving verifyProof(). REFUSED: ' + description);
    return Object.assign({ ok: false, errorCode: code,
                           error: 'invalid_dpop_proof',
                           description: description },
                         extra || {});
  };

  // Check 1: not more than one DPoP header field. Express joins repeated header
  // fields with ", " — and a compact JWS contains no comma — so a comma here
  // means two headers arrived, and accepting either of them would let an
  // attacker append their own proof to a captured request.
  if (rawHeader === undefined || rawHeader === null ||
      String(rawHeader).trim() === '') {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0093', 'No DPoP proof was presented.',
                { missing: true });
  }
  const raw = String(rawHeader).trim();
  if (raw.indexOf(',') >= 0) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0094', 'More than one DPoP header field was sent; ' +
                                  'RFC 9449 permits exactly one.');
  }

  // Check 2: a single well-formed JWT.
  const parts = raw.split('.');
  if (parts.length !== 3) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0095', 'The DPoP proof is not a compact JWS with ' +
                                  'three parts.');
  }
  let header;
  let claims;
  try {
    header = jsonFromB64u(parts[0]);
    claims = jsonFromB64u(parts[1]);
  } catch (e) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0096',
                'The DPoP proof could not be decoded: ' + e.message);
  }
  if (!header || typeof header !== 'object' || !claims ||
      typeof claims !== 'object') {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0097', 'The DPoP proof header or payload is not a ' +
                                  'JSON object.');
  }

  // Check 4: typ. Before the signature, because it costs nothing and it is the
  // check that stops a JWT signed for another purpose being accepted here.
  if (header.typ !== PROOF_TYP) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0098',
                'The DPoP proof must have typ "' + PROOF_TYP + '"; ' +
        'this one has ' +
                JSON.stringify(header.typ) + '. Without this check some ' +
                'other JWT the client signed with the same key would be ' +
                'accepted as a proof.');
  }

  // Check 5: a supported asymmetric algorithm, not none and not a MAC. The
  // table is common/crypto.js's, so this list and what the verifier below will
  // actually accept cannot drift apart.
  const spec = SIGNING_ALGS.indexOf(header.alg) === -1 ? null
    : stsCrypto.JWS_ALGS[header.alg];
  if (!spec) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0099',
                'The DPoP proof is signed with ' + JSON.stringify(header.alg) +
                ', which this server does not accept. RFC 9449 requires a ' +
                'registered asymmetric algorithm, never none and never a ' +
                'MAC: ' + SIGNING_ALGS.join(', ') + '.');
  }

  // Check 7: the jwk header must carry a public key and no private key. Checked
  // before the signature, because importing a key object that carries private
  // material would let a client hand over a whole key pair and be believed.
  const jwk = header.jwk;
  if (!jwk || typeof jwk !== 'object' || !jwk.kty) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0100', 'The DPoP proof header must carry the ' +
                                  'public key as a jwk.');
  }
  const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].filter(
      function (m) {
    return jwk[m] !== undefined;
  });
  if (privateMembers.length) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0101', 'The DPoP proof header carries private key ' +
                                  'material (' +
                privateMembers.join(', ') + '), which RFC 9449 forbids.');
  }
  if (jwk.kty !== spec.kty || (spec.crv && jwk.crv !== spec.crv)) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0102',
                'The DPoP proof header key (' + jwk.kty +
                (jwk.crv ? '/' + jwk.crv : '') +
                ') does not match its alg ' + header.alg + '.');
  }

  // Check 3: all required claims. Named individually so the client is told
  // which.
  const required = ['jti', 'htm', 'htu', 'iat'];
  const absent = required.filter(function (c) {
    return claims[c] === undefined || claims[c] === null || claims[c] === '';
  });
  if (absent.length) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0103',
                'The DPoP proof is missing ' + absent.join(', ') + '.');
  }

  // Check 6: the signature verifies with the key in the header.
  //
  // Delegated to the one verifier in common/crypto.js. The algorithm list is
  // passed EXPLICITLY — RFC 8725 section 3.1, and doubly so here, because the
  // key being verified against is the one the token itself supplied: a
  // verifier that also took the algorithm from the token would be letting the
  // proof choose both halves.
  try {
    stsCrypto.verifyCompactJws(raw, jwk, { algorithms: SIGNING_ALGS });
  } catch (e) {
    // Everything it throws is a sentence about this proof — a malformed
    // signature, a wrong length, a key that will not load, or a signature that
    // simply does not verify. A malformed one makes node throw rather than
    // return false, and this is what keeps that from becoming a 500.
    log.debug('the DPoP proof did not verify: ' + e.message);
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0104', 'The DPoP proof signature does not verify ' +
                'with the key in its own header: ' + e.message);
  }

  // Check 8: htm matches this request's method.
  if (String(claims.htm).toUpperCase() !== String(
      options.htm || '').toUpperCase()) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0105',
                'The DPoP proof was made for HTTP ' + claims.htm + ', ' +
        'but this is a ' +
                options.htm + ' request.');
  }

  // Check 9: htu matches this request's URI, ignoring query and fragment.
  const presented = normalizeHtu(claims.htu);
  const expected = normalizeHtu(options.htu);
  if (presented !== expected) {
    log.debug("Leaving verifyProof().");
    // The commonest cause of this on a deployment that works everywhere else is
    // a reverse proxy: the client made the request to the proxy's URL, the
    // socket here saw the last hop's, and the two differ in scheme, host or
    // both. So the setting is named rather than left to be discovered — a proof
    // refused for a reason nobody can see is an afternoon, and this refusal
    // would otherwise read as the client's bug.
    return fail('STS-OAUTH-0106',
                'The DPoP proof was made for ' + claims.htu + ', ' +
        'but this request went to ' +
                options.htu + '.' +
                (helpers.trustProxy()
                  ? ''
                  : ' If something is terminating TLS in front of this ' +
                    'service, that is why: global.trustProxy is OFF, so ' +
                    'X-Forwarded-Proto and X-Forwarded-Host are ignored and ' +
                    'this server describes the LAST HOP rather than the URL ' +
                    'the client used. Turn it on where a proxy really is in ' +
                    'front — and leave it off where one is not, because ' +
                    'those are headers any client can set, and a client that ' +
                    'chooses its own htu has unbound its own proof.'));
  }

  // Check 11: iat within an acceptable window.
  const age = nowSec() - Number(claims.iat);
  const window = iatSkewSeconds();
  if (!isFinite(age) || Math.abs(age) > window) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0107',
                'The DPoP proof iat is ' + (isFinite(age) ? age + ' ' +
        'seconds away' : 'not ' +
        'a number') +
                '; this server accepts ' + window + ' seconds either way ' +
                '(oauth2.dpopIatSkewS).');
  }

  // Check 10: the nonce, when this server is asking for one. The order matters:
  // a missing nonce is not a refusal but a REQUEST, answered with a fresh nonce
  // for the client to retry with, so it is reported separately from a wrong
  // one.
  if (nonceModeOn()) {
    if (claims.nonce === undefined) {
      log.debug("Leaving verifyProof().");
      return fail('STS-OAUTH-0108', 'This server requires a DPoP nonce.',
                  { needNonce: true });
    }
    if (!nonceIsCurrent(claims.nonce)) {
      log.debug("Leaving verifyProof().");
      return fail('STS-OAUTH-0109', 'The DPoP proof nonce is not one this ' +
                                    'server issued, or it has expired.',
                  { needNonce: true });
    }
  }

  // Section 11.1: replay. A proof is good for one request.
  pruneJtis();
  if (seenJtis.has(String(claims.jti))) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0110',
                'This DPoP proof has already been used (jti ' + claims.jti +
                '). ' +
                'A proof is good for one request.');
  }

  // Check 12, first half: ath, when an access token came with the proof.
  const jkt = thumbprint(jwk);
  if (options.accessToken) {
    if (claims.ath === undefined) {
      log.debug("Leaving verifyProof().");
      return fail('STS-OAUTH-0111', 'The DPoP proof must carry ath when it ' +
                  'accompanies an access token; without it a proof captured ' +
                  'with one token could be presented with another.');
    }
    if (claims.ath !== athOf(options.accessToken)) {
      log.debug("Leaving verifyProof().");
      return fail('STS-OAUTH-0112', 'The DPoP proof ath does not match the ' +
                                    'access token presented with it.');
    }
  }

  // Check 12, second half: the token's own binding. This is the comparison that
  // makes the token sender-constrained — without it the client simply presents
  // whichever key it likes and is believed.
  if (options.expectedJkt && options.expectedJkt !== jkt) {
    log.debug("Leaving verifyProof().");
    return fail('STS-OAUTH-0113', 'The access token is bound to a different ' +
                'key than the one that signed this DPoP proof ' +
                '(cnf.jkt ' + options.expectedJkt + ', proof key ' + jkt +
                ').');
  }

  seenJtis.set(String(claims.jti), nowSec());
  log.debug('Leaving verifyProof(). Accepted. jkt=' + jkt);
  return { ok: true, jkt: jkt, jwk: jwk, claims: claims, header: header };
}

function pruneJtis() {
  log.debug("Entering pruneJtis().");
  const cutoff = nowSec() - (iatSkewSeconds() * 2);
  seenJtis.forEach(function (seen, jti) {
    if (seen < cutoff) seenJtis.delete(jti);
  });
  log.debug("Leaving pruneJtis().");
}

// The confirmation a token carries, if any. RFC 9449 section 6.1 puts it in
// `cnf.jkt`; a token without one is a Bearer token and must be presented as
// one.
function jktOf(claims) {
  log.debug("Entering jktOf().");
  log.debug("Leaving jktOf().");
  return (claims && claims.cnf && typeof claims.cnf.jkt === 'string') ?
          claims.cnf.jkt : '';
}

// For tests and for /admin/sts-metadata: what this server will accept.
function state() {
  log.debug("Entering state().");
  log.debug("Leaving state().");
  return {
    signing_alg_values_supported: SIGNING_ALGS,
    nonces_required: nonceModeOn(),
    iat_skew_seconds: iatSkewSeconds(),
    nonce_ttl_seconds: nonceTtlSeconds(),
    proofs_remembered: seenJtis.size,
    nonces_outstanding: issuedNonces.size
  };
}

// Only for tests that need a clean slate: the replay cache is per realm (it
// said process-wide here long after it stopped being), so a test asserting "a
// fresh proof is accepted" after asserting "a replayed one is refused" needs a
// way to forget.
function forgetProofs() {
  log.debug('Entering forgetProofs(). ' + seenJtis.size + ' remembered ' +
      'proof(s) discarded.');
  seenJtis.clear();
  log.debug('Leaving forgetProofs().');
}

// ---------------------------------------------------------------------------
// The access token on a protected endpoint — Bearer (RFC 6750) or DPoP (RFC
// 9449 section 7).
//
// Three of this service's protected endpoints — Credential, Deferred Credential
// and Notification — used to carry their own copy of a Bearer-only check. They
// share this one, because a per-endpoint copy is how one of three ends up not
// demanding the proof, and the endpoint that forgot is the one an attacker
// would use.
//
// **It lives here rather than in vc_issuer.js, where it was written, because
// there are now four.** /oauth2/userinfo is the fourth, and it is in oauth2.js
// — a module vc_issuer.js cannot be required from without either building a
// cycle or moving OID4VCI ahead of OAuth2 in the route order. Copying the check
// into the OAuth2 module instead is precisely the mistake the paragraph above
// records having already been made once. dpop.js registers no routes and
// requires only helpers.js, so it is the one place both callers can reach.
//
// It answers the request itself on failure and returns null, so a caller reads:
//
//   const presented = dpop.presentedAccessToken(req, res, 'the credential endpoint');
//   if (!presented) return;
//
// What it will and will not vouch for. OID4VCI lets the authorization server be
// somebody else (this suite points the metadata at Keycloak), so a token this
// issuer cannot verify is still accepted — that is stated at the top of
// vc_issuer.js and has not changed. The consequence for DPoP is worth being
// explicit about: `cnf.jkt` is read from a token whose signature may be
// unverifiable here, so for a foreign token the binding is checked between the
// proof and a claim anyone could have written. When the token IS one of ours
// the signature is checked first and the binding is real. A production resource
// server has no such excuse and must verify the token before trusting its cnf.
//
// `verified` in the returned object is how a caller that CANNOT live with that
// tells the difference: the userinfo endpoint refuses a token it did not issue,
// because a profile is a statement about somebody this server authenticated,
// and there is nothing it can honestly say about the subject of a signature it
// cannot check.
// ---------------------------------------------------------------------------
// The audiences a token issued here carries, as this service's own resource
// server. `<base>/resource` is what accessToken() mints when nothing narrows
// it; anything else on the token came from an RFC 8707 `resource` parameter and
// names a resource server that is not this one.
//
// The path ENDS WITH `/resource` rather than equalling it, because this process
// publishes several authorization servers and a named one issues for
// `<base>/{id}/resource` — its own resource server, under its own name. Testing
// for equality refused every token any named authorization server had ever
// issued, at every protected endpoint, with a message about audience
// restriction that was true and completely misleading.
//
// What it still refuses is what it was written for: an audience from a
// `resource` parameter, which names somebody else's server and does not end
// there.
function isOwnResourceAudience(value) {
  log.debug('Entering isOwnResourceAudience().');
  const text = String(value || '');
  if (!text) {
    log.debug('Leaving isOwnResourceAudience().');
    return false;
  }
  try {
    const path = new URL(text).pathname;
    log.debug('Leaving isOwnResourceAudience().');
    return path === '/resource' || path.endsWith('/resource');
  } catch (e) {
    log.debug("Caught in isOwnResourceAudience(): " + ((e && e.message) || e));
    // Not a URL. RFC 8707 requires an absolute URI, and the default audience is
    // one — so an audience that does not parse was not minted by this service's
    // own default and is not this resource server.
    log.debug('Leaving isOwnResourceAudience().');
    return false;
  }
  log.debug('Leaving isOwnResourceAudience().');
}

function audienceRefusal(claims, verified) {
  log.debug("Entering audienceRefusal().");
  if (!verified || !claims || claims.aud === undefined) {
    log.debug("Leaving audienceRefusal(). Not ours, or it names no audience.");
    return null;
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audiences.some(isOwnResourceAudience)) {
    log.debug("Leaving audienceRefusal(). This token is for this resource " +
              "server.");
    return null;
  }
  log.debug("Leaving audienceRefusal(). It names " + audiences.join(', ') +
            ".");
  return {
    errorCode: 'STS-OAUTH-0114',
    error: 'invalid_token',
    description: 'RFC 9700 section 2.3: an access token is ' +
                 'audience-restricted and a resource server must refuse one ' +
                 'issued for a different audience. This token names ' +
                 audiences.map(function (one) { return '"' + one + '"'; })
                          .join(', ') +
                 ', and the endpoints here are the resource server this ' +
                 'service issues for. A token narrowed with the RFC 8707 ' +
                 '`resource` parameter is usable at THAT resource server and ' +
                 'nowhere else, which is the whole of what the restriction ' +
                 'buys.'
  };
}

function presentedAccessToken(req, res, where) {
  log.debug("Entering presentedAccessToken(). where=" + where);
  // RFC 9700 section 4.3.2 — an access token MUST NOT travel in a URI query
  // parameter. RFC 6750 section 2.3 defines a form that does, and this service
  // has never read it: the token comes from the Authorization header and
  // nowhere else, so one in the query has always been simply ignored.
  //
  // IGNORED IS NOT THE SAME AS REFUSED, and the difference is what this adds.
  // A client that sends `?access_token=...` gets a 401 saying a token is
  // required — which is true, unhelpful, and sends somebody looking at their
  // credential rather than at where they put it. In RFC 9700 mode the query is
  // looked at ONLY to say so, and the refusal names the reason: a URL goes into
  // browser history, into the address bar, into server logs and into the
  // Referer of anything the page then fetches, and a token in one is a token in
  // all of those.
  //
  // The token itself is never echoed back. It has already been somewhere it
  // should not be; putting it in a response body would be one more place.
  const inQuery = req.query && (req.query.access_token !== undefined ||
                                req.query.token !== undefined);
  if (inQuery && bcp.enabled()) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_request"');
    log.warn('RFC 9700 section 4.3.2: a request to ' + (where || 'a ' +
        'protected endpoint') +
             ' carried an access token in the QUERY STRING. Refused. That ' +
             'URL is now in this client\'s browser history and in whatever ' +
             'logged the request.');
    log.debug("Leaving presentedAccessToken(). A token was in the query " +
              "string.");
    errorCodes.mark(res, 'STS-OAUTH-0115');
    vciError(res, 400, 'invalid_request',
      'RFC 9700 section 4.3.2: an access token must not be sent in a URI ' +
      'query parameter. RFC 6750 section 2.3 defines that form and its own ' +
      'specification does not recommend it, because a URL ends up in browser ' +
      'history, in the address bar, in server logs and in the Referer header ' +
      'of anything the page goes on to fetch — so the token is in all of ' +
      'those too. This endpoint reads the Authorization header only, and ' +
      'treat the token you just sent as disclosed.');
    log.debug("Leaving presentedAccessToken().");
    return null;
  }
  const auth = String(req.headers['authorization'] || '');
  const match = /^(Bearer|DPoP)\s+(\S+)\s*$/i.exec(auth);
  if (!match) {
    // Both schemes are offered in the challenge, since either is acceptable
    // here; RFC 9449 section 7.1 requires DPoP to appear when the server
    // supports it, or a client has no way to discover that it may use it.
    res.set('WWW-Authenticate', 'DPoP algs="' + SIGNING_ALGS.join(' ') + '", ' +
        'Bearer');
    log.debug("Leaving presentedAccessToken(). No access token.");
    errorCodes.mark(res, 'STS-OAUTH-0116');
    vciError(res, 401, 'invalid_token',
      'An access token is required, presented as "Bearer <token>" or, when ' +
      'it is DPoP-bound, as "DPoP <token>" with a DPoP proof.');
    log.debug("Leaving presentedAccessToken().");
    return null;
  }
  const scheme = match[1].toLowerCase();
  const accessToken = match[2];

  // What the token says about its own binding. Verified where possible: an
  // unverified token could have a cnf its holder wrote.
  let claims = null;
  let verified = false;
  try {
    claims = stsCrypto.verifyJws(accessToken, STS.certPem);
    verified = true;
  } catch (e) {
    log.debug("This access token is not one of ours, so its claims are read " +
              "unverified: " +
              e.message);
    try {
      claims = jsonFromB64u(String(accessToken).split('.')[1]) || {};
    } catch (e2) {
      // Not a JWT at all. Opaque tokens are legal, and this issuer accepts them
      // as it always has — there is simply no binding to find in one.
      log.debug("...and it is not a JWT either, so there is no cnf to read: " +
                e2.message);
      claims = {};
    }
  }
  const boundTo = jktOf(claims);

  // RFC 8705 section 3.1 — the OTHER sender constraint, checked here for the
  // same reason the DPoP one is: this function is the single check the four
  // protected endpoints share, and a second one beside it would be a fourth
  // caller nobody updated. It refuses nothing on a token that carries no
  // certificate confirmation, so a Bearer or DPoP request is untouched.
  const certificateProblem = mtls.checkBinding(claims, req, verified);
  if (certificateProblem) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
    log.debug("Leaving presentedAccessToken(). The certificate binding did " +
              "not hold.");
    errorCodes.mark(res, certificateProblem.errorCode || 'STS-OAUTH-0092');
    vciError(res, 401, certificateProblem.error,
             certificateProblem.description);
    log.debug("Leaving presentedAccessToken().");
    return null;
  }

  // RFC 9700 section 2.3 — an access token is audience-restricted, and a
  // resource server MUST refuse one that names a different audience. Only for a
  // token this service ISSUED, which is the same judgement made about cnf
  // above: the `aud` of a token signed by somebody else is a string this
  // service cannot check and was never the audience of anyway.
  //
  // What counts as "this resource server" is deliberately the PATH and not the
  // whole URL. Every token issued here carries `<base>/resource`, and the base
  // is whatever URL the request that minted it arrived on — so a token minted
  // at localhost:8081 and presented at 127.0.0.1:8081 would fail a whole-URL
  // comparison while being, in every sense that matters, a token for this
  // service. What the check is FOR is a token narrowed to somebody else by an
  // RFC 8707 `resource` parameter, and that always has a different path.
  const audienceProblem = audienceRefusal(claims, verified);
  if (audienceProblem) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
    log.debug("Leaving presentedAccessToken(). The audience is somebody " +
              "else's.");
    errorCodes.mark(res, audienceProblem.errorCode || 'STS-OAUTH-0114');
    vciError(res, 401, audienceProblem.error, audienceProblem.description);
    log.debug("Leaving presentedAccessToken().");
    return null;
  }

  // A bound token presented as Bearer is a protocol error even though the bytes
  // are the same. Accepting it would throw the binding away silently, which is
  // the single most likely way to implement DPoP and gain nothing.
  if (boundTo && scheme !== 'dpop') {
    res.set('WWW-Authenticate', 'DPoP error="invalid_token", ' +
                                'error_description="the token is DPoP-bound ' +
                                'and must be presented with the DPoP scheme"');
    log.debug("Leaving presentedAccessToken(). A bound token was presented " +
              "as Bearer.");
    errorCodes.mark(res, 'STS-OAUTH-0117');
    vciError(res, 401, 'invalid_token',
      'This access token is DPoP-bound (it carries cnf.jkt), so it must be ' +
      'presented as "Authorization: DPoP <token>" with a DPoP proof — not as ' +
      'a Bearer token.');
    log.debug("Leaving presentedAccessToken().");
    return null;
  }

  // No binding and no proof: a plain Bearer request, exactly as before.
  if (!boundTo && req.headers['dpop'] === undefined) {
    log.debug("Leaving presentedAccessToken(). A Bearer request. verified=" +
              verified);
    return { accessToken: accessToken, claims: claims, scheme: scheme, jkt: '',
             verified: verified };
  }

  const checked = verifyProof(req.headers['dpop'], {
    htm: req.method,
    htu: htuOf(req),
    accessToken: accessToken,
    expectedJkt: boundTo
  });
  if (!checked.ok) {
    // RFC 9449 section 9: a RESOURCE server asks for a nonce with a 401 and
    // `use_dpop_nonce` in WWW-Authenticate — not with the 400 JSON body an
    // authorization server uses. Getting this shape wrong leaves a conforming
    // wallet unable to proceed, so the two are deliberately not shared.
    if (checked.needNonce) {
      res.set('DPoP-Nonce', issueNonce());
      res.set('WWW-Authenticate', 'DPoP error="use_dpop_nonce", ' +
                                  'error_description="Resource server ' +
                                  'requires nonce in DPoP proof"');
      log.debug("Leaving presentedAccessToken(). Asking the wallet for a " +
                "DPoP nonce.");
      errorCodes.mark(res, checked.errorCode || 'STS-OAUTH-0108');
      vciError(res, 401, 'use_dpop_nonce', 'Resource server requires nonce ' +
                                           'in DPoP proof');
      log.debug("Leaving presentedAccessToken().");
      return null;
    }
    res.set('WWW-Authenticate', 'DPoP error="invalid_dpop_proof"');
    log.debug("Leaving presentedAccessToken(). The DPoP proof was refused.");
    errorCodes.mark(res, checked.errorCode || 'STS-OAUTH-0118');
    vciError(res, 401, 'invalid_dpop_proof', checked.description);
    log.debug("Leaving presentedAccessToken().");
    return null;
  }
  log.debug("Leaving presentedAccessToken(). A valid DPoP request. jkt=" +
            checked.jkt +
            ", token verified=" + verified);
  return {
    accessToken: accessToken, claims: claims, scheme: scheme, jkt: checked.jkt,
    verified: verified, dpop: checked
  };
}

module.exports = {
  PROOF_TYP: PROOF_TYP,
  SIGNING_ALGS: SIGNING_ALGS,
  IAT_SKEW_SECONDS: IAT_SKEW_SECONDS,
  // Re-exported so that a caller reaching for the canonical form gets the ONE
  // implementation rather than writing a fourth. Nothing in this repository
  // consumes it today; the parent project's DPoP test computes its own on
  // purpose, so that a shared misunderstanding could not make both ends agree
  // and interoperate with nobody.
  canonicalJwk: stsCrypto.canonicalJwk,
  thumbprint: thumbprint,
  athOf: athOf,
  htuOf: htuOf,
  normalizeHtu: normalizeHtu,
  verifyProof: verifyProof,
  jktOf: jktOf,
  setNonceMode: setNonceMode,
  nonceModeOn: nonceModeOn,
  issueNonce: issueNonce,
  nonceIsCurrent: nonceIsCurrent,
  state: state,
  forgetProofs: forgetProofs,
  presentedAccessToken: presentedAccessToken
};
