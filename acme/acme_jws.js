'use strict';
//
// File: acme_jws.js
//
// ---------------------------------------------------------------------------
// WHAT AN ACME REQUEST IS ON THE WIRE, READ STRICTLY (RFC 8555 SECTION 6).
//
// Every POST to an ACME resource is a FLATTENED JWS JSON object (RFC 7515
// section 7.2.2) carrying a protected header with `alg`, `nonce`, `url` and
// exactly one of `jwk` or `kid`. This module is everything about that envelope
// that can be decided without a store: the media type, the three members, the
// strict base64url, the header's shape, the account key's shape, the
// signature, the Replay-Nonce, the External Account Binding (section 7.3.4),
// the payload schemas of each resource, the contact URIs, and RFC 9773's
// certificate identifier.
//
// **A LIBRARY (rule 3).** It registers no route and holds no state, so an
// in-process test can require it and `acme/acme.js` can be the only file that
// knows a request exists. It requires `common/crypto.js` for every signature
// and MAC it checks — the one place this service verifies anything (rule 3r)
// — and never hand-rolls one: `verifyFlattened()` rebuilds the compact form
// and hands it to `verifyCompactJws()` with the one algorithm the header
// named, which is RFC 8725 section 3.1's rule that the verifier and not the
// token chooses.
//
// **EVERY PARSE IS INSIDE A TRY AND ANSWERS A REFUSAL, NEVER A THROW.** A JWS
// is attacker-controlled bytes all the way down — base64 inside JSON inside
// base64 inside JSON — and a parse error that escaped would be a 500 with a
// stack trace where RFC 8555 section 6.7 wants a problem document.
//
// A refusal here is `{ ok: false, type, status, code, detail }`: the ACME
// error type (section 6.7, without its URN prefix), the HTTP status, the STS
// error code the route marks on the response, and a sentence for `detail`.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const net = require('net');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const { log } = require('../common/helpers');
const stsCrypto = require('../common/crypto');
// The secrets every node shares (2026-09-14, #46). A LIBRARY; see nonceSecret().
const clusterSecrets = require('../cluster/cluster_secrets');
const validation = require('../common/validation');

const vz = validation.z;

// The media type RFC 8555 section 6.2 requires of every POST body.
const MEDIA_TYPE = 'application/jose+json';

// What every error type is prefixed with (section 6.7).
const ERROR_PREFIX = 'urn:ietf:params:acme:error:';

// ---------------------------------------------------------------------------
// THE SIGNATURE ALGORITHMS AN ACCOUNT KEY MAY USE.
//
// RFC 8555 section 6.2 requires RS256 and recommends ES256; the rest are the
// asymmetric algorithms `common/crypto.js` verifies whose key type has an RFC
// 7638 thumbprint — which is the condition, because an ACME account IS its
// key's thumbprint (section 7.3.1 finds an existing account by key).
//
// **LEFT OUT, EACH FOR ITS REASON:** `none` and every HMAC (section 6.2 says a
// server MUST NOT accept them outside an External Account Binding); ES256K,
// which no ACME client sends; and the post-quantum algorithms, whose key type
// `AKP` has no RFC 7638 member list — an account key with no thumbprint is an
// account `newAccount` could never find again. A request with any of them is
// answered `badSignatureAlgorithm` with this list in `algorithms`, as the
// section asks.
// ---------------------------------------------------------------------------
const ACCOUNT_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                      'ES256', 'ES384', 'ES512', 'EdDSA'];

// The MACs an External Account Binding may be made with (section 7.3.4 names
// HS256 as the one a CA "MUST" support; the other two are the same
// construction with a longer hash and cost nothing to accept).
const EAB_ALGS = ['HS256', 'HS384', 'HS512'];

// The smallest RSA account key accepted. RFC 8555 names no floor; 2048 is the
// floor every public CA applies and the one the CA/Browser Forum requires of a
// subscriber key, and an account key is a longer-lived credential than one.
const MIN_RSA_BITS = 2048;

// Protected-header members this service refuses rather than ignores. `crit`
// would require understanding an extension it has not been told about (RFC
// 7515 section 4.1.11); `b64` changes what the signature covers (RFC 7797);
// `jku`, `x5u` and `x5c` point at a key somewhere other than `jwk` or `kid`,
// and section 6.2 allows exactly those two.
const REFUSED_HEADER_MEMBERS = ['crit', 'b64', 'jku', 'x5u', 'x5c'];

// Private members a JWK must never carry into a header (RFC 7518 section 6).
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

// The curve each ECDSA algorithm is pinned to (RFC 7518 section 3.4).
const EC_CURVE_FOR = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };

// The revocation reasons a SUBSCRIBER may give (RFC 5280 section 5.3.1 codes).
// RFC 8555 section 7.6 lets a server refuse any; these are the ones that are
// statements a certificate holder can make. `cACompromise` (2) and
// `aACompromise` (10) are about an AUTHORITY's key; `certificateHold` (6) is
// the one reversible reason and nothing here un-holds; 7 is unassigned; and
// `removeFromCRL` (8) exists only inside a delta CRL.
const REVOCATION_REASONS = {
  0: 'unspecified',
  1: 'keyCompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  9: 'privilegeWithdrawn'
};

const B64URL = /^[A-Za-z0-9_-]*$/;

// A value this module reads out of an attacker's document is capped before
// anything else looks at it; the route's own size limit caps the whole body.
const MAX_MEMBER = 1048576;

// ---------------------------------------------------------------------------
// REFUSALS.
// ---------------------------------------------------------------------------
function refusal(type, status, code, detail, extra) {
  log.debug("Entering refusal(). type=" + type + " code=" + code);
  log.debug("Leaving refusal().");
  return Object.assign({ ok: false, type: type, status: status, code: code,
                         detail: String(detail) }, extra || {});
}

// The first issue zod reported, as a sentence.
function zodSentence(error, what) {
  log.debug("Entering zodSentence().");
  const issue = ((error && error.issues) || [])[0];
  if (!issue) {
    log.debug("Leaving zodSentence(). No issue.");
    return 'the ' + what + ' did not validate.';
  }
  const where = (issue.path || []).length ? issue.path.join('.') : what;
  log.debug("Leaving zodSentence().");
  return 'the ' + what + ' member "' + where + '" is not acceptable: ' +
         String(issue.message).slice(0, 200) + '.';
}

// ---------------------------------------------------------------------------
// THE MEDIA TYPE. Parameters are compared away (a `charset` on a JSON type is
// meaningless but harmless); the type itself must be exactly this one.
// ---------------------------------------------------------------------------
function isJoseJson(contentType) {
  log.debug("Entering isJoseJson().");
  const type = String(contentType || '').split(';')[0].trim().toLowerCase();
  log.debug("Leaving isJoseJson(). type=" + type);
  return type === MEDIA_TYPE;
}

// ---------------------------------------------------------------------------
// STRICT BASE64URL (RFC 7515 section 2: no padding, no whitespace, the URL-safe
// alphabet). Canonical as well as well-formed: the decoded bytes must encode
// back to exactly what was sent, so two spellings of one value cannot both be
// accepted — which matters for a nonce, whose spelling is its identity.
// ---------------------------------------------------------------------------
function decodeB64url(text, allowEmpty) {
  log.debug("Entering decodeB64url().");
  const value = String(text == null ? '' : text);
  if (!value.length) {
    log.debug("Leaving decodeB64url(). Empty.");
    return allowEmpty ? Buffer.alloc(0) : null;
  }
  if (!B64URL.test(value) || value.length % 4 === 1) {
    log.debug("Leaving decodeB64url(). Not the alphabet.");
    return null;
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) {
    log.debug("Leaving decodeB64url(). Not canonical.");
    return null;
  }
  log.debug("Leaving decodeB64url().");
  return bytes;
}

function b64u(bytes) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(bytes).toString('base64url');
}

// JSON out of attacker bytes: parsed in a try, walked for polluting keys and
// depth by `common/validation.js`, and required to be an OBJECT.
function readJsonObject(bytes, what) {
  log.debug("Entering readJsonObject(). what=" + what);
  let value = null;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch (e) {
    log.debug("Caught in readJsonObject(): " + ((e && e.message) || e));
    log.debug("Leaving readJsonObject(). Not JSON.");
    return { ok: false, detail: 'the ' + what + ' is not JSON.' };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    log.debug("Leaving readJsonObject(). Not an object.");
    return { ok: false, detail: 'the ' + what + ' is not a JSON object.' };
  }
  const walked = validation.checkDocument(value, what, { maxDepth: 8,
                                                         maxKeys: 1024 });
  if (!walked.ok) {
    log.debug("Leaving readJsonObject(). The document was refused.");
    return { ok: false, detail: String(walked.detail || walked.code) };
  }
  log.debug("Leaving readJsonObject().");
  return { ok: true, value: value };
}

// ---------------------------------------------------------------------------
// THE FLATTENED JWS JSON OBJECT. Exactly three members: RFC 8555 section 6.2
// says the JWS MUST NOT have an unprotected header, and a `signatures` array is
// the general serialization, which the section does not allow either.
// ---------------------------------------------------------------------------
const FLATTENED = vz.strictObject({
  protected: vz.string().min(1).max(MAX_MEMBER),
  payload: vz.string().max(MAX_MEMBER),
  signature: vz.string().min(1).max(MAX_MEMBER)
});

function parseFlattenedObject(value, what) {
  log.debug("Entering parseFlattenedObject(). what=" + what);
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    log.debug("Leaving parseFlattenedObject(). Not an object.");
    return refusal('malformed', 400, 'STS-ACME-0012', 'The ' + what + ' is ' +
                   'not a flattened JWS JSON object (RFC 7515 section 7.2.2).');
  }
  const walked = validation.checkDocument(value, what, { maxDepth: 4,
                                                         maxKeys: 16 });
  if (!walked.ok) {
    log.debug("Leaving parseFlattenedObject(). Refused by the walker.");
    return refusal('malformed', 400, 'STS-ACME-0012', 'The ' + what + ' was ' +
                   'refused: ' + String(walked.detail || walked.code));
  }
  const parsed = FLATTENED.safeParse(value);
  if (!parsed.success) {
    log.debug("Leaving parseFlattenedObject(). Refused by the schema.");
    return refusal('malformed', 400, 'STS-ACME-0012', 'The ' + what + ' must ' +
                   'carry exactly "protected", "payload" and "signature" ' +
                   '(RFC 8555 section 6.2 allows no unprotected header): ' +
                   zodSentence(parsed.error, what));
  }
  const header = decodeB64url(parsed.data.protected, false);
  const payload = decodeB64url(parsed.data.payload, true);
  const signature = decodeB64url(parsed.data.signature, false);
  if (!header || !payload || !signature) {
    log.debug("Leaving parseFlattenedObject(). Not strict base64url.");
    return refusal('malformed', 400, 'STS-ACME-0013', 'A member of the ' +
                   what + ' is not strict base64url: the URL-safe alphabet, ' +
                   'no padding and no whitespace (RFC 7515 section 2).');
  }
  log.debug("Leaving parseFlattenedObject().");
  return { ok: true, protectedB64: parsed.data.protected,
           payloadB64: parsed.data.payload,
           signatureB64: parsed.data.signature,
           headerBytes: header, payloadBytes: payload };
}

// The body of a POST, which arrives as the TEXT the parser in common/app.js
// left on `req.body`.
function parseBody(text) {
  log.debug("Entering parseBody().");
  const read = readJsonObject(Buffer.from(String(text == null ? '' : text),
                                          'utf8'), 'request body');
  if (!read.ok) {
    log.debug("Leaving parseBody(). Unreadable.");
    return refusal('malformed', 400, 'STS-ACME-0012', 'The request body is ' +
                   'not a flattened JWS JSON object: ' + read.detail);
  }
  log.debug("Leaving parseBody().");
  return parseFlattenedObject(read.value, 'request body');
}

// ---------------------------------------------------------------------------
// THE PROTECTED HEADER (section 6.2). `looseObject` because RFC 7515 says an
// unknown member is ignored unless named in `crit` — and `crit` itself is on
// the refused list above, so nothing unknown can be made to matter.
// ---------------------------------------------------------------------------
const HEADER = vz.looseObject({
  alg: vz.string().min(1).max(32),
  nonce: vz.string().min(1).max(256).optional(),
  url: vz.string().min(1).max(2048),
  jwk: vz.looseObject({ kty: vz.string().min(1).max(8) }).optional(),
  kid: vz.string().min(1).max(2048).optional()
});

function parseProtectedHeader(parts) {
  log.debug("Entering parseProtectedHeader().");
  const read = readJsonObject(parts.headerBytes, 'protected header');
  if (!read.ok) {
    log.debug("Leaving parseProtectedHeader(). Unreadable.");
    return refusal('malformed', 400, 'STS-ACME-0014', 'The JWS protected ' +
                   'header is unreadable: ' + read.detail);
  }
  const refused = REFUSED_HEADER_MEMBERS.filter(function (name) {
    return Object.prototype.hasOwnProperty.call(read.value, name);
  });
  if (refused.length) {
    log.debug("Leaving parseProtectedHeader(). A refused member.");
    return refusal('malformed', 400, 'STS-ACME-0014', 'The protected header ' +
                   'carries "' + refused[0] + '". An ACME request names its ' +
                   'key with "jwk" or "kid" and nothing else (RFC 8555 ' +
                   'section 6.2), and this server understands no critical ' +
                   'extension.');
  }
  const parsed = HEADER.safeParse(read.value);
  if (!parsed.success) {
    log.debug("Leaving parseProtectedHeader(). Refused by the schema.");
    return refusal('malformed', 400, 'STS-ACME-0014', 'The JWS protected ' +
                   'header is not acceptable: ' +
                   zodSentence(parsed.error, 'protected header'));
  }
  log.debug("Leaving parseProtectedHeader().");
  return { ok: true, header: parsed.data };
}

function checkAlgorithm(alg) {
  log.debug("Entering checkAlgorithm(). alg=" + alg);
  if (ACCOUNT_ALGS.indexOf(String(alg)) < 0) {
    log.debug("Leaving checkAlgorithm(). Unsupported.");
    return refusal('badSignatureAlgorithm', 400, 'STS-ACME-0015', 'The JWS ' +
                   'is signed with "' + String(alg).slice(0, 32) + '", which ' +
                   'this server does not accept for an account key. It ' +
                   'accepts ' + ACCOUNT_ALGS.join(', ') + '.',
                   { algorithms: ACCOUNT_ALGS.slice() });
  }
  log.debug("Leaving checkAlgorithm().");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// AN ACCOUNT KEY (a `jwk` header). Checked for shape, for private members, for
// agreement with `alg`, and loaded — node refuses an EC point that is not on
// its curve — before its thumbprint is taken. What is kept is the PUBLIC JWK
// rebuilt from the required members only, so nothing a client added to its key
// is ever stored.
// ---------------------------------------------------------------------------
function checkAccountKey(jwk, alg) {
  log.debug("Entering checkAccountKey(). alg=" + alg);
  if (!jwk || typeof jwk !== 'object') {
    log.debug("Leaving checkAccountKey(). No key.");
    return refusal('malformed', 400, 'STS-ACME-0021', 'The "jwk" header is ' +
                   'not a JSON Web Key.');
  }
  const privateMember = PRIVATE_JWK_MEMBERS.filter(function (name) {
    return Object.prototype.hasOwnProperty.call(jwk, name);
  })[0];
  if (privateMember) {
    log.debug("Leaving checkAccountKey(). A private member.");
    return refusal('badPublicKey', 400, 'STS-ACME-0021', 'The "jwk" header ' +
                   'carries the private member "' + privateMember + '". An ' +
                   'account key is sent as its PUBLIC half only.');
  }
  let publicJwk = null;
  const kty = String(jwk.kty || '');
  const stringOk = function (value) {
    return typeof value === 'string' && value.length > 0 &&
           value.length <= 4096 && !!decodeB64url(value, false);
  };
  if (kty === 'RSA' && /^(RS|PS)\d{3}$/.test(alg) && stringOk(jwk.n) &&
      stringOk(jwk.e)) {
    publicJwk = { kty: 'RSA', n: jwk.n, e: jwk.e };
  } else if (kty === 'EC' && EC_CURVE_FOR[alg] &&
             jwk.crv === EC_CURVE_FOR[alg] && stringOk(jwk.x) &&
             stringOk(jwk.y)) {
    publicJwk = { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
  } else if (kty === 'OKP' && alg === 'EdDSA' && jwk.crv === 'Ed25519' &&
             stringOk(jwk.x)) {
    publicJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  }
  if (!publicJwk) {
    log.debug("Leaving checkAccountKey(). The key does not fit the alg.");
    return refusal('badPublicKey', 400, 'STS-ACME-0021', 'The "jwk" header ' +
                   'is not a ' + String(alg).slice(0, 32) + ' public key: an ' +
                   'RS or PS algorithm takes an RSA key, ES256/ES384/ES512 ' +
                   'an ' +
                   'EC key on P-256/P-384/P-521, and EdDSA an Ed25519 key.');
  }
  let key = null;
  try {
    key = nodeCrypto.createPublicKey({ key: publicJwk, format: 'jwk' });
  } catch (e) {
    log.debug("Caught in checkAccountKey(): " + ((e && e.message) || e));
    key = null;
  }
  if (!key) {
    log.debug("Leaving checkAccountKey(). The key does not load.");
    return refusal('badPublicKey', 400, 'STS-ACME-0021', 'The "jwk" header ' +
                   'does not describe a usable public key.');
  }
  if (kty === 'RSA') {
    const bits = Number((key.asymmetricKeyDetails || {}).modulusLength || 0);
    if (bits < MIN_RSA_BITS) {
      log.debug("Leaving checkAccountKey(). RSA too small.");
      return refusal('badPublicKey', 400, 'STS-ACME-0021', 'The RSA account ' +
                     'key is ' + bits + ' bits; this server requires at ' +
                     'least ' + MIN_RSA_BITS + '.');
    }
  }
  let thumbprint = '';
  try {
    thumbprint = stsCrypto.jwkThumbprint(publicJwk);
  } catch (e) {
    log.debug("Caught in checkAccountKey(): " + ((e && e.message) || e));
    thumbprint = '';
  }
  if (!thumbprint) {
    log.debug("Leaving checkAccountKey(). No thumbprint.");
    return refusal('badPublicKey', 400, 'STS-ACME-0021', 'No RFC 7638 ' +
                   'thumbprint can be taken of the "jwk" header.');
  }
  log.debug("Leaving checkAccountKey().");
  return { ok: true, jwk: publicJwk, thumbprint: thumbprint, key: key };
}

// Whether a stored account key can have signed with `alg` at all — a `kid`
// request names the key by account, and the header's `alg` must still fit it.
function algorithmFitsKey(alg, jwk) {
  log.debug("Entering algorithmFitsKey().");
  const kty = String((jwk && jwk.kty) || '');
  let fits = false;
  if (kty === 'RSA') {
    fits = /^(RS|PS)\d{3}$/.test(alg);
  } else if (kty === 'EC') {
    fits = EC_CURVE_FOR[alg] === jwk.crv;
  } else if (kty === 'OKP') {
    fits = alg === 'EdDSA';
  }
  log.debug("Leaving algorithmFitsKey(). fits=" + fits);
  return fits;
}

// ---------------------------------------------------------------------------
// THE SIGNATURE. The flattened members are put back into compact form — the
// signing input of a flattened JWS is exactly `protected.payload` — and
// verified by `common/crypto.js` with the one algorithm the header named. An
// empty payload is POST-as-GET (section 6.3) and verifies like any other.
// ---------------------------------------------------------------------------
function verifyFlattened(parts, key, alg) {
  log.debug("Entering verifyFlattened(). alg=" + alg);
  const compact = parts.protectedB64 + '.' + parts.payloadB64 + '.' +
                  parts.signatureB64;
  try {
    stsCrypto.verifyCompactJws(compact, key, { algorithms: [String(alg)],
                                               emptyPayload: true });
  } catch (e) {
    log.debug("Caught in verifyFlattened(): " + ((e && e.message) || e));
    log.debug("Leaving verifyFlattened(). It does not verify.");
    return refusal('malformed', 400, 'STS-ACME-0024', 'The JWS signature ' +
                   'does not verify with the account key.');
  }
  log.debug("Leaving verifyFlattened().");
  return { ok: true };
}

// The payload: `null` for POST-as-GET, an object otherwise.
function readPayload(parts) {
  log.debug("Entering readPayload().");
  if (!parts.payloadB64.length) {
    log.debug("Leaving readPayload(). POST-as-GET.");
    return { ok: true, value: null };
  }
  const read = readJsonObject(parts.payloadBytes, 'payload');
  if (!read.ok) {
    log.debug("Leaving readPayload(). Unreadable.");
    return refusal('malformed', 400, 'STS-ACME-0025', 'The JWS payload is ' +
                   'unreadable: ' + read.detail);
  }
  log.debug("Leaving readPayload().");
  return { ok: true, value: read.value };
}

// A payload against one resource's schema.
function checkPayload(value, schema, what) {
  log.debug("Entering checkPayload(). what=" + what);
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    log.debug("Leaving checkPayload(). Refused.");
    return refusal('malformed', 400, 'STS-ACME-0025', 'The ' + what + ' ' +
                   'payload is not acceptable: ' +
                   zodSentence(parsed.error, what));
  }
  log.debug("Leaving checkPayload().");
  return { ok: true, value: parsed.data };
}

// ---------------------------------------------------------------------------
// THE PAYLOAD SCHEMAS, one per resource (section 7). Loose where the RFC says
// unknown fields are ignored, strict where a member's presence would change
// what is asked for and this server does not offer it.
// ---------------------------------------------------------------------------
const CONTACTS = vz.array(vz.string().min(1).max(320)).max(10);

const NEW_ACCOUNT = vz.looseObject({
  contact: CONTACTS.optional(),
  termsOfServiceAgreed: vz.boolean().optional(),
  onlyReturnExisting: vz.boolean().optional(),
  externalAccountBinding: vz.looseObject({}).optional()
});

const ACCOUNT_UPDATE = vz.looseObject({
  contact: CONTACTS.optional(),
  status: vz.string().max(32).optional(),
  termsOfServiceAgreed: vz.boolean().optional()
});

const IDENTIFIER = vz.strictObject({
  type: vz.string().min(1).max(64),
  value: vz.string().min(1).max(1024)
});

const NEW_ORDER = vz.looseObject({
  identifiers: vz.array(IDENTIFIER).min(1).max(100),
  notBefore: vz.string().max(64).optional(),
  notAfter: vz.string().max(64).optional(),
  profile: vz.string().min(1).max(64).optional(),
  replaces: vz.string().min(1).max(1024).optional()
});

const FINALIZE = vz.looseObject({
  csr: vz.string().min(1).max(MAX_MEMBER)
});

const REVOKE = vz.looseObject({
  certificate: vz.string().min(1).max(MAX_MEMBER),
  reason: vz.number().int().min(-1000).max(1000).optional()
});

const AUTHZ_UPDATE = vz.looseObject({
  status: vz.literal('deactivated')
});

const KEY_CHANGE_INNER = vz.looseObject({
  account: vz.string().min(1).max(2048),
  oldKey: vz.looseObject({ kty: vz.string().min(1).max(8) })
});

// A challenge response is `{}` (section 7.5.1); a challenge type that needed
// fields would define them, and `sts-entry-binding-01` needs none.
const CHALLENGE_RESPONSE = vz.looseObject({});

// ---------------------------------------------------------------------------
// THE REPLAY-NONCE (section 6.5), AND WHY IT CARRIES ITS OWN PROOF.
//
// A nonce this service handed out has to be accepted by whichever process
// answers the next request — the front process, or any of the request workers
// `common/request_pool.js` forks — and a nonce written to a replicated store
// arrives at another process half a second to a second LATER, which is longer
// than a client waits. So the nonce is SELF-DESCRIBING: a version byte, an
// expiry, sixteen random bytes and a MAC over all three and the realm, under a
// secret every process of this run shares. Any process can check that it
// issued one, when it expires and for which realm, with no lookup at all.
//
// The secret travels the way `ssf/ssf_receivers.js` sends its own: generated
// once into the environment, so a forked worker inherits it, and never written
// down — a nonce outliving its process would outlive the only thing that could
// have checked it, and a client told `badNonce` retries with the fresh one on
// the same response (section 6.5), so a restart costs one retry.
//
// **SINGLE USE is the other half and is a store** (`acme_store.js`): the
// random part is recorded on first use and a second presentation is refused.
// That store converges across processes rather than synchronising, which is
// the DPoP `jti` set's trade stated in the root CLAUDE.md, and what a replay
// inside that window can achieve is bounded by every resource's own state — an
// order finalizes once, a certificate revokes once, an EAB key binds once.
// ---------------------------------------------------------------------------
const NONCE_VERSION = 1;
const NONCE_SECRET_VAR = 'STS_ACME_NONCE_SECRET';

// **THE CLUSTER'S SINCE 2026-09-14 (#46).** Per run and per container, every
// other container refused this one's nonces as forged and a client alternating
// between them looped on `badNonce`. `cluster/cluster_secrets.js` now owns the
// value — the store's, sealed, where one can be shared; this environment
// variable, per run, where none can — and keeps the environment channel below
// working, which is why `NONCE_SECRET_VAR` is still named here.
function nonceSecret() {
  log.debug("Entering nonceSecret().");
  const held = clusterSecrets.text('acme-nonce');
  log.debug("Leaving nonceSecret().");
  return held;
}

// AT REQUIRE TIME, and that is the whole of what makes the paragraph above
// true. A lazy first call would put the secret into the environment of
// whichever process answered the first ACME request — and `request_pool.js`
// forks its workers EAGERLY, before the listener binds, so by then every worker
// would already hold an environment without it and each would generate a
// secret of its own: a nonce issued by one worker refused as forged by the
// next, in exactly the `dispatch` mode the self-describing nonce exists for.
nonceSecret();

function nonceMac(realmId, expiresS, random) {
  log.debug("Entering nonceMac().");
  const mac = stsCrypto.deriveSharedCredential(nonceSecret(), 'acme-nonce',
                                               String(realmId || ''),
                                               String(expiresS),
                                               b64u(random));
  log.debug("Leaving nonceMac().");
  return Buffer.from(mac, 'base64url').subarray(0, 16);
}

function mintNonce(realmId, lifetimeS) {
  log.debug("Entering mintNonce().");
  const expiresS = Math.floor(Date.now() / 1000) +
                   Math.max(1, Number(lifetimeS) || 300);
  const random = nodeCrypto.randomBytes(16);
  const head = Buffer.alloc(5);
  head.writeUInt8(NONCE_VERSION, 0);
  head.writeUInt32BE(expiresS >>> 0, 1);
  const nonce = b64u(Buffer.concat([head, random,
                                    nonceMac(realmId, expiresS, random)]));
  log.debug("Leaving mintNonce().");
  return nonce;
}

// -> { ok, id, expiresS }
//  | { ok: false, reason: 'malformed' | 'forged' | 'expired' }
function checkNonce(nonce, realmId) {
  log.debug("Entering checkNonce().");
  const bytes = decodeB64url(nonce, false);
  if (!bytes || bytes.length !== 37 || bytes.readUInt8(0) !== NONCE_VERSION) {
    log.debug("Leaving checkNonce(). Malformed.");
    return { ok: false, reason: 'malformed' };
  }
  const expiresS = bytes.readUInt32BE(1);
  const random = bytes.subarray(5, 21);
  const presented = bytes.subarray(21, 37);
  const expected = nonceMac(realmId, expiresS, random);
  if (!nodeCrypto.timingSafeEqual(presented, expected)) {
    log.debug("Leaving checkNonce(). Not one this service issued here.");
    return { ok: false, reason: 'forged' };
  }
  if (expiresS <= Math.floor(Date.now() / 1000)) {
    log.debug("Leaving checkNonce(). Expired.");
    return { ok: false, reason: 'expired', expiresS: expiresS };
  }
  log.debug("Leaving checkNonce().");
  return { ok: true, id: b64u(random), expiresS: expiresS };
}

// ---------------------------------------------------------------------------
// THE EXTERNAL ACCOUNT BINDING (section 7.3.4). A flattened JWS whose protected
// header is `{ alg: <a MAC>, kid: <the EAB key id>, url: <the newAccount URL>
// }` with NO nonce, whose payload is the account's own public JWK, MACed with
// the key the CA handed out. `parseEab()` decides everything but the MAC, so
// the route can look the key up by `kid`; `verifyEabMac()` is the MAC, in
// constant time inside `common/crypto.js`.
// ---------------------------------------------------------------------------
const EAB_HEADER = vz.strictObject({
  alg: vz.string().min(1).max(16),
  kid: vz.string().min(1).max(512),
  url: vz.string().min(1).max(2048)
});

function parseEab(eab, expectedUrl, accountThumbprint) {
  log.debug("Entering parseEab().");
  const parts = parseFlattenedObject(eab, 'externalAccountBinding');
  if (!parts.ok) {
    log.debug("Leaving parseEab(). Not a flattened JWS.");
    return refusal('malformed', 400, 'STS-ACME-0032', parts.detail);
  }
  const read = readJsonObject(parts.headerBytes,
                              'externalAccountBinding protected header');
  if (!read.ok) {
    log.debug("Leaving parseEab(). The header is unreadable.");
    return refusal('malformed', 400, 'STS-ACME-0032', 'The ' +
                   'externalAccountBinding header is unreadable: ' +
                   read.detail);
  }
  const header = EAB_HEADER.safeParse(read.value);
  if (!header.success) {
    log.debug("Leaving parseEab(). The header is not acceptable.");
    return refusal('malformed', 400, 'STS-ACME-0032', 'The ' +
                   'externalAccountBinding protected header must be exactly ' +
                   '"alg", "kid" and "url" — no nonce (RFC 8555 section ' +
                   '7.3.4): ' + zodSentence(header.error, 'EAB header'));
  }
  if (EAB_ALGS.indexOf(header.data.alg) < 0) {
    log.debug("Leaving parseEab(). Not a MAC.");
    return refusal('badSignatureAlgorithm', 400, 'STS-ACME-0032', 'An ' +
                   'external account binding is MACed with ' +
                   EAB_ALGS.join(', ') + ', and this one names "' +
                   header.data.alg + '".', { algorithms: EAB_ALGS.slice() });
  }
  if (header.data.url !== expectedUrl) {
    log.debug("Leaving parseEab(). The url differs.");
    return refusal('malformed', 400, 'STS-ACME-0032', 'The ' +
                   'externalAccountBinding "url" must be the newAccount URL ' +
                   'the outer JWS was sent to.');
  }
  const keyRead = readJsonObject(parts.payloadBytes,
                                 'externalAccountBinding payload');
  let bound = '';
  if (keyRead.ok) {
    const alg = keyRead.value.kty === 'RSA' ? 'RS256'
      : (keyRead.value.kty === 'OKP' ? 'EdDSA'
        : ({ 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' })[
            keyRead.value.crv] || 'ES256');
    const key = checkAccountKey(keyRead.value, alg);
    bound = key.ok ? key.thumbprint : '';
  }
  if (!bound || bound !== accountThumbprint) {
    log.debug("Leaving parseEab(). It binds a different key.");
    return refusal('malformed', 400, 'STS-ACME-0032', 'The ' +
                   'externalAccountBinding payload must be the account\'s ' +
                   'own public key, the same one the outer JWS carries in ' +
                   '"jwk".');
  }
  log.debug("Leaving parseEab().");
  return { ok: true, kid: header.data.kid, alg: header.data.alg,
           parts: parts };
}

function verifyEabMac(parsed, hmacKey) {
  log.debug("Entering verifyEabMac().");
  const compact = parsed.parts.protectedB64 + '.' + parsed.parts.payloadB64 +
                  '.' + parsed.parts.signatureB64;
  let verified = false;
  try {
    stsCrypto.verifyCompactJws(compact, Buffer.from(hmacKey),
                               { algorithms: [parsed.alg] });
    verified = true;
  } catch (e) {
    log.debug("Caught in verifyEabMac(): " + ((e && e.message) || e));
    verified = false;
  }
  log.debug("Leaving verifyEabMac(). verified=" + verified);
  return verified;
}

// ---------------------------------------------------------------------------
// CONTACTS (section 7.3). `mailto:` is the only scheme this server supports,
// as section 7.3 lets it choose, and a mailto URI carrying header fields or
// more than one address is refused — RFC 8555 section 7.3 says so of `hfields`
// and a list of recipients is not "a contact".
// ---------------------------------------------------------------------------
function checkContacts(list) {
  log.debug("Entering checkContacts().");
  const values = list || [];
  for (let i = 0; i < values.length; i++) {
    const one = String(values[i]);
    if (!/^mailto:/i.test(one)) {
      log.debug("Leaving checkContacts(). Unsupported scheme.");
      return refusal('unsupportedContact', 400, 'STS-ACME-0037', 'Contact "' +
                     one.slice(0, 80) + '" is not a mailto: URI, the only ' +
                     'contact scheme this server supports.');
    }
    const address = one.slice(7);
    if (!/^[A-Za-z0-9.!#$%&'*+/=^_`{|}~-]{1,64}@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/
      .test(address) || address.length > 254) {
      log.debug("Leaving checkContacts(). Invalid address.");
      return refusal('invalidContact', 400, 'STS-ACME-0037', 'Contact "' +
                     one.slice(0, 80) + '" is not one mailto: address with ' +
                     'no header fields.');
    }
  }
  log.debug("Leaving checkContacts().");
  return { ok: true, contacts: values.map(String) };
}

// ---------------------------------------------------------------------------
// RFC 9773's CERTIFICATE IDENTIFIER: base64url of the Authority Key
// Identifier's keyIdentifier, a dot, base64url of the serial number's DER
// INTEGER content (with its leading zero octet when the high bit is set).
// ---------------------------------------------------------------------------
function serialContentBytes(serialHex) {
  log.debug("Entering serialContentBytes().");
  let hex = String(serialHex || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase()
    .replace(/^(00)+(?=.)/, '');
  if (hex.length % 2) {
    hex = '0' + hex;
  }
  let bytes = Buffer.from(hex, 'hex');
  if (bytes.length && (bytes[0] & 0x80)) {
    bytes = Buffer.concat([Buffer.from([0]), bytes]);
  }
  log.debug("Leaving serialContentBytes().");
  return bytes;
}

function certIdOf(akiBytes, serialHex) {
  log.debug("Entering certIdOf().");
  log.debug("Leaving certIdOf().");
  return b64u(akiBytes) + '.' + b64u(serialContentBytes(serialHex));
}

function parseCertId(text) {
  log.debug("Entering parseCertId().");
  const value = String(text || '');
  const pieces = value.split('.');
  if (pieces.length !== 2 || value.length > 512) {
    log.debug("Leaving parseCertId(). Not two parts.");
    return null;
  }
  const aki = decodeB64url(pieces[0], false);
  const serial = decodeB64url(pieces[1], false);
  if (!aki || !serial) {
    log.debug("Leaving parseCertId(). Not base64url.");
    return null;
  }
  log.debug("Leaving parseCertId().");
  return { aki: aki, serialHex: serial.toString('hex').replace(/^(00)+(?=.)/,
                                                                ''),
           certId: value };
}

// ---------------------------------------------------------------------------
// WHAT A CERTIFICATE SAYS, read with pkijs: the serial, the AKI keyIdentifier,
// the SubjectPublicKeyInfo DER and the validity. For revokeCert (whose
// `certificate` member is attacker bytes) and for the renewal index.
// ---------------------------------------------------------------------------
function asArrayBuffer(bytes) {
  log.debug("Entering asArrayBuffer().");
  const buf = Buffer.from(bytes);
  log.debug("Leaving asArrayBuffer().");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function certificateFacts(der) {
  log.debug("Entering certificateFacts().");
  const bytes = Buffer.from(der || []);
  if (!bytes.length) {
    log.debug("Leaving certificateFacts(). Empty.");
    return null;
  }
  try {
    const parsed = asn1js.fromBER(asArrayBuffer(bytes));
    if (parsed.offset === -1 || parsed.offset !== bytes.length) {
      throw new Error('not one complete DER value');
    }
    const cert = new pkijs.Certificate({ schema: parsed.result });
    const serial = Buffer.from(cert.serialNumber.valueBlock.valueHexView);
    let aki = null;
    (cert.extensions || []).forEach(function (extension) {
      if (extension.extnID === '2.5.29.35' && extension.parsedValue &&
          extension.parsedValue.keyIdentifier) {
        aki = Buffer.from(extension.parsedValue.keyIdentifier.valueBlock
                          .valueHexView);
      }
    });
    const spki = Buffer.from(cert.subjectPublicKeyInfo.toSchema()
                             .toBER(false));
    log.debug("Leaving certificateFacts().");
    return {
      der: bytes,
      serialHex: serial.toString('hex').replace(/^(00)+(?=.)/, ''),
      aki: aki,
      spkiDer: spki,
      notBefore: cert.notBefore.value.toISOString(),
      notAfter: cert.notAfter.value.toISOString()
    };
  } catch (e) {
    log.debug("Caught in certificateFacts(): " + ((e && e.message) || e));
    log.debug("Leaving certificateFacts(). Unreadable.");
    return null;
  }
}

// The DER of a PEM certificate (the first one in it).
function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  const match = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/
    .exec(String(pem || ''));
  log.debug("Leaving pemToDer().");
  return match ? Buffer.from(match[1].replace(/\s+/g, ''), 'base64') : null;
}

// A JWK's SubjectPublicKeyInfo DER, for "is this the certificate's own key".
function spkiOfJwk(jwk) {
  log.debug("Entering spkiOfJwk().");
  try {
    const der = nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' })
      .export({ type: 'spki', format: 'der' });
    log.debug("Leaving spkiOfJwk().");
    return Buffer.from(der);
  } catch (e) {
    log.debug("Caught in spkiOfJwk(): " + ((e && e.message) || e));
    log.debug("Leaving spkiOfJwk(). Unusable.");
    return null;
  }
}

// ---------------------------------------------------------------------------
// IDENTIFIER VALUES (section 7.1.4 and the three documents that add types).
// Returns the value normalised, or '' when it is not a value of that type.
// ---------------------------------------------------------------------------
function normalIdentifier(type, value) {
  log.debug("Entering normalIdentifier(). type=" + type);
  const text = String(value || '');
  let out = '';
  if (type === 'dns') {
    const lower = text.toLowerCase();
    const ok = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
      .test(lower) && lower.length <= 253 && !net.isIP(lower);
    out = ok ? lower : '';
  } else if (type === 'ip') {
    // RFC 8738 section 3: an IPv4 dotted quad or an RFC 5952 IPv6 text form.
    out = net.isIP(text) ? text.toLowerCase() : '';
  } else if (type === 'email') {
    // RFC 8823 section 3.1: an addr-spec, no display name.
    out = /^[A-Za-z0-9.!#$%&'*+/=^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$/
      .test(text) ? text : '';
  } else if (type === 'permanent-identifier') {
    out = text.length <= 256 && !/[\u0000-\u001f\u007f]/.test(text) ? text
                                                                     : '';
  }
  log.debug("Leaving normalIdentifier().");
  return out;
}

module.exports = {
  MEDIA_TYPE: MEDIA_TYPE,
  ERROR_PREFIX: ERROR_PREFIX,
  ACCOUNT_ALGS: ACCOUNT_ALGS,
  EAB_ALGS: EAB_ALGS,
  MIN_RSA_BITS: MIN_RSA_BITS,
  REVOCATION_REASONS: REVOCATION_REASONS,
  NONCE_SECRET_VAR: NONCE_SECRET_VAR,
  schemas: { NEW_ACCOUNT: NEW_ACCOUNT, ACCOUNT_UPDATE: ACCOUNT_UPDATE,
             NEW_ORDER: NEW_ORDER, FINALIZE: FINALIZE, REVOKE: REVOKE,
             AUTHZ_UPDATE: AUTHZ_UPDATE, KEY_CHANGE_INNER: KEY_CHANGE_INNER,
             CHALLENGE_RESPONSE: CHALLENGE_RESPONSE },
  refusal: refusal,
  isJoseJson: isJoseJson,
  decodeB64url: decodeB64url,
  b64u: b64u,
  parseBody: parseBody,
  parseFlattenedObject: parseFlattenedObject,
  parseProtectedHeader: parseProtectedHeader,
  checkAlgorithm: checkAlgorithm,
  checkAccountKey: checkAccountKey,
  algorithmFitsKey: algorithmFitsKey,
  verifyFlattened: verifyFlattened,
  readPayload: readPayload,
  checkPayload: checkPayload,
  mintNonce: mintNonce,
  checkNonce: checkNonce,
  parseEab: parseEab,
  verifyEabMac: verifyEabMac,
  checkContacts: checkContacts,
  certIdOf: certIdOf,
  parseCertId: parseCertId,
  serialContentBytes: serialContentBytes,
  certificateFacts: certificateFacts,
  pemToDer: pemToDer,
  spkiOfJwk: spkiOfJwk,
  normalIdentifier: normalIdentifier
};
