// @ts-check
'use strict';
//
// File: jose_certificate_header.js
//
// ===========================================================================
// THE CERTIFICATE CHAIN A SIGNED TOKEN POINTS AT: `x5c` AND `x5u` (2026-09-13).
//
// Every key pair this service signs a JWT with is a leaf of `common/pki.js`'s
// hierarchy — the RSA key, the curve keys and the eleven post-quantum keys,
// each certified under its realm's JOSE Issuing CA. Each of those certificates
// names its CRL, its OCSP responder and its issuer's certificate. **A token did
// not say so.** Its header carried `alg`, `kid` and `typ`, so a relying party
// that wanted the revocation information behind a signature had to fetch the
// JWKS, find the key by `kid`, and read the `x5c` there — which only the RSA
// key's JWKS entry carries.
//
// RFC 7515 gives a JWS two header parameters for exactly this:
//
//   x5c   section 4.1.6: the certificate or chain, base64 DER (NOT base64url),
//         the certificate holding the signing key FIRST
//   x5u   section 4.1.5: a URI for the same chain in PEM, which MUST be fetched
//         over TLS
//
// and this module decides, per USE CASE and per trust realm, which of them a
// token carries. `none`, `x5c`, `x5u` or `both`, one setting per use case, and
// `x5u` by default — the owner's choice: a full chain inline is four
// certificates and roughly five kilobytes on every access token, where a URL is
// a hundred bytes and one GET.
//
// ---------------------------------------------------------------------------
// WHY ONE SETTING PER USE CASE AND NOT ONE FOR THE SERVICE.
//
// The tokens are read by different parties with different constraints. An
// access token rides in an `Authorization` header past proxies with header size
// limits; a Security Event Token is POSTed to a receiver that may have no route
// back to this service and so can only use `x5c`; a signed `signed_metadata`
// document is fetched by a client that already reached this service and can
// follow `x5u` for free. One switch would force all of them into the answer
// that suits the most constrained. `USE_CASES` below is the list, each row
// names its setting, and the setting lives in its protocol's group so it is
// drawn on that protocol's console page — `tests/jose_certificate_header.js`
// holds the table and `common/config.js` to each other.
//
// **PER REALM FOR FREE**: every row is `runtime: true`, so `config.value()`
// consults the ambient realm's override first, which is how every other
// setting here became per realm without being edited.
//
// ---------------------------------------------------------------------------
// WHAT GETS A HEADER, AND WHAT DELIBERATELY DOES NOT.
//
//   * A SIGNATURE MADE WITH A CERTIFIED KEY OF THIS REALM. Nothing else. The
//     certificate must be the one this realm's register holds for that key's
//     slot AND must hold that key — compared by the SHA-256 of the
//     SubjectPublicKeyInfo — because RFC 7515 says the first certificate MUST
//     contain the signing key, and a register row left over from a key that
//     has since been regenerated would otherwise put a certificate over a
//     DIFFERENT key into a token, which verifies as nothing and names nothing.
//   * NOT AN HS* SIGNATURE. The key is a client's secret; there is no
//     certificate.
//   * NOT A KEY WITH NO CERTIFICATE YET. A key set is certified asynchronously
//     after it is made, and not at all where `pki.autoBuild` is off. The RSA
//     key's self-signed birth certificate is deliberately NOT used: it names no
//     CRL, no OCSP responder and no issuer, which is the whole of what this
//     header exists to carry.
//   * NOT A JWE. Every JWE this service makes is encrypted either to somebody
//     else's key — a client's, a wallet's, a resource server's — or to the
//     refresh-token keys, which are plain keys and not PKI leaves on purpose
//     (`helpers.js`'s makeRefreshTokenEncryptionKeys() argues it). A JWE's
//     `x5c` describes the RECIPIENT's key, so there is no certified key of this
//     service's to name. The owner chose signatures only on 2026-09-13; a
//     nested refresh token still gets one, on the JWS inside it.
//   * NOT THE SPIFFE JWT-SVID. The JWT authority has no certificate.
//   * NOT `oid4vc/vc_did.ts`'s generated credentials, signed with a key the
//     request generated and nobody certified.
//   * NOT THE DIF DOMAIN LINKAGE CREDENTIAL, although its key IS certified.
//     The Well Known DID Configuration specification allows exactly `alg` and
//     `kid` in that JWT's header — `typ` is forbidden and so is anything else —
//     and a verifier that reads it strictly refuses a linkage carrying `x5u`.
//     It had a setting for an hour on 2026-09-13; the vendored `vc_did.js` job
//     failed on the first run against it, and a setting whose every non-`none`
//     value breaks conformance with the document it governs is a trap rather
//     than an option. The DID document already carries the key.
//
// ---------------------------------------------------------------------------
// THE CHAIN IS THE FULL CHAIN.
//
// Leaf, Issuing CA, Intermediate, and the service Root — the owner asked for
// the full trust chain, and RFC 7515 permits the anchor. `pki.js` stores a
// certificate's chain WITHOUT the Root (what a TLS certificate_list wants), so
// the Root is appended here, and only when the last certificate of the stored
// chain really is signed by the Root this service holds NOW: a branch rebuilt
// under a replaced Root leaves records whose stored chain ends at an
// Intermediate the current Root never signed, and appending it would publish a
// chain that does not chain. That case gets the stored chain alone.
//
// ---------------------------------------------------------------------------
// THE `x5u` ADDRESS.
//
// `GET /pki/chain/{scope}/{sha256}.pem`, served by `pki/pki_service.ts` beside
// the CRL and OCSP endpoints and for their reason that the scope is in the
// path rather than taken from a realm prefix: an address inside a token is
// fetched by a client that knows nothing about this service's realm
// convention. The name is the certificate's SHA-256 rather than its `kid` or
// its slot, so a URL names ONE certificate for ever — a key rotated since the
// token was signed is a 404, not a chain over a different key.
//
// The ORIGIN is `global.publicBaseUrl` where that is pinned and otherwise the
// request being answered, read through `helpers.forwardedFrom()` — the one
// decision about forwarded headers this service makes, so `x5u` names the same
// host the token's `iss` does. The request is AMBIENT, in an
// `AsyncLocalStorage` `common/app.js` enters for every request, for the
// realm's reason: threading a request through a dozen signers to build one URL
// is the several-call-sites problem that design exists to avoid. A signature
// made with no request and no pinned base gets no `x5u` — there is no address
// to name — and says so at debug.
//
// **RFC 7515 SAYS THE FETCH MUST USE TLS.** The main port is HTTPS in every
// shipped configuration; where `global.https` is off the address is `http://`
// and a strict verifier will refuse to follow it. That is reported on the
// setting rather than silently switched to `x5c`.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, so its position in the require
// order is not a position. It requires `config`, `realms` and `error_codes` at
// the top and nothing that requires it back; `pki.js` and `helpers.js` are
// required LAZILY, inside the functions that need them — `helpers.js` requires
// THIS file, and `pki.js` is kept out of the load path of every in-process
// caller of helpers for the reason `helpers.js`'s certifiedView() gives.
// ===========================================================================

const bunyan = require('bunyan');
const nodeCrypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');
const config = require('./config');
const realms = require('./realms');
// The error-code registry, a LEAF. Nothing here refuses a request; the one
// failure this module can see — a certificate on record that does not hold the
// key it is filed under — is `tag()`ged onto its log line.
const errorCodes = require('./error_codes');
const cacheRegistry = require('./cache_registry');

// A logger of its own, for `pki.js`'s reason: `helpers.js` requires this file.
const log = bunyan.createLogger({
  name: 'jose_certificate_header',
  level: config.value('global.logLevel')
});

// The four answers a use case's setting may give. `common/config.js` writes the
// same list into each row's `enumValues`, and the test holds the two together.
const MODES = ['none', 'x5c', 'x5u', 'both'];

const DEFAULT_MODE = 'x5u';

// ---------------------------------------------------------------------------
// THE USE CASES. One row per KIND of token this service signs with a key this
// realm holds, and `where` names the call site so that a reader of a setting
// can find what it governs. Adding a signer is adding a row here, a row in
// `common/config.js`, and `certificateHeader: '<id>'` at the call —
// `tests/jose_certificate_header.js` fails on a signing call that names none.
// ---------------------------------------------------------------------------
const USE_CASES = [
  { id: 'access-token', setting: 'oauth2.accessTokenCertificateHeader',
    label: 'OAuth 2.0 access tokens',
    where: 'oauth-oidc/oauth2.ts accessToken() — every grant, the ' +
           'management API\'s tokens included' },
  { id: 'id-token', setting: 'oauth2.idTokenCertificateHeader',
    label: 'OpenID Connect ID Tokens',
    where: 'oauth-oidc/oauth2.ts idToken(), in the default RS256 and in ' +
           'whatever id_token_signed_response_alg a client registered' },
  { id: 'refresh-token', setting: 'oauth2.refreshTokenCertificateHeader',
    label: 'Refresh tokens (the signed JWT inside the JWE)',
    where: 'oauth-oidc/oauth2.ts refreshToken() — the header is on the inner ' +
           'JWS, which only this service ever opens' },
  { id: 'userinfo', setting: 'oauth2.userinfoCertificateHeader',
    label: 'Signed UserInfo responses',
    where: 'oauth-oidc/oauth2.ts, userinfo_signed_response_alg' },
  { id: 'introspection', setting: 'oauth2.introspectionCertificateHeader',
    label: 'RFC 9701 JWT introspection responses',
    where: 'oauth-oidc/introspection_jwt.ts respond(), in RS256 or whatever ' +
           'introspection_signed_response_alg a resource server registered' },
  { id: 'oauth-signed-metadata',
    setting: 'oauth2.signedMetadataCertificateHeader',
    label: 'RFC 8414 signed_metadata',
    where: 'oauth-oidc/oauth2.ts signedMetadata(), both discovery documents' },
  { id: 'vci-credential', setting: 'oid4vci.credentialCertificateHeader',
    label: 'OpenID4VCI credentials',
    where: 'oid4vc/vc_issuer.ts, the SD-JWT VC issuer JWT and the JWT VC' },
  { id: 'vci-signed-metadata',
    setting: 'oid4vci.signedMetadataCertificateHeader',
    label: 'OpenID4VCI signed issuer metadata',
    where: 'oid4vc/vc_issuer.ts, the credential issuer\'s signed_metadata' },
  { id: 'vp-request-object', setting: 'oid4vp.requestObjectCertificateHeader',
    label: 'OpenID4VP Request Objects',
    where: 'oid4vc/vc_verifier.ts, the signed authorization request' },
  { id: 'ssf-set', setting: 'ssf.setCertificateHeader',
    label: 'Security Event Tokens',
    where: 'ssf/ssf_events.js, every SET pushed or polled — CAEP and RISC ' +
           'included' },
  { id: 'wstrust-jwt', setting: 'wstrust.jwtCertificateHeader',
    label: 'WS-Trust JWT tokens',
    where: 'ws-trust/wstrust.ts, a JWT issued in a ' +
           'RequestSecurityTokenResponse' },
  { id: 'gnap-access-token', setting: 'gnap.accessTokenCertificateHeader',
    label: 'GNAP JWT access tokens',
    where: 'gnap/gnap_tokens.ts, the jwt-signed format and the JWS inside ' +
           'jwt-encrypted' }
];

const USE_CASE_IDS = USE_CASES.map(function (one) { return one.id; });

function useCase(id) {
  log.debug("Entering useCase().");
  log.debug("Leaving useCase().");
  return USE_CASES.filter(function (one) {
    return one.id === String(id || '');
  })[0] || null;
}

// What a use case's setting says in the ambient realm. An unreadable value is
// the default rather than `none`: a setting that cannot be read has not been
// switched off by anybody.
function modeFor(id) {
  log.debug("Entering modeFor().");
  const uc = useCase(id);
  if (!uc) {
    log.debug("Leaving modeFor(). No such use case.");
    return 'none';
  }
  const raw = String(config.value(uc.setting) || '');
  log.debug("Leaving modeFor().");
  return MODES.indexOf(raw) >= 0 ? raw : DEFAULT_MODE;
}

// ---------------------------------------------------------------------------
// THE AMBIENT REQUEST. `common/app.js` enters it for every request, just below
// the realm middleware, and the one reader is `chainUrlFor()`.
// ---------------------------------------------------------------------------
const requests = new AsyncLocalStorage();

function enterRequest(req, next) {
  log.debug("Entering enterRequest().");
  log.debug("Leaving enterRequest().");
  return requests.run(req, next);
}

function currentRequest() {
  log.debug("Entering currentRequest().");
  log.debug("Leaving currentRequest().");
  return requests.getStore() || null;
}

// `pki.js`, lazily, or null where this process has no certificate authority —
// in which case nothing is certified and nothing gets a header.
function pkiModule() {
  log.debug("Entering pkiModule().");
  try {
    const pki = require('./pki');
    log.debug("Leaving pkiModule().");
    return pki;
  } catch (e) {
    log.debug("Caught in pkiModule(): " + ((e && e.message) || e));
    log.debug("Leaving pkiModule(). No certificate authority here.");
    return null;
  }
}

function pemToBase64(pem) {
  log.debug("Entering pemToBase64().");
  log.debug("Leaving pemToBase64().");
  return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

// ---------------------------------------------------------------------------
// DOES THIS REGISTER ROW HOLD THIS KEY. Cached by the certificate's thumbprint
// and the SubjectPublicKeyInfo's, because the answer for one pair never
// changes and the question is asked on every signature. Bounded, because the
// pairs change whenever a key is rotated or a branch rebuilt.
// ---------------------------------------------------------------------------
const MATCH_CACHE_LIMIT = 512;
const matched = new Map();
// The certificates a mismatch has already been reported for, so a busy token
// endpoint logs it once rather than once per token. A Map for `remember()`.
const warnedMismatch = new Map();

// The two memos below, described to `/admin/caches` (#74, rule 3ap). Their
// answers never change for a key, so a row is valid for as long as it is held.
function memoRows(map) {
  log.debug("Entering memoRows().");
  const out = [];
  map.forEach(function (answer, key) {
    out.push({ key: key + ' → ' + (answer ? 'yes' : 'no'), validUntil: null,
               basis: 'content-keyed' });
  });
  log.debug("Leaving memoRows().");
  return out;
}

function memoLimit() {
  log.debug("Entering memoLimit().");
  log.debug("Leaving memoLimit().");
  return MATCH_CACHE_LIMIT;
}

function memoLifetime() {
  log.debug("Entering memoLifetime().");
  log.debug("Leaving memoLifetime().");
  return 'No expiry: keyed by the certificate thumbprint and the kid, ' +
    'whose answer never changes. The oldest goes first when full.';
}

const matchedCount = cacheRegistry.register({
  name: 'jose.x5c-key-match',
  title: 'Certificate-to-signing-key matches',
  description: 'Whether a certificate register row holds the signing key, ' +
    'asked before an x5c or x5t#S256 header is put on a token. Keyed by ' +
    'the row\'s thumbprint and the key\'s kid.',
  owner: 'common/jose_certificate_header.js',
  scope: 'process',
  maxEntries: memoLimit,
  bound: 'Enforced: 512 answers, the oldest dropped and worked out again ' +
    'when next asked for.',
  lifetime: memoLifetime,
  entries: function () {
    return memoRows(matched);
  }
});

function remember(map, key, value) {
  log.debug("Entering remember().");
  while (map.size >= MATCH_CACHE_LIMIT) {
    map.delete(map.keys().next().value);
  }
  map.set(key, value);
  log.debug("Leaving remember().");
}

// **KEYED BY THE `kid` AND NOT BY THE SubjectPublicKeyInfo**, so a cached
// answer costs no key export: reading the public key out of a certificate on
// every signature would be a parse on the hot path of the token endpoint. A
// `kid` here is derived from the key's own material, so one never names two
// keys, and the certificate's thumbprint beside it moves when the register row
// is replaced.
function holdsKey(pki, record, signer) {
  log.debug("Entering holdsKey().");
  const cacheKey = record.thumbprint + ' ' + signer.kid;
  if (matched.has(cacheKey)) {
    matchedCount.hit();
    log.debug("Leaving holdsKey(). Cached.");
    return matched.get(cacheKey);
  }
  matchedCount.miss();
  const wanted = pki.thumbprintOf(signer.spkiPem());
  let held = String(record.subjectKeyFingerprint || '');
  if (!held) {
    // A record written before the register kept the subject key (2026-09-13)
    // is read out of the certificate. Node cannot read a post-quantum key out
    // of one, and a post-quantum certificate is never that old, so a throw
    // here is an unreadable certificate and the answer is no.
    try {
      held = pki.thumbprintOf(new nodeCrypto.X509Certificate(
        record.certificatePem).publicKey.export({ type: 'spki',
                                                  format: 'pem' }));
    } catch (e) {
      log.debug("Caught in holdsKey(): " + ((e && e.message) || e));
      held = '';
    }
  }
  const answer = !!held && held === wanted;
  remember(matched, cacheKey, answer);
  log.debug("Leaving holdsKey(). " + answer);
  return answer;
}

// ---------------------------------------------------------------------------
// THE CHAIN OF ONE REGISTER ROW, LEAF FIRST, AS PEM — with the Root appended
// where the stored chain really does end under it (see the header). Cached by
// the row's thumbprint and the Root's, for `holdsKey()`'s reason.
// ---------------------------------------------------------------------------
const chains = new Map();

const chainsCount = cacheRegistry.register({
  name: 'jose.x5c-chain-under-root',
  title: 'Certificate chains ending under the Root',
  description: 'Whether a register row\'s stored chain ends under the ' +
    'current service Root, which decides whether the Root is appended to ' +
    'an x5c header. Keyed by the row\'s thumbprint and the Root\'s.',
  owner: 'common/jose_certificate_header.js',
  scope: 'process',
  maxEntries: memoLimit,
  bound: 'Enforced: 512 answers, the oldest dropped and worked out again ' +
    'when next asked for.',
  lifetime: memoLifetime,
  entries: function () {
    return memoRows(chains);
  }
});

function chainPemsOf(pki, record) {
  log.debug("Entering chainPemsOf().");
  const pems = [record.certificatePem].concat(record.chainPem || []);
  const root = pki.serviceRoot();
  const rootPem = root && root.certificatePem;
  if (!rootPem || pems.indexOf(rootPem) >= 0) {
    log.debug("Leaving chainPemsOf(). No Root to append.");
    return pems;
  }
  const cacheKey = record.thumbprint + ' ' + pki.thumbprintOf(rootPem);
  if (chains.has(cacheKey)) {
    chainsCount.hit();
  } else {
    chainsCount.miss();
    let underRoot = false;
    try {
      const last = new nodeCrypto.X509Certificate(pems[pems.length - 1]);
      const anchor = new nodeCrypto.X509Certificate(rootPem);
      underRoot = last.issuer === anchor.subject &&
                  last.verify(anchor.publicKey);
    } catch (e) {
      log.debug("Caught in chainPemsOf(): " + ((e && e.message) || e));
      underRoot = false;
    }
    if (!underRoot) {
      log.debug('The "' + record.slot + '" certificate\'s stored chain does ' +
                'not end under the current Root; it is published without ' +
                'one.');
    }
    remember(chains, cacheKey, underRoot);
  }
  log.debug("Leaving chainPemsOf().");
  return chains.get(cacheKey) ? pems.concat([rootPem]) : pems;
}

// The scope segment an address names a realm by — `pki/pki_service.ts`'s
// convention, `default` for the default realm.
function scopeSegmentOf(realmId) {
  log.debug("Entering scopeSegmentOf().");
  log.debug("Leaving scopeSegmentOf().");
  return String(realmId || '') || 'default';
}

function chainUrlFor(realmId, thumbprint) {
  log.debug("Entering chainUrlFor().");
  const helpers = require('./helpers');
  let origin = helpers.pinnedBaseUrl();
  if (!origin) {
    const req = currentRequest();
    if (!req) {
      log.debug("Leaving chainUrlFor(). No request and no pinned base.");
      return '';
    }
    const from = helpers.forwardedFrom(req);
    origin = from.proto + '://' + from.host;
  }
  log.debug("Leaving chainUrlFor().");
  return origin + '/pki/chain/' + encodeURIComponent(scopeSegmentOf(realmId)) +
         '/' + thumbprint + '.pem';
}

// ---------------------------------------------------------------------------
// THE HEADER MEMBERS FOR ONE SIGNATURE.
//
// `signer` is what `helpers.certificateHeaderFor()` resolved: the realm whose
// key set holds the key, the certificate SLOT that key is filed under in the
// register (`RS256`, `ES256:P-256`, `ML-DSA-44`), the key's `kid`, and a
// function answering its SubjectPublicKeyInfo — a function, so a signature
// whose use case is `none`, or whose answer is cached, never computes one.
//
// It answers `{}` for every case that gets nothing and never throws: a token
// whose certificate could not be described is still a token, and a signer that
// failed to issue one over a header would be the tail wagging the dog.
// ---------------------------------------------------------------------------
function headerFor(useCaseId, signer) {
  log.debug("Entering headerFor(). use=" + useCaseId);
  if (!useCase(useCaseId)) {
    log.warn('A signature named the certificate-header use case "' +
             useCaseId + '", which is not one of ' + USE_CASE_IDS.join(', ') +
             '. It carries no x5c or x5u.');
    log.debug("Leaving headerFor(). Unknown use case.");
    return {};
  }
  const mode = modeFor(useCaseId);
  if (mode === 'none' || !signer || !signer.slot) {
    log.debug("Leaving headerFor(). " + (mode === 'none'
      ? 'Switched off.' : 'No certified slot for this key.'));
    return {};
  }
  try {
    const pki = pkiModule();
    const record = pki && pki.certificateFor(signer.realm, 'jose', signer.slot);
    if (!record || !record.certificatePem) {
      log.debug("Leaving headerFor(). The key is not certified.");
      return {};
    }
    if (!holdsKey(pki, record, signer)) {
      if (!warnedMismatch.has(record.thumbprint)) {
        remember(warnedMismatch, record.thumbprint, true);
        log.warn(errorCodes.tag('STS-PKI-0163') + 'The "' + signer.slot +
                 '" certificate in the "' + signer.realm + '" realm\'s ' +
                 'register does not hold the key that is signing under that ' +
                 'slot, so tokens signed with it carry no x5c or x5u until ' +
                 'the key is certified again.');
      }
      log.debug("Leaving headerFor(). The certificate is over another key.");
      return {};
    }
    const out = {};
    if (mode === 'x5c' || mode === 'both') {
      out.x5c = chainPemsOf(pki, record).map(pemToBase64);
    }
    if (mode === 'x5u' || mode === 'both') {
      const url = chainUrlFor(signer.realm, record.thumbprint);
      if (url) {
        out.x5u = url;
      }
    }
    log.debug("Leaving headerFor(). " + Object.keys(out).join(', '));
    return out;
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0164') + 'The certificate header for ' +
              'a "' + useCaseId + '" signature could not be built, and the ' +
              'token is signed without one: ' + e.message);
    log.debug("Leaving headerFor(). It failed.");
    return {};
  }
}

// ---------------------------------------------------------------------------
// THE `x5u` RESOURCE: the PEM chain of the JOSE certificate with this SHA-256,
// in this scope, or null. Only the `jose` use case is searched — it is the only
// one an `x5u` this module wrote can name — and the thumbprint is matched
// exactly against the register, never parsed into anything.
// ---------------------------------------------------------------------------
function chainPemFor(scopeId, thumbprint) {
  log.debug("Entering chainPemFor().");
  const wanted = String(thumbprint || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(wanted)) {
    log.debug("Leaving chainPemFor(). Not a SHA-256.");
    return null;
  }
  const pki = pkiModule();
  if (!pki) {
    log.debug("Leaving chainPemFor(). No certificate authority.");
    return null;
  }
  const record = pki.certificatesFor(scopeId, 'jose').filter(function (one) {
    return one && one.thumbprint === wanted;
  })[0];
  if (!record) {
    log.debug("Leaving chainPemFor(). No such certificate.");
    return null;
  }
  log.debug("Leaving chainPemFor().");
  return chainPemsOf(pki, record).map(function (pem) {
    return String(pem).trim() + '\n';
  }).join('');
}

// What every use case is set to in the ambient realm — for a reader that wants
// the whole picture rather than one row of it.
function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return USE_CASES.map(function (one) {
    return { id: one.id, setting: one.setting, label: one.label,
             where: one.where, mode: modeFor(one.id) };
  });
}

module.exports = {
  MODES: MODES,
  DEFAULT_MODE: DEFAULT_MODE,
  USE_CASES: USE_CASES,
  USE_CASE_IDS: USE_CASE_IDS,
  useCase: useCase,
  modeFor: modeFor,
  enterRequest: enterRequest,
  currentRequest: currentRequest,
  headerFor: headerFor,
  chainPemFor: chainPemFor,
  report: report
};
