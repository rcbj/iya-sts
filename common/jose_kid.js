// @ts-check
'use strict';
//
// File: jose_kid.js
//
// ===========================================================================
// THE `kid` A SIGNED TOKEN CARRIES: THIS SERVICE'S OWN NAME, OR AN RFC 9278
// JWK THUMBPRINT URI (2026-09-13).
//
// Every key this service signs with has a `kid` of its own — `sts-` and a
// hash of the RSA key's certificate, `sts-<curve>-` and a hash of a curve
// key's coordinates, `sts-<alg>-` for a post-quantum key (`helpers.js`'s
// makeStsKeys() argues why each is derived from the key rather than typed).
// Those names are OPAQUE: a verifier holding a token can do nothing with one
// except look it up in the JWKS it came with.
//
// RFC 9278 gives a key a name ANYBODY can compute from the key itself:
//
//   urn:ietf:params:oauth:jwk-thumbprint:sha-256:<RFC 7638 thumbprint>
//
// and `keys.kidFormat` decides, per trust realm, which of the two a token's
// header carries: `internal` (the default — every token byte for byte what it
// was) or `jwk-thumbprint-uri`. The owner chose ONE setting per realm rather
// than one per use case, because a `kid` names a KEY in the realm's one JWKS,
// and asked that it not be the default.
//
// **IT NAMES THE KEY, NOT THE CERTIFICATE.** The certificate the key is filed
// under is `x5c` / `x5u`'s business (`common/jose_certificate_header.js`), and
// the two are independent: a key with no certificate yet still has a
// thumbprint, and a certificate reissued over the same key does not move it.
//
// ---------------------------------------------------------------------------
// THE INTERNAL `kid` STAYS THE KEY'S NAME INSIDE THIS SERVICE.
//
// The published name is a TRANSLATION applied at the edges and nowhere else:
// the header a signer writes, the JWK Set a verifier reads, and the lookups
// this service makes when it verifies a token of its own. Everything in
// between — the key set, the keystore's rows, the key channel's arbitration,
// the certificate register's slots, `certificateHeaderFor()`'s match, the
// logs — goes on naming a key by its internal `kid`. Changing the key set's
// own `kid` would have been a change to every one of those, several of them
// persisted, for a setting that can be flipped per realm at runtime.
//
// ---------------------------------------------------------------------------
// THE JWK SET CARRIES BOTH NAMES WHILE THE SETTING IS ON.
//
// The owner's choice. Each signing key appears once under its internal `kid`,
// exactly as before and in the same place — the RSA key is still `keys[0]` —
// and once more under its thumbprint URI, after every signing key and before
// the encryption keys. So a token signed before the setting was turned on
// still finds its key at a verifier that matches `kid` exactly (a refresh
// token lives a day), and a token signed after finds its own. With the setting
// OFF the set is what it always was, which means turning it off again leaves a
// token signed while it was on with no entry to match; that is the ordinary
// cost of renaming a key and it is stated on the setting.
//
// **A LOOKUP INSIDE THIS SERVICE ACCEPTS EITHER NAME, WHATEVER THE SETTING
// SAYS** — `names()` below. A token this service signed is this service's
// token under either spelling, and refusing one because the realm's setting
// changed since would be the service disowning its own signature.
//
// ---------------------------------------------------------------------------
// A FAILURE TO COMPUTE ONE IS NOT A FAILURE TO SIGN.
//
// A key whose thumbprint cannot be computed — a key type RFC 7638 has no
// member list for — is signed under its internal `kid`, and the reason is
// logged once per key with STS-KEYS-0055. A token that could not be named
// the way the setting asked is still a token, and a signer that refused to
// issue over its header would be the tail wagging the dog (the certificate
// header's argument, one member along).
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route and requires `config`, `crypto`
// and `error_codes`, none of which requires it back; `helpers.js` requires
// it, and is the one that knows which key a `kid` names.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');
const stsCrypto = require('./crypto');
// The error-code registry, a LEAF. Nothing here refuses a request; the one
// failure this module sees — a key it cannot compute a thumbprint for — is
// `tag()`ged onto its log line.
const errorCodes = require('./error_codes');
const cacheRegistry = require('./cache_registry');

// A logger of its own, for `jose_certificate_header.js`'s reason: `helpers.js`
// requires this file.
const log = bunyan.createLogger({
  name: 'jose_kid',
  level: config.value('global.logLevel')
});

const SETTING = 'keys.kidFormat';

// The two answers the setting may give. `common/config.js` writes the same
// list into the row's `enumValues`, and `tests/jose_kid.js` holds the two
// together.
const FORMATS = ['internal', 'jwk-thumbprint-uri'];

const DEFAULT_FORMAT = 'internal';

// What the setting says in the ambient realm. An unreadable value is the
// default: a setting nobody could read has not been switched on by anybody.
function formatFor() {
  log.debug("Entering formatFor().");
  const raw = String(config.value(SETTING) || '');
  log.debug("Leaving formatFor().");
  return FORMATS.indexOf(raw) >= 0 ? raw : DEFAULT_FORMAT;
}

function usesThumbprintUri() {
  log.debug("Entering usesThumbprintUri().");
  log.debug("Leaving usesThumbprintUri().");
  return formatFor() === 'jwk-thumbprint-uri';
}

function isThumbprintUri(kid) {
  log.debug("Entering isThumbprintUri().");
  log.debug("Leaving isThumbprintUri().");
  return String(kid || '').indexOf(stsCrypto.JWK_THUMBPRINT_URI_PREFIX) === 0;
}

// ---------------------------------------------------------------------------
// THE URI FOR ONE KEY, cached by its internal `kid`. A `kid` here is derived
// from the key's own material, so one never names two keys, and the RSA key's
// public JWK comes out of a certificate — a parse the token endpoint should
// not pay per signature. Bounded, because keys are rotated and realms made.
// ---------------------------------------------------------------------------
const CACHE_LIMIT = 512;
const uris = new Map();
// The keys a failure has already been reported for, so a busy token endpoint
// logs it once rather than once per token.
const warned = new Map();

// Described to `/admin/caches` (#74, rule 3ap). `warned` is a log
// de-duplication set, not a cache, and is not registered.
const urisCount = cacheRegistry.register({
  name: 'jose.kid-thumbprint-uris',
  title: 'RFC 9278 key identifiers',
  description: 'The JWK Thumbprint URI published as a kid under ' +
    'keys.kidFormat=jwk-thumbprint-uri, keyed by the internal kid, so a ' +
    'token signature does not re-read the key out of its certificate.',
  owner: 'common/jose_kid.js',
  scope: 'process',
  settings: ['keys.kidFormat'],
  maxEntries: function () {
    return CACHE_LIMIT;
  },
  lifetime: function () {
    return 'No expiry: an internal kid is derived from the key, so its ' +
      'answer never changes. The oldest goes first when full.';
  },
  entries: function () {
    const out = [];
    uris.forEach(function (uri, kid) {
      out.push({ key: kid, validUntil: null, basis: 'content-keyed' });
    });
    return out;
  }
});

function remember(map, key, value) {
  log.debug("Entering remember().");
  while (map.size >= CACHE_LIMIT) {
    map.delete(map.keys().next().value);
  }
  map.set(key, value);
  log.debug("Leaving remember().");
}

// `publicJwkOf` is the key's public JWK, or a function answering it — a
// function, so a signature under `internal`, or a cached answer, never
// computes one. Throws where there is no key or no thumbprint for it; the two
// callers below decide what that means.
function thumbprintUriFor(internalKid, publicJwkOf) {
  log.debug("Entering thumbprintUriFor().");
  const cacheKey = String(internalKid || '');
  if (cacheKey && uris.has(cacheKey)) {
    urisCount.hit();
    log.debug("Leaving thumbprintUriFor(). Cached.");
    return uris.get(cacheKey);
  }
  urisCount.miss();
  const jwk = typeof publicJwkOf === 'function' ? publicJwkOf() : publicJwkOf;
  if (!jwk) {
    log.debug("Leaving thumbprintUriFor(). No such key.");
    throw new Error('no public key is held under the kid "' + cacheKey +
                    '".');
  }
  const uri = stsCrypto.jwkThumbprintUri(jwk);
  if (cacheKey) {
    remember(uris, cacheKey, uri);
  }
  log.debug("Leaving thumbprintUriFor().");
  return uri;
}

// ---------------------------------------------------------------------------
// THE `kid` TO PUT IN A HEADER. The internal one under `internal`, and under
// `jwk-thumbprint-uri` wherever the URI cannot be computed.
// ---------------------------------------------------------------------------
function publishedKid(internalKid, publicJwkOf) {
  log.debug("Entering publishedKid().");
  if (!internalKid || !usesThumbprintUri()) {
    log.debug("Leaving publishedKid(). The internal kid.");
    return internalKid;
  }
  try {
    const uri = thumbprintUriFor(internalKid, publicJwkOf);
    log.debug("Leaving publishedKid(). The thumbprint URI.");
    return uri;
  } catch (e) {
    if (!warned.has(internalKid)) {
      remember(warned, internalKid, true);
      log.error(errorCodes.tag('STS-KEYS-0055') + 'keys.kidFormat asks for ' +
                'an RFC 9278 thumbprint URI and none could be computed for ' +
                'the key "' + internalKid + '", so tokens it signs carry its ' +
                'internal kid: ' + ((e && e.message) || e));
    }
    log.debug("Leaving publishedKid(). The internal kid, as a fallback.");
    return internalKid;
  }
}

// ---------------------------------------------------------------------------
// DOES A HEADER'S `kid` NAME THIS KEY — under either spelling, whatever the
// setting says now (see the header).
// ---------------------------------------------------------------------------
function names(headerKid, internalKid, publicJwkOf) {
  log.debug("Entering names().");
  const kid = String(headerKid || '');
  if (!kid || !internalKid) {
    log.debug("Leaving names(). Nothing to compare.");
    return false;
  }
  if (kid === internalKid) {
    log.debug("Leaving names(). The internal kid.");
    return true;
  }
  if (!isThumbprintUri(kid)) {
    log.debug("Leaving names(). Neither spelling.");
    return false;
  }
  try {
    const answer = thumbprintUriFor(internalKid, publicJwkOf) === kid;
    log.debug("Leaving names(). " + answer);
    return answer;
  } catch (e) {
    log.debug("Caught in names(): " + ((e && e.message) || e));
    log.debug("Leaving names(). No thumbprint for this key.");
    return false;
  }
}

// ---------------------------------------------------------------------------
// THE SECOND ENTRY FOR EACH SIGNING KEY IN A JWK SET: the same members under
// the thumbprint URI. Empty under `internal`. A key with no thumbprint gets no
// second entry, and its tokens carry the internal kid (`publishedKid()`), so
// the set and the tokens agree about it.
// ---------------------------------------------------------------------------
function thumbprintUriEntries(publicJwks) {
  log.debug("Entering thumbprintUriEntries().");
  if (!usesThumbprintUri()) {
    log.debug("Leaving thumbprintUriEntries(). The setting is off.");
    return [];
  }
  const out = [];
  (publicJwks || []).forEach(function (jwk) {
    if (!jwk || !jwk.kid || isThumbprintUri(jwk.kid)) {
      return;
    }
    try {
      out.push(Object.assign({}, jwk,
                             { kid: thumbprintUriFor(jwk.kid, jwk) }));
    } catch (e) {
      log.debug("Caught in thumbprintUriEntries(): " +
                ((e && e.message) || e));
    }
  });
  log.debug("Leaving thumbprintUriEntries(). " + out.length + " entr" +
            (out.length === 1 ? 'y' : 'ies') + ".");
  return out;
}

// A JWK Set's signing entries followed by their second entries — the shape
// `oauth2.js`'s `sendJwks()` publishes.
function withThumbprintUriEntries(publicJwks) {
  log.debug("Entering withThumbprintUriEntries().");
  const list = publicJwks || [];
  log.debug("Leaving withThumbprintUriEntries().");
  return list.concat(thumbprintUriEntries(list));
}

module.exports = {
  SETTING: SETTING,
  FORMATS: FORMATS,
  DEFAULT_FORMAT: DEFAULT_FORMAT,
  formatFor: formatFor,
  usesThumbprintUri: usesThumbprintUri,
  isThumbprintUri: isThumbprintUri,
  thumbprintUriFor: thumbprintUriFor,
  publishedKid: publishedKid,
  names: names,
  thumbprintUriEntries: thumbprintUriEntries,
  withThumbprintUriEntries: withThumbprintUriEntries
};
