// @ts-check
'use strict';
//
// File: client_jwks.js
//
// ===========================================================================
// A CLIENT'S REGISTERED `jwks_uri`, FETCHED (#120, rcbj's decision,
// 2026-09-22).
//
// Until #120 a `jwks_uri` was "recorded and never fetched", on the argument
// that dialling a URL somebody registered in order to verify a credential is a
// server-side request forgery with a citation attached. RFC 7591 section 2 and
// OpenID Connect Registration section 2 both expect an authorization server
// to honour one, and a `private_key_jwt` client that registered only a
// `jwks_uri` could not authenticate at all. So it is fetched now — under
// `federation/federation_http.ts`'s outbound policy, which is what answers the
// SSRF argument rather than a refusal: https only (unless
// `federation.outboundAllowHttp`, in development only — #171), verified
// against node's store and `federation.outboundCaFile`, no redirect, the
// body cap and the timeout, the kill switch, and in product mode an internal
// address refused with the connection pinned. It is the EIGHTH outbound fetch
// the root CLAUDE.md lists.
//
// THE READERS ARE SYNCHRONOUS, SO THE FETCH IS A PREFETCH. `assertion_grant`'s
// `keysForParty()` and `introspection_jwt`'s `recipientKey()` read keys off a
// record without waiting, and making every one of their callers asynchronous
// was not the change a new key source is worth. So each endpoint that may
// need a client's keys — the token, PAR, authorization, introspection and
// UserInfo endpoints — calls `ensureFor()` for its client first, and the two
// readers fall back to `cachedKeys()` when a client registered no `jwks`. A
// key set lacking the `kid` a client assertion names is fetched again, at most
// once per `oauth2.clientJwksRefetchS`, which is how a client that rotated
// its keys is picked up without a made-up kid forcing a fetch per request.
//
// A copy of something re-fetchable, per realm and not persisted, for
// `request_object.ts`'s `request_uri` cache's reason; described to
// `/admin/caches` and ejected by `caches.eject-expired` (#49), bounded at the
// insert.
//
// A LEAF (rule 3): `helpers`, `config`, `realms`, `cache_registry` and
// `error_codes`; `federation_http` and `applications` are required lazily,
// because `assertion_grant.js` — on `app.js`'s require chain — requires this
// file, and #145 showed what loading an instance-slot module that early does.
// ===========================================================================

const { log } = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
const cacheRegistry = require('../common/cache_registry');
const errorCodes = require('../common/error_codes');

const MAX_CACHED_KEY_SETS = 256;

// realm -> uri -> { jwks, fetchedAt, until }
const keySets = realms.map();

const keySetCount = cacheRegistry.register({
  name: 'oauth2.client-jwks',
  title: 'Fetched client key sets',
  description: 'The JSON Web Key Set a client\'s registered jwks_uri ' +
    'answered with, so its client assertions, request objects and ' +
    'encrypted responses find its keys without a fetch per request (#120).',
  owner: 'oauth-oidc/client_jwks.js',
  scope: 'realm',
  settings: ['oauth2.clientJwksCacheS', 'oauth2.clientJwksRefetchS'],
  maxEntries: function () {
    return MAX_CACHED_KEY_SETS;
  },
  bound: 'Enforced: ' + MAX_CACHED_KEY_SETS + ' key sets per realm, the ' +
    'oldest dropped and fetched again when next needed.',
  lifetime: function () {
    return 'oauth2.clientJwksCacheS (' +
      Number(config.value('oauth2.clientJwksCacheS')) + ' s) after the ' +
      'fetch, per realm; sooner when a kid it lacks is asked for.';
  },
  eject: cacheRegistry.realmMapEjector(realms, keySets,
    function (held, key, now) {
      return !(held && Number(held.until) > now);
    }),
  entries: function () {
    return cacheRegistry.realmRows(
      realms.list().map(function (r) {
        return r.id;
      }),
      function (id) {
        return keySets.realmMap(id);
      },
      function (held, key) {
        return { key: cacheRegistry.clipKey(key), validUntil: held.until };
      });
  }
});

// The key set a still-fresh fetch of `uri` answered, or null.
function cachedKeys(uri) {
  log.debug("Entering cachedKeys().");
  const held = uri ? keySets.get(String(uri)) : null;
  if (!held || !(Number(held.until) > Date.now())) {
    log.debug("Leaving cachedKeys(). None fresh.");
    return null;
  }
  log.debug("Leaving cachedKeys(). Held.");
  return held.jwks;
}

function hasKid(jwks, kid) {
  log.debug("Entering hasKid().");
  log.debug("Leaving hasKid().");
  return !kid || (jwks && Array.isArray(jwks.keys) &&
                  jwks.keys.some(function (one) {
                    return one && one.kid === kid;
                  }));
}

// Fetches `uri` unless a fresh copy answers (and holds `kid`, where one is
// named). Never rejects: `{ ok, jwks, why }`.
function ensure(uri, kid) {
  log.debug("Entering ensure(). " + uri);
  const key = String(uri || '');
  const now = Date.now();
  const held = key ? keySets.get(key) : null;
  const fresh = held && Number(held.until) > now;
  const refetchMs = Number(config.value('oauth2.clientJwksRefetchS')) * 1000;
  if (fresh && (hasKid(held.jwks, kid) ||
                now - Number(held.fetchedAt) < refetchMs)) {
    log.debug("Leaving ensure(). Held.");
    return Promise.resolve({ ok: true, jwks: held.jwks, why: '' });
  }
  const federationHttp = require('../federation/federation_http');
  log.debug("Leaving ensure(). Fetching.");
  return federationHttp.fetchPublished(key, {
    accept: 'application/jwk-set+json, application/json'
  }).then(function (answer) {
    log.debug("Entering the jwks_uri fetch's answer.");
    let jwks = null;
    let why = '';
    if (!answer.ok || answer.status !== 200) {
      why = answer.why || ('the jwks_uri answered ' + answer.status);
    } else {
      try {
        jwks = JSON.parse(answer.body.toString('utf8'));
      } catch (e) {
        log.debug("Caught in ensure(): " + ((e && e.message) || e));
        // Not JSON: refused below with the reason.
        jwks = null;
      }
      if (!jwks || !Array.isArray(jwks.keys)) {
        why = 'the jwks_uri did not answer a JSON Web Key Set';
        jwks = null;
      }
    }
    if (!jwks) {
      log.warn(errorCodes.tag('STS-OAUTH-0599') + 'oauth2: a client\'s ' +
               'jwks_uri ' + key + ' could not be read: ' + why);
      log.debug("Leaving the jwks_uri fetch's answer. Refused.");
      return { ok: false, jwks: fresh ? held.jwks : null, why: why };
    }
    if (keySets.size >= MAX_CACHED_KEY_SETS && !keySets.has(key)) {
      const oldest = keySets.keys().next().value;
      keySets.delete(oldest);
    }
    const lifetimeMs = Number(config.value('oauth2.clientJwksCacheS')) * 1000;
    keySets.set(key, { jwks: jwks, fetchedAt: Date.now(),
                       until: Date.now() + Math.max(lifetimeMs, 1000) });
    keySetCount.miss();
    log.debug("Leaving the jwks_uri fetch's answer. " + jwks.keys.length +
              " key(s).");
    return { ok: true, jwks: jwks, why: '' };
  });
}

// The registration members that ask for a response ENCRYPTED to the client —
// the synchronous readers' one use of its keys (`recipientKey()`).
const ENCRYPTION_MEMBERS = ['id_token_encrypted_response_alg',
                            'userinfo_encrypted_response_alg',
                            'introspection_encrypted_response_alg',
                            'authorization_encrypted_response_alg'];

// For an endpoint about to encrypt a response to `clientId`: fetch its
// jwks_uri where it registered one, no inline jwks, and an encrypted
// response. The verifiers fetch for themselves (`ensurePartyKeys()` in
// `assertion_grant.js`), so this dials nothing for a client that asked for
// no encryption. Never rejects.
function ensureFor(clientId, kid) {
  log.debug("Entering ensureFor().");
  if (!clientId) {
    log.debug("Leaving ensureFor(). No client.");
    return Promise.resolve(null);
  }
  const applications = require('../common/applications');
  const registered = applications.registrationOf(String(clientId)) || {};
  const encrypts = ENCRYPTION_MEMBERS.some(function (member) {
    return !!registered[member];
  });
  if (!registered.jwks_uri || registered.jwks || !encrypts) {
    log.debug("Leaving ensureFor(). No jwks_uri to fetch.");
    return Promise.resolve(null);
  }
  log.debug("Leaving ensureFor(). Fetching.");
  return ensure(registered.jwks_uri, kid).then(function (answer) {
    return answer;
  }, function (e) {
    log.debug("Caught in ensureFor(): " + ((e && e.message) || e));
    // ensure() never rejects; this is a belt for a bug in it.
    return null;
  });
}

// The `kid` in a compact JWS's protected header, or '' — read UNVERIFIED, and
// only to choose whether to fetch again.
function kidOf(jws) {
  log.debug("Entering kidOf().");
  let kid = '';
  try {
    kid = String(JSON.parse(Buffer.from(String(jws || '').split('.')[0],
                                        'base64url').toString('utf8')).kid ||
                 '');
  } catch (e) {
    log.debug("Caught in kidOf(): " + ((e && e.message) || e));
    // Unreadable: no kid to look for.
    kid = '';
  }
  log.debug("Leaving kidOf().");
  return kid;
}

module.exports = {
  MAX_CACHED_KEY_SETS: MAX_CACHED_KEY_SETS,
  cachedKeys: cachedKeys,
  ensure: ensure,
  ensureFor: ensureFor,
  kidOf: kidOf
};
