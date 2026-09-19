// @ts-check
'use strict';
//
// File: helpers.js
//
// ---------------------------------------------------------------------------
// The things every other module of this mock needs, and nothing that belongs to
// one protocol.
//
// Three kinds of thing live here, and the reason each is shared rather than
// owned is worth knowing before moving anything out:
//
//   * the LOG and the artifact log. This mock exists to show what it did, so
//     every module writes to one logger at one level.
//   * the KEYS. One key set per trust realm — an RSA key pair and the curve
//     and post-quantum keys beside it — signs everything (SAML assertions,
//     every JWT, the RFC 8414 and OID4VCI metadata, the DID documents), and
//     one BBS key pair signs every ldp_vc credential. They are made once per
//     start in development mode (once, then kept, in product mode — see
//     `keystore.js`), so they cannot be per-module: two modules generating
//     their own would publish two keys under one issuer and the symptom is
//     "the signature does not verify".
//   * the small helpers that more than one protocol needs — base64url, the
//     request's own base URL, a body parser that copes with form or JSON, the
//     two error-response shapes, and the mock's one user.
//
// The last group is why this file exists at all rather than each protocol
// keeping its own: `userFor`, `parseBody`, `bodyValues`, `oauthError`,
// `signJwt` and `vciError` were used across the OAuth2, OID4VCI and OID4VP
// sections, and leaving them in any one of those made the modules require each
// other in a CYCLE (the offer pages need the mock user; the authorization
// server needs the offer state). A cycle in node does not fail loudly — it
// hands back a half-initialised module whose exports are undefined, and the
// failure surfaces later as a function that is not a function. Keeping the
// shared leaves here is what makes the dependency graph a tree.
// ---------------------------------------------------------------------------

// CONFIG_FILE is made ABSOLUTE before it is read. This module lives in a
// subdirectory now, and a relative `./env/local.js` resolves against THIS
// directory rather than the package root — see common/config_file.js, which is
// required first for that reason and requires nothing itself.
require('./config_file').resolveConfigFile();
// NOTE that this module no longer requires CONFIG_FILE itself. It did — for the
// log level, before config.js existed — and the binding was dead by the time
// this was written, which mattered once CONFIG_FILE became optional: an unset
// variable made `require(undefined)` throw a TypeError naming an "id" argument
// nobody typed, out of a module that had no use for what it was loading.
// resolveConfigFile() above is still called, because eleven OTHER modules read
// the variable directly and this is one of the three places that runs early
// enough to make it absolute for them.
//
// Every setting this service has, resolved from the runtime overrides, the
// environment, and the two appconfig files in that order.
// It is BELOW this module in the dependency graph and requires nothing from
// here, which is what keeps the graph a tree (rule 3).
const config = require('./config');
const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const bunyan = require("bunyan");
const bbs2023 = require('./vendored/bbs2023.js');
// ---------------------------------------------------------------------------
// THE ONE PLACE THIS SERVICE SIGNS, VERIFIES, ENCRYPTS AND DECRYPTS, since
// 2026-08-27. It is a LEAF — it requires npm packages, the vendored XML signer
// and `config.js`, which requires nothing here — so this require is downward
// and cannot close a cycle. **IT MUST STAY THAT WAY**: `crypto.js` may never
// require this file back, which is why every function over there takes the key
// it is to use as a parameter rather than reaching for `STS`. The realm-aware
// half of that — one key per realm, and `STS` as a view onto the current one —
// is below and stays here.
// ---------------------------------------------------------------------------
const stsCrypto = require('./crypto');
// THE KEYSTORE. A LEAF (rule 3) requiring `config`, `crypto`, `mode`,
// `realms`, `secrets` and a few other leaves — and NOT this module, which is
// what keeps it requirable from here. It answers null for every realm in
// development mode, so requiring it changes nothing about how a development
// service starts.
const keystore = require('./keystore');
const pqJose = require('./pq_jose');
// TRUST REALMS. Two things in this file are per realm and both are here rather
// than in twenty modules for the same reason: this is where every one of them
// already looks. `baseUrlOf()` is how eighty call sites build a URL, and `STS`
// is how eight of them reach a signing key. realms.js requires config.js and
// nothing else here, so this cannot be a cycle.
const realms = require('./realms');
// A LEAF over `config` alone (see its header), so this require can close no
// cycle. `userFor()` asks it whether to invent persona values.
const mode = require('./mode');
// The registry of failure codes, a LEAF that requires nothing. NOT audit.js,
// which requires this file: a failure logged here leads with
// `errorCodes.tag()` rather than writing a row.
const errorCodes = require('./error_codes');
const cacheRegistry = require('./cache_registry');
// WHICH `x5c` OR `x5u` A SIGNED TOKEN CARRIES, per use case and per realm
// (2026-09-13). It requires `config`, `realms` and `error_codes` and reaches
// back into this file only lazily, inside a function, so this require closes
// no cycle. `certificateHeaderFor()` below is the one caller.
const certificateHeader = require('./jose_certificate_header');
// WHICH `kid` A SIGNED TOKEN CARRIES — this service's own name for the key, or
// its RFC 9278 thumbprint URI — per realm (2026-09-13). It requires `config`,
// `crypto` and `error_codes` and nothing that requires it back.
// `publishedKidFor()` and `kidNamesKey()` below are the callers.
const joseKid = require('./jose_kid');
// WHICH HOPS MAY SAY WHERE A REQUEST CAME FROM (2026-09-14, #46). A LEAF that
// requires `net`, bunyan and `config` only. `forwardedFrom()` below asks it
// whether a request's forwarded headers are believed at all — the connection's
// peer must be one of `global.trustedProxies` when that is set. It is in the
// parent project's Kerberos COPY set through this file (kerberos/CLAUDE.md).
const clientAddress = require('./client_address');
const log = bunyan.createLogger({ name: 'sts',
                                level: config.value('global.logLevel') });
// Registering it is what makes global.logLevel a setting rather than a claim:
// bunyan takes a level when the logger is created, so without this
// /admin/config could change the setting and every line after it would still be
// written at the level the process started with. This is the logger every
// protocol module destructures, so it is nearly all of them; see the note in
// config.js for the eight vendored krb5_* modules that cannot be registered.
config.registerLogger(log);
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Logging helpers.
//
// This is a mock whose whole purpose is to show what it did, so everything it
// produces is written down at debug level: the artifact BEFORE it was signed or
// encrypted, the artifact AFTER, and — for every endpoint — the request that
// came in, the response that went back, the status code and how long it took.
// ---------------------------------------------------------------------------

// A security artifact, recorded before and after it was protected.
//
//   what   'SAML assertion' / 'JWT' / 'SD-JWT VC' ...
//   stage  'before signing' / 'after signing' / 'before encryption' / ...
//   value  the object or string itself, recorded in full
function logArtifact(what, stage, value) {
  log.debug("Entering logArtifact().");
  log.debug({ artifact: what,
              stage: stage,
              value: (typeof value === 'string') ? value :
                      JSON.stringify(value) },
            what + ' ' + stage + '.');
  log.debug("Leaving logArtifact().");
}

// Headers with nothing removed: this mock issues test credentials only, and the
// point of the log is to be able to see exactly what was exchanged.
function headersOf(source) {
  log.debug("Entering headersOf().");
  const out = {};
  Object.keys(source || {}).forEach(function (k) { out[k] = source[k]; });
  log.debug("Leaving headersOf().");
  return out;
}

// Bodies arrive (and leave) as strings or objects; either way they go in whole.
function bodyOf(value) {
  log.debug("Entering bodyOf().");
  if (value === undefined || value === null) {
    log.debug("Leaving bodyOf().");
    return '';
  }
  log.debug("Leaving bodyOf().");
  return (typeof value === 'string') ? value : JSON.stringify(value);
}

// ---------------------------------------------------------------------------
// The one hook admin_stats.js needs, and the reason it is a hook rather than a
// require.
//
// The admin console has to know about every JWT this service issues, and
// signJwt() below is the single place all of them are minted — so counting them
// anywhere else would mean counting them at five call sites and forgetting the
// sixth. But `admin_stats.js` requires THIS file (it needs the log), so this
// file cannot require it back: a cycle in node hands back a half-initialised
// module whose exports are undefined, and the symptom arrives later as
// something that is not a function.
//
// So the direction is inverted. This file, the leaf, offers a slot;
// admin_stats.js installs itself in it at ITS require time. app.js requires
// admin_stats.js — which is not a trick to make the ordering work but a genuine
// dependency, since the call log in app.js is where the per-endpoint statistics
// are collected — and every protocol module requires app.js, so the recorder is
// installed before any route exists and therefore before any token can be
// minted.
//
// The recorder is called for its side effect only and its return value is
// ignored: statistics must never be able to stop a token being issued.
let jwtRecorder = null;

function setJwtRecorder(fn) {
  log.debug("Entering setJwtRecorder().");
  jwtRecorder = fn;
  log.debug("A JWT recorder was installed; every token this service signs " +
            "will now be counted.");
  log.debug("Leaving setJwtRecorder().");
}

// ---------------------------------------------------------------------------
// THE SUBJECT RESOLVER: A PERSON'S `sub` COMES FROM THEIR DIRECTORY ENTRY
// (2026-09-14).
//
// `userFor()` below minted `urn:sts:user:<username>` from the name alone. A
// rename changed it, and a person deleted and re-created under the same name
// inherited it — the account-recycling hole a relying party linking accounts
// on `sub` falls straight into. It is `urn:uuid:<entryUUID>` now, in both
// modes, and the UUID is on the entry: `ldap/ldap_server.js` assigns it and
// fills this slot with the two lookups. `authn/CLAUDE.md`, *What an
// authenticated identity is here*, carries the design.
//
// A SLOT FOR `setJwtRecorder()`'s REASON: this file is the leaf, the directory
// requires it, and a require the other way would close a cycle and register
// every directory route at #3. Rule 3e's test answers yes both ways round.
//
// **A PROCESS WITH NO DIRECTORY HAS NO SUBJECTS.** Nothing fills this slot in
// a module test that never requires the directory, or in the remote PEP
// container's shim, and `userFor()` then answers `sub: ''` — not the old
// name-derived form, which would be a second spelling of a subject that no
// running service issues any more.
// ---------------------------------------------------------------------------
let subjectResolver = null;

// The one subject form this service issued before 2026-09-14. It is still READ
// — refresh tokens, stored consent and another instance's tokens carry it —
// and never written.
const LEGACY_SUBJECT_PREFIX = 'urn:sts:user:';

// Whether this process can issue a subject at all. A caller that REFUSES a
// person with no entry asks this first, because in a process with no directory
// everybody has no entry and refusing them all would refuse every module test.
function hasSubjectResolver() {
  log.debug("Entering hasSubjectResolver().");
  log.debug("Leaving hasSubjectResolver().");
  return !!subjectResolver;
}

function setSubjectResolver(resolver) {
  log.debug("Entering setSubjectResolver().");
  if (!resolver || typeof resolver.subjectFor !== 'function' ||
      typeof resolver.nameFor !== 'function') {
    log.error(errorCodes.tag('STS-CORE-0090') +
              'helpers: setSubjectResolver() was given an object without ' +
              'both subjectFor() and nameFor(), and it was ignored. No ' +
              'person in this process will be issued a subject.');
    log.debug("Leaving setSubjectResolver(). Refused.");
    return;
  }
  subjectResolver = resolver;
  log.debug("Leaving setSubjectResolver(). Installed.");
}

// A person's subject, or '' where the directory holds no entry for them (or
// there is no directory). Never throws: a lookup that fails is a person with
// no subject, which every caller already has to handle.
function subjectForName(name) {
  log.debug("Entering subjectForName().");
  if (!subjectResolver || !name) {
    log.debug("Leaving subjectForName(). No resolver or no name.");
    return '';
  }
  try {
    const sub = String(subjectResolver.subjectFor(String(name)) || '');
    log.debug("Leaving subjectForName().");
    return sub;
  } catch (e) {
    log.error(errorCodes.tag('STS-CORE-0091') +
              'helpers: the subject resolver threw for "' + name + '" and ' +
              'the person was given no subject: ' + ((e && e.message) || e));
    log.debug("Leaving subjectForName(). The resolver threw.");
    return '';
  }
}

// Who a subject names, as the name this service files a person under, or ''.
// Both forms: `urn:uuid:` is looked up, `urn:sts:user:` is read, and anything
// else is not a subject this service issued.
function nameForSubject(sub) {
  log.debug("Entering nameForSubject().");
  const text = String(sub == null ? '' : sub).trim();
  if (text.indexOf(LEGACY_SUBJECT_PREFIX) === 0) {
    log.debug("Leaving nameForSubject(). The legacy form.");
    return text.slice(LEGACY_SUBJECT_PREFIX.length);
  }
  if (!/^urn:uuid:/i.test(text) || !subjectResolver) {
    log.debug("Leaving nameForSubject(). Not a subject this service issues.");
    return '';
  }
  try {
    const name = String(subjectResolver.nameFor(text) || '');
    log.debug("Leaving nameForSubject().");
    return name;
  } catch (e) {
    log.error(errorCodes.tag('STS-CORE-0091') +
              'helpers: the subject resolver threw looking up a subject and ' +
              'it was treated as naming nobody: ' + ((e && e.message) || e));
    log.debug("Leaving nameForSubject(). The resolver threw.");
    return '';
  }
}

// Read once, because the listener is bound with it before anything can ask
// for it again; config.js marks it restart-only for that reason and refuses
// to change it while this process runs.
const PORT = config.value('global.port');

// The bind address, likewise fixed once. 0.0.0.0 is every interface, which is
// what a container needs.
const HOST = config.value('global.host');

// ---------------------------------------------------------------------------
// ISSUER USED TO LIVE HERE, and it was ONE value doing three jobs: the SAML
// <Issuer>, the `iss` of the WS-Trust JWT, and the WS-Federation entityID.
// They shared a default and nothing else — an entityID names the identity
// provider, an Issuer names whoever signed an assertion — so a deployment
// that needed one of them to be its own real name had to change all three.
//
// They are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId` in
// config.js, all three still defaulting to `urn:wstrust:mock:sts` and all
// three still fed by STS_ISSUER when it is set, so nothing that worked before
// changed. Callers read them from config.js directly rather than through a
// re-export here: they are runtime-settable, so a constant captured at
// require time would be the one thing the console could not change.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE OPENID4VCI CREDENTIAL REQUEST-ENCRYPTION KEY IS A MEMBER OF THE REALM'S
// KEY SET (2026-09-12).
//
// OID4VCI section 10: the ISSUER publishes a key in
// `credential_request_encryption.jwks` and a wallet encrypts its Credential
// Request to it. That key lived in `oid4vc/vc_issuer.ts` until this date as a
// thing of its own — generated at module load, handed to request workers
// through `process.env.STS_VCI_REQUEST_ENC_KEY_PEM`, persisted in no mode — and
// every trust realm in a pooled process shared the one key the pool handed
// down, so a realm's issuer could decrypt a request encrypted to ANOTHER
// realm's published key. `common/mode.js` carried it as NOT_YET.
//
// **EVERY PROPERTY IT LACKED IS ONE THE KEY SET ALREADY HAS**, which is the
// whole argument for putting it here rather than building those properties a
// second time: one per realm (`stsKeysFor` is `realms.keyed()`), written down
// and sealed in product mode (`keystore.js`'s `sts_keys` row), decrypted only
// while it is used (`keys.plaintextRetention`), and agreed across the front
// process and every request worker by the first-generator-wins key channel. A
// second mechanism for one more private key would have been a second answer
// to *where does this service keep a private key* — `pki.js`'s placement
// argument, made for the same reason.
//
// **IT IS A PLAIN KEY AND DELIBERATELY NOT A LEAF OF THE PKI HIERARCHY.** The
// signing keys are certified because a certificate is how a relying party that
// never fetched this service's JWKS can decide to trust a signature — `x5c`,
// the SAML metadata, `/sts/cert`. Nothing of that shape exists for this key:
// section 10 publishes a bare JWK, a wallet trusts it because it read it out of
// metadata it fetched over TLS from the issuer itself, and no wallet looks for
// a certificate on it or would validate one. A leaf here would also be the
// wrong KIND of leaf — every certificate `pki.js` issues from a use case is a
// SIGNING certificate (`digitalSignature`), and this key only ever DECRYPTS —
// so certifying it would mean a key-encipherment profile nothing reads,
// published nowhere, and a certificate whose only effect is a second thing to
// rotate. The kid is derived from the key material instead, exactly as the
// curve keys' are.
//
// Its size is `oid4vci.requestEncryptionKeyBits`, read in the realm the key is
// being made for — the caller enters that realm — so a realm carrying the
// setting gets the size it asked for. A change reaches key sets made AFTER it
// and never a key that exists, which is what that setting's row says.
// ---------------------------------------------------------------------------
const VCI_REQUEST_ENC_ALG = 'RSA-OAEP-256';

// The public JWK a request-encryption private key publishes, with the members
// section 10 requires: `alg` (the algorithm is a property of the key, and
// there is no alg_values_supported for requests), `kid` (a JWE encrypted to a
// key with a kid MUST repeat it), `use` and `key_ops`. The kid prefix is the
// one `vc_issuer.js` used, so a wallet sees the same shape it always did.
function requestEncryptionJwkOf(privateKey) {
  log.debug("Entering requestEncryptionJwkOf().");
  const publicJwk = crypto.createPublicKey(privateKey)
                          .export({ format: 'jwk' });
  const thumbprint = stsCrypto.jwkThumbprint(publicJwk, { truncate: 16 });
  log.debug("Leaving requestEncryptionJwkOf().");
  return Object.assign({}, publicJwk, {
    kid: 'sts-req-enc-' + thumbprint,
    alg: VCI_REQUEST_ENC_ALG,
    use: 'enc',
    key_ops: ['encrypt']
  });
}

// `made` is an RSA pair generated OFF the event loop by `prepareKeySet()`
// (2026-09-14); absent, the pair is generated here, as it always was.
function makeRequestEncryptionKey(made) {
  log.debug("Entering makeRequestEncryptionKey().");
  const bits = rsaBitsFor('oid4vci.requestEncryptionKeyBits');
  const pair = made ||
               crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  const out = { privateKey: pair.privateKey,
                publicJwk: requestEncryptionJwkOf(pair.privateKey) };
  log.debug("Leaving makeRequestEncryptionKey(). " + bits + " bits, kid=" +
            out.publicJwk.kid);
  return out;
}

// ---------------------------------------------------------------------------
// THE REFRESH-TOKEN ENCRYPTION KEYS (2026-09-12).
//
// Every refresh token this service issues is a signed JWT ENCRYPTED to its own
// realm — `oauth-oidc/refresh_token_crypto.ts` does the sealing and argues it.
// These are the keys, and there are three because JWE key management comes in
// three kinds and the algorithm is a setting
// (`oauth2.refreshTokenEncryptionAlg`):
//
//   rsa     RSA-OAEP and RSA-OAEP-256
//   ec      ECDH-ES and its three key-wrapping variants
//   secret  A128KW..A256KW, A128GCMKW..A256GCMKW, dir, PBES2 — 64 random bytes,
//           from which the exact key size each needs is DERIVED, because those
//           algorithms have no key derivation of their own (RFC 7518 section 4.4)
//
// **ALL THREE ARE MADE, WHICHEVER ALGORITHM IS CONFIGURED.** A token already in
// a client's hands was sealed under the algorithm in force THEN; holding every
// kind means changing the setting never strands one, and the decrypt path
// simply picks the key the JWE header's `alg` names.
//
// **UNIQUE PER REALM** because the set is (`stsKeysFor` is `realms.keyed()`),
// and that is a property worth having rather than an accident: a refresh token
// minted in one realm does not open in another, so a realm is a cryptographic
// boundary for its refresh tokens and not merely a routing one.
//
// **A PLAIN KEY AND NOT A PKI LEAF**, for `makeRequestEncryptionKey()`'s reason
// below, more strongly: these keys are never published — a refresh token is
// opaque to its client (RFC 6749 section 1.5) and the only party that ever
// encrypts to or decrypts with them is this service. A certificate would be a
// statement to nobody. The kids are derived from the key material, so two
// realms or two instances cannot name different keys alike.
//
// The RSA size is `oauth2.refreshTokenEncryptionKeyBits` and the curve
// `oauth2.refreshTokenEncryptionCurve`, read in the realm the keys are made
// for; a change reaches key sets made after it and never keys that exist.
// ---------------------------------------------------------------------------
const REFRESH_TOKEN_SECRET_BYTES = 64;

const REFRESH_TOKEN_CURVES = { 'P-256': 'prime256v1', 'P-384': 'secp384r1',
                               'P-521': 'secp521r1' };

function refreshTokenJwkOf(privateKey, kind) {
  log.debug("Entering refreshTokenJwkOf().");
  const publicJwk = crypto.createPublicKey(privateKey)
                          .export({ format: 'jwk' });
  const thumbprint = stsCrypto.jwkThumbprint(publicJwk, { truncate: 16 });
  log.debug("Leaving refreshTokenJwkOf().");
  return Object.assign({}, publicJwk, {
    kid: 'sts-rt-' + kind + '-' + thumbprint,
    use: 'enc'
  });
}

function makeRefreshTokenEncryptionKeys(madeRsa) {
  log.debug("Entering makeRefreshTokenEncryptionKeys().");
  const bits = rsaBitsFor('oauth2.refreshTokenEncryptionKeyBits');
  const curveName = String(config.value('oauth2.refreshTokenEncryptionCurve') ||
                           'P-256');
  const curve = REFRESH_TOKEN_CURVES[curveName] ||
                REFRESH_TOKEN_CURVES['P-256'];
  const rsa = madeRsa ||
              crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: curve });
  const secret = crypto.randomBytes(REFRESH_TOKEN_SECRET_BYTES);
  const out = {
    rsa: { privateKey: rsa.privateKey,
           publicJwk: refreshTokenJwkOf(rsa.privateKey, 'rsa') },
    ec: { privateKey: ec.privateKey,
          publicJwk: refreshTokenJwkOf(ec.privateKey, 'ec') },
    secret: secret,
    // A kid for the secret too, so a JWE sealed under a symmetric algorithm
    // names which realm's secret opened it. A hash of 64 random bytes reveals
    // nothing usable about them, and it is never published anyway.
    secretKid: 'sts-rt-secret-' +
      crypto.createHash('sha256')
            .update(secret)
            .digest('base64url')
            .slice(0, 16)
  };
  log.debug("Leaving makeRefreshTokenEncryptionKeys(). rsa " + bits +
            " bits, " +
            curveName + ", kid=" + out.rsa.publicJwk.kid);
  return out;
}

// ---------------------------------------------------------------------------
// THE REQUEST OBJECT ENCRYPTION KEYS (2026-09-13).
//
// RFC 9101 section 6.1 lets a client ENCRYPT its request object to the
// authorization server, and the key it encrypts to is one this server
// PUBLISHES — so, unlike the refresh-token keys above, these two are in
// `/oauth2/jwks`, marked `use: "enc"`. `oauth-oidc/request_object.ts` decrypts
// with them. An RSA pair for RSA-OAEP and RSA-OAEP-256, an EC pair for ECDH-ES
// and its key-wrapping variants; the symmetric algorithms are keyed by the
// client's own secret and need no key here.
//
// **A MEMBER OF THE KEY SET, NOT A KEY OF ITS OWN**, for the reason the
// OpenID4VCI request-encryption key and the refresh-token keys are: the set is
// the unit the key channel agrees, the keystore seals and a realm owns, so a
// member made with it is per realm, persisted in product mode and the same in
// every process by construction. **AND A DIFFERENT KEY FROM EACH OF THOSE
// TWO**, deliberately: the OpenID4VCI key is published in another document for
// another protocol, and the refresh-token keys are never published at all — a
// key a client may encrypt to must not also open this service's own tokens.
//
// **PLAIN KEYS AND NOT PKI LEAVES**, `makeRequestEncryptionKey()`'s reason: a
// client trusts them because it read them out of this server's JWKS over TLS,
// and every certificate `pki.js` issues from a use case is a SIGNING one.
// ---------------------------------------------------------------------------
function requestObjectJwkOf(privateKey, kind) {
  log.debug("Entering requestObjectJwkOf().");
  const publicJwk = crypto.createPublicKey(privateKey)
                          .export({ format: 'jwk' });
  const thumbprint = stsCrypto.jwkThumbprint(publicJwk, { truncate: 16 });
  log.debug("Leaving requestObjectJwkOf().");
  return Object.assign({}, publicJwk, {
    kid: 'sts-ro-' + kind + '-' + thumbprint,
    use: 'enc'
  });
}

function makeRequestObjectEncryptionKeys(madeRsa) {
  log.debug("Entering makeRequestObjectEncryptionKeys().");
  const bits = rsaBitsFor('oauth2.requestObjectEncryptionKeyBits');
  const curveName = String(config.value(
    'oauth2.requestObjectEncryptionCurve') || 'P-256');
  const curve = REFRESH_TOKEN_CURVES[curveName] ||
                REFRESH_TOKEN_CURVES['P-256'];
  const rsa = madeRsa ||
              crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: curve });
  const out = {
    rsa: { privateKey: rsa.privateKey,
           publicJwk: requestObjectJwkOf(rsa.privateKey, 'rsa') },
    ec: { privateKey: ec.privateKey,
          publicJwk: requestObjectJwkOf(ec.privateKey, 'ec') }
  };
  log.debug("Leaving makeRequestObjectEncryptionKeys(). rsa " + bits +
            " bits, " + curveName + ", kids=" + out.rsa.publicJwk.kid + ", " +
            out.ec.publicJwk.kid);
  return out;
}

// The RSA size a member of the key set is made at, read in the realm the set
// is for. ONE reading for the synchronous maker and the asynchronous one, so a
// set prepared off the loop is the size a set made on it would have been.
function rsaBitsFor(key) {
  log.debug("Entering rsaBitsFor().");
  log.debug("Leaving rsaBitsFor().");
  return Number(config.value(key)) || 2048;
}

// The service signing key is 2048 bits and not a setting.
const STS_SIGNING_KEY_BITS = 2048;

// --- STS signing key/cert (generated once at startup) ----------------------
// `made` (2026-09-14) is the four RSA pairs `prepareKeySet()` generated in
// node's thread pool — `{ signingPem, vci, refresh, requestObject }` — and
// absent it everything is generated here, synchronously, exactly as before.
// The rest of the set (six curve keys, a 64-byte secret, a certificate
// signature) is a few tens of milliseconds and is built here either way, so
// there is ONE assembly of a key set and the two doors cannot disagree about
// its shape.
function makeStsKeys(made) {
  log.debug("Entering makeStsKeys().");
  const pre = made || {};
  // The RSA keygen-and-self-sign skeleton is shared with `tls/tls_server.js`,
  // which builds a very different certificate — a TLS server certificate lives
  // or dies by its subjectAltName and this one carries no extensions at all.
  // What they had in common was the twenty lines of forge boilerplate, and that
  // is what moved; the differences stayed as arguments.
  const keys = stsCrypto.selfSignedRsaCertificate({
    bits: STS_SIGNING_KEY_BITS,
    rsaPrivateKeyPem: pre.signingPem,
    commonName: 'ws-trust-sts',
    // The LEADING BYTE of a random serial, and not arbitrary: the TLS
    // listener's certificate is '03', so a person looking at two of this
    // service's certificates in a packet capture can tell which is which. It
    // was the WHOLE serial until 2026-09-01, and a constant serial over a key
    // regenerated at every start is what Firefox reports as
    // SEC_ERROR_REUSED_ISSUER_AND_SERIAL — see certificateSerial() in
    // common/crypto.js.
    serialPrefix: '02',
    years: 5
  });
  // -------------------------------------------------------------------------
  // THE OTHER SIGNING KEYS, AND WHY THEY ARE GENERATED UNCONDITIONALLY.
  //
  // This service advertised RS* and PS* for a signed UserInfo response and NOT
  // ES* or EdDSA, and the reason was never that it could not perform them — it
  // was that the only key here was RSA, so there was nothing for a client to
  // verify an ES256 signature against. That is a capability withheld because a
  // key pair was not generated, which is the wrong reason for a debugging tool
  // to refuse anything: the algorithm a person came here to reproduce is
  // exactly the one their real identity provider uses.
  //
  // So every curve the JOSE registry names for a signature gets a key, at
  // startup, always. The cost is the argument for doing it rather than against:
  // the RSA key above is ~100ms and these six together (four when this was
  // written) are a few milliseconds, so they are free beside what this
  // function already spends.
  // They are NOT lazy for the same reason — a lazily-made key is one that might
  // not exist when the JWKS is published, and a JWKS that varies by what has
  // been asked for is a JWKS a client cannot cache.
  //
  // Each gets a `kid` of its own derived from its own public key, so the
  // reasoning about kid collisions above holds per key rather than per service.
  // -------------------------------------------------------------------------
  const extraKeys = [
    { alg: 'ES256', kty: 'EC', gen: ['ec', { namedCurve: 'prime256v1' }] },
    { alg: 'ES384', kty: 'EC', gen: ['ec', { namedCurve: 'secp384r1' }] },
    { alg: 'ES512', kty: 'EC', gen: ['ec', { namedCurve: 'secp521r1' }] },
    // secp256k1 (RFC 8812). Its curve is not one of the three NIST ones and
    // node's OpenSSL has it anyway; what it costs is a signature FORMAT
    // conversion at signing time, in stsCrypto.signJws(), because the library
    // that signs everything else here has no ES256K at all.
    { alg: 'ES256K', kty: 'EC', gen: ['ec', { namedCurve: 'secp256k1' }] },
    { alg: 'EdDSA', kty: 'OKP', gen: ['ed25519', undefined] },
    // ED448, AND WHY IT NEEDS A SECOND ENTRY UNDER THE SAME `alg`.
    //
    // RFC 8037 registers ONE algorithm value for both Edwards curves — the
    // curve lives in the key's `crv` — so a client that registers
    // `id_token_signed_response_alg: "EdDSA"` has not said which it wants and
    // there is no member for it to say so with. Both keys are therefore
    // published, with different `kid`s, and `oauth2.eddsaCurve` decides which
    // one signs. A verifier follows the `kid` in the header and needs to know
    // nothing about the setting.
    //
    // Publishing both rather than only the configured one is deliberate: a
    // JWKS that changed shape when a setting changed would strand every client
    // holding a cached copy.
    { alg: 'EdDSA', curve: 'Ed448', kty: 'OKP', gen: ['ed448', undefined] }
  ].map(function (spec) {
    // `any`: the key type is a table value, and the overloads want literals.
    const generate = /** @type {any} */ (crypto.generateKeyPairSync);
    const pair = spec.gen[1]
      ? generate(spec.gen[0], spec.gen[1])
      : generate(spec.gen[0]);
    const publicJwk = pair.publicKey.export({ format: 'jwk' });
    // The kid is derived from the key's own public material, the way the RSA
    // one is derived from its certificate: two instances of this mock must not
    // publish one name over two different keys.
    const material = JSON.stringify([publicJwk.crv, publicJwk.x,
                                     publicJwk.y || '']);
    return {
      alg: spec.alg,
      privateKey: pair.privateKey,
      // The kid names the CURVE as well as the algorithm, because the two
      // EdDSA entries share an `alg` and a kid that did not tell them apart
      // would be one name over two keys — the collision this whole scheme
      // exists to avoid.
      publicJwk: Object.assign({ use: 'sig', alg: spec.alg }, publicJwk,
        { kid: 'sts-' +
          (spec.curve || spec.alg).toLowerCase() + '-' +
          forge.md.sha256.create()
                         .update(material)
                         .digest()
                         .toHex()
                         .slice(0, 8) })
    };
  });

  log.debug("Leaving makeStsKeys(). " + (extraKeys.length + 1) + " key(s).");
  return {
    privateKeyPem: keys.privateKeyPem,
    certPem: keys.certPem,
    certB64: keys.certB64,
    // Keyed by JOSE `alg` so a signer can ask for what it needs by name. The
    // RSA key is deliberately NOT in here: it is `privateKey`/`kid` above,
    // where eight modules already read it, and moving it would have been a
    // change to every one of them for no gain.
    extraKeys: extraKeys,
    // THE OPENID4VCI REQUEST-ENCRYPTION KEY, made WITH the set rather than
    // lazily, for the reason the curve keys above are eager: the set is the
    // unit the key channel arbitrates, so a member made with it is agreed with
    // it, and a member made later has to win a second race. See
    // makeRequestEncryptionKey() for why it is a plain key and not a leaf.
    vciRequestEncKey: makeRequestEncryptionKey(pre.vci),
    // THE REFRESH-TOKEN ENCRYPTION KEYS, made with the set for the same reason
    // as the request-encryption key: the set is what the key channel agrees.
    refreshTokenEncKeys: makeRefreshTokenEncryptionKeys(pre.refresh),
    // THE REQUEST OBJECT ENCRYPTION KEYS (RFC 9101), made with the set for the
    // same reason — see makeRequestObjectEncryptionKeys().
    requestObjectEncKeys: makeRequestObjectEncryptionKeys(pre.requestObject),
    // A `kid` names a KEY, so it is derived from the key material rather than
    // hard-coded. This key is regenerated on every start, and the kid was
    // previously a constant — so two instances of this mock (a stale container
    // beside a fresh one, or two ports during development) published the SAME
    // kid over DIFFERENT keys. A verifier matches the kid exactly, tries that
    // one key, fails, and reports "the signature does not verify", which reads
    // like a corrupt document instead of what it is: keys fetched from the
    // wrong instance. A per-key kid cannot collide, so the mismatch names
    // itself. **DERIVED FROM THE BASE64 TEXT AND NOT FROM THE DER**, which is
    // why this is not `stsCrypto.certificateThumbprint()`. That function hashes
    // the DER, as RFC 8705's `x5t#S256` and SPIRE's authority id both require,
    // and would produce a DIFFERENT value here. A kid is an opaque name and
    // either would do — but changing it would change every JWKS this service
    // has ever published, and a verifier matching a cached kid would report
    // "the signature does not verify" rather than "the key was renamed".
    kid: kidOf(keys.certB64)
  };
}

// ---------------------------------------------------------------------------
// THE `kid` DERIVATION, IN ONE PLACE. It was written out three times once
// `plainKeySet()` joined makeStsKeys() and lazyKeySet(), and the comment in
// makeStsKeys() explains exactly why a third copy is the wrong direction: the
// kid is DERIVED and never stored, so the only thing keeping the copies equal
// was that nobody had edited one of them yet. Changing it changes every JWKS
// this service has ever published, so it changes here or nowhere.
function kidOf(certB64) {
  log.debug("Entering kidOf().");
  log.debug("Leaving kidOf().");
  return 'sts-' +
    forge.md.sha256.create().update(certB64).digest().toHex().slice(0, 12);
}

// A key set this process can use directly, built from what a SIBLING PROCESS
// generated and sent over. It is `lazyKeySet()`'s twin and differs in exactly
// one way, which is the whole reason it exists: the private keys are HERE,
// already parsed, rather than fetched per use from the product-mode keystore.
// Shared material arrives in the clear over the fork's IPC channel and there is
// no key-encryption key in development mode to fetch it back through — routing
// it through the lazy view produced "the realm's signing key is held encrypted
// and could not be decrypted" on the first signature.
function plainKeySet(realmId, stored) {
  log.debug("Entering plainKeySet(). realm=" + realmId);
  const set = {
    realm: realmId,
    createdAt: stored.createdAt || 0,
    privateKeyPem: stored.privateKeyPem,
    // Already KeyObjects — `keystore.deserialise()` parsed them on the way in.
    extraKeys: stored.extraKeys || []
  };
  // **THE SAME CERTIFICATE VIEW AS `lazyKeySet()`, AND IT HAS TO BE THE SAME
  // ONE.** This set is built from what a SIBLING PROCESS sent; the certificate
  // that should be published is the one this realm's Issuing CA minted, read
  // from the store every process shares. A set that kept the self-signed
  // certificate here would make `/oauth2/jwks` answer a different `x5c` — and
  // a different `kid` — depending on which worker took the request, which is
  // the defect `sharedFor()`'s header records in its worst form.
  certifiedView(set, realmId, stored);
  // The parsed RSA key, for makeStsKeys()'s measured reason: parsing the PEM
  // per signature was 21% of non-idle CPU.
  set.privateKey = crypto.createPrivateKey(set.privateKeyPem);
  // The post-quantum half, where the sibling had already made it. Absent means
  // "not warmed yet"; this process will make and republish them.
  if (stored.pqKeys) {
    set.pqKeys = stored.pqKeys;
  }
  // AND THE OPENID4VCI REQUEST-ENCRYPTION KEY, already a KeyObject — the same
  // copy for the same reason, and the one `lazyKeySet()` below has to make as
  // well: a member that travels and is not put back on the set it arrived for
  // is the post-quantum defect `keystore.js` records, and a process holding a
  // set without it would generate one of its own and publish a different key.
  if (stored.vciRequestEncKey) {
    set.vciRequestEncKey = stored.vciRequestEncKey;
  }
  // AND THE REFRESH-TOKEN ENCRYPTION KEYS, for the same reason: dropped here,
  // this process would make its own and seal tokens no sibling can open.
  if (stored.refreshTokenEncKeys) {
    set.refreshTokenEncKeys = stored.refreshTokenEncKeys;
  }
  // AND THE REQUEST OBJECT ENCRYPTION KEYS, for the same reason: dropped here,
  // this process would publish keys of its own and fail to open a request
  // object a client encrypted to the JWKS a sibling served.
  if (stored.requestObjectEncKeys) {
    set.requestObjectEncKeys = stored.requestObjectEncKeys;
  }
  log.debug("Leaving plainKeySet(). kid=" + set.kid);
  return set;
}

// ===========================================================================
// THE CERTIFICATE A KEY SET PUBLISHES (2026-09-11).
//
// `makeStsKeys()` above is UNCHANGED and still gives every key set a
// self-signed certificate at the moment it is generated. What changed is which
// certificate is PUBLISHED: once `common/pki.js` has certified the key under
// this realm's JOSE Issuing CA, that is the one — so `/sts/cert`, the SAML
// metadata, the `x5c` on a JWKS entry and everything else that shows a
// certificate show one that chains to the service Root.
//
// **THE SELF-SIGNED ONE IS KEPT AND IS NOT DEAD CODE.** It is what a key set
// carries in the window between being generated and being certified, what it
// carries for ever when `pki.autoBuild` is off, and what it falls back to if
// the hierarchy could not be built — and `pki.start()` deliberately does not
// stop the service when that happens.
//
// **AND THE `kid` DOES NOT FOLLOW IT. IT STAYS WHAT IT ALWAYS WAS.**
//
// That was the other way round for an hour and the reasoning is worth keeping,
// because the obvious answer is the wrong one. `kidOf()` hashes a certificate,
// so the tempting move is to recompute the kid whenever the published
// certificate changes — and that makes the kid MOVE at the moment a key is
// certified. Before the listener binds that is harmless; for a realm created
// at runtime, whose keys are made lazily on first use, it is a window in which
// a token can be minted under a name that afterwards belongs to nothing.
//
// A `kid` names the KEY. It is derived from the self-signed certificate this
// key set was born with, which is itself derived from the key and never
// changes for the life of that key — so the kid is stable from the instant the
// key exists, the window closes completely, and "keep the startup key
// generation the same by default" stays literally true: the `kid` a client
// sees is byte for byte the one it saw before any of this existed.
//
// Nothing can observe the difference. RFC 7517 section 4.5 makes `kid` a HINT
// with no structure, so a name whose derivation mentions a document that is no
// longer published is a name — and the alternative is a name that moves.
// ===========================================================================
// Schedule the certification of a key set that has just been generated. It is
// a function of its own so that the `require` stays lazy — see
// `certifiedView()` — and so that the fire-and-forget is written down once
// rather than at each of the three places a key set is built.
function certifyLater(realmId, keys) {
  log.debug("Entering certifyLater().");
  setImmediate(function () {
    let pki = null;
    try {
      pki = require('./pki');
    } catch (e) {
      log.debug("Caught in a callback in certifyLater(): " +
                ((e && e.message) || e));
      // No certificate authority in this process. The key set keeps the
      // self-signed certificate it was born with, which is what this service
      // did before the hierarchy existed.
      return;
    }
    Promise.resolve(pki.certifyKeySet(realmId, keys)).then(function (done) {
      if (done && !done.ok && (done.errors || []).length) {
        log.debug('The "' + realmId + '" realm\'s keys were not certified: ' +
                  done.errors.join(' '));
      }
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-CORE-0024') +
                'The "' + realmId + '" realm\'s signing keys could not be ' +
                'certified under its Issuing CAs: ' + e.message + '. They ' +
                'still SIGN — what they lack is a certificate chaining to ' +
                'this service\'s Root.');
    });
  });
  log.debug("Leaving certifyLater().");
}

// ---------------------------------------------------------------------------
// THE SAME, FOR THE ELEVEN POST-QUANTUM KEYS (2026-09-13).
//
// `certifyLater()` runs when a key set is GENERATED, and the post-quantum half
// does not exist then — it is made on first use, seconds later, on the worker
// pool. So it is certified where it is made: `pqKeysFor()` and
// `pqKeysForAsync()` call this once they hold the set this realm keeps.
//
// **ONLY THE PUBLIC JWKS ARE HANDED OVER.** `pki.certifyPqKeys()` reads `alg`
// and `publicJwk` and nothing else, and passing a list without the private
// bytes makes that a property of the call rather than of the callee's manners —
// `common/vendored/CLAUDE.md`'s rule about this service's post-quantum keys and
// the certificate encoder is about exactly that boundary.
// ---------------------------------------------------------------------------
function certifyPqLater(realmId, pqKeys) {
  log.debug("Entering certifyPqLater().");
  const publicHalves = (pqKeys || []).map(function (one) {
    return { alg: one.alg, publicJwk: one.publicJwk };
  });
  setImmediate(function () {
    let pki = null;
    try {
      pki = require('./pki');
    } catch (e) {
      log.debug("Caught in a callback in certifyPqLater(): " +
                ((e && e.message) || e));
      // No certificate authority in this process: the keys go on being
      // published as bare AKP JWKs, which is all they ever were before.
      return;
    }
    Promise.resolve(pki.certifyPqKeys(realmId, publicHalves))
      .then(function (done) {
        if (done && !done.ok && (done.errors || []).length) {
          log.debug('The "' + realmId + '" realm\'s post-quantum keys were ' +
                    'not certified: ' + done.errors.join(' '));
        }
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-CORE-0024') +
                  'The "' + realmId + '" realm\'s post-quantum signing keys ' +
                  'could not be certified under its JOSE Issuing CA: ' +
                  e.message + '. They still SIGN — what they lack is a ' +
                  'certificate chaining to this service\'s Root.');
      });
  });
  log.debug("Leaving certifyPqLater().");
}

function certifiedView(set, realmId, stored) {
  log.debug("Entering certifiedView().");
  // The certificate this key set was BORN with, captured before the getters
  // below are installed — they fall back to it, and reading it off the object
  // they are being defined on would recurse.
  const selfSignedPem = stored.certPem;
  const selfSignedB64 = stored.certB64;
  const published = function () {
    log.debug("Entering published().");
    // `pki.js` is required lazily HERE and not at the top of this file, and it
    // is the one require in helpers.js that is: that module requires
    // `keystore.js`, which this file also requires, and hoisting it would put
    // a certificate authority in the load path of every in-process caller of
    // helpers — the parent project's Kerberos jobs among them — for a
    // certificate most of them never look at.
    let held = null;
    try {
      held = require('./pki').publishedCertificateFor(realmId, 'jose', 'RS256');
    } catch (e) {
      log.debug("Caught in published(): " + ((e && e.message) || e));
      // The hierarchy is not built, or could not be read. The self-signed
      // certificate below is the honest answer and the service goes on
      // exactly as it did before this existed.
      held = null;
    }
    log.debug("Leaving published().");
    return held;
  };
  Object.defineProperty(set, 'certPem', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      const held = published();
      log.debug("Leaving get().");
      return held ? held.certificatePem : selfSignedPem;
    }
  });
  Object.defineProperty(set, 'certB64', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      const held = published();
      log.debug("Leaving get().");
      return held ? stsCrypto.stripPem(held.certificatePem) : selfSignedB64;
    }
  });
  // The chain UNDER the published certificate — the Issuing CA and the
  // Intermediate, leaf-first and without the Root. Empty where the key is
  // self-signed, which is what makes "is this key certified" answerable
  // without asking the store a second time.
  Object.defineProperty(set, 'certChainPem', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      const held = published();
      log.debug("Leaving get().");
      return held ? held.chainPem.slice() : [];
    }
  });
  // A PLAIN VALUE, computed once from the self-signed certificate — see the
  // header. It is assigned rather than left alone because two of the three
  // callers used to set it themselves and one of them (`makeStsKeys()`'s own
  // return) already has it; assigning it here makes all three agree by
  // construction.
  set.kid = kidOf(selfSignedB64);
  // **THE SELF-SIGNED CERTIFICATE IS STILL REACHABLE**, and one caller needs
  // it: `/admin/keys` reports what a key was born with beside what it now
  // publishes, because "this key is certified" is a claim a reader should be
  // able to check rather than take.
  set.selfSignedCertPem = selfSignedPem;
  // **AND THE BASE64 OF IT, WHICH IS WHAT `keystore.serialise()` WRITES DOWN
  // (2026-09-11).** It is the same value the getter above answers before this
  // key is certified, and the whole point is that it goes on answering the
  // same thing afterwards: a SERIALISED key set is identified by its
  // certificate in two places — `publishShared()`'s enrichment test and the
  // `kid` a restored set derives — and both of those are about the KEY, which
  // does not change when a certificate is issued over it.
  //
  // Reading `certB64` there instead was a real defect and not a tidiness
  // point. Once `pki.js` certified a realm's keys the getter started answering
  // the CERTIFIED certificate, so a second publish of the same key set no
  // longer matched the blob already held — which made the post-quantum
  // enrichment look like a different key set every time. It was refused every
  // time, and every process in a dispatched service went on signing ML-DSA and
  // SLH-DSA with eleven keys of its own while publishing somebody else's JWKS.
  set.selfSignedCertB64 = selfSignedB64;
  log.debug("Leaving certifiedView().");
  return set;
}

// ---------------------------------------------------------------------------
// A KEY SET WHOSE PUBLIC HALF IS RESIDENT AND WHOSE PRIVATE HALF IS A GETTER
// (2026-09-06).
//
// Where key material persists, `keystore.js` holds the CIPHERTEXT and decrypts
// on demand — and that buys nothing at all if this file then caches the
// decrypted PEM and the parsed `KeyObject` on an object it keeps for the life
// of the process, which is exactly what it used to do. So the set built here
// holds:
//
//   * everything PUBLIC as an ordinary property — the kid, the certificate,
//     each curve key's public JWK. None of it is a secret, all of it is
//     already published at `/oauth2/jwks`, and the JWKS endpoint walking
//     `extraKeys` must not cause a decrypt;
//   * everything PRIVATE as a GETTER that asks the keystore afresh. That is
//     what re-arms the idle timer on use, and it is why the getter takes the
//     realm ID rather than closing over the material it was built from.
//
// **NOTHING IN THIS FUNCTION MAY CLOSE OVER `stored`.** It is the plaintext
// blob, and a closure holding it would keep the private key reachable for as
// long as the key set exists — which is the life of the process, which is the
// thing being removed. Each getter therefore captures the realm ID and, for a
// curve key, its `kid`, and nothing else. Read `one.publicJwk.kid` out into a
// local before defining the getter; capturing `one` captures the PEM beside it.
//
// The GETTERS ARE ENUMERABLE, because the `STS` proxy forwards `ownKeys` and
// `getOwnPropertyDescriptor` and something that spread this set would otherwise
// come out with no private key at all — a failure that would look like a
// signing bug rather than a visibility one.
//
// The eight modules that do `STS.privateKey` are untouched: a property read of
// a getter is a property read. That is the whole reason the proxy was worth
// having, and this change is the second thing it has paid for.
// ---------------------------------------------------------------------------
function lazyKeySet(realmId, stored) {
  log.debug("Entering lazyKeySet(). realm=" + realmId);
  const set = {
    realm: realmId,
    createdAt: stored.createdAt || 0,
    // `certPem` and `certB64` are GETTERS, installed by `certifiedView()`
    // above: the certificate this key set publishes is the one `common/pki.js`
    // issued for it where there is one, and the self-signed one it was born
    // with where there is not. The `kid` is a plain value DERIVED from the
    // self-signed one — see certifiedView()'s header — so storing it would be
    // storing a derived value, which is how a store comes to disagree with
    // itself after a change to the derivation.
    extraKeys: (stored.extraKeys || []).map(function (one) {
      const kid = one.publicJwk && one.publicJwk.kid;
      const entry = { alg: one.alg, publicJwk: one.publicJwk };
      Object.defineProperty(entry, 'privateKey', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering get().");
          const held = keystore.privateMaterialFor(realmId);
          // A null here means the keystore could not open its own record, and
          // it has already said so loudly. Throwing names the key rather than
          // letting `undefined` reach node's signer, which reports something
          // about a "key" argument and names nothing.
          if (!held) {
            throw new Error('the "' + realmId + '" realm\'s ' + one.alg +
              ' signing key is held encrypted and could not be decrypted; ' +
              'see the keystore errors above.');
          }
          log.debug("Leaving get().");
          return held.extra.get(kid);
        }
      });
      return entry;
    })
  };
  Object.defineProperty(set, 'privateKeyPem', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      const held = keystore.privateMaterialFor(realmId);
      if (!held) {
        throw new Error('the "' + realmId + '" realm\'s signing key is held ' +
          'encrypted and could not be decrypted; see the keystore errors ' +
          'above.');
      }
      log.debug("Leaving get().");
      return held.privateKeyPem;
    }
  });
  Object.defineProperty(set, 'privateKey', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      const held = keystore.privateMaterialFor(realmId);
      if (!held) {
        throw new Error('the "' + realmId + '" realm\'s signing key is held ' +
          'encrypted and could not be decrypted; see the keystore errors ' +
          'above.');
      }
      log.debug("Leaving get().");
      return held.privateKey;
    }
  });
  // ---------------------------------------------------------------------
  // **THE POST-QUANTUM HALF, LAZILY — AND ITS ABSENCE HERE WAS A REAL
  // DIVERGENCE (2026-09-12).**
  //
  // `plainKeySet()` — the SIBLING path — has copied `stored.pqKeys` since the
  // day they started travelling. This one, the STORED path, did not: the set
  // came back without them, `pqKeysForAsync()` saw none and generated eleven
  // more, `publishShared()` refused the offer because another process had got
  // there first, and this process went on signing with what it had made.
  // Three workers, three different ML-DSA kids, and a UserInfo response
  // verifiable only against the worker that signed it.
  //
  // It is a GETTER for the reason every other private key on this set is one:
  // the bytes come out of the keystore on demand and are dropped again on the
  // retention timer. **AND IT HAS A SETTER**, which is not symmetry — 
  // `pqKeysForAsync()` assigns `keys.pqKeys = made` when it really does have
  // to generate them (a realm whose store has none yet), and an accessor with
  // no setter makes that a TypeError in strict mode at the end of a two-second
  // key generation.
  // ---------------------------------------------------------------------
  let pqGenerated = null;
  Object.defineProperty(set, 'pqKeys', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      if (pqGenerated) {
        log.debug("Leaving get().");
        return pqGenerated;
      }
      const held = keystore.privateMaterialFor(realmId);
      log.debug("Leaving get().");
      return (held && held.pq && held.pq.length) ? held.pq : undefined;
    },
    set: function (made) {
      log.debug("Entering set().");
      pqGenerated = made;
      log.debug("Leaving set().");
    }
  });
  // WHETHER THIS SET HOLDS A POST-QUANTUM SET, ANSWERED WITHOUT THE GETTER
  // ABOVE (#74): `/admin/caches` must not decrypt to draw a row. Held means
  // generated in this process, or present in the stored blob — which the
  // getter would decrypt on first use. Non-enumerable, so the JWKS builder's
  // spread and the stored form never see it.
  const storedPq = (stored.pqKeys || []).length > 0;
  Object.defineProperty(set, 'pqHeld', {
    enumerable: false, configurable: true,
    value: function () {
      log.debug("Entering pqHeld().");
      log.debug("Leaving pqHeld().");
      return pqGenerated ? 'generated' : (storedPq ? 'stored' : '');
    }
  });
  // ---------------------------------------------------------------------
  // **THE OPENID4VCI REQUEST-ENCRYPTION KEY, PUBLIC HALF RESIDENT AND PRIVATE
  // HALF A GETTER (2026-09-12)** — the curve keys' arrangement exactly, and
  // for their reason: `credential_request_encryption.jwks` is published on
  // every issuer metadata fetch, and that must not cause a decrypt.
  //
  // `vciPublic` is the PUBLIC JWK and nothing else — read out into a local so
  // that no closure below captures `stored.vciRequestEncKey`, which carries
  // the PEM beside it. Absent on a blob written before the key joined the set;
  // `requestEncryptionKeyFor()` backfills that case and assigns through the
  // setter, which is `pqKeys`'s setter and for its reason.
  // ---------------------------------------------------------------------
  const vciPublic = (stored.vciRequestEncKey &&
                     stored.vciRequestEncKey.publicJwk) || null;
  let vciGenerated = null;
  Object.defineProperty(set, 'vciRequestEncKey', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      if (vciGenerated) {
        log.debug("Leaving get().");
        return vciGenerated;
      }
      if (!vciPublic) {
        log.debug("Leaving get().");
        return undefined;
      }
      const entry = { publicJwk: vciPublic };
      Object.defineProperty(entry, 'privateKey', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering get().");
          const held = keystore.privateMaterialFor(realmId);
          if (!held || !held.vci) {
            throw new Error('the "' + realmId + '" realm\'s OpenID4VCI ' +
              'request-encryption key is held encrypted and could not be ' +
              'decrypted; see the keystore errors above.');
          }
          log.debug("Leaving get().");
          return held.vci;
        }
      });
      log.debug("Leaving get().");
      return entry;
    },
    set: function (made) {
      log.debug("Entering set().");
      vciGenerated = made || null;
      log.debug("Leaving set().");
    }
  });
  // ---------------------------------------------------------------------
  // **THE REFRESH-TOKEN ENCRYPTION KEYS, PUBLIC HALVES RESIDENT AND EVERY
  // PRIVATE PART A GETTER (2026-09-12)** — the request-encryption key's
  // arrangement, with the SECRET treated as private material too, because it
  // opens every refresh token sealed under a symmetric algorithm. Only the
  // public JWKs and the secret's kid are read into locals, so no closure here
  // captures a PEM or the secret bytes.
  // ---------------------------------------------------------------------
  const rtStored = stored.refreshTokenEncKeys || null;
  const rtPublic = rtStored && rtStored.rsa && rtStored.ec
    ? { rsa: rtStored.rsa.publicJwk, ec: rtStored.ec.publicJwk,
        secretKid: rtStored.secretKid }
    : null;
  let rtGenerated = null;
  const rtHeld = function (part) {
    log.debug("Entering rtHeld().");
    const held = keystore.privateMaterialFor(realmId);
    if (!held || !held.rt) {
      throw new Error('the "' + realmId +
        '" realm\'s refresh-token encryption ' +
        part + ' is held encrypted and could not be decrypted; see the ' +
        'keystore errors above.');
    }
    log.debug("Leaving rtHeld().");
    return held.rt;
  };
  Object.defineProperty(set, 'refreshTokenEncKeys', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      if (rtGenerated) {
        log.debug("Leaving get().");
        return rtGenerated;
      }
      if (!rtPublic) {
        log.debug("Leaving get().");
        return undefined;
      }
      const view = { rsa: { publicJwk: rtPublic.rsa },
                     ec: { publicJwk: rtPublic.ec },
                     secretKid: rtPublic.secretKid };
      Object.defineProperty(view.rsa, 'privateKey', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering get().");
          log.debug("Leaving get().");
          return rtHeld('RSA key').rsa.privateKey;
        }
      });
      Object.defineProperty(view.ec, 'privateKey', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering get().");
          log.debug("Leaving get().");
          return rtHeld('EC key').ec.privateKey;
        }
      });
      Object.defineProperty(view, 'secret', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering get().");
          log.debug("Leaving get().");
          return rtHeld('secret').secret;
        }
      });
      log.debug("Leaving get().");
      return view;
    },
    set: function (made) {
      log.debug("Entering set().");
      rtGenerated = made || null;
      log.debug("Leaving set().");
    }
  });
  // ---------------------------------------------------------------------
  // **THE REQUEST OBJECT ENCRYPTION KEYS, PUBLIC HALVES RESIDENT AND BOTH
  // PRIVATE KEYS GETTERS (2026-09-13)** — the refresh-token keys' arrangement,
  // and for the reason it matters more here: these public halves are in
  // `/oauth2/jwks`, which every client fetches, and publishing them must not
  // cause a decrypt. Only the two public JWKs are read into locals.
  // ---------------------------------------------------------------------
  const roStored = stored.requestObjectEncKeys || null;
  const roPublic = roStored && roStored.rsa && roStored.ec
    ? { rsa: roStored.rsa.publicJwk, ec: roStored.ec.publicJwk }
    : null;
  let roGenerated = null;
  const roHeld = function (part) {
    log.debug("Entering roHeld().");
    const held = keystore.privateMaterialFor(realmId);
    if (!held || !held.ro) {
      throw new Error('the "' + realmId +
        '" realm\'s request object encryption ' + part + ' is held ' +
        'encrypted and could not be decrypted; see the keystore errors ' +
        'above.');
    }
    log.debug("Leaving roHeld().");
    return held.ro;
  };
  Object.defineProperty(set, 'requestObjectEncKeys', {
    enumerable: true, configurable: true,
    get: function () {
      log.debug("Entering get().");
      if (roGenerated) {
        log.debug("Leaving get().");
        return roGenerated;
      }
      if (!roPublic) {
        log.debug("Leaving get().");
        return undefined;
      }
      const view = { rsa: { publicJwk: roPublic.rsa },
                     ec: { publicJwk: roPublic.ec } };
      Object.defineProperty(view.rsa, 'privateKey', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering get().");
          log.debug("Leaving get().");
          return roHeld('RSA key').rsa.privateKey;
        }
      });
      Object.defineProperty(view.ec, 'privateKey', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering get().");
          log.debug("Leaving get().");
          return roHeld('EC key').ec.privateKey;
        }
      });
      log.debug("Leaving get().");
      return view;
    },
    set: function (made) {
      log.debug("Entering set().");
      roGenerated = made || null;
      log.debug("Leaving set().");
    }
  });
  certifiedView(set, realmId, stored);
  log.debug("Leaving lazyKeySet(). " + set.extraKeys.length + " curve key(s).");
  return set;
}

// THE OTHER HALF OF keystore.adoptShared(): when another process's keys win,
// the set this one built has to be dropped so the next read rebuilds from the
// blob that won. Registered here because this file owns the cache.
keystore.onAdopt(function (realmId) {
  const held = stsKeysFor.existing();
  if (held && typeof held.delete === 'function') {
    held.delete(String(realmId || ''));
  }
});

// ---------------------------------------------------------------------------
// ONE SIGNING KEY PER TRUST REALM, AND `STS` IS A VIEW ONTO THE CURRENT ONE.
//
// A realm that shared the process's key would not be a trust realm. The whole
// claim a realm makes is that a token it issued is ITS token — so a verifier
// that fetched realm `acme`'s JWKS and is handed a token minted in the default
// realm must find that the signature does not verify. Two realms on one key
// would make every realm's tokens interchangeable, which is the one property
// somebody defining a second realm is trying not to have.
//
// LAZY, per realm: `makeStsKeys()` generates a 2048-bit RSA key, which is a
// tenth of a second, and a realm that has issued nothing has not paid for one.
// The default realm's is made on the first read, which is during module load
// here — so a service with no realms does exactly what it did before, at
// exactly the same moment.
//
// A PROXY rather than a function (`STS`, below), and the reason is the call
// sites again: eight modules destructure `const { STS } = require('./helpers')`
// and then read `STS.kid`, `STS.certPem`, `STS.privateKey`. A function would
// have been `stsKeys().kid` at every one of them; the proxy leaves all eight
// untouched and correct. What it forwards is a property READ — there is
// nothing here that writes to STS after this file has finished, and the one
// thing that used to (`STS.privateKey = …`) is now part of what the factory
// returns.
// ---------------------------------------------------------------------------
// Described to `/admin/caches` (#74, rule 3ap): a row is a realm and its
// RSA key's kid, never the key. A hit is a read that found the realm's set
// already built; a miss builds it (or reads it out of the key store).
const stsKeysCount = cacheRegistry.register({
  name: 'keys.signing-sets',
  title: 'Signing key sets',
  description: 'Each trust realm\'s signing keys (RSA, EC, and the ' +
    'post-quantum set once asked for), built or read from the key store on ' +
    'first use and held for every signature after it.',
  owner: 'common/helpers.js',
  scope: 'realm',
  maxEntries: function () {
    return 1;
  },
  bound: 'Structural: one key set per realm, dropped with the realm or ' +
    'replaced when its keys are rotated or adopted.',
  lifetime: function () {
    return 'No expiry: dropped when the realm is removed, its keys are ' +
      'rotated, or another process\'s stored keys are adopted. One entry ' +
      'per realm that has signed.';
  },
  entries: function () {
    const out = [];
    stsKeysFor.existing().forEach(function (keys, id) {
      out.push({ realm: id || 'default',
                 // `kid` only: `pqKeys` and the private halves are GETTERS
                 // that decrypt in product mode, and a page must not.
                 key: String((keys && keys.kid) || '(no kid)'),
                 validUntil: null, basis: 'until rotated or adopted' });
    });
    return out;
  }
});

// The post-quantum half of each set, described separately because it is
// made separately — on the first use that needs it, not with the set (#74).
// Read through `pqHeld()` or a plain data property, never through the
// decrypting getter. A hit is a use that found the realm's set already made.
function pqStateOf(keys) {
  log.debug("Entering pqStateOf().");
  if (!keys) {
    log.debug("Leaving pqStateOf(). No set.");
    return '';
  }
  if (typeof keys.pqHeld === 'function') {
    log.debug("Leaving pqStateOf(). A stored set.");
    return keys.pqHeld();
  }
  const d = Object.getOwnPropertyDescriptor(keys, 'pqKeys');
  log.debug("Leaving pqStateOf().");
  return d && 'value' in d && d.value && d.value.length ? 'generated' : '';
}

const pqKeysCount = cacheRegistry.register({
  name: 'keys.post-quantum-sets',
  title: 'Post-quantum key sets',
  description: 'Each realm\'s ML-DSA and SLH-DSA keys, generated (or read ' +
    'from the stored set) the first time something needs them, and held ' +
    'with the realm\'s key set after that.',
  owner: 'common/helpers.js',
  scope: 'realm',
  maxEntries: function () {
    return 1;
  },
  bound: 'Structural: one post-quantum set per realm, held with the ' +
    'realm\'s key set.',
  lifetime: function () {
    return 'As for the realm\'s key set: no expiry, dropped when the realm ' +
      'is removed or its keys are replaced.';
  },
  entries: function () {
    const out = [];
    stsKeysFor.existing().forEach(function (keys, id) {
      const state = pqStateOf(keys);
      if (!state) {
        return;
      }
      out.push({ realm: id || 'default',
                 key: 'post-quantum set (' + state + ')',
                 validUntil: null, basis: 'until rotated or adopted' });
    });
    return out;
  }
});

const stsKeysFor = realms.keyed(function (realm) {
  // ---------------------------------------------------------------------
  // THE STORED KEYS FIRST, WHERE THERE ARE ANY (2026-09-06).
  //
  // **DEVELOPMENT MODE NEVER GETS HERE WITH ANYTHING**: `keystore.persists()`
  // is false, `storedFor()` answers null, and this factory generates exactly as
  // it always did. That is not a fallback — it is the mode, and a key
  // regenerated per start is what makes two instances of this mock impossible
  // to confuse.
  //
  // In product mode the material was READ in `keystore.start()`, before the
  // listener bound, so this is a synchronous lookup — which it has to be,
  // because this factory is reached through a PROXY on a property read and
  // cannot await anything. See keystore.js's header for how the asynchronous
  // half is kept out of here.
  //
  // **READ, NOT HELD DECRYPTED.** Since 2026-09-06 what that call returns is
  // decrypted on demand and dropped again, so this line costs one decrypt and
  // the set built from it below keeps only the public half. `lazyKeySet()`
  // above is the whole of it.
  //
  // A realm with nothing stored — a realm created at runtime, or the first
  // start of a product deployment — falls through, generates, and is written
  // back by `remember()` below.
  // ---------------------------------------------------------------------
  // A set `prepareKeySet()` generated off the event loop for this realm, TAKEN
  // here whichever branch below answers — a set that is not used is private
  // key material nobody will ever sign with, and it is not kept.
  const prepared = takePrepared(realm.id);
  const stored = keystore.storedFor(realm.id);
  if (stored) {
    const restored = lazyKeySet(realm.id, stored);
    // A post-quantum set written down before its keys were issued from the
    // realm's JOSE Issuing CA (2026-09-13) has no certificates in the register
    // and nothing else would ever give it any — so a restore asks. It is a
    // no-op for a set that is already certified, which is every restore after
    // the first: `certifyPqKeys()` compares the key and the issuer and leaves
    // both alone. The public halves only, as always.
    if ((stored.pqKeys || []).length) {
      certifyPqLater(realm.id, stored.pqKeys);
    }
    log.info('A signing key was RESTORED for the "' + realm.id + '" realm: ' +
             'kid=' + restored.kid + '. It was generated on ' +
             new Date(restored.createdAt || 0).toISOString() + ' and read ' +
             'back from the persistence store, so every token issued under ' +
             'it still verifies. ' + keystore.retentionSentence() + '.');
    return restored;
  }
  // ---------------------------------------------------------------------
  // AND THEN WHAT A SIBLING PROCESS ALREADY GENERATED (2026-09-07).
  //
  // Nothing is stored — this is development mode, or a realm made at runtime —
  // but this process may not be the only one running the stack. When
  // `workers.requestCount` is set, the front process and every request worker
  // load this file, and each one generated a realm's keys on its own first
  // read of them (a realm watcher did it the moment a realm appeared, until
  // 2026-08-30 — see below warmPqKeys()): four processes, four independently
  // generated key sets,
  // four different `kid`s advertised from one port. A token minted by one
  // worker then failed to verify at another, which is most of what a dispatched
  // run measured as broken.
  //
  // `keystore.sharedFor()` is the answer to "has a sibling already done this".
  //
  // **IT IS ASKED IN PRODUCT MODE TOO SINCE 2026-09-09, AND THE ORDER OF THESE
  // THREE LOOKUPS IS NOW LOAD-BEARING.** It used to answer null whenever the
  // keystore persisted, on the argument that a store IS the channel — true on
  // every start except the one where the store is empty, which is the first
  // start of every product deployment. Four processes then generated four key
  // sets and each kept its own: `/oauth2/jwks` answered differently per worker
  // and tokens did not verify across them. `keystore.js`'s `sharedFor()`
  // carries the measurement.
  //
  // So: STORED first, then a SIBLING'S, then generate. The stored set still
  // wins wherever there is one, which is what keeps `remember()` reachable —
  // the regression that early return was written for was this map being
  // consulted BEFORE the store. Do not reorder them.
  // ---------------------------------------------------------------------
  const fromSibling = keystore.sharedFor(realm.id);
  if (fromSibling) {
    const adopted = plainKeySet(realm.id, fromSibling);
    log.info('The "' + realm.id + '" realm\'s signing keys came from another ' +
             'process in this service: kid=' + adopted.kid + '. Every ' +
             'process here presents one key set, exactly as they all present ' +
             'one TLS certificate.');
    // AND WRITTEN DOWN, WHERE THIS SERVICE PERSISTS. A no-op in development.
    // The process that GENERATED this set has already called `remember()`, so
    // this is usually a second write of identical bytes — and it is here for
    // the case where that write failed or had not landed: without it, a start
    // in which every worker adopted one worker's keys could end with nothing
    // in `sts_keys` at all, and the next restart would generate a new set and
    // invalidate everything issued under this one. A duplicate write is much
    // the cheaper side of that trade.
    keystore.remember(realm.id, adopted);
    return adopted;
  }
  // IN THE REALM THE SET IS FOR, which `.of(id)` from a watcher or a sweep is
  // not ambient in: `makeStsKeys()` reads `oid4vci.requestEncryptionKeyBits`,
  // and a realm carrying that setting must get the size it asked for rather
  // than whichever realm happened to be current when its keys were made.
  // **WITH THE RSA PAIRS `prepareKeySet()` MADE, WHERE IT MADE THEM**
  // (2026-09-14, #46): four RSA generations are ~400ms of this thread per
  // realm, and a list of realms this process held no keys for built them back
  // to back — past `cluster.nodeTtlMs`, so the node lost its membership and
  // exited. The ORDER above is untouched: a stored set and a sibling's still
  // win.
  const keys = realms.run(realm, function () {
    return makeStsKeys(prepared);
  });
  keys.createdAt = Date.now();
  // ---------------------------------------------------------------------
  // THE SAME PRIVATE KEY AS AN ALREADY-PARSED `KeyObject`, and it is here for
  // speed rather than for tidiness.
  //
  // `jwt.sign(payload, pem, ...)` hands node a PEM STRING, and node has to turn
  // that string into a key before it can sign with it — every single time. That
  // parse is not a rounding error: under load it measured 21% of this service's
  // non-idle CPU, against 48% for the RSA signature it was preparing for, so
  // roughly a third of the cost of issuing a token was re-reading a key that
  // had not changed since startup. Parsing it once here took one signature from
  // 1.08ms to 0.48ms and rather more than doubled the token endpoint's
  // throughput.
  //
  // It lives ON the key set rather than beside it because every module that
  // signs already destructures `STS` from this file, so the eight call sites
  // needed nothing new imported. `privateKeyPem` is KEPT and is still what the
  // XML signer uses — `crypto.js`'s `signXml()` hands a PEM to the vendored
  // signer (it was three xml-crypto signers when this was written) — so
  // nothing that read it before had to change.
  //
  // It is derived rather than stored: there is exactly one private key per
  // realm and this is the same one, so the two cannot drift apart.
  // ---------------------------------------------------------------------
  keys.privateKey = crypto.createPrivateKey(keys.privateKeyPem);
  keys.realm = realm.id;
  // **AND THE CERTIFICATE VIEW, WHICH THIS PATH NEEDS MOST.** The two branches
  // above build their sets through `lazyKeySet()` and `plainKeySet()` and get
  // it there; this one is the DEVELOPMENT-MODE path and therefore the default,
  // so a set returned raw here would be the one most deployments actually use
  // — publishing the self-signed certificate for ever while the hierarchy sat
  // beside it, certified and unread. The self-signed pair is SNAPSHOT first,
  // because the getters fall back to it and reading it off the object they are
  // being defined on would recurse.
  certifiedView(keys, realm.id,
                { certPem: keys.certPem, certB64: keys.certB64 });
  // ---------------------------------------------------------------------
  // AND CERTIFY IT UNDER THIS REALM'S OWN ISSUING CAs — ASYNCHRONOUSLY, AND
  // DELIBERATELY NOT AWAITED (2026-09-11).
  //
  // This is a PROPERTY READ, so there is nothing here that can await eight
  // signatures. It is the same shape as the `keystore.remember()` call below
  // it and for the same reason: the work is scheduled, a failure is logged
  // loudly by the module that does it, and nothing is thrown out of whichever
  // request happened to be the first to touch this realm.
  //
  // **NOTHING WAITS ON IT, WHICH IS WHAT MAKES IT SAFE.** The `kid` is already
  // final — it names the key and not the certificate, see `certifiedView()` —
  // and until the certificates land this key set publishes the self-signed
  // certificate it was born with, which is what this service published for its
  // whole life until today. The default realm never takes this path at all:
  // `pki.start()` certifies it before the listener binds.
  // ---------------------------------------------------------------------
  certifyLater(realm.id, keys);
  log.info('A signing key was generated for the "' + realm.id +
           '" realm: kid=' +
           keys.kid + '.');
  // WRITE IT DOWN, where the keystore is in use. A no-op in development mode.
  // The write is asynchronous and deliberately not awaited — this is a property
  // read — so a failure is logged loudly by keystore.js rather than thrown out
  // of whichever request happened to be first.
  keystore.remember(realm.id, keys);
  // AND OFFERED TO EVERY OTHER PROCESS IN THIS SERVICE, which is the other half
  // of the sharedFor() lookup above. In a service with no request pool there is
  // no publisher and this records the set locally and returns. See the SHARED
  // KEY MATERIAL block above keystore.js's sharedFor().
  keystore.publishShared(realm.id, keys);
  // ---------------------------------------------------------------------
  // AND WHERE IT WAS WRITTEN DOWN, HAND BACK THE LAZY VIEW OF IT RATHER THAN
  // THE RESIDENT ONE (2026-09-06).
  //
  // Without this line the FIRST realm to generate its keys — a runtime realm,
  // or the first start of a product deployment — would keep them decrypted for
  // the life of the process while every realm restored on a later start held
  // ciphertext. One realm out of N behaving differently is the shape of bug
  // that survives a test suite, because the suite mostly exercises the restored
  // path and the difference is invisible from every endpoint.
  //
  // In DEVELOPMENT `remember()` is a no-op, `storedFor()` answers null, and the
  // generated set is returned exactly as it always was.
  // ---------------------------------------------------------------------
  const written = keystore.storedFor(realm.id);
  return written ? lazyKeySet(realm.id, written) : keys;
}, function (hit) {
  if (hit) {
    stsKeysCount.hit();
  } else {
    stsKeysCount.miss();
  }
});

// ---------------------------------------------------------------------------
// A REALM'S KEY SET, MADE OFF THE EVENT LOOP BEFORE ANYTHING READS IT
// (2026-09-14, #46 — the fail-stop under ordinary admin load).
//
// `stsKeysFor` is a factory behind a PROPERTY READ, so it cannot await, and a
// realm this process holds no keys for is generated inside whichever read
// touches it first: four 2048-bit RSA generations and a certificate, measured
// at ~470ms of a stopped process in development mode and ~1.2s on a loaded
// product node. One realm at a time that is a slow request. **A LIST of realms
// is not one at a time**: `GET /admin-api/realms` shows every realm's `kid`, a
// realm created on another node is one this node holds no keys for, and a
// burst of twenty creations followed by one list stopped a node's event loop
// for longer than `cluster.nodeTtlMs`. Its heartbeat could not run, its
// membership row expired by the database's clock, and its next write was
// fenced — `STS-CLUSTER-0011`, the node exited. Measured in process with
// thirteen realms: one 7.7s stall; `settleSigningKeys()` had the same loop at
// a cold start.
//
// **SO THE EXPENSIVE HALF IS GENERATED HERE, IN NODE'S THREAD POOL**
// (`crypto.generateKeyPair`, which runs in libuv's threads and never on this
// one), and handed to the factory through `prepared`, which assembles the set
// with the same `makeStsKeys()` a synchronous read uses. What is left on the
// thread — six curve keys, a certificate signature, four JWK exports — is tens
// of milliseconds, and `prepareKeySets()` yields between realms.
//
// **NOT `common/worker_pool.js`**, and the reason is not the one
// `pki_authoring.js` gives for its own generation (that one is about the
// post-quantum encoders' byte layouts): an RSA or EC generation is node's own
// OpenSSL either way, and node already has an asynchronous door to it that
// costs no IPC round trip and no forked child. The pool is for computation
// node has no asynchronous door to.
//
// **THE FACTORY'S ORDER IS NOT CHANGED**: stored, then a sibling's, then
// generated — and `prepared` is only ever the third. A set prepared here while
// another process's set arrived is dropped unused, which is the arbitration
// every other door already follows. Where there is nothing to prepare — held
// already, stored, or offered by a sibling — this does nothing.
//
// Callers: the realm middleware in `app.js` (the realm a request is in), the
// realm list and drill-down on `/admin/realms` and `GET /admin-api/realms`, and
// `service_state.js`'s cold-start settle. A read that reaches the factory by
// another road — an LDAP bind, a KDC exchange, a background sweep — still
// generates synchronously, one realm, as it always did.
// ---------------------------------------------------------------------------
const preparedSets = new Map();
const preparing = new Map();

function takePrepared(realmId) {
  log.debug("Entering takePrepared().");
  const id = String(realmId || '');
  const made = preparedSets.get(id) || null;
  preparedSets.delete(id);
  log.debug("Leaving takePrepared(). " + (made ? "Prepared." : "None."));
  return made;
}

// The id a key set is cached under, and the realm the factory would make it
// for, the way `realms.keyed()`'s `.of()` resolves them.
function realmForKeys(realmId) {
  log.debug("Entering realmForKeys().");
  const realm = realms.get(realmId) || realms.DEFAULT_REALM;
  log.debug("Leaving realmForKeys().");
  return realm;
}

// Whether a read of this realm's keys would GENERATE — the question
// `prepareKeySet()` asks before spending a thread on it. Cheap: a map lookup,
// the keystore's in-memory material, the sibling channel's blob.
function keySetNeedsMaking(realmId) {
  log.debug("Entering keySetNeedsMaking().");
  const held = stsKeysFor.existing();
  if (held && held.has(realmId)) {
    log.debug("Leaving keySetNeedsMaking(). Held.");
    return false;
  }
  const realm = realmForKeys(realmId);
  if (keystore.sharedBlobFor(realm.id) || keystore.storedFor(realm.id)) {
    log.debug("Leaving keySetNeedsMaking(). Stored or shared.");
    return false;
  }
  log.debug("Leaving keySetNeedsMaking(). Would generate.");
  return true;
}

function generateRsaPairAsync(bits, asPem) {
  log.debug("Entering generateRsaPairAsync(). bits=" + bits);
  const options = { modulusLength: bits };
  if (asPem) {
    options.privateKeyEncoding = { type: 'pkcs1', format: 'pem' };
    options.publicKeyEncoding = { type: 'pkcs1', format: 'pem' };
  }
  log.debug("Leaving generateRsaPairAsync().");
  return new Promise(function (resolve, reject) {
    crypto.generateKeyPair('rsa', options, function (err, publicKey,
                                                     privateKey) {
      if (err) {
        reject(err);
        return;
      }
      resolve({ publicKey: publicKey, privateKey: privateKey });
    });
  });
}

// Resolves once the realm's key set is held by this process (or there was
// nothing to prepare). Never rejects: a failure is logged and the read that
// follows generates synchronously, which is what it did before this existed.
function prepareKeySet(realmId) {
  log.debug("Entering prepareKeySet(). realm=" + realmId);
  const id = String(realmId || '');
  if (!keySetNeedsMaking(id)) {
    log.debug("Leaving prepareKeySet(). Nothing to make.");
    return Promise.resolve(false);
  }
  if (preparing.has(id)) {
    log.debug("Leaving prepareKeySet(). Already under way.");
    return preparing.get(id);
  }
  const realm = realmForKeys(id);
  const started = Date.now();
  // The sizes are read IN THE REALM, synchronously, before anything is
  // awaited — `makeStsKeys()` reads the same three settings the same way.
  const bits = realms.run(realm, function () {
    return {
      vci: rsaBitsFor('oid4vci.requestEncryptionKeyBits'),
      refresh: rsaBitsFor('oauth2.refreshTokenEncryptionKeyBits'),
      requestObject: rsaBitsFor('oauth2.requestObjectEncryptionKeyBits')
    };
  });
  const work = Promise.all([
    generateRsaPairAsync(STS_SIGNING_KEY_BITS, true),
    generateRsaPairAsync(bits.vci),
    generateRsaPairAsync(bits.refresh),
    generateRsaPairAsync(bits.requestObject)
  ]).then(function (pairs) {
    // Somebody may have made or adopted the set while the threads worked; the
    // factory's order decides, and a prepared set it does not use is dropped.
    if (keySetNeedsMaking(id)) {
      preparedSets.set(realm.id, { signingPem: pairs[0].privateKey,
                                   vci: pairs[1], refresh: pairs[2],
                                   requestObject: pairs[3] });
      stsKeysFor.of(id);
      preparedSets.delete(realm.id);
    }
    log.debug('prepareKeySet(): the "' + realm.id + '" realm\'s key set was ' +
              'generated off the event loop in ' + (Date.now() - started) +
              'ms.');
    return true;
  }).catch(function (e) {
    log.debug("Caught in prepareKeySet(): " + ((e && e.message) || e));
    preparedSets.delete(realm.id);
    log.warn(errorCodes.tag('STS-CORE-0092') + 'helpers: the "' + realm.id +
             '" realm\'s key set could not be generated off the event loop (' +
             ((e && e.message) || e) + '); the first read of it generates ' +
             'it on the loop instead.');
    return false;
  }).then(function (made) {
    preparing.delete(id);
    return made;
  });
  preparing.set(id, work);
  log.debug("Leaving prepareKeySet(). Generating.");
  return work;
}

// Several realms ONE AFTER ANOTHER, yielding to the event loop between them —
// what a list of realms or a cold start calls. In sequence rather than all at
// once because the thread pool is four threads that DNS, the file system and
// scrypt also use; one realm's four generations fill it.
function prepareKeySets(realmIds) {
  log.debug("Entering prepareKeySets().");
  const ids = (realmIds || []).slice();
  let chain = Promise.resolve();
  ids.forEach(function (id) {
    chain = chain.then(function () {
      return prepareKeySet(id);
    }).then(function () {
      return new Promise(function (resolve) {
        setImmediate(resolve);
      });
    });
  });
  log.debug("Leaving prepareKeySets(). " + ids.length + " realm(s).");
  return chain.then(function () {
    return ids.length;
  });
}

// ---------------------------------------------------------------------------
// THE OPENID4VCI REQUEST-ENCRYPTION KEY OF A KEY SET, as `{ privateKey,
// publicJwk }` — the CURRENT realm's when no set is named. What
// `oid4vc/vc_issuer.ts` publishes and decrypts with.
//
// Every set made from 2026-09-12 carries one, so this is a property read. The
// rest of the function is the ONE case that does not: a set RESTORED from a
// `sts_keys` row, or adopted from a sibling's blob, written by a build from
// before the key joined the set. That set is backfilled here, once, and the
// order of the three steps is the whole of it:
//
//   1. ASK FIRST. Another process of this service may already have backfilled
//      this realm and this process adopted the result — into the store in
//      product mode, into the shared map in development — while the set it
//      built earlier still lacks the member. Generating here would make a
//      second key and publish neither. `keystore.requestEncryptionKeyHeldFor()`
//      is that question, and it READS; it never makes anything.
//   2. THEN MAKE ONE, in the set's own realm, for `makeStsKeys()`'s reason.
//   3. AND HAND IT ON EXACTLY AS A GENERATED SET IS: written down where this
//      service persists, and offered to every other process as an ENRICHMENT
//      of the set they already hold — `keystore.enriches()` is the rule both
//      ends of that channel apply. A process whose offer loses that race is
//      told to adopt the winner and drops this set, which is the post-quantum
//      half's arrangement word for word.
//
// **THE ONE COST, SAID:** a backfilled key on a RESTORED set is held on the set
// until the process exits, where a stored one is decrypted per use. It is one
// key, once, on the first start after an upgrade; the next start restores it
// from the row like every other private key here.
// ---------------------------------------------------------------------------
function requestEncryptionKeyFor(keySet) {
  log.debug("Entering requestEncryptionKeyFor().");
  const keys = keySet || stsKeysFor();
  const present = keys.vciRequestEncKey;
  if (present && present.publicJwk) {
    log.debug("Leaving requestEncryptionKeyFor(). On the set.");
    return present;
  }
  const realmId = String(keys.realm || realms.currentId());
  const held = keystore.requestEncryptionKeyHeldFor(realmId);
  if (held) {
    keys.vciRequestEncKey = held;
    log.debug("Leaving requestEncryptionKeyFor(). Already made by this " +
              "service.");
    return held;
  }
  const realm = realms.get(realmId) || realms.DEFAULT_REALM;
  const made = realms.run(realm, makeRequestEncryptionKey);
  keys.vciRequestEncKey = made;
  log.info('An OpenID4VCI request-encryption key was added to the "' + realmId +
           '" realm\'s key set, which was written by a build from before the ' +
           'key joined it: kid=' + made.publicJwk.kid + '.');
  keystore.remember(realmId, keys);
  keystore.publishShared(realmId, keys);
  log.debug("Leaving requestEncryptionKeyFor(). Backfilled.");
  return keys.vciRequestEncKey || made;
}

// ---------------------------------------------------------------------------
// THE REFRESH-TOKEN ENCRYPTION KEYS FOR A KEY SET, BACKFILLED WHERE THE SET WAS
// WRITTEN BEFORE THEY EXISTED (2026-09-12). `requestEncryptionKeyFor()` above,
// step for step and for its reasons: ask whether some process already made
// them, make them in the set's own realm if not, and hand them on as an
// enrichment of the set every other process holds.
// ---------------------------------------------------------------------------
function refreshTokenKeysFor(keySet) {
  log.debug("Entering refreshTokenKeysFor().");
  const keys = keySet || stsKeysFor();
  const present = keys.refreshTokenEncKeys;
  if (present && present.rsa && present.rsa.publicJwk) {
    log.debug("Leaving refreshTokenKeysFor(). On the set.");
    return present;
  }
  const realmId = String(keys.realm || realms.currentId());
  const held = keystore.refreshTokenKeysHeldFor(realmId);
  if (held) {
    keys.refreshTokenEncKeys = held;
    log.debug("Leaving refreshTokenKeysFor(). Already made by this service.");
    return held;
  }
  const realm = realms.get(realmId) || realms.DEFAULT_REALM;
  const made = realms.run(realm, makeRefreshTokenEncryptionKeys);
  keys.refreshTokenEncKeys = made;
  log.info('Refresh-token encryption keys were added to the "' + realmId +
           '" realm\'s key set, which was written by a build from before ' +
           'they joined ' +
           'it: ' + made.rsa.publicJwk.kid + ', ' + made.ec.publicJwk.kid +
           ', ' + made.secretKid + '.');
  keystore.remember(realmId, keys);
  keystore.publishShared(realmId, keys);
  log.debug("Leaving refreshTokenKeysFor(). Backfilled.");
  return keys.refreshTokenEncKeys || made;
}

// ---------------------------------------------------------------------------
// THE REQUEST OBJECT ENCRYPTION KEYS FOR A KEY SET, BACKFILLED WHERE THE SET WAS
// WRITTEN BEFORE THEY EXISTED (2026-09-13). `refreshTokenKeysFor()` above, step
// for step: ask whether some process already made them, make them in the set's
// own realm if not, and hand them on as an enrichment of the set every other
// process holds.
// ---------------------------------------------------------------------------
function requestObjectKeysFor(keySet) {
  log.debug("Entering requestObjectKeysFor().");
  const keys = keySet || stsKeysFor();
  const present = keys.requestObjectEncKeys;
  if (present && present.rsa && present.rsa.publicJwk) {
    log.debug("Leaving requestObjectKeysFor(). On the set.");
    return present;
  }
  const realmId = String(keys.realm || realms.currentId());
  const held = keystore.requestObjectKeysHeldFor(realmId);
  if (held) {
    keys.requestObjectEncKeys = held;
    log.debug("Leaving requestObjectKeysFor(). Already made by this service.");
    return held;
  }
  const realm = realms.get(realmId) || realms.DEFAULT_REALM;
  const made = realms.run(realm, makeRequestObjectEncryptionKeys);
  keys.requestObjectEncKeys = made;
  log.info('Request object encryption keys were added to the "' + realmId +
           '" realm\'s key set, which was written by a build from before ' +
           'they joined it: ' + made.rsa.publicJwk.kid + ', ' +
           made.ec.publicJwk.kid + '.');
  keystore.remember(realmId, keys);
  keystore.publishShared(realmId, keys);
  log.debug("Leaving requestObjectKeysFor(). Backfilled.");
  return keys.requestObjectEncKeys || made;
}

// FORGET THE BUILT KEY SETS so the factory runs again, which is as close to a
// restart as one process can get. `realms.keyed()` exposes its map as
// `existing()`, which is the seam that makes this a clear rather than a
// reimplementation.
//
// Exported for `tests/keystore.js` and for nothing else — see the same note on
// `keystore.reset()`. Nothing in the service calls it, and nothing should: a
// running service that forgot its signing key would publish a new JWKS and
// invalidate every token it had issued, which is precisely what the keystore
// exists to prevent.
function resetStsKeys() {
  log.debug("Entering resetStsKeys().");
  const held = stsKeysFor.existing();
  if (held && typeof held.clear === 'function') {
    held.clear();
  }
  log.debug("Leaving resetStsKeys().");
}

const STS = /** @type {any} */ (new Proxy({}, {
  get: function (target, prop) {
    log.debug("Entering get().");
    log.debug("Leaving get().");
    return stsKeysFor()[prop];
  },
  has: function (target, prop) {
    log.debug("Entering has().");
    log.debug("Leaving has().");
    return prop in stsKeysFor();
  },
  ownKeys: function () {
    log.debug("Entering ownKeys().");
    log.debug("Leaving ownKeys().");
    return Reflect.ownKeys(stsKeysFor());
  },
  getOwnPropertyDescriptor: function (target, prop) {
    log.debug("Entering getOwnPropertyDescriptor().");
    const d = Object.getOwnPropertyDescriptor(stsKeysFor(), prop);
    log.debug("Leaving getOwnPropertyDescriptor().");
    // A proxy may not report a property as non-configurable when its target has
    // no such property, and this target is permanently empty. Marking every
    // descriptor configurable is what keeps Object.keys() and a spread legal
    // over this — the JWKS builder spreads it.
    return d ? Object.assign({}, d, { configurable: true }) : undefined;
  }
}));


// Every document that carries or describes this key is served `Cache-Control:
// no-store` (the RFC 8414 metadata, the OID4VCI credential issuer metadata, the
// jwt-vc-issuer document and the JWKS). The key is regenerated on every start
// in development mode (and on a rotation in product mode), so a cached copy
// of any of them outlives the key it describes — and the resulting failure is
// a signature that does not verify, which looks like a broken document rather
// than a stale one. Nothing about a mock is worth
// caching.

// --- helpers ---------------------------------------------------------------
function xmlEscape(s) {
  log.debug("Entering xmlEscape().");
  log.debug("Leaving xmlEscape().");
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function genId() {
  log.debug("Entering genId().");
  log.debug("Leaving genId().");
  return '_' + forge.util.bytesToHex(forge.random.getBytesSync(16));
}

// --- reading XML somebody else wrote ---------------------------------------
// An element, or its text, found by LOCAL NAME with the namespace ignored.
//
// Shared rather than owned because three readers need exactly this: WS-Trust
// parses an RST, WS-Federation parses the `wreq` RST that may ride on a sign-in
// request, and the mock relying party parses the `wresult` it is POSTed. All
// three are given XML written by somebody else, so the prefix is not knowable
// in advance and neither is the namespace: the trust namespace alone has four
// versions in use (2004/04, 2005/02, ws-sx 200512 and whatever a client
// invents), and WS-Federation's own responses are usually written with `t:`
// where this service writes `wst:`. Matching the local name is what lets one
// parser answer WS-Trust 1.0 through 1.4 instead of four, and it is the reason
// these are here and not in wstrust.js where they were written.
//
// getElementsByTagNameNS('*', name) searches DESCENDANTS ONLY, which is what
// every caller wants (find the UsernameToken anywhere in the SOAP envelope) but
// is worth stating: firstByLocal(el, 'Assertion') will not return `el` itself
// even when `el` IS the Assertion.
function firstByLocal(root, name) {
  log.debug("Entering firstByLocal().");
  const els = root.getElementsByTagNameNS('*', name);
  log.debug("Leaving firstByLocal().");
  return els && els.length ? els[0] : null;
}

function textByLocal(root, name) {
  log.debug("Entering textByLocal().");
  const e = firstByLocal(root, name);
  log.debug("Leaving textByLocal().");
  return e ? (e.textContent || '').trim() : '';
}

function iso(offsetMin) {
  log.debug("Entering iso().");
  log.debug("Leaving iso().");
  return new Date(Date.now() + (offsetMin || 0) * 60000).toISOString();
}

// base64url, from common/crypto.js and not written again here. This file had
// its own — a base64 encode plus three replaces, which is what you write before
// node had `'base64url'` — and authn/webauthn.js had a third. They agreed, so
// nothing was ever wrong; what a third copy costs is that the next person to
// need one writes a fourth, and one of the four eventually forgets the padding
// strip. The name is kept because a dozen call sites in this file use it.
const b64u = stsCrypto.b64u;

function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function jsonFromB64u(s) {
  log.debug("Entering jsonFromB64u().");
  log.debug("Leaving jsonFromB64u().");
  return JSON.parse(b64uDecode(s).toString('utf8'));
}

// Small and called constantly: no entering/leaving logs, they would drown the
// log.
function nowSec() { return Math.floor(Date.now() / 1000); }

function randomId(bytes) {
  log.debug("Entering randomId().");
  log.debug("Leaving randomId().");
  return b64u(crypto.randomBytes(bytes || 24));
}

// One BBS key pair per start, like the RSA one. Generated lazily because key
// generation is async and the module loads synchronously.
let bbsKeys = null;
// The encoded text `bbsKeys` was read from, or made as. `bbsKeyPair()` compares
// it with the environment variable on every call — see below.
let bbsKeysText = '';
// A handed-down text that would not read, so it is refused once and logged
// once rather than on every proof.
let bbsRefusedText = '';

// ---------------------------------------------------------------------------
// ONE BBS PAIR ACROSS EVERY PROCESS IN THIS SERVICE (2026-09-07).
//
// This is the key a Data Integrity proof is signed with and the key the did:web
// document PUBLISHES as its verification method. One per process was invisible
// until the request worker pool existed; with four processes, the document
// served by one names a key another signed with, and the proof does not verify
// — which is exactly what `ldp_vc_issuance`, `ldp_vc_refresh` and `vc_did`
// measured.
//
// It travels the way the TLS certificate and the signing keys do: generated
// once in the front process and handed down the fork's IPC channel, into the
// environment before this module is loaded. Absent — a service with no pool,
// which is every ordinary run — one is generated here exactly as before.
//
// **IT IS NOT ON `keystore`'s SHARED CHANNEL**, which carries a REALM's key set
// and is keyed by realm. This pair is one per service and not one per realm, so
// putting it there would have meant inventing a realm for it.
//
// **AND ACROSS NODES SINCE 2026-09-14 (#46 section 1).** The same three jobs
// failed again in the suite's `cluster` mode, one level up: each CONTAINER
// generated its own pair, so `/bbs/keys/1` answered a different key on each
// node. `cluster/cluster_secrets.ts` now declares the pair (`bbs-keypair`):
// the store keeps the first node's, sealed, and every front process puts it in
// `STS_BBS_KEYPAIR` before anything issues — the variable this function
// already read. Its argument for being there rather than in `sts_keys` is at
// that row.
//
// **THE VARIABLE IS COMPARED ON EVERY CALL, NOT ONLY THE FIRST.** A pair this
// process made before the store's arrived — nothing issues before start(),
// but "nothing" is a claim about every caller, now and later — would otherwise
// be held for the life of the process, which is the divergence this exists to
// remove. One string comparison per proof is the price.
// ---------------------------------------------------------------------------
async function bbsKeyPair() {
  log.debug("Entering bbsKeyPair().");
  const handed = process.env.STS_BBS_KEYPAIR || '';
  if (bbsKeys && (!handed || handed === bbsKeysText ||
                  handed === bbsRefusedText)) {
    log.debug("Leaving bbsKeyPair().");
    return bbsKeys;
  }
  if (handed && handed !== bbsRefusedText) {
    try {
      bbsKeys = bbsKeyPairFromText(handed);
      bbsKeysText = handed;
      log.info('The BBS key pair came from another process in this service, ' +
               'so every process signs and publishes the same one.');
      log.debug("Leaving bbsKeyPair().");
      return bbsKeys;
    } catch (e) {
      bbsRefusedText = handed;
      log.error(errorCodes.tag('STS-CORE-0025') +
                'The handed-down BBS key pair could not be read (' + e.message +
                '); generating one, which means this process publishes a ' +
                'different verification method from its siblings.');
      if (bbsKeys) {
        log.debug("Leaving bbsKeyPair(). Keeping the pair already held.");
        return bbsKeys;
      }
    }
  }
  const made = await bbs2023.generateKeyPair();
  // A concurrent caller may have finished first; the first pair held wins, so
  // one process never signs with two.
  if (!bbsKeys) {
    bbsKeys = made;
    bbsKeysText = bbsKeyPairText(made);
  }
  log.debug("Leaving bbsKeyPair().");
  return bbsKeys;
}

// The pair as the text the fork's IPC channel, the environment variable and
// the cluster's sealed secret all carry: base64 of a JSON object of two base64
// members. One encoding for all three, so a value any of them carries is one
// the other two can read.
function bbsKeyPairText(pair) {
  log.debug("Entering bbsKeyPairText().");
  log.debug("Leaving bbsKeyPairText().");
  return Buffer.from(JSON.stringify({
    secret: Buffer.from(pair.secretKey).toString('base64'),
    public: Buffer.from(pair.publicKey).toString('base64')
  }), 'utf8').toString('base64');
}

// The inverse. Throws on anything that is not that shape.
function bbsKeyPairFromText(text) {
  log.debug("Entering bbsKeyPairFromText().");
  const held = JSON.parse(Buffer.from(String(text), 'base64')
    .toString('utf8'));
  if (!held || !held.secret || !held.public) {
    log.debug("Leaving bbsKeyPairFromText(). Not a pair.");
    throw new Error('the text does not carry a secret and a public key');
  }
  log.debug("Leaving bbsKeyPairFromText().");
  return {
    secretKey: Uint8Array.from(Buffer.from(held.secret, 'base64')),
    publicKey: Uint8Array.from(Buffer.from(held.public, 'base64'))
  };
}

// A FRESH pair as that text, held by nobody — the OFFER `cluster_secrets.js`
// makes to the store. Deliberately not `bbsKeyPairForSharing()`: that one
// caches the pair it makes as this process's, and an offer that loses the
// race must be thrown away rather than kept.
async function newBbsKeyPairText() {
  log.debug("Entering newBbsKeyPairText().");
  const pair = await bbs2023.generateKeyPair();
  log.debug("Leaving newBbsKeyPairText().");
  return bbsKeyPairText(pair);
}

// The pair as a string the fork's IPC channel can carry. Generates it if this
// process has not needed one yet, which is the front process's ordinary case:
// nothing has issued a credential when the pool starts.
async function bbsKeyPairForSharing() {
  log.debug("Entering bbsKeyPairForSharing().");
  const pair = await bbsKeyPair();
  log.debug("Leaving bbsKeyPairForSharing().");
  return bbsKeyPairText(pair);
}

// ---------------------------------------------------------------------------
// DOES THIS SCOPE STRING CARRY THAT SCOPE.
//
// Here rather than in oauth2.js, where it was written, for the reason
// everything else in this file is here: more than one protocol needs it now.
// `scim_auth.js` reads it to decide whether an access token may write to the
// directory, and a second copy over there would be a second answer to "is
// `scim:write ` with a trailing space the write scope" — which is the kind of
// disagreement that shows up as one endpoint accepting a token another refuses.
//
// RFC 6749 section 3.3: a scope is a space-delimited, case-SENSITIVE list.
// Split on any run of whitespace rather than a single space, because a client
// that joined its scopes with a tab or sent one across a folded header is
// asking for exactly what it looks like it is asking for.
// ---------------------------------------------------------------------------
function hasScope(scope, name) {
  log.debug("Entering hasScope().");
  log.debug("Leaving hasScope().");
  return String(scope || '').split(/\s+/).indexOf(name) >= 0;
}

// Request bodies arrive as raw text (the SOAP parser takes every content type),
// so form-encoded and JSON are both decoded here.
function parseBody(req) {
  log.debug("Entering parseBody(). content-type=" +
            (req.headers['content-type'] || '(none)'));
  const raw = typeof req.body === 'string' ? req.body : '';
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    try {
      const parsed = JSON.parse(raw || '{}');
      log.debug("Leaving parseBody(). Parsed a JSON body.");
      return parsed;
    } catch (e) {
      log.error(errorCodes.tag('STS-CORE-0026') + 'the request body is not ' +
                                                  'JSON: ' + e.message);
      log.debug("Leaving parseBody(). Nothing could be parsed.");
      return {};
    }
  }
  // A FILE UPLOAD (2026-09-13). The one form in this service that sends one is
  // the RFC 9728 import on /admin/applications/new, and a browser with no script
  // can only send a file as multipart/form-data. Every part comes back under
  // its field name as text — a file part as its content decoded as UTF-8 — so
  // the console's CSRF check finds its token in an upload exactly as it does in
  // a form, and a caller that needs the filename asks multipartParts().
  if (/^multipart\/form-data/i.test(type)) {
    const fields = {};
    multipartParts(req).forEach(function (part) {
      fields[part.name] = part.data.toString('utf8');
    });
    log.debug("Leaving parseBody(). Parsed a multipart body with " +
              Object.keys(fields).length + " part(s).");
    return fields;
  }
  const out = {};
  new URLSearchParams(raw).forEach(function (v, k) { out[k] = v; });
  log.debug("Leaving parseBody(). Parsed a form-encoded body with " +
            Object.keys(out).length + " parameter(s).");
  return out;
}

// ---------------------------------------------------------------------------
// THE PARTS OF A multipart/form-data BODY (RFC 7578), as
// `[{ name, filename, contentType, data }]` with `data` a Buffer.
//
// Read off `req.rawBody` — the bytes app.js's text parser keeps beside the
// string — because a file's bytes are not the string: a decode is not
// reversible, and a boundary search over decoded text finds a boundary that
// was never on the wire. It is deliberately small: the parts of one body, a
// cap on how many, and no streaming, because the whole body has already been
// read under the body parser's own size limit. A body with no boundary, or a
// part with no name, yields nothing for that part rather than a guess.
// ---------------------------------------------------------------------------
const MULTIPART_MAX_PARTS = 200;

function multipartParts(req) {
  log.debug("Entering multipartParts().");
  const type = String((req && req.headers && req.headers['content-type']) ||
                      '');
  const found = /;\s*boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(type);
  if (!found) {
    log.debug("Leaving multipartParts(). No boundary.");
    return [];
  }
  const body = Buffer.isBuffer(req.rawBody)
    ? req.rawBody
    : Buffer.from(typeof req.body === 'string' ? req.body : '', 'utf8');
  const delimiter = Buffer.from('--' + (found[1] || found[2]), 'utf8');
  // RFC 2046 section 5.1.1: a delimiter STARTS A LINE and is followed by
  // `--`, or by optional whitespace and a CRLF. A line of the content that
  // merely begins with the boundary string is content, and a search that took
  // the first byte match would cut a file in two there.
  const delimiterAt = function (from) {
    log.debug("Entering delimiterAt().");
    let at = body.indexOf(delimiter, from);
    while (at >= 0) {
      const lineStart = at === 0 ||
                        (body[at - 2] === 0x0d && body[at - 1] === 0x0a);
      let after = at + delimiter.length;
      while (body[after] === 0x20 || body[after] === 0x09) {
        after += 1;
      }
      const lineEnd = (body[after] === 0x2d && body[after + 1] === 0x2d) ||
                      (body[after] === 0x0d && body[after + 1] === 0x0a) ||
                      after >= body.length;
      if (lineStart && lineEnd) {
        log.debug("Leaving delimiterAt().");
        return at;
      }
      at = body.indexOf(delimiter, at + 1);
    }
    log.debug("Leaving delimiterAt().");
    return -1;
  };
  const parts = [];
  let at = delimiterAt(0);
  while (at >= 0 && parts.length < MULTIPART_MAX_PARTS) {
    let start = at + delimiter.length;
    // The closing delimiter is the boundary followed by `--`.
    if (body[start] === 0x2d && body[start + 1] === 0x2d) {
      break;
    }
    while (body[start] === 0x20 || body[start] === 0x09) {
      start += 1;
    }
    if (body[start] === 0x0d && body[start + 1] === 0x0a) {
      start += 2;
    }
    const next = delimiterAt(start);
    if (next < 0) {
      break;
    }
    // The part's content ends at the CRLF that precedes the next delimiter.
    let end = next;
    if (body[end - 2] === 0x0d && body[end - 1] === 0x0a) {
      end -= 2;
    }
    const split = body.indexOf('\r\n\r\n', start);
    if (split >= 0 && split < end) {
      const head = body.slice(start, split).toString('utf8');
      const disposition = /content-disposition:([^\r\n]*)/i.exec(head);
      const name = disposition &&
                   /\bname="([^"]*)"/i.exec(disposition[1]);
      const filename = disposition &&
                       /\bfilename="([^"]*)"/i.exec(disposition[1]);
      const contentType = /content-type:\s*([^\r\n]*)/i.exec(head);
      if (name) {
        parts.push({ name: name[1],
                     filename: filename ? filename[1] : null,
                     contentType: contentType ? contentType[1].trim() : '',
                     data: body.slice(split + 4, end) });
      }
    }
    at = next;
  }
  log.debug("Leaving multipartParts(). " + parts.length + " part(s).");
  return parts;
}

// ---------------------------------------------------------------------------
// THE VALUES OF A PARAMETER THAT IS ALLOWED TO APPEAR MORE THAN ONCE.
//
// `parseBody()` above builds a PLAIN OBJECT, so a repeated field keeps only its
// last value — `resource=a&resource=b` arrives as `b` and the first is silently
// gone. That is not a bug there and it is not going to be fixed there:
// sixty-odd call sites across fourteen modules read that object with
// `String(body.x)`, and giving them an array for a repeat would change what
// every one of them sees to fix the two parameters that need it.
//
// So the repetition is read HERE, from the raw body, beside the parsed one —
// and only by the callers whose specification says the parameter may repeat.
// Two of them do: RFC 8707 section 2's `resource` (repeating it asks for the
// "small set" of resource servers RFC 9700 section 2.3 allows) and RFC 8693
// section 2.1's `audience` and `resource` on a token exchange. Until 2026-08-26
// neither could actually be repeated at the token endpoint whatever the RFC
// said, because this function did not exist and `parseBody()` had already
// thrown the extras away. `parseResourceIndicators()` in `oauth2.js` had
// handled an array since it was written; nothing could ever hand it one.
//
// **THE AUTHORIZATION ENDPOINT NEEDS NONE OF THIS**, which is worth knowing
// before somebody looks for a bug there: it reads `req.query`, and express's
// query parser gives an array for a repeat already.
//
// `admin-ui/admin.ts`'s `listField()` is the same function, written first, for
// the console's checkbox columns. It is not called from here and this is not
// called from there — that module requires `oauth2.js` (rule 5), so nothing
// below it can require it back. Folding the two together is a change to make in
// that file, and the shape here is deliberately identical so that it is a
// one-line delegation when somebody does.
// ---------------------------------------------------------------------------
function bodyValues(req, body, name) {
  log.debug("Entering bodyValues(). name=" + name);
  const type = String((req && req.headers &&
                       req.headers['content-type']) || '');
  if (/json/i.test(type)) {
    // A JSON body carries its own repetition, as an array. Read off the PARSED
    // object rather than the raw text, because that is where JSON.parse already
    // put it.
    const value = body ? body[name] : undefined;
    const out = Array.isArray(value) ? value.map(String)
              : (value === undefined || value === null || value === '' ? [] :
                 [String(value)]);
    log.debug("Leaving bodyValues(). " + out.length + " value(s) from a JSON " +
                                                      "body.");
    return out;
  }
  const raw = typeof req.body === 'string' ? req.body : '';
  const out = new URLSearchParams(raw).getAll(name);
  log.debug("Leaving bodyValues(). " + out.length + " value(s) from a form " +
                                                    "body.");
  return out;
}

function oauthError(res, status, error, description) {
  // error-code: none — the helper's trace line, not a call to it.
  log.debug("Entering oauthError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ error: error, error_description: description }));
  // error-code: none — the helper's trace line, not a call to it.
  log.debug("Leaving oauthError().");
}

// ---------------------------------------------------------------------------
// THE POST-QUANTUM KEYS, GENERATED LAZILY AND KEPT.
//
// Eleven of them — ML-DSA at three sizes, SLH-DSA at two, and the six
// composite ML-DSA + traditional algorithms — and together they cost about
// **1.9 seconds**, nearly all of it one SLH-DSA-SHAKE keygen. That is twelve
// times the RSA key this service already makes at startup, PER REALM, and a
// realm exists to be cheap.
//
// So they are made on first use and cached, which is the opposite of the
// decision made for the EC keys a few lines up — those are microseconds and
// making them eagerly keeps the JWKS constant from the first request. Here the
// cost is real, so the first thing that actually wants a post-quantum key pays
// for it and everything else pays nothing.
//
// What that trades away is honest and small: the FIRST JWKS fetch on a realm
// generates all eleven, so it is slow once. A JWKS that grew a key later would
// be far worse — a client that cached it would be missing the key it needs —
// which is why the JWKS triggers the whole set rather than one at a time.
// ---------------------------------------------------------------------------
function pqKeysFor(keys) {
  log.debug("Entering pqKeysFor().");
  if (keys.pqKeys) {
    pqKeysCount.hit();
  } else {
    pqKeysCount.miss();
    const started = Date.now();
    keys.pqKeys = pqJose.PQ_ALGS.map(function (alg) {
      const pair = pqJose.generate(alg);
      const material = Buffer.from(pair.pub).toString('base64');
      return {
        alg: alg,
        privateKey: pair.priv,
        publicJwk: pqJose.akpPublicJwk(alg, pair.pub,
          'sts-' + alg.toLowerCase() + '-' +
          forge.md.sha256.create().update(material).digest().toHex()
            .slice(0, 8))
      };
    });
    log.info('The post-quantum signing keys were generated for the "' +
             keys.realm + '" realm: ' + keys.pqKeys.length + ' key(s) in ' +
             (Date.now() - started) + 'ms.');
    // And issued from this realm's JOSE Issuing CA, as every other key it
    // signs with is. Not awaited: this is a synchronous caller.
    certifyPqLater(keys.realm, keys.pqKeys);
  }
  log.debug("Leaving pqKeysFor(). " + keys.pqKeys.length + " key(s).");
  return keys.pqKeys;
}

// ---------------------------------------------------------------------------
// THE SAME ELEVEN KEYS, MADE IN CHILD PROCESSES.
//
// Nearly all of the ~1.9 seconds above is one SLH-DSA-SHAKE keygen, and it is
// spent on the FIRST JWKS FETCH of a realm — a request that, until the worker
// pool existed, stopped this whole service for two seconds while it was
// answered. See common/worker.js.
//
// TWO THINGS HERE ARE NOT DECORATION.
//
//   * `keys.pqKeysPromise` — the generation in flight. Without it two requests
//     arriving together each start eleven keygens, and the second set
//     overwrites the first: a client that fetched the JWKS in between then
//     holds keys that verify nothing. With it, the second caller waits on the
//     first caller's work.
//   * FIRST WRITER WINS on `keys.pqKeys`. The synchronous pqKeysFor() above is
//     still reachable — signingKeyFor() calls it for an ES256 signature, which
//     needs the key list and not the post-quantum half of it — so the two can
//     race. Whichever finishes first is the set this realm keeps and BOTH
//     return it, so the JWKS and the signature can never be from different
//     sets. The loser's work is thrown away, which costs a second of a child
//     process and nothing that anybody can observe.
//
// A failure clears the in-flight promise rather than remembering it, so a realm
// whose first attempt failed can be asked again instead of being permanently
// without post-quantum keys.
// ---------------------------------------------------------------------------
function pqKeysForAsync(keys) {
  log.debug("Entering pqKeysForAsync().");
  if (keys.pqKeys) {
    pqKeysCount.hit();
    log.debug("Leaving pqKeysForAsync(). Already made.");
    return Promise.resolve(keys.pqKeys);
  }
  if (keys.pqKeysPromise) {
    log.debug("Leaving pqKeysForAsync(). One is already in flight.");
    return keys.pqKeysPromise;
  }
  pqKeysCount.miss();
  const started = Date.now();
  keys.pqKeysPromise = Promise.all(pqJose.PQ_ALGS.map(function (alg) {
    return pqJose.generateAsync(alg).then(function (pair) {
      const material = Buffer.from(pair.pub).toString('base64');
      return {
        alg: alg,
        privateKey: pair.priv,
        publicJwk: pqJose.akpPublicJwk(alg, pair.pub,
          'sts-' + alg.toLowerCase() + '-' +
          forge.md.sha256.create().update(material).digest().toHex()
            .slice(0, 8))
      };
    });
  })).then(function (made) {
    if (!keys.pqKeys) {
      keys.pqKeys = made;
      // AND OFFERED TO EVERY OTHER PROCESS. The set was published when it was
      // GENERATED, before these existed — so without this the shared blob keeps
      // the RSA and EC halves and every worker makes its own post-quantum keys,
      // which is what it did until 2026-09-07. `publishShared()` takes a richer
      // blob for a realm it already holds when the certificate matches; see the
      // enrichment branch there.
      // Whether this process's set is the one the realm keeps. `undefined`
      // where nothing was offered, which is "yes": there is nobody to lose to.
      let took;
      if (keys.realm) {
        took = keystore.publishShared(keys.realm, keys);
        // ---------------------------------------------------------------
        // **AND WRITTEN DOWN, WHICH THEY WERE NOT UNTIL 2026-09-12.**
        //
        // The line above hands them to the other processes running NOW. This
        // one hands them to the next process to restore this realm from the
        // store — `serialise()` has carried them since 2026-09-07 and the
        // only writer was `remember()` at GENERATION time, which is before
        // these exist. So the stored blob never had them, every restore
        // generated eleven more, and the sibling channel refused the offer
        // because somebody else had got there first.
        //
        // It is a no-op in development mode, where `remember()` returns at
        // once because nothing persists — which is why this was invisible
        // until the dispatch mode started running with a real keystore.
        //
        // `remember()` and not a partial write: the store holds ONE blob per
        // realm and the whole of it is what a restore reads.
        //
        // **AND ONLY IF THIS PROCESS'S SET IS THE ONE BEING SHARED.**
        // `publishShared()` answers false when another process had already
        // established this realm's keys — first-generator-wins — and a loser
        // writing the set it is about to be told to discard would leave the
        // store holding keys no process is using. When the winner's blob
        // arrives, `adoptShared()` writes THAT down; the two together are why
        // the row converges on what everybody is signing with.
        // ---------------------------------------------------------------
        if (took !== false) {
          keystore.remember(keys.realm, keys);
        }
      }
      // -----------------------------------------------------------------
      // **AND ISSUED FROM THIS REALM'S JOSE ISSUING CA (2026-09-13)** — by
      // the process whose set is the realm's, under the rule `remember()`
      // just followed and for its reason. A process that lost the race would
      // certify keys it is about to be told to discard, and the certificate
      // register is SHARED: its certificate would overwrite the winner's
      // slot with one over a key nobody signs with. The winner certifies; a
      // loser adopts the winner's keys and the winner's certificates both.
      // -----------------------------------------------------------------
      if (took !== false) {
        certifyPqLater(keys.realm, made);
      }
      log.info('The post-quantum signing keys were generated for the "' +
               keys.realm + '" realm: ' + made.length + ' key(s) in ' +
               (Date.now() - started) + 'ms, in worker processes, so this ' +
               'service went on answering throughout.');
    }
    return keys.pqKeys;
  }).catch(function (err) {
    keys.pqKeysPromise = null;
    throw err;
  });
  log.debug("Leaving pqKeysForAsync(). Generating.");
  return keys.pqKeysPromise;
}

// ---------------------------------------------------------------------------
// A REALM'S ELEVEN KEYS ARE MADE WHEN THE REALM IS, NOT WHEN SOMEBODY FIRST
// ASKS FOR THEM — AND THIS IS THE FIX FOR A FAILURE THE WORKER POOL EXPOSED
// RATHER THAN CAUSED.
//
// **HALF-REVERSED ON 2026-08-30 — read the block after this function.** The
// eager warm-up is now the DEFAULT REALM's alone, called from `server.js`'s
// announce(); a realm created at runtime makes its keys on first use again.
// This block is kept as the argument for warming at all.
//
// One of these eleven is expensive out of all proportion to the rest: an
// SLH-DSA-SHAKE-128s KEY GENERATION is about 5.1 of the 5.8 seconds the whole
// set takes, and it is one indivisible job, so a pool of any size still waits
// for it. That put the first JWKS fetch of a realm at a little over five
// seconds — and `federation.outboundTimeoutMs` is FIVE, deliberately, because
// a browser is waiting on that request.
//
// It never failed, and the reason it never failed is the interesting part:
// while the generation was SYNCHRONOUS it blocked this process's event loop,
// so the timer enforcing that five-second budget could not fire until the
// keys were already made. The response always won a race the timeout was
// never allowed to run in. The moment the computation moved to a worker and
// the loop stayed free, the timer fired correctly at five seconds and aborted
// a fetch that was three tenths of a second from finishing — one federated
// sign-in in the parent project's suite, reporting "the JWKS could not be
// fetched", which is a sentence about a service that was working.
//
// So the keys are made when the realm is created, in the pool, where nothing
// is waiting on them. That was not affordable before: eager generation used to
// mean 5.8 seconds of a stopped service per realm, which is why they were lazy
// in the first place. It is affordable now, and it is the whole point — the
// pool does not merely move the cost off the request that pays it, it makes
// paying it EARLY free.
//
// `stsKeysFor.of(id)` rather than `stsKeysFor()`: this runs from a change
// watcher, outside any request, so there is no ambient realm to read. See
// realms.js's keyed().
// ---------------------------------------------------------------------------
function warmPqKeys(realmId) {
  log.debug("Entering warmPqKeys(). realm=" + realmId);
  let keys;
  try {
    keys = stsKeysFor.of(realmId);
  } catch (e) {
    log.debug("Caught in warmPqKeys(): " + ((e && e.message) || e));
    // A realm that has gone between the change and this line. Nothing to warm
    // and nothing wrong: the next request to it would make its keys anyway.
    log.debug("Leaving warmPqKeys(). No keys for that realm.");
    return Promise.resolve(null);
  }
  log.debug("Leaving warmPqKeys(). Generating.");
  return pqKeysForAsync(keys).catch(function (err) {
    // Swallowed and named, because this is nobody's request: a realm whose
    // warm-up failed still makes its keys on the first JWKS fetch, the slow
    // way. A throw here would be an unhandled rejection from a watcher.
    log.warn(errorCodes.tag('STS-CORE-0028') +
             'helpers: the post-quantum keys for the "' + realmId +
             '" realm could not be generated ahead of time (' + err.message +
             '); the first JWKS fetch on it will make them instead.');
    return null;
  });
}

// ---------------------------------------------------------------------------
// THERE IS NO WATCHER ANY MORE, AND THAT REVERSES HALF OF `5d9b51b` ON
// EVIDENCE RATHER THAN ON TASTE (2026-08-30).
//
// It warmed every realm's eleven post-quantum keys as the realm was CREATED,
// on `realms.onChange(… 'create')`. The argument was the paragraph above and
// it is still correct as far as it goes: the pool makes paying early free, so
// pay early.
//
// What it did not account for is WHO CREATES REALMS HERE. In a deployment a
// realm is made by a person, once, and is then used. In this repository a
// realm is made by a TEST, constantly, used for a dozen assertions about the
// admin console or the management API, and removed — and not one of those
// realms ever signs a post-quantum token. Measured on one CI coverage run:
//
//     default                 11 keys in 43.9s   (wanted)
//     adminapi-mtgg0gs613jqe  11 keys in 58.9s   (never used)
//     console-mtgg0i6k1m2sj   11 keys in 71.5s   (never used)
//
// Over two minutes of both worker processes, under instrumentation, spent on
// key material nothing would ever ask for — on the same two cores the job that
// DOES sign is waiting for. Eager generation is free when the pool is idle and
// is not free when something else needs it.
//
// So the eager path is now the DEFAULT REALM ALONE, warmed from `announce()`
// in server.js once the port is open — the realm every process has, that every
// protocol answers in, and the one whose first JWKS fetch a person actually
// waits for. A realm created at runtime makes its keys on first use, the way
// every realm did before that commit: about 1.7 seconds in the pool, off the
// event loop, on a request nobody has made yet.
//
// **This is a latency optimisation and not a correctness one**, which is what
// makes it safe to narrow: no behaviour depends on when the keys exist, only
// on their existing by the time a JWKS is served, and `pqKeysForAsync()` is
// what guarantees that either way.
// ---------------------------------------------------------------------------

// Every signing key this realm can publish — the RSA one, the curve ones, and
// the post-quantum ones, which this call brings into being.
function allSigningKeys() {
  log.debug("Entering allSigningKeys().");
  const keys = stsKeysFor();
  const out = (keys.extraKeys || []).concat(pqKeysFor(keys));
  log.debug("Leaving allSigningKeys(). " + out.length + " key(s).");
  return out;
}

// The same list, with the post-quantum half generated in the pool. It is what
// the JWKS endpoint calls, because that endpoint is the one that brings those
// eleven keys into being.
function allSigningKeysAsync() {
  log.debug("Entering allSigningKeysAsync().");
  const keys = stsKeysFor();
  log.debug("Leaving allSigningKeysAsync().");
  return pqKeysForAsync(keys).then(function (pq) {
    return (keys.extraKeys || []).concat(pq);
  });
}

// ---------------------------------------------------------------------------
// The two halves of signingKeyFor(), split so that the asynchronous twin below
// is the SAME decision made about the same list. What is checked before the
// list is needed — an unknown algorithm, an HMAC, the RSA key — is one
// function; picking the key out of the list is the other. Two copies of either
// would be two places for "which key signs which algorithm" to be answered,
// which is the very thing this function was written to have one of.
//
// It returns null when the answer is "the list decides", so that the caller
// knows whether it has to build the list at all — which for the asynchronous
// path is the difference between an RS256 signature that resolves immediately
// and one that waits on eleven post-quantum keygens it will not use.
// ---------------------------------------------------------------------------
function signingKeyWithoutList(alg) {
  log.debug("Entering signingKeyWithoutList(). alg=" + alg);
  const spec = stsCrypto.JWS_ALGS[alg];
  if (!spec) {
    log.debug("Leaving signingKeyWithoutList(). Unknown algorithm.");
    throw new Error('this service cannot sign with "' + alg + '"; it signs ' +
      'with ' + stsCrypto.JWS_SIGNING_ALGS.join(', ') + '.');
  }
  if (spec.family === 'hmac') {
    log.debug("Leaving signingKeyWithoutList(). HMAC has no key here.");
    throw new Error('an HS* signature is made with the client\'s own secret, ' +
      'which this service does not choose. Pass the secret to signJws() ' +
      'directly.');
  }
  if (spec.family === 'rsa') {
    log.debug("Leaving signingKeyWithoutList(). The service RSA key.");
    // `slot` is the name `pki.certifyKeySet()` files this key's certificate
    // under — one RSA key signs every RS* and PS* algorithm, so it is one slot.
    return { key: STS.privateKey, kid: STS.kid, slot: 'RS256' };
  }
  log.debug("Leaving signingKeyWithoutList(). The list decides.");
  return null;
}

function signingKeyFromList(alg, list) {
  log.debug("Entering signingKeyFromList(). alg=" + alg);
  const found = list.filter(function (one) {
    // The two EdDSA entries share an `alg`, so the CURVE decides between them
    // — `oauth2.eddsaCurve`, which defaults to Ed25519 and is the only way a
    // client can end up with an Ed448 signature (RFC 8037 gives it no member
    // to ask with).
    if (one.alg !== alg) {
      return false;
    }
    if (alg !== 'EdDSA') {
      return true;
    }
    const wanted = String(config.value('oauth2.eddsaCurve') || 'Ed25519');
    return (one.publicJwk.crv || 'Ed25519') === wanted;
  })[0];
  if (!found) {
    // This is a defect here rather than anything the caller did: the algorithm
    // is in the table, so something advertises it, and no key was generated.
    log.debug("Leaving signingKeyFromList(). No key for " + alg + ".");
    throw new Error('this service names "' + alg + '" as a signing algorithm ' +
      'and has generated no key for it. That is a defect in makeStsKeys(), ' +
      'not in the request.');
  }
  log.debug("Leaving signingKeyFromList(). " + alg + ".");
  return { key: found.privateKey, kid: found.publicJwk.kid,
           slot: certificateSlotOf(found) };
}

// ---------------------------------------------------------------------------
// THE REGISTER SLOT A KEY'S CERTIFICATE IS FILED UNDER, which is
// `pki.certifyKeySet()`'s naming read back: a curve key is `<alg>:<crv>` —
// the two EdDSA keys share an `alg` — and a post-quantum key, whose AKP JWK has
// no curve, is its `alg`. Written once here so that a signer and the
// certificate header cannot disagree about which certificate is whose.
// ---------------------------------------------------------------------------
function certificateSlotOf(entry) {
  log.debug("Entering certificateSlotOf().");
  const jwk = (entry && entry.publicJwk) || {};
  log.debug("Leaving certificateSlotOf().");
  return jwk.kty !== 'AKP' && jwk.crv ? entry.alg + ':' + jwk.crv : entry.alg;
}

// ---------------------------------------------------------------------------
// `x5c` / `x5u` FOR ONE SIGNATURE (2026-09-13).
//
// `useCaseId` names a row of `common/jose_certificate_header.js`'s table; `alg`
// and `kid` name the key that is about to sign. The answer is the header
// members to merge — `{}` for an HMAC, for a key this realm does not hold, and
// for whatever that module decides gets nothing. The policy is all over there;
// what is here is the one thing only this file can answer, which of the
// ambient realm's keys a `kid` is and what its public half looks like.
//
// **THE PUBLIC KEY IS READ WITHOUT TOUCHING A PRIVATE ONE.** The RSA key's
// comes out of the certificate it was born with and the others' out of their
// public JWKs, so in product mode a header costs no decrypt — the signature
// beside it has already paid for one.
//
// Exported for the signers that call `stsCrypto.signJws()` directly —
// `signPublishedDocument()`, the OpenID4VCI credential signers and the Domain
// Linkage Credential — which merge it into their own `header`.
// ---------------------------------------------------------------------------
function certificateHeaderFor(useCaseId, alg, kid) {
  log.debug("Entering certificateHeaderFor(). use=" + useCaseId +
            ", alg=" + alg);
  const spec = stsCrypto.JWS_ALGS[alg];
  if (!useCaseId || !spec || spec.family === 'hmac' || !kid) {
    log.debug("Leaving certificateHeaderFor(). Nothing to name.");
    return {};
  }
  const keys = stsKeysFor();
  let signer = null;
  if (kid === keys.kid) {
    signer = {
      realm: keys.realm, slot: 'RS256', kid: kid,
      spkiPem: function () {
        log.debug("Entering spkiPem().");
        log.debug("Leaving spkiPem().");
        return crypto.createPublicKey(keys.selfSignedCertPem || keys.certPem)
                     .export({ type: 'spki', format: 'pem' });
      }
    };
  } else {
    const entry = (keys.extraKeys || []).concat(keys.pqKeys || [])
      .filter(function (one) {
        return one && one.publicJwk && one.publicJwk.kid === kid;
      })[0];
    if (entry) {
      const publicJwk = entry.publicJwk;
      const entryAlg = entry.alg;
      signer = {
        realm: keys.realm, slot: certificateSlotOf(entry), kid: kid,
        spkiPem: function () {
          log.debug("Entering spkiPem().");
          if (publicJwk.kty === 'AKP') {
            log.debug("Leaving spkiPem(). Post-quantum.");
            return require('./pki').pqSubjectPublicKeyPem(entryAlg, publicJwk);
          }
          log.debug("Leaving spkiPem().");
          return crypto.createPublicKey({ key: publicJwk, format: 'jwk' })
                       .export({ type: 'spki', format: 'pem' });
        }
      };
    }
  }
  if (!signer) {
    log.debug("Leaving certificateHeaderFor(). Not a key of this realm.");
    return {};
  }
  log.debug("Leaving certificateHeaderFor().");
  return certificateHeader.headerFor(useCaseId, signer);
}

// A caller's own header with the certificate members merged UNDER it — the
// caller's wins, so a signer that already sets one (none does today) is not
// overruled. `undefined` where there is nothing to merge, which keeps a
// signature whose use case is `none` byte for byte what it was.
function withCertificateHeader(header, useCaseId, alg, kid) {
  log.debug("Entering withCertificateHeader().");
  const extra = useCaseId ? certificateHeaderFor(useCaseId, alg, kid) : {};
  if (!Object.keys(extra).length) {
    log.debug("Leaving withCertificateHeader(). Nothing added.");
    return header;
  }
  log.debug("Leaving withCertificateHeader().");
  return Object.assign(extra, header || {});
}

// ---------------------------------------------------------------------------
// THE PUBLIC JWK OF THE AMBIENT REALM'S KEY NAMED BY AN INTERNAL `kid`, or
// null. The RSA key's comes out of the certificate it was born with and the
// others' are their own public JWKs, so no private key is touched —
// `certificateHeaderFor()`'s arrangement, and the same list it searches.
// ---------------------------------------------------------------------------
function publicJwkOfKid(kid) {
  log.debug("Entering publicJwkOfKid().");
  const keys = stsKeysFor();
  if (kid && kid === keys.kid) {
    const jwk = crypto.createPublicKey(keys.selfSignedCertPem || keys.certPem)
                      .export({ format: 'jwk' });
    log.debug("Leaving publicJwkOfKid(). The RSA key.");
    return jwk;
  }
  const entry = (keys.extraKeys || []).concat(keys.pqKeys || [])
    .filter(function (one) {
      return one && one.publicJwk && one.publicJwk.kid === kid;
    })[0];
  log.debug("Leaving publicJwkOfKid(). " + (entry ? 'Found.' : 'None.'));
  return entry ? entry.publicJwk : null;
}

// The `kid` a header carries for the key with this internal `kid` —
// `keys.kidFormat`'s answer, in `common/jose_kid.js`. Exported for the
// signers that call `stsCrypto.signJws()` directly, which are the ones that
// also call `certificateHeaderFor()`: that function still takes the INTERNAL
// kid, because the internal kid is how a key is found in this service.
function publishedKidFor(kid) {
  log.debug("Entering publishedKidFor().");
  log.debug("Leaving publishedKidFor().");
  return joseKid.publishedKid(kid, function () {
    return publicJwkOfKid(kid);
  });
}

// Does a header's `kid` name the ambient realm's key with this internal kid,
// under either spelling. For the verifiers here that find their own key by
// `kid` (`ssf/ssf_events.js`, `oid4vc/vc_verifier.ts`).
function kidNamesKey(headerKid, internalKid) {
  log.debug("Entering kidNamesKey().");
  log.debug("Leaving kidNamesKey().");
  return joseKid.names(headerKid, internalKid, function () {
    return publicJwkOfKid(internalKid);
  });
}

// ---------------------------------------------------------------------------
// WHICH KEY SIGNS A GIVEN ALGORITHM — the one answer, for the whole service.
//
// `signJwt()` below signs RS256 with the service key, which is what almost
// everything here wants. This is for the places where a CLIENT chose the
// algorithm: a registered `userinfo_signed_response_alg`, a registered
// `id_token_signed_response_alg`, and anything else a specification lets a
// relying party ask for.
//
// It lives here rather than beside any one of those because the mapping from
// algorithm to key is a property of THIS SERVICE'S KEY MATERIAL and not of the
// endpoint doing the signing — it was written once inside the UserInfo
// endpoint and a second caller would have copied it.
//
// HMAC is deliberately not here: its key is the CLIENT'S secret, which this
// function has no way to know and no business holding. A caller wanting an
// HS\* signature passes the secret itself.
// ---------------------------------------------------------------------------
function signingKeyFor(alg) {
  log.debug("Entering signingKeyFor(). alg=" + alg);
  const direct = signingKeyWithoutList(alg);
  if (direct) {
    log.debug("Leaving signingKeyFor(). No list needed.");
    return direct;
  }
  log.debug("Leaving signingKeyFor(). " + alg + ".");
  return signingKeyFromList(alg, allSigningKeys());
}

// The same key, with the post-quantum half of the list generated in the pool.
function signingKeyForAsync(alg) {
  log.debug("Entering signingKeyForAsync(). alg=" + alg);
  let direct;
  try {
    direct = signingKeyWithoutList(alg);
  } catch (e) {
    log.debug("Leaving signingKeyForAsync(). Refused.");
    return Promise.reject(e);
  }
  if (direct) {
    log.debug("Leaving signingKeyForAsync(). No list needed.");
    return Promise.resolve(direct);
  }
  log.debug("Leaving signingKeyForAsync(). Waiting on the key list.");
  return allSigningKeysAsync().then(function (list) {
    return signingKeyFromList(alg, list);
  });
}

// Sign with whichever key the algorithm needs. `secret` is required for HS\*
// and ignored otherwise.
//
// `opts.header` is merged into the PROTECTED HEADER, and it is here for one
// caller with one need: RFC 8417 section 2.2 gives a Security Event Token
// `typ: "secevent+jwt"`, and a receiver that dispatches on the media type —
// and several do — drops one without it with no error anybody sees. It is
// passed straight through to `common/crypto.js`, which honours it on all
// three of its signing paths since 2026-08-31; before that the two
// hand-rolled ones ignored it, so the same call produced a different header
// depending on which algorithm was chosen.
//
// `opts.certificateHeader` names the use case whose setting decides whether
// the token carries `x5c` or `x5u` (2026-09-13) — see
// `certificateHeaderFor()`. A caller that names none gets neither, and
// `tests/jose_certificate_header.js` fails on a signing call that names none.
function signJwtAs(payload, alg, secret, opts) {
  log.debug("Entering signJwtAs().");
  const options = opts || {};
  log.debug("Entering signJwtAs(). alg=" + alg);
  const spec = stsCrypto.JWS_ALGS[alg];
  if (spec && spec.family === 'hmac') {
    if (!secret) {
      log.debug("Leaving signJwtAs(). No secret for an HMAC algorithm.");
      throw new Error(alg + ' is signed with the client_secret, and this ' +
        'client has none — a public client cannot use a symmetric algorithm.');
    }
    // No `kid`: the key is the client_secret, which is in no JWK Set, and a
    // kid pointing into the JWKS would send the client to the wrong key.
    log.debug("Leaving signJwtAs(). HMAC.");
    // certificate-header: none — an HMAC key is a client's secret and has no
    // certificate to name.
    return stsCrypto.signJws(payload, secret,
                             { algorithm: alg, header: options.header });
  }
  const signer = signingKeyFor(alg);
  log.debug("Leaving signJwtAs(). " + alg + ".");
  return stsCrypto.signJws(payload, signer.key,
                           { algorithm: alg,
                             keyid: publishedKidFor(signer.kid),
                             header: withCertificateHeader(options.header,
                               options.certificateHeader, alg, signer.kid) });
}

// ---------------------------------------------------------------------------
// THE SAME SIGNATURE, OFF THIS PROCESS'S THREAD, and the two call sites that
// use it are the two a CLIENT can point at a post-quantum algorithm: the ID
// Token (`id_token_signed_response_alg`) and the signed UserInfo response
// (`userinfo_signed_response_alg`). An SLH-DSA-SHAKE-128s token took 14.6 and
// 15.4 seconds on 2026-08-29, and for those seconds this service answered
// nobody — see common/worker.js.
//
// Everything else it can be asked for resolves with the value signJwtAs()
// computed, unchanged and not deferred: an HS256 or RS256 signature is
// microseconds, and an IPC round trip to save that would be a cost with no
// saving. `opts.session` is the pool's routing hint and may be omitted.
// ---------------------------------------------------------------------------
function signJwtAsAsync(payload, alg, secret, opts) {
  log.debug("Entering signJwtAsAsync().");
  const options = opts || {};
  log.debug("Entering signJwtAsAsync(). alg=" + alg);
  const spec = stsCrypto.JWS_ALGS[alg];
  if (spec && spec.family === 'hmac') {
    try {
      // certificate-header: none — an HMAC signature, which has no certificate.
      const signed = signJwtAs(payload, alg, secret,
                               { header: options.header });
      log.debug("Leaving signJwtAsAsync(). HMAC, in process.");
      return Promise.resolve(signed);
    } catch (e) {
      log.debug("Leaving signJwtAsAsync(). Refused.");
      return Promise.reject(e);
    }
  }
  log.debug("Leaving signJwtAsAsync(). " + alg + ".");
  return signingKeyForAsync(alg).then(function (signer) {
    return stsCrypto.signJwsAsync(payload, signer.key,
      { algorithm: alg, keyid: publishedKidFor(signer.kid),
        session: options.session,
        header: withCertificateHeader(options.header,
                                      options.certificateHeader, alg,
                                      signer.kid) });
  });
}

// --- token minting ----------------------------------------------------------
// Every OAuth token this server issues goes through here, so this is where each
// one is recorded: the claim set before it is signed, and the JWT after.
//
// `context` is optional and is NOT part of the token: nothing in it is signed,
// read back or sent anywhere. It is how a caller states what the payload cannot
// say — at present the browser sign-on session the token was issued under and
// the grant that issued it, neither of which appears in any claim, because
// OIDC's `sid` is for front-channel logout and adding claims to every token to
// make an admin page easier to draw would change what every client receives. A
// caller that passes nothing is unaffected, which is why the parameter is
// optional.
//
// `opts.certificateHeader` is `signJwtAs()`'s, for the RS256 key. It is a
// THIRD parameter rather than a member of `context`, because `context` is
// handed to the token registry whole and a header decision is not a fact about
// the token anybody should find recorded there.
//
// `opts.header` is merged into the protected header, `signJwtAs()`'s option
// for the same reason: RFC 9068 section 2.1 gives a JWT access token
// `typ: "at+jwt"`, and `oauth2.js`'s `accessToken()` is the caller that asks
// for it (2026-09-13). The refresh token signed here names none and keeps
// `typ: "JWT"`. `alg` and `kid` stay `crypto.js`'s to set.
function signJwt(payload, context, opts) {
  log.debug("Entering signJwt(). typ=" + (payload.typ || '(none)'));
  const certificateHeaderMembers = withCertificateHeader(
    (opts && opts.header) || undefined,
    opts && opts.certificateHeader, 'RS256', STS.kid);
  const kid = publishedKidFor(STS.kid);
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'before ' +
      'signing',
              { header: Object.assign({ alg: 'RS256', kid: kid },
                                      certificateHeaderMembers || {}),
                payload: payload });
  const signed = stsCrypto.signJws(payload, STS.privateKey,
                                   { algorithm: 'RS256', keyid: kid,
                                     header: certificateHeaderMembers });
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'after ' +
      'signing', signed);
  // Every token this service issues passes through here, which is what makes
  // the admin console's count a count and not an estimate. Wrapped because a
  // throw in the statistics would otherwise fail the request that was issuing
  // the token — the tail wagging the dog.
  if (jwtRecorder) {
    try {
      jwtRecorder(payload, signed, context || null);
    } catch (e) {
      log.error(errorCodes.tag('STS-CORE-0027') +
                'the JWT recorder threw and was ignored; the token itself is ' +
                'unaffected: ' + e.message);
    }
  }
  log.debug("Leaving signJwt().");
  return signed;
}

function vciError(res, status, error, description) {
  // error-code: none — the helper's trace line, not a call to it.
  log.debug("Entering vciError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').send(JSON.stringify({
    error: error, error_description: description
  }));
  // error-code: none — the helper's trace line, not a call to it.
  log.debug("Leaving vciError().");
}

// ---------------------------------------------------------------------------
// THE URL THIS SERVICE IS BEING REACHED AT, which is the thing every issuer,
// every endpoint in both discovery documents and every DID here is built from.
//
// It comes off the REQUEST rather than out of configuration, which is what
// makes one process answer correctly as http://localhost:8081 from a host run,
// as http://sts:8081 on a compose network and through a published port without
// being told which. That has been true since the beginning and none of it
// changes here.
//
// What is new is the reverse-proxy case RFC 9700 section 2.6 is about. When
// something terminates TLS in front of this service, the socket sees http and
// the last hop's host, while the CLIENT used https and a different name — so a
// document built from the socket publishes URLs no client can use, and an
// `iss` no client will accept. `X-Forwarded-Proto` and `X-Forwarded-Host` are
// how a proxy says what the client used.
//
// **They are believed only when `global.trustProxy` says a proxy is there.**
// With nothing in front, those are ordinary request headers and any caller can
// set them — so believing them would let a client choose what this service
// thinks its own issuer and endpoints are. The setting is the whole of the
// difference and it is read per request, so it can be turned on without a
// restart when somebody puts a proxy in.
//
// `forwardedFrom()` is shared with dpop.js's htu derivation, which used to make
// this decision differently — it honoured the headers unconditionally — so that
// two functions in one service disagreed about whether a forwarded header was
// believable. One function now, and one setting.
// ---------------------------------------------------------------------------
function trustProxy() {
  log.debug("Entering trustProxy().");
  log.debug("Leaving trustProxy().");
  return !!config.value('global.trustProxy');
}

// The scheme and host a request should be understood as having arrived at:
// the forwarded ones where a proxy is trusted, the socket's otherwise. A
// comma-separated list takes its FIRST value, which is the client-facing hop —
// each proxy appends, so the left-hand end is the one furthest from here.
function forwardedFrom(req) {
  log.debug("Entering forwardedFrom().");
  const socketProto = (req && req.protocol) || 'http';
  const socketHost = (req && req.get && req.get('host')) || ('localhost:' +
      PORT);
  // AND FROM A PEER THE DEPLOYMENT VOUCHES FOR (2026-09-14, #46): with
  // `global.trustedProxies` set, a caller that reached this node directly —
  // past the load balancer — is answered from the socket, whatever it sent.
  if (!trustProxy() || !clientAddress.forwardedBelieved(req)) {
    log.debug("Leaving forwardedFrom().");
    return { proto: socketProto, host: socketHost, forwarded: false };
  }
  const headers = (req && req.headers) || {};
  const proto = String(headers['x-forwarded-proto'] || socketProto)
    .split(',')[0].trim().toLowerCase() || socketProto;
  const host = String(headers['x-forwarded-host'] || socketHost)
    .split(',')[0].trim() || socketHost;
  log.debug("Leaving forwardedFrom().");
  return {
    proto: proto, host: host,
    forwarded: !!(headers['x-forwarded-proto'] || headers['x-forwarded-host'])
  };
}

// ---------------------------------------------------------------------------
// IT INCLUDES THE TRUST REALM'S PATH PREFIX, AND THAT ONE LINE IS WHY EIGHTY
// CALL SITES ARE REALM-AWARE WITHOUT HAVING BEEN EDITED.
//
// Every issuer identifier, every RFC 8414 and OpenID Provider metadata
// document, every SAML entityID and metadata URL, every credential issuer
// identifier, every did:web, every DPoP `htu` and every redirect this service
// builds is `baseUrlOf(req)` with a path glued to it. Returning
// `http://host:8081/realm/acme` here rather than `http://host:8081` makes all
// of them name the realm the request arrived in — which is exactly what makes
// two realms two authorization servers rather than one served twice.
//
// It is EMPTY in the default realm, so this is the same string it always was.
// ---------------------------------------------------------------------------
//
// **`global.publicBaseUrl` PINS IT.** Left empty — the default — the base is
// read off the request, which is what lets one process answer correctly under
// every name it is reached by. Set, it is the base whatever `Host` a request
// carried: a caller can then no longer choose what this service believes its
// own issuer, its callback addresses and its WebAuthn origin are, which is the
// property a deployed identity provider needs and a mock reached by three
// container names does not. The realm prefix is still appended.
// ---------------------------------------------------------------------------
function pinnedBaseUrl() {
  log.debug("Entering pinnedBaseUrl().");
  const raw = String(config.value('global.publicBaseUrl') || '').trim();
  log.debug("Leaving pinnedBaseUrl().");
  return raw ? raw.replace(/\/+$/, '') : '';
}

function baseUrlOf(req) {
  log.debug("Entering baseUrlOf().");
  const pinned = pinnedBaseUrl();
  if (pinned) {
    const base = pinned + realms.currentPrefix();
    log.debug("Leaving baseUrlOf(). base=" + base + " (global.publicBaseUrl)");
    return base;
  }
  const from = forwardedFrom(req);
  const base = from.proto + '://' + from.host + realms.currentPrefix();
  log.debug("Leaving baseUrlOf(). base=" + base +
            (from.forwarded ? " (from forwarded headers; global.trustProxy " +
                              "is on)" : ""));
  return base;
}

// ---------------------------------------------------------------------------
// THE ADDRESS A LISTENER BINDS, AND THE ADDRESS THIS PROCESS DIALS ITSELF ON.
//
// Every socket family here used to bind the literal `0.0.0.0` whatever
// `global.host` said, so `STS_HOST=127.0.0.1` confined the HTTP port and left
// the KDC and both LDAP ports open on every interface — a setting
// that did half of what it claims is worse than none. `listenHost()` is what
// they bind now.
//
// `loopbackHost()` is its other half: the three places this service makes a
// request to ITSELF (the OpenID Connect back channel, the Shared Signals push
// to its own receivers) dialled `127.0.0.1` literally, which reaches nothing
// when the listener is bound to one interface address or to IPv6 only. A
// wildcard bind is reachable on loopback, so it answers loopback in the
// wildcard's own family; a specific address is dialled as itself.
// ---------------------------------------------------------------------------
function listenHost() {
  log.debug("Entering listenHost().");
  log.debug("Leaving listenHost().");
  return String(config.value('global.host') || '0.0.0.0');
}

function loopbackHost() {
  log.debug("Entering loopbackHost().");
  const host = listenHost();
  if (host === '0.0.0.0' || host === '') {
    log.debug("Leaving loopbackHost().");
    return '127.0.0.1';
  }
  if (host === '::' || host === '[::]') {
    log.debug("Leaving loopbackHost().");
    return '::1';
  }
  log.debug("Leaving loopbackHost().");
  return host.replace(/^\[|\]$/g, '');
}

// A host as it goes into a URL: an IPv6 literal needs its brackets there and
// nowhere else.
function hostForUrl(host) {
  log.debug("Entering hostForUrl().");
  const h = String(host);
  log.debug("Leaving hostForUrl().");
  return h.indexOf(':') >= 0 && h[0] !== '[' ? '[' + h + ']' : h;
}


// Where the wallet lives, as a URL the BROWSER can use. Shared because the
// Credential Offer pages and the OID4VP request pages both hand the End-User
// back to it (oid4vp.walletUrl falls back to this one).
//
// A FUNCTION rather than the constant it used to be, and that is the shape
// every runtime-settable value takes here: a constant is read once at require
// time, so /admin/config could change the setting and every caller would go
// on using what it captured at startup.
function walletBaseUrl() {
  log.debug("Entering walletBaseUrl().");
  log.debug("Leaving walletBaseUrl().");
  return config.value('oid4vci.walletUrl');
}

// Whoever signs in at the login screen, as the identity every token then
// describes.
//
// **IN DEVELOPMENT MODE IT IS A PERSONA AND SAYS SO**: a family name of `Mock`,
// an address at `sts.example` and `email_verified: true`, none of which is
// true of anybody — which is what a client exercising claim handling wants from
// a server that asks nobody for anything.
//
// **IN PRODUCT MODE IT INVENTS NOTHING** (`mode.inventsClaimValues()`). A
// relying party that links accounts on `email` because `email_verified` said so
// would be linking on a fact this service made up, and that is not a fidelity
// problem but an account-takeover one. So the persona fields are OMITTED here
// and the issuance sites fill them from the person's own directory entry,
// through the same claim-attribute resolver every other directory attribute
// reaches a token by. What stays is what this function genuinely knows: the
// name that authenticated, and the subject derived from it.
function userFor(username) {
  log.debug("Entering userFor(). username=" + username);
  const name = String(username || 'mock-user');
  const user = {
    // FROM THE DIRECTORY (2026-09-14), and '' where it holds nobody — see the
    // subject resolver above. Callers that ISSUE something to a person make
    // sure the entry exists first (`authn.startSession()`, the token grants),
    // so an empty value here is a preview, a lookup of somebody who is not
    // there, or a process with no directory.
    sub: subjectForName(name),
    username: name,
    preferred_username: name
  };
  if (mode.inventsClaimValues()) {
    user.name = name + ' (mock)';
    user.given_name = name;
    user.family_name = 'Mock';
    user.email = realms.inventedMailOf(name);
    user.email_verified = true;
  }
  log.debug("Leaving userFor(). sub=" + user.sub);
  return user;
}

// ---------------------------------------------------------------------------
// THE ONE SPELLING OF A CERTIFICATE SUBJECT.
//
// Here rather than in `tls/tls_server.js`, where it was written, because FOUR
// callers now need the same string and two of them cannot reach that module.
// `scim_auth.js` and `spiffe_auth.js` require it directly and always could;
// `spiffe_ca.js` cannot, and the reason is rule 3e's test rather than a
// preference — `admin-ui/admin.ts` requires `spiffe_ca.js`, and `server.js`
// requires `admin.js` at 18 and `tls_server.js` at 20, so a require from that
// module would pull every `/tls*` route into the express router ahead of the
// console's and `GET /admin/sts-metadata` walks that router. A leaf in
// `helpers.js` moves no route and closes no cycle, which is what a shared
// spelling has to be.
//
// WHY THIS FORM AT ALL, and why it is not what a report shows. Node hands a
// subject back most-significant-first (`C=US, O=Example, CN=alice`) and
// `openssl x509 -subject` prints it that way too. A DN as LDAP and every RFC
// 4514 document writes it is the REVERSE — leaf first,
// `CN=alice,O=Example,C=US` — with no spaces after the commas, and THAT is the
// form this service files an identity under and the directory builds an entry
// from. One form used for both would be wrong in whichever direction it was
// wrong: a report that disagreed with openssl, or a DN nothing in LDAP would
// accept.
//
// TWO SPELLINGS OF ONE DN IS TWO PEOPLE ON /admin/users, which is the whole
// reason this is one function. A verified TLS client certificate, a client
// certificate at the SCIM endpoints, an X509-SVID at the SPIRE Server API and
// an X509-SVID this service has just MINTED all produce a subject, and any two
// of them that render it differently put two objects in the directory for one
// identity.
//
// IT TAKES BOTH SHAPES NODE PRODUCES, because node has two and this service
// meets both. `tls.TLSSocket#getPeerCertificate()` gives an OBJECT keyed by
// attribute type, with repeated types collapsed into an array (`OU=A,OU=B`
// arrives as `OU: ['A','B']`, and those are separate RDNs rather than one
// multi-valued RDN, so each becomes its own component here).
// `crypto.X509Certificate#subject` gives a STRING with one `type=value` per
// LINE, in the same most-significant-first order — which is what
// `spiffe_ca.js` has, because it reads back the certificate it just issued
// rather than one that arrived on a socket. Anything else is returned as it
// stands.
//
// Values are ESCAPED. A comma inside `O=Example\, Ltd` that went through
// unescaped would turn one RDN into two and name an object that does not exist.
// ---------------------------------------------------------------------------
function escapeRdnValue(value) {
  log.debug("Entering escapeRdnValue().");
  const text = String(value == null ? '' : value);
  // RFC 4514 section 2.4: these are escaped anywhere, '#' only leading, and a
  // space only when it leads or trails.
  let out = text.replace(/([\\,+"<>;=])/g, '\\$1');
  if (out.indexOf('#') === 0) out = '\\' + out;
  out = out.replace(/^ /, '\\ ').replace(/ $/, '\\ ');
  log.debug("Leaving escapeRdnValue().");
  return out;
}

function dnRfc4514(dn) {
  log.debug("Entering dnRfc4514().");
  if (!dn) {
    log.debug("Leaving dnRfc4514().");
    return '';
  }
  // crypto.X509Certificate's shape: one `type=value` per line. Split rather
  // than parsed, because node has already done the parsing — a value that
  // itself contains a newline is not representable in that output and so
  // cannot arrive here.
  if (typeof dn === 'string') {
    if (dn.indexOf('\n') < 0) {
      // A single-component subject, or something already in one line. Returned
      // as it stands rather than guessed at: a caller that already holds an
      // RFC 4514 string must get it back unchanged.
      log.debug("Leaving dnRfc4514().");
      return dn.trim();
    }
    log.debug("Leaving dnRfc4514().");
    return dn.split('\n').map(function (line) {
      const text = String(line).trim();
      const eq = text.indexOf('=');
      if (eq < 0) {
        return '';
      }
      return text.slice(0, eq) + '=' + escapeRdnValue(text.slice(eq + 1));
    }).filter(function (part) {
      return part !== '';
    }).reverse().join(',');
  }
  if (typeof dn !== 'object') {
    log.debug("Leaving dnRfc4514().");
    return String(dn);
  }
  const parts = [];
  Object.keys(dn).forEach(function (key) {
    const value = dn[key];
    (Array.isArray(value) ? value : [value]).forEach(function (one) {
      parts.push(key + '=' + escapeRdnValue(one));
    });
  });
  log.debug("Leaving dnRfc4514().");
  return parts.reverse().join(',');
}

// ---------------------------------------------------------------------------
// A SMALL COUNT AS THE WORD FOR IT, for the refusal sentences that name what
// they know: "Unknown action \"x\". The seven are: …".
//
// It exists because those sentences used to carry the number as prose beside a
// list built from a table, and the two parted company exactly where it hurts —
// `applicationsAction()` said "The six are" over seven actions after
// `refresh-metadata` was added, and `createApplication()` said "The eight are"
// over nine kinds after `kerberos-service` was. Neither is cosmetic: the parent
// project's tests/admin_api.js READS the first of those sentences to check that
// every console action has an /admin-api operation, so a list short by one
// turns that check off for the missing one.
//
// Beyond fifteen it hands back the digits, because "twenty-three" reads worse
// than "23" in a sentence somebody is scanning for a name.
// ---------------------------------------------------------------------------
const NUMBER_WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six',
                      'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve',
                      'thirteen', 'fourteen', 'fifteen'];

function numberWord(count) {
  log.debug("Entering numberWord().");
  const n = Number(count);
  if (!Number.isInteger(n) || n < 0 || n >= NUMBER_WORDS.length) {
    log.debug("Leaving numberWord().");
    return String(count);
  }
  log.debug("Leaving numberWord().");
  return NUMBER_WORDS[n];
}

// ---------------------------------------------------------------------------
// A RESPONSE OBJECT THAT RECORDS INSTEAD OF WRITING.
//
// It exists so that a handler which ANSWERS a request itself can be called by
// something that needs its VERDICT rather than its reply. There is exactly one
// such handler here and it is the reason this is shared:
// `dpop.presentedAccessToken()` is the single access-token check the protected
// endpoints in this service share — it carries the RFC 9449 proof and the
// 401/DPoP-Nonce handshake, the RFC 8705 certificate binding, the RFC 9700
// refusal of a token in a query string and the RFC 8707 audience check — and
// it writes an OAuth `{error, error_description}` body. A caller that owes its
// client a DIFFERENT error shape (SCIM's RFC 7644 section 3.12 Error object, or
// the Shared Signals Framework's `{err, description}`) hands it one of these
// and translates what it would have said.
//
// **THE HEADERS IT SET ARE KEPT VERBATIM AND THAT IS THE PART THAT MATTERS
// MOST.** DPoP-Nonce and the `use_dpop_nonce` challenge are how a client learns
// to retry, and dropping them leaves a conforming client unable to proceed with
// no error to point at.
//
// It was written inside `scim/scim_auth.ts` and moved here on 2026-08-31 when
// `ssf/ssf_auth.ts` became the second caller. A second copy of this would be a
// second thing to update, and it would be a version behind within a release —
// which is the argument that file already made about not writing a second
// access-token check.
// ---------------------------------------------------------------------------
function capturingResponse() {
  log.debug("Entering capturingResponse().");
  const captured = { status: 0, headers: {}, body: '' };
  const res = {
    set: function (name, value) {
      log.debug("Entering set().");
      captured.headers[name] = value;
      log.debug("Leaving set().");
      return res;
    },
    setHeader: function (name, value) {
      log.debug("Entering setHeader().");
      captured.headers[name] = value;
      log.debug("Leaving setHeader().");
      return res;
    },
    status: function (code) {
      log.debug("Entering status().");
      captured.status = code;
      log.debug("Leaving status().");
      return res;
    },
    type: function () {
      log.debug("Entering type().");
      log.debug("Leaving type().");
      return res;
    },
    send: function (body) {
      log.debug("Entering send().");
      captured.body = String(body === undefined ? '' : body);
      log.debug("Leaving send().");
      return res;
    },
    json: function (body) {
      log.debug("Entering json().");
      captured.body = JSON.stringify(body);
      log.debug("Leaving json().");
      return res;
    },
    end: function (body) {
      log.debug("Entering end().");
      captured.body = String(body === undefined ? '' : body);
      log.debug("Leaving end().");
      return res;
    }
  };
  log.debug("Leaving capturingResponse().");
  return { res: res, captured: captured };
}

// What the captured reply was trying to say, as one sentence. The body is
// whatever the handler wrote; today that is always JSON, and a change there
// must not turn a 401 into an exception here — so the raw text is a better
// answer than nothing.
function capturedDescription(captured) {
  log.debug("Entering capturedDescription().");
  try {
    const parsed = JSON.parse((captured && captured.body) || '{}');
    log.debug("Leaving capturedDescription(). JSON.");
    return String(parsed.error_description || parsed.error || '').trim();
  } catch (e) {
    log.debug("Caught in capturedDescription(): " + ((e && e.message) || e));
    log.debug("Leaving capturedDescription(). Not JSON.");
    return String((captured && captured.body) || '').trim();
  }
}

module.exports = {
  signingKeyFor: signingKeyFor,
  signingKeyForAsync: signingKeyForAsync,
  allSigningKeys: allSigningKeys,
  allSigningKeysAsync: allSigningKeysAsync,
  signJwtAs: signJwtAs,
  signJwtAsAsync: signJwtAsAsync,
  certificateHeaderFor: certificateHeaderFor,
  publishedKidFor: publishedKidFor,
  kidNamesKey: kidNamesKey,
  warmPqKeys: warmPqKeys,
  prepareKeySet: prepareKeySet,
  prepareKeySets: prepareKeySets,
  log: log,
  logArtifact: logArtifact,
  headersOf: headersOf,
  bodyOf: bodyOf,
  PORT: PORT,
  HOST: HOST,
  STS: STS,
  resetStsKeys: resetStsKeys,
  xmlEscape: xmlEscape,
  genId: genId,
  firstByLocal: firstByLocal,
  textByLocal: textByLocal,
  iso: iso,
  baseUrlOf: baseUrlOf,
  pinnedBaseUrl: pinnedBaseUrl,
  listenHost: listenHost,
  loopbackHost: loopbackHost,
  hostForUrl: hostForUrl,
  forwardedFrom: forwardedFrom,
  trustProxy: trustProxy,
  b64u: b64u,
  b64uDecode: b64uDecode,
  jsonFromB64u: jsonFromB64u,
  nowSec: nowSec,
  randomId: randomId,
  bbsKeyPairForSharing: bbsKeyPairForSharing,
  newBbsKeyPairText: newBbsKeyPairText,
  bbsKeyPairFromText: bbsKeyPairFromText,
  bbsKeyPair: bbsKeyPair,
  walletBaseUrl: walletBaseUrl,
  parseBody: parseBody,
  multipartParts: multipartParts,
  // The repeated-parameter reader beside it. See its header for why parseBody()
  // is not the place.
  bodyValues: bodyValues,
  oauthError: oauthError,
  vciError: vciError,
  signJwt: signJwt,
  setJwtRecorder: setJwtRecorder,
  userFor: userFor,
  setSubjectResolver: setSubjectResolver,
  hasSubjectResolver: hasSubjectResolver,
  subjectForName: subjectForName,
  nameForSubject: nameForSubject,
  LEGACY_SUBJECT_PREFIX: LEGACY_SUBJECT_PREFIX,
  hasScope: hasScope,
  escapeRdnValue: escapeRdnValue,
  dnRfc4514: dnRfc4514,
  // The whole key set of ONE named realm, for the two callers that need a
  // realm's key while not in that realm: the console's realm list, which shows
  // each realm's kid, and the logout that has to know whose token it is looking
  // at. Everything else reads `STS` and gets the ambient realm's, which is what
  // it wanted.
  stsKeysFor: stsKeysFor,
  // The OpenID4VCI credential request-encryption key, which is a member of the
  // realm's key set since 2026-09-12 — see makeRequestEncryptionKey(). The
  // JWK builder is exported for `keystore.js`'s readers and the tests, so that
  // a key read back from a blob publishes exactly what a generated one does.
  requestEncryptionKeyFor: requestEncryptionKeyFor,
  refreshTokenKeysFor: refreshTokenKeysFor,
  requestObjectKeysFor: requestObjectKeysFor,
  makeRefreshTokenEncryptionKeys: makeRefreshTokenEncryptionKeys,
  requestEncryptionJwkOf: requestEncryptionJwkOf,
  VCI_REQUEST_ENC_ALG: VCI_REQUEST_ENC_ALG,
  // The count as a word, for the refusal sentences that name what they
  // know. See the block above it for the two sentences that went stale.
  numberWord: numberWord,
  // The recording response object and its one-sentence reading of what
  // the handler tried to say. See the block above them.
  capturingResponse: capturingResponse,
  capturedDescription: capturedDescription
};
