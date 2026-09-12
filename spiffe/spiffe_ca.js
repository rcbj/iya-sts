'use strict';
//
// File: spiffe_ca.js
//
// ---------------------------------------------------------------------------
// THE TRUST DOMAIN'S ISSUING AUTHORITY: the X.509 CA that signs X509-SVIDs, the
// JWT authority that signs JWT-SVIDs, the bundle that publishes both, and the
// bundles of foreign trust domains this one federates with.
//
// It is a LIBRARY (rule 3): it registers no route, so its position in the
// require order does not matter, and it requires `helpers.js`, `config.js`,
// `spiffe_id.js` and the two vendored PKI modules — none of which requires it
// back, so it cannot join a cycle.
//
// ---------------------------------------------------------------------------
// THE PKI CODE HERE IS NOT NEW, AND THAT IS THE POINT
//
// `x509.js`, `key_material.js`, `jose_jwe.js` and `crypto_bytes.js` are
// VENDORED COPIES of the OAuth2/OIDC Debugger's own modules — byte-identical,
// the way `bbs2023.js` and `krb5_spnego.js` already are in this repository.
// They are the code behind that project's PKI page, and the reason to take them
// rather than to write a fifth certificate builder here is `tests/pki_x509.js`
// over there: it drives roughly 240 certificates — every key algorithm against
// every signature algorithm, every X.509v3 extension, a four-deep chain — and
// checks each one with OPENSSL rather than by reading back what the same code
// just wrote. Four real defects were found by it, and all four produced
// certificates that parsed perfectly and were refused by something else with a
// message about a signature.
//
// What that buys here specifically: **EC P-256 is the default**, which is what
// SPIRE issues and what the X509-SVID specification recommends. `node-forge` —
// which `helpers.js` and `tls_server.js` use for the STS signing key and the
// TLS server certificate — cannot sign with an EC key at all, so a CA built on
// it would have been RSA-only. RSA is permitted by the specification and would
// have interoperated; it would simply not have been what a client author sees
// in front of a real SPIRE deployment.
//
// **Do not edit the four vendored files.** A change here that is not also made
// there is a fork nobody else can consume, and the sync is checked by hand
// (this repository has no tests yet — see CLAUDE.md).
//
// ---------------------------------------------------------------------------
// WHAT IS GENERATED PER START, AND WHAT IS NOT ANY MORE (2026-09-11)
//
// This section was unconditional and said EVERYTHING IS GENERATED PER START AND
// HELD IN MEMORY — *exactly like the signing key in `helpers.js` and the TLS
// certificate in `tls_server.js`, and for the same two reasons: nothing about a
// mock is worth persisting, and a certificate committed to a repository is a
// private key committed to a repository.*
//
// **THE SECOND REASON IS UNTOUCHED AND THE FIRST HAS A MODE ON IT NOW.** The
// X.509 authority is `common/pki.js`'s SPIFFE Issuing CA, so it INHERITS THAT
// MODULE'S MODE: in development — the default — the hierarchy dies with the
// process exactly as before, and in PRODUCT mode `keystore.js` keeps it, so the
// anchor survives a restart. The JWT authority has no certificate and no
// hierarchy to hang from and is generated per start in either mode.
//
// **AND THE CONSEQUENCE FOR A CALLER IS MUCH SMALLER THAN IT WAS, WHICH IS THE
// POINT OF THE MOVE.** It used to be: *the trust bundle changes on every
// restart, so a workload holding a cached bundle will fail to verify an SVID
// minted after a restart.* The bundle is the ROOT now, so it changes when the
// ROOT does — never, in product mode, and per start in development. A rotation
// of the authority does not change it at all. `GET /spiffe/bundle` and the
// endpoint's `spiffe_refresh_hint` are still what a consumer comes back to.
//
// ---------------------------------------------------------------------------
// INITIALISATION IS ASYNCHRONOUS, WHICH NOTHING ELSE IN THIS SERVICE IS
//
// `key_material.js` generates keys through Web Crypto, which is async, and
// `x509.js` signs through it too. Node modules load synchronously, so the
// authorities cannot exist at require time the way `helpers.js`'s STS key does.
//
// The shape is one promise, started at require time and awaited by every
// caller: `await ca.ready()`. It is NOT a lazy "generate on first use" — that
// would put a two-second key generation inside whichever request happened to
// arrive first, and on an RSA-4096 authority that request would look like a
// hang. Starting it at require time means it is almost always finished before
// anything is listening, and `ready()` is then a resolved promise.
//
// The one rule that comes out of it: **every entry point in this module is
// async and awaits `ready()` itself.** A caller cannot forget to, and a caller
// that reaches this module during startup gets the right answer rather than an
// empty bundle. `state()` is the single exception and says so.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
// For the federated bundle store below — a shared, persisted map rather than
// a plain one, so every process in this service sees the same bundles.
const realms = require('../common/realms');
const jwt = require('jsonwebtoken');
// One signer and one verifier for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');
const pkijs = require('pkijs');
const asn1js = require('asn1js');
const { log, b64u, nowSec, dnRfc4514 } = require('../common/helpers');
const config = require('../common/config');
const spiffeId = require('./spiffe_id');
const keys = require('../common/vendored/key_material');
const x509 = require('../common/vendored/x509');

// ---------------------------------------------------------------------------
// THE SETTINGS, READ WHERE THEY ARE USED.
//
// The three that are captured — the trust domain and the two key types — are
// captured because the authorities are BUILT from them at startup, which is
// exactly what `config.js` marks `runtime: false` for. Changing
// `spiffe.trustDomain` while this process runs would leave a CA whose
// certificates name the old one, so config.js refuses the change and names this
// as the reason. Everything else here is read per call.
// ---------------------------------------------------------------------------
const TRUST_DOMAIN = String(config.value('spiffe.trustDomain') || 'example.org')
  .trim().toLowerCase();

function svidTtlSeconds() { return config.value('spiffe.svidTtl'); }
function jwtSvidTtlSeconds() { return config.value('spiffe.jwtSvidTtl'); }
function refreshHintSeconds() { return config.value('spiffe.refreshHint'); }
function svidSubject() { return config.value('spiffe.svidSubject'); }
function maxFederatedBundles() { return config.value('spiffe.maxFederatedBundles'); }

// ---------------------------------------------------------------------------
// WHICH SIGNATURE ALGORITHM GOES WITH WHICH KEY.
//
// A table rather than a switch at each of the three signing sites, because the
// failure mode of getting it wrong is the one `x509.js`'s own header warns
// about: a certificate whose declared algorithm and actual signature disagree
// parses perfectly and is refused with a message about a signature, naming
// neither hash.
//
// `jwtAlg` is the JWS `alg` for the JWT authority. **Ed25519 has none here**,
// and that is a limitation of the signer rather than of the specification:
// `jsonwebtoken` — this repository's JWS implementation, already a dependency —
// does not sign EdDSA, and the JWT-SVID specification's algorithm list does not
// require it. An Ed25519 X.509 authority is fine; an Ed25519 JWT authority is
// refused at startup with that sentence, rather than accepted and then failing
// at the first FetchJWTSVID.
// ---------------------------------------------------------------------------
const KEY_TYPES = [
  { id: 'ec-p256', label: 'ECDSA P-256', kind: 'ec',
    sigAlg: 'sha256-ecdsa', jwtAlg: 'ES256',
    what: 'What SPIRE issues by default and what the X509-SVID specification ' +
          'recommends. The default here for the same reason.' },
  { id: 'ec-p384', label: 'ECDSA P-384', kind: 'ec',
    sigAlg: 'sha384-ecdsa', jwtAlg: 'ES384',
    what: 'A larger curve, for a client that pins one.' },
  { id: 'ec-p521', label: 'ECDSA P-521', kind: 'ec',
    sigAlg: 'sha512-ecdsa', jwtAlg: 'ES512',
    what: 'Larger still. Worth knowing that roughly one P-521 signature in ' +
          '256 is a byte shorter than the other 255, which is a real ' +
          'interoperability edge and is why x509.js has a function for it.' },
  { id: 'rsa-2048', label: 'RSA 2048', kind: 'rsa',
    sigAlg: 'sha256-rsa', jwtAlg: 'RS256',
    what: 'The floor the X509-SVID specification permits for RSA. Slower to ' +
          'generate — noticeable at startup — and produces much larger SVIDs.' },
  { id: 'rsa-4096', label: 'RSA 4096', kind: 'rsa',
    sigAlg: 'sha256-rsa', jwtAlg: 'RS256',
    what: 'Several seconds to generate at startup, which is worth knowing ' +
          'before wondering why the bundle endpoint is not answering yet.' },
  { id: 'ed25519', label: 'Ed25519', kind: 'okp',
    sigAlg: 'ed25519', jwtAlg: null,
    what: 'Permitted for X.509 by the specification. NOT available for the ' +
          'JWT authority: jsonwebtoken, this service\'s JWS implementation, ' +
          'does not sign EdDSA.' }
];

function keyTypeById(id) {
  const wanted = String(id == null ? '' : id).trim();
  for (let i = 0; i < KEY_TYPES.length; i++) {
    if (KEY_TYPES[i].id === wanted) return KEY_TYPES[i];
  }
  return null;
}

// ---------------------------------------------------------------------------
// THE STATE. All of it in memory, all of it gone when the process ends.
//
// `x509Authorities` and `jwtAuthorities` are LISTS rather than single values,
// and the reason is what a bundle is FOR. Rotation appends a new authority and
// keeps the old one published: an SVID minted a minute ago is still valid, and
// a workload that fetched the bundle before the rotation must still be able to
// verify one minted after it. The FIRST element is the active one — what
// everything is signed with now — and the rest are retired but still trusted.
// Publishing only the active authority is the mistake that makes a rotation
// look like an outage.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// PERSISTED, ENCODED ON THE WAY IN (2026-09-08), AND PER REALM (2026-09-11).
//
// These were two module arrays, which is one PROCESS's certificate authority.
// With request workers that is a service whose bundle depends on who answers:
// a worker publishing `GET /spiffe` offered keys that verify NONE of the SVIDs
// the four gRPC sockets had issued (those sockets are bound by the front
// process alone — `server.js` starts them and a request worker binds nothing
// but its own unix socket), and `/admin/spiffe`'s Rotate button rotated a CA
// that signs nothing while the one doing the signing stood still.
//
// **IT WAS `sharedMap` UNTIL 2026-09-11 AND THE ARGUMENT FOR THAT IS WORTH
// KEEPING, BECAUSE IT IS STILL HALF TRUE.** It read: *SPIFFE is ONE trust
// domain for the whole service — its sockets have no path to put a realm
// segment in — so this is not per realm.* The trust DOMAIN is still one:
// `spiffe.trustDomain` is read once, service-wide, and every SVID this
// service mints anywhere names it. What became per realm is the AUTHORITY
// that signs, because `common/pki.js`'s SPIFFE Issuing CA is a realm's now
// and this store has to follow its declaration (rule 2 of the realm design:
// a store becomes per realm AT ITS DECLARATION and nowhere else).
//
// **THAT IS COHERENT ONLY BECAUSE THE ANCHOR IS SHARED, AND IT IS THE WHOLE
// DESIGN IN ONE SENTENCE.** The bundle publishes the service ROOT, which no
// realm owns; an SVID carries its own realm's Issuing CA and Intermediate in
// its chain. So every realm's bundle is byte-identical, an SVID minted on the
// shared gRPC sockets (which answer in the DEFAULT realm, because a socket
// still has no path to put a segment in) verifies against the bundle a caller
// fetched from `/realm/acme/spiffe/bundle`, and what the chain adds is which
// realm issued it. One trust domain, one anchor, an authority per realm.
//
// **THE ENCODING IS THE PART THAT NEEDED CARE.** The journal writes JSON, and
// JSON turns a `Buffer` into `{"type":"Buffer","data":[…]}` and a `Map` into
// `{}` — a trap this service has already been caught by twice, in
// `krb5_principals.js`'s key cache and its sign-out stamp. Exactly one field
// here is a Buffer, `certificateDer`, so it rides as base64 and comes back a
// Buffer. Everything else is a string, a number or a plain object and survives
// unchanged. A field added to an authority record that is NOT one of those
// must be packed here too.
// ---------------------------------------------------------------------------
const authorities = realms.map({ persist: 'spiffe.authorities' });

// The realm whose authority a call is about. Every reader here takes an
// explicit id or falls back to the AMBIENT realm — the shape every per-realm
// store in this service has, and the reason the four gRPC sockets land in the
// default realm without a line of code saying so: nothing enters a realm for
// them, so `realms.current()` is the default.
function realmIdOf(realmId) {
  if (realmId !== undefined && realmId !== null) {
    return String(realmId);
  }
  const current = realms.current();
  return String((current && current.id) || '');
}

function authoritiesIn(realmId) {
  return authorities.realmMap(realmIdOf(realmId));
}

function packX509(one) {
  return Object.assign({}, one, {
    certificateDer: Buffer.isBuffer(one.certificateDer)
      ? one.certificateDer.toString('base64')
      : String(one.certificateDer || '')
  });
}

function unpackX509(one) {
  return Object.assign({}, one, {
    certificateDer: Buffer.isBuffer(one.certificateDer)
      ? one.certificateDer
      : Buffer.from(String(one.certificateDer || ''), 'base64')
  });
}

// THE UNPACKED LIST, MEMOISED ON THE STORED ARRAY'S IDENTITY. `x509List()[0]`
// is on the path of every SVID this service mints, and rebuilding a Buffer per
// call for a value that changes only when somebody rotates would be a cost with
// nothing to show for it. The store hands back the same array object until it
// is replaced — by a rotation here or by a replicated write from another
// process — so identity is exactly the right invalidation.
//
// **MEMOISED PER REALM SINCE 2026-09-11.** It was one slot, and one slot for a
// store that is now partitioned is a cache that answers the last realm asked
// rather than the realm asking — the memo would hit on the array identity of a
// DIFFERENT realm's list only if the two were the same object, which they
// never are, so the practical effect was a permanent miss rather than a wrong
// answer. Keyed anyway: a permanent miss in the memo on the path of every SVID
// is the thing this memo exists to prevent.
const x509Unpacked = new Map();

function x509List(realmId) {
  const id = realmIdOf(realmId);
  const raw = authoritiesIn(id).get('x509') || [];
  const held = x509Unpacked.get(id);
  if (!held || held.from !== raw) {
    x509Unpacked.set(id, { from: raw, list: raw.map(unpackX509) });
  }
  return x509Unpacked.get(id).list;
}

function setX509List(realmId, list) {
  authoritiesIn(realmId).set('x509', list.map(packX509));
}

function jwtList(realmId) {
  return authoritiesIn(realmId).get('jwt') || [];
}

function setJwtList(realmId, list) {
  authoritiesIn(realmId).set('jwt', list.slice(0));
}

// The foreign trust domains this one federates with, keyed by trust domain
// name. Each holds the bundle document exactly as it was given — see
// `setFederatedBundle()` for why it is given rather than fetched.
// **A SHARED, PERSISTED STORE AND NOT A PLAIN Map (2026-09-07).** A federated
// bundle is registered through `/admin-api/spiffe` or the console and read back
// off `GET /spiffe`, and a plain Map made it visible only in the process that
// took the call: with a request worker pool, registering a trust domain on one
// worker left the other two unable to see it, which is what
// `sts_admin_api_operations` and `sts_admin_console` measured.
//
// `sharedMap` and not `map`, because SPIFFE is one trust domain for the whole
// service — its four sockets have no path to put a realm segment in, so its
// state is not per realm (see the root CLAUDE.md's realm table). The values are
// plain JSON — strings, a document and a timestamp — so they survive the
// `JSON.stringify` the journal writes, which is the trap three other stores hit.
const federated = realms.sharedMap({ persist: 'spiffe.federatedBundles',
                                     scope: 'shared' });

// RFC-required monotonic counter on the bundle. It changes whenever the bundle
// changes and never otherwise, which is what lets a consumer tell "I have the
// current bundle" from "I have a bundle".
// IN THE SAME PERSISTED STORE, for the same reason: a counter a relying party
// watches for staleness that moved on one worker of three would tell two
// thirds of its readers that a rotated bundle was the one they already had.
//
// **AND IT IS PER REALM NOW, WHICH IS A SMALL LIE THIS SERVICE CANNOT AVOID
// TELLING.** Every realm's bundle publishes the same service Root, so the
// DOCUMENT is identical everywhere — but the sequence is a per-realm counter,
// so rotating the SPIFFE authority in one realm moves the number a caller in
// another realm reads without the bytes beside it having changed. It is
// monotonic, which is all the specification asks of it; what it costs is a
// consumer re-fetching a bundle it already had. The alternative — one shared
// counter — would have been worse in the direction that matters: a rotation in
// realm acme that DID change what acme publishes, with a number that never
// moved for a caller reading acme.
function sequenceNow(realmId) {
  const held = Number(authoritiesIn(realmId).get('sequence'));
  return held > 0 ? held : 1;
}

// What the startup actually did, for the pages that report it. Set once
// `initialise()` finishes and readable synchronously — see `state()`.
let started = null;
let startError = null;

function bumpSequence(realmId, why) {
  const id = realmIdOf(realmId);
  authoritiesIn(id).set('sequence', sequenceNow(id) + 1);
  log.debug('spiffe: the bundle sequence in "' + (id || 'default') +
            '" is now ' + sequenceNow(id) + ' (' + why + ').');
}

// ---------------------------------------------------------------------------
// BUILDING AN AUTHORITY.
//
// **THIS IS THE FALLBACK SINCE 2026-09-11, NOT THE ORDINARY PATH.** A realm
// with a certificate authority takes its X.509 authority from
// `common/pki.js` — see WHERE THE X.509 AUTHORITY COMES FROM below. This
// function is what a realm with no hierarchy gets, which is `pki.autoBuild:
// false`, a Root that could not be built, and every in-process caller that
// never runs `common/service_state.js`.
//
// The X.509 authority it builds is a self-signed CA. It is NOT the certificate
// `tls_server.js` generates and it must not be: that one is a leaf with
// `basicConstraints CA:FALSE` and an `extKeyUsage` of `serverAuth`, so it
// cannot sign anything. (The sentence that used to follow — *and a trust
// domain whose root was also the host's TLS certificate would be conflating
// two unrelated trust decisions. One process, two PKIs, on purpose* — is the
// one the move reversed, and it is answered where the move is argued rather
// than here.)
//
// **THE `pathLen` ARGUMENT WAS DOCUMENTED CORRECTLY AND PASSED WRONGLY, AND
// THAT IS A DEFECT THIS CHANGE FIXED ON THE WAY PAST.** The comment here said
// `NewDownstreamX509CA` "builds a SECOND authority with `pathLen: 0` beneath a
// root issued with `pathLen: 1`" — and both call sites passed `0`. So every
// downstream CA this service ever minted was a CA signed by a CA that had
// declared it would sign no CAs. It parses, it verifies as a signature, and a
// path builder refuses the chain with a message about basic constraints that
// names neither certificate — which is exactly the failure mode this file's
// own header warns about, three paragraphs above the line that caused it.
// Both call sites pass `1` now, and the PKI path gets the same depth from
// `pki.js`'s `spiffe` use case.
// ---------------------------------------------------------------------------
async function makeX509Authority(keyTypeId, ttlSeconds, pathLen) {
  log.debug('Entering makeX509Authority(). keyType=' + keyTypeId);
  const type = keyTypeById(keyTypeId);
  if (!type) {
    log.debug('Leaving makeX509Authority(). Unknown key type.');
    throw new Error('Unknown SPIFFE X.509 key type: ' + keyTypeId +
                    '. Known types are ' +
                    KEY_TYPES.map(function (t) { return t.id; }).join(', ') + '.');
  }
  const pair = await keys.generateKeyPair(type.id);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + (ttlSeconds || 86400) * 1000);
  const issued = await x509.issueCertificate({
    // The CA's own name. A SPIFFE trust domain has no naming rules for it —
    // only the SVIDs it signs are constrained — so this says what it is and
    // which trust domain it belongs to, which is what a person reading
    // `openssl x509 -text` on a bundle needs.
    subject: 'CN=mock-sts SPIFFE CA (' + TRUST_DOMAIN + '),O=mock-sts',
    subjectPublicKey: pair.publicPem,
    signatureAlg: type.sigAlg,
    issuerPrivateKey: pair.privatePem,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: pathLen === undefined ? 0 : pathLen },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] },
      // A CA in a SPIFFE bundle is also given the trust domain's own SPIFFE ID
      // as a URI subjectAltName. Nothing REQUIRES it — the X509-SVID
      // specification constrains leaves — but SPIRE does it, it costs nothing,
      // and it means a person looking at a certificate out of context can see
      // which trust domain it belongs to.
      subjectAltName: { present: true, critical: false,
                        names: [{ kind: 'uri',
                                  value: spiffeId.trustDomainId(TRUST_DOMAIN) }] },
      subjectKeyIdentifier: { present: true }
    }
  });
  const authority = {
    id: authorityIdOf(issued.pem),
    keyType: type.id,
    sigAlg: type.sigAlg,
    certificatePem: issued.pem,
    certificateDer: Buffer.from(issued.der),
    privateKeyPem: pair.privatePem,
    publicKeyPem: pair.publicPem,
    subject: issued.subject,
    serialHex: issued.serialHex,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    createdAt: Date.now()
  };
  log.debug('Leaving makeX509Authority(). id=' + authority.id);
  return authority;
}

// The JWT authority: a key pair and a `kid`, and no certificate at all. A JWT
// bundle is a JWK Set of PUBLIC KEYS — the JWT-SVID specification has no
// certificate in it — which is the whole structural difference from the X.509
// half and the reason these are two lists rather than one.
async function makeJwtAuthority(keyTypeId) {
  log.debug('Entering makeJwtAuthority(). keyType=' + keyTypeId);
  const type = keyTypeById(keyTypeId);
  if (!type) {
    log.debug('Leaving makeJwtAuthority(). Unknown key type.');
    throw new Error('Unknown SPIFFE JWT key type: ' + keyTypeId + '.');
  }
  if (!type.jwtAlg) {
    log.debug('Leaving makeJwtAuthority(). No JWS algorithm.');
    throw new Error('The SPIFFE JWT authority cannot use ' + type.label +
                    ': ' + type.what);
  }
  const pair = await keys.generateKeyPair(type.id);
  const jwk = publicJwkOf(pair.publicPem);
  const authority = {
    // A `kid` names a KEY, so it is derived from the key material — the same
    // rule helpers.js's STS kid follows, and for the same reason: two instances
    // of this mock publishing one kid over two different keys makes a verifier
    // report "the signature does not verify", which reads as a corrupt token
    // rather than as keys fetched from the wrong instance.
    id: 'spiffe-' + thumbprintOf(jwk),
    keyType: type.id,
    alg: type.jwtAlg,
    privateKeyPem: pair.privatePem,
    publicKeyPem: pair.publicPem,
    jwk: jwk,
    createdAt: Date.now()
  };
  log.debug('Leaving makeJwtAuthority(). kid=' + authority.id);
  return authority;
}

// An X.509 authority's id: a SHA-256 over the certificate DER, which is what
// SPIRE's `local authority` ids are and what a person can compare with
// `openssl x509 -fingerprint -sha256`.
function authorityIdOf(pem) {
  return stsCrypto.certificateThumbprint(pem, { format: 'hex', truncate: 16 });
}

// RFC 7638 JWK thumbprint, which is the only correct way to derive a kid from a
// key: the members are ordered and the set of them is fixed per key type, so
// two implementations agree. Hashing the PEM instead would give a different
// answer for the same key depending on line wrapping.
function thumbprintOf(jwk) {
  // RFC 7638, and it is still the only correct way to derive a kid from a key:
  // the members are ordered and the set of them is fixed per key type, so two
  // implementations agree. Hashing the PEM instead would give a different
  // answer for the same key depending on line wrapping.
  //
  // It used to build that canonical JSON here, with JSON.stringify over an
  // object literal — correct, and correct only because the members were typed
  // in lexicographic order. `common/crypto.js` builds it from an ordered list
  // instead, so the ordering is a property of the code rather than of how
  // somebody happened to type an object.
  return stsCrypto.jwkThumbprint(jwk, { truncate: 16 });
}

// A public key PEM as a JWK. Node's own converter rather than one of the
// vendored modules' — it handles RSA, EC and OKP, it is in the standard
// library, and there is nothing here for a second implementation to disagree
// with.
function publicJwkOf(publicPem) {
  const jwk = crypto.createPublicKey(publicPem).export({ format: 'jwk' });
  // `key_ops` and `ext` are Web Crypto members and are not part of a published
  // JWK. Deleted rather than left: a bundle is a document other software parses
  // strictly, and members it does not expect are members it may reject.
  delete jwk.key_ops;
  delete jwk.ext;
  return jwk;
}

// ===========================================================================
// WHERE THE X.509 AUTHORITY COMES FROM (2026-09-11): `common/pki.js`.
//
// **THIS REVERSES THE PARAGRAPH ABOVE `makeX509Authority()` AND THE ARGUMENT
// IT REVERSES IS WORTH READING FIRST.** That comment says the authority is
// self-signed on purpose — *a trust domain whose root was also the host's TLS
// certificate would be conflating two unrelated trust decisions. One process,
// two PKIs, on purpose.* `/admin/pki` said the same thing on the page, and
// added the mechanical half: an Issuing CA there carries `pathLen: 0`, so it
// signs leaves and no further authority, and a SPIFFE authority signs SVIDs.
//
// Both halves are answered rather than ignored:
//
//   * **The trust decision is not conflated, because the SPIFFE authority is
//     not the TLS certificate.** It is a SIBLING of it — its own Issuing CA,
//     its own key, under its own realm's Intermediate — and the only thing the
//     two now share is the anchor an operator installs. That was the whole ask:
//     one Root covering 8443, 9443, LDAPS 636, the main port, every token this
//     service signs AND every SVID it mints. Narrowing trust to SPIFFE alone is
//     still sayable, and is now sayable in the ordinary X.509 way — pin the
//     SPIFFE Issuing CA instead of the Root.
//   * **The `pathLen` was a real obstacle and it was moved rather than argued
//     around.** The `spiffe` use case carries `pathLen: 1` and the realm
//     Intermediate above it is widened to 2, both derived in `pki.js` from one
//     table so they cannot drift. That is what keeps `NewDownstreamX509CA`
//     working: a downstream CA is the one CA this authority is allowed to sign.
//
// **THE BUNDLE PUBLISHES THE ROOT, WHICH IS EXACTLY WHAT SPIRE DOES WITH AN
// UpstreamAuthority PLUGIN CONFIGURED**, and reading this service's PKI as
// SPIRE's upstream authority is the shortest true description of the whole
// change. The anchor is the Root; the SVID carries its issuing chain; a
// rotation of the authority does not change the anchor, so an SVID minted
// before one goes on verifying with nothing having to be re-fetched. Under the
// old self-signed arrangement every rotation changed the bundle, which is why
// `MAX_RETAINED_AUTHORITIES` exists and why it had to.
//
// **AND THE FALLBACK IS NOT A COURTESY — THREE SUPPORTED CONFIGURATIONS REACH
// IT.** `pki.autoBuild: false` is a documented setting meaning "what this
// service did before 2026-09-11"; a Root that could not be built is logged and
// never fatal (`pki.start()`'s own rule); and every in-process test and every
// caller that loads this module without running `common/service_state.js` —
// `npm test`, the parent project's in-process Kerberos jobs — has no hierarchy
// at all. In all three this module does what it has always done: it
// self-signs, it says so on every surface that reports an authority, and
// nothing about SPIFFE stops working.
//
// `pki.js` is a LEAF (rule 3w): it registers no route, so requiring it here
// moves nothing in the router, and it requires nothing that requires this
// module back.
// ===========================================================================
const pki = require('../common/pki');

const SPIFFE_USE_CASE = 'spiffe';

// ---------------------------------------------------------------------------
// THE AUTHORITY THIS REALM SIGNS WITH, as one record whatever produced it.
//
// **`source` IS THE FIELD EVERY REPORT HAS TO CARRY.** A reader looking at an
// SVID cannot tell a PKI-backed authority from a self-signed one without being
// told, and the difference decides what they have to install: a self-signed
// authority IS the anchor and has to be fetched again after every restart,
// where the Root is the anchor and survives one in product mode. Reporting the
// two identically would be the most expensive quiet untruth this module could
// tell.
//
// `anchorPem` is what goes in the BUNDLE and `chainPem` is what travels with a
// LEAF, and they are deliberately two fields rather than one list. For the
// self-signed case they coincide — the authority is both — which is precisely
// why a single field would have looked correct right up until the hierarchy
// existed.
// ---------------------------------------------------------------------------
function pkiAuthorityFrom(issuer) {
  return {
    source: 'pki',
    id: authorityIdOf(issuer.certificatePem),
    // The PKI's key algorithm id (`rsa-2048`, `ec-p256`, …) and NOT one of this
    // module's KEY_TYPES ids. They overlap for the EC and RSA entries and it
    // would be a coincidence to rely on: the certificate says what it is, and
    // `spiffe.x509KeyType` no longer decides the authority's key at all — it
    // decides the key of an SVID, which is a different key.
    keyType: issuer.keyAlg,
    signatureAlg: issuer.signatureAlg,
    subject: issuer.subject,
    serialHex: issuer.serialHex,
    notBefore: issuer.notBefore,
    notAfter: issuer.notAfter,
    certificatePem: issuer.certificatePem,
    certificateDer: pemToDer(issuer.certificatePem),
    // Leaf-first from the authority upward, Root EXCLUDED — see issueLeaf().
    chainPem: issuer.chainPem.slice(),
    chainDer: issuer.chainPem.map(pemToDer),
    // The trust anchor, which is the service Root and no realm's.
    anchorPem: issuer.root.certificatePem,
    anchorDer: pemToDer(issuer.root.certificatePem),
    anchorSubject: issuer.root.subject,
    anchorNotAfter: issuer.root.notAfter,
    intermediateSubject: issuer.intermediate.subject
  };
}

function selfSignedAuthorityFrom(one) {
  return Object.assign({}, one, {
    source: 'self-signed',
    chainPem: [],
    chainDer: [],
    // The authority IS the anchor here, which is the whole difference.
    anchorPem: one.certificatePem,
    anchorDer: one.certificateDer,
    anchorSubject: one.subject,
    anchorNotAfter: one.notAfter,
    intermediateSubject: ''
  });
}

// The realm's active X.509 authority, PKI-backed if there is a hierarchy and
// self-signed if there is not. Synchronous: both answers are already in a
// store, and the only asynchronous thing here is BUILDING the fallback, which
// `ensureTrustMaterial()` does.
function activeX509Authority(realmId) {
  const id = realmIdOf(realmId);
  const issuer = pki.describeIssuer(id, SPIFFE_USE_CASE);
  if (issuer) {
    return pkiAuthorityFrom(issuer);
  }
  const held = x509List(id)[0];
  return held ? selfSignedAuthorityFrom(held) : null;
}

// Every anchor a consumer of this realm's bundle should trust. One entry when
// the hierarchy is there — the Root — and the retained self-signed list when it
// is not, because in that arrangement each retired authority is an anchor of
// its own and dropping it is what makes a rotation look like an outage.
function trustAnchorsIn(realmId) {
  const id = realmIdOf(realmId);
  const issuer = pki.describeIssuer(id, SPIFFE_USE_CASE);
  if (issuer) {
    return [{ source: 'pki',
              id: authorityIdOf(issuer.root.certificatePem),
              subject: issuer.root.subject,
              notBefore: issuer.root.notBefore,
              notAfter: issuer.root.notAfter,
              certificatePem: issuer.root.certificatePem,
              certificateDer: pemToDer(issuer.root.certificatePem),
              publicKeyPem: crypto.createPublicKey(issuer.root.certificatePem)
                .export({ type: 'spki', format: 'pem' }) }];
  }
  return x509List(id).map(function (one) {
    return Object.assign({ source: 'self-signed' }, one);
  });
}

// ---------------------------------------------------------------------------
// ISSUE ONE CERTIFICATE FROM THIS REALM'S AUTHORITY, whichever kind it is.
//
// **THE TWO PATHS DIFFER IN WHO HOLDS THE KEY AND IN NOTHING ELSE THE CALLER
// CAN SEE.** A PKI-backed authority's private key never leaves `common/pki.js`
// — the request goes through `issueUnder()` and the certificate comes back —
// and a self-signed one's lives in this module's own store. Both answer the
// same record, so `issueLeaf()` and `downstreamCa()` above have ONE shape
// rather than a branch each. Two branches would be two places for the SVID
// extension set to drift, and that extension set IS the X509-SVID
// specification.
// ---------------------------------------------------------------------------
async function issueFromAuthority(realmId, authority, spec) {
  log.debug('Entering issueFromAuthority(). source=' + authority.source);
  if (authority.source === 'pki') {
    const made = await pki.issueUnder(realmIdOf(realmId), SPIFFE_USE_CASE, {
      subject: spec.subject,
      publicKeyPem: spec.publicKeyPem,
      profile: spec.profile,
      notBefore: spec.notBefore,
      notAfter: spec.notAfter,
      extensions: spec.extensions
    });
    if (!made.ok) {
      // Carried out rather than logged and swallowed: every caller of this is
      // a protocol handler that owes its client a reason.
      log.debug('Leaving issueFromAuthority(). The PKI refused.');
      throw new Error((made.errors || ['That certificate could not be issued.'])
        .join(' '));
    }
    log.debug('Leaving issueFromAuthority(). serial=' + made.serialHex);
    return { pem: made.certificatePem, der: made.certificateDer,
             serialHex: made.serialHex,
             notBefore: made.notBefore, notAfter: made.notAfter,
             chainPem: authority.chainPem.slice(),
             chainDer: authority.chainDer.slice() };
  }
  const type = keyTypeById(authority.keyType) || KEY_TYPES[0];
  const issued = await x509.issueCertificate({
    subject: spec.subject,
    subjectPublicKey: spec.publicKeyPem,
    signatureAlg: type.sigAlg,
    issuer: { certificatePem: authority.certificatePem,
              privateKeyPem: authority.privateKeyPem,
              keyAlg: authority.keyType },
    notBefore: spec.notBefore,
    notAfter: spec.notAfter,
    extensions: spec.extensions
  });
  log.debug('Leaving issueFromAuthority(). serial=' + issued.serialHex);
  return { pem: issued.pem, der: Buffer.from(issued.der),
           serialHex: issued.serialHex,
           notBefore: spec.notBefore, notAfter: spec.notAfter,
           chainPem: [], chainDer: [] };
}


// ---------------------------------------------------------------------------
// STARTUP.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// STARTUP IS TWO THINGS NOW, AND SPLITTING THEM IS WHAT MADE THE HIERARCHY
// REACHABLE AT ALL (2026-09-11).
//
// **THE ORDERING PROBLEM FIRST, BECAUSE IT DECIDED THE SHAPE.** This module
// used to build its authority at REQUIRE time, and the header above says why:
// generating a key lazily would put a two-second RSA-4096 keygen inside
// whichever request happened to arrive first, and on the Workload API that
// request looks like a hang. But `common/pki.js`'s hierarchy is built by
// `pki.start()`, which `common/service_state.js` runs AFTER the whole protocol
// stack has been required and before anything binds. So an authority resolved
// at require time is resolved when there is provably no hierarchy — this
// module would have self-signed, written that into the store, and the Root
// built a moment later would have certified nothing. That is exactly the trap
// `tls/tls_server.js` avoids with `pki.registerCertifiable()`, and a
// registration does not work here: what that mechanism certifies is a LEAF
// over a key its owner already holds, and what this module needs is a CA.
//
// So:
//
//   * **`initialise()` validates the trust domain and nothing else.** It is
//     the one thing that must fail loudly and must fail once, service-wide.
//   * **`ensureTrustMaterial(realm)` resolves that realm's authorities on
//     first use**, by which time `pki.start()` has run — the listeners bind
//     after it, so no request can precede it.
//
// **AND THE COST THE OLD COMMENT WAS AVOIDING HAS LARGELY GONE WITH IT.** In
// the ordinary case there is no X.509 key to generate at all: the authority is
// the realm's SPIFFE Issuing CA, already built. What is still generated here is
// the JWT authority, which has no certificate and no hierarchy to hang from —
// and it is EC P-256 by default, which is milliseconds. `spiffe.jwtKeyType` set
// to `rsa-4096` puts that generation on the first FetchJWTSVID in each realm,
// which is said here rather than left to be discovered.
//
// **A REALM IS THE UNIT because the authority is.** A realm created at runtime
// gets its trust material the first time somebody asks it for an SVID, which is
// the same rule `common/pki.js` follows for a realm's branch and removes any
// need for this module to watch `realms.onChange()`.
// ---------------------------------------------------------------------------
async function initialise() {
  log.debug('Entering initialise().');
  const parsed = spiffeId.parse(spiffeId.trustDomainId(TRUST_DOMAIN));
  if (!parsed.ok) {
    // Thrown rather than warned, and it is the one thing in this module that
    // is: every identifier this service will mint is built on the trust domain
    // name, so a bad one is not a degraded feature but a CA that can only issue
    // certificates naming something invalid. `server.js` catches it and reports
    // it on /spiffe rather than letting it stop the rest of the service.
    throw new Error('spiffe.trustDomain is not a valid trust domain name: ' +
                    parsed.reason);
  }
  started = Date.now();
  log.info('spiffe: the trust domain is ' +
           spiffeId.trustDomainId(TRUST_DOMAIN) + '. Its X.509 authority in ' +
           'each realm is that realm\'s SPIFFE Issuing CA under this ' +
           'service\'s own Root — see /admin/pki — and the bundle at GET ' +
           config.value('spiffe.bundlePath') + ' publishes the Root. A realm ' +
           'with no hierarchy falls back to a self-signed authority, which is ' +
           'what this service did before 2026-09-11 and is reported as such.');
  log.debug('Leaving initialise().');
}

// The one promise, started at require time. A failure is CAPTURED rather than
// left as an unhandled rejection — an unhandled one takes the process down on
// current node, and a SPIFFE CA that could not build its key must not stop the
// fourteen other protocol families in this service from running. Every entry
// point re-throws it, so a caller gets the real reason rather than an empty
// bundle.
const readyPromise = initialise().catch(function (err) {
  startError = err.message;
  log.error('spiffe: the issuing authority could not be built, so nothing ' +
            'here will issue an SVID: ' + err.message);
});

// ---------------------------------------------------------------------------
// ONE BUILD PER REALM, AND THE MAP IS WHAT MAKES THAT TRUE.
//
// The Workload API's very first call in a realm can be several concurrent
// requests — an agent and two workloads starting together — and each would
// otherwise generate a JWT authority, three of which would race to write and
// two of which would be thrown away. Keeping the PROMISE rather than a flag is
// what makes the second caller WAIT for the first rather than start its own.
// ---------------------------------------------------------------------------
const building = new Map();

async function buildTrustMaterial(realmId) {
  log.debug('Entering buildTrustMaterial(). realm=' + (realmId || 'default'));
  // ------------------------------------------------------------------------
  // WHAT IS ALREADY IN THE STORE WINS, and this is what makes several
  // processes ONE trust domain rather than several.
  //
  // Every process runs this on first use and each would otherwise mint an
  // authority of its own. The first to write establishes the realm's JWT
  // authority and the rest adopt it; two that raced both write, the later
  // wins, and both then READ the winner — because every reader below goes
  // through `jwtList()` rather than a local array. So the disagreement is a
  // window rather than a state, and it closes without anybody deciding.
  //
  // **THE X.509 HALF NEEDS NONE OF THIS WHEN THERE IS A HIERARCHY**, which is
  // a quiet second benefit of the move: `common/pki.js`'s row is in the
  // keystore and is replicated by the same mechanism, so every process reads
  // ONE Issuing CA rather than racing to establish one.
  // ------------------------------------------------------------------------
  const id = realmIdOf(realmId);
  if (!jwtList(id).length) {
    const jwtAuthority = await makeJwtAuthority(config.value('spiffe.jwtKeyType'));
    if (!jwtList(id).length) {
      setJwtList(id, [jwtAuthority]);
      log.info('spiffe: the "' + (id || 'default') + '" realm\'s JWT ' +
               'authority is ' + jwtAuthority.keyType + ' (kid ' +
               jwtAuthority.id + ').');
    } else {
      log.info('spiffe: another process had already established the "' +
               (id || 'default') + '" realm\'s JWT authority (kid ' +
               jwtList(id)[0].id + '); adopting it rather than the key just ' +
               'generated. One service is one trust domain.');
    }
  }
  // THE X.509 HALF. Nothing to do when the realm has a SPIFFE Issuing CA —
  // that IS the authority. The fallback is built only when it has none.
  if (pki.describeIssuer(id, SPIFFE_USE_CASE)) {
    log.debug('Leaving buildTrustMaterial(). The PKI holds the authority.');
    return;
  }
  if (x509List(id).length) {
    log.debug('Leaving buildTrustMaterial(). A self-signed authority is held.');
    return;
  }
  const x509Authority = await makeX509Authority(
    config.value('spiffe.x509KeyType'), config.value('spiffe.caTtl'), 1);
  if (!x509List(id).length) {
    setX509List(id, [x509Authority]);
    log.warn('spiffe: the "' + (id || 'default') + '" realm has no SPIFFE ' +
             'Issuing CA, so its X.509 authority is SELF-SIGNED (' +
             x509Authority.id + ', ' + x509Authority.keyType + ', valid ' +
             'until ' + x509Authority.notAfter + ') and IS the trust anchor — ' +
             'a consumer has to fetch the bundle again after every restart. ' +
             'Build the realm\'s certificate authority on /admin/pki to put ' +
             'it under this service\'s Root instead.');
  } else {
    log.info('spiffe: another process had already established the "' +
             (id || 'default') + '" realm\'s self-signed X.509 authority (' +
             x509List(id)[0].id + '); adopting it.');
  }
  log.debug('Leaving buildTrustMaterial().');
}

function ensureTrustMaterial(realmId) {
  const id = realmIdOf(realmId);
  if (!building.has(id)) {
    // The promise is kept whatever happens to it, and a FAILED one is dropped
    // so that the next caller retries: the ordinary cause of a failure here is
    // a key generation that threw, and caching that for the life of the
    // process would turn one bad moment into a realm that can never issue.
    const run = buildTrustMaterial(id).catch(function (err) {
      building.delete(id);
      throw err;
    });
    building.set(id, run);
  }
  return building.get(id);
}

// **EVERY ENTRY POINT IN THIS MODULE AWAITS THIS**, which is the one rule the
// header states: a caller cannot forget to, and a caller that reaches this
// module before the realm has trust material gets the right answer rather than
// an empty bundle. `state()` is the single exception and says so.
async function ready(realmId) {
  await readyPromise;
  if (startError) throw new Error(startError);
  await ensureTrustMaterial(realmId);
  return true;
}

// ---------------------------------------------------------------------------
// MINTING AN X509-SVID.
//
// The X509-SVID specification's rules, each of which is a line below:
//
//   * the SPIFFE ID goes in a URI subjectAltName, and there is EXACTLY ONE of
//     them. A certificate with two SPIFFE IDs in it names two things, and what
//     a verifier does with that is undefined — so it is one, always.
//   * `basicConstraints` says CA:FALSE. A leaf that could sign is a leaf that
//     can mint its own identity.
//   * `keyUsage` has `digitalSignature`; `keyCertSign` and `cRLSign` MUST NOT
//     be there.
//   * `extKeyUsage` carries `serverAuth` and `clientAuth`, because an SVID is
//     used for BOTH ends of an mTLS connection — that is the whole point of it.
//   * the subject may be anything. SPIRE writes `C=US, O=SPIRE` and so does
//     this, through `spiffe.svidSubject`, because a certificate with an empty
//     subject is refused by the vendored issuer and — more to the point — is
//     rendered as a blank line by every tool a person might inspect it with.
//
// The KEY IS GENERATED HERE and handed back with the certificate, because that
// is what the Workload API does: `X509SVID.x509_svid_key` is the workload's
// private key, DER PKCS#8, unencrypted. That looks alarming written down and is
// exactly correct — the Workload API's whole job is to deliver an identity to a
// workload over a channel already trusted (a Unix socket, in the ordinary
// case). `signCsr()` below is the other shape, where the caller kept its key.
// ---------------------------------------------------------------------------
async function mintX509Svid(id, options) {
  log.debug('Entering mintX509Svid(). id=' + id);
  await ready();
  const opts = options || {};
  const parsed = spiffeId.parse(id);
  if (!parsed.ok) {
    log.debug('Leaving mintX509Svid(). Invalid SPIFFE ID.');
    throw new Error('Cannot mint an X509-SVID for ' + id + ': ' + parsed.reason);
  }
  const type = keyTypeById(opts.keyType || config.value('spiffe.x509KeyType'));
  const pair = await keys.generateKeyPair((type || {}).id || 'ec-p256');
  const issued = await issueLeaf(parsed.id, pair.publicPem, opts);
  const privateKeyDer = pemToDer(pair.privatePem);
  log.debug('Leaving mintX509Svid(). serial=' + issued.serialHex);
  return {
    spiffeId: parsed.id,
    certificatePem: issued.pem,
    certificateDer: issued.der,
    // The chain, in the TWO shapes the two surfaces take. The Workload API's
    // `x509_svid` is ONE concatenated DER blob; the SPIRE Server API's
    // `cert_chain` is a `repeated bytes`, so it is the same certificates as
    // separate entries. Both are leaf-first and both exclude the anchor.
    // Handing one shape out and letting each caller reach for `Buffer.concat`
    // is how the two ends of a chain get reversed in one of them.
    chainDer: Buffer.concat(chainDerOf(issued)),
    chainCertificatesDer: chainDerOf(issued),
    chainPem: chainPemOf(issued),
    privateKeyPem: pair.privatePem,
    privateKeyDer: privateKeyDer,
    keyType: (type || {}).id || 'ec-p256',
    serialHex: issued.serialHex,
    notBefore: issued.notBefore,
    notAfter: issued.notAfter,
    expiresAt: Math.floor(new Date(issued.notAfter).getTime() / 1000),
    hint: opts.hint || '',
    // The six facts the directory files this identity's entry by. See
    // certificateFacts(); null if the certificate could not be read back,
    // which is bookkeeping lost and not an SVID lost.
    certificate: issued.certificate
  };
}

// The other shape: the caller has a key and sends a PKCS#10 CSR. This is what
// `BatchNewX509SVID` on the SPIRE Server API takes, and it is how a real agent
// gets its SVIDs — the agent's private key never leaves the agent.
//
// **ONLY THE PUBLIC KEY IS READ OUT OF THE CSR.** Not the subject, not the
// requested SANs, not any extension: everything else about the certificate is
// decided HERE from the registration entry. A CA that copied the subjectAltName
// out of a CSR would let any caller choose its own SPIFFE ID, which is the one
// thing an issuing authority exists to prevent. The CSR's signature is
// deliberately NOT checked either, and that is this service's permissive
// posture rather than an oversight — see the note on `/spiffe` — but reading
// only the key means a forged CSR still cannot name itself something it is not.
async function signCsr(csrDer, id, options) {
  log.debug('Entering signCsr(). id=' + id);
  await ready();
  const opts = options || {};
  const parsed = spiffeId.parse(id);
  if (!parsed.ok) {
    log.debug('Leaving signCsr(). Invalid SPIFFE ID.');
    throw new Error('Cannot sign a CSR for ' + id + ': ' + parsed.reason);
  }
  let publicPem;
  try {
    const csr = pkijs.CertificationRequest.fromBER(toArrayBuffer(csrDer));
    const spki = csr.subjectPublicKeyInfo.toSchema().toBER(false);
    publicPem = derToPem(Buffer.from(spki), 'PUBLIC KEY');
  } catch (e) {
    // Not a CSR, or not one this parser can read. The caller is a protocol
    // handler that has to answer InvalidArgument, so the reason is carried out
    // rather than logged and swallowed.
    log.debug('Leaving signCsr(). The CSR could not be read.');
    throw new Error('The certificate signing request could not be read: ' +
                    e.message);
  }
  const issued = await issueLeaf(parsed.id, publicPem, opts);
  log.debug('Leaving signCsr(). serial=' + issued.serialHex);
  return {
    spiffeId: parsed.id,
    certificatePem: issued.pem,
    certificateDer: issued.der,
    chainDer: Buffer.concat(chainDerOf(issued)),
    chainCertificatesDer: chainDerOf(issued),
    chainPem: chainPemOf(issued),
    serialHex: issued.serialHex,
    notBefore: issued.notBefore,
    notAfter: issued.notAfter,
    expiresAt: Math.floor(new Date(issued.notAfter).getTime() / 1000),
    hint: opts.hint || '',
    // The six facts the directory files this identity's entry by. See
    // certificateFacts(); null if the certificate could not be read back,
    // which is bookkeeping lost and not an SVID lost.
    certificate: issued.certificate
  };
}

// The shared half of both: everything about the certificate that is not the
// key. One function rather than two copies, because the extension set IS the
// X509-SVID specification and two copies of it is one copy that will eventually
// be missing `clientAuth`.
async function issueLeaf(id, publicPem, options) {
  log.debug('Entering issueLeaf(). id=' + id);
  const opts = options || {};
  const realmId = realmIdOf(opts.realm);
  const authority = activeX509Authority(realmId);
  if (!authority) {
    log.debug('Leaving issueLeaf(). No authority.');
    throw new Error('This trust domain has no X.509 authority in the "' +
                    (realmId || 'default') + '" realm.');
  }
  const ttl = Number(opts.ttl) > 0 ? Number(opts.ttl) : svidTtlSeconds();
  const notBefore = new Date();
  let notAfter = new Date(notBefore.getTime() + ttl * 1000);
  // An SVID may not outlive the authority that signed it. A certificate whose
  // notAfter is past its issuer's is not refused by every verifier — many check
  // only the leaf — so it produces an identity that works until it suddenly
  // does not, with nothing in the failure naming the CA.
  //
  // **`issueUnder()` CLAMPS THIS TOO AND THE DUPLICATION IS DELIBERATE.** That
  // one is the funnel every leaf in the service goes through and it cannot be
  // removed; this one is what lets the record below report the lifetime the
  // SVID actually got rather than the one that was asked for, on BOTH paths.
  const caNotAfter = new Date(authority.notAfter);
  if (notAfter > caNotAfter) {
    log.debug('issueLeaf(): the requested lifetime outlives the CA; ' +
              'shortening it to the CA\'s own notAfter.');
    notAfter = caNotAfter;
  }
  const names = [{ kind: 'uri', value: id }];
  // DNS names are the one thing a registration entry may add to an SVID, and
  // they are what makes an SVID usable by a TLS client that checks a hostname
  // rather than a SPIFFE ID. The SPIFFE ID stays the identity; these are an
  // accommodation for software that cannot read one.
  (opts.dnsNames || []).forEach(function (name) {
    const text = String(name || '').trim();
    if (text) names.push({ kind: 'dns', value: text });
  });
  const issued = await issueFromAuthority(realmId, authority, {
    subject: opts.subject || svidSubject(),
    publicKeyPem: publicPem,
    // **NO PROFILE, AND THAT IS SAFE FOR A REASON WORTH WRITING DOWN.** In
    // `common/vendored/x509.js` a profile decides exactly one thing at
    // issuance — a DEFAULT LIFETIME, used only when the caller supplies
    // neither `notBefore` nor `notAfter`. It contributes no extensions. This
    // caller supplies both, so naming one would change nothing and would
    // suggest to a reader that the extension set below came from somewhere
    // else. It does not: the extensions ARE the X509-SVID specification and
    // are passed whole.
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] },
      extKeyUsage: { present: true, usages: ['serverAuth', 'clientAuth'] },
      subjectAltName: { present: true, critical: false, names: names },
      subjectKeyIdentifier: { present: true },
      authorityKeyIdentifier: { present: true }
    }
  });
  log.debug('Leaving issueLeaf(). serial=' + issued.serialHex);
  return { pem: issued.pem, der: issued.der,
           serialHex: issued.serialHex,
           notBefore: issued.notBefore,
           notAfter: issued.notAfter,
           // WHAT TRAVELS WITH THE LEAF, and it is empty on the self-signed
           // path and two certificates long on the PKI one. A caller
           // concatenates rather than branching — see `chainOf()`.
           issuerChainPem: issued.chainPem,
           issuerChainDer: issued.chainDer,
           certificate: certificateFacts(issued.der) };
}

// ---------------------------------------------------------------------------
// THE CHAIN A CALLER SENDS, in the two shapes the two surfaces want.
//
// **LEAF FIRST, ANCHOR EXCLUDED.** The Workload API's `x509_svid` is "the
// X.509-SVID... and any intermediates" as one concatenated DER blob, and the
// SPIRE Server API's `cert_chain` is the same list as separate entries. Both
// exclude the anchor, which travels in the bundle: sending it is harmless and
// relying on it having been sent is the mistake.
//
// **THIS IS WHERE THE COMMENT THAT SAID "THERE ARE NONE HERE" USED TO BE.** It
// read: *the chain the Workload API returns: the leaf FIRST, then any
// intermediates. There are none here — the CA signs leaves directly — but the
// field is a chain rather than a certificate, and a caller that assumed one
// certificate would break the day a downstream CA is in front of it.* The
// field being a chain rather than a certificate is what made 2026-09-11 an
// edit to one function instead of four protocol handlers.
// ---------------------------------------------------------------------------
function chainPemOf(issued) {
  return [issued.pem].concat(issued.issuerChainPem || []);
}

function chainDerOf(issued) {
  return [issued.der].concat(issued.issuerChainDer || []);
}

// ---------------------------------------------------------------------------
// THE SIX FACTS ABOUT AN ISSUED CERTIFICATE, IN THE SPELLING THE TLS LISTENERS
// ALREADY PRODUCE.
//
// The directory grows an entry for the holder of every X509-SVID this authority
// mints (see `spiffePlan()` and `applySpiffeCertificate()` in
// `ldap/ldap_server.js`), and what goes ON that entry is the same `x509*`
// attribute set a verified TLS client certificate writes. That is a decision
// with one hard requirement: **the strings have to be IDENTICAL in form**, or
// `/admin/users` and an `ldapsearch` show one identity two ways and a filter
// written against a client certificate's entry silently misses an SVID's.
//
// So the facts are READ BACK OFF THE CERTIFICATE THIS FUNCTION JUST ISSUED
// rather than assembled from the inputs that produced it, and they are read
// with `crypto.X509Certificate` — which is node's own parser, the same one
// behind `tls.TLSSocket#getPeerCertificate()`. Four of the six then need no
// conversion at all, because node prints them the same way on both paths:
// `serialNumber` is uppercase hex with no separators, `validFrom` and
// `validTo` are `Mon DD HH:MM:SS YYYY GMT`, and `fingerprint256` is
// colon-separated uppercase hex. The two DNs come back as one `type=value` per
// LINE rather than as an object, which is the second shape `dnRfc4514()` learnt
// in order to serve this caller — one function, so the two paths cannot drift.
//
// Assembling them instead would have been cheaper and wrong in a way nothing
// would report: `spiffe.svidSubject` is the string `C=US,O=SPIRE`, which is
// most-significant-first and is NOT the RFC 4514 form of itself, and the CA's
// own subject is held on the authority as whatever `dnToString()` rendered.
// Either one written straight onto an entry would be a second spelling.
//
// A FAILURE HERE IS NOT A FAILURE TO ISSUE. The certificate exists and the
// caller is entitled to it; the facts are bookkeeping, and bookkeeping must
// never be able to fail the thing it is keeping books on — the rule
// `recordClientCertificate()` follows on the other path and the observer in
// `ldap_server.js` follows at the end of it.
// ---------------------------------------------------------------------------
function certificateFacts(der) {
  log.debug('Entering certificateFacts().');
  try {
    const parsed = new crypto.X509Certificate(der);
    log.debug('Leaving certificateFacts(). serial=' + parsed.serialNumber);
    return {
      subject: dnRfc4514(parsed.subject),
      issuer: dnRfc4514(parsed.issuer),
      serialNumber: parsed.serialNumber || '',
      validFrom: parsed.validFrom || '',
      validTo: parsed.validTo || '',
      fingerprint256: parsed.fingerprint256 || ''
    };
  } catch (e) {
    // A certificate this service built a moment ago that node cannot read is a
    // defect here rather than bad input, so it is logged at error — but it is
    // still swallowed, for the reason in the header: the SVID is minted and the
    // caller is owed it.
    log.error('spiffe: the certificate just issued could not be read back for ' +
              'the directory, and the SVID is unaffected: ' + e.message);
    log.debug('Leaving certificateFacts(). Unreadable.');
    return null;
  }
}

// ---------------------------------------------------------------------------
// AN INTERMEDIATE CA, FOR `NewDownstreamX509CA` — AND THE ONE PLACE THE WHOLE
// HIERARCHY HAD TO GIVE GROUND (2026-09-11).
//
// It is signed by this realm's authority and is itself allowed to sign leaves
// — `pathLen: 0` — and it is NOT added to this service's own authority list: a
// downstream CA belongs to whoever asked for it, and adding it here would mean
// this service started signing with somebody else's key.
//
// **THIS IS THE ONLY CA UNDER A SPIFFE AUTHORITY, AND IT IS WHY THAT AUTHORITY
// IS `pathLen: 1` WHILE EVERY OTHER ISSUING CA IN THIS SERVICE IS 0.** With the
// authority self-signed that cost nothing — it was its own anchor and could
// say what it liked about depth. Under the Root it costs a widening of two
// certificates: the SPIFFE Issuing CA to 1 and the realm Intermediate above it
// to 2. `common/pki.js`'s `intermediatePathLen()` derives the second from the
// first so that nobody can widen one and forget the other, which is the
// failure that encodes perfectly and validates nowhere.
//
// **IT USED TO GO INTO THE BUNDLE "for the same reason the root does" AND THAT
// SENTENCE IS NOW WRONG.** The bundle publishes the trust ANCHOR, and a
// downstream CA is not one — it is an intermediate, and it travels in the
// chain, which is what `chainDer` below is for. Under the old arrangement the
// authority was the anchor, so anything it signed that was itself a CA looked
// like bundle material; under the Root nothing changes about who is trusted
// when a downstream CA is minted, which is the correct answer and was not
// available before.
// ---------------------------------------------------------------------------
async function downstreamCa(options) {
  log.debug('Entering downstreamCa().');
  const opts = options || {};
  const realmId = realmIdOf(opts.realm);
  await ready(realmId);
  const authority = activeX509Authority(realmId);
  if (!authority) {
    log.debug('Leaving downstreamCa(). No authority.');
    throw new Error('This trust domain has no X.509 authority in the "' +
                    (realmId || 'default') + '" realm.');
  }
  const fallbackType = keyTypeById(authority.keyType) || KEY_TYPES[0];
  const pair = await keys.generateKeyPair(opts.keyType || fallbackType.id);
  const ttl = Number(opts.ttl) > 0 ? Number(opts.ttl) : config.value('spiffe.caTtl');
  const notBefore = new Date();
  let notAfter = new Date(notBefore.getTime() + ttl * 1000);
  const caNotAfter = new Date(authority.notAfter);
  if (notAfter > caNotAfter) notAfter = caNotAfter;
  const issued = await issueFromAuthority(realmId, authority, {
    subject: 'CN=mock-sts SPIFFE downstream CA (' + TRUST_DOMAIN + '),O=mock-sts',
    publicKeyPem: pair.publicPem,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true, pathLen: 0 },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] },
      subjectAltName: { present: true, critical: false,
                        names: [{ kind: 'uri',
                                  value: spiffeId.trustDomainId(TRUST_DOMAIN) }] },
      subjectKeyIdentifier: { present: true },
      authorityKeyIdentifier: { present: true }
    }
  });
  log.debug('Leaving downstreamCa(). serial=' + issued.serialHex);
  return {
    certificatePem: issued.pem,
    certificateDer: issued.der,
    privateKeyPem: pair.privatePem,
    // The downstream CA FIRST, then everything above it up to but not
    // including the anchor — which on the PKI path is the SPIFFE Issuing CA
    // and the realm's Intermediate, and on the self-signed path is the
    // authority itself, because there it IS the anchor's certificate and a
    // consumer holding the bundle has it either way.
    chainDer: [issued.der].concat(issued.chainDer.length
      ? issued.chainDer : [authority.certificateDer]),
    notAfter: notAfter.toISOString(),
    expiresAt: Math.floor(notAfter.getTime() / 1000)
  };
}

// ---------------------------------------------------------------------------
// MINTING A JWT-SVID.
//
// The JWT-SVID specification, in five claims:
//
//   `sub`  the SPIFFE ID. This is the identity; there is no other claim that
//          carries it.
//   `aud`  REQUIRED, and at least one. A JWT-SVID with no audience is a bearer
//          token good against everything that accepts one, which is why the
//          Workload API's FetchJWTSVID takes the audience as a parameter and
//          why this refuses an empty list rather than defaulting one.
//   `exp`  REQUIRED.
//   `iat`  optional, and written.
//   `jti`  optional. Written, because the console lists what this service has
//          issued and an artifact with no identifier cannot be pointed at.
//
// There is deliberately NO `iss`. A JWT-SVID is verified against the trust
// bundle of the trust domain in the `sub`, not against an issuer claim — that
// is the structural difference from every other JWT this service mints, and
// adding an `iss` here would teach a client to check the wrong thing.
// ---------------------------------------------------------------------------
async function mintJwtSvid(id, audiences, options) {
  log.debug('Entering mintJwtSvid(). id=' + id);
  await ready();
  const opts = options || {};
  const parsed = spiffeId.parse(id);
  if (!parsed.ok) {
    log.debug('Leaving mintJwtSvid(). Invalid SPIFFE ID.');
    throw new Error('Cannot mint a JWT-SVID for ' + id + ': ' + parsed.reason);
  }
  const list = (audiences || []).map(function (a) {
    return String(a == null ? '' : a).trim();
  }).filter(Boolean);
  if (!list.length) {
    log.debug('Leaving mintJwtSvid(). No audience.');
    throw new Error('A JWT-SVID must name at least one audience.');
  }
  const authority = jwtList()[0];
  if (!authority) {
    log.debug('Leaving mintJwtSvid(). No JWT authority.');
    throw new Error('This trust domain has no JWT authority.');
  }
  const ttl = Number(opts.ttl) > 0 ? Number(opts.ttl) : jwtSvidTtlSeconds();
  const issuedAt = nowSec();
  const expires = issuedAt + ttl;
  const payload = {
    sub: parsed.id,
    // One audience is written as a string and several as an array, which is
    // what RFC 7519 says and what every JWT library expects. Writing a
    // single-element array is legal and is read correctly by fewer things than
    // it should be.
    aud: list.length === 1 ? list[0] : list,
    exp: expires,
    iat: issuedAt,
    jti: b64u(crypto.randomBytes(12))
  };
  const token = stsCrypto.signJws(payload, authority.privateKeyPem, {
    algorithm: authority.alg,
    keyid: authority.id,
    // `JWT` rather than the default, and stated rather than left implicit: the
    // JWT-SVID specification says the `typ` header, if present, must be `JWT`
    // or `JOSE`.
    header: { typ: 'JWT' }
  });
  log.debug('Leaving mintJwtSvid(). aud=' + list.join(', '));
  return { spiffeId: parsed.id, token: token, audiences: list,
           expiresAt: expires, issuedAt: issuedAt, jti: payload.jti,
           kid: authority.id, alg: authority.alg, hint: opts.hint || '' };
}

// ---------------------------------------------------------------------------
// VALIDATING A JWT-SVID — the one thing in this whole module that REFUSES.
//
// `ValidateJWTSVID` on the Workload API is a verification service, so it has to
// actually verify: the point of the call is to be told no. It is the exception
// to this service's permissive posture for the same reason `/oauth2/userinfo`
// is the exception among the token-reading endpoints — a mock that said yes to
// everything here would be useless to the client author testing their error
// paths, which is the only reason anybody calls it.
//
// What is checked, in the order a real implementation checks it:
//
//   * the signature, against the JWT authorities of the trust domain named in
//     the `sub` — this one's, or a FEDERATED one's if the sub belongs to a
//     trust domain whose bundle has been given to us. A trust domain with no
//     bundle here cannot be validated and is refused saying so, rather than
//     refused as a bad signature.
//   * `exp`, with no leeway at all. A JWT-SVID has a short lifetime by design.
//   * `aud` contains the audience the caller says it is.
//   * `sub` is a valid SPIFFE ID belonging to the trust domain whose key
//     verified it. A token signed by trust domain A carrying a `sub` in trust
//     domain B is the confused-deputy shape this check exists for.
// ---------------------------------------------------------------------------
async function validateJwtSvid(token, audience) {
  log.debug('Entering validateJwtSvid().');
  await ready();
  const text = String(token == null ? '' : token).trim();
  if (!text) {
    log.debug('Leaving validateJwtSvid(). No token.');
    return { ok: false, reason: 'No JWT-SVID was given.' };
  }
  const wanted = String(audience == null ? '' : audience).trim();
  if (!wanted) {
    log.debug('Leaving validateJwtSvid(). No audience.');
    return { ok: false, reason: 'ValidateJWTSVID requires the audience the ' +
                                'validating party goes by; a JWT-SVID is only ' +
                                'meaningful against one.' };
  }
  let unverified;
  try {
    unverified = jwt.decode(text, { complete: true });
  } catch (e) {
    // Not a JWS at all. The text is not logged: it is somebody's credential.
    log.debug('Leaving validateJwtSvid(). Not a JWT.');
    return { ok: false, reason: 'That is not a JWT.' };
  }
  if (!unverified || !unverified.payload) {
    log.debug('Leaving validateJwtSvid(). Nothing decoded.');
    return { ok: false, reason: 'That is not a JWT.' };
  }
  const subject = String((unverified.payload || {}).sub || '');
  const parsedSub = spiffeId.parse(subject);
  if (!parsedSub.ok) {
    log.debug('Leaving validateJwtSvid(). The sub is not a SPIFFE ID.');
    return { ok: false, reason: 'The sub claim of a JWT-SVID is a SPIFFE ID; ' +
                                'this one is not: ' + parsedSub.reason };
  }
  // Which keys may verify it. The FIRST decision, before any cryptography,
  // because "I have no bundle for that trust domain" and "the signature is
  // wrong" are different answers and a caller acts differently on each.
  const candidates = jwkSetFor(parsedSub.trustDomain);
  if (!candidates) {
    log.debug('Leaving validateJwtSvid(). Unknown trust domain.');
    return { ok: false, reason: 'This service holds no JWT bundle for the ' +
                                'trust domain ' + parsedSub.trustDomain +
                                ', so nothing here can verify that SVID. Its ' +
                                'own trust domain is ' + TRUST_DOMAIN + '; a ' +
                                'foreign one has to be federated first.' };
  }
  const kid = ((unverified.header || {}).kid) || '';
  const usable = candidates.filter(function (entry) {
    return !kid || entry.kid === kid;
  });
  if (!usable.length) {
    log.debug('Leaving validateJwtSvid(). No key with that kid.');
    return { ok: false, reason: 'No key in the ' + parsedSub.trustDomain +
                                ' bundle has the kid ' + kid + '.' };
  }
  let verified = null;
  let lastError = '';
  for (let i = 0; i < usable.length && !verified; i++) {
    try {
      verified = stsCrypto.verifyJws(text, usable[i].pem, {
        audience: wanted,
        // No leeway, stated deliberately. A JWT-SVID lives for minutes by
        // design, and clock skew tolerance on a credential that short is most
        // of its lifetime. `stsCrypto.verifyJws()` would otherwise apply
        // `oauth2.clockSkewS`, which is the right default for an OAuth token
        // and the wrong one here — so this is the opt-out that default exists
        // to make visible.
        clockTolerance: 0,
        algorithms: usable[i].algorithms
      });
    } catch (e) {
      lastError = e.message;
    }
  }
  if (!verified) {
    log.debug('Leaving validateJwtSvid(). It did not verify: ' + lastError);
    return { ok: false, reason: lastError || 'The SVID did not verify.' };
  }
  if (String(verified.sub || '') !== parsedSub.id) {
    // Cannot happen with the check above, and checked anyway: this is the
    // claim the whole answer rests on, and reading it twice from two decodings
    // costs nothing.
    log.debug('Leaving validateJwtSvid(). The verified sub differs.');
    return { ok: false, reason: 'The verified sub is not the one presented.' };
  }
  log.debug('Leaving validateJwtSvid(). It verified. sub=' + verified.sub);
  return { ok: true, spiffeId: verified.sub, claims: verified,
           trustDomain: parsedSub.trustDomain };
}

// The verification keys for a trust domain, as PEMs the JWS library can use.
// null — not an empty array — when the trust domain is not one this service
// knows, because those are different answers.
function jwkSetFor(trustDomain) {
  log.debug('Entering jwkSetFor().');
  if (trustDomain === TRUST_DOMAIN) {
    log.debug('Leaving jwkSetFor().');
    return jwtList().map(function (authority) {
      return { kid: authority.id, pem: authority.publicKeyPem,
               algorithms: [authority.alg] };
    });
  }
  const foreign = federated.get(trustDomain);
  if (!foreign) {
    log.debug('Leaving jwkSetFor().');
    return null;
  }
  const out = [];
  (foreign.document.keys || []).forEach(function (key) {
    if (key.use !== 'jwt-svid') return;
    try {
      const pem = crypto.createPublicKey({ key: key, format: 'jwk' })
        .export({ type: 'spki', format: 'pem' });
      out.push({ kid: key.kid || '', pem: pem,
                 // The algorithms a key of this type could have signed with.
                 // Named rather than left open, because `algorithms` omitted
                 // lets `none` through in some libraries and this one is
                 // reading somebody else's document.
                 algorithms: algorithmsFor(key) });
    } catch (e) {
      // A JWK this service cannot read. Skipped rather than fatal: a foreign
      // bundle may hold key types nothing here understands, and the rest of it
      // is still usable.
      log.warn('spiffe: a JWT key in the ' + trustDomain + ' bundle could ' +
               'not be read and was skipped: ' + e.message);
    }
  });
  log.debug('Leaving jwkSetFor().');
  return out;
}

function algorithmsFor(jwk) {
  if (jwk.alg) return [jwk.alg];
  if (jwk.kty === 'RSA') return ['RS256', 'RS384', 'RS512', 'PS256'];
  if (jwk.kty === 'EC') {
    if (jwk.crv === 'P-384') return ['ES384'];
    if (jwk.crv === 'P-521') return ['ES512'];
    return ['ES256'];
  }
  return ['EdDSA'];
}

// ---------------------------------------------------------------------------
// THE BUNDLE.
//
// A JWK Set with two SPIFFE members on it, per the SPIFFE Trust Domain and
// Bundle specification:
//
//   `spiffe_sequence`      monotonic, changes when the bundle changes
//   `spiffe_refresh_hint`  how often a consumer should come back, in seconds
//
// and each JWK carrying `use`, which is what says whether a key is for X.509 or
// for JWT. **A JWK with a missing or unknown `use` MUST be ignored ENTIRELY by
// a consumer**, which is worth knowing because it is the failure mode of
// getting this wrong: the bundle parses, the key is silently dropped, and every
// SVID fails to verify with no error mentioning the bundle.
//
// The X.509 half carries `x5c` — the base64 DER of the certificate, NOT PEM and
// NOT base64url. The key parameters (`n`/`e`, or `crv`/`x`/`y`) are published
// beside it because a JWK needs `kty` at minimum and a consumer may use either.
// ---------------------------------------------------------------------------
// **WHAT THE X.509 HALF PUBLISHES CHANGED ON 2026-09-11 AND IT IS THE ONE
// OUTWARD-FACING CONSEQUENCE OF THE WHOLE MOVE.** It used to be the trust
// domain's own authorities, because they were self-signed and each was its own
// anchor. It is now the service ROOT — one entry, shared by every realm,
// unchanged by a rotation of any realm's SPIFFE Issuing CA. That is exactly
// what SPIRE publishes when an UpstreamAuthority plugin is configured, and it
// is the difference between "the bundle is the list of CAs that signed things"
// and "the bundle is the list of anchors you should trust". Only the second
// was ever what a bundle meant; the first was true here by coincidence.
//
// A realm with no hierarchy publishes its self-signed authorities exactly as
// before — see `trustAnchorsIn()`.
async function bundle(realmId) {
  log.debug('Entering bundle().');
  const id = realmIdOf(realmId);
  await ready(id);
  const keyList = [];
  trustAnchorsIn(id).forEach(function (anchor) {
    const jwk = publicJwkOf(anchor.publicKeyPem);
    jwk.use = 'x509-svid';
    jwk.x5c = [anchor.certificateDer.toString('base64')];
    keyList.push(jwk);
  });
  jwtList(id).forEach(function (authority) {
    const jwk = Object.assign({}, authority.jwk);
    jwk.use = 'jwt-svid';
    jwk.kid = authority.id;
    keyList.push(jwk);
  });
  const document = {
    keys: keyList,
    spiffe_sequence: sequenceNow(id),
    spiffe_refresh_hint: refreshHintSeconds()
  };
  log.debug('Leaving bundle(). ' + keyList.length + ' key(s), sequence ' +
            sequenceNow(id) + '.');
  return document;
}

// The X.509 half of the bundle as CONCATENATED DER, which is the shape the
// Workload API's `bundle` and `bundles` fields take — not PEM, not a list, one
// byte string holding every CA certificate end to end. Getting this wrong
// produces a field a workload parses as one certificate and then cannot verify
// anything against after a rotation.
async function x509BundleDer(realmId) {
  const id = realmIdOf(realmId);
  await ready(id);
  return Buffer.concat(trustAnchorsIn(id).map(function (a) {
    return a.certificateDer;
  }));
}

// The same, for a federated trust domain, built from the `x5c` members of the
// bundle somebody gave us.
function federatedX509BundleDer(trustDomain) {
  log.debug('Entering federatedX509BundleDer().');
  const foreign = federated.get(trustDomain);
  if (!foreign) {
    log.debug('Leaving federatedX509BundleDer().');
    return null;
  }
  const parts = [];
  (foreign.document.keys || []).forEach(function (key) {
    if (key.use !== 'x509-svid') return;
    (key.x5c || []).forEach(function (b64) {
      try {
        parts.push(Buffer.from(String(b64), 'base64'));
      } catch (e) {
        // A malformed x5c entry. Skipped, with the same reasoning as a
        // malformed JWK above: the rest of the bundle is still usable.
        log.warn('spiffe: an x5c entry in the ' + trustDomain + ' bundle ' +
                 'could not be decoded and was skipped: ' + e.message);
      }
    });
  });
  log.debug('Leaving federatedX509BundleDer().');
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// FEDERATION, AND THE ONE THING IT DELIBERATELY DOES NOT DO.
//
// **A foreign bundle is GIVEN to this service, never FETCHED by it.** The
// SPIFFE federation specification has a bundle endpoint URL in the federation
// relationship, and a real implementation polls it. This one records the URL
// and does not follow it, which is the same refusal `wsfed.js` gives `wreqptr`
// and `client_auth.js` gives `jwks_uri`, for the same reason: fetching a URL
// that somebody registered, in order to obtain a credential-verification key,
// is a server-side request forgery with a specification citation attached. On a
// service that authenticates nobody and accepts any registration, that is a
// blind HTTP client anybody can point anywhere.
//
// Holding that position in two files and not in a third would be no position at
// all. The bundle is pasted in — through `/admin/spiffe`, through
// `POST /admin-api/spiffe/federation-set`, or through the SPIRE Server API's
// `BatchCreateFederatedBundle` — and `RefreshBundle` answers by saying so.
// ---------------------------------------------------------------------------
function setFederatedBundle(trustDomain, document, options) {
  log.debug('Entering setFederatedBundle(). trustDomain=' + trustDomain);
  const opts = options || {};
  const name = String(trustDomain == null ? '' : trustDomain).trim().toLowerCase();
  const parsed = spiffeId.parse(spiffeId.trustDomainId(name));
  if (!parsed.ok) {
    log.debug('Leaving setFederatedBundle(). Bad trust domain.');
    return { ok: false, reason: parsed.reason };
  }
  if (name === TRUST_DOMAIN) {
    log.debug('Leaving setFederatedBundle(). That is this trust domain.');
    return { ok: false, reason: name + ' is this service\'s own trust ' +
                                'domain. A trust domain does not federate ' +
                                'with itself, and accepting this would give ' +
                                'it two bundles that could disagree.' };
  }
  const checked = checkBundleDocument(document);
  if (!checked.ok) {
    log.debug('Leaving setFederatedBundle(). Bad document.');
    return checked;
  }
  if (!federated.has(name) && federated.size >= maxFederatedBundles()) {
    log.debug('Leaving setFederatedBundle(). Full.');
    return { ok: false, reason: 'This service holds its maximum of ' +
                                maxFederatedBundles() + ' federated ' +
                                'bundle(s) (spiffe.maxFederatedBundles).' };
  }
  const existing = federated.get(name);
  federated.set(name, {
    trustDomain: name,
    document: checked.document,
    // Recorded and never followed. See the note above.
    bundleEndpointUrl: String(opts.bundleEndpointUrl ||
                              (existing || {}).bundleEndpointUrl || ''),
    bundleEndpointProfile: String(opts.bundleEndpointProfile ||
                                  (existing || {}).bundleEndpointProfile ||
                                  'https_web'),
    endpointSpiffeId: String(opts.endpointSpiffeId ||
                             (existing || {}).endpointSpiffeId || ''),
    createdAt: existing ? existing.createdAt : Date.now(),
    updatedAt: Date.now()
  });
  // The federated bundles are part of what this service publishes to workloads
  // — X509SVIDResponse.federated_bundles and JWTBundlesResponse.bundles both
  // carry them — so changing one changes the bundle a workload sees.
  bumpSequence(undefined,
               'a federated bundle was ' + (existing ? 'updated' : 'added'));
  log.debug('Leaving setFederatedBundle(). ' + federated.size + ' federated bundle(s).');
  return { ok: true, trustDomain: name, created: !existing };
}

function deleteFederatedBundle(trustDomain) {
  log.debug('Entering deleteFederatedBundle(). trustDomain=' + trustDomain);
  const name = String(trustDomain == null ? '' : trustDomain).trim().toLowerCase();
  const had = federated.delete(name);
  if (had) bumpSequence(undefined, 'a federated bundle was removed');
  log.debug('Leaving deleteFederatedBundle(). ' + (had ? 'Removed.' : 'It was not here.'));
  return had;
}

function federatedBundle(trustDomain) {
  const name = String(trustDomain == null ? '' : trustDomain).trim().toLowerCase();
  return federated.get(name) || null;
}

function federatedBundles() {
  const out = [];
  federated.forEach(function (entry) { out.push(entry); });
  out.sort(function (a, b) { return a.trustDomain.localeCompare(b.trustDomain); });
  return out;
}

// What a bundle document has to look like before this service will hold it.
// This IS a refusal, on a service that refuses almost nothing, and it earns its
// place: a malformed bundle is not stored and quietly ignored, it is stored and
// then silently drops every key when a workload parses it. The failure arrives
// as "nothing from that trust domain verifies" with nothing pointing back here.
function checkBundleDocument(value) {
  log.debug('Entering checkBundleDocument().');
  let document = value;
  if (typeof document === 'string') {
    try {
      document = JSON.parse(document);
    } catch (e) {
      log.debug('Leaving checkBundleDocument(). Not JSON.');
      return { ok: false, reason: 'A bundle is a JSON document and that is ' +
                                  'not JSON: ' + e.message };
    }
  }
  if (!document || typeof document !== 'object') {
    log.debug('Leaving checkBundleDocument(). Not an object.');
    return { ok: false, reason: 'A bundle is a JSON object.' };
  }
  if (!Array.isArray(document.keys)) {
    log.debug('Leaving checkBundleDocument(). No keys array.');
    return { ok: false, reason: 'A bundle has a `keys` member and it is an ' +
                                'array (it may be empty — a trust domain ' +
                                'with no authorities is a real state).' };
  }
  for (let i = 0; i < document.keys.length; i++) {
    const key = document.keys[i];
    if (!key || typeof key !== 'object') {
      log.debug('Leaving checkBundleDocument(). A key is not an object.');
      return { ok: false, reason: 'Key ' + i + ' is not a JWK.' };
    }
    if (!key.kty) {
      log.debug('Leaving checkBundleDocument(). A key has no kty.');
      return { ok: false, reason: 'Key ' + i + ' has no `kty`.' };
    }
    if (key.use !== 'x509-svid' && key.use !== 'jwt-svid' && key.use !== 'wit-svid') {
      // The specification says a consumer MUST ignore a JWK whose `use` is
      // missing or unknown — so a bundle full of them is a bundle that will
      // verify nothing, and accepting it silently is the worst of the three
      // options.
      log.debug('Leaving checkBundleDocument(). A key has no usable use.');
      return { ok: false, reason: 'Key ' + i + ' has `use` of ' +
                                  (key.use ? '"' + key.use + '"' : '(absent)') +
                                  '. Every JWK in a SPIFFE bundle carries ' +
                                  '`use` of x509-svid, jwt-svid or wit-svid, ' +
                                  'and a consumer MUST IGNORE one that does ' +
                                  'not — so a bundle of these would verify ' +
                                  'nothing and report no error.' };
    }
    if (key.use === 'x509-svid' && (!Array.isArray(key.x5c) || !key.x5c.length)) {
      log.debug('Leaving checkBundleDocument(). An x509-svid key has no x5c.');
      return { ok: false, reason: 'Key ' + i + ' is an x509-svid key with no ' +
                                  '`x5c`; the certificate is what an X.509 ' +
                                  'authority IS.' };
    }
  }
  log.debug('Leaving checkBundleDocument(). ' + document.keys.length + ' key(s).');
  return { ok: true, document: document };
}

// ===========================================================================
// ROTATION, WHICH IS TWO DIFFERENT ACTS NOW AND WAS ONE BEFORE 2026-09-11.
//
// **THE SELF-SIGNED CASE IS UNCHANGED AND ITS ARGUMENT IS KEPT VERBATIM**: a
// new authority is PREPENDED — it becomes the one everything is signed with —
// and the old one stays in the bundle so that SVIDs already in the field keep
// verifying. That is what a bundle is for, and dropping the old one is the
// difference between a rotation and an outage. The retired authorities are
// capped, because this is a mock and somebody will press the button fifty
// times: past the cap the oldest is dropped, which invalidates whatever it
// signed. Said out loud on the page rather than left to be discovered.
//
// **THE PKI CASE NEEDS NONE OF THAT, AND THE REASON IS THE POINT OF THE WHOLE
// MOVE.** Rotating there means re-issuing the realm's SPIFFE Issuing CA under
// an Intermediate that has not moved, under a Root that has not moved. The
// ANCHOR is unchanged, so a bundle nobody re-fetches is still correct; an SVID
// minted a minute ago carries the OLD Issuing CA in its own chain and goes on
// building a path to the same Root. There is nothing to retain, nothing to cap,
// and no window in which a rotation looks like an outage.
//
// So: one button on `/admin/spiffe`, two mechanisms, and the answer says which
// ran. Reporting them identically would have been the tempting thing and would
// have hidden the single most useful property this change bought.
// ===========================================================================
const MAX_RETAINED_AUTHORITIES = 4;

async function rotateX509Authority(realmId) {
  log.debug('Entering rotateX509Authority().');
  const id = realmIdOf(realmId);
  await ready(id);
  if (pki.describeIssuer(id, SPIFFE_USE_CASE)) {
    // `reissueUseCase()` supersedes the old authority on its Intermediate's
    // revocation list and re-mints everything that was certified under it —
    // which for SPIFFE is nothing, because `issueUnder()` records nothing. It
    // is called rather than reimplemented so that a SPIFFE rotation and the
    // Reissue button on /admin/pki are ONE act with one set of consequences.
    const done = await pki.reissueUseCase(id, SPIFFE_USE_CASE);
    if (!done.ok) {
      log.debug('Leaving rotateX509Authority(). The PKI refused.');
      throw new Error((done.errors || ['The SPIFFE Issuing CA could not be ' +
                                       're-issued.']).join(' '));
    }
    // **THE SEQUENCE DOES NOT MOVE, AND THAT IS NOT AN OVERSIGHT.** It is
    // defined to change when the BUNDLE changes, and the bundle is the Root.
    // Bumping it here would tell every consumer in the trust domain to
    // re-fetch a document that is byte-identical to the one they hold.
    const fresh = activeX509Authority(id);
    log.info('spiffe: the "' + (id || 'default') + '" realm\'s SPIFFE ' +
             'Issuing CA was re-issued (' + fresh.id + '). The bundle is ' +
             'UNCHANGED — it publishes this service\'s Root, which did not ' +
             'move — so SVIDs minted under the old authority go on verifying ' +
             'and no consumer has to re-fetch anything.');
    log.debug('Leaving rotateX509Authority(). Re-issued under the Root.');
    return fresh;
  }
  const authority = await makeX509Authority(config.value('spiffe.x509KeyType'),
                                            config.value('spiffe.caTtl'), 1);
  // READ, PREPEND, WRITE BACK — and the write is what makes the rotation the
  // SERVICE's rather than this process's. `x509List()` hands back the
  // memoised array, so it is copied before being changed.
  const kept = [authority].concat(x509List(id));
  const dropped = kept.splice(MAX_RETAINED_AUTHORITIES);
  setX509List(id, kept);
  bumpSequence(id, 'the X.509 authority was rotated');
  log.info('spiffe: a new SELF-SIGNED X.509 authority (' + authority.id +
           ') is now active in "' + (id || 'default') + '"; ' +
           (kept.length - 1) + ' retired one(s) are ' +
           'still published in the bundle' +
           (dropped.length ? ', and ' + dropped.length + ' was dropped — ' +
            'anything it signed no longer verifies' : '') + '.');
  log.debug('Leaving rotateX509Authority().');
  return selfSignedAuthorityFrom(authority);
}

async function rotateJwtAuthority(realmId) {
  log.debug('Entering rotateJwtAuthority().');
  const id = realmIdOf(realmId);
  await ready(id);
  const authority = await makeJwtAuthority(config.value('spiffe.jwtKeyType'));
  const kept = [authority].concat(jwtList(id));
  const dropped = kept.splice(MAX_RETAINED_AUTHORITIES);
  setJwtList(id, kept);
  bumpSequence(id, 'the JWT authority was rotated');
  log.info('spiffe: a new JWT authority (kid ' + authority.id + ') is now ' +
           'active; ' + (kept.length - 1) + ' retired one(s) are ' +
           'still published' +
           (dropped.length ? ', and ' + dropped.length + ' was dropped — ' +
            'anything it signed no longer verifies' : '') + '.');
  log.debug('Leaving rotateJwtAuthority().');
  return authority;
}

// ---------------------------------------------------------------------------
// SMALL CONVERSIONS. Here rather than in `jose_jwe.js` because that file is
// vendored and must stay byte-identical to the parent project's copy.
// ---------------------------------------------------------------------------
function pemToDer(pem) {
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
}

function derToPem(der, label) {
  const b64 = Buffer.from(der).toString('base64');
  const lines = b64.match(/.{1,64}/g) || [];
  return '-----BEGIN ' + label + '-----\n' + lines.join('\n') +
         '\n-----END ' + label + '-----\n';
}

function toArrayBuffer(buf) {
  const view = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
}

// ---------------------------------------------------------------------------
// WHAT THE PAGES REPORT.
//
// The ONE synchronous entry point, and it is synchronous on purpose: it is read
// by `/admin/spiffe` and by `GET /spiffe` while the authorities may still be
// being generated, and a page that awaited them would hang for the two seconds
// an RSA-4096 authority takes rather than saying "still starting". `ready`
// false with no `error` IS that state, and both pages print it.
//
// NO PRIVATE KEY IS IN HERE. The certificate, the public JWK and the kid are
// published; the keys stay in this module, exactly as `tls_server.js` publishes
// its certificate and not its key.
// ---------------------------------------------------------------------------
function state(realmId) {
  const id = realmIdOf(realmId);
  const active = activeX509Authority(id);
  const anchors = trustAnchorsIn(id);
  return {
    enabled: !!config.value('spiffe.enabled'),
    ready: !!started && !startError,
    error: startError || '',
    startedAt: started || 0,
    realm: id,
    trustDomain: TRUST_DOMAIN,
    trustDomainId: spiffeId.trustDomainId(TRUST_DOMAIN),
    serverId: started && !startError ? spiffeId.serverId(TRUST_DOMAIN) : '',
    sequence: sequenceNow(id),
    refreshHint: refreshHintSeconds(),
    // ---------------------------------------------------------------------
    // WHERE THE AUTHORITY CAME FROM, WHICH EVERY PAGE THAT DRAWS THIS MUST
    // SHOW (2026-09-11).
    //
    // `pki` means this realm's SPIFFE Issuing CA under this service's own
    // Root, and the anchor a consumer installs is that Root — one anchor for
    // every realm, every socket and every token this service signs, and it
    // survives a restart wherever the keystore does. `self-signed` means the
    // authority IS the anchor and has to be fetched again after every
    // restart. A reader cannot tell those apart from a certificate, and what
    // they have to DO about them is completely different, so it is a field
    // rather than something to infer from the chain being empty.
    // ---------------------------------------------------------------------
    authoritySource: active ? active.source : '',
    // The chain that travels WITH an SVID — the SPIFFE Issuing CA and this
    // realm's Intermediate — and never the anchor, which is in the bundle.
    chain: active ? active.chainPem.slice() : [],
    // The same list as names, for the pages. Read off the certificates with
    // node's own parser rather than assembled from the fields beside them, for
    // `certificateFacts()`'s reason: a subject rendered two ways is a subject
    // a reader cannot compare with an `openssl x509 -subject`.
    chainSubjects: active ? active.chainPem.map(function (pem) {
      try {
        return new crypto.X509Certificate(pem).subject.replace(/\n/g, ', ');
      } catch (e) {
        // A certificate this service built that node cannot read is a defect
        // here rather than bad input, so it is logged — and it is bookkeeping,
        // so it never fails the report it is part of.
        log.error('spiffe: a chain certificate would not parse for state(): ' +
                  e.message);
        return '(unreadable)';
      }
    }) : [],
    root: active && active.source === 'pki'
      ? { subject: active.anchorSubject, notAfter: active.anchorNotAfter,
          certificatePem: active.anchorPem }
      : null,
    intermediate: active ? active.intermediateSubject : '',
    // **THE ANCHORS AND THE AUTHORITIES ARE TWO LISTS NOW.** They were one,
    // because a self-signed authority is its own anchor; under the Root they
    // differ and a page showing only one of them would answer the wrong
    // question — "what signed this SVID" and "what do I have to trust" are
    // not the same question and stopped having the same answer.
    trustAnchors: anchors.map(function (a) {
      return { id: a.id, source: a.source, subject: a.subject,
               notBefore: a.notBefore, notAfter: a.notAfter,
               certificatePem: a.certificatePem };
    }),
    x509Authorities: active
      ? [{ id: active.id, active: true, source: active.source,
           keyType: active.keyType, subject: active.subject,
           serialHex: active.serialHex,
           notBefore: active.notBefore, notAfter: active.notAfter,
           certificatePem: active.certificatePem,
           createdAt: active.createdAt || 0 }].concat(
          // The retired self-signed authorities, which exist only on that
          // path — a re-issued Issuing CA leaves nothing behind here, for
          // `rotateX509Authority()`'s reason.
          active.source === 'self-signed'
            ? x509List(id).slice(1).map(function (a) {
                return { id: a.id, active: false, source: 'self-signed',
                         keyType: a.keyType, subject: a.subject,
                         serialHex: a.serialHex, notBefore: a.notBefore,
                         notAfter: a.notAfter,
                         certificatePem: a.certificatePem,
                         createdAt: a.createdAt };
              })
            : [])
      : [],
    jwtAuthorities: jwtList(id).map(function (a, index) {
      return { id: a.id, active: index === 0, keyType: a.keyType, alg: a.alg,
               jwk: a.jwk, createdAt: a.createdAt };
    }),
    federated: federatedBundles().map(function (entry) {
      const x509Keys = (entry.document.keys || []).filter(function (k) {
        return k.use === 'x509-svid';
      }).length;
      const jwtKeys = (entry.document.keys || []).filter(function (k) {
        return k.use === 'jwt-svid';
      }).length;
      return { trustDomain: entry.trustDomain,
               trustDomainId: spiffeId.trustDomainId(entry.trustDomain),
               x509Keys: x509Keys, jwtKeys: jwtKeys,
               keys: (entry.document.keys || []).length,
               sequence: entry.document.spiffe_sequence || 0,
               refreshHint: entry.document.spiffe_refresh_hint || 0,
               bundleEndpointUrl: entry.bundleEndpointUrl,
               bundleEndpointProfile: entry.bundleEndpointProfile,
               endpointSpiffeId: entry.endpointSpiffeId,
               createdAt: entry.createdAt, updatedAt: entry.updatedAt };
    }),
    keyTypes: KEY_TYPES.map(function (t) {
      return { id: t.id, label: t.label, kind: t.kind, jwtAlg: t.jwtAlg,
               what: t.what };
    })
  };
}

module.exports = {
  KEY_TYPES: KEY_TYPES,
  MAX_RETAINED_AUTHORITIES: MAX_RETAINED_AUTHORITIES,
  trustDomain: function () { return TRUST_DOMAIN; },
  trustDomainId: function () { return spiffeId.trustDomainId(TRUST_DOMAIN); },
  ready: ready,
  state: state,
  mintX509Svid: mintX509Svid,
  signCsr: signCsr,
  downstreamCa: downstreamCa,
  mintJwtSvid: mintJwtSvid,
  validateJwtSvid: validateJwtSvid,
  bundle: bundle,
  x509BundleDer: x509BundleDer,
  federatedX509BundleDer: federatedX509BundleDer,
  setFederatedBundle: setFederatedBundle,
  deleteFederatedBundle: deleteFederatedBundle,
  federatedBundle: federatedBundle,
  federatedBundles: federatedBundles,
  checkBundleDocument: checkBundleDocument,
  rotateX509Authority: rotateX509Authority,
  rotateJwtAuthority: rotateJwtAuthority,
  // The realm's active X.509 authority, for a caller that needs to say what
  // signed an SVID without drawing the whole of `state()`.
  activeX509Authority: activeX509Authority,
  trustAnchors: trustAnchorsIn,
  sequence: function (realmId) { return sequenceNow(realmId); }
};
