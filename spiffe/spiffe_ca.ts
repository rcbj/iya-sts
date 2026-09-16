'use strict';
//
// File: spiffe_ca.ts
//
// ---------------------------------------------------------------------------
// THE TRUST DOMAIN'S ISSUING AUTHORITY: the X.509 CA that signs X509-SVIDs, the
// JWT authority that signs JWT-SVIDs, the bundle that publishes both, and the
// bundles of foreign trust domains this one federates with.
//
// It is a LIBRARY (rule 3): it registers no route, so its position in the
// require order does not matter, and it requires `helpers.js`, `config.js`,
// `spiffe_id.ts` and the two vendored PKI modules — none of which requires it
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
// which `common/crypto.js` uses for the self-signed RSA certificates of the STS
// signing key and the TLS server — cannot sign with an EC key at all, so a CA
// built on it would have been RSA-only. RSA is permitted by the specification
// and would have interoperated; it would simply not have been what a client
// author sees in front of a real SPIRE deployment.
//
// **Do not edit the four vendored files** (they are in `common/vendored/`). A
// change here that is not also made there is a fork nobody else can consume,
// and nothing checks these four for drift automatically — see
// `common/vendored/CLAUDE.md`.
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

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpiffeCa` takes the modules it uses through its constructor
// (`SpiffeCaDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `SpiffeCa` is exported beside them for the
// composition root.
//
// **THE TABLES WHOSE ENTRIES CALL THIS MODULE** (`readyPromise`) are built by
// `build…()` methods, called at load where each was declared.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
// For the federated bundle store below — a persisted per-realm map rather than
// a plain one, so every process in this service sees the same bundles and no
// realm sees another's.
import realms = require('../common/realms');
import jwt = require('jsonwebtoken');
// One signer and one verifier for the whole service since 2026-08-27.
import stsCrypto = require('../common/crypto');
import pkijs = require('pkijs');
import asn1js = require('asn1js');
import helpers = require('../common/helpers');
const { log, b64u, nowSec, dnRfc4514 } = helpers;
import config = require('../common/config');
// THE ERROR CODES. A LEAF, so it cannot close a cycle from here — which is the
// constraint this module is under, since it does not require `audit.js`. Its
// refusals carry a code as `errorCode` on the result for the caller that
// records the row, and its own failures are tagged on the log line.
import errorCodes = require('../common/error_codes');
import spiffeId = require('./spiffe_id');
import keys = require('../common/vendored/key_material');
import x509 = require('../common/vendored/x509');

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
// ---------------------------------------------------------------------------
// **THE TRUST DOMAIN IS A REALM'S SINCE 2026-09-12, AND THIS CONSTANT WAS THE
// WHOLE OF WHY IT WAS NOT.**
//
// It read `const TRUST_DOMAIN = config.value('spiffe.trustDomain')`, captured
// once at require time, and every certificate, every SVID and every bundle in
// this file named it. That was the last thing keeping SPIFFE service-wide
// after the AUTHORITIES became per realm: `realmSupport()` said `none` for
// SPIFFE and gave this as the reason.
//
// Now each realm has one — `<realm>.<the process's>` by default, seeded when
// the realm is created the way its entityID is (see `realms.js`'s
// NAMED_BY_REALM), and settable outright on the realm. rcbj's instruction was
// *a common root domain + a unique issuer for each domain*, which is that
// arrangement exactly.
//
// **AND IT IS FIXED WHEN THE REALM'S AUTHORITIES ARE BUILT, WHICH IS THE HALF
// THAT CANNOT BE LEFT TO CONFIGURATION.** `spiffe.trustDomain` is
// `realmRuntime` in config.js — restart-only for the process, settable on a
// realm — because a realm is created with SPIFFE OFF and builds nothing until
// it is turned on. Once it HAS built them, every certificate it has issued
// names the old domain, so the built name goes on being used and the
// disagreement is REPORTED rather than acted on. `built` in the authority
// record is where it is kept; `trustDomainDrift()` is what the pages draw.
// ---------------------------------------------------------------------------
const PROCESS_TRUST_DOMAIN =
  String(config.value('spiffe.trustDomain') || 'example.org')
    .trim().toLowerCase();

// What `SpiffeCa` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface SpiffeCaDeps {
  crypto: typeof crypto;
  realms: typeof realms;
  jwt: typeof jwt;
  stsCrypto: typeof stsCrypto;
  pkijs: typeof pkijs;
  log: typeof log;
  b64u: typeof b64u;
  nowSec: typeof nowSec;
  dnRfc4514: typeof dnRfc4514;
  config: typeof config;
  errorCodes: typeof errorCodes;
  spiffeId: typeof spiffeId;
  keys: typeof keys;
  x509: typeof x509;
  pki: typeof pki;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadKeystore(): typeof import('../common/keystore');
  loadClusterClaims(): typeof import('../cluster/cluster_claims');
}

class SpiffeCa {
  constructor(private readonly deps: SpiffeCaDeps) {
    deps.log.debug("Entering SpiffeCa.constructor().");
    deps.log.debug("Leaving SpiffeCa.constructor().");
  }

  // What CONFIGURATION says this realm's trust domain is. Read through the
  // realm layer rather than from a captured value, which is the ordinary shape
  // for a per-realm setting here — and read OUTSIDE any realm for the default
  // one, so that a call arriving in `acme` cannot be answered with acme's name
  // when it asked about the default realm.
  configuredTrustDomain(realmId) {
    const { log, realms, config } = this.deps;
    log.debug("Entering SpiffeCa.configuredTrustDomain().");
    const id = this.realmIdOf(realmId);
    const realm = realms.get(id);
    const raw = realm
      ? realms.run(realm, function () {
          return config.value('spiffe.trustDomain');
        })
      : PROCESS_TRUST_DOMAIN;
    log.debug("Leaving SpiffeCa.configuredTrustDomain().");
    return String(raw || PROCESS_TRUST_DOMAIN).trim().toLowerCase();
  }

  // What this realm's authorities were actually BUILT with, if they have been.
  // Null until then, which is what lets a realm's domain still be changed.
  // The three settings an authority is GENERATED with, read in the realm they
  // are about. Every caller here is building or replacing material for one
  // realm, and a plain `config.value()` would answer with whichever realm the
  // request that triggered the work arrived in.
  realmSettings(realmId) {
    const { log, realms, config } = this.deps;
    log.debug("Entering SpiffeCa.realmSettings().");
    const realm = realms.get(this.realmIdOf(realmId));
    const read = function () {
      log.debug("Entering read().");
      log.debug("Leaving read().");
      return { x509KeyType: config.value('spiffe.x509KeyType'),
               jwtKeyType: config.value('spiffe.jwtKeyType'),
               caTtl: config.value('spiffe.caTtl'),
               caSubject: config.value('spiffe.caSubject'),
               retained: config.value('spiffe.retainedAuthorities') };
    };
    log.debug("Leaving SpiffeCa.realmSettings().");
    return realm ? realms.run(realm, read) : read();
  }

  // Run something inside a named realm. `realms.get('')` is the default realm's
  // record, so a missing id is the default realm here rather than no realm.
  inRealmOf(realmId, fn) {
    const { log, realms } = this.deps;
    log.debug("Entering SpiffeCa.inRealmOf().");
    const realm = realms.get(this.realmIdOf(realmId));
    log.debug("Leaving SpiffeCa.inRealmOf().");
    return realm ? realms.run(realm, fn) : fn();
  }

  builtTrustDomain(realmId) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.builtTrustDomain().");
    const held = this.authoritiesIn(realmId).get('trustDomain');
    log.debug("Leaving SpiffeCa.builtTrustDomain().");
    return held ? String(held) : null;
  }

  // THE ONE ANSWER EVERY OTHER FUNCTION IN THIS FILE USES. The built name wins
  // wherever there is one, for the reason the block above gives.
  trustDomainOf(realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.trustDomainOf().");
    log.debug("Leaving SpiffeCa.trustDomainOf().");
    return this.builtTrustDomain(realmId) ||
           this.configuredTrustDomain(realmId);
  }

  // Whether configuration and the material disagree, for the pages. A realm in
  // this state is not broken — it is issuing under the name it has always
  // issued under — and it is exactly the state `config.js`'s header calls the
  // silent disagreement, so nothing here is allowed to be silent about it.
  trustDomainDrift(realmId) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.trustDomainDrift().");
    const built = this.builtTrustDomain(realmId);
    const configured = this.configuredTrustDomain(realmId);
    if (!built || built === configured) {
      log.debug("Leaving SpiffeCa.trustDomainDrift().");
      return null;
    }
    log.debug("Leaving SpiffeCa.trustDomainDrift().");
    return { built: built, configured: configured };
  }

  svidTtlSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeCa.svidTtlSeconds().");
    log.debug("Leaving SpiffeCa.svidTtlSeconds().");
    return config.value('spiffe.svidTtl');
  }

  jwtSvidTtlSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeCa.jwtSvidTtlSeconds().");
    log.debug("Leaving SpiffeCa.jwtSvidTtlSeconds().");
    return config.value('spiffe.jwtSvidTtl');
  }

  refreshHintSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeCa.refreshHintSeconds().");
    log.debug("Leaving SpiffeCa.refreshHintSeconds().");
    return config.value('spiffe.refreshHint');
  }

  svidSubject() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeCa.svidSubject().");
    log.debug("Leaving SpiffeCa.svidSubject().");
    return config.value('spiffe.svidSubject');
  }

  maxFederatedBundles() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeCa.maxFederatedBundles().");
    log.debug("Leaving SpiffeCa.maxFederatedBundles().");
    return config.value('spiffe.maxFederatedBundles');
  }

  // ---------------------------------------------------------------------------
  // THE SUBJECT A CA THIS FILE BUILDS IS GIVEN (2026-09-12).
  //
  // It was the literal `CN=mock-sts SPIFFE CA (<domain>),O=mock-sts` — and the
  // downstream CA's the same with `downstream CA` in it — which put this
  // repository's name into every self-signed SPIFFE authority and every
  // downstream CA a deployment issued. `spiffe.svidSubject` covered the LEAVES
  // only. `spiffe.caSubject` is a TEMPLATE because the two CAs differ by one
  // word and both name their trust domain: `{kind}` becomes `CA` or
  // `downstream CA` and `{trustDomain}` the realm's domain. The default
  // rendered the old two strings byte for byte until the product name in every
  // identifier this service emits became `sts` the same day, so it now renders
  // `CN=sts SPIFFE CA (<domain>),O=sts`; no migration, because a SPIFFE CA is
  // minted per start in development and taken from /admin/pki everywhere else.
  //
  // The PKI path is untouched: a realm with a hierarchy takes its Issuing CA's
  // subject from `common/pki.js`, which owns it.
  // ---------------------------------------------------------------------------
  caSubjectFor(template, kind, trustDomain) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.caSubjectFor().");
    const raw = String(template == null ? '' : template).trim();
    const rendered = raw.split('{kind}').join(kind)
                        .split('{trustDomain}').join(String(trustDomain || ''));
    if (!rendered) {
      // config.js does not refuse an empty string for a string row, and an
      // empty subject is refused by the certificate builder with a message
      // about an RDN. Named here instead.
      throw new Error('spiffe.caSubject is empty, and a CA certificate needs ' +
                      'a subject. Set it to an X.501 name — the default is ' +
                      '`CN=sts SPIFFE {kind} ({trustDomain}),O=sts`.');
    }
    log.debug("Leaving SpiffeCa.caSubjectFor().");
    return rendered;
  }

  keyTypeById(id) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.keyTypeById().");
    const wanted = String(id == null ? '' : id).trim();
    for (let i = 0; i < KEY_TYPES.length; i++) {
      if (KEY_TYPES[i].id === wanted) {
        log.debug("Leaving SpiffeCa.keyTypeById().");
        return KEY_TYPES[i];
      }
    }
    log.debug("Leaving SpiffeCa.keyTypeById().");
    return null;
  }

  // The realm whose authority a call is about. Every reader here takes an
  // explicit id or falls back to the AMBIENT realm — the shape every per-realm
  // store in this service has. A gRPC call is in the realm whose socket it
  // arrived on, because `spiffe_server.ts`'s `handlersInRealm()` enters that
  // realm around every handler (the default realm's four sockets included).
  realmIdOf(realmId) {
    const { log, realms } = this.deps;
    log.debug("Entering SpiffeCa.realmIdOf().");
    if (realmId !== undefined && realmId !== null) {
      log.debug("Leaving SpiffeCa.realmIdOf().");
      return String(realmId);
    }
    const current = realms.current();
    log.debug("Leaving SpiffeCa.realmIdOf().");
    return String((current && current.id) || '');
  }

  authoritiesIn(realmId) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.authoritiesIn().");
    log.debug("Leaving SpiffeCa.authoritiesIn().");
    return authorities.realmMap(this.realmIdOf(realmId));
  }

  packX509(one) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.packX509().");
    log.debug("Leaving SpiffeCa.packX509().");
    return Object.assign({}, one, {
      certificateDer: Buffer.isBuffer(one.certificateDer)
        ? one.certificateDer.toString('base64')
        : String(one.certificateDer || '')
    });
  }

  unpackX509(one) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.unpackX509().");
    log.debug("Leaving SpiffeCa.unpackX509().");
    return Object.assign({}, one, {
      certificateDer: Buffer.isBuffer(one.certificateDer)
        ? one.certificateDer
        : Buffer.from(String(one.certificateDer || ''), 'base64')
    });
  }

  x509List(realmId) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.x509List().");
    const id = this.realmIdOf(realmId);
    const raw = this.authoritiesIn(id).get('x509') || [];
    const held = x509Unpacked.get(id);
    if (!held || held.from !== raw) {
      x509Unpacked.set(id,
                       { from: raw,
                         list: raw.map(this.unpackX509.bind(this)) });
    }
    log.debug("Leaving SpiffeCa.x509List().");
    return x509Unpacked.get(id).list;
  }

  setX509List(realmId, list) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.setX509List().");
    this.authoritiesIn(realmId).set('x509', list.map(this.packX509.bind(this)));
    log.debug("Leaving SpiffeCa.setX509List().");
  }

  jwtList(realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.jwtList().");
    log.debug("Leaving SpiffeCa.jwtList().");
    return this.authoritiesIn(realmId).get('jwt') || [];
  }

  setJwtList(realmId, list) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.setJwtList().");
    this.authoritiesIn(realmId).set('jwt', list.slice(0));
    log.debug("Leaving SpiffeCa.setJwtList().");
  }

  // The realm's own partition of that store — the ambient realm's when no id is
  // given, which is how every gRPC handler reaches it (they run inside the
  // realm whose socket the call arrived on).
  federatedIn(realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.federatedIn().");
    log.debug("Leaving SpiffeCa.federatedIn().");
    return federated.realmMap(this.realmIdOf(realmId));
  }

  // ---------------------------------------------------------------------------
  // EVERY TRUST DOMAIN THIS PROCESS SERVES, AND WHICH REALM SERVES IT.
  //
  // The default realm's and every defined realm's, read through
  // `trustDomainOf()` so a realm whose authorities were BUILT under an older
  // name is counted under the name it is actually issuing in. A realm with
  // SPIFFE off is counted too: its trust domain is still a name this service
  // has claimed, and a bundle registered under it today would be a second
  // authority for that name the moment somebody turned it on.
  // ---------------------------------------------------------------------------
  servedTrustDomains() {
    const { log, realms } = this.deps;
    const self = this;
    log.debug('Entering SpiffeCa.servedTrustDomains().');
    const out = new Map();
    out.set(this.trustDomainOf(''), '');
    realms.list().forEach(function (realm) {
      const id = realm.id === realms.DEFAULT_ID ? '' : String(realm.id);
      const name = self.trustDomainOf(id);
      if (!out.has(name)) {
        out.set(name, id);
      }
    });
    log.debug('Leaving SpiffeCa.servedTrustDomains(). ' + out.size +
              ' trust domain(s).');
    return out;
  }

  // Whether a federated entry must be IGNORED by a reader: its name is a trust
  // domain this process serves. Registration refuses that, so this is true only
  // of a row written before the refusal existed — and such a row must verify
  // nothing, anywhere, rather than wait for somebody to notice it.
  shadowsServedDomain(name) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.shadowsServedDomain().");
    log.debug("Leaving SpiffeCa.shadowsServedDomain().");
    return this.servedTrustDomains().has(String(name || ''));
  }

  // RFC-required monotonic counter on the bundle. It changes whenever the
  // bundle changes and never otherwise, which is what lets a consumer tell "I
  // have the current bundle" from "I have a bundle".
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
  // counter — would have been worse in the direction that matters: a rotation
  // in realm acme that DID change what acme publishes, with a number that never
  // moved for a caller reading acme.
  sequenceNow(realmId) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.sequenceNow().");
    const held = Number(this.authoritiesIn(realmId).get('sequence'));
    log.debug("Leaving SpiffeCa.sequenceNow().");
    return held > 0 ? held : 1;
  }

  bumpSequence(realmId, why) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.bumpSequence().");
    const id = this.realmIdOf(realmId);
    this.authoritiesIn(id).set('sequence', this.sequenceNow(id) + 1);
    log.debug('spiffe: the bundle sequence in "' + (id || 'default') +
              '" is now ' + this.sequenceNow(id) + ' (' + why + ').');
    log.debug("Leaving SpiffeCa.bumpSequence().");
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
  // The X.509 authority it builds is a self-signed CA. It is NOT the
  // certificate
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
  // `NewDownstreamX509CA` "builds a SECOND authority with `pathLen: 0` beneath
  // a root issued with `pathLen: 1`" — and both call sites passed `0`. So every
  // downstream CA this service ever minted was a CA signed by a CA that had
  // declared it would sign no CAs. It parses, it verifies as a signature, and a
  // path builder refuses the chain with a message about basic constraints that
  // names neither certificate — which is exactly the failure mode this file's
  // own header warns about, three paragraphs above the line that caused it.
  // Both call sites pass `1` now, and the PKI path gets the same depth from
  // `pki.js`'s `spiffe` use case.
  // ---------------------------------------------------------------------------
  // `trustDomain` is a PARAMETER and not a read, because this builds MATERIAL
  // for one realm and the answer has to be the one that realm is about to be
  // fixed at — a read here would take the ambient realm's, which is whichever
  // realm the request that triggered the lazy build happened to arrive in.
  async makeX509Authority(keyTypeId, ttlSeconds, pathLen, trustDomain,
                          subjectTemplate) {
    const { log, keys, x509, config, spiffeId } = this.deps;
    log.debug('Entering SpiffeCa.makeX509Authority(). keyType=' + keyTypeId +
              ' trustDomain=' + trustDomain);
    const type = this.keyTypeById(keyTypeId);
    if (!type) {
      log.debug('Leaving SpiffeCa.makeX509Authority(). Unknown key type.');
      throw new Error('Unknown SPIFFE X.509 key type: ' + keyTypeId +
                      '. Known types are ' +
                      KEY_TYPES.map(function (t) { return t.id; }).join(', ') +
                      '.');
    }
    const pair = await keys.generateKeyPair(type.id);
    const notBefore = new Date();
    const notAfter = new Date(notBefore.getTime() +
                              (ttlSeconds || 86400) * 1000);
    const issued = await x509.issueCertificate({
      // The CA's own name. A SPIFFE trust domain has no naming rules for it —
      // only the SVIDs it signs are constrained — so this says what it is and
      // which trust domain it belongs to, which is what a person reading
      // `openssl x509 -text` on a bundle needs.
      subject: this.caSubjectFor(subjectTemplate === undefined
                                   ? config.value('spiffe.caSubject') :
                                 subjectTemplate,
                                 'CA', trustDomain),
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
        // A CA in a SPIFFE bundle is also given the trust domain's own SPIFFE
        // ID as a URI subjectAltName. Nothing REQUIRES it — the X509-SVID
        // specification constrains leaves — but SPIRE does it, it costs
        // nothing, and it means a person looking at a certificate out of
        // context can see which trust domain it belongs to.
        subjectAltName: { present: true, critical: false,
                          names: [{ kind: 'uri',
                                    value: spiffeId.trustDomainId(
                                        trustDomain) }] },
        subjectKeyIdentifier: { present: true }
      }
    });
    const authority = {
      id: this.authorityIdOf(issued.pem),
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
    log.debug('Leaving SpiffeCa.makeX509Authority(). id=' + authority.id);
    return authority;
  }

  // The JWT authority: a key pair and a `kid`, and no certificate at all. A JWT
  // bundle is a JWK Set of PUBLIC KEYS — the JWT-SVID specification has no
  // certificate in it — which is the whole structural difference from the X.509
  // half and the reason these are two lists rather than one.
  async makeJwtAuthority(keyTypeId) {
    const { log, keys } = this.deps;
    log.debug('Entering SpiffeCa.makeJwtAuthority(). keyType=' + keyTypeId);
    const type = this.keyTypeById(keyTypeId);
    if (!type) {
      log.debug('Leaving SpiffeCa.makeJwtAuthority(). Unknown key type.');
      throw new Error('Unknown SPIFFE JWT key type: ' + keyTypeId + '.');
    }
    if (!type.jwtAlg) {
      log.debug('Leaving SpiffeCa.makeJwtAuthority(). No JWS algorithm.');
      throw new Error('The SPIFFE JWT authority cannot use ' + type.label +
                      ': ' + type.what);
    }
    const pair = await keys.generateKeyPair(type.id);
    const jwk = this.publicJwkOf(pair.publicPem);
    const authority = {
      // A `kid` names a KEY, so it is derived from the key material — the same
      // rule helpers.js's STS kid follows, and for the same reason: two
      // instances of this mock publishing one kid over two different keys makes
      // a verifier report "the signature does not verify", which reads as a
      // corrupt token rather than as keys fetched from the wrong instance.
      id: 'spiffe-' + this.thumbprintOf(jwk),
      keyType: type.id,
      alg: type.jwtAlg,
      privateKeyPem: pair.privatePem,
      publicKeyPem: pair.publicPem,
      jwk: jwk,
      createdAt: Date.now()
    };
    log.debug('Leaving SpiffeCa.makeJwtAuthority(). kid=' + authority.id);
    return authority;
  }

  // An X.509 authority's id: a SHA-256 over the certificate DER, which is what
  // SPIRE's `local authority` ids are and what a person can compare with
  // `openssl x509 -fingerprint -sha256`.
  authorityIdOf(pem) {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering SpiffeCa.authorityIdOf().");
    log.debug("Leaving SpiffeCa.authorityIdOf().");
    return stsCrypto.certificateThumbprint(pem,
                                           { format: 'hex', truncate: 16 });
  }

  // RFC 7638 JWK thumbprint, which is the only correct way to derive a kid from
  // a key: the members are ordered and the set of them is fixed per key type,
  // so two implementations agree. Hashing the PEM instead would give a
  // different answer for the same key depending on line wrapping.
  thumbprintOf(jwk) {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering SpiffeCa.thumbprintOf().");
    log.debug("Leaving SpiffeCa.thumbprintOf().");
    // RFC 7638, and it is still the only correct way to derive a kid from a
    // key: the members are ordered and the set of them is fixed per key type,
    // so two implementations agree. Hashing the PEM instead would give a
    // different answer for the same key depending on line wrapping.
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
  publicJwkOf(publicPem) {
    const { log, crypto } = this.deps;
    log.debug("Entering SpiffeCa.publicJwkOf().");
    const jwk = crypto.createPublicKey(publicPem).export({ format: 'jwk' });
    // `key_ops` and `ext` are Web Crypto members and are not part of a
    // published JWK. Deleted rather than left: a bundle is a document other
    // software parses strictly, and members it does not expect are members it
    // may reject.
    delete jwk.key_ops;
    delete jwk.ext;
    log.debug("Leaving SpiffeCa.publicJwkOf().");
    return jwk;
  }

  // ---------------------------------------------------------------------------
  // THE AUTHORITY THIS REALM SIGNS WITH, as one record whatever produced it.
  //
  // **`source` IS THE FIELD EVERY REPORT HAS TO CARRY.** A reader looking at an
  // SVID cannot tell a PKI-backed authority from a self-signed one without
  // being told, and the difference decides what they have to install: a
  // self-signed authority IS the anchor and has to be fetched again after every
  // restart, where the Root is the anchor and survives one in product mode.
  // Reporting the two identically would be the most expensive quiet untruth
  // this module could tell.
  //
  // `anchorPem` is what goes in the BUNDLE and `chainPem` is what travels with
  // a LEAF, and they are deliberately two fields rather than one list. For the
  // self-signed case they coincide — the authority is both — which is precisely
  // why a single field would have looked correct right up until the hierarchy
  // existed.
  // ---------------------------------------------------------------------------
  pkiAuthorityFrom(issuer) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.pkiAuthorityFrom().");
    log.debug("Leaving SpiffeCa.pkiAuthorityFrom().");
    return {
      source: 'pki',
      id: this.authorityIdOf(issuer.certificatePem),
      // The PKI's key algorithm id (`rsa-2048`, `ec-p256`, …) and NOT one of
      // this module's KEY_TYPES ids. They overlap for the EC and RSA entries
      // and it would be a coincidence to rely on: the certificate says what it
      // is, and
      // `spiffe.x509KeyType` no longer decides the authority's key at all — it
      // decides the key of an SVID, which is a different key.
      keyType: issuer.keyAlg,
      signatureAlg: issuer.signatureAlg,
      subject: issuer.subject,
      serialHex: issuer.serialHex,
      notBefore: issuer.notBefore,
      notAfter: issuer.notAfter,
      certificatePem: issuer.certificatePem,
      certificateDer: this.pemToDer(issuer.certificatePem),
      // Leaf-first from the authority upward, Root EXCLUDED — see issueLeaf().
      chainPem: issuer.chainPem.slice(),
      chainDer: issuer.chainPem.map(this.pemToDer.bind(this)),
      // The trust anchor, which is the service Root and no realm's.
      anchorPem: issuer.root.certificatePem,
      anchorDer: this.pemToDer(issuer.root.certificatePem),
      anchorSubject: issuer.root.subject,
      anchorNotAfter: issuer.root.notAfter,
      intermediateSubject: issuer.intermediate.subject
    };
  }

  selfSignedAuthorityFrom(one) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.selfSignedAuthorityFrom().");
    log.debug("Leaving SpiffeCa.selfSignedAuthorityFrom().");
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
  activeX509Authority(realmId) {
    const { log, pki } = this.deps;
    log.debug("Entering SpiffeCa.activeX509Authority().");
    const id = this.realmIdOf(realmId);
    const issuer = pki.describeIssuer(id, SPIFFE_USE_CASE);
    if (issuer) {
      log.debug("Leaving SpiffeCa.activeX509Authority().");
      return this.pkiAuthorityFrom(issuer);
    }
    const held = this.x509List(id)[0];
    log.debug("Leaving SpiffeCa.activeX509Authority().");
    return held ? this.selfSignedAuthorityFrom(held) : null;
  }

  // Every anchor a consumer of this realm's bundle should trust. One entry when
  // the hierarchy is there — the Root — and the retained self-signed list when
  // it is not, because in that arrangement each retired authority is an anchor
  // of its own and dropping it is what makes a rotation look like an outage.
  trustAnchorsIn(realmId) {
    const { log, pki, crypto } = this.deps;
    log.debug("Entering SpiffeCa.trustAnchorsIn().");
    const id = this.realmIdOf(realmId);
    const issuer = pki.describeIssuer(id, SPIFFE_USE_CASE);
    if (issuer) {
      log.debug("Leaving SpiffeCa.trustAnchorsIn().");
      return [{ source: 'pki',
                id: this.authorityIdOf(issuer.root.certificatePem),
                subject: issuer.root.subject,
                notBefore: issuer.root.notBefore,
                notAfter: issuer.root.notAfter,
                certificatePem: issuer.root.certificatePem,
                certificateDer: this.pemToDer(issuer.root.certificatePem),
                publicKeyPem: crypto.createPublicKey(issuer.root.certificatePem)
                  .export({ type: 'spki', format: 'pem' }) }];
    }
    log.debug("Leaving SpiffeCa.trustAnchorsIn().");
    return this.x509List(id).map(function (one) {
      return Object.assign({ source: 'self-signed' }, one);
    });
  }

  // ---------------------------------------------------------------------------
  // ISSUE ONE CERTIFICATE FROM THIS REALM'S AUTHORITY, whichever kind it is.
  //
  // **THE TWO PATHS DIFFER IN WHO HOLDS THE KEY AND IN NOTHING ELSE THE CALLER
  // CAN SEE.** A PKI-backed authority's private key never leaves
  // `common/pki.js` — the request goes through `issueUnder()` and the
  // certificate comes back — and a self-signed one's lives in this module's own
  // store. Both answer the same record, so `issueLeaf()` and `downstreamCa()`
  // above have ONE shape rather than a branch each. Two branches would be two
  // places for the SVID extension set to drift, and that extension set IS the
  // X509-SVID specification.
  // ---------------------------------------------------------------------------
  async issueFromAuthority(realmId, authority, spec) {
    const { log, pki, x509 } = this.deps;
    log.debug('Entering SpiffeCa.issueFromAuthority(). source=' +
              authority.source);
    if (authority.source === 'pki') {
      const made = await pki.issueUnder(this.realmIdOf(realmId),
                                        SPIFFE_USE_CASE, {
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
        log.debug('Leaving SpiffeCa.issueFromAuthority(). The PKI refused.');
        throw new Error((made.errors ||
                         ['That certificate could not be issued.'])
          .join(' '));
      }
      log.debug('Leaving SpiffeCa.issueFromAuthority(). serial=' +
                made.serialHex);
      return { pem: made.certificatePem, der: made.certificateDer,
               serialHex: made.serialHex,
               notBefore: made.notBefore, notAfter: made.notAfter,
               chainPem: authority.chainPem.slice(),
               chainDer: authority.chainDer.slice() };
    }
    const type = this.keyTypeById(authority.keyType) || KEY_TYPES[0];
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
    log.debug('Leaving SpiffeCa.issueFromAuthority(). serial=' +
              issued.serialHex);
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
  // `pki.start()`, which `common/service_state.js` runs AFTER the whole
  // protocol stack has been required and before anything binds. So an authority
  // resolved at require time is resolved when there is provably no hierarchy —
  // this module would have self-signed, written that into the store, and the
  // Root built a moment later would have certified nothing. That is exactly the
  // trap
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
  // the ordinary case there is no X.509 key to generate at all: the authority
  // is the realm's SPIFFE Issuing CA, already built. What is still generated
  // here is the JWT authority, which has no certificate and no hierarchy to
  // hang from — and it is EC P-256 by default, which is milliseconds.
  // `spiffe.jwtKeyType` set to `rsa-4096` puts that generation on the first
  // FetchJWTSVID in each realm, which is said here rather than left to be
  // discovered.
  //
  // **A REALM IS THE UNIT because the authority is.** A realm created at
  // runtime gets its trust material the first time somebody asks it for an
  // SVID, which is the same rule `common/pki.js` follows for a realm's branch
  // and removes any need for this module to watch `realms.onChange()`.
  // ---------------------------------------------------------------------------
  async initialise() {
    const { log, spiffeId, config } = this.deps;
    log.debug('Entering SpiffeCa.initialise().');
    // The DEFAULT realm's, which is this process's own and the root every
    // other realm's is built from. A REALM's is validated when its authorities
    // are built — `buildTrustMaterial()` — because a realm may not exist yet
    // and because a bad name there must take that realm's SPIFFE away and not
    // the service's.
    const parsed = spiffeId.parse(spiffeId.trustDomainId(PROCESS_TRUST_DOMAIN));
    if (!parsed.ok) {
      // Thrown rather than warned, and it is the one thing in this module that
      // is: every identifier this service will mint is built on the trust
      // domain name, so a bad one is not a degraded feature but a CA that can
      // only issue certificates naming something invalid. `server.js` catches
      // it and reports it on /spiffe rather than letting it stop the rest of
      // the service.
      throw new Error('spiffe.trustDomain is not a valid trust domain name: ' +
                      parsed.reason);
    }
    started = Date.now();
    log.info('spiffe: the default realm\'s trust domain is ' +
             spiffeId.trustDomainId(PROCESS_TRUST_DOMAIN) + ', and it is the ' +
             'root every other realm\'s is built from — a realm created here ' +
             'is given <realm>.' + PROCESS_TRUST_DOMAIN + ' unless it names ' +
             'its own. Its X.509 authority in ' +
             'each realm is that realm\'s SPIFFE Issuing CA under this ' +
             'service\'s own Root — see /admin/pki — and the bundle at GET ' +
             config.value('spiffe.bundlePath') +
             ' publishes the Root. A realm with no hierarchy falls back to a ' +
             'self-signed authority, which is what this service did before ' +
             '2026-09-11 and is reported as such.');
    log.debug('Leaving SpiffeCa.initialise().');
  }

  // The one promise, started at require time. A failure is CAPTURED rather than
  // left as an unhandled rejection — an unhandled one takes the process down on
  // current node, and a SPIFFE CA that could not build its key must not stop
  // the fourteen other protocol families in this service from running. Every
  // entry point re-throws it, so a caller gets the real reason rather than an
  // empty bundle.
  buildReadyPromise() {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SpiffeCa.buildReadyPromise().");
    const readyPromise = this.initialise().catch(function (err) {
      startError = err.message;
      log.error(errorCodes.tag('STS-SPIFFE-0043') +
                'spiffe: the issuing authority could not be built, so ' +
                'nothing here will issue an SVID: ' + err.message);
    });
    log.debug("Leaving SpiffeCa.buildReadyPromise().");
    return readyPromise;
  }

  async establishOnce(realmId, kind, present, make) {
    const { log, loadKeystore, loadClusterClaims, errorCodes } = this.deps;
    log.debug("Entering SpiffeCa.establishOnce(). realm=" + realmId + " kind=" +
              kind);
    const keystore = loadKeystore();
    // FROM REQUIRE'S CACHE AND NOT REQUIRED: a running service loaded the store
    // module long before a SPIFFE call, and an in-process test of this module
    // that opened no store must not have one loaded underneath it.
    const loaded = require.cache[require.resolve('../persistence/persistence')];
    const persistence = loaded && loaded.exports;
    if (typeof keystore.arbitrates !== 'function' || !keystore.arbitrates() ||
        !persistence || typeof persistence.clusterStore !== 'function' ||
        !persistence.clusterStore()) {
      if (!present()) {
        await make();
      }
      log.debug("Leaving SpiffeCa.establishOnce(). Nothing to coordinate.");
      return;
    }
    const claims = loadClusterClaims();
    const began = Date.now();
    for (;;) {
      await persistence.syncNow();
      if (present()) {
        log.debug("Leaving SpiffeCa.establishOnce(). Present.");
        return;
      }
      const claim = await claims.claim({ scope: 'spiffe.authority',
                                         value: kind + ':' + String(realmId),
                                         ttlMs: ESTABLISH_CLAIM_MS,
                                         realm: '' });
      if (claim.ok) {
        try {
          await persistence.syncNow();
          if (!present()) {
            await make();
            // COMMITTED BEFORE THE CLAIM GOES, or the next node to take it
            // reads a store without it and makes a second one.
            await persistence.flushMinted();
          }
        } finally {
          await claims.release(claim.handle);
        }
        log.debug("Leaving SpiffeCa.establishOnce(). Established here.");
        return;
      }
      if (claim.reason === 'store' || Date.now() - began > ESTABLISH_WAIT_MS) {
        log.error(errorCodes.tag('STS-SPIFFE-0076') + 'spiffe: the "' +
                  (realmId || 'default') + '" realm\'s ' + kind +
                  ' authority could not be established once for the cluster (' +
                  (claim.reason === 'store'
                    ? 'the store could not be asked: ' + claim.why
                    : 'another node held it for ' +
                      (ESTABLISH_WAIT_MS / 1000) + 's') + ').');
        log.debug("Leaving SpiffeCa.establishOnce(). Refused.");
        throw new Error('the "' + (realmId || 'default') + '" realm\'s ' +
                        kind + ' SPIFFE authority could not be established ' +
                        'once for this service\'s nodes, so none was made — ' +
                        'two would be two trust anchors for one trust domain.');
      }
      await new Promise(function (resolve) {
        setTimeout(resolve, ESTABLISH_POLL_MS);
      });
    }
  }

  async buildTrustMaterial(realmId) {
    const { log, spiffeId, pki } = this.deps;
    const self = this;
    log.debug('Entering SpiffeCa.buildTrustMaterial(). realm=' +
              (realmId || 'default'));
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
    const id = this.realmIdOf(realmId);
    // ------------------------------------------------------------------------
    // **THE NAME IS SETTLED FIRST, AND WRITING IT DOWN IS WHAT SETTLES IT.**
    //
    // Everything below names this trust domain in a certificate, so the realm's
    // domain is read once here, validated, and recorded in the realm's own
    // authority record. From this moment `trustDomainOf()` answers the RECORDED
    // one and a later change to the setting is reported as drift rather than
    // acted on — see the block above `PROCESS_TRUST_DOMAIN`.
    //
    // A bad name takes THIS REALM'S SPIFFE away and not the service's, which is
    // the difference between this and `initialise()`: there the process's own
    // domain is invalid and nothing anywhere can issue; here one realm is
    // misconfigured and the other realms are unaffected.
    //
    // The settings the two authorities are GENERATED with are read here too and
    // for the same reason — a realm carrying its own `spiffe.x509KeyType` is
    // reading it at the one moment it means anything.
    // ------------------------------------------------------------------------
    const settings = this.realmSettings(id);
    const domain = this.trustDomainOf(id);
    const named = spiffeId.parse(spiffeId.trustDomainId(domain));
    if (!named.ok) {
      log.debug('Leaving SpiffeCa.buildTrustMaterial(). The realm\'s name is ' +
                'invalid.');
      throw new Error('the "' + (id || 'default') + '" realm\'s ' +
                      'spiffe.trustDomain is not a valid trust domain name: ' +
                      named.reason + '. Nothing in this realm can issue an ' +
                      'SVID until it is corrected; every other realm is ' +
                      'unaffected.');
    }
    if (!this.builtTrustDomain(id)) {
      this.authoritiesIn(id).set('trustDomain', domain);
      log.info('spiffe: the "' + (id || 'default') +
               '" realm\'s trust domain ' +
               'is ' + spiffeId.trustDomainId(domain) + '. It is fixed now, ' +
               'because what follows names it in certificates.');
    }
    await this.establishOnce(id, 'jwt', function () {
      log.debug("Entering the JWT authority's presence check.");
      log.debug("Leaving the JWT authority's presence check.");
      return self.jwtList(id).length > 0;
    }, async function () {
      log.debug("Entering the JWT authority's build.");
      const jwtAuthority = await self.makeJwtAuthority(settings.jwtKeyType);
      if (!self.jwtList(id).length) {
        self.setJwtList(id, [jwtAuthority]);
        log.info('spiffe: the "' + (id || 'default') + '" realm\'s JWT ' +
                 'authority is ' + jwtAuthority.keyType + ' (kid ' +
                 jwtAuthority.id + ').');
      } else {
        log.info('spiffe: another process had already established the "' +
                 (id || 'default') + '" realm\'s JWT authority (kid ' +
                 self.jwtList(id)[0].id +
                 '); adopting it rather than the key just ' +
                 'generated. One service is one trust domain.');
      }
      log.debug("Leaving the JWT authority's build.");
    });
    // THE X.509 HALF. Nothing to do when the realm has a SPIFFE Issuing CA —
    // that IS the authority. The fallback is built only when it has none.
    if (pki.describeIssuer(id, SPIFFE_USE_CASE)) {
      log.debug('Leaving SpiffeCa.buildTrustMaterial(). The PKI holds the ' +
                'authority.');
      return;
    }
    if (this.x509List(id).length) {
      log.debug('Leaving SpiffeCa.buildTrustMaterial(). A self-signed ' +
                'authority is held.');
      return;
    }
    let x509Authority = null;
    await this.establishOnce(id, 'x509', function () {
      log.debug("Entering the X.509 authority's presence check.");
      log.debug("Leaving the X.509 authority's presence check.");
      return self.x509List(id).length > 0 ||
        !!pki.describeIssuer(id, SPIFFE_USE_CASE);
    }, async function () {
      log.debug("Entering the X.509 authority's build.");
      x509Authority = await self.makeX509Authority(
        settings.x509KeyType, settings.caTtl, 1, domain, settings.caSubject);
      if (!self.x509List(id).length) {
        self.setX509List(id, [x509Authority]);
      }
      log.debug("Leaving the X.509 authority's build.");
    });
    if (!x509Authority) {
      log.debug('Leaving SpiffeCa.buildTrustMaterial(). Another node ' +
                'established it.');
      return;
    }
    if (this.x509List(id)[0] && this.x509List(id)[0].id === x509Authority.id) {
      log.warn('spiffe: the "' + (id || 'default') + '" realm has no SPIFFE ' +
               'Issuing CA, so its X.509 authority is SELF-SIGNED (' +
               x509Authority.id + ', ' + x509Authority.keyType + ', valid ' +
               'until ' + x509Authority.notAfter +
               ') and IS the trust anchor ' +
               '— a consumer has to fetch the bundle again after every ' +
               'restart. Build the realm\'s certificate authority on ' +
               '/admin/pki to put it under this service\'s Root instead.');
    } else {
      log.info('spiffe: another process had already established the "' +
               (id || 'default') + '" realm\'s self-signed X.509 authority (' +
               this.x509List(id)[0].id + '); adopting it.');
    }
    log.debug('Leaving SpiffeCa.buildTrustMaterial().');
  }

  ensureTrustMaterial(realmId) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.ensureTrustMaterial().");
    const id = this.realmIdOf(realmId);
    if (!building.has(id)) {
      // The promise is kept whatever happens to it, and a FAILED one is dropped
      // so that the next caller retries: the ordinary cause of a failure here
      // is a key generation that threw, and caching that for the life of the
      // process would turn one bad moment into a realm that can never issue.
      const run = this.buildTrustMaterial(id).catch(function (err) {
        building.delete(id);
        throw err;
      });
      building.set(id, run);
    }
    log.debug("Leaving SpiffeCa.ensureTrustMaterial().");
    return building.get(id);
  }

  // **EVERY ENTRY POINT IN THIS MODULE AWAITS THIS**, which is the one rule the
  // header states: a caller cannot forget to, and a caller that reaches this
  // module before the realm has trust material gets the right answer rather
  // than an empty bundle. `state()` is the single exception and says so.
  async ready(realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.ready().");
    await readyPromise;
    if (startError) throw new Error(startError);
    await this.ensureTrustMaterial(realmId);
    log.debug("Leaving SpiffeCa.ready().");
    return true;
  }

  // ---------------------------------------------------------------------------
  // MINTING AN X509-SVID.
  //
  // The X509-SVID specification's rules, each of which is a line below:
  //
  //   * the SPIFFE ID goes in a URI subjectAltName, and there is EXACTLY ONE of
  //     them. A certificate with two SPIFFE IDs in it names two things, and
  //     what a verifier does with that is undefined — so it is one, always.
  //   * `basicConstraints` says CA:FALSE. A leaf that could sign is a leaf that
  //     can mint its own identity.
  //   * `keyUsage` has `digitalSignature`; `keyCertSign` and `cRLSign` MUST NOT
  //     be there.
  //   * `extKeyUsage` carries `serverAuth` and `clientAuth`, because an SVID is
  //     used for BOTH ends of an mTLS connection — that is the whole point of
  //     it.
  //   * the subject may be anything. SPIRE writes `C=US, O=SPIRE` and so does
  //     this, through `spiffe.svidSubject`, because a certificate with an empty
  //     subject is refused by the vendored issuer and — more to the point — is
  //     rendered as a blank line by every tool a person might inspect it with.
  //
  // The KEY IS GENERATED HERE and handed back with the certificate, because
  // that is what the Workload API does: `X509SVID.x509_svid_key` is the
  // workload's private key, DER PKCS#8, unencrypted. That looks alarming
  // written down and is exactly correct — the Workload API's whole job is to
  // deliver an identity to a workload over a channel already trusted (a Unix
  // socket, in the ordinary case). `signCsr()` below is the other shape, where
  // the caller kept its key.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // **AN AUTHORITY MAY ONLY MINT IN ITS OWN TRUST DOMAIN, AND UNTIL 2026-09-12
  // NOTHING HERE SAID SO.**
  //
  // Measured the day before: `ca.mintX509Svid('spiffe://acme.example/w')` on a
  // service whose trust domain was `example.org` produced a certificate with
  // that URI in its subjectAltName, signed by this authority. The refusal
  // existed — in `spiffe_registry.checkRecord()` — so every path that goes
  // through a registration entry was covered and every path that does not was
  // not: `NewDownstreamX509CA`, `MintX509SVID`, and this module's own callers.
  //
  // It cost nothing while there was ONE trust domain, because the only way to
  // reach it was to ask for something obviously wrong. With a trust domain per
  // realm it is the boundary itself: realm A minting in realm B's domain is a
  // certificate B's bundle will not verify and A's authority had no business
  // signing, and the two realms disagreeing about who issued it is exactly what
  // a trust domain is for.
  // ---------------------------------------------------------------------------
  refuseForeignDomain(what, id, realmId) {
    const { log, spiffeId } = this.deps;
    log.debug("Entering SpiffeCa.refuseForeignDomain().");
    const parsed = spiffeId.parse(id);
    const mine = this.trustDomainOf(realmId);
    if (!parsed.ok || parsed.trustDomain === mine) {
      log.debug("Leaving SpiffeCa.refuseForeignDomain().");
      return;
    }
    log.debug("Leaving SpiffeCa.refuseForeignDomain().");
    throw new Error('Cannot mint ' + what + ' for ' + id + ': this authority ' +
                    'issues in the trust domain ' +
                    spiffeId.trustDomainId(mine) +
                    ' — the "' + (this.realmIdOf(realmId) || 'default') + '" ' +
                    'realm\'s — ' +
                    'and ' + spiffeId.trustDomainId(parsed.trustDomain) +
                    ' is not it. An SVID naming a domain this authority does ' +
                    'not own is one no bundle anywhere verifies.');
  }

  async mintX509Svid(id, options) {
    const { log, spiffeId, keys } = this.deps;
    log.debug('Entering SpiffeCa.mintX509Svid(). id=' + id);
    const opts = options || {};
    // THE REALM'S material and not the ambient realm's: every caller here may
    // name a realm, and awaiting the wrong one leaves `issueLeaf()` looking for
    // an authority that was never built.
    await this.ready(this.realmIdOf(opts.realm));
    const parsed = spiffeId.parse(id);
    if (!parsed.ok) {
      log.debug('Leaving SpiffeCa.mintX509Svid(). Invalid SPIFFE ID.');
      throw new Error('Cannot mint an X509-SVID for ' + id + ': ' +
                      parsed.reason);
    }
    this.refuseForeignDomain('an X509-SVID', parsed.id, opts.realm);
    // ---------------------------------------------------------------------
    // **THE TARGET REALM'S KEY TYPE, NOT THE AMBIENT REALM'S (2026-09-12).**
    // This read `config.value('spiffe.x509KeyType')` while minting for
    // `opts.realm`, so an SVID minted for `acme` from a request that arrived in
    // the default realm took the default realm's key type. And the `'ec-p256'`
    // literal behind it was a second default beside config.js's `dflt` — the
    // one that would quietly win if the row ever stopped answering.
    // ---------------------------------------------------------------------
    const type = this.keyTypeById(opts.keyType ||
                                  this.realmSettings(opts.realm).x509KeyType);
    if (!type) {
      log.debug('Leaving SpiffeCa.mintX509Svid(). Unknown key type.');
      throw new Error('Cannot mint an X509-SVID for ' + id + ': the key type ' +
                      (opts.keyType ||
                       this.realmSettings(opts.realm).x509KeyType) +
                      ' is not one of ' +
                      KEY_TYPES.map(function (t) { return t.id; }).join(', ') +
                      ' (spiffe.x509KeyType).');
    }
    const pair = await keys.generateKeyPair(type.id);
    const issued = await this.issueLeaf(parsed.id, pair.publicPem, opts);
    const privateKeyDer = this.pemToDer(pair.privatePem);
    log.debug('Leaving SpiffeCa.mintX509Svid(). serial=' + issued.serialHex);
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
      chainDer: Buffer.concat(this.chainDerOf(issued)),
      chainCertificatesDer: this.chainDerOf(issued),
      chainPem: this.chainPemOf(issued),
      privateKeyPem: pair.privatePem,
      privateKeyDer: privateKeyDer,
      keyType: type.id,
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
  // `BatchNewX509SVID` on the SPIRE Server API takes, and it is how a real
  // agent gets its SVIDs — the agent's private key never leaves the agent.
  //
  // **ONLY THE PUBLIC KEY IS READ OUT OF THE CSR.** Not the subject, not the
  // requested SANs, not any extension: everything else about the certificate is
  // decided HERE from the registration entry. A CA that copied the
  // subjectAltName out of a CSR would let any caller choose its own SPIFFE ID,
  // which is the one thing an issuing authority exists to prevent. The CSR's
  // signature is deliberately NOT checked either, and that is this service's
  // permissive posture rather than an oversight — see the note on `/spiffe` —
  // but reading only the key means a forged CSR still cannot name itself
  // something it is not.
  async signCsr(csrDer, id, options) {
    const { log, spiffeId, pkijs } = this.deps;
    log.debug('Entering SpiffeCa.signCsr(). id=' + id);
    const opts = options || {};
    await this.ready(this.realmIdOf(opts.realm));
    const parsed = spiffeId.parse(id);
    if (!parsed.ok) {
      log.debug('Leaving SpiffeCa.signCsr(). Invalid SPIFFE ID.');
      throw new Error('Cannot sign a CSR for ' + id + ': ' + parsed.reason);
    }
    this.refuseForeignDomain('an X509-SVID', parsed.id, opts.realm);
    let publicPem;
    try {
      const csr =
        pkijs.CertificationRequest.fromBER(this.toArrayBuffer(csrDer));
      const spki = csr.subjectPublicKeyInfo.toSchema().toBER(false);
      publicPem = this.derToPem(Buffer.from(spki), 'PUBLIC KEY');
    } catch (e) {
      // Not a CSR, or not one this parser can read. The caller is a protocol
      // handler that has to answer InvalidArgument, so the reason is carried
      // out rather than logged and swallowed.
      log.debug('Leaving SpiffeCa.signCsr(). The CSR could not be read.');
      throw new Error('The certificate signing request could not be read: ' +
                      e.message);
    }
    const issued = await this.issueLeaf(parsed.id, publicPem, opts);
    log.debug('Leaving SpiffeCa.signCsr(). serial=' + issued.serialHex);
    return {
      spiffeId: parsed.id,
      certificatePem: issued.pem,
      certificateDer: issued.der,
      chainDer: Buffer.concat(this.chainDerOf(issued)),
      chainCertificatesDer: this.chainDerOf(issued),
      chainPem: this.chainPemOf(issued),
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
  // X509-SVID specification and two copies of it is one copy that will
  // eventually be missing `clientAuth`.
  async issueLeaf(id, publicPem, options) {
    const { log } = this.deps;
    log.debug('Entering SpiffeCa.issueLeaf(). id=' + id);
    const opts = options || {};
    const realmId = this.realmIdOf(opts.realm);
    const authority = this.activeX509Authority(realmId);
    if (!authority) {
      log.debug('Leaving SpiffeCa.issueLeaf(). No authority.');
      throw new Error('This trust domain has no X.509 authority in the "' +
                      (realmId || 'default') + '" realm.');
    }
    const ttl = Number(opts.ttl) > 0 ? Number(opts.ttl) : this.svidTtlSeconds();
    const notBefore = new Date();
    let notAfter = new Date(notBefore.getTime() + ttl * 1000);
    // An SVID may not outlive the authority that signed it. A certificate whose
    // notAfter is past its issuer's is not refused by every verifier — many
    // check only the leaf — so it produces an identity that works until it
    // suddenly does not, with nothing in the failure naming the CA.
    //
    // **`issueUnder()` CLAMPS THIS TOO AND THE DUPLICATION IS DELIBERATE.**
    // That one is the funnel every leaf in the service goes through and it
    // cannot be removed; this one is what lets the record below report the
    // lifetime the SVID actually got rather than the one that was asked for, on
    // BOTH paths.
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
    const issued = await this.issueFromAuthority(realmId, authority, {
      subject: opts.subject || this.svidSubject(),
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
        keyUsage: { present: true, critical: true,
                    usages: ['digitalSignature'] },
        extKeyUsage: { present: true, usages: ['serverAuth', 'clientAuth'] },
        subjectAltName: { present: true, critical: false, names: names },
        subjectKeyIdentifier: { present: true },
        authorityKeyIdentifier: { present: true }
      }
    });
    log.debug('Leaving SpiffeCa.issueLeaf(). serial=' + issued.serialHex);
    return { pem: issued.pem, der: issued.der,
             serialHex: issued.serialHex,
             notBefore: issued.notBefore,
             notAfter: issued.notAfter,
             // WHAT TRAVELS WITH THE LEAF, and it is empty on the self-signed
             // path and two certificates long on the PKI one. A caller
             // concatenates rather than branching — see `chainOf()`.
             issuerChainPem: issued.chainPem,
             issuerChainDer: issued.chainDer,
             certificate: this.certificateFacts(issued.der) };
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
  // **THIS IS WHERE THE COMMENT THAT SAID "THERE ARE NONE HERE" USED TO BE.**
  // It read: *the chain the Workload API returns: the leaf FIRST, then any
  // intermediates. There are none here — the CA signs leaves directly — but the
  // field is a chain rather than a certificate, and a caller that assumed one
  // certificate would break the day a downstream CA is in front of it.* The
  // field being a chain rather than a certificate is what made 2026-09-11 an
  // edit to one function instead of four protocol handlers.
  // ---------------------------------------------------------------------------
  chainPemOf(issued) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.chainPemOf().");
    log.debug("Leaving SpiffeCa.chainPemOf().");
    return [issued.pem].concat(issued.issuerChainPem || []);
  }

  chainDerOf(issued) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.chainDerOf().");
    log.debug("Leaving SpiffeCa.chainDerOf().");
    return [issued.der].concat(issued.issuerChainDer || []);
  }

  // ---------------------------------------------------------------------------
  // THE SIX FACTS ABOUT AN ISSUED CERTIFICATE, IN THE SPELLING THE TLS
  // CLIENT-CERTIFICATE SIGHTING ALREADY PRODUCES (`tls/tls_server.js`).
  //
  // The directory grows an entry for the holder of every X509-SVID this
  // authority mints (see `spiffePlan()` and `applySpiffeCertificate()` in
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
  // colon-separated uppercase hex. The two DNs come back as one `type=value`
  // per LINE rather than as an object, which is the second shape `dnRfc4514()`
  // learnt in order to serve this caller — one function, so the two paths
  // cannot drift.
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
  certificateFacts(der) {
    const { log, crypto, dnRfc4514, errorCodes } = this.deps;
    log.debug('Entering SpiffeCa.certificateFacts().');
    try {
      const parsed = new crypto.X509Certificate(der);
      log.debug('Leaving SpiffeCa.certificateFacts(). serial=' +
                parsed.serialNumber);
      return {
        subject: dnRfc4514(parsed.subject),
        issuer: dnRfc4514(parsed.issuer),
        serialNumber: parsed.serialNumber || '',
        validFrom: parsed.validFrom || '',
        validTo: parsed.validTo || '',
        fingerprint256: parsed.fingerprint256 || ''
      };
    } catch (e) {
      // A certificate this service built a moment ago that node cannot read is
      // a defect here rather than bad input, so it is logged at error — but it
      // is still swallowed, for the reason in the header: the SVID is minted
      // and the caller is owed it.
      log.error(errorCodes.tag('STS-SPIFFE-0044') +
                'spiffe: the certificate just issued could not be read back ' +
                'for the directory, and the SVID is unaffected: ' + e.message);
      log.debug('Leaving SpiffeCa.certificateFacts(). Unreadable.');
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // AN INTERMEDIATE CA, FOR `NewDownstreamX509CA` — AND THE ONE PLACE THE WHOLE
  // HIERARCHY HAD TO GIVE GROUND (2026-09-11).
  //
  // It is signed by this realm's authority and is itself allowed to sign leaves
  // — `pathLen: 0` — and it is NOT added to this service's own authority list:
  // a downstream CA belongs to whoever asked for it, and adding it here would
  // mean this service started signing with somebody else's key.
  //
  // **THIS IS THE ONLY CA UNDER A SPIFFE AUTHORITY, AND IT IS WHY THAT
  // AUTHORITY IS `pathLen: 1` WHILE EVERY OTHER ISSUING CA IN THIS SERVICE IS
  // 0.** With the authority self-signed that cost nothing — it was its own
  // anchor and could say what it liked about depth. Under the Root it costs a
  // widening of two certificates: the SPIFFE Issuing CA to 1 and the realm
  // Intermediate above it to 2. `common/pki.js`'s `intermediatePathLen()`
  // derives the second from the first so that nobody can widen one and forget
  // the other, which is the failure that encodes perfectly and validates
  // nowhere.
  //
  // **IT USED TO GO INTO THE BUNDLE "for the same reason the root does" AND
  // THAT SENTENCE IS NOW WRONG.** The bundle publishes the trust ANCHOR, and a
  // downstream CA is not one — it is an intermediate, and it travels in the
  // chain, which is what `chainDer` below is for. Under the old arrangement the
  // authority was the anchor, so anything it signed that was itself a CA looked
  // like bundle material; under the Root nothing changes about who is trusted
  // when a downstream CA is minted, which is the correct answer and was not
  // available before.
  // ---------------------------------------------------------------------------
  async downstreamCa(options) {
    const { log, keys, spiffeId } = this.deps;
    log.debug('Entering SpiffeCa.downstreamCa().');
    const opts = options || {};
    const realmId = this.realmIdOf(opts.realm);
    await this.ready(realmId);
    const authority = this.activeX509Authority(realmId);
    if (!authority) {
      log.debug('Leaving SpiffeCa.downstreamCa(). No authority.');
      throw new Error('This trust domain has no X.509 authority in the "' +
                      (realmId || 'default') + '" realm.');
    }
    const fallbackType = this.keyTypeById(authority.keyType) || KEY_TYPES[0];
    const pair = await keys.generateKeyPair(opts.keyType || fallbackType.id);
    const settings = this.realmSettings(realmId);
    const ttl = Number(opts.ttl) > 0 ? Number(opts.ttl) : settings.caTtl;
    const notBefore = new Date();
    let notAfter = new Date(notBefore.getTime() + ttl * 1000);
    const caNotAfter = new Date(authority.notAfter);
    if (notAfter > caNotAfter) notAfter = caNotAfter;
    const issued = await this.issueFromAuthority(realmId, authority, {
      subject: this.caSubjectFor(settings.caSubject, 'downstream CA',
                                 this.trustDomainOf(realmId)),
      publicKeyPem: pair.publicPem,
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      extensions: {
        basicConstraints: { present: true, critical: true, ca: true,
                            pathLen: 0 },
        keyUsage: { present: true, critical: true,
                    usages: ['keyCertSign', 'cRLSign'] },
        subjectAltName: { present: true, critical: false,
                          names: [{ kind: 'uri',
                                    value: spiffeId.trustDomainId(
                                      this.trustDomainOf(realmId)) }] },
        subjectKeyIdentifier: { present: true },
        authorityKeyIdentifier: { present: true }
      }
    });
    log.debug('Leaving SpiffeCa.downstreamCa(). serial=' + issued.serialHex);
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
  //   `aud`  REQUIRED, and at least one. A JWT-SVID with no audience is a
  //          bearer token good against everything that accepts one, which is
  //          why the Workload API's FetchJWTSVID takes the audience as a
  //          parameter and why this refuses an empty list rather than
  //          defaulting one.
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
  async mintJwtSvid(id, audiences, options) {
    const { log, spiffeId, nowSec, b64u, crypto, stsCrypto } = this.deps;
    log.debug('Entering SpiffeCa.mintJwtSvid(). id=' + id);
    const opts = options || {};
    await this.ready(this.realmIdOf(opts.realm));
    const parsed = spiffeId.parse(id);
    if (!parsed.ok) {
      log.debug('Leaving SpiffeCa.mintJwtSvid(). Invalid SPIFFE ID.');
      throw new Error('Cannot mint a JWT-SVID for ' + id + ': ' +
                      parsed.reason);
    }
    this.refuseForeignDomain('a JWT-SVID', parsed.id, opts.realm);
    const list = (audiences || []).map(function (a) {
      return String(a == null ? '' : a).trim();
    }).filter(Boolean);
    if (!list.length) {
      log.debug('Leaving SpiffeCa.mintJwtSvid(). No audience.');
      throw new Error('A JWT-SVID must name at least one audience.');
    }
    // THE REALM'S ACTIVE JWT AUTHORITY. It read `jwtList()` — the ambient
    // realm's — while every other line in this function already knew which
    // realm it was in, which is the shape of mistake a per-realm store makes
    // once and then never again: the caller named a realm, the material was
    // built for it, and the signature came from somewhere else.
    const authority = this.jwtList(this.realmIdOf(opts.realm))[0];
    if (!authority) {
      log.debug('Leaving SpiffeCa.mintJwtSvid(). No JWT authority.');
      throw new Error('The "' + (this.realmIdOf(opts.realm) || 'default') +
                      '" realm has no JWT authority.');
    }
    const ttl = Number(opts.ttl) > 0 ? Number(opts.ttl) :
                this.jwtSvidTtlSeconds();
    const issuedAt = nowSec();
    const expires = issuedAt + ttl;
    const payload = {
      sub: parsed.id,
      // One audience is written as a string and several as an array, which is
      // what RFC 7519 says and what every JWT library expects. Writing a
      // single-element array is legal and is read correctly by fewer things
      // than it should be.
      aud: list.length === 1 ? list[0] : list,
      exp: expires,
      iat: issuedAt,
      jti: b64u(crypto.randomBytes(12))
    };
    // certificate-header: none — the JWT authority has no certificate and no
    // hierarchy to hang from (common/jose_certificate_header.js).
    const token = stsCrypto.signJws(payload, authority.privateKeyPem, {
      algorithm: authority.alg,
      keyid: authority.id,
      // `JWT` rather than the default, and stated rather than left implicit:
      // the JWT-SVID specification says the `typ` header, if present, must be
      // `JWT` or `JOSE`.
      header: { typ: 'JWT' }
    });
    log.debug('Leaving SpiffeCa.mintJwtSvid(). aud=' + list.join(', '));
    return { spiffeId: parsed.id, token: token, audiences: list,
             expiresAt: expires, issuedAt: issuedAt, jti: payload.jti,
             kid: authority.id, alg: authority.alg, hint: opts.hint || '' };
  }

  // ---------------------------------------------------------------------------
  // VALIDATING A JWT-SVID — the one thing in this whole module that REFUSES.
  //
  // `ValidateJWTSVID` on the Workload API is a verification service, so it has
  // to actually verify: the point of the call is to be told no. It is the
  // exception to this service's permissive posture for the same reason
  // `/oauth2/userinfo` is the exception among the token-reading endpoints — a
  // mock that said yes to everything here would be useless to the client author
  // testing their error paths, which is the only reason anybody calls it.
  //
  // What is checked, in the order a real implementation checks it:
  //
  //   * the signature, against the JWT authorities of the trust domain named in
  //     the `sub` — this one's, or a FEDERATED one's if the sub belongs to a
  //     trust domain whose bundle has been given to us. A trust domain with no
  //     bundle here cannot be validated and is refused saying so, rather than
  //     refused as a bad signature.
  //   * `exp`, with no leeway at all. A JWT-SVID has a short lifetime by
  //     design.
  //   * `aud` contains the audience the caller says it is.
  //   * `sub` is a valid SPIFFE ID belonging to the trust domain whose key
  //     verified it. A token signed by trust domain A carrying a `sub` in trust
  //     domain B is the confused-deputy shape this check exists for.
  // ---------------------------------------------------------------------------
  async validateJwtSvid(token, audience, options?) {
    const { log, jwt, spiffeId, stsCrypto } = this.deps;
    const self = this;
    log.debug('Entering SpiffeCa.validateJwtSvid().');
    // THE REALM WHOSE BUNDLE IS BEING ASKED. It has an option now for the same
    // reason the minting pair does: `jwkSetFor()` reads the ambient realm, and
    // an in-process caller (a test, `/admin-api`) is not inside one.
    const opts = options || {};
    await this.ready(this.realmIdOf(opts.realm));
    const text = String(token == null ? '' : token).trim();
    if (!text) {
      log.debug('Leaving SpiffeCa.validateJwtSvid(). No token.');
      return { ok: false, reason: 'No JWT-SVID was given.',
               errorCode: 'STS-SPIFFE-0031' };
    }
    const wanted = String(audience == null ? '' : audience).trim();
    if (!wanted) {
      log.debug('Leaving SpiffeCa.validateJwtSvid(). No audience.');
      return { ok: false, reason: 'ValidateJWTSVID requires the audience the ' +
                                  'validating party goes by; a JWT-SVID is ' +
                                  'only meaningful against one.',
               errorCode: 'STS-SPIFFE-0032' };
    }
    let unverified;
    try {
      unverified = jwt.decode(text, { complete: true });
    } catch (e) {
      log.debug("Caught in SpiffeCa.validateJwtSvid(): " +
                ((e && e.message) || e));
      // Not a JWS at all. The text is not logged: it is somebody's credential.
      log.debug('Leaving SpiffeCa.validateJwtSvid(). Not a JWT.');
      return { ok: false, errorCode: 'STS-SPIFFE-0033',
               reason: 'That is not a ' +
          'JWT.' };
    }
    if (!unverified || !unverified.payload) {
      log.debug('Leaving SpiffeCa.validateJwtSvid(). Nothing decoded.');
      return { ok: false, errorCode: 'STS-SPIFFE-0033',
               reason: 'That is not a ' +
          'JWT.' };
    }
    const subject = String((unverified.payload || {}).sub || '');
    const parsedSub = spiffeId.parse(subject);
    if (!parsedSub.ok) {
      log.debug('Leaving SpiffeCa.validateJwtSvid(). The sub is not a SPIFFE ' +
                'ID.');
      return { ok: false, reason: 'The sub claim of a JWT-SVID is a SPIFFE ' +
                                  'ID; this one is not: ' + parsedSub.reason,
               errorCode: 'STS-SPIFFE-0034' };
    }
    // Which keys may verify it. The FIRST decision, before any cryptography,
    // because "I have no bundle for that trust domain" and "the signature is
    // wrong" are different answers and a caller acts differently on each.
    const candidates = this.inRealmOf(opts.realm, function () {
      return self.jwkSetFor(parsedSub.trustDomain);
    });
    if (!candidates) {
      log.debug('Leaving SpiffeCa.validateJwtSvid(). Unknown trust domain.');
      return { ok: false, reason: 'This service holds no JWT bundle for the ' +
                                  'trust domain ' + parsedSub.trustDomain +
                                  ', so nothing here can verify that SVID. ' +
                                  'Its own trust domain is ' +
                                  this.trustDomainOf(opts.realm) + '; a ' +
                                  'foreign one has to be federated first.',
               errorCode: 'STS-SPIFFE-0035' };
    }
    const kid = ((unverified.header || {}).kid) || '';
    const usable = candidates.filter(function (entry) {
      return !kid || entry.kid === kid;
    });
    if (!usable.length) {
      log.debug('Leaving SpiffeCa.validateJwtSvid(). No key with that kid.');
      return { ok: false, reason: 'No key in the ' + parsedSub.trustDomain +
                                  ' bundle has the kid ' + kid + '.',
               errorCode: 'STS-SPIFFE-0036' };
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
      log.debug('Leaving SpiffeCa.validateJwtSvid(). It did not verify: ' +
                lastError);
      return { ok: false, reason: lastError || 'The SVID did not verify.',
               errorCode: 'STS-SPIFFE-0037' };
    }
    if (String(verified.sub || '') !== parsedSub.id) {
      // Cannot happen with the check above, and checked anyway: this is the
      // claim the whole answer rests on, and reading it twice from two
      // decodings costs nothing.
      log.debug('Leaving SpiffeCa.validateJwtSvid(). The verified sub ' +
                'differs.');
      return { ok: false, reason: 'The verified sub is not the one presented.',
               errorCode: 'STS-SPIFFE-0038' };
    }
    log.debug('Leaving SpiffeCa.validateJwtSvid(). It verified. sub=' +
              verified.sub);
    return { ok: true, spiffeId: verified.sub, claims: verified,
             trustDomain: parsedSub.trustDomain };
  }

  // The verification keys for a trust domain, as PEMs the JWS library can use.
  // null — not an empty array — when the trust domain is not one this service
  // knows, because those are different answers.
  jwkSetFor(trustDomain) {
    const { log, crypto } = this.deps;
    const self = this;
    log.debug('Entering SpiffeCa.jwkSetFor().');
    // THE AMBIENT REALM'S, because that is the authority a caller reached: a
    // JWT-SVID presented on acme's Workload API socket is verified against
    // acme's own JWT authority, and a `sub` naming the default realm's trust
    // domain is a FOREIGN one there unless it has been federated.
    if (trustDomain === this.trustDomainOf()) {
      log.debug('Leaving SpiffeCa.jwkSetFor().');
      return this.jwtList().map(function (authority) {
        return { kid: authority.id, pem: authority.publicKeyPem,
                 algorithms: [authority.alg] };
      });
    }
    // THIS REALM'S federated bundles only, and never one named after a trust
    // domain this process serves — see `servedTrustDomains()`.
    const foreign = this.shadowsServedDomain(trustDomain)
      ? null : this.federatedIn().get(trustDomain);
    if (!foreign) {
      log.debug('Leaving SpiffeCa.jwkSetFor().');
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
                   algorithms: self.algorithmsFor(key) });
      } catch (e) {
        // A JWK this service cannot read. Skipped rather than fatal: a foreign
        // bundle may hold key types nothing here understands, and the rest of
        // it is still usable.
        log.warn('spiffe: a JWT key in the ' + trustDomain + ' bundle could ' +
                 'not be read and was skipped: ' + e.message);
      }
    });
    log.debug('Leaving SpiffeCa.jwkSetFor().');
    return out;
  }

  algorithmsFor(jwk) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.algorithmsFor().");
    if (jwk.alg) {
      log.debug("Leaving SpiffeCa.algorithmsFor().");
      return [jwk.alg];
    }
    if (jwk.kty === 'RSA') {
      log.debug("Leaving SpiffeCa.algorithmsFor().");
      return ['RS256', 'RS384', 'RS512', 'PS256'];
    }
    if (jwk.kty === 'EC') {
      if (jwk.crv === 'P-384') {
        log.debug("Leaving SpiffeCa.algorithmsFor().");
        return ['ES384'];
      }
      if (jwk.crv === 'P-521') {
        log.debug("Leaving SpiffeCa.algorithmsFor().");
        return ['ES512'];
      }
      log.debug("Leaving SpiffeCa.algorithmsFor().");
      return ['ES256'];
    }
    log.debug("Leaving SpiffeCa.algorithmsFor().");
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
  // and each JWK carrying `use`, which is what says whether a key is for X.509
  // or for JWT. **A JWK with a missing or unknown `use` MUST be ignored
  // ENTIRELY by a consumer**, which is worth knowing because it is the failure
  // mode of getting this wrong: the bundle parses, the key is silently dropped,
  // and every SVID fails to verify with no error mentioning the bundle.
  //
  // The X.509 half carries `x5c` — the base64 DER of the certificate, NOT PEM
  // and NOT base64url. The key parameters (`n`/`e`, or `crv`/`x`/`y`) are
  // published beside it because a JWK needs `kty` at minimum and a consumer may
  // use either.
  // ---------------------------------------------------------------------------
  // **WHAT THE X.509 HALF PUBLISHES CHANGED ON 2026-09-11 AND IT IS THE ONE
  // OUTWARD-FACING CONSEQUENCE OF THE WHOLE MOVE.** It used to be the trust
  // domain's own authorities, because they were self-signed and each was its
  // own anchor. It is now the service ROOT — one entry, shared by every realm,
  // unchanged by a rotation of any realm's SPIFFE Issuing CA. That is exactly
  // what SPIRE publishes when an UpstreamAuthority plugin is configured, and it
  // is the difference between "the bundle is the list of CAs that signed
  // things" and "the bundle is the list of anchors you should trust". Only the
  // second was ever what a bundle meant; the first was true here by
  // coincidence.
  //
  // A realm with no hierarchy publishes its self-signed authorities exactly as
  // before — see `trustAnchorsIn()`.
  async bundle(realmId?) {
    const { log } = this.deps;
    const self = this;
    log.debug('Entering SpiffeCa.bundle().');
    const id = this.realmIdOf(realmId);
    await this.ready(id);
    const keyList = [];
    this.trustAnchorsIn(id).forEach(function (anchor) {
      const jwk = self.publicJwkOf(anchor.publicKeyPem);
      jwk.use = 'x509-svid';
      jwk.x5c = [anchor.certificateDer.toString('base64')];
      keyList.push(jwk);
    });
    this.jwtList(id).forEach(function (authority) {
      const jwk = Object.assign({}, authority.jwk);
      jwk.use = 'jwt-svid';
      jwk.kid = authority.id;
      keyList.push(jwk);
    });
    const document = {
      keys: keyList,
      spiffe_sequence: this.sequenceNow(id),
      spiffe_refresh_hint: this.refreshHintSeconds()
    };
    log.debug('Leaving SpiffeCa.bundle(). ' + keyList.length +
              ' key(s), sequence ' +
              this.sequenceNow(id) + '.');
    return document;
  }

  // The X.509 half of the bundle as CONCATENATED DER, which is the shape the
  // Workload API's `bundle` and `bundles` fields take — not PEM, not a list,
  // one byte string holding every CA certificate end to end. Getting this wrong
  // produces a field a workload parses as one certificate and then cannot
  // verify anything against after a rotation.
  async x509BundleDer(realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.x509BundleDer().");
    const id = this.realmIdOf(realmId);
    await this.ready(id);
    log.debug("Leaving SpiffeCa.x509BundleDer().");
    return Buffer.concat(this.trustAnchorsIn(id).map(function (a) {
      return a.certificateDer;
    }));
  }

  // The same, for a federated trust domain, built from the `x5c` members of the
  // bundle somebody gave us.
  federatedX509BundleDer(trustDomain, realmId?) {
    const { log } = this.deps;
    log.debug('Entering SpiffeCa.federatedX509BundleDer().');
    const foreign = this.shadowsServedDomain(trustDomain)
      ? null : this.federatedIn(realmId).get(trustDomain);
    if (!foreign) {
      log.debug('Leaving SpiffeCa.federatedX509BundleDer().');
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
    log.debug('Leaving SpiffeCa.federatedX509BundleDer().');
    return Buffer.concat(parts);
  }

  // ---------------------------------------------------------------------------
  // FEDERATION, AND THE ONE THING IT DELIBERATELY DOES NOT DO.
  //
  // **A foreign bundle is GIVEN to this service, never FETCHED by it.** The
  // SPIFFE federation specification has a bundle endpoint URL in the federation
  // relationship, and a real implementation polls it. This one records the URL
  // and does not follow it, which is the same refusal `wsfed.js` gives
  // `wreqptr` and `client_auth.js` gives `jwks_uri`, for the same reason:
  // fetching a URL that somebody registered, in order to obtain a
  // credential-verification key, is a server-side request forgery with a
  // specification citation attached. On the service this was written for, which
  // authenticated nobody and accepted any registration, it would have been a
  // blind HTTP client anybody could point anywhere — and a registration is
  // still a thing an admin caller may create.
  //
  // Holding that position in two files and not in a third would be no position
  // at all. The bundle is pasted in — through `/admin/spiffe`, through
  // `POST /admin-api/spiffe/federation-set`, or through the SPIRE Server API's
  // `BatchCreateFederatedBundle` — and `RefreshBundle` answers by saying so.
  // ---------------------------------------------------------------------------
  setFederatedBundle(trustDomain, document, options): Record<string, any> {
    const { log, spiffeId, realms } = this.deps;
    log.debug('Entering SpiffeCa.setFederatedBundle(). trustDomain=' +
              trustDomain);
    const opts = options || {};
    const name = String(trustDomain == null ? '' : trustDomain).trim()
      .toLowerCase();
    const parsed = spiffeId.parse(spiffeId.trustDomainId(name));
    if (!parsed.ok) {
      log.debug('Leaving SpiffeCa.setFederatedBundle(). Bad trust domain.');
      return { ok: false, errorCode: 'STS-SPIFFE-0039', reason: parsed.reason };
    }
    // ---------------------------------------------------------------------
    // **ANY TRUST DOMAIN THIS PROCESS SERVES, NOT ONLY THE CALLING REALM'S.**
    // This compared against `trustDomainOf()` — the ambient realm — until
    // 2026-09-12, which let one realm register a bundle under another realm's
    // name and have its own certificates believed as that realm's identities.
    // See the declaration of `federated` for the whole of it. Refused in every
    // mode: it is a realm boundary, and a realm is isolated in both.
    // ---------------------------------------------------------------------
    const served = this.servedTrustDomains();
    if (served.has(name)) {
      const owner = served.get(name);
      // The default realm is '' in that map and 'default' as an ambient id, so
      // both sides are compared under one spelling.
      const mine = (owner || realms.DEFAULT_ID) ===
                   (this.realmIdOf(opts.realm) || realms.DEFAULT_ID);
      log.debug('Leaving SpiffeCa.setFederatedBundle(). That trust domain is ' +
                'served here.');
      return { ok: false, errorCode: 'STS-SPIFFE-0040', reason: mine
        ? name +
          ' is this realm\'s own trust domain. A trust domain does not ' +
          'federate with itself, and accepting this would give it two ' +
          'bundles that could disagree.'
        : name + ' is the trust domain the "' + (owner || 'default') + '" ' +
          'realm of this service issues in. A federated bundle is a FOREIGN ' +
          'trust domain\'s anchors, and one registered under a name this ' +
          'process serves would let this realm\'s certificates be believed ' +
          'as that realm\'s identities. Realms here are isolated; name a ' +
          'trust domain no realm of this service uses.' };
    }
    const checked = this.checkBundleDocument(document);
    if (!checked.ok) {
      log.debug('Leaving SpiffeCa.setFederatedBundle(). Bad document.');
      checked.errorCode = 'STS-SPIFFE-0041';
      log.debug("Leaving SpiffeCa.setFederatedBundle().");
      return checked;
    }
    const held = this.federatedIn(opts.realm);
    if (!held.has(name) && held.size >= this.maxFederatedBundles()) {
      log.debug('Leaving SpiffeCa.setFederatedBundle(). Full.');
      return { ok: false, reason: 'This realm holds its maximum of ' +
                                  this.maxFederatedBundles() + ' federated ' +
                                  'bundle(s) (spiffe.maxFederatedBundles).',
               errorCode: 'STS-SPIFFE-0042' };
    }
    const existing = held.get(name);
    held.set(name, {
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
    // The federated bundles are part of what this service publishes to
    // workloads — X509SVIDResponse.federated_bundles and
    // JWTBundlesResponse.bundles both carry them — so changing one changes the
    // bundle a workload sees.
    this.bumpSequence(opts.realm,
                      'a federated bundle was ' +
                      (existing ? 'updated' : 'added'));
    log.debug('Leaving SpiffeCa.setFederatedBundle(). ' + held.size +
              ' federated ' +
        'bundle(s).');
    return { ok: true, trustDomain: name, created: !existing };
  }

  // A DELETE IS NEVER REFUSED FOR A SERVED NAME, which is the asymmetry every
  // remove in this service has: a row an older build wrote under a name this
  // process now serves is exactly the row somebody needs to be able to take
  // off.
  deleteFederatedBundle(trustDomain, realmId?) {
    const { log } = this.deps;
    log.debug('Entering SpiffeCa.deleteFederatedBundle(). trustDomain=' +
              trustDomain);
    const name = String(trustDomain == null ? '' : trustDomain).trim()
      .toLowerCase();
    const had = this.federatedIn(realmId).delete(name);
    if (had) this.bumpSequence(realmId, 'a federated bundle was removed');
    log.debug('Leaving SpiffeCa.deleteFederatedBundle(). ' +
              (had ? 'Removed.' : 'It ' +
        'was not here.'));
    return had;
  }

  federatedBundle(trustDomain, realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.federatedBundle().");
    const name = String(trustDomain == null ? '' : trustDomain).trim()
      .toLowerCase();
    if (this.shadowsServedDomain(name)) {
      log.debug("Leaving SpiffeCa.federatedBundle().");
      return null;
    }
    log.debug("Leaving SpiffeCa.federatedBundle().");
    return this.federatedIn(realmId).get(name) || null;
  }

  federatedBundles(realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.federatedBundles().");
    const out = [];
    const served = this.servedTrustDomains();
    this.federatedIn(realmId).forEach(function (entry) {
      if (served.has(String(entry.trustDomain || ''))) {
        // Warned ONCE per name per process: this is on the path of every SVID
        // verification, and a line per call would bury the one that matters.
        if (warnedShadows.has(entry.trustDomain)) {
          return;
        }
        warnedShadows.add(entry.trustDomain);
        log.warn('spiffe: a federated bundle named ' + entry.trustDomain +
                 ' is IGNORED — that is a trust domain this service serves, ' +
                 'and a bundle under a served name would let a foreign ' +
                 'anchor vouch for this service\'s own identities. Delete it.');
        return;
      }
      out.push(entry);
    });
    out.sort(function (a, b) {
      return a.trustDomain.localeCompare(b.trustDomain);
    });
    log.debug("Leaving SpiffeCa.federatedBundles().");
    return out;
  }

  // What a bundle document has to look like before this service will hold it.
  // This IS a refusal, on a service that refuses almost nothing, and it earns
  // its place: a malformed bundle is not stored and quietly ignored, it is
  // stored and then silently drops every key when a workload parses it. The
  // failure arrives as "nothing from that trust domain verifies" with nothing
  // pointing back here.
  checkBundleDocument(value): Record<string, any> {
    const { log } = this.deps;
    log.debug('Entering SpiffeCa.checkBundleDocument().');
    let document = value;
    if (typeof document === 'string') {
      try {
        document = JSON.parse(document);
      } catch (e) {
        log.debug('Leaving SpiffeCa.checkBundleDocument(). Not JSON.');
        return { ok: false, reason: 'A bundle is a JSON document and that is ' +
                                    'not JSON: ' + e.message };
      }
    }
    if (!document || typeof document !== 'object') {
      log.debug('Leaving SpiffeCa.checkBundleDocument(). Not an object.');
      return { ok: false, reason: 'A bundle is a JSON object.' };
    }
    if (!Array.isArray(document.keys)) {
      log.debug('Leaving SpiffeCa.checkBundleDocument(). No keys array.');
      return { ok: false, reason: 'A bundle has a `keys` member and it is an ' +
                                  'array (it may be empty — a trust domain ' +
                                  'with no authorities is a real state).' };
    }
    for (let i = 0; i < document.keys.length; i++) {
      const key = document.keys[i];
      if (!key || typeof key !== 'object') {
        log.debug('Leaving SpiffeCa.checkBundleDocument(). A key is not an ' +
                  'object.');
        return { ok: false, reason: 'Key ' + i + ' is not a JWK.' };
      }
      if (!key.kty) {
        log.debug('Leaving SpiffeCa.checkBundleDocument(). A key has no kty.');
        return { ok: false, reason: 'Key ' + i + ' has no `kty`.' };
      }
      if (key.use !== 'x509-svid' && key.use !== 'jwt-svid' &&
          key.use !== 'wit-svid') {
        // The specification says a consumer MUST ignore a JWK whose `use` is
        // missing or unknown — so a bundle full of them is a bundle that will
        // verify nothing, and accepting it silently is the worst of the three
        // options.
        log.debug('Leaving SpiffeCa.checkBundleDocument(). A key has no ' +
                  'usable use.');
        return { ok: false, reason: 'Key ' + i + ' has `use` of ' +
                                    (key.use ? '"' + key.use + '"' :
                                     '(absent)') +
                                    '. Every JWK in a SPIFFE bundle carries ' +
                                    '`use` of x509-svid, jwt-svid or ' +
                                    'wit-svid, and a consumer MUST IGNORE ' +
                                    'one that does not — so a ' +
                                    'bundle of these would verify ' +
                                    'nothing and report no error.' };
      }
      if (key.use === 'x509-svid' &&
          (!Array.isArray(key.x5c) || !key.x5c.length)) {
        log.debug('Leaving SpiffeCa.checkBundleDocument(). An x509-svid key ' +
                  'has no x5c.');
        return { ok: false,
                 reason: 'Key ' + i + ' is an x509-svid key with no `x5c`; ' +
                                    'the certificate is what an X.509 ' +
                                    'authority IS.' };
      }
    }
    log.debug('Leaving SpiffeCa.checkBundleDocument(). ' +
              document.keys.length + ' ' +
        'key(s).');
    return { ok: true, document: document };
  }

  // How many authorities a rotation keeps published, the active one included.
  // A setting since 2026-09-12; the default is the old constant. The minimum is
  // 2 in config.js and not 1, because keeping only the new authority is the
  // rotation-as-outage this section argues against: every SVID in the field
  // stops verifying the moment the button is pressed.
  retainedAuthorities(realmId?) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.retainedAuthorities().");
    log.debug("Leaving SpiffeCa.retainedAuthorities().");
    return this.realmSettings(realmId).retained;
  }

  async rotateX509Authority(realmId?) {
    const { log, pki } = this.deps;
    log.debug('Entering SpiffeCa.rotateX509Authority().');
    const id = this.realmIdOf(realmId);
    await this.ready(id);
    if (pki.describeIssuer(id, SPIFFE_USE_CASE)) {
      // `reissueUseCase()` supersedes the old authority on its Intermediate's
      // revocation list and re-mints everything that was certified under it —
      // which for SPIFFE is nothing, because `issueUnder()` records nothing. It
      // is called rather than reimplemented so that a SPIFFE rotation and the
      // Reissue button on /admin/pki are ONE act with one set of consequences.
      const done = await pki.reissueUseCase(id, SPIFFE_USE_CASE);
      if (!done.ok) {
        log.debug('Leaving SpiffeCa.rotateX509Authority(). The PKI refused.');
        throw new Error((done.errors || ['The SPIFFE Issuing CA could not be ' +
                                         're-issued.']).join(' '));
      }
      // **THE SEQUENCE DOES NOT MOVE, AND THAT IS NOT AN OVERSIGHT.** It is
      // defined to change when the BUNDLE changes, and the bundle is the Root.
      // Bumping it here would tell every consumer in the trust domain to
      // re-fetch a document that is byte-identical to the one they hold.
      const fresh = this.activeX509Authority(id);
      log.info('spiffe: the "' + (id || 'default') + '" realm\'s SPIFFE ' +
               'Issuing CA was re-issued (' + fresh.id + '). The bundle is ' +
               'UNCHANGED — it publishes this service\'s Root, which did not ' +
               'move — so SVIDs minted under the old authority go on ' +
               'verifying and no consumer has to re-fetch anything.');
      log.debug('Leaving SpiffeCa.rotateX509Authority(). Re-issued under the ' +
                'Root.');
      return fresh;
    }
    // The REALM's key type and TTL, and the realm's own trust domain — a
    // rotation replaces material for one realm and must not take the ambient
    // realm's settings while doing it.
    const spec = this.realmSettings(id);
    const authority = await this.makeX509Authority(spec.x509KeyType, spec.caTtl,
                                                   1,
                                                   this.trustDomainOf(id),
                                                   spec.caSubject);
    // READ, PREPEND, WRITE BACK — and the write is what makes the rotation the
    // SERVICE's rather than this process's. `x509List()` hands back the
    // memoised array, so it is copied before being changed.
    const kept = [authority].concat(this.x509List(id));
    const dropped = kept.splice(this.retainedAuthorities(id));
    this.setX509List(id, kept);
    this.bumpSequence(id, 'the X.509 authority was rotated');
    log.info('spiffe: a new SELF-SIGNED X.509 authority (' + authority.id +
             ') is now active in "' + (id || 'default') + '"; ' +
             (kept.length - 1) + ' retired one(s) are ' +
             'still published in the bundle' +
             (dropped.length ? ', and ' + dropped.length + ' was dropped — ' +
              'anything it signed no longer verifies' : '') + '.');
    log.debug('Leaving SpiffeCa.rotateX509Authority().');
    return this.selfSignedAuthorityFrom(authority);
  }

  async rotateJwtAuthority(realmId?) {
    const { log } = this.deps;
    log.debug('Entering SpiffeCa.rotateJwtAuthority().');
    const id = this.realmIdOf(realmId);
    await this.ready(id);
    const authority = await this.makeJwtAuthority(this.realmSettings(id)
      .jwtKeyType);
    const kept = [authority].concat(this.jwtList(id));
    const dropped = kept.splice(this.retainedAuthorities(id));
    this.setJwtList(id, kept);
    this.bumpSequence(id, 'the JWT authority was rotated');
    log.info('spiffe: a new JWT authority (kid ' + authority.id + ') is now ' +
             'active; ' + (kept.length - 1) + ' retired one(s) are ' +
             'still published' +
             (dropped.length ? ', and ' + dropped.length + ' was dropped — ' +
              'anything it signed no longer verifies' : '') + '.');
    log.debug('Leaving SpiffeCa.rotateJwtAuthority().');
    return authority;
  }

  // ---------------------------------------------------------------------------
  // SMALL CONVERSIONS. Here rather than in `jose_jwe.js` because that file is
  // vendored and must stay byte-identical to the parent project's copy.
  // ---------------------------------------------------------------------------
  pemToDer(pem) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.pemToDer().");
    log.debug("Leaving SpiffeCa.pemToDer().");
    return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
  }

  derToPem(der, label) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.derToPem().");
    const b64 = Buffer.from(der).toString('base64');
    const lines = b64.match(/.{1,64}/g) || [];
    log.debug("Leaving SpiffeCa.derToPem().");
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') +
           '\n-----END ' + label + '-----\n';
  }

  toArrayBuffer(buf) {
    const { log } = this.deps;
    log.debug("Entering SpiffeCa.toArrayBuffer().");
    const view = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
    log.debug("Leaving SpiffeCa.toArrayBuffer().");
    return view.buffer.slice(view.byteOffset,
                             view.byteOffset + view.byteLength);
  }

  // ---------------------------------------------------------------------------
  // WHAT THE PAGES REPORT.
  //
  // The ONE synchronous entry point, and it is synchronous on purpose: it is
  // read by `/admin/spiffe` and by `GET /spiffe` while the authorities may
  // still be being generated, and a page that awaited them would hang for the
  // two seconds an RSA-4096 authority takes rather than saying "still
  // starting". `ready` false with no `error` IS that state, and both pages
  // print it.
  //
  // NO PRIVATE KEY IS IN HERE. The certificate, the public JWK and the kid are
  // published; the keys stay in this module, exactly as `tls_server.js`
  // publishes its certificate and not its key.
  // ---------------------------------------------------------------------------
  state(realmId?) {
    const { log, config, spiffeId, crypto, errorCodes } = this.deps;
    log.debug("Entering SpiffeCa.state().");
    const id = this.realmIdOf(realmId);
    const active = this.activeX509Authority(id);
    const anchors = this.trustAnchorsIn(id);
    log.debug("Leaving SpiffeCa.state().");
    return {
      enabled: !!config.value('spiffe.enabled'),
      ready: !!started && !startError,
      error: startError || '',
      startedAt: started || 0,
      realm: id,
      trustDomain: this.trustDomainOf(realmId),
      trustDomainId: spiffeId.trustDomainId(this.trustDomainOf(realmId)),
      // WHAT CONFIGURATION SAYS, BESIDE WHAT THE MATERIAL SAYS. Null when they
      // agree, which is every ordinary case — see the block above
      // `PROCESS_TRUST_DOMAIN`. A page that showed only one of the two would be
      // the silent disagreement this arrangement exists to avoid.
      trustDomainDrift: this.trustDomainDrift(realmId),
      serverId: started && !startError
        ? spiffeId.serverId(this.trustDomainOf(realmId)) : '',
      sequence: this.sequenceNow(id),
      refreshHint: this.refreshHintSeconds(),
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
      // node's own parser rather than assembled from the fields beside them,
      // for
      // `certificateFacts()`'s reason: a subject rendered two ways is a subject
      // a reader cannot compare with an `openssl x509 -subject`.
      chainSubjects: active ? active.chainPem.map(function (pem) {
        try {
          return new crypto.X509Certificate(pem).subject.replace(/\n/g, ', ');
        } catch (e) {
          // A certificate this service built that node cannot read is a defect
          // here rather than bad input, so it is logged — and it is
          // bookkeeping, so it never fails the report it is part of.
          log.error(errorCodes.tag('STS-SPIFFE-0045') +
                    'spiffe: a chain certificate ' +
                    'would not parse for state(): ' +
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
              ? this.x509List(id).slice(1).map(function (a) {
                  return { id: a.id, active: false, source: 'self-signed',
                           keyType: a.keyType, subject: a.subject,
                           serialHex: a.serialHex, notBefore: a.notBefore,
                           notAfter: a.notAfter,
                           certificatePem: a.certificatePem,
                           createdAt: a.createdAt };
                })
              : [])
        : [],
      jwtAuthorities: this.jwtList(id).map(function (a, index) {
        return { id: a.id, active: index === 0, keyType: a.keyType, alg: a.alg,
                 jwk: a.jwk, createdAt: a.createdAt };
      }),
      federated: this.federatedBundles(id).map(function (entry) {
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
}

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
          'generate — noticeable at startup — and produces much larger ' +
          'SVIDs.' },
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

// ---------------------------------------------------------------------------
// THE STATE. It was all in memory and gone when the process ended; it is
// persisted since 2026-09-08 — see the block after this one.
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
// KEEPING, BECAUSE IT WAS STILL HALF TRUE THAT DAY.** *(The other half went
// on 2026-09-12: the trust domain and the sockets are a realm's too — see
// `spiffe/CLAUDE.md` and the TRUST DOMAIN block above. This paragraph and the
// next are the 2026-09-11 state.)* It read: *SPIFFE is ONE trust
// domain for the whole service — its sockets have no path to put a realm
// segment in — so this is not per realm.* The trust DOMAIN was still one:
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

// The foreign trust domains this one federates with, keyed by trust domain
// name. Each holds the bundle document exactly as it was given — see
// `setFederatedBundle()` for why it is given rather than fetched.
// **A PERSISTED STORE AND NOT A PLAIN Map (2026-09-07)** — shared then, per
// realm since 2026-09-12 (below). A federated
// bundle is registered through `/admin-api/spiffe` or the console and read back
// off `GET /spiffe`, and a plain Map made it visible only in the process that
// took the call: with a request worker pool, registering a trust domain on one
// worker left the other two unable to see it, which is what
// `sts_admin_api_operations` and `sts_admin_console` measured.
//
// **IT WAS `sharedMap` UNTIL 2026-09-12, AND THAT WAS A SECURITY DEFECT RATHER
// THAN A STALE COMMENT.** The argument read: *SPIFFE is one trust domain for
// the whole service — its four sockets have no path to put a realm segment in,
// so its state is not per realm.* That stopped being true the day each realm
// got a trust domain and a pair of sockets of its own, and this store was left
// behind:
//
//   * realm `acme` could register a bundle NAMED `example.org` — the DEFAULT
//     realm's own trust domain — because the "not your own domain" check below
//     compared against the CALLING realm's domain only;
//   * `spiffe_auth.ts`'s `authorityCertificates()` then offered that bundle's
//     anchors in EVERY realm, and `verifyPresentedCertificate()` matches a
//     signer to a trust domain by the LABEL the bundle was stored under — so a
//     certificate acme's operator minted for `spiffe://example.org/anything`
//     authenticated on the default realm's SPIRE Server API as that identity;
//   * and `spiffe_workload.ts` keyed FetchX509Bundles by trust domain, so the
//     federated entry OVERWROTE the realm's own bundle in the reply.
//
// A realm is an isolated identity service in both modes (`common/mode.js`), so
// that was a boundary one API call wide, and it is closed in every mode. Three
// halves, and each is needed: the store is PER REALM (`realms.map()`, so a
// bundle one realm federates with is invisible to every other); a bundle may
// not be registered under ANY trust domain this process serves, whichever realm
// serves it (`servedTrustDomains()`); and every reader skips a federated entry
// whose name collides with a served one anyway, which is what protects a row
// persisted by an older build.
//
// **WHAT THAT COSTS, SAID RATHER THAN DISCOVERED**: one realm can no longer be
// told to trust another realm of THIS SERVICE by federating with its bundle.
// Two realms here share one Root and one process, and the only thing a
// federation between them could add is a way round the boundary the
// Intermediate draws — which is the defect above, asked for deliberately.
//
// The values are plain JSON — strings, a document and a timestamp — so they
// survive the `JSON.stringify` the journal writes, which is the trap three
// other stores hit. A row persisted by the shared store restores into the
// DEFAULT realm's partition, because a shared row carries the empty realm id.
const federated = realms.map({ persist: 'spiffe.federatedBundles' });

// What the startup actually did, for the pages that report it. Set once
// `initialise()` finishes and readable synchronously — see `state()`.
let started = null;
let startError = null;

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
//     one Root covering the main port, LDAPS 636, every token this
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
import pki = require('../common/pki');

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const spiffeCa = new SpiffeCa({
  crypto: crypto,
  realms: realms,
  jwt: jwt,
  stsCrypto: stsCrypto,
  pkijs: pkijs,
  log: log,
  b64u: b64u,
  nowSec: nowSec,
  dnRfc4514: dnRfc4514,
  config: config,
  errorCodes: errorCodes,
  spiffeId: spiffeId,
  keys: keys,
  x509: x509,
  pki: pki,
  loadKeystore: function () {
    return require('../common/keystore');
  },
  loadClusterClaims: function () {
    return require('../cluster/cluster_claims');
  }
});

const SPIFFE_USE_CASE = 'spiffe';

const readyPromise = spiffeCa.buildReadyPromise();

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

// ---------------------------------------------------------------------------
// ONE AUTHORITY FOR THE CLUSTER, NOT ONE PER NODE (2026-09-14, #46 section 1).
//
// The paragraph at the top of `buildTrustMaterial()` below says two processes
// that race both write, the later wins, and both then READ the winner — "the
// disagreement is a window rather than a state". Inside one container that
// window is the IPC round trip. Across containers it is replication, and in
// it a JWT-SVID minted by the node whose authority is about to be overwritten
// is refused by every other node's `validateJwtSvid()` — and by the minting
// node too, the moment the other write arrives. The issue measured the same
// shape one level down: `spiffe_auth.ts` refused on B an X509-SVID A issued.
//
// Where the store arbitrates, an authority is established ONCE: the node that
// takes the claim (`spiffe.authority`, per realm and kind) reads the store
// again, makes the authority only if it is still missing, and COMMITS it
// before letting the claim go; a node that finds the claim held waits for that
// commit to replicate and takes the authority it brings. Everywhere else —
// development, `ldif`, one process — `make()` runs as it always did.
//
// The X.509 half is normally not built here at all: it IS the realm's SPIFFE
// Issuing CA, which `common/pki.js` builds once for the cluster. This guards
// the self-signed fallback of a realm with no hierarchy.
// ---------------------------------------------------------------------------
const ESTABLISH_CLAIM_MS = 60000;
const ESTABLISH_WAIT_MS = 120000;
const ESTABLISH_POLL_MS = 250;

// This realm's federated bundles, less any named after a served trust domain.
// Every reader that TRUSTS a bundle — the SVID verifier, the Workload API's
// bundle maps, the JWT-SVID validator — goes through here or through the two
// lookups above, so a shadowing row written before the refusal verifies
// nothing.
const warnedShadows = new Set();

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
// The default, kept as an export for the pages that print it. What is APPLIED
// is `spiffe.retainedAuthorities`, read in the realm being rotated — see
// `retainedAuthorities()`.
const MAX_RETAINED_AUTHORITIES = 4;

// DECLARED AT REQUIRE TIME (cluster/CLAUDE.md): a realm's JWT authority and
// its self-signed X.509 fallback are established once for the cluster
// (`establishOnce()`), and its X.509 authority proper is the realm's SPIFFE
// Issuing CA, which `common/pki.js` builds once and every node adopts — so
// every node issues from, and `spiffe_auth.ts` verifies against, the same one.
import capabilities = require('../cluster/cluster_capabilities');
capabilities.provide('spiffe.authority-agreement');

export = {
  SpiffeCa: SpiffeCa,
  KEY_TYPES: KEY_TYPES,
  // A GETTER, so that `admin-core/admin_views.js` — which reads this member to
  // print the cap — reports the value `spiffe.retainedAuthorities` holds in the
  // ambient realm rather than the default it replaced.
  get MAX_RETAINED_AUTHORITIES() {
    log.debug("Entering MAX_RETAINED_AUTHORITIES().");
    log.debug("Leaving MAX_RETAINED_AUTHORITIES().");
    return spiffeCa.retainedAuthorities();
  },
  DEFAULT_RETAINED_AUTHORITIES: MAX_RETAINED_AUTHORITIES,
  // BOTH TAKE AN OPTIONAL REALM and fall back to the AMBIENT one, which is
  // the shape every per-realm reader in this module has. The gRPC handlers
  // run inside `realms.run()` for the realm whose socket the call arrived on
  // (see spiffe_server.ts), so a caller that passes nothing still gets the
  // right trust domain rather than the process's.
  trustDomain: function (realmId?) {
    log.debug("Entering trustDomain().");
    log.debug("Leaving trustDomain().");
    return spiffeCa.trustDomainOf(realmId);
  },
  trustDomainId: function (realmId?) {
    log.debug("Entering trustDomainId().");
    log.debug("Leaving trustDomainId().");
    return spiffeId.trustDomainId(spiffeCa.trustDomainOf(realmId));
  },
  trustDomainDrift: spiffeCa.trustDomainDrift.bind(spiffeCa) as
    SpiffeCa['trustDomainDrift'],
  processTrustDomain: function () {
    log.debug("Entering processTrustDomain().");
    log.debug("Leaving processTrustDomain().");
    return PROCESS_TRUST_DOMAIN;
  },
  ready: spiffeCa.ready.bind(spiffeCa) as SpiffeCa['ready'],
  state: spiffeCa.state.bind(spiffeCa) as SpiffeCa['state'],
  mintX509Svid: spiffeCa.mintX509Svid.bind(spiffeCa) as
    SpiffeCa['mintX509Svid'],
  signCsr: spiffeCa.signCsr.bind(spiffeCa) as SpiffeCa['signCsr'],
  downstreamCa: spiffeCa.downstreamCa.bind(spiffeCa) as
    SpiffeCa['downstreamCa'],
  mintJwtSvid: spiffeCa.mintJwtSvid.bind(spiffeCa) as SpiffeCa['mintJwtSvid'],
  validateJwtSvid: spiffeCa.validateJwtSvid.bind(spiffeCa) as
    SpiffeCa['validateJwtSvid'],
  bundle: spiffeCa.bundle.bind(spiffeCa) as SpiffeCa['bundle'],
  x509BundleDer: spiffeCa.x509BundleDer.bind(spiffeCa) as
    SpiffeCa['x509BundleDer'],
  federatedX509BundleDer: spiffeCa.federatedX509BundleDer.bind(spiffeCa) as
    SpiffeCa['federatedX509BundleDer'],
  setFederatedBundle: spiffeCa.setFederatedBundle.bind(spiffeCa) as
    SpiffeCa['setFederatedBundle'],
  deleteFederatedBundle: spiffeCa.deleteFederatedBundle.bind(spiffeCa) as
    SpiffeCa['deleteFederatedBundle'],
  federatedBundle: spiffeCa.federatedBundle.bind(spiffeCa) as
    SpiffeCa['federatedBundle'],
  federatedBundles: spiffeCa.federatedBundles.bind(spiffeCa) as
    SpiffeCa['federatedBundles'],
  checkBundleDocument: spiffeCa.checkBundleDocument.bind(spiffeCa) as
    SpiffeCa['checkBundleDocument'],
  rotateX509Authority: spiffeCa.rotateX509Authority.bind(spiffeCa) as
    SpiffeCa['rotateX509Authority'],
  rotateJwtAuthority: spiffeCa.rotateJwtAuthority.bind(spiffeCa) as
    SpiffeCa['rotateJwtAuthority'],
  // The realm's active X.509 authority, for a caller that needs to say what
  // signed an SVID without drawing the whole of `state()`.
  activeX509Authority: spiffeCa.activeX509Authority.bind(spiffeCa) as
    SpiffeCa['activeX509Authority'],
  trustAnchors: spiffeCa.trustAnchorsIn.bind(spiffeCa) as
    SpiffeCa['trustAnchorsIn'],
  sequence: function (realmId?) {
    log.debug("Entering sequence().");
    log.debug("Leaving sequence().");
    return spiffeCa.sequenceNow(realmId);
  },
  // For tests/cluster_key_pki_agreement.js (#46): that two establishments
  // racing across nodes make ONE authority is a protocol over a claim, a sync
  // and a commit, asserted with those three stubbed.
  establishOnce: spiffeCa.establishOnce.bind(spiffeCa) as
    SpiffeCa['establishOnce']
};
