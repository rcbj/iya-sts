'use strict';
//
// File: vc_issuer.ts
//
// ===========================================================================
// OpenID for Verifiable Credential Issuance (OID4VCI) — mock Credential Issuer
//
// The bare minimum needed to drive the debugger's SD-JWT VC issuance workflow
// end to end:
//
//   GET  /.well-known/openid-credential-issuer   Credential Issuer Metadata
//   GET  /.well-known/jwt-vc-issuer              JWT VC Issuer Metadata (the
//                                                SD-JWT VC key-resolution
//                                                document: issuer + jwks_uri)
//   POST /oid4vci/nonce                          a fresh c_nonce
//   POST /oid4vci/credential                     the Credential Request; returns
//                                                an SD-JWT VC built per RFC 9901
//
// This is a TEST issuer. It checks that a request carries SOME bearer token but
// cannot validate one issued by the separate authorization server (Keycloak in
// the test suite), so it does not try; what it DOES check properly is the
// wallet's proof of possession, because that is the part the debugger produces
// and therefore the part worth verifying.
//
// The authorization server the metadata advertises is configurable
// (OID4VCI_AUTHORIZATION_SERVER), so the document can point the wallet at the
// real IdP while the credential endpoint stays here.
// ===========================================================================
//
// What lives NEXT DOOR rather than here, and why: the credential configurations
// (vc_configs.ts, read by the authorization server too), the Credential Offer
// and its pre-authorized codes (vc_offers.ts, redeemed at the token endpoint),
// and the issuer's DID documents (vc_did.ts). This module is the part that
// MINTS: the metadata, the nonce, the proof check, the three credential
// builders, the Credential Request in both its plain and encrypted forms,
// deferred issuance and the notification endpoint.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `VcIssuer` takes everything it reads through its constructor, as
// `VcIssuerDeps` — the helpers, the crypto module, config, the admin
// register, the three sibling modules' members (under the names this file
// always destructured them by), the cluster claim, and the three stores. The
// stores are still declared at module scope with `realms.map()`, because a
// store becomes per realm at its declaration. `oauth2.js` is still required
// LAZILY, through `VcIssuer.loadOauth2()`, for the cycle the note
// at `sendVciMetadata()` names.
//
// The routes are registered by `registerRoutes(app)`, in the order they
// always had. Since #50's R1 loading the module does not call it: the module
// exports it, and `common/protocol_stack.ts` calls it at
// the point in the route order where requiring this module used to register
// the routes — so `capabilities.provide()`, still run at require time, now
// runs BEFORE the routes are registered rather than after. Since #50's R2
// that root also BUILDS the instance; the module's old exports are FACADES
// forwarding to it, for the unconverted modules and tests that require it,
// and a process without the root builds a default at load. `VcIssuer` is
// exported beside them.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and error_codes.js and nothing else here, so it cannot join a
// cycle and it registers no route, so its position is not a position at all.
import realms = require('../common/realms');
// Required, as it always was, although nothing here signs with it directly
// any more; the require keeps the load order of this module unchanged.
import jwt = require('jsonwebtoken');
// One signer, one verifier and one JWE for the whole service since 2026-08-27.
import stsCrypto = require('../common/crypto');
import app = require('../common/app');
import config = require('../common/config');
import bbs2023 = require('../common/vendored/bbs2023.js');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import dpop = require('../oauth-oidc/dpop');
import mode = require('../common/mode');
// The error codes (common/error_codes.js). A LEAF that requires nothing; a code
// is marked on the response object and never put in an error_description.
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
// The register the admin console counts credentials in. The three builders
// below sign with jsonwebtoken (or with BBS) directly rather than through
// helpers.signJwt(), so they are not counted by the recorder that catches every
// OAuth token — buildCredentialFor(), which all three go through, says so
// instead.
import stats = require('../common/admin_stats');
import vcConfigs = require('./vc_configs');
import vcDid = require('./vc_did');
// WHICH claims a credential carries, and what each one's value is. A library
// like dpop.js — it registers nothing, so its place in the require order does
// not matter — and it is the single list both the metadata below and the three
// builders read, so an issuer that advertises one claim set and mints another
// is not a state this file can reach. /admin/vc is what changes it.
import vcClaims = require('./vc_claims');
import vcOffers = require('./vc_offers');
// THE REGISTER OF CREDENTIALS ISSUED FOR A DIRECTORY ENTRY (2026-09-17, #38):
// what `/authn/wallet` reads to decide whom a presentation signs in. A
// LIBRARY (rule 3) requiring only `common/` leaves, so this require closes no
// cycle and moves no route. See `rememberIssued()` below.
import vcIssued = require('./vc_issued');
// THE STATUS LISTS (#38's follow-ups): every credential carries a reference
// into them, and they sign with the key a credential is signed with. A
// library and route module requiring only `common/` libraries, its codec and
// the outbound fetcher, none of which requires this file.
import vcStatus = require('./vc_status');
// THE HOLDER'S DATA INTEGRITY PROOF (#38's follow-ups): the did:jwk an ldp_vc
// names its holder by, and which key types a proof can be made with. A pure
// library over `common/` leaves.
import vcDataIntegrity = require('./vc_data_integrity');
// THE CLUSTER CLAIM (2026-09-14, #46): the atomic "once" a c_nonce is spent
// through — see spendProofNonces(). A LIBRARY that registers no route and
// requires persistence lazily, so it moves no route and closes no cycle.
import clusterClaims = require('../cluster/cluster_claims');
import capabilities = require('../cluster/cluster_capabilities');

// THE HOLDER KEYS AN ldp_vc MAY BE BOUND TO (#38's follow-ups): the JOSE
// algorithms whose keys a Data Integrity cryptosuite `vc_data_integrity.ts`
// verifies can prove at presentation — P-256 and P-384 (ecdsa-jcs-2019),
// Ed25519 (eddsa-jcs-2022) and ML-DSA-44 (mldsa44-jcs-2024, the one
// quantum-resistant JCS suite the W3C draft defines). A key of any other kind
// would be bound to a credential it could never present.
const LDP_HOLDER_ALGS = ['ES256', 'ES384', 'EdDSA', 'ML-DSA-44'];

// THE ALGORITHMS A KEY ATTESTATION MAY BE SIGNED WITH: its signer is named by
// a certificate, whose key this service reads into a node KeyObject — every
// asymmetric algorithm but the post-quantum ones, which it cannot.
const ATTESTATION_ALGS = stsCrypto.JWS_ASYMMETRIC_ALGS.filter(function (alg) {
  return stsCrypto.JWS_ALGS[alg].family !== 'pq';
});

// The express application's route-adding surface, as `registerRoutes()`
// uses it.
type RouteApp = Pick<typeof app, 'get' | 'post'>;

// What an issuer needs from the rest of the service. The names are the ones
// this file has always used for them, so the method bodies read as before.
interface VcIssuerDeps {
  log: typeof helpers.log;
  logArtifact: typeof helpers.logArtifact;
  STS: typeof helpers.STS;
  baseUrlOf: typeof helpers.baseUrlOf;
  b64u: typeof helpers.b64u;
  jsonFromB64u: typeof helpers.jsonFromB64u;
  randomId: typeof helpers.randomId;
  bbsKeyPair: typeof helpers.bbsKeyPair;
  vciError: typeof helpers.vciError;
  signingKeyFor: typeof helpers.signingKeyFor;
  requestEncryptionKeyFor: typeof helpers.requestEncryptionKeyFor;
  certificateHeaderFor: typeof helpers.certificateHeaderFor;
  publishedKidFor: typeof helpers.publishedKidFor;
  crypto: typeof crypto;
  stsCrypto: typeof stsCrypto;
  config: typeof config;
  bbs2023: typeof bbs2023;
  dpop: typeof dpop;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
  vciAuthorizationServer: typeof vcConfigs.vciAuthorizationServer;
  vciBatchSize: typeof vcConfigs.vciBatchSize;
  VCI_CONFIGS: typeof vcConfigs.VCI_CONFIGS;
  VCI_CONFIG_ID: typeof vcConfigs.VCI_CONFIG_ID;
  VCI_JWT_CONFIG_ID: typeof vcConfigs.VCI_JWT_CONFIG_ID;
  VCI_JWT_SCOPE: typeof vcConfigs.VCI_JWT_SCOPE;
  VCI_JWT_TYPES: typeof vcConfigs.VCI_JWT_TYPES;
  VCI_LDP_CONFIG_ID: typeof vcConfigs.VCI_LDP_CONFIG_ID;
  VCI_LDP_SCOPE: typeof vcConfigs.VCI_LDP_SCOPE;
  VCI_SCOPE: typeof vcConfigs.VCI_SCOPE;
  VCI_VCT: typeof vcConfigs.VCI_VCT;
  VC_CONTEXT: typeof vcConfigs.VC_CONTEXT;
  configIdOfIdentifier: typeof vcConfigs.configIdOfIdentifier;
  vciConfigIds: typeof vcConfigs.vciConfigIds;
  vciFormatOf: typeof vcConfigs.vciFormatOf;
  vciUsesIssuerDid: typeof vcConfigs.vciUsesIssuerDid;
  issuerDidFor: typeof vcDid.issuerDidFor;
  stsDid: typeof vcDid.stsDid;
  vcClaims: typeof vcClaims;
  vcIssued: typeof vcIssued;
  vcStatus: typeof vcStatus;
  vcDataIntegrity: typeof vcDataIntegrity;
  deferredIntervalS: typeof vcOffers.deferredIntervalS;
  deferredReadyMs: typeof vcOffers.deferredReadyMs;
  deferredAccessTokens: typeof vcOffers.deferredAccessTokens;
  deferredTransactions: typeof vcOffers.deferredTransactions;
  offerTtlMs: typeof vcOffers.offerTtlMs;
  clusterClaims: typeof clusterClaims;
  // The three stores declared below.
  vciNonces: typeof vciNonces;
  notificationIds: typeof notificationIds;
  lastCredentialRequestStore: typeof lastCredentialRequestStore;
  // `oauth2.js` itself, for its published-document signer. LAZY: see
  // `sendVciMetadata()`.
  loadOauth2: () => { signPublishedDocument: (...args: any[]) => any };
}

// c_nonce values this issuer has handed out and not yet seen used. A nonce is
// single-use (RFC-conformant behaviour, and it makes replay visible in a test).
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const vciNonces = realms.map({ persist: 'vc_issuer.vciNonces', retain: 'age' });

// `oid4vci.cNonceTtlS` since 2026-09-12; the constant is its default and keeps
// its exported name.
const VCI_NONCE_TTL_MS = 5 * 60 * 1000;

// Described to `/admin/caches` (#74, rule 3ap). The value IS the expiry, in
// milliseconds.
const vciNoncesCount = cacheRegistry.register({
  name: 'oid4vci.nonces',
  title: 'OID4VCI nonces',
  description: 'The c_nonce values handed to wallets, so a credential ' +
    'request\'s proof names one this issuer issued, and uses it once.',
  owner: 'oid4vc/vc_issuer.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a nonce this issuer handed out, so the proof was checked',
  settings: ['oid4vci.cNonceTtlS', 'oid4vci.cNonceCacheSize'],
  maxEntries: function (): number {
    return Number(config.value('oid4vci.cNonceCacheSize'));
  },
  bound: 'Enforced: oid4vci.cNonceCacheSize per realm; the oldest nonce is ' +
    'dropped, and a proof quoting it is answered invalid_nonce.',
  lifetime: function (): string {
    return 'oid4vci.cNonceTtlS after it was issued, or when it is used.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, vciNonces,
      function (expires: unknown, nonce: unknown): object {
        return { key: cacheRegistry.digestKey(nonce),
                 validUntil: Number(expires) };
      });
  }
});

// THE CONTENT ENCRYPTION VALUES A DIRECTION ADVERTISES AND ACCEPTS: the
// setting, intersected with what `common/crypto.js` implements here. A value
// the operator names that is not implemented is WARNED about and dropped
// rather than advertised, and a setting that intersects to nothing falls back
// to the implemented list with an error — an issuer that accepts no `enc` at
// all would refuse every encrypted request while its metadata said nothing
// about why.
const IMPLEMENTED_ENC_VALUES = ['A128GCM', 'A256GCM'];

// How long a spent c_nonce's claim outlives the nonce: see
// spendProofNonces().
const CLAIM_SKEW_MS = 60 * 1000;

// ---------------------------------------------------------------------------
// Notification ids (OID4VCI section 11).
//
// The issuer returns one per Credential Response so the wallet can report what
// it did with the credential. Remembering them is what lets the notification
// endpoint tell a real id from an invented one — and section 11.3 defines
// invalid_notification_id precisely so that distinction is made.
// ---------------------------------------------------------------------------
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// id -> { accessToken, expires, event }
const notificationIds = realms.map({ persist: 'vc_issuer.notificationIds' });

// ---------------------------------------------------------------------------
// Credential Response encryption (OID4VCI section 10).
//
// The wallet supplies the key and the content encryption algorithm, and gets a
// JWE back instead of JSON. Only what the metadata advertises is accepted —
// advertising an algorithm this then refuses would make the metadata a lie.
// ---------------------------------------------------------------------------
const VCI_ENC_ALG = 'RSA-OAEP-256';

// The implemented list, kept under its old name. What is ADVERTISED and
// ACCEPTED is `responseEncValues()` — `oid4vci.responseEncryptionEncValues`
// narrowed to this — since 2026-09-12.
const VCI_ENC_VALUES = IMPLEMENTED_ENC_VALUES;

// ---------------------------------------------------------------------------
// Credential REQUEST encryption (OID4VCI section 10), the other direction.
//
// The response side is the wallet's key travelling in the request. This side is
// the reverse and the asymmetry is the whole reason it needs its own code: the
// ISSUER publishes the key, in credential_request_encryption.jwks, and the
// wallet encrypts to it. Two consequences fall out of section 10 that the
// response side does not have:
//
//   * there is no alg_values_supported for requests. "The `alg` parameter MUST
//     be present [in the JWK]. The JWE `alg` algorithm used MUST be equal to
//     the `alg` value of the chosen JWK" — so the algorithm is a property of
//     the key, not a separate list, and this key therefore carries alg itself;
//   * "Each JWK in the set MUST have a kid (Key ID) parameter that uniquely
//     identifies the key", and a JWE encrypted to a key with a kid MUST repeat
//     it in the JWE header. That is what lets an issuer rotate keys, so the kid
//     is checked on the way in rather than ignored.
//
// The key lives and dies exactly as the signing key does — it is a member of
// the same per-realm key set since 2026-09-12, so it is regenerated per start
// in development and read back from the store in product — and its kid is
// derived from the key material for the same reason: two instances must not
// claim the same kid over different keys, or "decryption failed" looks like a
// corrupt request instead of the wrong issuer.
// ---------------------------------------------------------------------------
// The implemented list, kept under its old name; `requestEncValues()` is what
// is advertised and accepted (`oid4vci.requestEncryptionEncValues`).
const VCI_REQUEST_ENC_VALUES = IMPLEMENTED_ENC_VALUES;

// How the most recent Credential Request actually arrived, readable at the
// non-spec GET /oid4vci/last_request.
//
// This exists because a wallet's claim to have encrypted something is not
// observable from the wallet. A pane that assembles a perfect JWE, displays it,
// and then posts the plaintext anyway satisfies every client-side assertion —
// and while encryption_required is false the issuer accepts that JSON and
// issues, so even the end-to-end result looks right. Only the issuer knows what
// it received. A mutation test proved the point: dropping the ciphertext at the
// point of sending went completely undetected until this existed.
//
// **PER TRUST REALM SINCE 2026-09-12.** It was one `let` for the process, so
// `/realm/acme/oid4vci/last_request` answered with however the DEFAULT realm's
// last request had arrived — including the `kid` of a key acme does not hold —
// and a wallet under test in one realm could be told it had encrypted by a
// request made in another. It was `realms.keyed()` rather than `realms.obj()`
// because the record is REPLACED whole on every request rather than edited, and
// a holder object was the honest shape for that. ~~In memory and not persisted:
// it describes one request as seen by one process~~ — **PERSISTED SINCE
// 2026-09-14 (#46)**, and the struck sentence is why: behind a balancer the
// wallet's Credential Request is answered by one node and its read-back of
// `/oid4vci/last_request` by another, which answered `seen: false` or an
// older request, so a wallet that DID encrypt was told it had not — the one
// question this endpoint exists to answer truthfully. It is now a
// `realms.map()` with one key, `LAST_REQUEST_KEY`, the record still replaced
// whole (so it owes no `touch()`), and "last" means the last one the SERVICE
// saw, which is what a wallet under test is asking. The record names a media
// type, a kid, an alg and an enc and never the request itself.
const LAST_REQUEST_KEY = 'last';

const lastCredentialRequestStore = realms.map({
  persist: 'vc_issuer.lastCredentialRequest', retain: 'age' });

// The three events the Notification Endpoint accepts (OID4VCI section 11).
const NOTIFICATION_EVENTS = ['credential_accepted', 'credential_failure',
                             'credential_deleted'];

class VcIssuer {
  static readonly VCI_NONCE_TTL_MS = VCI_NONCE_TTL_MS;
  static readonly IMPLEMENTED_ENC_VALUES = IMPLEMENTED_ENC_VALUES;
  static readonly VCI_ENC_ALG = VCI_ENC_ALG;
  static readonly VCI_ENC_VALUES = VCI_ENC_VALUES;
  static readonly VCI_REQUEST_ENC_VALUES = VCI_REQUEST_ENC_VALUES;
  static readonly NOTIFICATION_EVENTS = NOTIFICATION_EVENTS;

  constructor(private readonly deps: VcIssuerDeps) {
    deps.log.debug("Entering VcIssuer.constructor().");
    deps.log.debug("Leaving VcIssuer.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): VcIssuerDeps {
    helpers.log.debug("Entering VcIssuer.defaultDeps().");
    helpers.log.debug("Leaving VcIssuer.defaultDeps().");
    return {
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      STS: helpers.STS,
      baseUrlOf: helpers.baseUrlOf,
      b64u: helpers.b64u,
      jsonFromB64u: helpers.jsonFromB64u,
      randomId: helpers.randomId,
      bbsKeyPair: helpers.bbsKeyPair,
      vciError: helpers.vciError,
      signingKeyFor: helpers.signingKeyFor,
      requestEncryptionKeyFor: helpers.requestEncryptionKeyFor,
      certificateHeaderFor: helpers.certificateHeaderFor,
      publishedKidFor: helpers.publishedKidFor,
      crypto: crypto,
      stsCrypto: stsCrypto,
      config: config,
      bbs2023: bbs2023,
      dpop: dpop,
      mode: mode,
      errorCodes: errorCodes,
      stats: stats,
      vciAuthorizationServer: vcConfigs.vciAuthorizationServer,
      vciBatchSize: vcConfigs.vciBatchSize,
      VCI_CONFIGS: vcConfigs.VCI_CONFIGS,
      VCI_CONFIG_ID: vcConfigs.VCI_CONFIG_ID,
      VCI_JWT_CONFIG_ID: vcConfigs.VCI_JWT_CONFIG_ID,
      VCI_JWT_SCOPE: vcConfigs.VCI_JWT_SCOPE,
      VCI_JWT_TYPES: vcConfigs.VCI_JWT_TYPES,
      VCI_LDP_CONFIG_ID: vcConfigs.VCI_LDP_CONFIG_ID,
      VCI_LDP_SCOPE: vcConfigs.VCI_LDP_SCOPE,
      VCI_SCOPE: vcConfigs.VCI_SCOPE,
      VCI_VCT: vcConfigs.VCI_VCT,
      VC_CONTEXT: vcConfigs.VC_CONTEXT,
      configIdOfIdentifier: vcConfigs.configIdOfIdentifier,
      vciConfigIds: vcConfigs.vciConfigIds,
      vciFormatOf: vcConfigs.vciFormatOf,
      vciUsesIssuerDid: vcConfigs.vciUsesIssuerDid,
      issuerDidFor: vcDid.issuerDidFor,
      stsDid: vcDid.stsDid,
      vcClaims: vcClaims,
      vcIssued: vcIssued,
      vcStatus: vcStatus,
      vcDataIntegrity: vcDataIntegrity,
      deferredIntervalS: vcOffers.deferredIntervalS,
      deferredReadyMs: vcOffers.deferredReadyMs,
      deferredAccessTokens: vcOffers.deferredAccessTokens,
      deferredTransactions: vcOffers.deferredTransactions,
      offerTtlMs: vcOffers.offerTtlMs,
      clusterClaims: clusterClaims,
      vciNonces: vciNonces,
      notificationIds: notificationIds,
      lastCredentialRequestStore: lastCredentialRequestStore,
      loadOauth2: VcIssuer.loadOauth2
    };
  }

  // `oauth2.js`, required LAZILY at the moment its published-document signer
  // is called: it requires this module's siblings for their stores, and a
  // top-level require back would be a cycle (rule 2). The default the
  // composition root passes (`defaultDeps()`).
  static loadOauth2() {
    helpers.log.debug("Entering VcIssuer.loadOauth2().");
    helpers.log.debug("Leaving VcIssuer.loadOauth2().");
    return require('../oauth-oidc/oauth2');
  }

  private cNonceTtlMs() {
    const { log, config } = this.deps;
    log.debug("Entering VcIssuer.cNonceTtlMs().");
    const seconds = Number(config.value('oid4vci.cNonceTtlS'));
    log.debug("Leaving VcIssuer.cNonceTtlMs().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) * 1000 :
           VCI_NONCE_TTL_MS;
  }

  // ---------------------------------------------------------------------------
  // THE NUMBERS AND NAMES A CREDENTIAL IS BUILT WITH, AS SETTINGS (2026-09-12).
  //
  // Each was a literal at its call site — thirty days in three builders, RS256
  // in five places, a six-hundred-second proof window, the issuer's display
  // name — and each is now read per use from `config.js`, whose `dflt` is the
  // literal that was here. One function per value so a builder reads as what it
  // asks.
  // ---------------------------------------------------------------------------
  private credentialLifetimeSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering VcIssuer.credentialLifetimeSeconds().");
    const seconds = Number(config.value('oid4vci.credentialLifetimeS'));
    log.debug("Leaving VcIssuer.credentialLifetimeSeconds().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) :
           30 * 24 * 3600;
  }

  private proofIatWindowSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering VcIssuer.proofIatWindowSeconds().");
    const seconds = Number(config.value('oid4vci.proofIatWindowS'));
    log.debug("Leaving VcIssuer.proofIatWindowSeconds().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 600;
  }

  // THE ALGORITHM A JOSE CREDENTIAL IS SIGNED WITH, AND THE KEY THAT SIGNS IT.
  //
  // `oid4vci.credentialSigningAlgorithm` names one of the algorithms this realm
  // holds a key for — the RSA key, the curve keys and, since #38's
  // follow-ups, the post-quantum ones (ML-DSA, SLH-DSA and the composites) —
  // and `vc_status.ts`'s `signerAsync()` is the one answer to which key that
  // is: the status lists are signed with the same key as the credentials
  // they describe, so a verifier resolves one key per issuer. It is
  // asynchronous because a post-quantum key set is generated in the worker
  // pool and a post-quantum signature is made there; RS256 takes the exact
  // path it always took (`STS.privateKey`, `STS.kid`).
  //
  // `kid` is the INTERNAL name, which `certificateHeaderFor()` finds the key
  // by; `headerKid` is what the credential's header carries, which
  // `keys.kidFormat` decides (common/jose_kid.js).
  private credentialSignerAsync() {
    const { log, vcStatus } = this.deps;
    log.debug("Entering VcIssuer.credentialSignerAsync().");
    log.debug("Leaving VcIssuer.credentialSignerAsync().");
    return vcStatus.signerAsync();
  }

  // The algorithm alone, for the metadata — which must not generate a key set
  // to say which one it would use.
  private credentialSigningAlg(): string {
    const { log, config } = this.deps;
    log.debug("Entering VcIssuer.credentialSigningAlg().");
    log.debug("Leaving VcIssuer.credentialSigningAlg().");
    return String(config.value('oid4vci.credentialSigningAlgorithm') ||
                  'RS256');
  }

  private encValuesFrom(settingKey) {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering VcIssuer.encValuesFrom(). setting=" + settingKey);
    const named = [].concat(config.value(settingKey) || []);
    const usable = named.filter((one) => {
      return IMPLEMENTED_ENC_VALUES.indexOf(one) >= 0;
    });
    if (usable.length !== named.length) {
      log.warn(settingKey + ' names ' + named.filter((one) => {
        return IMPLEMENTED_ENC_VALUES.indexOf(one) < 0;
      }).join(', ') + ', which this issuer does not implement; only ' +
      IMPLEMENTED_ENC_VALUES.join(' and ') + ' can be advertised.');
    }
    if (!usable.length) {
      log.error(errorCodes.tag('STS-VC-0001') +
                settingKey + ' names no content encryption this issuer ' +
                             'implements, so ' +
                IMPLEMENTED_ENC_VALUES.join(' and ') + ' are used instead.');
      log.debug("Leaving VcIssuer.encValuesFrom(). Fell back to the " +
                "implemented list.");
      return IMPLEMENTED_ENC_VALUES.slice(0);
    }
    log.debug("Leaving VcIssuer.encValuesFrom(). " + usable.join(', '));
    return usable;
  }

  vciMetadata(req) {
    const { log, baseUrlOf, stsCrypto, config, bbs2023, errorCodes,
            vciAuthorizationServer, vciBatchSize, VCI_CONFIGS,
            VCI_CONFIG_ID, VCI_JWT_CONFIG_ID, VCI_JWT_SCOPE, VCI_JWT_TYPES,
            VCI_LDP_CONFIG_ID, VCI_LDP_SCOPE, VCI_SCOPE, VCI_VCT,
            vciConfigIds, vciUsesIssuerDid, issuerDidFor, stsDid, vcClaims
            } = this.deps;
    log.debug("Entering VcIssuer.vciMetadata().");
    const base = baseUrlOf(req);
    const authServer = vciAuthorizationServer() || base;
    const meta: any = {
      // --- REQUIRED ---
      credential_issuer: base,
      credential_endpoint: base + '/oid4vci/credential',
      credential_configurations_supported: {},
      // --- OPTIONAL ---
      authorization_servers: [authServer],
      nonce_endpoint: base + '/oid4vci/nonce',
      // OPTIONAL, and a wallet must not assume it: an issuer that cannot defer
      // omits it entirely (walt.id's does). Ours can, so it says so.
      deferred_credential_endpoint: base + '/oid4vci/deferred_credential',
      notification_endpoint: base + '/oid4vci/notification',
      batch_credential_issuance: { batch_size: vciBatchSize() },
      // Only what this issuer actually performs. It used to advertise ECDH-ES
      // as well, which nothing implemented — metadata that overstates is worse
      // than metadata that says little.
      credential_response_encryption: {
        alg_values_supported: [VCI_ENC_ALG],
        enc_values_supported: this.responseEncValues(),
        encryption_required:
          config.value('oid4vci.responseEncryptionRequired') === true
      },
      // The other direction (section 10). Note the shape differs from the one
      // above and the difference is normative, not an oversight: requests carry
      // no alg_values_supported, because the JWE alg must equal the alg of the
      // JWK the wallet picked out of jwks.
      credential_request_encryption: this.credentialRequestEncryptionMetadata(),
      display: [{
        name: String(config.value('oid4vci.issuerDisplayName') || ''),
        locale: 'en-US',
        logo: { uri: base + '/images/logo.png', alt_text: 'IdP Tools' }
      }]
    };
    meta.credential_configurations_supported[VCI_CONFIG_ID] = {
      format: 'dc+sd-jwt',
      scope: VCI_SCOPE,
      vct: VCI_VCT,
      cryptographic_binding_methods_supported: ['jwk'],
      credential_signing_alg_values_supported: [this.credentialSigningAlg()],
      proof_types_supported:
        this.proofTypesSupported(stsCrypto.JWS_ASYMMETRIC_ALGS),
      display: [{
        name: 'Identity Credential',
        locale: 'en-US',
        background_color: '#12107c',
        text_color: '#FFFFFF'
      }],
      // Built from the configured claim set rather than written out, so that
      // this metadata cannot come to describe a credential this issuer no
      // longer mints. An SD-JWT VC's claims sit at the top level of the
      // payload, so there is no prefix. See /admin/vc. Through
      // advertisedClaims() rather than metadataClaims() directly, because the
      // authorization endpoint validates a wallet's requested claim paths
      // against the SAME list — an issuer that advertised one set of paths and
      // accepted another would make the metadata unusable for exactly the
      // wallet that read it.
      claims: vcClaims.advertisedClaims('dc+sd-jwt')
    };
    // The same facts as a W3C VC secured as a JWT. `credential_definition.type`
    // is what identifies the credential in this format — jwt_vc_json has no vct
    // — and the claim paths are rooted at credentialSubject because that is
    // where a W3C VC keeps them.
    meta.credential_configurations_supported[VCI_JWT_CONFIG_ID] = {
      format: 'jwt_vc_json',
      scope: VCI_JWT_SCOPE,
      credential_definition: { type: VCI_JWT_TYPES },
      cryptographic_binding_methods_supported: ['jwk'],
      credential_signing_alg_values_supported: [this.credentialSigningAlg()],
      proof_types_supported:
        this.proofTypesSupported(stsCrypto.JWS_ASYMMETRIC_ALGS),
      display: [{
        name: 'Identity Credential (JWT VC, no selective disclosure)',
        locale: 'en-US',
        background_color: '#0b6b4f',
        text_color: '#FFFFFF'
      }],
      claims: vcClaims.advertisedClaims('jwt_vc_json')
    };
    // ldp_vc: the signing "alg" slot holds a CRYPTOSUITE name, not a JOSE alg —
    // which is the visible sign that this format is secured differently.
    meta.credential_configurations_supported[VCI_LDP_CONFIG_ID] = {
      format: 'ldp_vc',
      scope: VCI_LDP_SCOPE,
      credential_definition: {
        '@context': ['https://www.w3.org/ns/credentials/v2',
                     bbs2023.IDENTITY_CONTEXT_URL],
        type: VCI_JWT_TYPES
      },
      // `did:jwk` — what buildLdpVc() names the holder by, and what the
      // holder's Data Integrity proof at sign-in is verified against. It said
      // `did:key` while the credential carried a `did:jwk`.
      cryptographic_binding_methods_supported: ['did:jwk'],
      credential_signing_alg_values_supported: ['bbs-2023'],
      // Only the algorithms a Data Integrity cryptosuite exists for: a key of
      // any other kind could be bound and never proved at presentation, so
      // the credential would verify and never sign its holder in.
      proof_types_supported: this.proofTypesSupported(LDP_HOLDER_ALGS),
      display: [{
        name: 'Identity Credential (ldp_vc, BBS selective disclosure)',
        locale: 'en-US', background_color: '#4a148c', text_color: '#FFFFFF'
      }],
      // NOT the same list as the two above, and the difference is the format's
      // rather than a choice: an ldp_vc credential is signed over canonicalized
      // JSON-LD, so it can only carry terms the vendored context defines. The
      // claims a selection asks for and this format cannot express are named on
      // /admin/vc rather than being quietly missing here.
      claims: vcClaims.advertisedClaims('ldp_vc')
    };
    // The DID variants, CLONED from the sibling each is based on rather than
    // written out a fourth and fifth time. Everything about the credential is
    // meant to be identical — the point of the pair is that only the issuer's
    // own name differs — so a claim or proof type added above must not be able
    // to go missing from the DID version.
    vciConfigIds().forEach((id) => {
      const config = VCI_CONFIGS[id];
      if (!config.basedOn) {
        return;
      }
      const sibling =
        meta.credential_configurations_supported[config.basedOn];
      if (!sibling) {
        // Loud, because the symptom otherwise is a configuration this issuer
        // advertises nowhere while still minting credentials for it.
        log.error(errorCodes.tag('STS-VC-0002') +
                  'the ' + id + ' configuration names a sibling ' +
                  config.basedOn +
                  ' that the metadata does not offer; it will not be ' +
                  'advertised.');
        return;
      }
      const entry = JSON.parse(JSON.stringify(sibling));
      entry.scope = config.scope;
      if (Array.isArray(entry.display) && entry.display.length) {
        entry.display[0].name = entry.display[0].name +
          ' — issuer named by DID';
      }
      meta.credential_configurations_supported[id] = entry;
    });

    // --- who this issuer says it is (both extensions; see vc_did.ts) ---------
    //
    // OID4VCI registers neither of these members. They are here because without
    // them a wallet that receives a credential whose iss is a did:web has been
    // told about that DID by nothing it fetched: it has to take the
    // credential's word for who issued it, which is the one thing a
    // credential's own contents cannot establish.
    //
    //   issuer_did          the DID this issuer also answers to. Always
    //                       present, because the DID document is always
    //                       served — a wallet can resolve it, and can check
    //                       the domain linkage at
    //                       /.well-known/did-configuration.json, before any
    //                       credential exists.
    //   issuer_identifier   per configuration: the value credentials from THIS
    //                       configuration will carry in iss (dc+sd-jwt) or
    //                       issuer (jwt_vc_json, ldp_vc). Stated per
    //                       configuration because that is the granularity at
    //                       which it varies, and computed from issuerDidFor() —
    //                       the same function the builders use — so the
    //                       advertisement and the credential cannot disagree.
    meta.issuer_did = stsDid(req);
    vciConfigIds().forEach((id) => {
      const entry = meta.credential_configurations_supported[id];
      if (entry) {
        entry.issuer_identifier = issuerDidFor(id, req) || base;
      }
    });

    log.debug("Leaving VcIssuer.vciMetadata(). " +
              Object.keys(meta.credential_configurations_supported).length +
              " credential configuration(s), " +
              vciConfigIds().filter(vciUsesIssuerDid).length + " of them " +
                  "naming the issuer by DID.");
    return meta;
  }

  // OID4VCI adopts RFC 8414's signed_metadata: a JWT of the metadata signed by
  // the issuer. Signed with the same STS key, so the debugger can verify it
  // against /oauth2/jwks exactly as it verifies an RFC 8414 document — and,
  // since 2026-09-12, with the same ALGORITHM,
  // `oauth2.signedMetadataAlgorithm`, through `oauth2.js`'s signer rather than
  // a copy of it. That module is required LAZILY, inside the handler
  // (`VcIssuer.loadOauth2()`): it requires this module's siblings
  // for their stores, and a top-level require back would be a cycle (rule 2).
  private sendVciMetadata(req, res) {
    const { log, logArtifact, errorCodes, loadOauth2 } = this.deps;
    log.debug("Entering VcIssuer.sendVciMetadata().");
    const meta = this.vciMetadata(req);
    const claims = Object.assign({}, meta, { sub: meta.credential_issuer });
    logArtifact('OID4VCI signed_metadata', 'before signing', claims);
    try {
      meta.signed_metadata = loadOauth2()
        .signPublishedDocument(claims, meta.credential_issuer, 3600,
                               'vci-signed-metadata');
      logArtifact('OID4VCI signed_metadata', 'after signing',
                  meta.signed_metadata);
    } catch (e) {
      log.debug("Caught in VcIssuer.sendVciMetadata(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0003') +
                'OID4VCI signed_metadata: ' + e.message);
    }
    res.status(200)
       .type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(meta, null, 2));
    log.debug("Leaving VcIssuer.sendVciMetadata().");
  }

  // SD-JWT VC key resolution: how a verifier finds the issuer's public keys.
  //
  // `issuer` is the https identifier and stays that way, because this document
  // is found BY that identifier: draft-ietf-oauth-sd-jwt-vc has a verifier take
  // the credential's iss, insert /.well-known/jwt-vc-issuer into it and require
  // that the document's issuer equals the iss it started from. A DID cannot be
  // the subject of that rule — there is no URL to insert anything into — which
  // is exactly why the DID route is an extension and not this.
  //
  // `issuer_did` is that extension, and it is one line rather than a mechanism:
  // it says the same issuer also answers to this DID, whose document publishes
  // the same keys this jwks_uri does. A wallet holding a DID-named credential
  // can start from the origin, find the DID named here, and confirm the two are
  // one entity at /.well-known/did-configuration.json. Without it, the DID and
  // the URL are two identifiers with nothing connecting them.
  private sendJwtVcIssuerMetadata(req, res) {
    const { log, baseUrlOf, stsDid } = this.deps;
    log.debug("Entering VcIssuer.sendJwtVcIssuerMetadata().");
    const base = baseUrlOf(req);
    res.status(200)
       .type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify({
      issuer: base,
      jwks_uri: base + '/oauth2/jwks',
      issuer_did: stsDid(req)
    }, null, 2));
    log.debug("Leaving VcIssuer.sendJwtVcIssuerMetadata().");
  }

  // ---------------------------------------------------------------------------
  // KEY ATTESTATIONS (OpenID4VCI 1.0 Appendix D, #38's follow-ups).
  //
  // A wallet may say how its key is kept: a `key-attestation+jwt`, signed by
  // its Wallet Provider or its key storage, naming the attested keys and the
  // attack potential the key storage (`key_storage`) and the user
  // authentication guarding it (`user_authentication`) resist, on ISO 18045's
  // scale. This issuer takes one in both places the specification defines —
  // the `key_attestation` header of a `jwt` proof (F.1), and the `attestation`
  // proof type (F.3) — and believes it only when it verifies against a
  // certificate in `oid4vci.keyAttestationTrustedCertificates`, either
  // directly or as the issuer of the attestation's own `x5c` leaf. What it
  // attests is RECORDED on the sign-in register (`vc_issued.ts`) with the
  // credential issued for that key, and that is where a wallet sign-in's
  // `amr` and `acr` come from (`vc_verifier.ts`'s `assuranceOf()`): nothing a
  // presentation says about itself is believed.
  //
  // `oid4vci.keyAttestationRequired` makes one REQUIRED: the metadata says so
  // (`key_attestations_required`) and a proof without one is refused. Off by
  // default, where an attestation is still verified and recorded if sent.
  // ---------------------------------------------------------------------------
  private proofTypesSupported(algs: string[]): any {
    const { log, config } = this.deps;
    log.debug("Entering VcIssuer.proofTypesSupported().");
    const jwt: any = { proof_signing_alg_values_supported: algs };
    const attestation: any = { proof_signing_alg_values_supported:
                                 ATTESTATION_ALGS };
    if (config.value('oid4vci.keyAttestationRequired') === true) {
      jwt.key_attestations_required = {};
      attestation.key_attestations_required = {};
    }
    log.debug("Leaving VcIssuer.proofTypesSupported().");
    return { jwt: jwt, attestation: attestation };
  }

  private attesterKeys(): any[] {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering VcIssuer.attesterKeys().");
    const text = String(config.value(
      'oid4vci.keyAttestationTrustedCertificates') || '');
    const blocks = text.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    const out: any[] = [];
    blocks.forEach(function (pem, i) {
      try {
        out.push({ label: 'trusted key attester ' + (i + 1),
                   cert: new crypto.X509Certificate(pem) });
      } catch (e) {
        log.debug("Caught in VcIssuer.attesterKeys(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0085') +
                  'oid4vci.keyAttestationTrustedCertificates: certificate ' +
                  (i + 1) + ' could not be read and is ignored: ' + e.message);
      }
    });
    log.debug("Leaving VcIssuer.attesterKeys(). " + out.length + ".");
    return out;
  }

  // Verifies one key attestation and answers what it attests. Throws with
  // the reason. `opts.proofJwk` — the key a `jwt` proof was signed with, which
  // must be one of the attested keys (Appendix D.1); `opts.expRequired` —
  // true for that proof type, where `exp` is required.
  verifyKeyAttestation(token: string, opts: { proofJwk?: any;
                                               expRequired?: boolean }): any {
    const { log, jsonFromB64u, stsCrypto, vciNonces } = this.deps;
    log.debug("Entering VcIssuer.verifyKeyAttestation().");
    const parts = String(token || '').split('.');
    if (parts.length !== 3) {
      throw new Error('the key attestation is not a three-part JWS.');
    }
    let header: any;
    try {
      header = jsonFromB64u(parts[0]);
    } catch (e) {
      log.debug("Caught in VcIssuer.verifyKeyAttestation(): " +
                ((e && e.message) || e));
      throw new Error('the key attestation header cannot be read.');
    }
    if (header.typ !== 'key-attestation+jwt') {
      throw new Error('a key attestation\'s typ must be ' +
                      'key-attestation+jwt, not "' + header.typ + '".');
    }
    if (ATTESTATION_ALGS.indexOf(header.alg) < 0) {
      throw new Error('the key attestation is signed with "' + header.alg +
                      '", and this issuer accepts ' +
                      ATTESTATION_ALGS.join(', ') + '.');
    }
    const trusted = this.attesterKeys();
    const candidates: any[] = trusted.map(function (t) {
      return { label: t.label, key: t.cert.publicKey };
    });
    if (Array.isArray(header.x5c) && header.x5c.length) {
      try {
        const leaf = new crypto.X509Certificate(
          Buffer.from(String(header.x5c[0]), 'base64'));
        trusted.forEach(function (t) {
          if (leaf.checkIssued(t.cert) && leaf.verify(t.cert.publicKey)) {
            candidates.unshift({ label: 'a certificate ' + t.label +
                                        ' issued', key: leaf.publicKey });
          }
        });
      } catch (e) {
        // An x5c that cannot be read names nobody; the trusted certificates
        // themselves are still tried below.
        log.debug("Caught in VcIssuer.verifyKeyAttestation(): " +
                  ((e && e.message) || e));
      }
    }
    let claims: any = null;
    let by = '';
    let last = 'no certificate in oid4vci.keyAttestationTrustedCertificates ' +
               'verifies it';
    for (let i = 0; i < candidates.length && !claims; i++) {
      try {
        claims = stsCrypto.verifyJws(String(token), candidates[i].key,
                                     { algorithms: [header.alg] });
        by = candidates[i].label;
      } catch (e) {
        log.debug("Caught in VcIssuer.verifyKeyAttestation(): " +
                  ((e && e.message) || e));
        last = e.message;
      }
    }
    if (!claims) {
      throw new Error('the key attestation does not verify: ' + last);
    }
    if (!claims.iat) {
      throw new Error('the key attestation carries no iat.');
    }
    if (opts.expRequired && !claims.exp) {
      throw new Error('a key attestation in a jwt proof must carry exp ' +
                      '(OpenID4VCI Appendix D.1).');
    }
    const keys = [].concat(claims.attested_keys || []).filter(function (k) {
      return !!k && typeof k === 'object' && !k.d && !k.priv;
    });
    if (!keys.length) {
      throw new Error('the key attestation attests no public key.');
    }
    if (opts.proofJwk) {
      const wanted = stsCrypto.jwkThumbprint(opts.proofJwk, {});
      const named = keys.some(function (k) {
        try {
          return stsCrypto.jwkThumbprint(k, {}) === wanted;
        } catch (e) {
          // A key with no thumbprint is not the proof's key.
          log.debug("Caught in VcIssuer.verifyKeyAttestation(): " +
                    ((e && e.message) || e));
          return false;
        }
      });
      if (!named) {
        throw new Error('the proof is signed by a key its key attestation ' +
                        'does not attest.');
      }
    } else {
      // THE `attestation` PROOF TYPE: the attestation is the proof, so its
      // nonce is the c_nonce (Appendix F.3).
      const expires = vciNonces.get(claims.nonce);
      if (!expires || expires < Date.now()) {
        throw new Error('the key attestation\'s nonce is not a c_nonce this ' +
                        'issuer handed out (or it was already used).');
      }
    }
    const levels = function (v: unknown): string[] {
      log.debug("Entering levels().");
      log.debug("Leaving levels().");
      return [].concat(v || []).map(String);
    };
    const out = { keys: keys, keyStorage: levels(claims.key_storage),
                  userAuthentication: levels(claims.user_authentication),
                  attester: by };
    log.debug("Leaving VcIssuer.verifyKeyAttestation(). By " + by + ".");
    return out;
  }

  // --- the wallet's proof of possession --------------------------------------
  // A JWT proof (OID4VCI): typ openid4vci-proof+jwt, the holder's public key in
  // the header as a JWK, and claims binding it to this issuer and to a c_nonce
  // this issuer handed out. Returns the holder JWK on success.
  // ASYNCHRONOUS SINCE THE WORKER POOL EXISTED. This is the third surface that
  // takes a JWS the CLIENT signed, and `proof_signing_alg_values_supported`
  // advertises every asymmetric algorithm in the shared table — the eleven
  // post-quantum and composite ones included. Verifying one of those takes
  // SECONDS on the thread that owns every listener here, and a wallet may send
  // a batch of them. See common/worker.js.
  private async verifyProofJwt(proofJwt, credentialIssuer) {
    const { log, logArtifact, jsonFromB64u, stsCrypto, vciNonces } = this.deps;
    log.debug("Entering VcIssuer.verifyProofJwt().");
    logArtifact('OID4VCI proof of possession', 'as received', proofJwt);
    const parts = String(proofJwt || '').split('.');
    if (parts.length !== 3) {
      throw new Error('the proof is not a three-part JWS.');
    }
    let header, claims;
    try {
      header = jsonFromB64u(parts[0]);
      claims = jsonFromB64u(parts[1]);
    } catch (e) {
      log.debug("Caught in VcIssuer.verifyProofJwt(): " +
                ((e && e.message) || e));
      throw new Error('the proof is not a readable JWT: ' + e.message);
    }

    if (header.typ !== 'openid4vci-proof+jwt') {
      throw new Error('the proof typ must be openid4vci-proof+jwt, got "' +
                      header.typ + '".');
    }
    if (!header.jwk) {
      throw new Error('the proof header carries no jwk (this ' +
                      'issuer binds to a JWK).');
    }
    // THE SAME LIST THE METADATA ADVERTISES, from the same place — this said
    // ['ES256','RS256'] while the metadata had grown to eleven, so a wallet
    // that read the metadata, chose EdDSA and signed a perfectly good proof was
    // told its algorithm was unsupported by the very issuer that had just
    // advertised it. Two lists describing one capability is how that happens;
    // there is now one, in common/crypto.js.
    if (stsCrypto.JWS_ASYMMETRIC_ALGS.indexOf(header.alg) < 0) {
      throw new Error('unsupported proof alg "' + header.alg + '"; this ' +
        'issuer accepts ' + stsCrypto.JWS_ASYMMETRIC_ALGS.join(', ') + '.');
    }
    if (claims.aud !== credentialIssuer) {
      throw new Error('the proof aud ("' + claims.aud + '") is not this ' +
                      'credential issuer ("' +
                      credentialIssuer + '").');
    }
    if (!claims.iat ||
        Math.abs(Date.now() / 1000 - claims.iat) >
          this.proofIatWindowSeconds()) {
      throw new Error('the proof iat is missing or more than ' +
                      this.proofIatWindowSeconds() +
                      ' seconds from now (oid4vci.proofIatWindowS).');
    }
    const expires = vciNonces.get(claims.nonce);
    if (expires) {
      vciNoncesCount.hit();
    } else {
      vciNoncesCount.miss();
    }
    if (!expires) {
      throw new Error('the proof nonce is not one this issuer ' +
                      'handed out (or was already used).');
    }

    // The c_nonce belongs to the REQUEST, not to a single proof: a batch
    // request carries several proofs and they all quote the same one (section
    // 8.2). So it is not spent here — the caller spends it once, after every
    // proof in the request has been verified. Consuming it per proof made the
    // second proof of any batch fail, which is exactly the bug batch issuance
    // uncovered.
    if (expires < Date.now()) {
      vciNonces.delete(claims.nonce);
      throw new Error('the proof nonce has expired.');
    }

    // Delegated to the one verifier in common/crypto.js, with the algorithm
    // list named explicitly (RFC 8725 section 3.1). What was here before
    // hardcoded 'sha256' and special-cased ES256 alone for the ECDSA encoding,
    // so ES384 and ES512 would have been checked against the WRONG DIGEST — a
    // signature this issuer would reject as bad while it was perfectly good —
    // and EdDSA and ES256K could not be verified at all.
    //
    // A proof of possession must be signed with a key the wallet holds, so the
    // algorithm has to be asymmetric: a MAC would need the issuer to know the
    // wallet's secret, which would make the proof prove nothing.
    try {
      await stsCrypto.verifyCompactJwsAsync(String(proofJwt || ''), header.jwk,
        { algorithms: stsCrypto.JWS_ASYMMETRIC_ALGS });
    } catch (e) {
      log.debug("Caught in VcIssuer.verifyProofJwt(): " +
                ((e && e.message) || e));
      throw new Error('the proof signature does not verify with the key in ' +
        'its own header: ' + e.message);
    }
    logArtifact('OID4VCI proof of possession', 'verified',
                { header: header, payload: claims });
    // A KEY ATTESTATION IN THE HEADER (Appendix F.1), verified and kept with
    // the key; required where `oid4vci.keyAttestationRequired` says so.
    let attestation = null;
    if (header.key_attestation) {
      attestation = this.verifyKeyAttestation(String(header.key_attestation),
                                              { proofJwk: header.jwk,
                                                expRequired: true });
    } else if (this.deps.config.value('oid4vci.keyAttestationRequired') ===
               true) {
      throw new Error('this issuer requires a key attestation ' +
                      '(key_attestations_required), and the proof carries ' +
                      'none in its key_attestation header.');
    }
    log.debug("Leaving VcIssuer.verifyProofJwt(). The proof is good.");
    return { jwk: header.jwk, attestation: attestation };
  }

  // --- SD-JWT VC construction (RFC 9901) -------------------------------------
  // A Disclosure is base64url(JSON [salt, claim name, claim value]); the digest
  // that goes in _sd is base64url(SHA-256(the ASCII of that base64url string)).
  private makeDisclosure(name, value) {
    const { log, b64u, crypto } = this.deps;
    log.debug("Entering VcIssuer.makeDisclosure(). name=" + name);
    const salt = b64u(crypto.randomBytes(16));
    const encoded = b64u(Buffer.from(JSON.stringify([salt, name, value]),
                                     'utf8'));
    const digest = b64u(crypto.createHash('sha256')
                              .update(encoded, 'ascii')
                              .digest());
    log.debug("Leaving VcIssuer.makeDisclosure(). digest=" + digest);
    return { salt: salt, name: name, value: value, encoded: encoded,
             digest: digest };
  }

  private async buildSdJwtVc(subjectClaims, holderJwk, credentialIssuer,
                             issuerDid, status) {
    const { log, logArtifact, b64u, certificateHeaderFor, crypto, stsCrypto,
            VCI_VCT } = this.deps;
    // An extension, not the spec: draft-ietf-oauth-sd-jwt-vc defines no
    // DID-based issuer signature mechanism. When one is configured the iss
    // becomes the DID and a wallet resolves it for the verification key instead
    // of fetching /.well-known/jwt-vc-issuer. cnf.jwk is untouched — holder
    // binding is RFC 7800 either way, and a DID there would be nobody's
    // convention.
    log.debug("Entering VcIssuer.buildSdJwtVc().");
    const issuerId = issuerDid || credentialIssuer;
    logArtifact('SD-JWT VC', 'the claims it will assert, before any of them ' +
                             'are hidden',
                { subjectClaims: subjectClaims, holderJwk: holderJwk,
                  credentialIssuer: credentialIssuer });
    const now = Math.floor(Date.now() / 1000);
    // Everything the holder can choose to disclose, one Disclosure each. sub is
    // not among them: it stays a plain claim, so the credential always says who
    // it is about.
    const disclosures = Object.keys(subjectClaims)
      .filter((name) => { return name !== 'sub'; })
      .map((name) => {
        return this.makeDisclosure(name, subjectClaims[name]);
      });
    // A decoy digest: RFC 9901 section 4.2.5 — hash a random value so the count
    // of _sd entries does not reveal how many claims there really are.
    const decoy = b64u(crypto.createHash('sha256')
                             .update(b64u(crypto.randomBytes(16)), 'ascii')
                             .digest());
    const digests = disclosures.map((d) => { return d.digest; })
                               .concat([decoy])
                               .sort();

    const signer = await this.credentialSignerAsync();
    const payload: Record<string, any> = {
      iss: issuerId,
      nbf: now,
      exp: now + this.credentialLifetimeSeconds(),
      vct: VCI_VCT,
      sub: subjectClaims.sub || 'urn:uuid:' + crypto.randomUUID(),
      cnf: { jwk: holderJwk },
      _sd_alg: 'sha-256',
      _sd: digests
    };
    // THE STATUS REFERENCE (draft-ietf-oauth-status-list section 6.2), in the
    // clear: a verifier has to find it without a Disclosure.
    if (status && status.status) {
      payload.status = status.status;
    }
    logArtifact('SD-JWT VC', 'before signing',
                { header: { alg: signer.alg, typ: 'dc+sd-jwt',
                            kid: signer.headerKid },
                  payload: payload,
                  disclosures: disclosures.map((d) => {
                    return { name: d.name, value: d.value, salt: d.salt,
                             digest: d.digest, encoded: d.encoded };
                  }),
                  decoyDigest: decoy });

    // iat is added by the signer (jsonwebtoken drops a payload iat when it is
    // told not to timestamp, so it is left to do it).
    // `oid4vci.credentialCertificateHeader` decides the `x5c` / `x5u` — and
    // SD-JWT VC section 3.5 names `x5c` as one of the ways a verifier may find
    // the issuer's key, which is the case this setting exists for.
    const issuerJwt = await stsCrypto.signJwsAsync(payload, signer.key, {
      algorithm: signer.alg,
      header: Object.assign(certificateHeaderFor('vci-credential', signer.alg,
                                                 signer.kid),
                            { alg: signer.alg, typ: 'dc+sd-jwt',
                              kid: signer.headerKid })
    });
    logArtifact('SD-JWT VC issuer-signed JWT', 'after signing', issuerJwt);

    // Combined Serialization: <JWT>~<D1>~...~<Dn>~ (the trailing ~ is required
    // when no Key Binding JWT is present).
    const serialized = [issuerJwt].concat(disclosures.map(
        (d) => { return d.encoded; })).join('~') + '~';
    logArtifact('SD-JWT VC', 'after signing, as it will be sent (Combined ' +
                             'Serialization)', serialized);
    log.debug("Leaving VcIssuer.buildSdJwtVc(). " + disclosures.length + " " +
        "disclosure(s) plus 1 decoy digest.");
    return { credential: serialized, disclosures: disclosures, payload: payload,
             decoy: decoy };
  }

  // A W3C Verifiable Credential secured as a JWT (OID4VCI format jwt_vc_json).
  //
  // The VC-JWT encoding of VCDM 1.1: the credential object goes in the `vc`
  // claim, and the JWT's own registered claims carry the parts that would
  // otherwise be duplicated inside it — iss is the issuer, sub the credential
  // subject, nbf/exp the validity window, jti the credential id.
  //
  // Two things to notice, because they are what the workflow is meant to show:
  // there are NO Disclosures and no _sd digests — every claim is in the clear
  // in the payload, so a holder presenting this discloses all of it; and holder
  // binding is the same cnf.jwk this issuer puts in an SD-JWT VC, but what
  // proves possession at presentation time is a Verifiable Presentation JWT
  // signed with that key rather than a Key Binding JWT.
  private async buildJwtVcJson(subjectClaims, holderJwk, credentialIssuer,
                               issuerDid, status) {
    const { log, logArtifact, certificateHeaderFor, crypto, stsCrypto,
            VCI_JWT_TYPES, VC_CONTEXT } = this.deps;
    // As for ldp_vc, naming the issuer by DID is ordinary in a W3C credential
    // rather than an extension — this is VCDM, and the DID goes in both the
    // JWT's iss and the credential's own issuer, which must agree. It is wired
    // here for the same reason it is wired there: issuerDidFor() can return a
    // DID for this format (the startup flag covers every JOSE-secured
    // configuration), and a builder that took the argument and ignored it would
    // issue https-named credentials from an issuer whose metadata said
    // otherwise.
    log.debug("Entering VcIssuer.buildJwtVcJson().");
    const issuerId = issuerDid || credentialIssuer;
    logArtifact('jwt_vc_json credential', 'the claims it will assert',
                { subjectClaims: subjectClaims, holderJwk: holderJwk,
                  credentialIssuer: credentialIssuer });
    const now = Math.floor(Date.now() / 1000);
    const exp = now + this.credentialLifetimeSeconds();
    const signer = await this.credentialSignerAsync();
    const subjectId = subjectClaims.sub || ('urn:uuid:' + crypto.randomUUID());

    // credentialSubject.id is the subject identifier; the rest of the claims
    // sit beside it. `sub` is not repeated inside as a claim of its own — it IS
    // the id.
    const credentialSubject = { id: subjectId };
    Object.keys(subjectClaims).forEach((name) => {
      if (name !== 'sub') {
        credentialSubject[name] = subjectClaims[name];
      }
    });

    const vc: Record<string, any> = {
      '@context': [VC_CONTEXT],
      type: VCI_JWT_TYPES,
      issuer: issuerId,
      issuanceDate: new Date(now * 1000).toISOString(),
      expirationDate: new Date(exp * 1000).toISOString(),
      credentialSubject: credentialSubject
    };
    // BOTH STATUS MECHANISMS: the credential is a W3C one, so Bitstring
    // Status List entries in `credentialStatus`, and a JWT, so the Token
    // Status List claim too. vc_status.ts's header says why one index serves
    // both.
    if (status && status.credentialStatus) {
      vc.credentialStatus = status.credentialStatus;
    }
    const payload: Record<string, any> = {
      iss: issuerId,
      sub: subjectId,
      nbf: now,
      exp: exp,
      jti: 'urn:uuid:' + crypto.randomUUID(),
      cnf: { jwk: holderJwk },
      vc: vc
    };
    if (status && status.status) {
      payload.status = status.status;
    }
    logArtifact('jwt_vc_json credential', 'before signing',
                { header: { alg: signer.alg, typ: 'JWT',
                            kid: signer.headerKid },
                  payload: payload });

    const token = await stsCrypto.signJwsAsync(payload, signer.key, {
      algorithm: signer.alg,
      header: Object.assign(certificateHeaderFor('vci-credential', signer.alg,
                                                 signer.kid),
                            { alg: signer.alg, typ: 'JWT',
                              kid: signer.headerKid })
    });
    logArtifact('jwt_vc_json credential', 'after signing, as it will be sent',
                token);
    log.debug("Leaving VcIssuer.buildJwtVcJson(). " +
              (Object.keys(credentialSubject).length - 1) +
              " claim(s), none of them selectively disclosable.");
    // `disclosures` is deliberately an empty array rather than absent: the
    // callers count them for logging, and "this format has none" is the honest
    // answer.
    return { credential: token, disclosures: [], payload: payload, vc: vc };
  }

  // ---------------------------------------------------------------------------
  // THE MEMBERS AN ldp_vc CREDENTIAL SUBJECT MAY CARRY, checked against the
  // context this process actually loaded rather than against a list.
  //
  // vc_claims.ts names a JSON-LD term per configurable attribute, and those
  // names were read off contexts/idptools_identity_v1.json by hand. Two files
  // agreeing by hand is a drift waiting to happen, and the way this one would
  // announce itself is the worst available: jsonld canonicalizes with `safe:
  // true`, so an undefined term THROWS, inside a cryptosuite, at the moment a
  // wallet asks for a credential.
  //
  // So the term list is filtered through the context bbs2023.js loaded. A term
  // that is not in it is dropped with an error in the log — the credential is
  // one claim short, which is visible and survivable, where the throw is
  // neither. The context is fetched through that module's own document loader
  // so there is no second reader of that file to keep right.
  // ---------------------------------------------------------------------------
  private async identityContextTerms() {
    const { log, bbs2023, errorCodes } = this.deps;
    log.debug("Entering VcIssuer.identityContextTerms().");
    try {
      const loaded =
        await bbs2023.documentLoader(bbs2023.IDENTITY_CONTEXT_URL);
      const terms = (loaded && loaded.document &&
                     loaded.document['@context']) || {};
      log.debug("Leaving VcIssuer.identityContextTerms(). The context " +
                "defines " + Object.keys(terms).length + " term(s).");
      return terms;
    } catch (e) {
      log.debug("Caught in VcIssuer.identityContextTerms(): " +
                ((e && e.message) || e));
      // Cannot happen while the context is vendored — bbs2023.js reads it at
      // require time and this service does not start without it — but a caught
      // failure here costs one claim and an uncaught one costs the credential.
      log.error(errorCodes.tag('STS-VC-0004') +
                'the identity JSON-LD context could not be read; no ' +
                'configured claim will be put in an ldp_vc credential this ' +
                'time: ' + e.message);
      log.debug("Leaving VcIssuer.identityContextTerms(). It could not be " +
                "read.");
      return {};
    }
  }

  private async ldpSubjectMembers(subjectClaims) {
    const { log, errorCodes, vcClaims } = this.deps;
    log.debug("Entering VcIssuer.ldpSubjectMembers().");
    const members = vcClaims.ldpSubjectFrom(subjectClaims);
    const terms = await this.identityContextTerms();
    Object.keys(members).forEach((term) => {
      if (!Object.prototype.hasOwnProperty.call(terms, term)) {
        log.error(errorCodes.tag('STS-VC-0005') +
                  'vc_claims.js maps a configured attribute to the JSON-LD ' +
                  'term "' + term +
                  '", which contexts/idptools_identity_v1.json does not ' +
                  'define; it is left out of this credential rather than ' +
                  'failing the signature.');
        delete members[term];
      }
    });
    const omitted = vcClaims.ldpOmitted();
    if (omitted.length) {
      log.debug("ldpSubjectMembers(): " + omitted.join(', ') + " is/are " +
                "configured and have no term in this format, so this " +
                "credential does not carry them.");
    }
    log.debug("Leaving VcIssuer.ldpSubjectMembers(). " +
              Object.keys(members).length + " member(s).");
    return members;
  }

  // A W3C credential with an EMBEDDED bbs-2023 proof (OID4VCI format ldp_vc).
  //
  // Async, unlike the other two, because canonicalization is — which is why
  // buildCredentialFor and the credential endpoint are async as well.
  //
  // Holder binding differs from the other formats by necessity: there is no
  // cnf.jwk here. The holder is named by credentialSubject.id, a did:jwk built
  // from the key it proved possession of, and what proves possession at a
  // sign-in is a Data Integrity proof by that did:jwk over the presentation
  // (`vc_data_integrity.ts`, rule 3at). This comment said did:key and "no
  // separate signature by the holder" until 2026-09-21, both since changed.
  private async buildLdpVc(subjectClaims, holderJwk, credentialIssuer,
                            issuerDid, status) {
    const { log, logArtifact, b64u, bbsKeyPair, bbs2023, VCI_JWT_TYPES
            } = this.deps;
    // VC Data Model 2.0 is DID-native, so naming the issuer by DID here is
    // ordinary rather than an extension. The verification method moves with it:
    // a DID URL fragment into this issuer's DID document instead of a
    // dereferenceable https URL.
    log.debug("Entering VcIssuer.buildLdpVc().");
    const issuerId = issuerDid || credentialIssuer;
    const bbsVerificationMethod = issuerDid ? issuerDid + '#bbs-1'
                                            : credentialIssuer + '/bbs/keys/1';
    const keys = await bbsKeyPair();
    const now = Math.floor(Date.now() / 1000);
    // THE HOLDER, as the did:jwk of the key the wallet proved at issuance —
    // the one binding this format has, and what the holder's Data Integrity
    // proof must verify against at presentation. Built by the library that
    // verifies it, so the public members a key type needs (EC crv/x/y, OKP
    // crv/x, RSA n/e, AKP alg/pub) are one list: this wrote EC's four for
    // every key, so an Ed25519 or ML-DSA holder got a did:jwk naming no key.
    void b64u;
    const subjectId = this.deps.vcDataIntegrity.didJwkOf(holderJwk);
    const unsecured: Record<string, any> = {
      '@context': ['https://www.w3.org/ns/credentials/v2',
                   bbs2023.IDENTITY_CONTEXT_URL],
      type: VCI_JWT_TYPES,
      issuer: issuerId,
      validFrom: new Date(now * 1000).toISOString(),
      validUntil: new Date((now + this.credentialLifetimeSeconds()) * 1000)
        .toISOString(),
      credentialSubject: Object.assign(
        { id: subjectId }, await this.ldpSubjectMembers(subjectClaims))
    };
    if (status && status.credentialStatus) {
      unsecured.credentialStatus = status.credentialStatus;
    }
    logArtifact('ldp_vc credential', 'before signing', unsecured);
    const issued = await bbs2023.issue(unsecured, {
      verificationMethod: bbsVerificationMethod,
      created: new Date(now * 1000).toISOString()
    }, keys.secretKey, keys.publicKey);

    // Verified immediately, by this service, before it is handed out: the
    // requirement is that the STS validate every crypto operation, and an
    // issuer that cannot verify its own output has no business emitting it.
    const check = await bbs2023.verifyBase(issued.credential, keys.publicKey);
    if (!check.ok) {
      log.debug("Leaving VcIssuer.buildLdpVc(). It does not verify.");
      throw new Error('the ldp_vc credential this issuer just ' +
                      'built does not verify');
    }

    logArtifact('ldp_vc credential',
                'after signing (' + issued.statements.length + ' ' +
                'statements)',
                issued.credential);
    log.debug("Leaving VcIssuer.buildLdpVc(). " + issued.statements.length +
              " canonical statement(s).");
    return { credential: issued.credential, disclosures: [],
             payload: issued.credential,
             statements: issued.statements,
             validFrom: unsecured.validFrom,
             validUntil: unsecured.validUntil };
  }

  // Mint whichever format the requested configuration names.
  // WHO THE ACCESS TOKEN SAYS THE CREDENTIAL IS ABOUT, as one function because
  // it is now asked twice and the two answers must be the same string.
  //
  // subjectClaimsFrom() asks it to pick the person a credential describes; the
  // credential endpoint asks it so that buildCredentialFor() can tell the
  // directory whose the holder DID is. Written out at both sites, a change to
  // either — the day this reads `sub` before `preferred_username`, say — would
  // link a DID to a person nothing else here is filed under, and the symptom
  // would be a second directory entry rather than an error.
  private holderNameFrom(accessToken) {
    const { log, jsonFromB64u } = this.deps;
    log.debug("Entering VcIssuer.holderNameFrom().");
    let t: any = {};
    try {
      const parts = String(accessToken || '').split('.');
      if (parts.length === 3) {
        t = jsonFromB64u(parts[1]) || {};
      }
    } catch (e) {
      log.debug("Caught in VcIssuer.holderNameFrom(): " +
                ((e && e.message) || e));
      // An opaque token, exactly as subjectClaimsFrom() treats one: the mock
      // default is the answer, not an error.
      t = {};
    }
    log.debug("Leaving VcIssuer.holderNameFrom().");
    return t.preferred_username || t.sub || 'mock-holder';
  }

  // `person` is the subject a VERIFIED, undisowned access token named (see
  // signInSubjectOf()), or ''. It files the credential under that person on
  // the issued register, which an ldp_vc's own subject — a did:jwk — cannot.
  async buildCredentialFor(configId, subjectClaims, holderJwk,
                           credentialIssuer, issuerDid,
                           holderName, person?: string) {
    const { log, stats, vciFormatOf, vcStatus } = this.deps;
    log.debug("Entering VcIssuer.buildCredentialFor(). configId=" + configId);
    const format = vciFormatOf(configId);
    // THE STATUS-LIST INDEX FIRST (vc_status.ts), because the reference is
    // signed into the credential.
    const status = await vcStatus.allocate({
      base: credentialIssuer, format: format, configId: configId,
      expiresAt: Date.now() + this.credentialLifetimeSeconds() * 1000 });
    let built;
    if (format === 'ldp_vc') {
      built = await this.buildLdpVc(subjectClaims, holderJwk,
                                    credentialIssuer, issuerDid, status);
    } else if (format === 'jwt_vc_json') {
      built = await this.buildJwtVcJson(subjectClaims, holderJwk,
                                        credentialIssuer, issuerDid, status);
    } else {
      built = await this.buildSdJwtVc(subjectClaims, holderJwk,
                                      credentialIssuer, issuerDid, status);
    }
    // Counted here, at the one point all three formats meet. The expiry is read
    // from whichever member the format uses to state it — `exp` in the two JWT
    // forms, `validUntil` in the Data Integrity one — because the console's
    // "still valid" column has to mean the same thing across all three or it
    // means nothing.
    const payload = built.payload || {};
    const expiresAt = payload.exp ? payload.exp * 1000
      : (Date.parse((built.credential &&
                     built.credential.validUntil) || '') || 0);
    const subject = payload.sub ||
                    (payload.credentialSubject &&
                     payload.credentialSubject.id) ||
                    subjectClaims.sub || '';

    const artifact = stats.recordCredential(format, {
      configId: configId,
      subject: subject,
      person: person && person !== subject ? person : '',
      expiresAt: expiresAt
    });
    vcStatus.attach(status.key, artifact && artifact.key);
    built.artifactKey = (artifact && artifact.key) || '';
    built.statusKey = status.key;
    built.expiresAt = expiresAt;
    // The credential's subject identifier, when it is a DECENTRALIZED
    // IDENTIFIER, is a SECOND identity and gets its own record — and its own
    // directory entry.
    //
    // It is not the same person as the one recorded in subjectClaimsFrom():
    // that is whoever the access token named, and this is the holder key the
    // wallet proved possession of, turned into a did:jwk by buildLdpVc(). One
    // wallet asking for credentials for one person can hold several, and a
    // directory that filed them all under the access token's name could not
    // tell them apart.
    //
    // Guarded on `did:` deliberately, and the two formats that are NOT DIDs are
    // why: an SD-JWT VC's subject is the access token's own `sub` (already
    // recorded above, so a second call would only double the count), and where
    // the token carries no sub at all it is a `urn:uuid:` minted fresh for this
    // one credential. Recording those would put a directory entry per issuance
    // in a store with a fixed maximum, and evict real people to hold
    // identifiers nothing will ever present again.
    //
    // One call per credential rather than per request, which is the right grain
    // here: a batch of three proofs is three holder keys and therefore three
    // DIDs.
    if (/^did:[a-z0-9]+:/i.test(subject)) {
      stats.recordAuthentication({
        presented: subject,
        // WHOSE DID IT IS, which this function knows and nothing downstream can
        // work out. The DIRECTORY uses it to put this identifier on that
        // person's entry rather than on a second one named by a digest — see
        // didPlan() in ldap_server.js, where the reversal of the paragraph
        // above is argued. The two records stay two: /admin/users still shows
        // the DID as its own identity, because a holder key and the person a
        // credential is about are genuinely different things to have seen.
        linkedTo: holderName,
        protocol: 'OpenID4VCI',
        method: 'credential subject (' + format + ', bound to the holder ' +
                'key the wallet proved possession of)',
        note: 'The subject identifier of an issued credential. It is a DID ' +
              'rather than a name, and nobody authenticated as it — the ' +
              'wallet proved possession of the key it is derived from.'
      });
    }
    log.debug("Leaving VcIssuer.buildCredentialFor(). Minted one " + format +
              " credential.");
    return built;
  }

  // ---------------------------------------------------------------------------
  // WHICH CREDENTIALS MAY LATER SIGN SOMEBODY IN (2026-09-17, #38).
  //
  // `vc_issued.ts` is the register and its header is the argument; this is
  // the issuer's half, in two calls. `signInSubjectOf()` is asked while the
  // access token is still in hand — the deferred endpoint is reached with a
  // transaction id and a possibly different token, so what the ORIGINAL
  // request established is carried on the deferred record rather than asked
  // again of whatever turns up later. `rememberIssued()` writes one row per
  // credential actually handed over, at the two places a credential leaves.
  //
  // **THE CREDENTIAL IS UNCHANGED.** Its `sub` was already the access token's,
  // which for a person this realm authenticated is `urn:uuid:<entryUUID>`;
  // nothing is added to it, because what the register knows — that this
  // realm VERIFIED the token that named the subject — is not something a
  // claim in the credential could prove to anybody but this realm, which has
  // the register anyway.
  // ---------------------------------------------------------------------------
  //
  // **A DISOWNED TOKEN COUNTS AS UNVERIFIED HERE (2026-09-17).** A sign-out
  // marks the session's access tokens revoked (`stats.revoke()`), and a token
  // still inside its `exp` verifies all the same. Counted as verified, it let
  // whoever still held it mint a credential that signs its subject in at
  // `/authn/wallet` — a sign-out undone by the token it was meant to cut off.
  // The credential is still ISSUED on such a token, as it always was (this
  // endpoint has never consulted revocation, and refusing is a separate
  // decision); what it no longer gets is the register row.
  private signInSubjectOf(presented: any): string {
    const { log, stats, vcIssued, VCI_CONFIGS } = this.deps;
    log.debug("Entering VcIssuer.signInSubjectOf().");
    const scopes = Object.keys(VCI_CONFIGS).map(function (id) {
      return VCI_CONFIGS[id].scope;
    });
    const claims = presented && presented.claims;
    const disowned = !!(claims && claims.jti && stats.isRevoked(claims.jti));
    if (disowned) {
      log.debug("VcIssuer.signInSubjectOf(): the access token was disowned " +
                "by a sign-out, so it verifies nobody for sign-in.");
    }
    const subject = vcIssued.subjectFromToken(claims,
      !!(presented && presented.verified) && !disowned, scopes);
    log.debug("Leaving VcIssuer.signInSubjectOf(). " +
              (subject ? "A person this realm verified." : "Nobody."));
    return subject;
  }

  private rememberIssued(issued: any[], holderJwks: any[], configId: string,
                         subject: string, attestations?: any[]): void {
    // ONE ROW PER CREDENTIAL FOR THE JOSE FORMATS, one row per holder key and
    // person for ldp_vc — `vc_issued.ts` argues the two kinds. Each row
    // carries the credential's issued-register handle and status-list entry,
    // which are two of the three ways it is later disowned.
    const { log, vcIssued, vciFormatOf, errorCodes } = this.deps;
    log.debug("Entering VcIssuer.rememberIssued(). " + issued.length +
              " credential(s).");
    if (!subject) {
      log.debug("Leaving VcIssuer.rememberIssued(). No verified subject, so " +
                "none of them may sign anybody in.");
      return;
    }
    const format = vciFormatOf(configId);
    issued.forEach(function (built, i) {
      try {
        vcIssued.record({
          credential: built && built.credential,
          format: format,
          configId: configId,
          subject: subject,
          holderJwk: holderJwks[i],
          expiresAt: Number(built && built.expiresAt) || 0,
          artifactKey: (built && built.artifactKey) || '',
          statusKey: (built && built.statusKey) || '',
          validFrom: (built && built.validFrom) || '',
          validUntil: (built && built.validUntil) || '',
          keyStorage: (attestations && attestations[i] &&
                       attestations[i].keyStorage) || [],
          userAuthentication: (attestations && attestations[i] &&
                               attestations[i].userAuthentication) || []
        });
      } catch (e) {
        log.debug("Caught in VcIssuer.rememberIssued(): " +
                  ((e && e.message) || e));
        // The credential has been issued either way; what is lost is its
        // ability to sign the holder in, which is said here and nowhere a
        // wallet would read it.
        log.error(errorCodes.tag('STS-VC-0068') +
                  'vc_issuer: an issued credential could not be recorded as ' +
                  'one that may sign its subject in: ' +
                  ((e && e.message) || e));
      }
    });
    log.debug("Leaving VcIssuer.rememberIssued().");
  }

  // THE ACCESS TOKEN AN OpenID4VCI ENDPOINT ACCEPTS (2026-09-18), asked by
  // the credential, deferred credential and notification endpoints alike.
  // `dpop.presentedAccessToken()` is the Bearer/DPoP check every protected
  // endpoint shares; what this adds is the one decision that differs by mode
  // (`mode.acceptsUnverifiedIssuerTokens()`). Development reads a token this
  // realm cannot verify unverified, because OID4VCI lets the authorization
  // server be somebody else. Product refuses it — through that function's own
  // `requireVerified` refusal, so there is one wording and one code for "not a
  // token this service can verify" — and refuses a token this realm REVOKED,
  // which is what UserInfo does with one and what a global sign-out means.
  // Answers the presented token, or null having answered the request itself.
  private presentedIssuerToken(req, res, where) {
    const { dpop, mode, stats, errorCodes, vciError, log } = this.deps;
    log.debug("Entering VcIssuer.presentedIssuerToken(). where=" + where);
    const strict = !mode.acceptsUnverifiedIssuerTokens();
    const presented = dpop.presentedAccessToken(req, res, where,
                                                { requireVerified: strict });
    if (!presented) {
      log.debug("Leaving VcIssuer.presentedIssuerToken(). Refused.");
      return null;
    }
    const claims = presented.claims || {};
    if (strict && claims.jti && stats.isRevoked(claims.jti)) {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
      errorCodes.mark(res, 'STS-VC-0086');
      vciError(res, 401, 'invalid_token',
        'This access token was revoked by this service, and ' + where +
        ' issues nothing on a revoked token.');
      log.debug("Leaving VcIssuer.presentedIssuerToken(). Revoked.");
      return null;
    }
    log.debug("Leaving VcIssuer.presentedIssuerToken(). verified=" +
              presented.verified);
    return presented;
  }

  // The claims the credential asserts.
  //
  // WHICH claims those are is configuration now (vc_claims.ts, set on
  // /admin/vc) and no longer the seven names that used to be written out here.
  // Where each VALUE comes from is that module's decision too and is stated
  // there: the access token first, then this person's LDAP entry, then a
  // persona invented from their username. What stays here is the two things
  // that are this file's own —
  //
  //   * `sub`, because each of the three formats names its subject differently
  //     and vc_claims.ts deliberately has no opinion about which.
  //   * WHO the credential is about, read off the access token exactly as
  //     before. The name is what everything downstream is keyed on: it selects
  //     the directory entry and seeds the persona, so `alice` gets the same
  //     invented person here that ldap_server.js wrote onto uid=alice,ou=users.
  subjectClaimsFrom(accessToken, configId) {
    const { log, jsonFromB64u, crypto, stats, vciFormatOf, vcClaims
            } = this.deps;
    log.debug("Entering VcIssuer.subjectClaimsFrom(). configId=" +
              (configId || '(none)'));
    let t: any = {};
    try {
      const parts = String(accessToken || '').split('.');
      if (parts.length === 3) {
        t = jsonFromB64u(parts[1]) || {};
      }
    } catch (e) {
      log.debug("Caught in VcIssuer.subjectClaimsFrom(): " +
                ((e && e.message) || e));
      // An opaque token — the mock defaults it is.
      log.debug("The access token is not a readable JWT; using the default " +
                "claims.");
    }
    const user = this.holderNameFrom(accessToken);
    // -------------------------------------------------------------------------
    // AND THAT PERSON IS RECORDED, which is the one funnel this subsystem was
    // missing.
    //
    // Every other family here calls stats.recordAuthentication() at the moment
    // a credential is ACCEPTED, and the embedded directory grows an entry off
    // the back of it (admin_stats.js's user observer). Issuance never did, and
    // the cost was visible in this function's own leaving-log: "with no
    // directory entry to read from". The people who reach this endpoint through
    // THIS service's authorization server were covered by accident — oauth2.js
    // records them at the token endpoint — but nobody else was, and "anybody
    // else" is not an edge case at a Credential Issuer: OID4VCI lets the
    // authorization server be somebody else entirely, so a FOREIGN access token
    // is the ordinary case and its subject had never been seen here.
    //
    // What is being recorded is a credential being ACCEPTED and not a sign-on,
    // and the method and note say so rather than leaving a reader of
    // /admin/users to assume otherwise. (tls_server.js drew the same line for a
    // verified client certificate until 2026-09-05, when a verified certificate
    // became a sign-on — `GET /tls/sign-in` since 2026-09-16; nothing here
    // did.) Nobody authenticated here; an access token was presented. In
    // development mode it may be one this realm cannot verify, and is read
    // unverified; product mode refuses one before this is reached
    // (`presentedIssuerToken()`, 2026-09-18).
    //
    // HERE rather than at the two endpoints, because this function is the
    // single point that decides who a credential is about: it is called once
    // per credential request and once when an issuance is deferred, so a batch
    // of five proofs is one record and not five, and a deferred credential is
    // not recorded twice.
    // -------------------------------------------------------------------------
    stats.recordAuthentication({
      presented: user,
      protocol: 'OpenID4VCI',
      method: 'credential request (the subject named by the presented ' +
              'access token)',
      sub: t.sub || '',
      client_id: t.client_id || t.azp || '',
      note: 'An access token was presented at the Credential Endpoint and ' +
            'the credential describes this subject. Nobody authenticated ' +
            'here, and this issuer does not verify access tokens it did not ' +
            'issue.'
    });
    // What the wallet asked for in its authorization_details, if it asked at
    // all (OID4VCI section 5.1.1). Null means it did not, which is not the same
    // as an empty selection: the whole configured set is issued, exactly as
    // before.
    const asked = this.requestedClaimPaths(accessToken, configId);
    const rows = asked ? vcClaims.rowsForPaths(asked, vciFormatOf(configId)) :
                 null;
    const built = vcClaims.subjectClaimsFor(user, t, rows);
    const claims = Object.assign({ sub: t.sub ||
                                        ('urn:uuid:' + crypto.randomUUID()) },
                                 built.claims);
    log.debug("Leaving VcIssuer.subjectClaimsFrom(). The credential will " +
              "describe " + user +
              " with " + built.report.length + " configured claim(s), " +
              (asked ? "the " + asked.length + " the wallet asked for, " : "") +
              (built.entryFound ? "read from their directory entry where it " +
                                  "has them."
                                : "with no directory entry to read from."));
    return claims;
  }

  // ---------------------------------------------------------------------------
  // WHICH CLAIMS THE WALLET ASKED FOR, or null if it asked for none in
  // particular.
  //
  // The request was made at the authorization endpoint, in the `claims` member
  // of an authorization_details entry (OID4VCI section 5.1.1), and it arrives
  // here inside the access token — the same route, and for the same reason, as
  // the credential_identifiers beside it: the token is signed by this service,
  // so a wallet cannot widen its own selection by editing anything, and the
  // credential endpoint needs no state to check it.
  //
  // Null rather than an empty array when nothing was asked for. The two are
  // genuinely different: no `claims` member means "whatever you issue", and an
  // empty one is not expressible at all (section A.1 requires a non-empty
  // array), so a caller that could not tell them apart would issue an empty
  // credential to every wallet that used a scope.
  // ---------------------------------------------------------------------------
  private requestedClaimPaths(accessToken, configId) {
    const { log, STS, stsCrypto } = this.deps;
    log.debug("Entering VcIssuer.requestedClaimPaths(). configId=" +
              (configId || '(none)'));
    let claims;
    try {
      // **THIS NOW APPLIES `oauth2.clockSkewS` AND DID NOT BEFORE 2026-08-27**,
      // which is a behaviour change rather than a refactor and is the point of
      // the change. `oauth2.js` has always said in capitals that every
      // read-back of one of our own tokens takes the configured allowance; this
      // file was outside the scope of that promise and quietly held a stricter
      // opinion, so a token that introspected active could be refused here
      // seconds before it should have been. The shared verifier applies it by
      // default.
      claims = stsCrypto.verifyJws(accessToken, STS.certPem);
    } catch (e) {
      log.debug("Caught in VcIssuer.requestedClaimPaths(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcIssuer.requestedClaimPaths(). The token is not " +
                "one of ours: " + e.message);
      return null;
    }
    const details = claims.authorization_details || [];
    let found = null;
    details.forEach((d) => {
      if (!d || !Array.isArray(d.claims) || !d.claims.length) {
        return;
      }
      // The entry for THIS credential. A token may authorize several
      // configurations and each carries its own selection, so matching on the
      // configuration is what keeps one credential's selection off another.
      if (configId && d.credential_configuration_id &&
          d.credential_configuration_id !== configId) {
        return;
      }
      found = d.claims.map((c) => { return (c || {}).path; })
                      .filter(Array.isArray);
    });
    log.debug("Leaving VcIssuer.requestedClaimPaths(). " +
              (found ? found.length + " claim(s) requested." : "None were " +
                  "requested."));
    return found;
  }

  // ---------------------------------------------------------------------------
  // The nonces a set of proofs quoted, spent together: one Credential Request,
  // one c_nonce, however many proofs.
  //
  // **ACROSS THE CLUSTER SINCE 2026-09-14 (#46), AND SO ASYNCHRONOUS.** The
  // delete below is the whole of "once" in one process, and in several it is a
  // write another node reads a moment later — two Credential Requests quoting
  // one c_nonce, sent to two nodes inside that moment, both verified their
  // proofs against a nonce each node still held and both were issued a
  // credential. So each distinct nonce is deleted here as before (the fast
  // path, and every other process's eventual refusal) and then SPENT THROUGH
  // `cluster_claims.claim()`: exactly one request wins it, on any node.
  //
  // That also closes the same race inside ONE process, which the delete alone
  // never did: `verifyProofJwt()` awaits the signature check, so two concurrent
  // requests could both find the nonce before either deleted it, and both were
  // answered. The claim is set before its first await, so the second is
  // refused.
  //
  // The claim lives for what is left of the nonce's own lifetime plus
  // CLAIM_SKEW_MS for clocks that disagree. A store that cannot be asked
  // refuses (fail closed). Nothing releases the claim: the nonce is already
  // gone from this process's map, and a claim given back without it would only
  // let another node that still holds it accept the replay.
  //
  // Resolves to `{ ok: true }` or `{ ok: false, errorCode, description }`.
  async spendProofNonces(proofJwts) {
    const { log, jsonFromB64u, errorCodes, clusterClaims, vciNonces
            } = this.deps;
    log.debug("Entering VcIssuer.spendProofNonces(). " + proofJwts.length +
              " proof(s).");
    const spent = [];
    const lifetimes = {};
    proofJwts.forEach((proof) => {
      let nonce;
      try {
        nonce = (jsonFromB64u(String(proof).split('.')[1]) || {}).nonce;
      } catch (e) {
        // Unreadable proofs never got this far; ignore it rather than throwing
        // after the credential has already been decided on.
        log.debug("Caught in VcIssuer.spendProofNonces(): a proof payload " +
                  "could not be read: " + ((e && e.message) || e));
        return;
      }
      if (!nonce || spent.indexOf(nonce) !== -1) {
        return;
      }
      const expires = Number(vciNonces.get(nonce));
      lifetimes[nonce] = isFinite(expires) && expires > 0
        ? Math.max(0, expires - Date.now()) : this.cNonceTtlMs();
      vciNonces.delete(nonce);
      spent.push(nonce);
    });
    for (const nonce of spent) {
      const claimed = await clusterClaims.claim({
        scope: 'oid4vci.c_nonce', value: nonce,
        ttlMs: lifetimes[nonce] + CLAIM_SKEW_MS });
      if (!claimed.ok && claimed.reason === 'used') {
        log.warn(errorCodes.tag('STS-VC-0050') + 'vc_issuer: a c_nonce the ' +
                 'proofs verified against was ALREADY SPENT by another ' +
                 'Credential Request, on this node or another against the ' +
                 'same store. Refused.');
        log.debug("Leaving VcIssuer.spendProofNonces(). Used elsewhere.");
        return { ok: false, errorCode: 'STS-VC-0050',
                 description: 'the proof nonce is not one this issuer handed ' +
                              'out (or was already used).' };
      }
      if (!claimed.ok) {
        log.error(errorCodes.tag('STS-VC-0051') + 'vc_issuer: whether a ' +
                  'c_nonce was already spent could not be asked of the claim ' +
                  'store (' + (claimed.why || 'no reason given') + '). The ' +
                  'Credential Request is refused.');
        log.debug("Leaving VcIssuer.spendProofNonces(). Store unavailable.");
        return { ok: false, errorCode: 'STS-VC-0051',
                 description: 'this issuer could not confirm the proof nonce ' +
                              'is unused; request a new c_nonce and retry.' };
      }
    }
    log.debug("Leaving VcIssuer.spendProofNonces(). Spent " + spent.length +
              " distinct nonce(s).");
    return { ok: true };
  }

  // ---------------------------------------------------------------------------
  // Which Credential Dataset identifiers an access token was granted.
  //
  // They were put into the token when it was issued, and the token is signed by
  // this service, so reading them back is a verification — a wallet cannot
  // award itself an identifier by editing anything.
  // ---------------------------------------------------------------------------
  private grantedIdentifiers(accessToken) {
    const { log, STS, stsCrypto } = this.deps;
    log.debug("Entering VcIssuer.grantedIdentifiers().");
    let claims;
    try {
      // Applies `oauth2.clockSkewS` since 2026-08-27 — see the note in
      // requestedClaimPaths() above; this was the second of the four sites that
      // had drifted away from the rule oauth2.js states.
      claims = stsCrypto.verifyJws(accessToken, STS.certPem);
    } catch (e) {
      // Not our token (or not valid): nothing was granted by us. The caller
      // still checks the token elsewhere; this only answers "what did we
      // grant".
      log.debug("Caught in VcIssuer.grantedIdentifiers(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcIssuer.grantedIdentifiers(). The token is not " +
                "one of ours: " + e.message);
      return [];
    }
    const details = claims.authorization_details || [];
    const out = [];
    details.forEach((d) => {
      (d.credential_identifiers || []).forEach((id) => { out.push(id); });
    });
    log.debug("Leaving VcIssuer.grantedIdentifiers(). " + out.length +
              " identifier(s).");

    return out;
  }

  private newNotificationId(accessToken) {
    const { log, b64u, crypto, offerTtlMs, notificationIds } = this.deps;
    log.debug("Entering VcIssuer.newNotificationId().");
    const id = b64u(crypto.randomBytes(12));
    notificationIds.set(id,
                        { accessToken: accessToken,
                          expires: Date.now() + offerTtlMs(), event: null });
    const now = Date.now();
    notificationIds.forEach((v, k) => {
      if (v.expires < now) {
        notificationIds.delete(k);
      }
    });
    log.debug("Leaving VcIssuer.newNotificationId(). " + id);
    return id;
  }

  private responseEncValues() {
    const { log } = this.deps;
    log.debug("Entering VcIssuer.responseEncValues().");
    log.debug("Leaving VcIssuer.responseEncValues().");
    return this.encValuesFrom('oid4vci.responseEncryptionEncValues');
  }

  private requestEncValues() {
    const { log } = this.deps;
    log.debug("Entering VcIssuer.requestEncValues().");
    log.debug("Leaving VcIssuer.requestEncValues().");
    return this.encValuesFrom('oid4vci.requestEncryptionEncValues');
  }

  // `oid4vci.requestEncryptionRequired`, a boolean that is OFF by default: a
  // mock that demanded encryption unless told otherwise would fail every
  // existing test with an error about something the test never mentioned.
  private vciRequestEncryptionRequired() {
    const { log, config } = this.deps;
    log.debug("Entering VcIssuer.vciRequestEncryptionRequired().");
    log.debug("Leaving VcIssuer.vciRequestEncryptionRequired().");
    return config.value('oid4vci.requestEncryptionRequired');
  }

  // ---------------------------------------------------------------------------
  // THE KEY IS A MEMBER OF THE REALM'S KEY SET SINCE 2026-09-12, AND THIS FILE
  // NO LONGER MAKES ONE.
  //
  // Until that date this block generated a process key at module load, took it
  // from `process.env.STS_VCI_REQUEST_ENC_KEY_PEM` in a request worker, and
  // kept a `realms.keyed()` map beside it that made a key per realm in a
  // process with no pool and SHARED the handed-down key in a process with one —
  // so in a dispatched service every realm's issuer could decrypt a request
  // encrypted to another realm's published key, and in no mode did the key
  // survive a restart.
  //
  // `helpers.requestEncryptionKeyFor()` answers with the AMBIENT realm's key
  // set's member now, and every property the old arrangement lacked comes from
  // the key set: per realm, sealed and written down in product mode, decrypted
  // only while used, and agreed across the front process and every request
  // worker by the key channel's first-generator-wins. `common/helpers.js`'s
  // makeRequestEncryptionKey() argues why it is there and why it is a plain key
  // rather than a leaf of the PKI hierarchy.
  //
  // **WHAT A WALLET SEES IS UNCHANGED**: one RSA-OAEP-256 key in
  // `credential_request_encryption.jwks`, a kid of `sts-req-enc-<thumbprint>`,
  // `use: enc`, `key_ops: ["encrypt"]` — per realm, at that realm's metadata.
  // ---------------------------------------------------------------------------
  private requestEncryptionKeys() {
    const { log, requestEncryptionKeyFor } = this.deps;
    log.debug("Entering VcIssuer.requestEncryptionKeys().");
    log.debug("Leaving VcIssuer.requestEncryptionKeys().");
    return requestEncryptionKeyFor();
  }

  credentialRequestEncryptionMetadata() {
    const { log } = this.deps;
    log.debug("Entering VcIssuer.credentialRequestEncryptionMetadata().");
    log.debug("Leaving VcIssuer.credentialRequestEncryptionMetadata().");
    return {
      jwks: { keys: [this.requestEncryptionKeys().publicJwk] },
      enc_values_supported: this.requestEncValues(),
      // zip_values_supported is deliberately absent: "If absent then no
      // compression algorithms are supported", and this issuer does not
      // decompress. Advertising a zip it then refused would make the metadata a
      // lie, which is the same rule the response side follows.
      encryption_required: this.vciRequestEncryptionRequired()
    };
  }

  // The mirror of encryptToJwe(): RSA-OAEP-256 unwrap of the content key, then
  // AES-GCM with the protected header as additional authenticated data. Written
  // out by hand for the same reason — having the steps visible is the point.
  //
  // Throws with a reason a caller can hand back to the wallet; every failure
  // here is the wallet's request being unusable, not an issuer fault.
  decryptJweRequest(compact) {
    const { log, logArtifact, stsCrypto } = this.deps;
    log.debug("Entering VcIssuer.decryptJweRequest().");
    // **THE MECHANICS MOVED TO `common/crypto.js` ON 2026-08-27; THE POLICY DID
    // NOT.** What is decided here is what THIS ENDPOINT accepts — which `enc`
    // values it advertised, and that the kid must be the issuer's current
    // request-encryption key — and those are OID4VCI section 10 facts about
    // this issuer rather than facts about JWE. What moved is the unwrap, the
    // AAD, the tag and the key-length check, which sat two hundred lines from
    // the encrypt half that had to agree with them exactly.
    //
    // The hand-rolled implementation was KEPT rather than replaced by a JOSE
    // library, for the reason encryptToJwe() has always given: having the steps
    // visible is the point of a mock. It is simply in one place now.
    const result = stsCrypto.decryptJweCompact(compact, {
      privateKey: this.requestEncryptionKeys().privateKey,
      allowedEnc: this.requestEncValues(),
      expectedKid: this.requestEncryptionKeys().publicJwk.kid
    });
    logArtifact('OID4VCI Credential Request',
                'JWE protected header as received', result.header);
    let body;
    try {
      body = JSON.parse(result.plaintext);
    } catch (e) {
      log.debug("Caught in VcIssuer.decryptJweRequest(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcIssuer.decryptJweRequest(). Not JSON.");
      throw new Error('the decrypted request is not JSON: ' + e.message);
    }
    logArtifact('OID4VCI Credential Request', 'after decryption', body);
    log.debug("Leaving VcIssuer.decryptJweRequest(). Decrypted " +
              result.plaintext.length + " characters.");
    return body;
  }

  private lastCredentialRequestRecord() {
    const { log, lastCredentialRequestStore } = this.deps;
    log.debug("Entering VcIssuer.lastCredentialRequestRecord().");
    log.debug("Leaving VcIssuer.lastCredentialRequestRecord().");
    return lastCredentialRequestStore.get(LAST_REQUEST_KEY) ||
      { seen: false };
  }

  // Written WHOLE through the store's `set()`, which is the journalled door.
  private recordLastCredentialRequest(record) {
    const { log, lastCredentialRequestStore } = this.deps;
    log.debug("Entering VcIssuer.recordLastCredentialRequest().");
    lastCredentialRequestStore.set(LAST_REQUEST_KEY, record);
    log.debug("Leaving VcIssuer.recordLastCredentialRequest().");
  }

  // What either encrypted-capable endpoint does with its request body.
  //
  // Returns {body} or {error}. The caller answers; this decides. Both endpoints
  // go through it so the credential and deferred paths cannot drift — section
  // 10 applies identically to each, and the deferred one is the easy one to
  // forget.
  readPossiblyEncryptedRequest(req) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcIssuer.readPossiblyEncryptedRequest().");
    const contentType = String(req.get('content-type') || '').toLowerCase();
    const encrypted = contentType.indexOf('application/jwt') === 0;
    if (!encrypted) {
      if (this.vciRequestEncryptionRequired()) {
        // Section 10: "When encryption of a message was required but the
        // received message is unencrypted, it SHOULD be rejected."
        log.debug("Leaving VcIssuer.readPossiblyEncryptedRequest(). " +
                  "Refused: encryption is required.");
        return {
          errorCode: 'STS-VC-0006',
          error: 'invalid_encryption_parameters',
          description: 'This issuer advertises ' +
            'credential_request_encryption.encryption_required = true, so ' +
            'the Credential Request must be a JWE sent as application/jwt.'
        };
      }
      // Every content type arrives as raw text here (app.js's body parser takes
      // all of them), so the plain path still has to parse its own JSON.
      try {
        const body = typeof req.body === 'string' ?
          JSON.parse(req.body || '{}') : (req.body || {});
        this.recordLastCredentialRequest({
          seen: true, encrypted: false, path: req.path,
          contentType: contentType || null, at: new Date().toISOString()
        });
        log.debug("Leaving VcIssuer.readPossiblyEncryptedRequest(). Plain " +
                  "JSON.");
        return { body: body, encrypted: false };
      } catch (e) {
        log.debug("Caught in VcIssuer.readPossiblyEncryptedRequest(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0007') +
                  'the credential request body is not JSON: ' + e.message);
        log.debug("Leaving VcIssuer.readPossiblyEncryptedRequest().");
        return { errorCode: 'STS-VC-0007',
                 error: 'invalid_request',
                 description: 'The request body is not JSON: ' + e.message };
      }
    }
    try {
      const compact = typeof req.body === 'string' ? req.body : '';
      const body = this.decryptJweRequest(compact);
      // Recorded only once it has actually decrypted, so "encrypted" means the
      // issuer really read ciphertext rather than merely being sent a media
      // type.
      let header: any = {};
      try {
        header = JSON.parse(Buffer.from(compact.split('.')[0], 'base64url')
                                  .toString('utf8'));
      } catch (e2) {
        // It decrypted, so its protected header was read once already and this
        // cannot fail; the record below simply names no kid, alg or enc if it
        // somehow does.
        log.debug("Caught in VcIssuer.readPossiblyEncryptedRequest(): the " +
                  "header would not re-read: " + e2.message);
      }
      this.recordLastCredentialRequest({
        seen: true, encrypted: true, path: req.path,
        kid: header.kid || null, alg: header.alg || null,
        enc: header.enc || null,
        at: new Date().toISOString()
      });
      log.debug("Leaving VcIssuer.readPossiblyEncryptedRequest(). " +
                "Decrypted.");
      return { body: body, encrypted: true };
    } catch (e) {
      log.debug("Caught in VcIssuer.readPossiblyEncryptedRequest(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0008') +
                'the encrypted Credential Request could not be read: ' +
                e.message);
      log.debug("Leaving VcIssuer.readPossiblyEncryptedRequest().");
      return { errorCode: 'STS-VC-0008',
               error: 'invalid_encryption_parameters',
               description: e.message };
    }
  }

  private encryptionProblem(encryption) {
    const { log } = this.deps;
    log.debug("Entering VcIssuer.encryptionProblem().");
    const jwk = encryption.jwk;
    if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
      log.debug("Leaving VcIssuer.encryptionProblem(). The key is unusable.");
      return 'credential_response_encryption.jwk must be an RSA public key; ' +
             'this issuer encrypts with ' +
             VCI_ENC_ALG + '.';
    }
    const alg = jwk.alg || encryption.alg || VCI_ENC_ALG;
    if (alg !== VCI_ENC_ALG) {
      log.debug("Leaving VcIssuer.encryptionProblem(). Unsupported alg " +
                alg);
      return 'This issuer supports alg ' + VCI_ENC_ALG + ' only; "' + alg +
             '" was requested.';
    }
    if (!encryption.enc) {
      log.debug("Leaving VcIssuer.encryptionProblem(). No enc.");
      return 'credential_response_encryption.enc is required (' +
             this.responseEncValues().join(' or ') + ').';
    }
    if (this.responseEncValues().indexOf(encryption.enc) === -1) {
      log.debug("Leaving VcIssuer.encryptionProblem(). Unsupported enc " +
                encryption.enc);
      return 'This issuer supports enc ' +
             this.responseEncValues().join(' or ') + '; "' + encryption.enc +
             '" was requested.';
    }
    if (encryption.zip) {
      log.debug("Leaving VcIssuer.encryptionProblem(). zip requested.");
      return 'This issuer does not compress responses, so zip cannot be used.';
    }
    log.debug("Leaving VcIssuer.encryptionProblem(). The parameters are " +
              "usable.");
    return "";
  }

  // A JWE in compact serialization: RSA-OAEP-256 for the content key, AES-GCM
  // for the content. Written out by hand rather than with a JOSE library,
  // because having the steps visible is the point of a mock.
  private encryptToJwe(plaintext, encryption) {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcIssuer.encryptToJwe(). enc=" + encryption.enc);
    // Still written out by hand rather than with a JOSE library — see
    // `common/crypto.js` Section 4, where that argument is now made once for
    // both directions. The wallet's key and the algorithm it asked for are this
    // endpoint's business; the CEK, the wrap, the AAD and the tag are not.
    const compact = stsCrypto.encryptJweCompact(plaintext, {
      jwk: encryption.jwk,
      enc: encryption.enc
    });
    log.debug("Leaving VcIssuer.encryptToJwe(). " + compact.length +
              " characters.");
    return compact;
  }

  // Every Credential Response goes out through here, so the encrypted and plain
  // paths cannot drift apart.
  private sendCredentialResponse(res, status, payload, encryption) {
    const { log, logArtifact } = this.deps;
    log.debug("Entering VcIssuer.sendCredentialResponse(). status=" + status +
              ", encrypted=" + !!encryption);
    res.set('Cache-Control', 'no-store');
    if (!encryption) {
      res.status(status).type('application/json')
         .send(JSON.stringify(payload));
      log.debug("Leaving VcIssuer.sendCredentialResponse(). Sent as JSON.");
      return;
    }
    logArtifact('OID4VCI Credential Response', 'before encryption', payload);
    const jwe = this.encryptToJwe(JSON.stringify(payload), encryption);
    logArtifact('OID4VCI Credential Response',
                'after encryption (JWE compact serialization)', jwe);

    // Section 10: an encrypted response is a JWT, and says so.
    res.status(status).type('application/jwt').send(jwe);
    log.debug("Leaving VcIssuer.sendCredentialResponse(). Sent as a JWE.");
  }

  // THE ROUTES, in the order this module always registered them (rule 1).
  // Called by `common/protocol_stack.ts` through `registerRoutes(app)`.
  registerRoutes(app: RouteApp): void {
    const { log, logArtifact, baseUrlOf, b64u, randomId, bbsKeyPair, vciError,
            crypto, config, bbs2023, dpop, errorCodes, vciBatchSize,
            VCI_CONFIGS, VCI_CONFIG_ID, configIdOfIdentifier, vciConfigIds,
            vciFormatOf, issuerDidFor, deferredIntervalS, deferredReadyMs,
            deferredAccessTokens, deferredTransactions, offerTtlMs, vciNonces,
            notificationIds }
      = this.deps;
    log.debug("Entering VcIssuer.registerRoutes().");

    app.get('/.well-known/openid-credential-issuer',
            this.sendVciMetadata.bind(this));

    app.get('/.well-known/openid-credential-issuer/*',
            this.sendVciMetadata.bind(this));

    app.get('/.well-known/jwt-vc-issuer',
            this.sendJwtVcIssuerMetadata.bind(this));

    app.get('/.well-known/jwt-vc-issuer/*',
            this.sendJwtVcIssuerMetadata.bind(this));

    // --- Nonce Endpoint ------------------------------------------------------
    app.post('/oid4vci/nonce', (req, res) => {
      log.debug("Entering the OID4VCI nonce endpoint.");
      const nonce = b64u(crypto.randomBytes(24));
      const now = Date.now();
      // The expired go first, then the bound (oid4vci.cNonceCacheSize): a
      // c_nonce is a value this issuer handed out, so at the bound the
      // oldest goes and a wallet quoting it is told invalid_nonce and asks
      // again — what OpenID4VCI has it do for an expired one.
      vciNonces.forEach((expires, key) => {
        if (expires < now) {
          vciNonces.delete(key);
        }
      });
      cacheRegistry.makeRoom(vciNonces,
                             Number(this.deps.config.value(
                               'oid4vci.cNonceCacheSize')),
                             { counter: vciNoncesCount });
      vciNonces.set(nonce, now + this.cNonceTtlMs());
      res.set('Cache-Control', 'no-store');
      // The one thing OID4VCI says about DPoP by name: "The Credential Issuer
      // MAY provide a DPoP nonce in an HTTP header as defined in Section 8.2 of
      // RFC 9449. In this case, the Wallet uses the new nonce value in the DPoP
      // proof when presenting an access token at the Credential Endpoint."
      //
      // Which is a genuinely useful pairing rather than a curiosity: the wallet
      // is already making this call to get a c_nonce for its proof of
      // possession, so handing it a DPoP nonce at the same time costs no extra
      // round trip. The alternative is the 401/retry handshake, and this
      // endpoint is the one place in the flow where that can be skipped.
      //
      // Only when nonces are actually being required — a DPoP-Nonce header on a
      // server that will accept a proof without one teaches the wallet to send
      // a claim nothing checks.
      if (dpop.nonceModeOn()) {
        const dpopNonce = dpop.issueNonce();
        res.set('DPoP-Nonce', dpopNonce);
        log.debug("...and a DPoP nonce alongside it (OID4VCI's Nonce " +
                  "Response, RFC 9449 8.2).");
      }
      res.status(200).type('application/json').send(JSON.stringify({
        c_nonce: nonce,
        c_nonce_expires_in: Math.round(this.cNonceTtlMs() / 1000)
      }));
      log.debug("Leaving the OID4VCI nonce endpoint. Handed out one " +
                "c_nonce; " + vciNonces.size + " now outstanding.");
    });

    // The BBS public key the ldp_vc proofs are made with. A BBS key is not a
    // JWK — there is no registered kty for BLS12-381 G2 in the JOSE registry —
    // so it is published as its raw compressed bytes in multibase base64url,
    // which is what the Data Integrity multikey encoding uses and what
    // verificationMethod above points at. Served no-store because the key is
    // regenerated on every start. Its CORS header is `common/cors.js`'s
    // decision like every other response's; the `*` this route used to set for
    // itself would have overridden it.
    app.get('/bbs/keys/1', async (req, res) => {
      log.debug("Entering the BBS key endpoint.");
      const keys = await bbsKeyPair();
      res.set('Cache-Control', 'no-store');
      res.status(200).type('application/json').send(JSON.stringify({
        id: baseUrlOf(req) + '/bbs/keys/1',
        type: 'Multikey',
        controller: baseUrlOf(req),
        cryptosuite: bbs2023.CRYPTOSUITE,
        publicKeyMultibase: 'u' + bbs2023.bytesToB64u(keys.publicKey)
      }));
      log.debug("Leaving the BBS key endpoint.");
    });

    app.post('/oid4vci/credential', async (req, res) => {
      log.debug("Entering the OID4VCI credential endpoint.");
      const presented = this.presentedIssuerToken(req, res,
                                                  'the credential endpoint');
      if (!presented) {
        return;
      }
      const accessToken = presented.accessToken;

      // Section 10: the request may arrive encrypted, as application/jwt.
      // Reading it is the same job on both endpoints, so both call this.
      const read = this.readPossiblyEncryptedRequest(req);
      if (read.error) {
        // error-code: none — the code was decided in readPossiblyEncryptedRequest() and is on read.errorCode
        errorCodes.mark(res, read.errorCode);
        return vciError(res, 400, read.error, read.description);
      }
      const body = read.body;

      // Which credential (OID4VCI section 8.2). Exactly one of the two
      // identifies it, and which one is not the wallet's choice: it depends on
      // whether the token response granted credential_identifiers.
      const granted = this.grantedIdentifiers(accessToken);
      const identifier = body.credential_identifier;
      const configId = body.credential_configuration_id;
      if (identifier && configId) {
        errorCodes.mark(res, 'STS-VC-0009');
        return vciError(res, 400, 'invalid_credential_request',
          'credential_identifier and credential_configuration_id are ' +
          'mutually exclusive; send one.');
      }
      if (identifier) {
        if (!granted.length) {
          errorCodes.mark(res, 'STS-VC-0010');
          return vciError(res, 400, 'invalid_credential_request',
            'credential_identifier may only be used when the token ' +
            'response granted credential_identifiers (this authorization ' +
            'used a scope, so send credential_configuration_id instead).');
        }
        if (granted.indexOf(identifier) === -1) {
          errorCodes.mark(res, 'STS-VC-0011');
          return vciError(res, 400, 'invalid_credential_request',
            'credential_identifier "' + identifier + '" was not granted by ' +
            'the token response. Granted: ' +
            granted.join(', '));
        }
      } else if (configId) {
        if (granted.length) {
          errorCodes.mark(res, 'STS-VC-0012');
          return vciError(res, 400, 'invalid_credential_request',
            'the token response granted credential_identifiers, so ' +
            'credential_configuration_id MUST NOT be used (OID4VCI section ' +
            '8.2).');
        }
        if (!VCI_CONFIGS[configId]) {
          errorCodes.mark(res, 'STS-VC-0013');
          return vciError(res, 400, 'unsupported_credential_type',
            'This issuer offers credential_configuration_id ' +
            vciConfigIds().map((id) => {
              return '"' + id + '"';
            }).join(' and ') + '.');
        }
      } else {
        errorCodes.mark(res, 'STS-VC-0014');
        return vciError(res, 400, 'invalid_credential_request',
          'Name the credential: credential_identifier (when one was ' +
          'granted) or credential_configuration_id.');
      }

      // Which format, decided once. An identifier names its configuration in
      // its own prefix; a configuration id names it directly. Anything else
      // falls back to the SD-JWT configuration, which is what this issuer has
      // always offered.
      const requestedConfigId = identifier
        ? (configIdOfIdentifier(identifier) || VCI_CONFIG_ID)
        : (configId || VCI_CONFIG_ID);
      log.debug("The credential endpoint will issue " +
                vciFormatOf(requestedConfigId) +
                " (configuration " + requestedConfigId + ").");

      // Encryption of the response is the wallet's call (section 8.2). Checked
      // before any signature work: a request this issuer is going to refuse
      // should not cost the wallet its single-use c_nonce, and "your enc is
      // unsupported" is a more useful answer than "your proof is stale".
      const encryption = body.credential_response_encryption;
      // OID4VCI section 10's encryption_required, for the RESPONSE direction
      // (`oid4vci.responseEncryptionRequired`, 2026-09-12). The metadata says
      // it too — see vciMetadata().
      if (!encryption &&
          config.value('oid4vci.responseEncryptionRequired') === true) {
        log.debug("Leaving the OID4VCI credential endpoint. An encrypted " +
                  "response is required.");
        errorCodes.mark(res, 'STS-VC-0015');
        return vciError(res, 400, 'invalid_encryption_parameters',
          'This issuer advertises ' +
          'credential_response_encryption.encryption_required = true, so ' +
          'the Credential Request must carry credential_response_encryption.');
      }
      if (encryption) {
        const problem = this.encryptionProblem(encryption);
        if (problem) {
          log.debug("Leaving the OID4VCI credential endpoint. The " +
                    "encryption parameters were refused.");
          errorCodes.mark(res, 'STS-VC-0016');
          return vciError(res, 400, 'invalid_encryption_parameters', problem);
        }
      }

      // OID4VCI 1.0 sends proofs.jwt[], one entry per key the credential should
      // be bound to; the earlier single-proof form is accepted too, since
      // wallets in the wild still send it. One credential comes back per proof
      // (section 8.3).
      let proofJwts = [];
      // THE `attestation` PROOF TYPE (Appendix F.3, #38's follow-ups): a key
      // attestation IS the proof, and a credential is issued for each key it
      // attests.
      let attestationProofs = [];
      if (body.proofs && Array.isArray(body.proofs.jwt) &&
          body.proofs.jwt.length) {
        proofJwts = body.proofs.jwt;
      } else if (body.proofs && Array.isArray(body.proofs.attestation) &&
                 body.proofs.attestation.length) {
        attestationProofs = body.proofs.attestation.map(String);
      } else if (body.proof && body.proof.jwt) {
        proofJwts = [body.proof.jwt];
      }
      if (!proofJwts.length && !attestationProofs.length) {
        errorCodes.mark(res, 'STS-VC-0017');
        return vciError(res, 400, 'invalid_proof',
                        'A proof is required: proofs.jwt (a proof of ' +
                        'possession) or proofs.attestation (a key ' +
                        'attestation).');
      }
      if (proofJwts.length > vciBatchSize()) {
        errorCodes.mark(res, 'STS-VC-0018');
        return vciError(res, 400, 'invalid_credential_request',
          'This issuer accepts at most ' + vciBatchSize() + ' proofs in one ' +
          'request ' +
          '(batch_credential_issuance.batch_size); ' + proofJwts.length +
          ' were sent.');
      }

      let holderJwks = [];
      // What each holder key's attestation said, index for index, or null.
      let attestations = [];
      try {
        // Promise.all, so a BATCH of proofs is verified across the pool at
        // once rather than one after another. A wallet may send up to
        // batch_credential_issuance.batch_size of them, and with post-quantum
        // proofs that is the difference between one wait and several.
        const proven = await Promise.all(proofJwts.map((jwt) => {
          return this.verifyProofJwt(jwt,
                                     this.vciMetadata(req).credential_issuer);
        }));
        holderJwks = proven.map(function (one) {
          return one.jwk;
        });
        attestations = proven.map(function (one) {
          return one.attestation;
        });
        attestationProofs.forEach((token) => {
          const read = this.verifyKeyAttestation(token, {});
          read.keys.forEach(function (key) {
            holderJwks.push(key);
            attestations.push(read);
          });
        });
        if (holderJwks.length > vciBatchSize()) {
          throw new Error('the key attestations attest ' + holderJwks.length +
                          ' keys, and this issuer issues at most ' +
                          vciBatchSize() + ' credentials per request.');
        }
      } catch (e) {
        log.debug("Caught in the OID4VCI credential endpoint: " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0019') +
                  'the proof of possession was refused: ' + e.message);
        errorCodes.mark(res, 'STS-VC-0019');
        return vciError(res, 400, 'invalid_proof', e.message);
      }
      // Every proof in this request quoted the same c_nonce, and it is single
      // use: spend it now that they have all been accepted, so replaying the
      // request is refused while a batch inside one request is not — on every
      // node against the store, since 2026-09-14 (see spendProofNonces()).
      const nonceSpent = await this.spendProofNonces(
        proofJwts.concat(attestationProofs));
      if (!nonceSpent.ok) {
        log.debug("Leaving the OID4VCI credential endpoint. The c_nonce was " +
                  "refused at its spend.");
        // STS-VC-0050 (spent elsewhere) or STS-VC-0051 (the store).
        errorCodes.mark(res, nonceSpent.errorCode);
        return vciError(res, 400, 'invalid_proof', nonceSpent.description);
      }
      // AN ldp_vc IS BOUND TO A KEY ITS HOLDER CAN PROVE AT PRESENTATION, and
      // the only proof that format has is a Data Integrity one: a key no
      // cryptosuite covers (RSA, secp256k1, Ed448, the composites) would get a
      // credential that verifies and never signs its holder in. Refused as the
      // metadata's proof_signing_alg_values_supported for it already says.
      if (vciFormatOf(requestedConfigId) === 'ldp_vc') {
        const unfit = holderJwks.filter((jwk) => {
          return !this.deps.vcDataIntegrity.cryptosuiteForJwk(jwk);
        });
        if (unfit.length) {
          errorCodes.mark(res, 'STS-VC-0080');
          return vciError(res, 400, 'invalid_proof', 'An ldp_vc credential ' +
            'is bound to a key its holder proves with a Data Integrity ' +
            'cryptosuite, and none covers this key: ' +
            this.deps.vcDataIntegrity.unsupportedReason(unfit[0]) +
            ' Use a P-256, P-384, Ed25519 or ML-DSA-44 key.');
        }
      }
      const holderJwk = holderJwks[0];

      // A deferred issuance (OID4VCI section 8.3 / Appendix H.3): the issuer
      // cannot produce the credential yet, so it answers 202 with a
      // transaction_id and the wallet comes back to the Deferred Credential
      // Endpoint for it. Everything needed to mint the credential is kept here;
      // only the answer is postponed.
      if (deferredAccessTokens.has(accessToken)) {
        deferredAccessTokens.delete(accessToken);
        const transactionId = randomId(16);
        deferredTransactions.set(transactionId, {
          claims: this.subjectClaimsFrom(accessToken, requestedConfigId),
          // Read HERE and kept, because the deferred endpoint is reached with
          // a transaction_id and not with the access token that named this
          // person — so it is the last moment anything knows whose credential
          // this is.
          holderName: this.holderNameFrom(accessToken),
          holderJwk: holderJwk,
          holderJwks: holderJwks,
          attestations: attestations,
          // WHOM these credentials may sign in (#38), decided NOW against
          // the token that made the request — see signInSubjectOf().
          signInSubject: this.signInSubjectOf(presented),
          // The format was chosen in the request that was deferred, not in the
          // one that collects it — the wallet asked for a credential, and
          // postponing the answer must not change which credential it gets.
          configId: requestedConfigId,
          // A deferred response is encrypted with the parameters given in the
          // DEFERRED request, not these — but keeping them means an issuer
          // that decides otherwise still has them. Section 9.2 is explicit that
          // the newly provided ones win.
          encryption: encryption,
          accessToken: accessToken,
          readyAt: Date.now() + deferredReadyMs(),
          expires: Date.now() + offerTtlMs()
        });
        const deferredResponse = { transaction_id: transactionId,
                                   interval: deferredIntervalS() };
        logArtifact('OID4VCI Credential Response', 'deferred',
                    deferredResponse);
        res.set('Cache-Control', 'no-store');
        res.status(202)
           .type('application/json')
           .send(JSON.stringify(deferredResponse));
        log.debug("Leaving the OID4VCI credential endpoint. Deferred as " +
                  transactionId +
                  ", ready in " + deferredReadyMs() + "ms.");
        return;
      }

      // One credential per key the wallet proved possession of.
      const claims = this.subjectClaimsFrom(accessToken, requestedConfigId);
      const issuerId = this.vciMetadata(req).credential_issuer;
      const signInSubject = this.signInSubjectOf(presented);
      let issued;
      try {
        issued = await Promise.all(holderJwks.map((jwk) => {
          return this.buildCredentialFor(requestedConfigId, claims, jwk,
                                         issuerId,
                                         issuerDidFor(requestedConfigId, req),
                                         this.holderNameFrom(accessToken),
                                         signInSubject);
        }));
      } catch (e) {
        log.debug("Caught in the OID4VCI credential endpoint: " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0079') + 'the credential could not ' +
                  'be built: ' + e.message);
        errorCodes.mark(res, 'STS-VC-0079');
        return vciError(res, 500, 'server_error', 'The credential could not ' +
                        'be built: ' + e.message);
      }
      this.rememberIssued(issued, holderJwks, requestedConfigId,
                          signInSubject, attestations);
      const response = {
        credentials: issued.map((b) => {
          return {credential: b.credential };
        }),
        notification_id: this.newNotificationId(accessToken)
      };
      logArtifact('OID4VCI Credential Response', 'as returned', response);
      this.sendCredentialResponse(res, 200, response, encryption);
      log.debug("Leaving the OID4VCI credential endpoint. Issued " +
                issued.length + " " +
                vciFormatOf(requestedConfigId) + " credential(s), " +
                issued[0].disclosures.length +
                " disclosure(s) each" +
                (encryption ? ", encrypted to the wallet's key" : "") + ".");
    });

    // The Deferred Credential Endpoint (OID4VCI section 9). 202 with the same
    // transaction_id while the issuance is still "in progress", 200 with the
    // credential once it is ready, and invalid_transaction_id for a transaction
    // this issuer never made or has already handed over.
    app.post('/oid4vci/deferred_credential', async (req, res) => {
      log.debug("Entering the OID4VCI deferred credential endpoint.");
      if (!this.presentedIssuerToken(req, res,
                                     'the deferred credential endpoint')) {
        return;
      }

      // Section 10 covers the Deferred Credential Request too, in the same
      // words as the Credential Request — so it goes through the same reader
      // rather than getting a second, subtly different implementation.
      const read = this.readPossiblyEncryptedRequest(req);
      if (read.error) {
        log.debug("Leaving the OID4VCI deferred credential endpoint. " +
                  "Unreadable body.");
        // error-code: none — the code was decided in readPossiblyEncryptedRequest() and is on read.errorCode
        errorCodes.mark(res, read.errorCode);
        return vciError(res, 400, read.error, read.description);
      }
      const body = read.body;

      const transactionId = String(body.transaction_id || '');
      const record = deferredTransactions.get(transactionId);
      if (!record || record.expires < Date.now()) {
        deferredTransactions.delete(transactionId);
        log.debug("Leaving the OID4VCI deferred credential endpoint. No such " +
                  "transaction.");
        errorCodes.mark(res, 'STS-VC-0020');
        return vciError(res, 400, 'invalid_transaction_id',
          'That transaction_id was not issued by this Credential Issuer, or ' +
          'it has already been used.');
      }

      if (Date.now() < record.readyAt) {
        const pending = { transaction_id: transactionId,
                          interval: deferredIntervalS() };
        logArtifact('OID4VCI Deferred Credential Response', 'still pending',
                    pending);
        res.set('Cache-Control', 'no-store');
        res.status(202).type('application/json')
           .send(JSON.stringify(pending));
        log.debug("Leaving the OID4VCI deferred credential endpoint. Still " +
                  (record.readyAt - Date.now()) + "ms to go.");
        return;
      }

      // Ready. The transaction_id MUST be invalidated once the credential has
      // been obtained, so a second poll with it is an error rather than a
      // second copy.
      deferredTransactions.delete(transactionId);
      const holderKeys = record.holderJwks || [record.holderJwk];
      const issuerId = this.vciMetadata(req).credential_issuer;
      // The format the DEFERRED request asked for, not a fresh choice: see the
      // note where it was recorded.
      const deferredConfigId = record.configId || VCI_CONFIG_ID;
      let issued;
      try {
        issued = await Promise.all(holderKeys.map((jwk) => {
          return this.buildCredentialFor(deferredConfigId, record.claims, jwk,
                                         issuerId,
                                         issuerDidFor(deferredConfigId, req),
                                         record.holderName,
                                         String(record.signInSubject || ''));
        }));
      } catch (e) {
        log.debug("Caught in the OID4VCI deferred credential endpoint: " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0079') + 'the deferred credential ' +
                  'could not be built: ' + e.message);
        errorCodes.mark(res, 'STS-VC-0079');
        return vciError(res, 500, 'server_error', 'The credential could not ' +
                        'be built: ' + e.message);
      }
      this.rememberIssued(issued, holderKeys, deferredConfigId,
                          String(record.signInSubject || ''),
                          record.attestations || []);
      const response = {
        credentials: issued.map((b) => {
          return {credential: b.credential };
        }),
        notification_id: this.newNotificationId(record.accessToken)
      };
      logArtifact('OID4VCI Deferred Credential Response', 'as returned',
                  response);
      this.sendCredentialResponse(res, 200, response, record.encryption);
      log.debug("Leaving the OID4VCI deferred credential endpoint. Issued " +
                issued.length + " " +
                vciFormatOf(deferredConfigId) + " credential(s).");
    });

    // The Notification Endpoint (OID4VCI section 11): the wallet reports what
    // it did with a credential this issuer issued.
    //
    // It used to answer 204 to anything at all, which made it useless — a
    // wallet could not tell a notification that was understood from one that
    // was ignored, and the suite could not tell whether it had sent a valid
    // one. Now the id has to be one this issuer handed out and the event one of
    // the three the spec defines.
    app.post('/oid4vci/notification', (req, res) => {
      log.debug("Entering the OID4VCI notification endpoint.");
      if (!this.presentedIssuerToken(req, res, 'the notification endpoint')) {
        return;
      }

      let body: any = {};
      try {
        body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') :
               (req.body || {});
      } catch (e) {
        log.debug("Caught in the OID4VCI notification endpoint: " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0021') +
                  'the notification body is not JSON: ' + e.message);
        log.debug("Leaving the OID4VCI notification endpoint. Unreadable " +
                  "body.");
        errorCodes.mark(res, 'STS-VC-0021');
        return vciError(res, 400, 'invalid_notification_request',
          'The request body is not JSON: ' + e.message);
      }

      const id = String(body.notification_id || '');
      const event = String(body.event || '');
      const record = notificationIds.get(id);
      if (!record || record.expires < Date.now()) {
        notificationIds.delete(id);
        log.debug("Leaving the OID4VCI notification endpoint. No such " +
                  "notification_id.");
        errorCodes.mark(res, 'STS-VC-0022');
        return vciError(res, 400, 'invalid_notification_id',
          'That notification_id was not issued by this Credential Issuer, ' +
          'or it has expired.');
      }
      if (NOTIFICATION_EVENTS.indexOf(event) === -1) {
        log.debug("Leaving the OID4VCI notification endpoint. Unknown event: " +
                  event);
        errorCodes.mark(res, 'STS-VC-0023');
        return vciError(res, 400, 'invalid_notification_request',
          'event must be one of ' + NOTIFICATION_EVENTS.join(', ') +
          '; got "' + event + '".');
      }

      record.event = event;
      record.description = body.event_description || '';
      record.notifiedAt = new Date().toISOString();
      // THROUGH THE STORE, so the notification is not a fact only this process
      // knows: `notificationIds` is `realms.map({persist})` and its journal
      // sees `set()` rather than a field stamped on the object it handed out.
      notificationIds.set(id, record);
      logArtifact('OID4VCI Notification', 'as received', {
        notification_id: id, event: event,
        event_description: record.description
      });
      // Section 11.2: 204, no body.
      res.status(204).end();
      log.debug("Leaving the OID4VCI notification endpoint. Recorded " +
                event + " for " + id + ".");
    });

    // Non-spec, like GET /oid4vci/notification/:id and GET
    // /oid4vp/result/:state: how the last Credential Request actually arrived
    // on the wire.
    //
    // A wallet cannot prove its own encryption. Everything observable in the
    // page — the media type it displays, the ciphertext in its pane, even a
    // credential coming back — is equally consistent with a wallet that built a
    // JWE and then posted the plaintext, because with encryption_required false
    // the issuer accepts that JSON and issues from it. This is the only place
    // the truth lives.
    app.get('/oid4vci/last_request', (req, res) => {
      log.debug("Entering the (non-spec) last credential request endpoint.");
      res.set('Cache-Control', 'no-store');
      const last = this.lastCredentialRequestRecord();
      res.status(200).type('application/json')
         .send(JSON.stringify(last, null, 2));
      log.debug("Leaving the (non-spec) last credential request endpoint. " +
                "encrypted=" +
                last.encrypted);
    });

    // What this issuer was told about a credential. Not part of OID4VCI — it
    // exists so a test can check that a notification actually arrived and was
    // understood, rather than trusting a 204.
    app.get('/oid4vci/notification/:id', (req, res) => {
      log.debug("Entering the notification inspection endpoint. id=" +
                req.params.id);
      const record = notificationIds.get(String(req.params.id));
      if (!record) {
        log.debug("Leaving the notification inspection endpoint. Unknown " +
                  "id.");
        errorCodes.mark(res, 'STS-VC-0024');
        return vciError(res, 404, 'invalid_notification_id', 'No such ' +
            'notification_id.');
      }
      res.status(200).type('application/json').send(JSON.stringify({
        notification_id: req.params.id,
        event: record.event,
        event_description: record.description || '',
        notified_at: record.notifiedAt || null
      }));
      log.debug("Leaving the notification inspection endpoint.");
    });
    log.debug("Leaving VcIssuer.registerRoutes().");
  }

  // The record `GET /oid4vci/last_request` answers with, for the tests.
  lastCredentialRequest() {
    const { log } = this.deps;
    log.debug("Entering VcIssuer.lastCredentialRequest().");
    log.debug("Leaving VcIssuer.lastCredentialRequest().");
    return this.lastCredentialRequestRecord();
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcIssuer>(
  'oid4vc/vc_issuer',
  () => new VcIssuer(VcIssuer.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.
// `jwt` is referenced so the compiler keeps its require (an unused
// `import = require` is dropped from the output).
void jwt;

// #46: a pre-authorized code and a c_nonce are spent once across the cluster,
// and Transaction Code failures are counted against one budget — the c_nonce
// by spendProofNonces() above, the other two by vc_offers.ts's
// spendPreAuthorizedCode() and checkTxCode(), which this module requires and
// the token endpoint calls. Provided here because the capability row names
// this file.
capabilities.provide('oid4vc.once');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcIssuer: VcIssuer,
  installInstance: (instance: VcIssuer): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  vciMetadata: slot.forward('vciMetadata'),
  // For tests/cluster_single_use_protocols.js: the c_nonce's spend, driven
  // twice with the local map restored between, which is what another node
  // that has not yet caught up looks like.
  spendProofNonces: slot.forward('spendProofNonces'),
  buildCredentialFor: slot.forward('buildCredentialFor'),
  verifyKeyAttestation: slot.forward('verifyKeyAttestation'),
  subjectClaimsFrom: slot.forward('subjectClaimsFrom'),
  vciNonces: vciNonces,
  VCI_NONCE_TTL_MS: VcIssuer.VCI_NONCE_TTL_MS,
  // The request-encryption half, for `tests/vci_request_encryption_key.js`:
  // what a realm PUBLISHES, what it will DECRYPT, and what it last SAW. A JWE
  // encrypted to one realm's published key and refused by another's is a claim
  // about these three and about nothing a single HTTP request can separate.
  credentialRequestEncryptionMetadata:
    slot.forward('credentialRequestEncryptionMetadata'),
  decryptJweRequest: slot.forward('decryptJweRequest'),
  readPossiblyEncryptedRequest: slot.forward('readPossiblyEncryptedRequest'),
  lastCredentialRequest: slot.forward('lastCredentialRequest')
};
