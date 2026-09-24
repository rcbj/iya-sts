'use strict';
//
// File: vc_verifier.ts
//
// ===========================================================================
// OpenID for Verifiable Presentations (OID4VP 1.0) — mock Verifier
//
// The other half of the SD-JWT VC story: the issuance flow (vc_issuer.ts) puts
// a credential in a wallet, and this is the Verifier that asks for part of it.
//
//   GET  /oid4vp/verifier          the Verifier's web page (where a
//                                  presentation starts, same device)
//   GET  /oid4vp/start             builds an Authorization Request and either
//                                  sends the browser to the wallet with it or
//                                  displays it as a QR code (cross device)
//   GET  /oid4vp/request/:id       the signed Request Object, fetched by
//                                  reference (RFC 9101 / OID4VP request_uri)
//   POST /oid4vp/response          the Response URI: response_mode direct_post,
//                                  where the vp_token arrives and is VERIFIED
//   GET  /oid4vp/result/:state     non-spec: the verdict, so the wallet page and
//                                  the tests can read what the Verifier decided
//   GET  /oid4vp/done              the Verifier's "thank you" page
//
// **AND SINCE 2026-09-17 (#38) A PRESENTATION CAN SIGN SOMEBODY IN** — not
// from these endpoints, which answer a wallet, but from `/authn/wallet`
// (`vc_signin.ts`), which builds its request through `buildVpRequest()` with
// `signIn` and reads the second verdict `signInOutcome()` writes onto the
// transaction. The bar door's own presentations still sign nobody in: they
// were not asked for by a browser waiting to be signed in, and a sign-in that
// happened because a bar door was shown a credential would be a session
// nobody requested. The rules of who may be signed in are
// `signInOutcome()`'s header.
//
// What it checks is the whole point, so it checks properly (RFC 9901 section
// 7.3 plus OID4VP's rules for the Key Binding JWT):
//
//   * the presentation is an SD-JWT+KB: <Issuer-signed
//     JWT>~<Disclosure>*~<KB-JWT>
//   * the Issuer-signed JWT verifies against the issuer's key, and its typ is
//     an SD-JWT VC media type
//   * every Disclosure presented hashes to a digest in _sd — a Disclosure the
//     issuer never signed is the forgery this catches
//   * the KB-JWT has typ kb+jwt, an alg that is not none, and verifies against
//     the cnf key IN THE CREDENTIAL — key binding means nothing if the
//     presenter may nominate the key
//   * its sd_hash equals the hash of exactly the bytes presented, so
//     disclosures cannot be added or removed after it was signed
//   * its nonce is the nonce from THIS request (replay) and its aud is this
//     Verifier's Client Identifier (an honest presentation to someone else is
//     not a presentation to us)
//   * the credential is inside its validity window, and every claim the DCQL
//     query asked for is actually there
// ===========================================================================
//
// WHAT it asks for, and in which credential format, is CONFIGURATION rather
// than a constant: vc_verifier_config.ts holds it and /admin/vc-verifier-config
// sets it. Read that module's header before changing anything about the DCQL
// query — the grouping of claims, the per-format paths and the "ask for a claim
// nothing here issues" case are all decisions with reasons written down there.
// What one request asked for is frozen onto its transaction in
// buildVpRequest(), because the configuration can change while a presentation
// is in flight.
//
// It shares nothing with vc_issuer.ts but the key: this is the OTHER side of
// the exchange, and it verifies what arrives from first principles rather than
// by asking the issuer module what it produced. That is deliberate — a verifier
// that called the issuer's own code to check a presentation would agree with it
// about any mistake they had in common.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `VcVerifier` takes the helpers it uses, the settings, the mode, the
// error codes, the revocation check, the identity registry, the request
// configuration, the signer and verifier, and the two stores through its
// constructor, and registers its six endpoints from `registerRoutes(app)`.
// Loading the module does not call it (#50, R1): the module exports it, and
// `common/protocol_stack.ts` calls it at the point in the route order where
// requiring this module used to register the endpoints. The stores stay
// module-scope `realms.map()` declarations. Since #50's R2 that root also
// BUILDS the instance; the module's four old names are FACADES forwarding to
// it, and a process without the root builds a default at load. Two method
// aliases keep the spellings
// `tests/revocation_status.js` reads in this file's source.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and error_codes.js and nothing else here, so it cannot join a
// cycle and it registers no route, so its position is not a position at all.
import realms = require('../common/realms');
import jwt = require('jsonwebtoken');
// One signer and one verifier for the whole service since 2026-08-27.
import stsCrypto = require('../common/crypto');
import qrcode = require('qrcode');
import app = require('../common/app');
import bbs2023 = require('../common/vendored/bbs2023.js');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// THE MODE (2026-09-12), for one question: may a response go to an address the
// request named — the `wallet` query parameter. A LEAF requiring only `config`.
import mode = require('../common/mode');
// The error codes (common/error_codes.js). A LEAF that requires nothing; a code
// is marked on the response object and never written into a response.
import errorCodes = require('../common/error_codes');
// A library (rule 3) that registers no route: the revocation check a configured
// trusted issuer certificate gets once it has verified a credential.
import revocationStatus = require('../common/revocation_status');
// The identity registry, for ONE call: a presentation that verified names a
// holder, and this is the funnel every other family here already goes through
// at the moment a credential is accepted. A library like dpop.js — it registers
// no route and nothing it requires reaches this module — so requiring it
// cannot move a route or make a cycle. See the call site in the response
// endpoint for what it does and does NOT claim about the holder.
import stats = require('../common/admin_stats');
import cacheRegistry = require('../common/cache_registry');
import vcConfigs = require('./vc_configs');
// THE REGISTER OF CREDENTIALS THIS REALM ISSUED FOR A DIRECTORY ENTRY
// (2026-09-17, #38), read by `signInOutcome()` to decide whom a presentation
// made for a sign-in signs in. A LIBRARY (rule 3) requiring only `common/`
// leaves: this require closes no cycle and moves no route.
import vcIssued = require('./vc_issued');
// THE STATUS LISTS (#38's follow-ups), consulted for every credential a
// presentation carries, and THE HOLDER'S DATA INTEGRITY PROOF, which is what
// binds an ldp_vc presentation to the key its credential names. Two
// libraries over `common/`; neither requires this file.
import vcStatus = require('./vc_status');
import vcDataIntegrity = require('./vc_data_integrity');
// THE KEY-ENCRYPTION KEY, for the one private key a transaction holds: the
// Digital Credentials API response key (see dcApiRequest()).
import keystore = require('../common/keystore');

// The input validator. A LEAF (rule 3): registers no route, closes no cycle.
import validation = require('../common/validation');

// SELF-ISSUED OPENID PROVIDER v2 (#129): the self-issued ID Token's check,
// the enrolled-subject register, and whom a verified one signs in. A LIBRARY
// over `common/` and `vc_data_integrity.ts`; it does not require this file.
import siop = require('./siop');
// This realm's did:web, for the `decentralized_identifier` Client
// Identifier. `vc_did.ts` requires `vc_configs.ts` and `common/` and never
// this file, and since #50's R1 a require of it registers no route.
import vcDid = require('./vc_did');

const { VCI_JWT_TYPES, VCI_VCT } = vcConfigs;

// `jsonwebtoken` was required here and is no longer called; the import is
// kept with the others it was listed beside.
void jwt;

// The parts of a `realms.map()` store this module uses.
interface Store {
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
}

// The transaction store is BOUNDED (oid4vp.maxTransactions), so it is asked
// its size and its oldest key as well.
interface BoundedStore extends Store {
  readonly size: number;
  keys(): Iterator<string>;
}

interface VcVerifierDeps {
  log: typeof helpers.log;
  logArtifact: typeof helpers.logArtifact;
  STS: typeof helpers.STS;
  baseUrlOf: typeof helpers.baseUrlOf;
  b64u: typeof helpers.b64u;
  b64uDecode: typeof helpers.b64uDecode;
  jsonFromB64u: typeof helpers.jsonFromB64u;
  nowSec: typeof helpers.nowSec;
  randomId: typeof helpers.randomId;
  xmlEscape: typeof helpers.xmlEscape;
  bbsKeyPair: typeof helpers.bbsKeyPair;
  bbsGenerations?: typeof helpers.bbsGenerations;
  parseBody: typeof helpers.parseBody;
  oauthError: typeof helpers.oauthError;
  signJwt: typeof helpers.signJwt;
  stsKeysFor: typeof helpers.stsKeysFor;
  kidNamesKey: typeof helpers.kidNamesKey;
  nameForSubject: typeof helpers.nameForSubject;
  subjectForName: typeof helpers.subjectForName;
  vcIssued: typeof vcIssued;
  vcStatus: typeof vcStatus;
  vcDataIntegrity: typeof vcDataIntegrity;
  keystore: typeof keystore;
  allSigningKeysAsync: typeof helpers.allSigningKeysAsync;
  config: { value(key: string): any };
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  revocationStatus: typeof revocationStatus;
  stats: typeof stats;
  vpConfig: typeof vpConfig;
  stsCrypto: typeof stsCrypto;
  vpTransactions: BoundedStore;
  vpRequests: Store;
  siop: typeof siop;
  stsDid: typeof vcDid.stsDid;
  publishedKidFor: typeof helpers.publishedKidFor;
}

// The credential formats this issuer actually offers, read off the table that
// defines them rather than written out again.
const VCI_FORMATS = Array.from(new Set(
  Object.keys(vcConfigs.VCI_CONFIGS).map(function (id) {
    return vcConfigs.VCI_CONFIGS[id].format;
  }).filter(Boolean)));
// What this Verifier asks for, and which credential format it asks for it in.
// Configuration rather than a constant since /admin/vc-verifier-config existed:
// a library like dpop.js and vc_claims.ts, registering no route, so requiring
// it here cannot move a route or make a cycle. See its header for why the unit
// of request is the top-level claim and why a claim that is not in the
// catalogue can still be asked for.
import vpConfig = require('./vc_verifier_config');
// `oid4vp.presentationRequestTtlS` since 2026-09-12; the constant is its
// default. Read once per request BUILT, and the transaction carries the expiry
// it was given.
const VP_TTL_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// WHICH KEYS A PRESENTED CREDENTIAL'S ISSUER SIGNATURE MAY VERIFY AGAINST
// (2026-09-12).
//
// It was `STS.certPem` with jsonwebtoken's RS256 default — this service's own
// RSA key and nothing else. Two things moved:
//
//   * THIS ISSUER may sign with `oid4vci.credentialSigningAlgorithm`, which can
//     name a curve algorithm, so the realm's own key for the credential's
//     `alg` is found the way the signer found it: RS/PS against the RSA
//     certificate, anything else by its `kid` in the realm's key set.
//   * `oid4vp.trustedIssuerCertificates` names OTHER issuers, as PEM
//     certificates whose public keys are tried as well. A certificate is used
//     as a key and nothing more — no path is built and no revocation is
//     checked — which is what the setting's own description says.
//
// The algorithm list is the credential header's `alg` ALONE, and it must be an
// asymmetric, non-post-quantum JOSE algorithm: a MAC here would verify a
// signature with a public key used as a secret, and a post-quantum one would
// block this thread (the Verifier's checks are synchronous). Naming the one
// algorithm is what stops a key of one family being tried under another.
// ---------------------------------------------------------------------------
const ISSUER_ALGS = stsCrypto.JWS_ASYMMETRIC_ALGS.filter(function (alg) {
  return stsCrypto.JWS_ALGS[alg].family !== 'pq';
});

// ---------------------------------------------------------------------------
// AND EVERY ASYMMETRIC ALGORITHM, POST-QUANTUM INCLUDED (#38's follow-ups),
// for the checks that are asynchronous now: this realm's issuer may sign with
// ML-DSA, SLH-DSA or a composite (`oid4vci.credentialSigningAlgorithm`), and a
// holder may bind a credential to such a key, so the issuer signature, the
// Key Binding JWT and the VP JWT are verified through `common/crypto.js`'s
// asynchronous verifier, which hands a post-quantum check to the worker pool.
// ISSUER_ALGS above is what a CONFIGURED trusted issuer certificate may sign
// with — a certificate's key is a node KeyObject, and node has no ML-DSA
// KeyObject this service could be handed.
// ---------------------------------------------------------------------------
const ALL_ALGS = stsCrypto.JWS_ASYMMETRIC_ALGS.slice();

// ---------------------------------------------------------------------------
// A SIGN-IN'S CREDENTIAL QUERIES, ONE PER FORMAT (#38's follow-ups). The
// SD-JWT query keeps the id the bar door has always used, so a wallet that
// answers only `identity_credential` still answers it; the other two are
// distinct, because the response is keyed by query id and the id is how the
// Verifier knows which format arrived.
// ---------------------------------------------------------------------------
const SIGN_IN_QUERY_IDS = {
  'dc+sd-jwt': 'identity_credential',
  'jwt_vc_json': 'identity_credential_jwt_vc',
  'ldp_vc': 'identity_credential_ldp_vc'
};
const SIGN_IN_FORMATS = Object.keys(SIGN_IN_QUERY_IDS);

// THE DIGITAL CREDENTIALS API (#38's follow-ups). OpenID4VP 1.0 Appendix A.1:
// the exchange protocol identifier for a signed request in JWS Compact
// Serialization. An unsigned request (`openid4vp-v1-unsigned`) would carry no
// client identifier and no `expected_origins`, and this door always signs.
const DC_API_PROTOCOL = 'openid4vp-v1-signed';
const DC_API_RESPONSE_MODES = ['dc_api.jwt', 'dc_api'];
// The content encryption the response may use (Section 8.3): A128GCM is the
// default a wallet assumes, the others are offered in
// `encrypted_response_enc_values_supported`.
const DC_API_ENC_VALUES = ['A128GCM', 'A256GCM'];
// The `kid` prefix of a direct_post.jwt transaction's response key; the rest
// of the kid is the transaction's state (#187).
const DIRECT_POST_JWT_KID = 'dpj-';

// The N-Quads IRIs an ldp_vc's disclosed statements are read by.
const CRED = 'https://www.w3.org/2018/credentials#';
const STATUS_NS = 'https://www.w3.org/ns/credentials/status#';

// The claims this Verifier asks for used to be here, read once from
// OID4VP_CLAIMS at require time. They are now vpConfig's, read at the moment a
// request is BUILT and then frozen onto that request — see buildVpRequest().
// OID4VP_CLAIMS is still what the process starts with and what Reset on the
// console goes back to.

// The DCQL credential query's id, and therefore the key the vp_token arrives
// under. It is the configuration module's, because the query is built there —
// two copies of this string would mean a response this Verifier could not find
// the presentation in.
const VP_DCQL_ID = vpConfig.DCQL_ID;

// state -> { id, nonce, state, responseMode, clientId, requestObject, dcql,
//            expires, verdict }
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const vpTransactions = realms.map({ persist: 'vc_verifier.vpTransactions',
                                    retain: 'age' });

// id -> state, so a Request Object fetched by reference can find its
// transaction. PER TRUST REALM. `realms.map()` is a Map that holds a separate
// one for each realm and hands out the ambient realm's — so every reader below
// is unchanged and every one of them is now realm-correct. In the default
// realm, and in a service with no realms defined, there is exactly one
// partition and this behaves as the plain Map it replaced. See
// common/realms.js.
const vpRequests = realms.map({ persist: 'vc_verifier.vpRequests',
                                retain: 'age' });

// ---------------------------------------------------------------------------
// DESCRIBED TO `/admin/caches` (rule 3ap, #38's follow-ups). A transaction is
// a one-time value — answered once, finished once — so it is the replay kind
// rather than a cache, and it is where a sign-in's Digital Credentials API
// state lives: the signed request, the response mode and the sealed key its
// answer is encrypted to. A row is the state alone; the transaction's own
// value never leaves this store.
// ---------------------------------------------------------------------------
const vpTransactionsCount = cacheRegistry.register({
  name: 'oid4vp.transactions',
  title: 'OpenID4VP transactions',
  description: 'Every presentation request this Verifier is waiting on — ' +
    'the bar door\'s and a wallet sign-in\'s, the latter carrying the ' +
    'Digital Credentials API request, its response mode and the key its ' +
    'answer is encrypted to.',
  owner: 'oid4vc/vc_verifier.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a wallet\'s answer found the request it was made for',
  settings: ['oid4vp.presentationRequestTtlS', 'oid4vp.signInTtlS',
             'oid4vp.maxTransactions'],
  maxEntries: function (): number {
    return Number(config.value('oid4vp.maxTransactions'));
  },
  bound: 'Enforced: oid4vp.maxTransactions per realm; the oldest waiting ' +
    'request is dropped (federation.maxContexts\'s rule), because refusing ' +
    'would let anybody stop the request endpoint for everybody.',
  lifetime: function (): string {
    return 'oid4vp.presentationRequestTtlS, or oid4vp.signInTtlS for a ' +
      'sign-in; swept when the next request is built.';
  },
  // What `sweepVpTransactions()` drops, in every realm, WITH the request
  // each names in `vpRequests` — the two go together (#49 P5).
  eject: function (now: number): number {
    let total = 0;
    realms.list().forEach(function (r: { id: string }): void {
      const tx = vpTransactions.realmMap(r.id);
      const reqs = vpRequests.realmMap(r.id);
      if (!tx) {
        return;
      }
      const gone: Array<[unknown, any]> = [];
      tx.forEach(function (v: any, k: unknown): void {
        if (v && v.expires < now) {
          gone.push([k, v]);
        }
      });
      gone.forEach(function (pair: [unknown, any]): void {
        if (reqs && pair[1] && pair[1].id) {
          reqs.delete(pair[1].id);
        }
        tx.delete(pair[0]);
      });
      total += gone.length;
    });
    return total;
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, vpTransactions,
      function (record: any, state: unknown): object {
        return { key: cacheRegistry.digestKey(state),
                 validUntil: Number((record && record.expires) || 0) || null,
                 basis: record && record.signIn
                   ? (record.signIn.completed ? 'finished' : 'sign-in')
                   : 'time' };
      });
  }
});

// The Verifier's own web page — where a same-device presentation starts.
// ---------------------------------------------------------------------------
// THE FOUR SCALAR PARAMETERS THESE PAGES TAKE.
//
// **THE FORMAT LIST IS DERIVED FROM `VCI_CONFIGS` AND NEVER RETYPED.** Which
// credential formats this issuer offers is that table's statement — three of
// them today (`dc+sd-jwt`, `jwt_vc_json`, `ldp_vc`) — and a list written out
// here would be the second copy that goes stale the day a fourth is added.
// Same argument `sts_metadata.js` makes about reading the router.
//
// **`wallet` IS TYPED AS A URI AND THAT IS THE ONE THAT MATTERS.** It is a URL
// this service builds into a link and a QR code for somebody to follow, so a
// `javascript:` or `data:` scheme here is script execution on the machine of
// whoever scans it. `vt.uri` refuses the executable schemes; it deliberately
// does NOT constrain the host, because pointing this at a wallet on a laptop is
// the whole reason the parameter exists.
//
// `mode` and `by` are CASE-SENSITIVE, matching their call sites, which compare
// with `===` and lower-case nothing.
// ---------------------------------------------------------------------------
const OID4VC_QUERY = validation.z.looseObject({
  mode: validation.types.opt(validation.types.oneOf(
    ['same-device', 'cross-device', 'deferred', 'direct'])),
  by: validation.types.opt(validation.types.oneOf(['value', 'reference'])),
  format: validation.types.opt(validation.types.oneOf(VCI_FORMATS)),
  wallet: validation.types.opt(validation.types.uri),
  state: validation.types.opt(validation.types.opaque),
  credential_configuration_ids: validation.types.opt(
    validation.z.string().max(validation.CAP.SCOPE)),
  // SIOPv2 (#129): a self-issued ID Token alone, or with a presentation,
  // and the two response modes a Verifier here may ask for.
  response_type: validation.types.opt(validation.types.oneOf(
    ['vp_token', 'id_token', 'vp_token id_token'])),
  response_mode: validation.types.opt(validation.types.oneOf(
    ['direct_post', 'direct_post.jwt', 'form_post']))
});

class VcVerifier {
  static readonly VP_TTL_MS = VP_TTL_MS;

  constructor(private readonly deps: VcVerifierDeps) {
    deps.log.debug("Entering VcVerifier.constructor().");
    deps.log.debug("Leaving VcVerifier.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): VcVerifierDeps {
    helpers.log.debug("Entering VcVerifier.defaultDeps().");
    helpers.log.debug("Leaving VcVerifier.defaultDeps().");
    return {
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      STS: helpers.STS,
      baseUrlOf: helpers.baseUrlOf,
      b64u: helpers.b64u,
      b64uDecode: helpers.b64uDecode,
      jsonFromB64u: helpers.jsonFromB64u,
      nowSec: helpers.nowSec,
      randomId: helpers.randomId,
      xmlEscape: helpers.xmlEscape,
      bbsKeyPair: helpers.bbsKeyPair,
      bbsGenerations: helpers.bbsGenerations,
      parseBody: helpers.parseBody,
      oauthError: helpers.oauthError,
      signJwt: helpers.signJwt,
      stsKeysFor: helpers.stsKeysFor,
      kidNamesKey: helpers.kidNamesKey,
      nameForSubject: helpers.nameForSubject,
      subjectForName: helpers.subjectForName,
      vcIssued: vcIssued,
      vcStatus: vcStatus,
      vcDataIntegrity: vcDataIntegrity,
      keystore: keystore,
      allSigningKeysAsync: helpers.allSigningKeysAsync,
      config: config,
      mode: mode,
      errorCodes: errorCodes,
      revocationStatus: revocationStatus,
      stats: stats,
      vpConfig: vpConfig,
      stsCrypto: stsCrypto,
      vpTransactions: vpTransactions,
      vpRequests: vpRequests,
      siop: siop,
      stsDid: vcDid.stsDid,
      publishedKidFor: helpers.publishedKidFor
    };
  }

  private vpClientId() {
    const { log, config } = this.deps;
    log.debug("Entering VcVerifier.vpClientId().");
    log.debug("Leaving VcVerifier.vpClientId().");
    return config.value('oid4vp.clientId');
  }

  // oid4vp.walletUrl falls back to the OID4VCI one in config.js's table, which
  // is why walletBaseUrl() is not consulted here any more — the fallback moved
  // to where the setting is declared rather than being spelt out at one of the
  // two places that read it.
  private vpWalletUrl() {
    const { log, config } = this.deps;
    log.debug("Entering VcVerifier.vpWalletUrl().");
    log.debug("Leaving VcVerifier.vpWalletUrl().");
    return config.value('oid4vp.walletUrl');
  }

  private vpTtlMs() {
    const { log, config } = this.deps;
    log.debug("Entering VcVerifier.vpTtlMs().");
    const seconds = Number(config.value('oid4vp.presentationRequestTtlS'));
    log.debug("Leaving VcVerifier.vpTtlMs().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) * 1000 :
           VP_TTL_MS;
  }

  private trustedIssuerKeys() {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering VcVerifier.trustedIssuerKeys().");
    const text = String(config.value('oid4vp.trustedIssuerCertificates') || '');
    const blocks = text.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    const out = [];
    blocks.forEach((pem, i) => {
      try {
        out.push({ label: 'trusted issuer certificate ' + (i + 1), pem: pem,
                   key: new crypto.X509Certificate(pem).publicKey });
      } catch (e) {
        log.debug("Caught in VcVerifier.trustedIssuerKeys(): " +
                  ((e && e.message) || e));
        // One unreadable certificate must not take the others with it; it is
        // named in the log so that an operator can see which entry is wrong.
        log.error(errorCodes.tag('STS-VC-0031') +
                  'oid4vp.trustedIssuerCertificates: certificate ' + (i + 1) +
                  ' could not be read and is ignored: ' + e.message);
      }
    });
    log.debug("Leaving VcVerifier.trustedIssuerKeys(). " + out.length + " " +
              "key(s).");
    return out;
  }

  private verifyIssuerSignature(token: unknown) {
    const { log, STS, jsonFromB64u, stsKeysFor, kidNamesKey,
            stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.verifyIssuerSignature().");
    let header: any = {};
    try {
      header = jsonFromB64u(String(token || '').split('.')[0]);
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyIssuerSignature(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcVerifier.verifyIssuerSignature(). The header is " +
                "unreadable.");
      throw new Error('the issuer-signed JWT header cannot be read: ' +
                      e.message);
    }
    const alg = String(header.alg || '');
    if (ISSUER_ALGS.indexOf(alg) < 0) {
      log.debug("Leaving VcVerifier.verifyIssuerSignature(). Unacceptable " +
                "alg.");
      throw new Error('the credential is signed with "' + alg + '", and this ' +
          'Verifier accepts ' +
                      ISSUER_ALGS.join(', ') + '.');
    }
    const candidates = [];
    const family = stsCrypto.JWS_ALGS[alg].family;
    // EVERY LIVE GENERATION of this realm's keys (#42): a credential outlives
    // a rotation, and verifies against the key that signed it until that
    // key's grace ends.
    if (family === 'rsa' || family === 'rsa-pss' || /^(RS|PS)/.test(alg)) {
      helpers.ownRsaCertificates('jose').forEach((one: any) => {
        if (!header.kid || kidNamesKey(header.kid, one.kid)) {
          candidates.push({ label: 'this issuer\'s RSA key (' + one.role +
                                   ')', key: one.certPem });
        }
      });
    } else {
      helpers.allVerificationKeys().forEach((one: any) => {
        if (one.publicJwk && one.publicJwk.kty !== 'AKP' && one.alg === alg &&
            (!header.kid || kidNamesKey(header.kid, one.publicJwk.kid))) {
          candidates.push({ label: 'this issuer\'s ' + alg + ' key',
                            key: crypto.createPublicKey(
                                { key: one.publicJwk, format: 'jwk' }) });
        }
      });
    }
    this.trustedIssuerKeys().forEach((one) => { candidates.push(one); });
    let lastError = 'no key this Verifier trusts can verify a ' + alg + ' ' +
        'signature';
    for (let i = 0; i < candidates.length; i++) {
      try {
        const claims = stsCrypto.verifyJws(token, candidates[i].key,
                                           { algorithms: [alg] });
        log.debug("Leaving VcVerifier.verifyIssuerSignature(). Verified by " +
                  candidates[i].label + ".");
        // `certificatePem` is set only for a CONFIGURED trusted issuer
        // certificate, which the response endpoint then checks for revocation.
        return { claims: claims, alg: alg, by: candidates[i].label,
                 certificatePem: candidates[i].pem || '' };
      } catch (e) {
        // The next candidate may verify it; the last failure is the answer.
        log.debug("Caught in VcVerifier.verifyIssuerSignature(): " +
                  ((e && e.message) || e));
        lastError = e.message;
      }
    }
    log.debug("Leaving VcVerifier.verifyIssuerSignature(). Nothing verified " +
              "it.");
    throw new Error(lastError);
  }

  // ---------------------------------------------------------------------------
  // THE SAME QUESTION FOR A POST-QUANTUM SIGNATURE (#38's follow-ups).
  //
  // `oid4vci.credentialSigningAlgorithm` may name ML-DSA, SLH-DSA or a
  // composite, and a credential this realm signed that way must be accepted
  // as this realm's. Its key is one of the realm's post-quantum keys (an AKP
  // JWK, made in the worker pool, `helpers.allSigningKeysAsync()`), found by
  // `alg` and `kid` as the curve keys are, and the check runs in the pool
  // with the same claim rules — `exp`, `nbf`, the clock skew — as every other
  // (`stsCrypto.verifyJwsAsync()`). A trusted issuer CERTIFICATE is not tried
  // for these algorithms: its key would have to be a node KeyObject, and this
  // service reads no ML-DSA certificate key into one.
  //
  // Every other algorithm goes to the synchronous verifier above unchanged.
  // ---------------------------------------------------------------------------
  private async verifyIssuerSignatureAsync(token: unknown) {
    const { log, jsonFromB64u, kidNamesKey, stsCrypto,
            allSigningKeysAsync } = this.deps;
    log.debug("Entering VcVerifier.verifyIssuerSignatureAsync().");
    let header: any = {};
    try {
      header = jsonFromB64u(String(token || '').split('.')[0]);
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyIssuerSignatureAsync(): " +
                ((e && e.message) || e));
      header = {};
    }
    const alg = String(header.alg || '');
    const spec = stsCrypto.JWS_ALGS[alg];
    if (!spec || spec.family !== 'pq') {
      log.debug("Leaving VcVerifier.verifyIssuerSignatureAsync(). Not " +
                "post-quantum.");
      return this.verifyIssuerSignature(token);
    }
    // Every live generation (#42).
    const keys = await helpers.allVerificationKeysAsync();
    const candidates = keys.filter(function (one) {
      return !!one.publicJwk && one.alg === alg &&
             (!header.kid || kidNamesKey(header.kid, one.publicJwk.kid));
    });
    let lastError = 'this realm holds no ' + alg + ' key that can verify it';
    for (let i = 0; i < candidates.length; i++) {
      try {
        const claims = await stsCrypto.verifyJwsAsync(String(token),
          candidates[i].publicJwk, { algorithms: [alg] });
        log.debug("Leaving VcVerifier.verifyIssuerSignatureAsync(). " +
                  "Verified by this issuer's " + alg + " key.");
        return { claims: claims, alg: alg,
                 by: 'this issuer\'s ' + alg + ' key', certificatePem: '' };
      } catch (e) {
        // The next candidate may verify it; the last failure is the answer.
        log.debug("Caught in VcVerifier.verifyIssuerSignatureAsync(): " +
                  ((e && e.message) || e));
        lastError = e.message;
      }
    }
    log.debug("Leaving VcVerifier.verifyIssuerSignatureAsync(). Nothing " +
              "verified it.");
    throw new Error(lastError);
  }

  // ---------------------------------------------------------------------------
  // THE CONFIGURED TRUSTED ISSUER CERTIFICATE THAT VERIFIED A CREDENTIAL,
  // checked for revocation once it has been used (2026-09-12).
  //
  // It is a certificate an operator wrote into
  // `oid4vp.trustedIssuerCertificates`, so it gets
  // `common/revocation_status.js`'s registered-certificate check — the register
  // for one this service issued, its issuer's OCSP responder and CRL otherwise,
  // under `pki.revocationCheck`. The two verifiers are synchronous and the
  // response endpoint is not, so the check is made THERE, on the certificate
  // the verifier reports having used, rather than inside them. A credential
  // this service signed itself verified against no configured certificate and
  // has nothing to check. It adds a check row either way and turns `ok` off on
  // a refusal; `revocationRefused` is what lets the endpoint name the code.
  // ---------------------------------------------------------------------------
  async issuerCertificateRevocation(verified: any) {
    const { log, revocationStatus } = this.deps;
    log.debug("Entering VcVerifier.issuerCertificateRevocation().");
    if (!verified || !verified.ok || !verified.issuerCertificatePem) {
      log.debug("Leaving VcVerifier.issuerCertificateRevocation(). Nothing " +
                "configured was used.");
      return verified;
    }
    const issuerRevocation = await revocationStatus.registeredVerdictFor({
      certificate: verified.issuerCertificatePem,
      source: 'a certificate in oid4vp.trustedIssuerCertificates'
    });
    this.vpCheck(verified.checks, 'Issuer certificate revocation',
      !issuerRevocation.refused,
      issuerRevocation.why);
    verified.ok = !issuerRevocation.refused;
    verified.revocationRefused = !!issuerRevocation.refused;
    log.debug("Leaving VcVerifier.issuerCertificateRevocation(). " +
              issuerRevocation.status);
    return verified;
  }

  // ---------------------------------------------------------------------------
  // WHERE THE HOLDER IS SENT (2026-09-12) — `vc_offers.ts`'s walletFor() made
  // again for this side, rather than shared, because the two settings are two
  // rows (`oid4vp.*`) and a wallet URL accepted for issuance is not by that
  // fact one accepted for presentation. The page is
  // `oid4vp.walletPresentationPath`; the `wallet` parameter may name any URL in
  // development and, where a realm accepts only registered addresses, only
  // oid4vp.walletUrl or one listed in `oid4vp.allowedWalletUrls` — anything
  // else is an open redirect carrying a presentation request, and is refused by
  // name.
  // ---------------------------------------------------------------------------
  vpWalletFor(req: any) {
    const { log, config, mode } = this.deps;
    log.debug("Entering VcVerifier.vpWalletFor().");
    const configured = String(this.vpWalletUrl() || '').replace(/\/+$/, '');
    const asked = req.query.wallet ?
                  String(req.query.wallet).replace(/\/+$/, '') : '';
    if (asked && asked !== configured && !mode.acceptsUnregisteredAddresses()) {
      const allowed = (config.value('oid4vp.allowedWalletUrls') || []).map(
          (one) => {
        return String(one).replace(/\/+$/, '');
      });
      if (allowed.indexOf(asked) < 0) {
        log.debug("Leaving VcVerifier.vpWalletFor(). An unregistered wallet " +
                  "URL was refused.");
        return { error: 'The wallet URL "' + asked + '" is neither ' +
                        'oid4vp.walletUrl nor one listed in ' +
                        'oid4vp.allowedWalletUrls, and this realm does not ' +
                        'send a presentation request to an address the ' +
                        'request named. Add it to that setting, or leave the ' +
                        'wallet ' +
                        'parameter off.' };
      }
    }
    log.debug("Leaving VcVerifier.vpWalletFor().");
    return { url: (asked ||
                   configured) + String(config.value(
                       'oid4vp.walletPresentationPath') || '') };
  }

  // How old a Key Binding JWT may be. It is signed for one presentation, so
  // this is short on purpose.
  private vpKbMaxAgeS() {
    const { log, config } = this.deps;
    log.debug("Entering VcVerifier.vpKbMaxAgeS().");
    log.debug("Leaving VcVerifier.vpKbMaxAgeS().");
    return config.value('oid4vp.kbMaxAgeS');
  }

  // THE BOUND (oid4vp.maxTransactions, 2026-09-18), asked before a NEW
  // request is kept. At the bound the OLDEST waiting request goes, with its
  // request object — federation.maxContexts's rule, and for its reason: the
  // alternative is an endpoint anybody can reach that stops working for
  // everybody once it has been hit enough times, where this loses one
  // request somebody most likely abandoned, which fails and says so.
  private makeRoomForTransaction() {
    const { log, vpTransactions, vpRequests, config } = this.deps;
    log.debug("Entering VcVerifier.makeRoomForTransaction().");
    const max = Number(config.value('oid4vp.maxTransactions'));
    let evicted = 0;
    while (max > 0 && vpTransactions.size >= max) {
      const first = vpTransactions.keys().next();
      if (first.done) {
        break;
      }
      const record = vpTransactions.get(first.value);
      if (record && record.id) {
        vpRequests.delete(record.id);
      }
      vpTransactions.delete(first.value);
      evicted += 1;
    }
    if (evicted) {
      vpTransactionsCount.evicted(evicted);
    }
    log.debug("Leaving VcVerifier.makeRoomForTransaction(). " + evicted +
              " dropped.");
  }

  private sweepVpTransactions() {
    const { log, vpTransactions, vpRequests } = this.deps;
    log.debug("Entering VcVerifier.sweepVpTransactions().");
    const now = Date.now();
    vpTransactions.forEach((v, k) => {
      if (v.expires < now) {
        vpRequests.delete(v.id);
        vpTransactions.delete(k);
      }
    });
    log.debug("Leaving VcVerifier.sweepVpTransactions().");
  }

  // The DCQL query (OID4VP section 6): which credential, of which format, with
  // which claims. `claims` is what makes this a selective-disclosure request —
  // the Verifier names the paths it needs rather than asking for the
  // credential.
  //
  // The query differs by format in two ways, and both of them now live in
  // vc_verifier_config.ts rather than here: how the credential is IDENTIFIED (a
  // vct against a type array) and where the CLAIMS live (the top level, or
  // credentialSubject, or credentialSubject under a JSON-LD term that is not
  // the claim's own name). Getting the second wrong does not fail loudly — it
  // asks for a claim that is not there, and the presentation looks as though it
  // withheld something.
  vpDcqlQuery(format?: unknown) {
    const { log, logArtifact, vpConfig } = this.deps;
    log.debug("Entering VcVerifier.vpDcqlQuery(). format=" +
              (format || vpConfig.defaultFormatId()));
    const wanted = vpConfig.formatOf(format);
    const query = vpConfig.dcqlQuery(wanted);
    logArtifact('OID4VP DCQL query', 'as built (' + wanted + ')', query);
    log.debug("Leaving VcVerifier.vpDcqlQuery(). Asked as " + wanted + ".");
    return query;
  }

  // One Authorization Request, in the two shapes this mock offers:
  //
  //   by value client_id uses the redirect_uri prefix, so the request needs no
  //                 signature — and cannot have one, because the Wallet has no
  //                 way to obtain a key for a client identified only by a URL
  //                 (OID4VP section 5.10).
  //   by reference  a pre-registered client_id and a SIGNED Request Object at
  //                 request_uri, verifiable against this service's published
  //                 JWKS.
  //
  // **AND A THIRD, FOR A SIGN-IN (2026-09-17, #38).** `opts.signIn` is what
  // `vc_signin.ts` passes, and it changes these things about the request: it
  // is always by reference (the wallet can check a signed request names this
  // service); it asks for THIS issuer's credentials, in EVERY format a
  // sign-in accepts (`oid4vp.signInFormats`), one credential query per format
  // with a `credential_sets` saying any one of them will do
  // (`signInDcqlQuery()`); each query asks for what identifies the
  // credential and nothing more; and it lives as long as
  // `oid4vp.signInTtlS` says. What the sign-in module needs to find the
  // pending authentication again rides on the transaction as `signIn`, never
  // in anything the wallet is shown.
  //
  // **AND A SECOND REQUEST FOR THE DIGITAL CREDENTIALS API** when
  // `signIn.dcApiOrigin` is given (`dcApiRequest()`): the same nonce and the
  // same query, `response_mode` `dc_api.jwt` (or `dc_api`), no response URI,
  // and `expected_origins` naming this service's origin. One transaction, two
  // ways in, answered once.
  // ---------------------------------------------------------------------------
  // THE CLIENT IDENTIFIER OF A SIGNED REQUEST (OpenID4VP section 5.9, #129):
  // how the wallet is to know the key that signed it. `oid4vp.clientIdPrefix`
  // chooses; an unsigned request is always `redirect_uri:`.
  //
  //   pre-registered            `oid4vp.clientId`, as it always was: the
  //                             wallet has this Verifier's key out of band.
  //   decentralized_identifier  this realm's did:web, and the request's `kid`
  //                             a DID URL naming the signing key in that
  //                             document (`vc_did.ts` lists it).
  //   verifier_attestation      the `sub` of a Verifier Attestation JWT
  //                             carried in the `jwt` header, whose `cnf` is
  //                             the signing key — the configured one
  //                             (`oid4vp.verifierAttestation`), checked
  //                             against this realm's key before it is used,
  //                             or one this realm signs for itself.
  //   openid_federation         this realm's Entity Identifier; the wallet
  //                             resolves `/.well-known/openid-federation`
  //                             (`oidfed/oidfed.ts`, #132), whose
  //                             `openid_credential_verifier` metadata is
  //                             federationVerifierMetadata() below.
  //
  // Throws, with `code`, where the configured attestation cannot be used —
  // a request a wallet must refuse is worse than none.
  // ---------------------------------------------------------------------------
  signedClientId(req: any): { clientId: string; header: any;
                               kidDid: string } {
    const { log, config, baseUrlOf, stsDid } = this.deps;
    log.debug("Entering VcVerifier.signedClientId().");
    const prefix = String(config.value('oid4vp.clientIdPrefix') ||
                          'pre-registered');
    if (prefix === 'decentralized_identifier') {
      const did = stsDid(req);
      log.debug("Leaving VcVerifier.signedClientId(). A DID.");
      return { clientId: 'decentralized_identifier:' + did, header: {},
               kidDid: did };
    }
    if (prefix === 'verifier_attestation') {
      const attestation = this.verifierAttestation(req);
      log.debug("Leaving VcVerifier.signedClientId(). An attestation.");
      return { clientId: 'verifier_attestation:' + attestation.sub,
               header: { jwt: attestation.jwt }, kidDid: '' };
    }
    if (prefix === 'openid_federation') {
      // The realm's ENTITY IDENTIFIER (#132): its issuer, which is what its
      // Entity Configuration names as `iss` — the base URL unless an
      // `oauth2.issuer` is pinned.
      const entityId = require('../oidfed/oidfed').entityId(req);
      log.debug("Leaving VcVerifier.signedClientId(). A federation entity.");
      return { clientId: 'openid_federation:' + (entityId || baseUrlOf(req)),
               header: {}, kidDid: '' };
    }
    log.debug("Leaving VcVerifier.signedClientId(). Pre-registered.");
    return { clientId: this.vpClientId(), header: {}, kidDid: '' };
  }

  // The public JWK of the key signJwt() signs a request object with (the
  // realm's RS256 key), for an attestation's `cnf`.
  private requestSigningJwk(): any {
    const { log, STS, publishedKidFor } = this.deps;
    log.debug("Entering VcVerifier.requestSigningJwk().");
    const jwk: any = crypto.createPublicKey(STS.privateKey)
      .export({ format: 'jwk' });
    log.debug("Leaving VcVerifier.requestSigningJwk().");
    // The `kid` the signed header carries (`keys.kidFormat`), so a wallet
    // finds the key by it.
    return { kty: jwk.kty, n: jwk.n, e: jwk.e, use: 'sig', alg: 'RS256',
             kid: publishedKidFor(STS.kid) };
  }

  // THIS REALM'S VERIFIER AS AN OPENID FEDERATION ENTITY TYPE (OpenID4VP
  // section 11.2): the `openid_credential_verifier` metadata the realm's
  // Entity Configuration carries (`oidfed/oidfed.ts`, #132, which replaced
  // the Entity Configuration #129 served from here). `jwks` is the key the
  // request objects are signed with — a PROTOCOL key, published under the
  // protocol's entity type, never the Federation Entity Key.
  federationVerifierMetadata(req: any): Record<string, any> {
    const { log, baseUrlOf, siop } = this.deps;
    log.debug("Entering VcVerifier.federationVerifierMetadata().");
    const entity = baseUrlOf(req);
    const key = this.requestSigningJwk();
    const out = Object.assign({
      client_name: 'OpenID4VP Verifier',
      jwks: { keys: [key] },
      response_uris: [entity + '/oid4vp/response'],
      redirect_uris: [entity + '/oid4vp/response'],
      vp_formats_supported: this.vpFormatsSupported()
    }, siop.clientMetadata());
    log.debug("Leaving VcVerifier.federationVerifierMetadata().");
    return out;
  }

  // THE VERIFIER ATTESTATION (OpenID4VP section 12): `{ jwt, sub }`.
  verifierAttestation(req: any): { jwt: string; sub: string } {
    const { log, config, signJwt, nowSec, baseUrlOf, stsCrypto,
            errorCodes } = this.deps;
    log.debug("Entering VcVerifier.verifierAttestation().");
    const ours = this.requestSigningJwk();
    const configured = String(config.value('oid4vp.verifierAttestation') ||
                              '').trim();
    if (configured) {
      let header: any = null;
      let claims: any = null;
      try {
        const parts = configured.split('.');
        header = JSON.parse(Buffer.from(parts[0], 'base64url')
          .toString('utf8'));
        claims = JSON.parse(Buffer.from(parts[1], 'base64url')
          .toString('utf8'));
      } catch (e) {
        log.debug("Caught in VcVerifier.verifierAttestation(): " +
                  ((e && e.message) || e));
      }
      const cnf = claims && claims.cnf && claims.cnf.jwk;
      let problem = '';
      if (!header || !claims) {
        problem = 'it is not a readable JWT';
      } else if (header.typ !== 'verifier-attestation+jwt') {
        problem = 'its typ is "' + header.typ + '", not ' +
                  'verifier-attestation+jwt';
      } else if (typeof claims.sub !== 'string' || !claims.sub) {
        problem = 'it names no sub';
      } else if (!(Number(claims.exp) > nowSec())) {
        problem = 'it has expired';
      } else if (!cnf || stsCrypto.jwkThumbprint(cnf) !==
                 stsCrypto.jwkThumbprint(ours)) {
        problem = 'its cnf is not this realm\'s request-signing key';
      }
      if (problem) {
        log.error(errorCodes.tag('STS-VC-0092') + 'oid4vp: ' +
                  'oid4vp.verifierAttestation cannot be used — ' + problem +
                  '; no signed request is built until it is replaced.');
        const refused: any = new Error('oid4vp.verifierAttestation cannot ' +
                                       'be used: ' + problem + '.');
        refused.code = 'STS-VC-0092';
        log.debug("Leaving VcVerifier.verifierAttestation(). Unusable.");
        throw refused;
      }
      log.debug("Leaving VcVerifier.verifierAttestation(). Configured.");
      return { jwt: configured, sub: claims.sub };
    }
    // SELF-ATTESTED: this realm vouches for its own key. A wallet that does
    // not already trust this realm has no reason to believe it, which the
    // setting's description says; it is what makes the prefix testable.
    const sub = String(this.vpClientId());
    const now = nowSec();
    // certificate-header: none — a self-attestation names its key in `cnf`;
    // a chain would claim a trust the attestation does not have.
    const jwt = signJwt({ iss: baseUrlOf(req), sub: sub, iat: now,
                          exp: now + 3600, cnf: { jwk: ours } }, null,
                        { header: { typ: 'verifier-attestation+jwt' } });
    log.debug("Leaving VcVerifier.verifierAttestation(). Self-attested.");
    return { jwt: jwt, sub: sub };
  }

  buildVpRequest(req: any, opts: { byReference?: boolean; format?: string;
                                   signIn?: any; responseType?: string;
                                   responseMode?: string }) {
    const { log, logArtifact, baseUrlOf, nowSec, randomId, signJwt, vpConfig,
            stsCrypto, vpTransactions, vpRequests } = this.deps;
    log.debug("Entering VcVerifier.buildVpRequest(). byReference=" +
              !!opts.byReference +
              ", format=" + (opts.format || 'dc+sd-jwt') +
              ", signIn=" + !!opts.signIn);
    const signIn = opts.signIn || null;
    const byReference = !!opts.byReference || !!signIn;
    const base = baseUrlOf(req);
    const responseUri = base + '/oid4vp/response';
    const id = randomId(16);
    const nonce = randomId(18);
    const state = randomId(18);
    // SIOPv2 (#129): `id_token` asks for a self-issued ID Token alone,
    // `vp_token id_token` for one beside a presentation, whose holder it must
    // be. `form_post` sends the answer through the browser to a
    // `redirect_uri` where `direct_post` has the wallet POST it to a
    // `response_uri`; the handler is the same either way. A sign-in is always
    // `direct_post`: its binding cookie is SameSite=Lax, which a form posted
    // from the wallet's page would not carry.
    const responseType = String(opts.responseType || 'vp_token');
    const selfIssued = responseType.split(' ').indexOf('id_token') >= 0;
    const wantsVp = responseType.split(' ').indexOf('vp_token') >= 0;
    // OpenID4VP 1.0 section 8.3.1's `direct_post.jwt` (#187): the bar door
    // asks for an ENCRYPTED response when told to, to an ephemeral ECDH-ES
    // key of this transaction's own — the Digital Credentials API door's
    // arrangement (dcApiRequest()), over the Response URI. The OpenID
    // conformance suite's verifier plan has a variant for it, and the start
    // page refused the mode until then.
    const responseMode = !signIn && (opts.responseMode === 'form_post' ||
                                     opts.responseMode === 'direct_post.jwt')
      ? String(opts.responseMode) : 'direct_post';
    const signed = byReference ? this.signedClientId(req) : null;
    const clientId = signed ? signed.clientId :
                     ('redirect_uri:' + responseUri);
    const ttlMs = signIn && signIn.ttlMs > 0 ? Number(signIn.ttlMs) :
                  this.vpTtlMs();
    const formats = signIn && wantsVp ? this.signInFormats(signIn.formats) :
                    [];
    const request: Record<string, any> = {
      client_id: clientId,
      response_type: responseType,
      response_mode: responseMode,
      nonce: nonce,
      state: state,
      // OpenID4VP 1.0 section 5.1: client_metadata carries jwks,
      // encrypted_response_enc_values_supported and vp_formats_supported,
      // and "other metadata parameters MUST be ignored" — so the
      // `client_name` it carried was sent to be ignored, and the OpenID
      // conformance suite warned of it (#187). It is filled in below.
      client_metadata: {}
    };
    if (responseMode === 'form_post') {
      request.redirect_uri = responseUri;
    } else {
      request.response_uri = responseUri;
    }
    if (wantsVp) {
      request.dcql_query = signIn ? this.signInDcqlQuery(formats, base) :
                           this.vpDcqlQuery(opts.format);
      // All three formats are advertised whichever one this request asks
      // for: this is what the Verifier CAN accept, not what it wants this
      // time — the DCQL query is what says that.
      request.client_metadata.vp_formats_supported =
        this.vpFormatsSupported();
    }
    if (selfIssued) {
      // SIOPv2 section 9: the request is an OpenID Connect one, and section
      // 8 is what it says about the subjects and algorithms it accepts.
      request.scope = 'openid';
      Object.assign(request.client_metadata,
                    this.deps.siop.clientMetadata());
    }
    let encKey: any = null;
    if (responseMode === 'direct_post.jwt') {
      const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      // The kid NAMES the transaction: the encrypted response carries no
      // readable `state`, and its JWE header's `kid` is how the Response URI
      // finds whose key opens it.
      const kid = DIRECT_POST_JWT_KID + state;
      const publicJwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
        { use: 'enc', alg: 'ECDH-ES', kid: kid });
      const privatePem = String(pair.privateKey.export(
        { type: 'pkcs8', format: 'pem' }));
      const sealed = this.deps.keystore.seal(privatePem,
                                             'oid4vp direct_post.jwt key');
      encKey = { kid: kid, sealed: sealed || '',
                 plain: sealed ? '' : privatePem };
      request.client_metadata.jwks = { keys: [publicJwk] };
      request.client_metadata.encrypted_response_enc_values_supported =
        DC_API_ENC_VALUES;
    }
    if (!Object.keys(request.client_metadata).length) {
      delete request.client_metadata;
    }
    const record: Record<string, any> = {
      encKey: encKey,
      id: id, nonce: nonce, state: state, clientId: clientId,
      responseMode: responseMode, request: request,
      responseType: responseType,
      byReference: byReference,
      // The claims asked for, FROZEN onto the transaction rather than read
      // again when the presentation arrives. That is not tidiness: the list is
      // editable from /admin/vc-verifier-config while a presentation is in
      // flight, and a verifier that judged what came back against a list
      // changed after the request was sent would refuse a wallet for answering
      // the question it was actually asked.
      requested: signIn || !wantsVp ? [] : vpConfig.requestedClaims(),
      // Which format this Verifier asked for. The response is verified against
      // THIS, not against whatever shape happens to turn up, so a wallet that
      // answers a jwt_vc_json query with an SD-JWT is refused rather than
      // quietly accepted by the other code path.
      format: !wantsVp ? '' :
              signIn ? formats[0] : vpConfig.formatOf(opts.format),
      // The `vct` a presented SD-JWT VC must carry, frozen for the same
      // reason as the claims. Only a sign-in pins it; the bar door reads
      // `oid4vp.expectedVct` when the answer arrives, as it always did.
      expectedVct: signIn ? VCI_VCT : '',
      expires: Date.now() + ttlMs, verdict: null
    };
    if (signIn) {
      record.signIn = {
        authnId: String(signIn.authnId || ''),
        bindingHash: String(signIn.bindingHash || ''),
        completePath: String(signIn.completePath || ''),
        crossDevice: !!signIn.crossDevice,
        // query id -> format, and what each asks for; see signInDcqlQuery().
        queries: formats.reduce(function (acc, f) {
          acc[SIGN_IN_QUERY_IDS[f]] = f;
          return acc;
        }, {}),
        // The identifiers this realm issues under, for an ldp_vc's disclosed
        // `issuer`: the credential issuer URL, and its DID when any
        // configuration names one.
        issuers: [base].concat(signIn.issuerDids || []),
        responseCode: '',
        outcome: null,
        completed: false,
        dcApi: null,
        via: ''
      };
    }
    logArtifact('OID4VP Authorization Request', 'as built', request);
    if (byReference) {
      // RFC 9101: the Request Object is a signed JWT. iss/aud are the client
      // and the wallet; the wallet checks the signature against the client's
      // key, which for a pre-registered client it has out of band — here, this
      // service's JWKS.
      const payload = Object.assign({
        iss: clientId,
        aud: 'https://self-issued.me/v2',
        iat: nowSec(),
        exp: nowSec() + Math.floor(ttlMs / 1000)
      }, request);
      // `oid4vp.requestObjectCertificateHeader` decides the `x5c` / `x5u`.
      // `typ` goes in the PROTECTED HEADER (RFC 9101 section 10.8, explicit
      // typing), where a strict wallet looks for it; until 2026-09-18 it was
      // only a payload claim and the header said "JWT", which
      // `tests/vendored/sts_oid4vp_wallet.js` found. The claim is kept: it is
      // what the token registry labels this JWT by on /admin/tokens.
      record.requestObject = signJwt(
        Object.assign({ typ: 'oauth-authz-req+jwt' }, payload), null,
        { certificateHeader: 'vp-request-object',
          header: Object.assign({ typ: 'oauth-authz-req+jwt' },
                                signed.header),
          kidDid: signed.kidDid || undefined });
      logArtifact('OID4VP Request Object', 'after signing',
                  record.requestObject);
      vpRequests.set(id, state);
    }
    // The Digital Credentials API carries OpenID4VP only: a self-issued
    // request is answered by link or QR code.
    if (signIn && signIn.dcApiOrigin && !selfIssued) {
      record.signIn.dcApi = this.dcApiRequest(record, String(
        signIn.dcApiOrigin), String(signIn.dcApiResponseMode || ''));
    }
    this.sweepVpTransactions();
    this.makeRoomForTransaction();
    vpTransactions.set(state, record);
    log.debug("Leaving VcVerifier.buildVpRequest(). state=" + state + ", " +
              "nonce=" + nonce);
    return record;
  }

  // What this Verifier can accept, per format (OpenID4VP Appendix B). Every
  // asymmetric algorithm the shared table has, post-quantum included, for the
  // JOSE formats — the checks are asynchronous and hand a post-quantum one to
  // the pool; for ldp_vc the Data Integrity proof type and the cryptosuites:
  // bbs-2023 for the credential, and the holder suites a presentation's proof
  // may use.
  private vpFormatsSupported(): any {
    const { log, vcDataIntegrity } = this.deps;
    log.debug("Entering VcVerifier.vpFormatsSupported().");
    log.debug("Leaving VcVerifier.vpFormatsSupported().");
    return {
      'dc+sd-jwt': { 'sd-jwt_alg_values': ALL_ALGS,
                     'kb-jwt_alg_values': ALL_ALGS },
      'jwt_vc_json': { alg_values: ALL_ALGS },
      'ldp_vc': { proof_type_values: ['DataIntegrityProof'],
                  cryptosuite_values: ['bbs-2023'].concat(
                    vcDataIntegrity.SUPPORTED_CRYPTOSUITES) }
    };
  }

  // The formats a sign-in asks in: `oid4vp.signInFormats`, in the order given
  // (the order is the preference a wallet that answers only the first query
  // it understands will follow), filtered to the ones a sign-in can verify.
  signInFormats(asked?: unknown): string[] {
    const { log, config } = this.deps;
    log.debug("Entering VcVerifier.signInFormats().");
    const named = [].concat(asked || config.value('oid4vp.signInFormats') ||
                            [])
      .map(function (one) {
        return String(one).trim().replace(/ /g, '+');
      })
      .filter(function (one, i, all) {
        return SIGN_IN_FORMATS.indexOf(one) >= 0 && all.indexOf(one) === i;
      });
    log.debug("Leaving VcVerifier.signInFormats(). " + named.join(', '));
    return named.length ? named : SIGN_IN_FORMATS.slice();
  }

  // ---------------------------------------------------------------------------
  // THE SIGNED REQUEST FOR THE DIGITAL CREDENTIALS API (OpenID4VP 1.0
  // Appendix A.3.2.1), and the key its response is encrypted to.
  //
  //   * `expected_origins` names this service's origin, and nothing else: a
  //     wallet that is handed this request by a page on another origin
  //     refuses it (A.2), which is what stops somebody copying it into a page
  //     of their own.
  //   * `response_mode` is `dc_api.jwt` by default — the response travels
  //     through the page's script, and encrypting it to a key only this
  //     transaction holds keeps the credential out of anything else on the
  //     page (Section 14.5) — or `dc_api` where `oid4vp.signInDcApiResponseMode`
  //     says so, for a wallet that cannot encrypt.
  //   * The key is an ephemeral P-256 ECDH-ES key, one per transaction,
  //     published in `client_metadata.jwks` with `alg` and a `kid` (Section
  //     8.3). Its private half is kept on the transaction SEALED under the
  //     key-encryption key where one exists (product mode) and lives exactly
  //     as long as the transaction.
  //   * No `response_uri`, `redirect_uri` or `state`: the response comes back
  //     to the page that asked (A.2 lists what applies).
  // ---------------------------------------------------------------------------
  private dcApiRequest(record: any, origin: string, modeAsked: string): any {
    const { log, logArtifact, nowSec, signJwt, keystore, randomId,
            config } = this.deps;
    log.debug("Entering VcVerifier.dcApiRequest(). origin=" + origin);
    const configured = String(modeAsked ||
      config.value('oid4vp.signInDcApiResponseMode') || 'dc_api.jwt');
    const responseMode = DC_API_RESPONSE_MODES.indexOf(configured) >= 0 ?
      configured : 'dc_api.jwt';
    // No `client_name`: section 5.1's parameters only (#187).
    const clientMetadata: any = {
      vp_formats_supported: this.vpFormatsSupported()
    };
    let encKey: any = null;
    if (responseMode === 'dc_api.jwt') {
      const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const kid = 'dcapi-' + randomId(8);
      const publicJwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
        { use: 'enc', alg: 'ECDH-ES', kid: kid });
      const privatePem = String(pair.privateKey.export(
        { type: 'pkcs8', format: 'pem' }));
      const sealed = keystore.seal(privatePem, 'oid4vp dc_api response key');
      encKey = { kid: kid, sealed: sealed || '',
                 plain: sealed ? '' : privatePem };
      clientMetadata.jwks = { keys: [publicJwk] };
      clientMetadata.encrypted_response_enc_values_supported =
        DC_API_ENC_VALUES;
    }
    const payload = {
      iss: record.clientId,
      aud: 'https://self-issued.me/v2',
      iat: nowSec(),
      exp: Math.floor(record.expires / 1000),
      client_id: record.clientId,
      response_type: 'vp_token',
      response_mode: responseMode,
      nonce: record.nonce,
      dcql_query: record.request.dcql_query,
      client_metadata: clientMetadata,
      expected_origins: [origin]
    };
    logArtifact('OID4VP Request Object (Digital Credentials API)', 'as built',
                payload);
    // `typ` in the protected header too (RFC 9101 section 10.8) — see
    // buildVpRequest().
    const requestObject = signJwt(
      Object.assign({ typ: 'oauth-authz-req+jwt' }, payload), null,
      { certificateHeader: 'vp-request-object',
        header: { typ: 'oauth-authz-req+jwt' } });
    log.debug("Leaving VcVerifier.dcApiRequest(). " + responseMode + ".");
    return { origin: origin, protocol: DC_API_PROTOCOL,
             responseMode: responseMode, request: requestObject,
             encKey: encKey };
  }

  // What the page hands `navigator.credentials.get()`: one request, in the
  // protocol this door signs.
  dcApiRequestFor(record: any): any {
    const { log } = this.deps;
    log.debug("Entering VcVerifier.dcApiRequestFor().");
    const dc = record && record.signIn && record.signIn.dcApi;
    log.debug("Leaving VcVerifier.dcApiRequestFor(). " + (dc ? "One." :
                                                          "None."));
    return dc ? { protocol: dc.protocol, data: { request: dc.request } }
              : null;
  }

  // ---------------------------------------------------------------------------
  // THE DCQL QUERY A SIGN-IN ASKS WITH (OpenID4VP section 6): one credential
  // query per format in `formats`, and a credential set saying any ONE of
  // them answers it (section 6.2). Each asks for this issuer's credential by
  // what identifies it — the `vct`, or the W3C type set — and for the claims
  // a sign-in needs and no more:
  //
  //   dc+sd-jwt    `sub` (never a Disclosure, so this discloses nothing
  //                else)
  //   jwt_vc_json  `credentialSubject.id` — the format discloses the whole
  //                credential regardless, and the wallet shows the person so
  //                before anything is sent
  //   ldp_vc       `credentialSubject.id` (the holder's did:jwk), `issuer`,
  //                `validFrom` and `validUntil` — see verifyLdpVc() for why
  //                each — and `credentialStatus`, which the status check
  //                reads
  //
  // Holder binding is left at its default, REQUIRED, for all three.
  // ---------------------------------------------------------------------------
  signInDcqlQuery(formats?: string[], base?: string) {
    const { log, logArtifact } = this.deps;
    log.debug("Entering VcVerifier.signInDcqlQuery().");
    void base;
    const wanted = formats && formats.length ? formats :
                   this.signInFormats();
    const credentials = wanted.map(function (format) {
      const id = SIGN_IN_QUERY_IDS[format];
      if (format === 'dc+sd-jwt') {
        return { id: id, format: format,
                 meta: { vct_values: [VCI_VCT] },
                 claims: [{ path: ['sub'] }] };
      }
      if (format === 'jwt_vc_json') {
        return { id: id, format: format,
                 meta: { type_values: [VCI_JWT_TYPES] },
                 claims: [{ path: ['credentialSubject', 'id'] }] };
      }
      return { id: id, format: format,
               meta: { type_values: [VCI_JWT_TYPES] },
               claims: [{ path: ['credentialSubject', 'id'] },
                        { path: ['issuer'] },
                        { path: ['validFrom'] },
                        { path: ['validUntil'] },
                        { path: ['credentialStatus'] }] };
    });
    const query: any = { credentials: credentials };
    if (credentials.length > 1) {
      query.credential_sets = [{
        options: credentials.map(function (c) {
          return [c.id];
        }),
        required: true
      }];
    }
    logArtifact('OID4VP DCQL query', 'as built for a sign-in', query);
    log.debug("Leaving VcVerifier.signInDcqlQuery(). " + wanted.join(', '));
    return query;
  }

  // The query the wallet is handed: by value it carries the whole request, by
  // reference only client_id and request_uri (OID4VP section 5.2).
  vpRequestQuery(req: any, record: any) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering VcVerifier.vpRequestQuery().");
    const base = baseUrlOf(req);
    // By value, every member the request holds — the SIOPv2 ones (#129:
    // `scope`, a `redirect_uri` for form_post, no `dcql_query` for an ID
    // Token alone) included — objects as JSON.
    const params: Record<string, string> = {};
    if (record.byReference) {
      params.client_id = record.clientId;
      params.request_uri = base + '/oid4vp/request/' + record.id;
      params.request_uri_method = 'get';
    } else {
      ['client_id', 'response_type', 'response_mode', 'response_uri',
       'redirect_uri', 'scope', 'nonce', 'state', 'dcql_query',
       'client_metadata'].forEach(function (k) {
        const v = record.request[k];
        if (v !== undefined) {
          params[k] = typeof v === 'string' ? v : JSON.stringify(v);
        }
      });
    }
    const query = Object.keys(params)
      .map((k) => {
        return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
      })
      .join('&');
    log.debug("Leaving VcVerifier.vpRequestQuery(). " +
              Object.keys(params).length + " parameter(s).");
    return query;
  }

  // The Verifier's screen in a cross-device presentation.
  private renderVpQrPage(res: any, opts: any) {
    const { log, xmlEscape, errorCodes } = this.deps;
    log.debug("Entering VcVerifier.renderVpQrPage().");
    qrcode.toDataURL(opts.requestUri,
                     { errorCorrectionLevel: 'M', margin: 2, width: 320 })
      .then((dataUrl) => {
        const page = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
          'charset="utf-8"><title>The Bar Door — scan to ' +
          'present</title><style>body{font-family:system-ui,-apple-system,' +
          '"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
          'display:flex;align-items:center;justify-content:center;' +
          'min-height:100vh;color:#222}.card{background:#fff;border:1px ' +
          'solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
          'box-shadow:0 6px 24px rgba(0,0,0,.08);text-align:center}' +
          'h1{font-size:1.25em;margin:0 0 6px}p{line-height:1.5;color:#333}' +
          'img.qr{margin:14px auto;display:block;border:1px solid #eee;' +
          'border-radius:8px}.uri{word-break:break-all;' +
          'font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
          'font-size:.72em;color:#555;background:#fafafa;border:1px solid ' +
          '#eee;border-radius:6px;padding:8px;text-align:left}' +
          '.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;' +
          'font-size:.78em;color:#777;text-align:left}' +
          'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
          '</style></head><body><div class="card"><h1>Scan this with your ' +
          'wallet</h1><p>Your wallet will show you exactly which claims we ' +
          'are asking for before anything is sent.</p><img class="qr" ' +
          'id="request_qr" alt="OID4VP Authorization Request QR code" ' +
          'src="' + dataUrl + '"><div class="uri" ' +
          'id="request_uri">' + xmlEscape(opts.requestUri) + '</div><div ' +
          'class="meta">OID4VP cross-device flow. The wallet is on your ' +
          'other device, so it cannot be redirected — it reads the request ' +
          'from this code and POSTs the presentation straight back to us ' +
          '(<code>response_mode=direct_post</code>). The <code>nonce</code> ' +
          'in the request is what stops a presentation from being replayed. ' +
          'If your wallet is on this device, <a id="open_in_wallet" ' +
          'href="' + xmlEscape(opts.walletUrl) + '">open ' +
          'it here</a>.</div></div></body></html>\n';
        res.status(200).type('text/html').send(page);
        log.debug("Leaving VcVerifier.renderVpQrPage().");
      })
      .catch((e) => {
        log.debug("Caught in VcVerifier.renderVpQrPage(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0034') +
                  "could not render the presentation QR code: " + e.message);
        errorCodes.mark(res, 'STS-VC-0034');
        res.status(500).type('text/plain').send('Could not render the ' +
                                                'Authorization Request QR ' +
                                                'code: ' + e.message);
      });
    log.debug("Leaving VcVerifier.renderVpQrPage().");
  }

  // ---------------------------------------------------------------------------
  // Verifying a presentation (RFC 9901 section 7.3, plus OID4VP's rules for the
  // Key Binding JWT).
  //
  // Every check is recorded with its own verdict rather than collapsed into one
  // boolean: "the presentation was refused" is not a useful answer to a wallet
  // developer, and a debugger's job is to say WHICH rule was broken.
  // ---------------------------------------------------------------------------
  private vpCheck(checks: any[], name: string, ok: unknown, detail: unknown) {
    const { log } = this.deps;
    log.debug("Entering VcVerifier.vpCheck().");
    checks.push({ name: name, ok: !!ok, detail: detail });
    log.debug("this.vpCheck(): " + name + " -> " + (ok ? "OK" : "FAILED") +
              " (" +
              detail + ")");
    log.debug("Leaving VcVerifier.vpCheck().");
    return !!ok;
  }

  // base64url(hash) of the US-ASCII of everything before the KB-JWT, which is
  // what sd_hash has to be (RFC 9901 section 4.3.1).
  private sdHashOf(presentedWithoutKb: string, sdAlg: unknown) {
    const { log, b64u } = this.deps;
    log.debug("Entering VcVerifier.sdHashOf().");
    const alg = String(sdAlg || 'sha-256').toLowerCase();
    const nodeAlg = { 'sha-256': 'sha256', 'sha-384': 'sha384',
                      'sha-512': 'sha512' }[alg];
    if (!nodeAlg) {
      log.debug("Leaving VcVerifier.sdHashOf().");
      return null;
    }
    log.debug("Leaving VcVerifier.sdHashOf().");
    return b64u(crypto.createHash(nodeAlg)
                      .update(presentedWithoutKb, 'ascii')
                      .digest());
  }

  // A bbs-2023 derived proof (OID4VP format ldp_vc).
  //
  // The same questions as the other two formats, asked of a very different
  // artefact. There is no issuer signature to check on what arrives — a derived
  // proof IS the signature, re-randomised — so "did the issuer sign this" is
  // the derived proof's check.
  //
  // SHAPE NOTE, a stated simplification: a full bbs-2023 presentation
  // reconstructs a JSON-LD document from the disclosed statements. This mock is
  // handed the statements and their indexes directly, beside the proof and the
  // issuer's proof options. Everything cryptographic is real — the proof is
  // verified against this service's BBS key over exactly those statements, with
  // this request's nonce as the presentation header — but another verifier
  // would expect a document.
  //
  // ---------------------------------------------------------------------------
  // **AND THE HOLDER (#38's follow-ups).** A derived proof is not a holder
  // binding: bbs-2023 has no holder secret, so anybody holding the base
  // credential can derive one, and it binds the request's nonce and nothing
  // about who derived it or for whom. OpenID4VP B.1.3.2.5 says what does: a
  // W3C VerifiablePresentation whose Data Integrity proof carries
  // `challenge` = the nonce and `domain` = the Client Identifier (or
  // `origin:<origin>` over the Digital Credentials API). So the presentation
  // may arrive in either of two shapes:
  //
  //   * the bare envelope above — `{ cryptosuite, proof, disclosedStatements,
  //     disclosedIndexes, proofOptions }` — which the bar door still accepts,
  //     and whose query says `require_cryptographic_holder_binding: false`;
  //   * `{ @context, type: [VerifiablePresentation], holder?,
  //     verifiableCredential: [<that envelope>], proof: <Data Integrity> }`,
  //     whose proof `vc_data_integrity.ts` verifies — over the whole
  //     presentation, envelope included — and whose key must be the one the
  //     disclosed `credentialSubject` statement names as a did:jwk.
  //
  // A sign-in (`ctx.requireHolderBinding`) accepts only the second, and also
  // needs the credential's `issuer`, `validFrom` and `validUntil` statements
  // disclosed: the issuer because this service's BBS key is one for every
  // realm (so the derived proof alone does not say which realm issued it),
  // and the window because it is what tells a presented credential apart
  // from its siblings in the sign-in register (`vc_issued.ts`) and whether it
  // is still valid.
  // ---------------------------------------------------------------------------
  private async verifyLdpVc(presentation: any, record: any, ctx?: any) {
    const { log, bbsKeyPair, vcDataIntegrity, nowSec } = this.deps;
    log.debug("Entering VcVerifier.verifyLdpVc().");
    const context = ctx || {};
    const expectedAud = String(context.aud || record.clientId);
    const checks = [];
    const result: any = { ok: false, checks, claims: {}, disclosed: [], vct: '',
                     sub: '', extraDisclosed: [], holderJwk: null,
                     credentialStatus: [], validFrom: '', validUntil: '',
                     issuer: '' };

    let payload;
    try {
      payload = typeof presentation === 'string' ? JSON.parse(presentation) :
                presentation;
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyLdpVc(): " +
                ((e && e.message) || e));
      this.vpCheck(checks, 'Format', false, 'an ldp_vc presentation here is ' +
                   'a JSON ' +
        'object carrying the derived proof and the statements it discloses; ' +
        'this is not JSON: ' + e.message);
      log.debug("Leaving VcVerifier.verifyLdpVc().");
      return result;
    }
    const vp = payload && [].concat(payload.type || [])
      .indexOf('VerifiablePresentation') >= 0 ? payload : null;
    const envelope = vp ? [].concat(vp.verifiableCredential || [])[0]
                        : payload;
    if (vp && (!envelope || typeof envelope !== 'object')) {
      this.vpCheck(checks, 'Format', false, 'the VerifiablePresentation ' +
                   'carries no derived credential in verifiableCredential.');
      log.debug("Leaving VcVerifier.verifyLdpVc(). An empty presentation.");
      return result;
    }
    const proofBytes = envelope && typeof envelope.proof === 'string' ?
      bbs2023.b64uToBytes(envelope.proof) : null;
    const statements = [].concat((envelope && envelope.disclosedStatements) ||
                                 []);
    const indexes = [].concat((envelope && envelope.disclosedIndexes) || []);
    if (!proofBytes || !statements.length ||
        statements.length !== indexes.length) {
      this.vpCheck(checks, 'Format', false,
        'expected proof, disclosedStatements and disclosedIndexes of equal ' +
        'length; got ' +
        statements.length + ' statement(s) and ' + indexes.length +
        ' index(es).');
      log.debug("Leaving VcVerifier.verifyLdpVc().");
      return result;
    }
    this.vpCheck(checks, 'Format', true,
      'a bbs-2023 derived proof disclosing ' + statements.length + ' ' +
      'canonical statement(s)' + (vp ? ', inside a VerifiablePresentation.' :
                                       ', with no presentation around it.'));

    // EVERY LIVE GENERATION OF THE REALM'S BBS KEY (#49 P5): the one the
    // proof options name first, then the rest — a credential issued before a
    // rotation still verifies through its grace.
    const generations = this.deps.bbsGenerations
      ? await this.deps.bbsGenerations()
      : [{ kid: '', publicKey: (await bbsKeyPair()).publicKey }];
    const named = String((envelope.proofOptions || {}).verificationMethod ||
                         '');
    generations.sort(function (a: any, b: any): number {
      return (named && named.indexOf(b.kid) >= 0 ? 1 : 0) -
             (named && named.indexOf(a.kid) >= 0 ? 1 : 0);
    });
    let header;
    try {
      header = await bbs2023.headerFor(envelope.proofOptions || {});
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyLdpVc(): " +
                ((e && e.message) || e));
      this.vpCheck(checks, 'Proof options', false,
              'could not be canonicalized: ' + e.message);
      log.debug("Leaving VcVerifier.verifyLdpVc().");
      return result;
    }
    this.vpCheck(checks, 'Proof options', true, 'canonicalized to the ' +
                 'header the base proof was bound to.');

    let ok = false;
    for (let g = 0; g < generations.length && !ok; g++) {
      ok = await bbs2023.verifyDerived(generations[g].publicKey, proofBytes,
        header, Buffer.from(String(record.nonce), 'utf8'), statements,
        indexes);
    }
    this.vpCheck(checks, 'Derived proof', ok, ok
      ? "verifies against this issuer's BBS key over exactly the statements " +
        "disclosed, and against this request's nonce — so it was derived for " +
        "THIS request and cannot be replayed."
      : 'does not verify. Either it was not derived from a credential this ' +
        'issuer signed, the statements do not match what was proved, or it ' +
        'was derived against a different nonce.');

    statements.forEach((line, i) => {
      result.claims['statement ' + (indexes[i] + 1)] = String(line).trim();
    });
    result.disclosed = indexes.map((i) => {
      return 'statement ' + (i + 1);
    });

    // What the disclosed statements say about the credential itself.
    const read = this.ldpFacts(statements);
    result.sub = read.subject;
    result.issuer = read.issuer;
    result.validFrom = read.validFrom;
    result.validUntil = read.validUntil;
    result.credentialStatus = read.credentialStatus;
    const now = nowSec();
    const from = Date.parse(read.validFrom) / 1000;
    const until = Date.parse(read.validUntil) / 1000;
    if (read.validFrom || read.validUntil || context.requireHolderBinding) {
      this.vpCheck(checks, 'Validity window',
        (!!read.validFrom || !context.requireHolderBinding) &&
        (!!read.validUntil || !context.requireHolderBinding) &&
        (!read.validFrom || from <= now + 60) &&
        (!read.validUntil || until > now),
        'validFrom ' + (read.validFrom || '(not disclosed)') + ', validUntil ' +
        (read.validUntil || '(not disclosed)') + ', now ' + now + '.' +
        (context.requireHolderBinding ? ' A sign-in asks for both.' : ''));
    }
    if (context.requireHolderBinding) {
      const issuers = [].concat(context.issuers || []);
      this.vpCheck(checks, 'Issuer', issuers.indexOf(read.issuer) >= 0,
        'the disclosed issuer is "' + (read.issuer || '(not disclosed)') +
        '"; this realm issues as ' + issuers.join(' or ') + '.');
    }

    // --- the holder --------------------------------------------------------
    if (!vp) {
      this.vpCheck(checks, 'Holder binding', !context.requireHolderBinding,
        context.requireHolderBinding
          ? 'a bare derived proof proves nothing about who presents it; ' +
            'this request needs a VerifiablePresentation whose Data ' +
            'Integrity proof is made with the key the credential names.'
          : 'none asked for: this request said ' +
            'require_cryptographic_holder_binding is false, and a bare ' +
            'derived proof binds only the nonce.');
    } else {
      const verdict = await vcDataIntegrity.verifyProof(vp, {
        expectedChallenge: record.nonce,
        expectedDomain: expectedAud,
        expectedPurpose: 'authentication',
        maxAgeS: Number(this.vpKbMaxAgeS()) || undefined
      });
      verdict.checks.forEach((c) => {
        this.vpCheck(checks, 'Holder proof — ' + c.name, c.ok, c.detail);
      });
      let named: any = null;
      try {
        named = read.subject ? vcDataIntegrity.jwkOfDidJwk(read.subject) : null;
      } catch (e) {
        log.debug("Caught in VcVerifier.verifyLdpVc(): " +
                  ((e && e.message) || e));
        named = null;
      }
      let same = false;
      try {
        same = !!named && !!verdict.jwk &&
          this.deps.stsCrypto.jwkThumbprint(named, {}) ===
          this.deps.stsCrypto.jwkThumbprint(verdict.jwk, {});
      } catch (e) {
        log.debug("Caught in VcVerifier.verifyLdpVc(): " +
                  ((e && e.message) || e));
        same = false;
      }
      this.vpCheck(checks, 'Holder binding', verdict.ok && same,
        !read.subject
          ? 'the credentialSubject statement was not disclosed, so nothing ' +
            'says which key may present this credential.'
          : same
            ? 'the presentation is proved by ' + read.subject + ', the key ' +
              'the credential names as its subject.'
            : 'the presentation is proved by ' +
              (verdict.controller || 'no key') + ', and the credential names ' +
              read.subject + '.');
      if (same) {
        result.holderJwk = named;
      }
    }
    result.ok = checks.every((c) => { return c.ok; });
    log.debug("Leaving VcVerifier.verifyLdpVc(). " +
              (result.ok ? 'accepted' : 'REFUSED'));
    return result;
  }

  // ---------------------------------------------------------------------------
  // THE FACTS AN ldp_vc's DISCLOSED STATEMENTS STATE ABOUT THE CREDENTIAL:
  // its subject (a did:jwk), issuer, validity window and status entries.
  // Canonical N-Quads, one statement per line; the credential itself is a
  // blank node, and a `credentialStatus` entry is the node its `id` names.
  // Nothing here is trusted until the derived proof over exactly these lines
  // has verified, which the caller asks first.
  // ---------------------------------------------------------------------------
  private ldpFacts(statements: string[]): any {
    const { log } = this.deps;
    log.debug("Entering VcVerifier.ldpFacts().");
    const out: any = { subject: '', issuer: '', validFrom: '',
                       validUntil: '', credentialStatus: [] };
    const nodes: Record<string, any> = {};
    const term = /^(<[^>]*>|_:\S+)\s+<([^>]*)>\s+(<[^>]*>|_:\S+|"(?:[^"\\]|\\.)*"(?:\^\^<[^>]*>|@[A-Za-z-]+)?)/;
    const value = function (raw: string): string {
      log.debug("Entering value().");
      if (raw.charAt(0) === '<') {
        log.debug("Leaving value(). An IRI.");
        return raw.slice(1, -1);
      }
      if (raw.charAt(0) === '"') {
        log.debug("Leaving value(). A literal.");
        return JSON.parse(raw.slice(0, raw.lastIndexOf('"') + 1));
      }
      log.debug("Leaving value(). A blank node.");
      return raw;
    };
    statements.forEach(function (line) {
      const m = term.exec(String(line).trim());
      if (!m) {
        return;
      }
      const s = value(m[1]);
      const p = m[2];
      const o = value(m[3]);
      if (p === CRED + 'credentialSubject' && /^did:jwk:/.test(o)) {
        out.subject = o;
      } else if (p === CRED + 'issuer') {
        out.issuer = o;
      } else if (p === CRED + 'validFrom') {
        out.validFrom = o;
      } else if (p === CRED + 'validUntil') {
        out.validUntil = o;
      } else if (p.indexOf(STATUS_NS) === 0 ||
                 (p === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type' &&
                  o === STATUS_NS + 'BitstringStatusListEntry')) {
        const node = nodes[s] || (nodes[s] = { id: s });
        if (p.indexOf(STATUS_NS) === 0) {
          node[p.slice(STATUS_NS.length)] = o;
        } else {
          node.type = 'BitstringStatusListEntry';
        }
      }
    });
    Object.keys(nodes).forEach(function (id) {
      const n = nodes[id];
      if (n.type && n.statusListIndex !== undefined) {
        out.credentialStatus.push({
          id: n.id, type: 'BitstringStatusListEntry',
          statusPurpose: n.statusPurpose,
          statusListIndex: String(n.statusListIndex),
          statusListCredential: n.statusListCredential });
      }
    });
    log.debug("Leaving VcVerifier.ldpFacts(). subject=" +
              (out.subject ? 'yes' : 'no') + ", status entries " +
              out.credentialStatus.length + ".");
    return out;
  }

  // A W3C Verifiable Presentation secured as a JWT, carrying a jwt_vc_json
  // credential (OID4VP with format jwt_vc_json).
  //
  // The checks are the same QUESTIONS the SD-JWT path asks, answered against a
  // different artefact — which is the point of running both formats through
  // this workflow:
  //
  //   who signed the credential          the issuer's key, as before
  //   is it still valid                  nbf/exp, as before
  //   is the holder the one it was bound to
  //                                      here the VP JWT's signature against
  //                                      the credential's cnf.jwk, where an
  //                                      SD-JWT uses a Key Binding JWT
  //   is this presentation fresh and for us
  //                                      nonce and aud, as before — but they
  //                                      are claims of the VP JWT, not of a
  //                                      KB-JWT
  //   what was disclosed everything in credentialSubject, because
  //                                      this format cannot withhold anything
  //
  // There is deliberately no sd_hash equivalent: an SD-JWT's KB-JWT commits to
  // the exact bytes presented because a presentation can be a SUBSET. A VP JWT
  // signs over the whole credential it embeds, so the commitment is the
  // signature.
  //
  // **FRESHNESS AND THE AUDIENCE FORM (#38's follow-ups).** The VP JWT's
  // `iat` is held to `oid4vp.kbMaxAgeS`, as a Key Binding JWT's is — without
  // it a VP made for this nonce could be kept and replayed for as long as the
  // transaction lives, and a sign-in is exactly where that matters. `aud` is
  // the Client Identifier, or `origin:<origin>` over the Digital Credentials
  // API (OpenID4VP B.1.3.1.5), and may be a string or an array holding it
  // (RFC 7519 section 4.1.3). The signature checks — the credential's and
  // the presentation's — are asynchronous, so a post-quantum issuer or
  // holder key is verified in the worker pool like any other.
  private async verifyVpJwt(presentation: any, record: any, ctx?: any) {
    const { log, logArtifact, jsonFromB64u, nowSec, stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.verifyVpJwt().");
    const context = ctx || {};
    const expectedAud = String(context.aud || record.clientId);
    // Named as the source check in tests/revocation_status.js reads it.
    const verifyIssuerSignatureAsync =
        this.verifyIssuerSignatureAsync.bind(this);
    logArtifact('OID4VP Verifiable Presentation (jwt_vc_json)', 'as received',
                presentation);
    const checks = [];
    const result: any = { ok: false, checks: checks, claims: {}, disclosed: [],
                     vct: '', sub: '',
                     extraDisclosed: [] };

    // The tilde test comes FIRST, and it has to. An SD-JWT Combined
    // Serialization is <JWT>~<Disclosure>*~ — splitting THAT on "." also yields
    // three parts, because the tildes hang off the end of the signature
    // segment. So a part-count check alone lets an SD-JWT through to be
    // reported as an undecodable JWT, which names the wrong problem: the wallet
    // answered in the wrong FORMAT, and that is what it needs to be told.
    const raw = String(presentation || '');
    if (raw.indexOf('~') >= 0) {
      this.vpCheck(checks, 'Format', false,
        'this is an SD-JWT Combined Serialization (it contains "~"), but ' +
        'this request asked for jwt_vc_json, whose presentation is a ' +
        'Verifiable Presentation JWT.');
      log.debug("Leaving VcVerifier.verifyVpJwt(). An SD-JWT answered a " +
                "jwt_vc_json query.");
      return result;
    }
    const vpParts = raw.split('.');
    if (vpParts.length !== 3) {
      this.vpCheck(checks, 'Format', false,
        'a jwt_vc_json presentation is a Verifiable Presentation JWT (three ' +
        'parts); this has ' +
        vpParts.length + ' part(s).');
      log.debug("Leaving VcVerifier.verifyVpJwt(). Not a JWS.");
      return result;
    }
    let vpHeader: any = {}, vpPayload: any = {};
    try {
      vpHeader = jsonFromB64u(vpParts[0]);
      vpPayload = jsonFromB64u(vpParts[1]);
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyVpJwt(): " +
                ((e && e.message) || e));
      this.vpCheck(checks, 'Format', false,
              'the presentation JWT cannot be decoded: ' + e.message);
      log.debug("Leaving VcVerifier.verifyVpJwt().");
      return result;
    }
    const vp = vpPayload.vp || {};
    const embedded = [].concat(vp.verifiableCredential || []);
    if (!embedded.length || typeof embedded[0] !== 'string') {
      this.vpCheck(checks, 'Format', false,
        'the vp claim carries no verifiableCredential; a jwt_vc_json ' +
        'presentation embeds the credential JWT there.');
      log.debug("Leaving VcVerifier.verifyVpJwt(). No credential inside.");
      return result;
    }
    this.vpCheck(checks, 'Format', true,
      'Verifiable Presentation JWT carrying ' + embedded.length + ' ' +
      'credential(s); no Disclosures, because jwt_vc_json has no selective ' +
      'disclosure.');

    // --- the credential inside -----------------------------------------------
    const vcJwt = embedded[0];
    let vcHeader: any = {}, vcPayload: any = {};
    try {
      vcHeader = jsonFromB64u(vcJwt.split('.')[0]);
      vcPayload = jsonFromB64u(vcJwt.split('.')[1]);
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyVpJwt(): " +
                ((e && e.message) || e));
      this.vpCheck(checks, 'Credential', false, 'the embedded credential ' +
                   'cannot be ' +
                                           'decoded: ' + e.message);
      log.debug("Leaving VcVerifier.verifyVpJwt().");
      return result;
    }
    const vc = vcPayload.vc || {};
    const subject = vc.credentialSubject || {};
    result.sub = vcPayload.sub || subject.id || '';

    let issuerSignatureOk = false;
    try {
      // Applies `oauth2.clockSkewS` since 2026-08-27. This was the third of the
      // four verifications of our own tokens that had drifted away from the
      // rule `oauth-oidc/oauth2.ts` states — and here the effect was sharpest,
      // because a credential presented at the very edge of its validity window
      // was reported to a person as a FAILED ISSUER SIGNATURE, which is the one
      // verdict on this page that reads like an attack rather than like a
      // clock.
      result.issuerCertificatePem =
        (await verifyIssuerSignatureAsync(vcJwt)).certificatePem;
      issuerSignatureOk = true;
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyVpJwt(): " +
                ((e && e.message) || e));
      this.vpCheck(checks, 'Issuer signature', false, 'does not verify: ' +
                   e.message);
    }
    if (issuerSignatureOk) {
      this.vpCheck(checks, 'Issuer signature', true, "verifies against the " +
                   "issuer's key " +
                                                "(alg " + vcHeader.alg + ').');
    }
    const now = nowSec();
    this.vpCheck(checks, 'Validity window',
      (!vcPayload.exp || vcPayload.exp > now) && (!vcPayload.nbf ||
                                                  vcPayload.nbf <= now),
      'nbf ' + (vcPayload.nbf || '—') + ', exp ' + (vcPayload.exp || '—') +
          ', ' +
          'now ' + now + '.');

    const types = [].concat(vc.type || []);
    const wantedTypes = VCI_JWT_TYPES;
    const typesOk = wantedTypes.every((t) => {
      return types.indexOf(t) >= 0;
    });
    this.vpCheck(checks, 'Credential type', typesOk,
      'type is [' + types.join(', ') + ']; this Verifier asked for [' +
      wantedTypes.join(', ') + '].');

    // --- holder binding: the VP JWT is signed by the key the credential names
    const cnfJwk = (vcPayload.cnf || {}).jwk;
    // Kept for status, the register and a sign-in.
    result.credentialJwt = vcJwt;
    result.credentialClaims = vcPayload;
    result.holderJwk = cnfJwk || null;
    if (!cnfJwk) {
      this.vpCheck(checks, 'Holder binding', false,
        'the credential carries no cnf.jwk, so nothing says which key may ' +
        'present it.');
    } else {
      let holderOk = false;
      try {
        // The one verifier in common/crypto.js. What was here chose the digest
        // by testing `alg === 'RS256'` and passed a NULL hash for everything
        // else — right for Ed25519 by accident and wrong for every ECDSA
        // algorithm, which is most of what a wallet signs with.
        //
        // Asymmetric only: the credential names the holder's key in `cnf.jwk`
        // and the presentation has to be signed by the matching private one. A
        // MAC there would mean the verifier held the holder's secret.
        await stsCrypto.verifyCompactJwsAsync(raw, cnfJwk,
          { algorithms: ALL_ALGS });
        holderOk = true;
      } catch (e) {
        log.debug("Caught in VcVerifier.verifyVpJwt(): " +
                  ((e && e.message) || e));
        this.vpCheck(checks, 'Holder binding', false, 'the presentation ' +
                     'signature could not be ' +
                                                 'checked: ' + e.message);
      }
      if (holderOk) {
        this.vpCheck(checks, 'Holder binding', true,
          'the presentation JWT is signed by the key the credential is bound ' +
          'to (cnf.jwk, alg ' +
          vpHeader.alg + ').');
      } else {
        this.vpCheck(checks, 'Holder binding', false,
          'the presentation JWT is NOT signed by the key the credential is ' +
          'bound to (cnf.jwk).');
      }
    }

    // --- freshness and audience ----------------------------------------------
    this.vpCheck(checks, 'Nonce', vpPayload.nonce === record.nonce,
      'nonce is "' + (vpPayload.nonce || '—') + '"; this request used "' +
      record.nonce + '".');
    const auds = [].concat(vpPayload.aud === undefined ? [] :
                           vpPayload.aud).map(String);
    this.vpCheck(checks, 'Audience', auds.indexOf(expectedAud) >= 0,
      'aud is "' + auds.join(', ') + '"; this Verifier is "' + expectedAud +
      '".');
    this.vpCheck(checks, 'Freshness',
      !!vpPayload.iat &&
          Math.abs(now - Number(vpPayload.iat)) <= this.vpKbMaxAgeS() &&
          (!vpPayload.exp || Number(vpPayload.exp) > now) &&
          (!vpPayload.nbf || Number(vpPayload.nbf) <= now),
      'iat is ' + (vpPayload.iat || 'absent') + (vpPayload.iat ? ' (' +
      (now - Number(vpPayload.iat)) + 's ago)' : '') + '; at most ' +
      this.vpKbMaxAgeS() + 's is accepted.');

    // --- what arrived --------------------------------------------------------
    // Everything in credentialSubject came, because this format cannot send
    // less. `id` is the subject identifier rather than a claim, so it is not
    // counted.
    const present = Object.keys(subject)
                          .filter((k) => { return k !== 'id'; });
    present.forEach((name) => { result.claims[name] = subject[name]; });
    result.disclosed = present;
    // What THIS request asked for, not what the console is configured to ask
    // for now: see buildVpRequest(), where the list is frozen onto the
    // transaction.
    const requested = [].concat(context.requested || record.requested || []);
    const missing = requested.filter((name) => {
      return present.indexOf(name) < 0;
    });
    // Over-disclosure is measured against what was ASKED FOR, so a request that
    // named no claims has none of it: an absent DCQL claims member asks for the
    // whole credential, and reporting every claim in it as "more than we asked
    // for" would contradict the request in the same sentence.
    result.extraDisclosed = requested.length
      ? present.filter((name) => { return requested.indexOf(name) < 0; })
      : [];
    this.vpCheck(checks, 'Requested claims', missing.length === 0,
      missing.length
        ? 'missing: ' + missing.join(', ') + '.'
        : (requested.length
            ? 'all ' + requested.length + ' requested claim(s) arrived'
            : 'this request named no claims at all, so the whole credential ' +
              'was asked for') +
          (result.extraDisclosed.length
            ? ', along with ' + result.extraDisclosed.length + ' this ' +
                'Verifier did not ask for (' +
              result.extraDisclosed.join(', ') + ') — jwt_vc_json cannot ' +
                                                 'withhold them.'
            : '.'));

    result.ok = checks.every((c) => { return c.ok; });
    log.debug("Leaving VcVerifier.verifyVpJwt(). " +
              (result.ok ? "accepted" : "REFUSED") +
              ", " +
              checks.filter((c) => { return !c.ok; }).length + " failed " +
                  "check(s).");
    return result;
  }

  //
  // `ctx.aud` is the audience this answer must name (`origin:<origin>` over
  // the Digital Credentials API), and `ctx.requested` the claims this query
  // asked for. Asynchronous since #38's follow-ups, for verifyVpJwt()'s
  // reason: a post-quantum issuer or holder key is checked in the pool.
  async verifyPresentation(presentation: any, record: any, ctx?: any) {
    const { log, logArtifact, b64u, b64uDecode, jsonFromB64u, nowSec,
            errorCodes, vpConfig, stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.verifyPresentation().");
    const context = ctx || {};
    const expectedAud = String(context.aud || record.clientId);
    // Named as the source check in tests/revocation_status.js reads it.
    const verifyIssuerSignatureAsync =
        this.verifyIssuerSignatureAsync.bind(this);
    logArtifact('OID4VP Verifiable Presentation', 'as received', presentation);
    const checks = [];
    const result: any = { ok: false, checks: checks, claims: {}, disclosed: [],
                     vct: '', sub: '' };
    const parts = String(presentation || '').split('~');
    if (parts.length < 2) {
      this.vpCheck(checks, 'Format', false,
        'a presentation is <Issuer-signed JWT>~<Disclosure>*~<KB-JWT>; this ' +
        'has ' + parts.length + ' part(s).');
      log.debug("Leaving VcVerifier.verifyPresentation(). Not a Combined " +
                "Serialization.");
      return result;
    }
    const issuerJwt = parts[0];
    const kbJwt = parts[parts.length - 1];
    const disclosures = parts.slice(1, parts.length - 1)
                             .filter((d) => { return d !== ''; });
    this.vpCheck(checks, 'Format', true,
      'SD-JWT+KB with ' + disclosures.length + ' Disclosure(s) and a Key ' +
                                               'Binding JWT.');

    // --- the issuer-signed JWT -----------------------------------------------
    let header: any = {};
    let payload: any = {};
    try {
      header = jsonFromB64u(issuerJwt.split('.')[0]);
      payload = jsonFromB64u(issuerJwt.split('.')[1]);
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyPresentation(): " +
                ((e && e.message) || e));
      this.vpCheck(checks, 'Issuer-signed JWT', false,
              'cannot be decoded: ' + e.message);
      log.debug("Leaving VcVerifier.verifyPresentation(). Undecodable " +
                "credential.");
      return result;
    }
    result.vct = payload.vct || '';
    result.sub = payload.sub || '';
    result.credentialJwt = issuerJwt;
    result.credentialClaims = payload;
    this.vpCheck(checks, 'Media type (typ)',
      ['dc+sd-jwt', 'vc+sd-jwt'].indexOf(String(header.typ)) >= 0,
      'typ is "' + header.typ + '".');
    let issuerSignatureOk = false;
    try {
      // The fourth. Same change, same reason as the note above.
      result.issuerCertificatePem =
        (await verifyIssuerSignatureAsync(issuerJwt)).certificatePem;
      issuerSignatureOk = true;
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyPresentation(): " +
                ((e && e.message) || e));
      // Not signed by us — or expired, which jsonwebtoken reports here too.
      // Both are reasons to refuse, and the message says which.
      this.vpCheck(checks, 'Issuer signature', false, 'does not verify: ' +
                   e.message);
    }
    if (issuerSignatureOk) {
      this.vpCheck(checks, 'Issuer signature', true, 'verifies against the ' +
                                                'issuer\'s key (alg ' +
        header.alg + ').');
    }
    const now = nowSec();
    this.vpCheck(checks, 'Validity window',
      (!payload.exp || payload.exp > now) &&
          (!payload.nbf || payload.nbf <= now),
      'nbf ' + (payload.nbf || '—') + ', exp ' + (payload.exp || '—') + ', ' +
      'now ' +
      now + '.');
    // A sign-in pins the type on its transaction (see buildVpRequest());
    // everything else reads the setting, as it always did.
    const expectedVct = record.expectedVct || vpConfig.expectedVct();
    this.vpCheck(checks, 'Credential type (vct)',
      payload.vct === expectedVct,
      'vct is "' + payload.vct + '"; this Verifier asked for "' +
      expectedVct + '"' + (record.expectedVct ?
        ' (this issuer\'s own type, which a sign-in always asks for).' :
        ' (oid4vp.expectedVct).'));

    // --- the Disclosures presented -------------------------------------------
    // Every one must hash to a digest the issuer signed. This is the check that
    // catches a Disclosure invented by whoever is presenting.
    const sdAlg = payload._sd_alg || 'sha-256';
    const nodeAlg = { 'sha-256': 'sha256', 'sha-384': 'sha384',
                      'sha-512': 'sha512' }[String(sdAlg).toLowerCase()];
    const signedDigests = [];
    (function collect(node) {
      log.debug("Entering collect().");
      if (!node || typeof node !== 'object') {
        log.debug("Leaving collect().");
        return;
      }
      if (Array.isArray(node)) {
        node.forEach((item) => {
          if (item && typeof item === 'object' &&
              typeof item['...'] === 'string') signedDigests.push(item['...']);
          else collect(item);
        });
        log.debug("Leaving collect().");
        return;
      }
      Object.keys(node).forEach((k) => {
        if (k === '_sd' &&
            Array.isArray(node[k])) node[k].forEach(
                (d) => { signedDigests.push(d); });
        else if (typeof node[k] === 'object') collect(node[k]);
      });
      log.debug("Leaving collect().");
    })(payload);

    let unmatched = 0;
    disclosures.forEach((encoded) => {
      let arr = null;
      try {
        arr = JSON.parse(b64uDecode(encoded).toString('utf8'));
      } catch (e) {
        log.debug("Caught in VcVerifier.verifyPresentation(): " +
                  ((e && e.message) || e));
        unmatched++;
        log.error(errorCodes.tag('STS-VC-0039') +
                  'a presented Disclosure is not base64url JSON: ' + e.message);
        return;
      }
      const digest = nodeAlg ?
                     b64u(crypto.createHash(nodeAlg)
                                .update(encoded, 'ascii')
                                .digest()) : '';
      if (signedDigests.indexOf(digest) === -1) {
        unmatched++;
        log.error(errorCodes.tag('STS-VC-0040') +
                  'a presented Disclosure hashes to a digest the issuer ' +
                  'never ' +
                  'signed: ' + digest);
        return;
      }
      if (Array.isArray(arr) && arr.length === 3) {
        result.claims[arr[1]] = arr[2];
        result.disclosed.push(arr[1]);
      }
    });
    this.vpCheck(checks, 'Disclosure digests', unmatched === 0,
      unmatched === 0
        ? 'all ' + disclosures.length + ' presented Disclosure(s) hash to a ' +
                                        'digest in _sd.'
        : unmatched + ' presented Disclosure(s) were not signed by the ' +
            'issuer.');

    // The always-visible claims are part of what was presented too.
    Object.keys(payload).forEach((k) => {
      if (['_sd', '_sd_alg', 'cnf'].indexOf(k) >= 0) return;
      if (!(k in result.claims)) result.claims[k] = payload[k];
    });

    // --- the Key Binding JWT -------------------------------------------------
    let kbHeader: any = {};
    let kbPayload: any = {};
    let kbReadable = false;
    try {
      kbHeader = jsonFromB64u(kbJwt.split('.')[0]);
      kbPayload = jsonFromB64u(kbJwt.split('.')[1]);
      kbReadable = kbJwt.split('.').length === 3;
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyPresentation(): " +
                ((e && e.message) || e));
      kbReadable = false;
    }
    if (!kbReadable) {
      this.vpCheck(checks, 'Key Binding JWT', false,
        'the last element is not a readable three-part JWS, so the ' +
        'presentation has no holder proof at all.');
      result.ok = checks.every((c) => { return c.ok; });
      log.debug("Leaving VcVerifier.verifyPresentation(). No usable KB-JWT.");
      return result;
    }
    logArtifact('OID4VP Key Binding JWT', 'as received',
                { header: kbHeader, payload: kbPayload });
    this.vpCheck(checks, 'KB-JWT media type', String(kbHeader.typ) === 'kb+jwt',
      'typ is "' + kbHeader.typ + '"; RFC 9901 section 4.3 requires kb+jwt.');
    this.vpCheck(checks, 'KB-JWT algorithm',
                 !!kbHeader.alg && kbHeader.alg !== 'none',
      'alg is ' + kbHeader.alg + '.');
    this.vpCheck(checks, 'KB-JWT nonce', kbPayload.nonce === record.nonce,
      kbPayload.nonce === record.nonce
        ? 'matches the nonce in this Authorization Request.'
        : 'is "' + kbPayload.nonce + '", but this request\'s nonce is "' +
          record.nonce +
          '" — a presentation made for another request, or replayed.');
    this.vpCheck(checks, 'KB-JWT audience', kbPayload.aud === expectedAud,
      kbPayload.aud === expectedAud
        ? 'is ' + (context.aud ? 'this origin, as the Digital Credentials ' +
                                 'API requires' :
                                 'this Verifier\'s Client Identifier') + '.'
        : 'is "' + kbPayload.aud + '", not "' + expectedAud + '" — this ' +
            'presentation was made for someone else.');
    this.vpCheck(checks, 'KB-JWT freshness',
      !!kbPayload.iat &&
          Math.abs(now - Number(kbPayload.iat)) <= this.vpKbMaxAgeS(),
      'iat is ' + kbPayload.iat + ' (' +
      (kbPayload.iat ? (now - Number(kbPayload.iat)) + 's ' +
          'ago' : 'absent') +
      '); at most ' + this.vpKbMaxAgeS() + 's is accepted.');

    // sd_hash ties the KB-JWT to exactly these bytes: the issuer-signed JWT and
    // the Disclosures presented, each followed by a tilde.
    const withoutKb = parts.slice(0, parts.length - 1).join('~') + '~';
    const expectedSdHash = this.sdHashOf(withoutKb, sdAlg);
    this.vpCheck(checks, 'KB-JWT sd_hash',
      !!expectedSdHash && kbPayload.sd_hash === expectedSdHash,
      kbPayload.sd_hash === expectedSdHash
        ? 'is the hash of exactly the bytes presented, so no Disclosure was ' +
          'added or removed after it was signed.'
        : 'is "' + kbPayload.sd_hash + '" but these bytes hash to "' +
          expectedSdHash +
          '" — the presentation was altered after the holder signed it.');

    // The signature must verify against the key the CREDENTIAL names, not one
    // the presenter chose: that is what key binding means.
    const cnfJwk = (payload.cnf && payload.cnf.jwk) || null;
    // Kept on the result for a sign-in, which compares it with the key the
    // credential was issued to (`signInOutcome()`).
    result.holderJwk = cnfJwk;
    if (!cnfJwk) {
      this.vpCheck(checks, 'KB-JWT signature', false,
        'the credential carries no cnf.jwk, so there is no key this ' +
        'presentation could be bound to.');
    } else {
      try {
        // THE HOLDER'S KEY AS ITS JWK, not a node KeyObject: an AKP
        // (post-quantum) key has no KeyObject here, and the shared verifier
        // reads either.
        // NOT one of our tokens — the key is the HOLDER'S, so the algorithm
        // list is theirs and is named explicitly rather than taking the RS256
        // default. The clock allowance is still ours to grant, and it comes
        // from the shared verifier for the same reason it does everywhere else.
        //
        // THE LIST WAS FOUR ALGORITHMS AND THE ISSUER BINDS TO MORE
        // (2026-09-12, every mode). The issuer accepts a proof of possession in
        // every asymmetric algorithm `proof_signing_alg_values_supported`
        // advertises, so a wallet holding an EdDSA, ES512, ES256K, RS384 or
        // PS512 key was issued a credential bound to it and then refused at
        // presentation for signing with the very key the credential names. It
        // is every asymmetric non-post-quantum algorithm now — the post-quantum
        // ones have no JWK `cnf` a node KeyObject can be built from, and this
        // check is synchronous.
        await stsCrypto.verifyCompactJwsAsync(kbJwt, cnfJwk,
                                              { algorithms: ALL_ALGS });
        this.vpCheck(checks, 'KB-JWT signature', true,
          'verifies against the cnf key in the credential (' + cnfJwk.kty +
              ' ' +
          (cnfJwk.crv || '') + ').');
      } catch (e) {
        log.debug("Caught in VcVerifier.verifyPresentation(): " +
                  ((e && e.message) || e));
        this.vpCheck(checks, 'KB-JWT signature', false,
          'does NOT verify against the cnf key in the credential: ' +
              e.message);
      }
    }

    // --- did we get what we asked for? ---------------------------------------
    // What THIS request asked for; see buildVpRequest() for why it is the
    // transaction's list and not the one the console holds at this moment.
    const requested = [].concat(context.requested || record.requested || []);
    const missing =
        requested.filter((name) => { return !(name in result.claims); });
    this.vpCheck(checks, 'Requested claims', missing.length === 0,
      missing.length === 0
        ? (requested.length
            ? 'every claim the DCQL query asked for is present (' +
              requested.join(', ') + ').'
            : 'this request named no claims at all, so there was nothing to ' +
                'be ' +
              'missing — an absent DCQL claims member asks for the whole ' +
              'credential.')
        : 'missing: ' + missing.join(', ') + '.');
    // Not a failure — the holder may disclose more than was asked — but worth
    // saying, because over-disclosure is the thing SD-JWT VC exists to prevent.
    // Nothing is "extra" when nothing was asked for; see the same note in
    // verifyVpJwt() for why that is not the same as counting everything.
    const extra = requested.length
      ? result.disclosed.filter((name) => {
        return requested.indexOf(name) === -1;
      })
      : [];
    result.extraDisclosed = extra;

    result.ok = checks.every((c) => { return c.ok; });
    log.debug("Leaving VcVerifier.verifyPresentation(). ok=" + result.ok +
              ", " +
        checks.length + " check(s), " +
              result.disclosed.length + " disclosed claim(s), " + extra.length +
        " more than asked for.");
    return result;
  }

  // Where a wallet sends the End-User once this Verifier has answered: the
  // bar door's thank-you page, or — for a sign-in — back to the page the
  // browser that started it is waiting on, carrying the `response_code` when
  // there is one. The path is the one the sign-in module put on the
  // transaction; this module does not know it.
  private afterResponseUri(req: any, record: any, responseCode: string) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering VcVerifier.afterResponseUri().");
    const base = baseUrlOf(req);
    if (!record.signIn || !record.signIn.completePath) {
      log.debug("Leaving VcVerifier.afterResponseUri(). The bar door.");
      return base + '/oid4vp/done?state=' + encodeURIComponent(record.state);
    }
    log.debug("Leaving VcVerifier.afterResponseUri(). A sign-in.");
    const path = String(record.signIn.completePath);
    return base + path + (path.indexOf('?') >= 0 ? '&' : '?') +
      'authn=' + encodeURIComponent(record.signIn.authnId) +
      '&state=' + encodeURIComponent(record.state) +
      (responseCode ? '&response_code=' + encodeURIComponent(responseCode) :
                      '');
  }

  // ---------------------------------------------------------------------------
  // WHOM A VERIFIED PRESENTATION SIGNS IN, IF ANYBODY (2026-09-17, #38).
  //
  // Asked of every presentation made against a SIGN-IN transaction, after the
  // verification above and whatever it concluded. The answer is a verdict of
  // its own, `{ ok, username, subject, amr, acr, reason, errorCode }`, and it
  // is kept APART from the presentation's verdict on purpose: "this
  // presentation verified" and "this presentation signs somebody in" are two
  // claims, and a foreign issuer's credential is the ordinary case where the
  // first is true and the second is not. The page the browser is waiting on
  // prints both.
  //
  // The conditions, in the order they are asked, each with the code the page
  // is marked with when it is the one that fails:
  //
  //   1. the presentation VERIFIED — every check above, which already covers
  //      the Key Binding JWT against the credential's `cnf` key, this
  //      request's nonce and this Verifier's audience, freshness, `sd_hash`,
  //      the validity window and this issuer's `vct` (STS-VC-0061);
  //   2. THIS REALM'S KEY signed it, not a certificate in
  //      `oid4vp.trustedIssuerCertificates`: a partner's credential may
  //      verify at the bar door, and a partner does not get to say who is
  //      signed in here (STS-VC-0058);
  //   3. THIS REALM'S REGISTER holds it — issued here, on an access token this
  //      realm verified, for a person (`vc_issued.ts`). A credential another
  //      realm issued fails 1 or 2 before it gets here, and would not be in
  //      this realm's partition if it did not (STS-VC-0059);
  //   4. what the register says AGREES with the credential: the same subject
  //      and the same holder key. Neither can differ for a credential this
  //      issuer signed, and both are compared anyway, because the register is
  //      keyed by a digest and a sign-in is the one place a mismatch would be
  //      somebody else's session (STS-VC-0066);
  //   5. the subject STILL NAMES AN ENTRY, and that entry's subject is still
  //      this one — so a deleted person, or a name re-created under a new
  //      `entryUUID`, is nobody (STS-VC-0060).
  //
  // What it does not ask is whether the person is ALLOWED a session. That is
  // the issuance policy's question, and `startSession()` asks it for every
  // door (STS-VC-0064 on the page when it refuses). The directory has no
  // "disabled" flag for it to consult beyond that — until 2026-09-17, when
  // one arrived: `startSession()` refuses a disabled account
  // (`common/account_state.ts`), so this door does too.
  //
  // **`amr` IS `["pop"]` AND `acr` IS `"1"`.** RFC 8176's `pop` is "proof of
  // possession of a key" where it is unspecified whether the key is hardware-
  // or software-secured — which is exactly what is known here: the Key
  // Binding JWT proves the key, and a JWK says nothing about where the key
  // lives. `hwk` or `swk` would be this service claiming knowledge it does not
  // have — UNLESS the issuer verified a key attestation when it issued the
  // credential, which `assuranceOf()` below reads off the register: hardware
  // storage adds `hwk`, and user authentication attested as well makes `mfa`.
  // Nothing the presentation says about itself is believed.
  // `user` is not appropriate either: nothing about a presentation proves the
  // holder was present or tested, only that their wallet signed. It is ONE
  // factor, rated as every other one factor here is rated (`"1"`); two are
  // never claimed, which is also why the mechanism is withheld from a request
  // that demanded two (`authn.ts`, `walletOptionHtml()`).
  // ---------------------------------------------------------------------------
  signInOutcome(verified: any, answer?: any) {
    const { log, vcIssued, nameForSubject, subjectForName,
            stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.signInOutcome().");
    const refuse = (errorCode: string, reason: string) => {
      log.debug("Leaving VcVerifier.signInOutcome(). " + errorCode);
      return { ok: false, errorCode: errorCode, reason: reason,
               username: '', subject: '' };
    };
    // A STATUS REFUSAL IS THE ONE FAILURE THAT GOES ON (#38's follow-ups).
    // `statusCheck()` runs only after everything else verified, so a
    // presentation that failed only there is one this door can still say
    // something USEFUL about: where the register knows the credential was
    // disowned — a global sign-out, an administrator's revocation, a
    // suspension — the page should say THAT (STS-VC-0071) rather than
    // "the list says INVALID", which is the same fact one layer down. So the
    // register is read first and this is decided at the end.
    const statusRefused = !!(verified && verified.statusRefused);
    if (!statusRefused && (!verified || !verified.ok)) {
      return refuse('STS-VC-0061', 'The presentation did not verify, so it ' +
                    'signs nobody in. The checks above say which rule it ' +
                    'broke.');
    }
    if (verified.issuerCertificatePem) {
      return refuse('STS-VC-0058', 'The credential verified against a ' +
                    'certificate in oid4vp.trustedIssuerCertificates, not ' +
                    'against this realm\'s own key. A credential another ' +
                    'issuer signed may be presented to this Verifier, and ' +
                    'it does not sign anybody in here: only a credential ' +
                    'this realm issued can say who a person here is.');
    }
    const format = String((answer && answer.format) || 'dc+sd-jwt');
    let presentedJkt = '';
    try {
      presentedJkt = verified.holderJwk ?
        stsCrypto.jwkThumbprint(verified.holderJwk, {}) : '';
    } catch (e) {
      log.debug("Caught in VcVerifier.signInOutcome(): " +
                ((e && e.message) || e));
      presentedJkt = '';
    }
    const notIssued = 'This realm has no record of issuing this credential ' +
      'to a person it authenticated. Only a credential this realm\'s ' +
      'issuer minted on an access token this realm issued and verified — ' +
      'for a person, for credential issuance, and not disowned since — may ' +
      'sign somebody in. A credential from another realm, one issued on a ' +
      'token this service did not issue, or one issued before a restart in ' +
      'development mode is not one.';
    let row = null;
    let candidates = [];
    if (format === 'ldp_vc') {
      // A DERIVED PROOF names no credential; the holder key and the disclosed
      // validity window are what find it (vc_issued.ts's header).
      const rows = presentedJkt ? vcIssued.lookupHolder(presentedJkt) : [];
      if (!rows.length) {
        return refuse('STS-VC-0059', notIssued);
      }
      const subjects = rows.map(function (r) {
        return r.subject;
      }).filter(function (one, i, all) {
        return all.indexOf(one) === i;
      });
      if (subjects.length > 1) {
        return refuse('STS-VC-0066', 'This wallet key was issued credentials ' +
                      'for more than one person here, and an ldp_vc ' +
                      'presentation does not say which credential it came ' +
                      'from, so it signs nobody in.');
      }
      row = rows[0];
      candidates = vcIssued.credentialsMatching(row, {
        validFrom: verified.validFrom, validUntil: verified.validUntil });
      if (!candidates.length) {
        return refuse('STS-VC-0059', notIssued);
      }
    } else {
      row = vcIssued.lookup(verified.credentialJwt);
      if (!row) {
        return refuse('STS-VC-0059', notIssued);
      }
      if (String(verified.sub || '') !== row.subject ||
          !presentedJkt || presentedJkt !== row.jkt) {
        return refuse('STS-VC-0066', 'The credential does not match what ' +
                      'this realm recorded when it issued it (its subject or ' +
                      'the key it is bound to), so it signs nobody in.');
      }
      candidates = [].concat(row.credentials || []);
    }
    const disowned = vcIssued.disownedReason(row, candidates);
    if (disowned) {
      return refuse('STS-VC-0071', 'This credential has been disowned: ' +
                    disowned + '. It still verifies, and it signs nobody in ' +
                    'here any more — its status list says so too. A ' +
                    'credential issued to you after that will.');
    }
    if (statusRefused) {
      return refuse(verified.statusErrorCode || 'STS-VC-0072',
                    'The credential\'s status says it is ' +
                    'no longer good (' + (verified.statusDetail || 'revoked ' +
                    'or suspended') + '), so it signs nobody in.');
    }
    const username = nameForSubject(row.subject);
    if (!username || subjectForName(username) !== row.subject) {
      return refuse('STS-VC-0060', 'The directory entry this credential was ' +
                    'issued for no longer exists — it was deleted, or its ' +
                    'name now belongs to a different entry — so the ' +
                    'credential signs nobody in.');
    }
    const assurance = this.assuranceOf(row, candidates);
    log.debug("Leaving VcVerifier.signInOutcome(). " + username + ".");
    return { ok: true, errorCode: '', reason: '', username: username,
             subject: row.subject, amr: assurance.amr, acr: assurance.acr,
             format: format, keyStorage: assurance.keyStorage,
             // What the presentation disclosed, for the identity
             // verification a wallet sign-in records (#127).
             disclosed: verified.claims || {},
             holderKey: (verified.holderJwk.kty || '') +
                        (verified.holderJwk.crv ?
                          ' ' + verified.holderJwk.crv :
                          (verified.holderJwk.alg ?
                            ' ' + verified.holderJwk.alg : '')) };
  }

  // ---------------------------------------------------------------------------
  // WHAT A WALLET SIGN-IN CLAIMS (#38's follow-ups).
  //
  // By default one factor of unknown storage: `amr ["pop"]`, `acr "1"` —
  // RFC 8176's `pop` is proof of possession of a key whose storage is not
  // specified, which is exactly what a bare JWK says.
  //
  // A KEY ATTESTATION the issuer VERIFIED when the credential was issued
  // (`vc_issuer.ts`'s `verifyKeyAttestation()`, recorded on the register row)
  // says more, and only that is believed — nothing a presentation says about
  // itself is:
  //
  //   * `key_storage` resisting at least "Moderate" attack potential
  //     (ISO 18045 VAN.4, `iso_18045_moderate` or `iso_18045_high`) is a
  //     hardware-grade key: `hwk` is added.
  //   * and `user_authentication` at least "Moderate" as well means the key
  //     cannot be used without the person authenticating to the wallet (a PIN
  //     or a biometric) — possession and a second factor in one act, so
  //     `mfa` is added and `acr` is `"mfa"`.
  //
  // Every credential the presentation could be (for an ldp_vc, each sibling
  // with its validity window) must carry the attestation, or the weakest one
  // decides.
  // ---------------------------------------------------------------------------
  private assuranceOf(row: any, candidates: any[]): any {
    const { log } = this.deps;
    log.debug("Entering VcVerifier.assuranceOf().");
    const rank = function (values: unknown): number {
      log.debug("Entering rank().");
      const scale = ['iso_18045_basic', 'iso_18045_enhanced-basic',
                     'iso_18045_moderate', 'iso_18045_high'];
      const best = [].concat(values || []).reduce(function (m, v) {
        return Math.max(m, scale.indexOf(String(v)) + 1);
      }, 0);
      log.debug("Leaving rank(). " + best);
      return best;
    };
    const list = [].concat(candidates || []);
    const storage = list.length ? Math.min.apply(null, list.map(function (c) {
      return rank(c.keyStorage);
    })) : 0;
    const userAuth = list.length ? Math.min.apply(null, list.map(function (c) {
      return rank(c.userAuthentication);
    })) : 0;
    void row;
    const hardware = storage >= 3;
    const twoFactors = hardware && userAuth >= 3;
    const names = ['', 'iso_18045_basic', 'iso_18045_enhanced-basic',
                   'iso_18045_moderate', 'iso_18045_high'];
    log.debug("Leaving VcVerifier.assuranceOf(). storage=" + storage +
              ", user=" + userAuth);
    return {
      amr: ['pop'].concat(hardware ? ['hwk'] : [])
                  .concat(twoFactors ? ['mfa'] : []),
      acr: twoFactors ? 'mfa' : '1',
      keyStorage: names[storage] || ''
    };
  }

  // ---------------------------------------------------------------------------
  // ONE ANSWER, VERIFIED: the vp_token read for the query it answers, the
  // presentation checked in that query's format, the issuer certificate's
  // revocation, and the credential's status. Shared by the direct_post
  // endpoint and the Digital Credentials API door so the two cannot come to
  // check different things. `ctx.aud` is the audience the answer must name.
  //
  // A sign-in's vp_token must answer EXACTLY ONE of its credential queries
  // with exactly one presentation: the credential set offers each as a
  // complete answer, and two would be two people's worth of evidence for one
  // session.
  // ---------------------------------------------------------------------------
  async verifyAnswer(record: any, rawVpToken: unknown,
                     ctx: any): Promise<any> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcVerifier.verifyAnswer().");
    const issuerCertificateRevocation =
        this.issuerCertificateRevocation.bind(this);
    let parsed: any = null;
    try {
      parsed = typeof rawVpToken === 'string' ? JSON.parse(rawVpToken) :
               rawVpToken;
    } catch (e) {
      log.debug("Caught in VcVerifier.verifyAnswer(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0038') +
                'the vp_token is not the JSON object OID4VP defines: ' +
                e.message);
      parsed = null;
    }
    const ids = record.signIn ? Object.keys(record.signIn.queries || {})
                              : [VP_DCQL_ID];
    const answered = parsed && typeof parsed === 'object' ?
      ids.filter(function (id) {
        return parsed[id] !== undefined;
      }) : [];
    const shape = (why: string): any => {
      log.debug("Leaving VcVerifier.verifyAnswer(). " + why);
      return { shapeOk: false, why: why };
    };
    if (!answered.length || (record.signIn && answered.length !== 1)) {
      return shape('vp_token must be a JSON object keyed by ' +
        (record.signIn ? 'exactly one of the DCQL credential query ids (' +
                         ids.join(', ') + ')' :
                         'the DCQL credential query id ("' + VP_DCQL_ID +
                         '")') +
        ', each value an array of presentations.');
    }
    const id = answered[0];
    const list = Array.isArray(parsed[id]) ? parsed[id] :
                 (typeof parsed[id] === 'string' ||
                  (parsed[id] && typeof parsed[id] === 'object') ?
                   [parsed[id]] : []);
    if (!list.length || (record.signIn && list.length !== 1)) {
      return shape('the vp_token for "' + id + '" must carry ' +
                   (record.signIn ? 'exactly one presentation' :
                                    'a presentation') + '.');
    }
    const format = record.signIn ? record.signIn.queries[id] : record.format;
    const vctx = {
      aud: ctx && ctx.aud,
      requested: record.signIn ? [] : undefined,
      requireHolderBinding: !!record.signIn,
      issuers: record.signIn ? record.signIn.issuers : []
    };
    const presentation = list[0];
    const verified = format === 'ldp_vc'
      ? await this.verifyLdpVc(presentation, record, vctx)
      : format === 'jwt_vc_json'
        ? await this.verifyVpJwt(presentation, record, vctx)
        : await this.verifyPresentation(presentation, record, vctx);
    await issuerCertificateRevocation(verified);
    await this.statusCheck(verified, format, !!record.signIn);
    log.debug("Leaving VcVerifier.verifyAnswer(). ok=" + verified.ok + ".");
    return { shapeOk: true, verified: verified, presentation: presentation,
             format: format, id: id };
  }

  // ---------------------------------------------------------------------------
  // THE CREDENTIAL'S STATUS (vc_status.ts), asked once everything else
  // verified (draft-ietf-oauth-status-list section 8.3: a token that failed
  // its own checks is not looked up). A credential this realm signed is read
  // from the realm's own lists; one a trusted issuer certificate verified has
  // its list fetched and checked against that certificate's key.
  //
  // A CREDENTIAL WITH NO REFERENCE IS REFUSED BY DEFAULT (#165):
  // `oid4vp.requireStatusReference`, read through `mode.valueInForce()` so a
  // product realm reads its development-only `off` as `all`, and the
  // per-issuer exemption `oid4vp.statusOptionalIssuers`, keyed by the
  // thumbprint of the certificate that verified the credential. vc_status.ts's
  // checkPresented() decides; this passes it the policy and the exemption.
  //
  // AN ldp_vc THAT DISCLOSED NO STATUS ENTRY is the case the policy could not
  // see until #165: a bbs-2023 derived proof discloses what the holder
  // chooses, the credentialStatus entries are part of what the issuer signed,
  // and a presentation without them cannot be told from a credential that
  // never had any. Every ldp_vc this realm issues carries them, so a missing
  // entry means the holder withheld it — and a revoked credential passed the
  // bar door by withholding it. The bar door's query now ASKS for
  // `credentialStatus` (vc_verifier_config.ts's dcqlQuery()), and a
  // presentation that did not disclose it is refused (STS-VC-0089) unless the
  // rule is `off`, in development. A SIGN-IN is the exception: its query asks
  // for the entry too, and the register (`vc_issued.disownedReason()`) reads
  // that credential's status whether or not it was disclosed.
  // ---------------------------------------------------------------------------
  private async statusCheck(verified: any, format: string,
                            signIn: boolean): Promise<void> {
    const { log, vcStatus, mode } = this.deps;
    log.debug("Entering VcVerifier.statusCheck().");
    if (!verified || !verified.ok) {
      log.debug("Leaving VcVerifier.statusCheck(). Not verified.");
      return;
    }
    const own = !verified.issuerCertificatePem;
    const policy = String(mode.valueInForce('oid4vp.requireStatusReference') ||
                          'all');
    if (format === 'ldp_vc' && !(verified.credentialStatus || []).length) {
      if (signIn || policy === 'off') {
        this.vpCheck(verified.checks, 'Credential status', true,
          'no status entry was disclosed' + (signIn ?
            '; the sign-in register holds this credential\'s status' :
            ', and oid4vp.requireStatusReference is off (development ' +
            'only)') + '.');
        log.debug("Leaving VcVerifier.statusCheck(). Not disclosed, and " +
                  "not required.");
        return;
      }
      const detail = 'the presentation disclosed no credentialStatus entry, ' +
        'though the request asked for it: every ldp_vc this realm issues ' +
        'carries one, so it was withheld, and a credential whose status is ' +
        'withheld could be one that was revoked (oid4vp.' +
        'requireStatusReference is ' + policy + ')';
      this.vpCheck(verified.checks, 'Credential status', false, detail);
      verified.ok = false;
      verified.statusRefused = true;
      verified.statusDetail = detail;
      verified.statusErrorCode = 'STS-VC-0089';
      log.debug("Leaving VcVerifier.statusCheck(). Not disclosed: refused.");
      return;
    }
    let key: any = null;
    if (!own) {
      try {
        key = new crypto.X509Certificate(verified.issuerCertificatePem)
          .publicKey;
      } catch (e) {
        log.debug("Caught in VcVerifier.statusCheck(): " +
                  ((e && e.message) || e));
        key = null;
      }
    }
    const answer = await vcStatus.checkPresented({
      own: own, format: format,
      claims: format === 'ldp_vc' ? {} : verified.credentialClaims,
      credentialStatus: format === 'ldp_vc' ? verified.credentialStatus :
                        undefined,
      key: key, algs: ISSUER_ALGS, policy: policy,
      exempt: !own && this.statusOptional(verified.issuerCertificatePem)
    });
    this.vpCheck(verified.checks, 'Credential status', answer.ok,
                 answer.detail);
    if (!answer.ok) {
      verified.ok = false;
      verified.statusRefused = true;
      verified.statusDetail = answer.detail;
      verified.statusErrorCode = answer.errorCode || 'STS-VC-0072';
    }
    log.debug("Leaving VcVerifier.statusCheck(). " + answer.ok + ".");
  }

  // Is the trusted issuer certificate that verified a credential listed in
  // `oid4vp.statusOptionalIssuers` (#165)? The setting takes a SHA-256
  // thumbprint in any of the three spellings `certificateThumbprint()` makes
  // — hex, colon-hex, base64url — so each is brought to lower-case hex and
  // compared with the certificate's.
  private statusOptional(pem: string): boolean {
    const { log, config, stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.statusOptional().");
    const listed = [].concat(config.value('oid4vp.statusOptionalIssuers') ||
                             []).map(function (one: any) {
      const raw = String(one || '').trim();
      const hex = raw.replace(/:/g, '').toLowerCase();
      if (/^[0-9a-f]{64}$/.test(hex)) {
        return hex;
      }
      return /^[A-Za-z0-9_-]{43}$/.test(raw)
        ? Buffer.from(raw, 'base64url').toString('hex') : '';
    }).filter(function (one: string) {
      return !!one;
    });
    if (!listed.length || !pem) {
      log.debug("Leaving VcVerifier.statusOptional(). None listed.");
      return false;
    }
    let mine = '';
    try {
      mine = stsCrypto.certificateThumbprint(pem, { format: 'hex' });
    } catch (e) {
      log.debug("Caught in VcVerifier.statusOptional(): " +
                ((e && e.message) || e));
      mine = '';
    }
    const exempt = !!mine && listed.indexOf(mine) >= 0;
    log.debug("Leaving VcVerifier.statusOptional(). " + exempt);
    return exempt;
  }

  // ---------------------------------------------------------------------------
  // AN ANSWER THROUGH THE DIGITAL CREDENTIALS API (OpenID4VP Appendix A.4),
  // posted by the page that called `navigator.credentials.get()`.
  //
  //   `response`  the DigitalCredential the page received, as JSON:
  //               `{ protocol, data }`, where `data` is `{ vp_token }`
  //               (`dc_api`), `{ response: <JWE> }` (`dc_api.jwt`) or
  //               `{ error }`
  //   `origin`    this service's origin, which the answer's audience must
  //               name as `origin:<origin>` (A.4)
  //
  // The caller has already established the browser (the binding cookie) and
  // the page's own origin (the request's `Origin` header). This answers
  // `{ ok, status, errorCode, why }` and writes the verdict and the sign-in
  // outcome onto the transaction exactly as the direct_post endpoint does,
  // answered once.
  // ---------------------------------------------------------------------------
  async answerDcApi(record: any, response: unknown, origin: string) {
    const { log, stsCrypto, keystore, vpTransactions } = this.deps;
    log.debug("Entering VcVerifier.answerDcApi().");
    const refuse = (status: number, errorCode: string, why: string) => {
      log.debug("Leaving VcVerifier.answerDcApi(). " + errorCode);
      return { ok: false, status: status, errorCode: errorCode, why: why };
    };
    const dc = record && record.signIn && record.signIn.dcApi;
    if (!dc) {
      return refuse(400, 'STS-VC-0083', 'this sign-in was not offered ' +
                    'through the Digital Credentials API');
    }
    if (record.verdict) {
      return refuse(400, 'STS-VC-0057', 'this sign-in has already been ' +
                    'answered');
    }
    if (String(origin) !== dc.origin) {
      return refuse(403, 'STS-VC-0074', 'the answer was posted for origin "' +
                    origin + '", and the request named "' + dc.origin + '"');
    }
    let credential: any = null;
    try {
      credential = typeof response === 'string' ? JSON.parse(response) :
                   response;
    } catch (e) {
      log.debug("Caught in VcVerifier.answerDcApi(): " +
                ((e && e.message) || e));
      credential = null;
    }
    if (!credential || typeof credential !== 'object' ||
        credential.protocol !== dc.protocol || !credential.data ||
        typeof credential.data !== 'object') {
      return refuse(400, 'STS-VC-0073', 'the answer is not a ' + dc.protocol +
                    ' DigitalCredential ({ protocol, data })');
    }
    let data = credential.data;
    if (data.error) {
      record.verdict = { ok: false, refused: true, error: String(data.error),
                         errorDescription: String(data.error_description ||
                                                  ''),
                         checks: [], at: new Date().toISOString() };
      record.signIn.outcome = {
        ok: false, errorCode: 'STS-VC-0037', username: '', subject: '',
        reason: 'The wallet declined to present a credential (' +
                String(data.error) + '), so nobody was signed in.' };
      record.signIn.via = 'dc_api';
      vpTransactions.set(String(record.state), record);
      log.debug("Leaving VcVerifier.answerDcApi(). The wallet refused.");
      return { ok: true, status: 200, errorCode: 'STS-VC-0037', why: '' };
    }
    if (dc.responseMode === 'dc_api.jwt') {
      if (typeof data.response !== 'string') {
        return refuse(400, 'STS-VC-0073', 'this request asked for an ' +
                      'encrypted response (dc_api.jwt), and the answer ' +
                      'carries no `response`');
      }
      try {
        const pem = dc.encKey.sealed ?
          keystore.open(dc.encKey.sealed, 'oid4vp dc_api response key') :
          dc.encKey.plain;
        const opened = stsCrypto.decryptJweCompact(data.response, {
          privateKey: crypto.createPrivateKey(String(pem || '')),
          allowedAlg: ['ECDH-ES'],
          allowedEnc: DC_API_ENC_VALUES,
          expectedKid: dc.encKey.kid
        });
        data = JSON.parse(opened.plaintext);
      } catch (e) {
        log.debug("Caught in VcVerifier.answerDcApi(): " +
                  ((e && e.message) || e));
        return refuse(400, 'STS-VC-0073', 'the encrypted response could not ' +
                      'be opened: ' + e.message);
      }
    } else if (data.response !== undefined) {
      return refuse(400, 'STS-VC-0073', 'this request asked for an ' +
                    'unencrypted response (dc_api), and the answer is ' +
                    'encrypted');
    }
    // The audience A.4 requires. The origin is serialised without a trailing
    // slash (HTML's serialisation, which is what a browser hands a wallet);
    // the specification's own example has one, so both are read.
    const withSlash = 'origin:' + dc.origin + '/';
    const answer = await this.verifyAnswer(record, data.vp_token,
      { aud: 'origin:' + dc.origin });
    let result = answer;
    if (answer.shapeOk && !answer.verified.ok &&
        this.audienceWas(answer.verified, withSlash)) {
      result = await this.verifyAnswer(record, data.vp_token,
                                       { aud: withSlash });
    }
    const outcome = this.recordAnswer(record, result, 'dc_api');
    log.debug("Leaving VcVerifier.answerDcApi(). " +
              (outcome.ok ? "Signs in." : outcome.errorCode));
    return { ok: true, status: 200, errorCode: outcome.errorCode, why: '' };
  }

  // -------------------------------------------------------------------------
  // A DIRECT_POST.JWT RESPONSE, OPENED (#187, OpenID4VP 1.0 section 8.3.1):
  // `{ ok, body, encrypted }` — the decrypted parameters for an encrypted
  // answer, the form as it came for any other, or `{ ok: false, why }` when
  // a `response` is there and cannot be opened. The transaction is named by
  // the JWE's `kid` (see buildVpRequest()); only its own key, sealed on the
  // transaction, opens it, and only by ECDH-ES with the encryption the
  // request offered.
  // -------------------------------------------------------------------------
  private openEncryptedResponse(form: any): any {
    const { log, keystore, stsCrypto, vpTransactions } = this.deps;
    log.debug("Entering VcVerifier.openEncryptedResponse().");
    if (!form || typeof form.response !== 'string' || form.vp_token ||
        form.error) {
      log.debug("Leaving VcVerifier.openEncryptedResponse(). Plain.");
      return { ok: true, body: form || {}, encrypted: false };
    }
    let kid = '';
    try {
      kid = String(JSON.parse(Buffer.from(String(form.response)
        .split('.')[0], 'base64url').toString('utf8')).kid || '');
    } catch (e) {
      log.debug("Caught in VcVerifier.openEncryptedResponse(): " +
                ((e && e.message) || e));
      kid = '';
    }
    const record = kid.indexOf(DIRECT_POST_JWT_KID) === 0
      ? vpTransactions.get(kid.slice(DIRECT_POST_JWT_KID.length)) : null;
    if (!record || !record.encKey || record.encKey.kid !== kid) {
      log.debug("Leaving VcVerifier.openEncryptedResponse(). No key.");
      return { ok: false, why: 'the encrypted response names no key of an ' +
               'Authorization Request outstanding here (its JWE kid is "' +
               kid + '").' };
    }
    try {
      const pem = record.encKey.sealed
        ? keystore.open(record.encKey.sealed, 'oid4vp direct_post.jwt key')
        : record.encKey.plain;
      const plain = stsCrypto.decryptJweCompact(String(form.response), {
        privateKey: crypto.createPrivateKey(String(pem || '')),
        allowedAlg: ['ECDH-ES'],
        allowedEnc: DC_API_ENC_VALUES,
        expectedKid: kid
      });
      const body = JSON.parse(plain.plaintext);
      log.debug("Leaving VcVerifier.openEncryptedResponse(). Opened.");
      return { ok: true, encrypted: true,
               body: Object.assign({ state: record.state }, body) };
    } catch (e) {
      log.debug("Caught in VcVerifier.openEncryptedResponse(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcVerifier.openEncryptedResponse(). Unopened.");
      return { ok: false, why: 'the encrypted response could not be ' +
               'opened: ' + ((e && e.message) || e) };
    }
  }

  // Did a failed verification fail on its audience alone, naming this one?
  private audienceWas(verified: any, aud: string): boolean {
    const { log } = this.deps;
    log.debug("Entering VcVerifier.audienceWas().");
    const failed = (verified.checks || []).filter(function (c) {
      return !c.ok;
    });
    log.debug("Leaving VcVerifier.audienceWas().");
    return failed.length > 0 && failed.every(function (c) {
      return /audience|Domain/i.test(c.name) &&
             String(c.detail).indexOf(aud) >= 0;
    });
  }

  // Writes a verified answer onto a SIGN-IN transaction — the verdict, the
  // sign-in outcome, and for the direct_post path the one-time
  // response_code — through the store. Answers the outcome.
  private recordAnswer(record: any, answer: any, via: string): any {
    const { log, errorCodes, vpTransactions } = this.deps;
    log.debug("Entering VcVerifier.recordAnswer(). via=" + via);
    if (!answer.shapeOk) {
      record.verdict = {
        ok: false, at: new Date().toISOString(),
        checks: [{ name: 'vp_token', ok: false, detail: answer.why }]
      };
      record.signIn.outcome = this.signInOutcome(null, null);
      record.signIn.via = via;
      vpTransactions.set(String(record.state), record);
      log.debug("Leaving VcVerifier.recordAnswer(). Malformed.");
      return record.signIn.outcome;
    }
    const verified = answer.verified;
    record.verdict = {
      ok: verified.ok,
      at: new Date().toISOString(),
      checks: verified.checks,
      claims: verified.claims,
      disclosed: verified.disclosed,
      extraDisclosed: verified.extraDisclosed || [],
      requested: record.requested || [],
      vct: verified.vct,
      sub: verified.sub,
      format: answer.format,
      presentation: answer.presentation
    };
    const outcome = this.signInOutcome(verified, answer);
    record.signIn.outcome = outcome;
    record.signIn.via = via;
    if (!outcome.ok && verified.ok) {
      log.info(errorCodes.tag(outcome.errorCode) + 'oid4vp: a ' +
               'presentation verified and signs nobody in: ' +
               outcome.reason);
    }
    vpTransactions.set(String(record.state), record);
    log.debug("Leaving VcVerifier.recordAnswer(). " + outcome.ok + ".");
    return outcome;
  }

  // ---------------------------------------------------------------------------
  // A SELF-ISSUED ANSWER (SIOPv2, #129), at the Response URI (`direct_post`)
  // or the Redirect URI (`form_post`) — one handler, because the body is the
  // same form either way; only the reply differs (JSON for the wallet, a 303
  // for the browser).
  //
  //   * the ID Token is checked by `siop.ts` (section 11.1) against this
  //     request's Client Identifier and nonce;
  //   * with `vp_token id_token`, the presentation is verified as any other,
  //     and the ID Token's subject must be the HOLDER the presentation's key
  //     binding proved — otherwise the two answer for two different people;
  //   * for a sign-in, who is signed in: the credential's person when a
  //     presentation came with it (and the holder matched), the enrolled
  //     subject's person when the ID Token came alone.
  // ---------------------------------------------------------------------------
  private async answerSelfIssued(req: any, res: any, record: any,
                                 body: any): Promise<void> {
    const { log, errorCodes, siop, vpTransactions, stats,
            logArtifact } = this.deps;
    log.debug("Entering VcVerifier.answerSelfIssued().");
    const types = String(record.responseType).split(' ');
    const withVp = types.indexOf('vp_token') >= 0;
    const idv = await siop.verifyIdToken(body.id_token,
      { clientId: record.clientId, nonce: record.nonce });
    let answer: any = null;
    let checks = idv.checks.slice(0);
    let ok = idv.ok;
    if (withVp) {
      answer = await this.verifyAnswer(record, body.vp_token,
                                       { aud: record.clientId });
      if (!answer.shapeOk) {
        checks.push({ name: 'vp_token', ok: false, detail: answer.why });
        ok = false;
      } else {
        checks = checks.concat(answer.verified.checks);
        const same = idv.ok && answer.verified.ok &&
          siop.sameHolder(idv.jwk, answer.verified.holderJwk);
        checks.push({ name: 'id_token subject is the holder', ok: same,
                      detail: same ? idv.subject
                        : 'the ID Token and the presentation were signed ' +
                          'by different keys' });
        ok = ok && answer.verified.ok && same;
      }
    }
    record.verdict = {
      ok: ok, at: new Date().toISOString(), checks: checks,
      selfIssued: { subject: idv.subject, claims: idv.claims },
      claims: answer && answer.shapeOk ? answer.verified.claims : {},
      requested: record.requested || [],
      sub: idv.subject,
      format: answer && answer.shapeOk ? answer.format : 'siopv2'
    };
    let responseCode = '';
    if (record.signIn) {
      let outcome: any;
      if (withVp) {
        outcome = ok ? this.signInOutcome(answer.verified, answer) :
          { ok: false, errorCode: 'STS-VC-0090', username: '', subject: '',
            reason: 'The self-issued ID Token and the presentation did not ' +
                    'both verify for one holder, so nobody was signed in.' };
      } else if (record.signIn.enrol && idv.ok) {
        // AN ENROLMENT (#129): the key is proved, and the person it is for
        // is the one the transaction was started by; whether it may be
        // enrolled (nobody else's, not too many) is `siop.enrol()`'s, asked
        // when the browser collects this.
        outcome = { ok: true, errorCode: '', reason: '',
                    username: String(record.signIn.enrol.username),
                    subject: idv.subject, enrol: true };
      } else {
        outcome = siop.signInOutcome(idv);
      }
      record.signIn.outcome = outcome;
      record.signIn.via = record.responseMode;
      if (outcome.ok) {
        responseCode = this.deps.randomId(24);
        record.signIn.responseCodeHash = crypto.createHash('sha256')
          .update(responseCode, 'utf8').digest('base64url');
      } else if (idv.ok) {
        log.info(errorCodes.tag(outcome.errorCode) + 'oid4vp: a ' +
                 'self-issued ID Token verified and signs nobody in: ' +
                 outcome.reason);
      }
    }
    vpTransactions.set(String(record.state), record);
    logArtifact('SIOPv2 verification result', ok ? 'accepted' : 'REFUSED',
                record.verdict);
    const signsIn = !!(record.signIn && record.signIn.outcome &&
                       record.signIn.outcome.ok);
    if (ok && !signsIn && idv.subject) {
      // The bar door's rule (see the response endpoint): an identity that
      // got somewhere is recorded; a sign-in is recorded by its session.
      stats.recordAuthentication({
        presented: idv.subject, protocol: 'SIOPv2',
        method: 'self-issued ID Token (' + record.responseType + ')',
        client_id: record.clientId || '',
        applicationKind: 'oid4vp-verifier',
        note: 'A self-issued ID Token that verified. It started no session.'
      });
    }
    const next = this.afterResponseUri(req, record, responseCode);
    if (record.responseMode === 'form_post') {
      if (!ok) {
        errorCodes.mark(res, 'STS-VC-0090');
      }
      res.redirect(303, next);
      log.debug("Leaving VcVerifier.answerSelfIssued(). form_post, ok=" + ok);
      return;
    }
    if (!ok) {
      errorCodes.mark(res, 'STS-VC-0090');
      res.status(400).type('application/json').send(JSON.stringify({
        error: 'invalid_request',
        error_description: 'The self-issued answer was refused: ' +
          checks.filter(function (c: any) {
            return !c.ok;
          }).map(function (c: any) {
            return c.name + ' — ' + c.detail;
          }).join(' | ')
      }));
      log.debug("Leaving VcVerifier.answerSelfIssued(). Refused.");
      return;
    }
    res.status(200).type('application/json').send(JSON.stringify({
      redirect_uri: next }));
    log.debug("Leaving VcVerifier.answerSelfIssued(). Accepted.");
  }

  // The transaction a state names, or null. An expired one is removed on the
  // way past. For `vc_signin.ts`, which must not read the store directly: a
  // second reader of a persisted store is a second place to forget the
  // expiry.
  transactionFor(state: unknown) {
    const { log, vpTransactions, vpRequests } = this.deps;
    log.debug("Entering VcVerifier.transactionFor().");
    const key = String(state || '');
    const record = key ? vpTransactions.get(key) : null;
    if (record) {
      vpTransactionsCount.hit();
    } else {
      vpTransactionsCount.miss();
    }
    if (!record) {
      log.debug("Leaving VcVerifier.transactionFor(). None.");
      return null;
    }
    if (record.expires < Date.now()) {
      vpRequests.delete(record.id);
      vpTransactions.delete(key);
      log.debug("Leaving VcVerifier.transactionFor(). Expired.");
      return null;
    }
    log.debug("Leaving VcVerifier.transactionFor(). Found.");
    return record;
  }

  // ---------------------------------------------------------------------------
  // THE SIGN-INS A WALLET HAS ANSWERED AND NO BROWSER HAS COLLECTED YET
  // (#38), for `logout/logout.ts`. Between the wallet's `direct_post` and the
  // browser's next poll a transaction NAMES A PERSON and will become their
  // session — so a sign-out in that window that left it alone would be
  // followed, seconds later, by a session nobody could have ended. Each is
  // `{ state, username, subject, expires, decidedAt }`; `withdrawSignIn()`
  // ends one, and the wait page then says a sign-out ended it
  // (STS-VC-0070).
  // ---------------------------------------------------------------------------
  signInsAwaitingCollection() {
    const { log, vpTransactions } = this.deps;
    log.debug("Entering VcVerifier.signInsAwaitingCollection().");
    const now = Date.now();
    const out: any[] = [];
    vpTransactions.forEach((record) => {
      const signIn = record && record.signIn;
      if (!signIn || signIn.completed || !signIn.outcome ||
          !signIn.outcome.ok || record.expires < now) {
        return;
      }
      out.push({ state: record.state, username: signIn.outcome.username,
                 subject: signIn.outcome.subject, expires: record.expires,
                 decidedAt: (record.verdict && record.verdict.at) || '' });
    });
    log.debug("Leaving VcVerifier.signInsAwaitingCollection(). " +
              out.length + ".");
    return out;
  }

  withdrawSignIn(state: unknown, why: string) {
    const { log, vpTransactions } = this.deps;
    log.debug("Entering VcVerifier.withdrawSignIn().");
    const record = this.transactionFor(state);
    if (!record || !record.signIn || record.signIn.completed ||
        !record.signIn.outcome || !record.signIn.outcome.ok) {
      log.debug("Leaving VcVerifier.withdrawSignIn(). Nothing to withdraw.");
      return false;
    }
    record.signIn.outcome = {
      ok: false, errorCode: 'STS-VC-0070', username: '', subject: '',
      reason: 'This sign-in was ended before this browser collected it: ' +
              String(why || 'a sign-out') + '. Nobody was signed in.' };
    vpTransactions.set(String(record.state), record);
    log.debug("Leaving VcVerifier.withdrawSignIn(). Withdrawn.");
    return true;
  }

  // Writes a transaction back THROUGH THE STORE, for the reason the response
  // endpoint gives: the journal sees `set()`, not a field on an object.
  saveTransaction(record: any) {
    const { log, vpTransactions } = this.deps;
    log.debug("Entering VcVerifier.saveTransaction().");
    vpTransactions.set(String(record.state), record);
    log.debug("Leaving VcVerifier.saveTransaction().");
  }

  // The six endpoints, in the order they were registered at load before
  // #50's R1. Called by `common/protocol_stack.ts`.
  registerRoutes(app: any) {
    const { log, logArtifact, baseUrlOf, xmlEscape, parseBody, oauthError,
            errorCodes, stats, vpConfig, vpTransactions,
            vpRequests } = this.deps;
    log.debug("Entering VcVerifier.registerRoutes().");
    app.get('/oid4vp/verifier', (req, res) => {
      log.debug("Entering the verifier web page. format=" +
                (req.query.format || 'dc+sd-jwt'));
      const base = baseUrlOf(req);
      // Which format this verifier will ask for. A wallet arriving from the
      // debugger's presentation step 0 names the format it is actually holding,
      // because the format is the VERIFIER's choice and a wallet cannot convert
      // a credential into another one. Without carrying it through these links,
      // every button below would start a dc+sd-jwt request whatever the holder
      // has.
      const askedPage = validation.check(req, 'query', OID4VC_QUERY);
      if (!askedPage.ok) {
        log.debug('Leaving the verifier web page. ' + askedPage.detail);
        errorCodes.mark(res, 'STS-VC-0032');
        return res.status(400).type('text/plain').send(askedPage.detail + '\n');
      }
      const pageFormat = String(req.query.format || '');
      // Recognised through the configuration's own lookup rather than compared
      // here, which is what makes `?format=dc+sd-jwt` work: a plus in a query
      // string is a space by the time express has parsed it, so the literal
      // comparison this replaced answered "no such format" for the one format
      // whose id contains one.
      const named = vpConfig.formatById(pageFormat);
      const knownFormat = named ? named.id : '';
      const withFormat = (path) => {
        log.debug("Entering withFormat().");
        if (!knownFormat) {
          log.debug("Leaving withFormat().");
          return path;
        }
        log.debug("Leaving withFormat().");
        return path + (path.indexOf('?') === -1 ? '?' : '&') + 'format=' +
               encodeURIComponent(knownFormat);
      };
      const askingFor = vpConfig.formatOf(knownFormat);
      // What this door is currently configured to ask for. Read here rather
      // than at require time, so that the page a tester is looking at and the
      // request the button builds cannot disagree — the console can change this
      // between the two.
      const wantedClaims = vpConfig.requestedClaims();
      // The claims an ldp_vc request will silently NOT carry, because the
      // vendored JSON-LD context defines no term for them. Said on the page
      // rather than left to be found in a presentation that disclosed less than
      // was asked for.
      const ldpOmitted = askingFor === 'ldp_vc' ? vpConfig.ldpOmitted() : [];
      // What the request will name the credential by: a vct for an SD-JWT VC, a
      // type array for the two W3C formats. Read from the configuration rather
      // than decided again here — this page saying "type
      // urn:idptools:sd-jwt-vc:identity" over a request that named a type array
      // is exactly the kind of small lie that costs somebody an afternoon.
      const askingType = vpConfig.formatById(askingFor).identifierText;
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
        'charset="utf-8"><title>The Bar Door — are you over ' +
        '21?</title><style>body{font-family:system-ui,-apple-system,"Segoe ' +
        'UI",Arial,sans-serif;background:#f4f4f7;margin:0;display:flex;' +
        'align-items:center;justify-content:center;min-height:100vh;' +
        'color:#222}.card{background:#fff;border:1px solid #d5d5dd;' +
        'border-radius:10px;padding:30px 34px;width:560px;box-shadow:0 6px ' +
        '24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
        'p{line-height:1.5;color:#333}a.cta{display:inline-block;' +
        'margin-top:14px;margin-right:10px;padding:10px 16px;' +
        'border-radius:6px;background:#12107c;color:#fff;' +
        'text-decoration:none;font-weight:600}' +
        'a.cta.secondary{background:#fff;color:#12107c;border:1px solid ' +
        '#12107c}p.alt{margin-top:20px;font-size:.92em;color:#555}' +
        '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;' +
        'font-size:.78em;color:#777}code{font-family:ui-monospace,' +
        'SFMono-Regular,Menlo,monospace}</style></head><body><div ' +
        'class="card"><h1>The Bar Door</h1>' +
        (wantedClaims.length
          ? '<p>We need to see that you are who you say you are — but only ' +
              'that. Present the ' +
            '<code>' + xmlEscape(wantedClaims.join(', ')) + '</code> ' +
            'claim(s) from a credential of type ' +
            '<code>' + xmlEscape(askingType) + '</code>, and nothing else.</p>'
          // A configuration naming no claims is a real setting and not an empty
          // page: DCQL with no `claims` member asks for the whole credential,
          // which is the opposite of everything else this door says, so it says
          // THAT instead of printing an empty list.
          : '<p>This door is currently asking for <strong>no particular ' +
            'claim</strong>, which in DCQL means the whole credential: the ' +
            'request carries no <code>claims</code> member, so your wallet ' +
            'is being asked for a credential of type <code>' +
            xmlEscape(askingType) + '</code> and everything in it.</p>') +
        (ldpOmitted.length
          ? '<p class="alt">' + ldpOmitted.length +
            (ldpOmitted.length === 1 ? ' of these is' : ' of these are') +
            ' asked for in the other formats and not in this one: ' +
            '<code>' + xmlEscape(ldpOmitted.join(', ')) + '</code> — an ' +
            '<code>ldp_vc</code> credential is signed over canonicalized ' +
            'JSON-LD, so a claim the vendored context defines no term for ' +
            'cannot be named at all, and it is dropped from the query rather ' +
            'than asked for under a name that would fail canonicalization.</p>'
          : '') +
        '<p><a class="cta" id="present_by_value" href="' +
        xmlEscape(withFormat('/oid4vp/start')) +
        '">Present your credential</a>' +
        '<a class="cta secondary" id="present_by_reference" href="' +
        xmlEscape(withFormat('/oid4vp/start?by=reference')) + '">' +
        'Present it (signed request by reference)</a></p>' +
        '<p class="alt">Wallet on another device?<br>' +
        '<a class="cta secondary" id="present_cross_device" href="' +
        xmlEscape(withFormat('/oid4vp/start?mode=cross-device')) + '">' +
        'Show a QR code (cross-device)</a></p>' +
        '<p class="alt">This request asks for a <code>' + xmlEscape(askingFor) +
        '</code> credential. A presentation cannot convert between formats, ' +
        'so a wallet holding a different one has nothing to answer with — ' +
        'pick the format you hold:<br><a class="cta secondary" ' +
        'id="present_sd_jwt_vc" ' +
        'href="/oid4vp/start?format=dc%2Bsd-jwt">Present an SD-JWT VC</a> <a ' +
        'class="cta secondary" id="present_jwt_vc_json" ' +
        'href="/oid4vp/start?format=jwt_vc_json">Present a JWT VC</a> <a ' +
        'class="cta secondary" id="present_ldp_vc" ' +
        'href="/oid4vp/start?format=ldp_vc">Present an LDP VC ' +
        '(BBS)</a></p><p class="alt"><code>jwt_vc_json</code> has no ' +
        'selective disclosure, so presenting it hands over every claim it ' +
        'carries. <code>ldp_vc</code> discloses over canonical statements ' +
        'with a bbs-2023 derived proof, and each presentation is unlinkable ' +
        'to the last.</p><div class="meta">This is the Verifier in OID4VP. ' +
        'It builds an Authorization Request with ' +
        '<code>response_type=vp_token</code>, a <code>dcql_query</code> ' +
        'naming the claims above, a fresh <code>nonce</code>, and ' +
        '<code>response_mode=direct_post</code> — so your wallet POSTs the ' +
        'presentation to ' +
        '<code>' + xmlEscape(base) + '/oid4vp/response</code> rather than ' +
        'putting it in a URL. The wallet is at ' +
        '<code>' + xmlEscape(this.vpWalletUrl()) + '</code>. What it asks ' +
        'for is configuration, not a constant: <a ' +
        'href="/admin/vc-verifier-config">/admin/vc-verifier-config</a> ' +
        'chooses the claims and the format, from the same catalogue of LDAP ' +
        'attribute ' +
        'types the issuer fills a credential from.</div></div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving the verifier web page.");
    });

    // The link on that page: build the request and hand it to the wallet.
    app.get('/oid4vp/start', (req, res) => {
      log.debug("Entering the presentation start endpoint. mode=" +
                (req.query.mode || 'same-device') +
                ", format=" + (req.query.format || 'dc+sd-jwt'));
      const askedStart = validation.check(req, 'query', OID4VC_QUERY);
      if (!askedStart.ok) {
        log.debug('Leaving the presentation start endpoint. ' +
                  askedStart.detail);
        errorCodes.mark(res, 'STS-VC-0032');
        return res.status(400).type('text/plain').send(askedStart.detail +
                                                       '\n');
      }
      const byReference = String(req.query.by || '') === 'reference';
      const startMode = String(req.query.mode || 'same-device');
      // Which credential format to ask for. Anything unrecognised — and a link
      // that names none, which is the ordinary case — falls back to the
      // CONFIGURED default rather than to a constant; dc+sd-jwt is what that
      // default starts as, so a link that worked before this page existed asks
      // for what it always did.
      const format = vpConfig.formatOf(String(req.query.format || ''));
      let record: any = null;
      try {
        record = this.buildVpRequest(req,
                                     { byReference: byReference,
                                       format: format,
                                       responseType: String(
                                         req.query.response_type || ''),
                                       responseMode: String(
                                         req.query.response_mode || '') });
      } catch (e) {
        // The one thing that stops a request being built: a configured
        // Verifier Attestation this realm cannot use (it is logged there).
        log.debug("Caught in the presentation start endpoint: " +
                  ((e && e.message) || e));
        errorCodes.mark(res, (e && e.code) || 'STS-VC-0092');
        return res.status(500).type('text/plain').send(
          ((e && e.message) || String(e)) + '\n');
      }
      const query = this.vpRequestQuery(req, record);
      const walletChoice = this.vpWalletFor(req);
      if (walletChoice.error) {
        log.debug("Leaving the presentation start endpoint. " +
                  walletChoice.error);
        errorCodes.mark(res, 'STS-VC-0033');
        return res.status(400).type('text/plain').send(walletChoice.error +
                                                       '\n');
      }
      const wallet = walletChoice.url;

      if (startMode !== 'cross-device') {
        // Same device: the browser IS the wallet's user agent, so send it
        // there.
        res.redirect(302, wallet + '?' + query);
        log.debug("Leaving the presentation start endpoint. Redirected to " +
                  "the wallet.");
        return;
      }
      // Cross device: display the request for the wallet on the other device to
      // scan, as the openid4vp URI a wallet registers for.
      this.renderVpQrPage(res, {
        base: baseUrlOf(req),
        // SIOPv2 section 7.2's static `siopv2:` for an ID Token alone; the
        // OpenID4VP scheme whenever a presentation is asked for.
        requestUri: (record.responseType === 'id_token' ? 'siopv2://?' :
                     'openid4vp://?') + query,
        walletUrl: wallet + '?' + query,
        record: record
      });
      log.debug("Leaving the presentation start endpoint. Displayed a QR " +
                "code.");
    });

    // The Request Object, fetched by reference (request_uri). Signed, and
    // served with the media type RFC 9101 defines for it.
    app.get('/oid4vp/request/:id', (req, res) => {
      log.debug("Entering the request object endpoint. id=" + req.params.id);
      const state = vpRequests.get(String(req.params.id));
      const record = state ? vpTransactions.get(state) : null;
      if (!record || !record.requestObject) {
        log.debug("Leaving the request object endpoint. No such request.");
        errorCodes.mark(res, 'STS-VC-0035');
        return oauthError(res, 404, 'invalid_request', 'No such Request ' +
                          'Object.');
      }
      res.status(200)
         .type('application/oauth-authz-req+jwt')
         .send(record.requestObject);
      log.debug("Leaving the request object endpoint. Served a signed " +
                "Request Object.");
    });

    // The Response URI (OID4VP section 8.2): response_mode direct_post, so the
    // Authorization Response arrives as a form POST rather than in a URL.
    app.post('/oid4vp/response', async (req, res) => {
      log.debug("Entering the OID4VP response endpoint.");
      let body = parseBody(req);
      // A `direct_post.jwt` answer (section 8.3.1): one `response`, a JWE to
      // the transaction's own key, which its header's `kid` names (#187).
      const opened = this.openEncryptedResponse(body);
      if (!opened.ok) {
        errorCodes.mark(res, 'STS-VC-0096');
        return oauthError(res, 400, 'invalid_request', opened.why);
      }
      body = opened.body;
      const state = String(body.state || '');
      let record = vpTransactions.get(state);
      if (record && !record.signIn &&
          (record.responseMode === 'direct_post.jwt') !== opened.encrypted) {
        log.debug("Leaving the OID4VP response endpoint. The response " +
                  "mode was not the one asked for.");
        errorCodes.mark(res, 'STS-VC-0096');
        return oauthError(res, 400, 'invalid_request',
          'This Authorization Request asked for response_mode ' +
          record.responseMode + ', and the response ' +
          (opened.encrypted ? 'is' : 'is not') + ' encrypted (OpenID4VP ' +
          'section 8.3.1).');
      }
      // A SIGN-IN'S TRANSACTION EXPIRES WHEN IT SAYS (#38). The bar door's
      // are swept only when the next one is built, so a late answer to one
      // is still verified as it always was; a sign-in's lifetime is a
      // setting a deployment chose to bound a relay, and an answer after it
      // is one the setting said not to take.
      if (record && record.signIn && record.expires < Date.now()) {
        record = null;
      }
      if (!record) {
        log.debug("Leaving the OID4VP response endpoint. Unknown state.");
        errorCodes.mark(res, 'STS-VC-0036');
        return oauthError(res, 400, 'invalid_request',
          'Unknown or expired state: this Verifier has no such Authorization ' +
          'Request outstanding.');
      }
      // A SIGN-IN'S TRANSACTION IS ANSWERED ONCE (2026-09-17, #38). The bar
      // door lets a second `direct_post` overwrite the verdict, which costs
      // nothing there; here the verdict decides WHO a waiting browser is about
      // to be signed in as, and a second presentation replacing the first
      // after the page has shown it would be exactly the swap a sign-in must
      // not allow.
      if (record.signIn && record.verdict) {
        log.debug("Leaving the OID4VP response endpoint. A sign-in's " +
                  "transaction was answered twice.");
        errorCodes.mark(res, 'STS-VC-0057');
        return oauthError(res, 400, 'invalid_request',
          'This Authorization Request is a sign-in and has already been ' +
          'answered. Start the sign-in again for a new one.');
      }
      if (body.error) {
        // The wallet refused, which is a legitimate answer (section 8.4).
        record.verdict = { ok: false, refused: true, error: String(body.error),
                           errorDescription: String(body.error_description ||
                                                    ''),
                           checks: [], at: new Date().toISOString() };
        if (record.signIn) {
          record.signIn.outcome = {
            ok: false, errorCode: 'STS-VC-0037', username: '', subject: '',
            reason: 'The wallet declined to present a credential (' +
                    String(body.error) + '), so nobody was signed in.' };
        }
        // THROUGH THE STORE, so the verdict is not a fact only this process
        // holds: `vpTransactions` is `realms.map({persist})` and its journal
        // sees `set()` rather than a field stamped on the object it handed out.
        // The status endpoint a wallet polls may well be answered by another
        // process, which would otherwise report the transaction as still
        // outstanding for ever.
        vpTransactions.set(state, record);
        errorCodes.mark(res, 'STS-VC-0037');
        res.status(200).type('application/json').send(JSON.stringify({
          redirect_uri: this.afterResponseUri(req, record, '')
        }));
        log.debug("Leaving the OID4VP response endpoint. The wallet refused: " +
                  body.error);
        return;
      }

      // A SELF-ISSUED ID TOKEN (SIOPv2, #129) — alone, or beside a
      // presentation — is answered by its own method.
      if (String(record.responseType || '').split(' ')
            .indexOf('id_token') >= 0) {
        await this.answerSelfIssued(req, res, record, body);
        log.debug("Leaving the OID4VP response endpoint. Self-issued.");
        return;
      }
      // vp_token is a JSON object keyed by the DCQL credential query id, each
      // value an array of presentations (section 8.1). Read, verified in the
      // format its query asked for — so answering a jwt_vc_json query with an
      // SD-JWT (or the reverse) is refused rather than silently handled by the
      // other code path — and checked for revocation and status, by
      // verifyAnswer(), which the Digital Credentials API door shares.
      const answer = await this.verifyAnswer(record, body.vp_token,
                                             { aud: record.clientId });
      if (!answer.shapeOk) {
        if (record.signIn) {
          this.recordAnswer(record, answer, 'direct_post');
        } else {
          record.verdict = {
            ok: false, at: new Date().toISOString(),
            checks: [{ name: 'vp_token', ok: false, detail: answer.why }]
          };
          vpTransactions.set(state, record);  // through the store, as above
        }
        errorCodes.mark(res, 'STS-VC-0038');
        res.status(400).type('application/json').send(JSON.stringify({
          error: 'invalid_request',
          error_description: 'vp_token is not the JSON object OID4VP ' +
              'section 8.1 defines: ' + answer.why
        }));
        log.debug("Leaving the OID4VP response endpoint. Malformed vp_token.");
        return;
      }
      const verified = answer.verified;
      // A SIGN-IN'S SECOND VERDICT (#38): whom, if anybody, this signs in.
      // The browser that started the sign-in reads it; a same-device wallet
      // is handed a one-time `response_code` to take that browser back with
      // (OID4VP section 8.2), and only its SHA-256 is kept.
      let responseCode = '';
      if (record.signIn) {
        const outcome = this.recordAnswer(record, answer, 'direct_post');
        if (outcome.ok) {
          responseCode = this.deps.randomId(24);
          record.signIn.responseCodeHash = crypto.createHash('sha256')
            .update(responseCode, 'utf8').digest('base64url');
          vpTransactions.set(state, record);  // through the store, as above
        }
      } else {
        record.verdict = {
          ok: verified.ok,
          at: new Date().toISOString(),
          checks: verified.checks,
          claims: verified.claims,
          disclosed: verified.disclosed,
          extraDisclosed: verified.extraDisclosed || [],
          requested: record.requested || [],
          vct: verified.vct,
          sub: verified.sub,
          presentation: answer.presentation
        };
        vpTransactions.set(state, record);  // through the store, as above
      }
      logArtifact('OID4VP verification result',
                  verified.ok ? 'accepted' : 'REFUSED', record.verdict);

      if (!verified.ok) {
        // Section 8.4: an invalid presentation is invalid_request. The failing
        // checks go in the description, because a wallet developer cannot fix
        // "no".
        const failed = verified.checks.filter((c) => { return !c.ok; });
        // A refusal whose only failed check is the issuer certificate's
        // revocation is named for that, so an operator is sent to the
        // certificate rather than to the wallet.
        errorCodes.mark(res, (verified.revocationRefused && failed.length === 1)
          ? 'STS-PKI-0129' : verified.statusRefused ?
          (verified.statusErrorCode || 'STS-VC-0072') : 'STS-VC-0041');
        res.status(400).type('application/json').send(JSON.stringify({
          error: 'invalid_request',
          error_description: 'The presentation was refused: ' +
            failed.map((c) => { return c.name + ' — ' + c.detail; })
                  .join(' | ')
        }));
        log.debug("Leaving the OID4VP response endpoint. Refused " +
                  failed.length +
            " check(s).");
        return;
      }
      // -----------------------------------------------------------------------
      // The holder, recorded — and a directory entry for them, which is the
      // whole of what this call is for.
      //
      // BELOW the refusal above, deliberately: this is the funnel that means "a
      // credential was accepted", so a presentation that failed a check gets no
      // record, exactly as a wrong password does not. That is what keeps
      // /admin/users a list of identities that got somewhere rather than of
      // ones that were tried.
      //
      // AND THIS CALL IS NOT THE SIGN-ON. What is recorded here is narrower
      // and true: an identity presented a credential and it verified. No
      // session starts HERE — this request is the wallet's, and a cookie set
      // on it would land in the wallet rather than in the browser somebody is
      // signing in with. Since 2026-09-17 (#38) a presentation made for a
      // sign-in CAN start a session, in the browser that asked for it, at
      // `/authn/wallet/wait` (`vc_signin.ts`); `tls_server.js` drew the same
      // line for a verified client certificate, which became a sign-on at
      // `GET /tls/sign-in`.
      //
      // The identity is the credential's SUBJECT, which is usually a DID (an
      // ldp_vc names its subject `did:jwk:…`) and is whatever the credential
      // says otherwise. A presentation with no readable subject records nothing
      // rather than a blank: recordAuthentication() drops an empty identity, so
      // the guard here is only to save the call.
      //
      // **A PRESENTATION THAT SIGNS SOMEBODY IN IS NOT RECORDED HERE**
      // (2026-09-17, #38). It is recorded when the browser that started the
      // sign-in comes back for its session, by `startSession()`, which
      // records every sign-in itself with the session id on it — recording
      // it here as well would count one sign-in twice, the defect federation
      // and SPNEGO each fixed the same way. A sign-in nobody comes back for
      // is on this transaction's verdict and nowhere else. Everything that
      // does NOT sign anybody in — the bar door's presentations, and a
      // sign-in's presentation of a credential that cannot — is recorded
      // exactly as it always was.
      const signsIn = !!(record.signIn && record.signIn.outcome &&
                         record.signIn.outcome.ok);
      if (verified.sub && !signsIn) {
        stats.recordAuthentication({
          presented: verified.sub,
          protocol: 'OpenID4VP',
          method: 'verifiable presentation (' + (record.format || 'dc+sd-jwt') +
                  ')',
          client_id: record.clientId || '',
          // Which kind of application that client_id names. Without it the
          // funnel files every client_id it is handed as an OAuth client, and
          // the mock Verifier is not one — it is the OID4VP verifier this
          // service configures at oid4vp.clientId.
          applicationKind: 'oid4vp-verifier',
          note: 'A presentation that verified against every check this ' +
                'Verifier makes. It started no session: ' +
                (record.signIn
                  ? 'it was made to sign in, and ' +
                    record.signIn.outcome.reason
                  : 'it was made to the Verifier at /oid4vp/verifier, which ' +
                    'signs nobody in — a wallet signs in at /authn/wallet.')
        });
      }
      res.status(200).type('application/json').send(JSON.stringify({
        redirect_uri: this.afterResponseUri(req, record, responseCode)
      }));
      log.debug("Leaving the OID4VP response endpoint. Accepted.");
    });

    // Not in the spec: the verdict, so the wallet's own page (and the test
    // suite) can show what this Verifier decided and why. A real Verifier tells
    // the End-User in its own UI; this makes the same information
    // machine-readable. Its CORS header is `common/cors.js`'s decision
    // (2026-09-13) — the `*` this route set for itself would have let any page
    // read a presentation's verdict.
    app.get('/oid4vp/result/:state', (req, res) => {
      log.debug("Entering the presentation result endpoint. state=" +
                req.params.state);
      const record = vpTransactions.get(String(req.params.state));
      if (!record) {
        log.debug("Leaving the presentation result endpoint. Unknown state.");
        errorCodes.mark(res, 'STS-VC-0042');
        return oauthError(res, 404, 'invalid_request', 'No such presentation.');
      }
      res.status(200).type('application/json').send(JSON.stringify({
        state: record.state,
        nonce: record.nonce,
        client_id: record.clientId,
        requested: record.requested || [],
        dcql_query: record.request.dcql_query,
        received: !!record.verdict,
        verdict: record.verdict
      }));
      log.debug("Leaving the presentation result endpoint. received=" +
                !!record.verdict);
    });

    // Where the wallet sends the End-User once the Verifier has answered.
    app.get('/oid4vp/done', (req, res) => {
      log.debug("Entering the verifier done page.");
      const record = vpTransactions.get(String(req.query.state || ''));
      const verdict = record && record.verdict;
      const ok = !!(verdict && verdict.ok);
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
          'charset="utf-8">' +
        '<title>The Bar Door — ' + (ok ? 'come on in' : 'not today') +
        '</title><style>body{font-family:system-ui,-apple-system,"Segoe UI",' +
        'Arial,sans-serif;background:#f4f4f7;margin:0;display:flex;' +
        'align-items:center;justify-content:center;min-height:100vh;' +
        'color:#222}.card{background:#fff;border:1px solid #d5d5dd;' +
        'border-radius:10px;padding:30px 34px;width:560px;box-shadow:0 6px ' +
        '24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
        'p{line-height:1.5;color:#333}ul{line-height:1.5}.ok{color:#2e7d32;' +
        'font-weight:700}.bad{color:#b00020;font-weight:700}' +
        'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
        '</style></head><body><div class="card"><h1>The Bar Door</h1>' +
        (verdict
          ? '<p class="' + (ok ? 'ok' : 'bad') + '" id="verdict">' +
            (ok ? 'Presentation accepted.' : 'Presentation refused.') + '</p>' +
            '<ul id="claims">' +
            Object.keys(verdict.claims || {}).map((k) => {
              return '<li><code>' + xmlEscape(k) + '</code>: <code>' +
                     xmlEscape(typeof verdict.claims[k] === 'object'
                       ? JSON.stringify(verdict.claims[k]) :
                               String(verdict.claims[k])) + '</code></li>';
            }).join('') + '</ul>' +
            '<p style="font-size:.85em;color:#666">We asked for <code>' +
            xmlEscape((verdict.requested || []).join(', ')) + '</code> and ' +
                'that is all we know about you.</p>'
          : '<p id="verdict">Nothing has been presented for this request ' +
              'yet.</p>') +
        '</div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving the verifier done page. ok=" + ok);
    });

    log.debug("Leaving VcVerifier.registerRoutes().");
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
const slot = new InstanceSlot<VcVerifier>(
  'oid4vc/vc_verifier',
  () => new VcVerifier(VcVerifier.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcVerifier: VcVerifier,
  installInstance: (instance: VcVerifier): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  verifyPresentation: slot.forward('verifyPresentation'),
  // For tests/revocation_status.js, which asks it about a revoked certificate.
  issuerCertificateRevocation: slot.forward('issuerCertificateRevocation'),
  buildVpRequest: slot.forward('buildVpRequest'),
  // SIOPv2 and the Client Identifier prefixes (#129).
  signedClientId: slot.forward('signedClientId'),
  verifierAttestation: slot.forward('verifierAttestation'),
  federationVerifierMetadata: slot.forward('federationVerifierMetadata'),
  vpDcqlQuery: slot.forward('vpDcqlQuery'),
  // THE SIGN-IN'S HALF (2026-09-17, #38), for `vc_signin.ts` and its test:
  // the request a sign-in asks with, how a wallet is handed it, whom a
  // presentation signs in, and the transaction read and written back
  // through the one store.
  signInDcqlQuery: slot.forward('signInDcqlQuery'),
  vpRequestQuery: slot.forward('vpRequestQuery'),
  vpWalletFor: slot.forward('vpWalletFor'),
  signInOutcome: slot.forward('signInOutcome'),
  signInFormats: slot.forward('signInFormats'),
  verifyAnswer: slot.forward('verifyAnswer'),
  answerDcApi: slot.forward('answerDcApi'),
  dcApiRequestFor: slot.forward('dcApiRequestFor'),
  transactionFor: slot.forward('transactionFor'),
  saveTransaction: slot.forward('saveTransaction'),
  // For `logout/logout.ts`'s `wallet-signin` family.
  signInsAwaitingCollection: slot.forward('signInsAwaitingCollection'),
  withdrawSignIn: slot.forward('withdrawSignIn')
};
