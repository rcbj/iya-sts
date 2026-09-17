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
import vcConfigs = require('./vc_configs');
// THE REGISTER OF CREDENTIALS THIS REALM ISSUED FOR A DIRECTORY ENTRY
// (2026-09-17, #38), read by `signInOutcome()` to decide whom a presentation
// made for a sign-in signs in. A LIBRARY (rule 3) requiring only `common/`
// leaves: this require closes no cycle and moves no route.
import vcIssued = require('./vc_issued');

// The input validator. A LEAF (rule 3): registers no route, closes no cycle.
import validation = require('../common/validation');

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
  parseBody: typeof helpers.parseBody;
  oauthError: typeof helpers.oauthError;
  signJwt: typeof helpers.signJwt;
  stsKeysFor: typeof helpers.stsKeysFor;
  kidNamesKey: typeof helpers.kidNamesKey;
  nameForSubject: typeof helpers.nameForSubject;
  subjectForName: typeof helpers.subjectForName;
  vcIssued: typeof vcIssued;
  config: { value(key: string): any };
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  revocationStatus: typeof revocationStatus;
  stats: typeof stats;
  vpConfig: typeof vpConfig;
  stsCrypto: typeof stsCrypto;
  vpTransactions: Store;
  vpRequests: Store;
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
const vpTransactions = realms.map({ persist: 'vc_verifier.vpTransactions' });

// id -> state, so a Request Object fetched by reference can find its
// transaction. PER TRUST REALM. `realms.map()` is a Map that holds a separate
// one for each realm and hands out the ambient realm's — so every reader below
// is unchanged and every one of them is now realm-correct. In the default
// realm, and in a service with no realms defined, there is exactly one
// partition and this behaves as the plain Map it replaced. See
// common/realms.js.
const vpRequests = realms.map({ persist: 'vc_verifier.vpRequests' });

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
    validation.z.string().max(validation.CAP.SCOPE))
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
      parseBody: helpers.parseBody,
      oauthError: helpers.oauthError,
      signJwt: helpers.signJwt,
      stsKeysFor: helpers.stsKeysFor,
      kidNamesKey: helpers.kidNamesKey,
      nameForSubject: helpers.nameForSubject,
      subjectForName: helpers.subjectForName,
      vcIssued: vcIssued,
      config: config,
      mode: mode,
      errorCodes: errorCodes,
      revocationStatus: revocationStatus,
      stats: stats,
      vpConfig: vpConfig,
      stsCrypto: stsCrypto,
      vpTransactions: vpTransactions,
      vpRequests: vpRequests
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
    if (family === 'rsa' || family === 'rsa-pss' || /^(RS|PS)/.test(alg)) {
      candidates.push({ label: 'this issuer\'s RSA key', key: STS.certPem });
    } else {
      (stsKeysFor().extraKeys || []).forEach((one) => {
        if (one.publicJwk && one.alg === alg &&
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
  // `vc_signin.ts` passes, and it changes four things about the request and
  // nothing about how the answer is verified: it is always by reference (the
  // wallet can check a signed request names this service), it always asks for
  // THIS issuer's SD-JWT VC by its own `vct` whatever `oid4vp.expectedVct`
  // says (only a credential this realm issued can sign anybody in, so asking
  // for anybody else's would be asking for a refusal), it asks for the
  // subject and nothing else (a sign-in needs to know who, and a DCQL query
  // with no `claims` would ask for the whole credential), and it lives as long
  // as `oid4vp.signInTtlS` says rather than as long as the bar door's
  // requests. What the sign-in module needs to find the pending
  // authentication again rides on the transaction as `signIn`, never in
  // anything the wallet is shown.
  buildVpRequest(req: any, opts: { byReference?: boolean; format?: string;
                                   signIn?: any }) {
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
    const clientId = byReference ? this.vpClientId() :
                     ('redirect_uri:' + responseUri);
    const ttlMs = signIn && signIn.ttlMs > 0 ? Number(signIn.ttlMs) :
                  this.vpTtlMs();
    const request = {
      client_id: clientId,
      response_type: 'vp_token',
      response_mode: 'direct_post',
      response_uri: responseUri,
      nonce: nonce,
      state: state,
      dcql_query: signIn ? this.signInDcqlQuery() :
                  this.vpDcqlQuery(opts.format),
      client_metadata: {
        client_name: signIn ? 'Sign-in with a wallet' :
                     'Mock Verifier (bar door)',
        // All three formats are advertised whichever one this request asks for:
        // this is what the Verifier CAN accept, not what it wants this time —
        // the DCQL query is what says that.
        vp_formats_supported: {
          // From the shared table, not written out: the KB-JWT is checked by
          // stsCrypto.verifyCompactJws() against JWS_ASYMMETRIC_ALGS, and a
          // narrower list here would tell a wallet its perfectly acceptable
          // algorithm was unwelcome. The `sd-jwt_alg_values` are what the
          // ISSUER may have signed the credential with, which is the same set.
          'dc+sd-jwt': { 'sd-jwt_alg_values': stsCrypto.JWS_ASYMMETRIC_ALGS,
                         'kb-jwt_alg_values': stsCrypto.JWS_ASYMMETRIC_ALGS },
          'jwt_vc_json': { alg_values: stsCrypto.JWS_ASYMMETRIC_ALGS },
          'ldp_vc': { cryptosuites: ['bbs-2023'] }
        }
      }
    };
    const record: Record<string, any> = {
      id: id, nonce: nonce, state: state, clientId: clientId,
      responseMode: 'direct_post', request: request,
      byReference: byReference,
      // The claims asked for, FROZEN onto the transaction rather than read
      // again when the presentation arrives. That is not tidiness: the list is
      // editable from /admin/vc-verifier-config while a presentation is in
      // flight, and a verifier that judged what came back against a list
      // changed after the request was sent would refuse a wallet for answering
      // the question it was actually asked.
      requested: signIn ? ['sub'] : vpConfig.requestedClaims(),
      // Which format this Verifier asked for. The response is verified against
      // THIS, not against whatever shape happens to turn up, so a wallet that
      // answers a jwt_vc_json query with an SD-JWT is refused rather than
      // quietly accepted by the other code path.
      format: signIn ? 'dc+sd-jwt' : vpConfig.formatOf(opts.format),
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
        responseCode: '',
        outcome: null,
        completed: false
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
      record.requestObject = signJwt(
        Object.assign({ typ: 'oauth-authz-req+jwt' }, payload), null,
        { certificateHeader: 'vp-request-object' });
      logArtifact('OID4VP Request Object', 'after signing',
                  record.requestObject);
      vpRequests.set(id, state);
    }
    vpTransactions.set(state, record);
    this.sweepVpTransactions();
    log.debug("Leaving VcVerifier.buildVpRequest(). state=" + state + ", " +
              "nonce=" + nonce);
    return record;
  }

  // The DCQL query a sign-in asks with: this issuer's SD-JWT VC, and its
  // subject. See buildVpRequest() for why each part is what it is.
  signInDcqlQuery() {
    const { log, logArtifact } = this.deps;
    log.debug("Entering VcVerifier.signInDcqlQuery().");
    const query = {
      credentials: [{
        id: VP_DCQL_ID,
        format: 'dc+sd-jwt',
        meta: { vct_values: [VCI_VCT] },
        claims: [{ path: ['sub'] }]
      }]
    };
    logArtifact('OID4VP DCQL query', 'as built for a sign-in', query);
    log.debug("Leaving VcVerifier.signInDcqlQuery().");
    return query;
  }

  // The query the wallet is handed: by value it carries the whole request, by
  // reference only client_id and request_uri (OID4VP section 5.2).
  vpRequestQuery(req: any, record: any) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering VcVerifier.vpRequestQuery().");
    const base = baseUrlOf(req);
    const params = record.byReference
      ? { client_id: record.clientId,
          request_uri: base + '/oid4vp/request/' + record.id,
          request_uri_method: 'get' }
      : {
          client_id: record.clientId,
          response_type: record.request.response_type,
          response_mode: record.request.response_mode,
          response_uri: record.request.response_uri,
          nonce: record.nonce,
          state: record.state,
          dcql_query: JSON.stringify(record.request.dcql_query),
          client_metadata: JSON.stringify(record.request.client_metadata)
        };
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
  // proof IS the signature, re-randomised — so "did the issuer sign this" and
  // "is this the holder presenting it" collapse into one check.
  //
  // SHAPE NOTE, a stated simplification: a full bbs-2023 presentation
  // reconstructs a JSON-LD document from the disclosed statements. This mock is
  // handed the statements and their indexes directly, beside the proof and the
  // issuer's proof options. Everything cryptographic is real — the proof is
  // verified against this service's BBS key over exactly those statements, with
  // this request's nonce as the presentation header — but another verifier
  // would expect a document.
  private async verifyLdpVc(presentation: any, record: any) {
    const { log, bbsKeyPair } = this.deps;
    log.debug("Entering VcVerifier.verifyLdpVc().");
    const checks = [];
    const result: any = { ok: false, checks, claims: {}, disclosed: [], vct: '',
                     sub: '', extraDisclosed: [] };

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
    const proofBytes = payload.proof ?
      bbs2023.b64uToBytes(payload.proof) : null;
    const statements = [].concat(payload.disclosedStatements || []);
    const indexes = [].concat(payload.disclosedIndexes || []);
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
      'canonical statement(s).');

    const keys = await bbsKeyPair();
    let header;
    try {
      header = await bbs2023.headerFor(payload.proofOptions || {});
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

    const ok = await bbs2023.verifyDerived(keys.publicKey, proofBytes, header,
      Buffer.from(String(record.nonce), 'utf8'), statements, indexes);
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
    result.ok = checks.every((c) => { return c.ok; });
    log.debug("Leaving VcVerifier.verifyLdpVc(). " +
              (result.ok ? 'accepted' : 'REFUSED'));
    return result;
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
  private verifyVpJwt(presentation: any, record: any) {
    const { log, logArtifact, jsonFromB64u, nowSec, stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.verifyVpJwt().");
    // Named as the source check in tests/revocation_status.js reads it.
    const verifyIssuerSignature =
        this.verifyIssuerSignature.bind(this);
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
      result.issuerCertificatePem = verifyIssuerSignature(vcJwt).certificatePem;
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
        stsCrypto.verifyCompactJws(raw, cnfJwk,
          { algorithms: stsCrypto.JWS_ASYMMETRIC_ALGS });
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
    this.vpCheck(checks, 'Audience',
                 String(vpPayload.aud) === String(record.clientId),
      'aud is "' + vpPayload.aud + '"; this Verifier is "' + record.clientId +
      '".');

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
    const requested = [].concat(record.requested || []);
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

  verifyPresentation(presentation: any, record: any) {
    const { log, logArtifact, b64u, b64uDecode, jsonFromB64u, nowSec,
            errorCodes, vpConfig, stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.verifyPresentation().");
    // Named as the source check in tests/revocation_status.js reads it.
    const verifyIssuerSignature =
        this.verifyIssuerSignature.bind(this);
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
    this.vpCheck(checks, 'Media type (typ)',
      ['dc+sd-jwt', 'vc+sd-jwt'].indexOf(String(header.typ)) >= 0,
      'typ is "' + header.typ + '".');
    let issuerSignatureOk = false;
    try {
      // The fourth. Same change, same reason as the note above.
      result.issuerCertificatePem = verifyIssuerSignature(
          issuerJwt).certificatePem;
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
    this.vpCheck(checks, 'KB-JWT audience', kbPayload.aud === record.clientId,
      kbPayload.aud === record.clientId
        ? 'is this Verifier\'s Client Identifier.'
        : 'is "' + kbPayload.aud + '", not "' + record.clientId + '" — this ' +
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
        const holderKey = crypto.createPublicKey({ key: cnfJwk,
                                                  format: 'jwk' });
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
        stsCrypto.verifyJws(kbJwt, holderKey, { algorithms: ISSUER_ALGS });
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
    const requested = [].concat(record.requested || []);
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
    return base + record.signIn.completePath +
      '?authn=' + encodeURIComponent(record.signIn.authnId) +
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
  // have, and the issuer accepts no key attestation that could supply it.
  // `user` is not appropriate either: nothing about a presentation proves the
  // holder was present or tested, only that their wallet signed. It is ONE
  // factor, rated as every other one factor here is rated (`"1"`); two are
  // never claimed, which is also why the mechanism is withheld from a request
  // that demanded two (`authn.ts`, `walletOptionHtml()`).
  // ---------------------------------------------------------------------------
  signInOutcome(verified: any, presentation: unknown) {
    const { log, vcIssued, nameForSubject, subjectForName,
            stsCrypto } = this.deps;
    log.debug("Entering VcVerifier.signInOutcome().");
    const refuse = (errorCode: string, reason: string) => {
      log.debug("Leaving VcVerifier.signInOutcome(). " + errorCode);
      return { ok: false, errorCode: errorCode, reason: reason,
               username: '', subject: '' };
    };
    if (!verified || !verified.ok) {
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
    const row = vcIssued.lookup(presentation);
    if (!row) {
      return refuse('STS-VC-0059', 'This realm has no record of issuing ' +
                    'this credential to a person it authenticated. Only a ' +
                    'credential this realm\'s issuer minted on an access ' +
                    'token this realm issued and verified — for a person, ' +
                    'and for credential issuance — may sign somebody in. ' +
                    'A credential from another realm, one issued on a ' +
                    'token this service did not issue, or one issued ' +
                    'before a restart in development mode is not one.');
    }
    let presentedJkt = '';
    try {
      presentedJkt = verified.holderJwk ?
        stsCrypto.jwkThumbprint(verified.holderJwk, {}) : '';
    } catch (e) {
      log.debug("Caught in VcVerifier.signInOutcome(): " +
                ((e && e.message) || e));
      presentedJkt = '';
    }
    if (String(verified.sub || '') !== row.subject ||
        !presentedJkt || presentedJkt !== row.jkt) {
      return refuse('STS-VC-0066', 'The credential does not match what this ' +
                    'realm recorded when it issued it (its subject or the ' +
                    'key it is bound to), so it signs nobody in.');
    }
    const username = nameForSubject(row.subject);
    if (!username || subjectForName(username) !== row.subject) {
      return refuse('STS-VC-0060', 'The directory entry this credential was ' +
                    'issued for no longer exists — it was deleted, or its ' +
                    'name now belongs to a different entry — so the ' +
                    'credential signs nobody in.');
    }
    log.debug("Leaving VcVerifier.signInOutcome(). " + username + ".");
    return { ok: true, errorCode: '', reason: '', username: username,
             subject: row.subject, amr: ['pop'], acr: '1',
             holderKey: (verified.holderJwk.kty || '') +
                        (verified.holderJwk.crv ?
                          ' ' + verified.holderJwk.crv : '') };
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
    // The response endpoint is named as the test for it reads it.
    const issuerCertificateRevocation =
        this.issuerCertificateRevocation.bind(this);
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
      const record = this.buildVpRequest(req,
                                    { byReference: byReference,
                                     format: format });
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
        requestUri: 'openid4vp://?' + query,
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
      const body = parseBody(req);
      const state = String(body.state || '');
      let record = vpTransactions.get(state);
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

      // vp_token is a JSON object keyed by the DCQL credential query id, each
      // value an array of presentations (section 8.1).
      let presentations = [];
      let tokenShapeOk = true;
      try {
        const parsed = typeof body.vp_token === 'string' ?
                       JSON.parse(body.vp_token) : body.vp_token;
        const forQuery = parsed && parsed[VP_DCQL_ID];
        if (Array.isArray(forQuery)) presentations = forQuery;
        else if (typeof forQuery === 'string') presentations = [forQuery];
        else tokenShapeOk = false;
      } catch (e) {
        log.debug("Caught in VcVerifier.registerRoutes(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0038') +
                  'the vp_token is not the JSON object OID4VP defines: ' +
                  e.message);
        tokenShapeOk = false;
      }
      if (!tokenShapeOk || !presentations.length) {
        record.verdict = {
          ok: false, at: new Date().toISOString(),
          checks: [{ name: 'vp_token', ok: false,
                     detail: 'vp_token must be a JSON object keyed by the ' +
                         'DCQL credential query id ("' +
                             VP_DCQL_ID + '"), each value an array of ' +
                                          'presentations.' }]
        };
        if (record.signIn) {
          record.signIn.outcome = this.signInOutcome(null, '');
        }
        vpTransactions.set(state, record);  // through the store, as above
        errorCodes.mark(res, 'STS-VC-0038');
        res.status(400).type('application/json').send(JSON.stringify({
          error: 'invalid_request',
          error_description: 'vp_token is not the JSON object OID4VP ' +
              'section 8.1 defines.'
        }));
        log.debug("Leaving the OID4VP response endpoint. Malformed vp_token.");
        return;
      }

      // Verified against the format THIS request asked for, so answering a
      // jwt_vc_json query with an SD-JWT (or the reverse) is refused rather
      // than silently handled by the other code path.
      const verified = record.format === 'ldp_vc'
        ? await this.verifyLdpVc(presentations[0], record)
        : record.format === 'jwt_vc_json'
          ? this.verifyVpJwt(presentations[0], record)
          : this.verifyPresentation(presentations[0], record);
      await issuerCertificateRevocation(verified);
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
        presentation: presentations[0]
      };
      // A SIGN-IN'S SECOND VERDICT (#38): whom, if anybody, this signs in.
      // The browser that started the sign-in reads it; a same-device wallet
      // is handed a one-time `response_code` to take that browser back with
      // (OID4VP section 8.2), and only its SHA-256 is kept.
      let responseCode = '';
      if (record.signIn) {
        const outcome = this.signInOutcome(verified, presentations[0]);
        record.signIn.outcome = outcome;
        if (outcome.ok) {
          responseCode = this.deps.randomId(24);
          record.signIn.responseCodeHash = crypto.createHash('sha256')
            .update(responseCode, 'utf8').digest('base64url');
        } else if (verified.ok) {
          log.info(errorCodes.tag(outcome.errorCode) + 'oid4vp: a ' +
                   'presentation verified and signs nobody in: ' +
                   outcome.reason);
        }
      }
      vpTransactions.set(state, record);  // through the store, as above
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
          ? 'STS-PKI-0129' : 'STS-VC-0041');
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
  vpDcqlQuery: slot.forward('vpDcqlQuery'),
  // THE SIGN-IN'S HALF (2026-09-17, #38), for `vc_signin.ts` and its test:
  // the request a sign-in asks with, how a wallet is handed it, whom a
  // presentation signs in, and the transaction read and written back
  // through the one store.
  signInDcqlQuery: slot.forward('signInDcqlQuery'),
  vpRequestQuery: slot.forward('vpRequestQuery'),
  vpWalletFor: slot.forward('vpWalletFor'),
  signInOutcome: slot.forward('signInOutcome'),
  transactionFor: slot.forward('transactionFor'),
  saveTransaction: slot.forward('saveTransaction'),
  // For `logout/logout.ts`'s `wallet-signin` family.
  signInsAwaitingCollection: slot.forward('signInsAwaitingCollection'),
  withdrawSignIn: slot.forward('withdrawSignIn')
};
