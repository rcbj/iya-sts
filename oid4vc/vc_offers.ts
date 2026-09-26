'use strict';
//
// File: vc_offers.ts
//
// ---------------------------------------------------------------------------
// Credential Offer (OID4VCI section 4) — the issuer-initiated half of issuance.
//
// Appendix H.1 "Credential Offer - Same-Device": the End-User is browsing the
// issuer's site, follows a "request your digital diploma" link, and is taken to
// their Wallet with a Credential Offer in hand. That is what these three
// endpoints are:
//
//   GET /issuer                     the issuer's web page, with the link
//   GET /issuer/offer               builds an offer and redirects to the wallet,
//                                   by value (credential_offer) or by reference
//                                   (credential_offer_uri)
//   GET /oid4vci/credential-offer/:id  serves an offer fetched by reference
//
// The offer names this issuer, the credential configuration(s) on offer, and
// the grant. For H.1 that grant is authorization_code carrying an issuer_state,
// which the Wallet must hand back on the authorization request so the issuer
// can tie the two together.
//
// The Wallet a browser page can be sent to is a URL, not the
// openid-credential-offer:// scheme a native wallet would register —
// `oid4vci.walletUrl` (OID4VCI_WALLET_URL) says where it lives.
// ---------------------------------------------------------------------------
//
// This module owns the STATE the offer creates — the offers themselves, the
// issuer_states, the pre-authorized codes and the deferred transactions — and
// that ownership is the reason it is a module rather than part of vc_issuer.ts.
// The pre-authorized code grant is redeemed at the TOKEN ENDPOINT, which
// belongs to the authorization server, and issuer_state is read on the
// AUTHORIZATION request. So this state is shared between OID4VCI and OAuth2 by
// design, and putting it in either of them would make those two require each
// other.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `VcOffers` takes the helpers it uses, the settings, the mode, the
// signer, the error codes, the cluster claims, the validator, a loader for the
// authentication service (still required lazily, inside the offer page) and
// the five stores through its constructor, and registers the three pages from
// `registerRoutes(app)`. The stores stay module-scope `realms.map()`
// declarations. Loading the module registers nothing (#50, R1) — the module
// exports `registerRoutes(app)`, and `common/protocol_stack.ts` calls it at
// the point in the route order where requiring this module used to register
// the pages, which is IMMEDIATELY BEFORE `oauth2.ts`'s routes, because
// `oauth2.ts` is what first requires this file. Since #50's R2 that root also
// BUILDS the instance, and the module exports every old name as a FACADE
// forwarding to it, as ONE `export =` where `module.exports` was — this file
// breaks a require cycle (root `CLAUDE.md` rule 2: `oauth2.js` requires it for
// its stores), so what that caller sees and when must not change. That is why
// `deferredAccessTokens` is a stable forwarding object rather than a getter:
// `oauth2.ts` reads it at its own load. A process without the root builds a
// default at load.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import qrcode = require('qrcode');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and error_codes.js and nothing else here, so it cannot join a
// cycle and it registers no route, so its position is not a position at all.
import realms = require('../common/realms');
import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// THE MODE (2026-09-12), for two questions only — are the test controls open
// (an anonymous offer page), and may a response go to an address the request
// named (the `wallet` parameter). A LEAF requiring only `config`.
import mode = require('../common/mode');
// Constant-time comparison, for the Transaction Code. A leaf.
import stsCrypto = require('../common/crypto');
// The error codes (common/error_codes.js). A LEAF that requires nothing; a code
// is marked on the response object and never written into a response.
import errorCodes = require('../common/error_codes');
import vcConfigs = require('./vc_configs');
// THE CLUSTER CLAIM (2026-09-14, #46): the atomic "once" a pre-authorized
// code is spent through and a Transaction Code failure is counted with — see
// spendPreAuthorizedCode() and checkTxCode(). A LIBRARY that registers no
// route and requires persistence lazily, so it closes no cycle.
import clusterClaims = require('../cluster/cluster_claims');

// The input validator. A LEAF (rule 3): registers no route, closes no cycle.
import validation = require('../common/validation');

const { VCI_CONFIG_ID } = vcConfigs;

// The parts of a `realms.map()` store this module uses.
interface Store {
  get(key: string): any;
  set(key: string, value: any): unknown;
  has(key: string): boolean;
  delete(key: string): boolean;
  clear(): void;
  forEach(fn: (value: any, key: string) => void): void;
  size: number;
}

interface VcOffersDeps {
  log: typeof helpers.log;
  logArtifact: typeof helpers.logArtifact;
  baseUrlOf: typeof helpers.baseUrlOf;
  randomId: typeof helpers.randomId;
  xmlEscape: typeof helpers.xmlEscape;
  vciError: typeof helpers.vciError;
  userFor: typeof helpers.userFor;
  walletBaseUrl: typeof helpers.walletBaseUrl;
  config: { value(key: string): any };
  mode: typeof mode;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  clusterClaims: typeof clusterClaims;
  validation: typeof validation;
  // The authentication service, required when first needed — see the offer
  // page.
  loadAuthn(): any;
  credentialOffers: Store;
  issuerStates: Store;
  preAuthorizedCodes: Store;
  deferredTransactions: Store;
  deferredAccessTokenStore: Store;
}

// The credential formats this issuer actually offers, read off the table that
// defines them rather than written out again.
const VCI_FORMATS = Array.from(new Set(
  Object.keys(vcConfigs.VCI_CONFIGS).map(function (id) {
    return vcConfigs.VCI_CONFIGS[id].format;
  }).filter(Boolean)));
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// id -> { offer, issuerState, expires }
const credentialOffers = realms.map({ persist: 'vc_offers.credentialOffers',
                                      retain: 'age' });

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// issuer_state -> { configurationIds, expires }
const issuerStates = realms.map({ persist: 'vc_offers.issuerStates',
                                  retain: 'age' });

// Pre-authorized codes (OID4VCI Appendix H.2 / H.3): the End-User authorized
// the issuance out of band, so there is no authorization request at all — the
// code in the offer IS the authorization. `txCode` is the Transaction Code the
// issuer shows on its own screen and the End-User types into the wallet;
// `deferred` marks an issuance the credential endpoint will not complete
// immediately. PER TRUST REALM. `realms.map()` is a Map that holds a separate
// one for each realm and hands out the ambient realm's — so every reader below
// is unchanged and every one of them is now realm-correct. In the default
// realm, and in a service with no realms defined, there is exactly one
// partition and this behaves as the plain Map it replaced. See
// common/realms.js.
// code -> { configurationIds, txCode, user, deferred, expires }
const preAuthorizedCodes =
    realms.map({ persist: 'vc_offers.preAuthorizedCodes', retain: 'age' });

// Deferred issuance transactions (OID4VCI section 9): the credential endpoint
// answered 202 with one of these instead of a credential.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// transaction_id -> { claims, holderJwk, readyAt, expires }
const deferredTransactions =
    realms.map({ persist: 'vc_offers.deferredTransactions', retain: 'age' });

// Access tokens minted from a deferred offer: the credential endpoint answers
// 202 for these instead of issuing straight away.
//
// **PER TRUST REALM AND PERSISTED SINCE 2026-09-12, AND IT WAS NEITHER.** It
// was the one store in this file declared `new Set()` beside four that were
// `realms.map()` — so a deferred access token minted at
// `/realm/acme/oauth2/token` was honoured as deferred at the DEFAULT realm's
// credential endpoint too, and in a dispatched service a token minted on one
// worker was an ordinary token on every other one, which is the deferred flow
// silently not being deferred. `vc_offers.deferredTransactions`, the other half
// of the same flow, has been declared since the day minted state persisted.
//
// **THE KEY IS A DIGEST OF THE TOKEN AND NOT THE TOKEN.** An access token is a
// bearer credential, and a declared store is journalled, replicated to every
// process and written to `sts_minted` in product mode — sealed there, but a
// credential this service does not need to hold is better never held at all.
// Membership is the only question ever asked, and SHA-256 answers it.
//
// Kept a SET-SHAPED FACADE (`add`, `has`, `delete`, `size`, `clear`) because
// `oauth-oidc/oauth2.ts` adds and `vc_issuer.ts` asks and spends, and neither
// has any reason to learn that the store underneath changed.
const deferredAccessTokenStore =
    realms.map({ persist: 'vc_offers.deferredAccessTokens', retain: 'age' });

// `oid4vci.offerTtlS` since 2026-09-12. The constant is the default and keeps
// its name because `vc_issuer.ts` imports it; `offerTtlMs()` is the live value
// and what every reader here uses.
const OFFER_TTL_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// ONE WRONG TRANSACTION CODE, COUNTED ATOMICALLY ACROSS THE CLUSTER (#46).
//
// A counter is a number every node agrees on, and `cluster_claims.js` already
// is one — just not a number: each failure CLAIMS THE NEXT SLOT, `<code>#1`,
// `<code>#2`, … up to the limit, and the slot this failure won is its number.
// A slot is claimed by exactly one caller on any node, so two concurrent wrong
// codes take slots 1 and 2 rather than both writing "1", and N nodes share one
// budget of `limit` slots. When every slot is already taken the budget is
// gone, and the answer is `limit` — the caller spends the code.
//
// **A CLAIMS VARIANT RATHER THAN A COUNTER TABLE**, and the choice is the
// bound: `oid4vci.txCodeMaxAttempts` is at most 100 and five by default, so
// the worst probe is a few statements, on the wrong-code path only, and it
// costs no schema, no driver statement and no second memory fallback — on a
// store that cannot be shared the claims are this process's memory, which
// counts exactly as the record always did.
//
// **THE RECORD'S COUNT IS WHERE THE PROBE STARTS**, and that is safe in one
// direction only, which is the direction it is used: a node writes
// `txCodeFailures = n` after it has won slot n, and it reached slot n only
// having found every slot below it taken, so a replicated count never claims
// more slots were taken than were. A lost update makes the hint LOWER, which
// costs a probe and nothing else.
//
// The slots live as long as the code can still be redeemed, plus the skew.
// `{ failures }`, or `{ store: true }` when the store cannot be asked — the
// caller refuses the attempt rather than letting it go uncounted.
// ---------------------------------------------------------------------------
const CLAIM_SKEW_MS = 60 * 1000;

// The issuer's own web page — where H.1 starts.
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

class VcOffers {
  static readonly OFFER_TTL_MS = OFFER_TTL_MS;

  // Access tokens minted from a deferred offer, as the SET-SHAPED FACADE the
  // store comment above describes. Built once, here; `add` returns it.
  readonly deferredAccessTokens: {
    add(token: unknown): unknown;
    has(token: unknown): boolean;
    delete(token: unknown): boolean;
    clear(): void;
    readonly size: number;
  };

  constructor(private readonly deps: VcOffersDeps) {
    deps.log.debug("Entering VcOffers.constructor().");
    const self = this;
    const store = deps.deferredAccessTokenStore;
    const log = deps.log;
    const facade = {
      add: function (token) {
        log.debug("Entering add().");
        store.set(self.deferredTokenKey(token), { at: Date.now() });
        log.debug("Leaving add().");
        return facade;
      },
      has: function (token) {
        log.debug("Entering has().");
        log.debug("Leaving has().");
        return store.has(self.deferredTokenKey(token));
      },
      delete: function (token) {
        log.debug("Entering delete().");
        log.debug("Leaving delete().");
        return store.delete(self.deferredTokenKey(token));
      },
      clear: function () {
        log.debug("Entering clear().");
        log.debug("Leaving clear().");
        return store.clear();
      },
      get size() {
        log.debug("Entering size().");
        log.debug("Leaving size().");
        return store.size;
      }
    };
    this.deferredAccessTokens = facade;
    deps.log.debug("Leaving VcOffers.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): VcOffersDeps {
    helpers.log.debug("Entering VcOffers.defaultDeps().");
    helpers.log.debug("Leaving VcOffers.defaultDeps().");
    return {
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      baseUrlOf: helpers.baseUrlOf,
      randomId: helpers.randomId,
      xmlEscape: helpers.xmlEscape,
      vciError: helpers.vciError,
      userFor: helpers.userFor,
      walletBaseUrl: helpers.walletBaseUrl,
      config: config,
      mode: mode,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      clusterClaims: clusterClaims,
      validation: validation,
      loadAuthn: function () {
        return require('../authn/authn');
      },
      credentialOffers: credentialOffers,
      issuerStates: issuerStates,
      preAuthorizedCodes: preAuthorizedCodes,
      deferredTransactions: deferredTransactions,
      deferredAccessTokenStore: deferredAccessTokenStore
    };
  }

  private deferredTokenKey(token: unknown) {
    const { log } = this.deps;
    log.debug("Entering VcOffers.deferredTokenKey().");
    log.debug("Leaving VcOffers.deferredTokenKey().");
    return crypto.createHash('sha256').update(String(token || ''), 'utf8')
      .digest('base64url');
  }

  // How long a deferred issuance "takes". Short enough for a test to wait for
  // it, long enough that the first poll genuinely comes back still-pending.
  deferredReadyMs() {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.deferredReadyMs().");
    log.debug("Leaving VcOffers.deferredReadyMs().");
    return config.value('oid4vci.deferredReadyMs');
  }

  deferredIntervalS() {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.deferredIntervalS().");
    log.debug("Leaving VcOffers.deferredIntervalS().");
    return config.value('oid4vci.deferredIntervalS');
  }

  offerTtlMs() {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.offerTtlMs().");
    const seconds = Number(config.value('oid4vci.offerTtlS'));
    log.debug("Leaving VcOffers.offerTtlMs().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) * 1000 :
           OFFER_TTL_MS;
  }

  // ---------------------------------------------------------------------------
  // THE TRANSACTION CODE (2026-09-12), and three things about it that were
  // wrong in every mode or missing in product.
  //
  // **IT IS DRAWN FROM A CSPRNG.** It was `Math.random()`, whose V8
  // implementation (xorshift128+) is recoverable from a handful of its outputs
  // — and this service hands its outputs to anybody who loads an offer page.
  // The Transaction Code is the only thing binding a pre-authorized code to the
  // person standing at the issuer's screen, so a predictable one is no binding.
  // `crypto.randomInt()` is uniform over the range, which a modulo of random
  // bytes is not. BOTH MODES: a guessable code is a defect a mock should not
  // teach anybody to expect.
  //
  // **ITS LENGTH IS `oid4vci.txCodeLength`** — five digits by default, the
  // value the page has always shown — and the leading digit is never zero,
  // which is what `Math.floor(Math.random() * 90000) + 10000` produced and what
  // a wallet that renders the input as a number relies on.
  //
  // **COMPARISON AND ATTEMPTS ARE THE TOKEN ENDPOINT'S** — `checkTxCode()`
  // below, which `oauth2.js` calls — because that is where the code is
  // presented.
  // ---------------------------------------------------------------------------
  private txCodeLength() {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.txCodeLength().");
    const digits = Number(config.value('oid4vci.txCodeLength'));
    log.debug("Leaving VcOffers.txCodeLength().");
    return isFinite(digits) && digits >= 4 ? Math.floor(digits) : 5;
  }

  private newTxCode() {
    const { log } = this.deps;
    log.debug("Entering VcOffers.newTxCode().");
    const length = this.txCodeLength();
    const low = Math.pow(10, length - 1);
    log.debug("Leaving VcOffers.newTxCode().");
    return String(crypto.randomInt(low, low * 10));
  }

  // ---------------------------------------------------------------------------
  // CHECK A PRESENTED TRANSACTION CODE AGAINST A PRE-AUTHORIZED CODE'S RECORD.
  //
  // CONSTANT-TIME IN BOTH MODES — a `!==` on a short numeric string leaks how
  // many leading digits a guess got right, which turns a hundred thousand
  // guesses into fifty.
  //
  // **THE ATTEMPT LIMIT IS PRODUCT MODE'S**, asked through
  // `mode.verifiesCredentials()`: a Transaction Code is a credential this
  // service verifies, and five digits inside a ten-minute offer are guessable
  // at the token endpoint by anybody holding the offer. So in product each
  // wrong code is counted — on the record through the store until 2026-09-14,
  // in claims since (below; a request worker that counted in its own memory
  // would give every worker its own five, and a node every node its own), and
  // the one that reaches `oid4vci.txCodeMaxAttempts` SPENDS the pre-authorized
  // code. The End-User asks for a new offer. Development counts nothing, so a
  // wallet's wrong-code path can be driven as often as a test likes — which is
  // what that mode is for.
  //
  // **COUNTED ACROSS THE CLUSTER SINCE 2026-09-14 (#46), AND SO ASYNCHRONOUS.**
  // The count lived on the record alone, and a record is replicated rather than
  // shared: every node read its own copy, so N nodes gave a guesser N times
  // `oid4vci.txCodeMaxAttempts`, and two wrong codes at once on two nodes wrote
  // `failures = 1` twice, so concurrent guesses were not counted at all. The
  // count is now COUNTED IN CLAIMS — see countTxCodeFailure() — and the
  // record's `txCodeFailures` is kept only as the hint that saves the next
  // count its probes and as what the console shows.
  //
  // Returns `{ ok }`, or `{ ok: false, missing | spent | store, attemptsLeft
  // }`, and writes to `preAuthorizedCodes` itself so the caller cannot forget
  // either the count or the spending.
  // ---------------------------------------------------------------------------
  async checkTxCode(code: string, record: any, presented: unknown) {
    const { log, config, mode, stsCrypto, errorCodes,
            preAuthorizedCodes } = this.deps;
    log.debug("Entering VcOffers.checkTxCode().");
    if (!record.txCode) {
      log.debug("Leaving VcOffers.checkTxCode(). This offer carries no " +
                "Transaction Code.");
      return { ok: true };
    }
    const given = String(presented || '');
    if (!given) {
      log.debug("Leaving VcOffers.checkTxCode(). None was presented.");
      return { ok: false, missing: true };
    }
    if (stsCrypto.constantTimeEquals(given, record.txCode)) {
      log.debug("Leaving VcOffers.checkTxCode(). It matches.");
      return { ok: true };
    }
    if (!mode.verifiesCredentials()) {
      log.debug("Leaving VcOffers.checkTxCode(). Wrong, and development " +
                "counts nothing.");
      return { ok: false };
    }
    const limit = Math.max(1,
                           Number(config.value('oid4vci.txCodeMaxAttempts')) ||
                           5);
    const counted = await this.countTxCodeFailure(code, record, limit);
    if (counted.store) {
      log.debug("Leaving VcOffers.checkTxCode(). The failure could not be " +
                "counted.");
      return { ok: false, store: true };
    }
    const failures = counted.failures;
    if (failures >= limit) {
      preAuthorizedCodes.delete(code);
      // SPENT ON EVERY NODE, not only in this process's map: a node whose copy
      // of the record has not caught up would otherwise still redeem the code
      // with the right Transaction Code after the budget was exhausted here. A
      // store failure here changes nothing the caller can do — the code is
      // refused either way — so its answer is logged by the spend and ignored.
      await this.spendPreAuthorizedCode(code, record);
      log.warn(errorCodes.tag('STS-VC-0030') +
               'vc_offers: a pre-authorized code was SPENT after ' + failures +
               ' wrong Transaction Code(s) (oid4vci.txCodeMaxAttempts = ' +
               limit + ').');
      log.debug("Leaving VcOffers.checkTxCode(). Spent.");
      return { ok: false, spent: true, attemptsLeft: 0 };
    }
    const current = preAuthorizedCodes.get(code) || record;
    preAuthorizedCodes.set(code,
                           Object.assign({}, current,
                                         { txCodeFailures: Math.max(failures,
                                           Number(current.txCodeFailures) ||
                                           0) }));
    log.debug("Leaving VcOffers.checkTxCode(). Wrong; " + (limit - failures) +
              " attempt(s) left.");
    return { ok: false, attemptsLeft: limit - failures };
  }

  private remainingLifetimeMs(record: any) {
    const { log } = this.deps;
    log.debug("Entering VcOffers.remainingLifetimeMs().");
    const expires = Number(record && record.expires);
    log.debug("Leaving VcOffers.remainingLifetimeMs().");
    return isFinite(expires) && expires > 0 ? Math.max(0, expires - Date.now())
      : this.offerTtlMs();
  }

  private async countTxCodeFailure(code: string, record: any, limit: number) {
    const { log, errorCodes, clusterClaims } = this.deps;
    log.debug("Entering VcOffers.countTxCodeFailure().");
    const known = Math.floor(Number(record && record.txCodeFailures) || 0);
    const first = Math.max(1, Math.min(limit, known + 1));
    const ttlMs = this.remainingLifetimeMs(record) + CLAIM_SKEW_MS;
    for (let slot = first; slot <= limit; slot++) {
      const claimed = await clusterClaims.claim({
        scope: 'oid4vci.tx-code-failure', value: code + '#' + slot,
        ttlMs: ttlMs });
      if (claimed.ok) {
        log.debug("Leaving VcOffers.countTxCodeFailure(). Failure " + slot +
                  ".");
        return { failures: slot };
      }
      if (claimed.reason !== 'used') {
        log.error(errorCodes.tag('STS-VC-0051') + 'vc_offers: a wrong ' +
                  'Transaction Code could not be counted, because the claim ' +
                  'store could not be asked (' + (claimed.why ||
                  'no reason given') + '). The attempt is refused uncounted.');
        log.debug("Leaving VcOffers.countTxCodeFailure(). Store unavailable.");
        return { store: true };
      }
    }
    log.debug("Leaving VcOffers.countTxCodeFailure(). Every slot was " +
              "already taken.");
    return { failures: limit };
  }

  // ---------------------------------------------------------------------------
  // SPENDING A PRE-AUTHORIZED CODE ACROSS THE CLUSTER (2026-09-14, #46).
  //
  // The token endpoint deletes the code from `preAuthorizedCodes`, which is
  // "once" in one process and a replicated write in several: two token requests
  // carrying one code, on two nodes inside the replication window, both found
  // it and both were issued an access token for a credential somebody else was
  // offered. The delete stays where it is and first; this is then the atomic
  // half, called by oauth2.js right after it. Exactly one caller on any node
  // gets `{ ok: true }`.
  //
  // Nothing releases it: the code is gone from this process's map whatever the
  // token response turns out to be, which is how a refused request spent it
  // before this, and a claim given back without the map restored would only let
  // another node redeem it. A store that cannot be asked refuses (fail closed).
  //
  // `{ ok: true }` or `{ ok: false, errorCode, description }`.
  // ---------------------------------------------------------------------------
  async spendPreAuthorizedCode(code: string, record: any) {
    const { log, errorCodes, clusterClaims } = this.deps;
    log.debug("Entering VcOffers.spendPreAuthorizedCode().");
    const claimed = await clusterClaims.claim({
      scope: 'oid4vci.pre-authorized-code', value: code,
      ttlMs: this.remainingLifetimeMs(record) + CLAIM_SKEW_MS });
    if (claimed.ok) {
      log.debug("Leaving VcOffers.spendPreAuthorizedCode(). Spent here.");
      return { ok: true };
    }
    if (claimed.reason === 'used') {
      log.warn(errorCodes.tag('STS-VC-0049') + 'vc_offers: a pre-authorized ' +
               'code this process still held was ALREADY REDEEMED (or spent ' +
               'by wrong Transaction Codes) on another node against the same ' +
               'store. Refused.');
      log.debug("Leaving VcOffers.spendPreAuthorizedCode(). Used elsewhere.");
      return { ok: false, errorCode: 'STS-VC-0049',
               description: 'Unknown or already-used pre-authorized code.' };
    }
    log.error(errorCodes.tag('STS-VC-0051') + 'vc_offers: whether a ' +
              'pre-authorized code was already redeemed could not be asked ' +
              'of ' +
              'the claim store (' + (claimed.why || 'no reason given') + '). ' +
              'It is refused.');
    log.debug("Leaving VcOffers.spendPreAuthorizedCode(). Store unavailable.");
    return { ok: false, errorCode: 'STS-VC-0051',
             description: 'The issuer could not confirm this pre-authorized ' +
                          'code is unused; ask the issuer for a new ' +
                          'Credential ' +
                          'Offer.' };
  }

  // ---------------------------------------------------------------------------
  // WHERE THE END-USER IS SENT: the wallet URL and the page under it.
  //
  // The page is `oid4vci.walletIssuancePath` (2026-09-12). The `wallet` query
  // parameter overrides the configured URL — which is how a wallet on a laptop
  // is pointed at this service without reconfiguring it, and in DEVELOPMENT
  // that stays true for any absolute URL. In a realm that accepts only
  // registered addresses (`mode.acceptsUnregisteredAddresses()` false) it is AN
  // OPEN REDIRECT carrying a pre-authorized code or an issuer_state, so it must
  // name the configured wallet or one listed in `oid4vci.allowedWalletUrls`,
  // and anything else is refused by name rather than silently replaced.
  //
  // Compared with trailing slashes removed, which is the only normalisation the
  // URL gets before it is used, so what is compared is what is dialled.
  // ---------------------------------------------------------------------------
  walletFor(req: any) {
    const { log, walletBaseUrl, config, mode } = this.deps;
    log.debug("Entering VcOffers.walletFor().");
    const configured = String(walletBaseUrl() || '').replace(/\/+$/, '');
    const asked = req.query.wallet ?
                  String(req.query.wallet).replace(/\/+$/, '') : '';
    if (asked && asked !== configured && !mode.acceptsUnregisteredAddresses()) {
      const allowed = (config.value('oid4vci.allowedWalletUrls') || []).map(
          (one) => {
        return String(one).replace(/\/+$/, '');
      });
      if (allowed.indexOf(asked) < 0) {
        log.debug("Leaving VcOffers.walletFor(). An unregistered wallet URL " +
                  "was refused.");
        return { error: 'The wallet URL "' + asked + '" is neither ' +
                        'oid4vci.walletUrl nor one listed in ' +
                        'oid4vci.allowedWalletUrls, and this realm does not ' +
                        'send an offer to an address the request named. Add ' +
                        'it ' +
                        'to that setting, or leave the wallet parameter off.' };
      }
    }
    const path = String(config.value('oid4vci.walletIssuancePath') || '');
    log.debug("Leaving VcOffers.walletFor().");
    return { url: (asked || configured) + path };
  }

  // A pre-authorized offer is made to an End-User the issuer has ALREADY
  // identified (H.2: they uploaded documents to an employee portal days
  // before), so the issuer knows the subject without anyone signing in.
  vciOfferUsername() {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.vciOfferUsername().");
    log.debug("Leaving VcOffers.vciOfferUsername().");
    return config.value('oid4vci.offerUsername');
  }

  // Build a Credential Offer for one of the Appendix H use cases.
  //
  //   same-device (H.1) authorization_code + issuer_state: the wallet still has
  //                      to take the End-User through the authorization server.
  //   cross-device (H.2) pre-authorized_code + tx_code: the End-User already
  //                      identified themselves to the issuer by some other
  //                      route, so the code IS the authorization and the
  //                      Transaction Code shown on the issuer's screen is what
  //                      ties the wallet on the other device to this End-User.
  //   deferred     (H.3) the same pre-authorized offer, but flagged so the
  //                      credential endpoint answers 202 with a transaction_id
  //                      instead of a credential.
  //
  // `options.user` (2026-09-12) is WHO a pre-authorized offer is for. Absent,
  // it is `oid4vci.offerUsername` — the H.2 story, where the issuer identified
  // the End-User out of band — which is what this function always did and what
  // development still does. The offer page passes the signed-in person in a
  // realm whose test controls are closed; see that route.
  buildCredentialOffer(req: any, configurationIds: string[],
                         mode: string, options?: { user?: any }) {
    const { log, logArtifact, baseUrlOf, randomId, userFor, config,
            issuerStates, preAuthorizedCodes } = this.deps;
    log.debug("Entering VcOffers.buildCredentialOffer(). mode=" + mode);
    const base = baseUrlOf(req);
    const expires = Date.now() + this.offerTtlMs();
    const opts = options || {};
    const offer: Record<string, any> = {
      credential_issuer: base,
      credential_configuration_ids: configurationIds
    };
    let issuerState = "";
    let preAuthorizedCode = "";
    let txCodeValue = "";

    if (mode === 'cross-device' || mode === 'deferred') {
      preAuthorizedCode = randomId(24);
      // Numeric digits, which is what the issuer's page displays — see
      // newTxCode() for the length and the generator. The value never travels
      // in the offer — only its shape does — because the whole point is that it
      // reaches the End-User by a different channel.
      txCodeValue = this.newTxCode();
      preAuthorizedCodes.set(preAuthorizedCode, {
        configurationIds: configurationIds,
        txCode: txCodeValue,
        txCodeFailures: 0,
        user: opts.user || userFor(this.vciOfferUsername()),
        deferred: mode === 'deferred',
        expires: expires
      });
      offer.grants = {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          tx_code: {
            input_mode: 'numeric',
            length: txCodeValue.length,
            // No apostrophe: this string is URL-encoded into the offer, and an
            // apostrophe survives encodeURIComponent only to be XML-escaped
            // into "&apos;" when the offer URI is displayed — which turns one
            // query parameter into two for anything reading it off the page.
            description: 'Type the ' + txCodeValue.length + '-digit code ' +
                'shown by the issuer.'
          },
          // No `interval` (#187): the drafts put a polling interval in the
          // grant; OpenID4VCI 1.0 section 4.1.1 defines pre-authorized_code,
          // tx_code and authorization_server only, and the OpenID
          // conformance suite's offer schema flagged it. A wallet waiting on
          // a deferred credential is told its interval by the Deferred
          // Credential endpoint.
        }
      };
    } else {
      issuerState = randomId(18);
      issuerStates.set(issuerState,
                       { configurationIds: configurationIds,
                        expires: expires });
      offer.grants = { authorization_code: { issuer_state: issuerState } };
    }

    logArtifact('OID4VCI Credential Offer', 'as built', offer);
    log.debug("Leaving VcOffers.buildCredentialOffer(). mode=" + mode + ", " +
              "issuer_state=" +
              issuerState +
              ", pre-authorized=" + (preAuthorizedCode ? "yes" : "no"));
    return { offer: offer, issuerState: issuerState,
             preAuthorizedCode: preAuthorizedCode, txCode: txCodeValue,
             mode: mode || 'same-device' };
  }

  // The issuer's screen in a cross-device flow: a QR code carrying the
  // Credential Offer, and — separately, which is the whole point — the
  // Transaction Code.
  renderOfferQrPage(res: any, opts: any) {
    const { log, xmlEscape, errorCodes } = this.deps;
    log.debug("Entering VcOffers.renderOfferQrPage(). mode=" + opts.mode);
    qrcode.toDataURL(opts.offerUri,
                     { errorCorrectionLevel: 'M', margin: 2, width: 320 })
      .then((dataUrl) => {
        const deferred = opts.mode === 'deferred';
        const page = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
          'charset="utf-8"><title>Mock University — scan to receive your ' +
          'credential</title><style>body{font-family:system-ui,-apple-system,' +
          '"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
          'display:flex;align-items:center;justify-content:center;' +
          'min-height:100vh;color:#222}.card{background:#fff;border:1px ' +
          'solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
          'box-shadow:0 6px 24px rgba(0,0,0,.08);text-align:center}' +
          'h1{font-size:1.25em;margin:0 0 6px}p{line-height:1.5;color:#333}' +
          'img.qr{margin:14px auto;display:block;border:1px solid #eee;' +
          'border-radius:8px}.txcode{font-family:ui-monospace,SFMono-Regular,' +
          'Menlo,monospace;font-size:2.1em;letter-spacing:.28em;' +
          'font-weight:700;color:#12107c;background:#f0f0fa;' +
          'border-radius:8px;padding:12px 6px;margin:6px 0 2px}' +
          '.uri{word-break:break-all;font-family:ui-monospace,SFMono-Regular,' +
          'Menlo,monospace;font-size:.72em;color:#555;background:#fafafa;' +
          'border:1px solid #eee;border-radius:6px;padding:8px;' +
          'text-align:left}.meta{margin-top:20px;padding-top:14px;' +
          'border-top:1px solid #eee;font-size:.78em;color:#777;' +
          'text-align:left}code{font-family:ui-monospace,SFMono-Regular,' +
          'Menlo,monospace}</style></head><body><div class="card"><h1>Scan ' +
          'this with your wallet</h1><p>Your digital diploma is ready to be ' +
          'claimed' +
          (deferred ? ', though issuing it will take us a little time once ' +
           'you ' +
                      'ask.' : '.') + '</p><img ' +
          'class="qr" id="offer_qr" alt="Credential Offer QR code" ' +
          'src="' + dataUrl + '"><p>Then ' +
          'type this Transaction Code into your wallet:</p><div ' +
          'class="txcode" ' +
          'id="tx_code">' + xmlEscape(opts.txCode) + '</div><p ' +
          'style="font-size:.8em;color:#777">It is shown here, and only here ' +
          '— it does not travel in the QR code.</p><div class="uri" ' +
          'id="offer_uri">' + xmlEscape(opts.offerUri) + '</div><div ' +
          'class="meta">OID4VCI ' +
          'Appendix ' + (deferred ? 'H.3' : 'H.2') + '. ' +
          'The offer uses the <code>pre-authorized_code</code> grant: you ' +
          'already identified yourself to this issuer, so your wallet goes ' +
          'straight to the token endpoint — there is no authorization ' +
          'request. ' +
          (deferred ? 'The credential endpoint will answer with a ' +
                      '<code>transaction_id</code> and your wallet will have ' +
                      'to come back for the credential. ' : '') +
          'If your wallet is on this device, <a id="open_in_wallet" href="' +
          xmlEscape(opts.walletUrl) + '">open ' +
          'it here</a>.</div></div></body></html>\n';
        res.status(200).type('text/html').send(page);
        log.debug("Leaving VcOffers.renderOfferQrPage(). Rendered a QR code.");
      })
      .catch((e) => {
        log.debug("Caught in VcOffers.renderOfferQrPage(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0028') +
                  "could not render the offer QR code: " + e.message);
        errorCodes.mark(res, 'STS-VC-0028');
        res.status(500).type('text/plain').send('Could not render the ' +
                                                'Credential Offer QR ' +
                                                'code: ' + e.message);
      });
    log.debug("Leaving VcOffers.renderOfferQrPage().");
  }

  // The three pages, in the order they were registered at load before
  // #50's R1. Called by `common/protocol_stack.ts`.
  registerRoutes(app: any) {
    const { log, baseUrlOf, randomId, xmlEscape, vciError, userFor,
            walletBaseUrl, mode, errorCodes, validation, loadAuthn,
            credentialOffers, issuerStates, preAuthorizedCodes,
            deferredTransactions } = this.deps;
    log.debug("Entering VcOffers.registerRoutes().");
    app.get('/issuer', (req, res) => {
      log.debug("Entering the issuer web page.");
      const base = baseUrlOf(req);
      const configId = VCI_CONFIG_ID;
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
        'charset="utf-8"><title>Mock University — digital ' +
        'diploma</title><style>body{font-family:system-ui,-apple-system,' +
        '"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
        'display:flex;align-items:center;justify-content:center;' +
        'min-height:100vh;color:#222}.card{background:#fff;border:1px solid ' +
        '#d5d5dd;border-radius:10px;padding:30px 34px;width:520px;' +
        'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 ' +
        '6px}p{line-height:1.5;color:#333}a.cta{display:inline-block;' +
        'margin-top:14px;margin-right:10px;padding:10px 16px;' +
        'border-radius:6px;background:#12107c;color:#fff;' +
        'text-decoration:none;font-weight:600}' +
        'a.cta.secondary{background:#fff;color:#12107c;border:1px solid ' +
        '#12107c}p.alt{margin-top:20px;font-size:.92em;color:#555}' +
        '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;' +
        'font-size:.78em;color:#777}code{font-family:ui-monospace,' +
        'SFMono-Regular,Menlo,monospace}</style></head><body><div ' +
        'class="card"><h1>Mock University</h1><p>Congratulations on your ' +
        'graduation. Your diploma is available as a digital credential ' +
        '(<code>' + xmlEscape(configId) + '</code>) that you can keep in ' +
        'your wallet.</p><p><a class="cta" href="/issuer/offer">Request your ' +
        'digital diploma</a><a class="cta secondary" ' +
        'href="/issuer/offer?by=reference">Request it (offer by ' +
        'reference)</a></p><p class="alt">On a different device? These show ' +
        'a QR code to scan with your wallet instead:<br><a class="cta ' +
        'secondary" href="/issuer/offer?mode=cross-device">Show a QR code ' +
        '(cross-device)</a><a class="cta secondary" ' +
        'href="/issuer/offer?mode=deferred">Show a QR code (issuance takes a ' +
        'while)</a></p><div class="meta">This is the Credential Issuer\'s ' +
        'web page in OID4VCI Appendix H. The first two links build a ' +
        'Credential Offer and send you to your wallet at ' +
        '<code>' + xmlEscape(walletBaseUrl()) + '</code> ' +
        '(H.1, same device). The other two hand the offer over by QR code ' +
        'and a Transaction Code instead — H.2, and H.3 where the issuer ' +
        'needs time to produce the credential. The issuer is ' +
        '<code>' + xmlEscape(base) + '</code>.</div></div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving the issuer web page.");
    });

    // The link on that page: build the offer and send the End-User to their
    // wallet.
    app.get('/issuer/offer', (req, res) => {
      log.debug("Entering the credential offer endpoint.");
      const base = baseUrlOf(req);
      const configurationIds = req.query.credential_configuration_ids
        ? String(req.query.credential_configuration_ids).split(',')
            .filter(Boolean)
        : [VCI_CONFIG_ID];
      const askedOffer = validation.check(req, 'query', OID4VC_QUERY);
      if (!askedOffer.ok) {
        log.debug('Leaving the offer page. ' + askedOffer.detail);
        errorCodes.mark(res, 'STS-VC-0025');
        return res.status(400).type('text/plain').send(askedOffer.detail +
                                                       '\n');
      }
      const offerMode = String(req.query.mode || 'same-device');
      const walletChoice = this.walletFor(req);
      if (walletChoice.error) {
        log.debug("Leaving the credential offer endpoint. " +
                  walletChoice.error);
        errorCodes.mark(res, 'STS-VC-0026');
        return res.status(400).type('text/plain').send(walletChoice.error +
                                                       '\n');
      }
      // -----------------------------------------------------------------------
      // WHO A PRE-AUTHORIZED OFFER IS FOR (2026-09-12).
      //
      // A cross-device or deferred offer carries a pre-authorized code, and
      // that code IS the authorization: whoever redeems it is issued a
      // credential about the person it names. This page minted one for
      // `oid4vci.offerUsername` for anybody who loaded it and printed the
      // Transaction Code beside it — a credential about a fixed person, for the
      // asking. That is H.2's DEMO ("they uploaded documents to an employee
      // portal days before") and it is a test control.
      //
      // So where the test controls are closed the page requires a SIGN-ON
      // SESSION and mints the offer for the person signed in: the issuer's
      // screen is then what H.2 says it is, a page the End-User reached after
      // identifying themselves to the issuer. With no session the browser is
      // sent through the sign-in screen and comes back here. An unauthenticated
      // ("continue without signing in") session is not an identification and is
      // refused by name.
      //
      // A SAME-DEVICE offer is not gated. It carries an issuer_state and no
      // authorization at all — the wallet still takes the End-User through
      // /oauth2/authorize, which authenticates them there — so there is nothing
      // to mint for anybody.
      //
      // `authn.js` is required HERE rather than at the top of this file: this
      // module is required by `oauth2.js` for its stores, and a top-level
      // require of the authentication service from a store module is a cycle
      // waiting for the load order to change. Inside the handler it is always a
      // cache hit.
      // -----------------------------------------------------------------------
      let offerUser = null;
      const preAuthorized = offerMode === 'cross-device' ||
                            offerMode === 'deferred';
      if (preAuthorized && !mode.opensTestControls()) {
        const authn = loadAuthn();
        const session = authn.sessionOf(req);
        if (!session || !session.user || !session.user.username) {
          log.debug("Leaving the credential offer endpoint. A sign-in is " +
                    "needed first.");
          return res.redirect(302, authn.beginAuthentication({
            returnTo: req.originalUrl && req.originalUrl.charAt(0) === '/' &&
                      req.originalUrl.charAt(1) !== '/' ? req.originalUrl :
                      '/issuer/offer',
            protocol: 'OpenID4VCI'
          }));
        }
        if (session.authenticated === false) {
          log.debug("Leaving the credential offer endpoint. The session is " +
                    "not authenticated.");
          errorCodes.mark(res, 'STS-VC-0027');
          return res.status(403).type('text/plain').send(
            'A pre-authorized Credential Offer is a credential about the ' +
            'person it is made for, and this browser has not signed in — it ' +
            'chose to continue without doing so. Sign in as the person the ' +
            'credential should describe and load this page again.\n');
        }
        offerUser = Object.assign({}, userFor(session.user.username),
                                  session.user.sub ? { sub: session.user.sub } :
                                  {});
        // THE OFFER IS MADE ON THE SESSION'S AUTHORITY, AND CAEP's
        // `session-presented` SAYS SO (#240). The pre-authorized code minted
        // below IS the authorization for a credential about this person, and
        // nobody authenticated for it: the sign-on session this browser
        // already held was presented and honoured. A same-device offer, and
        // any offer where the test controls are open, is not made on a
        // session at all and reports nothing.
        authn.notePresented(session, 'OpenID4VCI', req);
      }
      const built = this.buildCredentialOffer(req, configurationIds, offerMode,
                                         { user: offerUser });
      const wallet = walletChoice.url;

      // Sweep expired offers/states/codes while we are here.
      const now = Date.now();
      credentialOffers.forEach((v, k) => {
        if (v.expires < now) credentialOffers.delete(k);
      });
      issuerStates.forEach((v, k) => {
        if (v.expires < now) issuerStates.delete(k);
      });
      preAuthorizedCodes.forEach((v, k) => {
        if (v.expires < now) preAuthorizedCodes.delete(k);
      });
      deferredTransactions.forEach((v, k) => {
        if (v.expires < now) deferredTransactions.delete(k);
      });

      // How the offer reaches the wallet: in the URL, or behind a URI it
      // fetches.
      let offerQuery;
      if (String(req.query.by || '') === 'reference') {
        // 128 bits (#65): fetching this URI hands over the offer and its
        // pre-authorized code, so it is a bearer value like the code.
        const id = randomId(16);
        credentialOffers.set(id,
                             { offer: built.offer, expires: now +
                              this.offerTtlMs() });
        const offerUri = base + '/oid4vci/credential-offer/' + id;
        offerQuery = 'credential_offer_uri=' + encodeURIComponent(offerUri);
        log.debug("The offer is passed by reference: " + offerUri);
      } else {
        offerQuery = 'credential_offer=' +
                     encodeURIComponent(JSON.stringify(built.offer));
        log.debug("The offer is passed by value.");
      }

      // Same device (H.1): the wallet is right here, so send the browser to it.
      if (built.mode !== 'cross-device' && built.mode !== 'deferred') {
        res.redirect(302, wallet + '?' + offerQuery);
        log.debug("Leaving the credential offer endpoint. Sent the End-User " +
                  "to " +
                  wallet + ".");
        return;
      }

      // Cross device (H.2 / H.3): the wallet is on the End-User's OTHER device,
      // so the offer is displayed for it to scan — as the
      // openid-credential-offer URI a wallet registers for — and the
      // Transaction Code is shown here, on the issuer's screen, never in the
      // offer.
      const offerUri = 'openid-credential-offer://?' + offerQuery;
      this.renderOfferQrPage(res, {
        base: base,
        mode: built.mode,
        offerUri: offerUri,
        walletUrl: wallet + '?' + offerQuery,
        txCode: built.txCode,
        offer: built.offer
      });
      log.debug("Leaving the credential offer endpoint. Displayed a QR code " +
                "for the wallet to scan.");
    });

    app.get('/oid4vci/credential-offer/:id', (req, res) => {
      log.debug("Entering the credential offer retrieval endpoint. id=" +
                req.params.id);
      const record = credentialOffers.get(req.params.id);
      if (!record || record.expires < Date.now()) {
        credentialOffers.delete(req.params.id);
        log.debug("Leaving the credential offer retrieval endpoint. No such " +
                  "offer.");
        errorCodes.mark(res, 'STS-VC-0029');
        return vciError(res, 404, 'invalid_request', 'No such Credential ' +
                        'Offer, or it has expired.');
      }
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(record.offer, null, 2));
      log.debug("Leaving the credential offer retrieval endpoint.");
    });

    log.debug("Leaving VcOffers.registerRoutes().");
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
const slot = new InstanceSlot<VcOffers>(
  'oid4vc/vc_offers',
  () => new VcOffers(VcOffers.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// THE SET-SHAPED FACADE, EXPORTED AS A STABLE OBJECT (#50, R2). Each member
// forwards to the instance's own `deferredAccessTokens`, so a module that
// reads this export at ITS load — `oauth-oidc/oauth2.ts` does — holds the same
// shape it always did and builds nothing before the root installs the
// instance. A getter answering `slot.get().deferredAccessTokens` would have
// built the default at that read, and the root's install would then refuse.
const deferredAccessTokens = {
  add: function (token: unknown): unknown {
    helpers.log.debug("Entering deferredAccessTokens.add().");
    slot.get().deferredAccessTokens.add(token);
    helpers.log.debug("Leaving deferredAccessTokens.add().");
    return deferredAccessTokens;
  },
  has: function (token: unknown): boolean {
    helpers.log.debug("Entering deferredAccessTokens.has().");
    helpers.log.debug("Leaving deferredAccessTokens.has().");
    return slot.get().deferredAccessTokens.has(token);
  },
  delete: function (token: unknown): boolean {
    helpers.log.debug("Entering deferredAccessTokens.delete().");
    helpers.log.debug("Leaving deferredAccessTokens.delete().");
    return slot.get().deferredAccessTokens.delete(token);
  },
  clear: function (): void {
    helpers.log.debug("Entering deferredAccessTokens.clear().");
    slot.get().deferredAccessTokens.clear();
    helpers.log.debug("Leaving deferredAccessTokens.clear().");
  },
  get size(): number {
    helpers.log.debug("Entering deferredAccessTokens.size().");
    helpers.log.debug("Leaving deferredAccessTokens.size().");
    return slot.get().deferredAccessTokens.size;
  }
};

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcOffers: VcOffers,
  installInstance: (instance: VcOffers): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  credentialOffers: credentialOffers,
  issuerStates: issuerStates,
  preAuthorizedCodes: preAuthorizedCodes,
  deferredTransactions: deferredTransactions,
  deferredAccessTokens: deferredAccessTokens,
  deferredReadyMs: slot.forward('deferredReadyMs'),
  deferredIntervalS: slot.forward('deferredIntervalS'),
  OFFER_TTL_MS: VcOffers.OFFER_TTL_MS,
  offerTtlMs: slot.forward('offerTtlMs'),
  checkTxCode: slot.forward('checkTxCode'),
  spendPreAuthorizedCode: slot.forward('spendPreAuthorizedCode'),
  walletFor: slot.forward('walletFor'),
  vciOfferUsername: slot.forward('vciOfferUsername'),
  buildCredentialOffer: slot.forward('buildCredentialOffer'),
  renderOfferQrPage: slot.forward('renderOfferQrPage')
};
