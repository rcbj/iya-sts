// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   GET /issuer/offer               builds an offer and sends the browser to
//                                   the wallet, by value (credential_offer) or
//                                   by reference (credential_offer_uri)
//
// (both a demonstration's pages, development only (#585), and a static
// surface since #582: the shell, drawn from `/vc-demo-api` in the browser,
// which makes the offer through `offerAct()` below)
//   GET /oid4vci/credential-offer/:id  serves an offer fetched by reference
//
// A person's OWN pre-authorized offer is made on the user portal since #589
// (`POST /account-api/credentials/offers`, `portal/portal_wallet.ts`), through
// this module's `makeOffer()` — the one function `/issuer/offer` calls too.
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

// WHICH CELL MINTED AN ARTIFACT (#98 D10): a keyed tag appended to what
// this module mints and read where it is presented. A leaf library.
import cellLocator = require('../common/cell_locator');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and error_codes.js and nothing else here, so it cannot join a
// cycle and it registers no route, so its position is not a position at all.
import realms = require('../common/realms');
import app = require('../common/app');
// THE DEMONSTRATION MARK (#585), read off the shared app here because
// `registerRoutes(app)`'s parameter shadows the name — and a stand-in app
// a test passes carries no mark. `common/app.js` argues it.
const demoOnly = app.demoOnly;
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
// THE DEMONSTRATION'S SHELL (#582): what `/issuer` and `/issuer/offer`
// answer. A library over libraries; it requires nothing of this family.
import VcDemoShell = require('./vc_demo_shell');

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
/**
 * Credential Offers served by reference, per trust realm: id to `{ offer,
 * issuerState, expires }`.
 */
const credentialOffers = realms.map({ persist: 'vc_offers.credentialOffers',
                                      retain: 'age',
                                      // #333: the offer's `expires`, ms.
                                      expiresAt: realms.expiryField('expires',
                                                                    1) });

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// issuer_state -> { configurationIds, expires }
/**
 * Issuer states of same-device offers, per trust realm: `issuer_state` to `{
 * configurationIds, expires }`.
 */
const issuerStates = realms.map({ persist: 'vc_offers.issuerStates',
                                  retain: 'age',
                                  // #333: its `expires`, ms.
                                  expiresAt: realms.expiryField('expires',
                                                                1) });

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
/**
 * Pre-authorized codes (OID4VCI Appendix H.2 and H.3), per trust realm: code to
 * `{ configurationIds, txCode, user, deferred, expires }`.
 */
const preAuthorizedCodes =
    realms.map({ persist: 'vc_offers.preAuthorizedCodes', retain: 'age',
                 // #333: the code's `expires`, ms.
                 expiresAt: realms.expiryField('expires', 1) });

// Deferred issuance transactions (OID4VCI section 9): the credential endpoint
// answered 202 with one of these instead of a credential.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// transaction_id -> { claims, holderJwk, readyAt, expires }
/**
 * Deferred issuance transactions (OID4VCI section 9), per trust realm:
 * `transaction_id` to `{ claims, holderJwk, readyAt, expires }`.
 */
const deferredTransactions =
    realms.map({ persist: 'vc_offers.deferredTransactions', retain: 'age',
                 // #333: the transaction's `expires`, ms.
                 expiresAt: realms.expiryField('expires', 1) });

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

/**
 * Credential Offer (OID4VCI section 4), the issuer-initiated half of issuance:
 * the issuer's page, the offer built and handed to the wallet by value or by
 * reference, and the offer served by reference, for the three Appendix H use
 * cases.
 */
class VcOffers {
  /**
   * The default lifetime of an offer, in milliseconds; `offerTtlMs()` is the
   * live value.
   */
  static readonly OFFER_TTL_MS = OFFER_TTL_MS;

  // Access tokens minted from a deferred offer, as the SET-SHAPED FACADE the
  // store comment above describes. Built once, here; `add` returns it.
  /**
   * The access tokens minted from a deferred offer, for which the credential
   * endpoint answers 202: a set-shaped facade over the per-realm store.
   */
  readonly deferredAccessTokens: {
    add(token: unknown): unknown;
    has(token: unknown): boolean;
    delete(token: unknown): boolean;
    clear(): void;
    readonly size: number;
  };

  /**
   * Builds the offer pages from the modules and stores they read.
   *
   * @param deps - the modules the composition root passes
   */
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
  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
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
    return stsCrypto.digest('sha256', String(token || ''), 'base64url');
  }

  // How long a deferred issuance "takes". Short enough for a test to wait for
  // it, long enough that the first poll genuinely comes back still-pending.
  /**
   * Returns how long a deferred issuance takes before it is ready
   * (`oid4vci.deferredReadyMs`).
   *
   * @returns milliseconds
   */
  deferredReadyMs() {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.deferredReadyMs().");
    log.debug("Leaving VcOffers.deferredReadyMs().");
    return config.value('oid4vci.deferredReadyMs');
  }

  /**
   * Returns the polling interval a deferred response tells the wallet
   * (`oid4vci.deferredIntervalS`).
   *
   * @returns seconds
   */
  deferredIntervalS() {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.deferredIntervalS().");
    log.debug("Leaving VcOffers.deferredIntervalS().");
    return config.value('oid4vci.deferredIntervalS');
  }

  /**
   * Returns the lifetime of an offer (`oid4vci.offerTtlS`), or the default.
   *
   * @returns milliseconds
   */
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
  // `stsCrypto.randomInt()` is uniform over the range, which a modulo of random
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
    return String(stsCrypto.randomInt(low, low * 10));
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
  /**
   * Checks a Transaction Code presented with a pre-authorized code, counting
   * wrong ones across the cluster and spending the code when its attempts run
   * out.
   *
   * @param code - the pre-authorized code
   * @param record - its record in `preAuthorizedCodes`
   * @param presented - the Transaction Code the wallet sent
   * @returns `{ ok }`, or `{ ok: false, missing | spent | store, attemptsLeft
   *   }`
   */
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
  /**
   * Claims a pre-authorized code once across the cluster; exactly one caller on
   * any node gets `{ ok: true }`. Fails closed when the store cannot be asked.
   *
   * @param code - the pre-authorized code
   * @param record - its record
   * @returns `{ ok: true }`, or `{ ok: false, errorCode, description }`
   */
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
  /**
   * Returns where the End-User is sent: the configured wallet URL, or the
   * `wallet` query parameter — which, where only registered addresses are
   * accepted, must name the configured wallet or an allowed one.
   *
   * @param req - the request
   * @param named - the wallet a caller named in a body (#582: the
   *   demonstration's `POST /vc-demo-api/offer`); the query's `wallet`
   *   where left out
   * @returns `{ url }`, or `{ error }` naming the refused wallet
   */
  walletFor(req: any, named?: unknown) {
    const { log, walletBaseUrl, config, mode } = this.deps;
    log.debug("Entering VcOffers.walletFor().");
    const configured = String(walletBaseUrl() || '').replace(/\/+$/, '');
    const given = named === undefined
      ? (req && req.query ? req.query.wallet : '') : named;
    const asked = given ? String(given).replace(/\/+$/, '') : '';
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
  /**
   * Returns whom a pre-authorized offer is for when no one is named
   * (`oid4vci.offerUsername`).
   *
   * @returns the username
   */
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
  /**
   * Builds a Credential Offer for one of the Appendix H use cases:
   * `same-device` (authorization code and issuer state), `cross-device`
   * (pre-authorized code and Transaction Code) or `deferred`.
   *
   * @param req - the request
   * @param configurationIds - the configurations on offer
   * @param mode - the use case
   * @param options - `user`, whom a pre-authorized offer is for
   * @returns `{ offer, issuerState, preAuthorizedCode, txCode, mode,
   *   expires }`, `expires` when the offer and its code stop being honoured
   *   (ms since the epoch)
   */
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
      // Stamped with the minting cell (#98 D10): the wallet redeems it at
      // the cell nearest it, which relays the token request here.
      preAuthorizedCode = cellLocator.stamp(randomId(24));
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
             mode: mode || 'same-device', expires: expires };
  }

  // ---------------------------------------------------------------------------
  // MAKING AN OFFER, FOR BOTH OF ITS DOORS (#589, 2026-10-12).
  //
  // A Credential Offer is made in two places: `GET /issuer/offer`, the demo
  // issuer's page, and `POST /account-api/credentials/offers`, where a person
  // signed in to the portal puts a credential about THEMSELVES into their own
  // wallet (`portal/portal_wallet.ts`). **ONE FUNCTION MAKES IT FOR BOTH**,
  // and that is the point of this method rather than a convenience: what an
  // offer is — the code minted, whom it names, how long it lives, the
  // expired state swept, the reference stored and stamped for its cell, the
  // `openid-credential-offer://` URI and the wallet link — is said once, so
  // the portal's offer and the issuer page's cannot come to differ.
  //
  // **THE SESSION IS PRESENTED HERE, BEFORE ANYTHING IS MINTED** (#240): a
  // pre-authorized code IS the authorization for a credential about the
  // person it names, and nobody authenticates for it — the sign-on session
  // the person already holds is what it rests on, and CAEP's
  // `session-presented` says so, naming OpenID4VCI. The caller passes the
  // session when there is one the offer is made on: the portal's operation
  // always does (the sign-on session its token was issued on); the issuer
  // page, which since #589 makes a pre-authorized offer only where the test
  // controls are open, for `oid4vci.offerUsername`, never does.
  //
  // `byReference` also stores the offer under a 128-bit id and answers its
  // `credential_offer_uri` (#65: fetching it hands over the offer and its
  // code, so it is a bearer value like the code). The issuer page asks for
  // the one form its `by` names; the portal's operation asks for both, so a
  // person's screen can show a QR code small enough to scan beside a link
  // that carries the offer whole.
  // ---------------------------------------------------------------------------
  /**
   * Makes a Credential Offer — for the issuer page and the portal's account
   * API alike — and the forms it is handed to a wallet in.
   *
   * @param req - the request (its realm and its base URL)
   * @param ask - `configurationIds`, `mode` (`same-device`, `cross-device`
   *   or `deferred`), `user` (whom a pre-authorized offer is for), `session`
   *   (the sign-on session the offer is made on, presented over CAEP),
   *   `byReference` (also store it and answer its reference) and `wallet`
   *   (the wallet URL a link goes to, '' for none)
   * @returns `{ built, byValue, byReference }`: what
   *   `buildCredentialOffer()` built, and for each form its `query`, its
   *   `openid-credential-offer://` URI and its wallet link (byReference also
   *   its `credentialOfferUri`, and null where it was not asked for)
   */
  makeOffer(req: any, ask: { configurationIds: string[]; mode: string;
                             user?: any; session?: any;
                             byReference?: boolean; wallet?: string }) {
    const { log, baseUrlOf, randomId, loadAuthn, credentialOffers,
            issuerStates, preAuthorizedCodes,
            deferredTransactions } = this.deps;
    log.debug("Entering VcOffers.makeOffer(). mode=" + ask.mode);
    const session = ask.session || null;
    if (session) {
      // `authn.ts` is required here rather than at the top of this file:
      // `oauth2.ts` requires this module for its stores, and a top-level
      // require of the authentication service from a store module is a cycle
      // waiting for the load order to change. Here it is a cache hit.
      const authn = loadAuthn();
      authn.notePresented(session, 'OpenID4VCI', req);
    }
    const built = this.buildCredentialOffer(req, ask.configurationIds,
                                            ask.mode,
                                            { user: ask.user || null });
    // Sweep expired offers, states, codes and transactions while here.
    const now = Date.now();
    [credentialOffers, issuerStates, preAuthorizedCodes,
     deferredTransactions].forEach(function (store: Store): void {
      store.forEach(function (v: any, k: string): void {
        if (v.expires < now) {
          store.delete(k);
        }
      });
    });
    const wallet = String(ask.wallet || '');
    const formOf = function (query: string): any {
      log.debug("Entering formOf().");
      log.debug("Leaving formOf().");
      return { query: query,
               offerUri: 'openid-credential-offer://?' + query,
               walletUrl: wallet ? wallet + '?' + query : '' };
    };
    const byValue = formOf('credential_offer=' +
                           encodeURIComponent(JSON.stringify(built.offer)));
    let byReference = null;
    if (ask.byReference) {
      // Stamped (#98 D10): a wallet fetches the offer from the cell nearest
      // it, whose edge relays the fetch here.
      const id = cellLocator.stamp(randomId(16));
      credentialOffers.set(id, { offer: built.offer,
                                 expires: now + this.offerTtlMs() });
      const uri = baseUrlOf(req) + '/oid4vci/credential-offer/' + id;
      byReference = Object.assign(
        formOf('credential_offer_uri=' + encodeURIComponent(uri)),
        { credentialOfferUri: uri });
      log.debug("The offer is also passed by reference: " + uri);
    }
    log.debug("Leaving VcOffers.makeOffer(). mode=" + built.mode);
    return { built: built, byValue: byValue, byReference: byReference };
  }

  /**
   * The configured wallet's issuance page (`oid4vci.walletUrl` and
   * `oid4vci.walletIssuancePath`), or '' where no wallet is configured — the
   * wallet a link made for somebody who named none goes to.
   *
   * @returns the URL, or ''
   */
  configuredWalletUrl(): string {
    const { log, walletBaseUrl, config } = this.deps;
    log.debug("Entering VcOffers.configuredWalletUrl().");
    const configured = String(walletBaseUrl() || '').replace(/\/+$/, '');
    if (!configured) {
      log.debug("Leaving VcOffers.configuredWalletUrl(). None.");
      return '';
    }
    log.debug("Leaving VcOffers.configuredWalletUrl().");
    return configured + String(config.value('oid4vci.walletIssuancePath') ||
                               '');
  }

  // ---------------------------------------------------------------------------
  // THE DEMONSTRATION ISSUER'S PAGES, AS VIEWS AND AN ACT (#582, 2026-10-12).
  //
  // `/issuer` and `/issuer/offer` were pages this module drew until #582 —
  // the issuer's page with its four links, and the offer: a 302 to the
  // wallet on this device, or a page drawing the offer as a QR code (a PNG
  // the `qrcode` package made here) beside the Transaction Code. They are
  // routes of the demonstration's static surface now (`vc_demo_shell.ts`,
  // drawn by `web_vc_demo*.ts`), and these are what `/vc-demo-api`
  // (`vc_demo_api.ts`) answers them with:
  //
  //   * `issuerView()` — the issuer's page: the configuration on offer, the
  //     wallet a same-device offer goes to, and this issuer's identifier.
  //   * `offerChecked()` — what an offer's query or body asked, checked as
  //     the page checked its query (`STS-VC-0025` for what the schema
  //     refuses, `STS-VC-0026` for a wallet this realm will not send to), and
  //     NOTHING MINTED: the start page's view asks it, and a GET must create
  //     nothing (#574's rule, since a prefetcher follows a GET).
  //   * `offerAct()` — the act: `makeOffer()` exactly as the page called it,
  //     answered as `location` (the wallet, on this device — the address the
  //     302 named) or as the QR page's view (the offer URI, the wallet link
  //     and the Transaction Code; the browser draws the code from the URI).
  //
  // **WHAT A WALLET IS HANDED IS NOT CHANGED**: the offer, its
  // `openid-credential-offer://` URI and the wallet link are `makeOffer()`'s,
  // to the byte, as they were when this page sent them.
  //
  // **WHO A PRE-AUTHORIZED OFFER IS FOR (#589, #585).** A cross-device or
  // deferred offer carries a pre-authorized code, and that code IS the
  // authorization: whoever redeems it is issued a credential about the
  // person it names. This demonstration mints one for
  // `oid4vci.offerUsername` and shows the Transaction Code beside it — H.2's
  // story ("they uploaded documents to an employee portal days before"), a
  // credential about a fixed person for the asking, and so a test control,
  // served in a development realm only (`common/app.js`'s `demoOnly`). A
  // person's own offer into their own wallet is the portal's
  // (`/portal/wallet`, `portal/portal_wallet.ts`), through `makeOffer()` too.
  // ---------------------------------------------------------------------------
  /**
   * The demonstration issuer's page's view.
   *
   * @param req - the request (its realm and its base URL)
   * @returns `{ kind: 'issuer', configurationId, wallet, issuer }`
   */
  issuerView(req: any) {
    const { log, baseUrlOf, walletBaseUrl } = this.deps;
    log.debug("Entering VcOffers.issuerView().");
    log.debug("Leaving VcOffers.issuerView().");
    return { kind: 'issuer', configurationId: VCI_CONFIG_ID,
             wallet: String(walletBaseUrl() || ''),
             issuer: baseUrlOf(req) };
  }

  /**
   * Checks what a demonstration offer asks for — the offer page's query, or
   * the act's body — and mints nothing.
   *
   * @param req - the request
   * @param asked - `mode`, `by`, `wallet`, `credential_configuration_ids`
   * @param where - the input group's name for a refusal (`query`, `body`)
   * @returns `{ ok: true, configurationIds, mode, byReference, wallet }`, or
   *   `{ ok: false, status, code, error }`
   */
  offerChecked(req: any, asked: any, where: string) {
    const { log, validation } = this.deps;
    log.debug("Entering VcOffers.offerChecked(). where=" + where);
    const checked = validation.checkParsed(asked || {}, where, OID4VC_QUERY);
    if (!checked.ok) {
      log.debug("Leaving VcOffers.offerChecked(). " + checked.detail);
      return { ok: false, status: 400, code: 'STS-VC-0025',
               error: String(checked.detail) };
    }
    const given: any = checked.value;
    const walletChoice = this.walletFor(req, String(given.wallet || ''));
    if (walletChoice.error) {
      log.debug("Leaving VcOffers.offerChecked(). " + walletChoice.error);
      return { ok: false, status: 400, code: 'STS-VC-0026',
               error: walletChoice.error };
    }
    const configurationIds = given.credential_configuration_ids
      ? String(given.credential_configuration_ids).split(',')
          .filter(Boolean)
      : [VCI_CONFIG_ID];
    log.debug("Leaving VcOffers.offerChecked().");
    return { ok: true, configurationIds: configurationIds,
             mode: String(given.mode || 'same-device'),
             byReference: String(given.by || '') === 'reference',
             wallet: String(walletChoice.url) };
  }

  /**
   * Makes the demonstration's Credential Offer and says how the page hands
   * it to the wallet.
   *
   * @param req - the request
   * @param asked - what was asked, as `offerChecked()` reads it
   * @param where - the input group's name for a refusal
   * @returns `{ ok: true, location }` (same device: the wallet), `{ ok:
   *   true, view }` (another device: the QR page's view), or `{ ok: false,
   *   status, code, error }`
   */
  offerAct(req: any, asked: any, where: string) {
    const { log } = this.deps;
    log.debug("Entering VcOffers.offerAct(). where=" + where);
    const checked: any = this.offerChecked(req, asked, where);
    if (!checked.ok) {
      log.debug("Leaving VcOffers.offerAct(). Refused.");
      return checked;
    }
    const made = this.makeOffer(req, {
      configurationIds: checked.configurationIds, mode: checked.mode,
      byReference: checked.byReference, wallet: checked.wallet });
    const built = made.built;
    // How the offer reaches the wallet: in the URL, or behind a URI it
    // fetches.
    const handed = made.byReference || made.byValue;
    // Same device (H.1): the wallet is right here, so the browser goes to
    // it — the address the 302 named.
    if (built.mode !== 'cross-device' && built.mode !== 'deferred') {
      log.debug("Leaving VcOffers.offerAct(). Same device.");
      return { ok: true, location: handed.walletUrl };
    }
    // Cross device (H.2 / H.3): the wallet is on the End-User's OTHER
    // device, so the offer is shown for it to scan — as the
    // openid-credential-offer URI a wallet registers for — and the
    // Transaction Code is shown beside it, on the issuer's screen, never in
    // the offer.
    log.debug("Leaving VcOffers.offerAct(). Another device.");
    return { ok: true,
             view: { kind: 'offer', mode: built.mode,
                     offerUri: handed.offerUri, walletUrl: handed.walletUrl,
                     txCode: built.txCode } };
  }

  // The three pages, in the order they were registered at load before
  // #50's R1. Called by `common/protocol_stack.ts`.
  /**
   * Registers the three offer routes — `/issuer`, `/issuer/offer` and
   * `/oid4vci/credential-offer/:id` — in the order they were always registered.
   *
   * Called by `common/protocol_stack.ts`, just before `oauth2`'s routes.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: any) {
    const { log, vciError, errorCodes, credentialOffers } = this.deps;
    log.debug("Entering VcOffers.registerRoutes().");
    // THE ISSUER'S PAGE AND THE OFFER (#582): the demonstration's shell;
    // the runtime draws each from `/vc-demo-api` and makes the offer there.
    app.get('/issuer', demoOnly, (req, res) => {
      log.debug("Entering the issuer web page.");
      VcDemoShell.send(req, res, 'Mock University — digital diploma');
      log.debug("Leaving the issuer web page.");
    });

    app.get('/issuer/offer', demoOnly, (req, res) => {
      log.debug("Entering the credential offer page.");
      VcDemoShell.send(req, res, 'Mock University — your digital diploma');
      log.debug("Leaving the credential offer page.");
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
/**
 * The deferred access tokens as a stable set-shaped object, each member
 * forwarding to the installed instance's store, so a module that reads it at
 * its own load builds nothing.
 */
const deferredAccessTokens = {
  /**
   * Adds a deferred access token.
   *
   * @param token - the access token
   * @returns this facade
   */
  add: function (token: unknown): unknown {
    helpers.log.debug("Entering deferredAccessTokens.add().");
    slot.get().deferredAccessTokens.add(token);
    helpers.log.debug("Leaving deferredAccessTokens.add().");
    return deferredAccessTokens;
  },
  /**
   * Says whether an access token was minted from a deferred offer.
   *
   * @param token - the access token
   * @returns true when it was
   */
  has: function (token: unknown): boolean {
    helpers.log.debug("Entering deferredAccessTokens.has().");
    helpers.log.debug("Leaving deferredAccessTokens.has().");
    return slot.get().deferredAccessTokens.has(token);
  },
  /**
   * Removes a deferred access token.
   *
   * @param token - the access token
   * @returns true when there was one
   */
  delete: function (token: unknown): boolean {
    helpers.log.debug("Entering deferredAccessTokens.delete().");
    helpers.log.debug("Leaving deferredAccessTokens.delete().");
    return slot.get().deferredAccessTokens.delete(token);
  },
  /**
   * Removes every deferred access token in the realm.
   */
  clear: function (): void {
    helpers.log.debug("Entering deferredAccessTokens.clear().");
    slot.get().deferredAccessTokens.clear();
    helpers.log.debug("Leaving deferredAccessTokens.clear().");
  },
  /**
   * The number of deferred access tokens in the realm.
   *
   * @returns the count
   */
  get size(): number {
    helpers.log.debug("Entering deferredAccessTokens.size().");
    helpers.log.debug("Leaving deferredAccessTokens.size().");
    return slot.get().deferredAccessTokens.size;
  }
};

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Credential Offer (OID4VCI section 4), the issuer-initiated half of issuance,
 * and the stores the token endpoint redeems offers from.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcOffers: VcOffers,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcOffers): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
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
  // #589: the one maker of an offer, for /issuer/offer and the portal's
  // `POST /account-api/credentials/offers`; and the configured wallet.
  makeOffer: slot.forward('makeOffer'),
  configuredWalletUrl: slot.forward('configuredWalletUrl'),
  // #582: the demonstration issuer's pages' views and act, for
  // `oid4vc/vc_demo_api.ts`.
  issuerView: slot.forward('issuerView'),
  offerChecked: slot.forward('offerChecked'),
  offerAct: slot.forward('offerAct')
};
