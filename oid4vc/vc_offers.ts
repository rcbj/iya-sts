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
// their Wallet with a Credential Offer in hand. The issuer's SITE is not this
// service's any more: `/issuer` and `/issuer/offer`, the demonstration's pages,
// moved to the development companion on #594 (`companion/`), which makes the
// same-device offer itself — an authorization_code grant with no issuer_state,
// which section 4.1.1 allows — and leaves the authorization to
// `/oauth2/authorize`. What stays here is the protocol's:
//
//   GET /oid4vci/credential-offer/:id  serves an offer fetched by reference
//
// and the state an offer creates, which the token and authorization endpoints
// redeem. A person's OWN pre-authorized offer is made on the user portal since
// #589 (`POST /account-api/credentials/offers`, `portal/portal_wallet.ts`),
// through this module's `makeOffer()`.
//
// The offer names this issuer, the credential configuration(s) on offer, and
// the grant. For H.1 that grant is authorization_code carrying an issuer_state,
// which the Wallet must hand back on the authorization request so the issuer
// can tie the two together.
//
// AN OFFER IS HANDED TO A WALLET APP BY ITS SCHEME (2026-10-12):
// `openid-credential-offer://`, or HAIP's `haip-vci://`
// (`oid4vci.walletInvocation`), which a wallet on the device registers
// for. A WEB wallet is a URL a browser page can be sent to, offered beside
// it only where `oid4vci.walletUrl` configures one; the default is none —
// it was the embedded debugger's address until then, which no person's
// wallet is.
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
// signer, the error codes, the cluster claims, a loader for the
// authentication service (still required lazily, inside `makeOffer()`) and
// the five stores through its constructor, and registers its one route from
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
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// THE MODE (2026-09-12), for one question since #594 — does this realm verify
// credentials (the Transaction Code's attempts). A LEAF requiring only
// `config`.
import mode = require('../common/mode');
// Constant-time comparison, for the Transaction Code, and
// `credentialDigest()`, the name every store below keys a credential by
// (#614). A leaf.
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

// ---------------------------------------------------------------------------
// A STORE KEYED BY THE DIGEST OF A CREDENTIAL, NEVER BY THE CREDENTIAL (#614).
//
// Four of the stores below are keyed by a value somebody PRESENTS and this
// service only ever looks up, spends or deletes: the pre-authorized code a
// wallet redeems at the token endpoint, the `issuer_state` it hands back on
// an authorization request, the id an offer passed by reference is fetched
// by, and the `transaction_id` a deferred credential is collected with. Each
// is a bearer value — whoever holds it gets what it names — and a declared
// store is journalled, replicated into every request worker and every node,
// and written to `sts_minted` in product mode. So the store holds
// `crypto.credentialDigest()` of the value and never the value: a heap
// snapshot, a `sts_changes` row or a dump of `sts_minted` yields nothing a
// wallet could redeem. The precedent is `deferredAccessTokens` below, keyed
// the same way since 2026-09-12.
//
// **THE KEY IS HASHED WHERE THE VALUE IS PRESENTED, BY THIS FACADE**, so the
// callers that are not this module's — `oauth-oidc/oauth2.ts` reads the
// codes and the issuer states, `vc_issuer.ts` the deferred transactions —
// keep calling `get(code)` with what arrived and never learn that the store
// underneath changed. That is `deferredAccessTokens`' argument again, and
// the reason this is a facade rather than a `keyOf()` every caller must
// remember: a caller that forgot would find nothing and fail closed, but a
// caller that SET a raw key would put the credential back in the store.
//
// **ITERATION HANDS OUT THE DIGEST, AND SAYS SO IN ITS NAME** —
// `forEachDigest()` and `deleteDigest()`, never a `forEach()` whose key a
// reader would take for the presented value and hand back to `delete()`,
// which would hash it a second time and delete nothing. `logout.ts` is the
// one outside reader that walks a store, to end a person's codes.
//
// **NO MIGRATION.** A row persisted before #614 is under the raw value, is
// never found under its digest, and expires on its own `expires`.
// ---------------------------------------------------------------------------
/**
 * A `realms.map()` store keyed by `crypto.credentialDigest()` of a presented
 * credential: every keyed call hashes what it is given, and iteration hands
 * out the digest (#614).
 */
class DigestKeyedStore {
  /**
   * Wraps a declared store.
   *
   * @param store - the per-realm store the digests key
   */
  constructor(private readonly store: Store) {
    helpers.log.debug("Entering DigestKeyedStore.constructor().");
    helpers.log.debug("Leaving DigestKeyedStore.constructor().");
  }

  /**
   * The key a presented value is stored under.
   *
   * @param presented - the credential as it arrived
   * @returns its SHA-256, base64url
   */
  static keyOf(presented: unknown): string {
    helpers.log.debug("Entering DigestKeyedStore.keyOf().");
    helpers.log.debug("Leaving DigestKeyedStore.keyOf().");
    return stsCrypto.credentialDigest(String(presented || ''));
  }

  /**
   * The record a presented value names.
   *
   * @param presented - the credential as it arrived
   * @returns the record, or undefined
   */
  get(presented: unknown): any {
    helpers.log.debug("Entering DigestKeyedStore.get().");
    helpers.log.debug("Leaving DigestKeyedStore.get().");
    return this.store.get(DigestKeyedStore.keyOf(presented));
  }

  /**
   * Records a value under the digest of the credential it is for.
   *
   * @param presented - the credential, as it will be presented
   * @param value - the record
   * @returns this store
   */
  set(presented: unknown, value: any): DigestKeyedStore {
    helpers.log.debug("Entering DigestKeyedStore.set().");
    this.store.set(DigestKeyedStore.keyOf(presented), value);
    helpers.log.debug("Leaving DigestKeyedStore.set().");
    return this;
  }

  /**
   * Says whether a presented value names a record.
   *
   * @param presented - the credential as it arrived
   * @returns true when it does
   */
  has(presented: unknown): boolean {
    helpers.log.debug("Entering DigestKeyedStore.has().");
    helpers.log.debug("Leaving DigestKeyedStore.has().");
    return this.store.has(DigestKeyedStore.keyOf(presented));
  }

  /**
   * Removes the record a presented value names.
   *
   * @param presented - the credential as it arrived
   * @returns true when there was one
   */
  delete(presented: unknown): boolean {
    helpers.log.debug("Entering DigestKeyedStore.delete().");
    helpers.log.debug("Leaving DigestKeyedStore.delete().");
    return this.store.delete(DigestKeyedStore.keyOf(presented));
  }

  /**
   * Walks the realm's records with the DIGEST each is keyed by — never the
   * credential, which this store does not hold.
   *
   * @param fn - called with each record and its digest
   */
  forEachDigest(fn: (value: any, digest: string) => void): void {
    helpers.log.debug("Entering DigestKeyedStore.forEachDigest().");
    this.store.forEach(fn);
    helpers.log.debug("Leaving DigestKeyedStore.forEachDigest().");
  }

  /**
   * Removes a record by the digest `forEachDigest()` handed out.
   *
   * @param digest - the key, already a digest
   * @returns true when there was one
   */
  deleteDigest(digest: string): boolean {
    helpers.log.debug("Entering DigestKeyedStore.deleteDigest().");
    helpers.log.debug("Leaving DigestKeyedStore.deleteDigest().");
    return this.store.delete(digest);
  }

  /**
   * Removes every record whose `expires` is before `now`.
   *
   * @param now - the instant, ms
   * @returns how many went
   */
  sweepExpired(now: number): number {
    helpers.log.debug("Entering DigestKeyedStore.sweepExpired().");
    const gone: string[] = [];
    this.store.forEach(function (v: any, k: string): void {
      if (v && v.expires < now) {
        gone.push(k);
      }
    });
    gone.forEach((k) => {
      this.store.delete(k);
    });
    helpers.log.debug("Leaving DigestKeyedStore.sweepExpired(). " +
                      gone.length + " gone.");
    return gone.length;
  }

  /**
   * Removes every record in the realm.
   */
  clear(): void {
    helpers.log.debug("Entering DigestKeyedStore.clear().");
    this.store.clear();
    helpers.log.debug("Leaving DigestKeyedStore.clear().");
  }

  /**
   * The number of records in the realm.
   *
   * @returns the count
   */
  get size(): number {
    helpers.log.debug("Entering DigestKeyedStore.size().");
    helpers.log.debug("Leaving DigestKeyedStore.size().");
    return this.store.size;
  }
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
  // The authentication service, required when first needed — see the offer
  // page.
  loadAuthn(): any;
  credentialOffers: DigestKeyedStore;
  issuerStates: DigestKeyedStore;
  preAuthorizedCodes: DigestKeyedStore;
  deferredTransactions: DigestKeyedStore;
  deferredAccessTokenStore: Store;
}

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// digest(id) -> { offer, expires }
//
// THE KEY IS A DIGEST (#614): the id is the bearer half of the
// `credential_offer_uri`, and fetching it hands over the offer and its code.
// THE VALUE IS THE OFFER, WHOLE, PRE-AUTHORIZED CODE AND ALL, and that is
// the documented exception: OpenID4VCI section 4.1.3 has the wallet fetch
// the offer BY REFERENCE, so the exact document has to be here to be
// served. It lives `oid4vci.offerTtlS`, as the code it carries does.
/**
 * Credential Offers served by reference, per trust realm: the digest of the
 * id to `{ offer, expires }`.
 */
const credentialOffers = new DigestKeyedStore(
  realms.map({ persist: 'vc_offers.credentialOffers', retain: 'age',
               // #333: the offer's `expires`, ms.
               expiresAt: realms.expiryField('expires', 1) }));

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// digest(issuer_state) -> { configurationIds, expires }. The key is a
// digest (#614): the value is only ever looked up, by the authorization
// endpoint, with what the wallet handed back.
/**
 * Issuer states of same-device offers, per trust realm: the digest of the
 * `issuer_state` to `{ configurationIds, expires }`.
 */
const issuerStates = new DigestKeyedStore(
  realms.map({ persist: 'vc_offers.issuerStates', retain: 'age',
               // #333: its `expires`, ms.
               expiresAt: realms.expiryField('expires', 1) }));

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
// digest(code) -> { configurationIds, txCodeDigest, txCodeFailures, user,
//                   deferred, expires }
//
// BOTH CREDENTIALS ARE DIGESTS (#614): the code keys the row by its digest,
// and the Transaction Code is kept as `txCodeDigest` — see checkTxCode() for
// what that does and does not buy for a five-digit value.
/**
 * Pre-authorized codes (OID4VCI Appendix H.2 and H.3), per trust realm: the
 * digest of the code to `{ configurationIds, txCodeDigest, txCodeFailures,
 * user, deferred, expires }`.
 */
const preAuthorizedCodes = new DigestKeyedStore(
  realms.map({ persist: 'vc_offers.preAuthorizedCodes', retain: 'age',
               // #333: the code's `expires`, ms.
               expiresAt: realms.expiryField('expires', 1) }));

// Deferred issuance transactions (OID4VCI section 9): the credential endpoint
// answered 202 with one of these instead of a credential.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// digest(transaction_id) -> { claims, holderJwk, readyAt, expires }
//
// THE KEY IS A DIGEST (#614): a `transaction_id` collects a credential at
// the Deferred Credential Endpoint, which asks for a token this issuer
// signed but not the one that started the transaction, so the id is the
// bearer half. **AND THE ACCESS TOKEN IS NOT KEPT**: the row carried it
// whole until #614, and it was read only to be copied onto the
// notification row, where nothing read it either — what the credential
// needs from the token (its claims, the holder's name, whom it may sign in)
// is read off it when the 202 is answered and kept instead.
/**
 * Deferred issuance transactions (OID4VCI section 9), per trust realm: the
 * digest of the `transaction_id` to `{ claims, holderJwk, readyAt, expires
 * }`.
 */
const deferredTransactions = new DigestKeyedStore(
  realms.map({ persist: 'vc_offers.deferredTransactions', retain: 'age',
               // #333: the transaction's `expires`, ms.
               expiresAt: realms.expiryField('expires', 1) }));

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
   * Builds the offers from the modules and stores they read.
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
    // The same SHA-256 it always was, through the one helper (#614).
    return DigestKeyedStore.keyOf(token);
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
  // **THE RECORD HOLDS ITS DIGEST, NOT THE CODE (#614)**: `txCodeDigest`,
  // compared with the digest of what was presented, byte for byte in constant
  // time. Be clear what that buys. A Transaction Code is five digits by
  // default (`oid4vci.txCodeLength`), so its SHA-256 is NOT a secret against
  // anybody holding the row: ninety thousand hashes recover it in well under
  // a second, offline, and no salt or slow hash changes that order of
  // magnitude for a value this small. What it does buy is that the row no
  // longer CARRIES the code — a heap snapshot, a replication record or a
  // sealed `sts_minted` row read by somebody casually is not the code beside
  // the pre-authorized code it unlocks, and a log line or a console view
  // that ever printed the record would print a digest. The protection that
  // matters against guessing is the attempt limit below, which is online,
  // and the offer's short life.
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
   * @param code - the pre-authorized code, as presented (its digest keys
   *   the record)
   * @param record - its record in `preAuthorizedCodes`
   * @param presented - the Transaction Code the wallet sent, compared by its
   *   digest with the record's `txCodeDigest`
   * @returns `{ ok }`, or `{ ok: false, missing | spent | store, attemptsLeft
   *   }`
   */
  async checkTxCode(code: string, record: any, presented: unknown) {
    const { log, config, mode, stsCrypto, errorCodes,
            preAuthorizedCodes } = this.deps;
    log.debug("Entering VcOffers.checkTxCode().");
    if (!record.txCodeDigest) {
      log.debug("Leaving VcOffers.checkTxCode(). This offer carries no " +
                "Transaction Code.");
      return { ok: true };
    }
    const given = String(presented || '');
    if (!given) {
      log.debug("Leaving VcOffers.checkTxCode(). None was presented.");
      return { ok: false, missing: true };
    }
    if (stsCrypto.bytesEqualConstantTime(
          Buffer.from(stsCrypto.credentialDigest(given), 'utf8'),
          Buffer.from(String(record.txCodeDigest), 'utf8'))) {
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
  // development still does. The portal's offer passes the signed-in person
  // (#589).
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
      // Keyed by the code's digest, and holding the Transaction Code's
      // digest (#614): the plain values leave this function in its answer,
      // for the page that shows them, and are not kept.
      preAuthorizedCodes.set(preAuthorizedCode, {
        configurationIds: configurationIds,
        txCodeDigest: stsCrypto.credentialDigest(txCodeValue),
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
  // MAKING AN OFFER (#589, 2026-10-12).
  //
  // A Credential Offer is made at `POST /account-api/credentials/offers`,
  // where a person signed in to the portal puts a credential about
  // THEMSELVES into their own wallet (`portal/portal_wallet.ts`); the demo
  // issuer's `GET /issuer/offer` was a second door until #594. What an offer
  // is — the code minted, whom it names, how long it lives, the expired
  // state swept, the reference stored and stamped for its cell, the
  // `openid-credential-offer://` URI and the wallet link — is said here,
  // once.
  //
  // **THE SESSION IS PRESENTED HERE, BEFORE ANYTHING IS MINTED** (#240): a
  // pre-authorized code IS the authorization for a credential about the
  // person it names, and nobody authenticates for it — the sign-on session
  // the person already holds is what it rests on, and CAEP's
  // `session-presented` says so, naming OpenID4VCI. The caller passes the
  // session when there is one the offer is made on: the portal's operation
  // always does (the sign-on session its token was issued on).
  //
  // `byReference` also stores the offer under a 128-bit id and answers its
  // `credential_offer_uri` (#65: fetching it hands over the offer and its
  // code, so it is a bearer value like the code). The portal's operation
  // asks for both, so a person's screen can show a QR code small enough to
  // scan beside a link that carries the offer whole.
  // ---------------------------------------------------------------------------
  /**
   * Makes a Credential Offer — for the portal's account API — and the forms
   * it is handed to a wallet in.
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
    // Sweep expired offers, states, codes and transactions while here. Each
    // is keyed by a digest (#614), so the sweep removes by the key it walks
    // rather than through `delete()`, which would hash it again.
    const now = Date.now();
    [credentialOffers, issuerStates, preAuthorizedCodes,
     deferredTransactions].forEach(function (store: DigestKeyedStore): void {
      store.sweepExpired(now);
    });
    const wallet = String(ask.wallet || '');
    // THE SCHEME A WALLET APP IS HANDED THE OFFER UNDER (2026-10-12):
    // OpenID4VCI 1.0 section 4.1's `openid-credential-offer://`, or HAIP
    // 1.0 section 4.2's `haip-vci://` where `oid4vci.walletInvocation` says
    // so. The web wallet's link, `walletUrl`, is beside it only where a web
    // wallet is configured or named.
    const scheme = this.offerScheme();
    const formOf = function (query: string): any {
      log.debug("Entering formOf().");
      log.debug("Leaving formOf().");
      return { query: query,
               offerUri: scheme + '?' + query,
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
   * The custom URL scheme, with its `://`, a Credential Offer is handed to a
   * wallet app under (`oid4vci.walletInvocation`).
   *
   * @returns `openid-credential-offer://` or `haip-vci://`
   */
  offerScheme(): string {
    const { log, config } = this.deps;
    log.debug("Entering VcOffers.offerScheme().");
    const scheme = String(config.value('oid4vci.walletInvocation') || '') ===
      'haip-vci' ? 'haip-vci://' : 'openid-credential-offer://';
    log.debug("Leaving VcOffers.offerScheme(). " + scheme);
    return scheme;
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

  // The one route left (`/issuer` and `/issuer/offer`, the demonstration
  // issuer's pages, moved to the development companion on #594). Called by
  // `common/protocol_stack.ts`.
  /**
   * Registers `/oid4vci/credential-offer/:id`, where an offer passed by
   * reference is fetched.
   *
   * Called by `common/protocol_stack.ts`, just before `oauth2`'s routes.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: any) {
    const { log, vciError, errorCodes, credentialOffers } = this.deps;
    log.debug("Entering VcOffers.registerRoutes().");
    app.get('/oid4vci/credential-offer/:id', (req, res) => {
      log.debug("Entering the credential offer retrieval endpoint. id=" +
                req.params.id);
      // By the id's digest (#614): the store never held the id.
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
  vciOfferUsername: slot.forward('vciOfferUsername'),
  buildCredentialOffer: slot.forward('buildCredentialOffer'),
  // #589: the maker of an offer, for the portal's `POST
  // /account-api/credentials/offers`; and the configured wallet.
  makeOffer: slot.forward('makeOffer'),
  configuredWalletUrl: slot.forward('configuredWalletUrl'),
  // #614: the facade the four credential-keyed stores are, for a reader that
  // must name its type, and the key a presented value is stored under.
  DigestKeyedStore: DigestKeyedStore,
  credentialKeyOf: DigestKeyedStore.keyOf
};
