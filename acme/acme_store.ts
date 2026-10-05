// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: acme_store.ts
//
// ---------------------------------------------------------------------------
// EVERYTHING ACME MINTS, PER TRUST REALM (RFC 8555 section 7.1).
//
// Accounts, orders, authorizations, the index of certificates issued at
// finalize, the RFC 9773 renewal index, and the nonces already spent. **EACH
// STORE IS PER REALM AT ITS DECLARATION** (common/CLAUDE.md's rule, and
// `tests/realm_isolation.js`'s): an account made at `/realm/a/enroll/acme` is
// realm a's, and its URL presented at realm b finds nothing — not an account
// it is refused for, nothing — because the two realms are two logical
// certificate authorities.
//
// **EACH IS DECLARED WITH `persist`**, `gnap/gnap_store.ts`'s shape, so in
// product mode on a postgres store it survives a restart and replicates
// between request workers. Three consequences, honoured everywhere below:
//
//   * **a row is JSON** — a key is the public JWK the client sent, never a
//     KeyObject;
//   * **an in-place edit is re-set** — the journal sees `set` and `delete`,
//     so every mutation goes through a `save*()` here;
//   * **a row is small.** A certificate's PEM is NOT copied here: it is on the
//     directory entry the certificate names (`common/cert_enrollment.ts`
//     writes it there), and the index keeps the serial and the entry so the
//     download reads the one copy.
//
// **WHAT IS NOT HERE IS THE CREDENTIAL.** An External Account Binding key lives
// on the entry it was issued for (`stsAcmeEabKey` / `appAcmeEabKey`), sealed,
// and is read through the enrollment core; an account records only the key id
// that bound it.
//
// Expiry is checked on READ, for gnap_store.js's reason: a sweep on a timer
// runs in every request worker and races a lookup in another. A row past its
// life is pruned opportunistically when something new is written.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AcmeStore` takes the modules it uses through its constructor
// (`AcmeStoreDeps`). Since #50's R2 the composition root builds the instance
// (`AcmeStore.defaultDeps()`) and installs it; the module's old export names
// are FACADES that forward to it, for the JavaScript callers, and a process
// without the root builds a default when the module finishes loading.
// `AcmeStore` is exported beside them for the composition root.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;
import realms = require('../common/realms');
import config = require('../common/config');
// The atomic "once" a nonce is spent through across nodes — see
// `spendNonceOnce()`. A LIBRARY that reaches `persistence.js` lazily.
import claims = require('../cluster/cluster_claims');
import InstanceSlot = require('../common/instance_slot');
// Which cell minted an identifier (#98 D10). A leaf library.
import cellLocator = require('../common/cell_locator');
import cacheRegistry = require('../common/cache_registry');

const accounts = realms.map({ persist: 'acme.accounts' });
// thumbprint -> account id. An account IS its key (section 7.3.1), and a key
// bound to one account may not be bound to a second (section 7.3.5).
const accountKeys = realms.map({ persist: 'acme.accountKeys' });
// `expiresAt` (#333): pruneOrders()'s rule — an order that never became
// VALID goes a day after its `expires` (an ISO string), with its
// authorizations; a valid one is kept while its account lists it. An
// authorization follows the same rule, being deleted only with its order.
function unlessValid(record: any): number | null {
  // A hot path (every row a flush writes): no Entering/Leaving pair.
  if (!record || record.status === 'valid') {
    return null;
  }
  const at = Date.parse(String(record.expires || ''));
  return isFinite(at) && at > 0 ? at + 86400000 : null;
}
const orders = realms.map({ persist: 'acme.orders',
                            expiresAt: unlessValid });
const authorizations = realms.map({ persist: 'acme.authorizations',
                                    retain: 'age',
                                    expiresAt: unlessValid });
const certificates = realms.map({ persist: 'acme.certificates' });
// RFC 9773 certID -> certificate id.
const renewals = realms.map({ persist: 'acme.renewalInfo' });
// The random part of every Replay-Nonce already presented, with its expiry.
const usedNonces = realms.map({ persist: 'acme.usedNonces', retain: 'age',
                                // #333: the value IS the expiry, seconds.
                                expiresAt: realms.expiryField(null, 1000) });

// A realm holding this many spent nonces refuses to remember more by dropping
// the ones that have expired first; a nonce is only useful until it expires, so
// what is dropped can never be presented again anyway.
//
// A SETTING SINCE #346 (2026-09-29), `acme.maxSpentNonces`, where it was a
// literal 100,000. The default came down to 10,000 because the history is
// resident in every process of every node, per realm (#339). Lowering it does
// not shorten the replay window — a full history REFUSES, it never forgets a
// live spend — so what the lower number costs is throughput: a realm answers
// badNonce past about acme.maxSpentNonces / acme.nonceLifetimeS spends a
// second (33 at the defaults).
/**
 * How many spent nonces a realm remembers; past it, expired ones are dropped
 * first and a new spend is refused rather than forgotten.
 *
 * @returns the realm's `acme.maxSpentNonces`
 */
function maxUsedNonces(): number {
  log.debug("Entering maxUsedNonces().");
  const max = Number(config.value('acme.maxSpentNonces'));
  log.debug("Leaving maxUsedNonces().");
  return max;
}

// Described to `/admin/caches` (#74, rule 3ap). The value is the nonce's
// expiry in seconds. The bound is soft: at it, only expired nonces go.
const usedNoncesCount = cacheRegistry.register({
  name: 'acme.nonces',
  title: 'ACME nonces',
  description: 'The Replay-Nonce values already presented to the ACME ' +
    'server (RFC 8555 section 6.5), so each is accepted once.',
  owner: 'acme/acme_store.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a nonce already spent, so the request was refused',
  settings: ['acme.nonceLifetimeS', 'acme.maxSpentNonces'],
  maxEntries: function (): number {
    return maxUsedNonces();
  },
  bound: 'Enforced: acme.maxSpentNonces spent nonces per realm. Expired ' +
    'ones are cleared at the bound; a history still full REFUSES the next ' +
    'spend (answered badNonce) rather than forget a live one.',
  lifetime: function (): string {
    return 'Until the nonce expires; expired ones are cleared when the ' +
      'limit is reached.';
  },
  // The spends `spendNonce()`'s makeRoom() already treats as expired — a
  // nonce past its own expiry is refused before it is spent (#49 P5).
  eject: cacheRegistry.realmMapEjector(realms, usedNonces,
    function (expiresS: unknown, id: unknown, now: number): boolean {
      return Number(expiresS) <= Math.floor(now / 1000);
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, usedNonces,
      function (expiresS: unknown, id: unknown): object {
        return { key: cacheRegistry.digestKey(id),
                 validUntil: Number(expiresS) * 1000 };
      });
  }
});

// Orders kept per account once they are finished. A client that loops on
// newOrder must not grow a store without bound.
const MAX_ORDERS_PER_ACCOUNT = 1000;

// What `AcmeStore` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface AcmeStoreDeps {
  nodeCrypto: typeof nodeCrypto;
  log: typeof log;
  claims: typeof claims;
  cellLocator: typeof cellLocator;
}

/**
 * Everything ACME mints, per trust realm: accounts, orders, authorizations, the
 * certificate index, the RFC 9773 renewal index and the spent nonces.
 *
 * Each store is per realm at its declaration and persisted, so a row is JSON
 * and every change goes through a `save*()` here.
 */
class AcmeStore {
  /**
   * Creates the store.
   *
   * @param deps - node's crypto, the logger and the cluster claims
   */
  constructor(private readonly deps: AcmeStoreDeps) {
    deps.log.debug("Entering AcmeStore.constructor().");
    deps.log.debug("Leaving AcmeStore.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the dependencies
   */
  static defaultDeps(): AcmeStoreDeps {
    log.debug("Entering AcmeStore.defaultDeps().");
    log.debug("Leaving AcmeStore.defaultDeps().");
    return {
      nodeCrypto: nodeCrypto,
      log: log,
      claims: claims,
      cellLocator: cellLocator
    };
  }

  /**
   * Makes a random base64url identifier.
   *
   * @param bytes - how many random bytes; 15 when absent
   * @returns the identifier
   */
  //
  // **STAMPED WITH THE CELL THAT MINTED IT (#98 D10).** Every identifier made
  // here is the last segment of a URL the client POSTs to later — an
  // account's `kid`, an order, an authorization and its one challenge, a
  // certificate — and the rows it names are this cell's (`acme.*` is cell
  // tier). The placement table's ACME rows read the tag off the path at the
  // edge, and `Acme.placeRequest()` reads it off a `kid`, so a request that
  // reaches another cell is relayed here before its JWS is looked at. Twelve
  // base64url characters more (28 or 32 in all), inside `ID_PATTERN`'s 8 to
  // 64; nothing in a single-cell service.
  newId(bytes) {
    const { log, nodeCrypto, cellLocator } = this.deps;
    log.debug("Entering AcmeStore.newId().");
    log.debug("Leaving AcmeStore.newId().");
    return cellLocator.stamp(nodeCrypto.randomBytes(bytes || 15)
      .toString('base64url'));
  }

  /**
   * Returns the time now, in milliseconds.
   *
   * @returns the time
   */
  nowMs() {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.nowMs().");
    log.debug("Leaving AcmeStore.nowMs().");
    return Date.now();
  }

  // ---------------------------------------------------------------------------
  // ACCOUNTS.
  // ---------------------------------------------------------------------------
  /**
   * Creates an account and binds its key's thumbprint to it.
   *
   * @param fields - the account's fields, `jwk` and `thumbprint` among them
   * @returns the account
   */
  createAccount(fields) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.createAccount().");
    const account = Object.assign({
      id: this.newId(12),
      status: 'valid',
      contact: [],
      termsOfServiceAgreed: false,
      createdAt: new Date(this.nowMs()).toISOString(),
      orderIds: []
    }, fields || {});
    accounts.set(account.id, account);
    accountKeys.set(account.thumbprint, account.id);
    log.debug("Leaving AcmeStore.createAccount(). id=" + account.id);
    return account;
  }

  /**
   * Finds an account by id in the ambient realm.
   *
   * @param id - the account id
   * @returns the account, or null
   */
  getAccount(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getAccount().");
    const found = id && accounts.has(String(id)) ? accounts.get(String(id))
                                                 : null;
    log.debug("Leaving AcmeStore.getAccount(). found=" + !!found);
    return found;
  }

  /**
   * Finds the account a key is bound to.
   *
   * @param thumbprint - the key's JWK thumbprint
   * @returns the account, or null
   */
  accountByThumbprint(thumbprint) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.accountByThumbprint().");
    const id = thumbprint && accountKeys.has(thumbprint)
      ? accountKeys.get(thumbprint) : null;
    log.debug("Leaving AcmeStore.accountByThumbprint().");
    return id ? this.getAccount(id) : null;
  }

  /**
   * Writes an account back after a change.
   *
   * @param account - the account
   * @returns the account
   */
  saveAccount(account) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.saveAccount().");
    accounts.set(account.id, account);
    log.debug("Leaving AcmeStore.saveAccount().");
    return account;
  }

  // Section 7.3.5: the account's key is replaced, the old thumbprint freed.
  /**
   * Replaces an account's key (RFC 8555 section 7.3.5), freeing the old
   * thumbprint.
   *
   * @param account - the account
   * @param jwk - the new public key
   * @param thumbprint - its thumbprint
   * @returns the account
   */
  rekeyAccount(account, jwk, thumbprint) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.rekeyAccount().");
    if (accountKeys.has(account.thumbprint) &&
        accountKeys.get(account.thumbprint) === account.id) {
      accountKeys.delete(account.thumbprint);
    }
    account.jwk = jwk;
    account.thumbprint = thumbprint;
    account.rekeyedAt = new Date(this.nowMs()).toISOString();
    accounts.set(account.id, account);
    accountKeys.set(thumbprint, account.id);
    log.debug("Leaving AcmeStore.rekeyAccount().");
    return account;
  }

  /**
   * Lists the realm's accounts, newest first.
   *
   * @returns the accounts
   */
  listAccounts() {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.listAccounts().");
    const out = [];
    accounts.forEach(function (account) {
      out.push(account);
    });
    log.debug("Leaving AcmeStore.listAccounts(). " + out.length + ".");
    return out.sort(function (a, b) {
      return String(b.createdAt).localeCompare(String(a.createdAt));
    });
  }

  // ---------------------------------------------------------------------------
  // ORDERS AND AUTHORIZATIONS.
  // ---------------------------------------------------------------------------
  /**
   * Creates an authorization.
   *
   * @param fields - its fields
   * @returns the authorization
   */
  createAuthorization(fields) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.createAuthorization().");
    const authz = Object.assign({ id: this.newId(15), status: 'valid' },
                                fields || {});
    authorizations.set(authz.id, authz);
    log.debug("Leaving AcmeStore.createAuthorization(). id=" + authz.id);
    return authz;
  }

  /**
   * Finds an authorization by id.
   *
   * @param id - the authorization id
   * @returns the authorization, or null
   */
  getAuthorization(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getAuthorization().");
    const found = id && authorizations.has(String(id))
      ? authorizations.get(String(id)) : null;
    log.debug("Leaving AcmeStore.getAuthorization().");
    return found;
  }

  /**
   * Writes an authorization back after a change.
   *
   * @param authz - the authorization
   * @returns the authorization
   */
  saveAuthorization(authz) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.saveAuthorization().");
    authorizations.set(authz.id, authz);
    log.debug("Leaving AcmeStore.saveAuthorization().");
    return authz;
  }

  /**
   * Creates an order for an account, first pruning dead orders; the account
   * keeps its most recent 1000.
   *
   * @param account - the account
   * @param fields - the order's fields
   * @returns the order
   */
  createOrder(account, fields) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.createOrder().");
    this.pruneOrders();
    const order = Object.assign({ id: this.newId(15), accountId: account.id,
                                  status: 'ready',
                                  createdAt: new Date(this.nowMs())
                                    .toISOString() },
                                fields || {});
    orders.set(order.id, order);
    account.orderIds = (account.orderIds || []).concat([order.id])
      .slice(-MAX_ORDERS_PER_ACCOUNT);
    accounts.set(account.id, account);
    log.debug("Leaving AcmeStore.createOrder(). id=" + order.id);
    return order;
  }

  /**
   * Finds an order by id.
   *
   * @param id - the order id
   * @returns the order, or null
   */
  getOrder(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getOrder().");
    const found = id && orders.has(String(id)) ? orders.get(String(id)) : null;
    log.debug("Leaving AcmeStore.getOrder().");
    return found;
  }

  /**
   * Writes an order back after a change.
   *
   * @param order - the order
   * @returns the order
   */
  saveOrder(order) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.saveOrder().");
    orders.set(order.id, order);
    log.debug("Leaving AcmeStore.saveOrder().");
    return order;
  }

  // An order that expired a day ago and never became valid is gone, with the
  // authorizations only it referred to. A VALID order is kept for as long as
  // the account lists it, because its certificate URL is still being fetched.
  /**
   * Removes every order that never became valid and expired more than a day
   * ago, with its authorizations.
   */
  pruneOrders() {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.pruneOrders().");
    const cutoff = this.nowMs() - 86400000;
    const dead = [];
    orders.forEach(function (order, id) {
      if (order.status !== 'valid' &&
          new Date(order.expires).getTime() < cutoff) {
        dead.push(id);
      }
    });
    dead.forEach(function (id) {
      const order = orders.get(id);
      (order.authorizationIds || []).forEach(function (authzId) {
        authorizations.delete(authzId);
      });
      orders.delete(id);
    });
    log.debug("Leaving AcmeStore.pruneOrders(). " + dead.length + " pruned.");
  }

  // ---------------------------------------------------------------------------
  // CERTIFICATES AND THE RENEWAL INDEX.
  // ---------------------------------------------------------------------------
  /**
   * Records a certificate issued at finalize, and its RFC 9773 certID in the
   * renewal index. The PEM stays on the directory entry.
   *
   * @param fields - the certificate's serial, entry, `certId` and the rest
   * @returns the record
   */
  recordCertificate(fields) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.recordCertificate().");
    const record = Object.assign({ id: this.newId(15),
                                   issuedAt: new Date(this.nowMs())
                                     .toISOString() },
                                 fields || {});
    certificates.set(record.id, record);
    if (record.certId) {
      renewals.set(record.certId, record.id);
    }
    log.debug("Leaving AcmeStore.recordCertificate(). id=" + record.id);
    return record;
  }

  /**
   * Finds a certificate record by id.
   *
   * @param id - the record id
   * @returns the record, or null
   */
  getCertificate(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getCertificate().");
    const found = id && certificates.has(String(id))
      ? certificates.get(String(id)) : null;
    log.debug("Leaving AcmeStore.getCertificate().");
    return found;
  }

  /**
   * Writes a certificate record back after a change.
   *
   * @param record - the record
   * @returns the record
   */
  saveCertificate(record) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.saveCertificate().");
    certificates.set(record.id, record);
    log.debug("Leaving AcmeStore.saveCertificate().");
    return record;
  }

  /**
   * Finds a certificate record by its RFC 9773 certID.
   *
   * @param certId - the certID
   * @returns the record, or null
   */
  certificateByCertId(certId) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.certificateByCertId().");
    const id = certId && renewals.has(String(certId))
      ? renewals.get(String(certId)) : null;
    log.debug("Leaving AcmeStore.certificateByCertId().");
    return id ? this.getCertificate(id) : null;
  }

  /**
   * Finds a certificate record by serial number, ignoring case and leading
   * zeros.
   *
   * @param serialHex - the serial in hex
   * @returns the record, or null
   */
  certificateBySerial(serialHex) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.certificateBySerial().");
    const wanted = String(serialHex || '').toLowerCase()
      .replace(/^0+(?=.)/, '');
    let found = null;
    certificates.forEach(function (record) {
      if (!found && String(record.serialHex).toLowerCase()
                      .replace(/^0+(?=.)/, '') === wanted) {
        found = record;
      }
    });
    log.debug("Leaving AcmeStore.certificateBySerial(). found=" + !!found);
    return found;
  }

  // ---------------------------------------------------------------------------
  // SPENT NONCES. `spendNonce()` answers false for one already spent, which is
  // the replay; it records the spend otherwise. The check and the record are
  // one synchronous step in this process, so two requests here cannot both
  // spend one.
  // ---------------------------------------------------------------------------
  /**
   * Spends a nonce in this process: false for one already spent, which is the
   * replay.
   *
   * A realm full of live spends refuses the new one, answered badNonce so the
   * client retries with a fresh nonce.
   *
   * @param id - the nonce's random part
   * @param expiresS - when it expires, in seconds
   * @returns true when spent now
   */
  spendNonce(id, expiresS) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.spendNonce().");
    if (usedNonces.has(id)) {
      usedNoncesCount.hit();
      log.debug("Leaving AcmeStore.spendNonce(). Already spent.");
      return false;
    }
    usedNoncesCount.miss();
    // THE BOUND (acme.maxSpentNonces). The expired go first, as they always did;
    // what changed on 2026-09-18 is a store still full of LIVE spends, which
    // took the new one anyway and grew past its bound. It decides a replay,
    // so it refuses rather than forgets: the spend answers false, the request
    // is answered badNonce and the client fetches a fresh nonce and retries,
    // which RFC 8555 section 6.5 has it do. The registry logs the real reason
    // (STS-CORE-0097) at most once a minute.
    const nowS = Math.floor(this.nowMs() / 1000);
    const room = cacheRegistry.makeRoom(usedNonces, maxUsedNonces(), {
      policy: 'refuse', counter: usedNoncesCount, name: 'acme.nonces',
      setting: 'acme.maxSpentNonces',
      expired: function (value: unknown): boolean {
        return Number(value) <= nowS;
      }
    });
    if (!room.ok) {
      log.debug("Leaving AcmeStore.spendNonce(). The history is full.");
      return false;
    }
    usedNonces.set(id, Number(expiresS));
    log.debug("Leaving AcmeStore.spendNonce(). Spent.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // A NONCE, SPENT ONCE ACROSS THE CLUSTER (2026-09-14, #46 section 2).
  //
  // `spendNonce()` is one synchronous step IN THIS PROCESS, which is what its
  // comment says and all it says. `usedNonces` is persisted and replicated, so
  // a nonce spent on one node reaches the others — a moment later. Inside that
  // moment two copies of one signed request (a retry that raced its original, a
  // captured request replayed at a second node) both passed, and RFC 8555
  // section 6.5's replay protection held per node.
  //
  // **THE LOCAL MAP STAYS THE FIRST CHECK** (no round trip for the ordinary
  // replay), and a nonce it accepts is then CLAIMED; a claim that another
  // request holds is the replay. The claim lives until the nonce itself expires
  // plus a minute of skew — after that `acme_jws.checkNonce()` refuses it as
  // expired and the claim guards nothing.
  //
  // Resolves `{ ok: true }`, `{ ok: false, reason: 'used' }` or
  // `{ ok: false, reason: 'store', why }`.
  // ---------------------------------------------------------------------------
  /**
   * Spends a nonce once across the cluster: the local check first, then a claim
   * that lasts until the nonce expires plus a minute.
   *
   * @param id - the nonce's random part
   * @param expiresS - when it expires, in seconds
   * @returns a promise of `{ ok: true }`, `{ ok: false, reason: 'used' }` or `{
   * ok: false, reason, why }`
   */
  spendNonceOnce(id, expiresS): Record<string, any> {
    const { log, claims } = this.deps;
    log.debug("Entering AcmeStore.spendNonceOnce().");
    if (!this.spendNonce(id, expiresS)) {
      log.debug("Leaving AcmeStore.spendNonceOnce(). Spent here.");
      return Promise.resolve({ ok: false, reason: 'used' });
    }
    const remaining = Number(expiresS) * 1000 - this.nowMs();
    log.debug("Leaving AcmeStore.spendNonceOnce(). Claiming.");
    return claims.claim({ scope: 'acme.nonce', value: String(id),
                          ttlMs: Math.max(60 * 1000,
                                          (remaining || 0) + 60 * 1000) })
      .then(function (claimed) {
        if (claimed.ok) {
          return { ok: true };
        }
        return { ok: false, reason: claimed.reason,
                 why: claimed.why || '' };
      });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AcmeStore>(
  'acme/acme_store',
  () => new AcmeStore(AcmeStore.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The ACME stores, per trust realm.
 *
 * Exports the class and facades forwarding to the instance the composition root
 * built.
 *
 * @namespace
 */
export = {
  AcmeStore: AcmeStore,
  installInstance: (instance: AcmeStore): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  createAccount: slot.forward('createAccount'),
  getAccount: slot.forward('getAccount'),
  accountByThumbprint: slot.forward('accountByThumbprint'),
  saveAccount: slot.forward('saveAccount'),
  rekeyAccount: slot.forward('rekeyAccount'),
  listAccounts: slot.forward('listAccounts'),
  createAuthorization: slot.forward('createAuthorization'),
  getAuthorization: slot.forward('getAuthorization'),
  saveAuthorization: slot.forward('saveAuthorization'),
  createOrder: slot.forward('createOrder'),
  getOrder: slot.forward('getOrder'),
  saveOrder: slot.forward('saveOrder'),
  recordCertificate: slot.forward('recordCertificate'),
  getCertificate: slot.forward('getCertificate'),
  saveCertificate: slot.forward('saveCertificate'),
  certificateByCertId: slot.forward('certificateByCertId'),
  certificateBySerial: slot.forward('certificateBySerial'),
  spendNonce: slot.forward('spendNonce'),
  spendNonceOnce: slot.forward('spendNonceOnce')
};
