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
//     directory entry the certificate names (`common/cert_enrollment.js`
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
// (`AcmeStoreDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `AcmeStore` is exported beside them for the
// composition root.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;
import realms = require('../common/realms');
// The atomic "once" a nonce is spent through across nodes — see
// `spendNonceOnce()`. A LIBRARY that reaches `persistence.js` lazily.
import claims = require('../cluster/cluster_claims');

const accounts = realms.map({ persist: 'acme.accounts' });
// thumbprint -> account id. An account IS its key (section 7.3.1), and a key
// bound to one account may not be bound to a second (section 7.3.5).
const accountKeys = realms.map({ persist: 'acme.accountKeys' });
const orders = realms.map({ persist: 'acme.orders' });
const authorizations = realms.map({ persist: 'acme.authorizations' });
const certificates = realms.map({ persist: 'acme.certificates' });
// RFC 9773 certID -> certificate id.
const renewals = realms.map({ persist: 'acme.renewalInfo' });
// The random part of every Replay-Nonce already presented, with its expiry.
const usedNonces = realms.map({ persist: 'acme.usedNonces' });

// A realm holding this many spent nonces refuses to remember more by dropping
// the ones that have expired first; a nonce is only useful until it expires, so
// what is dropped can never be presented again anyway.
const MAX_USED_NONCES = 100000;

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
}

class AcmeStore {
  constructor(private readonly deps: AcmeStoreDeps) {
    deps.log.debug("Entering AcmeStore.constructor().");
    deps.log.debug("Leaving AcmeStore.constructor().");
  }

  newId(bytes) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering AcmeStore.newId().");
    log.debug("Leaving AcmeStore.newId().");
    return nodeCrypto.randomBytes(bytes || 15).toString('base64url');
  }

  nowMs() {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.nowMs().");
    log.debug("Leaving AcmeStore.nowMs().");
    return Date.now();
  }

  // ---------------------------------------------------------------------------
  // ACCOUNTS.
  // ---------------------------------------------------------------------------
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

  getAccount(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getAccount().");
    const found = id && accounts.has(String(id)) ? accounts.get(String(id))
                                                 : null;
    log.debug("Leaving AcmeStore.getAccount(). found=" + !!found);
    return found;
  }

  accountByThumbprint(thumbprint) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.accountByThumbprint().");
    const id = thumbprint && accountKeys.has(thumbprint)
      ? accountKeys.get(thumbprint) : null;
    log.debug("Leaving AcmeStore.accountByThumbprint().");
    return id ? this.getAccount(id) : null;
  }

  saveAccount(account) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.saveAccount().");
    accounts.set(account.id, account);
    log.debug("Leaving AcmeStore.saveAccount().");
    return account;
  }

  // Section 7.3.5: the account's key is replaced, the old thumbprint freed.
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
  createAuthorization(fields) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.createAuthorization().");
    const authz = Object.assign({ id: this.newId(15), status: 'valid' },
                                fields || {});
    authorizations.set(authz.id, authz);
    log.debug("Leaving AcmeStore.createAuthorization(). id=" + authz.id);
    return authz;
  }

  getAuthorization(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getAuthorization().");
    const found = id && authorizations.has(String(id))
      ? authorizations.get(String(id)) : null;
    log.debug("Leaving AcmeStore.getAuthorization().");
    return found;
  }

  saveAuthorization(authz) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.saveAuthorization().");
    authorizations.set(authz.id, authz);
    log.debug("Leaving AcmeStore.saveAuthorization().");
    return authz;
  }

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

  getOrder(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getOrder().");
    const found = id && orders.has(String(id)) ? orders.get(String(id)) : null;
    log.debug("Leaving AcmeStore.getOrder().");
    return found;
  }

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

  getCertificate(id) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.getCertificate().");
    const found = id && certificates.has(String(id))
      ? certificates.get(String(id)) : null;
    log.debug("Leaving AcmeStore.getCertificate().");
    return found;
  }

  saveCertificate(record) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.saveCertificate().");
    certificates.set(record.id, record);
    log.debug("Leaving AcmeStore.saveCertificate().");
    return record;
  }

  certificateByCertId(certId) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.certificateByCertId().");
    const id = certId && renewals.has(String(certId))
      ? renewals.get(String(certId)) : null;
    log.debug("Leaving AcmeStore.certificateByCertId().");
    return id ? this.getCertificate(id) : null;
  }

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
  spendNonce(id, expiresS) {
    const { log } = this.deps;
    log.debug("Entering AcmeStore.spendNonce().");
    if (usedNonces.has(id)) {
      log.debug("Leaving AcmeStore.spendNonce(). Already spent.");
      return false;
    }
    if (usedNonces.size >= MAX_USED_NONCES) {
      const nowS = Math.floor(this.nowMs() / 1000);
      const expired = [];
      usedNonces.forEach(function (value, key) {
        if (Number(value) <= nowS) {
          expired.push(key);
        }
      });
      expired.forEach(function (key) {
        usedNonces.delete(key);
      });
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

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const acmeStore = new AcmeStore({
  nodeCrypto: nodeCrypto,
  log: log,
  claims: claims
});

export = {
  AcmeStore: AcmeStore,
  MAX_USED_NONCES: MAX_USED_NONCES,
  createAccount: acmeStore.createAccount.bind(acmeStore) as
    AcmeStore['createAccount'],
  getAccount: acmeStore.getAccount.bind(acmeStore) as AcmeStore['getAccount'],
  accountByThumbprint: acmeStore.accountByThumbprint.bind(acmeStore) as
    AcmeStore['accountByThumbprint'],
  saveAccount: acmeStore.saveAccount.bind(acmeStore) as
    AcmeStore['saveAccount'],
  rekeyAccount: acmeStore.rekeyAccount.bind(acmeStore) as
    AcmeStore['rekeyAccount'],
  listAccounts: acmeStore.listAccounts.bind(acmeStore) as
    AcmeStore['listAccounts'],
  createAuthorization: acmeStore.createAuthorization.bind(acmeStore) as
    AcmeStore['createAuthorization'],
  getAuthorization: acmeStore.getAuthorization.bind(acmeStore) as
    AcmeStore['getAuthorization'],
  saveAuthorization: acmeStore.saveAuthorization.bind(acmeStore) as
    AcmeStore['saveAuthorization'],
  createOrder: acmeStore.createOrder.bind(acmeStore) as
    AcmeStore['createOrder'],
  getOrder: acmeStore.getOrder.bind(acmeStore) as AcmeStore['getOrder'],
  saveOrder: acmeStore.saveOrder.bind(acmeStore) as AcmeStore['saveOrder'],
  recordCertificate: acmeStore.recordCertificate.bind(acmeStore) as
    AcmeStore['recordCertificate'],
  getCertificate: acmeStore.getCertificate.bind(acmeStore) as
    AcmeStore['getCertificate'],
  saveCertificate: acmeStore.saveCertificate.bind(acmeStore) as
    AcmeStore['saveCertificate'],
  certificateByCertId: acmeStore.certificateByCertId.bind(acmeStore) as
    AcmeStore['certificateByCertId'],
  certificateBySerial: acmeStore.certificateBySerial.bind(acmeStore) as
    AcmeStore['certificateBySerial'],
  spendNonce: acmeStore.spendNonce.bind(acmeStore) as AcmeStore['spendNonce'],
  spendNonceOnce: acmeStore.spendNonceOnce.bind(acmeStore) as
    AcmeStore['spendNonceOnce']
};
