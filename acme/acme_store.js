'use strict';
//
// File: acme_store.js
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
// **EACH IS DECLARED WITH `persist`**, `gnap/gnap_store.js`'s shape, so in
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

const nodeCrypto = require('crypto');
const { log } = require('../common/helpers');
const realms = require('../common/realms');

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

function newId(bytes) {
  log.debug("Entering newId().");
  log.debug("Leaving newId().");
  return nodeCrypto.randomBytes(bytes || 15).toString('base64url');
}

function nowMs() {
  log.debug("Entering nowMs().");
  log.debug("Leaving nowMs().");
  return Date.now();
}

// ---------------------------------------------------------------------------
// ACCOUNTS.
// ---------------------------------------------------------------------------
function createAccount(fields) {
  log.debug("Entering createAccount().");
  const account = Object.assign({
    id: newId(12),
    status: 'valid',
    contact: [],
    termsOfServiceAgreed: false,
    createdAt: new Date(nowMs()).toISOString(),
    orderIds: []
  }, fields || {});
  accounts.set(account.id, account);
  accountKeys.set(account.thumbprint, account.id);
  log.debug("Leaving createAccount(). id=" + account.id);
  return account;
}

function getAccount(id) {
  log.debug("Entering getAccount().");
  const found = id && accounts.has(String(id)) ? accounts.get(String(id))
                                               : null;
  log.debug("Leaving getAccount(). found=" + !!found);
  return found;
}

function accountByThumbprint(thumbprint) {
  log.debug("Entering accountByThumbprint().");
  const id = thumbprint && accountKeys.has(thumbprint)
    ? accountKeys.get(thumbprint) : null;
  log.debug("Leaving accountByThumbprint().");
  return id ? getAccount(id) : null;
}

function saveAccount(account) {
  log.debug("Entering saveAccount().");
  accounts.set(account.id, account);
  log.debug("Leaving saveAccount().");
  return account;
}

// Section 7.3.5: the account's key is replaced, the old thumbprint freed.
function rekeyAccount(account, jwk, thumbprint) {
  log.debug("Entering rekeyAccount().");
  if (accountKeys.has(account.thumbprint) &&
      accountKeys.get(account.thumbprint) === account.id) {
    accountKeys.delete(account.thumbprint);
  }
  account.jwk = jwk;
  account.thumbprint = thumbprint;
  account.rekeyedAt = new Date(nowMs()).toISOString();
  accounts.set(account.id, account);
  accountKeys.set(thumbprint, account.id);
  log.debug("Leaving rekeyAccount().");
  return account;
}

function listAccounts() {
  log.debug("Entering listAccounts().");
  const out = [];
  accounts.forEach(function (account) {
    out.push(account);
  });
  log.debug("Leaving listAccounts(). " + out.length + ".");
  return out.sort(function (a, b) {
    return String(b.createdAt).localeCompare(String(a.createdAt));
  });
}

// ---------------------------------------------------------------------------
// ORDERS AND AUTHORIZATIONS.
// ---------------------------------------------------------------------------
function createAuthorization(fields) {
  log.debug("Entering createAuthorization().");
  const authz = Object.assign({ id: newId(15), status: 'valid' },
                              fields || {});
  authorizations.set(authz.id, authz);
  log.debug("Leaving createAuthorization(). id=" + authz.id);
  return authz;
}

function getAuthorization(id) {
  log.debug("Entering getAuthorization().");
  const found = id && authorizations.has(String(id))
    ? authorizations.get(String(id)) : null;
  log.debug("Leaving getAuthorization().");
  return found;
}

function saveAuthorization(authz) {
  log.debug("Entering saveAuthorization().");
  authorizations.set(authz.id, authz);
  log.debug("Leaving saveAuthorization().");
  return authz;
}

function createOrder(account, fields) {
  log.debug("Entering createOrder().");
  pruneOrders();
  const order = Object.assign({ id: newId(15), accountId: account.id,
                                status: 'ready',
                                createdAt: new Date(nowMs()).toISOString() },
                              fields || {});
  orders.set(order.id, order);
  account.orderIds = (account.orderIds || []).concat([order.id])
    .slice(-MAX_ORDERS_PER_ACCOUNT);
  accounts.set(account.id, account);
  log.debug("Leaving createOrder(). id=" + order.id);
  return order;
}

function getOrder(id) {
  log.debug("Entering getOrder().");
  const found = id && orders.has(String(id)) ? orders.get(String(id)) : null;
  log.debug("Leaving getOrder().");
  return found;
}

function saveOrder(order) {
  log.debug("Entering saveOrder().");
  orders.set(order.id, order);
  log.debug("Leaving saveOrder().");
  return order;
}

// An order that expired a day ago and never became valid is gone, with the
// authorizations only it referred to. A VALID order is kept for as long as the
// account lists it, because its certificate URL is still being fetched.
function pruneOrders() {
  log.debug("Entering pruneOrders().");
  const cutoff = nowMs() - 86400000;
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
  log.debug("Leaving pruneOrders(). " + dead.length + " pruned.");
}

// ---------------------------------------------------------------------------
// CERTIFICATES AND THE RENEWAL INDEX.
// ---------------------------------------------------------------------------
function recordCertificate(fields) {
  log.debug("Entering recordCertificate().");
  const record = Object.assign({ id: newId(15),
                                 issuedAt: new Date(nowMs()).toISOString() },
                               fields || {});
  certificates.set(record.id, record);
  if (record.certId) {
    renewals.set(record.certId, record.id);
  }
  log.debug("Leaving recordCertificate(). id=" + record.id);
  return record;
}

function getCertificate(id) {
  log.debug("Entering getCertificate().");
  const found = id && certificates.has(String(id))
    ? certificates.get(String(id)) : null;
  log.debug("Leaving getCertificate().");
  return found;
}

function saveCertificate(record) {
  log.debug("Entering saveCertificate().");
  certificates.set(record.id, record);
  log.debug("Leaving saveCertificate().");
  return record;
}

function certificateByCertId(certId) {
  log.debug("Entering certificateByCertId().");
  const id = certId && renewals.has(String(certId))
    ? renewals.get(String(certId)) : null;
  log.debug("Leaving certificateByCertId().");
  return id ? getCertificate(id) : null;
}

function certificateBySerial(serialHex) {
  log.debug("Entering certificateBySerial().");
  const wanted = String(serialHex || '').toLowerCase().replace(/^0+(?=.)/, '');
  let found = null;
  certificates.forEach(function (record) {
    if (!found && String(record.serialHex).toLowerCase()
                    .replace(/^0+(?=.)/, '') === wanted) {
      found = record;
    }
  });
  log.debug("Leaving certificateBySerial(). found=" + !!found);
  return found;
}

// ---------------------------------------------------------------------------
// SPENT NONCES. `spendNonce()` answers false for one already spent, which is
// the replay; it records the spend otherwise. The check and the record are one
// synchronous step in this process, so two requests here cannot both spend one.
// ---------------------------------------------------------------------------
function spendNonce(id, expiresS) {
  log.debug("Entering spendNonce().");
  if (usedNonces.has(id)) {
    log.debug("Leaving spendNonce(). Already spent.");
    return false;
  }
  if (usedNonces.size >= MAX_USED_NONCES) {
    const nowS = Math.floor(nowMs() / 1000);
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
  log.debug("Leaving spendNonce(). Spent.");
  return true;
}

module.exports = {
  MAX_USED_NONCES: MAX_USED_NONCES,
  createAccount: createAccount,
  getAccount: getAccount,
  accountByThumbprint: accountByThumbprint,
  saveAccount: saveAccount,
  rekeyAccount: rekeyAccount,
  listAccounts: listAccounts,
  createAuthorization: createAuthorization,
  getAuthorization: getAuthorization,
  saveAuthorization: saveAuthorization,
  createOrder: createOrder,
  getOrder: getOrder,
  saveOrder: saveOrder,
  recordCertificate: recordCertificate,
  getCertificate: getCertificate,
  saveCertificate: saveCertificate,
  certificateByCertId: certificateByCertId,
  certificateBySerial: certificateBySerial,
  spendNonce: spendNonce
};
