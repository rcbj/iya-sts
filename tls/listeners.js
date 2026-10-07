// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: listeners.js
//
// ---------------------------------------------------------------------------
// THE CUSTOM LISTENERS: BOUND, REBOUND AND CLOSED AS THEIR DEFINITIONS CHANGE
// (#472, 2026-10-07; a realm's own listener, #99, 2026-10-02, is one of them).
//
// `common/listener_map.js` says what the listeners are — the service's in
// `listeners.custom`, each realm's own in its `listeners.realm` — and which
// hosted application each one answers. This module OWNS THEIR SOCKETS: one
// HTTPS listener per definition, bound in the front process on every node (a
// socket is held by one process; request workers bind nothing; and no node is
// ever exposed on an address of its own, so every node binds every
// listener), built by the SAME factory as the main port (`server.js`'s
// `customListener()`: the client-certificate request and truststore, the TLS
// policy, the shared session-ticket key, keep-alive, the PROXY protocol, the
// JA4 fingerprint, the connection observer), and kept in step with the
// settings and the realm registry: a definition added, changed or removed
// binds, rebinds or closes its listener at once. A listener that cannot bind
// is RECORDED with its reason and code and shown on Server configuration ->
// Listeners and `GET /admin-api/listeners`; it never stops the service (the
// rule every socket owner here follows).
//
// A CHANGE OF TLS POLICY OR CLIENT AUTHENTICATION DOES NOT REBIND: those are
// applied in place at the next handshake by `tls_server.js`'s
// `reapplyPolicy()`, which reads a custom listener's definition through
// `policyFor('custom', id)`. Only what a socket or its certificate is made of
// — the port, the owner, the names and the certificate files — rebinds.
//
// EVERY SOCKET IS MARKED with its listener (`stsListener`), and a realm's own
// listener's with its realm as well (`stsRealmListener`): `common/app.js`
// refuses on a listener the paths of an application that is not mapped to it
// (STS-TLS-0047), and on a realm's listener the paths of any other realm
// (STS-TLS-0041); `common/request_pool.js` carries the mark to a worker.
//
// THE CERTIFICATE: an operator's (`certificateFile` and `privateKeyFile`, a
// public CA's for a browser-facing listener), or one the owning realm's
// `realm-tls` Issuing CA issues for the listener's hostnames (the default
// realm's for a service listener; rcbj's D5), one slot per listener per node
// so that one node's issuance never supersedes — and so revokes — another's.
// An issued one is renewed by the per-process `tls.listener-renew` job once
// two thirds of its life are gone.
// ---------------------------------------------------------------------------

const fs = require('fs');
const helpers = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const stsCrypto = require('../common/crypto');
const listenerMap = require('../common/listener_map');

const { log } = helpers;

const RENEW_JOB = 'tls.listener-renew';
const USE_CASE = 'realm-tls';

/**
 * @typedef {{ id: string, owner: string, port: number, publicBaseUrl: string,
 *   hostnames: string[], certificateFile: string, privateKeyFile: string,
 *   clientAuth: string, label: string }} Desired
 * @typedef {{ id: string, owner: string, desired: Desired, signature: string,
 *   server: any, state: string, why: string, code: string,
 *   certificate: { key: string, cert: string, source: string,
 *     notBefore: string, notAfter: string, serialHex: string } | null,
 *   boundAt: string }} Entry
 */

/** @type {Map<string, Entry>} */
const entries = new Map();
/** @type {any} */
let factory = null;
let started = false;
let reconciling = Promise.resolve();

// What makes a socket: a change to any of these rebinds. The TLS block and the
// client authentication are applied in place, and the public base is only
// where URLs are built, so neither is here.
function signatureOf(desired) {
  log.debug("Entering signatureOf().");
  log.debug("Leaving signatureOf().");
  return JSON.stringify({ owner: desired.owner, port: desired.port,
                          hostnames: desired.hostnames,
                          certificateFile: desired.certificateFile,
                          privateKeyFile: desired.privateKeyFile });
}

function nodeSlot(id) {
  log.debug("Entering nodeSlot(). " + id);
  let name = '';
  try {
    name = String(require('../cluster/cluster').nodeName() || '');
  } catch (e) {
    log.debug("Caught in nodeSlot(): " + ((e && e.message) || e));
  }
  log.debug("Leaving nodeSlot().");
  return 'listener:' + id + ':' + (name || require('os').hostname());
}

// The realm a listener belongs to, as a realm object `realms.run()` takes.
function ownerRealm(desired) {
  log.debug("Entering ownerRealm(). " + desired.owner);
  const realm = desired.owner === realms.DEFAULT_ID
    ? null : realms.get(desired.owner);
  log.debug("Leaving ownerRealm().");
  return realm;
}

// The certificate a listener presents: an operator's files, read whole, or
// one its owning realm's CA issues for this node.
async function certificateFor(desired) {
  log.debug("Entering certificateFor(). " + desired.id);
  if (desired.certificateFile) {
    let cert = '';
    let key = '';
    try {
      cert = fs.readFileSync(desired.certificateFile, 'utf8');
      key = fs.readFileSync(desired.privateKeyFile, 'utf8');
    } catch (e) {
      log.debug("Leaving certificateFor(). Unreadable.");
      return errorCodes.mark({ ok: false,
        why: 'the certificate or key file could not be read: ' +
             ((e && e.message) || e) }, 'STS-TLS-0040');
    }
    let notBefore = '';
    let notAfter = '';
    let serialHex = '';
    try {
      const x = stsCrypto.parseCertificate(cert);
      if (!x.checkPrivateKey(stsCrypto.privateKeyFrom(key))) {
        log.debug("Leaving certificateFor(). The key is not the cert's.");
        return errorCodes.mark({ ok: false,
          why: 'privateKeyFile is not the key of the first certificate in ' +
               'certificateFile' }, 'STS-TLS-0040');
      }
      notBefore = new Date(x.validFrom).toISOString();
      notAfter = new Date(x.validTo).toISOString();
      serialHex = x.serialNumber.toLowerCase();
    } catch (e) {
      log.debug("Leaving certificateFor(). Unparseable.");
      return errorCodes.mark({ ok: false,
        why: 'the certificate or key file is not PEM this service can read: ' +
             ((e && e.message) || e) }, 'STS-TLS-0040');
    }
    log.debug("Leaving certificateFor(). From files.");
    return { ok: true, certificate: { key: key, cert: cert, source: 'file',
                                      notBefore: notBefore,
                                      notAfter: notAfter,
                                      serialHex: serialHex } };
  }
  if (!desired.hostnames.length) {
    log.debug("Leaving certificateFor(). No names.");
    return errorCodes.mark({ ok: false,
      why: 'no DNS name to issue the certificate for: set the listener\'s ' +
           'hostnames or publicBaseUrl' }, 'STS-TLS-0040');
  }
  const pki = require('../common/pki');
  const issue = function () {
    return pki.issueTlsServerKeyPair(desired.owner, USE_CASE, {
      slot: nodeSlot(desired.id),
      label: 'listener ' + desired.id,
      commonName: desired.hostnames[0],
      dnsNames: desired.hostnames,
      ipAddresses: []
    });
  };
  const realm = ownerRealm(desired);
  const result = await (realm ? realms.run(realm, issue) : issue());
  if (!result || !result.ok) {
    log.debug("Leaving certificateFor(). The CA refused.");
    return errorCodes.mark({ ok: false,
      why: 'the ' + (realm ? 'realm\'s' : 'default realm\'s') +
           ' certificate authority did not issue one: ' +
           ((result && (result.errors || []).join(' ')) || 'no answer') },
      (result && errorCodes.codeOf(result)) || 'STS-TLS-0040');
  }
  const issued = result.issued;
  log.debug("Leaving certificateFor(). Issued.");
  return { ok: true, certificate: {
    key: issued.privateKeyPem,
    cert: [issued.certificatePem].concat(issued.chainPem || []).join(''),
    source: 'issued', notBefore: String(issued.notBefore || ''),
    notAfter: String(issued.notAfter || ''),
    serialHex: String(issued.serialHex || '') } };
}

function close(entry, why) {
  log.debug("Entering close(). " + entry.id);
  if (entry.server) {
    try {
      require('./tls_server').forgetListener(entry.server);
    } catch (e) {
      log.debug("Caught in close(): " + ((e && e.message) || e));
    }
    try {
      entry.server.close();
      if (typeof entry.server.closeIdleConnections === 'function') {
        entry.server.closeIdleConnections();
      }
    } catch (e) {
      log.debug("Caught in close(): " + ((e && e.message) || e));
    }
    log.info('tls: listener "' + entry.id + '" on port ' +
             entry.desired.port + ' is closed (' + why + ').');
  }
  entry.server = null;
  log.debug("Leaving close().");
}

async function open(desired) {
  log.debug("Entering open(). " + desired.id + " " + desired.port);
  /** @type {Entry} */
  const entry = { id: desired.id, owner: desired.owner, desired: desired,
                  signature: signatureOf(desired), server: null,
                  state: 'binding', why: '', code: '', certificate: null,
                  boundAt: '' };
  entries.set(desired.id, entry);
  const got = await certificateFor(desired);
  if (!got.ok) {
    entry.state = 'failed';
    entry.why = got.why;
    entry.code = errorCodes.codeOf(got) || 'STS-TLS-0040';
    log.error(errorCodes.tag(entry.code) + 'tls: listener "' + desired.id +
              '" on port ' + desired.port + ' was NOT bound: ' + got.why +
              '. The applications mapped to it are still answered on the ' +
              'other listeners they are on.');
    log.debug("Leaving open(). No certificate.");
    return;
  }
  entry.certificate = got.certificate;
  const label = 'listener "' + desired.id + '" (' + desired.port + ')';
  const server = factory.build(label, {
    key: got.certificate.key, cert: got.certificate.cert
  }, function () {
    return entry.certificate ? { key: entry.certificate.key,
                                 cert: entry.certificate.cert } : null;
  }, desired.id);
  server.on('secureConnection', function (socket) {
    socket.stsListener = desired.id;
    if (desired.owner !== realms.DEFAULT_ID) {
      socket.stsRealmListener = desired.owner;
    }
  });
  await new Promise(function (resolve) {
    const failed = function (e) {
      entry.state = 'failed';
      entry.why = 'the port could not be bound: ' + ((e && e.message) || e);
      entry.code = 'STS-TLS-0039';
      log.error(errorCodes.tag('STS-TLS-0039') + 'tls: listener "' +
                desired.id + '" on port ' + desired.port + ' was NOT ' +
                'bound: ' + ((e && e.message) || e) + '. The applications ' +
                'mapped to it are still answered on the other listeners ' +
                'they are on.');
      try {
        require('./tls_server').forgetListener(server);
      } catch (e2) {
        log.debug("Caught in open(): " + ((e2 && e2.message) || e2));
      }
      resolve(null);
    };
    server.once('error', failed);
    server.listen(desired.port, helpers.listenHost(), function () {
      server.removeListener('error', failed);
      server.on('error', function (e) {
        log.error(errorCodes.tag('STS-TLS-0039') + 'tls: listener "' +
                  desired.id + '" failed: ' + ((e && e.message) || e));
      });
      entry.server = server;
      entry.state = 'bound';
      entry.boundAt = new Date().toISOString();
      log.info('tls: listener "' + desired.id + '"' +
               (desired.owner !== realms.DEFAULT_ID
                 ? ' (realm "' + desired.owner + '")' : '') +
               ' is bound on port ' + desired.port + ', presenting a ' +
               got.certificate.source + ' certificate for ' +
               desired.hostnames.join(', ') + ', client certificates ' +
               desired.clientAuth + '; URLs advertised on it are built on ' +
               desired.publicBaseUrl + '.');
      resolve(null);
    });
  });
  log.debug("Leaving open().");
}

// The definitions the listeners should match: every custom listener whose
// owner is the default realm or a live realm.
function wanted() {
  log.debug("Entering wanted().");
  const out = new Map();
  let all = [];
  try {
    all = listenerMap.allListeners();
  } catch (e) {
    log.error(errorCodes.tag('STS-CORE-0157') + 'tls: the listener ' +
              'definitions could not be read (' + ((e && e.message) || e) +
              '); no custom listener changes until they can.');
    log.debug("Leaving wanted(). Unreadable.");
    return null;
  }
  all.forEach(function (one) {
    if (one.builtin) {
      return;
    }
    out.set(one.id, { id: one.id, owner: one.owner, port: one.port,
                      publicBaseUrl: one.publicBaseUrl,
                      hostnames: one.hostnames.slice(),
                      certificateFile: one.certificateFile,
                      privateKeyFile: one.privateKeyFile,
                      clientAuth: one.clientAuth, label: one.label });
  });
  log.debug("Leaving wanted(). " + out.size);
  return out;
}

/**
 * Brings the listeners in step with their definitions: binds one that is
 * new, rebinds one whose socket-making members changed, closes one that is
 * gone (its realm with it). Serialised, so two changes in a row cannot race.
 *
 * @returns a promise settled when the listeners match the definitions
 */
function reconcile() {
  log.debug("Entering reconcile().");
  if (!started) {
    log.debug("Leaving reconcile(). Not started.");
    return Promise.resolve();
  }
  reconciling = reconciling.then(async function () {
    const want = wanted();
    if (!want) {
      return;
    }
    Array.from(entries.keys()).forEach(function (id) {
      const entry = entries.get(id);
      const desired = want.get(id);
      if (!desired || signatureOf(desired) !== entry.signature) {
        close(entry, desired ? 'its definition changed'
                             : 'it is no longer defined');
        entries.delete(id);
      } else {
        // Not rebound: the public base, label and client authentication are
        // read where they are used.
        entry.desired = desired;
      }
    });
    for (const [id, desired] of want) {
      if (!entries.has(id)) {
        await open(desired);
      }
    }
  }).catch(function (e) {
    log.error(errorCodes.tag('STS-TLS-0039') + 'tls: the custom listeners ' +
              'could not be reconciled: ' + ((e && e.message) || e));
  });
  log.debug("Leaving reconcile().");
  return reconciling;
}

/**
 * Starts the custom listeners, from `server.js`'s `listen()` in the front
 * process, and keeps them in step with their definitions.
 *
 * @param build - `{ build(label, certificate, certificateOf, listenerId) }`:
 *   makes an unbound HTTPS server wired exactly as the main port is
 * @returns a promise settled when the first reconcile is done
 */
function start(build) {
  log.debug("Entering start().");
  if (started) {
    log.debug("Leaving start(). Already started.");
    return reconciling;
  }
  factory = build;
  started = true;
  realms.onChange(function () {
    reconcile();
  });
  realms.onCreate(function () {
    reconcile();
  });
  realms.onRemove(function () {
    reconcile();
  });
  if (typeof config.onOverridesChanged === 'function') {
    config.onOverridesChanged(function () {
      reconcile();
    });
  }
  registerJob();
  log.debug("Leaving start().");
  return reconcile();
}

/**
 * Re-issues an issued certificate past two thirds of its life, and applies
 * it to the listener without closing it.
 *
 * @returns a promise of how many were renewed
 */
async function renewDue() {
  log.debug("Entering renewDue().");
  let renewed = 0;
  for (const entry of entries.values()) {
    const c = entry.certificate;
    if (!entry.server || !c || c.source !== 'issued') {
      continue;
    }
    const from = Date.parse(c.notBefore);
    const to = Date.parse(c.notAfter);
    if (!(to > from) || Date.now() < from + (to - from) * 2 / 3) {
      continue;
    }
    const got = await certificateFor(entry.desired);
    if (!got.ok) {
      log.warn(errorCodes.tag(errorCodes.codeOf(got) || 'STS-TLS-0040') +
               'tls: listener "' + entry.id + '"\'s certificate could not ' +
               'be renewed: ' + got.why + '; it keeps the one it has, ' +
               'which expires ' + c.notAfter + '.');
      continue;
    }
    entry.certificate = got.certificate;
    try {
      require('./tls_server').reapplyTruststore();
    } catch (e) {
      log.debug("Caught in renewDue(): " + ((e && e.message) || e));
    }
    renewed += 1;
  }
  log.debug("Leaving renewDue(). " + renewed);
  return renewed;
}

function registerJob() {
  log.debug("Entering registerJob().");
  let scheduler = null;
  try {
    scheduler = require('../cluster/scheduler');
  } catch (e) {
    log.debug("Caught in registerJob(): " + ((e && e.message) || e));
  }
  if (!scheduler || scheduler.job(RENEW_JOB)) {
    log.debug("Leaving registerJob(). None, or already there.");
    return;
  }
  scheduler.register({
    id: RENEW_JOB,
    title: 'Custom listener certificate renewal',
    describe: 'Re-issues the certificate a custom listener presents (#472, ' +
              'a realm\'s own among them) once two thirds of its life are ' +
              'gone, from its owning realm\'s certificate authority, and ' +
              'applies it without closing the listener. An operator\'s ' +
              'certificate (the definition\'s certificateFile) is the ' +
              'operator\'s to renew.',
    owner: 'tls/listeners.js',
    kind: 'per-process', quiet: true,
    everyMs: function () {
      return 3600 * 1000;
    },
    off: function () {
      return entries.size ? '' : 'no custom listener is bound on this ' +
        'process';
    },
    run: function () {
      return renewDue().then(function (n) {
        return { summary: n + ' renewed' };
      });
    }
  });
  log.debug("Leaving registerJob().");
}

/**
 * What each custom listener on this process is doing, for the Listeners page
 * and `GET /admin-api/listeners`. Carries no private key.
 *
 * @param owner - optional; one realm's listeners only
 * @returns the rows
 */
function status(owner) {
  log.debug("Entering status().");
  const out = [];
  entries.forEach(function (entry) {
    if (owner && entry.owner !== owner) {
      return;
    }
    const c = entry.certificate;
    out.push({
      id: entry.id, owner: entry.owner, port: entry.desired.port,
      publicBaseUrl: entry.desired.publicBaseUrl,
      hostnames: entry.desired.hostnames, state: entry.state,
      why: entry.why, code: entry.code, boundAt: entry.boundAt,
      certificate: c ? { source: c.source, notBefore: c.notBefore,
                         notAfter: c.notAfter, serialHex: c.serialHex }
                     : null
    });
  });
  log.debug("Leaving status(). " + out.length);
  return out;
}

/**
 * Closes every custom listener, for a process shutting down.
 *
 * @returns nothing
 */
function stop() {
  log.debug("Entering stop().");
  entries.forEach(function (entry) {
    close(entry, 'the process is stopping');
  });
  entries.clear();
  started = false;
  log.debug("Leaving stop().");
}

module.exports = {
  start: start,
  reconcile: reconcile,
  status: status,
  stop: stop,
  renewDue: renewDue,
  RENEW_JOB: RENEW_JOB,
  USE_CASE: USE_CASE
};
