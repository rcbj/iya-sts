// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_listeners.js
//
// ---------------------------------------------------------------------------
// A TRUST REALM'S OWN FRONT-END LISTENER (#99, 2026-10-02).
//
// A realm may be served on a port of its own on every node, so that a load
// balancer of its own can stand in front of it and a DNS name of its own can
// point at that — `https://acme.example.com/realm/acme/...`. The realm is
// still told apart by its `/realm/<id>` path prefix (rcbj's decision on #99);
// what changes is the scheme, host and port every URL it builds is on
// (`listener.publicBaseUrl`, read by `helpers.pinnedBaseUrl()`), and the
// socket it is answered on. The load balancer and the DNS records are the
// deployment's — Terraform's here — and not this service's.
//
// WHAT THIS MODULE OWNS: one HTTPS listener per realm that sets
// `listener.port`, bound in the front process (a socket is held by one
// process; request workers bind nothing), built by the SAME factory as the
// main port (`server.js`'s `secureListener()`: the client-certificate request
// and truststore, the TLS policy, the shared session-ticket key, keep-alive,
// the PROXY protocol, the JA4 fingerprint, the connection observer), and kept
// in step with the realm registry: a realm created, changed or removed binds,
// rebinds or closes its listener at once, on every node, because every node
// sees the same registry. A listener that cannot bind is RECORDED with its
// reason and code and shown on the realm's page and `GET /admin-api/realms`;
// it never stops the service (the rule every socket owner here follows).
//
// THE CERTIFICATE: an operator's (`listener.certificateFile` and
// `listener.privateKeyFile`, a public CA's for a browser-facing realm), or one
// the realm's own `realm-tls` Issuing CA issues for `listener.hostnames`, one
// slot per node so that one node's issuance never supersedes — and so revokes
// — another's. An issued one is renewed by the per-process
// `tls.realm-listener-renew` job once two thirds of its life are gone.
//
// WHAT A REQUEST ON IT MAY ASK FOR: only its own realm's paths. The socket is
// marked with the realm (`stsRealmListener`), and `common/app.js`'s
// `enterRealm` refuses any other path there with a 404 (STS-TLS-0041) — the
// default realm's included — so a realm's host serves that realm and nothing
// else. The main port still serves every realm under its prefix.
// ---------------------------------------------------------------------------

const fs = require('fs');
const helpers = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');

const { log } = helpers;

const RENEW_JOB = 'tls.realm-listener-renew';
const USE_CASE = 'realm-tls';

/**
 * @typedef {{ port: number, base: string, hostnames: string[],
 *   certificateFile: string, privateKeyFile: string }} Desired
 * @typedef {{ realm: string, desired: Desired, signature: string,
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

// What a realm asks for, read inside the realm: the five settings are
// `realmOnly`, so each answers that realm's own value or its default.
function desiredOf(realm) {
  log.debug("Entering desiredOf(). " + realm.id);
  const read = function (key) {
    return realms.run(realm, function () {
      return config.value(key);
    });
  };
  const port = Number(read('listener.port')) || 0;
  const base = String(read('listener.publicBaseUrl') || '').trim()
    .replace(/\/+$/, '');
  let host = '';
  try {
    host = base ? new URL(base).hostname : '';
  } catch (e) {
    log.debug("Caught in desiredOf(): " + ((e && e.message) || e));
  }
  const listed = (/** @type {any} */ (read('listener.hostnames')) || [])
    .map(function (one) { return String(one || '').trim(); })
    .filter(Boolean);
  log.debug("Leaving desiredOf().");
  return {
    port: port,
    base: base,
    hostnames: listed.length ? listed : (host ? [host] : []),
    certificateFile: String(read('listener.certificateFile') || '').trim(),
    privateKeyFile: String(read('listener.privateKeyFile') || '').trim()
  };
}

function signatureOf(desired) {
  log.debug("Entering signatureOf().");
  log.debug("Leaving signatureOf().");
  return JSON.stringify(desired);
}

function nodeSlot() {
  log.debug("Entering nodeSlot().");
  let name = '';
  try {
    name = String(require('../cluster/cluster').nodeName() || '');
  } catch (e) {
    log.debug("Caught in nodeSlot(): " + ((e && e.message) || e));
  }
  log.debug("Leaving nodeSlot().");
  return 'listener:' + (name || require('os').hostname());
}

// The certificate a realm's listener presents: an operator's files, read
// whole, or one this realm's CA issues for this node.
async function certificateFor(realm, desired) {
  log.debug("Entering certificateFor(). " + realm.id);
  if (!!desired.certificateFile !== !!desired.privateKeyFile) {
    log.debug("Leaving certificateFor(). Half a certificate.");
    return errorCodes.mark({ ok: false,
      why: 'listener.certificateFile and listener.privateKeyFile are both ' +
           'or neither: one is set and the other is not' }, 'STS-TLS-0040');
  }
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
      const x = new (require('crypto').X509Certificate)(cert);
      if (!x.checkPrivateKey(require('crypto').createPrivateKey(key))) {
        log.debug("Leaving certificateFor(). The key is not the cert's.");
        return errorCodes.mark({ ok: false,
          why: 'listener.privateKeyFile is not the key of the first ' +
               'certificate in listener.certificateFile' }, 'STS-TLS-0040');
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
      why: 'no DNS name to issue the certificate for: set ' +
           'listener.hostnames or listener.publicBaseUrl' }, 'STS-TLS-0040');
  }
  const pki = require('../common/pki');
  const result = await realms.run(realm, function () {
    return pki.issueTlsServerKeyPair(realm.id, USE_CASE, {
      slot: nodeSlot(),
      label: 'realm ' + realm.id + ' listener',
      commonName: desired.hostnames[0],
      dnsNames: desired.hostnames,
      ipAddresses: []
    });
  });
  if (!result || !result.ok) {
    log.debug("Leaving certificateFor(). The CA refused.");
    return errorCodes.mark({ ok: false,
      why: 'the realm\'s certificate authority did not issue one: ' +
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
  log.debug("Entering close(). " + entry.realm);
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
    log.info('tls: realm "' + entry.realm + '"\'s own listener on port ' +
             entry.desired.port + ' is closed (' + why + ').');
  }
  entry.server = null;
  log.debug("Leaving close().");
}

async function open(realm, desired) {
  log.debug("Entering open(). " + realm.id + " " + desired.port);
  /** @type {Entry} */
  const entry = { realm: realm.id, desired: desired,
                  signature: signatureOf(desired), server: null,
                  state: 'binding', why: '', code: '', certificate: null,
                  boundAt: '' };
  entries.set(realm.id, entry);
  const got = await certificateFor(realm, desired);
  if (!got.ok) {
    entry.state = 'failed';
    entry.why = got.why;
    entry.code = errorCodes.codeOf(got) || 'STS-TLS-0040';
    log.error(errorCodes.tag(entry.code) + 'tls: realm "' + realm.id +
              '"\'s own listener on port ' + desired.port + ' was NOT ' +
              'bound: ' + got.why + '. The realm is still served on the ' +
              'main port under its prefix.');
    log.debug("Leaving open(). No certificate.");
    return;
  }
  entry.certificate = got.certificate;
  const label = 'realm "' + realm.id + '" (' + desired.port + ')';
  const server = factory.build(label, {
    key: got.certificate.key, cert: got.certificate.cert
  }, function () {
    return entry.certificate ? { key: entry.certificate.key,
                                 cert: entry.certificate.cert } : null;
  }, realm.id);
  server.on('secureConnection', function (socket) {
    socket.stsRealmListener = realm.id;
  });
  await new Promise(function (resolve) {
    const failed = function (e) {
      entry.state = 'failed';
      entry.why = 'the port could not be bound: ' + ((e && e.message) || e);
      entry.code = 'STS-TLS-0039';
      log.error(errorCodes.tag('STS-TLS-0039') + 'tls: realm "' + realm.id +
                '"\'s own listener on port ' + desired.port + ' was NOT ' +
                'bound: ' + ((e && e.message) || e) + '. The realm is ' +
                'still served on the main port under its prefix.');
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
        log.error(errorCodes.tag('STS-TLS-0039') + 'tls: realm "' +
                  realm.id + '"\'s own listener failed: ' +
                  ((e && e.message) || e));
      });
      entry.server = server;
      entry.state = 'bound';
      entry.boundAt = new Date().toISOString();
      log.info('tls: realm "' + realm.id + '" has its own listener on ' +
               'port ' + desired.port + ', presenting a ' +
               got.certificate.source + ' certificate for ' +
               desired.hostnames.join(', ') + '; its URLs are built on ' +
               desired.base + '.');
      resolve(null);
    });
  });
  log.debug("Leaving open().");
}

/**
 * Brings the listeners in step with the realm registry: binds a realm that
 * asks for one, rebinds one whose settings changed, closes one that no longer
 * asks or no longer exists. Serialised, so two changes in a row cannot race.
 *
 * @returns a promise settled when the listeners match the registry
 */
function reconcile() {
  log.debug("Entering reconcile().");
  if (!started) {
    log.debug("Leaving reconcile(). Not started.");
    return Promise.resolve();
  }
  reconciling = reconciling.then(async function () {
    const wanted = new Map();
    realms.list().forEach(function (realm) {
      if (realm.id === realms.DEFAULT_ID ||
          Number(realm.retiringSince) > 0) {
        return;
      }
      const desired = desiredOf(realm);
      if (desired.port > 0 && desired.base) {
        wanted.set(realm.id, { realm: realm, desired: desired });
      }
    });
    Array.from(entries.keys()).forEach(function (id) {
      const entry = entries.get(id);
      const want = wanted.get(id);
      if (!want || signatureOf(want.desired) !== entry.signature) {
        close(entry, want ? 'its settings changed' : 'the realm no longer ' +
              'asks for one');
        entries.delete(id);
      }
    });
    for (const [id, want] of wanted) {
      if (!entries.has(id)) {
        await open(want.realm, want.desired);
      }
    }
  }).catch(function (e) {
    log.error(errorCodes.tag('STS-TLS-0039') + 'tls: the realm listeners ' +
              'could not be reconciled: ' + ((e && e.message) || e));
  });
  log.debug("Leaving reconcile().");
  return reconciling;
}

/**
 * Starts the realm listeners, from `server.js`'s `listen()` in the front
 * process, and keeps them in step with the realm registry.
 *
 * @param build - `{ build(label, certificate, certificateOf, realmId) }`: makes an
 *   unbound HTTPS server wired exactly as the main port is
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
    const realm = realms.get(entry.realm);
    if (!realm) {
      continue;
    }
    const got = await certificateFor(realm, entry.desired);
    if (!got.ok) {
      log.warn(errorCodes.tag(errorCodes.codeOf(got) || 'STS-TLS-0040') +
               'tls: realm "' + entry.realm + '"\'s listener certificate ' +
               'could not be renewed: ' + got.why + '; it keeps the one it ' +
               'has, which expires ' + c.notAfter + '.');
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
    title: 'Realm listener certificate renewal',
    describe: 'Re-issues the certificate a trust realm\'s own listener ' +
              'presents (#99) once two thirds of its life are gone, from ' +
              'the realm\'s own certificate authority, and applies it ' +
              'without closing the listener. An operator\'s certificate ' +
              '(listener.certificateFile) is the operator\'s to renew.',
    owner: 'tls/realm_listeners.js',
    kind: 'per-process', quiet: true,
    everyMs: function () {
      return 3600 * 1000;
    },
    off: function () {
      return entries.size ? '' : 'no realm has a listener of its own on ' +
        'this process';
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
 * What each realm listener on this process is doing, for the realm's page
 * and `GET /admin-api/realms`. Carries no private key.
 *
 * @param id - optional; one realm
 * @returns the rows
 */
function status(id) {
  log.debug("Entering status().");
  const out = [];
  entries.forEach(function (entry) {
    if (id && entry.realm !== id) {
      return;
    }
    const c = entry.certificate;
    out.push({
      realm: entry.realm, port: entry.desired.port,
      publicBaseUrl: entry.desired.base, hostnames: entry.desired.hostnames,
      state: entry.state, why: entry.why, code: entry.code,
      boundAt: entry.boundAt,
      certificate: c ? { source: c.source, notBefore: c.notBefore,
                         notAfter: c.notAfter, serialHex: c.serialHex }
                     : null
    });
  });
  log.debug("Leaving status(). " + out.length);
  return out;
}

/**
 * Closes every realm listener, for a process shutting down.
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
