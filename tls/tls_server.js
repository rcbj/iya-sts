// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls_server.js
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE THIS SERVICE PRESENTS, THE ONES IT IS PRESENTED WITH, AND
// WHAT IT MAKES OF THEM.
//
// This file owned two HTTPS listeners of its own until 2026-09-16 and owns
// none now — the block below says what happened to them. What is left is a
// LIBRARY plus two ordinary routes on the main app (#597 deleted the other
// four, and `/tls` and `/tls/forwarded` became Monitoring → TLS connection's
// view, `connectionView()`): the server certificate
// and the hierarchy it is certified under, the client truststore a caller
// fills at runtime, the record of every client certificate presented to this
// process, and `GET /tls/sign-in`, which turns a verified one into a session.
//
// ---------------------------------------------------------------------------
// WHY ANY OF IT EXISTS, GIVEN THAT THE DEBUGGER ALREADY REPORTS THE HANDSHAKE.
//
// The parent project's PKI page builds a certificate authority in the browser —
// a Root, an Intermediate, an Issuing CA — issues a client certificate from it,
// and then has to find out whether anything on earth accepts the thing. Its api
// opens the socket and reports the handshake, because a browser cannot choose a
// client certificate, cannot be given a truststore and cannot read the
// negotiated version, cipher or chain.
//
// But that report is ONE SIDE of the exchange, and it is the side that already
// knows what it sent. What it cannot say is what the SERVER made of the
// certificate: which chain the server built out of what arrived, which anchor
// it verified against, what it read out of the leaf, and whether it considers
// the caller authenticated at all. A client that completed a handshake has
// proved that the bytes were acceptable to OpenSSL on this machine, and no
// more. Under TLS 1.3 it has not even proved that — the client is finished
// before the server has said anything about the certificate.
//
// **THE ANSWER TO THAT USED TO BE A CONNECTION ECHO, AND IT IS GONE.** The two
// listeners served a report of what the server made of the handshake, at
// `/tls/whoami` and on a page, and it was deleted with them: it is a debugging
// surface rather than a protocol, and it is being taken up in the project that
// asks the question. What this file still answers is the part that is about
// this service rather than about the connection — whose anchors verify a
// client certificate (the truststore, `/admin-api/tls/trust`), what this
// service presents (`/tls/server-certificate`), what a certificate that verified is worth
// (`/tls/sign-in`), and what arrived (the sighting, on /admin/tls).
//
// ---------------------------------------------------------------------------
// THIS MODULE OWNED TWO LISTENERS UNTIL 2026-09-16, AND OWNS NONE NOW.
//
// They were 8443 (`tls.port`), which asked every connection for a client
// certificate and accepted whatever arrived, and 9443 (`tls.mutualPort`),
// which required one at the handshake. Both settings are gone.
//
// **THE FIRST WAS REDUNDANT THE DAY THE MAIN PORT LEARNED TO ASK.**
// `server.js` binds the main listener `requestCert: true,
// rejectUnauthorized: false` whenever `global.https` is on — the same posture,
// on the port every other protocol in this service answers on — so a
// deployment was paying for three HTTPS sockets to get two behaviours, and the
// interesting one was on the port nobody was pointing at.
//
// **THE SECOND HAS NO SUCCESSOR, AND THAT IS THE DELIBERATE LOSS.** Refusing a
// connection during the handshake is a property of a SOCKET. This socket
// carries OAuth, SAML, SCIM, the console and everything else, so it cannot
// refuse every caller who has no client certificate. What a certificate is
// worth is therefore decided one layer up, where it is USED: RFC 8705 client
// authentication at the token endpoint, `/xacml`, `/scim/v2`, and
// `GET /tls/sign-in` below, which turns a verified one into a session. A
// client under test can no longer meet a TLS handshake this service refuses.
//
// What moved here rather than dying with them is argued where it now lives:
// the sighting above `observeConnectionsOn()`, the sign-in above
// `GET /tls/sign-in`. What was deleted outright is the connection ECHO — the
// report of what the server made of the handshake, at `/tls/whoami` and on a
// page — which was those listeners' whole content and is a debugging surface
// rather than a protocol.
//
// ---------------------------------------------------------------------------
// THE TRUSTSTORE IS EMPTY AT STARTUP AND IS FILLED AT RUNTIME.
//
// It has to be. The certificate authority whose clients this is meant to verify
// is generated in somebody's BROWSER, thirty seconds before the connection, and
// exists nowhere else — so there is no configuration file that could hold it
// and no image that could bake it in. `POST /admin-api/tls/trust/add` takes
// the anchors (the open `POST /tls/trust` until #597) and
// `tls.Server.setSecureContext()` applies them; existing connections are not
// disturbed, and the next handshake is judged against the new list.
//
// Two details about that are load-bearing and both were measured rather than
// assumed:
//
//   * `ca: []` means NO ANCHORS. It is not the same as omitting `ca`, which
//     selects node's bundled root store — the opposite of what is wanted here,
//     since a public root has no business verifying a client certificate issued
//     by a private CA. So the empty case is passed explicitly, and with it
//     every client certificate presented to this service is UNVERIFIED — it
//     still arrives, and everything that reads one refuses it. That is the
//     correct starting state and the truststore page (/admin/tls/trust)
//     says so.
//   * the anchors go in over the main port, which is where everything else
//     goes now too. Without `global.https` it is plain HTTP, which is the one
//     thing reachable before anything is trusted, and this is a mock: an
//     endpoint that could only be called by somebody who had already been
//     trusted would be a chicken-and-egg with a specification citation.
//
//     `global.https` — which every appconfig file in `env/` sets, and which
//     RFC 9700 and OAuth 2.1 mode turn on by default — takes that property
//     away, and it is worth knowing rather than discovering: with it on there
//     is no plain listener in this process at all, so the FIRST fetch of
//     /tls/server-certificate and the first call to /admin-api have to be made
//     without verifying the certificate (`curl -k`). That is the ordinary
//     bootstrap for a certificate regenerated on every start — it is the same
//     act as trusting the PEM this endpoint hands back, done a step earlier.
//     Monitoring → TLS connection says whether the request it describes
//     arrived over HTTPS (the view's `connection.https`, #597).
//
// ---------------------------------------------------------------------------
// AND IT AUTHENTICATES PEOPLE THE WAY THE REST OF THIS SERVICE DOES, WHICH IS
// PERMISSIVELY (2026-09-05).
//
// **THIS SECTION SAID "IT AUTHENTICATES NOBODY" UNTIL THAT DAY AND THE REASON
// IT SAID SO IS WORTH KEEPING.** A verified client certificate here means one
// thing exactly: a chain was built from what the client sent to an anchor
// somebody POSTed to this process. No revocation was checked then, so a
// revoked certificate verified here and would not have verified anywhere that
// matters (revocation is consulted since 2026-09-12 — `checkedSocket()`).
// A mock that quietly turned a certificate into a TRUSTWORTHY identity would
// teach a client something false about every server it will meet afterwards.
//
// **WHAT CHANGED IS THE SESSION, NOT THE STRENGTH OF THE CLAIM.** PKI
// client-certificate authentication is a real, deployed way for a person to
// sign in to a web application, and this service exists to exercise clients of
// exactly that kind. Every other family here resolves the same tension the same
// way in development mode and always has: the KDC issues tickets to anybody
// who asks with the one shared password, the sign-in screen checks no password
// at all, LDAP refuses no bind — and all three start real sessions (product
// mode verifies all three). **The permissiveness lives in
// what is ACCEPTED, not in refusing to record what was accepted.** Refusing the
// session was the one place this service made the opposite choice, and what it
// cost was that a global sign-out could not end a way in that it could not see.
//
// So a request to `GET /tls/sign-in` on a connection carrying a verified
// certificate starts a session for its common name;
// `startCertificateSession()` below performs it and argues the details, and
// every report this file emits says in the same breath what the revocation
// check found. It was every request to either deleted listener until
// 2026-09-16, which meant loading a diagnostic page signed you in — a route
// that has to be asked for is the better shape as well as the only one left.
// ---------------------------------------------------------------------------

const https = require('https');
const tls = require('tls');
const fs = require('fs');
const forge = require('node-forge');
// The RSA keygen-and-self-sign skeleton this shares with `common/helpers.js`
// lives in one module since 2026-08-27. What is NOT shared is anything below —
// the extensions, and the subjectAltName that is the only place the names are.
const stsCrypto = require('../common/crypto');
const app = require('../common/app');
const helpers = require('../common/helpers');
// THE CLUSTER BARRIER (2026-09-14, #46 section 4). It covered the two deleted
// listeners, which were not the express app; what still needs it is
// `GET /tls/sign-in`, which starts a session and must not answer before that
// session has committed. A library; app.js has already loaded it.
const clusterBarrier = require('../cluster/cluster_barrier');

// The input validator was required here for the two `/tls` pages' one
// parameter; both pages were deleted by #597, and nothing else here takes a
// parameter it has to check.
const { log, baseUrlOf } = helpers;
// WHAT A FORWARDED HEADER IS BELIEVED FROM (#597): Monitoring → TLS
// connection reports what `client_address.js` made of this request's
// forwarding headers. A leaf (config and the cache registry); it registers
// nothing.
const clientAddress = require('../common/client_address');
// The single funnel every authentication in this service passes through at the
// moment a credential is ACCEPTED. A verified client certificate is one, and
// going through here rather than writing to the console and the directory
// directly is what keeps it one call site and not three — see the note above
// recordClientCertificate().
const stats = require('../common/admin_stats');
const config = require('../common/config');
// A PLAIN REQUIRE IN THE ORDINARY DIRECTION, and rule 3e's test is why it needs
// no slot. `authn.js` is required at 8 and this module at 20, so by the time
// this line runs that module is a CACHE HIT and registers nothing — no route
// moves. And it does not require this one back, so no cycle closes. What
// crosses is `startSession()` and `sessionOf()`, for the certificate sign-in
// below.
const authn = require('../authn/authn');
// ERROR CODES and the audit log. Both already in this closure through authn.js.
// A failed handshake reaches a listener as a socket error and never as a
// request, so it has no call log to carry a code: it is recorded with
// audit.failure() in `observeConnectionsOn()`. The views on the main port are
// ordinary routes and mark the response.
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
// #507: the master-secret digest a TLS 1.2 ticket's name is kept under is
// `stsCrypto.sha256Hex()` (every digest goes through common/crypto.js,
// tests/crypto_centralised.js), and this is the room-maker for its
// replicated store (rule 3ap).
const cacheRegistry = require('../common/cache_registry');
// The PROXY protocol v2 reader was required here until 2026-09-16 and is not
// any more: it was installed on this module's two listeners, and with those
// deleted the only installs are `server.js`'s on the main port and the
// debugger's on its own. Nothing in this file reads a proxied address.
// REVOCATION, CONSULTED (2026-09-12). A LIBRARY that registers no route; it
// requires `common/pki.js`, which this module already loads at require time to
// register its certificate with it. A verified certificate is checked BEFORE
// its session starts and before its authentication is recorded, and the report
// says what the check found — see `checkedSocket()` below.
const revocationStatus = require('../common/revocation_status');

// THE PORT THIS SERVICE ANSWERS ON, for the audit rows and the report below.
// It was `tls.port` (8443) and `tls.mutualPort` (9443) until 2026-09-16, when
// both listeners were deleted: what a client certificate is presented to now
// is the main port, which `server.js` binds `requestCert: true,
// rejectUnauthorized: false`.
const MAIN_PORT = config.value('global.port');


// The names the server certificate is issued for. A caller reaches this stack
// as `localhost` from a host run, as `sts` from the compose network and as
// `127.0.0.1` from whatever is easiest, and a certificate that named only one
// of them would produce a hostname-verification failure that is about this file
// rather than about anything the reader is debugging.
const TLS_HOSTNAMES = config.value('tls.hostnames');
const TLS_IPS = config.value('tls.ips');

// A truststore is a list of anchors, not a certificate store dump. The cap is
// generous for any private PKI and stops a caller handing over a body that
// costs more to parse than the handshakes it will be used for.
const MAX_ANCHORS = 32;
// The anchors of each listener's own trustAnchorsFile (#429), by path.
const listenerFileCache = new Map();

// ---------------------------------------------------------------------------
// THE MODE, UNDER A NAME THAT IS NOT `mode` (2026-09-12). This module already
// calls a listener's client-certificate posture `mode` ('optional' or
// 'required') in a dozen places, and a module-level `mode` beside them would be
// shadowed in exactly the functions a reader is likeliest to look for it in.
// A LEAF requiring only `config`; `helpers.js` above already requires it.
// ---------------------------------------------------------------------------
const serviceMode = require('../common/mode');
// A person's identity verifications (#127): a certificate sign-in records an
// electronic_signature one. A library; it registers nothing.
const identityAssurance = require('../common/identity_assurance');
// For the one question below that must be asked of the PROCESS rather than of
// the ambient realm. A LEAF this module's closure already holds (`app.js` and
// `helpers.js` both require it).
const realms = require('../common/realms');
// THE CUSTOM LISTENERS' DEFINITIONS (#472): a custom listener's TLS policy and
// client authentication are members of its definition. A LEAF (it requires
// the settings, the realms and the catalogue of applications).
const listenerMap = require('../common/listener_map');
// WHICH CELL SIGNS A CERTIFICATE'S HOLDER IN (#98): the cell map and the
// placement helper. Libraries that register nothing; their own requires of
// the channel and the routing index are lazy.
const cells = require('../common/cells');
const cellPlacement = require('../common/cell_placement');

// ---------------------------------------------------------------------------
// THE PROTOCOL FLOOR AND THE CIPHER LIST, FOR EVERY TLS SOCKET THIS PROCESS
// OWNS (2026-09-12).
//
// `tls.minVersion` and `tls.ciphers`. They go into `secureContextOptions()`,
// which is what `applyAnchors()` hands every registered listener — the main
// HTTPS port among them — so one function is where the policy is stated;
// `ldap/ldap_server.js` asks it for LDAPS.
//
// The floor is node's own (TLSv1.2). THE CIPHER LIST IS BCP 195 SINCE #140
// (2026-09-22, rcbj's decision): the TLS 1.3 suites first, then only RFC 9325
// section 4.2's four ECDHE AES-GCM suites for TLS 1.2 — FAPI 2.0 section
// 5.2.2's requirement, made the default of every listener because a cipher
// suite belongs to the socket and not to a realm. `honorCipherOrder` makes the
// SERVER's order win, which is what puts TLS 1.3's and the strongest TLS 1.2
// suites first whatever a client lists. An empty `tls.ciphers` still means
// `tls.DEFAULT_CIPHERS`.
//
// AND THE GROUPS AND SIGNATURE ALGORITHMS SINCE #212 (2026-09-26):
// `tls.groups` (node's ecdhCurve) and `tls.signatureAlgorithms` (sigalgs).
// tlsfuzzer found node's defaults offering one of OpenSSL's three post-quantum
// hybrid groups and both finite-field ones, and advertising DSA and SHA-224 in
// every TLS 1.2 CertificateRequest; each row in common/config.js says what
// its default is instead and why.
//
// **A CIPHER LIST THAT MATCHES NOTHING STOPS THE SERVICE HERE**, at require
// time, naming the setting. Found any later it is a TypeError out of
// `https.createServer()` in `server.js`, or — worse, through
// `setSecureContext()` on a truststore change — a listener that silently keeps
// its old context while the page says the new one is in force.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE LISTENERS' POLICY (#423, 2026-10-02, rcbj's request): TLS 1.2 off or
// on, the TLS 1.3 cipher suites chosen one by one, post-quantum safe only, and
// whether a listener asks for a client certificate, requires one, or neither.
//
// A POLICY is what one listener is held to: `{ disableTls12, pqcOnly,
// tls13Suites, clientAuth }`. `policyFor(kind, realmId)` builds it from the
// settings — the process's `tls.*` and per-listener toggles, and for a realm's
// own listener (#99) the realm's `listener.*` rows, which inherit the
// process's unless set. `protocolOptions(policy)` turns it into node's
// options; with no argument it is the PROCESS's policy, which is what every
// caller that predates this passes.
//
// WHAT "POST-QUANTUM SAFE" MEANS HERE, because a TLS 1.3 cipher suite names
// only the record protection — the AEAD and its hash — and the key exchange
// is the GROUP. Grover's algorithm halves a symmetric key, so the 256-bit
// suites keep 128 bits against a quantum adversary and the 128-bit ones 64;
// and what stops a session recorded today being decrypted later is an ML-KEM
// key exchange, which TLS 1.2 has none of in OpenSSL. So pqcOnly is all
// three: TLS 1.3, the 256-bit suites, the ML-KEM groups. It does not touch the
// signature algorithms: authentication cannot be broken retroactively.
//
// THESE ARE RUNTIME SETTINGS, AND A LISTENER BAKES ITS POLICY IN. The floor,
// the suites and the groups are in its secure context; whether it asks for a
// certificate is a property of the server (node reads `server.requestCert`
// and `server.rejectUnauthorized` at every connection). So a change is
// re-applied here — `reapplyPolicy()`, called whenever an override or a realm
// row changes — to every listener registered with this module, and handed to
// the appliers other modules registered for listeners this module cannot
// re-key itself (SPIFFE's gRPC servers, the channel between cells). Only a
// listener whose policy CHANGED is touched.
// ---------------------------------------------------------------------------

/**
 * The five TLS 1.3 cipher suites RFC 8446 defines, with what this service
 * says about each.
 */
const TLS13_SUITES = {
  TLS_AES_256_GCM_SHA384: { keyBits: 256, postQuantum: true },
  TLS_CHACHA20_POLY1305_SHA256: { keyBits: 256, postQuantum: true },
  TLS_AES_128_GCM_SHA256: { keyBits: 128, postQuantum: false },
  TLS_AES_128_CCM_SHA256: { keyBits: 128, postQuantum: false },
  TLS_AES_128_CCM_8_SHA256: { keyBits: 128, postQuantum: false }
};

// The key-exchange groups OpenSSL 3.5 implements with ML-KEM in them: the
// three hybrids and the three pure sets. Compared without case, as OpenSSL
// reads a groups list.
const PQ_GROUPS = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024',
                   'MLKEM512', 'MLKEM768', 'MLKEM1024'];
const PQ_DEFAULT_GROUPS =
  'X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024';

// The settings each kind of listener reads its client authentication from.
// A kind with no row here — SPIFFE's gRPC servers, the channel between cells
// — has it fixed by its protocol (spiffe/CLAUDE.md, common/CLAUDE.md).
const CLIENT_AUTH_SETTINGS = {
  main: ['tls.mainPortDisableOptionalClientCertificate',
         'tls.mainPortRequireClientCertificate'],
  ldaps: ['ldap.ldapsDisableOptionalClientCertificate',
          'ldap.ldapsRequireClientCertificate'],
  debugger: ['debugger.disableOptionalClientCertificate',
             'debugger.requireClientCertificate']
};
// A CUSTOM LISTENER (#472; a realm's own since #99 is one) carries its client
// authentication in its definition — `clientAuth`, none / optional /
// required — rather than in a pair of settings: `customClientAuth()`.

// A list setting as an array of trimmed, non-empty entries.
function listOf(raw) {
  log.debug("Entering listOf().");
  const out = (Array.isArray(raw) ? raw : String(raw || '').split(','))
    .map(function (one) { return String(one).trim(); })
    .filter(function (one) { return one.length > 0; });
  log.debug("Leaving listOf(). " + out.length);
  return out;
}

/**
 * The 256-bit TLS 1.3 suites of a list, in its order.
 *
 * @param suites - suite names
 * @returns those post-quantum safe
 */
function postQuantumSuites(suites) {
  log.debug("Entering postQuantumSuites().");
  const out = suites.filter(function (name) {
    return !!(TLS13_SUITES[name] && TLS13_SUITES[name].postQuantum);
  });
  log.debug("Leaving postQuantumSuites(). " + out.length);
  return out;
}

/**
 * An OpenSSL groups list with only its ML-KEM groups kept, tuples and order
 * as written; empty where it held none.
 *
 * @param groups - the groups list (`tls.groups`)
 * @returns the post-quantum part
 */
function postQuantumGroups(groups) {
  log.debug("Entering postQuantumGroups().");
  const wanted = PQ_GROUPS.map(function (one) { return one.toLowerCase(); });
  const out = String(groups || '').split('/').map(function (tuple) {
    return tuple.split(':').map(function (one) { return one.trim(); })
      .filter(function (one) {
        return wanted.indexOf(one.replace(/^\*/, '').toLowerCase()) >= 0;
      }).join(':');
  }).filter(function (tuple) { return tuple.length > 0; }).join(' / ');
  log.debug("Leaving postQuantumGroups(). " + out);
  return out;
}

// What a client-authentication pair of toggles means. Require wins.
function clientAuthFrom(disableOptional, require) {
  log.debug("Entering clientAuthFrom().");
  const mode = require ? 'required' : disableOptional ? 'none' : 'optional';
  log.debug("Leaving clientAuthFrom(). " + mode);
  return mode;
}

// ---------------------------------------------------------------------------
// EVERY SETTING PER LISTENER, INHERITING THE SERVICE'S (#429, 2026-10-02).
//
// A listener's own row is `listener<Id>.<name>` (generated in common/config.js
// from `PER_LISTENER_SETTINGS`), and a custom listener's (#472, a realm's own
// among them) is the same name in its definition's `tls` block
// (`common/listener_map.js`), kind `custom` and the listener's id where a
// realm id was. `own()` answers that value, or undefined where it says
// inherit — `inherit` in an enum, the empty string otherwise, -1 for a number
// — or the listener has no such value; `pick()` falls back to the
// service-wide row.
// ---------------------------------------------------------------------------
const LISTENER_KINDS = ['main', 'ldaps', 'debugger', 'spiffeServer',
                        'spiffeBroker', 'cell', 'revocation'];

// A listener's own value for one setting, or undefined to inherit.
function ownValue(kind, realmId, name) {
  log.debug("Entering ownValue(). " + kind + " " + name);
  let raw;
  try {
    if (kind === 'custom') {
      const one = listenerMap.listenerById(String(realmId || ''));
      raw = one && Object.prototype.hasOwnProperty.call(one.tls, name)
        ? one.tls[name] : undefined;
    } else if (LISTENER_KINDS.indexOf(String(kind)) >= 0) {
      raw = config.value('listener' + String(kind).charAt(0).toUpperCase() +
                         String(kind).slice(1) + '.' + name);
    }
  } catch (e) {
    // No such row for this listener — the table leaves it out on purpose
    // (tls13 only on the cell channel, no truststore on SPIFFE's).
    log.debug("Caught in ownValue(): " + ((e && e.message) || e));
    raw = undefined;
  }
  log.debug("Leaving ownValue().");
  // -1 is an integer row's inherit (it has no empty value).
  if (raw === undefined || raw === null || raw === 'inherit' || raw === -1 ||
      (typeof raw === 'string' && raw.trim() === '') ||
      (Array.isArray(raw) && !raw.length)) {
    return undefined;
  }
  return raw === 'on' ? true : raw === 'off' ? false : raw;
}

// A custom listener's client authentication, from its definition: `none`,
// `optional` (the default, as the main port's) or `required`. A listener
// that has gone since it registered answers optional; it is about to be
// forgotten.
function customClientAuth(id) {
  log.debug("Entering customClientAuth(). " + id);
  const one = listenerMap.listenerById(id);
  log.debug("Leaving customClientAuth().");
  return one && one.clientAuth ? one.clientAuth : 'optional';
}

/**
 * The policy one listener is held to: each of its own settings where it has
 * one, the service-wide setting where it inherits.
 *
 * @param kind - `main`, `ldaps`, `debugger`, `spiffeServer`, `spiffeBroker`,
 *   `cell` or `custom`; omitted, the service-wide policy
 * @param realmId - for `custom`, the listener's id (#472)
 * @returns `{ kind, realm, minVersion, disableTls12, pqcOnly, tls13Suites,
 *   ciphers12, groups, sigalgs, trustAnchorsFile, trustIssued, clientAuth }`;
 *   `clientAuth` is null for a kind whose protocol decides it
 */
function policyFor(kind, realmId) {
  log.debug("Entering policyFor(). " + kind + " " + (realmId || ''));
  const pick = function (name, base) {
    const own = kind ? ownValue(kind, realmId, name) : undefined;
    return own !== undefined ? own : config.value(base);
  };
  // `spiffe` was one kind for both gRPC surfaces until #429.
  const k = kind === 'spiffe' ? 'spiffeServer' : kind;
  const pqcOnly = pick('pqcOnly', 'tls.pqcOnly') === true;
  let suites = listOf(pick('tls13CipherSuites', 'tls.tls13CipherSuites'));
  let clientAuth = null;
  const pair = CLIENT_AUTH_SETTINGS[String(k || '')];
  if (k === 'custom') {
    clientAuth = customClientAuth(String(realmId || ''));
  } else if (pair) {
    clientAuth = clientAuthFrom(config.value(pair[0]) === true,
                                config.value(pair[1]) === true);
  }
  // A suite list that holds nothing usable falls back to the default rather
  // than a listener with no TLS 1.3 at all; the write rule refuses such a
  // list before it is stored, so this is a store edited by hand.
  suites = suites.filter(function (name) { return !!TLS13_SUITES[name]; });
  if (!suites.length) {
    suites = ['TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256',
              'TLS_CHACHA20_POLY1305_SHA256'];
  }
  if (pqcOnly) {
    const kept = postQuantumSuites(suites);
    suites = kept.length ? kept : ['TLS_AES_256_GCM_SHA384'];
  }
  const disableTls12 = pick('disableTls12', 'tls.disableTls12') === true ||
    pqcOnly || k === 'cell';
  const ownAnchors = kind ? ownValue(k, realmId, 'trustAnchorsFile')
                          : undefined;
  const policy = {
    kind: String(k || 'process'), realm: realmId || null,
    minVersion: String(pick('minVersion', 'tls.minVersion') || 'TLSv1.2'),
    disableTls12: disableTls12, pqcOnly: pqcOnly, tls13Suites: suites,
    ciphers12: String(pick('ciphers', 'tls.ciphers') || '').trim(),
    groups: String(pick('groups', 'tls.groups') || '').trim(),
    sigalgs: String(pick('signatureAlgorithms', 'tls.signatureAlgorithms') ||
                    '').trim(),
    // The listener's OWN anchors file, which replaces the service's file
    // anchors for it; '' where it inherits them.
    trustAnchorsFile: ownAnchors === undefined ? '' : String(ownAnchors),
    trustIssued: pick('trustIssuedClientCertificates',
                      'tls.trustIssuedClientCertificates') !== false,
    // THE TLS SESSION CACHE (#429): how long a session resumes, and how many
    // session IDs this listener keeps (`attachSessionCache()`).
    sessionTimeoutS: Math.max(1, Number(pick('sessionTimeoutS',
                                             'tls.sessionTimeoutS')) || 300),
    sessionCacheSize: Math.max(0, Number(pick('sessionCacheSize',
                                              'tls.sessionCacheSize')) || 0),
    clientAuth: clientAuth
  };
  log.debug("Leaving policyFor().");
  return policy;
}

// The TLS 1.2 suites of `tls.ciphers`: the setting as written, or node's
// default list without its TLS 1.3 names where it is empty.
function tls12Ciphers(listed) {
  log.debug("Entering tls12Ciphers().");
  const raw = String(listed === undefined ? config.value('tls.ciphers') || ''
                                          : listed).trim();
  const out = (raw || tls.DEFAULT_CIPHERS).split(':')
    .map(function (one) { return one.trim(); })
    .filter(function (one) { return one.length > 0 && !/^TLS_/.test(one); });
  log.debug("Leaving tls12Ciphers(). " + out.length);
  return out;
}

/**
 * Returns the TLS protocol options a listener uses: the floor (TLS 1.3 when
 * TLS 1.2 is disabled), the TLS 1.3 suites the policy names followed by
 * `tls.ciphers`' TLS 1.2 suites, the groups (only the ML-KEM ones under
 * pqcOnly), `tls.signatureAlgorithms`, the server's cipher order honoured,
 * and no renegotiation.
 *
 * @param policy - from `policyFor()`; omitted, the process's
 * @returns the options, for a TLS server or secure context
 */
function protocolOptions(policy) {
  log.debug("Entering protocolOptions().");
  const p = policy || policyFor();
  const floor = String(p.minVersion || 'TLSv1.2');
  // `any`: the setting is a string, and the TLS types want a version literal.
  /** @type {any} */
  const options = { minVersion: p.disableTls12 ? 'TLSv1.3' : floor,
                    honorCipherOrder: true };
  // ONE STRING, AS NODE TAKES IT: names beginning TLS_ are the TLS 1.3 suites
  // (SSL_CTX_set_ciphersuites), the rest the TLS 1.2 list. A string with no
  // TLS_ name in it would turn TLS 1.3 OFF, which is why the suites are
  // always first and never empty (policyFor()).
  options.ciphers = p.tls13Suites
    .concat(p.disableTls12 ? [] : tls12Ciphers(p.ciphers12)).join(':');
  // THE GROUPS AND THE SIGNATURE ALGORITHMS (#212, 2026-09-26) — see their
  // rows in common/config.js. Empty leaves node's own: 'auto' for the
  // groups, and OpenSSL's list for the signature algorithms.
  const groups = String(p.groups || '').trim();
  if (p.pqcOnly) {
    options.ecdhCurve = postQuantumGroups(groups) || PQ_DEFAULT_GROUPS;
  } else if (groups) {
    options.ecdhCurve = groups;
  }
  const sigalgs = String(p.sigalgs || '').trim();
  if (sigalgs) {
    options.sigalgs = sigalgs;
  }
  // NO TLS 1.2 RENEGOTIATION, IN EITHER DIRECTION (#212, 2026-09-26).
  // tlsfuzzer's test-renegotiation-disabled found the main port accepting a
  // client-initiated secure renegotiation (node only counts them, three per
  // ten minutes, and then drops the socket). Nothing in this service
  // renegotiates — a client certificate is asked for in the first handshake
  // — and each renegotiation is a full handshake's CPU spent at the peer's
  // choosing, so OpenSSL refuses every one with a no_renegotiation warning.
  // TLS 1.3 has no renegotiation to refuse.
  options.secureOptions = stsCrypto.TLS_NO_RENEGOTIATION;
  // How long a session may be resumed (#429): a ticket's lifetime and the
  // session cache's. In the context, so every re-application carries it.
  if (p.sessionTimeoutS) {
    options.sessionTimeout = p.sessionTimeoutS;
  }
  log.debug("Leaving protocolOptions().");
  return options;
}

/**
 * Node's `requestCert` and `rejectUnauthorized` for a client-authentication
 * mode.
 *
 * @param mode - `none`, `optional` or `required`
 * @returns the two options
 */
function clientAuthOptions(mode) {
  log.debug("Entering clientAuthOptions(). " + mode);
  log.debug("Leaving clientAuthOptions().");
  return { requestCert: mode !== 'none',
           rejectUnauthorized: mode === 'required' };
}

// THE RULES BETWEEN THESE SETTINGS, asked at every write (config.js's
// `addWriteRule()`): a TLS 1.3 suite list may not be empty, `tls.ciphers` may
// not carry a TLS 1.3 name (that is tls.tls13CipherSuites' now), and
// post-quantum only may not be on while the suites or the groups hold nothing
// post-quantum — each of those would leave every listener refusing every
// client, which is worse than refusing the write.
function policyWriteRule(key, parsed) {
  log.debug("Entering policyWriteRule(). " + key);
  const refuse = function (problem) {
    log.debug("Leaving policyWriteRule(). Refused.");
    return { problem: problem, code: 'STS-TLS-0043' };
  };
  // ONE LISTENER'S OWN ROW (#429): the same rule, read for that listener —
  // its own value where it has one (the one being written included), the
  // service's where it inherits.
  const one = /^listener([A-Z][A-Za-z]*)\.(pqcOnly|tls13CipherSuites|groups)$/
    .exec(String(key));
  if (one) {
    const kind = one[1].charAt(0).toLowerCase() + one[1].slice(1);
    const written = String(parsed === undefined || parsed === null ? ''
                                                                   : parsed);
    const inherits = written === '' || written === 'inherit';
    const valueOf = function (name, base) {
      if (name === one[2] && !inherits) {
        return written === 'on' ? true : written === 'off' ? false : parsed;
      }
      const own = name === one[2] ? undefined : ownValue(kind, null, name);
      return own !== undefined ? own : config.value(base);
    };
    if (valueOf('pqcOnly', 'tls.pqcOnly') === true) {
      if (!postQuantumSuites(listOf(valueOf('tls13CipherSuites',
                                            'tls.tls13CipherSuites'))).length) {
        return refuse('post-quantum only on the ' + kind + ' listener needs ' +
                      'a 256-bit TLS 1.3 suite in its suites (its own, or ' +
                      'tls.tls13CipherSuites, which it inherits) — ' +
                      'TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256.');
      }
      const groups = String(valueOf('groups', 'tls.groups') || '');
      if (groups.trim() && !postQuantumGroups(groups)) {
        return refuse('post-quantum only on the ' + kind + ' listener needs ' +
                      'an ML-KEM group in its groups (its own, or ' +
                      'tls.groups, which it inherits).');
      }
    }
    log.debug("Leaving policyWriteRule(). A listener's row, accepted.");
    return null;
  }
  if (key === 'tls.tls13CipherSuites' && !listOf(parsed).length) {
    return refuse('"tls.tls13CipherSuites" needs at least one suite: with ' +
                  'none, no listener completes a TLS 1.3 handshake.');
  }
  if (key === 'tls.ciphers' && /(^|:)\s*TLS_/.test(String(parsed || ''))) {
    return refuse('"tls.ciphers" is the TLS 1.2 list; the TLS 1.3 suites ' +
                  'are chosen in tls.tls13CipherSuites.');
  }
  const pqc = key === 'tls.pqcOnly' ? parsed === true
    : config.value('tls.pqcOnly') === true;
  if (pqc && ['tls.pqcOnly', 'tls.tls13CipherSuites',
              'tls.groups'].indexOf(key) >= 0) {
    const suites = key === 'tls.tls13CipherSuites' ? listOf(parsed)
      : listOf(config.value('tls.tls13CipherSuites'));
    if (!postQuantumSuites(suites).length) {
      return refuse('post-quantum only (tls.pqcOnly) needs a 256-bit TLS 1.3 ' +
                    'suite in tls.tls13CipherSuites — TLS_AES_256_GCM_SHA384 ' +
                    'or TLS_CHACHA20_POLY1305_SHA256 — and the list holds ' +
                    'none.');
    }
    const groups = key === 'tls.groups' ? String(parsed || '')
      : String(config.value('tls.groups') || '');
    if (groups.trim() && !postQuantumGroups(groups)) {
      return refuse('post-quantum only (tls.pqcOnly) needs an ML-KEM group ' +
                    'in tls.groups (X25519MLKEM768, SecP256r1MLKEM768, ' +
                    'SecP384r1MLKEM1024, MLKEM512/768/1024), and the list ' +
                    'holds none.');
    }
  }
  log.debug("Leaving policyWriteRule().");
  return null;
}

if (typeof config.addWriteRule === 'function') {
  config.addWriteRule(policyWriteRule);
}

(function checkProtocolOptions() {
  log.debug("Entering checkProtocolOptions().");
  // A TLS 1.3 NAME IN tls.ciphers, OR A POLICY THAT HOLDS NOTHING, IS A
  // VALUE THAT REACHED HERE FROM THE ENVIRONMENT OR A FILE, where no write
  // rule asked: the same rules, at startup, where they stop the service.
  for (const key of ['tls.ciphers', 'tls.tls13CipherSuites', 'tls.pqcOnly']) {
    const ruled = policyWriteRule(key, config.value(key));
    if (ruled) {
      log.fatal(errorCodes.tag('STS-TLS-0042') + 'tls: NOT STARTING. ' +
                ruled.problem);
      process.exit(1);
    }
  }
  try {
    tls.createSecureContext(protocolOptions());
    tls.createSecureContext(protocolOptions(Object.assign({}, policyFor(),
      { disableTls12: false, pqcOnly: false })));
  } catch (e) {
    log.fatal(errorCodes.tag('STS-TLS-0001') + 'tls: NOT STARTING. ' +
              'tls.minVersion / tls.ciphers / tls.tls13CipherSuites / ' +
              'tls.groups / tls.signatureAlgorithms (STS_TLS_MIN_VERSION / ' +
              'STS_TLS_CIPHERS / STS_TLS_TLS13_CIPHER_SUITES / ' +
              'STS_TLS_GROUPS / STS_TLS_SIGALGS) cannot ' +
              'build a TLS context: ' + e.message + '. An OpenSSL cipher ' +
              'list names suites such as ECDHE-RSA-AES256-GCM-SHA384, a ' +
              'groups list names groups such as X25519MLKEM768:P-256, a ' +
              'signature list schemes such as rsa_pss_rsae_sha256, and an ' +
              'empty one means node\'s default.');
    process.exit(1);
  }
  // THEN EVERY LISTENER'S OWN POLICY BUILDS — after the service-wide one,
  // so an inherited bad value is named by its service-wide setting —, AND EVERY OWN ANCHORS FILE READS
  // (#429): a listener whose rows build no context would refuse every
  // client, found only at its first handshake.
  for (const kind of LISTENER_KINDS) {
    const policy = policyFor(kind);
    try {
      tls.createSecureContext(protocolOptions(policy));
      // ITS TLS 1.2 LIST TOO, WHEN TLS 1.2 IS OFF: the context above does not
      // carry it then, and a list matching nothing would otherwise be found
      // only by whoever turns TLS 1.2 back on (#429 made off the default).
      tls.createSecureContext(protocolOptions(Object.assign({}, policy,
        { disableTls12: false, pqcOnly: false })));
    } catch (e) {
      log.fatal(errorCodes.tag('STS-TLS-0001') + 'tls: NOT STARTING. The ' +
                kind + ' listener\'s own TLS settings (listener' +
                kind.charAt(0).toUpperCase() + kind.slice(1) + '.*) cannot ' +
                'build a TLS context: ' + e.message + '.');
      process.exit(1);
    }
    if (policy.trustAnchorsFile &&
        !listenerFileAnchors(policy.trustAnchorsFile).length) {
      log.fatal(errorCodes.tag('STS-TLS-0045') + 'tls: NOT STARTING. The ' +
                kind + ' listener\'s own trustAnchorsFile is "' +
                policy.trustAnchorsFile + '" and it could not be read or ' +
                'holds no -----BEGIN CERTIFICATE----- block, so that ' +
                'listener\'s client truststore would be empty while ' +
                'configured to be filled.');
      process.exit(1);
    }
  }
  log.debug("Leaving checkProtocolOptions().");
})();

// ---------------------------------------------------------------------------
// THE CLIENT TRUSTSTORE BELONGS TO THE PROCESS THAT TERMINATES TLS, AND THAT
// IS THE FRONT PROCESS (2026-09-08).
//
// This was briefly a shared, persisted store, on the theory that `POST
// /tls/trust` could land on a request worker while the handshake it exists for
// happens somewhere else. It cannot: `request_pool.js`'s `NEVER_DISPATCHED`
// names `/tls` precisely so that every route in this module is answered by the
// process holding the listeners. So one array in that process is the whole of
// it, and a store would have implied a sharing that does not happen — the
// workers never write here and would report an empty truststore either way.
//
// **AND IT IS PERSISTED AGAIN SINCE 2026-09-12, FOR A DIFFERENT REASON.** The
// argument above is about SHARING and still holds: the array is the listeners',
// and only this process applies it. What changed is SURVIVING a restart — a
// runtime anchor is written to ou=trustAnchors in the default realm's directory
// and read back from there, and a change another process makes to that
// container is re-applied here. See `setTrustAnchorStore()`. The array is still
// the one thing a handshake reads.
//
// **WHAT ACTUALLY WENT WRONG WAS A TEST**, and it is recorded here because the
// symptom pointed at this file for a day: `sts_route_inputs` drives every route
// it can find, `POST /tls/trust/clear` needs no credential and succeeds, and a
// remote PEP eleven jobs later then authenticated as nobody with a perfectly
// good certificate. That job skips the route by name now, which is the second
// entry on a list `tests/CLAUDE.md` argues.
// ---------------------------------------------------------------------------

// State every registered listener shares (the two this module owned until
// 2026-09-16, and now the main port and the debugger's).
let anchors = [];
let listenError = null;

// ---------------------------------------------------------------------------
// The server certificate.
//
// Generated at start and never written to a file, because a certificate
// committed to a repository is a private key committed to a repository —
// and where minted state persists, the KEY is kept per node in the sealed
// store (*THE LISTENER KEY IS KEPT PER NODE*, below SERVER_CERTIFICATE).
// It is born SELF-SIGNED, and until 2026-09-11 it stayed that way, so the
// anchor changed on every restart — which is why `GET
// /tls/server-certificate` exists: a debugger fetches it and puts it in its
// own truststore, rather than being told to disable verification, which is
// the habit this whole workflow is trying to break. Since that day the key
// is certified under this service's own Root, which is the anchor now — see
// the block above `serverCertificateExtensions()`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// EVERY LEAF THE MAIN PORT PRESENTS, AS THIS PROCESS KNOWS THEM (#248).
//
// The SAML identity provider's metadata publishes the certificate its back
// channel presents (`saml/listener_keys.ts`), so a service provider can
// authenticate artifact resolution and the attribute query from metadata
// alone. That needs the LEAVES, every one — with `tls.certificateAlgorithms`
// naming two, OpenSSL presents whichever matches what the client offered —
// and it needs them to be the SOCKET's, which is a different answer in a
// request worker: a worker was handed the front process's first leaf, and
// every other entry of SERVER_CERTIFICATES there is a certificate that
// worker made for itself and nothing presents. So a handed-in process
// answers the first leaf and the others the front process handed with it
// (the fork's environment, then every re-issue's bundle), and a process that
// owns the socket answers what it built. Public material only: no key.
// ---------------------------------------------------------------------------
let adoptedExtraCertPems = null;

function handedExtraCertPems() {
  log.debug("Entering handedExtraCertPems().");
  if (adoptedExtraCertPems) {
    log.debug("Leaving handedExtraCertPems(). Adopted.");
    return adoptedExtraCertPems.slice(0);
  }
  const text = process.env.STS_TLS_SERVER_EXTRA_CERTS_PEM || '';
  const found = String(text).match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving handedExtraCertPems(). " + found.length + ".");
  return found.map(function (one) {
    return one + '\n';
  });
}

/**
 * Returns every leaf certificate the main port presents, in PEM.
 *
 * @returns the PEM certificates
 */
function presentedCertificatePems() {
  log.debug("Entering presentedCertificatePems().");
  if (SERVER_CERTIFICATE.handedIn) {
    log.debug("Leaving presentedCertificatePems(). Handed in.");
    return [SERVER_CERTIFICATE.certPem].concat(handedExtraCertPems());
  }
  log.debug("Leaving presentedCertificatePems().");
  return SERVER_CERTIFICATES.map(function (one) {
    return one.certPem;
  }).filter(function (pem) {
    return !!pem;
  });
}

// ---------------------------------------------------------------------------
// A CERTIFICATE HANDED IN, RATHER THAN ONE MADE HERE (2026-09-07).
//
// This certificate is self-signed and generated PER START, which is right for a
// process that owns its own listener and was silently wrong the moment a
// REQUEST WORKER existed. A worker loads this module like everything else, so
// it made a certificate of its own — and `/admin` and `/portal` are OpenID
// Connect relying parties that dial this service BACK on a loopback address and
// PIN its certificate (`common/oidc_rp.ts`). So a worker pinned the one it had
// just made, the front process presented the one IT had made, and the back
// channel failed TLS verification. The symptom is `TypeError: fetch failed`
// during a console sign-in, which names nothing.
//
// So the front process's material can be handed in, and every process in the
// service then presents and pins the same certificate. It arrives over the IPC
// channel and is put in `process.env` by the worker BEFORE this module is
// loaded — deliberately not passed in the fork's environment, because that
// would put a private key in `/proc/<pid>/environ` for anything running as this
// user to read, while an assignment made after start is visible only inside
// the process.
// ---------------------------------------------------------------------------
function handedInCertificate() {
  log.debug("Entering handedInCertificate().");
  const certPem = process.env.STS_TLS_SERVER_CERT_PEM || '';
  const keyPem = process.env.STS_TLS_SERVER_KEY_PEM || '';
  if (!certPem || !keyPem) {
    log.debug("Leaving handedInCertificate().");
    return null;
  }
  // ---------------------------------------------------------------------
  // **THE CHAIN AND THE ANCHOR COME WITH IT (2026-09-11), AND WITHOUT THEM
  // THIS HAND-OFF WAS ONLY HALF DONE.**
  //
  // The block above solved one half: every process presents the SAME
  // certificate. The other half is that every process must publish the same
  // ANCHOR — and a worker that was handed a leaf and nothing else fell back to
  // asking `common/pki.js`, which in a worker answers a Root that worker built
  // itself. So the certificate came from the front process and the anchor came
  // from here, they were from different hierarchies with the same subject
  // name, and `/admin` and `/portal` failed their own OpenID Connect back
  // channel with `unable to get local issuer certificate`.
  //
  // They are PUBLIC, unlike the key, so `process.env` costs nothing here: a
  // chain travels in every handshake and the anchor is published at
  // `GET /tls/server-certificate`.
  //
  // The chain arrives CONCATENATED and is split on the END marker, which is
  // how every other reader of a PEM bundle in this repository does it. It was
  // briefly NUL-separated, and that is the one byte an environment variable
  // cannot carry — the value truncates at it, so the worker got the Issuing
  // CA and lost the Intermediate.
  // ---------------------------------------------------------------------
  //
  // **THE NEWLINE IN THE LOOKBEHIND IS REQUIRED, NOT OPTIONAL.** Written as
  // `\n?` the split lands BEFORE the newline, so the first certificate loses
  // its final line ending and the next one gains a leading blank line —
  // OpenSSL rejects both with `error:04800066:PEM routines::bad end line`, and
  // the whole worker pool failed to start. Every piece is re-normalised below
  // rather than trusted, so a bundle that arrives without a trailing newline
  // is still split into usable PEMs.
  const chainPem = (process.env.STS_TLS_SERVER_CHAIN_PEM || '')
    .split(/(?<=-----END CERTIFICATE-----)\n?/)
    .map(function (one) { return one.trim(); })
    .filter(function (one) { return one; })
    .map(function (one) { return one + '\n'; });
  const anchorPem = process.env.STS_TLS_SERVER_ANCHOR_PEM || '';
  log.info('tls: using the server certificate handed in by the front ' +
           'process rather than generating one, so that every process in ' +
           'this service presents and pins the same certificate. ' +
           chainPem.length + ' chain certificate(s) and ' +
           (anchorPem ? 'its trust anchor' : 'NO trust anchor') +
           ' came with it.');
  log.debug("Leaving handedInCertificate().");
  return { privateKeyPem: keyPem, certPem: certPem,
           chainPem: chainPem,
           // **THE MARKER THAT SAYS THIS PROCESS DOES NOT OWN THE SOCKET.**
           // Read by certifyServerCertificateUnderPki() below, which is the
           // one place it decides anything. See that block for the run it was
           // written after.
           handedIn: true,
           // **THE ANCHOR THE FRONT PROCESS PUBLISHES**, remembered so that
           // trustAnchorPems() can prefer it over anything this process's own
           // PKI would answer. See that function.
           handedAnchorPem: anchorPem,
           subject: 'CN=' + (TLS_HOSTNAMES[0] || 'localhost') + ', O=' +
                    selfSignedOrganization(),
           names: TLS_HOSTNAMES.concat(TLS_IPS),
           fingerprint256: fingerprintOf(certPem),
           // The handed-in certificate's own expiry is what matters and it is
           // not parsed here: this value is reported, not enforced, and the
           // process that MADE the certificate reports the real one.
           notAfter: '' };
}

// The O= of the self-signed certificates, and of the `subject` string reported
// beside them — one function so the two cannot say different things.
function selfSignedOrganization() {
  log.debug("Entering selfSignedOrganization().");
  log.debug("Leaving selfSignedOrganization().");
  return String(config.value('tls.selfSignedOrganization') || 'sts');
}

function makeServerCertificate() {
  log.debug('Entering makeServerCertificate().');
  const handed = handedInCertificate();
  if (handed) {
    log.debug('Leaving makeServerCertificate(). Handed in.');
    return handed;
  }
  // altNames type 2 is dNSName and type 7 is iPAddress. The CN is ignored by
  // every current client — RFC 6125 has said so since 2011 and browsers stopped
  // reading it years ago — so the subjectAltName is not decoration here, it is
  // the only place the names are.
  const altNames = TLS_HOSTNAMES.map(function (name) {
    return { type: 2, value: name };
  }).concat(TLS_IPS.map(function (address) {
    return { type: 7, ip: address };
  }));
  const keys = stsCrypto.selfSignedRsaCertificate({
    // `tls.selfSignedKeyBits`, `tls.selfSignedValidityYears` and
    // `tls.selfSignedOrganization` since 2026-09-12; the defaults are the
    // literals 2048, 2 and 'iya-sts' this call used to carry — the last of
    // which became 'sts' when the product name in every identifier this
    // service emits was renamed, the same day.
    bits: config.value('tls.selfSignedKeyBits'),
    commonName: TLS_HOSTNAMES[0] || 'localhost',
    organizationName: selfSignedOrganization(),
    // The LEADING BYTE of a random serial; '02' is the signing key's. Two
    // years rather than five because this one is put in somebody's truststore
    // and a shorter life is the honest default for a certificate a person is
    // told to trust by hand.
    //
    // IT WAS THE WHOLE SERIAL UNTIL 2026-09-01, and this is the certificate
    // that made that a bug: it is self-signed, it is regenerated at every
    // start, its subject never varies, and it is the one a PERSON is asked to
    // trust in a browser. NSS files a certificate under (issuer, serial), so
    // the second start of this service collided with the first and Firefox
    // refused the port outright — SEC_ERROR_REUSED_ISSUER_AND_SERIAL, which is
    // a database conflict rather than a trust warning and cannot be accepted
    // past. certificateSerial() in common/crypto.js argues the whole of it.
    serialPrefix: '03',
    years: config.value('tls.selfSignedValidityYears'),
    // Passed through to forge untouched rather than modelled: the signing
    // certificate wants none of these and a third caller will want a third set,
    // so modelling it would be inventing a certificate profile language.
    extensions: [
      { name: 'basicConstraints', cA: false, critical: true },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true,
        critical: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: altNames }
    ]
  });
  const pem = keys.certPem;
  log.debug('Leaving makeServerCertificate(). names=' +
            TLS_HOSTNAMES.concat(TLS_IPS).join(', '));
  return {
    privateKeyPem: keys.privateKeyPem,
    certPem: pem,
    subject: 'CN=' + (TLS_HOSTNAMES[0] || 'localhost') + ', O=' +
             selfSignedOrganization(),
    names: TLS_HOSTNAMES.concat(TLS_IPS),
    fingerprint256: fingerprintOf(pem),
    notAfter: keys.notAfter.toISOString()
  };
}

// The extra sentence a bootstrap instruction needs when there is no plain port
// left to bootstrap from. Empty in the ordinary case, so it can be appended
// unconditionally.
function bootstrapNote() {
  log.debug("Entering bootstrapNote().");
  log.debug("Leaving bootstrapNote().");
  return config.value('global.https')
    ? ' That port is HTTPS too (global.https), so the first fetch has to be ' +
      'made without verifying the certificate — curl -k, or its equivalent — ' +
      'since this is where the certificate to verify with comes from.'
    : '';
}

// WHAT THIS SERVICE'S CERTIFICATE IS, in a phrase another module can put in
// a sentence — and it is not decoration, because it changes what a CALLER has
// to do. A self-signed certificate regenerated per start has to be fetched
// and trusted again after every restart; one issued by somebody else does not,
// and telling a reader to re-trust a certificate that never changed sends them
// to look for a problem that is not there. Six modules used to assert the
// first outright.
/**
 * Describes where this service's listener certificate comes from, as a phrase
 * another module can put in a sentence: supplied from disk, issued under this
 * service's Root, or self-signed per start.
 *
 * @returns the phrase
 */
function certificateProvenance() {
  log.debug('Entering certificateProvenance().');
  if (SERVER_CERTIFICATE && SERVER_CERTIFICATE.algorithm === 'supplied') {
    log.debug('Leaving certificateProvenance(). Supplied.');
    return 'issued by somebody else and read from disk at startup ' +
           '(tls.certificateFile), so it does NOT change when this service ' +
           'restarts — trust its issuer once';
  }
  // #70: this said "self-signed" whatever the certificate was. Since
  // 2026-09-11 the listener certificate is issued under this service's Root
  // whenever there is a hierarchy, which is what a non-empty chain records;
  // only a process with none still presents a self-signed one.
  if (SERVER_CERTIFICATE && (SERVER_CERTIFICATE.chainPem || []).length) {
    log.debug('Leaving certificateProvenance(). Issued under the Root.');
    return 'issued by this service\'s TLS Issuing CA under its own Root, ' +
           'over a key each node keeps where minted state persists and ' +
           'makes at every start where it does not, so trust the Root ' +
           '(/pki/revocation lists it) rather than the certificate itself';
  }
  log.debug('Leaving certificateProvenance(). Self-signed.');
  return 'self-signed and regenerated on every start';
}

// SHA-256 over the DER, rendered the way every tool renders it, so that what
// a page prints can be compared with `openssl x509 -fingerprint -sha256`
// without anybody having to reformat it.
function fingerprintOf(pem) {
  log.debug("Entering fingerprintOf().");
  log.debug("Leaving fingerprintOf().");
  // `colon-hex` is what `openssl x509 -fingerprint -sha256` prints, which is
  // what a person is holding when they compare this by eye. It is the same
  // digest RFC 8705's `x5t#S256` uses in `oauth-oidc/mtls.js` and the same one
  // SPIRE's authority id truncates in `spiffe/spiffe_ca.ts` — three spellings
  // of one computation, which is why the format is a parameter and the three
  // functions that each computed it are one.
  return stsCrypto.certificateThumbprint(pem, { format: 'colon-hex' });
}

// ---------------------------------------------------------------------------
// AN ML-DSA SERVER CERTIFICATE BESIDE THE RSA ONE, WHEN ASKED FOR.
//
// `tls.certificateAlgorithms` names what the TLS sockets present. More than
// one is the setting worth having: OpenSSL 3.5 serves whichever certificate
// matches the signature algorithms the CLIENT offered, so one port answers an
// ordinary client with RSA and a post-quantum one with ML-DSA — which is how a
// migration is actually run, and something a debugger can otherwise only be
// told about.
//
// The ML-DSA certificate is built by common/crypto.js's own encoder over
// node's OpenSSL, not by node-forge (which cannot represent the key) and not
// by anything vendored from the debugger (which would make the two sides share
// one reading of RFC 9881 — see the note on selfSignedMlDsaCertificate()).
//
// WHAT IT COSTS, and it is the reason the default is RSA alone: an ML-DSA
// certificate is refused by everything older than OpenSSL 3.5, and which
// `openssl` a caller has is not this service's to decide — 3.0 (Ubuntu
// 22.04's) cannot even print one. A client that offers no ML-DSA signature
// algorithm gets `no suitable signature algorithm` if there is no classical
// certificate to fall back to.
function makeMlDsaServerCertificate(algorithm) {
  log.debug('Entering makeMlDsaServerCertificate(). algorithm=' + algorithm);
  const built = stsCrypto.selfSignedMlDsaCertificate({
    algorithm: algorithm,
    commonName: TLS_HOSTNAMES[0] || 'localhost',
    organizationName: selfSignedOrganization(),
    // The leading byte of a random serial, for the reason above: '04' is this
    // one, so a capture still says which certificate it is looking at.
    serialPrefix: '04',
    years: config.value('tls.selfSignedValidityYears'),
    dnsNames: TLS_HOSTNAMES,
    ipAddresses: TLS_IPS
  });
  log.debug('Leaving makeMlDsaServerCertificate().');
  return {
    algorithm: algorithm,
    privateKeyPem: built.privateKeyPem,
    certPem: built.certPem,
    subject: 'CN=' + (TLS_HOSTNAMES[0] || 'localhost') + ', O=' +
             selfSignedOrganization(),
    names: TLS_HOSTNAMES.concat(TLS_IPS),
    fingerprint256: fingerprintOf(built.certPem),
    notAfter: built.notAfter.toISOString()
  };
}

// ---------------------------------------------------------------------------
// A CERTIFICATE SOMEBODY ELSE ISSUED, WHICH IS THE ONE WAY A CALLER TRUSTS
// THIS SERVICE WITHOUT A TRUST DECISION OF ITS OWN.
//
// Everything above this makes a SELF-SIGNED certificate at every start, and
// the cost of that is stated where it is paid: the anchor changes on each
// restart, so `GET /tls/server-certificate` exists for a caller to fetch and
// trust the new one. That is honest and it is still the default — a bare
// `docker run` of this image needs no files and gets what it always got.
//
// What it cannot do is be the SECOND of two certificates a person accepts. The
// debugger serves a UI and an api from a root that outlives their leaves, so
// trusting that root once covers both across restarts; a self-signed mock
// beside them is a third origin and a fresh warning every time. Handed a leaf
// issued by the same issuing CA, this service joins that root and the count of
// trust decisions goes from three-and-renewed to one.
//
// BOTH SETTINGS OR NEITHER. A certificate without its key, or a key that does
// not match, fails inside the TLS handshake with a message about neither of
// them — so it is refused here, by name, at startup.
//
// The file may hold a CHAIN. Node sends every certificate in `cert`, which is
// what a client needs to build a path to a root it holds; everything that
// reads a certificate OUT of this — the fingerprint, the subject, the names,
// `GET /tls/server-certificate` — takes the first, which is the leaf.
// ---------------------------------------------------------------------------
function suppliedServerCertificate() {
  log.debug('Entering suppliedServerCertificate().');
  const certFile = String(config.value('tls.certificateFile') || '').trim();
  const keyFile = String(config.value('tls.keyFile') || '').trim();
  if (!certFile && !keyFile) {
    log.debug('Leaving suppliedServerCertificate(). Neither is set.');
    return null;
  }
  if (!certFile || !keyFile) {
    // Loud and fatal rather than a fallback to self-signed: an operator who
    // set one of these meant to be serving their certificate, and quietly
    // serving a different one is the failure they would debug last.
    log.debug('Leaving suppliedServerCertificate(). Only one is set.');
    throw new Error(errorCodes.tag('STS-TLS-0002') +
      'tls.certificateFile and tls.keyFile go together: ' +
      (certFile ? 'tls.keyFile' : 'tls.certificateFile') + ' is not set. ' +
      'Set both, or neither to keep the self-signed certificate this ' +
      'service issues at startup.');
  }
  let certPem = '';
  let keyPem = '';
  try {
    certPem = fs.readFileSync(certFile, 'utf8');
    keyPem = fs.readFileSync(keyFile, 'utf8');
  } catch (e) {
    log.debug('Leaving suppliedServerCertificate(). Unreadable.');
    throw new Error(errorCodes.tag('STS-TLS-0003') +
      'tls: cannot read the certificate or key named by ' +
      'tls.certificateFile / tls.keyFile: ' + e.message);
  }
  // Parsed here rather than at the handshake, for the same reason as above:
  // node reports a malformed certificate from inside listen() with a message
  // that names OpenSSL rather than this setting.
  let leaf = null;
  try {
    leaf = stsCrypto.parseCertificate(certPem);
  } catch (e) {
    log.debug('Leaving suppliedServerCertificate(). Unparseable.');
    throw new Error(errorCodes.tag('STS-TLS-0004') +
      'tls: ' + certFile + ' is not a PEM certificate: ' +
      e.message);
  }
  // A key that does not go with the certificate is the other failure that
  // surfaces as an OpenSSL message three layers down.
  let pair = false;
  try {
    pair = leaf.checkPrivateKey(stsCrypto.privateKeyFrom(keyPem));
  } catch (e) {
    throw new Error(errorCodes.tag('STS-TLS-0005') +
      'tls: ' + keyFile + ' is not a readable private key: ' +
      e.message);
  }
  if (!pair) {
    log.debug('Leaving suppliedServerCertificate(). Key mismatch.');
    throw new Error(errorCodes.tag('STS-TLS-0006') +
      'tls: the key in ' + keyFile + ' does not match the ' +
      'certificate in ' + certFile + '.');
  }
  const names = String(leaf.subjectAltName || '').split(',')
    .map(function (entry) {
      return entry.trim().replace(/^(DNS|IP Address):/, '');
    })
    .filter(function (entry) {
      return !!entry;
    });
  const parts = splitSuppliedBundle(certPem, certFile);
  log.info('tls: serving the certificate from ' + certFile + ' (' +
           (1 + parts.chainPem.length) + ' certificate(s) presented, ' +
           (parts.anchorPem ? 'a trust anchor in the file'
                            : 'no trust anchor in the file') +
           ', subject ' + leaf.subject.replace(/\n/g, ', ') + ', names ' +
           (names.join(', ') || 'none') + '). It is not regenerated on ' +
           'restart, so a caller that trusts its issuer stays trusting it.');
  log.debug('Leaving suppliedServerCertificate().');
  return {
    algorithm: 'supplied',
    privateKeyPem: keyPem,
    certPem: parts.leafPem,
    chainPem: parts.chainPem,
    suppliedAnchorPem: parts.anchorPem,
    selfSigned: parts.selfSigned,
    subject: leaf.subject.replace(/\n/g, ', '),
    names: names,
    fingerprint256: fingerprintOf(parts.leafPem),
    notAfter: new Date(leaf.validTo).toISOString()
  };
}

// ---------------------------------------------------------------------------
// A SUPPLIED FILE IS A BUNDLE, AND ITS THREE KINDS OF CERTIFICATE ARE KEPT
// APART (2026-09-15).
//
// Until this date the whole file went into `certPem` and `chainPem` stayed
// empty. Serving was unaffected — node sends every certificate in `cert` —
// but every reader of the record's SHAPE was misled by it, and one of them
// mattered: `trustAnchorPems()` decides whether this service's own Root
// signs the listener's chain by looking at `chainPem`, found none, concluded
// there was nothing to check, and published that Root FIRST. So the console's
// and the portal's OpenID Connect back channel, and the SSF loopback push,
// pinned a Root that signs nothing this listener presents, and every
// `/admin` sign-in on a deployment with `tls.certificateFile` set failed with
// STS-AUTHN-0120 `self-signed certificate in certificate chain`.
//
// So the file is split the way the rest of this module already models a
// certified listener:
//
//   * the LEAF is the first certificate — the one the key must match, and
//     the one every reader of "the server certificate" means;
//   * the CHAIN is every later certificate that is NOT self-signed, in file
//     order, which is what travels with the leaf (RFC 8446 section 4.4.2
//     lets the Root be left out, and this module leaves its own out);
//   * the ANCHOR is a self-signed certificate in the file that signs the top
//     of that chain — checked by signature, for the reason `anchorSigns()`
//     gives. A file with none (a publicly issued certificate and its
//     intermediates) has no anchor here, and a caller verifying this service
//     uses its own trust store, which is right for that certificate.
//
// A self-signed certificate that signs nothing in the chain is reported and
// not used: it is either the wrong Root or a stray, and pinning it is the
// defect this function was written to end.
// ---------------------------------------------------------------------------
function splitSuppliedBundle(bundlePem, certFile) {
  log.debug('Entering splitSuppliedBundle().');
  const pems = splitPemCertificates(bundlePem).map(function (pem) {
    return pem + '\n';
  });
  const leafPem = pems[0];
  const chainPem = [];
  const selfSignedPems = [];
  pems.slice(1).forEach(function (pem) {
    if (isSelfSignedPem(pem)) {
      selfSignedPems.push(pem);
    } else {
      chainPem.push(pem);
    }
  });
  const topPem = chainPem.length ? chainPem[chainPem.length - 1] : leafPem;
  let anchorPem = '';
  selfSignedPems.forEach(function (pem) {
    if (anchorPem) {
      return;
    }
    try {
      const top = stsCrypto.parseCertificate(topPem);
      if (top.verify(stsCrypto.parseCertificate(pem).publicKey)) {
        anchorPem = pem;
      }
    } catch (e) {
      log.debug('splitSuppliedBundle(): a candidate anchor could not be ' +
                'checked: ' + e.message);
    }
  });
  if (selfSignedPems.length && !anchorPem) {
    log.warn(errorCodes.tag('STS-TLS-0032') +
             'tls: ' + certFile + ' holds ' + selfSignedPems.length +
             ' self-signed certificate(s) and none of them signs the chain ' +
             'the listener presents, so none is used as this service\'s ' +
             'trust anchor. A caller verifying this service will use its ' +
             'own trust store.');
  }
  const selfSigned = pems.length === 1 && isSelfSignedPem(leafPem);
  log.debug('Leaving splitSuppliedBundle(). chain=' + chainPem.length +
            ' anchor=' + !!anchorPem + ' selfSigned=' + selfSigned);
  return { leafPem: leafPem, chainPem: chainPem, anchorPem: anchorPem,
           selfSigned: selfSigned };
}

// Issued by itself AND signed by its own key. The name comparison alone is
// not enough, for the reason anchorSigns() gives about identical subjects.
function isSelfSignedPem(pem) {
  log.debug('Entering isSelfSignedPem().');
  try {
    const cert = stsCrypto.parseCertificate(pem);
    const self = cert.checkIssued(cert) && cert.verify(cert.publicKey);
    log.debug('Leaving isSelfSignedPem(). ' + self);
    return self;
  } catch (e) {
    log.debug('Leaving isSelfSignedPem(). Unreadable: ' + e.message);
    return false;
  }
}

// Every certificate the TLS sockets present, in the order the setting names
// them. The FIRST is what every existing caller means by "the server
// certificate" — GET /tls/server-certificate still returns it — and the rest
// are additional choices OpenSSL may make on a client's behalf.
const SERVER_CERTIFICATES = (function buildServerCertificates() {
  log.debug("Entering buildServerCertificates().");
  const supplied = suppliedServerCertificate();
  if (supplied) {
    // tls.certificateAlgorithms is about certificates this service ISSUES, so
    // it has nothing to choose from here. Named rather than ignored: asking
    // for ml-dsa-65 and being served one certificate is worth a line.
    const asked = config.value('tls.certificateAlgorithms') || [];
    if (asked.length && !(asked.length === 1 && asked[0] === 'rsa')) {
      log.warn('tls: tls.certificateAlgorithms (' + asked.join(', ') +
               ') is ignored while tls.certificateFile is set — that ' +
               'setting chooses among certificates this service issues, ' +
               'and it is serving one it was given.');
    }
    log.debug("Leaving buildServerCertificates().");
    return [supplied];
  }
  const wanted = (config.value('tls.certificateAlgorithms') || ['rsa'])
    .map(function (name) {
      return String(name || '').trim().toLowerCase();
    })
    .filter(function (name) {
      return !!name;
    });
  const built = [];
  (wanted.length ? wanted : ['rsa']).forEach(function (name) {
    if (name === 'rsa') {
      built.push(Object.assign({ algorithm: 'rsa' }, makeServerCertificate()));
      return;
    }
    // THE RUNTIME BEFORE THE SPELLING. An ML-DSA certificate needs node's
    // OpenSSL 3.5 (node 24; this repository's Dockerfile pins 24.22.1), and
    // this block runs at MODULE TOP LEVEL — so on node 22 a configured
    // `ml-dsa-65` used to throw out of a `require` and take the whole service
    // down before it bound anything, which is the failure the root CLAUDE.md's
    // rule about listeners exists to prevent. It is warned about and skipped
    // for the same reason an unknown spelling below is: this is a mock, and a
    // certificate algorithm the interpreter cannot produce must not stop the
    // other sixteen protocol families from starting. The fall-back to rsa is
    // the `if (!built.length)` below, so a service configured for ML-DSA alone
    // still listens.
    if (stsCrypto.ML_DSA_OIDS[name] && !stsCrypto.mlDsaAvailable()) {
      log.warn('tls: "' + name + '" was asked for and this runtime cannot ' +
               'build an ML-DSA certificate — node ' + process.versions.node +
               ' is linked against OpenSSL ' + process.versions.openssl +
               ' and ML-DSA needs 3.5, which is node 24. The listener will ' +
               'present the certificates it CAN build; /tls and ' +
               '/admin/crypto-metadata report what it is really serving.');
      return;
    }
    if (!stsCrypto.ML_DSA_OIDS[name]) {
      // Named and ignored rather than fatal: this is a mock, and a typo in a
      // certificate algorithm should not stop the whole service from starting
      // — but it must be loud, because the alternative is a listener quietly
      // presenting one fewer certificate than the operator asked for.
      log.warn('tls: ignoring unknown certificate algorithm "' + name +
               '". Known: rsa, ' + Object.keys(stsCrypto.ML_DSA_OIDS)
                 .join(', ') + '.');
      return;
    }
    built.push(makeMlDsaServerCertificate(name));
  });
  if (!built.length) {
    log.warn('tls: no usable certificate algorithm was configured; falling ' +
             'back to rsa.');
    built.push(Object.assign({ algorithm: 'rsa' }, makeServerCertificate()));
  }
  log.debug("Leaving buildServerCertificates().");
  return built;
})();

const SERVER_CERTIFICATE = SERVER_CERTIFICATES[0];

// ===========================================================================
// THE LISTENER KEY IS KEPT PER NODE, WHERE MINTED STATE PERSISTS (2026-10-08).
//
// The keys above are made at require time, and until this date that was the
// whole of it: every start of a product container with its database kept
// presented a NEW key pair under the Root it had kept, certified by the
// process CA it had kept. rcbj: "#162 was supposed to generate a key pair if
// one didn't already exist in the database. Not recreate it on every restart
// with a persisted volume." #162's decision 2 still binds and shapes the
// whole of this: **each node keeps its OWN listener key**, no listener
// private key is shared between nodes, the process CA is one shared
// authority, and no node address is published anywhere.
//
// **WHERE.** `tls.listenerKeys`, a `realms.sharedMap()` beside
// `tls.listenerAnnounced` (#264), so it persists exactly where that record
// does — product mode on postgres, a cluster, a dispatched pool with a real
// key-encryption key (`persistence_minted.js`'s `enabled()`) — and every row
// is SEALED under the KEK like every other minted row. Not a table of its
// own: a private key the store already seals beside the session ids and the
// Kerberos keys is one more row of the same kind, and a second table would
// be a second answer to *where does this service keep a private key*.
// Anywhere else the map is this process's memory and dies with it, so
// development, `memory` mode and an `ldif` store still make a key per start,
// and an ephemeral-KEK pool clears the rows it finds, as it does for all.
//
// **KEYED BY ALGORITHM UNIT AND NODE NAME** — `rsa@node-a`,
// `ml-dsa-65@node-a` (the units #264 names) — the node name being
// `cluster.nodeName`, else the host name (`cluster.js`'s `nodeName()`; the
// compose stack's `hostname: sts`, AWS's `STS_CLUSTER_NODE_NAME` per node).
// A unit never contains `@`, so the split is unambiguous. **Two nodes given
// ONE name would share a key**, which is the configuration's fault and is
// said in `tls/CLAUDE.md`; a node RENAMED makes a key of its own and leaves
// the old row behind, unread.
//
// **EACH NODE HOLDS ONLY ITS OWN ROW.** The store is shared — a change log
// carries every row to every node — so the reconciler below admits a row
// only when it names THIS node, at a restore and at replication alike; any
// other node's row is opened by the persistence layer, dropped, and never
// held. That is decision 2 read strictly: another node's key is in the
// database it cannot read without the KEK, and in no other node's memory.
//
// **WHAT A ROW HOLDS**: the private key, its unit and (RSA) its modulus
// size, and the certificate this node last took for it with its chain and
// what it was issued for. The certificate is what lets a plain restart
// present the SAME leaf (`heldListenerCertificate()`, and `common/pki.js`'s
// `heldCertificateCurrent()`, which decides), so #264's `restarted` notice
// does not fire for a restart that changed nothing. It is kept per node and
// not read off the `tls:server` slot, because that slot holds ONE node's
// record at a time (#162) and a cluster restart would find another node's
// there.
//
// **WHEN.** The key is settled the first time `common/pki.js` asks for the
// public key to certify (`settleListenerKey()`, from the registration's
// `publicKeyPem()`), which is inside `pki.start()` — after the minted rows
// are restored and before anything binds. The record's own `privateKeyPem`
// stays the one its self-signed bootstrap certificate is over until a
// certificate over the settled key is taken (`takeIssuedCertificate()`), so
// key and certificate never disagree on a socket, and with no hierarchy
// (`pki.autoBuild` off) nothing is settled or stored at all.
//
// **A STORED KEY THAT NO LONGER FITS** — another algorithm, an RSA modulus
// other than `tls.selfSignedKeyBits`, a row that will not parse — is
// replaced by the key made at this start, with `STS-TLS-0048` saying why.
// A request worker (handed in), a supplied certificate and a process with no
// registration settle nothing.
// ===========================================================================
const listenerKeys = realms.sharedMap({
  persist: 'tls.listenerKeys',
  scope: 'shared',
  reconcile: {
    // Only this node's rows are held — see the block above.
    restore: function (key, incoming) {
      log.debug("Entering restore().");
      const own = isOwnListenerKeyName(key);
      log.debug("Leaving restore(). " + (own ? 'This node\'s.' : 'Not held.'));
      return own ? incoming : undefined;
    }
  }
});

// This node's name, read when asked: a setting is final by the time anything
// certifies, and `cluster.js` is a library that registers nothing, required
// here lazily so that loading this module loads nothing more.
function listenerNodeName() {
  log.debug("Entering listenerNodeName().");
  const name = String(require('../cluster/cluster').nodeName() || '');
  log.debug("Leaving listenerNodeName().");
  return name;
}

function listenerKeyName(unit) {
  log.debug("Entering listenerKeyName(). " + unit);
  log.debug("Leaving listenerKeyName().");
  return String(unit) + '@' + listenerNodeName();
}

function isOwnListenerKeyName(key) {
  log.debug("Entering isOwnListenerKeyName().");
  const text = String(key || '');
  const at = text.indexOf('@');
  const own = at > 0 && text.slice(at + 1) === listenerNodeName();
  log.debug("Leaving isOwnListenerKeyName(). " + own);
  return own;
}

// Why a stored key may not be used for this unit now, or '' when it may.
function storedKeyProblem(unit, held) {
  log.debug("Entering storedKeyProblem(). " + unit);
  if (!held || typeof held !== 'object' || !held.privateKeyPem) {
    log.debug("Leaving storedKeyProblem(). No key.");
    return 'the row holds no key';
  }
  if (String(held.unit || '') !== String(unit)) {
    log.debug("Leaving storedKeyProblem(). Another unit.");
    return 'the row is for "' + held.unit + '"';
  }
  let key = null;
  try {
    key = stsCrypto.privateKeyFrom(held.privateKeyPem);
  } catch (e) {
    log.debug("Caught in storedKeyProblem(): " + ((e && e.message) || e));
    log.debug("Leaving storedKeyProblem(). Unreadable.");
    return 'the key will not parse (' + ((e && e.message) || e) + ')';
  }
  const type = String(key.asymmetricKeyType || '');
  if (unit === 'rsa') {
    const bits = Number((key.asymmetricKeyDetails || {}).modulusLength || 0);
    const wanted = Number(config.value('tls.selfSignedKeyBits'));
    if (type !== 'rsa') {
      log.debug("Leaving storedKeyProblem(). Not RSA.");
      return 'it is a ' + (type || 'unknown') + ' key, not RSA';
    }
    if (bits !== wanted) {
      log.debug("Leaving storedKeyProblem(). Another size.");
      return 'it is ' + bits + ' bits and tls.selfSignedKeyBits is ' + wanted;
    }
    log.debug("Leaving storedKeyProblem(). Fits.");
    return '';
  }
  if (type !== unit) {
    log.debug("Leaving storedKeyProblem(). Another algorithm.");
    return 'it is a ' + (type || 'unknown') + ' key, not ' + unit;
  }
  log.debug("Leaving storedKeyProblem(). Fits.");
  return '';
}

/**
 * Settles the key this node certifies for one listener certificate: the one
 * stored for this node and unit where it still fits the configuration, and
 * otherwise the key made at this start, which is then stored. Idempotent.
 *
 * @param record - an entry of SERVER_CERTIFICATES this process owns
 * @returns the private key PEM to certify
 */
function settleListenerKey(record) {
  log.debug("Entering settleListenerKey(). " + record.algorithm);
  if (record.nodeKeyPem) {
    log.debug("Leaving settleListenerKey(). Already settled.");
    return record.nodeKeyPem;
  }
  const unit = String(record.algorithm);
  const name = listenerKeyName(unit);
  const held = listenerKeys.get(name);
  const problem = held ? storedKeyProblem(unit, held) : '';
  if (held && !problem) {
    record.nodeKeyPem = held.privateKeyPem;
    log.info('tls: this node (' + listenerNodeName() + ') keeps its ' + unit +
             ' listener key across restarts, and the one it stored is used ' +
             'again.');
    log.debug("Leaving settleListenerKey(). Stored.");
    return record.nodeKeyPem;
  }
  if (held) {
    log.warn(errorCodes.tag('STS-TLS-0048') + 'tls: the ' + unit +
             ' listener key stored for this node (' + listenerNodeName() +
             ') cannot be used — ' + problem + ' — so the key made at this ' +
             'start replaces it, and a new certificate is issued over it.');
  }
  record.nodeKeyPem = record.privateKeyPem;
  const row = { unit: unit, node: listenerNodeName(),
                privateKeyPem: record.nodeKeyPem,
                createdAt: new Date().toISOString() };
  if (unit === 'rsa') {
    row.bits = Number(config.value('tls.selfSignedKeyBits'));
  }
  listenerKeys.set(name, row);
  log.debug("Leaving settleListenerKey(). Made at this start.");
  return record.nodeKeyPem;
}

// What a listener certificate is issued FOR — the name, the key usage and
// the extensions — in one place, so the registration and the comparison
// below cannot drift. A change to any of them (tls.hostnames, tls.ips) makes
// a held certificate stale.
function listenerIssuance(record) {
  log.debug("Entering listenerIssuance(). " + record.algorithm);
  const mlDsa = !!stsCrypto.ML_DSA_OIDS[record.algorithm];
  log.debug("Leaving listenerIssuance().");
  return {
    commonName: TLS_HOSTNAMES[0] || 'localhost',
    // digitalSignature ALONE for ML-DSA: such a key cannot encipher anything,
    // and TLS 1.3 — the only version that negotiates one — needs nothing else
    // of a server certificate's key.
    keyUsage: mlDsa ? ['digitalSignature']
                    : ['digitalSignature', 'keyEncipherment'],
    extensions: serverCertificateExtensions()
  };
}

function issuanceSignature(record) {
  log.debug("Entering issuanceSignature().");
  log.debug("Leaving issuanceSignature().");
  return JSON.stringify(listenerIssuance(record));
}

/**
 * Answers the certificate this node last took over its stored listener key,
 * for `common/pki.js` to present again where it is still current, or null.
 *
 * @param record - an entry of SERVER_CERTIFICATES this process owns
 * @returns `{ certificatePem, chainPem }`, or null
 */
function heldListenerCertificate(record) {
  log.debug("Entering heldListenerCertificate(). " + record.algorithm);
  const held = listenerKeys.get(listenerKeyName(record.algorithm));
  if (!held || !record.nodeKeyPem ||
      held.privateKeyPem !== record.nodeKeyPem || !held.certificatePem ||
      !Array.isArray(held.chainPem) ||
      held.issuedFor !== issuanceSignature(record)) {
    log.debug("Leaving heldListenerCertificate(). None to offer.");
    return null;
  }
  log.debug("Leaving heldListenerCertificate().");
  return { certificatePem: held.certificatePem,
           chainPem: held.chainPem.slice() };
}

// The certificate just taken, written onto this node's row beside its key.
function rememberListenerCertificate(record) {
  log.debug("Entering rememberListenerCertificate(). " + record.algorithm);
  const name = listenerKeyName(record.algorithm);
  const held = listenerKeys.get(name);
  if (!held || held.privateKeyPem !== record.nodeKeyPem) {
    log.debug("Leaving rememberListenerCertificate(). Not this key's row.");
    return;
  }
  if (held.certificatePem === record.certPem) {
    log.debug("Leaving rememberListenerCertificate(). Unchanged.");
    return;
  }
  listenerKeys.set(name, Object.assign({}, held, {
    certificatePem: record.certPem,
    chainPem: (record.chainPem || []).slice(),
    issuedFor: issuanceSignature(record),
    certifiedAt: new Date().toISOString()
  }));
  log.debug("Leaving rememberListenerCertificate().");
}

// What this process holds of `tls.listenerKeys`, for the tests and a page:
// the row names and their public facts, never a key.
/**
 * Returns the listener-key rows this process holds, without their keys.
 *
 * @returns `{ "<unit>@<node>": { unit, node, bits, createdAt, certified } }`
 */
function heldListenerKeys() {
  log.debug("Entering heldListenerKeys().");
  const out = {};
  listenerKeys.forEach(function (value, name) {
    out[name] = { unit: value.unit, node: value.node,
                  bits: value.bits || null, createdAt: value.createdAt,
                  certified: !!value.certificatePem };
  });
  log.debug("Leaving heldListenerKeys().");
  return out;
}

// ===========================================================================
// AND IT IS CERTIFIED BY THIS SERVICE'S OWN CERTIFICATE AUTHORITY (2026-09-11).
//
// The certificate built above is SELF-SIGNED, and until this date that was the
// end of it: anybody who wanted to verify this service had to fetch that exact
// certificate and trust it, and a restart invalidated what they had trusted.
// Now `common/pki.js` builds a Root for the service at startup, and this
// certificate's key is a leaf of it — so **one anchor covers LDAPS 636, the
// main port AND every token this service signs**, and it survives a
// restart wherever the keystore does.
//
// **IT IS A REGISTRATION AND NOT A CALL, and the ordering is the whole of why
// it works.** This module is required at 20 and its certificate is built at
// require time; `pki.start()` runs afterwards, from
// `common/service_state.ts`, and BEFORE `listen()` binds anything. So the
// swap below has already happened by the time a socket exists — nothing is
// re-keyed under a live listener, and no client ever sees the self-signed one.
//
// **THE PRIVATE KEY DOES NOT MOVE.** What is replaced is the certificate over
// the key that was already made here; `secureContextOptions()` reads
// `certPem` off this record on every context build, so mutating it is the
// whole mechanism.
//
// **A SUPPLIED CERTIFICATE IS LEFT ALONE.** `tls.certificateFile` means an
// operator handed this service a certificate somebody else issued, and
// re-issuing it under this mock's Root would be the opposite of what they
// asked for.
// ===========================================================================
// The extensions every certificate this listener presents is issued with —
// the RSA one and every ML-DSA one — so the names cannot be carried over for
// one algorithm and lost for the other.
function serverCertificateExtensions() {
  log.debug("Entering serverCertificateExtensions().");
  log.debug("Leaving serverCertificateExtensions().");
  return {
    extKeyUsage: { present: true, critical: false, usages: ['serverAuth'] },
    // **THE NAMES ARE THE POINT OF THIS CERTIFICATE AND ARE CARRIED OVER
    // EXACTLY.** Every current client reads the subjectAltName and ignores
    // the Common Name (RFC 6125, since 2011), so a re-issued certificate
    // that lost them would be a listener nothing can verify — which is a
    // worse state than the self-signed one it replaced.
    subjectAltName: { present: true, critical: false,
                      names: TLS_HOSTNAMES.map(function (name) {
                        return { kind: 'dns', value: name };
                      }).concat(TLS_IPS.map(function (address) {
                        return { kind: 'ip', value: address };
                      })) }
  };
}

// A certificate `common/pki.js` issued over one of this listener's keys, put
// on that key's record and onto the sockets. One function for the RSA
// certificate and every ML-DSA one, so the two cannot come to disagree about
// what adopting a certificate involves.
function takeIssuedCertificate(record, certPem, chainPem) {
  log.debug("Entering takeIssuedCertificate(). " + record.algorithm);
  // **THE SAME CERTIFICATE AGAIN IS NOTHING TO DO (2026-10-08).** Since the
  // listener key is kept per node, `common/pki.js` hands back the certificate
  // this record already presents whenever it is still current — a second
  // `certifyRegistered()` in one life among them — and re-applying it would
  // re-key every socket and tell every observer about a change that is not
  // one.
  if (record.selfSigned === false && record.certPem === certPem &&
      JSON.stringify(record.chainPem || []) === JSON.stringify(chainPem)) {
    log.debug("Leaving takeIssuedCertificate(). Already presented.");
    return;
  }
  // What the socket presented until now, for the notice below (#245).
  const wasFingerprint = record.fingerprint256 || '';
  const wasIssued = !!record.certPem && record.selfSigned === false;
  // **THE KEY THE CERTIFICATE IS OVER GOES ON THE RECORD WITH IT.** What
  // `common/pki.js` certified is the key `settleListenerKey()` settled — the
  // one this node stored, where it had one — and until this moment the
  // record carried the key its self-signed bootstrap is over. One assignment
  // beside the certificate's, so the socket never holds one without the
  // other.
  if (record.nodeKeyPem) {
    record.privateKeyPem = record.nodeKeyPem;
  }
  record.certPem = certPem;
  // The chain travels with it: without the Issuing CA and the
  // Intermediate a client holding only the Root cannot build a path, and
  // "trust this one anchor" would be true and unusable.
  record.chainPem = chainPem.slice();
  record.fingerprint256 = fingerprintOf(certPem);
  record.selfSigned = false;
  try {
    const read = stsCrypto.parseCertificate(certPem);
    record.subject = read.subject.replace(/\n/g, ', ');
    record.notAfter = new Date(read.validTo).toISOString();
  } catch (e) {
    // The certificate is in use either way; what is lost is a page's
    // subject line. Named rather than swallowed.
    log.warn('tls: the certified ' + record.algorithm + ' server ' +
             'certificate could not be read back for its subject and ' +
             'expiry: ' + e.message);
  }
  // Kept beside this node's key, so the next start can present it again
  // where it is still current (`heldListenerCertificate()`).
  rememberListenerCertificate(record);
  // **AND THE LISTENERS HAVE TO BE TOLD, because they were built before
  // this ran.** Every listener this module knows — the main port and the
  // debugger's, registered through `trustClientCertificatesOn()` — was
  // created with the secure context evaluated THERE, before `pki.start()`
  // had run, so mutating the record above is invisible to a socket that
  // already has a context. `applyAnchors()` is the rebuild
  // path every truststore change already uses, and it re-reads
  // `secureContextOptions()`, which is where the new certificate and its
  // chain are picked up. Without this line the certificate is issued,
  // recorded, reported on every page — and not served, which is the most
  // convincing way for this to look finished and be wrong.
  applyAnchors();
  // **AND THE SOCKETS THIS MODULE DOES NOT HOLD (2026-09-21).** LDAPS 636 and
  // every realm's SPIRE Server API present a certificate built from this
  // record or from the Root it chains to, and neither is a listener
  // `applyAnchors()` reaches — both set their context ONCE, when they bound.
  // So after `POST /admin-api/pki/build-root` they went on presenting a chain
  // under a Root nothing held any more, and every client that re-fetched the
  // anchor failed with `unable to get local issuer certificate` until the
  // service restarted (tests/protocol/sts_ldaps.js and sts_spiffe_grpc.js,
  // red in every mode). The log line below said "one anchor covers LDAPS 636"
  // the whole time. The owners of those sockets re-key on this.
  notifyCertificateObservers(record.algorithm);
  // **AND A RELYING PARTY THAT PINS IT IS TOLD (#245)**: a certificate this
  // service had ALREADY issued to the listener was replaced — a rebuilt
  // hierarchy, a reissued TLS Issuing CA — so `tls-certificate-changed` goes
  // to every realm's streams, the one port serving them all.
  //
  // **THE FIRST CERTIFICATE A PROCESS TAKES OVER ITS SELF-SIGNED BOOTSTRAP IS
  // COMPARED WITH WHAT THE SERVICE LAST ANNOUNCED (#264)**, not ignored: a
  // start may present a certificate a receiver has never seen — wherever the
  // listener key is not kept (it is per node, and only where minted state
  // persists), and in a cluster whenever another node announced last. A
  // restart that presents the SAME certificate again announces nothing,
  // because nothing differs. At start that comparison waits
  // for `listen()` — the main port is bound by then, so a receiver that
  // fetches the certificate at once reaches it; a first certificate taken
  // AFTER `listen()` (a hierarchy that arrived late) is compared here.
  if (wasIssued) {
    if (wasFingerprint && wasFingerprint !== record.fingerprint256) {
      announceCertificateChange(record.algorithm, wasFingerprint,
                                record.fingerprint256);
    }
    rememberAnnounced(record);
  } else if (listened) {
    announceSinceLastStart([record]);
  }
  log.info('tls: the ' + record.algorithm + ' listener certificate is ' +
           'issued by this service\'s ' +
           'own TLS Issuing CA and chains to its Root — so one anchor ' +
           'covers LDAPS 636, the main port and every token ' +
           'this service signs.');
  log.debug("Leaving takeIssuedCertificate().");
}

// The Shared Signals notice of a replaced listener certificate (#245).
// `ssf/service_signals.ts` is required HERE, lazily, and not at the top: this
// module loads at 20 and Shared Signals at 23b, and the library reads
// `ssf.ts` from the cache anyway. Never throws into the certificate change,
// which has happened.
function announceCertificateChange(algorithm, from, to) {
  log.debug("Entering announceCertificateChange(). " + algorithm);
  sendCertificateNotice([{ unit: String(algorithm), from: from, to: to }],
                        'requested');
  log.debug("Leaving announceCertificateChange().");
}

// The one place the notice leaves, for a re-issue and for a start (#264).
function sendCertificateNotice(rotated, reason) {
  log.debug("Entering sendCertificateNotice(). " + reason);
  try {
    Promise.resolve(require('../ssf/service_signals').keyChanged('tls', '*',
      { rotated: rotated, reason: reason }))
      .catch(function (e) {
        log.debug("Caught in a callback in sendCertificateNotice(): " +
                  ((e && e.message) || e));
      });
  } catch (e) {
    log.debug("Caught in sendCertificateNotice(): " +
              ((e && e.message) || e));
  }
  log.debug("Leaving sendCertificateNotice().");
}

// ---------------------------------------------------------------------------
// WHAT THE SERVICE LAST ANNOUNCED, KEPT ACROSS A RESTART (#264, 2026-09-26).
//
// `tls-certificate-changed` was sent only when a certificate the RUNNING
// process had issued was replaced. The listener key was made again at every
// start (`makeServerCertificate()`), so a restart presented a certificate
// nobody was told about, and a receiver that pins it learned nothing. Since
// 2026-10-08 the key — and, while it is current, the certificate — is kept
// per node where minted state persists, so a plain restart of one node
// presents what it presented before and this compares equal; what is still
// announced is a start that presents something else: a new key, a re-issue
// after the hierarchy moved, or another node's leaf.
//
// **FOR THE SERVICE, NOT PER NODE — rcbj's rule that no node is ever
// exposed, and a fact about node identity.** A receiver reaches the
// service's address and whichever node answers there; it has no notion of a
// node. And a node cannot remember itself: its membership id is a fresh UUID
// at every start (`cluster/CLAUDE.md`), and `cluster.nodeName` is stable only
// where the platform keeps host names. So the record is shared through the
// store and any node compares against it — #162's arrangement for the
// process CA. It also catches a node that JOINS and presents a leaf nobody
// was told of, which a per-node record would have nothing to compare with.
// **The cost, documented rather than hidden**: every node's start is
// announced (each has a listener key of its own), and `from` is the
// certificate the SERVICE last announced, which another live node may still
// present. A receiver behind a balancer pins the anchor, not a leaf.
//
// **KEYED BY THE CERTIFICATE'S ALGORITHM UNIT** (`rsa`, `ml-dsa-65`, …) —
// the `unit` the event names — holding `{ fingerprint256, at }`. Public
// fingerprints only. Written whenever the listener takes a certificate this
// service issued, at start and at every re-issue, so the next start compares
// with the latest.
//
// **IT SURVIVES A RESTART WHEREVER MINTED STATE DOES** — product mode on
// postgres, a cluster, a dispatched pool (`persistence_minted.js`'s
// `enabled()`). In `memory` mode, on an `ldif` store and in a
// single-process development service it does not, so a restart there is not
// announced; nothing could have been pinned across it, since development
// builds a new Root at every start.
//
// **NEVER RECORDED, NEVER ANNOUNCED**: a self-signed bootstrap certificate (a
// process with no hierarchy — `selfSigned` is false only on one this service
// ISSUED), a supplied one (`tls.certificateFile`) and a request worker's
// handed-in copy (`listenerCertificatesOwned()` excludes both).
// ---------------------------------------------------------------------------
const announcedListener = realms.sharedMap({ persist: 'tls.listenerAnnounced',
                                             scope: 'shared' });
// Set by `listen()`: from then on a first issued certificate is compared at
// once rather than left for it.
let listened = false;

function rememberAnnounced(record) {
  log.debug("Entering rememberAnnounced(). " + record.algorithm);
  const unit = String(record.algorithm);
  const held = announcedListener.get(unit);
  if (!held || held.fingerprint256 !== record.fingerprint256) {
    announcedListener.set(unit, { fingerprint256: record.fingerprint256,
                                  at: new Date().toISOString() });
  }
  log.debug("Leaving rememberAnnounced().");
}

// The units whose issued certificate differs from what the service last
// announced, as the event's `rotated` rows. A unit with no record is
// remembered and not announced: nothing was announced for it to differ from
// (a first start, or a store that keeps nothing across a restart). Remembers
// every certificate it is shown, so asking twice announces once.
/**
 * Returns the listener certificates that differ from what the service last
 * announced, as the key-changed event's `rotated` rows, and remembers every
 * certificate it is shown.
 *
 * @param records - the listener certificates this process owns
 * @returns `{ unit, from, to }` for each one that changed
 */
function listenerChangesSinceAnnounced(records) {
  log.debug("Entering listenerChangesSinceAnnounced().");
  const rotated = [];
  (records || []).forEach(function (record) {
    if (!record || record.selfSigned !== false || record.handedIn ||
        record.algorithm === 'supplied' || !record.fingerprint256) {
      return;
    }
    const held = announcedListener.get(String(record.algorithm));
    const was = (held && held.fingerprint256) || '';
    if (was && was !== record.fingerprint256) {
      rotated.push({ unit: String(record.algorithm), from: was,
                     to: record.fingerprint256 });
    }
    rememberAnnounced(record);
  });
  log.debug("Leaving listenerChangesSinceAnnounced(). " + rotated.length);
  return rotated;
}

// Compare and, when anything moved, send ONE event naming every unit, with
// the reason `restarted`. Never throws into a start.
function announceSinceLastStart(records) {
  log.debug("Entering announceSinceLastStart().");
  let rotated = [];
  try {
    rotated = listenerChangesSinceAnnounced(records);
  } catch (e) {
    // The record could not be read or written; the certificate is served
    // either way, and the next start compares again.
    log.warn('tls: the listener certificate could not be compared with the ' +
             'one last announced: ' + ((e && e.message) || e));
    rotated = [];
  }
  if (!rotated.length) {
    log.debug("Leaving announceSinceLastStart(). Nothing moved.");
    return 0;
  }
  log.info('tls: the listener presents ' + rotated.length + ' certificate(s) ' +
           'other than the one(s) this service last announced, so ' +
           'tls-certificate-changed goes to every realm\'s streams, reason ' +
           '"restarted".');
  sendCertificateNotice(rotated, 'restarted');
  log.debug("Leaving announceSinceLastStart().");
  return rotated.length;
}

// What the store says was last announced, for a page and for the tests.
/**
 * Returns what the store says was last announced of each listener certificate.
 *
 * @returns the records, keyed by unit
 */
function lastAnnouncedListenerCertificates() {
  log.debug("Entering lastAnnouncedListenerCertificates().");
  const out = {};
  announcedListener.forEach(function (value, unit) {
    out[unit] = Object.assign({}, value);
  });
  log.debug("Leaving lastAnnouncedListenerCertificates().");
  return out;
}

// ---------------------------------------------------------------------------
// WHO ELSE PRESENTS THIS CERTIFICATE, AND IS TOLD WHEN IT CHANGES (2026-09-21).
//
// An OBSERVER list and not a slot (rule 3e): the owners of those sockets —
// `ldap/ldap_server.js` and `spiffe/spiffe_server.ts` — already require this
// module in the ordinary direction and load after it, so registering adds no
// require, closes no cycle and moves no route. It fires in whichever process
// adopts a re-issued certificate, which is the process holding the sockets:
// a build-root in one process, the front process reconciling after a worker's
// build-root in `dispatch` mode, and a cluster node adopting a hierarchy
// another node built.
// ---------------------------------------------------------------------------
const certificateObservers = [];

/**
 * Registers an observer told whenever the listener certificate is re-issued, so
 * the other sockets presenting it (LDAPS, the SPIRE Server API) re-key.
 *
 * @param fn - called with the algorithm of the certificate that changed
 */
function onServerCertificateChange(fn) {
  log.debug("Entering onServerCertificateChange().");
  if (typeof fn === 'function') {
    certificateObservers.push(fn);
  }
  log.debug("Leaving onServerCertificateChange().");
}

function notifyCertificateObservers(algorithm) {
  log.debug("Entering notifyCertificateObservers(). " + algorithm);
  certificateObservers.forEach(function (fn) {
    try {
      fn(algorithm);
    } catch (e) {
      // One socket that could not be re-keyed must not stop the next, and
      // the certificate is already issued and served on the main port.
      log.error(errorCodes.tag('STS-TLS-0033') +
                'tls: a socket could not take the re-issued listener ' +
                'certificate: ' + ((e && e.message) || e));
    }
  });
  log.debug("Leaving notifyCertificateObservers().");
}

// ---------------------------------------------------------------------------
// **AND A REQUEST WORKER DOES NOT DO IT AT ALL (2026-09-12), BECAUSE IT DOES
// NOT OWN THE SOCKET.**
//
// A worker was handed this certificate, its chain and its anchor by the front
// process — handedInCertificate() above is the whole of that — and it binds no
// TLS listener of its own. Registering here anyway meant `pki.start()` issued
// it a leaf from the hierarchy THIS process holds and `onCertified()` below
// overwrote the record with it: a certificate no socket in this service
// presents, and a chain the handed-in anchor does not sign.
//
// Nothing showed until somebody rebuilt the Root. `POST
// /admin-api/pki/build-root` is dispatched like any other request, so it lands
// on ONE worker, which rebuilds every branch it holds and re-certifies its own
// copy of this record under the new Root. From that moment `trustAnchorPems()`
// finds that the handed-in anchor no longer signs the chain beside it, reports
// the hand-off as broken — which it is not — and falls back to this process's
// own Root. That Root signs nothing the front process is serving, so every
// OpenID Connect back channel this worker runs fails with `unable to get local
// issuer certificate`, and `/admin` and `/portal` answer 400 at their own
// callback. On 2026-09-12 that was six jobs in the dispatch mode of the suite,
// none of which mentions a certificate.
//
// **THE RULE IS THE ONE THE LDAP CONNECTION ALREADY ESTABLISHED** (see the root
// CLAUDE.md): a store is shared by coordination, and a socket is not. The
// listener certificate belongs to the process holding the listener. A worker
// serves what it was handed and certifies nothing.
// ---------------------------------------------------------------------------
(function certifyServerCertificateUnderPki() {
  log.debug("Entering certifyServerCertificateUnderPki().");
  if (SERVER_CERTIFICATE && SERVER_CERTIFICATE.algorithm === 'supplied') {
    log.debug('tls: the server certificate was handed in, so it is not ' +
              'certified under this service\'s own Root.');
    log.debug("Leaving certifyServerCertificateUnderPki().");
    return;
  }
  if (SERVER_CERTIFICATE && SERVER_CERTIFICATE.handedIn) {
    log.info('tls: this process was handed its server certificate by the ' +
             'front process and binds no TLS listener of its own, so it does ' +
             'NOT certify one under this process\'s Root. What it presents ' +
             'and what it pins are the front process\'s, which is the only ' +
             'pair that can agree with the socket a client actually reaches.');
    log.debug("Leaving certifyServerCertificateUnderPki().");
    return;
  }
  // A LEAF (rule 3w): it registers no route, so requiring it here moves
  // nothing. The registration is passive — `pki.start()` is what acts on it.
  const pki = require('../common/pki');
  // What it is issued for, in one place with the comparison that decides
  // whether a held certificate still fits (`listenerIssuance()`).
  const rsaIssuance = listenerIssuance(SERVER_CERTIFICATE);
  pki.registerCertifiable({
    scope: pki.PROCESS_SCOPE,
    useCase: 'tls',
    slot: 'server',
    alg: 'RS256',
    keyAlg: 'rsa-2048',
    label: 'TLS server certificate',
    commonName: rsaIssuance.commonName,
    profile: 'tls-server',
    keyUsage: rsaIssuance.keyUsage,
    extensions: rsaIssuance.extensions,
    // THE KEY THIS NODE KEEPS (2026-10-08), settled on the first ask — see
    // *THE LISTENER KEY IS KEPT PER NODE* above. `pki.start()` is the first
    // caller, after the minted rows are back and before anything binds.
    publicKeyPem: function () {
      log.debug("Entering publicKeyPem().");
      log.debug("Leaving publicKeyPem().");
      return stsCrypto.publicKeyOf(settleListenerKey(SERVER_CERTIFICATE))
        .export({ type: 'spki', format: 'pem' });
    },
    heldCertificate: function () {
      log.debug("Entering heldCertificate().");
      log.debug("Leaving heldCertificate().");
      return heldListenerCertificate(SERVER_CERTIFICATE);
    },
    onCertified: function (certPem, chainPem) {
      log.debug("Entering onCertified().");
      takeIssuedCertificate(SERVER_CERTIFICATE, certPem, chainPem);
      log.debug("Leaving onCertified().");
    }
  });
  // ---------------------------------------------------------------------
  // **AND EVERY ML-DSA CERTIFICATE BESIDE IT (2026-09-13).** Those were the
  // one key pair on these sockets still self-signed: a post-quantum
  // client that offered ML-DSA and was handed that certificate had to pin
  // it, while a classical client on the same port trusted the Root. Now
  // both are leaves of the TLS Issuing CA, so one anchor covers whichever
  // certificate OpenSSL picks for the client.
  //
  // The KEY is still made by node's OpenSSL in
  // `makeMlDsaServerCertificate()`, and what crosses to `common/pki.js`
  // is its public SubjectPublicKeyInfo, exported by that same OpenSSL —
  // so the certificate encoder is handed RFC 9881 octets it did not
  // write. The ISSUING CA signs; nothing here asks the vendored module to
  // sign with an ML-DSA key.
  //
  // A slot per algorithm (`server:ml-dsa-65`) and not a second `server`,
  // because the register's handle is (use case, slot) and two records in
  // one slot would be one overwriting the other at every start.
  // ---------------------------------------------------------------------
  SERVER_CERTIFICATES.filter(function (one) {
    return one !== SERVER_CERTIFICATE &&
           !!stsCrypto.ML_DSA_OIDS[one.algorithm];
  }).forEach(function (record) {
    // digitalSignature ALONE, in `listenerIssuance()`: an ML-DSA key cannot
    // encipher anything.
    const issuance = listenerIssuance(record);
    pki.registerCertifiable({
      scope: pki.PROCESS_SCOPE,
      useCase: 'tls',
      slot: 'server:' + record.algorithm,
      alg: record.algorithm.toUpperCase(),
      keyAlg: record.algorithm,
      label: 'TLS server certificate (' + record.algorithm + ')',
      commonName: issuance.commonName,
      profile: 'tls-server',
      keyUsage: issuance.keyUsage,
      extensions: issuance.extensions,
      // Kept per node like the RSA key, under its own unit.
      publicKeyPem: function () {
        log.debug("Entering publicKeyPem().");
        log.debug("Leaving publicKeyPem().");
        return stsCrypto.publicKeyOf(settleListenerKey(record))
          .export({ type: 'spki', format: 'pem' });
      },
      heldCertificate: function () {
        log.debug("Entering heldCertificate().");
        log.debug("Leaving heldCertificate().");
        return heldListenerCertificate(record);
      },
      onCertified: function (certPem, chainPem) {
        log.debug("Entering onCertified().");
        takeIssuedCertificate(record, certPem, chainPem);
        log.debug("Leaving onCertified().");
      }
    });
  });
  log.debug("Leaving certifyServerCertificateUnderPki().");
})();

// ---------------------------------------------------------------------------
// ONE CERTIFICATE FOR EVERY TLS SOCKET IN THIS PROCESS.
//
// ldap_server.js's LDAPS listener on 636 serves this same certificate and key,
// read through serverCertificate() below rather than generating a second pair.
// That is a decision about what a CALLER has to do rather than a saving of one
// keypair: anybody who wants to verify this service has to fetch its anchor
// and trust it — and one anchor covering the main port and 636 is one fetch.
// Two keypairs would mean an `ldapsearch` that verifies perfectly well against
// a truststore built for the HTTPS port failing with `unable to get local
// issuer certificate`, which names nothing and reads as a broken directory.
//
// The names are the other half of why one certificate works for both: they are
// in the subjectAltName (see above — the CN is ignored by every current client)
// and they are the names this stack is reached at, not names about HTTPS.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The client truststore.
// ---------------------------------------------------------------------------

// A truststore is nearly always pasted as a bundle, and node's `ca` option
// takes an array — handing it the bundle as one string works on some node
// versions and silently uses only the first certificate on others, which reads
// as "the root I added is not trusted".
/**
 * Splits a PEM bundle into its certificates.
 *
 * @param text - the bundle
 * @returns the PEM certificates, in order
 */
function splitPemCertificates(text) {
  log.debug("Entering splitPemCertificates().");
  const matches = String(text || '').match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  log.debug("Leaving splitPemCertificates().");
  return matches || [];
}

function describePem(pem) {
  log.debug('Entering describePem().');
  let subject = '(unreadable)';
  try {
    const cert = forge.pki.certificateFromPem(pem);
    subject = cert.subject.attributes.map(function (attribute) {
      return (attribute.shortName || attribute.name) + '=' + attribute.value;
    }).join(', ');
  } catch (e) {
    // Not a certificate this parser can read. It is still handed to OpenSSL as
    // an anchor — forge and OpenSSL do not accept exactly the same set, and
    // refusing here on forge's opinion would reject anchors that work. The
    // subject is a label on a page, not a check.
    //
    // AND THE COMMONEST CASE IS NOW A POST-QUANTUM ANCHOR. node-forge has no
    // ML-DSA and cannot parse a certificate signed with one at all, while the
    // OpenSSL underneath this process reads it perfectly — so ask OpenSSL
    // before giving up, or every ML-DSA root a debugger uploads is labelled
    // '(unreadable)' on a page whose whole job is to say what was trusted.
    try {
      subject = stsCrypto.parseCertificate(pem).subject
          .split('\n').join(', ');
    } catch (openSslError) {
      log.warn('tls: an anchor could not be parsed for display: ' +
               e.message + ' / ' + openSslError.message);
    }
  }
  // THE REST OF WHAT A PERSON COMPARES BY EYE (2026-09-12), for the truststore
  // page at /admin/tls/trust: the issuer, the serial and the validity. Read
  // from OpenSSL rather than from forge, because OpenSSL is what the listener
  // will verify against and it reads the ML-DSA anchors forge cannot.
  // `readable` is the one fact the management door refuses on — see
  // `addAnchors()` — and it is recorded here so that a caller never has to
  // parse a certificate twice to learn whether the first parse worked.
  let details = { issuer: '', serial: '', notBefore: '', notAfter: '',
                  ca: false, readable: false };
  try {
    const parsed = stsCrypto.parseCertificate(pem);
    details = {
      issuer: parsed.issuer.split('\n').join(', '),
      serial: parsed.serialNumber,
      notBefore: new Date(parsed.validFrom).toISOString(),
      notAfter: new Date(parsed.validTo).toISOString(),
      ca: !!parsed.ca,
      readable: true
    };
  } catch (e) {
    // OpenSSL cannot read it, so it is not an anchor OpenSSL will use either.
    // The row is still described — a non-strict add (the in-process tests')
    // accepts what it was given, and that is not this function's to change —
    // and `readable: false` says why the rest is blank.
    log.debug('describePem(): OpenSSL could not read the certificate: ' +
              e.message);
  }
  log.debug('Leaving describePem(). subject=' + subject);
  return Object.assign({ pem: pem, subject: subject,
                         fingerprint256: fingerprintOf(pem) }, details);
}

// ---------------------------------------------------------------------------
// THE SERVICE ROOT, FOR THE TLS CLIENT CERTIFICATES THE USER PORTAL ISSUES
// (2026-09-13).
//
// A person issues themselves a TLS client certificate on /portal/signing-key,
// installs it in a browser and presents it here. That only works if this
// truststore holds the Root it chains to, and OpenSSL will not end a path at an
// Issuing CA or an Intermediate — so the anchor is the service Root, behind
// `tls.trustIssuedClientCertificates`. It is read LIVE, so the context this
// module re-applies when the listener is re-certified under a rebuilt Root
// carries the new one.
//
// **TRUSTING THE ROOT IS NOT TRUSTING WHAT IT ISSUED.** Every key pair this
// service hands out chains to it, and most of them are not identities.
// `common/tls_client_certificates.js`'s `identityOf()` is what every door below
// asks before a verified chain through a held authority signs anybody in or is
// recorded as an authentication. An anchor added through /admin-api/tls/trust
// that happens to be the same Root is not added twice.
//
// Required lazily and answered '' on any failure: this is called whenever a
// secure context is built, which can be before the certificate authority has
// started, and a truststore must never be the thing that fails to build.
// ---------------------------------------------------------------------------
function issuedClientCertificateAnchor(trust) {
  log.debug("Entering issuedClientCertificateAnchor().");
  let pem = '';
  try {
    pem = require('../common/tls_client_certificates').trustAnchorPem(trust);
  } catch (e) {
    log.debug("Caught in issuedClientCertificateAnchor(): " +
              ((e && e.message) || e));
    pem = '';
  }
  const already = !!pem && anchors.some(function (anchor) {
    return String(anchor.pem).trim() === String(pem).trim();
  });
  log.debug("Leaving issuedClientCertificateAnchor().");
  return pem && !already ? [pem] : [];
}

// What the truststore report says about the Root added above, or null in a
// process with no certificate authority.
function issuedClientCertificateReport() {
  log.debug("Entering issuedClientCertificateReport().");
  let out = null;
  try {
    out = require('../common/tls_client_certificates').report();
  } catch (e) {
    log.debug("Caught in issuedClientCertificateReport(): " +
              ((e && e.message) || e));
    out = null;
  }
  log.debug("Leaving issuedClientCertificateReport().");
  return out;
}

// The identity gate for whatever this socket presented — see the block above.
// `{ issuedHere: false }` when nothing verified or it was not issued here.
// With `options.stored` (#1061) an outside authority's certificate is
// resolved to the one entry storing it, in the ambient realm — what every
// sign-in asks; the connection page and the handshake's recording do not.
function issuedIdentityOf(socket, options) {
  log.debug("Entering issuedIdentityOf().");
  let identity = { issuedHere: false, accepted: false };
  try {
    identity = require('../common/tls_client_certificates').identityOf(
      revocationStatus.fromSocket(socket), options);
  } catch (e) {
    // No certificate authority in this process: nothing here was issued by
    // one, so the gate has nothing to say.
    log.debug("Caught in issuedIdentityOf(): " + ((e && e.message) || e));
    identity = { issuedHere: false, accepted: false };
  }
  log.debug("Leaving issuedIdentityOf().");
  return identity;
}

// Run `fn` in the realm a TLS client certificate names, or as the listener
// always ran when it names none. A realm that has gone is refused upstream by
// `identityOf()`, so `realms.get()` answering null here means "not ours".
function inCertificateRealm(identity, fn) {
  log.debug("Entering inCertificateRealm().");
  const realm = identity && identity.accepted ? realms.get(identity.realm)
                                              : null;
  log.debug("Leaving inCertificateRealm().");
  return realm ? realms.run(realm, fn) : fn();
}

// The `ca` half of the secure context. See the header: the empty case is passed
// EXPLICITLY as an empty array, because omitting `ca` selects node's bundled
// root store — which would mean a client certificate chaining to a public CA
// verified here, a chain nobody asked about.
/**
 * Returns the secure-context options a TLS listener needs: the certificates
 * this service presents with their chains and keys, and the client truststore
 * (an explicit empty list when there are no anchors).
 *
 * @param policy - the listener's, from `policyFor()`; omitted, the process's
 * @returns the options
 */
// A listener's own anchors file (#429), read once and kept: the row is
// restart-only. One that cannot be read, or holds no certificate, STOPS THE
// SERVICE at startup (`checkProtocolOptions()`, STS-TLS-0045), as the
// service's own file does; here it answers nothing. (The cache is declared
// beside MAX_ANCHORS: that startup check runs as this module loads.)

/**
 * The certificates in a listener's own anchors file.
 *
 * @param file - the path
 * @returns the PEM blocks, or an empty list where it could not be read
 */
function listenerFileAnchors(file) {
  log.debug("Entering listenerFileAnchors(). " + file);
  if (!listenerFileCache.has(file)) {
    let found = [];
    try {
      found = splitPemCertificates(fs.readFileSync(file, 'utf8'))
        .slice(0, MAX_ANCHORS);
    } catch (e) {
      log.debug("Caught in listenerFileAnchors(): " + ((e && e.message) || e));
      found = [];
    }
    listenerFileCache.set(file, found);
  }
  log.debug("Leaving listenerFileAnchors().");
  return listenerFileCache.get(file);
}

function secureContextOptions(policy) {
  log.debug('Entering secureContextOptions(). anchors=' + anchors.length);
  log.debug('Leaving secureContextOptions().');
  // ARRAYS, always — node takes parallel key/cert arrays and OpenSSL picks
  // the one that matches the client's signature algorithms. With a single
  // certificate this is the same thing it always was.
  return {
    key: SERVER_CERTIFICATES.map(function (one) { return one.privateKeyPem; }),
    // **THE CHAIN GOES WITH THE CERTIFICATE**, which is what node's `cert`
    // takes: a PEM bundle, leaf first. Since 2026-09-11 this listener's
    // certificate is issued by this service's own TLS Issuing CA, so a client
    // holding only the Root needs the two certificates between them — without
    // that, "trust this one anchor" is true and unusable, and the failure is
    // `unable to get local issuer certificate`, which names nothing.
    cert: SERVER_CERTIFICATES.map(function (one) {
      return (one.chainPem && one.chainPem.length)
        ? [one.certPem].concat(one.chainPem).join('')
        : one.certPem;
    }),
    // THE LISTENER'S OWN TRUSTSTORE (#429): the runtime anchors every
    // listener shares (/admin/tls/trust), the anchors of its OWN file where it
    // names one — replacing the service's file anchors for it — and the
    // service Root where its trustIssuedClientCertificates says so.
    ca: anchors.filter(function (anchor) {
      return !(policy && policy.trustAnchorsFile) || anchor.source !== 'file';
    }).map(function (anchor) { return anchor.pem; })
      .concat(policy && policy.trustAnchorsFile
        ? listenerFileAnchors(policy.trustAnchorsFile) : [])
      .concat(issuedClientCertificateAnchor(policy ? policy.trustIssued
                                                   : undefined)),
    // The protocol floor, the cipher list, the groups and the signature
    // algorithms — see protocolOptions(). In here so that a truststore
    // change, which re-applies this whole object, cannot quietly reset a
    // listener to node's defaults. All of it since #212: the groups and
    // signature algorithms were added to protocolOptions() alone, and a
    // listener would have lost them at its first re-application. The
    // listener's OWN policy since #423, so a realm's listener keeps its own.
    ...protocolOptions(policy)
  };
}

// ---------------------------------------------------------------------------
// WHAT A CALLER VERIFIES THIS LISTENER AGAINST — WHICH IS NOT THE CERTIFICATE
// IT PRESENTS ANY MORE (2026-09-11).
//
// While the certificate above was SELF-SIGNED those were one question with one
// answer, and three callers in this repository answered it by pinning the leaf:
// the back channel in `common/oidc_rp.ts`, the loopback push in
// `ssf/ssf_http.ts`, and the suite's anchor in `tests/tools/trust.js`.
//
// The hour the leaf acquired an ISSUER all three broke, and they broke in the
// way that names nothing about what changed. OpenSSL takes a self-signed leaf
// found in a truststore as an anchor and will NOT take a certified one, so the
// path walks leaf -> Issuing CA -> Intermediate, finds no Root, and fails with
// `unable to get local issuer certificate` — at depth 2, about a certificate
// the caller never mentioned. The admin console reported it as **Signing in
// did not complete**, which is the sign-in flow correctly describing a token
// request that never got a connection.
//
// So the anchor is ASKED FOR here rather than assumed: the Root when this
// service has one, and the self-signed certificate itself when it does not —
// which is what `tls.certificateFile` and any process that never ran
// `pki.start()` (`npm test`, every in-process job) leave behind. Callers pin
// what this returns and stop caring which of the two they are looking at.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// DOES THIS ANCHOR ACTUALLY SIGN THIS CHAIN? (2026-09-11)
//
// **THE ANCHOR AND THE CHAIN ARE FETCHED FROM TWO DIFFERENT PLACES AND CAN
// DRIFT APART, WHICH IS A BUG THAT LOOKS EXACTLY LIKE A WORKING SERVICE.**
// `SERVER_CERTIFICATE.chainPem` is a SNAPSHOT, taken when the listener was
// certified; `pki.serviceRoot()` is read LIVE, and answers whatever Root the
// store holds now. Every one of these pulls them apart:
//
//   * the hierarchy is rebuilt and the listener is not re-certified with it;
//   * a REQUEST WORKER answers this route — it holds its own `pki` state and
//     its own Root, while the certificate it presents was handed in by the
//     front process that owns the socket;
//   * a rebuild half-fails and leaves a new Root over an old branch.
//
// What comes out is a bundle whose four certificates look perfectly right —
// `CN=sts Root CA` at the top, correct names all the way down — and whose
// Root has a different KEY from the one that signed the Intermediate. OpenSSL
// calls it `error 30 at 2 depth lookup: authority and subject key identifier
// mismatch`; node calls it `unable to get local issuer certificate`; curl is
// permissive enough to accept it, so it is invisible from a shell and fatal to
// every node client — which is every test job in this repository and this
// service's own OpenID Connect back channel.
//
// **SO THE ANCHOR IS CHECKED AGAINST THE CHAIN BEFORE IT IS PUBLISHED.** Not
// reasoned about, not arranged by whoever rebuilds a hierarchy remembering to
// re-certify: verified here, at the one place both halves are in hand, with
// the signature itself.
//
// It answers the ANCHOR and never a diagnosis, because its callers are a
// truststore endpoint and a TLS agent. The diagnosis goes to the log.
// ---------------------------------------------------------------------------
function anchorSigns(anchorPem, record) {
  log.debug("Entering anchorSigns().");
  const chain = (record && record.chainPem) || [];
  // The certificate the anchor has to have signed is the TOP of what travels
  // with the leaf — the Intermediate — or the leaf itself where nothing does.
  const topPem = chain.length ? chain[chain.length - 1]
                              : (record && record.certPem);
  if (!anchorPem || !topPem) {
    log.debug("Leaving anchorSigns().");
    return false;
  }
  try {
    const anchor = stsCrypto.parseCertificate(anchorPem);
    const top = stsCrypto.parseCertificate(topPem);
    log.debug("Leaving anchorSigns().");
    // `verify()` is the SIGNATURE and not the name. That is the whole point:
    // the two Roots this has to tell apart have identical subjects, so
    // comparing issuer strings — the obvious check, and the one a reader will
    // want to replace this with — passes on exactly the case that is broken.
    return top.verify(anchor.publicKey);
  } catch (e) {
    log.warn('tls: a candidate trust anchor could not be checked against the ' +
             'server certificate chain (' + e.message + '), so it is not ' +
             'published. A bundle whose anchor does not sign its own chain ' +
             'is refused by every node client and accepted by curl, which is ' +
             'the worst way for this to be wrong.');
    log.debug("Leaving anchorSigns().");
    return false;
  }
}

/**
 * Returns the anchors a client verifies this service's listener certificates
 * against, each checked to sign the chain it is offered for.
 *
 * @returns the PEM anchors; empty where there is no honest anchor to give
 */
function trustAnchorPems() {
  log.debug('Entering trustAnchorPems().');
  const out = [];
  // ---------------------------------------------------------------------
  // **AN ANCHOR HANDED IN BY THE FRONT PROCESS WINS, AND IT IS THE ONLY
  // ANSWER A REQUEST WORKER CAN HONESTLY GIVE** (2026-09-11).
  //
  // A worker does not own the socket and did not make the certificate it
  // serves — both were handed to it. Its own `common/pki.js` holds a Root it
  // built itself, which signs nothing this process presents. Asking that Root
  // is how the console and the portal came to fail their own back channel.
  //
  // It is checked like any other candidate rather than trusted because it
  // arrived: `anchorSigns()` below is the same gate, and an anchor that does
  // not sign the chain it came with is a hand-off that has gone wrong in some
  // new way worth hearing about.
  // ---------------------------------------------------------------------
  const handed = SERVER_CERTIFICATES.map(function (one) {
    return one.handedAnchorPem;
  }).filter(function (pem) { return !!pem; });
  handed.forEach(function (pem) {
    if (out.indexOf(pem) >= 0) {
      return;
    }
    const covers = SERVER_CERTIFICATES.some(function (one) {
      return anchorSigns(pem, one);
    });
    if (covers) {
      out.push(pem);
    } else {
      log.error(errorCodes.tag('STS-TLS-0007') +
                'tls: the trust anchor handed in by the front process does ' +
                'not sign the certificate handed in with it. That is a ' +
                'hand-off gone wrong rather than a hierarchy drifting — both ' +
                'came from one process in one message — so it is reported ' +
                'rather than worked around, and no anchor is published.');
    }
  });
  if (out.length) {
    log.debug('Leaving trustAnchorPems(). ' + out.length +
              ' handed-in anchor(s).');
    return out;
  }
  // ---------------------------------------------------------------------
  // **A SUPPLIED CERTIFICATE IS NEVER THIS SERVICE'S ROOT'S** (2026-09-15),
  // so that Root is not asked. The anchor is whatever self-signed
  // certificate came in the file and signs its chain (see
  // splitSuppliedBundle()); a lone self-signed certificate is its own; and
  // anything else has no anchor here, which serverCertificate() reports as
  // an empty string and a caller reads as "use your own trust store".
  // ---------------------------------------------------------------------
  const supplied = SERVER_CERTIFICATES.filter(function (one) {
    return one.algorithm === 'supplied';
  });
  if (supplied.length) {
    supplied.forEach(function (one) {
      const pem = one.suppliedAnchorPem ||
                  (one.selfSigned ? one.certPem : '');
      if (pem && out.indexOf(pem) < 0) {
        out.push(pem);
      }
    });
    log.debug('Leaving trustAnchorPems(). ' + out.length +
              ' supplied anchor(s).');
    return out;
  }
  try {
    // A LEAF (rule 3w), and lazily for the reason the certification block
    // above gives: requiring it at the top of this file would move nothing but
    // reading it here is a cache hit either way.
    const root = require('../common/pki').serviceRoot();
    if (root && root.certificatePem) {
      // **CHECKED, NOT ASSUMED.** See anchorSigns() above.
      const certified = SERVER_CERTIFICATES.filter(function (one) {
        return one.chainPem && one.chainPem.length;
      });
      const covers = !certified.length ||
                     certified.some(function (one) {
                       return anchorSigns(root.certificatePem, one);
                     });
      if (covers) {
        out.push(root.certificatePem);
      } else {
        // **AND NOTHING IS PUBLISHED IN ITS PLACE.** The obvious substitute
        // is the chain's own Intermediate — it IS a CA, so it looks like a
        // usable anchor — and it was tried and is wrong: OpenSSL will not
        // terminate a path at a trusted certificate that is not SELF-SIGNED
        // without `-partial_chain`, so `openssl verify` still fails and so
        // does every client that does not set that flag. An anchor that only
        // some clients can use is the same class of mistake as the one this
        // branch exists to catch.
        //
        // So the bundle goes out as leaf + chain with no anchor, which is
        // honest — this process cannot prove what signed that chain — and the
        // error below is the thing that gets somebody to fix it. In practice
        // this should never fire: `common/pki.js`'s `certify()` rebuilds a
        // stale branch before issuing, so the drift is repaired before a
        // certificate carrying it exists.
        log.error(errorCodes.tag('STS-TLS-0008') +
                  'tls: this service\'s Root CA does NOT sign the ' +
                  'certificate chain this listener presents — two ' +
                  'hierarchies with the same name have got mixed, most ' +
                  'likely because the hierarchy was rebuilt without the ' +
                  'listener being re-certified, or because this process is a ' +
                  'request worker holding a Root of its own while the front ' +
                  'process owns the socket. The Root is NOT being published ' +
                  'as an anchor, because a bundle whose anchor does not sign ' +
                  'its own chain is refused by every node client (`unable to ' +
                  'get local issuer certificate`) while curl accepts it. NO ' +
                  'anchor is published in its place — an Intermediate is a ' +
                  'CA but is not self-signed, and OpenSSL will not terminate ' +
                  'a path at one. Rebuild the hierarchy on /admin/pki.');
      }
    }
  } catch (e) {
    // NOT an error and named rather than swallowed: a process with no PKI is
    // the ordinary case for `npm test` and for a supplied certificate, and the
    // self-signed leaves below are the right answer there.
    log.debug('trustAnchorPems(): this service has no Root of its own (' +
              e.message +
              '); the listener certificates are their own anchors.');
  }
  SERVER_CERTIFICATES.forEach(function (one) {
    // **A CERTIFIED LEAF IS NOT AN ANCHOR.** Putting one in a truststore is
    // exactly the bug above: the path does not terminate there, so it is worse
    // than useless — it looks like a pin and refuses every connection.
    if (one.certPem && !(one.chainPem && one.chainPem.length)) {
      out.push(one.certPem);
    }
  });
  log.debug('Leaving trustAnchorPems(). ' + out.length + ' anchor(s).');
  return out;
}

// ===========================================================================
// THE HIERARCHY MOVED UNDERNEATH THE SOCKET (2026-09-12).
//
// `POST /admin-api/pki/build-root` replaces the Root and every branch under it.
// In one process that is the end of it: `certify()` fires `onCertified()`
// above, the record is replaced and `applyAnchors()` puts the new certificate
// on the listener in the same act.
//
// **WITH REQUEST WORKERS IT IS NOT, BECAUSE THE PROCESS THAT REBUILT THE
// HIERARCHY IS NOT THE PROCESS HOLDING THE SOCKET.** That request is dispatched
// like any other, so it lands on a worker; the worker rebuilds, publishes the
// new hierarchy over the IPC channel, and every process adopts it — including
// this one, which goes on serving a leaf whose Root nothing here holds any
// more. `trustAnchorPems()` then correctly refuses to publish an anchor (see
// its error, which names exactly this state), so `GET /tls/server-certificate`
// answers a bundle that terminates nowhere and every client that fetched it
// fails with `unable to get local issuer certificate`.
//
// So the front process RECONCILES: if the certificate it is serving no longer
// chains to the Root this service now holds — or, since 2026-09-13, no longer
// chains through the process branch this process now holds (see
// `strandedListenerCertificates()` below) — it re-certifies from the current
// hierarchy. `certifyRegistered()` is the same call `pki.start()` makes, and
// `certify()` rebuilds a branch that no longer chains before it issues from
// it — so one call repairs the branch and the leaf together.
//
// **IT IS IDEMPOTENT AND THE CHECK IS THE SIGNATURE**, not a name or a serial:
// `anchorSigns()` is the same gate `trustAnchorPems()` uses, and the two Roots
// this has to tell apart have identical subjects. Called on every adopted
// hierarchy, it does nothing at all in the ordinary case.
//
// A WORKER NEVER TAKES THIS PATH — it owns no socket and was handed its
// certificate; see certifyServerCertificateUnderPki() above.
// ===========================================================================
// ---------------------------------------------------------------------------
// **"STILL CHAINS TO THE ROOT" WAS NOT THE WHOLE QUESTION (2026-09-13).**
//
// The check above was the SIGNATURE of the Root over the chain this listener
// travels with, and that is true of every Intermediate CA (Process) this
// service has ever built under its current Root — the one the socket presents
// AND the one this process now HOLDS and publishes at
// `/pki/ca/process/intermediate.cer`, names in every CRL distribution point
// and signs that list with. Two different authorities, one subject, both
// signed by the same Root, and the reconcile answered "already chains" about
// the stale one.
//
// It reached the suite as `tests/protocol/sts_pki_distribution_points.js` in
// dispatch mode only: *http://…/pki/crl/process/intermediate.crl is named by
// certificates of two different authorities — CN=sts Intermediate CA
// (Process), O=sts and CN=sts Intermediate CA (Process), O=sts*. Measured on
// the kept stack: the handshake and `GET /tls/server-certificate` chained to
// an Intermediate made at 14:53:56 by the FRONT process, every worker and the
// front process's own register held one made at 14:53:57 by worker 33. The
// sequence, from its log, was a `build-root` on worker 33:
//
//   .491  worker 33 publishes the new Root; the front process adopts it, its
//         listener no longer chains, and `certify()` REBUILDS the stale
//         process branch here (A) and issues the listener from it;
//   .644  worker 33 publishes the process branch it rebuilt in the same act
//         (B); the front process adopts it — and the listener, under A, still
//         chains to the Root, so nothing is re-issued;
//   57.18 a second rebuild of that branch on worker 33 (C) is adopted the same
//         way, with the same non-answer.
//
// So a certificate is CURRENT when the Root signs its chain AND that chain is
// the one this process holds for the scope it was certified in. The second
// half is a comparison of certificates rather than of names, for the reason
// every check in this file is: every candidate carries the same subject.
// `pki.js`'s refusal to rebuild a branch on this caller's behalf is the other
// half — it is what stopped A being built at all.
// ---------------------------------------------------------------------------
function certificateBody(pem) {
  log.debug("Entering certificateBody().");
  log.debug("Leaving certificateBody().");
  return String(pem || '').replace(/-----[^-]+-----|\s+/g, '');
}

// The Issuing CA and the Intermediate this process holds for the listener's
// scope and use case — the registration above names both — or null where it
// holds no such branch, which is nothing to compare against.
function heldListenerChain() {
  log.debug("Entering heldListenerChain().");
  let row = null;
  try {
    const pki = require('../common/pki');
    row = pki.rawRowFor(pki.PROCESS_SCOPE);
  } catch (e) {
    // A process with no PKI is the ordinary case for `npm test`. Named rather
    // than swallowed, and answered "nothing held".
    log.debug("Caught in heldListenerChain(): " + ((e && e.message) || e));
    row = null;
  }
  const issuing = row && row.issuing && row.issuing.tls;
  if (!issuing || !issuing.certificatePem || !row.intermediate ||
      !row.intermediate.certificatePem) {
    log.debug("Leaving heldListenerChain(). None.");
    return null;
  }
  log.debug("Leaving heldListenerChain().");
  return [issuing.certificatePem, row.intermediate.certificatePem];
}

function chainIsHeld(record, held) {
  log.debug("Entering chainIsHeld().");
  if (!held) {
    log.debug("Leaving chainIsHeld(). Nothing held to compare with.");
    return true;
  }
  const chain = (record && record.chainPem) || [];
  const same = chain.length === held.length &&
               chain.every(function (pem, i) {
                 return certificateBody(pem) === certificateBody(held[i]);
               });
  log.debug("Leaving chainIsHeld(). " + same);
  return same;
}

// Every certificate this process certified for its own listeners. **EVERY ONE,
// NOT ONLY THE FIRST (2026-09-13).** An ML-DSA certificate beside the RSA one
// is a leaf of the same TLS Issuing CA, so it is stranded by a moved hierarchy
// in exactly the same way — and a post-quantum client is handed it by
// OpenSSL's choice rather than by anybody's. One that was never certified (its
// registration failed) has no chain and is not this module's to repair: it is
// its own anchor, as it always was.
function listenerCertificatesOwned() {
  log.debug("Entering listenerCertificatesOwned().");
  if (!SERVER_CERTIFICATE || SERVER_CERTIFICATE.algorithm === 'supplied' ||
      SERVER_CERTIFICATE.handedIn) {
    log.debug("Leaving listenerCertificatesOwned(). Not this process's.");
    return [];
  }
  log.debug("Leaving listenerCertificatesOwned().");
  return SERVER_CERTIFICATES.filter(function (one) {
    return one === SERVER_CERTIFICATE ||
           (one.chainPem && one.chainPem.length && !one.handedIn &&
            one.algorithm !== 'supplied');
  });
}

// The owned certificates that are not current against `rootPem`, per the
// block above.
function strandedListenerCertificates(rootPem) {
  log.debug("Entering strandedListenerCertificates().");
  const held = heldListenerChain();
  const out = listenerCertificatesOwned().filter(function (one) {
    return !anchorSigns(rootPem, one) || !chainIsHeld(one, held);
  });
  log.debug("Leaving strandedListenerCertificates(). " + out.length);
  return out;
}

function currentRootPem() {
  log.debug("Entering currentRootPem().");
  let root = null;
  try {
    root = require('../common/pki').serviceRoot();
  } catch (e) {
    // No PKI in this process — see heldListenerChain().
    log.debug("Caught in currentRootPem(): " + ((e && e.message) || e));
    root = null;
  }
  log.debug("Leaving currentRootPem().");
  return (root && root.certificatePem) || '';
}

// ---------------------------------------------------------------------------
// IS THIS LISTENER WAITING FOR A BRANCH ANOTHER PROCESS IS BUILDING?
//
// True when a certificate this process serves is not current AND the process
// branch it holds does not chain to the Root — the state a Root published
// ahead of its branches leaves behind. `common/request_pool.js` reads it after
// a reconcile that declined to build (`buildBranch: false`) and arms the
// fallback that does build, for the case where that branch never arrives.
// ---------------------------------------------------------------------------
/**
 * Says whether the listener is waiting for a process branch another process is
 * building: a certificate it serves is not current and its branch does not
 * chain to the Root.
 *
 * @returns true when it is waiting
 */
function listenerAwaitsBranch() {
  log.debug("Entering listenerAwaitsBranch().");
  const rootPem = currentRootPem();
  if (!rootPem || !strandedListenerCertificates(rootPem).length) {
    log.debug("Leaving listenerAwaitsBranch(). No.");
    return false;
  }
  let chains = true;
  try {
    const pki = require('../common/pki');
    chains = pki.scopeChainsToRoot(pki.PROCESS_SCOPE);
  } catch (e) {
    // No PKI — nothing is being waited for.
    log.debug("Caught in listenerAwaitsBranch(): " + ((e && e.message) || e));
    chains = true;
  }
  log.debug("Leaving listenerAwaitsBranch(). " + !chains);
  return !chains;
}

// `options.buildBranch === false` (2026-09-13): a process branch that does not
// chain to the Root is WAITED FOR rather than rebuilt here. The front process
// of a dispatched service passes it on every hierarchy a worker publishes —
// that worker is rebuilding the branch — and omits it on the fallback it arms
// in case the branch never arrives. Omitted, this is the repair it always was,
// which is what an in-process caller wants.
/**
 * Re-issues the listener certificate under the current certificate hierarchy
 * when it no longer chains to the Root, in the process that owns the socket.
 *
 * @param options - `buildBranch: false` to wait for a process branch another
 * process is building rather than rebuild it here
 * @returns a promise of whether the certificate was re-issued
 */
async function reconcileWithHierarchy(options) {
  log.debug('Entering reconcileWithHierarchy().');
  const buildBranch = !(options && options.buildBranch === false);
  if (!SERVER_CERTIFICATE || SERVER_CERTIFICATE.algorithm === 'supplied' ||
      SERVER_CERTIFICATE.handedIn) {
    log.debug('Leaving reconcileWithHierarchy(). Not this process\'s to make.');
    return false;
  }
  const rootPem = currentRootPem();
  if (!rootPem) {
    // A process with no PKI is the ordinary case for `npm test`; the
    // self-signed certificate is its own anchor and there is nothing to
    // reconcile with.
    log.debug('Leaving reconcileWithHierarchy(). No Root.');
    return false;
  }
  const mine = listenerCertificatesOwned();
  const stranded = strandedListenerCertificates(rootPem);
  if (!stranded.length) {
    log.debug('Leaving reconcileWithHierarchy(). Already current.');
    return false;
  }
  const fingerprints = function () {
    log.debug("Entering fingerprints().");
    log.debug("Leaving fingerprints().");
    return mine.map(function (one) { return one.fingerprint256; }).join(',');
  };
  const was = fingerprints();
  try {
    await require('../common/pki').certifyRegistered({
      repairBranch: buildBranch
    });
  } catch (e) {
    // Reported rather than thrown: the caller is the worker pool's message
    // handler, and a listener that could not be re-certified must not take the
    // service down. What it leaves is the state above — a bundle with no
    // anchor — which trustAnchorPems() already reports at error level.
    log.error(errorCodes.tag('STS-TLS-0009') +
              'tls: the listener certificate could not be re-issued under ' +
              'the hierarchy this service now holds: ' + e.message + '. It ' +
              'goes on presenting the one it has, which chains to a Root ' +
              'that is gone, so GET /tls/server-certificate publishes no ' +
              'anchor until somebody rebuilds on /admin/pki.');
    log.debug('Leaving reconcileWithHierarchy(). Failed.');
    return false;
  }
  if (fingerprints() === was && !buildBranch && listenerAwaitsBranch()) {
    // `certify()` declined: the Root does not sign the process branch this
    // process holds, and this caller asked not to rebuild it. Not the refusal
    // below — the branch is on its way from the process that replaced the
    // Root, and the next publish asks again.
    log.info('tls: this service\'s Root was replaced in another process and ' +
             'the process branch under it has not arrived yet, so the ' +
             'listener certificate is re-issued when it does rather than ' +
             'from a branch built here — two processes building one branch ' +
             'publish two Intermediate CAs of the same name.');
    log.debug('Leaving reconcileWithHierarchy(). Waiting for the branch.');
    return false;
  }
  if (fingerprints() === was) {
    log.warn(errorCodes.tag('STS-TLS-0026') +
             'tls: the listener certificate does not chain to this ' +
             'service\'s Root, or not through the process branch this ' +
             'process holds, and re-issuing it produced the same ' +
             'certificate. Nothing was changed, and GET ' +
             '/tls/server-certificate publishes a chain nothing else here ' +
             'publishes while that is true.');
    log.debug('Leaving reconcileWithHierarchy(). No change.');
    return false;
  }
  log.info('tls: the certificate authority was rebuilt in another process of ' +
           'this service, so this listener has been re-issued under it. ' +
           'ANYTHING THAT FETCHED THIS SERVICE\'S ANCHOR BEFORE NOW NEEDS IT ' +
           'AGAIN — GET /tls/server-certificate publishes the new one.');
  log.debug('Leaving reconcileWithHierarchy(). Re-issued.');
  return true;
}

// ---------------------------------------------------------------------------
// WHAT THE FRONT PROCESS HANDS A WORKER, AND WHAT A WORKER DOES WITH A SECOND
// ONE (2026-09-12).
//
// The first hand-off is `process.env`, set before this module is loaded —
// handedInCertificate() above argues why. It is a SNAPSHOT, and reconciling
// above means there is now a second edition of it: the front process re-issues
// its listener and every worker is still pinning the certificate it was forked
// with. A worker that pins the previous leaf fails its own OpenID Connect back
// channel, which is the defect this whole pair of functions exists to close.
//
// The private key does NOT travel here and does not need to: what a worker
// does with this material is PIN it and report it, never present it — the
// socket is the front process's. The key it was handed at fork is left alone.
// ---------------------------------------------------------------------------
/**
 * Returns the public material a request worker needs to pin and report the
 * listener certificate: the certificate, its chain, its anchor and the other
 * leaves the socket presents. No private key.
 *
 * @returns `{ certPem, chainPem, anchorPem, extraCertPems }`
 */
function serverCertificateBundle() {
  log.debug("Entering serverCertificateBundle().");
  log.debug("Leaving serverCertificateBundle().");
  return {
    certPem: SERVER_CERTIFICATE.certPem,
    chainPem: (SERVER_CERTIFICATE.chainPem || []).slice(0),
    anchorPem: trustAnchorPems()[0] || '',
    // THE OTHER LEAVES THE SOCKET PRESENTS (#248): an ML-DSA certificate
    // beside the RSA one. Public, like the rest of this bundle; see
    // presentedCertificatePems().
    extraCertPems: presentedCertificatePems().slice(1)
  };
}

/**
 * In a request worker, adopts a re-issued listener certificate bundle from the
 * front process, to pin and report it.
 *
 * @param bundle - what `serverCertificateBundle()` answered
 * @returns true when it was adopted
 */
function adoptServerCertificate(bundle) {
  log.debug('Entering adoptServerCertificate().');
  if (!bundle || !bundle.certPem) {
    log.debug('Leaving adoptServerCertificate(). Nothing in it.');
    return false;
  }
  SERVER_CERTIFICATE.certPem = bundle.certPem;
  SERVER_CERTIFICATE.chainPem = (bundle.chainPem || []).slice(0);
  SERVER_CERTIFICATE.handedAnchorPem = bundle.anchorPem || '';
  SERVER_CERTIFICATE.handedIn = true;
  if (Array.isArray(bundle.extraCertPems)) {
    adoptedExtraCertPems = bundle.extraCertPems.slice(0);
  }
  SERVER_CERTIFICATE.selfSigned = !(bundle.chainPem || []).length;
  SERVER_CERTIFICATE.fingerprint256 = fingerprintOf(bundle.certPem);
  try {
    const read = stsCrypto.parseCertificate(bundle.certPem);
    SERVER_CERTIFICATE.subject = read.subject.replace(/\n/g, ', ');
    SERVER_CERTIFICATE.notAfter = new Date(read.validTo).toISOString();
  } catch (e) {
    // The certificate is pinned either way; what is lost is a page's subject
    // line. Named rather than swallowed.
    log.warn('tls: the re-issued server certificate handed in by the front ' +
             'process could not be read back for its subject and expiry: ' +
             e.message);
  }
  log.info('tls: the front process re-issued this service\'s listener ' +
           'certificate and handed in the new one. This process now pins and ' +
           'reports what the socket actually presents.');
  log.debug('Leaving adoptServerCertificate(). Adopted.');
  return true;
}

// ---------------------------------------------------------------------------
// LISTENERS THAT ARE NOT THIS MODULE'S, AND WHY THE TRUSTSTORE REACHES THEM.
//
// **THIS MODULE OWNS NO LISTENER SINCE 2026-09-16** and owned two until then.
// **THE MAIN HTTPS LISTENER IS STILL NOT ITS**: `server.js` creates it,
// because it is the one every
// protocol family answers on and this module is required at 20 of a twenty-four
// line require order. Until 2026-09-06 that meant the truststore stopped at
// this module's own two sockets, and a client certificate presented on the main
// port could be THUMBPRINTED but never VERIFIED — `socket.authorized` was false
// for every certificate ever presented there, because there was no `ca` to
// build a path to and no way to add one after the listener existed.
//
// That was exactly right while the only thing on that port which read a client
// certificate was RFC 8705 token binding, which binds to the certificate and
// explicitly does not care whether anybody vouched for it. It stopped being
// right when the remote XACML PEP arrived: that caller has to be RECOGNISED —
// its DN resolved to a directory entry, to a group, to a role, to a policy
// decision — and recognition is precisely the thing an unverified certificate
// cannot support.
//
// So a listener created elsewhere registers here and gets every anchor change.
// It is a REGISTRATION rather than a require in the other
// direction for the ordinary reason: `server.js` requires this module, so this
// module cannot require it back.
//
// **THE POSTURE ON THAT PORT IS UNCHANGED AND MUST STAY THAT WAY.** It is
// `requestCert: true, rejectUnauthorized: false` — asked for, never required —
// so a certificate that chains to nothing still completes the handshake and
// still binds a token, exactly as before. What the truststore adds is that a
// certificate which DOES chain to an anchor is now known to. Making it
// `rejectUnauthorized: true` would refuse every caller that presents no
// certificate at all, which is almost all of them.
//
// **AND SINCE #423 IT IS THE OPERATOR'S TO CHANGE, ITS DEFAULT UNCHANGED.**
// `tls.mainPortDisableOptionalClientCertificate` and
// `tls.mainPortRequireClientCertificate` (and each other listener's pair) are
// what rcbj asked for; each says in its description what turning it on
// costs. `applyAnchors()` applies them with the truststore.
// ---------------------------------------------------------------------------
/** @type {Array<any>} */
const externalServers = [];

// ---------------------------------------------------------------------------
// A CLIENT CERTIFICATE WHOSE EC KEY IS ON A CURVE OUTSIDE THE NIST SET BELOW
// IS REFUSED, AND EVERY READER IS SERVED FROM ONE READING (#212, 2026-09-26).
//
// Certificates whose EC key is on a curve other than the NIST ones listed
// in ACCEPTED_CLIENT_CURVES are refused before any certificate object is
// built for the rest of this service to read (a third-party runtime defect
// found by #212; details are held privately by the maintainer). The rule
// applies to EVERY certificate in the chain the peer presents and the chain
// this listener completes from its anchors, because the revocation check and
// the path rules walk the whole chain for every connection that presents a
// certificate. The main port and the debugger ask every connection for one.
//
// So this guard reads the chain ONCE, as X509Certificate objects, prepended
// to `secureConnection` so it runs before every other reader, and then:
//
//   * a certificate on a curve outside the set, anywhere in the chain:
//     `getPeerCertificate` answers node's own "no certificate" ({}), the
//     connection is closed, `STS-TLS-0035`;
//   * otherwise `getPeerCertificate(detailed)` is REPLACED on the socket by
//     the same objects node would have built, from that one reading, linked
//     by `issuerCertificate` exactly as node links them: the chain the
//     client sent, then issuers found among this listener's trust anchors
//     (node completes from the context's store), and a self-issued top
//     pointing at itself. Every reader sees the same chain, whatever order
//     they ask in.
//
// The first line is `tls.signatureAlgorithms`, whose default omits brainpool
// from the offered signature schemes by policy. Only this guard covers the
// chain.
// ---------------------------------------------------------------------------
const ACCEPTED_CLIENT_CURVES = new Set([
  'prime192v1', 'secp224r1', 'prime256v1', 'secp384r1', 'secp521r1',
  'sect163k1', 'sect163r2', 'sect233k1', 'sect233r1', 'sect283k1',
  'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1'
]);

// Why this certificate's key is refused, or ''.
function refusedCurveKey(cert) {
  log.debug("Entering refusedCurveKey().");
  const key = cert.publicKey;
  if (key.asymmetricKeyType !== 'ec') {
    log.debug("Leaving refusedCurveKey(). Not EC.");
    return '';
  }
  const curve = String((key.asymmetricKeyDetails || {}).namedCurve || '');
  log.debug("Leaving refusedCurveKey(). " + curve);
  return ACCEPTED_CLIENT_CURVES.has(curve) ? ''
    : 'an EC key on ' + (curve || 'an unnamed curve');
}

// The trust anchors a listener's context holds, parsed once per PEM.
const parsedAnchors = new Map();
function anchorCertificates() {
  log.debug("Entering anchorCertificates().");
  const out = [];
  (secureContextOptions().ca || []).forEach(function (pem) {
    const text = String(pem);
    if (!parsedAnchors.has(text)) {
      let parsed = null;
      try {
        parsed = stsCrypto.parseCertificate(text);
      } catch (e) {
        log.debug("Caught in anchorCertificates(): " +
                  ((e && e.message) || e));
        // An anchor node cannot parse completes no chain; it is skipped.
        parsed = null;
      }
      parsedAnchors.set(text, parsed);
    }
    if (parsedAnchors.get(text)) {
      out.push(parsedAnchors.get(text));
    }
  });
  log.debug("Leaving anchorCertificates(). " + out.length);
  return out;
}

// The peer's chain as X509Certificate objects, leaf first: what the client
// sent, then issuers from the anchors, stopping at a self-issued top.
// `selfIssuedTop` says whether the last one issued itself.
function peerChainOf(leaf) {
  log.debug("Entering peerChainOf().");
  const chain = [leaf];
  const seen = new Set([leaf.fingerprint256]);
  let next = leaf.issuerCertificate;
  while (next && chain.length < 16 && !seen.has(next.fingerprint256)) {
    chain.push(next);
    seen.add(next.fingerprint256);
    next = next.issuerCertificate;
  }
  let top = chain[chain.length - 1];
  let selfIssuedTop = top.checkIssued(top);
  const anchors = selfIssuedTop ? [] : anchorCertificates();
  while (!selfIssuedTop && chain.length < 16) {
    const issuer = anchors.find(function (one) {
      return !seen.has(one.fingerprint256) && top.checkIssued(one);
    });
    if (!issuer) {
      break;
    }
    chain.push(issuer);
    seen.add(issuer.fingerprint256);
    top = issuer;
    selfIssuedTop = top.checkIssued(top);
  }
  log.debug("Leaving peerChainOf(). " + chain.length);
  return { chain: chain, selfIssuedTop: selfIssuedTop };
}

// `getPeerCertificate(detailed)` as node answers it, from the chain above.
function legacyPeerCertificate(read, detailed) {
  log.debug("Entering legacyPeerCertificate().");
  if (!detailed) {
    log.debug("Leaving legacyPeerCertificate(). Leaf.");
    return read.chain[0].toLegacyObject();
  }
  const objects = read.chain.map(function (one) {
    return one.toLegacyObject();
  });
  objects.forEach(function (object, i) {
    if (i + 1 < objects.length) {
      object.issuerCertificate = objects[i + 1];
    }
  });
  if (read.selfIssuedTop) {
    objects[objects.length - 1].issuerCertificate =
      objects[objects.length - 1];
  }
  log.debug("Leaving legacyPeerCertificate(). " + objects.length);
  return objects[0];
}

// The first certificate of the peer's chain on a refused curve, described,
// or '' — and the chain, for the replacement reader.
function readPeerChain(socket) {
  log.debug("Entering readPeerChain().");
  const leaf = typeof socket.getPeerX509Certificate === 'function'
    ? socket.getPeerX509Certificate() : undefined;
  if (!leaf) {
    log.debug("Leaving readPeerChain(). No certificate.");
    return null;
  }
  const read = peerChainOf(leaf);
  read.problem = '';
  read.chain.some(function (cert, depth) {
    const why = refusedCurveKey(cert);
    if (why) {
      read.problem = (depth ? 'the certificate at depth ' + depth
                            : 'the leaf') + ' (' +
        cert.subject.replace(/\n/g, ', ') + ') has ' + why;
    }
    return !!why;
  });
  log.debug("Leaving readPeerChain(). " + (read.problem || 'accepted'));
  return read;
}

// Kept for callers that only want the verdict.
/**
 * Describes the first certificate of a peer's chain on a curve outside the NIST
 * set.
 *
 * @param socket - the TLS socket
 * @returns the description, or an empty string when there is none
 */
function nonNistCurvePeerCertificate(socket) {
  log.debug("Entering nonNistCurvePeerCertificate().");
  const read = readPeerChain(socket);
  log.debug("Leaving nonNistCurvePeerCertificate().");
  return read ? read.problem : '';
}

/**
 * Closes, on a TLS listener, every connection whose client certificate chain
 * uses a curve outside the NIST set, audited under `STS-TLS-0035`.
 *
 * @param server - the TLS listener
 * @param label - its name, for the log and the audit row
 */
function refuseNonNistCurveCertificatesOn(server, label) {
  log.debug('Entering refuseNonNistCurveCertificatesOn(). label=' + label);
  server.prependListener('secureConnection', function (socket) {
    let read = null;
    try {
      read = readPeerChain(socket);
    } catch (e) {
      // A chain X509Certificate itself cannot walk is not one this guard
      // can judge; the socket is left exactly as node made it.
      log.debug("Caught in refuseNonNistCurveCertificatesOn(): " +
                ((e && e.message) || e));
      read = null;
    }
    if (!read) {
      return;
    }
    if (!read.problem) {
      const memo = {};
      socket.getPeerCertificate = function (detailed) {
        log.debug("Entering getPeerCertificate() (read once).");
        const key = detailed ? 'detailed' : 'leaf';
        if (!memo[key]) {
          memo[key] = legacyPeerCertificate(read, !!detailed);
        }
        log.debug("Leaving getPeerCertificate() (read once).");
        return memo[key];
      };
      return;
    }
    socket.getPeerCertificate = function () {
      log.debug("Entering getPeerCertificate() (refused).");
      log.debug("Leaving getPeerCertificate() (refused).");
      return {};
    };
    log.warn(errorCodes.tag('STS-TLS-0035') + 'tls: closed a connection on ' +
             label + ' from ' + (socket.remoteAddress || 'an unknown ' +
             'address') + ': ' + read.problem + '. Only the NIST curves are ' +
             'accepted in a client certificate chain (#212).');
    audit.failure('STS-TLS-0035', {
      protocol: 'TLS', channel: 'tls', target: label,
      summary: 'a client certificate on a curve outside the NIST set ' +
               'was refused: ' + read.problem,
      outcome: 'refused'
    });
    socket.destroy();
  });
  log.debug('Leaving refuseNonNistCurveCertificatesOn().');
}

/**
 * Registers a TLS listener created elsewhere so that the client truststore, and
 * every change to it, applies to it too.
 *
 * @param server - the TLS listener
 * @param label - its name, for the log
 * @param certificateOf - optional; for a listener that presents a certificate
 *   of its own rather than this module's (a custom listener, #472), answers
 *   `{ key, cert }` each time the truststore is applied
 * @param which - optional `{ kind, realm }` naming the listener's policy;
 *   for kind `custom`, `realm` is the listener's id
 *   (`policyFor()`, #423); omitted, the main port's
 * @returns true when it was registered; false (logged) when `server` is not a
 * TLS server
 */
function trustClientCertificatesOn(server, label, certificateOf, which) {
  log.debug('Entering trustClientCertificatesOn(). label=' + label);
  if (!server || typeof server.setSecureContext !== 'function') {
    // Refused rather than thrown: the caller is `server.js` at startup, and a
    // truststore that could not be extended must not stop this service from
    // listening. It is loud because the consequence is silent — every client
    // certificate on that port stays unverified and the only symptom is a
    // remote PEP that cannot register.
    log.error(errorCodes.tag('STS-TLS-0010') +
              'tls: trustClientCertificatesOn() was given something that is ' +
              'not a TLS server (' + label + '), so the client truststore ' +
              'does NOT cover it. Certificates presented there will be ' +
              'thumbprinted and never verified.');
    log.debug('Leaving trustClientCertificatesOn(). Refused.');
    return false;
  }
  externalServers.push({ server: server,
                         label: String(label || 'a listener'),
                         certificateOf: typeof certificateOf === 'function'
                           ? certificateOf : null,
                         kind: String((which && which.kind) || 'main'),
                         realm: (which && which.realm) || null,
                         applied: '' });
  // Its TLS session cache (#429), bounded by its own policy.
  attachSessionCache(server, String((which && which.kind) || 'main'),
                     (which && which.realm) || null);
  // Every listener that registers here ASKS for a client certificate (the
  // main port, the debugger), so every one is guarded (#212).
  refuseNonNistCurveCertificatesOn(server, String(label || 'a listener'));
  // APPLIED IMMEDIATELY, because anchors may already be loaded — this service
  // can be handed a truststore before the main port binds, and a listener that
  // only picked anchors up on the NEXT change would be one whose behaviour
  // depended on the order two unrelated things happened in.
  applyAnchors();
  log.info('tls: the client truststore now covers ' + label + '. A client ' +
           'certificate presented there is verified against ' +
           'the ' + anchors.length + ' anchor(s) ' +
           'in the truststore; one that chains to none of them is still ' +
           'accepted ' +
           'and still binds a token, which is what that port has always done.');
  log.debug('Leaving trustClientCertificatesOn(). Covered.');
  return true;
}


/**
 * Stops applying the truststore to a listener that has closed — a custom
 * listener taken away or rebound (#99, #472) — so the list does not keep it.
 *
 * @param server - the listener given to `trustClientCertificatesOn()`
 * @returns true when it was registered
 */
function forgetListener(server) {
  log.debug('Entering forgetListener().');
  const at = externalServers.findIndex(function (one) {
    return one.server === server;
  });
  if (at >= 0) {
    externalServers.splice(at, 1);
  }
  // Its connection pooling is no longer re-applied either (#429).
  for (let i = httpListeners.length - 1; i >= 0; i -= 1) {
    if (httpListeners[i].server === server) {
      httpListeners.splice(i, 1);
    }
  }
  log.debug('Leaving forgetListener(). ' + (at >= 0));
  return at >= 0;
}

// Apply the current anchors to every listener whose truststore this module
// owns. Existing connections keep the context they were made under — node says
// so and it is the behaviour worth having, since a connection judged under one
// truststore should not silently change its mind halfway through.
function applyAnchors() {
  log.debug('Entering applyAnchors(). anchors=' + anchors.length);
  // EVERY listener is an external one since 2026-09-16: this module creates
  // none of its own any more, so the list that was "our two, plus theirs" is
  // now just theirs — the main HTTPS port and the debugger's.
  // A CUSTOM LISTENER PRESENTS A CERTIFICATE OF ITS OWN (#99, #472): it said
  // so when it registered, and its own key and chain replace this module's in
  // the context it is given, so a truststore change never swaps its
  // certificate for the main port's.
  externalServers.forEach(function (one) {
    const server = one.server;
    try {
      const policy = policyFor(one.kind, one.realm);
      const options = secureContextOptions(policy);
      const own = one.certificateOf ? one.certificateOf() : null;
      if (own && own.key && own.cert) {
        options.key = own.key;
        options.cert = own.cert;
      }
      server.setSecureContext(options);
      // WHETHER IT ASKS FOR A CERTIFICATE (#423) is the server's, not the
      // context's: node reads these two at every connection.
      if (policy.clientAuth) {
        Object.assign(server, clientAuthOptions(policy.clientAuth));
      }
      one.applied = JSON.stringify(policy);
    } catch (e) {
      // Reported rather than thrown: the caller is a route, and a truststore
      // that could not be applied must not take the service down with it. The
      // anchors are already recorded, so the page and ?format=json will show
      // them while the listener has not got them — which is exactly the state
      // this message is here to make visible.
      log.error(errorCodes.tag('STS-TLS-0011') +
                'tls: the truststore could not be applied to a listener: ' +
                e.message);
    }
  });
  log.debug('Leaving applyAnchors().');
}

// ---------------------------------------------------------------------------
// RE-APPLYING THE POLICY WHEN A SETTING MOVES (#423).
//
// The listeners registered above are re-keyed by `applyAnchors()`, which now
// carries each one's policy; a listener this module cannot re-key itself —
// SPIFFE's gRPC servers re-key through grpc-js's credentials, the channel
// between cells through its own context — registers an APPLIER, handed the
// policy whenever it changes. `reapplyPolicy()` compares each listener's
// policy with the one it last applied and touches only those that moved, so
// a setting nobody's listener reads costs one comparison.
// ---------------------------------------------------------------------------
/** @type {Array<any>} */
const policyAppliers = [];

/**
 * Registers a listener this module does not re-key: `apply(policy)` is
 * called now and whenever its policy changes.
 *
 * @param label - its name, for the log and the Listeners page
 * @param kind - as for `policyFor()`
 * @param apply - re-keys the listener with a policy
 * @param realm - for a custom listener, its id (#472)
 * @returns a function that unregisters it
 */
function registerPolicyApplier(label, kind, apply, realm) {
  log.debug('Entering registerPolicyApplier(). ' + label);
  const entry = { label: String(label), kind: String(kind),
                  realm: realm || null, apply: apply, applied: '' };
  policyAppliers.push(entry);
  log.debug('Leaving registerPolicyApplier().');
  return function unregister() {
    log.debug('Entering unregister(). ' + label);
    const at = policyAppliers.indexOf(entry);
    if (at >= 0) {
      policyAppliers.splice(at, 1);
    }
    log.debug('Leaving unregister().');
  };
}

/**
 * Re-applies every listener's policy that changed since it was last applied.
 *
 * @returns how many listeners were re-keyed
 */
function reapplyPolicy() {
  log.debug('Entering reapplyPolicy().');
  let moved = 0;
  const stale = externalServers.some(function (one) {
    return JSON.stringify(policyFor(one.kind, one.realm)) !== one.applied;
  });
  if (stale) {
    applyAnchors();
    moved += 1;
  }
  policyAppliers.forEach(function (one) {
    const policy = policyFor(one.kind, one.realm);
    const signature = JSON.stringify(policy);
    if (signature === one.applied) {
      return;
    }
    try {
      one.apply(policy);
      one.applied = signature;
      moved += 1;
    } catch (e) {
      log.error(errorCodes.tag('STS-TLS-0044') + 'tls: the listener ' +
                'policy could not be applied to ' + one.label + ' (' +
                ((e && e.message) || e) + '); it keeps the one it had.');
    }
  });
  httpListeners.forEach(function (entry) {
    if (JSON.stringify(httpPolicyFor(entry.kind, entry.realm)) !==
        entry.applied) {
      applyHttpPolicy(entry);
      moved += 1;
    }
  });
  if (moved) {
    log.info('tls: the listeners\' TLS policy changed and was re-applied ' +
             '(TLS 1.2 ' + (policyFor().disableTls12 ? 'off' : 'on') +
             ', TLS 1.3 suites ' + policyFor().tls13Suites.join(':') +
             (policyFor().pqcOnly ? ', post-quantum only' : '') + ').');
  }
  log.debug('Leaving reapplyPolicy(). ' + moved);
  return moved;
}

if (typeof config.onOverridesChanged === 'function') {
  config.onOverridesChanged(function () {
    reapplyPolicy();
  });
}
realms.onChange(function () {
  reapplyPolicy();
});

// ---------------------------------------------------------------------------
// THE TLS SESSION CACHE, PER LISTENER (#429, 2026-10-02).
//
// node keeps no server-side session cache of its own: it resumes by TICKETS
// (TLS 1.3 always, TLS 1.2 when the client has one), which hold the session
// themselves and need no server memory. A TLS 1.2 client resuming by session
// ID finds nothing to resume unless the server answers node's `newSession` /
// `resumeSession` events — its documented external cache. This is that cache:
// a Map per listener, bounded by the listener's sessionCacheSize (the oldest
// forgotten past it) and its sessionTimeoutS, both read at each event so a
// change takes effect at once. Size 0 keeps nothing: every resumption is then
// a ticket's.
//
// A SESSION IS RESUMED ONLY UNDER THE SERVER NAME IT WAS MADE UNDER (RFC 6066
// section 3, 2026-10-07). "A server that implements this extension MUST NOT
// accept the request to resume the session if the server_name extension
// contains a different name. Instead, it proceeds with a full handshake to
// establish a new session." Neither half of the stack does that for us:
// OpenSSL, given a TLS 1.2 session by ID, resumes it and merely notes that
// the name differs (tls_parse_ctos_server_name() sets servername_done = 0 on
// a hit, and parses no name at all, so a malformed one is not refused
// either), and node's `resumeSession` event hands the listener the session
// ID and nothing else. tlsfuzzer found it the day the cache went on by
// default (2048, 2026-10-07): test-invalid-server-name-extension-
// resumption.py's "session resume with different SNI" and "... malformed
// SNI" were RESUMED on the debugger's listener, where with the cache at 0
// they had full handshakes.
//
// So the cache keeps the name with the session and compares. Node 24's
// early ClientHello callback hands `onclienthello` the session id and
// whether a ticket was offered, and nothing else: `hello.servername` is
// absent, and `getServername()` is still false while `resumeSession` runs,
// because OpenSSL parses the name only after the session has been chosen.
// `installSessionNameSniffer()` therefore reads the name from the raw
// ClientHello before the TLS engine sees the socket — the same
// pause-and-unshift `tls/client_hello.ts` uses — and is installed from
// `attachSessionCache()`, which runs before that module's `install()` and
// before the PROXY protocol's, so this wrapper is the inner one and reads
// a hello whose header is already gone. `hello.servername` is still
// preferred when a node passes it. `watchClientHello()` wraps
// `onclienthello` and `onnewsession` on every server socket of a listener
// with a cache, and `offeredHello` carries the name to the two listeners
// for exactly the length of that SYNCHRONOUS call. A resumption whose name
// differs in any byte — a different name, an added or missing one, a NUL
// inside it — is answered "nothing to resume", which is the full handshake
// the RFC asks for; OpenSSL then judges the name as it judges any full
// handshake's (a malformed one is refused, unrecognized_name). A hello the
// sniffer cannot read is not resumed either.
//
// FAILING CLOSED: a name the cache does not know (the hook missing, a node
// that stopped passing `servername`) refuses the resumption rather than
// skipping the comparison, so the failure mode is a full handshake.
// tests/listener_tls_policy.js L5 resumes one, so that state is not silent.
//
// A TLS 1.2 TICKET IS HELD TO THE SAME RULE, AFTER THE HANDSHAKE (#507,
// 2026-10-26). Node resumes a ticket inside OpenSSL with no event, OpenSSL
// makes the same TLS 1.2 non-check there, and nothing node exposes carries
// the name a ticket was made under: `servername` is false after a TLS 1.2
// hit and the session's DER holds no name, with or without an SNI
// callback (shown by hand against a bare node server, 2026-10-26). What a
// resumed TLS 1.2 session DOES keep is the master secret of the session it
// resumes. So `rememberTicketName()` records, at the end of every full TLS
// 1.2 handshake, the server name the hello offered under a digest of that
// session's master secret (read from `getSession()`), and
// `checkResumedName()` looks the digest up on every resumed TLS 1.2
// connection and CLOSES the connection when the name differs
// (STS-TLS-0052) or is one this process never recorded (STS-TLS-0053).
// Closed, not resumed afresh: by `secureConnection` the handshake is over,
// and a client answered under the wrong name is the thing the RFC forbids.
// The record is per listener and per process, bounded by
// TICKET_NAME_ENTRIES and the listener's sessionTimeoutS (a ticket lives no
// longer), and where minted state persists it is also a replicated shared
// store (`tls.ticketNames`, `tls.presentedChains`'s arrangement) so a
// ticket sealed under the cluster's shared key is known on the node that
// did not make it. A mismatch closes at once; a session with NO record on
// this node waits for one read barrier (`persistence.syncNow()`) and is
// judged again, because behind a balancer that row is simply still
// replicating (2026-10-27, the cluster mode's tlsfuzzer). TLS 1.3 is left
// alone on purpose: RFC 8446 section 4.2.11 removes the server's check and
// section 4.6.1 puts it on the client, and OpenSSL resumes a TLS 1.3 PSK
// under another name (same probe). tests/listener_tls_policy.js L5d.
// ---------------------------------------------------------------------------

/**
 * The server name of the ClientHello whose handler is running, while it
 * runs: `{ servername }`, or null between hellos.
 * @type {{servername: (string|null)}|null}
 */
let offeredHello = null;

/** The servers whose sockets carry `watchClientHello()`. */
const helloWatchedServers = new WeakSet();

// The name `installSessionNameSniffer()` read, on the raw socket, and the
// mark that this sniffer has already handed that socket to the TLS engine.
const SESSION_NAME = Symbol('sts.sessionServerName');
const SESSION_SEEN = Symbol('sts.sessionNameSeen');
// The same bounds `tls/client_hello.ts` uses: past either, the bytes are
// handed to the TLS engine unread and the session is not resumed by ID.
const SESSION_HELLO_LIMIT = 64 * 1024;
const SESSION_HELLO_WAIT_MS = 10 * 1000;
// The TLS 1.2 ticket names a listener remembers (#507): one per full TLS
// 1.2 handshake, the oldest forgotten past this. Its own bound rather than
// sessionCacheSize, because a size of 0 means "resume by ticket only" and
// must not become "close every resumed TLS 1.2 connection".
const TICKET_NAME_ENTRIES = 4096;
// The replicated half (#507): a row per full TLS 1.2 handshake, aged out
// at the listener's session lifetime, so a node that did not make a ticket
// still knows the name it was made under. `tls.presentedChains`'s shape.
const ticketNamesShared = realms.sharedMap({
  persist: 'tls.ticketNames',
  retain: 'age',
  scope: 'shared',
  expiresAt: realms.expiryField('until', 1)
});
const TICKET_NAME_SHARED_ENTRIES = 4096;
// How many read barriers a resumed session with no record here is given
// before it is judged, and the pause between them (2026-10-27).
const TICKET_NAME_BARRIERS = 4;
const TICKET_NAME_BARRIER_PAUSE_MS = 250;
// Rule 3ap: the replicated half describes itself to /admin/caches; each
// listener's own record is reported beside its session cache.
cacheRegistry.register({
  name: 'tls.ticket-names',
  title: 'TLS 1.2 ticket names, for resumed sessions',
  description: 'The server name a full TLS 1.2 handshake was made under, ' +
    'keyed by a digest of the session\'s master secret, compared when ' +
    'that session is RESUMED by ticket (#507, RFC 6066 section 3): node ' +
    'resumes a ticket inside OpenSSL with no event, and OpenSSL does not ' +
    'compare the name. A resumption under another name, or one no record ' +
    'vouches for, is closed after the handshake. Each listener keeps its ' +
    'own copy as well, bounded the same way.',
  owner: 'tls/tls_server.js',
  scope: 'process',
  persisted: true,
  maxEntries: function () {
    return TICKET_NAME_SHARED_ENTRIES;
  },
  bound: 'Enforced: ' + TICKET_NAME_SHARED_ENTRIES + ' sessions; expired ' +
    'rows go first, then the oldest.',
  lifetime: function () {
    return 'Shared by every node and replicated: the listener\'s session ' +
      'lifetime (tls.sessionTimeoutS), which is as long as a ticket lives.';
  },
  entries: function () {
    const out = [];
    ticketNamesShared.forEach(function (row, key) {
      const until = row && Number(row.until) > 0 ? Number(row.until) : null;
      out.push({ key: 'master-secret sha256 ' + String(key).slice(0, 16) +
                      '\u2026 (' + (row && typeof row.servername === 'string'
                        ? (row.servername || 'no name') : '?') + ')',
                 validUntil: until, basis: 'content-keyed' });
    });
    return out;
  }
});

/**
 * `tls/client_hello.ts`'s `parse`, loaded once. Null when it could not be
 * loaded: every session-ID resumption then fails closed.
 * @type {((bytes: Buffer) => { state: string,
 *   hello?: { serverName?: string } })|null}
 */
let readClientHello = null;

// Set on a server once `installSessionNameSniffer()` has wrapped its emit.
const SESSION_SNIFFER = Symbol('sts.sessionNameSniffer');

let clientHelloHookInstalled = false;

/**
 * Loads `tls/client_hello.ts`'s parser, once. A later listener retries
 * when the first load found nothing.
 */
function loadClientHelloReader() {
  log.debug('Entering loadClientHelloReader().');
  if (typeof readClientHello === 'function') {
    log.debug('Leaving loadClientHelloReader(). Cached.');
    return;
  }
  try {
    const clientHello = require('./client_hello');
    if (clientHello && typeof clientHello.parse === 'function') {
      readClientHello = clientHello.parse;
    }
  } catch (e) {
    log.debug('Caught in loadClientHelloReader(): ' +
              ((e && e.message) || e));
  }
  log.debug('Leaving loadClientHelloReader(). ' +
            (typeof readClientHello === 'function' ? 'loaded'
                                                   : 'unavailable'));
}

// A hot path: once per chunk of every ClientHello on a listener with a
// cache, and no Entering/Leaving pair here would drown the log. `undefined`
// asks for more bytes; null is a hello whose name cannot be read.
function nameOfHello(bytes) {
  if (typeof readClientHello !== 'function') {
    return null;
  }
  let parsed;
  try {
    parsed = readClientHello(bytes);
  } catch (e) {
    log.debug('Caught in nameOfHello(): ' + ((e && e.message) || e));
    return null;
  }
  if (!parsed || parsed.state === 'incomplete') {
    return undefined;
  }
  if (parsed.state === 'complete' && parsed.hello &&
      typeof parsed.hello.serverName === 'string') {
    return parsed.hello.serverName;
  }
  return null;
}

// A hot path: once per connection, and no Entering/Leaving pair here would
// drown the log. '' is a hello that offered no name; null was not read.
function sniffedServerName(raw) {
  if (!raw || !Object.prototype.hasOwnProperty.call(raw, SESSION_NAME)) {
    return null;
  }
  const name = raw[SESSION_NAME];
  if (typeof name === 'string') {
    return name;
  }
  return null;
}

/**
 * Reads the server name from the raw ClientHello before the TLS engine
 * takes the socket, and remembers it on the socket for `watchClientHello()`.
 * Installed inside the JA4 reader's and the PROXY protocol's wrappers, so
 * both have already returned the bytes. Idempotent per server.
 *
 * @param server - the TLS server
 */
function installSessionNameSniffer(server) {
  log.debug('Entering installSessionNameSniffer().');
  if (!server || typeof server.emit !== 'function' ||
      server[SESSION_SNIFFER]) {
    log.debug('Leaving installSessionNameSniffer(). Nothing to do.');
    return;
  }
  server[SESSION_SNIFFER] = true;
  loadClientHelloReader();
  const originalEmit = server.emit;

  // A hot path: one connection on every listener with a cache, and no
  // Entering/Leaving pair on the readers below would drown the log.
  function capture(socket) {
    let buffered = Buffer.alloc(0);
    let finished = false;

    // Hot path: once per connection. See capture().
    function handOver(name) {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onDone);
      socket.removeListener('close', onDone);
      socket[SESSION_NAME] = typeof name === 'string' ? name : null;
      socket[SESSION_SEEN] = true;
      socket.pause();
      if (buffered.length) {
        socket.unshift(buffered);
      }
      if (!socket.destroyed) {
        originalEmit.call(server, 'connection', socket);
      }
    }

    // Hot path: once per chunk. See capture().
    function onData(chunk) {
      if (finished) {
        return;
      }
      buffered = buffered.length ? Buffer.concat([buffered, chunk])
                                 : chunk;
      if (buffered.length > SESSION_HELLO_LIMIT) {
        handOver(null);
        return;
      }
      const name = nameOfHello(buffered);
      if (name === undefined) {
        return;
      }
      handOver(name);
    }

    // Hot path: the client went away while the hello was read. See capture().
    function onDone() {
      finished = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
    }

    const timer = setTimeout(function () {
      if (!finished) {
        handOver(null);
      }
    }, SESSION_HELLO_WAIT_MS);
    socket.on('data', onData);
    socket.once('error', onDone);
    socket.once('close', onDone);
    // A socket straight from accept is flowing. One handed on by the
    // PROXY protocol or the JA4 reader is paused, with the hello already
    // buffered — a data listener alone never makes it flow. resume()
    // delivers either, and handOver() pauses again before the TLS engine
    // is given the socket.
    socket.resume();
  }

  // Anonymous and unlogged: emit runs for every event the server raises,
  // and only a first connection is this sniffer's business.
  server.emit = function (event, socket) {
    if (event !== 'connection' || !socket || socket[SESSION_SEEN]) {
      return originalEmit.apply(server, arguments);
    }
    capture(socket);
    return true;
  };
  log.debug('Leaving installSessionNameSniffer().');
}

/**
 * The server name a parsed ClientHello offered, '' for none, null if node
 * did not say.
 *
 * @param hello - node's parsed ClientHello
 * @returns the name, '' or null
 */
// A hot path: called for every handshake on a listener with a cache, and no
// Entering/Leaving pair here would tell a reader anything but would drown
// the log.
function offeredServername(hello) {
  if (hello && typeof hello.servername === 'string') {
    return hello.servername;
  }
  return null;
}

/**
 * Wraps one server socket's `onclienthello` and `onnewsession` so that the
 * session cache's listeners can see the server name its hello offered.
 *
 * @param handle - the socket's TLSWrap handle
 */
// A hot path: once per connection on every listener with a cache, and no
// Entering/Leaving pair here would tell a reader anything but would drown
// the log.
function watchClientHello(handle) {
  const onHello = handle.onclienthello;
  const onNewSession = handle.onnewsession;
  if (typeof onHello !== 'function' || typeof onNewSession !== 'function') {
    return;
  }
  // The name THIS connection's hello offered, for its resumeSession and
  // for its newSession at the end of a full handshake. Node 24 leaves the
  // name off the hello object, so the sniffer's reading is compared unless
  // the hello carries a name of its own.
  let offered = sniffedServerName(handle._parentWrap);
  handle.onclienthello = function (hello) {
    const parsed = offeredServername(hello);
    if (parsed !== null) {
      offered = parsed;
    }
    const outer = offeredHello;
    offeredHello = { servername: offered };
    try {
      return onHello.apply(this, arguments);
    } finally {
      offeredHello = outer;
    }
  };
  handle.onnewsession = function () {
    const outer = offeredHello;
    offeredHello = { servername: offered };
    try {
      return onNewSession.apply(this, arguments);
    } finally {
      offeredHello = outer;
    }
  };
}

/**
 * Installs, once, the hook through which every server socket of a listener
 * with a session cache gets `watchClientHello()`. node builds a server's
 * sockets inside `tls.Server`'s own connection listener and hands the
 * listener no socket, so the one place a socket can be reached before its
 * hello arrives is `TLSSocket.prototype._init`, which sets the handlers
 * this wraps; it is wrapped for the servers in `helloWatchedServers` alone.
 *
 * @returns whether the hook is in place
 */
function installClientHelloHook() {
  log.debug('Entering installClientHelloHook().');
  if (clientHelloHookInstalled) {
    log.debug('Leaving installClientHelloHook(). Already.');
    return true;
  }
  // `_init`, `_tlsOptions`, `_handle` and `server` are node's own and
  // undeclared in @types/node, hence the cast.
  const proto = /** @type {any} */ (tls.TLSSocket &&
                                     tls.TLSSocket.prototype);
  const originalInit = proto && proto._init;
  if (typeof originalInit !== 'function') {
    // Fails CLOSED: every session-ID resumption is then refused (a full
    // handshake), never resumed under a name nobody compared.
    log.error(errorCodes.tag('STS-TLS-0046') +
              'tls: this node has no TLSSocket.prototype._init, so the TLS ' +
              'session cache cannot see a ClientHello\'s server name; no ' +
              'session will be resumed by ID (RFC 6066 section 3).');
    log.debug('Leaving installClientHelloHook(). No _init.');
    return false;
  }
  // A hot path: every TLS socket in the process is built through it, and
  // no Entering/Leaving pair here would tell a reader anything but would
  // drown the log.
  proto._init = function () {
    const out = originalInit.apply(this, arguments);
    const socket = /** @type {any} */ (this);
    if (socket._tlsOptions && socket._tlsOptions.isServer &&
        socket._handle && helloWatchedServers.has(socket.server)) {
      watchClientHello(socket._handle);
    }
    return out;
  };
  clientHelloHookInstalled = true;
  log.debug('Leaving installClientHelloHook().');
  return true;
}

/**
 * Whether a held session may be resumed by the hello now offering it: only
 * under the very server name it was made under (RFC 6066 section 3).
 *
 * @param held - the cache's entry
 * @param offered - `offeredHello`, as the listener found it
 * @returns true to resume
 */
// A hot path: every TLS 1.2 resumption by ID, and no Entering/Leaving pair
// here would tell a reader anything but would drown the log.
function sameServerName(held, offered) {
  if (!held || !offered) {
    return false;
  }
  if (typeof held.servername !== 'string' ||
      typeof offered.servername !== 'string') {
    return false;
  }
  return held.servername === offered.servername;
}

/**
 * The server name a connection's ClientHello offered, as the sniffer read
 * it off the raw socket, else as OpenSSL reports it (a full handshake's
 * `servername`; after a TLS 1.2 hit OpenSSL reports none). '' is a hello
 * that offered no name; null is a name nobody read.
 *
 * @param socket - the TLS socket
 * @returns the name, '' or null
 */
// A hot path: once per TLS 1.2 connection, and no Entering/Leaving pair
// here would tell a reader anything but would drown the log.
function helloServerName(socket) {
  const raw = socket && socket._parent;
  const sniffed = sniffedServerName(raw);
  if (sniffed !== null) {
    return sniffed;
  }
  if (socket && typeof socket.servername === 'string') {
    return socket.servername;
  }
  return null;
}

/**
 * A digest of the master secret of the session a socket is on, read from
 * OpenSSL's serialized SSL_SESSION (`getSession()`): SEQUENCE { version,
 * sslVersion, cipher, sessionId, masterKey, ... }, the fifth element. The
 * same across a TLS 1.2 resumption, which is what makes it the key the
 * ticket's name is kept under. Never the secret itself: the digest is all
 * that is held or replicated.
 *
 * @param socket - the TLS socket
 * @returns the hex digest, or null where the session could not be read
 */
// A hot path, as above.
function masterSecretDigest(socket) {
  let der = null;
  try {
    der = socket && typeof socket.getSession === 'function'
      ? socket.getSession() : null;
  } catch (e) {
    log.debug('Caught in masterSecretDigest(): ' + ((e && e.message) || e));
    return null;
  }
  if (!der || !der.length || der[0] !== 0x30) {
    return null;
  }
  const tlv = function (off) {
    if (off + 2 > der.length) {
      return null;
    }
    const tag = der[off];
    let len = der[off + 1];
    let p = off + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) {
        if (p >= der.length) {
          return null;
        }
        len = len * 256 + der[p++];
      }
    }
    if (p + len > der.length) {
      return null;
    }
    return { tag: tag, start: p, end: p + len };
  };
  const seq = tlv(0);
  if (!seq) {
    return null;
  }
  let p = seq.start;
  let fifth = null;
  for (let i = 0; i < 5 && p < seq.end; i++) {
    const t = tlv(p);
    if (!t) {
      return null;
    }
    fifth = t;
    p = t.end;
  }
  if (!fifth || fifth.tag !== 0x04 || fifth.end - fifth.start < 16) {
    return null;
  }
  return stsCrypto.sha256Hex(der.subarray(fifth.start, fifth.end));
}

/**
 * Records the name a full TLS 1.2 handshake was made under (#507), in the
 * listener's own record and, where minted state persists, in the
 * replicated store.
 *
 * @param record - the listener's Map
 * @param key - the master-secret digest
 * @param name - the server name the hello offered ('' for none)
 * @param ttlMs - the listener's session lifetime
 */
// A hot path, as above.
function rememberTicketName(record, key, name, ttlMs) {
  const now = Date.now();
  record.delete(key);
  record.set(key, { servername: name, at: now });
  while (record.size > TICKET_NAME_ENTRIES) {
    record.delete(record.keys().next().value);
  }
  try {
    ticketNamesShared.delete(key);
    cacheRegistry.makeRoom(ticketNamesShared, TICKET_NAME_SHARED_ENTRIES, {
      expired: function (row) {
        return !row || Number(row.until) <= now;
      }
    });
    ticketNamesShared.set(key, { servername: name, until: now + ttlMs });
    // FLUSHED NOW, NOT AT THE NEXT UNRELATED WRITE (2026-10-27): a client
    // resumes within milliseconds of its full handshake, on whichever node
    // the balancer picks, and that node's read barrier can only see a row
    // that has been COMMITTED. The minted flush coalesces concurrent
    // callers into one write (persistence_minted.js), and nothing here
    // waits for it.
    const flushed = require('../persistence/persistence').flushMinted();
    Promise.resolve(flushed).then(function () {
      return null;
    }, function (e) {
      log.debug('Caught flushing a ticket name: ' + ((e && e.message) || e));
      return null;
    });
  } catch (e) {
    log.debug('Caught in rememberTicketName(): ' + ((e && e.message) || e));
  }
}

/**
 * The name a resumed TLS 1.2 session was made under (#507): the listener's
 * own record first, then the replicated store. Null where neither knows.
 *
 * @param record - the listener's Map
 * @param key - the master-secret digest
 * @param ttlMs - the listener's session lifetime
 * @returns the name, or null
 */
// A hot path, as above.
function recordedTicketName(record, key, ttlMs) {
  const now = Date.now();
  const own = record.get(key);
  if (own && now - own.at <= ttlMs && typeof own.servername === 'string') {
    return own.servername;
  }
  let shared = null;
  try {
    shared = ticketNamesShared.get(key);
  } catch (e) {
    log.debug('Caught in recordedTicketName(): ' + ((e && e.message) || e));
  }
  if (shared && Number(shared.until) > now &&
      typeof shared.servername === 'string') {
    return shared.servername;
  }
  return null;
}

/**
 * Attaches a session-ID cache to a TLS server, bounded by the listener's
 * policy, and resuming a session only under the server name it was made
 * under.
 *
 * @param server - the TLS server
 * @param kind - the listener's kind, as for `policyFor()`
 * @param realmId - for a custom listener, its id (#472)
 * @returns the cache, for its report
 */
function attachSessionCache(server, kind, realmId) {
  log.debug('Entering attachSessionCache(). ' + kind);
  if (!server || typeof server.on !== 'function') {
    log.debug('Leaving attachSessionCache(). Not a server.');
    return null;
  }
  if (installClientHelloHook()) {
    installSessionNameSniffer(server);
  }
  helloWatchedServers.add(server);
  const cache = new Map();
  const bounds = function () {
    const policy = policyFor(kind, realmId);
    return { size: policy.sessionCacheSize,
             ttlMs: policy.sessionTimeoutS * 1000 };
  };
  server.on('newSession', function (id, data, done) {
    const b = bounds();
    if (b.size > 0) {
      const key = Buffer.from(id).toString('hex');
      cache.delete(key);
      cache.set(key, { data: data, at: Date.now(),
                       servername: offeredHello ? offeredHello.servername
                         : null });
      while (cache.size > b.size) {
        cache.delete(cache.keys().next().value);
      }
    } else {
      cache.clear();
    }
    done();
  });
  server.on('resumeSession', function (id, done) {
    const b = bounds();
    const key = Buffer.from(id).toString('hex');
    const held = b.size > 0 ? cache.get(key) : null;
    if (held && Date.now() - held.at <= b.ttlMs) {
      if (sameServerName(held, offeredHello)) {
        done(null, held.data);
        return;
      }
      // Not resumed, and not forgotten: the session is still good for the
      // name it was made under. The full handshake makes a new one.
      log.debug('tls: a ' + kind + ' session ID offered under another ' +
                'server name is not resumed (RFC 6066 section 3).');
      done(null, null);
      return;
    }
    cache.delete(key);
    done(null, null);
  });
  // THE TLS 1.2 TICKET'S NAME (#507; the block above the sniffer). First
  // among the listeners, so a connection resumed under another name is
  // closed before node's HTTP server, the connection observer or anything
  // else reads it, which is `refuseNonNistCurveCertificatesOn()`'s
  // arrangement for a chain it refuses.
  const ticketNames = new Map();
  server.prependListener('secureConnection', function (socket) {
    let protocol = null;
    try {
      protocol = typeof socket.getProtocol === 'function'
        ? socket.getProtocol() : null;
    } catch (e) {
      log.debug('Caught in the ticket-name check: ' +
                ((e && e.message) || e));
    }
    if (protocol !== 'TLSv1.2' || socket.destroyed) {
      return;
    }
    const ttlMs = bounds().ttlMs;
    const key = masterSecretDigest(socket);
    const offered = helloServerName(socket);
    let reused = false;
    try {
      reused = typeof socket.isSessionReused === 'function' &&
               socket.isSessionReused();
    } catch (e) {
      log.debug('Caught in the ticket-name check: ' +
                ((e && e.message) || e));
    }
    if (!reused) {
      if (key && offered !== null) {
        rememberTicketName(ticketNames, key, offered, ttlMs);
      }
      return;
    }
    const judge = function (madeUnder) {
      log.debug('Entering judge().');
      if (madeUnder === null || offered === null) {
        // Fails CLOSED, as the session-ID cache does: a session this
        // process cannot vouch for is not answered under a name nobody
        // compared.
        log.info(errorCodes.tag('STS-TLS-0053') + 'tls: a ' + kind +
                 ' TLS 1.2 session was resumed by ticket whose server ' +
                 'name this node does not know (' + (madeUnder === null
                   ? 'no record of the session'
                   : 'the hello\'s name was not read') + '); the ' +
                 'connection is closed (RFC 6066 section 3).');
        socket.destroy();
        log.debug('Leaving judge(). No record.');
        return;
      }
      if (madeUnder !== offered) {
        log.info(errorCodes.tag('STS-TLS-0052') + 'tls: a ' + kind +
                 ' TLS 1.2 session made under ' + JSON.stringify(madeUnder) +
                 ' was resumed by ticket under ' + JSON.stringify(offered) +
                 '; the connection is closed (RFC 6066 section 3).');
        socket.destroy();
      }
      log.debug('Leaving judge().');
    };
    const madeUnder = key ? recordedTicketName(ticketNames, key, ttlMs)
                          : null;
    if (madeUnder !== null || offered === null || !key) {
      judge(madeUnder);
      return;
    }
    // NO RECORD HERE YET: ONE READ BARRIER BEFORE THE VERDICT (2026-10-27).
    // Behind a balancer the ticket was made on another node seconds or
    // milliseconds ago, and its `tls.ticketNames` row is still on the
    // change log this node has not pulled — the cluster mode's tlsfuzzer
    // (test-session-ticket-resumption over sts-lb) closed every such
    // resumption, which is every quick reconnect a real client makes. The
    // socket is held (an explicit pause survives the HTTP server's own
    // 'data' listener), everything committed before this moment is pulled
    // (`persistence.syncNow()`, bounded by its own deadline; a memory
    // store answers at once with nothing to pull), and the record is read
    // again. A mismatch still closes without waiting, above.
    // Asked up to TICKET_NAME_BARRIERS times, a short pause between: the
    // making node flushes the row as it records it (rememberTicketName()),
    // but that commit and this node's pull are two processes' timers, and
    // one barrier can land between them.
    socket.pause();
    const barrierOnce = function () {
      log.debug('Entering barrierOnce().');
      let barrier = null;
      try {
        barrier = require('../persistence/persistence').syncNow();
      } catch (e) {
        log.debug('Caught in the ticket-name check: ' +
                  ((e && e.message) || e));
        barrier = null;
      }
      log.debug('Leaving barrierOnce().');
      return Promise.resolve(barrier).then(function () {
        return null;
      }, function (e) {
        log.debug('Caught in the ticket-name check\'s barrier: ' +
                  ((e && e.message) || e));
        return null;
      });
    };
    // A loop, not a chain: the pause between two barriers is a one-shot
    // delay inside one operation (tests/no_periodic_timers.js).
    const lookAgain = async function () {
      log.debug('Entering lookAgain().');
      let found = null;
      for (let left = TICKET_NAME_BARRIERS; left > 0; left--) {
        await barrierOnce();
        if (socket.destroyed) {
          log.debug('Leaving lookAgain(). Gone.');
          return null;
        }
        found = recordedTicketName(ticketNames, key, ttlMs);
        if (found !== null || left === 1) {
          break;
        }
        await new Promise(function (resolve) {
          setTimeout(resolve, TICKET_NAME_BARRIER_PAUSE_MS);
        });
      }
      log.debug('Leaving lookAgain().');
      return found;
    };
    lookAgain().then(function (found) {
      if (socket.destroyed) {
        return;
      }
      judge(found);
      if (!socket.destroyed) {
        socket.resume();
      }
    }, function (e) {
      log.debug('Caught in lookAgain(): ' + ((e && e.message) || e));
      if (!socket.destroyed) {
        socket.destroy();
      }
    });
  });
  sessionCaches.push({ kind: kind, realm: realmId || null, cache: cache,
                       ticketNames: ticketNames });
  log.debug('Leaving attachSessionCache().');
  return cache;
}

/** @type {Array<any>} */
const sessionCaches = [];

// ---------------------------------------------------------------------------
// HTTP CONNECTION POOLING, PER LISTENER (#429, 2026-10-02; #406's keep-alive
// on the main port made per listener and editable). The keep-alive and
// header timeouts, the requests one connection may carry and the connections
// held at once are properties of the http(s) server, read by node at each
// new connection or request, so a change is applied to the server object
// where it stands. An HTTP listener registers here; `reapplyPolicy()` re-applies.
// ---------------------------------------------------------------------------
/** @type {Array<any>} */
const httpListeners = [];

/**
 * The connection-pooling values one HTTP listener is held to: its own where
 * set, the service's otherwise.
 *
 * @param kind - `main`, `debugger`, `revocation` or `custom`
 * @param realmId - for `custom`, the listener's id
 * @returns `{ keepAliveTimeoutS, headersTimeoutS, maxRequestsPerSocket,
 *   maxConnections, http2, http2MaxConcurrentStreams }`, the header timeout
 *   resolved
 */
function httpPolicyFor(kind, realmId) {
  log.debug('Entering httpPolicyFor(). ' + kind);
  const pick = function (name, base) {
    const own = kind ? ownValue(kind, realmId, name) : undefined;
    return Number(own !== undefined ? own : config.value(base));
  };
  const keepAlive = Math.max(1, pick('keepAliveTimeoutS',
                                     'http.keepAliveTimeoutS') || 60);
  const asked = Math.max(0, pick('headersTimeoutS', 'http.headersTimeoutS') ||
                            0);
  // A boolean, so not through `pick()`'s Number(): the listener's own on or
  // off (`ownValue()` turns those into true and false; a custom listener's
  // definition may also say `"true"` or `"false"`), else the service's. A
  // value that is none of those follows the service's, as `inherit` does.
  const ownHttp2 = kind ? ownValue(kind, realmId, 'http2') : undefined;
  const ownSays = ownHttp2 === true || ownHttp2 === 'true' ? true
    : ownHttp2 === false || ownHttp2 === 'false' ? false : undefined;
  const http2 = ownSays !== undefined ? ownSays
                                      : config.value('http.http2') !== false;
  // THE STREAMS ONE HTTP/2 CONNECTION MAY HAVE OPEN AT ONCE (#407). 0 is not
  // a legal value (the row's `min` is 1), so the `||` only catches a value
  // that is not a number.
  const streams = Math.max(1, pick('http2MaxConcurrentStreams',
                                   'http.http2MaxConcurrentStreams') || 100);
  log.debug('Leaving httpPolicyFor().');
  return {
    keepAliveTimeoutS: keepAlive,
    // Kept ABOVE the keep-alive, so a connection reused at the last moment
    // never meets one this end is closing.
    headersTimeoutS: asked > keepAlive ? asked : keepAlive + 1,
    maxRequestsPerSocket: Math.max(0, pick('maxRequestsPerSocket',
                                           'http.maxRequestsPerSocket') || 0),
    maxConnections: Math.max(0, pick('maxConnections',
                                     'http.maxConnections') || 0),
    http2: http2,
    http2MaxConcurrentStreams: streams
  };
}

// WHAT ALPN OFFERS, as the TLS layer wants it: length-prefixed protocol
// names, most preferred first (RFC 7301 section 3.1). `http/1.1` is in both,
// so a client that asks only for it is answered either way.
const ALPN_HTTP2 = Buffer.from('\x02h2\x08http/1.1', 'latin1');
const ALPN_HTTP1 = Buffer.from('\x08http/1.1', 'latin1');

// Whether a registered server is node's http2 secure server, which has no
// exported class to test against.
function isHttp2Server(server) {
  log.debug('Entering isHttp2Server().');
  const yes = !!(server && server.constructor &&
                 server.constructor.name === 'Http2SecureServer');
  log.debug('Leaving isHttp2Server(). ' + yes);
  return yes;
}

// The pooling values onto the server object.
function applyHttpPolicy(entry) {
  log.debug('Entering applyHttpPolicy(). ' + entry.kind);
  const p = httpPolicyFor(entry.kind, entry.realm);
  entry.server.keepAliveTimeout = p.keepAliveTimeoutS * 1000;
  entry.server.headersTimeout = p.headersTimeoutS * 1000;
  entry.server.maxRequestsPerSocket = p.maxRequestsPerSocket;
  // 0 is "no limit" here and Infinity there: node refuses EVERY connection
  // at a maxConnections of 0.
  entry.server.maxConnections = p.maxConnections > 0 ? p.maxConnections
                                                     : Infinity;
  // HTTP/2 OFFERED OR NOT (#407). Only node's http2 secure server — built
  // with `allowHTTP1` for every TLS HTTP listener — speaks both, and it reads
  // `ALPNProtocols` at each new connection, so the offer changes here, in
  // place, for the next handshake; an open connection keeps its protocol. A
  // plain-HTTP server (the revocation listener, or the main port with
  // global.https off) has no handshake to offer it in.
  if (isHttp2Server(entry.server)) {
    entry.server.ALPNProtocols = p.http2 ? ALPN_HTTP2 : ALPN_HTTP1;
    // THE SAME BOUNDS ON AN HTTP/2 CONNECTION (#407). Node applies the
    // pooling values above to HTTP/1.1 only, so without these one HTTP/2
    // connection held open every stream a client asked for (node's own
    // SETTINGS_MAX_CONCURRENT_STREAMS is 2^32-1) for as long as it liked:
    // `maxConnections` bounded connections and nothing bounded the work on
    // each. `updateSettings()` is what a new session announces; an open one
    // is sent the new SETTINGS too, and given the new idle timeout.
    entry.server.updateSettings({
      maxConcurrentStreams: p.http2MaxConcurrentStreams });
    entry.policy = p;
    entry.sessions.forEach(function (session) {
      holdHttp2Session(entry, session);
    });
  }
  entry.applied = JSON.stringify(p);
  log.debug('Leaving applyHttpPolicy().');
}

/**
 * Holds one HTTP/2 session to its listener's policy as it now stands: the
 * stream cap, and the idle timeout. Called when the session opens and again
 * when the policy changes.
 *
 * - **Idle**: `keepAliveTimeoutS` with no frame either way, and the session
 *   is closed GRACEFULLY — a GOAWAY, then whatever stream is still open
 *   finishes — which is what the keep-alive timeout does to an idle HTTP/1.1
 *   connection.
 * - **Streams**: the SETTINGS the session announces.
 *
 * @param entry - the listener's registration
 * @param session - the server's `Http2Session`
 */
function holdHttp2Session(entry, session) {
  log.debug('Entering holdHttp2Session(). ' + entry.kind);
  const p = entry.policy;
  if (!p || session.destroyed || session.closed) {
    log.debug('Leaving holdHttp2Session(). Nothing to hold.');
    return;
  }
  try {
    session.settings({ maxConcurrentStreams: p.http2MaxConcurrentStreams });
  } catch (e) {
    // A session part-way through closing refuses new SETTINGS; it is
    // about to go, and the next one announces the new value.
    log.debug('Caught in holdHttp2Session(): ' + ((e && e.message) || e));
  }
  session.setTimeout(p.keepAliveTimeoutS * 1000, function () {
    log.debug('tls: an idle HTTP/2 session on the ' + entry.kind +
              ' listener is closed after ' + p.keepAliveTimeoutS + ' s.');
    session.close();
  });
  log.debug('Leaving holdHttp2Session().');
}

/**
 * Follows the HTTP/2 sessions of one registered listener: each is held to
 * the policy when it opens (holdHttp2Session()), counted against
 * `maxRequestsPerSocket` — an HTTP/2 connection carries requests as
 * streams, and one that has carried its share is sent a GOAWAY after the
 * last, so the client opens a new one exactly as it would over HTTP/1.1 —
 * and forgotten when it closes.
 *
 * @param entry - the listener's registration
 */
function followHttp2Sessions(entry) {
  log.debug('Entering followHttp2Sessions(). ' + entry.kind);
  entry.server.on('session', function (session) {
    entry.sessions.add(session);
    holdHttp2Session(entry, session);
    let carried = 0;
    // Once per stream; no Entering/Leaving pair (a hot path).
    session.on('stream', function () {
      carried += 1;
      const most = entry.policy ? entry.policy.maxRequestsPerSocket : 0;
      if (most > 0 && carried >= most && !session.closed) {
        session.close();
      }
    });
    session.once('close', function () {
      entry.sessions.delete(session);
    });
  });
  log.debug('Leaving followHttp2Sessions().');
}

/**
 * Registers an http(s) server whose connection pooling follows its
 * listener's settings, now and whenever they change.
 *
 * @param server - the http or https server
 * @param kind - `main`, `debugger`, `revocation` or `custom`
 * @param realmId - for `custom`, the listener's id
 * @returns a function that unregisters it
 */
function registerHttpListener(server, kind, realmId) {
  log.debug('Entering registerHttpListener(). ' + kind);
  const entry = { server: server, kind: String(kind), realm: realmId || null,
                  applied: '', policy: null, sessions: new Set() };
  httpListeners.push(entry);
  if (isHttp2Server(server)) {
    followHttp2Sessions(entry);
  }
  applyHttpPolicy(entry);
  log.debug('Leaving registerHttpListener().');
  return function unregister() {
    log.debug('Entering unregister(). ' + kind);
    const at = httpListeners.indexOf(entry);
    if (at >= 0) {
      httpListeners.splice(at, 1);
    }
    log.debug('Leaving unregister().');
  };
}

/**
 * What every listener this module knows is held to, for the Listeners page:
 * each one's label, kind, realm and policy as last applied.
 *
 * @returns the rows
 */
function listenerPolicies() {
  log.debug('Entering listenerPolicies().');
  const rows = externalServers.map(function (one) {
    return { label: one.label, kind: one.kind, realm: one.realm,
             policy: policyFor(one.kind, one.realm) };
  }).concat(policyAppliers.map(function (one) {
    return { label: one.label, kind: one.kind, realm: one.realm,
             policy: policyFor(one.kind, one.realm) };
  }));
  log.debug('Leaving listenerPolicies(). ' + rows.length);
  return rows;
}

// `options.source` is `runtime` unless a caller says otherwise — the file
// loader below pushes directly and marks its own rows `file` — and
// `options.strict` is the management door's: see the block above `truststore`
// at the foot of this section; the in-process tests' adds do not pass it.
/**
 * Adds the certificates in a PEM bundle to the client truststore, storing
 * runtime anchors so they survive a restart, and applies it to every registered
 * listener.
 *
 * @param text - the PEM bundle
 * @param options - `source` (default `runtime`), `strict` (refuse the whole
 * bundle if any block cannot be read) and `addedBy`
 * @returns `{ added, duplicates, total }`, or with `error` and `errorCode` when
 * nothing was added
 */
function addAnchors(text, options) {
  log.debug('Entering addAnchors().');
  const opts = options || {};
  const found = splitPemCertificates(text);
  if (!found.length) {
    log.debug('Leaving addAnchors(). Nothing that looks like a certificate.');
    return { added: 0, total: anchors.length, errorCode: 'STS-TLS-0012', error:
      'No PEM certificate was found in the body. Send one or more ' +
      '-----BEGIN CERTIFICATE----- blocks, as raw text or as the ' +
      '`certificates` field of a form or JSON body.' };
  }
  // STRICT MEANS ALL OR NOTHING, AND IT IS CHECKED BEFORE ANYTHING IS PUSHED.
  // A bundle of three whose second block OpenSSL cannot read must not leave
  // the first in force and report a refusal: the caller would read "refused"
  // and the listener would have changed.
  const described = found.map(function (pem) { return describePem(pem); });
  if (opts.strict) {
    const unreadable = described.filter(function (
        one) { return !one.readable; });
    if (unreadable.length) {
      log.debug('Leaving addAnchors(). ' + unreadable.length + ' unreadable.');
      return { added: 0, total: anchors.length, errorCode: 'STS-TLS-0013',
               error:
        unreadable.length + ' of the ' + found.length + ' certificate(s) ' +
        'sent could not be read by OpenSSL, which is what the listeners ' +
        'verify against — so none was added. A block OpenSSL cannot parse is ' +
        'not an anchor it will use, and putting one in the truststore makes ' +
        'the next setSecureContext() on every listener throw.' };
    }
  }
  let added = 0;
  let duplicates = 0;
  for (const one of described) {
    const already = anchors.some(function (anchor) {
      return anchor.fingerprint256 === one.fingerprint256;
    });
    if (already) {
      duplicates += 1;
      continue;
    }
    if (anchors.length >= MAX_ANCHORS) {
      if (added) applyAnchors();
      log.debug('Leaving addAnchors(). The truststore is full.');
      return { added: added, duplicates: duplicates, total: anchors.length,
        errorCode: 'STS-TLS-0014',
        error: 'This truststore holds at most ' + MAX_ANCHORS + ' anchors; ' +
          added + ' were added before it filled up. Remove one first — ' +
          'POST /admin-api/tls/trust/remove, or the row button on ' +
          '/admin/tls/trust.' };
    }
    const pushed = Object.assign(one, {
      source: opts.source === 'file' ? 'file' : 'runtime',
      addedAt: new Date().toISOString()
    });
    // WRITTEN DOWN AS IT IS ADDED, where a store is installed and the anchor is
    // not one the file will bring back. `stored` is what
    // `reloadStoredAnchors()` reads to tell an anchor the store forgot (another
    // process removed it) from one the store never had (the directory was
    // full).
    if (pushed.source === 'runtime') {
      pushed.stored = storeAnchor(pushed, opts);
    }
    anchors.push(pushed);
    added += 1;
    log.info('tls: trusting client certificates issued by ' +
             one.subject + ' (' + one.fingerprint256 + ')');
  }
  if (added) applyAnchors();
  log.debug('Leaving addAnchors(). added=' + added + ' duplicates=' +
            duplicates);
  return { added: added, duplicates: duplicates, total: anchors.length };
}

// ---------------------------------------------------------------------------
// ONE ANCHOR TAKEN AWAY, BY ITS SHA-256 FINGERPRINT (2026-09-12).
//
// The management door's remove. There is deliberately no bulk counterpart on
// that door: `clearAnchors()` is what the in-process tests call (`POST
// /tls/trust/clear` did until #597 deleted it), and a
// bulk clear is exactly what `tests/CLAUDE.md` records costing a remote PEP its
// identity for the rest of a run. A caller that means to empty the truststore
// removes what it can see, one row at a time, and the rows it did not put
// there are the ones it has to name.
//
// The fingerprint is compared NORMALISED — colons and case removed — because
// the colon form is what `openssl x509 -fingerprint -sha256` prints and plain
// hex is what most other tools print, and a refusal that said "no such anchor"
// about the anchor on the screen would be a control that works for one of two
// spellings of the same number.
// ---------------------------------------------------------------------------
function normalisedFingerprint(value) {
  log.debug("Entering normalisedFingerprint().");
  log.debug("Leaving normalisedFingerprint().");
  return String(value || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
}

/**
 * Removes one anchor from the client truststore by its SHA-256 fingerprint.
 *
 * @param fingerprint - 64 hex digits, with or without colons
 * @returns `{ removed, total }`, or with `error` and `errorCode`
 */
function removeAnchor(fingerprint) {
  log.debug('Entering removeAnchor().');
  const wanted = normalisedFingerprint(fingerprint);
  if (wanted.length !== 64) {
    log.debug('Leaving removeAnchor(). Not a SHA-256 fingerprint.');
    return { removed: 0, total: anchors.length, errorCode: 'STS-TLS-0015',
             error:
      'Name the anchor by its SHA-256 fingerprint in `fingerprint` — 64 hex ' +
      'digits, with or without the colons `openssl x509 -fingerprint ' +
      '-sha256` prints. Nothing was removed.' };
  }
  const index = anchors.findIndex(function (anchor) {
    return normalisedFingerprint(anchor.fingerprint256) === wanted;
  });
  if (index < 0) {
    log.debug('Leaving removeAnchor(). Not held.');
    return { removed: 0, total: anchors.length, errorCode: 'STS-TLS-0016',
             error:
      'This truststore holds no anchor with the SHA-256 fingerprint ' +
      String(fingerprint) + '. Nothing was removed.' };
  }
  const gone = anchors.splice(index, 1)[0];
  if (gone.stored) {
    unstoreAnchor(gone.fingerprint256);
  }
  applyAnchors();
  log.info('tls: no longer trusting client certificates issued by ' +
           gone.subject + ' (' + gone.fingerprint256 + '), which came from ' +
           (gone.source === 'file' ? 'tls.trustAnchorsFile' : 'a runtime add') +
           '. ' + anchors.length + ' anchor(s) remain.');
  log.debug('Leaving removeAnchor().');
  return { removed: 1, total: anchors.length, anchor: publicAnchor(gone) };
}

// An anchor as it is REPORTED. The PEM is included — it is a certificate, the
// half of a key pair meant to be handed around, and this truststore holds no
// private key of anybody's — and the record is COPIED, because the array is
// the listeners' and a caller that mutated a row it was handed would change
// what a page says without changing what a handshake reads.
function publicAnchor(anchor) {
  log.debug("Entering publicAnchor().");
  log.debug("Leaving publicAnchor().");
  return {
    subject: anchor.subject, issuer: anchor.issuer, serial: anchor.serial,
    notBefore: anchor.notBefore, notAfter: anchor.notAfter,
    fingerprint256: anchor.fingerprint256, ca: !!anchor.ca,
    readable: !!anchor.readable,
    source: anchor.source === 'file' ? 'file' : 'runtime',
    // Whether this anchor survives a restart. A `file` anchor does, because
    // the file brings it back; a `runtime` one does exactly when it was
    // written to ou=trustAnchors, which fails only on a full directory or in
    // a process with no directory installed.
    persisted: anchor.source === 'file' ? true : !!anchor.stored,
    addedAt: anchor.addedAt || '', pem: anchor.pem
  };
}

function listAnchors() {
  log.debug("Entering listAnchors().");
  log.debug("Leaving listAnchors().");
  return {
    anchors: anchors.map(publicAnchor),
    max: MAX_ANCHORS,
    file: anchorsFileReport.file || '',
    loadedFromFile: anchorsFileReport.loaded,
    // Whether a runtime add is written down at all. With a store installed it
    // lands in ou=trustAnchors, which survives a restart wherever the
    // directory does — the `ldif` and `postgres` persistence modes — and
    // reaches every other process against the same store. In `memory` mode the
    // directory itself dies with the process, and this still answers true:
    // the anchor was stored, and the store was not kept.
    stored: !!trustAnchorStore
  };
}

// ---------------------------------------------------------------------------
// THE TRUSTSTORE'S DURABLE HALF (2026-09-12), AND WHY IT IS A SLOT.
//
// An anchor added at runtime used to live exactly as long as the process — the
// note above `anchors` argued that, and it was right about SHARING (the array
// is the listeners', and a worker's copy configures nothing) and silent about
// SURVIVING, which is a different question. A product deployment that added
// its PEP's CA through the gated door lost it at the next restart, with every
// remote PEP failing to authenticate and nothing on any page saying why.
//
// **THE STORE IS THE DIRECTORY**, `ou=trustAnchors` in the DEFAULT realm, and
// `ldap/ldap_server.js` owns it. That module argues the choice; what matters
// here is that it persists in every store mode and replicates between
// processes, so an anchor added in one front process reaches another through
// the change log and `reloadStoredAnchors()`.
//
// **A SLOT BECAUSE A REQUIRE CANNOT WORK IN EITHER DIRECTION.** This module is
// loaded from inside `admin-ui/admin.ts`'s require, long before the directory
// module, and a require from here to it would register every /ldap route ahead
// of the console's (rule 3e); the directory module requires THIS one for its
// LDAPS certificate, so it fills the slot with a call in the ordinary
// direction. With nothing installed — `npm test`, the parent project's
// in-process Kerberos jobs — the truststore behaves exactly as it always did.
//
// The array is still the truth for a HANDSHAKE. The store is what the array is
// rebuilt from at start and after another process changes it.
// ---------------------------------------------------------------------------
let trustAnchorStore = null;

/**
 * Installs the durable store for runtime trust anchors (`ou=trustAnchors`); a
 * store without `list`, `write` and `remove` is refused whole.
 *
 * @param store - the store
 * @returns true when it was installed
 */
function setTrustAnchorStore(store) {
  log.debug('Entering setTrustAnchorStore().');
  const needed = ['list', 'write', 'remove'];
  const missing = needed.filter(function (name) {
    return !store || typeof store[name] !== 'function';
  });
  if (missing.length) {
    // Refused WHOLE, for `setLogoutReader()`'s reason: a store that could write
    // and not list would record anchors that never came back, which is the
    // failure this slot exists to remove, dressed as working.
    log.error(errorCodes.tag('STS-TLS-0027') + 'tls: setTrustAnchorStore() ' +
                                               'was given something without ' +
              missing.join(', ') + ', and was ignored whole. Runtime trust ' +
              'anchors will not survive a restart.');
    log.debug('Leaving setTrustAnchorStore(). Refused.');
    return false;
  }
  trustAnchorStore = store;
  log.debug('Leaving setTrustAnchorStore(). Installed.');
  return true;
}

function storeAnchor(anchor, options) {
  log.debug("Entering storeAnchor().");
  if (!trustAnchorStore) {
    log.debug("Leaving storeAnchor().");
    return false;
  }
  try {
    log.debug("Leaving storeAnchor().");
    return trustAnchorStore.write(normalisedFingerprint(anchor.fingerprint256),
                                  anchor.pem,
                                  { addedBy: (options &&
                                              options.addedBy) || '' }) !== false;
  } catch (e) {
    // Reported rather than thrown: the anchor is IN FORCE on every listener
    // already, and a caller told "refused" would retry an add that worked. What
    // is lost is the restart, which the `persisted: false` on its row says.
    log.error(errorCodes.tag('STS-TLS-0028') + 'tls: trust anchor ' +
              anchor.fingerprint256 + ' ' +
              'is in force and could not be written to the directory, so it ' +
              'will not survive a restart: ' + e.message);
    log.debug("Leaving storeAnchor().");
    return false;
  }
}

function unstoreAnchor(fingerprint) {
  log.debug("Entering unstoreAnchor().");
  if (!trustAnchorStore) {
    log.debug("Leaving unstoreAnchor().");
    return;
  }
  try {
    trustAnchorStore.remove(normalisedFingerprint(fingerprint));
  } catch (e) {
    // Reported rather than thrown, for storeAnchor()'s reason: the anchor is
    // already out of every listener, and what this failure costs is that the
    // next start brings it back — which the log line has to say.
    log.error(errorCodes.tag('STS-TLS-0029') + 'tls: trust anchor ' +
              fingerprint + ' ' +
              'was removed from every listener and could not be removed from ' +
              'the directory, so it will COME BACK at the next ' +
              'start: ' + e.message);
  }
  log.debug("Leaving unstoreAnchor().");
}

// ---------------------------------------------------------------------------
// REBUILD THE RUNTIME HALF OF THE ARRAY FROM THE STORE.
//
// Called at `listen()`, which is after `persistence.start()` restored the
// directory and before a listener binds, and by the directory's replication
// appliers when another process changes ou=trustAnchors. Three rules:
//
//   * a STORED anchor this array lacks is added (source `runtime`, stored);
//   * a runtime anchor this array holds as `stored` and the store no longer
//     has is REMOVED — another process removed it, and keeping it would leave
//     this listener trusting a CA the operator took away;
//   * a runtime anchor that was never stored (a full directory) and every
//     `file` anchor are left alone — the store has no opinion about either.
//
// It WRITES nothing, so calling it from inside an applier cannot echo a change
// back to the process that made it.
// ---------------------------------------------------------------------------
/**
 * Rebuilds the runtime half of the client truststore from the store: adds a
 * stored anchor it lacks, removes one another process removed, and leaves the
 * rest. It writes nothing.
 *
 * @returns `{ added, removed }`
 */
function reloadStoredAnchors() {
  log.debug('Entering reloadStoredAnchors().');
  if (!trustAnchorStore) {
    log.debug('Leaving reloadStoredAnchors(). No store installed.');
    return { added: 0, removed: 0 };
  }
  let rows = [];
  try {
    rows = trustAnchorStore.list() || [];
  } catch (e) {
    // The array is left exactly as it was: a store that could not be read is
    // not evidence that anything was removed, and treating it as empty would
    // take every stored anchor out of every listener.
    log.error(errorCodes.tag('STS-TLS-0030') + 'tls: the stored trust ' +
              'anchors could not be read; the truststore is ' +
              'unchanged: ' + e.message);
    log.debug('Leaving reloadStoredAnchors(). The store threw.');
    return { added: 0, removed: 0 };
  }
  const storedPrints = new Set(rows.map(function (row) {
    return normalisedFingerprint(row.fingerprint || '');
  }));
  const before = anchors.length;
  anchors = anchors.filter(function (anchor) {
    return !(anchor.source === 'runtime' && anchor.stored &&
             !storedPrints.has(normalisedFingerprint(anchor.fingerprint256)));
  });
  const removed = before - anchors.length;
  let added = 0;
  rows.forEach(function (row) {
    if (anchors.length >= MAX_ANCHORS) {
      return;
    }
    const described = describePem(row.pem);
    const held = anchors.some(function (anchor) {
      return normalisedFingerprint(anchor.fingerprint256) ===
             normalisedFingerprint(described.fingerprint256);
    });
    if (held || !described.readable) {
      return;
    }
    anchors.push(Object.assign(described, {
      source: 'runtime', stored: true, addedAt: row.addedAt || ''
    }));
    added += 1;
  });
  if (added || removed) {
    applyAnchors();
    log.info('tls: the client truststore was brought in line with ' +
             'ou=trustAnchors: ' + added + ' anchor(s) restored, ' + removed +
             ' removed, ' + anchors.length + ' in force.');
  }
  log.debug('Leaving reloadStoredAnchors(). added=' + added + ' removed=' +
            removed);
  return { added: added, removed: removed };
}

/**
 * Empties the client truststore, removing stored anchors from the store as
 * well.
 *
 * @returns `{ removed, total }`
 */
function clearAnchors() {
  log.debug('Entering clearAnchors(). anchors=' + anchors.length);
  const removed = anchors.length;
  anchors.forEach(function (anchor) {
    if (anchor.stored) {
      unstoreAnchor(anchor.fingerprint256);
    }
  });
  anchors = [];
  applyAnchors();
  log.info('tls: the client truststore was emptied; ' + removed +
           ' anchor(s) removed. Every client certificate presented to this ' +
           'service is unverified again, so nothing that asks for a VERIFIED ' +
           'one — RFC 8705 client authentication, /xacml, GET /tls/sign-in — ' +
           'will accept any of them.');
  log.debug('Leaving clearAnchors().');
  return { removed: removed, total: 0 };
}

// ---------------------------------------------------------------------------
// Describing one connection.
// ---------------------------------------------------------------------------

// node hands a certificate's subject back as an object of arrays. Render it as
// the one-line DN everybody recognises, because that is the form a reader will
// compare with what their own tool printed.
function dnToString(dn) {
  log.debug("Entering dnToString().");
  if (!dn || typeof dn !== 'object') {
    log.debug("Leaving dnToString().");
    return String(dn || '');
  }
  log.debug("Leaving dnToString().");
  return Object.keys(dn).map(function (key) {
    const value = dn[key];
    return key + '=' + (Array.isArray(value) ? value.join('+') : value);
  }).join(', ');
}

// The SAME subject in RFC 4514 form, which is a different string and has to be.
//
// dnToString() above renders what a reader's own tool prints: node hands the
// subject back most-significant-first (`C=US, O=Example, CN=alice`) and openssl
// x509 -subject shows it that way too. A DN as LDAP writes it is the REVERSE,
// leaf first and with no spaces after the commas, and that is the form this
// service files the identity under and the directory builds an entry from.
//
// **THE FUNCTION ITSELF NOW LIVES IN `common/helpers.js`** and is re-exported
// from here unchanged, because the string has FOUR producers rather than two
// and two spellings of one DN is two people on /admin/users. `scim_auth.js`
// and `spiffe_auth.js` require this module for it and still may; `spiffe_ca.js`
// cannot — `admin.js` requires that module and is required BEFORE this one, so
// the require would move every `/tls*` route ahead of the console's — and it
// needs the same spelling for a certificate it has just MINTED. The header in
// `helpers.js` carries the whole argument, including the second shape of DN it
// learnt in order to serve that caller.
/**
 * Formats a subject as an RFC 4514 string; `common/helpers.js`'s, re-exported
 * for the modules that have always required it from here.
 */
const dnRfc4514 = helpers.dnRfc4514;

// The address in a certificate, if it carries one: the emailAddress RDN, or the
// first rfc822Name in the subjectAltName. Read rather than invented, because
// the directory entry this ends up on is derived from the certificate and an
// address the certificate does not carry would be this service making one up.
function emailOf(cert) {
  log.debug("Entering emailOf().");
  if (!cert) {
    log.debug("Leaving emailOf().");
    return '';
  }
  const subject = cert.subject || {};
  const fromDn = subject.emailAddress || subject.E || '';
  if (fromDn) {
    log.debug("Leaving emailOf().");
    return String(Array.isArray(fromDn) ? fromDn[0] : fromDn);
  }
  const san = String(cert.subjectaltname || '');
  const match = san.match(/email:([^,]+)/i);
  log.debug("Leaving emailOf().");
  return match ? match[1].trim() : '';
}

function describeCertificate(cert, depth) {
  log.debug('Entering describeCertificate(). depth=' + depth);
  if (!cert || !Object.keys(cert).length) {
    log.debug('Leaving describeCertificate(). Nothing was presented.');
    return null;
  }
  const out = {
    depth: depth,
    subject: dnToString(cert.subject),
    issuer: dnToString(cert.issuer),
    serialNumber: cert.serialNumber || null,
    validFrom: cert.valid_from || null,
    validTo: cert.valid_to || null,
    subjectAltName: cert.subjectaltname || null,
    extendedKeyUsage: cert.ext_key_usage || null,
    keySize: cert.bits || null,
    curve: cert.nistCurve || cert.asn1Curve || null,
    fingerprint256: cert.fingerprint256 || null,
    pem: cert.raw
      ? '-----BEGIN CERTIFICATE-----\n' +
        (cert.raw.toString('base64').match(/.{1,64}/g) || []).join('\n') +
        '\n-----END CERTIFICATE-----\n'
      : null
  };
  log.debug('Leaving describeCertificate(). subject=' + out.subject);
  return out;
}

// The revocation verdict for whatever this socket presented, or null when it
// presented nothing. NEVER REJECTS: a check that threw is reported as unknown
// by `revocation_status.js` itself, and the caller must answer either way.
function checkedSocket(socket) {
  log.debug('Entering checkedSocket().');
  const input = revocationStatus.fromSocket(socket);
  if (!input) {
    log.debug('Leaving checkedSocket(). Nothing presented.');
    return Promise.resolve(null);
  }
  log.debug('Leaving checkedSocket(). The verdict follows.');
  return revocationStatus.verdictFor(input).then(function (verdict) {
    return verdict;
  }, function (e) {
    log.error(errorCodes.tag('STS-PKI-0121') + 'tls: the revocation check ' +
              'rejected, which it must not do; treated as not consulted: ' +
              e.message);
    return null;
  });
}

// ---------------------------------------------------------------------------
// A VERIFIED CLIENT CERTIFICATE IS A SIGN-IN (2026-09-05), AND THIS FILE
// ARGUED AT LENGTH THAT IT WAS NOT.
//
// **THE OLD POSITION IS BELOW, KEPT RATHER THAN DELETED**, because it was a
// good argument and knowing what it protected is how to avoid losing that when
// changing it. What it said was that verification means exactly one thing —
// OpenSSL built a chain from what the client sent to an anchor somebody added
// through `/admin-api/tls/trust` — and that turning it into an identity
// would teach a client
// something false about every server it will ever meet.
//
// **WHAT THE ARGUMENT ACTUALLY PROTECTED WAS THE STRENGTH OF THE CLAIM, NOT
// THE ABSENCE OF THE SESSION.** PKI client-certificate authentication is a
// real, deployed way for a person to sign in to a web application; the thing a
// mock must not do is pretend the chain check proved more than it did. Every
// other family here resolves the same tension the same way and has for as long
// as this service has existed, in development mode: the KDC issues tickets to
// anybody who asks with the one shared password, the sign-in screen checks no
// password at all, LDAP refuses no bind — and all three start real sessions
// (product mode verifies all three). **The permissiveness
// lives in what is accepted, not in refusing to record what was accepted.**
//
// SO THREE THINGS ARE TRUE AT ONCE AND THIS FUNCTION KEEPS THEM APART:
//
//   * the certificate VERIFIED — a chain to an anchor an operator installed,
//     which is all `socket.authorized` says;
//   * ITS REVOCATION IS WHATEVER THE CHECK FOUND. This bullet read "no
//     revocation was checked" until 2026-09-12; the verdict is consulted
//     first now (below), and every report repeats what it found;
//   * a SESSION EXISTS, which is this service tracking that the holder of that
//     certificate got in — and which is what makes a global sign-out able to
//     end it. Without it, an identity provider that had "signed somebody out"
//     would leave a live way in that nothing on `/admin/sessions` could see.
//
// THE USERNAME IS THE COMMON NAME where the certificate has one, and the RFC
// 4514 subject otherwise. That is the one decision here that is not forced, and
// it is made this way so a certificate naming `CN=alice` signs in the SAME
// alice the password screen, the KDC and the SAML profile do — one entry per
// person, whatever they authenticated with, which is a rule this repository
// already keeps in eight places. Recording still uses the full subject, because
// what goes in the DIRECTORY is the certificate's own identity.
//
// `amr` IS `["swk"]` — RFC 8176's software-key authenticator — and `acr` is
// `"1"`. One factor, and a factor whose private key sits in a file: claiming
// `hwk` would say a hardware key was used, and this service cannot know that.
//
// IT IS ONE SESSION PER BROWSER AT MOST, not one per request: the cookie
// comes back on the next request and is honoured, so six requests to
// /tls/sign-in are one sign-in. That is the same property
// `recordClientCertificate()` achieves by living on `secureConnection`, arrived
// at differently because a cookie needs a response to be written on and
// `secureConnection` has none.
// ---------------------------------------------------------------------------
function startCertificateSession(req, res, mode, revocation, identity) {
  log.debug('Entering startCertificateSession(). mode=' + mode);
  const checked = certificateRefusal(req.socket, mode, revocation, identity);
  if (checked.refusal) {
    log.debug('Leaving startCertificateSession(). Refused.');
    return checked.refusal;
  }
  const gated = checked.gated;
  // A TLS CLIENT OR ENROLLED CERTIFICATE SIGNS ITS HOLDER IN TO ITS OWN REALM,
  // which is the realm of the authority that signed it; this socket has no
  // path to carry one. Everything below — the existing-session read, the
  // session store, the issuance policy — runs in that realm.
  log.debug('Leaving startCertificateSession(). Continuing in the ' +
            'certificate\'s realm.');
  return inCertificateRealm(gated, function () {
    return startCertificateSessionIn(req, res, mode, revocation, gated);
  });
}

// ---------------------------------------------------------------------------
// THE FOUR REFUSALS EVERY CERTIFICATE SIGN-IN MAKES FIRST, IN THIS ORDER
// (#1051, 2026-10-27: moved out of `startCertificateSession()` unchanged, so
// that the sign-in screen's "Continue with your certificate" asks exactly
// what `GET /tls/sign-in` asks rather than a copy of it): nothing verified,
// refused on revocation, a certificate of this service's that is not an
// identity, and an application's certificate. Answers `{ refusal }` — the
// object `GET /tls/sign-in` reports as `session` — or `{ refusal: null,
// gated }`, the identity gate's answer, for the caller to go on with.
// ---------------------------------------------------------------------------
function certificateRefusal(socket, mode, revocation, identity) {
  log.debug('Entering certificateRefusal(). mode=' + mode);
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving certificateRefusal(). Nothing verified here.');
    return { gated: null, refusal: { started: false,
             why: 'no verified client certificate on this connection, so ' +
                  'there is nobody to sign in' } };
  }
  // REFUSED ON REVOCATION (2026-09-12), before the existing-session read below:
  // a browser already holding a session is not handed a new one, and a revoked
  // certificate must not be the thing that is reported as having "already" got
  // in. The session is the one thing this function gives out, so it is the
  // point the refusal is made at.
  if (revocation && revocation.refused) {
    log.info('tls: a verified client certificate on the ' + mode + ' ' +
             'listener was refused a session on revocation: ' + revocation.why);
    log.debug('Leaving certificateRefusal(). Refused on revocation.');
    return { gated: null, refusal: { started: false,
                                     refusedOnRevocation: true,
             why: 'the certificate verified and was REFUSED ON REVOCATION ' +
                  '(pki.revocationCheck is ' + revocation.policy + '): ' +
                  revocation.why } };
  }
  // NOT AN IDENTITY (2026-09-13): a chain through this service's own Root from
  // an authority that does not issue TLS client identities. See
  // `issuedClientCertificateAnchor()` for why that Root is trusted at all and
  // why trusting it is not trusting everything under it.
  const gated = identity || issuedIdentityOf(socket, { stored: true });
  // AN OUTSIDE AUTHORITY'S CERTIFICATE NOT STORED ON EXACTLY ONE ENTRY
  // (#1061, rcbj 2026-10-27). Until then such a certificate signed in by its
  // common name, and seeded a directory entry for it; now it is the one entry
  // storing it in `userCertificate`, or nobody.
  if (!gated.issuedHere && gated.outside === true && !gated.accepted) {
    log.info('tls: a verified client certificate from an outside ' +
             'certificate authority on the ' + mode + ' listener started ' +
             'no session: ' + gated.why + '.');
    log.debug('Leaving certificateRefusal(). An outside certificate, ' +
              'not stored on one entry.');
    return { gated: gated, refusal: { started: false,
                                      refusedAsStored: String(gated.error),
             why: 'the certificate verified and is NOT AN IDENTITY here: ' +
                  gated.why } };
  }
  if (gated.issuedHere && !gated.accepted) {
    log.info('tls: a verified client certificate on the ' + mode + ' ' +
             'listener was issued by this service and is not a TLS client ' +
             'identity, so no session was started: ' + gated.why + '.');
    log.debug('Leaving certificateRefusal(). Not an identity.');
    return { gated: gated, refusal: { started: false,
                                      refusedAsIdentity: true,
             why: 'the certificate verified and is NOT AN IDENTITY here: ' +
                  gated.why } };
  }
  // AN APPLICATION'S CERTIFICATE IS A CLIENT CREDENTIAL AND NOT A SIGN-IN
  // (2026-09-13). The identity gate accepts a leaf naming a
  // urn:sts:application: — that is what RFC 8705's implicit mapping at the
  // token endpoint reads — and until then this function started a browser
  // sign-on session for whatever name it carried, so an application whose
  // identifier happened to be a person's username signed in AS that person.
  // It became reachable by anybody holding such a certificate the day the
  // application Credentials section started issuing them.
  if (gated.accepted && gated.kind === 'application') {
    log.info('tls: a verified client certificate on the ' + mode + ' ' +
             'listener was issued to the application ' + gated.username +
             ', which authenticates at the token endpoint (RFC 8705) and ' +
             'signs nobody in, so no session was started.');
    log.debug('Leaving certificateRefusal(). An application.');
    return { gated: gated, refusal: { started: false,
                                      application: gated.username,
             why: 'the certificate verified and was issued to the ' +
                  'application "' + gated.username + '"; an application ' +
                  'presents it at the token endpoint under RFC 8705, and it ' +
                  'is not a browser sign-in' } };
  }
  log.debug('Leaving certificateRefusal(). None.');
  return { refusal: null, gated: gated };
}

// WHAT A CLIENT CERTIFICATE SAYS ABOUT ITS HOLDER, in claim names (#127):
// the subject's common name, given name, surname and e-mail address (the
// attribute or an rfc822Name in subjectAltName), with the issuer, serial and
// start of validity an electronic_signature evidence element names.
function certificateFacts(cert) {
  log.debug('Entering certificateFacts().');
  const subject = (cert && cert.subject) || {};
  const first = function (value) {
    log.debug('Entering first().');
    log.debug('Leaving first().');
    return Array.isArray(value) ? String(value[0] || '') :
      String(value || '');
  };
  const claims = {};
  if (first(subject.CN)) {
    claims.name = first(subject.CN);
  }
  if (first(subject.GN)) {
    claims.given_name = first(subject.GN);
  }
  if (first(subject.SN)) {
    claims.family_name = first(subject.SN);
  }
  const email = first(subject.emailAddress) ||
    ((String((cert && cert.subjectaltname) || '')
      .match(/(?:^|,\s*)email:([^,\s]+)/) || [])[1] || '');
  if (email) {
    claims.email = email;
  }
  const started = Date.parse(String((cert && cert.valid_from) || ''));
  log.debug('Leaving certificateFacts(). ' + Object.keys(claims).length +
            ' claim(s).');
  return { claims: claims,
           issuer: cert && cert.issuer ? dnRfc4514(cert.issuer) : '',
           serial: String((cert && cert.serialNumber) || ''),
           notBefore: isNaN(started) ? '' :
             new Date(started).toISOString().replace(/\.\d+Z$/, 'Z') };
}

function startCertificateSessionIn(req, res, mode, revocation, gated) {
  log.debug('Entering startCertificateSessionIn(). mode=' + mode);
  const socket = req.socket;
  // ALREADY SIGNED IN ON THIS BROWSER. Read rather than replaced, so that a
  // second fetch of /tls/sign-in does not mint a second session for somebody
  // who already has one — which would leave a global sign-out reporting two
  // where the person experienced one.
  //
  // NOT WITH SEVERAL ACCOUNTS IN ONE BROWSER (#561): there "the browser's
  // session" is not one thing. `sessionOf()` answers nobody for a browser
  // holding two accounts and naming neither, and answered the cookie's
  // default — perhaps somebody else entirely — for one holding one; either
  // way the certificate's holder would be told they were "already" signed in
  // as whoever that was. So the question is asked of the CERTIFICATE'S
  // account, below, once its name is known: `startSession()` re-authenticates
  // that account's session where the browser's set holds it live (one live
  // session per person per browser, `authn/CLAUDE.md`) and adds one where it
  // does not. Still one session per person per browser, however many
  // fetches. Unchanged with `authn.multipleAccounts` off.
  const several = authn.multipleAccounts();
  const existing = several ? null : authn.sessionOf(req);
  if (existing) {
    log.debug('Leaving startCertificateSessionIn(). One was already open.');
    return { started: false, id: existing.id, username: existing.user &&
             existing.user.username,
             why: 'this browser already holds a sign-on session, and ' +
                  'presenting a certificate to this listener does not start ' +
                  'a second one' };
  }
  const peer = certificatePeer(socket, gated);
  if (!peer.ok) {
    log.debug('Leaving startCertificateSessionIn(). ' + peer.why);
    return { started: false, why: peer.why };
  }
  const cert = peer.cert;
  const subject = peer.subject;
  const username = peer.username;
  // WHICH OF THE BROWSER'S ACCOUNTS THIS IS (#561), for the answer: the
  // certificate's account live in the set is re-authenticated, any other
  // added.
  const held = several ? certificateAccountHeld(req, username) : null;
  let session = null;
  try {
    session = authn.startSession(res, username, ['swk'], '1',
                                 'a client certificate on the ' + mode +
                                 '-client-certificate listener',
                                 // Which certificate, as a thumbprint the
                                 // event fingerprints again (#62 P0).
                                 { request: req,
                                   credential: {
                                     kind: 'certificate',
                                     id: cert.fingerprint256 || '' } });
  } catch (e) {
    // Bookkeeping must never break a connection that has already been
    // accepted — the same rule recordClientCertificate() states.
    log.error(errorCodes.tag('STS-TLS-0017') +
              'tls: starting a session for the verified client certificate ' +
              'failed and was ignored; the connection is unaffected: ' +
              e.message);
    log.debug("Leaving startCertificateSessionIn().");
    return { started: false, why: 'starting the session threw: ' + e.message };
  }
  // THE ISSUANCE POLICY CAN REFUSE IT (2026-09-06), and a NULL is how
  // `startSession()` says so rather than a throw — which matters here more than
  // anywhere, because the `catch` above deliberately swallows a failure and
  // carries on. A refusal reaching that branch would have been reported as
  // bookkeeping and the session started anyway.
  //
  // The connection is untouched either way, and /tls/sign-in still reports
  // what arrived and whether it verified. What is refused is the SESSION,
  // which is the thing the policy is about.
  if (!session) {
    log.info('tls: the issuance policy refused a session for ' + username +
             ' on a verified client certificate (' + mode + ' listener). The ' +
             'handshake and the chain are unaffected and are still reported.');
    log.debug("Leaving startCertificateSessionIn().");
    return { started: false,
             why: 'the issuance policy refused a session for "' + username +
                  '". The certificate verified and the connection is ' +
                  'unaffected — this is a POLICY decision about the SESSION. ' +
                  'See /admin/roles and /admin/xacml.' };
  }
  // The sentence about revocation is the verdict's own since 2026-09-12. It
  // read NO REVOCATION WAS CHECKED here for a week, which was true then.
  const revocationSaid = revocation && revocation.checked
    ? 'its revocation was consulted (' + revocation.policy + '): ' +
      revocation.why
    : 'NO REVOCATION WAS CHECKED (pki.revocationCheck is off)';
  // AN IDENTITY VERIFICATION (#127): what the certificate's subject says
  // that the entry agrees with, as an electronic_signature under the
  // certificate's issuer and serial. Never throws, and switched by
  // `oauth2.idaAutomaticVerifications`.
  identityAssurance.recordAutomatic(username, 'certificate',
                                    certificateFacts(cert));
  log.info('tls: ' + username + ' is signed in on a verified client ' +
           'certificate ' +
           '(' + mode + ' listener). The chain verified and ' + revocationSaid);
  log.debug('Leaving startCertificateSessionIn(). Started ' + session.id + '.');
  const answer = { started: true, id: session.id, username: username,
           subject: subject,
           // The realm the session is in: the certificate's issuing authority's
           // for one this service issued, the default realm's otherwise.
           realm: realms.currentId(),
           note: 'the chain verified against an anchor in this service\'s ' +
                 'truststore and ' + revocationSaid + '. The session is this ' +
                 'service tracking that the holder got in, which is what ' +
                 'lets a global sign-out end it.' };
  // With several accounts on (#561), what became of the browser's set: the
  // certificate's account `reauthenticated` where it was already signed in
  // here, `added` beside the others where it was not. Absent off, so the
  // answer is then the one it always was.
  if (several) {
    answer.account = held ? 'reauthenticated' : 'added';
  }
  return answer;
}

// THE CERTIFICATE ON THE CONNECTION AND WHOM IT NAMES (#1051: moved out of
// `startCertificateSessionIn()` unchanged, for the sign-in screen's door):
// `{ ok: true, cert, subject, username }`, or `{ ok: false, why }` for a
// socket that went away, a resumed session that carries no certificate, or a
// certificate that names nobody.
function certificatePeer(socket, gated) {
  log.debug('Entering certificatePeer().');
  let cert = null;
  try {
    cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
  } catch (e) {
    // A socket that went away between the handshake and this line. Swallowed
    // for recordClientCertificate()'s reason: this runs inside the
    // handler that asked, and a throw here answers nothing.
    log.debug('Caught in certificatePeer(): the peer certificate could ' +
              'not be read: ' + ((e && e.message) || e));
    log.debug('Leaving certificatePeer(). Unreadable.');
    return { ok: false, why: 'the peer certificate could not be read' };
  }
  if (!cert || !Object.keys(cert).length) {
    // A RESUMED TLS SESSION carries no peer certificate — the client does not
    // send it again. Nothing is started, rather than a session with no identity
    // on it.
    log.debug('Leaving certificatePeer(). No peer certificate; a resumed ' +
              'session.');
    return { ok: false,
             why: 'the connection verified but carries no peer certificate, ' +
                  'which is what a resumed TLS session looks like' };
  }
  const subject = dnRfc4514(cert.subject);
  const common = cert.subject && cert.subject.CN
    ? String(Array.isArray(cert.subject.CN) ? cert.subject.CN[0] :
             cert.subject.CN)
    : '';
  // THE IDENTITY THE GATE ANSWERED, AND NOTHING ELSE (#1061): the
  // `urn:sts:person:` name this service's own authority wrote, or the entry
  // an outside authority's certificate is stored on. It was the common name,
  // else the subject, from 2026-09-05 until rcbj's decision on #1061 — a name
  // a certificate carries is a name its issuer chose, and an outside issuer
  // could choose anybody's.
  const username = gated && gated.accepted ? String(gated.username || '')
                                           : '';
  if (!username) {
    log.debug('Leaving certificatePeer(). Not an identity here.');
    return { ok: false,
             why: 'the certificate (' + (common || subject || 'no subject') +
                  ') names nobody here: an outside certificate authority\'s ' +
                  'certificate names only the one entry it is stored on ' +
                  '(userCertificate), and nothing is read off its common ' +
                  'name or subject' };
  }
  log.debug('Leaving certificatePeer(). ' + username);
  return { ok: true, cert: cert, subject: subject, username: username };
}

// THE CERTIFICATE'S ACCOUNT, LIVE IN THIS BROWSER'S SET (#561): the session
// the set holds for that person, or null. By name, as `startSession()`
// matches a re-authentication — the certificate names a login name, not a
// subject. [] — so null — with `authn.multipleAccounts` off.
function certificateAccountHeld(req, username) {
  log.debug('Entering certificateAccountHeld().');
  const wanted = String(username || '').toLowerCase();
  const found = authn.accountSessionsOf(req).filter(function (one) {
    return !!(one && one.user && wanted &&
              String(one.user.username || '').toLowerCase() === wanted);
  })[0] || null;
  log.debug('Leaving certificateAccountHeld(). ' +
            (found ? 'Held.' : 'Not held.'));
  return found;
}

// ---------------------------------------------------------------------------
// THE SIGN-IN SCREEN CONTINUES WITH THE CERTIFICATE ON THE CONNECTION (#1051,
// 2026-10-27).
//
// rcbj's decision on #520: every browser protocol — SAML 2.0 and 1.1 SSO,
// WS-Federation, the OIDC authorization endpoint, GNAP's interaction — reaches
// the one sign-in screen, so the certificate is offered THERE, once, as
// "Continue as <name> with your certificate". These two functions are what
// `authn/authn.ts` asks, and they are here rather than there because what
// they ask is what `GET /tls/sign-in` asks, in the same functions:
// `certificateRefusal()` (nothing verified, revocation, not an identity, an
// application's certificate) and `certificatePeer()` (the certificate and the
// name it signs in). The SESSION is the screen's: it is a first factor of a
// pending sign-in, so `authn.ts` asks the authentication policy, the risk, a
// second factor where one is needed, and returns to the protocol that sent
// the person — none of which `GET /tls/sign-in`, which has no caller, does.
//
// TWO DIFFERENCES FROM `GET /tls/sign-in`, BOTH FORCED:
//
//   * THE REALM IS THE PENDING SIGN-IN'S, not the certificate's. The protocol
//     that sent the person here decided the realm, so the certificate has to
//     belong to it: `tls_client_certificates.checkSocket()` refuses one from
//     another realm's authority, exactly as at the other doors of the main
//     port that have an ambient realm. A certificate from an anchor somebody
//     installed signs in by its common name, as at `GET /tls/sign-in`.
//   * NO "ALREADY SIGNED IN" ANSWER. A person at the screen is not signed in
//     for this request — that is why they are at it — and the screen's
//     session replaces or re-authenticates as every first factor's does.
//
// `authn.ts` reaches this module LAZILY and only where it is loaded already
// (`Authn.certificateDoor()`): this is a JavaScript route module, #20 in the
// require order, and requiring it from #8 would drag its `/tls*` views to the
// front of the router and close a cycle, since it requires `authn` itself.
// ---------------------------------------------------------------------------
/**
 * Whom the connection's verified client certificate would sign in at the
 * sign-in screen, in the request's realm, or null. The offer only: no
 * revocation is asked here, and nothing is logged above debug.
 *
 * @param req - the request for the screen's view
 * @returns `{ username }`, or null
 */
function screenCertificateOffer(req) {
  log.debug('Entering screenCertificateOffer().');
  const socket = req && req.socket;
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving screenCertificateOffer(). Nothing verified.');
    return null;
  }
  let checked = null;
  try {
    checked = require('../common/tls_client_certificates')
      .checkSocket(socket, { stored: true });
  } catch (e) {
    log.debug('Caught in screenCertificateOffer(): ' +
              ((e && e.message) || e));
    checked = null;
  }
  const identity = checked ? checked.identity : null;
  if (!checked || !checked.ok || !identity || !identity.accepted ||
      identity.kind === 'application') {
    log.debug('Leaving screenCertificateOffer(). Not a person here.');
    return null;
  }
  const peer = certificatePeer(socket, identity);
  log.debug('Leaving screenCertificateOffer(). ' +
            (peer.ok ? 'Offered.' : 'Not offered.'));
  return peer.ok ? { username: peer.username } : null;
}

/**
 * The connection's verified client certificate as a first factor at the
 * sign-in screen: revocation consulted, the identity gate and the ambient
 * realm asked, an application's certificate refused — `GET /tls/sign-in`'s
 * refusals, in its order, by its functions.
 *
 * @param req - the act's request
 * @returns a promise of `{ ok: true, username, credentialId, revocationSaid,
 *   recordVerification }`, or `{ ok: false, code, why }` with an English
 *   sentence for the screen and the error code to record
 */
function screenCertificateHolder(req) {
  log.debug('Entering screenCertificateHolder().');
  const socket = req && req.socket;
  const none = { ok: false, code: 'STS-AUTHN-0463',
                 why: 'No verified client certificate arrived on this ' +
                      'connection, so there is nobody to continue as. ' +
                      'Choose the certificate when your browser asks, or ' +
                      'sign in another way.' };
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving screenCertificateHolder(). Nothing verified.');
    return Promise.resolve(none);
  }
  log.debug('Leaving screenCertificateHolder(). The verdict follows.');
  return checkedSocket(socket).then(function (revocation) {
    let checked = null;
    try {
      checked = require('../common/tls_client_certificates')
        .checkSocket(socket, { stored: true });
    } catch (e) {
      log.debug('Caught in screenCertificateHolder(): ' +
                ((e && e.message) || e));
      checked = null;
    }
    // AN OUTSIDE AUTHORITY'S CERTIFICATE (#1061) continues only as the one
    // entry it is stored on — refused after revocation, which
    // `certificateRefusal()` below would otherwise report first.
    if (checked && !checked.ok && !(revocation && revocation.refused) &&
        (checked.error === 'NOT_STORED' ||
         checked.error === 'STORED_TWICE')) {
      log.info('tls: the sign-in screen refused a client certificate from ' +
               'an outside certificate authority: ' + checked.why);
      log.debug('Leaving screenCertificateHolder(). An outside ' +
                'certificate, not stored on one entry.');
      return checked.error === 'STORED_TWICE'
        ? { ok: false, code: 'STS-AUTHN-0469',
            why: 'Your certificate is stored on more than one account ' +
                 'here, so it cannot say which one is yours. Ask an ' +
                 'administrator to store it on yours alone.' }
        : { ok: false, code: 'STS-AUTHN-0468',
            why: 'Your certificate is not stored on any account here, so ' +
                 'it cannot sign you in. Ask an administrator to store it ' +
                 'on your account (a renewed certificate is stored again), ' +
                 'or sign in another way.' };
    }
    if (checked && !checked.ok && checked.error === 'OTHER_REALM') {
      log.info('tls: the sign-in screen refused a client certificate from ' +
               'another realm: ' + checked.why);
      log.debug('Leaving screenCertificateHolder(). Another realm\'s.');
      return { ok: false, code: 'STS-AUTHN-0465',
               why: 'Your certificate was issued in another realm, so it ' +
                    'cannot sign you in here.' };
    }
    const pre = certificateRefusal(socket, 'optional', revocation,
                                   checked ? checked.identity : undefined);
    if (pre.refusal) {
      const r = pre.refusal;
      log.info('tls: the sign-in screen did not continue with the client ' +
               'certificate: ' + r.why);
      log.debug('Leaving screenCertificateHolder(). Refused.');
      if (r.refusedOnRevocation) {
        return { ok: false, code: 'STS-AUTHN-0464',
                 why: 'Your certificate has been revoked, or its revocation ' +
                      'could not be confirmed, so it cannot sign you in.' };
      }
      if (r.refusedAsIdentity) {
        return { ok: false, code: 'STS-AUTHN-0465',
                 why: 'This certificate is not a TLS client certificate ' +
                      'for a person here, so it cannot sign you in.' };
      }
      if (r.application) {
        return { ok: false, code: 'STS-AUTHN-0466',
                 why: 'This certificate was issued to an application, and ' +
                      'an application\'s certificate signs nobody in.' };
      }
      return none;
    }
    const peer = certificatePeer(socket, pre.gated);
    if (!peer.ok) {
      log.info('tls: the sign-in screen did not continue with the client ' +
               'certificate: ' + peer.why);
      log.debug('Leaving screenCertificateHolder(). ' + peer.why);
      return none;
    }
    const revocationSaid = revocation && revocation.checked
      ? 'its revocation was consulted (' + revocation.policy + '): ' +
        revocation.why
      : 'NO REVOCATION WAS CHECKED (pki.revocationCheck is off)';
    log.debug('Leaving screenCertificateHolder(). ' + peer.username);
    return {
      ok: true,
      username: peer.username,
      credentialId: String(peer.cert.fingerprint256 || ''),
      revocationSaid: revocationSaid,
      // THE IDENTITY VERIFICATION (#127) `GET /tls/sign-in` records once
      // its session has started, recorded by the screen at the same point.
      recordVerification: function recordVerification() {
        log.debug('Entering recordVerification().');
        identityAssurance.recordAutomatic(peer.username, 'certificate',
                                          certificateFacts(peer.cert));
        log.info('tls: ' + peer.username + ' continued at the sign-in ' +
                 'screen with a verified client certificate. The chain ' +
                 'verified and ' + revocationSaid);
        log.debug('Leaving recordVerification().');
      }
    };
  });
}

// ---------------------------------------------------------------------------
// THE ARGUMENT THAT USED TO BE HERE, AND WHAT OF IT STILL HOLDS.
//
// Everything below about RECORDING is unchanged and still correct. The
// sentences saying no session starts are the ones the function above reversed,
// and "no revocation is checked" stopped being true on 2026-09-12; they are
// kept because they name exactly what must not be lost — that verification is
// a chain check and nothing more.
//
// The two are worth holding apart, because this module's whole value is that
// it does not confuse them. What a verified certificate means here has not
// changed and is stated everywhere this module speaks: OpenSSL built a chain
// from what the client sent to an anchor somebody added through
// /admin-api/tls/trust. No
// session starts, no token is issued, no revocation is checked, and no endpoint
// of this service will let the holder do anything it would not let an anonymous
// caller do.
//
// What it now also does is get WRITTEN DOWN. `/admin/users` answers "who has
// this service seen, in an interaction that succeeded", and a mutual-TLS client
// that verified is exactly that — leaving it out made the console's answer
// wrong by omission, and it is the one family whose identity the embedded
// directory can seed an entry for verbatim, because a certificate subject is
// already a DN. So this calls `stats.recordAuthentication()`, the same funnel
// the other thirteen families pass through, and the LDAP entry follows from the
// observer that is already on it rather than from a second call here.
//
// Three decisions in the implementation, each of which can be got wrong
// quietly:
//
//   * IT HAPPENS AT THE HANDSHAKE, not in the request handler. The credential
//     was accepted when the handshake completed, which is the rule every other
//     call site in this service follows; recording in the handler would count
//     REQUESTS instead, so one connection carrying six of them would read as
//     six authentications. The consequence to expect is the other way round and
//     is honest: a client that opens six CONNECTIONS did present its
//     certificate six times, and the console says six.
//   * ONLY WHEN `authorized` IS TRUE. On the main port a certificate
//     that did not verify, or none at all, records nothing — the console lists
//     identities that got somewhere, not names that were tried.
//   * A RESUMED SESSION may carry no peer certificate: the client does not send
//     it again, and node hands back an empty object. Nothing is recorded then,
//     rather than an authentication with no identity on it.
// ---------------------------------------------------------------------------
function recordClientCertificate(socket, mode, revocation) {
  log.debug('Entering recordClientCertificate(). mode=' + mode);
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving recordClientCertificate(). Nothing verified here.');
    return null;
  }
  // REFUSED ON REVOCATION (2026-09-12): not an authentication, so not filed as
  // one — the console lists identities that got somewhere. It IS a refusal,
  // and gets the audit row a refusal gets, with its code.
  if (revocation && revocation.refused) {
    audit.failure(revocation.status === 'revoked' ? 'STS-PKI-0118' :
                  'STS-PKI-0119', {
      protocol: 'TLS', channel: 'tls',
      target: 'the main port (' + MAIN_PORT + ')',
      summary: 'a verified client certificate was not recorded as an ' +
               'authentication because it was refused on revocation: ' +
               revocation.why,
      outcome: 'refused'
    });
    log.debug('Leaving recordClientCertificate(). Refused on revocation.');
    return null;
  }
  // NOT AN IDENTITY (2026-09-13), for `startCertificateSession()`'s reason: a
  // chain through this service's own Root from an authority that does not
  // issue TLS client identities is not an authentication, so it is not filed
  // as one. It is logged, once per handshake; `GET /tls/sign-in` reports the
  // same certificate as `refusedAsIdentity`.
  const gated = issuedIdentityOf(socket);
  if (gated.issuedHere && !gated.accepted) {
    log.info('tls: a verified client certificate on the ' + mode + ' ' +
             'listener was not recorded as an authentication: ' + gated.why +
             '.');
    log.debug('Leaving recordClientCertificate(). Not an identity.');
    return null;
  }
  // An application's certificate is not a person's authentication, for
  // `startCertificateSession()`'s reason; filing it on /admin/users would put
  // an application in the register of people.
  if (gated.issuedHere && gated.accepted && gated.kind === 'application') {
    log.debug('Leaving recordClientCertificate(). An application.');
    return null;
  }
  // AN OUTSIDE AUTHORITY'S CERTIFICATE IS NOT RECORDED HERE (#1061). Until
  // rcbj's decision it was recorded under its subject, and the observer
  // SEEDED a directory entry for it (`certificatePlan()`) — an entry created
  // out of a name somebody else's authority chose. It is an identity now
  // only as the one entry storing it, in a realm, and a handshake has no
  // realm: `GET /tls/sign-in` and every other door resolve it where the
  // request names one, and the sign-in they start is the authentication.
  if (!gated.issuedHere) {
    log.debug('Leaving recordClientCertificate(). An outside certificate; ' +
              'its doors resolve it.');
    return null;
  }
  let cert = null;
  try {
    cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
  } catch (e) {
    // A socket that went away between the handshake and this line. Logged
    // rather than thrown: this is an event handler on a listener, so a throw
    // out of it is an uncaught exception and takes the service down.
    log.debug('recordClientCertificate(): the peer certificate could not be ' +
              'read: ' + e.message);
    log.debug('Leaving recordClientCertificate(). No certificate.');
    return null;
  }
  if (!cert || !Object.keys(cert).length) {
    log.debug('Leaving recordClientCertificate(). The connection verified ' +
              'but carries no peer certificate, which is what a resumed ' +
              'session looks like.');
    return null;
  }
  const subject = dnRfc4514(cert.subject);
  if (!subject) {
    log.debug('Leaving recordClientCertificate(). The subject is empty.');
    return null;
  }
  const common = cert.subject && cert.subject.CN
    ? String(Array.isArray(cert.subject.CN) ? cert.subject.CN[0] :
             cert.subject.CN)
    : '';
  try {
    // IN THE CERTIFICATE'S REALM, so the directory entry the observer seeds is
    // in the subtree of the realm whose authority issued it.
    inCertificateRealm(gated, function () {
      recordCertificateAuthentication(subject, common, cert, mode, revocation);
    });
  } catch (e) {
    // Same reason as the read above, and one more: the console and the
    // directory are bookkeeping, and bookkeeping must never be able to break a
    // connection that has already been accepted.
    log.error(errorCodes.tag('STS-TLS-0018') +
              'tls: recording the client certificate failed and was ignored; ' +
              'the connection is unaffected: ' + e.message);
    log.debug('Leaving recordClientCertificate(). The recording threw.');
    return null;
  }
  log.info('tls: ' + subject + ' presented a client certificate that ' +
           'verified on ' +
           'the ' + mode + ' listener. It is recorded in the admin ' +
           'console and the directory has an entry for it. The SIGN-IN is a ' +
           'separate act and startCertificateSession() performs it on the ' +
           'request, because a cookie needs a response to be written on.');
  log.debug('Leaving recordClientCertificate(). Recorded.');
  return subject;
}

// The authentication itself, split out of `recordClientCertificate()` so it
// can run inside the certificate's realm. It may throw; its caller catches.
function recordCertificateAuthentication(subject, common, cert, mode,
                                         revocation) {
  log.debug('Entering recordCertificateAuthentication().');
  stats.recordAuthentication({
    presented: subject,
    protocol: 'TLS',
    method: 'client certificate on the main port (' + MAIN_PORT + ')',
    // The certificate subject, RFC 4514, which is what an application's
    // oauthTlsClientAuthSubjectDn holds. The attempts tab matches that.
    // Not client_id: this sighting is the certificate, and the token
    // endpoint records its own client_id when one authenticated there.
    application: subject,
    note: 'the chain verified against one of the ' + anchors.length +
      ' anchor(s) in this service\'s truststore, and ' +
      (revocation && revocation.checked
        ? 'its revocation was consulted (' + revocation.policy + ', ' +
          revocation.status + ')'
        : 'NO REVOCATION WAS CHECKED (pki.revocationCheck is off)') +
      '. Since 2026-09-05 a sign-on session is started for the holder, so ' +
      'a global sign-out can end it; no token is issued.',
    // Both DNs in RFC 4514 form, which is not the form dnToString() renders
    // for a reader — see dnRfc4514(). These two go into a DIRECTORY, and
    // that is the only form a directory takes.
    certificate: {
      subject: subject,
      commonName: common,
      issuer: dnRfc4514(cert.issuer),
      serialNumber: cert.serialNumber || '',
      validFrom: cert.valid_from || '',
      validTo: cert.valid_to || '',
      fingerprint256: cert.fingerprint256 || '',
      email: emailOf(cert)
    }
  });
  log.debug('Leaving recordCertificateAuthentication().');
}

// ---------------------------------------------------------------------------
// THE TRUSTSTORE FROM A FILE, READ BEFORE THE LISTENERS EXIST (2026-09-12).
//
// `tls.trustAnchorsFile`. There is no open door to the truststore (#597), and
// a deployment that verifies client certificates at all — a remote XACML
// PEP is the one this service ships — needs its anchors from somewhere an
// operator controls rather than from whoever reaches the port. So they are
// CONFIGURATION: a PEM file read once, here, before any listener is given a
// context built from `secureContextOptions()`, which is why this pushes into
// `anchors` directly rather than going through `addAnchors()` — that function
// re-applies the context to listeners that do not exist yet.
//
// A file that cannot be read, or holds no certificate, STOPS THE SERVICE. A
// truststore silently empty because of a typo in a path is a deployment whose
// every client certificate is refused, and nothing on any page would say why.
// ---------------------------------------------------------------------------
let anchorsFileReport = { file: '', loaded: 0 };

(function loadAnchorsFile() {
  log.debug("Entering loadAnchorsFile().");
  const file = String(config.value('tls.trustAnchorsFile') || '').trim();
  if (!file) {
    log.debug("Leaving loadAnchorsFile().");
    return;
  }
  let text = '';
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    log.fatal(errorCodes.tag('STS-TLS-0019') +
              'tls: NOT STARTING. tls.trustAnchorsFile ' +
              '(STS_TLS_TRUST_ANCHORS_FILE) is ' +
              '"' + file + '" and it could not be read: ' + e.message + '.');
    process.exit(1);
  }
  const found = splitPemCertificates(text);
  if (!found.length) {
    log.fatal(errorCodes.tag('STS-TLS-0020') +
              'tls: NOT STARTING. tls.trustAnchorsFile is "' + file + '" and ' +
              'it holds no -----BEGIN CERTIFICATE----- block, so the client ' +
              'truststore would be empty while configured to be filled.');
    process.exit(1);
  }
  found.slice(0, MAX_ANCHORS).forEach(function (pem) {
    const described = describePem(pem);
    if (!anchors.some(function (one) {
      return one.fingerprint256 === described.fingerprint256;
    })) {
      // `file`, which is what /admin/tls/trust draws as the SOURCE column: a
      // row from here comes back at the next start however it is removed.
      anchors.push(Object.assign(described, {
        source: 'file', addedAt: new Date().toISOString() }));
    }
  });
  if (found.length > MAX_ANCHORS) {
    log.warn('tls: tls.trustAnchorsFile holds ' + found.length + ' ' +
             'certificates and the truststore holds at ' +
             'most ' + MAX_ANCHORS + '; the rest ' +
             'were NOT loaded.');
  }
  anchorsFileReport = { file: file, loaded: anchors.length };
  log.info('tls: trusting client certificates issued by the ' + anchors.length +
           ' anchor(s) in ' + file + ' (tls.trustAnchorsFile).');
  log.debug("Leaving loadAnchorsFile().");
})();

// ---------------------------------------------------------------------------
// THE TWO LISTENERS WERE DELETED ON 2026-09-16, AND THIS IS WHAT REPLACED
// THEM.
//
// 8443 asked for a client certificate and never required one; 9443 required
// one at the handshake. The MAIN PORT already does the first — `server.js`
// binds it `requestCert: true, rejectUnauthorized: false` — so 8443 was a
// second socket with the same posture as the one every other protocol answers
// on, and a deployment paid for three HTTPS ports to get two behaviours.
//
// What moved here rather than dying with them:
//
//   * THE SIGHTING. `recordClientCertificate()` hung on those sockets'
//     `secureConnection`, so the main port recorded nothing — a client
//     certificate presented to the token endpoint was used and never seen on
//     /admin/tls. `observeConnectionsOn()` below puts it on whatever listener
//     is given to it, and `server.js` gives it the main one.
//   * THE SIGN-IN. A verified client certificate is a session (2026-09-05),
//     and that ran in the deleted handler. It is now `GET /tls/sign-in` on the
//     main port. **The CLIENT decides whether to present a certificate**: this
//     port asks for one and requires none, so the route signs in whoever
//     presented a verified one and tells anybody else that there was nobody to
//     sign in.
//
// What did NOT move, deliberately: the connection ECHO — the page and
// /tls/whoami that reported what the server made of the handshake. It was the
// two listeners' whole content, it is a debugging surface rather than a
// protocol, and it is being taken up in the debugger project instead.
//
// The handshake REFUSAL 9443 performed has no replacement and cannot have one
// here: refusing at the handshake is a property of a socket, and this socket
// answers every other protocol. A certificate that does not verify is refused
// where it is USED — the token endpoint (RFC 8705), /xacml, /scim — which is
// the same answer arriving one layer up.
// ---------------------------------------------------------------------------

// Watch a listener this module did not create. `server.js` calls it for the
// main HTTPS port; a second call for another listener would be the same two
// lines, which is why this takes the server rather than reaching for one.
//
// AFTER THE REVOCATION CHECK (2026-09-12), which is why it waits on a promise:
// a certificate the policy refuses is recorded as a refusal rather than as an
// authentication. `checkedSocket()` never rejects.
// ---------------------------------------------------------------------------
// WHAT OPENSSL VERIFIED, HELD TO THE PATH RULES EVERY OTHER PATH HERE IS
// (#201).
//
// `socket.authorized` is OpenSSL's answer, and every reader of a client
// certificate on this port reads it — certificate sign-in, RFC 8705, the
// XACML gate, SCIM, the portal, and the flag the request pool forwards to a
// worker. x509-limbo found OpenSSL accepting paths `pki.pathRuleProblem()`
// refuses (a malformed name under a name constraint, a nameConstraints on an
// end entity, an empty constraint, a root without basicConstraints). So a
// chain OpenSSL verified is asked those rules here, once per connection,
// BEFORE any request on it is read — node's HTTP server parses the first
// request on a later turn than this event — and one that breaks them is
// reported as unverified: `authorized` false, `authorizationError` naming
// the rule. It is still thumbprinted and may still bind a token (RFC 8705
// section 3 binds to the certificate, not to a CA), exactly as a chain
// OpenSSL refused is. Required lazily: `pki` is loaded after this module.
// ---------------------------------------------------------------------------
/**
 * Holds a chain OpenSSL verified to this service's path rules, marking a
 * connection whose chain breaks one as unverified before any request on it is
 * read.
 *
 * @param socket - the TLS socket
 * @param label - the listener's name, for the log
 * @returns the rule broken, or null
 */
function holdToPathRules(socket, label) {
  log.debug('Entering holdToPathRules().');
  if (!socket || socket.authorized !== true ||
      typeof socket.getPeerCertificate !== 'function') {
    log.debug('Leaving holdToPathRules(). Nothing verified.');
    return null;
  }
  let problem = null;
  try {
    problem = require('../common/pki')
      .peerChainProblem(socket.getPeerCertificate(true));
  } catch (e) {
    // A defect here must not make an unverified chain look verified, nor a
    // verified one unverified for a reason nobody can read. OpenSSL's answer
    // stands and the failure is logged.
    log.error(errorCodes.tag('STS-PKI-0198') + 'tls: the path rules could ' +
              'not be asked of a client chain on ' + label + ': ' +
              ((e && e.message) || e));
    problem = null;
  }
  if (problem) {
    socket.authorized = false;
    socket.authorizationError = 'ERR_STS_PATH_RULES: ' + problem.why;
    log.warn(errorCodes.tag('STS-PKI-0198') + 'tls: a client certificate ' +
             'chain on ' + label + ' verified with OpenSSL and breaks RFC ' +
             '5280, so it is treated as unverified: ' + problem.why + '.');
  }
  log.debug('Leaving holdToPathRules().' + (problem ? ' Demoted.' : ''));
  return problem;
}

// ---------------------------------------------------------------------------
// WHICH SIDE BROKE A HANDSHAKE, AND WHY (2026-09-26, #225).
//
// rcbj signed in to /admin from Chrome on his laptop and the log filled with
// `ssl/tls alert certificate unknown … SSL alert number 46`, each line saying
// "this is the handshake itself rather than a certificate being refused" —
// which sent the diagnosis the wrong way. OpenSSL's `ssl3_read_bytes … alert`
// means this service RECEIVED the alert: the CLIENT checked this service's
// certificate and refused it, which from a browser almost always means it
// does not trust this service's Root. That is a certificate being refused,
// by the other end.
//
// So the failure is classified before it is logged. An alert the peer SENT
// is read off node's error — its code (`ERR_SSL_SSLV3_ALERT_…`,
// `ERR_SSL_TLSV1_ALERT_…`) or OpenSSL's `SSL alert number N` on a read — and
// the alerts of RFC 8446 section 6.2 (and RFC 5246 7.2.2 before it) that are
// about the certificate the peer was SENT are named as that. Everything else
// is a handshake that failed for another reason: a version, a cipher, a
// client that is not speaking TLS. A pure function, exported for
// tests/tls_handshake_alerts.js.
// ---------------------------------------------------------------------------
const CERTIFICATE_ALERTS = {
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  48: 'unknown_ca'
};

/**
 * Classifies a failed TLS handshake: the peer refused this service's
 * certificate (a certificate alert it sent), or another failure.
 *
 * @param error - the handshake's error
 * @returns `{ kind, alert, alertName }`, `kind` being
 * `peer-refused-certificate` or `handshake`
 */
function handshakeFailureOf(error) {
  log.debug('Entering handshakeFailureOf().');
  const message = String((error && error.message) || '');
  const code = String((error && error.code) || '');
  const numbered = /SSL alert number (\d+)/.exec(message);
  const received = /_read_bytes|read_bytes:/.test(message) ||
                   /^ERR_SSL_(SSLV3|TLSV1)_ALERT_/.test(code);
  const alert = numbered ? Number(numbered[1]) : null;
  const byCode = {
    ERR_SSL_SSLV3_ALERT_BAD_CERTIFICATE: 42,
    ERR_SSL_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE: 43,
    ERR_SSL_SSLV3_ALERT_CERTIFICATE_REVOKED: 44,
    ERR_SSL_SSLV3_ALERT_CERTIFICATE_EXPIRED: 45,
    ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN: 46,
    ERR_SSL_TLSV1_ALERT_UNKNOWN_CA: 48
  };
  const number = alert !== null ? alert
    : (byCode[code] !== undefined ? byCode[code] : null);
  if (received && number !== null && CERTIFICATE_ALERTS[number]) {
    log.debug('Leaving handshakeFailureOf(). The peer refused the ' +
              'certificate: ' + CERTIFICATE_ALERTS[number] + '.');
    return { kind: 'peer-refused-certificate', alert: number,
             alertName: CERTIFICATE_ALERTS[number] };
  }
  log.debug('Leaving handshakeFailureOf(). Another handshake failure.');
  return { kind: 'handshake', alert: received ? number : null,
           alertName: null };
}

/**
 * Records every client certificate presented on a TLS listener this module did
 * not create, after holding it to the path rules and consulting revocation.
 *
 * @param server - the TLS listener
 * @param label - its name, for the log and the record
 * @returns true when it is observed; false (logged) when `server` is not a TLS
 * server
 */
function observeConnectionsOn(server, label) {
  log.debug('Entering observeConnectionsOn(). label=' + label);
  if (!server || typeof server.on !== 'function') {
    log.error(errorCodes.tag('STS-TLS-0010') +
              'tls: observeConnectionsOn() was given something that is not a ' +
              'TLS server (' + label + '), so client certificates presented ' +
              'there are NOT recorded. /admin/tls will look quiet while they ' +
              'arrive.');
    log.debug('Leaving observeConnectionsOn(). Refused.');
    return false;
  }
  server.on('secureConnection', function (socket) {
    holdToPathRules(socket, label);
    checkedSocket(socket).then(function (revocation) {
      recordClientCertificate(socket, 'optional', revocation);
    });
  });
  // A handshake that failed reaches a listener as a socket error and never as
  // a request, so without this it is invisible: the far end sees a closed
  // connection and this log says nothing at all. It is the single most
  // confusing failure in mutual TLS, so it is logged with the reason OpenSSL
  // gave. On this port a client certificate is never REQUIRED, so a failure
  // here is never this service refusing a client's credential — but it may
  // be the CLIENT refusing THIS service's certificate, which
  // handshakeFailureOf() tells apart and says so (#225).
  server.on('tlsClientError', function (error, socket) {
    // A PEER THAT CLOSED BEFORE SAYING ANYTHING (2026-09-21) is a load
    // balancer's TCP health check — a connect and a close — or a client that
    // gave up before its hello, and it is not a handshake that failed. On the
    // ci environment each node logged one about every second, all day: 162 a
    // minute across three nodes, each an audit row too. Debug, and no row;
    // every other failure keeps both.
    if (error && (error.code === 'ECONNRESET' ||
                  error.message === 'socket hang up')) {
      log.debug('tls: a connection on ' + label + ' closed before its TLS ' +
                'hello (' + error.message + ') — a health check or a ' +
                'client that gave up.');
      return;
    }
    const from = (socket && socket.remoteAddress) || 'an unknown address';
    const failure = handshakeFailureOf(error);
    if (failure.kind === 'peer-refused-certificate') {
      log.warn(errorCodes.tag('STS-TLS-0034') + 'tls: the client at ' + from +
               ' REFUSED this service\'s certificate on ' + label + ' (it ' +
               'sent the TLS alert ' + failure.alertName + ', ' +
               failure.alert + '). From a browser this almost always means ' +
               'it does not trust this service\'s Root CA: install the Root ' +
               'from GET /tls/server-certificate (the last certificate) in ' +
               'its trust store, and reach the service by a name in the ' +
               'certificate (tls.hostnames, tls.ips). OpenSSL said: ' +
               error.message);
      audit.failure('STS-TLS-0034', {
        protocol: 'TLS', channel: 'tls',
        target: label,
        summary: 'the client refused this service\'s certificate: TLS ' +
                 'alert ' + failure.alertName,
        outcome: 'refused'
      });
      return;
    }
    log.warn('tls: a handshake failed on ' + label + ' from ' + from + ': ' +
             error.message + '. A client certificate is asked for and never ' +
             'required here, and the client sent no alert refusing this ' +
             'service\'s certificate, so this is the handshake itself — a ' +
             'version, a cipher, or a client not speaking TLS.');
    audit.failure('STS-TLS-0021', {
      protocol: 'TLS', channel: 'tls',
      target: label,
      summary: 'a TLS handshake failed: ' + error.message,
      outcome: 'refused'
    });
  });
  log.debug('Leaving observeConnectionsOn(). Watching.');
  return true;
}

// ---------------------------------------------------------------------------
// A VERIFIED CLIENT CERTIFICATE IS A SIGN-IN, ON THE MAIN PORT (2026-09-16).
//
// It was a side effect of reaching 8443 or 9443 at all: the deleted handler
// started a session for whatever verified, and every page load did it again.
// Those sockets are gone, so it is a route — and being a route is better than
// what it replaced, because a sign-in that happens because you loaded a
// diagnostic page is a sign-in nobody asked for.
//
// **THE CLIENT DECIDES WHETHER TO PRESENT A CERTIFICATE.** The main port asks
// every connection for one (`server.js`, `requestCert: true`) and requires
// none, so a browser or a curl that has one sends it and a caller that has
// none is simply not signed in. This route does not and cannot demand one at
// the handshake: refusing there is a property of the socket, and this socket
// answers every other protocol in the service.
//
// Everything it decides is `startCertificateSession()`'s, unchanged from when
// the listeners called it: revocation first, then the identity gate, then an
// application's certificate refused as a sign-in (it is an RFC 8705 client
// credential), then the session in the certificate's own realm.
//
// Behind the cluster barrier for the reason the deleted handler was: this
// STARTS A SESSION, and in active-active mode an answer sent before the
// session committed left a sign-out on another node unable to see it.
// ---------------------------------------------------------------------------
app.get('/tls/sign-in', function (req, res) {
  log.debug('Entering GET /tls/sign-in.');
  // WHICH CELL SIGNS THE HOLDER IN (#98 D10), BEFORE the revocation check,
  // the identity gate and the session: a session is started where its person
  // is homed. `placeCertificateSignIn()` argues it; single-cell mode answers
  // at once and the rest runs exactly as it did.
  placeCertificateSignIn(req, res).then(function (relayed) {
    if (relayed) {
      log.debug('Leaving GET /tls/sign-in. Relayed to the home cell.');
      return;
    }
    answerCertificateSignIn(req, res);
    log.debug('Leaving GET /tls/sign-in.');
  });
});

// ---------------------------------------------------------------------------
// A CERTIFICATE SIGN-IN IS ANSWERED IN ITS PERSON'S HOME CELL (#98 D10,
// 2026-09-28).
//
// The certificate names its holder — the `urn:sts:person:` name this
// service's own authority wrote (`tls_client_certificates.js`), else the
// common name, else the subject, exactly as `startCertificateSessionIn()`
// reads it — and a session for somebody is started where their entry is. So
// a holder homed in another cell is sent there WHOLE, in the realm the
// certificate names. THE CERTIFICATE GOES WITH IT: the channel forwards the
// client's certificate and its chain as the front process hands one to a
// request worker, and the receiving cell shims the socket so
// `getPeerCertificate()` answers with the CLIENT's and `authorized` with this
// handshake's verdict (`cell_channel.ts`, *what a relayed request carries*).
// The home cell then runs the whole door — the revocation check
// (`revocation_status.fromSocket()` reads the forwarded `issuerChain`, as it
// does in a worker), the identity gate, the issuance policy — and starts the
// session, which pins the browser to it (`authn.startSession()`).
//
// **A BROWSER ALREADY HOLDING A SESSION HERE IS ANSWERED HERE**: this route's
// rule is one session per browser, and sending it home would start a second
// one there for somebody this cell already signed in. The placement table
// honours a pinned browser's cell before this handler runs (`browser: true`).
//
// **ONLY A VERIFIED CERTIFICATE IS PLACED.** Nothing else starts a session,
// so anything else is answered here with what it is, as it always was.
// ---------------------------------------------------------------------------
function placeCertificateSignIn(req, res) {
  log.debug('Entering placeCertificateSignIn().');
  if (!cells.isMulti() || req.stsCellRelay || !req.socket ||
      req.socket.authorized !== true) {
    log.debug('Leaving placeCertificateSignIn(). Here.');
    return Promise.resolve(false);
  }
  const identity = issuedIdentityOf(req.socket, { stored: true });
  let name = '';
  let held = false;
  try {
    // THE GATE'S NAME ONLY (#1061): an outside certificate is the entry it
    // is stored on, and one stored nowhere is answered here, refused.
    name = identity && identity.accepted ? String(identity.username || '')
                                         : '';
    // With several accounts on (#561) "held" is the CERTIFICATE'S account
    // live in this browser's set, for `startCertificateSessionIn()`'s
    // reason: the browser's other accounts are not this person, and one
    // signed in here does not make this one a sign-in nobody needs.
    held = !!inCertificateRealm(identity, function () {
      return authn.multipleAccounts()
        ? certificateAccountHeld(req, name) : authn.sessionOf(req);
    });
  } catch (e) {
    log.debug('Caught in placeCertificateSignIn(): ' +
              ((e && e.message) || e));
    name = '';
  }
  // An application's certificate signs nobody in; it is answered here.
  if (!name || held || (identity && identity.kind === 'application')) {
    log.debug('Leaving placeCertificateSignIn(). Here.');
    return Promise.resolve(false);
  }
  const realmId = identity && identity.accepted && identity.realm
    ? String(identity.realm) : realms.currentId();
  log.debug('Leaving placeCertificateSignIn(). Asking where ' + name +
            ' is homed.');
  return cellPlacement.relayToHome(req, res, realmId, 'name', name,
                                   'tls-sign-in')
    .catch(function (e) {
      // A lookup that failed is served here, as an unknown holder is.
      log.debug('Caught in placeCertificateSignIn(): ' +
                ((e && e.message) || e));
      return false;
    });
}

// The certificate sign-in, once it is known to be answered here.
function answerCertificateSignIn(req, res) {
  log.debug('Entering answerCertificateSignIn().');
  clusterBarrier.middleware()(req, res, function () {
    checkedSocket(req.socket).then(function (revocation) {
      const identity = issuedIdentityOf(req.socket, { stored: true });
      const session = startCertificateSession(req, res, 'optional', revocation,
                                              identity);
      // AN OUTSIDE CERTIFICATE STORED ON NO ENTRY, OR ON SEVERAL (#1061):
      // the answer is still 200 with `session.started` false, as every
      // refusal of this route's is, and the condition is recorded.
      if (session.refusedAsStored) {
        errorCodes.mark(res, session.refusedAsStored === 'STORED_TWICE'
          ? 'STS-TLS-0055' : 'STS-TLS-0054');
      }
      const presented = !!(req.socket && req.socket.getPeerCertificate &&
                           req.socket.getPeerCertificate().raw &&
                           req.socket.getPeerCertificate().raw.length);
      const answer = {
        signedIn: !!session.started,
        session: session,
        clientCertificate: {
          presented: presented,
          verified: !!(req.socket && req.socket.authorized === true),
          // The thumbprint the token endpoint would bind a token to, so that
          // one request answers "is my certificate arriving, and as what".
          thumbprint: presented
            ? stsCrypto.certificateThumbprint(
                req.socket.getPeerCertificate().raw)
            : ''
        },
        revocation: revocation,
        note: presented
          ? 'This port asks for a client certificate and requires none. What ' +
            'arrived is above; what it is worth is decided here for a ' +
            'session, and at each door that reads one for everything else.'
          : 'No client certificate arrived. This port asks every connection ' +
            'for one and requires none, so presenting it is the client\'s ' +
            'own doing — send one and this route will sign its holder in.'
      };
      res.set('Cache-Control', 'no-store');
      // COMMITTED BEFORE IT IS ANSWERED, WHERE A SESSION WAS STARTED
      // (2026-09-23). This route is never dispatched, so the session is written
      // by the FRONT process, and the read barrier learns about a front-process
      // write only once it has COMMITTED (`request_pool.js`'s
      // noteLocalWrites()). Answered before that, the browser's next request —
      // the console's code flow, straight to /oauth2/authorize on a request
      // worker — could reach a worker that had not caught up and was sent to
      // the sign-in screen with a session in its cookie
      // (`sts_console_bootstrap_product` in single-node). With nothing started
      // there is nothing to wait for.
      const send = function () {
        res.status(200).type('application/json').send(JSON.stringify(answer));
        log.debug('Leaving GET /tls/sign-in. signedIn=' + answer.signedIn);
      };
      if (!session.started) {
        send();
        return;
      }
      const persistence = require('../persistence/persistence');
      const flushAndSend = function () {
        Promise.all([persistence.flush(), persistence.flushMinted()])
          .then(send, function (e) {
            // The store's own failure is reported by persistence.js; the
            // answer goes out, and a worker catches up on the change log's
            // own clock.
            log.debug('Caught in GET /tls/sign-in: ' +
                      ((e && e.message) || e));
            send();
          });
      };
      // THE ATTRIBUTE SOURCES A SIGN-IN READS (#94), in the realm the session
      // is in — the certificate's, which need not be this request's — before
      // the answer goes. A refusing source that failed ended the session:
      // the answer says so, with the refusal's status.
      const sessionRealm = realms.get(session.realm);
      const settle = function () {
        authn.afterSignIn(res, flushAndSend, function (why) {
          answer.signedIn = false;
          answer.session = { started: false, why: why };
          // error-code: none — afterSignIn() marked STS-ATTR-0012 on `res`
          res.status(403).type('application/json')
             .send(JSON.stringify(answer));
          log.debug('Leaving GET /tls/sign-in. An attribute source refused.');
        });
      };
      if (sessionRealm) {
        realms.run(sessionRealm, settle);
      } else {
        settle();
      }
    });
  });
  log.debug('Leaving answerCertificateSignIn().');
}

app.get('/tls/server-certificate', function (req, res) {
  log.debug('Entering GET /tls/server-certificate.');
  // no-store for the same reason every document describing the signing key
  // carries it: this certificate is regenerated on every start, so a cached
  // copy outlives the key it describes and the failure it produces is a
  // handshake that does not verify — which reads as a broken server rather
  // than a stale anchor.
  // EVERY certificate the TLS sockets may present, concatenated. With the
  // default single RSA certificate this is byte-for-byte what it always was;
  // with an ML-DSA one configured beside it, a caller that put only the first
  // in its truststore would fail to verify the connection it actually got —
  // which one it gets is OpenSSL's choice, made from the signature algorithms
  // the caller itself offered.
  //
  // **AND SINCE 2026-09-11 THE CHAIN AND THE ROOT GO WITH THEM**, which is a
  // change of content and not of contract: every document in this repository
  // that names this path tells a reader to fetch it and TRUST it
  // (`NODE_EXTRA_CA_CERTS=/tmp/sts.pem`, `--cacert`, an LDAP client's
  // truststore), and the hour these certificates were certified under this
  // service's own Root that stopped being possible. OpenSSL takes a
  // self-signed leaf in a truststore as an anchor and will not take a
  // certified one, so what came back here was a pin that matched nothing:
  // `unable to get local issuer certificate`, about a Root the caller was
  // never given. A truststore built from this document terminates now.
  //
  // THE LEAVES STAY FIRST. `tests/tools/trust.js` reads the first certificate
  // in this document to compute the SPKI pin the browser job uses, and a
  // reader looking for "the server certificate" should find it at the top.
  const chain = [];
  SERVER_CERTIFICATES.forEach(function (one) {
    (one.chainPem || []).forEach(function (pemText) {
      if (chain.indexOf(pemText) < 0) {
        chain.push(pemText);
      }
    });
  });
  const pem = SERVER_CERTIFICATES.map(function (one) {
    return one.certPem;
  }).concat(chain).concat(trustAnchorPems().filter(function (anchorPem) {
    // The self-signed case answers the leaf here, and it is already above.
    return SERVER_CERTIFICATES.every(function (one) {
      return one.certPem !== anchorPem;
    });
  })).join('');
  res.status(200).type('text/plain').set('Cache-Control', 'no-store')
     .send(pem);
  log.debug('Leaving GET /tls/server-certificate. ' +
           SERVER_CERTIFICATES.length + ' certificate(s).');
});

// ---------------------------------------------------------------------------
// THE TRUSTSTORE HAS NO OPEN DOOR SINCE #597 (2026-10-12).
//
// `POST /tls/trust` and `POST /tls/trust/clear` answered anybody who could
// reach the main port — test controls, development only since #585, the
// PROCESS's demonstration mark (itself removed by #599) because the anchors
// are one array for every listener. Adding an anchor decides whose client certificates
// VERIFY, and a verified certificate is an identity here, so #597 deleted
// both: the doors are `/admin/tls/trust` behind the console's roles and
// `POST /admin-api/tls/trust/{add,remove}` behind the management API's
// access token, both through `truststore` below, in either mode. There is
// deliberately no bulk clear on them (`clearAnchors()` stays, for the
// in-process tests).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE TRUSTSTORE AS THE GATED DOORS SEE IT (2026-09-12).
//
// Three functions, handed to `admin-ui/admin.ts`'s `setTruststore()` slot and
// forwarded from there to the action and view layers in `admin-core/`. This
// module cannot hand them over itself at require time, and the reason is worth
// knowing before anybody tries: it is first loaded from INSIDE `admin.js`'s own
// require — `admin.js` → `admin-core/admin_views.ts` → `spiffe/spiffe_auth.ts`
// → here — so a `require('../admin-ui/admin')` at this module's top level
// would be a cycle and would hand back that module's half-built exports, on
// which `setTruststore` does not exist yet. `common/protocol_stack.ts` fills
// the slot on the line after it requires this module, where both are whole.
//
// **`add` IS STRICT.** A block OpenSSL cannot read is refused whole here,
// because an anchor the listener cannot parse makes the next
// `setSecureContext()` throw on every listener (logged, and the listeners
// keep their old context while the page says otherwise).
//
// **A RUNTIME ANCHOR IS PERSISTED SINCE LATER THE SAME DAY**, and this
// paragraph said *nothing here is persisted* until then. It is written to
// ou=trustAnchors as it is added (see `setTrustAnchorStore()`), so it survives
// a restart wherever the directory does and reaches every other process against
// the same store. What did NOT change: an anchor from `tls.trustAnchorsFile`
// is not stored, and removing one lasts until the next start. The doors say so.
// ---------------------------------------------------------------------------
/**
 * The client truststore as the console and the management API reach it: `list`,
 * `add` (strict, and stored) and `remove`.
 */
const truststore = {
  list: listAnchors,
  add: function (text, meta) {
    log.debug("Entering add().");
    log.debug("Leaving add().");
    return addAnchors(text, { source: 'runtime', strict: true,
                              addedBy: (meta && meta.actor) || '' });
  },
  remove: removeAnchor
};

// ---------------------------------------------------------------------------
// WHAT A REVERSE PROXY TOLD THIS SERVICE, AND WHAT WAS BELIEVED OF IT — the
// second half of Monitoring → TLS connection (`connectionView()` below). It
// was `GET /tls/forwarded`, a development page, until #597.
//
// RFC 9700 section 2.6 has a paragraph about reverse proxies with two halves.
// The proxy's half is that it MUST sanitize inbound security-sensitive headers
// before forwarding — a client must not be able to reach past the proxy by
// setting a header the proxy is supposed to set. The application's half, which
// is the one this service can do something about, is that it must not BELIEVE
// those headers unless it knows a proxy set them.
//
// So the view reports the request as it arrived: every forwarding header,
// every security-sensitive header a proxy might inject, whether this service
// believed any of it, and what the effective base URL — the thing every issuer
// and every endpoint in both discovery documents is built from — came out as.
//
// It lives in this module for the same reason /tls/sign-in does: this file's
// whole subject is what the SERVER saw of a connection, and a forwarding header
// is what the server was TOLD about a connection it did not see. The difference
// between those two sentences is the page.
//
// **The client certificate headers are the important row.** A proxy that
// terminates mTLS forwards the certificate in a header — X-Client-Cert,
// X-Forwarded-Client-Cert, X-SSL-Client-Cert, and a dozen vendor spellings —
// and an application that believed one would be accepting a certificate anybody
// can forge, since a header costs nothing to write. THIS SERVICE READS NONE OF
// THEM, in either mode, and the view says so with the ones it saw listed: a
// mock that silently ignored a header somebody was relying on would be as bad
// as one that silently trusted it.
// ---------------------------------------------------------------------------
const FORWARDING_HEADERS = [
  { name: 'x-forwarded-proto', what: 'The scheme the CLIENT used. Believed ' +
      'when global.trustProxy is on, and then it decides whether every URL ' +
      'this service publishes says http or https.' },
  { name: 'x-forwarded-host', what: 'The host the CLIENT used. Believed when ' +
      'global.trustProxy is on, and then it is the authority in every ' +
      'published URL and in the issuer of every token.' },
  { name: 'x-forwarded-port', what: 'READ BY NOTHING HERE. The port is taken ' +
      'from x-forwarded-host, which carries one where it matters — two ' +
      'sources for one value is two values that will eventually disagree.' },
  { name: 'x-forwarded-for', what: 'The client\'s address. Read by the ' +
      'rate limiter\'s address bucket and nothing else, and only with ' +
      'global.trustProxy on — from any peer while global.trustedProxies is ' +
      'empty, and otherwise only from a peer in those ranges, taking the ' +
      'right-most hop that is not one of them (common/client_address.js). ' +
      'The audit log deliberately records the CHANNEL rather than an ' +
      'address: on a service reached over a compose bridge an address is a ' +
      'fact about docker.' },
  { name: 'forwarded', what: 'RFC 7239\'s single-header form. NOT PARSED — ' +
      'this service reads the X- forms only, which is what every proxy in ' +
      'front of it emits as well.' }
];

const SENSITIVE_HEADERS = [
  { name: 'x-client-cert', what: 'A client certificate forwarded by a proxy ' +
      'that terminated mTLS.' },
  { name: 'x-forwarded-client-cert', what: 'The same thing, as Envoy and ' +
                                           'Istio spell it.' },
  { name: 'x-ssl-client-cert', what: 'The same thing, as nginx spells it.' },
  { name: 'x-ssl-client-verify', what: 'A proxy\'s verdict on the ' +
                                       'certificate it verified.' },
  { name: 'x-ssl-client-s-dn', what: 'The subject DN of a certificate a ' +
                                     'proxy verified.' },
  { name: 'x-amzn-mtls-clientcert', what: 'The same thing, as an AWS load ' +
                                          'balancer spells it.' }
];

// ---------------------------------------------------------------------------
// MONITORING → TLS CONNECTION: WHAT THIS SERVICE SAW OF A REQUEST (#597,
// 2026-10-12; rcbj's decision 3 on #591).
//
// `GET /tls` and `GET /tls/forwarded` described the connection a page was
// loaded on and the headers it arrived with, to anybody, development only
// (#585). #591 moved every demonstration out of the runtime, and rcbj kept
// this one as a CONSOLE PAGE — Admin Read, and answered in product mode,
// because "what did the server make of my connection, and of the proxy in
// front of it" is a question an operator of a product deployment has. So
// the two pages are one view, `GET /admin-api/tls-connection`, drawn at
// `/admin/tls-connection` by `tls/web_tls_connection.ts`.
//
// **THE REQUEST DESCRIBED IS THE API CALL, NOT THE PAGE LOAD**, and the
// page says so. The console is a static application (#446): the browser
// loads its shell and then asks the management API, with a DPoP-bound
// token, for the view — a second request, on whatever connection the
// browser chose for it (HTTP keep-alive usually makes it the same one).
// For a console page that is fine: the client certificate a browser
// presents is per connection, and the forwarded headers a proxy writes are
// the same on every request it relays. A caller of the API reads the same
// view about ITS OWN request.
//
// **ANSWERED BY THE FRONT PROCESS**: both paths are in
// `common/request_pool.js`'s NEVER_DISPATCHED, beside `/tls`, because a
// request worker sees a unix socket where the front process sees the
// client's — the argument `/tls` was pinned on.
//
// What it reads: the socket's own TLS facts (version, cipher), the client
// certificate as `describeCertificate()` describes the sightings, whether
// it VERIFIED against the truststore and why not, what the identity gate
// (`tls_client_certificates.js`) makes of it, the revocation verdict
// `GET /tls/sign-in` would act on — and the forwarding headers with what
// `common/client_address.js` believed of them under `global.trustProxy` and
// `global.trustedProxies`. It changes nothing: no session is started, no
// sighting is recorded, no setting is written. The English sentences in it
// are data, as every view's are (#539).
// ---------------------------------------------------------------------------
/**
 * Describes the connection and the forwarding headers of the request it is
 * given, as this service saw and believed them: what `GET
 * /admin-api/tls-connection` answers and `/admin/tls-connection` draws.
 *
 * @param req - the request to describe
 * @returns a promise of the view; it never rejects
 */
function connectionView(req) {
  log.debug('Entering connectionView().');
  const socket = (req && (req.socket || req.connection)) || {};
  const headers = (req && req.headers) || {};
  let peer = null;
  try {
    peer = typeof socket.getPeerCertificate === 'function'
      ? socket.getPeerCertificate(true) : null;
  } catch (e) {
    // A socket that went away between the handshake and this line: nothing
    // presented to describe.
    log.debug('Caught in connectionView(): ' + ((e && e.message) || e));
    peer = null;
  }
  const presented = !!(peer && peer.raw && peer.raw.length);
  const tlsFact = function (name) {
    log.debug('Entering tlsFact(). ' + name);
    let out = null;
    try {
      if (name === 'protocol' && typeof socket.getProtocol === 'function') {
        out = socket.getProtocol() || null;
      } else if (name === 'cipher' &&
                 typeof socket.getCipher === 'function') {
        const cipher = socket.getCipher();
        out = cipher && cipher.name ? String(cipher.name) : null;
      }
    } catch (e) {
      log.debug('Caught in tlsFact(): ' + ((e && e.message) || e));
      out = null;
    }
    log.debug('Leaving tlsFact().');
    return out;
  };
  const seen = function (rows) {
    log.debug('Entering seen().');
    log.debug('Leaving seen().');
    return rows.map(function (row) {
      const value = headers[row.name];
      return { header: row.name, present: value !== undefined,
               value: value === undefined ? null : String(value),
               what: row.what };
    });
  };
  const trusted = !!config.value('global.trustProxy');
  const ranges = clientAddress.trustedProxyRanges();
  const sensitive = seen(SENSITIVE_HEADERS);
  const presentSensitive = sensitive.filter(function (row) {
    return row.present;
  });
  const identity = presented ? issuedIdentityOf(socket) : null;
  const view = {
    generatedAt: new Date().toISOString(),
    connection: {
      https: !!req.secure,
      encrypted: !!socket.encrypted,
      protocol: tlsFact('protocol'),
      cipher: tlsFact('cipher'),
      peerAddress: clientAddress.normalise(socket.remoteAddress) || null,
      clientAddress: clientAddress.clientAddressOf(req)
    },
    clientCertificate: {
      presented: presented,
      verified: presented && socket.authorized === true,
      authorizationError: presented && socket.authorizationError
        ? String(socket.authorizationError) : null,
      certificate: presented ? describeCertificate(peer, 0) : null,
      thumbprint: presented ? stsCrypto.certificateThumbprint(peer.raw) : '',
      identity: identity ? {
        issuedHere: !!identity.issuedHere,
        accepted: !!identity.accepted,
        kind: identity.kind || null,
        username: identity.username || null,
        realm: identity.realm === undefined ? null : identity.realm,
        why: identity.why || null
      } : null,
      revocation: null,
      signIn: '/tls/sign-in',
      note: presented
        ? 'What this connection carried. Verified means a chain to an anchor ' +
          'in the client truststore (/admin/tls/trust); what a verified ' +
          'certificate is worth is decided where it is used — a sign-on ' +
          'session at GET /tls/sign-in, RFC 8705 at the token endpoint, ' +
          '/xacml, /scim/v2. Nothing here started a session.'
        : 'No client certificate arrived on this connection. The main port ' +
          'asks every connection for one and requires none, so presenting ' +
          'one is the client\'s own doing.'
    },
    forwarded: {
      trustProxy: trusted,
      trustedProxies: config.value('global.trustedProxies') || [],
      rangesConfigured: ranges.configured,
      rangesUsable: ranges.count,
      peerIsTrustedProxy: clientAddress.peerIsTrustedProxy(req),
      believed: clientAddress.forwardedBelieved(req),
      socket: { scheme: req.protocol, host: req.get ? req.get('host') || ''
                                                    : '',
                encrypted: !!req.secure },
      effectiveBaseUrl: baseUrlOf(req),
      whatItMeans: !trusted
        ? 'global.trustProxy is OFF, so the forwarding headers below are ' +
          'IGNORED and this service describes the connection it can see. If ' +
          'a proxy is terminating TLS in front of it, the metadata is ' +
          'publishing the wrong URLs and every DPoP proof is being refused ' +
          'for naming the real endpoint — turn the setting on.'
        : (clientAddress.forwardedBelieved(req)
          ? 'global.trustProxy is ON and this request came from a peer it ' +
            'believes (' + (ranges.configured
              ? 'one of global.trustedProxies'
              : 'global.trustedProxies is empty, so ANY peer') + '), so ' +
            'X-Forwarded-Proto and X-Forwarded-Host decide what this ' +
            'service thinks its own URLs are, and X-Forwarded-For its ' +
            'idea of the client\'s address. That is correct behind a ' +
            'reverse proxy and unsafe without one.'
          : 'global.trustProxy is ON, but this request\'s peer is not in ' +
            'global.trustedProxies, so its forwarding headers were IGNORED: ' +
            'a caller that reached the node directly cannot choose this ' +
            'service\'s URL or its own address.'),
      forwarding: seen(FORWARDING_HEADERS),
      clientCertificateHeaders: {
        readByThisService: false,
        seen: presentSensitive.map(function (row) { return row.header; }),
        note: 'THIS SERVICE READS NONE OF THESE, in either mode. A ' +
              'certificate in a header is a certificate anybody can write, ' +
              'so believing one would let any client claim any identity — ' +
              'and RFC 8705 binding here reads the certificate off the TLS ' +
              'handshake itself. A proxy that terminates mTLS in front of ' +
              'this service therefore cannot pass the certificate through, ' +
              'which is a real limitation rather than an oversight: the ' +
              'alternative is trusting a header.' +
              (presentSensitive.length
                ? ' This request carried ' + presentSensitive.length + ' of ' +
                  'them and they were ignored.'
                : ''),
        headers: sensitive
      },
      proxyMustSanitize: 'RFC 9700 section 2.6: a reverse proxy MUST strip ' +
        'these headers from what a CLIENT sent before setting its own, or a ' +
        'client can reach past it by setting them itself. That is the ' +
        'proxy\'s job and this service cannot do it — what it can do is not ' +
        'believe them unless told to, which is what the settings above are.'
    }
  };
  if (!presented) {
    log.debug('Leaving connectionView(). No client certificate.');
    return Promise.resolve(view);
  }
  log.debug('Leaving connectionView(). The revocation verdict follows.');
  return checkedSocket(socket).then(function (verdict) {
    view.clientCertificate.revocation = verdict || null;
    return view;
  });
}

// ---------------------------------------------------------------------------
// THIS MODULE BINDS NOTHING SINCE 2026-09-16.
//
// It owned two listeners and started them from here, for the reason every
// socket owner in this service does: a bind can fail, and a `require` that
// throws takes the whole process down where a route cannot. Both are gone —
// see the block above `observeConnectionsOn()` — and what is left is a
// LIBRARY: the certificate, the truststore, the sightings and two routes on
// the main app.
//
// `listen()` and `close()` are kept rather than deleted, because `server.js`
// and three tests call them, and a socket owner that stops owning a socket
// should not also change the shape of the module on the same day. `close()`
// is a no-op; `listen()` binds nothing and reports no ports, and still does
// the two truststore steps below.
// ---------------------------------------------------------------------------
/**
 * Runs this module's startup step: reloads the stored trust anchors, applies
 * the truststore, and announces a listener certificate that changed since the
 * last start. It binds nothing.
 *
 * @returns `{ whenReady }`, a promise that is already resolved
 */
function listen() {
  log.debug('Entering listen().');
  // ---------------------------------------------------------------------
  // IT BINDS NOTHING AND IT IS STILL A STARTUP STEP, WHICH IS THE WHOLE
  // REASON IT WAS NOT DELETED.
  //
  // These two calls were the last thing `listen()` did before binding 8443
  // and 9443, and they are about the TRUSTSTORE rather than about a socket:
  //
  //   * the stored anchors come back. `persistence.start()` has restored the
  //     directory by the time `server.js` calls this, so this is the first
  //     moment `ou=trustAnchors` holds what was written before the restart.
  //     Dropping it — which the first draft of the deletion did — left a
  //     product service starting with an EMPTY client truststore however many
  //     anchors its store held, so every certificate that used to verify was
  //     unverified at the main port and nothing said why.
  //     `tests/truststore_persistence.js` is what caught it.
  //   * the context is re-applied whatever that found (2026-09-13): the main
  //     port and the debugger's listener were created before the certificate
  //     authority started, so the service Root that
  //     `issuedClientCertificateAnchor()` adds for the portal's TLS client
  //     certificates was not there to add.
  // ---------------------------------------------------------------------
  reloadStoredAnchors();
  applyAnchors();
  // AND A LISTENER CERTIFICATE OTHER THAN THE ONE LAST ANNOUNCED IS
  // ANNOUNCED (#264), now that the main port is bound — `server.js` calls
  // this from its listening callback. See `announceSinceLastStart()`.
  listened = true;
  announceSinceLastStart(listenerCertificatesOwned());
  log.info('tls: no listener of this module\'s own to bind — the 8443 and ' +
           '9443 listeners were deleted on 2026-09-16 and the main port ' +
           'carries what they did. The client truststore holds ' +
           anchors.length + ' anchor(s).');
  log.debug('Leaving listen(). The truststore is current.');
  return { whenReady: Promise.resolve({}) };
}

/**
 * Does nothing: this module owns no listener.
 */
function close() {
  log.debug('Entering close().');
  log.debug('Leaving close(). Nothing to close.');
}

/**
 * The certificate this service presents, the client certificates it is
 * presented with, and the client truststore: a library plus a few routes on the
 * main app, owning no listener of its own.
 *
 * @namespace
 */
module.exports = {
  listen: listen,
  close: close,
  // What the service last announced of the listener certificate (#264).
  lastAnnouncedListenerCertificates: lastAnnouncedListenerCertificates,
  listenerChangesSinceAnnounced: listenerChangesSinceAnnounced,
  // The listener-key rows this node holds, without their keys (2026-10-08).
  heldListenerKeys: heldListenerKeys,
  // Exported for tests, which check these without opening a socket.
  splitPemCertificates: splitPemCertificates,
  // The RFC 4514 form of a subject. It now LIVES in common/helpers.js and is
  // re-exported here so that scim_auth.js and spiffe_auth.js — which require
  // this module for it and have done since before it moved — go on getting the
  // same string this module records and the directory files a certificate
  // under. Two spellings of one DN is two people on /admin/users, and the
  // difference between them is a comma and a space.
  dnRfc4514: dnRfc4514,
  addAnchors: addAnchors,
  clearAnchors: clearAnchors,
  removeAnchor: removeAnchor,
  // The three the console and the management API reach the truststore
  // through — see the block above it. `common/protocol_stack.ts` hands this to
  // `admin.setTruststore()`.
  truststore: truststore,
  // The truststore's durable half: `ldap/ldap_server.js` installs the store
  // (ou=trustAnchors) and calls the reload when another process changes it.
  setTrustAnchorStore: setTrustAnchorStore,
  reloadStoredAnchors: reloadStoredAnchors,
  // The main HTTPS listener is created in server.js and registers here so that
  // a truststore change reaches it too — see the block above
  // trustClientCertificatesOn().
  trustClientCertificatesOn: trustClientCertificatesOn,
  forgetListener: forgetListener,
  // Applies the truststore again to every registered listener — and so each
  // listener's own certificate, after a custom listener's is renewed (#99, #472).
  reapplyTruststore: applyAnchors,
  // #212: the guard, for a TLS listener that does not register above.
  refuseNonNistCurveCertificatesOn: refuseNonNistCurveCertificatesOn,
  nonNistCurvePeerCertificate: nonNistCurvePeerCertificate,
  // LDAPS 636 and the SPIRE Server API re-key themselves on this (2026-09-21).
  onServerCertificateChange: onServerCertificateChange,
  // What secureContextOptions() would give a listener created elsewhere: the
  // certificates this service presents AND the anchors it verifies clients
  // against. Exported so that server.js and the debugger build their
  // listeners from the same answer applyAnchors() re-applies to them, rather
  // than assembling a second one that can drift.
  clientTruststoreOptions: secureContextOptions,
  // `tls.minVersion` / `tls.ciphers` / `tls.groups` /
  // `tls.signatureAlgorithms` for a TLS listener this module does not
  // create — LDAPS, which ldapjs builds, and the main port at creation.
  protocolOptions: protocolOptions,
  policyFor: policyFor,
  // A listener's own value for one setting, or undefined where it inherits
  // (#429): for a module that has a default of its own (SPIFFE's sigalgs).
  attachSessionCache: attachSessionCache,
  registerHttpListener: registerHttpListener,
  httpPolicyFor: httpPolicyFor,
  listenerOwnValue: function (kind, name) {
    return ownValue(kind, null, name);
  },
  clientAuthOptions: clientAuthOptions,
  // The sign-in screen's certificate (#1051), asked by `authn/authn.ts`
  // lazily: the offer its view draws and the first factor its act takes.
  screenCertificateOffer: screenCertificateOffer,
  screenCertificateHolder: screenCertificateHolder,
  registerPolicyApplier: registerPolicyApplier,
  reapplyPolicy: reapplyPolicy,
  listenerPolicies: listenerPolicies,
  postQuantumGroups: postQuantumGroups,
  TLS13_SUITES: TLS13_SUITES,
  PQ_GROUPS: PQ_GROUPS,
  /**
   * Reports what `tls.trustAnchorsFile` loaded.
   *
   * @returns the report
   */
  trustAnchorsFileLoaded: function () {
    log.debug("Entering trustAnchorsFileLoaded().");
    log.debug("Leaving trustAnchorsFileLoaded().");
    return anchorsFileReport;
  },
  // See the note above it: the modules that describe this certificate to a
  // reader ask here rather than each asserting it is self-signed.
  certificateProvenance: certificateProvenance,
  /**
   * Returns the listener certificate, in PEM.
   *
   * @returns the certificate
   */
  serverCertificatePem: function () {
    log.debug("Entering serverCertificatePem().");
    log.debug("Leaving serverCertificatePem().");
    return SERVER_CERTIFICATE.certPem;
  },
  // The whole of it, private key included, because ldap_server.js serves it on
  // 636 — see the note above SERVER_CERTIFICATE. Handing a private key to
  // another module in this process is not the same act as publishing one: this
  // key is held in memory, and written down only as this node's SEALED row of
  // `tls.listenerKeys` where minted state persists. Nothing here writes it to
  // a response; GET
  // /tls/server-certificate publishes the CERTIFICATE alone.
  /**
   * Returns the listener certificate with its private key, chain and trust
   * anchor, for another socket in this process to present. The key is never
   * written to a response.
   *
   * @returns `{ certPem, privateKeyPem, chainPem, trustAnchorPem, subject,
   * names, fingerprint256, notAfter }`
   */
  serverCertificate: function () {
    log.debug("Entering serverCertificate().");
    log.debug("Leaving serverCertificate().");
    return {
      certPem: SERVER_CERTIFICATE.certPem,
      privateKeyPem: SERVER_CERTIFICATE.privateKeyPem,
      // THE CHAIN AND THE ANCHOR ARE TWO DIFFERENT THINGS AND BOTH ARE HERE
      // (2026-09-11). `chainPem` is what this certificate TRAVELS WITH — the
      // Issuing CA and the Intermediate, leaf-first and without the Root, as
      // RFC 5246 section 7.4.2 asks — and it is empty while the certificate is
      // self-signed. `trustAnchorPem` is what a caller VERIFIES it against,
      // which is the Root. A caller that pins the leaf builds no path; see
      // trustAnchorPems() above for what that cost.
      chainPem: (SERVER_CERTIFICATE.chainPem || []).slice(0),
      // **THE LEAF IS THE FALLBACK ONLY WHERE THERE IS NO CHAIN**, which is
      // the self-signed case and is the one arrangement where the leaf really
      // is its own anchor. Where there IS a chain and `trustAnchorPems()`
      // answers nothing, the Root has been found not to sign it (see
      // `anchorSigns()`) and there is no honest anchor to give: the leaf
      // terminates no path, and neither does the Intermediate under OpenSSL's
      // default rules. An empty string is what a caller can test.
      // A supplied certificate falls back to nothing: trustAnchorPems() has
      // already answered for it, and a CA-issued leaf is no anchor.
      trustAnchorPem: trustAnchorPems()[0] ||
        (((SERVER_CERTIFICATE.chainPem || []).length ||
          SERVER_CERTIFICATE.algorithm === 'supplied')
          ? '' : SERVER_CERTIFICATE.certPem),
      subject: SERVER_CERTIFICATE.subject,
      names: SERVER_CERTIFICATE.names.slice(0),
      fingerprint256: SERVER_CERTIFICATE.fingerprint256,
      notAfter: SERVER_CERTIFICATE.notAfter
    };
  },
  // EVERY certificate the TLS sockets present, with its chain and nothing
  // private (2026-09-13). `serverCertificate()` above answers the FIRST, which
  // is what every existing caller means; an ML-DSA certificate beside it is a
  // leaf of the same TLS Issuing CA now, and this is where that is visible.
  // Every leaf the main port presents, as the socket presents it (#248).
  presentedCertificatePems: presentedCertificatePems,
  /**
   * Returns every certificate the TLS sockets present, with its chain and
   * nothing private.
   *
   * @returns one `{ algorithm, certPem, chainPem, fingerprint256, certified }`
   * per certificate
   */
  serverCertificateChains: function () {
    log.debug("Entering serverCertificateChains().");
    log.debug("Leaving serverCertificateChains().");
    return SERVER_CERTIFICATES.map(function (one) {
      return { algorithm: one.algorithm, certPem: one.certPem,
               chainPem: (one.chainPem || []).slice(0),
               fingerprint256: one.fingerprint256,
               certified: !!(one.chainPem && one.chainPem.length) };
    });
  },
  // Every anchor, for a caller building a truststore rather than one
  // connection: with two listener certificates configured there are two, and
  // which one a connection gets is OpenSSL's choice from the signature
  // algorithms the caller itself offered.
  trustAnchorPems: trustAnchorPems,
  // The three the request-worker pool uses. See their headers: the hierarchy
  // can be rebuilt in a process that does not own this socket.
  reconcileWithHierarchy: reconcileWithHierarchy,
  // Whether the listener is waiting for a process branch another process is
  // building (2026-09-13) — `common/request_pool.js` arms its fallback on it.
  listenerAwaitsBranch: listenerAwaitsBranch,
  serverCertificateBundle: serverCertificateBundle,
  adoptServerCertificate: adoptServerCertificate,
  /**
   * Returns how many anchors the client truststore holds.
   *
   * @returns the count
   */
  anchorCount: function () {
    log.debug("Entering anchorCount().");
    log.debug("Leaving anchorCount().");
    return anchors.length;
  },
  // The port a client certificate is presented to, for the pages that say so.
  // It answered `{ tls, mtls }` — 8443 and 9443 — until both were deleted on
  // 2026-09-16, and every caller wanted the same thing from it: where do I
  // send one.
  /**
   * Returns the port a client certificate is presented to.
   *
   * @returns `{ main }`
   */
  ports: function () {
    log.debug("Entering ports().");
    log.debug("Leaving ports().");
    return { main: MAIN_PORT };
  },
  // Installed by `server.js` on the main HTTPS listener: the sighting, and the
  // failed-handshake log that is otherwise invisible.
  observeConnectionsOn: observeConnectionsOn,
  // Monitoring → TLS connection's view (#597), for `GET
  // /admin-api/tls-connection`, which reaches this module lazily.
  connectionView: connectionView,
  // Exported for tests/tls_handshake_alerts.js (#225).
  handshakeFailureOf: handshakeFailureOf,
  // #201: the path rules asked of a chain OpenSSL verified; exported for
  // tests/x509_limbo.js, which holds the main port's posture to x509-limbo.
  holdToPathRules: holdToPathRules
};
