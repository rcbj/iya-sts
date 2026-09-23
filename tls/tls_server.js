// @ts-check
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
// LIBRARY plus six ordinary routes on the main app: the server certificate
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
// client certificate (`/tls/trust`), what this service presents
// (`/tls/server-certificate`), what a certificate that verified is worth
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
// and no image that could bake it in. `POST /tls/trust` takes the anchors and
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
//     correct starting state and the `/tls` page says so.
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
//     /tls/server-certificate and the first POST to /tls/trust have to be made
//     without verifying the certificate (`curl -k`). That is the ordinary
//     bootstrap for a certificate regenerated on every start — it is the same
//     act as trusting the PEM this endpoint hands back, done a step earlier —
//     and `mainPortPhrase()` below is what keeps every page in this module from
//     claiming a plain port that is not there.
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
// way and always has: the KDC issues tickets to anybody who asks with the one
// shared password, the sign-in screen checks no password at all, LDAP refuses
// no bind — and all three start real sessions. **The permissiveness lives in
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
const crypto = require('crypto');
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

// The input validator. A LEAF (rule 3): it registers no route and closes no
// cycle. Both `/tls` pages take exactly one parameter and it is a closed set.
const validation = require('../common/validation');
const { log, xmlEscape, parseBody, baseUrlOf } = helpers;
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

// ---------------------------------------------------------------------------
// THE MODE, UNDER A NAME THAT IS NOT `mode` (2026-09-12). This module already
// calls a listener's client-certificate posture `mode` ('optional' or
// 'required') in a dozen places, and a module-level `mode` beside them would be
// shadowed in exactly the functions a reader is likeliest to look for it in.
// A LEAF requiring only `config`; `helpers.js` above already requires it.
// ---------------------------------------------------------------------------
const serviceMode = require('../common/mode');
// For the one question below that must be asked of the PROCESS rather than of
// the ambient realm. A LEAF this module's closure already holds (`app.js` and
// `helpers.js` both require it).
const realms = require('../common/realms');

// ---------------------------------------------------------------------------
// THE TRUSTSTORE IS THE PROCESS'S, SO THE MODE THAT GUARDS IT IS TOO.
//
// `global.mode` is per trust realm, and `/realm/<id>/tls/trust` reaches this
// module's routes like any other path. The anchors are one array for every
// listener in the process, so a realm left in development inside a product
// process must not be a way to add one — asked in the DEFAULT realm, which is
// where a process-wide setting lives, the answer is the process's.
// ---------------------------------------------------------------------------
function truststoreOpenToAnybody() {
  log.debug("Entering truststoreOpenToAnybody().");
  log.debug("Leaving truststoreOpenToAnybody().");
  return realms.run(realms.get(realms.DEFAULT_ID), function () {
    return serviceMode.opensTestControls();
  });
}

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
// **A CIPHER LIST THAT MATCHES NOTHING STOPS THE SERVICE HERE**, at require
// time, naming the setting. Found any later it is a TypeError out of
// `https.createServer()` in `server.js`, or — worse, through
// `setSecureContext()` on a truststore change — a listener that silently keeps
// its old context while the page says the new one is in force.
// ---------------------------------------------------------------------------
function protocolOptions() {
  log.debug("Entering protocolOptions().");
  // `any`: the setting is a string, and the TLS types want a version literal.
  /** @type {any} */
  const options = { minVersion: String(config.value('tls.minVersion') ||
                                       'TLSv1.2'),
                    honorCipherOrder: true };
  const ciphers = String(config.value('tls.ciphers') || '').trim();
  if (ciphers) {
    options.ciphers = ciphers;
  }
  log.debug("Leaving protocolOptions().");
  return options;
}

(function checkProtocolOptions() {
  log.debug("Entering checkProtocolOptions().");
  try {
    tls.createSecureContext(protocolOptions());
  } catch (e) {
    log.fatal(errorCodes.tag('STS-TLS-0001') + 'tls: NOT STARTING. ' +
              'tls.minVersion / tls.ciphers (STS_TLS_MIN_VERSION / ' +
              'STS_TLS_CIPHERS) cannot build a TLS ' +
              'context: ' + e.message + '. An OpenSSL cipher list names ' +
              'suites such as ECDHE-RSA-AES256-GCM-SHA384, and an empty one ' +
              'means node\'s default.');
    process.exit(1);
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
// Generated per start and never written down, because a certificate committed
// to a repository is a private key committed to a repository. It is born
// SELF-SIGNED, and until 2026-09-11 it stayed that way, so the anchor changed
// on every restart — which is why `GET /tls/server-certificate` exists: a
// debugger fetches it and puts it in its own truststore, rather than being
// told to disable verification, which is the habit this whole workflow is
// trying to break. Since that day the key is certified under this service's
// own Root, which is the anchor now — see the block above
// `serverCertificateExtensions()`.
// ---------------------------------------------------------------------------
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
    // literals 2048, 2 and 'mock-sts' this call used to carry — the last of
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

// What to CALL the port these views answer on. It is the plain HTTP port
// unless `global.https` has made it TLS as well, and seven sentences in this
// module used to say "the plain HTTP port" outright — each of them correct
// until the day somebody turned that setting on, and then quietly wrong in
// the one place a reader goes when a handshake is failing. Read per call
// rather than captured: the setting is restart-only, but a captured const
// here would be a second thing to remember if that ever changed.
function mainPortPhrase() {
  log.debug("Entering mainPortPhrase().");
  log.debug("Leaving mainPortPhrase().");
  return config.value('global.https')
    ? 'the main HTTPS port' : 'the plain HTTP port';
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
    return 'issued by this service\'s TLS Issuing CA under its own Root ' +
           'and reissued on every start, so trust the Root ' +
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
    leaf = new crypto.X509Certificate(certPem);
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
    pair = leaf.checkPrivateKey(crypto.createPrivateKey(keyPem));
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
      const top = new crypto.X509Certificate(topPem);
      if (top.verify(new crypto.X509Certificate(pem).publicKey)) {
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
    const cert = new crypto.X509Certificate(pem);
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
    // OpenSSL 3.5 (node 24; this repository's Dockerfile pins 24.16.0), and
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
  record.certPem = certPem;
  // The chain travels with it: without the Issuing CA and the
  // Intermediate a client holding only the Root cannot build a path, and
  // "trust this one anchor" would be true and unusable.
  record.chainPem = chainPem.slice();
  record.fingerprint256 = fingerprintOf(certPem);
  record.selfSigned = false;
  try {
    const read = new crypto.X509Certificate(certPem);
    record.subject = read.subject.replace(/\n/g, ', ');
    record.notAfter = new Date(read.validTo).toISOString();
  } catch (e) {
    // The certificate is in use either way; what is lost is a page's
    // subject line. Named rather than swallowed.
    log.warn('tls: the certified ' + record.algorithm + ' server ' +
             'certificate could not be read back for its subject and ' +
             'expiry: ' + e.message);
  }
  // **AND THE LISTENERS HAVE TO BE TOLD, because they were built before
  // this ran.** Every listener this module knows — the main port and the
  // debugger's, registered through `trustClientCertificatesOn()` — was
  // created with the secure context evaluated THERE, before `pki.start()`
  // had run, so mutating the record above is invisible to a socket that
  // already has a context. `applyAnchors()` is the rebuild
  // path `POST /tls/trust` already uses, and it re-reads
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
  // service restarted (tests/vendored/sts_ldaps.js and sts_spiffe_grpc.js,
  // red in every mode). The log line below said "one anchor covers LDAPS 636"
  // the whole time. The owners of those sockets re-key on this.
  notifyCertificateObservers(record.algorithm);
  log.info('tls: the ' + record.algorithm + ' listener certificate is ' +
           'issued by this service\'s ' +
           'own TLS Issuing CA and chains to its Root — so one anchor ' +
           'covers LDAPS 636, the main port and every token ' +
           'this service signs.');
  log.debug("Leaving takeIssuedCertificate().");
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
  pki.registerCertifiable({
    scope: pki.PROCESS_SCOPE,
    useCase: 'tls',
    slot: 'server',
    alg: 'RS256',
    keyAlg: 'rsa-2048',
    label: 'TLS server certificate',
    commonName: TLS_HOSTNAMES[0] || 'localhost',
    profile: 'tls-server',
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extensions: serverCertificateExtensions(),
    publicKeyPem: function () {
      log.debug("Entering publicKeyPem().");
      log.debug("Leaving publicKeyPem().");
      return crypto.createPublicKey(SERVER_CERTIFICATE.privateKeyPem)
        .export({ type: 'spki', format: 'pem' });
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
    pki.registerCertifiable({
      scope: pki.PROCESS_SCOPE,
      useCase: 'tls',
      slot: 'server:' + record.algorithm,
      alg: record.algorithm.toUpperCase(),
      keyAlg: record.algorithm,
      label: 'TLS server certificate (' + record.algorithm + ')',
      commonName: TLS_HOSTNAMES[0] || 'localhost',
      profile: 'tls-server',
      // digitalSignature ALONE. An ML-DSA key cannot encipher anything, and
      // TLS 1.3 — the only version that negotiates one — needs nothing
      // else of a server certificate's key.
      keyUsage: ['digitalSignature'],
      extensions: serverCertificateExtensions(),
      publicKeyPem: function () {
        log.debug("Entering publicKeyPem().");
        log.debug("Leaving publicKeyPem().");
        return crypto.createPublicKey(record.privateKeyPem)
          .export({ type: 'spki', format: 'pem' });
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
      subject = new crypto.X509Certificate(pem).subject
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
    const parsed = new crypto.X509Certificate(pem);
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
    // The row is still described — `/tls/trust` has always accepted what it
    // was given, and that door's behaviour is not this function's to change —
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
// recorded as an authentication. An anchor POSTed to /tls/trust that happens to
// be the same Root is not added twice.
//
// Required lazily and answered '' on any failure: this is called whenever a
// secure context is built, which can be before the certificate authority has
// started, and a truststore must never be the thing that fails to build.
// ---------------------------------------------------------------------------
function issuedClientCertificateAnchor() {
  log.debug("Entering issuedClientCertificateAnchor().");
  let pem = '';
  try {
    pem = require('../common/tls_client_certificates').trustAnchorPem();
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
function issuedIdentityOf(socket) {
  log.debug("Entering issuedIdentityOf().");
  let identity = { issuedHere: false, accepted: false };
  try {
    identity = require('../common/tls_client_certificates').identityOf(
      revocationStatus.fromSocket(socket));
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
function secureContextOptions() {
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
    ca: anchors.map(function (anchor) { return anchor.pem; })
      .concat(issuedClientCertificateAnchor()),
    // The protocol floor and cipher list — see protocolOptions(). In here so
    // that a truststore change, which re-applies this whole object, cannot
    // quietly reset a listener to node's defaults.
    minVersion: protocolOptions().minVersion,
    ciphers: protocolOptions().ciphers,
    honorCipherOrder: true
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
    const anchor = new crypto.X509Certificate(anchorPem);
    const top = new crypto.X509Certificate(topPem);
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
// It reached the suite as `tests/vendored/sts_pki_distribution_points.js` in
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
function serverCertificateBundle() {
  log.debug("Entering serverCertificateBundle().");
  log.debug("Leaving serverCertificateBundle().");
  return {
    certPem: SERVER_CERTIFICATE.certPem,
    chainPem: (SERVER_CERTIFICATE.chainPem || []).slice(0),
    anchorPem: trustAnchorPems()[0] || ''
  };
}

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
  SERVER_CERTIFICATE.selfSigned = !(bundle.chainPem || []).length;
  SERVER_CERTIFICATE.fingerprint256 = fingerprintOf(bundle.certPem);
  try {
    const read = new crypto.X509Certificate(bundle.certPem);
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
// ---------------------------------------------------------------------------
const externalServers = [];

function trustClientCertificatesOn(server, label) {
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
                         label: String(label || 'a listener') });
  // APPLIED IMMEDIATELY, because anchors may already be loaded — this service
  // can be handed a truststore before the main port binds, and a listener that
  // only picked anchors up on the NEXT change would be one whose behaviour
  // depended on the order two unrelated things happened in.
  applyAnchors();
  log.info('tls: the client truststore now covers ' + label + '. A client ' +
           'certificate presented there is verified against ' +
           'the ' + anchors.length + ' anchor(s) ' +
           'at /tls/trust; one that chains to none of them is still accepted ' +
           'and still binds a token, which is what that port has always done.');
  log.debug('Leaving trustClientCertificatesOn(). Covered.');
  return true;
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
  externalServers.map(function (one) { return one.server; })
    .forEach(function (server) {
    try {
      server.setSecureContext(secureContextOptions());
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

// `options.source` is `runtime` unless a caller says otherwise — the file
// loader below pushes directly and marks its own rows `file` — and
// `options.strict` is the management door's: see the block above `truststore`
// at the foot of this section for why `/tls/trust` does not pass it.
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
// that door: `clearAnchors()` is what `POST /tls/trust/clear` calls, and a
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

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

function pageShell(title, inner) {
  log.debug("Entering pageShell().");
  log.debug("Leaving pageShell().");
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) +
    '</title><style>body{font-family:system-ui,-apple-system,"Segoe UI",' +
    'Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem;color:#222;' +
    'line-height:1.45}.card{background:#fff;border:1px solid ' +
    '#d5d5dd;border-radius:10px;padding:24px 28px;max-width:60rem;margin:0 ' +
    'auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 ' +
    '0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 ' +
    '.4em}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
    '18px}p.verdict{background:#f0f0f8;border-left:4px solid ' +
    '#12107c;padding:.6rem .8rem;margin:.6rem ' +
    '0}table{border-collapse:collapse;width:100%;margin:.5rem 0 ' +
    '1rem;font-size:.85em}th,td{border:1px solid #ddd;padding:.35rem .55rem;' +
    'text-align:left;vertical-align:top}th{background:#f0f0f5}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
    'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;' +
    'border-radius:3px;word-break:break-all}a{color:#12107c}' +
    'textarea{width:100%;font-family:ui-monospace,monospace;font-size:.8em}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em ' +
    '0}</style></head><body><div ' +
    'class="card">' + inner + '</div></body></html>\n';
}

function rowsFrom(pairs) {
  log.debug("Entering rowsFrom().");
  log.debug("Leaving rowsFrom().");
  return pairs.map(function (pair) {
    return '<tr><td>' + xmlEscape(pair[0]) + '</td><td><code>' +
      xmlEscape(pair[1] === null || pair[1] === undefined
        ? '(none)' : String(pair[1])) + '</code></td></tr>';
  }).join('');
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
// OpenSSL built a chain from what the client sent to an anchor somebody POSTed
// to `/tls/trust` — and that turning it into an identity would teach a client
// something false about every server it will ever meet.
//
// **WHAT THE ARGUMENT ACTUALLY PROTECTED WAS THE STRENGTH OF THE CLAIM, NOT
// THE ABSENCE OF THE SESSION.** PKI client-certificate authentication is a
// real, deployed way for a person to sign in to a web application; the thing a
// mock must not do is pretend the chain check proved more than it did. Every
// other family here resolves the same tension the same way and has for as long
// as this service has existed: the KDC issues tickets to anybody who asks with
// the one shared password, the sign-in screen checks no password at all, LDAP
// refuses no bind — and all three start real sessions. **The permissiveness
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
  const socket = req.socket;
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving startCertificateSession(). Nothing verified here.');
    return { started: false,
             why: 'no verified client certificate on this connection, so ' +
                  'there is nobody to sign in' };
  }
  // REFUSED ON REVOCATION (2026-09-12), before the existing-session read below:
  // a browser already holding a session is not handed a new one, and a revoked
  // certificate must not be the thing that is reported as having "already" got
  // in. The session is the one thing this function gives out, so it is the
  // point the refusal is made at.
  if (revocation && revocation.refused) {
    log.info('tls: a verified client certificate on the ' + mode + ' ' +
             'listener was refused a session on revocation: ' + revocation.why);
    log.debug('Leaving startCertificateSession(). Refused on revocation.');
    return { started: false, refusedOnRevocation: true,
             why: 'the certificate verified and was REFUSED ON REVOCATION ' +
                  '(pki.revocationCheck is ' + revocation.policy + '): ' +
                  revocation.why };
  }
  // NOT AN IDENTITY (2026-09-13): a chain through this service's own Root from
  // an authority that does not issue TLS client identities. See
  // `issuedClientCertificateAnchor()` for why that Root is trusted at all and
  // why trusting it is not trusting everything under it.
  const gated = identity || issuedIdentityOf(socket);
  if (gated.issuedHere && !gated.accepted) {
    log.info('tls: a verified client certificate on the ' + mode + ' ' +
             'listener was issued by this service and is not a TLS client ' +
             'identity, so no session was started: ' + gated.why + '.');
    log.debug('Leaving startCertificateSession(). Not an identity.');
    return { started: false, refusedAsIdentity: true,
             why: 'the certificate verified and is NOT AN IDENTITY here: ' +
                  gated.why };
  }
  // AN APPLICATION'S CERTIFICATE IS A CLIENT CREDENTIAL AND NOT A SIGN-IN
  // (2026-09-13). The identity gate accepts a leaf naming a
  // urn:sts:application: — that is what RFC 8705's implicit mapping at the
  // token endpoint reads — and until then this function started a browser
  // sign-on session for whatever name it carried, so an application whose
  // identifier happened to be a person's username signed in AS that person.
  // It became reachable by anybody holding such a certificate the day the
  // application Credentials section started issuing them.
  if (gated.issuedHere && gated.accepted && gated.kind === 'application') {
    log.info('tls: a verified client certificate on the ' + mode + ' ' +
             'listener was issued to the application ' + gated.username +
             ', which authenticates at the token endpoint (RFC 8705) and ' +
             'signs nobody in, so no session was started.');
    log.debug('Leaving startCertificateSession(). An application.');
    return { started: false, application: gated.username,
             why: 'the certificate verified and was issued to the ' +
                  'application "' + gated.username + '"; an application ' +
                  'presents it at the token endpoint under RFC 8705, and it ' +
                  'is not a browser sign-in' };
  }
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

function startCertificateSessionIn(req, res, mode, revocation, gated) {
  log.debug('Entering startCertificateSessionIn(). mode=' + mode);
  const socket = req.socket;
  // ALREADY SIGNED IN ON THIS BROWSER. Read rather than replaced, so that a
  // second fetch of /tls/sign-in does not mint a second session for somebody
  // who already has one — which would leave a global sign-out reporting two
  // where the person experienced one.
  const existing = authn.sessionOf(req);
  if (existing) {
    log.debug('Leaving startCertificateSessionIn(). One was already open.');
    return { started: false, id: existing.id, username: existing.user &&
             existing.user.username,
             why: 'this browser already holds a sign-on session, and ' +
                  'presenting a certificate to this listener does not start ' +
                  'a second one' };
  }
  let cert = null;
  try {
    cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
  } catch (e) {
    // A socket that went away between the handshake and this line. Swallowed
    // for recordClientCertificate()'s reason: this runs inside the
    // /tls/sign-in handler, and a throw here answers nothing.
    log.debug('startCertificateSessionIn(): the peer certificate could not ' +
              'be read: ' + e.message);
    log.debug("Leaving startCertificateSessionIn().");
    return { started: false, why: 'the peer certificate could not be read' };
  }
  if (!cert || !Object.keys(cert).length) {
    // A RESUMED TLS SESSION carries no peer certificate — the client does not
    // send it again. Nothing is started, rather than a session with no identity
    // on it.
    log.debug('Leaving startCertificateSessionIn(). No peer certificate; a ' +
              'resumed session.');
    return { started: false,
             why: 'the connection verified but carries no peer certificate, ' +
                  'which is what a resumed TLS session looks like' };
  }
  const subject = dnRfc4514(cert.subject);
  const common = cert.subject && cert.subject.CN
    ? String(Array.isArray(cert.subject.CN) ? cert.subject.CN[0] :
             cert.subject.CN)
    : '';
  // THE IDENTITY THE ISSUING AUTHORITY WROTE, where this service issued it:
  // the `urn:sts:person:` (or application) name, which is what an enrolled
  // certificate is mapped to its entry by. Otherwise the common name, as it
  // has been since 2026-09-05.
  const username = (gated && gated.accepted && gated.username) ||
                   common || subject;
  if (!username) {
    log.debug('Leaving startCertificateSessionIn(). The subject is empty.');
    return { started: false,
             why: 'the certificate names nobody: it has neither a common ' +
                  'name nor a subject' };
  }
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
  log.info('tls: ' + username + ' is signed in on a verified client ' +
           'certificate ' +
           '(' + mode + ' listener). The chain verified and ' + revocationSaid);
  log.debug('Leaving startCertificateSessionIn(). Started ' + session.id + '.');
  return { started: true, id: session.id, username: username,
           subject: subject,
           // The realm the session is in: the certificate's issuing authority's
           // for one this service issued, the default realm's otherwise.
           realm: realms.currentId(),
           note: 'the chain verified against an anchor in this service\'s ' +
                 'truststore and ' + revocationSaid + '. The session is this ' +
                 'service tracking that the holder got in, which is what ' +
                 'lets a global sign-out end it.' };
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
// from what the client sent to an anchor somebody POSTed to /tls/trust. No
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
// `tls.trustAnchorsFile`. Product mode refuses `POST /tls/trust` (see there),
// and a deployment that verifies client certificates at all — a remote XACML
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
    checkedSocket(socket).then(function (revocation) {
      recordClientCertificate(socket, 'optional', revocation);
    });
  });
  // A handshake that failed reaches a listener as a socket error and never as
  // a request, so without this it is invisible: the far end sees a closed
  // connection and this log says nothing at all. It is the single most
  // confusing failure in mutual TLS, so it is logged with the reason OpenSSL
  // gave. On this port a client certificate is never REQUIRED, so what lands
  // here is a broken handshake rather than a refused credential.
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
    log.warn('tls: a handshake failed on ' + label + ' from ' +
             ((socket && socket.remoteAddress) || 'an unknown address') +
             ': ' + error.message + '. A client certificate is asked for and ' +
             'never required here, so this is the handshake itself rather ' +
             'than a certificate being refused.');
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
// The views on the main port.
//
// Every surface of this module is a route since 2026-09-16, so
// /admin/sts-metadata, which walks the Express router, sees all of them. The
// ungated truststore controls are on the MAIN port on purpose — see the
// header, including what global.https changes about that — and the gated
// doors are the console's and the management API's (`truststore` below).
// ---------------------------------------------------------------------------

function description(req) {
  log.debug('Entering description().');
  const host = String(req.get('host') || 'localhost').split(':')[0];
  const out = {
    // What this service presents, and — when there is more than one — the
    // fact that WHICH one arrives is decided by the client's own signature
    // algorithms rather than by this service.
    serverCertificates: SERVER_CERTIFICATES.map(function (one) {
      return { algorithm: one.algorithm, subject: one.subject,
              names: one.names, fingerprint256: one.fingerprint256,
              notAfter: one.notAfter,
              // Whether this one is a leaf of the TLS Issuing CA or still the
              // self-signed certificate it was born with — per certificate,
              // since the ML-DSA ones joined the tree (2026-09-13).
              certified: !!(one.chainPem && one.chainPem.length) };
    }),
    serverCertificateNote: SERVER_CERTIFICATES.length > 1
      ? 'Several certificates are configured (tls.certificateAlgorithms). ' +
        'OpenSSL serves whichever one matches the signature algorithms the ' +
        'CLIENT offered, so an ordinary client and a post-quantum one get ' +
        'different certificates from the same port — which is what a ' +
        'migration looks like. GET /tls/server-certificate returns all of ' +
        'them, and a truststore needs all of them.'
      : 'One certificate, self-signed and regenerated at every start. GET ' +
        '/tls/server-certificate for it. Add an ML-DSA one beside it with ' +
        'tls.certificateAlgorithms=rsa,ml-dsa-65.',
    // ONE LISTENER SINCE 2026-09-16. This was two entries — 8443 asking for a
    // client certificate and 9443 requiring one — and both sockets were
    // deleted: the main port already had the first posture, and the second
    // cannot be had on a port every other protocol answers on. What a client
    // certificate is worth is now decided where it is USED.
    listeners: [
      { mode: 'optional',
        url: 'https://' + host + ':' + MAIN_PORT + '/',
        port: MAIN_PORT,
        listening: true,
        requestsClientCertificate: !!config.value('global.https'),
        requiresClientCertificate: false,
        what: 'The main port asks every connection for a client certificate ' +
          'and requires none, so presenting one is the CLIENT\'s decision. ' +
          'What arrives is recorded, and is judged where it is used: at the ' +
          'token endpoint (RFC 8705), at /xacml, at /scim/v2, and at ' +
          'GET /tls/sign-in, which starts a session for a verified one.' }
    ],
    listenError: listenError,
    // `report: '/tls/whoami'` and `page: '/'` were here until 2026-09-16,
    // and both were routes on the deleted listeners. What a caller can be
    // pointed at now is the sign-in — which reports what the connection
    // carried as well as signing its holder in — and the two documents.
    paths: {
      signIn: '/tls/sign-in',
      trust: '/tls/trust',
      serverCertificate: '/tls/server-certificate'
    },
    serverCertificate: {
      subject: SERVER_CERTIFICATE.subject,
      names: SERVER_CERTIFICATE.names,
      fingerprint256: SERVER_CERTIFICATE.fingerprint256,
      notAfter: SERVER_CERTIFICATE.notAfter,
      selfSigned: true,
      pemUrl: '/tls/server-certificate'
    },
    truststore: {
      anchors: anchors.length,
      maxAnchors: MAX_ANCHORS,
      subjects: anchors.map(function (anchor) { return anchor.subject; }),
      fingerprints: anchors.map(function (anchor) {
        return anchor.fingerprint256;
      }),
      addUrl: '/tls/trust',
      clearUrl: '/tls/trust/clear',
      // The GATED doors, which answer in both modes (2026-09-12): the console
      // page lists every anchor with where it came from, and the management
      // API adds and removes one at a time.
      consoleUrl: '/admin/tls/trust',
      apiUrl: '/admin-api/tls/trust',
      // Whether those two answer anybody (development) or refuse (product), and
      // the file product mode reads instead.
      changeableOverHttp: truststoreOpenToAnybody(),
      anchorsFile: anchorsFileReport.file || null,
      anchorsFromFile: anchorsFileReport.loaded
    },
    // `tls.minVersion` and `tls.ciphers`, as every TLS socket applies them.
    protocol: { minVersion: protocolOptions().minVersion,
                ciphers: protocolOptions().ciphers || '(node default)' },
    // WHAT A PRESENTED CERTIFICATE IS HELD TO BEYOND ITS CHAIN (2026-09-12):
    // the policy in force, how it was decided, where it is and is not
    // consulted, and the one sentence every surface repeats. The verdict for
    // a particular connection is on /tls/sign-in.
    revocation: Object.assign(revocationStatus.describePolicy(),
                              { cache: revocationStatus.cacheReport() }),
    // FALSE SINCE 2026-09-05 AND KEPT UNDER ITS OLD NAME, because a client
    // reading this document by that key is entitled to a truthful answer
    // rather than a missing one. A verified client certificate now starts a
    // sign-on session at GET /tls/sign-in, after the revocation check that
    // `revocation` above describes.
    authenticatesNobody: false,
    signsInVerifiedCertificates: {
      started: true,
      what: 'GET /tls/sign-in on a connection carrying a client certificate ' +
        'that VERIFIED starts a sign-on session for its common name (or its ' +
        'RFC 4514 subject, where it has no common name), and the response ' +
        'carries the session cookie',
      when: 'when that route is asked, and not again while the ' +
        'browser sends the cookie back',
      note: 'REVOCATION IS CONSULTED BEFORE THE SESSION STARTS (see ' +
        '`revocation` above — it said NO REVOCATION IS CHECKED until ' +
        '2026-09-12), and a certificate the policy refuses gets no session; ' +
        'the route still answers 200, saying so. The session is this service ' +
        'tracking that the holder got in — which is what lets /admin/logout ' +
        'end it.',
      endUrl: '/admin/logout'
    },
    // Beside the sign-in rather than instead of it, and the two are next to
    // each other so that neither can be read alone: what is RECORDED is the
    // certificate's own identity, and who is SIGNED IN is its common name.
    recordsVerifiedCertificates: {
      recorded: true,
      what: 'when a handshake completes with a client certificate that ' +
        'verified, the subject DN is filed as an authentication (protocol ' +
        '"TLS") and the embedded LDAP directory seeds an entry for it',
      when: 'once per handshake, not once per request',
      consoleUrl: '/admin/users?protocol=TLS',
      directoryUrl: '/admin/ldap/directory',
      note: 'a record of what happened. A session IS started beside it since ' +
        '2026-09-05 (see signsInVerifiedCertificates above) and no token is ' +
        'issued; a certificate refused on revocation is not recorded, and ' +
        'nothing in this service consults the record itself.'
    }
  };
  log.debug('Leaving description().');
  return out;
}

// ---------------------------------------------------------------------------
// The one parameter these two pages take.
//
// **CASE-INSENSITIVE ON PURPOSE**, because the call sites below compare after
// `.toLowerCase()` — a closed set written case-sensitively here would refuse
// `?format=JSON`, which those lines accept today. A validator that changes what
// an endpoint accepts is not validating it.
//
// `html` is in the set although nothing compares against it: anything that is
// not `json` renders HTML, so it is the other real answer and a caller naming
// it should not be refused for being explicit.
// ---------------------------------------------------------------------------
const TLS_QUERY = validation.z.looseObject({
  format: validation.types.opt(validation.z.string().regex(/^(json|html)$/i,
    'must be "json" or "html"'))
});

app.get('/tls', function (req, res) {
  log.debug('Entering GET /tls.');
  const info = description(req);
  const askedFormat = validation.check(req, 'query', TLS_QUERY);
  if (!askedFormat.ok) {
    log.debug('Leaving the TLS page. ' + askedFormat.detail);
    errorCodes.mark(res, 'STS-TLS-0023');
    return res.status(400).type('text/plain').send(askedFormat.detail + '\n');
  }
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /tls. JSON.');
    return res.status(200).set('Cache-Control', 'no-store').json(info);
  }
  const listenerRows = info.listeners.map(function (listener) {
    return '<tr><td><code>' + xmlEscape(listener.url) + '</code></td><td>' +
      (listener.requiresClientCertificate ? 'required' : 'optional') +
      '</td><td>' + (listener.listening ? 'up' : 'DOWN') + '</td><td>' +
      xmlEscape(listener.what) + '</td></tr>';
  }).join('');
  const anchorRows = anchors.length
    ? anchors.map(function (anchor) {
        return '<tr><td><code>' + xmlEscape(anchor.subject) +
          '</code></td><td><code>' + xmlEscape(anchor.fingerprint256) +
          '</code></td></tr>';
      }).join('')
    : '<tr><td colspan="2">Empty. No client certificate can verify here ' +
      'yet, and nothing can connect to the listener that requires one.</td>' +
      '</tr>';
  const inner = '<h1>A TLS endpoint lives here</h1><p class="sub">Two HTTPS ' +
    'listeners whose only content is what the server saw: the request as it ' +
    'arrived, what TLS negotiated underneath it, and the client certificate ' +
    'exactly as it was presented. This page is on ' +
    xmlEscape(mainPortPhrase()) +
    (config.value('global.https')
      ? ', so there is no plain listener in this process: fetch the server ' +
        'certificate below without verifying it the first time, then trust it.'
      : ', which is the one that is reachable before anything is trusted.') +
    '</p>' +
    '<table><tr><th>URL</th><th>Client certificate</th><th>Listener</th>' +
    '<th>What it is for</th></tr>' + listenerRows + '</table>' +
    (info.listenError
      ? '<p class="verdict">A listener did not bind: ' +
        xmlEscape(info.listenError) + '. This page is HTTP and answers ' +
        'either way; the listener does not.</p>'
      : '') +
    '<h2>The server certificate</h2>' +
    '<p>Self-signed, and <strong>regenerated on every start</strong> — so it ' +
    'is an anchor nobody can have baked in. Fetch it and put it in your own ' +
    'truststore rather than switching verification off, which is the habit ' +
    'this whole workflow exists to break.</p>' +
    '<table>' + rowsFrom([
      ['Subject', info.serverCertificate.subject],
      ['Names', info.serverCertificate.names.join(', ')],
      ['SHA-256', info.serverCertificate.fingerprint256],
      ['Not after', info.serverCertificate.notAfter],
      ['PEM', 'GET /tls/server-certificate']
    ]) + '</table><h2>What client certificates are verified ' +
    'against</h2><p>Empty at startup, and it has to be: the certificate ' +
    'authority whose clients this verifies is generated in a ' +
    '<em>browser</em>, minutes before the connection, and exists nowhere ' +
    'else. Paste its certificate here — the root, or the whole chain above ' +
    'the ' +
    'leaf.</p><table><tr><th>Anchor</th><th>SHA-256</th></tr>' + anchorRows +
    '</table><form method="post" action="/tls/trust"><textarea ' +
    'name="certificates" rows="6" placeholder="-----BEGIN ' +
    'CERTIFICATE-----"></textarea><p><button type="submit">Trust ' +
    'these</button></p></form><form method="post" ' +
    'action="/tls/trust/clear"><button type="submit">Empty the ' +
    'truststore</button></form><p class="sub">Both buttons are test controls ' +
    'and product mode refuses them. The gated doors answer in every mode: <a ' +
    'href="/admin/tls/trust">the truststore page in the admin console</a>, ' +
    'which also says where each anchor came from, and <code>POST ' +
    '/admin-api/tls/trust/add</code> / ' +
    '<code>remove</code>.</p><h2>Revocation</h2><p>' +
    xmlEscape(revocationStatus.describePolicy().sentence) + '</p><h2>What a ' +
    'verified certificate is worth here</h2><p>A verified client ' +
    'certificate means one thing: a chain was built from what the client ' +
    'sent to an anchor somebody supplied. No token is issued for presenting ' +
    'one, and this port requires nobody to present one at all. What it is ' +
    'good for is <a href="/tls/sign-in">GET /tls/sign-in</a>, which starts ' +
    'a sign-on session for its holder, and the doors that read a certificate ' +
    'for themselves: RFC 8705 client authentication at the token endpoint, ' +
    '<code>/xacml</code> and <code>/scim/v2</code>.</p><p>It is also ' +
    '<em>recorded</em>, which is a different ' +
    'claim. When the handshake completes with a certificate that verified, ' +
    'the subject DN is filed as an authentication on <a ' +
    'href="/admin/users">/admin/users</a> and the embedded LDAP directory ' +
    'seeds an entry for it — a certificate subject is already a DN, so it is ' +
    'the one identity here that does not have to be turned into one, and the ' +
    'subject, issuer, serial and validity go on the entry beside it. <a ' +
    'href="/admin/ldap/service">The directory service</a> says where. Both ' +
    'are a record of what happened; neither is a credential.</p><p ' +
    'class="sub"><a href="/tls?format=json">This page as JSON</a> &middot; ' +
    '<a href="/admin/sts-metadata">everything this service speaks</a></p>';
  res.status(200).type('html').set('Cache-Control', 'no-store')
     .send(pageShell('TLS endpoint', inner));
  log.debug('Leaving GET /tls.');
});

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
  clusterBarrier.middleware()(req, res, function () {
    checkedSocket(req.socket).then(function (revocation) {
      const identity = issuedIdentityOf(req.socket);
      const session = startCertificateSession(req, res, 'optional', revocation,
                                              identity);
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
      res.status(200).type('application/json').send(JSON.stringify(answer));
      log.debug('Leaving GET /tls/sign-in. signedIn=' + answer.signedIn);
    });
  });
});

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
// A TEST CONTROL, AND PRODUCT MODE REFUSES IT (2026-09-12).
//
// Adding an anchor decides whose client certificates VERIFY on the main port
// — and since 2026-09-06 a verified certificate is an identity:
// it resolves to a directory entry, a group and a role, and it is what admits a
// remote XACML PEP to the documents this service enforces its own access with.
// Both routes answered anybody who could reach the port. In development that is
// the point (a test drives the truststore, and the launchers post the PEP's
// Root here). In product mode (`mode.opensTestControls()` false) an anchor
// anybody can add is a certificate anybody can make verify.
//
// **REFUSED RATHER THAN GATED, AND THE REFUSAL SAYS WHERE TO GO.** The obvious
// alternative was to require the credential `/admin-api` requires — an access
// token with `admin:write` — and it was not taken for a structural reason:
// that verification is middleware inside `mgmt-api/admin_api.ts`, exported as
// nothing, and a second copy of it here would be a second answer to "who may
// administer this service" (the mistake `logout.js` exists to prevent).
//
// **THE RUNTIME DOOR EXISTS SINCE 2026-09-12 AND IT IS NOT THIS ONE.** This
// paragraph ended "a management-API operation that calls `addAnchors()` behind
// that API's own gate is the runtime door still to be built". It is built:
// `/admin/tls/trust` behind the console's session and roles, and
// `POST /admin-api/tls/trust/{add,remove}` behind that API's access token —
// both through `truststore` below, handed to the console through
// `admin.setTruststore()`. So these two routes stay exactly as they were in
// both modes, and the refusal now names the gated doors as well as the file.
// ---------------------------------------------------------------------------
function refuseTruststoreChange(req, res, route) {
  log.debug('Entering refuseTruststoreChange(). route=' + route);
  const message = route + ' changes whose client certificates this service ' +
    'verifies, and in product mode it is not open to whoever can reach the ' +
    'port. At runtime, use the gated doors: the console page ' +
    '/admin/tls/trust (Admin Write) or POST /admin-api/tls/trust/add and ' +
    'POST /admin-api/tls/trust/remove (an access token carrying ' +
    'admin:write). Neither persists what it adds; for anchors that must ' +
    'survive a restart, put the CA certificates in a PEM file and set ' +
    'tls.trustAnchorsFile (STS_TLS_TRUST_ANCHORS_FILE), which is read at ' +
    'startup. ' + anchors.length +
    ' anchor(s) are in force now.';
  log.info('tls: refused ' + route + ' — product mode.');
  errorCodes.mark(res, 'STS-TLS-0024');
  if (/html/i.test(String(req.headers.accept || ''))) {
    log.debug('Leaving refuseTruststoreChange(). HTML.');
    return res.status(403).type('html').send(pageShell('Truststore',
      '<h1>The truststore is not changed from here</h1><p>' +
      xmlEscape(message) +
      '</p><p class="sub"><a href="/admin/tls/trust">the truststore page in ' +
      'the admin console</a> &middot; <a href="/tls">back to the TLS ' +
      'endpoint</a></p>'));
  }
  log.debug('Leaving refuseTruststoreChange(). JSON.');
  errorCodes.mark(res, 'STS-TLS-0024');
  log.debug("Leaving refuseTruststoreChange().");
  return res.status(403).json({ error: 'forbidden', errors: [message],
                                anchors: anchors.length,
                                console: '/admin/tls/trust',
                                api: '/admin-api/tls/trust' });
}

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
// **`add` IS STRICT AND `/tls/trust` IS NOT.** A block OpenSSL cannot read is
// refused whole here, because an anchor the listener cannot parse makes the
// next `setSecureContext()` throw on every listener (logged, and the listeners
// keep their old context while the page says otherwise). `/tls/trust` has
// always accepted what it was given, and a development-mode test control is
// left behaving as it did.
//
// **A RUNTIME ANCHOR IS PERSISTED SINCE LATER THE SAME DAY**, and this
// paragraph said *nothing here is persisted* until then. It is written to
// ou=trustAnchors as it is added (see `setTrustAnchorStore()`), so it survives
// a restart wherever the directory does and reaches every other process against
// the same store. What did NOT change: an anchor from `tls.trustAnchorsFile`
// is not stored, and removing one lasts until the next start. The doors say so.
// ---------------------------------------------------------------------------
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

// The body may be raw PEM (what a script sends), or the `certificates` member
// of a form or JSON body (what the /tls page sends). They are told apart by
// looking for the PEM header rather than by the content type, because a raw PEM
// posted as text/plain would otherwise be run through URLSearchParams and come
// out as a set of nonsense keys — a silent mangling rather than a refusal.
app.post('/tls/trust', function (req, res) {
  log.debug('Entering POST /tls/trust.');
  if (!truststoreOpenToAnybody()) {
    log.debug('Leaving POST /tls/trust. Product mode.');
    return refuseTruststoreChange(req, res, 'POST /tls/trust');
  }
  const raw = typeof req.body === 'string' ? req.body : '';
  const looksLikePem = /-----BEGIN CERTIFICATE-----/.test(raw) &&
      !/^certificates=/.test(raw.trim());
  const text = looksLikePem ? raw
    : String((parseBody(req) || {}).certificates || '');
  const result = addAnchors(text);
  const wantsHtml = /html/i.test(String(req.headers.accept || '')) &&
      !/json/i.test(String(req.headers['content-type'] || ''));
  if (result.error && !result.added) {
    log.debug('Leaving POST /tls/trust. Refused: ' + result.error);
    errorCodes.mark(res, result.errorCode || 'STS-TLS-0012');
    if (wantsHtml) {
      return res.status(400).type('html').send(pageShell('Truststore',
        '<h1>Nothing was added</h1><p>' + xmlEscape(result.error) + '</p>' +
        '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
    }
    errorCodes.mark(res, result.errorCode || 'STS-TLS-0012');
    return res.status(400)
              .json({ error: result.error, anchors: anchors.length });
  }
  if (wantsHtml) {
    log.debug('Leaving POST /tls/trust. HTML, added=' + result.added);
    return res.status(200).type('html').send(pageShell('Truststore',
      '<h1>' + result.added + ' anchor(s) added</h1>' +
      '<p>This service now verifies client certificates against ' +
      anchors.length + ' anchor(s). Existing connections keep the truststore ' +
      'they were made under; the next handshake is judged against this ' +
      'one.</p><p class="sub"><a href="/tls">back to the TLS ' +
      'endpoint</a></p>'));
  }
  res.status(200).json({
    added: result.added,
    duplicates: result.duplicates || 0,
    anchors: anchors.length,
    subjects: anchors.map(function (anchor) { return anchor.subject; }),
    note: 'Applied with tls.Server.setSecureContext(). Existing connections ' +
      'keep the truststore they were made under; the next handshake is ' +
      'judged against this one.'
  });
  log.debug('Leaving POST /tls/trust. added=' + result.added);
});

app.post('/tls/trust/clear', function (req, res) {
  log.debug('Entering POST /tls/trust/clear.');
  if (!truststoreOpenToAnybody()) {
    log.debug('Leaving POST /tls/trust/clear. Product mode.');
    return refuseTruststoreChange(req, res, 'POST /tls/trust/clear');
  }
  const result = clearAnchors();
  if (/html/i.test(String(req.headers.accept || ''))) {
    log.debug('Leaving POST /tls/trust/clear. HTML.');
    return res.status(200).type('html').send(pageShell('Truststore',
      '<h1>The truststore is empty</h1>' +
      '<p>' + result.removed + ' anchor(s) removed. No client certificate ' +
      'verifies here now: one presented to the main port still arrives, and ' +
      'everything that reads one refuses it — which is the state this ' +
      'service starts in.</p>' +
      '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
  }
  res.status(200).json({ removed: result.removed, anchors: 0 });
  log.debug('Leaving POST /tls/trust/clear.');
});

// ---------------------------------------------------------------------------
// GET /tls/forwarded — what a reverse proxy told this service, and what was
// believed of it.
//
// RFC 9700 section 2.6 has a paragraph about reverse proxies with two halves.
// The proxy's half is that it MUST sanitize inbound security-sensitive headers
// before forwarding — a client must not be able to reach past the proxy by
// setting a header the proxy is supposed to set. The application's half, which
// is the one this service can do something about, is that it must not BELIEVE
// those headers unless it knows a proxy set them.
//
// So this page reports the request as it arrived: every forwarding header,
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
// THEM, in either mode, and the page says so with the ones it saw listed: a
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
      'address: on a mock reached over a compose bridge an address is a ' +
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

app.get('/tls/forwarded', function (req, res) {
  log.debug('Entering GET /tls/forwarded.');
  const trusted = !!config.value('global.trustProxy');
  const seen = function (rows) {
    log.debug("Entering seen().");
    log.debug("Leaving seen().");
    return rows.map(function (row) {
      const value = req.headers[row.name];
      return { header: row.name, present: value !== undefined,
               value: value === undefined ? null : String(value),
               what: row.what };
    });
  };
  const forwarding = seen(FORWARDING_HEADERS);
  const sensitive = seen(SENSITIVE_HEADERS);
  const presentSensitive = sensitive.filter(function (
      row) { return row.present; });
  const payload = {
    trustProxy: trusted,
    socket: { scheme: req.protocol, host: req.get('host') || '',
              encrypted: !!req.secure },
    effectiveBaseUrl: baseUrlOf(req),
    what_it_means: trusted
      ? 'global.trustProxy is ON, so X-Forwarded-Proto and X-Forwarded-Host ' +
        'decide what this service thinks its own URLs are. That is correct ' +
        'behind a reverse proxy and unsafe without one, because those are ' +
        'headers any client can set.'
      : 'global.trustProxy is OFF, so the forwarding headers below are ' +
        'IGNORED and this service describes the connection it can see. If a ' +
        'proxy is terminating TLS in front of it, the metadata is publishing ' +
        'the wrong URLs and every DPoP proof is being refused for naming the ' +
        'real endpoint — turn the setting on.',
    forwarding: forwarding,
    clientCertificateHeaders: {
      readByThisService: false,
      seen: presentSensitive.map(function (row) { return row.header; }),
      note: 'THIS SERVICE READS NONE OF THESE, in either mode. A certificate ' +
            'in a header is a certificate anybody can write, so believing ' +
            'one would let any client claim any identity — and RFC 8705 ' +
            'binding here reads the certificate off the TLS handshake itself ' +
            '(see /tls/sign-in and mtls.js). A proxy that terminates mTLS in ' +
            'front of this service therefore cannot pass the certificate ' +
            'through, which is a real limitation rather than an oversight: ' +
            'the alternative is trusting a header.' +
            (presentSensitive.length
              ? ' This request carried ' + presentSensitive.length + ' of ' +
                'them and they were ignored.'
              : ''),
      headers: sensitive
    },
    proxyMustSanitize: 'RFC 9700 section 2.6: a reverse proxy MUST strip ' +
      'these headers from what a CLIENT sent before setting its own, or a ' +
      'client can reach past it by setting them itself. That is the proxy\'s ' +
      'job and this service cannot do it — what it can do is not believe ' +
      'them unless told to, which is what the setting above is.'
  };
  const askedFormat = validation.check(req, 'query', TLS_QUERY);
  if (!askedFormat.ok) {
    log.debug('Leaving the TLS page. ' + askedFormat.detail);
    errorCodes.mark(res, 'STS-TLS-0023');
    return res.status(400).type('text/plain').send(askedFormat.detail + '\n');
  }
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /tls/forwarded. JSON.');
    return res.status(200).json(payload);
  }
  const rowsOf = function (rows) {
    log.debug("Entering rowsOf().");
    log.debug("Leaving rowsOf().");
    return rows.map(function (row) {
      return '<tr><td><code>' + xmlEscape(row.header) + '</code></td>' +
        '<td>' + (row.present
          ? '<code>' + xmlEscape(row.value) + '</code>'
          : '<span class="none">not sent</span>') + '</td>' +
        '<td>' + xmlEscape(row.what) + '</td></tr>';
    }).join('');
  };
  const inner = '<h1>What a proxy told this service</h1><p class="sub">The ' +
    'request as it arrived, and what was believed of it. Every issuer and ' +
    'every endpoint in both discovery documents is built from the effective ' +
    'base URL below, so if that is wrong, everything a client reads is wrong ' +
    'with it.</p><table><tr><th>Thing</th><th>Value</th></tr><tr><td>' +
    'global.trustProxy</td><td>' + (trusted
      ? '<strong>on</strong> — the forwarding headers are believed'
      : '<strong>off</strong> — the forwarding headers are ignored') +
    '</td></tr><tr><td>The ' +
    'socket saw</td><td><code>' + xmlEscape(req.protocol) + '://' +
    xmlEscape(req.get('host') || '') + '</code>' +
    (req.secure ? ' (encrypted)' : ' (not encrypted)') + '</td></tr>' +
    '<tr><td>Effective base URL</td><td><code>' + xmlEscape(baseUrlOf(req)) +
    '</code></td></tr>' +
    '</table>' +
    '<p class="' + (trusted ? 'sub' : 'verdict') + '">' +
    xmlEscape(payload.what_it_means) +
    '</p><h2>Forwarding headers</h2><table><tr><th>Header</th><th>This ' +
    'request</th><th>What it does here</th></tr>' +
    rowsOf(forwarding) + '</table>' +
    '<h2>Client certificate headers</h2>' +
    '<p class="verdict">' + xmlEscape(payload.clientCertificateHeaders.note) +
    '</p><table><tr><th>Header</th><th>This ' +
    'request</th><th>What it is</th></tr>' +
    rowsOf(sensitive) + '</table>' +
    '<h2>What the proxy has to do</h2>' +
    '<p>' + xmlEscape(payload.proxyMustSanitize) + '</p><p class="sub"><a ' +
    'href="/tls/forwarded?format=json">This page as JSON</a> &middot; <a ' +
    'href="/tls">what the TLS endpoint is</a> &middot; <a ' +
    'href="/.well-known/oauth-authorization-server">the document built from ' +
    'that base URL</a></p>';
  res.status(200).type('html').send(pageShell('Forwarded headers', inner));
  log.debug('Leaving GET /tls/forwarded. trustProxy=' + trusted);
});

// ---------------------------------------------------------------------------
// THIS MODULE BINDS NOTHING SINCE 2026-09-16.
//
// It owned two listeners and started them from here, for the reason every
// socket owner in this service does: a bind can fail, and a `require` that
// throws takes the whole process down where a route cannot. Both are gone —
// see the block above `observeConnectionsOn()` — and what is left is a
// LIBRARY: the certificate, the truststore, the sightings and six routes on
// the main app.
//
// `listen()` and `close()` are kept rather than deleted, because `server.js`
// and three tests call them, and a socket owner that stops owning a socket
// should not also change the shape of the module on the same day. `close()`
// is a no-op; `listen()` binds nothing and reports no ports, and still does
// the two truststore steps below.
// ---------------------------------------------------------------------------
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
  log.info('tls: no listener of this module\'s own to bind — the 8443 and ' +
           '9443 listeners were deleted on 2026-09-16 and the main port ' +
           'carries what they did. The client truststore holds ' +
           anchors.length + ' anchor(s).');
  log.debug('Leaving listen(). The truststore is current.');
  return { whenReady: Promise.resolve({}) };
}

function close() {
  log.debug('Entering close().');
  log.debug('Leaving close(). Nothing to close.');
}

module.exports = {
  listen: listen,
  close: close,
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
  // /tls/trust reaches it too — see the block above
  // trustClientCertificatesOn().
  trustClientCertificatesOn: trustClientCertificatesOn,
  // LDAPS 636 and the SPIRE Server API re-key themselves on this (2026-09-21).
  onServerCertificateChange: onServerCertificateChange,
  // What secureContextOptions() would give a listener created elsewhere: the
  // certificates this service presents AND the anchors it verifies clients
  // against. Exported so that server.js and the debugger build their
  // listeners from the same answer applyAnchors() re-applies to them, rather
  // than assembling a second one that can drift.
  clientTruststoreOptions: secureContextOptions,
  // `tls.minVersion` / `tls.ciphers` for a TLS listener this module does not
  // create — LDAPS, which ldapjs builds, and the main port at creation.
  protocolOptions: protocolOptions,
  trustAnchorsFileLoaded: function () {
    log.debug("Entering trustAnchorsFileLoaded().");
    log.debug("Leaving trustAnchorsFileLoaded().");
    return anchorsFileReport;
  },
  // See the note above it: the modules that describe this certificate to a
  // reader ask here rather than each asserting it is self-signed.
  certificateProvenance: certificateProvenance,
  serverCertificatePem: function () {
    log.debug("Entering serverCertificatePem().");
    log.debug("Leaving serverCertificatePem().");
    return SERVER_CERTIFICATE.certPem;
  },
  // The whole of it, private key included, because ldap_server.js serves it on
  // 636 — see the note above SERVER_CERTIFICATE. Handing a private key to
  // another module in this process is not the same act as publishing one: this
  // key is generated per start, exists only in memory and dies with the
  // process. Nothing here writes it to a response; GET
  // /tls/server-certificate publishes the CERTIFICATE alone.
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
  anchorCount: function () {
    log.debug("Entering anchorCount().");
    log.debug("Leaving anchorCount().");
    return anchors.length;
  },
  // The port a client certificate is presented to, for the pages that say so.
  // It answered `{ tls, mtls }` — 8443 and 9443 — until both were deleted on
  // 2026-09-16, and every caller wanted the same thing from it: where do I
  // send one.
  ports: function () {
    log.debug("Entering ports().");
    log.debug("Leaving ports().");
    return { main: MAIN_PORT };
  },
  // Installed by `server.js` on the main HTTPS listener: the sighting, and the
  // failed-handshake log that is otherwise invisible.
  observeConnectionsOn: observeConnectionsOn
};
