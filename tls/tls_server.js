'use strict';
//
// File: tls_server.js
//
// ---------------------------------------------------------------------------
// TWO HTTPS LISTENERS WHOSE ONLY CONTENT IS WHAT THE SERVER SAW.
//
// Everything else in this service is HTTP behind the one plain listener in
// server.js. This is not: it is TLS, so it is its own socket — a third one
// beside the KDC's port 88 and the directory's 389 — and it has the same
// consequences those two have. `GET /admin/sts-metadata` is built by walking
// the Express router, so it cannot see a socket; the two rows it carries for
// this module are the plain-HTTP views below, and the listeners themselves are
// described in their text.
//
// ---------------------------------------------------------------------------
// WHY IT EXISTS, GIVEN THAT THE DEBUGGER ALREADY REPORTS THE HANDSHAKE.
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
// certificate: which chain the server built out of what arrived, which anchor it
// verified against, what it read out of the leaf, and whether it considers the
// caller authenticated at all. A client that completed a handshake has proved
// that the bytes were acceptable to OpenSSL on this machine, and no more. Under
// TLS 1.3 it has not even proved that — the client is finished before the server
// has said anything about the certificate.
//
// So this is the other side, and the whole of its content is that answer: a
// message, and three sections saying what arrived over HTTPS, what was
// negotiated at the TLS layer, and what the client certificate is. Fetch
// `/tls/whoami` over one of these listeners and the reply describes the very
// connection it is travelling on.
//
// ---------------------------------------------------------------------------
// TWO LISTENERS, BECAUSE "DOES THIS SERVER REQUIRE A CERTIFICATE" HAS TWO
// ANSWERS AND BOTH ARE WORTH BEING ABLE TO REACH.
//
//   * STS_TLS_PORT (8443) always ASKS for a client certificate and accepts
//     whatever arrives, including nothing: `requestCert: true,
//     rejectUnauthorized: false`. Every connection is answered and the answer
//     says whether the certificate verified. This is the listener to point a
//     debugger at, because a refusal at the TLS layer tells you almost nothing —
//     node's own TLS server refuses a client certificate by closing the socket
//     with no alert at all — while this one can tell you which check failed.
//
//   * STS_MTLS_PORT (9443) REQUIRES one: `rejectUnauthorized: true`, so node
//     refuses the connection itself and no handler here ever runs. That is not
//     redundancy — it is what makes the debugger's five mutual-authentication
//     verdicts reachable against a real server rather than against a fixture.
//     With the issuing CA trusted here the verdict is `required`; before it is
//     trusted the verdict is `required-and-rejected`, which is the case an
//     operator hits most and the one a single connection cannot tell from the
//     first.
//
// Reaching the second listener at all is therefore the proof: if this page came
// back from 9443, the certificate verified.
//
// ---------------------------------------------------------------------------
// THE TRUSTSTORE IS EMPTY AT STARTUP AND IS FILLED AT RUNTIME.
//
// It has to be. The certificate authority whose clients this is meant to verify
// is generated in somebody's BROWSER, thirty seconds before the connection, and
// exists nowhere else — so there is no configuration file that could hold it and
// no image that could bake it in. `POST /tls/trust` takes the anchors and
// `tls.Server.setSecureContext()` applies them; existing connections are not
// disturbed, and the next handshake is judged against the new list.
//
// Two details about that are load-bearing and both were measured rather than
// assumed:
//
//   * `ca: []` means NO ANCHORS. It is not the same as omitting `ca`, which
//     selects node's bundled root store — the opposite of what is wanted here,
//     since a public root has no business verifying a client certificate issued
//     by a private CA. So the empty case is passed explicitly, and with it every
//     client certificate is unverified: on 8443 that is reported, and on 9443 it
//     means nothing can connect. That is the correct starting state and the
//     `/tls` page says so.
//   * the anchors go in over the MAIN port, not over 8443 or 9443. That port is
//     normally plain HTTP, which is the one reachable before anything is
//     trusted, and this is a mock: an endpoint that could only be called by
//     somebody who had already been trusted would be a chicken-and-egg with a
//     specification citation.
//
//     `global.https` — which RFC 9700 mode turns on — takes that property away,
//     and it is worth knowing rather than discovering: with it on there is no
//     plain listener in this process at all, so the FIRST fetch of
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
// somebody POSTed to this process. No revocation is checked, so a revoked
// certificate verifies here and would not verify anywhere that matters. A mock
// that quietly turned a certificate into a TRUSTWORTHY identity would teach a
// client something false about every server it will meet afterwards.
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
// So a request on a connection carrying a verified certificate starts a session
// for its common name; `startCertificateSession()` below performs it and argues
// the details, and every report this file emits says in the same breath that no
// revocation was checked.
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

// The permissive listener: always asks, never refuses, always explains.
const TLS_PORT = config.value('tls.port');
// The strict one: node refuses an unverified client certificate during the
// handshake, so nothing below ever runs for one.
const MTLS_PORT = config.value('tls.mutualPort');

// The names the server certificate is issued for. A caller reaches this stack
// as `localhost` from a host run, as `sts` from the compose network and as
// `127.0.0.1` from whatever is easiest, and a certificate that named only one of
// them would produce a hostname-verification failure that is about this file
// rather than about anything the reader is debugging.
const TLS_HOSTNAMES = config.value('tls.hostnames');
const TLS_IPS = config.value('tls.ips');

// A truststore is a list of anchors, not a certificate store dump. The cap is
// generous for any private PKI and stops a caller handing over a body that costs
// more to parse than the handshakes it will be used for.
const MAX_ANCHORS = 32;

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
// **WHAT ACTUALLY WENT WRONG WAS A TEST**, and it is recorded here because the
// symptom pointed at this file for a day: `sts_route_inputs` drives every route
// it can find, `POST /tls/trust/clear` needs no credential and succeeds, and a
// remote PEP eleven jobs later then authenticated as nobody with a perfectly
// good certificate. That job skips the route by name now, which is the second
// entry on a list `tests/CLAUDE.md` argues.
// ---------------------------------------------------------------------------

// State the two listeners share.
let anchors = [];
let boundTlsPort = null;
let boundMtlsPort = null;
let tlsListening = false;
let mtlsListening = false;
let listenError = null;

// ---------------------------------------------------------------------------
// The server certificate.
//
// Self-signed and generated per start, exactly like the signing key in
// helpers.js, and for the same reason: nothing about a mock is worth persisting,
// and a certificate committed to a repository is a private key committed to a
// repository. The consequence for a caller is that the anchor changes on every
// restart, which is why `GET /tls/server-certificate` exists — a debugger
// fetches it and puts it in its own truststore, rather than being told to
// disable verification, which is the habit this whole workflow is trying to
// break.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A CERTIFICATE HANDED IN, RATHER THAN ONE MADE HERE (2026-09-07).
//
// This certificate is self-signed and generated PER START, which is right for a
// process that owns its own listener and was silently wrong the moment a
// REQUEST WORKER existed. A worker loads this module like everything else, so
// it made a certificate of its own — and `/admin` and `/portal` are OpenID
// Connect relying parties that dial this service BACK on a loopback address and
// PIN its certificate (`common/oidc_rp.js`). So a worker pinned the one it had
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
  const certPem = process.env.STS_TLS_SERVER_CERT_PEM || '';
  const keyPem = process.env.STS_TLS_SERVER_KEY_PEM || '';
  if (!certPem || !keyPem) {
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
           subject: 'CN=' + (TLS_HOSTNAMES[0] || 'localhost') + ', O=mock-sts',
           names: TLS_HOSTNAMES.concat(TLS_IPS),
           fingerprint256: fingerprintOf(certPem),
           // The handed-in certificate's own expiry is what matters and it is
           // not parsed here: this value is reported, not enforced, and the
           // process that MADE the certificate reports the real one.
           notAfter: '' };
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
    bits: 2048,
    commonName: TLS_HOSTNAMES[0] || 'localhost',
    organizationName: 'mock-sts',
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
    years: 2,
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
    subject: 'CN=' + (TLS_HOSTNAMES[0] || 'localhost') + ', O=mock-sts',
    names: TLS_HOSTNAMES.concat(TLS_IPS),
    fingerprint256: fingerprintOf(pem),
    notAfter: keys.notAfter.toISOString()
  };
}

// SHA-256 over the DER, rendered the way every tool renders it, so that what
// this page prints can be compared with `openssl x509 -fingerprint -sha256`
// without anybody having to reformat it.
// What to CALL the port these views answer on. It is the plain HTTP port unless
// `global.https` has made it TLS as well, and seven sentences in this module
// used to say "the plain HTTP port" outright — each of them correct until the
// day somebody turned that setting on, and then quietly wrong in the one place
// a reader goes when a handshake is failing. Read per call rather than captured:
// the setting is restart-only, but a captured const here would be a second
// thing to remember if that ever changed.
function mainPortPhrase() {
  return config.value('global.https')
    ? 'the main HTTPS port' : 'the plain HTTP port';
}

// The extra sentence a bootstrap instruction needs when there is no plain port
// left to bootstrap from. Empty in the ordinary case, so it can be appended
// unconditionally.
function bootstrapNote() {
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
  log.debug('Leaving certificateProvenance(). Self-signed.');
  return 'self-signed and regenerated on every start';
}

function fingerprintOf(pem) {
  // `colon-hex` is what `openssl x509 -fingerprint -sha256` prints, which is
  // what a person is holding when they compare this by eye. It is the same
  // digest RFC 8705's `x5t#S256` uses in `oauth-oidc/mtls.js` and the same one
  // SPIRE's authority id truncates in `spiffe/spiffe_ca.js` — three spellings
  // of one computation, which is why the format is a parameter and the three
  // functions that each computed it are one.
  return stsCrypto.certificateThumbprint(pem, { format: 'colon-hex' });
}

// ---------------------------------------------------------------------------
// AN ML-DSA SERVER CERTIFICATE BESIDE THE RSA ONE, WHEN ASKED FOR.
//
// `tls.certificateAlgorithms` names what the listeners present. More than one
// is the setting worth having: OpenSSL 3.5 serves whichever certificate
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
    organizationName: 'mock-sts',
    // The leading byte of a random serial, for the reason above: '04' is this
    // one, so a capture still says which certificate it is looking at.
    serialPrefix: '04',
    years: 2,
    dnsNames: TLS_HOSTNAMES,
    ipAddresses: TLS_IPS
  });
  log.debug('Leaving makeMlDsaServerCertificate().');
  return {
    algorithm: algorithm,
    privateKeyPem: built.privateKeyPem,
    certPem: built.certPem,
    subject: 'CN=' + (TLS_HOSTNAMES[0] || 'localhost') + ', O=mock-sts',
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
    throw new Error('tls.certificateFile and tls.keyFile go together: ' +
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
    throw new Error('tls: cannot read the certificate or key named by ' +
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
    throw new Error('tls: ' + certFile + ' is not a PEM certificate: ' +
      e.message);
  }
  // A key that does not go with the certificate is the other failure that
  // surfaces as an OpenSSL message three layers down.
  let pair = false;
  try {
    pair = leaf.checkPrivateKey(crypto.createPrivateKey(keyPem));
  } catch (e) {
    throw new Error('tls: ' + keyFile + ' is not a readable private key: ' +
      e.message);
  }
  if (!pair) {
    log.debug('Leaving suppliedServerCertificate(). Key mismatch.');
    throw new Error('tls: the key in ' + keyFile + ' does not match the ' +
      'certificate in ' + certFile + '.');
  }
  const names = String(leaf.subjectAltName || '').split(',')
    .map(function (entry) {
      return entry.trim().replace(/^(DNS|IP Address):/, '');
    })
    .filter(function (entry) {
      return !!entry;
    });
  const chainLength = splitPemCertificates(certPem).length;
  log.info('tls: serving the certificate from ' + certFile + ' (' +
           chainLength + ' certificate(s) in the chain, subject ' +
           leaf.subject.replace(/\n/g, ', ') + ', names ' +
           (names.join(', ') || 'none') + '). It is NOT self-signed and is ' +
           'not regenerated on restart, so a caller that trusts its issuer ' +
           'stays trusting it.');
  log.debug('Leaving suppliedServerCertificate().');
  return {
    algorithm: 'supplied',
    privateKeyPem: keyPem,
    certPem: certPem,
    subject: leaf.subject.replace(/\n/g, ', '),
    names: names,
    fingerprint256: fingerprintOf(certPem),
    notAfter: new Date(leaf.validTo).toISOString()
  };
}

// Every certificate the listeners present, in the order the setting names
// them. The FIRST is what every existing caller means by "the server
// certificate" — GET /tls/server-certificate still returns it — and the rest
// are additional choices OpenSSL may make on a client's behalf.
const SERVER_CERTIFICATES = (function buildServerCertificates() {
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
// listener's key is a leaf of it — so **one anchor covers 8443, 9443, LDAPS
// 636, the main port AND every token this service signs**, and it survives a
// restart wherever the keystore does.
//
// **IT IS A REGISTRATION AND NOT A CALL, and the ordering is the whole of why
// it works.** This module is required at 20 and its certificate is built at
// require time; `pki.start()` runs afterwards, from
// `common/service_state.js`, and BEFORE `listen()` binds anything. So the
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
// Nothing showed until somebody rebuilt the Root. `POST /admin-api/pki/build-root`
// is dispatched like any other request, so it lands on ONE worker, which
// rebuilds every branch it holds and re-certifies its own copy of this record
// under the new Root. From that moment `trustAnchorPems()` finds that the
// handed-in anchor no longer signs the chain beside it, reports the hand-off as
// broken — which it is not — and falls back to this process's own Root. That
// Root signs nothing the front process is serving, so every OpenID Connect back
// channel this worker runs fails with `unable to get local issuer certificate`,
// and `/admin` and `/portal` answer 400 at their own callback. On 2026-09-12
// that was six jobs in the dispatch mode of the suite, none of which mentions a
// certificate.
//
// **THE RULE IS THE ONE THE LDAP CONNECTION ALREADY ESTABLISHED** (see the root
// CLAUDE.md): a store is shared by coordination, and a socket is not. The
// listener certificate belongs to the process holding the listener. A worker
// serves what it was handed and certifies nothing.
// ---------------------------------------------------------------------------
(function certifyServerCertificateUnderPki() {
  if (SERVER_CERTIFICATE && SERVER_CERTIFICATE.algorithm === 'supplied') {
    log.debug('tls: the server certificate was handed in, so it is not ' +
              'certified under this service\'s own Root.');
    return;
  }
  if (SERVER_CERTIFICATE && SERVER_CERTIFICATE.handedIn) {
    log.info('tls: this process was handed its server certificate by the ' +
             'front process and binds no TLS listener of its own, so it does ' +
             'NOT certify one under this process\'s Root. What it presents ' +
             'and what it pins are the front process\'s, which is the only ' +
             'pair that can agree with the socket a client actually reaches.');
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
    extensions: {
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
    },
    publicKeyPem: function () {
      return crypto.createPublicKey(SERVER_CERTIFICATE.privateKeyPem)
        .export({ type: 'spki', format: 'pem' });
    },
    onCertified: function (certPem, chainPem) {
      SERVER_CERTIFICATE.certPem = certPem;
      // The chain travels with it: without the Issuing CA and the
      // Intermediate a client holding only the Root cannot build a path, and
      // "trust this one anchor" would be true and unusable.
      SERVER_CERTIFICATE.chainPem = chainPem.slice();
      SERVER_CERTIFICATE.fingerprint256 = fingerprintOf(certPem);
      SERVER_CERTIFICATE.selfSigned = false;
      try {
        const read = new crypto.X509Certificate(certPem);
        SERVER_CERTIFICATE.subject = read.subject.replace(/\n/g, ', ');
        SERVER_CERTIFICATE.notAfter = new Date(read.validTo).toISOString();
      } catch (e) {
        // The certificate is in use either way; what is lost is a page's
        // subject line. Named rather than swallowed.
        log.warn('tls: the certified server certificate could not be read ' +
                 'back for its subject and expiry: ' + e.message);
      }
      // **AND THE LISTENERS HAVE TO BE TOLD, because they were built at
      // require time.** `permissiveServer` and `strictServer` are created at
      // module top level with the secure context evaluated THERE — before
      // `pki.start()` has run — so mutating the record above is invisible to
      // a socket that already has a context. `applyAnchors()` is the rebuild
      // path `POST /tls/trust` already uses, and it re-reads
      // `secureContextOptions()`, which is where the new certificate and its
      // chain are picked up. Without this line the certificate is issued,
      // recorded, reported on every page — and not served, which is the most
      // convincing way for this to look finished and be wrong.
      applyAnchors();
      log.info('tls: the listener certificate is issued by this service\'s ' +
               'own TLS Issuing CA and chains to its Root — so one anchor ' +
               'covers 8443, 9443, LDAPS 636, the main port and every token ' +
               'this service signs.');
    }
  });
})();

// ---------------------------------------------------------------------------
// ONE CERTIFICATE FOR EVERY TLS SOCKET IN THIS PROCESS.
//
// ldap_server.js's LDAPS listener on 636 serves this same certificate and key,
// read through serverCertificate() below rather than generating a second pair.
// That is a decision about what a CALLER has to do rather than a saving of one
// keypair: this certificate is self-signed and regenerated on every start, so
// anybody who wants to verify this service has to fetch it and trust it — and
// one anchor covering 8443, 9443 and 636 is one fetch. Two keypairs would mean
// an `ldapsearch` that verifies perfectly well against a truststore built for
// the HTTPS ports failing with `unable to get local issuer certificate`, which
// names nothing and reads as a broken directory.
//
// The names are the other half of why one certificate works for both: they are
// in the subjectAltName (see above — the CN is ignored by every current client)
// and they are the names this stack is reached at, not names about HTTPS.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The client truststore.
// ---------------------------------------------------------------------------

// A truststore is nearly always pasted as a bundle, and node's `ca` option takes
// an array — handing it the bundle as one string works on some node versions and
// silently uses only the first certificate on others, which reads as "the root I
// added is not trusted".
function splitPemCertificates(text) {
  const matches = String(text || '').match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
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
  log.debug('Leaving describePem(). subject=' + subject);
  return { pem: pem, subject: subject, fingerprint256: fingerprintOf(pem) };
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
  };
}

// ---------------------------------------------------------------------------
// WHAT A CALLER VERIFIES THIS LISTENER AGAINST — WHICH IS NOT THE CERTIFICATE
// IT PRESENTS ANY MORE (2026-09-11).
//
// While the certificate above was SELF-SIGNED those were one question with one
// answer, and three callers in this repository answered it by pinning the leaf:
// the back channel in `common/oidc_rp.js`, the loopback push in
// `ssf/ssf_http.js`, and the suite's anchor in `tests/tools/trust.js`.
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
// `CN=mock-sts Root CA` at the top, correct names all the way down — and whose
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
  const chain = (record && record.chainPem) || [];
  // The certificate the anchor has to have signed is the TOP of what travels
  // with the leaf — the Intermediate — or the leaf itself where nothing does.
  const topPem = chain.length ? chain[chain.length - 1]
                              : (record && record.certPem);
  if (!anchorPem || !topPem) {
    return false;
  }
  try {
    const anchor = new crypto.X509Certificate(anchorPem);
    const top = new crypto.X509Certificate(topPem);
    // `verify()` is the SIGNATURE and not the name. That is the whole point:
    // the two Roots this has to tell apart have identical subjects, so
    // comparing issuer strings — the obvious check, and the one a reader will
    // want to replace this with — passes on exactly the case that is broken.
    return top.verify(anchor.publicKey);
  } catch (e) {
    log.warn('tls: a candidate trust anchor could not be checked against the ' +
             'server certificate chain (' + e.message + '), so it is not ' +
             'published. A bundle whose anchor does not sign its own chain is ' +
             'refused by every node client and accepted by curl, which is the ' +
             'worst way for this to be wrong.');
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
      log.error('tls: the trust anchor handed in by the front process does ' +
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
        log.error('tls: this service\'s Root CA does NOT sign the certificate ' +
                  'chain this listener presents — two hierarchies with the ' +
                  'same name have got mixed, most likely because the ' +
                  'hierarchy was rebuilt without the listener being ' +
                  're-certified, or because this process is a request worker ' +
                  'holding a Root of its own while the front process owns the ' +
                  'socket. The Root is NOT being published as an anchor, ' +
                  'because a bundle whose anchor does not sign its own chain ' +
                  'is refused by every node client (`unable to get local ' +
                  'issuer certificate`) while curl accepts it. NO anchor is ' +
                  'published in its place — an Intermediate is a CA but is ' +
                  'not self-signed, and OpenSSL will not terminate a path at ' +
                  'one. Rebuild the hierarchy on /admin/pki.');
      }
    }
  } catch (e) {
    // NOT an error and named rather than swallowed: a process with no PKI is
    // the ordinary case for `npm test` and for a supplied certificate, and the
    // self-signed leaves below are the right answer there.
    log.debug('trustAnchorPems(): this service has no Root of its own (' +
              e.message + '); the listener certificates are their own anchors.');
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
// chains to the Root this service now holds, it re-certifies from the current
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
async function reconcileWithHierarchy() {
  log.debug('Entering reconcileWithHierarchy().');
  if (!SERVER_CERTIFICATE || SERVER_CERTIFICATE.algorithm === 'supplied' ||
      SERVER_CERTIFICATE.handedIn) {
    log.debug('Leaving reconcileWithHierarchy(). Not this process\'s to make.');
    return false;
  }
  let root = null;
  try {
    root = require('../common/pki').serviceRoot();
  } catch (e) {
    // A process with no PKI is the ordinary case for `npm test`; the
    // self-signed certificate is its own anchor and there is nothing to
    // reconcile with.
    log.debug('Leaving reconcileWithHierarchy(). No hierarchy: ' + e.message);
    return false;
  }
  if (!root || !root.certificatePem) {
    log.debug('Leaving reconcileWithHierarchy(). No Root.');
    return false;
  }
  if (anchorSigns(root.certificatePem, SERVER_CERTIFICATE)) {
    log.debug('Leaving reconcileWithHierarchy(). Already chains.');
    return false;
  }
  const was = SERVER_CERTIFICATE.fingerprint256;
  try {
    await require('../common/pki').certifyRegistered();
  } catch (e) {
    // Reported rather than thrown: the caller is the worker pool's message
    // handler, and a listener that could not be re-certified must not take the
    // service down. What it leaves is the state above — a bundle with no
    // anchor — which trustAnchorPems() already reports at error level.
    log.error('tls: the listener certificate could not be re-issued under ' +
              'the hierarchy this service now holds: ' + e.message + '. It ' +
              'goes on presenting the one it has, which chains to a Root ' +
              'that is gone, so GET /tls/server-certificate publishes no ' +
              'anchor until somebody rebuilds on /admin/pki.');
    log.debug('Leaving reconcileWithHierarchy(). Failed.');
    return false;
  }
  if (SERVER_CERTIFICATE.fingerprint256 === was) {
    log.warn('tls: the listener certificate does not chain to this service\'s ' +
             'Root and re-issuing it produced the same certificate. Nothing ' +
             'was changed, and GET /tls/server-certificate publishes no ' +
             'anchor while that is true.');
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
// 8443 and 9443 are created below and this module owns them. **THE MAIN HTTPS
// LISTENER IS NOT**: `server.js` creates it, because it is the one every
// protocol family answers on and this module is required at 20 of a
// twenty-four line require order. Until 2026-09-06 that meant the truststore
// stopped at this module's own two sockets, and a client certificate presented
// on the main port could be THUMBPRINTED but never VERIFIED — `socket.authorized`
// was false for every certificate ever presented there, because there was no
// `ca` to build a path to and no way to add one after the listener existed.
//
// That was exactly right while the only thing on that port which read a client
// certificate was RFC 8705 token binding, which binds to the certificate and
// explicitly does not care whether anybody vouched for it. It stopped being
// right when the remote XACML PEP arrived: that caller has to be RECOGNISED —
// its DN resolved to a directory entry, to a group, to a role, to a policy
// decision — and recognition is precisely the thing an unverified certificate
// cannot support.
//
// So a listener created elsewhere registers here and gets every anchor change
// the two below get. It is a REGISTRATION rather than a require in the other
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
    log.error('tls: trustClientCertificatesOn() was given something that is ' +
              'not a TLS server (' + label + '), so the client truststore ' +
              'does NOT cover it. Certificates presented there will be ' +
              'thumbprinted and never verified.');
    log.debug('Leaving trustClientCertificatesOn(). Refused.');
    return false;
  }
  externalServers.push({ server: server, label: String(label || 'a listener') });
  // APPLIED IMMEDIATELY, because anchors may already be loaded — this service
  // can be handed a truststore before the main port binds, and a listener that
  // only picked anchors up on the NEXT change would be one whose behaviour
  // depended on the order two unrelated things happened in.
  applyAnchors();
  log.info('tls: the client truststore now covers ' + label + ' as well as ' +
           TLS_PORT + ' and ' + MTLS_PORT + '. A client certificate presented ' +
           'there is verified against the ' + anchors.length + ' anchor(s) at ' +
           '/tls/trust; one that chains to none of them is still accepted and ' +
           'still binds a token, which is what that port has always done.');
  log.debug('Leaving trustClientCertificatesOn(). Covered.');
  return true;
}


// Apply the current anchors to every listener whose truststore this module
// owns. Existing connections keep the context they were made under — node says
// so and it is the behaviour worth having, since a connection judged under one
// truststore should not silently change its mind halfway through.
function applyAnchors() {
  log.debug('Entering applyAnchors(). anchors=' + anchors.length);
  [permissiveServer, strictServer].concat(
    externalServers.map(function (one) { return one.server; })
  ).forEach(function (server) {
    try {
      server.setSecureContext(secureContextOptions());
    } catch (e) {
      // Reported rather than thrown: the caller is a route, and a truststore
      // that could not be applied must not take the service down with it. The
      // anchors are already recorded, so the page and ?format=json will show
      // them while the listener has not got them — which is exactly the state
      // this message is here to make visible.
      log.error('tls: the truststore could not be applied to a listener: ' +
                e.message);
    }
  });
  log.debug('Leaving applyAnchors().');
}

function addAnchors(text) {
  log.debug('Entering addAnchors().');
  const found = splitPemCertificates(text);
  if (!found.length) {
    log.debug('Leaving addAnchors(). Nothing that looks like a certificate.');
    return { added: 0, total: anchors.length, error:
      'No PEM certificate was found in the body. Send one or more ' +
      '-----BEGIN CERTIFICATE----- blocks, as raw text or as the ' +
      '`certificates` field of a form or JSON body.' };
  }
  let added = 0;
  let duplicates = 0;
  for (const pem of found) {
    if (anchors.length >= MAX_ANCHORS) {
      log.debug('Leaving addAnchors(). The truststore is full.');
      return { added: added, total: anchors.length, error:
        'This truststore holds at most ' + MAX_ANCHORS + ' anchors; ' + added +
        ' were added before it filled up. POST /tls/trust/clear to empty it.' };
    }
    const described = describePem(pem);
    const already = anchors.some(function (anchor) {
      return anchor.fingerprint256 === described.fingerprint256;
    });
    if (already) {
      duplicates += 1;
      continue;
    }
    anchors.push(described);
    added += 1;
    log.info('tls: trusting client certificates issued by ' +
             described.subject + ' (' + described.fingerprint256 + ')');
  }
  if (added) applyAnchors();
  log.debug('Leaving addAnchors(). added=' + added + ' duplicates=' +
            duplicates);
  return { added: added, duplicates: duplicates, total: anchors.length };
}

function clearAnchors() {
  log.debug('Entering clearAnchors(). anchors=' + anchors.length);
  const removed = anchors.length;
  anchors = [];
  applyAnchors();
  log.info('tls: the client truststore was emptied; ' + removed +
           ' anchor(s) removed. Every client certificate is unverified again, ' +
           'and nothing can connect to the listener on ' + MTLS_PORT + '.');
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
  if (!dn || typeof dn !== 'object') return String(dn || '');
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
// first rfc822Name in the subjectAltName. Read rather than invented, because the
// directory entry this ends up on is derived from the certificate and an address
// the certificate does not carry would be this service making one up.
function emailOf(cert) {
  if (!cert) return '';
  const subject = cert.subject || {};
  const fromDn = subject.emailAddress || subject.E || '';
  if (fromDn) {
    return String(Array.isArray(fromDn) ? fromDn[0] : fromDn);
  }
  const san = String(cert.subjectaltname || '');
  const match = san.match(/email:([^,]+)/i);
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

// Walk the chain as OpenSSL assembled it, leaf first. `issuerCertificate` is a
// self-reference at the end of the walk, which is what stops it; the loop is
// additionally bounded, because the shape of that structure is decided by
// somebody else's bytes.
//
// Note precisely whose certificates these are, because the obvious reading is
// wrong in a way that matters here: this is the path that was BUILT, not the
// bytes that arrived. When verification succeeds the last entry is the anchor
// this service holds — which the client did not send and, for a root, must not
// have. So a chain of three from a client that sent two is the normal, correct
// case, and the report says so rather than letting a reader count the rows as
// "what I sent".
function chainOf(socket) {
  log.debug('Entering chainOf().');
  const out = [];
  const seen = new Set();
  let cert = socket.getPeerCertificate(true);
  let depth = 0;
  while (cert && Object.keys(cert).length && depth < 10) {
    const fingerprint = cert.fingerprint256 || String(depth);
    if (seen.has(fingerprint)) break;
    seen.add(fingerprint);
    out.push(describeCertificate(cert, depth));
    if (!cert.issuerCertificate || cert.issuerCertificate === cert) break;
    cert = cert.issuerCertificate;
    depth += 1;
  }
  log.debug('Leaving chainOf(). ' + out.length + ' certificate(s).');
  return out;
}

// The sentence that says what this connection actually proved. It is the one
// piece of prose here that draws a conclusion rather than reporting a fact, so
// it states what it is concluding from.
function verdictFor(mode, presented, authorized, authorizationError) {
  log.debug('Entering verdictFor(). mode=' + mode);
  let verdict;
  if (mode === 'required') {
    verdict = 'You are reading this from the listener that REQUIRES a client ' +
      'certificate, so the handshake could not have completed unless the ' +
      'certificate verified against an anchor this service holds. Reaching ' +
      'this page at all is the proof; the chain below is what was built. The ' +
      'subject DN was recorded as an authentication when that handshake ' +
      'completed — see below for what that does and does not mean.';
  } else if (!presented) {
    verdict = 'This listener asked for a client certificate and none was ' +
      'presented. It answered anyway — never refusing is what makes it useful ' +
      'for debugging — so this exchange proves the server certificate and the ' +
      'transport, and says nothing whatever about client authentication. ' +
      'Present one, or use port ' + MTLS_PORT + ', which will not answer ' +
      'without it.';
  } else if (authorized) {
    verdict = 'A client certificate was presented and it VERIFIED against ' +
      anchors.length + ' anchor(s) this service was given at runtime. That is ' +
      'the whole of what it PROVED: a chain was built from what you sent to ' +
      'something somebody POSTed to /tls/trust. No session was started and no ' +
      'token was issued. It was, however, written down — the subject DN is now ' +
      'an identity in the admin console and an entry in this service\'s LDAP ' +
      'directory, which is a record of what happened and not a credential.';
  } else {
    verdict = 'A client certificate was presented and it did NOT verify: ' +
      (authorizationError || 'no reason was given') + '. The connection ' +
      'completed regardless, because this listener never refuses one — which ' +
      'is exactly why it can tell you why. On port ' + MTLS_PORT + ' the same ' +
      'certificate is refused during the handshake, and node refuses it by ' +
      'closing the socket with no alert at all, so the far end learns nothing. ' +
      (anchors.length
        ? 'This truststore holds ' + anchors.length + ' anchor(s); the issuing ' +
          'CA is evidently not one of them.'
        : 'This truststore is EMPTY — nothing has been POSTed to /tls/trust — ' +
          'so no client certificate can verify here yet.');
  }
  log.debug('Leaving verdictFor().');
  return verdict;
}

// Which server certificate this socket presented, found by fingerprint.
// `getCertificate()` is node's accessor for the LOCAL certificate; with a
// single one configured this is a lookup with one possible answer, and with
// several it is the only way to know what the client was given.
function servedCertificate(socket) {
  log.debug('Entering servedCertificate().');
  let local = null;
  try {
    local = typeof socket.getCertificate === 'function'
      ? socket.getCertificate() : null;
  } catch (e) {
    log.debug('servedCertificate(): ' + e.message);
    local = null;
  }
  const wanted = local && local.fingerprint256 ? local.fingerprint256 : null;
  const found = wanted
    ? SERVER_CERTIFICATES.filter(function (one) {
        return one.fingerprint256 === wanted;
      })[0]
    : null;
  log.debug('Leaving servedCertificate(). ' +
            ((found || SERVER_CERTIFICATE).algorithm));
  return found || SERVER_CERTIFICATE;
}

// ---------------------------------------------------------------------------
// THE POST-QUANTUM READING OF ONE CONNECTION, IN TWO INDEPENDENT HALVES.
//
// They answer different questions on different timescales and a single
// boolean would be wrong for almost every connection made today:
//
//   * the KEY EXCHANGE decides whether a RECORDING of this connection can be
//     decrypted by a quantum computer years from now. OpenSSL 3.5 offers
//     X25519MLKEM768 first and both ends usually take it without anybody
//     asking, so this half is frequently post-quantum already.
//   * the CERTIFICATES decide whether either end can be IMPERSONATED by one,
//     which requires an attacker who has the machine NOW.
//
// Node cannot name a hybrid group: `getEphemeralKeyInfo()` describes ECDH and
// DH and returns an empty object for anything else, which under OpenSSL 3.5
// means an ML-KEM hybrid — or a resumed session, which has no ephemeral key at
// all. Both readings are reported rather than one being guessed.
function postQuantumOf(socket, leaf) {
  log.debug('Entering postQuantumOf().');
  let ephemeral = null;
  try {
    ephemeral = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo()
      : null;
  } catch (e) {
    log.debug('postQuantumOf(): no ephemeral key info: ' + e.message);
  }
  const named = !!(ephemeral && ephemeral.name);
  const served = servedCertificate(socket);
  const serverIsPq = served.algorithm !== 'rsa';
  let clientKeyType = null;
  if (leaf && leaf.pem) {
    try {
      clientKeyType = new crypto.X509Certificate(leaf.pem)
          .publicKey.asymmetricKeyType || null;
    } catch (e) {
      // A composite certificate, or one this OpenSSL cannot read. Reported as
      // unknown rather than as classical: those are different answers.
      log.debug('postQuantumOf(): the client key could not be read: ' +
                e.message);
      clientKeyType = null;
    }
  }
  const out = {
    keyExchange: {
      namedByNode: named,
      ephemeralKey: named ? ephemeral : null,
      note: named
        ? 'The negotiated group is ' + ephemeral.name + ', which node can ' +
          'name — so it is a classical ECDH or DH group and a recording of ' +
          'this connection is NOT safe from a future quantum computer.'
        : 'Node could not name the negotiated group. Its API knows ECDH and ' +
          'DH only, so under OpenSSL ' + process.versions.openssl + ' this ' +
          'is either an ML-KEM hybrid — the default first choice from 3.5 — ' +
          'or a resumed session with no ephemeral key of its own. This ' +
          'service will not guess between the two.'
    },
    serverCertificate: {
      algorithm: served.algorithm,
      postQuantum: serverIsPq,
      note: serverIsPq
        ? 'This connection was authenticated with an ' + served.algorithm +
          ' certificate, so the server cannot be impersonated by an ' +
          'adversary with a quantum computer.'
        : 'This connection was authenticated with an RSA certificate. Set ' +
          'tls.certificateAlgorithms to add an ML-DSA one beside it — with ' +
          'both configured, a client that offers ML-DSA signature ' +
          'algorithms gets the ML-DSA certificate and everything else keeps ' +
          'getting this one.'
    },
    clientCertificate: {
      presented: !!leaf,
      publicKeyType: clientKeyType,
      postQuantum: /^(ml-dsa|slh-dsa)/.test(String(clientKeyType || '')),
      note: leaf
        ? (clientKeyType
          ? 'The client certificate carries an ' + clientKeyType + ' key.'
          : 'The client certificate carries a key this OpenSSL cannot ' +
            'parse, which is what a COMPOSITE certificate looks like: no ' +
            'released OpenSSL implements draft-ietf-lamps-pq-composite-sigs. ' +
            'The chain was still built and reported.')
        : 'No client certificate was presented.'
    }
  };
  log.debug('Leaving postQuantumOf().');
  return out;
}

function describeConnection(req, mode) {
  log.debug('Entering describeConnection(). mode=' + mode);
  const socket = req.socket;
  const cipher = socket.getCipher ? (socket.getCipher() || {}) : {};
  const chain = chainOf(socket);
  const leaf = chain.length ? chain[0] : null;
  const presented = !!leaf;
  const authorized = socket.authorized === true;
  // The leaf's subject as a DN, computed ONCE. It is the string this service
  // filed the identity under when the handshake completed, so it appears in two
  // places below and in a link; reading the peer certificate again for each of
  // them would be three chances to disagree with the chain the report is
  // otherwise built from.
  const subjectDn = presented ? dnRfc4514(socket.getPeerCertificate().subject)
                              : null;
  const authorizationError = socket.authorizationError
    ? String(socket.authorizationError) : null;
  // WHICH of the configured certificates this connection actually got. With
  // one certificate it is that one; with several, OpenSSL chose on the
  // client's behalf from the signature algorithms it offered, and the choice
  // is the whole point of configuring several.
  const served = servedCertificate(socket);
  let ephemeral = null;
  try {
    ephemeral = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo()
      : null;
  } catch (e) {
    // Not available on every negotiation, and it is a detail rather than the
    // point of the page. Recorded so its absence is not read as an omission.
    log.debug('describeConnection(): no ephemeral key info: ' + e.message);
  }
  const report = {
    service: 'mock-sts',
    message: 'This is what the server saw. Everything below describes the ' +
      'very connection this response is travelling on — the HTTPS request as ' +
      'it arrived, what TLS negotiated underneath it, and the client ' +
      'certificate, if any, exactly as it was presented.',
    receivedAt: new Date().toISOString(),
    https: {
      method: req.method,
      url: req.url,
      httpVersion: req.httpVersion,
      host: req.headers.host || null,
      userAgent: req.headers['user-agent'] || null,
      // Every header, with nothing removed. This mock issues test credentials
      // only and the point of it is to show exactly what was exchanged.
      headers: Object.assign({}, req.headers),
      remoteAddress: socket.remoteAddress || null,
      remotePort: socket.remotePort || null,
      localPort: socket.localPort || null,
      secure: true
    },
    tls: {
      listener: mode,
      listenerPort: mode === 'required' ? boundMtlsPort : boundTlsPort,
      clientCertificatePolicy: mode === 'required'
        ? 'requestCert: true, rejectUnauthorized: true — a certificate that ' +
          'does not verify is refused during the handshake and no request is ' +
          'ever read'
        : 'requestCert: true, rejectUnauthorized: false — a certificate is ' +
          'always asked for, whatever arrives is accepted, and the verdict is ' +
          'reported rather than enforced',
      protocol: socket.getProtocol ? socket.getProtocol() : null,
      cipher: { name: cipher.name || null,
                standardName: cipher.standardName || null,
                version: cipher.version || null },
      // The name in the ClientHello, which is what a virtual host would route
      // on and what hostname verification is done against. Null means the
      // client sent none — every client dialling by IP address does.
      sniServername: socket.servername || null,
      alpnProtocol: socket.alpnProtocol || null,
      sessionReused: typeof socket.isSessionReused === 'function'
        ? socket.isSessionReused() : null,
      ephemeralKey: ephemeral || null,
      // THE POST-QUANTUM READING OF THIS CONNECTION, and its two halves are
      // deliberately separate fields — see postQuantumOf() below. A report
      // that answered "is this post-quantum" with one boolean would be wrong
      // for almost every connection made in 2026.
      postQuantum: postQuantumOf(socket, leaf),
      serverCertificate: {
        subject: served.subject,
        names: served.names,
        algorithm: served.algorithm,
        fingerprint256: served.fingerprint256,
        notAfter: served.notAfter,
        // What ELSE was on offer. With more than one certificate configured,
        // WHICH one arrived is OpenSSL's answer to the signature algorithms
        // this client offered — so naming the alternatives is the difference
        // between "this server is RSA" and "this server gave YOU RSA".
        alsoAvailable: SERVER_CERTIFICATES.filter(function (one) {
          return one.fingerprint256 !== served.fingerprint256;
        }).map(function (one) {
          return { algorithm: one.algorithm,
                  fingerprint256: one.fingerprint256 };
        }),
        selfSigned: true,
        note: 'Self-signed and regenerated on every start, so it is an anchor ' +
          'nobody can have baked in. GET /tls/server-certificate over ' +
          mainPortPhrase() + ' for the PEM, and put it in your truststore ' +
          'rather than switching verification off.' + bootstrapNote()
      }
    },
    clientCertificate: {
      presented: presented,
      authorized: authorized,
      authorizationError: authorizationError,
      // The chain OpenSSL BUILT, leaf first — not a count of what arrived. Its
      // last entry is the anchor this service holds whenever verification
      // succeeded, and that certificate came from here rather than from the
      // client. What the difference is for: a leaf presented without its
      // intermediates is the commonest mutual-TLS mistake there is and is
      // invisible from the client, and it shows here as a chain of one that
      // did not verify.
      chainLength: chain.length,
      chainNote: 'the path as it was assembled, leaf first. When verification ' +
        'succeeded the last entry is an anchor this service holds — the client ' +
        'did not send it, and for a root it must not: a server that does not ' +
        'already hold a root will not trust it because somebody offered it.',
      chain: chain,
      subject: leaf ? leaf.subject : null,
      // The same subject as a DIRECTORY writes it: leaf first, no spaces after
      // the commas, values escaped. It is here because it is the exact string
      // this service filed the identity under — /admin/users?user=<this> is the
      // page for it — and because the difference between the two forms is worth
      // seeing side by side rather than discovering. See dnRfc4514().
      subjectRfc4514: subjectDn,
      issuer: leaf ? leaf.issuer : null,
      serialNumber: leaf ? leaf.serialNumber : null,
      validFrom: leaf ? leaf.validFrom : null,
      validTo: leaf ? leaf.validTo : null,
      subjectAltName: leaf ? leaf.subjectAltName : null,
      extendedKeyUsage: leaf ? leaf.extendedKeyUsage : null,
      fingerprint256: leaf ? leaf.fingerprint256 : null
    },
    truststore: {
      anchors: anchors.length,
      subjects: anchors.map(function (anchor) { return anchor.subject; }),
      note: 'The anchors this service verifies CLIENT certificates against. ' +
        'They are POSTed to /tls/trust at runtime over ' + mainPortPhrase() +
        ', because the CA in question is usually generated in a browser ' +
        'minutes before the connection and exists nowhere else.' +
        bootstrapNote()
    },
    authentication: {
      // TRUE SINCE 2026-09-05 WHEN THE CERTIFICATE VERIFIED, and this member
      // was the most important `false` in the report until then. What it meant
      // was "no endpoint of this service will let the holder do anything an
      // anonymous caller cannot", and that stopped being true the day a
      // verified certificate started a session — so reporting `false` would
      // now be this report contradicting the Set-Cookie header on the same
      // response.
      //
      // **IT IS STILL NOT A CLAIM THAT THE CERTIFICATE IS GOOD.** No
      // revocation was checked, and `revocationChecked` below says so in the
      // same object rather than three paragraphs away.
      authenticated: presented && authorized,
      revocationChecked: false,
      sessionUrl: presented && authorized ? '/admin/sessions' : null,
      // What DID happen, when the certificate verified: the subject DN was
      // filed as an authentication. Recorded and not authenticated — the
      // distinction the rest of this page exists to keep.
      recorded: presented && authorized,
      identity: presented && authorized ? subjectDn : null,
      consoleUrl: presented && authorized
        ? '/admin/users?user=' + encodeURIComponent(subjectDn) : null,
      directoryUrl: presented && authorized ? '/admin/ldap/directory' : null,
      note: 'Nothing here is a login. A verified client certificate means a ' +
        'chain was built to an anchor somebody supplied, and no more: no ' +
        'session is started, no token is issued, no revocation is checked, and ' +
        'no endpoint of this service will let you do anything an anonymous ' +
        'caller cannot. What a verified certificate DOES do is get written ' +
        'down. The subject DN is filed as an authentication on /admin/users, ' +
        'and the embedded LDAP directory seeds an entry for it — a certificate ' +
        'subject is already a DN, so it is the one identity here that does not ' +
        'have to be turned into one. Both of those are records of what ' +
        'happened. Neither is a credential, and nothing in this service ' +
        'consults them to decide anything. The two links above are on the ' +
        'PLAIN HTTP port, not this one.'
    }
  };
  report.verdict = verdictFor(mode, presented, authorized, authorizationError);
  log.debug('Leaving describeConnection(). presented=' + presented +
            ' authorized=' + authorized);
  return report;
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

function pageShell(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
    'background:#f4f4f7;margin:0;padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
    'padding:24px 28px;max-width:60rem;margin:0 auto;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}' +
    'h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    'p.verdict{background:#f0f0f8;border-left:4px solid #12107c;' +
    'padding:.6rem .8rem;margin:.6rem 0}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;' +
    'font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;' +
    'vertical-align:top}th{background:#f0f0f5}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
    'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;' +
    'word-break:break-all}a{color:#12107c}' +
    'textarea{width:100%;font-family:ui-monospace,monospace;font-size:.8em}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

function rowsFrom(pairs) {
  return pairs.map(function (pair) {
    return '<tr><td>' + xmlEscape(pair[0]) + '</td><td><code>' +
      xmlEscape(pair[1] === null || pair[1] === undefined
        ? '(none)' : String(pair[1])) + '</code></td></tr>';
  }).join('');
}

function reportPage(report) {
  log.debug('Entering reportPage().');
  const httpsRows = rowsFrom([
    ['Request', report.https.method + ' ' + report.https.url +
      ' HTTP/' + report.https.httpVersion],
    ['Host header', report.https.host],
    ['User-Agent', report.https.userAgent],
    ['From', report.https.remoteAddress + ':' + report.https.remotePort],
    ['Arrived on', 'port ' + report.https.localPort]
  ]);
  const tlsRows = rowsFrom([
    ['Listener', report.tls.listener + ' (port ' + report.tls.listenerPort +
      ')'],
    ['Client certificate policy', report.tls.clientCertificatePolicy],
    ['Protocol', report.tls.protocol],
    ['Cipher', (report.tls.cipher.standardName || report.tls.cipher.name) +
      ' (' + report.tls.cipher.version + ')'],
    ['SNI server name', report.tls.sniServername],
    ['ALPN', report.tls.alpnProtocol],
    ['Session reused', String(report.tls.sessionReused)],
    ['Server certificate', report.tls.serverCertificate.subject],
    ['Its names', report.tls.serverCertificate.names.join(', ')],
    ['Its SHA-256', report.tls.serverCertificate.fingerprint256]
  ]);
  const certRows = report.clientCertificate.presented
    ? rowsFrom([
        ['Verified', report.clientCertificate.authorized ? 'yes' :
          'no — ' + (report.clientCertificate.authorizationError || '')],
        ['Subject', report.clientCertificate.subject],
        ['Subject as a DN (RFC 4514)',
          report.clientCertificate.subjectRfc4514],
        ['Issuer', report.clientCertificate.issuer],
        ['Serial', report.clientCertificate.serialNumber],
        ['Valid from', report.clientCertificate.validFrom],
        ['Valid to', report.clientCertificate.validTo],
        ['subjectAltName', report.clientCertificate.subjectAltName],
        ['extendedKeyUsage',
          (report.clientCertificate.extendedKeyUsage || []).join(', ')],
        ['SHA-256', report.clientCertificate.fingerprint256],
        ['Certificates in the path built',
          String(report.clientCertificate.chainLength) + ' (leaf first)']
      ])
    : '<tr><td colspan="2">Nothing was presented.</td></tr>';
  const chainRows = (report.clientCertificate.chain || []).map(function (c) {
    return '<tr><td>' + c.depth + '</td><td><code>' + xmlEscape(c.subject) +
      '</code></td><td><code>' + xmlEscape(c.issuer) + '</code></td><td>' +
      xmlEscape(c.validTo || '') + '</td></tr>';
  }).join('');
  const inner = '<h1>This is what the server saw</h1>' +
    '<p class="sub">' + xmlEscape(report.message) + '</p>' +
    '<p class="verdict">' + xmlEscape(report.verdict) + '</p>' +
    '<h2>The HTTPS request</h2><table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' + httpsRows + '</table>' +
    '<h2>The TLS connection underneath it</h2><table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' + tlsRows + '</table>' +
    '<h2>The client certificate</h2><table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' + certRows + '</table>' +
    (chainRows
      ? '<h2>The chain that was built, leaf first</h2>' +
        '<p class="sub">The path as it was assembled &mdash; not a list of ' +
        'what arrived. When verification succeeded the last entry is an ' +
        'anchor this service holds, which the client did not send. What this ' +
        'does show is the commonest mutual-TLS mistake there is and one that ' +
        'is invisible from the client: a leaf presented without its ' +
        'intermediates, which appears here as a chain of one that did not ' +
        'verify.</p>' +
        '<table><tr><th>Depth</th><th>Subject</th><th>Issuer</th>' +
        '<th>Not after</th></tr>' + chainRows + '</table>'
      : '') +
    '<h2>What this proves about who you are</h2>' +
    '<p>' + xmlEscape(report.authentication.note) + '</p>' +
    (report.authentication.recorded
      ? '<table><tr><th>Thing</th><th>Value</th></tr>' + rowsFrom([
          ['Recorded as', report.authentication.identity],
          ['In the console', report.authentication.consoleUrl +
            ' (on ' + mainPortPhrase() + ')'],
          // Not "under ou=users": a subject that already lies inside this
          // directory's own tree keeps its place there, so naming the branch
          // here would be right most of the time and wrong exactly when a
          // reader was testing that case.
          ['In the directory', 'an entry derived from this subject — ' +
            report.authentication.directoryUrl + ' lists every one, and ' +
            '/admin/ldap/service says how the DN is chosen']
        ]) + '</table>'
      : '') +
    '<p class="sub"><a href="/tls/whoami">This page as JSON</a></p>';
  log.debug('Leaving reportPage().');
  return pageShell('What the server saw', inner);
}

// One handler, given to both listeners with the mode they were created in.
// Which listener answered is part of the report, so the two cannot be confused
// by a reader looking at a saved response.
function makeHandler(mode) {
  log.debug('Entering makeHandler(). mode=' + mode);
  log.debug('Leaving makeHandler().');
  return function (req, res) {
    log.debug('Entering the TLS listener handler. mode=' + mode + ' url=' +
              req.url);
    const report = describeConnection(req, mode);
    // Logged in full, like every other exchange this service records: this is
    // the one place the server's own view of a handshake is written down, and
    // when a mutual-TLS test fails it is the first thing worth reading.
    log.debug({ tlsConnection: report },
              'TLS connection on the ' + mode + ' listener: ' +
              (report.clientCertificate.presented
                ? (report.clientCertificate.authorized
                    ? 'a verified client certificate'
                    : 'an unverified client certificate')
                : 'no client certificate'));
    const path = String(req.url || '/').split('?')[0];
    const query = String(req.url || '').split('?')[1] || '';
    const wantsJson = /(^|&)format=json(&|$)/.test(query) ||
        path === '/tls/whoami' ||
        /application\/json/i.test(String(req.headers.accept || ''));
    res.setHeader('Cache-Control', 'no-store');
    // A VERIFIED CLIENT CERTIFICATE IS A SIGN-IN SINCE 2026-09-05, and the
    // section below this function argued the opposite until that day. See it
    // for what changed and what did not.
    report.session = startCertificateSession(req, res, mode);
    if (wantsJson) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(report, null, 2));
      log.debug('Leaving the TLS listener handler. JSON.');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(reportPage(report));
    log.debug('Leaving the TLS listener handler. HTML.');
  };
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
//     which is exactly what `describeConnection()` already reported;
//   * NO REVOCATION WAS CHECKED, so a revoked certificate verifies here and
//     would not verify anywhere that matters. The report says so and still
//     does;
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
// IT IS ONE SESSION PER CONNECTION AT MOST, not one per request: the cookie
// comes back on the next request and is honoured, so six requests on one
// connection are one sign-in. That is the same property `recordClientCertificate()`
// achieves by living on `secureConnection`, arrived at differently because a
// cookie needs a response to be written on and `secureConnection` has none.
// ---------------------------------------------------------------------------
function startCertificateSession(req, res, mode) {
  log.debug('Entering startCertificateSession(). mode=' + mode);
  const socket = req.socket;
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving startCertificateSession(). Nothing verified here.');
    return { started: false,
             why: 'no verified client certificate on this connection, so there ' +
                  'is nobody to sign in' };
  }
  // ALREADY SIGNED IN ON THIS BROWSER. Read rather than replaced, so that a
  // page load on 9443 does not mint a second session for somebody who already
  // has one — which would leave a global sign-out reporting two where the
  // person experienced one.
  const existing = authn.sessionOf(req);
  if (existing) {
    log.debug('Leaving startCertificateSession(). One was already open.');
    return { started: false, id: existing.id, username: existing.user &&
             existing.user.username,
             why: 'this browser already holds a sign-on session, and presenting ' +
                  'a certificate to this listener does not start a second one' };
  }
  let cert = null;
  try {
    cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
  } catch (e) {
    // A socket that went away between the handshake and this line. Swallowed
    // for recordClientCertificate()'s reason: this runs inside a request
    // handler on a listener of its own, and a throw here answers nothing.
    log.debug('startCertificateSession(): the peer certificate could not be ' +
              'read: ' + e.message);
    return { started: false, why: 'the peer certificate could not be read' };
  }
  if (!cert || !Object.keys(cert).length) {
    // A RESUMED TLS SESSION carries no peer certificate — the client does not
    // send it again. Nothing is started, rather than a session with no identity
    // on it.
    log.debug('Leaving startCertificateSession(). No peer certificate; a resumed session.');
    return { started: false,
             why: 'the connection verified but carries no peer certificate, ' +
                  'which is what a resumed TLS session looks like' };
  }
  const subject = dnRfc4514(cert.subject);
  const common = cert.subject && cert.subject.CN
    ? String(Array.isArray(cert.subject.CN) ? cert.subject.CN[0] : cert.subject.CN)
    : '';
  const username = common || subject;
  if (!username) {
    log.debug('Leaving startCertificateSession(). The subject is empty.');
    return { started: false,
             why: 'the certificate names nobody: it has neither a common name ' +
                  'nor a subject' };
  }
  let session = null;
  try {
    session = authn.startSession(res, username, ['swk'], '1',
                                 'a client certificate on the ' + mode +
                                 '-client-certificate listener',
                                 { request: req });
  } catch (e) {
    // Bookkeeping must never break a connection that has already been
    // accepted — the same rule recordClientCertificate() states.
    log.error('tls: starting a session for the verified client certificate ' +
              'failed and was ignored; the connection is unaffected: ' + e.message);
    return { started: false, why: 'starting the session threw: ' + e.message };
  }
  // THE ISSUANCE POLICY CAN REFUSE IT (2026-09-06), and a NULL is how
  // `startSession()` says so rather than a throw — which matters here more than
  // anywhere, because the `catch` above deliberately swallows a failure and
  // carries on. A refusal reaching that branch would have been reported as
  // bookkeeping and the session started anyway.
  //
  // The connection is untouched either way: this listener's whole content is
  // what the SERVER saw of the handshake, and that is still reported. What is
  // refused is the SESSION, which is the thing the policy is about.
  if (!session) {
    log.info('tls: the issuance policy refused a session for ' + username +
             ' on a verified client certificate (' + mode + ' listener). The ' +
             'handshake and the chain are unaffected and are still reported.');
    return { started: false,
             why: 'the issuance policy refused a session for "' + username +
                  '". The certificate verified and the connection is ' +
                  'unaffected — this is a POLICY decision about the SESSION. ' +
                  'See /admin/roles and /admin/xacml.' };
  }
  log.info('tls: ' + username + ' is signed in on a verified client certificate ' +
           '(' + mode + ' listener). The chain verified and NO REVOCATION WAS ' +
           'CHECKED, which is what this listener has always said; what is new ' +
           'is that the sign-in is tracked, so a global sign-out can end it.');
  log.debug('Leaving startCertificateSession(). Started ' + session.id + '.');
  return { started: true, id: session.id, username: username,
           subject: subject,
           note: 'the chain verified against an anchor POSTed to /tls/trust and ' +
                 'NO REVOCATION WAS CHECKED. The session is this service tracking ' +
                 'that the holder got in, which is what lets a global sign-out ' +
                 'end it — it is not a claim that the certificate is currently ' +
                 'good.' };
}

// ---------------------------------------------------------------------------
// THE ARGUMENT THAT USED TO BE HERE, AND WHAT OF IT STILL HOLDS.
//
// Everything below about RECORDING is unchanged and still correct. The
// sentences saying no session starts are the ones the function above reversed;
// they are kept because they name exactly what must not be lost — that
// verification is a chain check and nothing more.
//
// The two are worth holding apart, because this listener's whole value is that
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
// Three decisions in the implementation, each of which can be got wrong quietly:
//
//   * IT HAPPENS AT THE HANDSHAKE, not in the request handler. The credential
//     was accepted when the handshake completed, which is the rule every other
//     call site in this service follows; recording in the handler would count
//     REQUESTS instead, so one connection carrying six of them would read as six
//     authentications. The consequence to expect is the other way round and is
//     honest: a client that opens six CONNECTIONS did present its certificate
//     six times, and the console says six.
//   * ONLY WHEN `authorized` IS TRUE. On the optional listener a certificate
//     that did not verify, or none at all, records nothing — the console lists
//     identities that got somewhere, not names that were tried.
//   * A RESUMED SESSION may carry no peer certificate: the client does not send
//     it again, and node hands back an empty object. Nothing is recorded then,
//     rather than an authentication with no identity on it.
// ---------------------------------------------------------------------------
function recordClientCertificate(socket, mode) {
  log.debug('Entering recordClientCertificate(). mode=' + mode);
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving recordClientCertificate(). Nothing verified here.');
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
    log.debug('Leaving recordClientCertificate(). The connection verified but ' +
              'carries no peer certificate, which is what a resumed session ' +
              'looks like.');
    return null;
  }
  const subject = dnRfc4514(cert.subject);
  if (!subject) {
    log.debug('Leaving recordClientCertificate(). The subject is empty.');
    return null;
  }
  const common = cert.subject && cert.subject.CN
    ? String(Array.isArray(cert.subject.CN) ? cert.subject.CN[0] : cert.subject.CN)
    : '';
  try {
    stats.recordAuthentication({
      presented: subject,
      protocol: 'TLS',
      method: 'client certificate on the ' + mode + '-client-certificate ' +
        'listener (port ' + (mode === 'required'
          ? (boundMtlsPort || MTLS_PORT) : (boundTlsPort || TLS_PORT)) + ')',
      note: 'the chain verified against one of the ' + anchors.length +
        ' anchor(s) POSTed to /tls/trust, and NO REVOCATION WAS CHECKED — a ' +
        'revoked certificate verifies here and would not verify anywhere that ' +
        'matters. Since 2026-09-05 a sign-on session is started for the ' +
        'holder, so a global sign-out can end it; no token is issued.',
      // Both DNs in RFC 4514 form, which is not the form the report on this
      // connection shows — see dnRfc4514(). These two go into a DIRECTORY, and
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
  } catch (e) {
    // Same reason as the read above, and one more: the console and the
    // directory are bookkeeping, and bookkeeping must never be able to break a
    // connection that has already been accepted.
    log.error('tls: recording the client certificate failed and was ignored; ' +
              'the connection is unaffected: ' + e.message);
    log.debug('Leaving recordClientCertificate(). The recording threw.');
    return null;
  }
  log.info('tls: ' + subject + ' presented a client certificate that verified ' +
           'on the ' + mode + ' listener. It is recorded in the admin console ' +
           'and the directory has an entry for it. The SIGN-IN is a separate ' +
           'act and startCertificateSession() performs it on the request, ' +
           'because a cookie needs a response to be written on.');
  log.debug('Leaving recordClientCertificate(). Recorded.');
  return subject;
}

// ---------------------------------------------------------------------------
// The two listeners.
//
// Created at require time — creating a server binds nothing — and started from
// listen() in server.js, for the same reason the KDC's and the directory's
// sockets are: a bind can fail, and a require that throws takes the whole
// service down where a route cannot.
// ---------------------------------------------------------------------------
const permissiveServer = https.createServer(
    Object.assign({ requestCert: true, rejectUnauthorized: false },
                  secureContextOptions()),
    makeHandler('optional'));

const strictServer = https.createServer(
    Object.assign({ requestCert: true, rejectUnauthorized: true },
                  secureContextOptions()),
    makeHandler('required'));

// The moment the credential is accepted, on both listeners. `secureConnection`
// fires once per completed handshake — on the strict listener it cannot fire at
// all unless the certificate verified, and on the permissive one the check
// inside decides. See recordClientCertificate() for why it is here and not in
// the request handler.
permissiveServer.on('secureConnection', function (socket) {
  recordClientCertificate(socket, 'optional');
});

strictServer.on('secureConnection', function (socket) {
  recordClientCertificate(socket, 'required');
});

// A refused client certificate reaches the STRICT listener as a socket error
// and never as a request, so without this it is invisible: the far end sees a
// closed connection with no alert and this log says nothing at all. It is the
// single most confusing failure in mutual TLS, so it is logged with the reason
// OpenSSL gave.
strictServer.on('tlsClientError', function (error, socket) {
  log.warn('tls: the listener on ' + (boundMtlsPort || MTLS_PORT) +
           ' refused a connection from ' +
           ((socket && socket.remoteAddress) || 'an unknown address') + ': ' +
           error.message + '. That listener requires a client certificate ' +
           'that verifies against one of the ' + anchors.length + ' anchor(s) ' +
           'it holds. POST the issuing CA to /tls/trust on ' +
           mainPortPhrase() + ', or use port ' + (boundTlsPort || TLS_PORT) +
           ', which answers whatever arrives and says what it made of it.');
});

permissiveServer.on('tlsClientError', function (error, socket) {
  // This listener refuses nothing about the CLIENT certificate, so an error
  // here is about the handshake itself — a version or cipher mismatch, or a
  // caller that spoke something other than TLS at it.
  log.warn('tls: a handshake failed on ' + (boundTlsPort || TLS_PORT) +
           ' from ' + ((socket && socket.remoteAddress) || 'an unknown ' +
           'address') + ': ' + error.message + '. This listener accepts any ' +
           'client certificate or none, so this is not about one.');
});

// ---------------------------------------------------------------------------
// The plain-HTTP views.
//
// These are the only surfaces of this module that /admin/sts-metadata can see,
// since that page is built by walking the Express router and the two listeners
// above are sockets. They are also the only way to configure the truststore,
// and they are on the MAIN port on purpose — see the header, including what
// global.https changes about that.
// ---------------------------------------------------------------------------

function description(req) {
  log.debug('Entering description().');
  const host = String(req.get('host') || 'localhost').split(':')[0];
  const out = {
    // What the listeners present, and — when there is more than one — the
    // fact that WHICH one arrives is decided by the client's own signature
    // algorithms rather than by this service.
    serverCertificates: SERVER_CERTIFICATES.map(function (one) {
      return { algorithm: one.algorithm, subject: one.subject,
              names: one.names, fingerprint256: one.fingerprint256,
              notAfter: one.notAfter };
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
    listeners: [
      { mode: 'optional',
        url: 'https://' + host + ':' + (boundTlsPort || TLS_PORT) + '/',
        port: boundTlsPort || TLS_PORT,
        listening: tlsListening,
        requestsClientCertificate: true,
        requiresClientCertificate: false,
        what: 'Always asks for a client certificate, accepts whatever ' +
          'arrives including nothing, and reports the verdict instead of ' +
          'enforcing it. Point a debugger here.' },
      { mode: 'required',
        url: 'https://' + host + ':' + (boundMtlsPort || MTLS_PORT) + '/',
        port: boundMtlsPort || MTLS_PORT,
        listening: mtlsListening,
        requestsClientCertificate: true,
        requiresClientCertificate: true,
        what: 'Refuses a client certificate that does not verify, during the ' +
          'handshake, the way a real server does — which is to say by closing ' +
          'the socket with no alert. Reaching it is the proof that the ' +
          'certificate verified.' }
    ],
    // Published because these pages are HTTP and the listeners are not: /tls
    // answers 200 whether or not either socket bound, so a reader has no other
    // way to tell a running listener from one whose port was already taken.
    listenError: listenError,
    paths: {
      report: '/tls/whoami',
      page: '/'
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
      clearUrl: '/tls/trust/clear'
    },
    // FALSE SINCE 2026-09-05 AND KEPT UNDER ITS OLD NAME, because a client
    // reading this document by that key is entitled to a truthful answer
    // rather than a missing one. A verified client certificate now starts a
    // sign-on session; what it still does not do is prove the certificate is
    // CURRENTLY good, because no revocation is checked here.
    authenticatesNobody: false,
    signsInVerifiedCertificates: {
      started: true,
      what: 'a request on a connection carrying a client certificate that ' +
        'VERIFIED starts a sign-on session for its common name (or its RFC ' +
        '4514 subject, where it has no common name), and the response carries ' +
        'the session cookie',
      when: 'on the first request of a connection, and not again while the ' +
        'browser sends the cookie back',
      note: 'NO REVOCATION IS CHECKED, which is what this listener has always ' +
        'said and is the part that must not be lost: a revoked certificate ' +
        'verifies here and would not verify anywhere that matters. The ' +
        'session is this service tracking that the holder got in — which is ' +
        'what lets /admin/logout end it — and not a claim that the ' +
        'certificate is currently good.',
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
        'issued; no revocation is checked, and nothing in this service ' +
        'consults the record itself.'
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
  const inner = '<h1>A TLS endpoint lives here</h1>' +
    '<p class="sub">Two HTTPS listeners whose only content is what the server ' +
    'saw: the request as it arrived, what TLS negotiated underneath it, and ' +
    'the client certificate exactly as it was presented. This page is on ' +
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
    ]) + '</table>' +
    '<h2>What client certificates are verified against</h2>' +
    '<p>Empty at startup, and it has to be: the certificate authority whose ' +
    'clients this verifies is generated in a <em>browser</em>, minutes before ' +
    'the connection, and exists nowhere else. Paste its certificate here — ' +
    'the root, or the whole chain above the leaf.</p>' +
    '<table><tr><th>Anchor</th><th>SHA-256</th></tr>' + anchorRows +
    '</table>' +
    '<form method="post" action="/tls/trust">' +
    '<textarea name="certificates" rows="6" ' +
    'placeholder="-----BEGIN CERTIFICATE-----"></textarea>' +
    '<p><button type="submit">Trust these</button></p></form>' +
    '<form method="post" action="/tls/trust/clear">' +
    '<button type="submit">Empty the truststore</button></form>' +
    '<h2>It authenticates nobody</h2>' +
    '<p>A verified client certificate here means one thing: a chain was built ' +
    'from what the client sent to an anchor somebody supplied. No session is ' +
    'started, no token is issued, no revocation is checked, and no endpoint of ' +
    'this service will let the holder do anything an anonymous caller cannot.</p>' +
    '<p>It is <em>recorded</em>, which is a different claim. When the ' +
    'handshake completes with a certificate that verified, the subject DN is ' +
    'filed as an authentication on <a href="/admin/users">/admin/users</a> and ' +
    'the embedded LDAP directory seeds an entry for it — a certificate subject ' +
    'is already a DN, so it is the one identity here that does not have to be ' +
    'turned into one, and the subject, issuer, serial and validity go on the ' +
    'entry beside it. <a href="/admin/ldap/service">The directory ' +
    'service</a> says where. Both are a ' +
    'record of what happened; neither is a credential.</p>' +
    '<p class="sub"><a href="/tls?format=json">This page as JSON</a> ' +
    '&middot; <a href="/admin/sts-metadata">everything this service ' +
    'speaks</a></p>';
  res.status(200).type('html').set('Cache-Control', 'no-store')
     .send(pageShell('TLS endpoint', inner));
  log.debug('Leaving GET /tls.');
});

app.get('/tls/server-certificate', function (req, res) {
  log.debug('Entering GET /tls/server-certificate.');
  // no-store for the same reason every document describing the signing key
  // carries it: this certificate is regenerated on every start, so a cached
  // copy outlives the key it describes and the failure it produces is a
  // handshake that does not verify — which reads as a broken server rather
  // than a stale anchor.
  // EVERY certificate the listeners may present, concatenated. With the
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

// The body may be raw PEM (what a script sends), or the `certificates` member
// of a form or JSON body (what the page above sends). They are told apart by
// looking for the PEM header rather than by the content type, because a raw PEM
// posted as text/plain would otherwise be run through URLSearchParams and come
// out as a set of nonsense keys — a silent mangling rather than a refusal.
app.post('/tls/trust', function (req, res) {
  log.debug('Entering POST /tls/trust.');
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
    if (wantsHtml) {
      return res.status(400).type('html').send(pageShell('Truststore',
        '<h1>Nothing was added</h1><p>' + xmlEscape(result.error) + '</p>' +
        '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
    }
    return res.status(400).json({ error: result.error, anchors: anchors.length });
  }
  if (wantsHtml) {
    log.debug('Leaving POST /tls/trust. HTML, added=' + result.added);
    return res.status(200).type('html').send(pageShell('Truststore',
      '<h1>' + result.added + ' anchor(s) added</h1>' +
      '<p>This service now verifies client certificates against ' +
      anchors.length + ' anchor(s). Existing connections keep the truststore ' +
      'they were made under; the next handshake is judged against this one.</p>' +
      '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
  }
  res.status(200).json({
    added: result.added,
    duplicates: result.duplicates || 0,
    anchors: anchors.length,
    subjects: anchors.map(function (anchor) { return anchor.subject; }),
    note: 'Applied with tls.Server.setSecureContext(). Existing connections ' +
      'keep the truststore they were made under; the next handshake is judged ' +
      'against this one.'
  });
  log.debug('Leaving POST /tls/trust. added=' + result.added);
});

app.post('/tls/trust/clear', function (req, res) {
  log.debug('Entering POST /tls/trust/clear.');
  const result = clearAnchors();
  if (/html/i.test(String(req.headers.accept || ''))) {
    log.debug('Leaving POST /tls/trust/clear. HTML.');
    return res.status(200).type('html').send(pageShell('Truststore',
      '<h1>The truststore is empty</h1>' +
      '<p>' + result.removed + ' anchor(s) removed. No client certificate ' +
      'verifies here now, and nothing can connect to the listener that ' +
      'requires one — which is the state this service starts in.</p>' +
      '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
  }
  res.status(200).json({ removed: result.removed, anchors: 0 });
  log.debug('Leaving POST /tls/trust/clear.');
});

// ---------------------------------------------------------------------------
// Starting the listeners.
//
// Called from server.js rather than at require time, for the reason the KDC and
// the directory record: a bind can fail — 8443 and 9443 are ordinary ports, but
// a second instance of this service is not an unusual thing to have running —
// and a require that throws takes the whole service down where a route cannot.
// Callers await `whenReady` rather than reading a port that is not bound yet.
// ---------------------------------------------------------------------------
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
// So this page reports the request as it arrived: every forwarding header, every
// security-sensitive header a proxy might inject, whether this service believed
// any of it, and what the effective base URL — the thing every issuer and every
// endpoint in both discovery documents is built from — came out as.
//
// It lives in this module for the same reason /tls/whoami does: this file's
// whole content is what the SERVER saw of a connection, and a forwarding header
// is what the server was TOLD about a connection it did not see. The difference
// between those two sentences is the page.
//
// **The client certificate headers are the important row.** A proxy that
// terminates mTLS forwards the certificate in a header — X-Client-Cert,
// X-Forwarded-Client-Cert, X-SSL-Client-Cert, and a dozen vendor spellings — and
// an application that believed one would be accepting a certificate anybody can
// forge, since a header costs nothing to write. THIS SERVICE READS NONE OF THEM,
// in either mode, and the page says so with the ones it saw listed: a mock that
// silently ignored a header somebody was relying on would be as bad as one that
// silently trusted it.
// ---------------------------------------------------------------------------
const FORWARDING_HEADERS = [
  { name: 'x-forwarded-proto', what: 'The scheme the CLIENT used. Believed when ' +
      'global.trustProxy is on, and then it decides whether every URL this service ' +
      'publishes says http or https.' },
  { name: 'x-forwarded-host', what: 'The host the CLIENT used. Believed when ' +
      'global.trustProxy is on, and then it is the authority in every published URL and in ' +
      'the issuer of every token.' },
  { name: 'x-forwarded-port', what: 'READ BY NOTHING HERE. The port is taken from ' +
      'x-forwarded-host, which carries one where it matters — two sources for one value is ' +
      'two values that will eventually disagree.' },
  { name: 'x-forwarded-for', what: 'The client\'s address. READ BY NOTHING HERE, and the ' +
      'audit log deliberately records the CHANNEL rather than an address: on a mock reached ' +
      'over a compose bridge an address is a fact about docker, and a column right on a laptop ' +
      'and quietly wrong everywhere else is worse than none.' },
  { name: 'forwarded', what: 'RFC 7239\'s single-header form. NOT PARSED — this service ' +
      'reads the X- forms only, which is what every proxy in front of it emits as well.' }
];

const SENSITIVE_HEADERS = [
  { name: 'x-client-cert', what: 'A client certificate forwarded by a proxy that terminated ' +
      'mTLS.' },
  { name: 'x-forwarded-client-cert', what: 'The same thing, as Envoy and Istio spell it.' },
  { name: 'x-ssl-client-cert', what: 'The same thing, as nginx spells it.' },
  { name: 'x-ssl-client-verify', what: 'A proxy\'s verdict on the certificate it verified.' },
  { name: 'x-ssl-client-s-dn', what: 'The subject DN of a certificate a proxy verified.' },
  { name: 'x-amzn-mtls-clientcert', what: 'The same thing, as an AWS load balancer spells it.' }
];

app.get('/tls/forwarded', function (req, res) {
  log.debug('Entering GET /tls/forwarded.');
  const trusted = !!config.value('global.trustProxy');
  const seen = function (rows) {
    return rows.map(function (row) {
      const value = req.headers[row.name];
      return { header: row.name, present: value !== undefined,
               value: value === undefined ? null : String(value), what: row.what };
    });
  };
  const forwarding = seen(FORWARDING_HEADERS);
  const sensitive = seen(SENSITIVE_HEADERS);
  const presentSensitive = sensitive.filter(function (row) { return row.present; });
  const payload = {
    trustProxy: trusted,
    socket: { scheme: req.protocol, host: req.get('host') || '', encrypted: !!req.secure },
    effectiveBaseUrl: baseUrlOf(req),
    what_it_means: trusted
      ? 'global.trustProxy is ON, so X-Forwarded-Proto and X-Forwarded-Host decide what this ' +
        'service thinks its own URLs are. That is correct behind a reverse proxy and unsafe ' +
        'without one, because those are headers any client can set.'
      : 'global.trustProxy is OFF, so the forwarding headers below are IGNORED and this ' +
        'service describes the connection it can see. If a proxy is terminating TLS in front ' +
        'of it, the metadata is publishing the wrong URLs and every DPoP proof is being ' +
        'refused for naming the real endpoint — turn the setting on.',
    forwarding: forwarding,
    clientCertificateHeaders: {
      readByThisService: false,
      seen: presentSensitive.map(function (row) { return row.header; }),
      note: 'THIS SERVICE READS NONE OF THESE, in either mode. A certificate in a header is a ' +
            'certificate anybody can write, so believing one would let any client claim any ' +
            'identity — and RFC 8705 binding here reads the certificate off the TLS handshake ' +
            'itself (see /tls/whoami and mtls.js). A proxy that terminates mTLS in front of ' +
            'this service therefore cannot pass the certificate through, which is a real ' +
            'limitation rather than an oversight: the alternative is trusting a header.' +
            (presentSensitive.length
              ? ' This request carried ' + presentSensitive.length + ' of them and they were ' +
                'ignored.'
              : ''),
      headers: sensitive
    },
    proxyMustSanitize: 'RFC 9700 section 2.6: a reverse proxy MUST strip these headers from ' +
      'what a CLIENT sent before setting its own, or a client can reach past it by setting ' +
      'them itself. That is the proxy\'s job and this service cannot do it — what it can do ' +
      'is not believe them unless told to, which is what the setting above is.'
  };
  const askedFormat = validation.check(req, 'query', TLS_QUERY);
  if (!askedFormat.ok) {
    log.debug('Leaving the TLS page. ' + askedFormat.detail);
    return res.status(400).type('text/plain').send(askedFormat.detail + '\n');
  }
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /tls/forwarded. JSON.');
    return res.status(200).json(payload);
  }
  const rowsOf = function (rows) {
    return rows.map(function (row) {
      return '<tr><td><code>' + xmlEscape(row.header) + '</code></td>' +
        '<td>' + (row.present
          ? '<code>' + xmlEscape(row.value) + '</code>'
          : '<span class="none">not sent</span>') + '</td>' +
        '<td>' + xmlEscape(row.what) + '</td></tr>';
    }).join('');
  };
  const inner = '<h1>What a proxy told this service</h1>' +
    '<p class="sub">The request as it arrived, and what was believed of it. Every issuer and ' +
    'every endpoint in both discovery documents is built from the effective base URL below, ' +
    'so if that is wrong, everything a client reads is wrong with it.</p>' +
    '<table><tr><th>Thing</th><th>Value</th></tr>' +
    '<tr><td>global.trustProxy</td><td>' + (trusted
      ? '<strong>on</strong> — the forwarding headers are believed'
      : '<strong>off</strong> — the forwarding headers are ignored') + '</td></tr>' +
    '<tr><td>The socket saw</td><td><code>' + xmlEscape(req.protocol) + '://' +
    xmlEscape(req.get('host') || '') + '</code>' +
    (req.secure ? ' (encrypted)' : ' (not encrypted)') + '</td></tr>' +
    '<tr><td>Effective base URL</td><td><code>' + xmlEscape(baseUrlOf(req)) +
    '</code></td></tr>' +
    '</table>' +
    '<p class="' + (trusted ? 'sub' : 'verdict') + '">' + xmlEscape(payload.what_it_means) +
    '</p>' +
    '<h2>Forwarding headers</h2>' +
    '<table><tr><th>Header</th><th>This request</th><th>What it does here</th></tr>' +
    rowsOf(forwarding) + '</table>' +
    '<h2>Client certificate headers</h2>' +
    '<p class="verdict">' + xmlEscape(payload.clientCertificateHeaders.note) + '</p>' +
    '<table><tr><th>Header</th><th>This request</th><th>What it is</th></tr>' +
    rowsOf(sensitive) + '</table>' +
    '<h2>What the proxy has to do</h2>' +
    '<p>' + xmlEscape(payload.proxyMustSanitize) + '</p>' +
    '<p class="sub"><a href="/tls/forwarded?format=json">This page as JSON</a> &middot; ' +
    '<a href="/tls">what the TLS endpoint is</a> &middot; ' +
    '<a href="/.well-known/oauth-authorization-server">the document built from that base ' +
    'URL</a></p>';
  res.status(200).type('html').send(pageShell('Forwarded headers', inner));
  log.debug('Leaving GET /tls/forwarded. trustProxy=' + trusted);
});

function listen() {
  log.debug('Entering listen().');
  function start(server, port, label) {
    return new Promise(function (resolve, reject) {
      function onError(error) {
        server.removeListener('error', onError);
        listenError = label + ' on ' + port + ': ' + error.message;
        log.error('tls: the ' + label + ' listener could not bind ' + port +
                  ': ' + error.message);
        reject(error);
      }
      server.once('error', onError);
      server.listen(port, '0.0.0.0', function () {
        server.removeListener('error', onError);
        const address = server.address();
        resolve(address ? address.port : port);
      });
    });
  }
  const whenReady = Promise.all([
    start(permissiveServer, TLS_PORT, 'optional-client-certificate'),
    start(strictServer, MTLS_PORT, 'required-client-certificate')
  ]).then(function (ports) {
    boundTlsPort = ports[0];
    boundMtlsPort = ports[1];
    tlsListening = true;
    mtlsListening = true;
    log.debug('Leaving listen(). Both listeners are up.');
    return { tlsPort: boundTlsPort, mtlsPort: boundMtlsPort };
  });
  log.debug('Leaving listen(). Binding.');
  return { whenReady: whenReady };
}

function close() {
  log.debug('Entering close().');
  try {
    permissiveServer.close();
    strictServer.close();
  } catch (e) {
    // Closing a listener that never bound throws, and there is nothing useful
    // to do about it: this exists for tests and for an orderly shutdown.
    log.debug('close(): ' + e.message);
  }
  tlsListening = false;
  mtlsListening = false;
  log.debug('Leaving close().');
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
  // The main HTTPS listener is created in server.js and registers here so that
  // /tls/trust reaches it too — see the block above trustClientCertificatesOn().
  trustClientCertificatesOn: trustClientCertificatesOn,
  // What secureContextOptions() would give a listener created elsewhere: the
  // certificates this service presents AND the anchors it verifies clients
  // against. Exported so that server.js builds its listener from the same
  // answer this module applies to its own two, rather than assembling a second
  // one that can drift.
  clientTruststoreOptions: secureContextOptions,
  // See the note above it: the six modules that describe this certificate to
  // a reader ask here rather than each asserting it is self-signed.
  certificateProvenance: certificateProvenance,
  serverCertificatePem: function () { return SERVER_CERTIFICATE.certPem; },
  // The whole of it, private key included, because ldap_server.js serves it on
  // 636 — see the note above SERVER_CERTIFICATE. Handing a private key to
  // another module in this process is not the same act as publishing one: this
  // key is generated per start, exists only in memory and dies with the
  // process, exactly like the signing key in helpers.js. Nothing here writes it
  // to a response; GET /tls/server-certificate publishes the CERTIFICATE alone.
  serverCertificate: function () {
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
      trustAnchorPem: trustAnchorPems()[0] ||
        ((SERVER_CERTIFICATE.chainPem || []).length
          ? '' : SERVER_CERTIFICATE.certPem),
      subject: SERVER_CERTIFICATE.subject,
      names: SERVER_CERTIFICATE.names.slice(0),
      fingerprint256: SERVER_CERTIFICATE.fingerprint256,
      notAfter: SERVER_CERTIFICATE.notAfter
    };
  },
  // Every anchor, for a caller building a truststore rather than one
  // connection: with two listener certificates configured there are two, and
  // which one a connection gets is OpenSSL's choice from the signature
  // algorithms the caller itself offered.
  trustAnchorPems: trustAnchorPems,
  // The three the request-worker pool uses. See their headers: the hierarchy
  // can be rebuilt in a process that does not own this socket.
  reconcileWithHierarchy: reconcileWithHierarchy,
  serverCertificateBundle: serverCertificateBundle,
  adoptServerCertificate: adoptServerCertificate,
  anchorCount: function () { return anchors.length; },
  ports: function () {
    return { tls: boundTlsPort || TLS_PORT,
             mtls: boundMtlsPort || MTLS_PORT };
  }
};
