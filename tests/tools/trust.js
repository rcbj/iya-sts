// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// tests/tools/trust.js — how a test run comes to trust the mock's certificate.
//
// ---------------------------------------------------------------------------
// SINCE 2026-08-30 THE MOCK'S MAIN PORT IS TLS IN EVERY STACK IN THIS
// REPOSITORY (env/*.js carry `global.https: true`, and STS_HTTPS is set on the
// service in both compose files), which leaves the suite one problem it did not
// have before: the certificate — self-signed until 2026-09-11, a leaf of the
// service's own Root since (below) — is REGENERATED ON EVERY START of the
// service in development mode, Root and all, so nothing that exists before the
// service does can hold an anchor for it. Not an image, not a CA bundle, not a
// browser profile, not a checked-in PEM.
//
// The only moment at which that key can be learned is AFTER the service is
// answering and BEFORE the first job runs, and that is exactly where
// run-report.js calls this module.
//
// TWO CONSUMERS, WHICH IS WHY THERE ARE TWO OUTPUTS AND NOT ONE:
//
//   NODE_EXTRA_CA_CERTS   the node-driven jobs. node reads it ONCE, at
//                         process start, so it can only be handed to a CHILD —
//                         which is what these jobs are. It cannot be set for
//                         the runner's own process from inside it, which is why
//                         the runner names the file to tools/service_trust.js
//                         (`useBundle()`) for its own calls instead.
//   STS_SPKI_PIN          the browser jobs. tests/protocol/browser_flags.js
//                         already reads exactly this variable and turns it into
//                         Chrome's --ignore-certificate-errors-spki-list. That
//                         file is VENDORED from the parent project, whose
//                         stacks have been https for months, so the browser
//                         half of this needed no new code at all — only
//                         somebody to export the variable here.
//
// WHY A PIN AND NOT --ignore-certificate-errors: the blunt flag accepts every
// certificate, and this suite contains assertions about certificates being
// REFUSED. A pin is a truststore of one key — a different certificate,
// including the one this same service will generate on its next start, still
// meets an interstitial.
//
// NODE_EXTRA_CA_CERTS ACCEPTS A SELF-SIGNED CERTIFICATE DESPITE
// `basicConstraints CA:FALSE`, which surprises people: OpenSSL takes a
// self-signed leaf found in the trust store as an anchor. Without it the jobs
// fail with DEPTH_ZERO_SELF_SIGNED_CERT — a message that names TLS and nothing
// about which service or why.
//
// **AND IT WILL NOT DO THE SAME FOR A CERTIFIED ONE, WHICH IS WHY THAT
// DOCUMENT CARRIES THE CHAIN AND THE ROOT SINCE 2026-09-11.** That is the day
// this service's listener certificate became a LEAF of its own Root, and the
// leaf this file used to write out stopped being an anchor at all: the path
// walks up to the Intermediate, finds no Root, and every node-driven job fails
// with UNABLE_TO_GET_ISSUER_CERT_LOCALLY before it makes a single assertion.
// Nothing here had to change — `/tls/server-certificate` publishes a truststore
// that terminates now — but what this file writes is a BUNDLE rather than one
// certificate, and the leaf being FIRST is load-bearing: `spkiPin()` below
// reads the first certificate in it, and a pin computed over the Root would
// match nothing while looking exactly like a pin.
// `tests/tls_trust_anchor.js` is the in-process half of this.
//
// A NO-OP ON A PLAIN-HTTP SERVICE, and that matters: `STS_HTTPS=false` is the
// documented way back to an unencrypted port, and a run against one must add
// nothing at all to a job's environment rather than adding an empty variable
// (an empty NODE_EXTRA_CA_CERTS makes node warn on every child).
// ---------------------------------------------------------------------------
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const tls = require('tls');
const serviceTrust = require('./service_trust.js');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'trust',
  level: process.env.LOG_LEVEL || 'info' });

// The document is served as `text/plain` and is the PEM itself — see
// tls/tls_server.js. It is on the MAIN port deliberately: it and POST
// /tls/trust are what a caller reaches before it trusts anything.
const CERTIFICATE_PATH = '/tls/server-certificate';

// Whether this URL needs any of the below at all.
function isTls(url) {
  log.debug("Entering isTls().");
  log.debug("Leaving isTls().");
  return /^https:/i.test(String(url || ''));
}

// ---------------------------------------------------------------------------
// FETCH IT, VERIFIED, AGAINST THE ROOT THE SERVICE PUBLISHES (2026-11-20).
//
// This is the bootstrap fetch: the question being asked is "what chain is
// this service using", and in development mode nothing that existed before
// the service holds an anchor for it. Until today it was answered with
// verification OFF — the `curl -k` the /tls page tells a person to make.
// It is answered with verification ON now, in two steps:
//
//   1. against the system's roots and the bundle this process already holds
//      (tools/service_trust.js, when there is one): an AWS target's
//      publicly-trusted certificate, and a refresh after nothing rotated,
//      verify here and nothing else is asked;
//   2. when THIS client refused that chain, against the service Root from
//      the plain-HTTP revocation listener's `/pki/ca/service/root.cer` —
//      the `caIssuers` address every certificate the service issues names
//      (pki/pki_service.ts), on `PKI_HTTP_PORT` (8082 by default; the
//      cluster mode's balancer forwards it; a runner-started service hands
//      its own port in `options.pkiPort`). The listener binds before the
//      main port (server.js), so it is answering whenever this is asked.
//
// WHAT THAT CHANGES, SAID PLAINLY. The Root over plain HTTP is no better
// authenticated than an unverified handshake was: in development mode it is
// made at start, and learning it is trust on first use either way. What is
// new is that the chain the runner writes for every job is CHECKED — it must
// lead to the Root the service publishes and name the host the jobs dial —
// so a listener presenting the wrong chain, or a chain for another name,
// fails here, naming this file, instead of failing every job one at a time.
// And no connection in this suite dials the service unverified any more.
//
// `https.get` rather than the global fetch(): fetch's dispatcher takes no
// per-request `ca`, and this module must load in the container image too,
// where the runner has no dependency on undici's public API.
// ---------------------------------------------------------------------------

// The service Root, as PEM, from the plain-HTTP revocation listener on the
// host `url` names.
function rootOverHttp(url, timeoutMs, options) {
  log.debug("Entering rootOverHttp().");
  const target = new URL(url);
  const port = Number((options && options.pkiPort) ||
                      process.env.PKI_HTTP_PORT || 8082);
  const where = 'http://' + target.hostname + ':' + port +
                '/pki/ca/service/root.cer';
  log.debug("Leaving rootOverHttp(). " + where);
  return new Promise(function (resolve, reject) {
    const req = http.get(where, { timeout: timeoutMs || 10000 },
      function (res) {
        const chunks = [];
        res.on('data', function (chunk) {
          chunks.push(chunk);
        });
        res.on('end', function () {
          if (res.statusCode !== 200) {
            reject(new Error(where + ' answered ' + res.statusCode));
            return;
          }
          try {
            resolve(new crypto.X509Certificate(Buffer.concat(chunks))
              .toString());
          } catch (e) {
            log.debug("Caught in a callback in rootOverHttp(): " +
                      ((e && e.message) || e));
            reject(new Error(where + ' answered 200 with something that ' +
                             'is not a certificate (' + e.message + ')'));
          }
        });
      });
    req.on('error', function (e) {
      log.debug("Caught in a callback in rootOverHttp(): " +
                ((e && e.message) || e));
      reject(new Error(where + ': ' + ((e && e.message) || e)));
    });
    req.on('timeout', function () {
      req.destroy(new Error('timed out'));
    });
  });
}

// The anchors step 1 verifies against: the system's roots, `options.ca`
// and the bundle this process holds, when it holds one.
function knownAnchors(options) {
  log.debug("Entering knownAnchors().");
  let held = [];
  if (serviceTrust.bundlePath()) {
    try {
      held = serviceTrust.ca();
    } catch (e) {
      // A bundle named and unreadable (a run's first fetch, before the file
      // exists) is no anchor; step 2 is what this fetch then rests on.
      log.debug("Caught in knownAnchors(): " + ((e && e.message) || e));
      held = [];
    }
  }
  const extra = options && options.ca ? [].concat(options.ca) : [];
  log.debug("Leaving knownAnchors(). " + held.length + " held.");
  return tls.rootCertificates.concat(held, extra);
}

// One verified GET of the certificate document against `ca`.
function getCertificateDocument(target, timeoutMs, options, ca) {
  log.debug("Entering getCertificateDocument().");
  log.debug("Leaving getCertificateDocument().");
  return new Promise(function (resolve, reject) {
    const req = https.get({
      host: target.hostname,
      port: target.port || 443,
      path: target.pathname,
      ca: ca,
      timeout: timeoutMs || 10000,
      // A NEW CONNECTION when asked (the `cluster` mode, below); otherwise the
      // default agent, exactly as before.
      agent: options && options.fresh ? false : undefined
    }, function (res) {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', function (chunk) {
        body += chunk;
      });
      res.on('end', function () {
        if (res.statusCode !== 200) {
          reject(new Error(CERTIFICATE_PATH + ' answered ' + res.statusCode));
          return;
        }
        if (body.indexOf('-----BEGIN CERTIFICATE-----') < 0) {
          // Worth its own message: a reverse proxy or a wrong port answers 200
          // with something that is not a certificate, and "no anchor" would be
          // the wrong diagnosis for it.
          reject(new Error(CERTIFICATE_PATH + ' answered 200 with something ' +
                           'that is not a PEM certificate (' +
                           body.slice(0, 60).replace(/\s+/g, ' ') + ')'));
          return;
        }
        resolve(body);
      });
    });
    req.on('error', function (e) {
      reject(e);
    });
    req.on('timeout', function () {
      req.destroy();
      reject(new Error('timed out fetching ' + CERTIFICATE_PATH));
    });
  });
}

// Whether a handshake with `url` verifies against `ca`: true, false when
// THIS client refused the chain, and true for any other failure, which the
// caller's own request will meet and report in its own words.
function handshakeVerifies(url, ca, timeoutMs) {
  log.debug("Entering handshakeVerifies().");
  const target = new URL(url);
  const options = { host: target.hostname,
                    port: Number(target.port || 443), ca: ca,
                    timeout: timeoutMs || 10000 };
  if (!/^[0-9.]+$/.test(target.hostname) &&
      target.hostname.indexOf(':') < 0) {
    options.servername = target.hostname;
  }
  log.debug("Leaving handshakeVerifies().");
  return new Promise(function (resolve) {
    const socket = tls.connect(options, function () {
      socket.end();
      resolve(true);
    });
    socket.on('error', function (e) {
      log.debug("Caught in a callback in handshakeVerifies(): " +
                ((e && e.message) || e));
      resolve(!serviceTrust.isUntrusted(e));
    });
    socket.on('timeout', function () {
      socket.destroy();
      resolve(true);
    });
  });
}

// THE TRUSTSTORE FOR A TOOL THAT DIALS THE SERVICE BEFORE, OR WITHOUT, THE
// RUN'S BUNDLE — tools/admin-api-token.js and tools/scheduler-takeover.js,
// which the launchers run in the service image with nothing to trust yet:
// the known anchors, and the service Root from the revocation listener
// (above) when those do not verify the listener. Never an empty answer that
// would read as "do not verify": a Root that cannot be read leaves the
// known anchors, and the caller's request then fails verification saying
// so. A plain-http URL gets the known anchors, which it ignores.
async function anchorsFor(url, options) {
  log.debug("Entering anchorsFor().");
  const known = knownAnchors(options);
  if (!isTls(url) || await handshakeVerifies(url, known)) {
    log.debug("Leaving anchorsFor(). Known anchors.");
    return known;
  }
  try {
    const root = await rootOverHttp(url, 10000, options);
    log.debug("Leaving anchorsFor(). With the service Root.");
    return known.concat([root]);
  } catch (e) {
    log.debug("Caught in anchorsFor(): " + ((e && e.message) || e));
    log.warn('trust: ' + url + ' presents a chain no known root verifies, ' +
             'and the service Root could not be read (' + e.message + ').');
    log.debug("Leaving anchorsFor(). Known anchors only.");
    return known;
  }
}

async function fetchCertificate(url, timeoutMs, options) {
  log.debug("Entering fetchCertificate().");
  let target;
  try {
    target = new URL(CERTIFICATE_PATH, url);
  } catch (e) {
    log.debug("Caught in fetchCertificate(): " + ((e && e.message) || e));
    log.debug("Leaving fetchCertificate(). Not a URL.");
    throw new Error('not a URL: ' + url);
  }
  const known = knownAnchors(options);
  try {
    const body = await getCertificateDocument(target, timeoutMs, options,
                                              known);
    log.debug("Leaving fetchCertificate(). Verified against known roots.");
    return body;
  } catch (e) {
    log.debug("Caught in fetchCertificate(): " + ((e && e.message) || e));
    if (!serviceTrust.isUntrusted(e)) {
      log.debug("Leaving fetchCertificate(). " + e.message);
      throw e;
    }
  }
  let root;
  try {
    root = await rootOverHttp(url, timeoutMs, options);
  } catch (e) {
    log.debug("Caught in fetchCertificate(): " + ((e && e.message) || e));
    log.debug("Leaving fetchCertificate(). No Root.");
    throw new Error(url + ' presents a chain no known root verifies, and ' +
                    'the service Root could not be read from its ' +
                    'revocation listener (' + e.message + '). Set ' +
                    'PKI_HTTP_PORT to that listener\'s port, or ' +
                    'STS_TRUST_BUNDLE to the PEM ' + CERTIFICATE_PATH +
                    ' serves.');
  }
  try {
    const body = await getCertificateDocument(target, timeoutMs, options,
                                              known.concat([root]));
    log.debug("Leaving fetchCertificate(). Verified against the Root.");
    return body;
  } catch (e) {
    log.debug("Caught in fetchCertificate(): " + ((e && e.message) || e));
    log.debug("Leaving fetchCertificate(). " + e.message);
    if (serviceTrust.isUntrusted(e)) {
      throw new Error(url + ' presents a chain that does not verify ' +
                      'against the service Root its revocation listener ' +
                      'publishes (' + e.code + ': ' + e.message + ')');
    }
    throw e;
  }
}

// The base64 SHA-256 of the DER SubjectPublicKeyInfo — which is what Chrome's
// --ignore-certificate-errors-spki-list wants, and NOT a hash of the
// certificate or of the PEM. Getting that wrong produces a pin that is simply
// never matched, which on the command line looks identical to no pin at all.
//
// Verified equal to
//   openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
//     | openssl dgst -sha256 -binary | openssl enc -base64
function spkiPin(pem) {
  log.debug("Entering spkiPin().");
  const cert = new crypto.X509Certificate(pem);
  const der = cert.publicKey.export({ type: 'spki', format: 'der' });
  log.debug("Leaving spkiPin().");
  return crypto.createHash('sha256').update(der).digest('base64');
}

// ---------------------------------------------------------------------------
// WHAT TO TRUST, FROM EVERY NODE BEHIND THE ADDRESS (2026-09-14, issue #46).
//
// In every mode but `cluster` this is one fetch and its pin — the code path
// this file always had. In the `cluster` mode the address is a load balancer
// in front of `STS_TEST_CLUSTER_NODES` nodes, and **each node presents a leaf
// of its own**: the same Root, Intermediate and Issuing CA, a different key.
// That is legitimate — a node's listener is the node's — and it is invisible
// to the node-driven jobs, whose NODE_EXTRA_CA_CERTS terminates at the shared
// Root whichever node's bundle it came from. It is NOT invisible to Chrome:
// the SPKI pin is a truststore of ONE KEY, so a browser job pinned to node A's
// leaf meets an interstitial on every connection the balancer gives node B,
// and fails naming a sign-in form.
//
// So a cluster fetch is repeated, each on a NEW connection (the balancer picks
// a node per connection), until as many distinct leaves as there are nodes
// have been seen, and both outputs carry all of them: the bundles one after
// another, and the pins comma-separated — which is the list syntax of
// `--ignore-certificate-errors-spki-list`, and `browser_flags.js` puts the
// variable into that list verbatim. SORTED BY PIN, so the same nodes give the
// same bytes and refreshTrust() does not report a rotation that is only a
// different order. Bounded at four attempts a node; fewer leaves than nodes is
// said out loud and the ones seen are used.
// ---------------------------------------------------------------------------
// `options` is fetchCertificate()'s (`pkiPort` for a runner-started service).
async function readTrust(url, nodes, options) {
  log.debug("Entering readTrust().");
  const want = Number(nodes || process.env.STS_TEST_CLUSTER_NODES || 1);
  if (!(want > 1)) {
    const pem = await fetchCertificate(url, 10000, options);
    log.debug("Leaving readTrust(). One node.");
    return { pem: pem, pin: spkiPin(pem), leaves: 1 };
  }
  // THE ANCHORS FIRST, ONCE (run #607). A fetch the known anchors do not
  // verify is TWO connections — the refused one and the one against the
  // Root — and a round-robin balancer then hands every second connection to
  // the same node, so eight fetches saw one key and a browser met the
  // other node's interstitial. With the Root among the anchors from the
  // start, each fetch is one connection, as it was.
  const anchors = await anchorsFor(url, options);
  const byPin = new Map();
  for (let attempt = 0; attempt < want * 4 && byPin.size < want;
       attempt += 1) {
    const pem = await fetchCertificate(url, 10000,
      Object.assign({}, options || {}, { fresh: true, ca: anchors }));
    byPin.set(spkiPin(pem), pem);
  }
  const pins = Array.from(byPin.keys()).sort();
  if (pins.length < want) {
    log.warn('trust: ' + want + ' nodes are expected behind ' + url +
             ' and ' + pins.length + ' distinct listener key(s) answered in ' +
             (want * 4) + ' fetches; trusting what was seen. A browser job ' +
             'will meet an interstitial on a node whose key is not here.');
  }
  log.debug("Leaving readTrust(). n=" + pins.length);
  return {
    pem: pins.map(function (pin) {
      return byPin.get(pin).replace(/\s*$/, '\n');
    }).join(''),
    pin: pins.join(','),
    leaves: pins.length
  };
}

// ---------------------------------------------------------------------------
// THE ONE CALL A LAUNCHER MAKES.
//
// Returns an object of ENVIRONMENT VARIABLES to merge into a child's
// environment, and `{}` when there is nothing to trust — so a caller writes
//
//   Object.assign(job.env, trust.variables)
//
// with no branch of its own, on every stack, TLS or not.
//
// `dir` is where the PEM is written. run-report.js passes the run's own report
// directory, so the certificate a run trusted is kept beside that run's logs:
// when a job fails on a certificate, the question is always which certificate,
// and a file in /tmp that the next run overwrites cannot answer it.
// ---------------------------------------------------------------------------
// `options` is fetchCertificate()'s: `pkiPort`, the revocation listener's
// port, when the runner started the service on a port block of its own.
async function trustTheService(url, dir, log, options) {
  log.debug('Entering trustTheService().');
  if (!isTls(url)) {
    log.debug('Leaving trustTheService(). Not TLS; nothing to trust.');
    return { url: url, tls: false, variables: {} };
  }
  const read = await readTrust(url, 0, options);
  const pem = read.pem;
  const pin = read.pin;
  fs.mkdirSync(dir, { recursive: true });
  const pemPath = path.join(dir, 'sts-certificate.pem');
  fs.writeFileSync(pemPath, pem);
  log.info('trusting IYA STS\'s per-start certificate: ' + pemPath +
           ' (SPKI pin ' + pin + ')');
  log.debug('Leaving trustTheService().');
  return {
    url: url,
    tls: true,
    pemPath: pemPath,
    pin: pin,
    variables: {
      NODE_EXTRA_CA_CERTS: pemPath,
      STS_SPKI_PIN: pin
    }
  };
}

module.exports = {
  isTls: isTls,
  spkiPin: spkiPin,
  fetchCertificate: fetchCertificate,
  rootOverHttp: rootOverHttp,
  anchorsFor: anchorsFor,
  readTrust: readTrust,
  trustTheService: trustTheService,
  CERTIFICATE_PATH: CERTIFICATE_PATH
};
