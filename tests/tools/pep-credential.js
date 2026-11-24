// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// tests/tools/pep-credential.js — A CA CHAIN AND A CLIENT CERTIFICATE FOR THE
// REMOTE XACML PEP, BUILT OUTSIDE THIS SERVICE AND TRUSTED BY IT AT RUNTIME.
//
// ===========================================================================
// WHAT THIS IS FOR
//
// The remote PEP container has to be RECOGNISED by the mock — its DN resolved
// to a directory entry, to a group, to a role, to a policy decision — and that
// takes a client certificate the mock can build a path from. This tool makes
// one and tells the mock to trust the authority behind it. Both launchers ran
// it after the service is up and before the PEP container starts, and then
// mounted what it wrote — until phase 4 of #1827's follow-up (rcbj,
// 2026-11-16) retired the PEP's client certificate: the launchers now run
// only `--assertion --csr-only` (below), and the default mode is what the
// protocol jobs use for the OTHER callers they drive over mutual TLS (an
// XACML_USER, an AuthZEN caller, a PEP in a realm that opted in to
// `xacml.pepAuthentication` `either`).
//
// ---------------------------------------------------------------------------
// IT BUILDS THE CHAIN OUTSIDE THE SERVICE, WHICH IS THE ESTABLISHED PATTERN
// AND NOT A CONVENIENCE.
//
// The mock has had a certificate authority of its own since 2026-09-11
// (`common/pki.js`; its listener certificate is a leaf of the service Root),
// but the PEP stands for a workload whose authority is SOMEBODY ELSE'S. What
// admits a foreign authority is the TRUSTSTORE — `POST
// /admin-api/tls/trust/add` — which
// holds no foreign anchor until one is added at runtime, precisely because
// the CA in question does not exist anywhere until somebody builds it
// (`tls/CLAUDE.md`).
//
// The parent project's `tests/pki_mutual_tls.js` has done exactly this since
// long before the remote PEP existed: it builds a Root CA and an Issuing CA in
// a browser, issues a client certificate from them, POSTs the CA to the
// truststore, and then reads back which chain the mock built out of what was
// sent. This file is that flow with a command line instead of a browser.
//
// **SO NOTHING WAS ADDED TO THE MOCK OR TO THE PEP TO PROVIDE THIS
// CERTIFICATE.** The mock gained no issuance endpoint for it and the PEP gained
// no enrolment step. The mock verifies what it is shown against anchors
// somebody gave it, which is what a truststore is; the PEP reads a certificate
// from a path, which it already did.
//
// ---------------------------------------------------------------------------
// THE ENGINE IS THE VENDORED ONE, AND THAT IS THE POINT OF USING IT
//
// `common/crypto_impl/x509.js` is the debugger's own PKI code, byte-identical,
// already in this repository and already the thing `spiffe/spiffe_ca.ts` runs
// its certificate authority on. Over there it is held to roughly 240
// certificates by `tests/pki_x509.js` — every key algorithm against every
// signature algorithm, every X.509v3 extension, a four-deep chain — and each
// one is checked with OPENSSL rather than by reading back what the same code
// just wrote.
//
// Writing a fifth certificate builder here to make two certificates would have
// been a fifth reading of RFC 5280, and the first thing it got wrong would have
// looked like a mock that refuses valid certificates.
//
// ---------------------------------------------------------------------------
// THREE CERTIFICATES AND NOT ONE, DELIBERATELY
//
//   Root CA  ──issues──▶  Issuing CA  ──issues──▶  the PEP's client leaf
//
// A single self-signed client certificate would authenticate perfectly well and
// would demonstrate nothing about path building. With a two-deep chain the PEP
// presents LEAF + ISSUING CA and the mock holds only the ROOT — so the mock has
// to build a path from what arrived to an anchor it was given, which is the
// commonest thing to get wrong in mutual TLS and is invisible from the client
// side. `pki_mutual_tls.js` makes the same point at length.
//
// ---------------------------------------------------------------------------
// WHAT IT WRITES, and why the names are what they are
//
//   <out>/pep.crt    THE LEAF FOLLOWED BY THE ISSUING CA. `xacml-pep/pep.js`
//                    hands this file to node as `cert`, and node sends every
//                    certificate in it — which is how the mock gets the
//                    intermediate it needs and does not have.
//   <out>/pep.key    the leaf's private key. Nothing else ever sees it.
//   <out>/ca.crt     the ROOT alone, which is what was POSTed to the mock. Not
//                    used by the PEP; written so that a person debugging the
//                    stack can check what the mock was asked to trust.
//   <out>/chain.txt  a one-line summary per certificate, for the same reader.
//   <out>/crl/       with --crl-base only: root.crl and issuing.crl, the two
//                    lists the certificates name (#174). Signed documents,
//                    not key material; the PEP container serves them.
//
// ---------------------------------------------------------------------------
// USAGE
//
//   node tests/tools/pep-credential.js --url=https://localhost:8081 \
//        --out=/tmp/pep-certs --subject="CN=remote-pep-1,OU=remote-peps,O=iya-sts"
//
// **EVERY FLAG TAKES `=`.** `--url https://…` leaves `--url` empty and reports
// the URL as an unknown option; this block showed that form until it was fixed,
// so the documented invocation exited 2 naming the argument the reader had got
// right. See `parseArgs()` for why the doc moved rather than the parser.
//
//   --url       the mock, where the anchor is POSTed. Required.
//   --out       where the three files go. Required; created if absent.
//   --subject   the leaf's DN in RFC 4514 order. Defaults to the CN below.
//   --root-subject
//               the Root CA's DN (#695). Default `CN=iya-sts test Root CA,
//               O=iya-sts tests`, the name the test suite's own roots carry
//               — and the AWS suite reset (deploy/aws/reset-environment.js)
//               removes every runtime anchor with that common name. An
//               operator's PEP sets its own, so the reset leaves its root.
//   --years     the leaf's life. Default 1.
//   --quiet     only the DN on stdout, for a launcher to capture.
//   --crl-base  where the Issuing CA's and the leaf's CRLs will be served
//               (#174): the certificates name <crl-base>/root.crl and
//               <crl-base>/issuing.crl, and both lists are written to
//               <out>/crl/ for that server. Without it no certificate names
//               a list, and a product-mode service refuses the chain
//               (STS-PKI-0190) — which is what the launchers pass it for.
//               Name the PEP's PLAIN port, http://<pep>:<PEP_PORT>/crl
//               (9090): the PEP serves <out>/crl there on its CRL-only
//               listener even with PEP_HTTP off (2026-11-14, PEP_CRL_HTTP),
//               because a CRL is fetched in the clear (RFC 5280 section
//               4.2.1.13). Until then 9090 was dark with HTTP off, the list
//               could not be fetched, and every pull was refused as
//               unauthenticated. An https base is refused here: the list
//               would have to be validated with the certificate it revokes.
//
//   --store-on  a username (#1061): after the anchor, the leaf is STORED on
//               that person's entry (created first if absent), through
//               POST /admin-api/users/add-certificate. Needs --realm when
//               the entry is not in the default realm, and the realm must
//               already exist.
//   --realm     the realm --store-on writes in. Default: the default realm.
//               With --assertion, the realm whose Issuing CA certifies the
//               key and whose ou=users holds --name.
//
// ---------------------------------------------------------------------------
// --assertion: THE PEP'S ONE ASSERTION KEY INSTEAD (#1827's follow-up, phase
// 3, rcbj 2026-11-16: "the service never holds the PEP's private key").
//
//   node tests/tools/pep-credential.js --assertion --url=https://… \
//        --out=/tmp/pep --name=remote-pep-1 [--realm=acme] \
//        [--key-alg=ec-p256|rsa-2048] [--revoke-previous] [--quiet]
//
// A remote PEP reaches the service on a DPoP-bound access token from its RFC
// 7523 self-assertion, signed with ONE key (`PEP_ASSERTION_KEY`), and the
// service accepts it only once that key is registered on the PEP's entry.
// This mode generates the key pair HERE (EC P-256 by default, ES256; or RSA
// 2048), writes a PKCS #10 request signed with it, and sends ONLY THE
// REQUEST to `POST /admin-api/xacml/issue-pep-credential`: the realm's
// Issuing CA certifies the public key as `urn:sts:sa:<name>` and registers
// it. The private key never leaves this process except as the file below.
// The entry must already exist, be a service account and be in the remote
// PEPs group — the act refuses otherwise, naming which.
//
//   <out>/pep-assertion.key  the private key, PKCS #8 PEM. 0644, for the
//                            reason the launchers relax pep.key: the PEP
//                            container is not this user and its mount is
//                            read-only, so a key only the writer can read
//                            is a PEP that starts with no credential.
//   <out>/pep-assertion.csr  the request that was sent.
//   <out>/pep-assertion.crt  the leaf followed by its chain through the Root
//                            (public; the PEP does not need it).
//
// The PEP environment is printed on stdout, one VAR=value a line:
// PEP_ASSERTION_KEY (the file above), PEP_NAME and PEP_CLIENT_ID.
//
//   --name        the username of the PEP's entry. Required unless
//                 --csr-only.
//   --key-alg     ec-p256 (the default) or rsa-2048.
//   --csr-only    write the key and the request and send nothing; --url is
//                 then not needed. For a launcher whose PEP's entry does not
//                 exist yet: the job that creates it sends the request
//                 (`issueAssertionCredential()`, exported below).
//   --reuse-key   use pep-assertion.key and pep-assertion.csr already in
//                 --out rather than generating new ones (a request written
//                 by --csr-only, sent later).
//   --revoke-previous  revoke the entry's other RFC 7523 keys once this one
//                 is registered. Off by default: a running PEP keeps its old
//                 key until it is restarted on the new one.
//
// It prints the leaf's DN as its LAST line, so `$(... --quiet)` is the DN and a
// launcher needs no parsing.
//
// ---------------------------------------------------------------------------
// **TRUSTING THE ROOT NO LONGER MAKES THE LEAF ANYBODY (#1061, rcbj
// 2026-10-27).** A certificate from an outside authority — which is every
// certificate this file makes — is an identity at a door that reads a client
// certificate as a person or application (the XACML gates, /tls/sign-in, the
// sign-in screen, SCIM, Shared Signals, WS-Trust, LDAP SASL EXTERNAL) only
// while it is STORED, byte for byte, in `userCertificate` on exactly one
// entry of the realm the request is in. Its CN is never read as a name. So
// whoever presents one of these leaves stores it first: `--store-on` here,
// or `storeOnEntry()` (exported below) from a job, which makes the entry
// where it is missing. The launchers mint the PEP's leaf before the job that
// creates the PEP's realm has run, so `sts_xacml_remote_pep.js` stores the
// launcher's `pep.crt` itself; the AWS runner's `pep-credential.sh` is in the
// same position. RFC 8705 client authentication and GNAP's key proof read
// the certificate as a KEY and are unchanged.
//
// **`MOCK_STS_DIR` RELOCATES THE ENGINE**, defaulting to two directories up.
// The containerized launcher runs this file with the repository mounted into an
// image whose own copy lives elsewhere, which is the same override
// `tests/protocol/module_paths.js` takes and for the same reason.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pep-credential',
  level: process.env.LOG_LEVEL || 'info' });

const REPO = process.env.MOCK_STS_DIR ||
             path.join(__dirname, '..', '..');
const x509 = require(path.join(REPO, 'common', 'crypto_impl', 'x509.js'));
const keys = require(path.join(REPO, 'common', 'crypto_impl',
                               'key_material.js'));

const DEFAULT_SUBJECT = 'CN=remote-pep-1,OU=remote-peps,O=iya-sts';

// ---------------------------------------------------------------------------
// The arguments. Hand-parsed for `tests/run.js`'s reason: this directory takes
// no dependency to run, and five flags do not justify the first one.
// ---------------------------------------------------------------------------
// **`--flag=value` ONLY, AND THE HEADER SAID OTHERWISE UNTIL IT WAS FIXED.**
// Each argument is split on its first `=`, so a bare `--url` is a flag whose
// value is the empty string and the URL that followed it is an unknown option:
// the invocation the USAGE block documented exited 2, naming the one argument
// the reader had typed correctly.
//
// **THE DOCUMENTATION MOVED RATHER THAN THIS FUNCTION**, which is worth saying
// because the other repair is four lines and looks obviously kinder. Nothing
// calls this file the space way — both launchers pass `=`,
// `docs/v1.2.0/remote-pep.md` passes `=`, and the tests that want a certificate
// `require()` this file for `mint()` and never reach a command line at all — so
// accepting the space form would have been a behaviour change made to rescue a
// comment, in the one directory whose rule is that it takes no dependency and
// stays small.
function parseArgs(argv) {
  log.debug("Entering parseArgs().");
  const opts = { url: '', out: '', subject: DEFAULT_SUBJECT, years: 1,
                 quiet: false, crlBase: '' };
  argv.forEach(function (arg) {
    const eq = arg.indexOf('=');
    const name = eq > 0 ? arg.slice(0, eq) : arg;
    const value = eq > 0 ? arg.slice(eq + 1) : '';
    if (name === '--url') { opts.url = value; }
    else if (name === '--out') { opts.out = value; }
    else if (name === '--subject') { opts.subject = value; }
    else if (name === '--root-subject') { opts.rootSubject = value; }
    else if (name === '--years') { opts.years = parseInt(value, 10) || 1; }
    else if (name === '--quiet') { opts.quiet = true; }
    else if (name === '--store-on') { opts.storeOn = value; }
    else if (name === '--realm') { opts.realm = value; }
    else if (name === '--assertion') { opts.assertion = true; }
    else if (name === '--name') { opts.name = value; }
    else if (name === '--key-alg') { opts.keyAlg = value; }
    else if (name === '--csr-only') { opts.csrOnly = true; }
    else if (name === '--reuse-key') { opts.reuseKey = true; }
    else if (name === '--revoke-previous') { opts.revokePrevious = true; }
    else if (name === '--crl-base') {
      opts.crlBase = value.replace(/\/+$/, '');
    }
    else if (name === '--help' || name === '-h') { opts.help = true; }
    else { opts.unknown = (opts.unknown || []).concat(arg); }
  });
  log.debug("Leaving parseArgs().");
  return opts;
}

function say(opts, line) {
  log.debug("Entering say().");
  if (!opts.quiet) {
    process.stderr.write(line + '\n');
  }
  log.debug("Leaving say().");
}

// ---------------------------------------------------------------------------
// ONE HTTP CALL TO THE MOCK, to hand it the anchor.
//
// **`rejectUnauthorized: false`, AND IT IS ARGUED RATHER THAN ASSUMED.** This
// call posts a PUBLIC CERTIFICATE to a service this launcher started seconds
// ago on this machine or on its own bridge. There is no secret in the request
// and nothing in the response worth forging. More to the point, the anchor for
// the mock's own certificate is fetched FROM the mock — the service Root,
// regenerated per start in development mode — so there is no file, image or
// CA bundle that could hold it before this runs. Verifying here would mean
// fetching that anchor first over an unverified connection, which is the same
// trust decision one step further away.
// ---------------------------------------------------------------------------
// **THE GATED DOOR, AND SINCE #597 THE ONLY ONE (2026-10-12).** The anchor
// goes through `POST /admin-api/tls/trust/add`, which is gated by the
// management API's access token (a job's preload attaches one to any
// /admin-api request; a launcher passes STS_ADMIN_API_TOKEN) and persisted
// in ou=trustAnchors, so every node of a cluster applies it — and **it
// VERIFIES the connection**, because it carries a bearer token and the
// argument above is about a request with no secret in it (the launchers
// fetch the service's own certificate first, `tests/tools/trust.js`).
// `POST /tls/trust`, the open test control this fell back to for a
// development stack, was deleted by #597, so there is no fallback: a
// caller with no token, or no anchor for the service, is told so.
function postAnchor(url, pem) {
  log.debug("Entering postAnchor().");
  const base = String(url || '').replace(/\/+$/, '');
  const token = process.env.STS_ADMIN_API_TOKEN || '';
  log.debug("Leaving postAnchor().");
  return sender(base + '/admin-api/tls/trust/add', 'application/json',
    JSON.stringify({ certificates: pem }),
    token ? { Authorization: 'Bearer ' + token } : {}, true)
    .then(function (answer) {
      if (!answer.ok) {
        answer.why = 'POST /admin-api/tls/trust/add answered ' +
          (answer.status || answer.why) + ' ' +
          String(answer.body || '').slice(0, 200) +
          (token ? '' : ' (no STS_ADMIN_API_TOKEN was set)');
      }
      return answer;
    });
}

function send(where, type, body, extraHeaders, verify) {
  log.debug("Entering send().");
  log.debug("Leaving send().");
  return new Promise(function (resolve) {
    let target;
    try {
      target = new URL(where);
    } catch (error) {
      log.debug("Caught in a callback in send(): " +
                ((error && error.message) || error));
      resolve({ ok: false, why: '--url is not a URL: ' + where });
      return;
    }
    const insecure = target.protocol === 'http:';
    const transport = insecure ? http : https;
    const request = transport.request({
      method: 'POST',
      hostname: target.hostname,
      port: target.port || (insecure ? 80 : 443),
      path: target.pathname,
      headers: Object.assign({ 'Content-Type': type,
                               'Content-Length': Buffer.byteLength(body) },
                             extraHeaders || {}),
      timeout: 15000,
      rejectUnauthorized: !!verify
    }, function (response) {
      let text = '';
      response.on('data', function (chunk) { text += chunk; });
      response.on('end', function () {
        resolve({ ok: response.statusCode >= 200 && response.statusCode < 300,
                  status: response.statusCode, body: text });
      });
    });
    request.on('timeout', function () {
      request.destroy(new Error('the mock did not answer within 15s'));
    });
    request.on('error', function (error) {
      log.debug("Caught in a callback in send(): " +
                ((error && error.message) || error));
      resolve({ ok: false, why: error.message });
    });
    request.end(body);
  });
}

// ---------------------------------------------------------------------------
// THE ONE CALL EVERY ADD AND REMOVE GOES THROUGH, REPLACEABLE FOR A TEST
// (#1307). `tests/trust_anchor_cleanup.js` drives `forgetAnchors()`,
// `settleAnchors()` and `trustRecorded()` against a fake with send()'s
// signature and answer shape, so the cleanup's decisions are asserted without
// a service. `useSender(null)` puts send() back; a test restores what
// `useSender()` handed it, never null by assumption.
// ---------------------------------------------------------------------------
let sender = send;

function useSender(fn) {
  log.debug("Entering useSender().");
  const previous = sender;
  sender = typeof fn === 'function' ? fn : send;
  log.debug("Leaving useSender().");
  return previous;
}

// THE ANCHORS WHOSE ADD THE SERVICE CONFIRMED, by SHA-256 fingerprint.
// "Not held" is a finished remove only for an anchor NOT in here: its add
// timed out or was refused, so the service may never have taken it. For one
// in here the add answered 2xx, and "not held" is a node of a cluster that
// has not yet applied the row — the remove retries (REMOVE_TRIES, one
// operation's retry delay, not periodic work) and then fails as it always
// did, because a pass there would leave the row in ou=trustAnchors.
const confirmed = new Set();
const REMOVE_TRIES = 5;
let retryDelayMs = 1000;

// For a test: the delay between the tries of one remove. Answers the
// previous value; a non-number or a negative one restores 1000.
function useRetryDelay(ms) {
  log.debug("Entering useRetryDelay().");
  const previous = retryDelayMs;
  retryDelayMs = typeof ms === 'number' && ms >= 0 ? ms : 1000;
  log.debug("Leaving useRetryDelay().");
  return previous;
}

function fingerprintOf(pem) {
  log.debug("Entering fingerprintOf().");
  try {
    const print = new crypto.X509Certificate(pem).fingerprint256;
    log.debug("Leaving fingerprintOf().");
    return print;
  } catch (error) {
    // Not a certificate: the caller decides what that means, with ''.
    log.debug("Caught in fingerprintOf(): " +
              ((error && error.message) || error));
    log.debug("Leaving fingerprintOf(). Not a certificate.");
    return '';
  }
}

// A job posting through its own door calls this after its post answered
// 2xx; trustRecorded() calls it itself. Answers whether it was a certificate.
function confirmAnchor(pem) {
  log.debug("Entering confirmAnchor().");
  const print = fingerprintOf(pem);
  if (print) {
    confirmed.add(print);
  }
  log.debug("Leaving confirmAnchor().");
  return !!print;
}

function isConfirmed(pem) {
  log.debug("Entering isConfirmed().");
  const print = fingerprintOf(pem);
  log.debug("Leaving isConfirmed().");
  return !!print && confirmed.has(print);
}

// The sentence `tls/tls_server.js`'s removeAnchor() refuses a fingerprint it
// does not hold with (STS-TLS-0016; codes are never sent, and the APIs' errors
// stay English), carried in the 400's `errors`.
const NOT_HELD = /holds no anchor with the SHA-256 fingerprint/;

// ---------------------------------------------------------------------------
// RECORD AN ANCHOR BEFORE IT IS POSTED (#1307, from #695's review of #682).
//
// Every job recorded its anchor only after the add answered 2xx. send()
// gives up after 15s, and an add the service APPLIED but answered late was
// then never recorded, so the job's own cleanup left it in the truststore
// (32 anchors, service-wide) and only `deploy/aws/reset-environment.js`
// caught it. Recording first costs nothing, because a remove of an anchor
// the service never took answers "not held", which removeAnchor() counts as
// done for an anchor whose add was never confirmed (see `confirmed`).
//
// `recordAnchor(added, pem)` is the record alone, for a job that posts
// through a door of its own, which calls `confirmAnchor(pem)` once its post
// answered 2xx; `trustRecorded(url, pem, added)` is the record, then
// `trustAnchor()`'s post, then the confirmation on a 2xx, and answers what
// the post answered. Only an
// anchor THE JOB MINTED is recorded: removing one it re-posts (the remote
// PEP's, `XACML_PEP_CA_PEM`) would take it from somebody else.
// ---------------------------------------------------------------------------
function recordAnchor(added, pem) {
  log.debug("Entering recordAnchor().");
  if (!Array.isArray(added)) {
    log.debug("Leaving recordAnchor(). No list.");
    throw new Error('recordAnchor() needs the job\'s list of added anchors');
  }
  if (pem && added.indexOf(pem) < 0) {
    added.push(pem);
  }
  log.debug("Leaving recordAnchor().");
  return added;
}

function trustRecorded(url, pem, added) {
  log.debug("Entering trustRecorded().");
  recordAnchor(added, pem);
  log.debug("Leaving trustRecorded().");
  return postAnchor(url, pem).then(function (answer) {
    if (answer.ok) {
      confirmAnchor(pem);
    }
    return answer;
  });
}

// ---------------------------------------------------------------------------
// REMOVE AN ANCHOR THIS PROCESS ADDED (#335).
//
// The client truststore is service-wide and holds 32. A job that posts a
// suite CA removes it when the job finishes, pass or fail. The command-line
// `main()` does not: the remote PEP needs that anchor for the rest of the
// run, and `deploy/aws/reset-environment.js` spares it by fingerprint.
// A fingerprint the service answers it does not hold is a remove that is
// done (#1307), answered `{ ok: true, absent: true }` — for an anchor whose
// add was never confirmed. A confirmed one is asked again, REMOVE_TRIES in
// all, and then fails, saying so.
// ---------------------------------------------------------------------------
function removeAnchor(url, pem) {
  log.debug("Entering removeAnchor().");
  const base = String(url || '').replace(/\/+$/, '');
  const token = process.env.STS_ADMIN_API_TOKEN || '';
  let fingerprint = '';
  try {
    fingerprint = new crypto.X509Certificate(pem).fingerprint256;
  } catch (error) {
    // A PEM this process cannot read is one failed remove, reported to
    // forgetAnchors(), rather than an exception that skips the rest of
    // the list.
    log.debug("Caught in removeAnchor(): " +
              ((error && error.message) || error));
    log.debug("Leaving removeAnchor(). Not a certificate.");
    return Promise.resolve({ ok: false,
                             why: 'the anchor is not a certificate' });
  }
  const wasConfirmed = confirmed.has(fingerprint);
  const once = function () {
    log.debug("Entering once().");
    log.debug("Leaving once().");
    return sender(base + '/admin-api/tls/trust/remove', 'application/json',
      JSON.stringify({ fingerprint: fingerprint }),
      token ? { Authorization: 'Bearer ' + token } : {}, true);
  };
  const attempt = function (tries) {
    log.debug("Entering attempt(). try " + tries);
    log.debug("Leaving attempt().");
    return once().then(function (answer) {
      const notHeld = !answer.ok && answer.status === 400 &&
                      NOT_HELD.test(String(answer.body || ''));
      if (notHeld && !wasConfirmed) {
        // NOT HELD IS DONE (#1307), for an add never confirmed: it timed
        // out or was refused, so the service may never have taken it, and
        // holding no such anchor is the state the remove was for.
        return { ok: true, status: answer.status, body: answer.body,
                 absent: true };
      }
      if (notHeld && tries < REMOVE_TRIES) {
        // CONFIRMED AND NOT HELD: a node that has not applied the add yet.
        // Asked again after a pause, a bounded number of times.
        return new Promise(function (resolve) {
          setTimeout(resolve, retryDelayMs);
        }).then(function () {
          return attempt(tries + 1);
        });
      }
      if (answer.ok) {
        confirmed.delete(fingerprint);
      }
      if (!answer.ok) {
        answer.why = 'POST /admin-api/tls/trust/remove answered ' +
          (answer.status || answer.why) + ' ' +
          String(answer.body || '').slice(0, 200) +
          (token ? '' : ' (no STS_ADMIN_API_TOKEN was set)') +
          (notHeld ? ' — its add was CONFIRMED and it is still not held ' +
                     'after ' + tries + ' tries' : '');
      }
      return answer;
    });
  };
  log.debug("Leaving removeAnchor().");
  return attempt(1);
}

function forgetAnchors(url, pems) {
  log.debug("Entering forgetAnchors().");
  const list = Array.isArray(pems) ? pems.filter(Boolean) : [];
  log.debug("Leaving forgetAnchors().");
  return list.reduce(function (chain, pem) {
    return chain.then(function (problems) {
      return removeAnchor(url, pem).then(function (answer) {
        if (!answer.ok) {
          problems.push(answer.why || ('HTTP ' + answer.status));
        }
        return problems;
      });
    });
  }, Promise.resolve([]));
}

// `failed` is the error the job already threw, or null when it passed. A
// remove that fails after a passing job fails the job. A remove that fails
// after a job that already failed is logged and the original error is kept.
function settleAnchors(url, pems, failed) {
  log.debug("Entering settleAnchors().");
  log.debug("Leaving settleAnchors().");
  return forgetAnchors(url, pems).then(function (problems) {
    if (problems.length && failed) {
      log.warn("the trust anchors this job added were not removed: " +
               problems.join("; ") + "; the job had already failed");
      throw failed;
    }
    if (problems.length) {
      throw new Error("the trust anchors this job added were not removed: " +
                      problems.join("; "));
    }
    if (failed) {
      throw failed;
    }
  }, function (error) {
    log.debug("Caught in settleAnchors(): " +
              ((error && error.message) || error));
    if (failed) {
      log.warn("removing the trust anchors this job added failed: " +
               ((error && error.message) || error) +
               "; the job had already failed");
      throw failed;
    }
    throw error;
  });
}

// ---------------------------------------------------------------------------
// ONE CERTIFICATE. The shape `spiffe/spiffe_ca.ts` uses, because there is one
// right way to call this engine and a second spelling of it here would be a
// second set of edge cases.
// ---------------------------------------------------------------------------
//
// THREE OPTIONS A TEST ASKS FOR (#2081), each absent in every other caller:
// `pair`, a key pair to certify again (a renewal under the same key, so the
// same SubjectPublicKeyInfo and the same derived subjectKeyIdentifier);
// `expiredSince`, milliseconds, a validity that ENDED that long ago; and
// `san`, subjectAltName entries as the engine takes them
// (`[{ kind: 'email', value }]`).
async function issue(spec) {
  log.debug("Entering issue().");
  const pair = spec.pair || await keys.generateKeyPair('rsa-2048');
  const expired = Number(spec.expiredSince) > 0;
  const now = expired
    ? new Date(Date.now() - Number(spec.expiredSince) - 24 * 3600 * 1000)
    : new Date();
  const until = expired
    ? new Date(Date.now() - Number(spec.expiredSince))
    : new Date(now.getTime() + (spec.years || 1) * 365 * 24 * 3600 * 1000);
  const extensions = {
    basicConstraints: { present: true, critical: true, ca: !!spec.ca,
                        pathLen: spec.ca ? (spec.pathLen || 0) : undefined },
    keyUsage: { present: true, critical: true,
                usages: spec.ca ? ['keyCertSign', 'cRLSign']
                                : ['digitalSignature', 'keyEncipherment'] },
    subjectKeyIdentifier: { present: true },
    authorityKeyIdentifier: { present: true }
  };
  if (spec.crl) {
    // THE LIST OF THE CA THAT SIGNED THIS ONE (#174): a product-mode service
    // refuses, under hard-fail, a certificate from an authority it does not
    // hold that names none — nobody could ever revoke it.
    extensions.cRLDistributionPoints = { present: true, critical: false,
                                         urls: [spec.crl] };
  }
  if (!spec.ca) {
    // clientAuth AND NOTHING ELSE. A certificate that also claimed serverAuth
    // would work here and would be a lie about what it is for — and this one is
    // about to be handed to a container as its identity, which is exactly the
    // place an over-broad extended key usage stops being cosmetic.
    extensions.extKeyUsage = { present: true, usages: ['clientAuth'] };
  }
  if (Array.isArray(spec.san) && spec.san.length) {
    extensions.subjectAltName = { present: true, critical: false,
                                  names: spec.san };
  }
  const issued = await x509.issueCertificate({
    subject: spec.subject,
    subjectPublicKey: pair.publicPem,
    signatureAlg: 'sha256-rsa',
    // A self-signed root signs with its OWN key and names no issuer; a leaf
    // names the certificate above it. The engine tells the two apart by which
    // of these is present, which is why they are not both set.
    issuerPrivateKey: spec.issuer ? undefined : pair.privatePem,
    issuer: spec.issuer,
    notBefore: now.toISOString(),
    notAfter: until.toISOString(),
    extensions: extensions
  });
  log.debug("Leaving issue().");
  return { pem: issued.pem, privateKeyPem: pair.privatePem,
           publicKeyPem: pair.publicPem, pair: pair, subject: spec.subject,
           serialHex: issued.serialHex,
           notAfter: until.toISOString() };
}

// ---------------------------------------------------------------------------
// THE WHOLE CHAIN, IN MEMORY. Exported so that a TEST can mint a credential
// without writing files — `tests/protocol/sts_xacml_endpoints.js` needs a
// trusted client certificate to drive the three PEP endpoints at all now that
// they are gated, and a second implementation of this in that file would be a
// second reading of how a chain is built.
// ---------------------------------------------------------------------------
//
// **EVERY CERTIFICATE BELOW THE ROOT NAMES ITS ISSUER'S CRL (#174).** Since
// then a product-mode service refuses a CA-issued foreign certificate that
// names no CRL and no OCSP responder, so the Issuing CA names the Root's list
// and the leaf the Issuing CA's. Where those lists are served is the caller's
// choice, by `options.crlBase`:
//
//   * absent — the default, for a test: `tests/protocol/test_crl_host.js`
//     serves them from THIS process, which is alive while its certificate is
//     presented;
//   * a URL — the lists are named `<crlBase>/root.crl` and
//     `<crlBase>/issuing.crl` and returned in `crls` for the caller to put
//     there (the launcher writes them beside the credential, and the PEP
//     container serves them, because this process exits first);
//   * `false` — no distribution point at all, for a credential nothing will
//     present to a product-mode service.
// ---------------------------------------------------------------------------
async function mint(opts) {
  log.debug("Entering mint().");
  const options = opts || {};
  const host = options.crlBase === undefined
    ? require('../protocol/test_crl_host.js') : null;
  const rootList = host ? await host.reserve('root')
    : (options.crlBase ? { url: options.crlBase + '/root.crl' } : null);
  const issuingList = host ? await host.reserve('issuing')
    : (options.crlBase ? { url: options.crlBase + '/issuing.crl' } : null);
  const root = await issue({
    subject: options.rootSubject || 'CN=iya-sts test Root CA,O=iya-sts tests',
    ca: true, pathLen: 1, years: 10
  });
  const issuing = await issue({
    subject: options.issuingSubject ||
             'CN=iya-sts test Issuing CA,O=iya-sts tests',
    ca: true, pathLen: 0, years: 5,
    crl: rootList ? rootList.url : '',
    issuer: { certificatePem: root.pem, privateKeyPem: root.privateKeyPem,
              keyAlg: 'rsa-2048' }
  });
  const leaf = await issue({
    subject: options.subject || DEFAULT_SUBJECT,
    years: options.years || 1,
    san: options.leafSan,
    crl: issuingList ? issuingList.url : '',
    issuer: { certificatePem: issuing.pem,
              privateKeyPem: issuing.privateKeyPem, keyAlg: 'rsa-2048' }
  });
  let crls = null;
  if (host) {
    await rootList.publish(root);
    // TWO STATES A TEST ASKS FOR (#2089): `revokeLeaf`, the Issuing CA's
    // list naming the leaf; `crlMissing`, that list never published, so
    // its address answers 404 and the leaf's status cannot be established.
    if (!options.crlMissing) {
      await issuingList.publish(issuing, options.revokeLeaf
        ? { revoked: [leaf.serialHex] } : {});
    }
  } else if (options.crlBase) {
    // Fresh for as long as the leaf lives, because nothing re-signs them: the
    // container serving them has no key.
    const days = (options.years || 1) * 366;
    const lists = require('../protocol/test_crl_host.js');
    crls = { 'root.crl': await lists.crlFor(root, { days: days }),
             'issuing.crl': await lists.crlFor(issuing, { days: days }) };
  }
  log.debug("Leaving mint().");
  return {
    root: root, issuing: issuing, leaf: leaf,
    issuingList: issuingList ? issuingList.url : '',
    // WHAT A TLS CLIENT NEEDS, spelt the way node's `cert`/`key` options take
    // it: the leaf followed by the intermediate, because node sends every
    // certificate in `cert` and the service holds only the root.
    certPem: leaf.pem + issuing.pem,
    keyPem: leaf.privateKeyPem,
    anchorPem: root.pem,
    subject: leaf.subject,
    crls: crls
  };
}

// ANOTHER LEAF FROM A CREDENTIAL'S OWN ISSUING CA (#2081), for a test that
// needs a second certificate under the same authority: a renewal
// (`o.sameKey`, the old leaf's key pair certified again, so its
// SubjectPublicKeyInfo and derived subjectKeyIdentifier are kept), or an
// expired leaf (`o.expiredSince`, milliseconds). Answers `mint()`'s shape
// with the new leaf in it, so `certPem`/`keyPem` present the new one.
async function reissue(minted, o) {
  log.debug("Entering reissue().");
  const opts = o || {};
  const leaf = await issue({
    subject: opts.subject || minted.leaf.subject,
    years: 1, san: opts.san, expiredSince: opts.expiredSince,
    pair: opts.sameKey ? minted.leaf.pair : undefined,
    crl: minted.issuingList || '',
    issuer: { certificatePem: minted.issuing.pem,
              privateKeyPem: minted.issuing.privateKeyPem,
              keyAlg: 'rsa-2048' }
  });
  log.debug("Leaving reissue().");
  return Object.assign({}, minted, { leaf: leaf,
    certPem: leaf.pem + minted.issuing.pem, keyPem: leaf.privateKeyPem,
    subject: leaf.subject });
}

async function main() {
  log.debug("Entering main().");
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(
      fs.readFileSync(__filename, 'utf8')
        .split('\n')
        .filter(function (line) { return line.indexOf('//') === 0; })
        .map(function (line) { return line.replace(/^\/\/ ?/, ''); })
        .join('\n') + '\n');
    process.exit(0);
  }
  if (opts.unknown) {
    process.stderr.write('Unknown option(s): ' + opts.unknown.join(' ') +
                         '. --help says what there is.\n');
    process.exit(2);
  }
  if (opts.assertion) {
    await assertionMain(opts);
    log.debug("Leaving main(). The assertion key.");
    return;
  }
  if (opts.crlBase && !/^http:\/\//i.test(opts.crlBase)) {
    process.stderr.write('--crl-base must be an http:// URL, the PEP\'s ' +
                         'plain port (http://<pep>:9090/crl): a CRL behind ' +
                         'TLS would have to be validated with the ' +
                         'certificate it revokes.\n');
    process.exit(2);
  }
  if (!opts.url || !opts.out) {
    process.stderr.write('Both --url and --out are required. --help says ' +
                         'what they are.\n');
    process.exit(2);
  }

  say(opts, 'Building a Root CA, an Issuing CA and a TLS client certificate ' +
            'for ' + opts.subject + ' on ' + REPO +
            '/common/crypto_impl/x509.js ' +
            '— the same engine spiffe/spiffe_ca.ts issues X509-SVIDs with.');

  // THE LISTS GO WHERE --crl-base SAYS, OR NOWHERE (#174): this process exits
  // as soon as it has written the credential, so it cannot serve them itself.
  const minted = await mint({ subject: opts.subject, years: opts.years,
                              rootSubject: opts.rootSubject || '',
                              crlBase: opts.crlBase || false });
  const root = minted.root;
  const issuing = minted.issuing;
  const leaf = minted.leaf;

  fs.mkdirSync(opts.out, { recursive: true });
  // THE LEAF AND THE INTERMEDIATE, in that order. Node sends every certificate
  // in `cert`, so this is what puts the Issuing CA on the wire — and the mock
  // holds only the Root, so without it there is no path to build and the
  // handshake produces an unverified certificate rather than an error.
  fs.writeFileSync(path.join(opts.out, 'pep.crt'), minted.certPem);
  fs.writeFileSync(path.join(opts.out, 'pep.key'), leaf.privateKeyPem);
  fs.writeFileSync(path.join(opts.out, 'ca.crt'), root.pem);
  if (minted.crls) {
    // PUBLIC, SIGNED DOCUMENTS — no key material — for whoever serves
    // --crl-base: the PEP container answers GET /crl/<name> from this
    // directory on its plain port — the CRL-only listener when PEP_HTTP is
    // off (`rust/bins/xacml-pep/src/options.rs`, `crl_listener()`).
    fs.mkdirSync(path.join(opts.out, 'crl'), { recursive: true });
    Object.keys(minted.crls).forEach(function (name) {
      fs.writeFileSync(path.join(opts.out, 'crl', name), minted.crls[name]);
    });
    say(opts, 'Wrote the Root\'s and the Issuing CA\'s CRLs to ' +
              path.join(opts.out, 'crl') + ', named by the certificates at ' +
              opts.crlBase + '.');
  }
  fs.writeFileSync(path.join(opts.out, 'chain.txt'),
    ['These three were generated by tests/tools/pep-credential.js.',
     '',
     'Root CA      ' + root.subject + '   (serial ' + root.serialHex + ')',
     '  issues     ' + issuing.subject + '   (serial ' + issuing.serialHex +
     ')',
     '    issues   ' + leaf.subject + '   (serial ' + leaf.serialHex + ')',
     '',
     'pep.crt is the LEAF followed by the ISSUING CA, which is what the PEP',
     'presents. Only the ROOT was added to the truststore at ' + opts.url,
     '(POST /admin-api/tls/trust/add), so the',
     'mock has to build the path from what arrives to the anchor it holds.',
     'The leaf expires ' + leaf.notAfter + '.',
     ''].join('\n'));
  // 0600 ON THE KEY. It is a throwaway on a test machine and it is still a
  // private key on a shared filesystem; the cost of saying so is one line.
  fs.chmodSync(path.join(opts.out, 'pep.key'), 0o600);
  say(opts, 'Wrote pep.crt (leaf + issuing CA), pep.key and ca.crt to ' +
            opts.out + '.');

  // THE ROOT ALONE. The intermediate travels on the wire with the leaf, so
  // posting it here would be trusting an anchor that does not need to be one —
  // and it would hide exactly the mistake this chain exists to catch, since a
  // PEP that forgot to send its intermediate would still verify.
  const posted = await postAnchor(opts.url, root.pem);
  if (!posted.ok) {
    process.stderr.write('Could not add the Root CA to ' + opts.url +
      '/admin-api/tls/trust/add: ' + (posted.why || ('HTTP ' +
      posted.status + ' ' + String(posted.body).slice(0, 300))) +
      '\nThe certificate files were written, but the mock will not verify them: this credential is ' +
      'useless until the anchor is trusted.\n');
    process.exit(1);
  }
  say(opts, 'The Root CA is in the mock\'s client truststore. That ' +
            'truststore covers the MAIN listener — since 2026-09-06, and ' +
            'since 2026-09-16 there is no other, the 8443 and 9443 listeners ' +
            'having been deleted; see tls/tls_server.js — which is what lets ' +
            'a certificate presented at /xacml/pep/register be verified ' +
            'rather than merely thumbprinted.');

  // THE DN, LAST AND ON STDOUT, so that `$(pep-credential.js --quiet ...)` is
  // the DN and a launcher needs no parsing. Everything else this file says
  // goes to stderr for that reason.
  if (opts.storeOn) {
    const stored = await storeFromCli(opts, leaf.pem);
    if (!stored.ok) {
      process.stderr.write('Could not store the leaf on ' + opts.storeOn +
        ': POST /admin-api/users/add-certificate answered ' +
        (stored.status || stored.why) + ' ' +
        String(stored.body || '').slice(0, 300) + '\nThe anchor is trusted, ' +
        'but the certificate names nobody until it is stored (#1061).\n');
      process.exit(1);
    }
    say(opts, 'The leaf is stored on ' + opts.storeOn + '\'s entry' +
              (opts.realm ? ' in the "' + opts.realm + '" realm' : '') +
              ', which is what makes it that entry\'s identity (#1061).');
  }
  process.stdout.write(leaf.subject + '\n');
  log.debug("Leaving main().");
}

// Guarded so that a test can require this file for `mint()`, `trustAnchor()`,
// `trustRecorded()`, `removeAnchor()`, `forgetAnchors()` and `settleAnchors()`
// (and `useSender()`, `useRetryDelay()`, #1307) without it parsing
// arguments and writing files — the same guard `xacml-pep/pep.js` and
// `common/request_worker.ts` carry, for the same reason.
// ---------------------------------------------------------------------------
// STORE A LEAF ON ITS ENTRY (#1061), from a job.
//
// `api` is the job's own verbs — `{ get(url), post(url, payload) }`, each a
// promise of `{ status, body, text }` — because every job already
// authenticates to /admin-api its own way and this file must not grow a
// second one. `prefix` is '' for the default realm or `/realm/<id>`. The
// entry is created first where `GET /admin-api/users/certificates` says there
// is none (a 400 is that refusal, STS-ADMIN-0898; codes are never sent), with
// the attributes a product-mode realm's attribute policy requires.
// Answers `{ prefix, user, sha256 }` for `forgetStored()`.
// ---------------------------------------------------------------------------
async function storeOnEntry(api, base, prefix, username, leafPem, attributes) {
  log.debug("Entering storeOnEntry(). " + prefix + " " + username);
  const root = String(base || '').replace(/\/+$/, '') + String(prefix || '') +
               '/admin-api/users';
  const listed = await api.get(root + '/certificates?user=' +
                               encodeURIComponent(username));
  if (listed.status !== 200) {
    const made = await api.post(root + '/create', {
      username: username, invent: false,
      attributes: Object.assign({ cn: username, givenName: 'Certificate',
                                  sn: username,
                                  mail: username + '@certificate-holder.test',
                                  displayName: username }, attributes || {})
    });
    if (made.status !== 200) {
      log.debug("Leaving storeOnEntry(). The create was refused.");
      throw new Error('POST ' + prefix + '/admin-api/users/create for ' +
        username + ' answered ' + made.status + ' ' +
        String(made.text || JSON.stringify(made.body)).slice(0, 300) +
        '. An outside certificate is an identity only on an entry that ' +
        'stores it, so there has to be one.');
    }
  }
  const leaf = String(leafPem || '').match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  const stored = await api.post(root + '/add-certificate', {
    user: username, certificate: leaf ? leaf[0] : String(leafPem || '') });
  if (stored.status !== 200 || !stored.body || !stored.body.ok) {
    log.debug("Leaving storeOnEntry(). The store was refused.");
    throw new Error('POST ' + prefix + '/admin-api/users/add-certificate ' +
      'for ' + username + ' answered ' + stored.status + ' ' +
      String(stored.text || JSON.stringify(stored.body)).slice(0, 300) +
      '. Without it the certificate verifies and names nobody (#1061).');
  }
  log.debug("Leaving storeOnEntry(). " + stored.body.sha256);
  return { prefix: String(prefix || ''), user: username,
           sha256: String(stored.body.sha256 || '') };
}

// Takes off what `storeOnEntry()` stored, for a job's cleanup: an entry in a
// realm the run keeps (the default one) must not keep a certificate whose key
// was a temporary file. Failures are logged and answered, never thrown — a
// cleanup that throws would replace the job's own verdict.
async function forgetStored(api, base, list) {
  log.debug("Entering forgetStored(). " + (list || []).length);
  const problems = [];
  for (const one of (list || [])) {
    try {
      const r = await api.post(String(base || '').replace(/\/+$/, '') +
        one.prefix + '/admin-api/users/remove-certificate',
        { user: one.user, sha256: one.sha256 });
      if (r.status !== 200) {
        problems.push(one.user + ': ' + r.status);
      }
    } catch (e) {
      log.debug("Caught in forgetStored(): " + ((e && e.message) || e));
      problems.push(one.user + ': ' + ((e && e.message) || e));
    }
  }
  if (problems.length) {
    log.warn('pep-credential: some stored certificates were not taken off: ' +
             problems.join('; '));
  }
  log.debug("Leaving forgetStored().");
  return problems;
}

// The CLI's `--store-on`, over `send()`: create (a refusal because the entry
// exists is expected and passed over), then store.
async function storeFromCli(opts, leafPem) {
  log.debug("Entering storeFromCli().");
  const prefix = opts.realm ? '/realm/' + opts.realm : '';
  const root = String(opts.url).replace(/\/+$/, '') + prefix +
               '/admin-api/users';
  const token = process.env.STS_ADMIN_API_TOKEN || '';
  const headers = token ? { Authorization: 'Bearer ' + token } : {};
  const user = String(opts.storeOn);
  const made = await send(root + '/create', 'application/json',
    JSON.stringify({ username: user, invent: false,
      attributes: { cn: user, givenName: 'Remote', sn: user,
                    mail: user + '@xacml-remote-pep.test',
                    displayName: user } }), headers, true);
  if (!made.ok) {
    log.info('pep-credential: the create of ' + user + ' answered ' +
             (made.status || made.why) + '; an entry that is already there ' +
             'is the usual reason, and the store below says if not.');
  }
  const leaf = String(leafPem).match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  const stored = await send(root + '/add-certificate', 'application/json',
    JSON.stringify({ user: user, certificate: leaf ? leaf[0] : leafPem }),
    headers, true);
  log.debug("Leaving storeFromCli().");
  return stored;
}

// ---------------------------------------------------------------------------
// --assertion (#1827's follow-up, phase 3): see the header. THE KEY AND THE
// REQUEST ARE MADE IN `utilities/pep-assertion-request.js` since 2026-11-16,
// with the same vendored engine the chain above is: the operator's
// `utilities/register-remote-pep.js` needs them too and runs from the
// service image, which ships no tests/, so the code moved to where both can
// reach it rather than being copied. These two names are re-exported below
// for the jobs that require them from here.
// ---------------------------------------------------------------------------
const assertionRequests = require(path.join(REPO, 'utilities',
                                            'pep-assertion-request.js'));
const ASSERTION_KEY_ALGS = assertionRequests.ASSERTION_KEY_ALGS;
const assertionRequest = assertionRequests.assertionRequest;

// THE ACT, FROM A JOB (`api` is the job's own verbs, as `storeOnEntry()`
// takes them) or from the CLI below. Answers the act's JSON body; throws
// with the status and body when it is refused.
async function issueAssertionCredential(api, base, prefix, name, csrPem,
                                        options) {
  log.debug("Entering issueAssertionCredential(). " + prefix + " " + name);
  const url = String(base || '').replace(/\/+$/, '') + String(prefix || '') +
              '/admin-api/xacml/issue-pep-credential';
  const payload = Object.assign({ name: name, csr: csrPem },
    (options && options.revokePrevious) ? { revokePrevious: true } : {});
  // A REALM'S CERTIFICATE AUTHORITY IS BUILT JUST AFTER realms/create
  // ANSWERS (2026-11-16): a job that creates a realm and issues straight
  // away met "has no certificate authority yet" (STS-PKI-0008) on the first
  // local runs — sts_xacml_remote_pep in memory, sts_fga in single-node —
  // with the branch logged built a second or two later. That refusal, and
  // only that one, is asked again for up to a minute.
  const deadline = Date.now() + 60000;
  let r = await api.post(url, payload);
  while (r.status === 400 && Date.now() < deadline &&
         /no certificate authority yet/.test(String(r.text ||
           JSON.stringify(r.body || {})))) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
    r = await api.post(url, payload);
  }
  if (r.status !== 200 || !r.body || !r.body.ok) {
    log.debug("Leaving issueAssertionCredential(). Refused.");
    throw new Error('POST ' + prefix + '/admin-api/xacml/' +
      'issue-pep-credential for ' + name + ' answered ' + r.status + ' ' +
      String(r.text || JSON.stringify(r.body)).slice(0, 400));
  }
  log.debug("Leaving issueAssertionCredential(). kid=" + r.body.kid);
  return r.body;
}

// The CLI's verbs over `send()`, in the `{ status, body, text }` shape the
// function above takes from a job.
function cliApi() {
  log.debug("Entering cliApi().");
  const token = process.env.STS_ADMIN_API_TOKEN || '';
  const headers = token ? { Authorization: 'Bearer ' + token } : {};
  log.debug("Leaving cliApi().");
  return {
    post: function (url, payload) {
      log.debug("Entering post(). " + url);
      log.debug("Leaving post().");
      return send(url, 'application/json', JSON.stringify(payload), headers,
                   true).then(function (answer) {
        let body = null;
        try {
          body = JSON.parse(String(answer.body || ''));
        } catch (e) {
          log.debug("Caught in cliApi(): " + ((e && e.message) || e));
          body = null;
        }
        return { status: answer.status || 0, body: body,
                 text: String(answer.body || answer.why || '') };
      });
    }
  };
}

async function assertionMain(opts) {
  log.debug("Entering assertionMain().");
  if (!opts.out || (!opts.csrOnly && (!opts.url || !opts.name))) {
    process.stderr.write('--assertion needs --out, and --url and --name ' +
                         'unless --csr-only. --help says what they are.\n');
    process.exit(2);
  }
  fs.mkdirSync(opts.out, { recursive: true });
  const keyFile = path.join(opts.out, 'pep-assertion.key');
  const csrFile = path.join(opts.out, 'pep-assertion.csr');
  let made = null;
  if (opts.reuseKey && fs.existsSync(keyFile) && fs.existsSync(csrFile)) {
    made = { privateKeyPem: fs.readFileSync(keyFile, 'utf8'),
             csrPem: fs.readFileSync(csrFile, 'utf8'), keyAlg: 'as written' };
    say(opts, 'Reusing the key and the request already in ' + opts.out + '.');
  } else {
    made = await assertionRequest({ keyAlg: opts.keyAlg || 'ec-p256',
                                    name: opts.name || '' });
    // 0644 — see the header: the PEP container reads it as another user.
    fs.writeFileSync(keyFile, made.privateKeyPem, { mode: 0o644 });
    fs.chmodSync(keyFile, 0o644);
    fs.writeFileSync(csrFile, made.csrPem, { mode: 0o644 });
    say(opts, 'Generated a ' + made.keyAlg + ' key (' + keyFile + ') and a ' +
              'certificate request signed with it (' + csrFile + '). The ' +
              'key stays here; only the request is sent.');
  }
  if (opts.csrOnly) {
    process.stdout.write('PEP_ASSERTION_KEY=' + keyFile + '\n');
    log.debug("Leaving assertionMain(). The request only.");
    return;
  }
  const prefix = opts.realm ? '/realm/' + opts.realm : '';
  let answer = null;
  try {
    answer = await issueAssertionCredential(cliApi(), opts.url, prefix,
      opts.name, made.csrPem, { revokePrevious: !!opts.revokePrevious });
  } catch (e) {
    log.debug("Caught in assertionMain(): " + ((e && e.message) || e));
    process.stderr.write(String((e && e.message) || e) +
      (process.env.STS_ADMIN_API_TOKEN ? ''
        : ' (no STS_ADMIN_API_TOKEN was set)') + '\nThe key and the ' +
      'request are in ' + opts.out + '; nothing was registered.\n');
    process.exit(1);
  }
  fs.writeFileSync(path.join(opts.out, 'pep-assertion.crt'),
                   String(answer.fullChainPem || answer.certificatePem || ''));
  say(opts, 'The realm certified the key as ' + answer.urn + ' (kid ' +
            answer.kid + ', valid until ' + answer.notAfter + ') and ' +
            'registered it on ' + opts.name + '\'s entry.');
  const env = answer.environment || {};
  process.stdout.write('PEP_ASSERTION_KEY=' + keyFile + '\n' +
                       'PEP_NAME=' + String(env.PEP_NAME || opts.name) +
                       '\n' + 'PEP_CLIENT_ID=' +
                       String(env.PEP_CLIENT_ID || 'sts-remote-pep') + '\n');
  log.debug("Leaving assertionMain().");
}

// ---------------------------------------------------------------------------
// A PEP'S TOKEN, AS THE REMOTE PEP GETS ONE (#1827's follow-up, for the
// protocol jobs). The RFC 7523 self-assertion (`iss` and `sub` the PEP's
// name, `aud` the realm's token endpoint), presented through
// `sts-remote-pep` with an RFC 9449 proof by the SAME key, for one
// audience; and the `Authorization`/`DPoP` pair a call on it carries. What
// `rust/bins/xacml-pep/src/credential.rs` does, in node, so a job can be a
// PEP without a container. Over node's own `fetch`, because the token
// endpoint's `DPoP-Nonce` header is read; a job's trust settings
// (`NODE_EXTRA_CA_CERTS`) apply to it as to every other call it makes.
// ---------------------------------------------------------------------------
function joseOf(privateKeyPem) {
  log.debug("Entering joseOf().");
  const key = crypto.createPrivateKey(privateKeyPem);
  const ec = key.asymmetricKeyType === 'ec';
  const full = crypto.createPublicKey(key).export({ format: 'jwk' });
  const jwk = ec ? { kty: full.kty, crv: full.crv, x: full.x, y: full.y }
                 : { kty: full.kty, n: full.n, e: full.e };
  log.debug("Leaving joseOf().");
  return {
    alg: ec ? 'ES256' : 'RS256',
    jwk: jwk,
    sign: function (input) {
      log.debug("Entering sign().");
      log.debug("Leaving sign().");
      return crypto.sign('sha256', Buffer.from(input),
        ec ? { key: key, dsaEncoding: 'ieee-p1363' } : key)
        .toString('base64url');
    }
  };
}

function compactJws(jose, header, claims) {
  log.debug("Entering compactJws().");
  const input = Buffer.from(JSON.stringify(header)).toString('base64url') +
    '.' + Buffer.from(JSON.stringify(claims)).toString('base64url');
  log.debug("Leaving compactJws().");
  return input + '.' + jose.sign(input);
}

// The `DPoP` proof for one call; `token` adds `ath` (RFC 9449 section 4.2).
function dpopProof(privateKeyPem, method, url, token, nonce) {
  log.debug("Entering dpopProof(). " + method + " " + url);
  const jose = joseOf(privateKeyPem);
  const claims = { jti: crypto.randomBytes(16).toString('hex'), htm: method,
                   htu: String(url).split(/[?#]/)[0],
                   iat: Math.floor(Date.now() / 1000) };
  if (token) {
    claims.ath = crypto.createHash('sha256').update(token)
      .digest('base64url');
  }
  if (nonce) {
    claims.nonce = nonce;
  }
  log.debug("Leaving dpopProof().");
  return compactJws(jose, { typ: 'dpop+jwt', alg: jose.alg, jwk: jose.jwk },
                    claims);
}

// The headers of a call on a DPoP-bound token. `scheme` `Bearer` is the
// refusal a job asserts.
function dpopHeaders(privateKeyPem, method, url, token, scheme) {
  log.debug("Entering dpopHeaders().");
  log.debug("Leaving dpopHeaders().");
  return { Authorization: (scheme || 'DPoP') + ' ' + token,
           DPoP: dpopProof(privateKeyPem, method, url, token) };
}

// The token request. `realmBase` is the service's base with the realm's
// prefix (`https://sts:8081/realm/acme`), `resourcePath` the audience under
// it (`/xacml/pep`). One retry on `use_dpop_nonce`, as the PEP makes.
async function pepAccessToken(realmBase, name, privateKeyPem, scope,
                              resourcePath) {
  log.debug("Entering pepAccessToken(). " + name + " " + scope);
  const base = String(realmBase || '').replace(/\/+$/, '');
  const tokenUrl = base + '/oauth2/token';
  const jose = joseOf(privateKeyPem);
  const now = Math.floor(Date.now() / 1000);
  const ask = function (nonce) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    const form = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: compactJws(jose, { alg: jose.alg, typ: 'JWT' }, {
        iss: name, sub: name, aud: tokenUrl, iat: now, exp: now + 120,
        jti: crypto.randomBytes(16).toString('hex') }),
      client_id: 'sts-remote-pep', scope: scope,
      resource: base + resourcePath }).toString();
    return fetch(tokenUrl, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                 DPoP: dpopProof(privateKeyPem, 'POST', tokenUrl, '',
                                 nonce) },
      body: form }).then(async function (r) {
      const text = await r.text();
      let body = null;
      try {
        body = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in pepAccessToken(): " + ((e && e.message) || e));
        body = null;
      }
      return { status: r.status, body: body, text: text,
               nonce: r.headers.get('dpop-nonce') || '' };
    });
  };
  let answer = await ask('');
  if (answer.status === 400 && answer.body &&
      answer.body.error === 'use_dpop_nonce' && answer.nonce) {
    answer = await ask(answer.nonce);
  }
  log.debug("Leaving pepAccessToken(). " + answer.status);
  return { status: answer.status, body: answer.body, text: answer.text,
           token: (answer.body && answer.body.access_token) || '' };
}

if (require.main === module) {
  main().catch(function (error) {
    process.stderr.write((error && error.stack ? error.stack : String(error)) +
                         '\n');
    process.exit(1);
  });
}

module.exports = { mint: mint, reissue: reissue, trustAnchor: postAnchor,
                   removeAnchor: removeAnchor, forgetAnchors: forgetAnchors,
                   settleAnchors: settleAnchors,
                   recordAnchor: recordAnchor, trustRecorded: trustRecorded,
                   confirmAnchor: confirmAnchor, isConfirmed: isConfirmed,
                   useSender: useSender, useRetryDelay: useRetryDelay,
                   storeOnEntry: storeOnEntry, forgetStored: forgetStored,
                   assertionRequest: assertionRequest,
                   issueAssertionCredential: issueAssertionCredential,
                   ASSERTION_KEY_ALGS: ASSERTION_KEY_ALGS,
                   pepAccessToken: pepAccessToken, dpopHeaders: dpopHeaders,
                   dpopProof: dpopProof,
                   DEFAULT_SUBJECT: DEFAULT_SUBJECT };
