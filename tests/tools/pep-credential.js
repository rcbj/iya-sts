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
// one and tells the mock to trust the authority behind it. Both launchers run
// it after the service is up and before the PEP container starts, and then
// mount what it wrote.
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
//   --years     the leaf's life. Default 1.
//   --quiet     only the DN on stdout, for a launcher to capture.
//   --crl-base  where the Issuing CA's and the leaf's CRLs will be served
//               (#174): the certificates name <crl-base>/root.crl and
//               <crl-base>/issuing.crl, and both lists are written to
//               <out>/crl/ for that server. Without it no certificate names
//               a list, and a product-mode service refuses the chain
//               (STS-PKI-0190) — which is what the launchers pass it for.
//
//   --store-on  a username (#1061): after the anchor, the leaf is STORED on
//               that person's entry (created first if absent), through
//               POST /admin-api/users/add-certificate. Needs --realm when
//               the entry is not in the default realm, and the realm must
//               already exist.
//   --realm     the realm --store-on writes in. Default: the default realm.
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
// calls this file the space way — both launchers pass `=`, `docs/remote-pep.md`
// passes `=`, and the tests that want a certificate `require()` this file for
// `mint()` and never reach a command line at all — so accepting the space
// form would have been a behaviour change made to rescue a comment, in the one
// directory whose rule is that it takes no dependency and stays small.
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
    else if (name === '--years') { opts.years = parseInt(value, 10) || 1; }
    else if (name === '--quiet') { opts.quiet = true; }
    else if (name === '--store-on') { opts.storeOn = value; }
    else if (name === '--realm') { opts.realm = value; }
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
  return send(base + '/admin-api/tls/trust/add', 'application/json',
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
// REMOVE AN ANCHOR THIS PROCESS ADDED (#335).
//
// The client truststore is service-wide and holds 32. A job that posts a
// suite CA removes it when the job finishes, pass or fail. The command-line
// `main()` does not: the remote PEP needs that anchor for the rest of the
// run, and `deploy/aws/reset-environment.js` spares it by fingerprint.
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
  log.debug("Leaving removeAnchor().");
  return send(base + '/admin-api/tls/trust/remove', 'application/json',
    JSON.stringify({ fingerprint: fingerprint }),
    token ? { Authorization: 'Bearer ' + token } : {}, true)
    .then(function (answer) {
      if (!answer.ok) {
        answer.why = 'POST /admin-api/tls/trust/remove answered ' +
          (answer.status || answer.why) + ' ' +
          String(answer.body || '').slice(0, 200) +
          (token ? '' : ' (no STS_ADMIN_API_TOKEN was set)');
      }
      return answer;
    });
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
async function issue(spec) {
  log.debug("Entering issue().");
  const pair = await keys.generateKeyPair('rsa-2048');
  const now = new Date();
  const until = new Date(now.getTime() +
                         (spec.years || 1) * 365 * 24 * 3600 * 1000);
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
           publicKeyPem: pair.publicPem, subject: spec.subject,
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
    crl: issuingList ? issuingList.url : '',
    issuer: { certificatePem: issuing.pem,
              privateKeyPem: issuing.privateKeyPem, keyAlg: 'rsa-2048' }
  });
  let crls = null;
  if (host) {
    await rootList.publish(root);
    await issuingList.publish(issuing);
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
    // directory (`xacml-pep/pep.js`).
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
// `removeAnchor()`, `forgetAnchors()` and `settleAnchors()` without it parsing
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

if (require.main === module) {
  main().catch(function (error) {
    process.stderr.write((error && error.stack ? error.stack : String(error)) +
                         '\n');
    process.exit(1);
  });
}

module.exports = { mint: mint, trustAnchor: postAnchor,
                   removeAnchor: removeAnchor, forgetAnchors: forgetAnchors,
                   settleAnchors: settleAnchors,
                   storeOnEntry: storeOnEntry, forgetStored: forgetStored,
                   DEFAULT_SUBJECT: DEFAULT_SUBJECT };
