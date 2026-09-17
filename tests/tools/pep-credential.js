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
// admits a foreign authority is the TRUSTSTORE — `POST /tls/trust` — which
// holds no foreign anchor until one is added at runtime, precisely because
// the CA in question does not exist anywhere until somebody builds it
// (`tls/CLAUDE.md`).
//
// The parent project's `tests/pki_mutual_tls.js` has done exactly this since
// long before the remote PEP existed: it builds a Root CA and an Issuing CA in
// a browser, issues a client certificate from them, POSTs the CA to
// `/tls/trust`, and then reads back which chain the mock built out of what was
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
// `common/vendored/x509.js` is the debugger's own PKI code, byte-identical,
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
//
// ---------------------------------------------------------------------------
// USAGE
//
//   node tests/tools/pep-credential.js --url=https://localhost:8081 \
//        --out=/tmp/pep-certs --subject="CN=remote-pep-1,OU=remote-peps,O=mock-sts"
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
//
// It prints the leaf's DN as its LAST line, so `$(... --quiet)` is the DN and a
// launcher needs no parsing.
//
// **`MOCK_STS_DIR` RELOCATES THE ENGINE**, defaulting to two directories up.
// The containerized launcher runs this file with the repository mounted into an
// image whose own copy lives elsewhere, which is the same override
// `tests/vendored/module_paths.js` takes and for the same reason.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pep-credential',
  level: process.env.LOG_LEVEL || 'info' });

const REPO = process.env.MOCK_STS_DIR ||
             path.join(__dirname, '..', '..');
const x509 = require(path.join(REPO, 'common', 'vendored', 'x509.js'));
const keys = require(path.join(REPO, 'common', 'vendored', 'key_material.js'));

const DEFAULT_SUBJECT = 'CN=remote-pep-1,OU=remote-peps,O=mock-sts';

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
                 quiet: false };
  argv.forEach(function (arg) {
    const eq = arg.indexOf('=');
    const name = eq > 0 ? arg.slice(0, eq) : arg;
    const value = eq > 0 ? arg.slice(eq + 1) : '';
    if (name === '--url') { opts.url = value; }
    else if (name === '--out') { opts.out = value; }
    else if (name === '--subject') { opts.subject = value; }
    else if (name === '--years') { opts.years = parseInt(value, 10) || 1; }
    else if (name === '--quiet') { opts.quiet = true; }
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
function postAnchor(url, pem) {
  log.debug("Entering postAnchor().");
  log.debug("Leaving postAnchor().");
  return new Promise(function (resolve) {
    let target;
    try {
      target = new URL(url.replace(/\/+$/, '') + '/tls/trust');
    } catch (error) {
      log.debug("Caught in a callback in postAnchor(): " +
                ((error && error.message) || error));
      resolve({ ok: false, why: '--url is not a URL: ' + url });
      return;
    }
    const insecure = target.protocol === 'http:';
    const transport = insecure ? http : https;
    const request = transport.request({
      method: 'POST',
      hostname: target.hostname,
      port: target.port || (insecure ? 80 : 443),
      path: target.pathname,
      headers: { 'Content-Type': 'text/plain',
                 'Content-Length': Buffer.byteLength(pem) },
      timeout: 15000,
      rejectUnauthorized: false
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
      resolve({ ok: false, why: error.message });
    });
    request.end(pem);
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
// without writing files — `tests/vendored/sts_xacml_endpoints.js` needs a
// trusted client certificate to drive the three PEP endpoints at all now that
// they are gated, and a second implementation of this in that file would be a
// second reading of how a chain is built.
// ---------------------------------------------------------------------------
async function mint(opts) {
  log.debug("Entering mint().");
  const options = opts || {};
  const root = await issue({
    subject: options.rootSubject || 'CN=mock-sts test Root CA,O=mock-sts tests',
    ca: true, pathLen: 1, years: 10
  });
  const issuing = await issue({
    subject: options.issuingSubject ||
             'CN=mock-sts test Issuing CA,O=mock-sts tests',
    ca: true, pathLen: 0, years: 5,
    issuer: { certificatePem: root.pem, privateKeyPem: root.privateKeyPem,
              keyAlg: 'rsa-2048' }
  });
  const leaf = await issue({
    subject: options.subject || DEFAULT_SUBJECT,
    years: options.years || 1,
    issuer: { certificatePem: issuing.pem,
              privateKeyPem: issuing.privateKeyPem, keyAlg: 'rsa-2048' }
  });
  log.debug("Leaving mint().");
  return {
    root: root, issuing: issuing, leaf: leaf,
    // WHAT A TLS CLIENT NEEDS, spelt the way node's `cert`/`key` options take
    // it: the leaf followed by the intermediate, because node sends every
    // certificate in `cert` and the service holds only the root.
    certPem: leaf.pem + issuing.pem,
    keyPem: leaf.privateKeyPem,
    anchorPem: root.pem,
    subject: leaf.subject
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
            '/common/vendored/x509.js ' +
            '— the same engine spiffe/spiffe_ca.ts issues X509-SVIDs with.');

  const minted = await mint({ subject: opts.subject, years: opts.years });
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
  fs.writeFileSync(path.join(opts.out, 'chain.txt'),
    ['These three were generated by tests/tools/pep-credential.js.',
     '',
     'Root CA      ' + root.subject + '   (serial ' + root.serialHex + ')',
     '  issues     ' + issuing.subject + '   (serial ' + issuing.serialHex +
     ')',
     '    issues   ' + leaf.subject + '   (serial ' + leaf.serialHex + ')',
     '',
     'pep.crt is the LEAF followed by the ISSUING CA, which is what the PEP',
     'presents. Only the ROOT was POSTed to ' + opts.url + '/tls/trust, so the',
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
      '/tls/trust: ' + (posted.why || ('HTTP ' + posted.status + ' ' +
      String(posted.body).slice(0, 300))) + '\nThe certificate files were ' +
      'written, but the mock will not verify them: this credential is ' +
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
  process.stdout.write(leaf.subject + '\n');
  log.debug("Leaving main().");
}

// Guarded so that a test can require this file for `mint()` and `trustAnchor()`
// without it parsing arguments and writing files — the same guard
// `xacml-pep/pep.js` and `common/worker.js` carry, for the same reason.
if (require.main === module) {
  main().catch(function (error) {
    process.stderr.write((error && error.stack ? error.stack : String(error)) +
                         '\n');
    process.exit(1);
  });
}

module.exports = { mint: mint, trustAnchor: postAnchor,
                   DEFAULT_SUBJECT: DEFAULT_SUBJECT };
