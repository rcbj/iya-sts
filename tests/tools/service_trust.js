// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/service_trust.js
//
// ===========================================================================
// THE TRUSTSTORE A JOB VERIFIES THE RUNNING SERVICE AGAINST (2026-11-20).
//
// `tools/trust.js` fetches the running service's chain — its listener leaf,
// the Issuing CA and Intermediate above it, and the service Root — once the
// service answers, and `run-report.js` writes it to the run's report
// directory and hands every protocol job its path as `NODE_EXTRA_CA_CERTS`
// (re-read before every job, because `build-root` replaces it). That is the
// only moment the anchor can be learned: in development mode the Root is
// regenerated on every start.
//
// Until today some jobs dialled the service with `rejectUnauthorized: false`
// anyway — every raw `tls.connect()` and `https.request()` that needed an
// option of its own (a client certificate, an ALPN list, a TLS version) —
// and so verified nothing, while `fetch()` beside them verified everything.
// CodeQL counted thirty-seven of them. This module is what they use instead:
//
//   ca()           the bundle's certificates, as PEM strings, read from the
//                  file NOW (the runner rewrites it between jobs);
//   roots()        the self-signed ones among them: the service Root, which
//                  anchors every chain this service issues — the listener's
//                  AND its signing keys' (`/pki/chain/...`, `x5c`), because
//                  there is one Root per service and every realm's
//                  Intermediate is under it;
//   trustedCa()    node's default roots plus the bundle: what `ca:` of a
//                  raw connection to the service is set to;
//   isUntrusted(e) whether a handshake error is THIS client refusing the
//                  server's certificate — so a job asserting a refusal
//                  cannot pass on a stale anchor;
//   serviceRoot(b) the Root itself, fetched from `/pki/ca/service/root.cer`
//                  (verified, on an https service): the anchor a job's own
//                  server verifies a client certificate the SERVICE
//                  presents against, in either scheme;
//   tlsOptions(o)  `o` with `ca` set to the default roots plus the bundle,
//                  so a handshake is VERIFIED — chain and host name — and
//                  a target behind a publicly-trusted front (an AWS target's
//                  load balancer) verifies too, exactly as `fetch()` with
//                  `NODE_EXTRA_CA_CERTS` does.
//
// **WHY `ca` EXPLICITLY, WHEN NODE_EXTRA_CA_CERTS ALREADY REACHES THE DEFAULT
// STORE.** Three reasons. The RUNNER has no NODE_EXTRA_CA_CERTS (node reads
// it at start, and the runner fetched the chain after it started), so its
// own calls to the service — a token, a realm removed, a cluster restart —
// can only verify with `ca` given (`useBundle()`). The default store is
// fixed when a child starts, so a job that rotates the chain itself verifies
// the NEW one only through `refresh(base)`, which re-reads it over a
// connection verified against the old. And a truststore a reader can SEE in
// the call is the claim this module exists to make.
//
// **NO BUNDLE ON AN HTTPS TARGET IS AN ERROR, NOT A FALL BACK TO NOT
// VERIFYING.** `bundlePath()` names the runner's own (`useBundle()`), then
// `NODE_EXTRA_CA_CERTS`, then `STS_TRUST_BUNDLE`; a job or tool started by
// hand sets one of the two variables to the PEM
// `curl -k https://HOST/tls/server-certificate` printed (that is the same
// bootstrap `tools/trust.js` makes, and the only place one is made). An
// empty truststore would refuse every handshake with a message naming
// OpenSSL rather than this file, so `ca()` says which variable is missing.
// ===========================================================================

const fs = require('fs');
const https = require('https');
const nodeCrypto = require('crypto');
const tls = require('tls');

const log = require('bunyan').createLogger({ name: 'service_trust',
  level: process.env.LOG_LEVEL || 'info' });

// The path tools/trust.js serves the bundle at, beside the listener.
const CERTIFICATE_PATH = '/tls/server-certificate';
const PEM_BLOCK =
  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

// A bundle refresh() fetched, which then wins over the file.
let refreshed = null;
// The file the RUNNER's own process reads (useBundle()): node reads
// NODE_EXTRA_CA_CERTS only at start, so the runner cannot have one, and
// putting the path in its environment would hand it to every job beside
// the one the job is given.
let used = '';

/**
 * The file the runner wrote the service's chain to: the one useBundle()
 * named in this process, else the job's `NODE_EXTRA_CA_CERTS`, else
 * `STS_TRUST_BUNDLE` (a hand run).
 *
 * @returns the path, or '' when none names one
 */
function bundlePath() {
  log.debug('Entering bundlePath().');
  log.debug('Leaving bundlePath().');
  return used || process.env.NODE_EXTRA_CA_CERTS ||
    process.env.STS_TRUST_BUNDLE || '';
}

/**
 * Names the bundle THIS process verifies the service against: what the
 * runner calls once tools/trust.js has written it, for its own calls to
 * the service (a token, a realm removed, a cluster restart). The path does
 * not change when the runner rewrites the file, and `ca()` reads it at
 * every call, so a rotation is picked up without another call.
 *
 * @param file - the PEM file, or '' to forget it
 */
function useBundle(file) {
  log.debug('Entering useBundle().');
  used = String(file || '');
  log.debug('Leaving useBundle().');
}

/**
 * Splits PEM text into its certificate blocks.
 *
 * @param text - PEM, any number of certificates
 * @returns the blocks, each ending in a newline
 */
function blocksOf(text) {
  log.debug('Entering blocksOf().');
  const found = String(text || '').match(PEM_BLOCK) || [];
  log.debug('Leaving blocksOf(). n=' + found.length);
  return found.map(function (b) {
    return b + '\n';
  });
}

/**
 * The service's chain, as PEM certificates: the listener leaf (or each
 * node's, in the cluster mode), the CAs above it and the Root.
 *
 * @returns an array of PEM strings, never empty
 * @throws when no bundle is configured or it holds no certificate
 */
function ca() {
  log.debug('Entering ca().');
  if (refreshed) {
    log.debug('Leaving ca(). Refreshed in this job.');
    return refreshed.slice();
  }
  const where = bundlePath();
  if (!where) {
    log.debug('Leaving ca(). No bundle.');
    throw new Error('service_trust: no truststore for the service. The ' +
      'runner sets NODE_EXTRA_CA_CERTS to the chain it fetched from ' +
      CERTIFICATE_PATH + '; a job started by hand sets STS_TRUST_BUNDLE ' +
      'to that PEM. Nothing here dials the service unverified.');
  }
  const blocks = blocksOf(fs.readFileSync(where, 'utf8'));
  if (blocks.length === 0) {
    log.debug('Leaving ca(). Empty bundle.');
    throw new Error('service_trust: ' + where + ' holds no certificate');
  }
  log.debug('Leaving ca(). n=' + blocks.length);
  return blocks;
}

/**
 * The self-signed certificates of the bundle: the service Root, which
 * anchors both the listener's chain and every signing key's.
 *
 * @returns an array of PEM strings
 */
function roots() {
  log.debug('Entering roots().');
  const out = ca().filter(function (pem) {
    const cert = new nodeCrypto.X509Certificate(pem);
    return cert.subject === cert.issuer && cert.verify(cert.publicKey);
  });
  log.debug('Leaving roots(). n=' + out.length);
  return out;
}

/**
 * The truststore to verify the service against: node's default roots and the
 * service's chain. What `ca:` of a raw `tls.connect()` or `https.request()`
 * dialling the service is set to.
 *
 * @returns an array of PEM strings
 */
function trustedCa() {
  log.debug('Entering trustedCa().');
  log.debug('Leaving trustedCa().');
  return tls.rootCertificates.concat(ca());
}

/**
 * The service Root, as PEM, from `/pki/ca/service/root.cer` (the
 * `caIssuers` address every chain this service issues names). Fetched with
 * the global `fetch()`, so over https it is verified against the bundle the
 * runner handed this process; over plain http (`STS_HTTPS=false`) it is the
 * only anchor there is, and the one a job verifies a CLIENT certificate the
 * service presents against — the listener's chain, a federation
 * relationship's client certificate and every signing key's chain are all
 * under it.
 *
 * @param base - the service's base URL
 * @returns a promise of the Root's PEM
 */
async function serviceRoot(base) {
  log.debug('Entering serviceRoot().');
  const answer = await fetch(new URL('/pki/ca/service/root.cer', base));
  if (answer.status !== 200) {
    log.debug('Leaving serviceRoot(). ' + answer.status);
    throw new Error('/pki/ca/service/root.cer answered ' + answer.status);
  }
  const der = Buffer.from(await answer.arrayBuffer());
  const pem = new nodeCrypto.X509Certificate(der).toString();
  log.debug('Leaving serviceRoot().');
  return pem;
}

/**
 * Options for `tls.connect()`, `https.request()` or `http2.connect()` that
 * verify the service: `extra` with `ca` set to the default roots and the
 * service's chain. A `ca` already in `extra` is kept and the service's
 * chain added to it.
 *
 * @param extra - the caller's own options (servername, cert, key, ALPN...)
 * @returns a new options object
 */
function tlsOptions(extra) {
  log.debug('Entering tlsOptions().');
  const own = extra && extra.ca ? [].concat(extra.ca) : [];
  const out = Object.assign({}, extra || {}, {
    ca: trustedCa().concat(own)
  });
  log.debug('Leaving tlsOptions().');
  return out;
}

/**
 * Re-reads the service's chain from `base` over a connection verified
 * against the chain held now, for a job that rotates it itself. Every later
 * `ca()` and `tlsOptions()` answer the new one.
 *
 * @param base - the service's base URL
 * @returns a promise of the new PEM array
 */
function refresh(base) {
  log.debug('Entering refresh().');
  const target = new URL(CERTIFICATE_PATH, base);
  log.debug('Leaving refresh().');
  return new Promise(function (resolve, reject) {
    const req = https.get(target, tlsOptions({ agent: false,
      timeout: 15000 }), function (res) {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', function (c) {
        body += c;
      });
      res.on('end', function () {
        const blocks = blocksOf(body);
        if (res.statusCode !== 200 || blocks.length === 0) {
          reject(new Error(CERTIFICATE_PATH + ' answered ' + res.statusCode +
                           ' with ' + blocks.length + ' certificate(s)'));
          return;
        }
        refreshed = blocks;
        resolve(blocks.slice());
      });
    });
    req.on('timeout', function () {
      req.destroy(new Error('timed out fetching ' + CERTIFICATE_PATH));
    });
    req.on('error', reject);
  });
}

// The codes node and OpenSSL give a handshake that failed VERIFICATION, as
// against one the server refused. A job whose claim is "this handshake is
// refused" uses it, so an anchor gone stale is a failed job and never a
// refusal passing for the one it asserts.
const UNTRUSTED = /CERT|SELF_SIGNED|UNABLE_TO_GET_ISSUER|UNABLE_TO_VERIFY|ALTNAME/;

/**
 * Whether a TLS error is this client refusing the SERVER's certificate.
 *
 * @param error - what a socket's `error` event carried
 * @returns true when the chain or the name did not verify
 */
function isUntrusted(error) {
  log.debug('Entering isUntrusted().');
  const code = String((error && error.code) || '');
  log.debug('Leaving isUntrusted().');
  return UNTRUSTED.test(code) &&
    !/^ERR_SSL_TLSV1_ALERT|^ERR_SSL_SSLV3_ALERT/.test(code);
}

/**
 * Forgets a bundle refresh() fetched, so the file is read again.
 */
function forgetRefresh() {
  log.debug('Entering forgetRefresh().');
  refreshed = null;
  log.debug('Leaving forgetRefresh().');
}

module.exports = {
  CERTIFICATE_PATH: CERTIFICATE_PATH,
  bundlePath: bundlePath,
  useBundle: useBundle,
  blocksOf: blocksOf,
  ca: ca,
  trustedCa: trustedCa,
  roots: roots,
  serviceRoot: serviceRoot,
  tlsOptions: tlsOptions,
  refresh: refresh,
  isUntrusted: isUntrusted,
  forgetRefresh: forgetRefresh
};
