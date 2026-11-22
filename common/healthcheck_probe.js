// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: common/healthcheck_probe.js
//
// ===========================================================================
// THE CONTAINER'S HEALTHCHECK, AND IT VERIFIES THE CERTIFICATE (2026-11-20).
//
//   node /usr/src/sts/common/healthcheck_probe.js
//
// is what every compose file and the ECS task definition run. It answers 0
// when the main port's `GET /healthcheck` is a 200 over a connection whose
// certificate VERIFIED — chain and name — and 1 otherwise. Until today the
// probe was a `node -e` one-liner with `rejectUnauthorized: false`, on the
// argument that liveness is the question and nothing can hold an anchor for
// a certificate regenerated on every start. The first half is still true;
// the second is not: the service publishes its own Root on the plain-HTTP
// revocation listener (`pki.httpPort`, 8082, `/pki/ca/service/root.cer`),
// which `server.js` binds BEFORE the main port, on the same loopback.
//
// THE ANCHORS, in this order, all of them at once:
//   * `STS_HEALTHCHECK_CA_FILE`, when an operator names one (an operator's
//     own `tls.certificateFile` under a private CA);
//   * the service Root, read from the revocation listener — a missing
//     listener (`pki.httpPort` 0) is not an error here, it only adds none;
//   * node's default roots (an operator's certificate from a public CA).
// A certificate none of them verifies is an UNHEALTHY container, which is
// the point: a listener presenting a chain that does not reach the Root the
// service publishes is a service every client of it refuses, and a probe
// that skipped the check reported it healthy.
//
// THE NAME. The probe dials 127.0.0.1 and checks the certificate for
// `STS_HEALTHCHECK_NAME`, else the first of `STS_TLS_HOSTNAMES`, else
// `localhost` — the first of `tls.hostnames`' default, which the service's
// own certificate always carries. An operator's certificate for another
// name sets one of the two.
//
// PLAIN HTTP when the main port is: the scheme is decided as `config.js`
// derives `global.https` (STS_HTTPS, else RFC 9700 or OAuth 2.1 mode).
//
// IT REQUIRES NOTHING OF THIS SERVICE and loads no logger: it runs every
// few seconds in its own process, and a probe that loaded the configuration
// would cost a start-up's worth of work each time. For the same reason it
// carries no Entering/Leaving lines (code style's exemption for a process
// with no logger, as `config_file.js` argues), and says what failed on
// stderr, which docker and ECS keep with the check's result.
// ===========================================================================
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const tls = require('tls');
const nodeCrypto = require('crypto');

const TIMEOUT_MS = 4000;
const env = process.env;
const PORT = Number(env.STS_PORT || 8081);
const PKI_PORT = Number(env.PKI_HTTP_PORT || 8082);
const SECURE = env.STS_HTTPS === 'true' ||
  (env.STS_HTTPS === undefined && (env.STS_OAUTH2_RFC9700 === 'true' ||
                                   env.STS_OAUTH2_OAUTH21 === 'true'));
const NAME = env.STS_HEALTHCHECK_NAME ||
  String(env.STS_TLS_HOSTNAMES || '').split(',')
    .map(function (one) {
      return one.trim();
    }).filter(Boolean)[0] || 'localhost';

/**
 * Ends the probe with `code`, saying why on stderr when it failed.
 *
 * @param {number} code - 0 healthy, 1 not
 * @param {string} [why] - what failed
 */
function finish(code, why) {
  if (why) {
    process.stderr.write('healthcheck: ' + why + '\n');
  }
  process.exit(code);
}

/**
 * The service Root from the loopback revocation listener, as PEM, or ''
 * when that listener does not answer one.
 *
 * @returns {Promise<string>} the PEM, or ''
 */
function serviceRoot() {
  return new Promise(function (resolve) {
    if (!(PKI_PORT > 0)) {
      resolve('');
      return;
    }
    const req = http.get({ host: '127.0.0.1', port: PKI_PORT,
      path: '/pki/ca/service/root.cer', timeout: TIMEOUT_MS },
    function (res) {
      const chunks = [];
      res.on('data', function (c) {
        chunks.push(c);
      });
      res.on('end', function () {
        if (res.statusCode !== 200) {
          resolve('');
          return;
        }
        try {
          resolve(new nodeCrypto.X509Certificate(Buffer.concat(chunks))
            .toString());
        } catch (e) {
          // Not a certificate: no anchor from here, and the verify below
          // says so if nothing else covers the listener.
          process.stderr.write('healthcheck: the revocation listener ' +
            'answered something that is not a certificate (' +
            ((e && e.message) || e) + ')\n');
          resolve('');
        }
      });
    });
    req.on('timeout', function () {
      req.destroy(new Error('timed out'));
    });
    req.on('error', function (e) {
      // No listener there (pki.httpPort 0, or not bound yet): no anchor
      // from it, which is not by itself unhealthy.
      process.stderr.write('healthcheck: no service Root from 127.0.0.1:' +
        PKI_PORT + ' (' + ((e && e.message) || e) + ')\n');
      resolve('');
    });
  });
}

/**
 * The anchors the main port's certificate is verified against.
 *
 * @returns {Promise<string[]>} PEM certificates
 */
async function anchors() {
  const out = tls.rootCertificates.slice();
  if (env.STS_HEALTHCHECK_CA_FILE) {
    out.push(fs.readFileSync(env.STS_HEALTHCHECK_CA_FILE, 'utf8'));
  }
  const root = await serviceRoot();
  if (root) {
    out.push(root);
  }
  return out;
}

async function main() {
  const options = { host: '127.0.0.1', port: PORT, path: '/healthcheck',
                    timeout: TIMEOUT_MS, agent: false };
  if (SECURE) {
    Object.assign(options, { ca: await anchors(), servername: NAME });
  }
  const req = (SECURE ? https : http).get(options, function (res) {
    res.resume();
    finish(res.statusCode === 200 ? 0 : 1,
           res.statusCode === 200 ? '' : '/healthcheck answered ' +
             res.statusCode);
  });
  req.on('timeout', function () {
    req.destroy(new Error('no answer within ' + TIMEOUT_MS + ' ms'));
  });
  req.on('error', function (e) {
    finish(1, (SECURE ? 'https' : 'http') + '://127.0.0.1:' + PORT +
           '/healthcheck' + (SECURE ? ' as ' + NAME : '') +
           ': ' + (((e && /** @type {any} */ (e).code) || '') + ' ' +
           ((e && e.message) || e)).trim());
  });
}

main().catch(function (e) {
  finish(1, String((e && e.message) || e));
});
