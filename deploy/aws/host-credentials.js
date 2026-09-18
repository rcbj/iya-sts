#!/usr/bin/env node
//
// File: deploy/aws/host-credentials.js
//
// ---------------------------------------------------------------------------
// THE HOST'S AWS SESSION, SERVED TO THE TERRAFORM CONTAINER AS IT REFRESHES
// (2026-09-18).
//
// terraform-local.sh used to resolve credentials ONCE, with `aws configure
// export-credentials`, and hand the container a snapshot. An `aws login`
// session's credentials last about fifteen minutes and the CLI refreshes them
// on the host, but a snapshot does not refresh: every apply longer than the
// snapshot died part-way through with an expired token, left the S3 state
// LOCKED, and twice needed a force-unlock and imports to recover.
//
// So the launcher starts this instead: a listener on 127.0.0.1 that answers
// in the shape of the ECS container credentials endpoint — the AWS SDKs'
// `AWS_CONTAINER_CREDENTIALS_FULL_URI` provider, which the Terraform AWS
// provider, its S3 backend and the aws CLI in the container all read, and
// which they ask AGAIN before the credentials it gave them expire. Each ask
// is answered from `aws configure export-credentials` on the host, which is
// what does the refreshing.
//
// Three rules keep it from being a way to take somebody's credentials:
//   * it binds 127.0.0.1 only, on a port the kernel chooses, and the SDKs
//     accept plain http for a loopback address and nothing else;
//   * every request must carry the random token the launcher gave it (the
//     SDK sends `AWS_CONTAINER_AUTHORIZATION_TOKEN` as `Authorization`), and
//     anything else is a 403 with no body;
//   * it prints its port on the first line of stdout and nothing else there,
//     and it never logs a credential.
//
// Usage (the launcher's):  node host-credentials.js <token-file>
// It exits when its parent does (stdin closes), so a killed launcher does not
// leave it behind.
// ---------------------------------------------------------------------------
'use strict';

const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const { execFile } = require('child_process');

// A console-backed logger of bunyan's shape: this runs on the HOST, beside a
// checkout whose node_modules is not built there (the service runs from an
// image), so bunyan may not be loadable. The same arrangement as
// mgmt-api/admin_api_explorer.js. Debug lines only with HOST_CREDENTIALS_DEBUG.
const log = {
  debug: function (m) {
    if (process.env.HOST_CREDENTIALS_DEBUG) {
      console.error('host-credentials: ' + m);
    }
  },
  error: function (m) {
    console.error('host-credentials: ' + m);
  }
};

// Refetched once fewer than this many milliseconds remain, so an SDK asking
// shortly before expiry is never handed the credentials it is replacing.
const REFRESH_MARGIN_MS = 5 * 60 * 1000;

let cached = null;

function exportCredentials() {
  log.debug("Entering exportCredentials().");
  return new Promise(function (resolve, reject) {
    execFile('aws', ['configure', 'export-credentials', '--format', 'process'],
      { timeout: 60000 }, function (err, stdout) {
        if (err) {
          log.debug("Leaving exportCredentials(). The CLI failed.");
          reject(err);
          return;
        }
        let parsed;
        try {
          parsed = JSON.parse(stdout);
        } catch (e) {
          log.debug("Caught in exportCredentials(): " +
                    ((e && e.message) || e));
          reject(new Error('the aws CLI did not answer JSON'));
          return;
        }
        log.debug("Leaving exportCredentials().");
        resolve(parsed);
      });
  });
}

async function current() {
  log.debug("Entering current().");
  const fresh = cached && cached.Expiration &&
    Date.parse(cached.Expiration) - Date.now() > REFRESH_MARGIN_MS;
  if (!fresh) {
    cached = await exportCredentials();
  }
  log.debug("Leaving current().");
  return cached;
}

function sameToken(given, expected) {
  log.debug("Entering sameToken().");
  const a = Buffer.from(String(given || ''));
  const b = Buffer.from(expected);
  const same = a.length === b.length && crypto.timingSafeEqual(a, b);
  log.debug("Leaving sameToken().");
  return same;
}

function main() {
  log.debug("Entering main().");
  const tokenFile = process.argv[2];
  if (!tokenFile) {
    log.error('usage: host-credentials.js <token-file>');
    log.debug("Leaving main(). No token file.");
    process.exit(2);
  }
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  const server = http.createServer(function (req, res) {
    if (!sameToken(req.headers.authorization, token)) {
      res.writeHead(403);
      res.end();
      return;
    }
    current().then(function (c) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        AccessKeyId: c.AccessKeyId,
        SecretAccessKey: c.SecretAccessKey,
        Token: c.SessionToken,
        Expiration: c.Expiration
      }));
    }, function (e) {
      log.error('could not resolve the host session: ' +
                ((e && e.message) || e));
      res.writeHead(500);
      res.end();
    });
  });
  server.listen(0, '127.0.0.1', function () {
    process.stdout.write(server.address().port + '\n');
  });
  // The launcher holds our stdin; when it goes, so do we. AND ONLY THEN: an
  // interrupt aimed at the launcher reaches its whole process group, this
  // process included, and terraform is still shutting down cleanly at that
  // moment — writing state and releasing the lock — on the credentials this
  // serves. Dying on the interrupt left it with "No valid credential sources
  // found" halfway through exactly that (the first test of the relay).
  process.on('SIGINT', function () {
    log.debug('SIGINT ignored; exiting when the launcher does.');
  });
  process.on('SIGTERM', function () {
    log.debug('SIGTERM ignored; exiting when the launcher does.');
  });
  process.stdin.resume();
  process.stdin.on('end', function () {
    process.exit(0);
  });
  log.debug("Leaving main().");
}

main();
