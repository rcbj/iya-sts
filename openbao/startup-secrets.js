// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openbao/startup-secrets.js
//
// ===========================================================================
// THE START-UP SECRETS, TAKEN ONCE, AS ROOT, BEFORE THE SERVICE STARTS (#254).
//
// The compose stacks' `sts` command runs this as ROOT, before it drops to uid
// 10001 and execs node. It:
//
//   1. reads this node's wrapping token — `<node>.wrap` in
//      `STS_BAO_STARTUP_DIR`, written 0600 by `openbao/seed.js` — and DELETES
//      the file before using it, so the token is gone from disk whatever
//      happens next;
//   2. unwraps it (`sys/wrapping/unwrap`). A wrapping token is single-use and
//      short-lived, so a refusal means it was unwrapped already — somebody
//      else took the secret — or it outlived `STS_BAO_STARTUP_WRAP_TTL`.
//      Either way the node does NOT start (exit 1): the first is the one
//      event this whole arrangement exists to make visible;
//   3. reads `secret/sts-admin` with the token it unwrapped, and revokes that
//      token;
//   4. writes each value it found to a file of its own in
//      `STS_STARTUP_SECRETS_DIR` (a tmpfs), 0400 and owned by the service,
//      and prints `export <ENV>_FILE=<path>` for each on stdout — paths only,
//      never a value — for the command to `eval`. The service reads each file
//      once and deletes it (`common/delivered_secrets.ts`).
//
// No file at all is not a refusal: a node restarted without a seeder run
// (`docker compose restart` rather than `up`) has nothing to unwrap, and it
// starts without the start-up secrets — the management API client then gets a
// secret minted at start, and an operator gets in through an application of
// their own (`docs/management-api.md`). It says so on stderr.
//
// WHY A SCRIPT RUN AS ROOT, AND NOT THE SERVICE READING THE STORE ITSELF: the
// service seeds its management API client as it LOADS, before anything
// asynchronous can run; and the wrapping token is then never readable by the
// service's own user at all — not on disk, not in its environment.
//
// Node's own `https`, like the seeder: the image has no Vault CLI.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const https = require('https');

// To stderr: stdout is what the command evaluates.
const log = require('bunyan').createLogger({ name: 'sts-startup-secrets',
  level: process.env.LOG_LEVEL || 'info', stream: process.stderr });

const ADDR = process.env.STS_BAO_ADDR || process.env.STS_KEYS_KEK_VAULT ||
             'https://openbao:8200';
const CA_FILE = process.env.STS_KEYS_VAULT_CA_CERT ||
                '/run/secrets/openbao/bao-ca.crt';
const STARTUP_DIR = process.env.STS_BAO_STARTUP_DIR ||
                    '/run/secrets/openbao-startup';
const NODE = process.env.STS_BAO_STARTUP_NODE || 'sts';
const SECRET_PATH = process.env.STS_BAO_ADMIN_SECRET || 'sts-admin';
const OUT_DIR = process.env.STS_STARTUP_SECRETS_DIR || '/run/sts-startup';
const SERVICE_UID = Number(process.env.STS_BAO_SERVICE_UID || 10001);
const SERVICE_GID = Number(process.env.STS_BAO_SERVICE_GID || 10001);
// THE FIELDS `openbao/seed.js` WRITES, and the setting's variable each one is
// delivered as. `common/delivered_secrets.ts` lists the same three settings.
const FIELDS = [
  { field: 'adminApiClientSecret', env: 'ADMIN_API_CLIENT_SECRET' },
  { field: 'krb5KrbtgtPassword', env: 'KRB5_KRBTGT_PASSWORD' },
  { field: 'krb5ServicePassword', env: 'KRB5_SERVICE_PASSWORD' }
];

let ca = null;

// One request; `{ status, body }`, never a throw for an HTTP status.
function call(method, route, body, token) {
  log.debug("Entering call(). " + method + " " + route);
  log.debug("Leaving call().");
  return new Promise(function (resolve, reject) {
    const payload = body === undefined ? null :
                    Buffer.from(JSON.stringify(body));
    const url = new URL(ADDR + route);
    const req = https.request({
      method: method,
      host: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      ca: ca,
      headers: Object.assign(
        { 'Content-Type': 'application/json' },
        token ? { 'X-Vault-Token': token } : {},
        payload ? { 'Content-Length': payload.length } : {})
    }, function (res) {
      let text = '';
      res.on('data', function (chunk) { text += chunk; });
      res.on('end', function () {
        let parsed = null;
        try {
          parsed = text ? JSON.parse(text) : null;
        } catch (e) {
          log.debug("Caught in a callback in call(): " +
                    ((e && e.message) || e));
          // Not JSON: a proxy, or a listener that is not the store's.
          parsed = { raw: text };
        }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

function errorsOf(answer) {
  log.debug("Entering errorsOf().");
  const errors = (answer && answer.body && answer.body.errors) || [];
  log.debug("Leaving errorsOf().");
  return answer.status + (errors.length ? ': ' + errors.join('; ') : '');
}

// The wrapping token, read and its file deleted — or null when there is none.
function takeWrappingToken() {
  log.debug("Entering takeWrappingToken().");
  const file = path.join(STARTUP_DIR, NODE + '.wrap');
  if (!fs.existsSync(file)) {
    log.debug("Leaving takeWrappingToken(). None.");
    return null;
  }
  const token = String(fs.readFileSync(file, 'utf8')).trim();
  fs.unlinkSync(file);
  log.debug("Leaving takeWrappingToken().");
  return token;
}

function deliver(values) {
  log.debug("Entering deliver().");
  fs.mkdirSync(OUT_DIR, { recursive: true, mode: 0o700 });
  fs.chmodSync(OUT_DIR, 0o700);
  fs.chownSync(OUT_DIR, SERVICE_UID, SERVICE_GID);
  const lines = [];
  FIELDS.forEach(function (one) {
    const value = String(values[one.field] || '').trim();
    if (!value) {
      return;
    }
    const file = path.join(OUT_DIR, one.env);
    fs.writeFileSync(file, value, { mode: 0o400 });
    fs.chmodSync(file, 0o400);
    fs.chownSync(file, SERVICE_UID, SERVICE_GID);
    lines.push('export ' + one.env + '_FILE=' + file);
  });
  log.debug("Leaving deliver(). " + lines.length);
  return lines;
}

async function main() {
  log.debug("Entering main().");
  const wrapping = takeWrappingToken();
  if (!wrapping) {
    log.warn('startup-secrets: there is no start-up token for ' + NODE +
             ' in ' + STARTUP_DIR + ', so the service starts without the ' +
             'start-up secrets (secret/' + SECRET_PATH + '). A node ' +
             'restarted without a seeder run has none: `docker compose up` ' +
             're-runs the seeder, `restart` does not.');
    log.debug("Leaving main(). Nothing to unwrap.");
    return;
  }
  ca = fs.readFileSync(CA_FILE);
  const unwrapped = await call('POST', '/v1/sys/wrapping/unwrap', {},
                               wrapping);
  const token = unwrapped.body && unwrapped.body.auth &&
                unwrapped.body.auth.client_token;
  if (unwrapped.status !== 200 || !token) {
    throw new Error('the start-up token for ' + NODE + ' could not be ' +
                    'unwrapped (' + errorsOf(unwrapped) + '). It is single-' +
                    'use: either somebody else unwrapped it — and has the ' +
                    'start-up secrets — or it was older than its wrap TTL. ' +
                    'This node does not start. Find out which before running ' +
                    'the seeder again.');
  }
  const read = await call('GET', '/v1/secret/data/' + SECRET_PATH, undefined,
                          token);
  // Revoked whether or not the read worked: it has no other use.
  const revoked = await call('POST', '/v1/auth/token/revoke-self', {}, token);
  if (revoked.status !== 204 && revoked.status !== 200) {
    log.warn('startup-secrets: the start-up token could not be revoked (' +
             errorsOf(revoked) + '); it expires on its own.');
  }
  const values = (read.body && read.body.data && read.body.data.data) || null;
  if (read.status !== 200 || !values) {
    throw new Error('the start-up token for ' + NODE + ' could not read ' +
                    'secret/' + SECRET_PATH + ' (' + errorsOf(read) + ').');
  }
  const lines = deliver(values);
  // WHICH, AND NEVER WHAT — and on stderr, since stdout is evaluated.
  log.info('startup-secrets: delivered ' + lines.length + ' start-up ' +
           'secret(s) for ' + NODE + ' to ' + OUT_DIR + ', 0400 and owned ' +
           'by ' + SERVICE_UID + '.');
  process.stdout.write(lines.join('\n') + (lines.length ? '\n' : ''));
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error('startup-secrets: ' + ((e && e.message) ? e.message : e));
  process.exit(1);
});
