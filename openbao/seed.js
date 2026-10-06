// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openbao/seed.js
//
// ===========================================================================
// BRINGING THE SECRET STORE UP TO THE STATE THIS SERVICE EXPECTS (2026-09-12).
//
// One shot, idempotent, run before the identity service starts: initialise the
// store if it has never been, put the two secrets in it, build a certificate
// authority inside it, issue THE SERVICE its client certificate, and bind that
// certificate to a policy that can read those two values and nothing else.
// Since #254, also: keep the START-UP secrets on a path of their own
// (`secret/sts-admin`), hand each node a single-use token that can read them,
// and revoke the root token once the store is configured.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NODE AND NOT A SHELL SCRIPT AGAINST THE `bao` CLI.
//
// The `openbao/openbao` image is Alpine with `bao` and busybox in it: **no
// jq, no curl, no openssl.** Every interesting step here answers JSON — the
// root token, the issued certificate and its private key — and a bootstrap
// that parses JSON with `sed` is one nobody can review and nobody will touch
// again. This runs in the image this repository already builds, against
// OpenBao's HTTP API, which is the same API `common/secrets.js` uses.
//
// ---------------------------------------------------------------------------
// WHAT IS IDEMPOTENT AND WHAT IS NOT, WHICH IS THE WHOLE DESIGN OF THE FILE.
//
//   * **THE KEY-ENCRYPTION KEY IS WRITTEN ONCE AND NEVER REPLACED.** Every
//     signing key, every certificate authority and every minted row this
//     service has sealed is unreadable without it, so a seeder that generated
//     a fresh one on each start would quietly destroy the store it exists to
//     protect. It is generated only when `secret/sts` does not exist.
//   * **THE DATABASE PASSWORD IS CHECKED EVERY TIME** and rewritten when it
//     differs, because the database's own copy comes from the same
//     environment variable and the two have to agree. If they ever disagree,
//     the one in the environment is the one the database was built with.
//   * **THE CLIENT CERTIFICATE IS ISSUED ONCE** and left in the shared volume,
//     and re-issued only when it is within `STS_BAO_RENEW_WITHIN_DAYS` of
//     expiring. Re-issuing on every start would be a new credential per
//     restart for no reason; the certificate authority stays inside the store
//     either way.
//   * Everything else — mounts, roles, the policy, the trusted CA — is written
//     on every run, because those are declarations and re-declaring them is
//     free.
//
// ---------------------------------------------------------------------------
// THE ROOT TOKEN IS REVOKED ONCE THE STORE IS CONFIGURED (#254, 2026-10-06).
//
// `PUT /v1/sys/init` hands back a root token exactly once. Until #254 this
// wrote it into the store's own volume, so that a later run could re-declare a
// policy or issue a replacement certificate — and so a shell in the store's
// container held everything. rcbj's decision on #254 was to revoke it: the
// run that initialises the store uses it in memory, writes it NOWHERE, and
// revokes it (`revoke-self`) as its last act. A volume from before #254 that
// still has `seed/root.token` is used once the same way, then revoked and the
// file deleted.
//
// **WHAT A LATER RUN USES INSTEAD** is a narrow PERIODIC token made by the
// first run, `seed/seeder.token` (0600, in the store's own volume), whose
// policy is `seeder.hcl`: issue the service's client certificate, and mint the
// start-up and operator tokens of `admin-secret.hcl`, and keep
// `secret/sts-admin` as a launcher pins it. Nothing else — no policy, mount or
// auth method can be changed by it, and it cannot read `secret/sts`. A later
// run therefore DECLARES NOTHING: it renews its own token, writes a pinned
// start-up secret, renews the client certificate when due, proves the
// service's identity, and hands out the start-up tokens. Changing a
// declaration on a running store is an operator's act — `STS_BAO_TOKEN`
// with a token made for it (`bao operator generate-root` and the recovery
// key), or `down -v`.
//
// **THE RECOVERY KEY IS PRINTED ONCE AND KEPT NOWHERE**, for the same reason:
// with an auto seal it is what regenerates a root token, so a copy of it in
// the volume would be the root token by another name. So is the OPERATOR
// TOKEN this prints on every run (`STS_BAO_PRINT_CREDENTIALS`, on by default
// and off on the test stacks): read on `secret/sts-admin` and nothing else,
// for `STS_BAO_OPERATOR_TTL` — the way a person gets the management API secret
// for the first token on a stack they own (`docs/management-api.md`).
//
// ---------------------------------------------------------------------------
// THE START-UP SECRETS, AND WHY THE SERVICE'S OWN IDENTITY CANNOT READ THEM.
//
// The management API client's secret (and, on a product test stack, the two
// Kerberos passwords) live at `secret/sts-admin`, apart from `secret/sts`:
// the identity the service holds while it runs is the client certificate,
// and a shell that has it must not have `/admin-api` as well. So the
// certificate's policy names no such path, and the service reads them ONCE,
// at start, through a token that can do nothing else:
//
//   * this seeder mints one per node in `STS_BAO_STARTUP_NODES` from the
//     `sts-admin-secret` token role — `admin-secret.hcl`, orphan, a short TTL
//     and two uses — RESPONSE-WRAPPED for `STS_BAO_STARTUP_WRAP_TTL`, and
//     writes the wrapping token to `<node>.wrap` (0600, root) in
//     `STS_BAO_STARTUP_DIR`, a volume mounted only into that node;
//   * `openbao/startup-secrets.js`, run as ROOT by the node's start command
//     before it drops to uid 10001, deletes the file, unwraps it, reads, and
//     revokes the token, and hands the values to the service as files it
//     reads once and deletes (`common/delivered_secrets.ts`).
//
// A wrapping token is single-use and says so: an unwrap that finds it already
// unwrapped means somebody else took the secret, and the node refuses to
// start. A node restarted without a seeder run finds no file and starts
// without the secret (`docker compose up` re-runs the seeder; `restart`
// does not).
//
// ---------------------------------------------------------------------------
// SEVERAL STACKS AGAINST ONE STORE (2026-09-14, #46 section 8).
//
// This was written for one stack, and a cluster is several containers — and
// several seeders, if each stack brings one — against ONE store. Two things
// went wrong there and one was data loss:
//
//   * **TWO SEEDERS ON AN EMPTY STORE RACED THE KEY-ENCRYPTION KEY.** Each read
//     `secret/sts`, found nothing, generated a key and wrote it: the later
//     write won the path, and a service that had started against the earlier
//     one sealed rows under a key the store no longer held — a node that can
//     never start again, and nothing said so. The write is now KV version 2's
//     CHECK-AND-SET: `cas: 0` writes only if the path has no version at all,
//     and a refusal means another seeder won, so this one READS BACK and keeps
//     theirs. A key already there is updated (the database password) with
//     `cas` set to the version read, so a concurrent writer is never
//     overwritten either.
//   * **A SECOND STACK'S SEEDER REFUSED TO FINISH** — "already initialised and
//     there is no root token" — because the root token lives in the FIRST
//     stack's volume. It now finishes where it honestly can: with an
//     operator's token in `STS_BAO_TOKEN` it re-declares everything as usual,
//     and with none but a client credential already in its own volume it
//     PROVES that credential (`proveReadOnly()`) and succeeds without
//     changing the store. Only a stack with neither is refused, and the
//     sentence says which of the two to supply.
//
// **THE DEPLOYMENT SHAPE THIS POINTS AT** is one seeding, out of band — a
// one-shot init job run once against the store, handing each node its client
// credential — rather than a seeder per container. `openbao/CLAUDE.md` says
// so, and says that the client certificate's lifetime (`STS_BAO_CLIENT_TTL`,
// ninety days since #254; it was a year) is renewed only when a seeder runs
// (`ensureClientCertificate()`).
// ===========================================================================

const fs = require('fs');
const path = require('path');
const https = require('https');
const nodeCrypto = require('crypto');

// This script's own logger. Its level is LOG_LEVEL, and info without one.
const log = require('bunyan').createLogger({ name: 'sts-bao-seed',
  level: process.env.LOG_LEVEL || 'info' });

const ADDR = process.env.STS_BAO_ADDR || 'https://openbao:8200';
const CA_FILE = process.env.STS_BAO_CA_FILE || '/openbao/file/tls/server.crt';
const SEED_DIR = process.env.STS_BAO_SEED_DIR || '/openbao/file/seed';
const CLIENT_DIR = process.env.STS_BAO_CLIENT_DIR || '/openbao/client';
const SECRET_PATH = process.env.STS_BAO_SECRET || 'sts';
const DB_PASSWORD = process.env.STS_DB_APP_PASSWORD || 'sts_app';
const COMMON_NAME = process.env.STS_BAO_CLIENT_CN || 'sts';
const POLICY_FILE = process.env.STS_BAO_POLICY_FILE ||
                    '/openbao/config/read-only.hcl';
const POLICY_NAME = 'sts-read';
// The Transit key that is the key-encryption key with
// `keys.kekProvider=vault-transit` (#391). Its name is the policy's too.
const TRANSIT_KEY = 'sts-kek';
const WAIT_SECONDS = Number(process.env.STS_BAO_WAIT_SECONDS || 60);
// An operator's token for a store this stack did not initialise — see the
// header's section on several stacks. Never written anywhere by this script.
const OPERATOR_TOKEN = String(process.env.STS_BAO_TOKEN || '').trim();
// A client certificate this close to expiry is re-issued by a seeder that can.
const RENEW_WITHIN_DAYS = Number(process.env.STS_BAO_RENEW_WITHIN_DAYS || 30);
// ---------------------------------------------------------------------------
// #254: the client certificate's lifetime, who it is for, the start-up
// secrets, and the tokens that replace the root token. See the header.
// ---------------------------------------------------------------------------
// Ninety days, and it was a year: the certificate is the running service's
// identity, and renewal comes with every seeder run inside the last
// RENEW_WITHIN_DAYS.
const CLIENT_TTL = process.env.STS_BAO_CLIENT_TTL || '2160h';
// THE SERVICE'S UID AND GID, which the Dockerfile fixes at 10001. The client
// key is written 0600 and owned by them, so the service reads it and no other
// non-root user in its container can.
const SERVICE_UID = Number(process.env.STS_BAO_SERVICE_UID || 10001);
const SERVICE_GID = Number(process.env.STS_BAO_SERVICE_GID || 10001);
// Where the start-up secrets live, and the policy and role that read them.
const ADMIN_SECRET_PATH = process.env.STS_BAO_ADMIN_SECRET || 'sts-admin';
const ADMIN_POLICY_NAME = 'sts-admin-secret';
const ADMIN_POLICY_FILE = process.env.STS_BAO_ADMIN_POLICY_FILE ||
                          path.join(__dirname, 'admin-secret.hcl');
const ADMIN_ROLE = 'sts-admin-secret';
const SEEDER_POLICY_NAME = 'sts-seeder';
const SEEDER_POLICY_FILE = process.env.STS_BAO_SEEDER_POLICY_FILE ||
                           path.join(__dirname, 'seeder.hcl');
const SEEDER_PERIOD = process.env.STS_BAO_SEEDER_PERIOD || '768h';
// The start-up tokens: one per node named here, wrapped for this long, each
// living this long once unwrapped.
const STARTUP_DIR = process.env.STS_BAO_STARTUP_DIR || '/openbao/startup';
const STARTUP_NODES = String(process.env.STS_BAO_STARTUP_NODES || 'sts')
  .split(/[\s,]+/).filter(Boolean);
const STARTUP_WRAP_TTL = process.env.STS_BAO_STARTUP_WRAP_TTL || '30m';
const STARTUP_TTL = process.env.STS_BAO_STARTUP_TTL || '10m';
// The operator token's lifetime, and whether this prints it (and, on the run
// that initialises the store, the recovery key) at all.
const OPERATOR_TTL = process.env.STS_BAO_OPERATOR_TTL || '24h';
const PRINT_CREDENTIALS =
  String(process.env.STS_BAO_PRINT_CREDENTIALS || 'true') !== 'false';
// THE START-UP SECRETS THIS SEEDER WRITES, field by field, and the variable
// each is taken from when a launcher pins it. The management API secret is
// GENERATED when nobody pins one and none is stored; the Kerberos passwords
// are stored only when given (a product test stack's launcher gives them).
const ADMIN_FIELDS = [
  { field: 'adminApiClientSecret', from: 'STS_ADMIN_API_CLIENT_SECRET',
    generate: true },
  { field: 'krb5KrbtgtPassword', from: 'STS_KRB5_KRBTGT_PASSWORD',
    generate: false },
  { field: 'krb5ServicePassword', from: 'STS_KRB5_SERVICE_PASSWORD',
    generate: false }
];

let ca = null;

function say(what) {
  log.debug("Entering say().");
  log.info(what);
  log.debug("Leaving say().");
}

// ---------------------------------------------------------------------------
// ONE REQUEST FUNCTION. It answers `{ status, body }` and NEVER throws for an
// HTTP status: every caller here has a status it is expecting and several have
// a 404 that means "not configured yet", which is the ordinary path rather
// than an error. `headers` adds request headers — `X-Vault-Wrap-TTL`, which
// asks for the answer response-wrapped (#254).
// ---------------------------------------------------------------------------
function call(method, route, body, token, headers) {
  log.debug("Entering call().");
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
        headers || {},
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
          // Not JSON. Every OpenBao error is JSON, so this is a proxy or a
          // listener that is not the one we think — the raw text is what says
          // which.
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

function refuse(answer, what) {
  log.debug("Entering refuse().");
  const errors = (answer.body && answer.body.errors) || [];
  log.debug("Leaving refuse().");
  throw new Error(what + ' — OpenBao answered ' + answer.status +
                  (errors.length ? ': ' + errors.join('; ') : ''));
}

// The listener is up when it answers its own seal status. Waiting here rather
// than in compose's healthcheck as well, because this container may be started
// by a launcher that has no healthcheck to wait on.
async function waitForListener() {
  log.debug("Entering waitForListener().");
  const until = Date.now() + WAIT_SECONDS * 1000;
  let last = '';
  while (Date.now() < until) {
    try {
      const answer = await call('GET', '/v1/sys/seal-status');
      if (answer.status === 200 && answer.body) {
        log.debug("Leaving waitForListener().");
        return answer.body;
      }
      last = 'status ' + answer.status;
    } catch (e) {
      last = e.message;
    }
    await new Promise(function (r) { setTimeout(r, 1000); });
  }
  log.debug("Leaving waitForListener().");
  throw new Error('the secret store did not answer at ' + ADDR + ' within ' +
                  WAIT_SECONDS + ' seconds (' + last + ')');
}

// **UNSEALED IS NOT READY, AND THE DIFFERENCE COST A RUN.** `sys/seal-status`
// answers `sealed: false` the moment the static seal has done its work, and
// the node is not yet the ACTIVE one — a write in that window is refused with
// `local node not active but active cluster node not found`, which reads like
// a clustering problem in a single-node store. `sys/health` is the endpoint
// that means ready: 200 is initialised, unsealed AND active.
async function waitForActive() {
  log.debug("Entering waitForActive().");
  const until = Date.now() + WAIT_SECONDS * 1000;
  let sealed = null;
  while (Date.now() < until) {
    const health = await call('GET', '/v1/sys/health');
    if (health.status === 200) {
      log.debug("Leaving waitForActive().");
      return;
    }
    const seal = await call('GET', '/v1/sys/seal-status');
    sealed = (seal.body && seal.body.sealed);
    await new Promise(function (r) { setTimeout(r, 1000); });
  }
  if (sealed) {
    // **THIS IS THE ONE FAILURE WITH A NAME WORTH PRINTING.** A store that
    // initialised and stayed sealed means the static seal did not take, which
    // is almost always a key that is not base64 of exactly 32 bytes.
    throw new Error('the secret store initialised and did not unseal ' +
                    'itself. The static seal key ' +
                    '(BAO_STATIC_SEAL_CURRENT_KEY) must be base64 of exactly ' +
                    '32 bytes.');
  }
  log.debug("Leaving waitForActive().");
  throw new Error('the secret store unsealed and did not become active ' +
                  'within ' + WAIT_SECONDS + ' seconds.');
}

// THE TOKEN THIS RUN HOLDS, and what kind it is — the answer decides how much
// of the store this run may touch (see the header on the root token):
//
//   { token, kind: 'root', revoke: true }   the root token of a store this run
//                                           initialised, or one a volume from
//                                           before #254 kept: used, revoked
//   { token, kind: 'operator' }             `STS_BAO_TOKEN`: everything is
//                                           declared, and it is not revoked
//   { token, kind: 'seeder' }               `seed/seeder.token`: nothing is
//                                           declared; renewals and start-up
//                                           tokens only
//   null                                    nothing: the credential this stack
//                                           holds is proved, and that is all
// ---------------------------------------------------------------------------
function tokenForInitialisedStore() {
  log.debug("Entering tokenForInitialisedStore().");
  const legacy = path.join(SEED_DIR, 'root.token');
  if (fs.existsSync(legacy)) {
    say('the store is already initialised and its volume still holds a ' +
        'root token from before #254; it is used for this run and then ' +
        'revoked and deleted.');
    log.debug("Leaving tokenForInitialisedStore(). The kept root token.");
    return { token: String(fs.readFileSync(legacy, 'utf8')).trim(),
             kind: 'root', revoke: true, file: legacy };
  }
  if (OPERATOR_TOKEN) {
    say('the store is already initialised; using the operator token in ' +
        'STS_BAO_TOKEN, which is not revoked.');
    log.debug("Leaving tokenForInitialisedStore(). The operator's token.");
    return { token: OPERATOR_TOKEN, kind: 'operator' };
  }
  const seeder = path.join(SEED_DIR, 'seeder.token');
  if (fs.existsSync(seeder)) {
    say('the store is already initialised; using this stack\'s seeder ' +
        'token, which renews the client certificate and hands out start-up ' +
        'tokens and declares nothing.');
    log.debug("Leaving tokenForInitialisedStore(). The seeder token.");
    return { token: String(fs.readFileSync(seeder, 'utf8')).trim(),
             kind: 'seeder' };
  }
  log.debug("Leaving tokenForInitialisedStore(). None.");
  return null;
}

async function rootToken() {
  log.debug("Entering rootToken().");
  const status = await call('GET', '/v1/sys/init');
  if (status.body && status.body.initialized) {
    log.debug("Leaving rootToken(). Already initialised.");
    return tokenForInitialisedStore();
  }
  // ONE RECOVERY SHARE. With an auto seal the shares are RECOVERY keys rather
  // than unseal keys — they exist to rekey or to recover, never to start the
  // store — and a quorum of five for a stack that unseals itself would be
  // ceremony with nothing on the other end of it.
  const made = await call('PUT', '/v1/sys/init',
                          { recovery_shares: 1, recovery_threshold: 1 });
  if (made.status !== 200 || !made.body || !made.body.root_token) {
    // **ANOTHER SEEDER MAY HAVE INITIALISED IT A MOMENT AGO** — two stacks
    // started together both read "not initialised". Initialisation is the
    // store's own check-and-set: exactly one of them gets a root token. The
    // other is an ordinary second stack, not a failure.
    const again = await call('GET', '/v1/sys/init');
    if (again.body && again.body.initialized) {
      say('another seeder initialised the store while this one was asking ' +
          'to; carrying on as a second stack.');
      log.debug("Leaving rootToken(). Initialised by somebody else.");
      return tokenForInitialisedStore();
    }
    refuse(made, 'the secret store could not be initialised');
  }
  // THE RECOVERY KEY, ONCE (#254): printed here and written nowhere — a copy
  // in the volume would regenerate the root token this run is about to
  // revoke. With STS_BAO_PRINT_CREDENTIALS=false it is not printed either,
  // which is the test stacks' answer: their store lives for one run.
  //
  // `recovery_keys_base64`, which is the field's name: it was read as
  // `recovery_keys_b64` until #254, so the file this seeder kept then held
  // `[]` and no recovery key was ever kept anywhere. Harmless while the root
  // token sat beside it, and not once the root token is revoked.
  const recovery = (made.body.recovery_keys_base64 ||
                    made.body.recovery_keys || []).join(', ');
  if (!recovery) {
    log.warn('the store returned no recovery key at initialisation, so once ' +
             'the root token is revoked nothing can make one again; a ' +
             'change to this store\'s declarations will need ' +
             '`docker compose down -v`.');
  } else if (PRINT_CREDENTIALS) {
    say('initialised the store. Its RECOVERY KEY (base64), printed this once ' +
        'and kept nowhere — it is what `bao operator generate-root` needs to ' +
        'make a root token again: ' + recovery);
  } else {
    say('initialised the store; its recovery key was not printed ' +
        '(STS_BAO_PRINT_CREDENTIALS=false) and is kept nowhere.');
  }
  log.debug("Leaving rootToken().");
  return { token: made.body.root_token, kind: 'root', revoke: true };
}

async function ensureMount(token, mount, type, options) {
  log.debug("Entering ensureMount().");
  const mounts = await call('GET', '/v1/sys/mounts', undefined, token);
  if (mounts.status === 200 && mounts.body && mounts.body[mount + '/']) {
    log.debug("Leaving ensureMount().");
    return false;
  }
  const made = await call('POST', '/v1/sys/mounts/' + mount,
                          Object.assign({ type: type }, options || {}), token);
  if (made.status !== 204 && made.status !== 200) {
    refuse(made, 'the "' + mount + '" engine could not be enabled');
  }
  say('enabled the ' + type + ' engine at ' + mount + '/.');
  log.debug("Leaving ensureMount().");
  return true;
}

// Is this answer the kv engine asking to be come back to? The message is the
// only signal — the status is an ordinary 400 — so it is matched on the two
// words that cannot be anything else.
function upgrading(answer) {
  log.debug("Entering upgrading().");
  if (!answer || answer.status !== 400) {
    log.debug("Leaving upgrading().");
    return false;
  }
  const said = JSON.stringify(answer.body || '');
  log.debug("Leaving upgrading().");
  return /Upgrading from non-versioned/i.test(said);
}

// Is this answer KV version 2 refusing a check-and-set? A 400 whose message
// names it; every other 400 is a real refusal.
function casRefused(answer) {
  log.debug("Entering casRefused().");
  const said = JSON.stringify((answer && answer.body) || '');
  log.debug("Leaving casRefused().");
  return !!answer && answer.status === 400 && /check-and-set/i.test(said);
}

// The secret as it stands: its data, its version, and whether its latest
// version was deleted (KV v2 answers a soft-deleted version 404 WITH its
// metadata, which is a different fact from "never written").
async function readSecrets(token, at) {
  log.debug("Entering readSecrets().");
  const held = await call('GET', '/v1/secret/data/' + (at || SECRET_PATH),
                          undefined, token);
  const body = held.body || {};
  const metadata = (body.data && body.data.metadata) || {};
  log.debug("Leaving readSecrets().");
  return {
    status: held.status,
    data: (held.status === 200 && body.data && body.data.data) || {},
    version: Number(metadata.version) || 0,
    deleted: !!(metadata.deletion_time || metadata.destroyed)
  };
}

async function writeSecrets(token, data, cas, where) {
  log.debug("Entering writeSecrets(). cas=" + cas);
  const at = '/v1/secret/data/' + (where || SECRET_PATH);
  // ---------------------------------------------------------------------
  // **THE FIRST WRITE AFTER ENABLING THE ENGINE CAN BE REFUSED, AND IT IS NOT
  // A FAILURE (2026-09-12).**
  //
  // `ensureMount()` enables `secret/` as kv version 2, and OpenBao answers the
  // very next write with **400 `Upgrading from non-versioned to versioned
  // data. This backend will be unavailable for a brief period and will resume
  // service shortly.`** — which is the store telling us to come back, in the
  // shape of an error.
  //
  // It is a RACE and therefore intermittent: seen twice in a row on a machine
  // building an image at the same time, and never before that on the same
  // code. What it cost is the whole run — this seeder is
  // `service_completed_successfully` for the service, so a refusal here is a
  // stack that never starts and a suite that reports *the service under the
  // protocol jobs never came up*.
  //
  // **RETRIED ONLY FOR THAT MESSAGE.** Every other 400 is a real refusal — a
  // bad path, a bad payload, a policy — and retrying those would turn a
  // mistake into a ten-second pause followed by the same mistake. A
  // check-and-set refusal is returned to the caller, which re-reads.
  // ---------------------------------------------------------------------
  const body = { options: { cas: cas }, data: data };
  let wrote = await call('POST', at, body, token);
  for (let attempt = 0; attempt < 20 && upgrading(wrote); attempt++) {
    if (attempt === 0) {
      say('the kv engine is still upgrading to versioned data, which it says ' +
          'in the shape of a 400. Waiting for it rather than failing the ' +
          'stack.');
    }
    await new Promise(function (r) { setTimeout(r, 500); });
    wrote = await call('POST', at, body, token);
  }
  log.debug("Leaving writeSecrets(). status=" + wrote.status);
  return wrote;
}

async function ensureSecrets(token) {
  log.debug("Entering ensureSecrets().");
  for (let round = 0; round < 10; round++) {
    const held = await readSecrets(token);
    if (!held.data.kek && held.version && held.deleted) {
      // A KEY THAT WAS THERE AND IS DELETED is not a key to replace. Whatever
      // this service sealed is sealed under it, and `bao kv undelete` brings it
      // back; generating a new one here would make that impossible to notice.
      throw new Error('the latest version (' + held.version + ') of secret/' +
                      SECRET_PATH + ' is deleted or destroyed. This seeder ' +
                      'will not write a new key-encryption key over it: ' +
                      'everything sealed under the old one would be ' +
                      'unreadable. Undelete it (`bao kv undelete -versions=' +
                      held.version + ' secret/' + SECRET_PATH + '`), or, for ' +
                      'a store nothing was ever sealed under, delete its ' +
                      'metadata (`bao kv metadata delete secret/' +
                      SECRET_PATH + '`) and run this again.');
    }
    if (held.data.kek) {
      // THE KEK IS KEPT. The database password is refreshed from the
      // environment when it differs — pinned to the version just read, so a
      // concurrent writer's change is re-read rather than overwritten.
      if (held.data.databasePassword === DB_PASSWORD) {
        say('the key-encryption key was already in the store (version ' +
            held.version + ') and was left alone; the database password ' +
            'already matches the environment.');
        log.debug("Leaving ensureSecrets(). Nothing to write.");
        return;
      }
      const updated = await writeSecrets(token,
        Object.assign({}, held.data, { databasePassword: DB_PASSWORD }),
        held.version);
      if (casRefused(updated)) {
        say('secret/' + SECRET_PATH + ' changed while this seeder was ' +
            'updating it; reading it again.');
        continue;
      }
      if (updated.status !== 200 && updated.status !== 204) {
        refuse(updated, 'the secrets could not be written');
      }
      say('the key-encryption key was already in the store and was left ' +
          'alone; the database password was refreshed from the environment.');
      log.debug("Leaving ensureSecrets(). Password refreshed.");
      return;
    }
    // NO KEY YET. Offered with `cas: 0` — written only if the path has no
    // version at all — so of two seeders racing an empty store exactly one
    // writes, and the other is told so and reads back the winner's.
    const offered = nodeCrypto.randomBytes(32).toString('base64');
    const created = await writeSecrets(token,
      { kek: offered, databasePassword: DB_PASSWORD },
      held.version ? held.version : 0);
    if (casRefused(created)) {
      say('another seeder wrote secret/' + SECRET_PATH + ' first; reading ' +
          'back the key-encryption key it wrote, which is the one every ' +
          'node will use.');
      continue;
    }
    if (created.status !== 200 && created.status !== 204) {
      refuse(created, 'the secrets could not be written');
    }
    const confirmed = await readSecrets(token);
    if (confirmed.data.kek !== offered) {
      // Not expected after a successful `cas` write, and said rather than
      // assumed: what is stored is what the service will read.
      say('the key-encryption key stored is not the one this seeder offered; ' +
          'the stored one stands.');
    } else {
      say('generated a key-encryption key and wrote it with the database ' +
          'password (check-and-set: nobody had written one). It will never ' +
          'be replaced by this seeder.');
    }
    log.debug("Leaving ensureSecrets(). Created.");
    return;
  }
  log.debug("Leaving ensureSecrets(). Gave up.");
  throw new Error('secret/' + SECRET_PATH + ' kept changing under this ' +
                  'seeder\'s check-and-set for ten rounds; something else is ' +
                  'writing it continuously.');
}

async function ensurePki(token) {
  log.debug("Entering ensurePki().");
  await ensureMount(token, 'pki', 'pki',
                    { config: { max_lease_ttl: '87600h' } });
  // Tuned separately: `max_lease_ttl` on the mount config at creation is
  // ignored by some versions, and a CA with a 32-day ceiling is a CA that
  // expires in the middle of somebody's week.
  await call('POST', '/v1/sys/mounts/pki/tune',
             { max_lease_ttl: '87600h' }, token);
  const caFile = path.join(SEED_DIR, 'pki-ca.crt');
  const held = await call('GET', '/v1/pki/cert/ca');
  let caPem = (held.status === 200 && held.body && held.body.data &&
               held.body.data.certificate) || '';
  if (!caPem) {
    const made = await call('POST', '/v1/pki/root/generate/internal',
                            { common_name: 'iya-sts secret store CA',
                              ttl: '87600h', key_type: 'rsa',
                              key_bits: 2048 }, token);
    if (made.status !== 200 || !made.body || !made.body.data) {
      refuse(made, 'the store\'s certificate authority could not be built');
    }
    caPem = made.body.data.certificate;
    say('built a certificate authority INSIDE the store. The client ' +
        'certificate this service authenticates with is issued by it, which ' +
        'is what makes "the store decides who may read" true rather than a ' +
        'file somebody copied in.');
  }
  fs.mkdirSync(SEED_DIR, { recursive: true });
  fs.writeFileSync(caFile, caPem, { mode: 0o644 });
  // client_flag and NOT server_flag: this role issues CLIENT certificates.
  // One that could also be a server certificate would be a credential usable
  // to impersonate a listener, minted by a role whose name says otherwise.
  const role = await call('POST', '/v1/pki/roles/sts-client',
                          { allow_any_name: true, client_flag: true,
                            server_flag: false, key_type: 'rsa',
                            key_bits: 2048, max_ttl: '8760h',
                            ttl: '8760h' }, token);
  if (role.status !== 204 && role.status !== 200) {
    refuse(role, 'the client certificate role could not be written');
  }
  log.debug("Leaving ensurePki().");
  return caPem;
}

// ===========================================================================
// THE TRANSIT KEY (#391): the key-encryption key that never leaves the store.
//
// Made ONCE, like the KV key: a Transit key is created only when absent, and
// never replaced, because every data encryption key the service wrapped under
// it is unreadable without it. `aes256-gcm96`, because the service binds each
// wrapped data key to its realm and class as associated data, which only an
// AEAD key takes; not exportable and not deletable, which are Transit's
// defaults and are asserted rather than assumed. The KV `kek` stays beside it:
// it is the key with `keys.kekProvider=vault`, and the PREVIOUS key a stack
// moving to Transit names in `keys.previousKek*`.
// ===========================================================================
async function ensureTransitKey(token) {
  log.debug("Entering ensureTransitKey().");
  await ensureMount(token, 'transit', 'transit');
  const route = '/v1/transit/keys/' + TRANSIT_KEY;
  let held = await call('GET', route, undefined, token);
  if (held.status === 404) {
    const made = await call('POST', route, { type: 'aes256-gcm96' }, token);
    if (made.status !== 204 && made.status !== 200) {
      refuse(made, 'the Transit key "' + TRANSIT_KEY + '" could not be made');
    }
    say('made the Transit key ' + TRANSIT_KEY + ' (aes256-gcm96), the ' +
        'key-encryption key for keys.kekProvider=vault-transit.');
    held = await call('GET', route, undefined, token);
  }
  const d = (held.body && held.body.data) || {};
  if (held.status !== 200 || d.type !== 'aes256-gcm96' || d.exportable ||
      d.deletion_allowed) {
    throw new Error('the Transit key "' + TRANSIT_KEY + '" is not an ' +
                    'aes256-gcm96 key that can neither be exported nor ' +
                    'deleted (' + held.status + ', ' + (d.type || '?') +
                    (d.exportable ? ', exportable' : '') +
                    (d.deletion_allowed ? ', deletable' : '') + '). It is ' +
                    'not replaced here: data keys may already be wrapped ' +
                    'under it.');
  }
  log.debug("Leaving ensureTransitKey().");
}

async function ensurePolicy(token) {
  log.debug("Entering ensurePolicy().");
  await writePolicy(token, POLICY_NAME, POLICY_FILE,
                    'read on two paths and no write anywhere');
  // #254: the start-up secrets' read, and the seeder's two acts.
  await writePolicy(token, ADMIN_POLICY_NAME, ADMIN_POLICY_FILE,
                    'read on secret/' + ADMIN_SECRET_PATH + ' and nothing ' +
                    'else');
  await writePolicy(token, SEEDER_POLICY_NAME, SEEDER_POLICY_FILE,
                    'issue the client certificate and mint ' +
                    ADMIN_POLICY_NAME + ' tokens, and nothing else');
  log.debug("Leaving ensurePolicy().");
}

async function writePolicy(token, name, file, what) {
  log.debug("Entering writePolicy(). " + name);
  const policy = fs.readFileSync(file, 'utf8');
  const wrote = await call('PUT', '/v1/sys/policies/acl/' + name,
                           { policy: policy }, token);
  if (wrote.status !== 204 && wrote.status !== 200) {
    refuse(wrote, 'the ' + name + ' policy could not be written');
  }
  say('wrote the ' + name + ' policy from ' + file + ' — ' + what + '.');
  log.debug("Leaving writePolicy().");
}

// ===========================================================================
// THE START-UP SECRETS (#254): `secret/sts-admin`, written by every run that
// holds a token — the seeder token included (`seeder.hcl` says why).
//
// Each field of ADMIN_FIELDS is taken from its variable when a launcher pins
// one (the test launchers pin the management API secret per run, and the
// product one the Kerberos passwords), kept when it is already stored, and —
// for the management API secret alone — GENERATED when neither: the default
// stack's operator reads it from here for the first token. Written with
// check-and-set, as `secret/sts` is.
// ===========================================================================
async function ensureAdminSecrets(token) {
  log.debug("Entering ensureAdminSecrets().");
  for (let round = 0; round < 10; round++) {
    const held = await readSecrets(token, ADMIN_SECRET_PATH);
    const data = Object.assign({}, held.data);
    const changed = [];
    ADMIN_FIELDS.forEach(function (one) {
      const pinned = String(process.env[one.from] || '').trim();
      if (pinned && data[one.field] !== pinned) {
        data[one.field] = pinned;
        changed.push(one.field + ' (from ' + one.from + ')');
      } else if (!pinned && !data[one.field] && one.generate) {
        // 24 characters of base64url's alphabet without its two symbols, the
        // shape the compose file's wrapper used to mint into a file.
        data[one.field] = nodeCrypto.randomBytes(32).toString('base64')
          .replace(/[^A-Za-z0-9]/g, '').slice(0, 24);
        changed.push(one.field + ' (generated)');
      }
    });
    if (!changed.length) {
      say('secret/' + ADMIN_SECRET_PATH + ' already holds the start-up ' +
          'secrets (' + Object.keys(data).join(', ') + '); nothing written.');
      log.debug("Leaving ensureAdminSecrets(). Unchanged.");
      return;
    }
    const wrote = await writeSecrets(token, data, held.version,
                                     ADMIN_SECRET_PATH);
    if (casRefused(wrote)) {
      say('secret/' + ADMIN_SECRET_PATH + ' changed while this seeder was ' +
          'writing it; reading it again.');
      continue;
    }
    if (wrote.status !== 200 && wrote.status !== 204) {
      refuse(wrote, 'the start-up secrets could not be written');
    }
    // WHICH FIELDS, AND NEVER WHAT.
    say('wrote secret/' + ADMIN_SECRET_PATH + ': ' + changed.join(', ') + '.');
    log.debug("Leaving ensureAdminSecrets(). Written.");
    return;
  }
  log.debug("Leaving ensureAdminSecrets(). Gave up.");
  throw new Error('secret/' + ADMIN_SECRET_PATH + ' kept changing under this ' +
                  'seeder\'s check-and-set for ten rounds.');
}

// THE TOKEN ROLE every start-up and operator token comes from: the one policy,
// orphans (so revoking the seeder token does not take a running node's start
// with it), not renewable, and a ceiling no request can lift.
async function ensureTokenRole(token) {
  log.debug("Entering ensureTokenRole().");
  const wrote = await call('POST', '/v1/auth/token/roles/' + ADMIN_ROLE,
                           { allowed_policies: [ADMIN_POLICY_NAME],
                             orphan: true, renewable: false,
                             token_type: 'service',
                             token_explicit_max_ttl: '168h' }, token);
  if (wrote.status !== 204 && wrote.status !== 200) {
    refuse(wrote, 'the ' + ADMIN_ROLE + ' token role could not be written');
  }
  say('wrote the ' + ADMIN_ROLE + ' token role — ' + ADMIN_POLICY_NAME +
      ' only, orphan, not renewable, seven days at most.');
  log.debug("Leaving ensureTokenRole().");
}

// THE SEEDER TOKEN (#254): made once, by a run holding root, and kept as
// `seed/seeder.token` for the runs after. A token that is already there and
// still answers is kept; one the store no longer knows is replaced.
async function ensureSeederToken(token) {
  log.debug("Entering ensureSeederToken().");
  const file = path.join(SEED_DIR, 'seeder.token');
  if (fs.existsSync(file)) {
    const held = String(fs.readFileSync(file, 'utf8')).trim();
    const looked = await call('GET', '/v1/auth/token/lookup-self', undefined,
                              held);
    if (looked.status === 200) {
      say('the seeder token in the store\'s volume is still valid; kept.');
      log.debug("Leaving ensureSeederToken(). Kept.");
      return;
    }
  }
  const made = await call('POST', '/v1/auth/token/create-orphan',
                          { policies: [SEEDER_POLICY_NAME],
                            period: SEEDER_PERIOD, renewable: true,
                            display_name: 'sts-seeder' }, token);
  const issued = made.body && made.body.auth && made.body.auth.client_token;
  if (made.status !== 200 || !issued) {
    refuse(made, 'the seeder token could not be made');
  }
  fs.mkdirSync(SEED_DIR, { recursive: true });
  fs.writeFileSync(file, issued, { mode: 0o600 });
  say('made the seeder token (' + SEEDER_POLICY_NAME + ', periodic ' +
      SEEDER_PERIOD + ') and kept it in the store\'s own volume, 0600. It is ' +
      'what later runs use; root is revoked at the end of this one.');
  log.debug("Leaving ensureSeederToken(). Made.");
}

// The seeder token's renewal, at the start of every run that uses it. False
// when the store no longer accepts it (expired, revoked), which main() turns
// into proving only.
async function renewSeederToken(token) {
  log.debug("Entering renewSeederToken().");
  const renewed = await call('POST', '/v1/auth/token/renew-self', {}, token);
  log.debug("Leaving renewSeederToken(). status=" + renewed.status);
  return renewed.status === 200;
}

// AND THE ROOT TOKEN, REVOKED (#254) — this run's last act when it held one it
// owns: the store's own, from `sys/init`, or one a volume from before #254
// kept, whose file is deleted after.
async function revokeRoot(held) {
  log.debug("Entering revokeRoot().");
  const revoked = await call('POST', '/v1/auth/token/revoke-self', {},
                             held.token);
  if (revoked.status !== 204 && revoked.status !== 200) {
    refuse(revoked, 'the root token could not be revoked');
  }
  if (held.file) {
    fs.unlinkSync(held.file);
  }
  say('revoked the root token' +
      (held.file ? ' and deleted ' + held.file : '') +
      '. Nothing on disk holds root; later runs use the seeder token.');
  log.debug("Leaving revokeRoot().");
}

// ===========================================================================
// ONE START-UP TOKEN PER NODE (#254), response-wrapped, into the node's file.
//
// The wrapped token is `admin-secret.hcl`'s read for STARTUP_TTL and two uses
// (the read, and the revoke-self after it); the WRAPPING token is what is
// written, and it can be unwrapped once, within STARTUP_WRAP_TTL. A file left
// by a run whose node never started is replaced — its token simply expires.
// ===========================================================================
async function issueStartupTokens(token) {
  log.debug("Entering issueStartupTokens().");
  fs.mkdirSync(STARTUP_DIR, { recursive: true, mode: 0o700 });
  // A volume's root is made 0755 by docker, whatever mkdir asked for.
  fs.chmodSync(STARTUP_DIR, 0o700);
  for (let i = 0; i < STARTUP_NODES.length; i++) {
    const node = STARTUP_NODES[i];
    if (!/^[A-Za-z0-9._-]+$/.test(node) || node === '.' || node === '..') {
      throw new Error('STS_BAO_STARTUP_NODES names "' + node + '", which is ' +
                      'not a plain file name.');
    }
    const made = await call('POST', '/v1/auth/token/create/' + ADMIN_ROLE,
                            { ttl: STARTUP_TTL, num_uses: 2,
                              display_name: 'startup-' + node },
                            token, { 'X-Vault-Wrap-TTL': STARTUP_WRAP_TTL });
    const wrapping = made.body && made.body.wrap_info &&
                     made.body.wrap_info.token;
    if (made.status !== 200 || !wrapping) {
      refuse(made, 'a start-up token for ' + node + ' could not be made');
    }
    const file = path.join(STARTUP_DIR, node + '.wrap');
    fs.writeFileSync(file, wrapping + '\n', { mode: 0o600 });
    fs.chmodSync(file, 0o600);
    say('wrote a single-use, response-wrapped start-up token for ' + node +
        ' (unwrap within ' + STARTUP_WRAP_TTL + ', then ' + STARTUP_TTL +
        ' and two uses) to ' + file + '.');
  }
  log.debug("Leaving issueStartupTokens().");
}

// THE OPERATOR TOKEN (#254): read on `secret/sts-admin` for OPERATOR_TTL,
// printed for the person running the stack. Off with
// STS_BAO_PRINT_CREDENTIALS=false, when it is not made at all.
async function issueOperatorToken(token) {
  log.debug("Entering issueOperatorToken().");
  if (!PRINT_CREDENTIALS) {
    log.debug("Leaving issueOperatorToken(). Not asked for.");
    return;
  }
  const made = await call('POST', '/v1/auth/token/create/' + ADMIN_ROLE,
                          { ttl: OPERATOR_TTL, display_name: 'operator' },
                          token);
  const issued = made.body && made.body.auth && made.body.auth.client_token;
  if (made.status !== 200 || !issued) {
    refuse(made, 'the operator token could not be made');
  }
  say('an OPERATOR TOKEN for the first /admin-api token on this stack — read ' +
      'on secret/' + ADMIN_SECRET_PATH + ' and nothing else, for ' +
      OPERATOR_TTL + ' (docs/management-api.md): ' + issued);
  log.debug("Leaving issueOperatorToken().");
}

async function ensureCertAuth(token, caPem) {
  log.debug("Entering ensureCertAuth().");
  const auths = await call('GET', '/v1/sys/auth', undefined, token);
  if (!(auths.status === 200 && auths.body && auths.body['cert/'])) {
    const made = await call('POST', '/v1/sys/auth/cert', { type: 'cert' },
                            token);
    if (made.status !== 204 && made.status !== 200) {
      refuse(made, 'the certificate auth method could not be enabled');
    }
    say('enabled the certificate auth method.');
  }
  // **THE TRUST IS THE STORE'S OWN CA AND THE NAME IS PINNED.** Trusting the CA
  // alone would admit every certificate it ever issues; `allowed_common_names`
  // is what makes this one identity rather than a class of them.
  const bound = await call('POST', '/v1/auth/cert/certs/sts',
                           { display_name: 'sts',
                             certificate: caPem,
                             allowed_common_names: COMMON_NAME,
                             token_policies: POLICY_NAME,
                             token_ttl: '1h',
                             token_max_ttl: '24h' }, token);
  if (bound.status !== 204 && bound.status !== 200) {
    refuse(bound, 'the client certificate could not be bound to the policy');
  }
  say('bound CN=' + COMMON_NAME + ' certificates from that CA to ' +
      POLICY_NAME + '.');
  log.debug("Leaving ensureCertAuth().");
}

// The client key's mode and owner (#254): 0600, the service's uid and gid.
// The seeder runs as root, which is what lets it chown.
function ownKey(keyFile) {
  log.debug("Entering ownKey().");
  fs.chmodSync(keyFile, 0o600);
  fs.chownSync(keyFile, SERVICE_UID, SERVICE_GID);
  log.debug("Leaving ownKey().");
}

// Days until a certificate file expires, or null when it cannot be read.
function daysLeft(certFile) {
  log.debug("Entering daysLeft().");
  try {
    const cert = new nodeCrypto.X509Certificate(fs.readFileSync(certFile));
    const out = (Date.parse(cert.validTo) - Date.now()) / 86400000;
    log.debug("Leaving daysLeft().");
    return Number.isFinite(out) ? out : null;
  } catch (e) {
    log.debug("Caught in daysLeft(): " + ((e && e.message) || e));
    log.debug("Leaving daysLeft(). Unreadable.");
    return null;
  }
}

async function ensureClientCertificate(token, caPem) {
  log.debug("Entering ensureClientCertificate().");
  fs.mkdirSync(CLIENT_DIR, { recursive: true });
  const certFile = path.join(CLIENT_DIR, 'client.crt');
  const keyFile = path.join(CLIENT_DIR, 'client.key');
  const caOut = path.join(CLIENT_DIR, 'bao-ca.crt');
  // THE LISTENER'S certificate, which is what the service verifies the
  // CONNECTION against — a different question from who signed the client
  // certificate, and the two are different CAs here on purpose.
  fs.writeFileSync(caOut, fs.readFileSync(CA_FILE), { mode: 0o644 });
  if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
    // A KEY ALREADY THERE IS MADE THE SERVICE'S OWN EVERY RUN (#254): a volume
    // written before #254 has it 0644 and root's, and re-issuing to fix a
    // mode would be a new credential for no reason.
    ownKey(keyFile);
    const left = daysLeft(certFile);
    if (left === null || left > RENEW_WITHIN_DAYS) {
      say('the client certificate is already in the shared volume' +
          (left === null ? '' : ' (' + Math.floor(left) + ' days left)') +
          '; it was not re-issued.');
      log.debug("Leaving ensureClientCertificate().");
      return;
    }
    // RENEWED HERE AND NOWHERE ELSE (2026-09-14). The certificate is issued
    // for a year and nothing in the running service renews it, so a stack
    // that is never re-seeded stops reading its secrets on the day it
    // expires. A seeder run inside the last RENEW_WITHIN_DAYS re-issues it.
    say('the client certificate in the shared volume expires in ' +
        Math.floor(left) + ' days (STS_BAO_RENEW_WITHIN_DAYS is ' +
        RENEW_WITHIN_DAYS + '); issuing a new one.');
  }
  const issued = await call('POST', '/v1/pki/issue/sts-client',
                            { common_name: COMMON_NAME, ttl: CLIENT_TTL },
                            token);
  if (issued.status !== 200 || !issued.body || !issued.body.data) {
    refuse(issued, 'a client certificate could not be issued');
  }
  const data = issued.body.data;
  fs.writeFileSync(certFile, data.certificate + '\n', { mode: 0o644 });
  // 0600 AND THE SERVICE'S (#254). It was 0644 until then, said out loud as a
  // cost: the service ran as root, so no mode could have kept the key from a
  // shell in its container. It runs as uid 10001 now, and the key is that
  // user's alone — written to a temporary name and renamed, so the key is
  // never readable at a wider mode, even for an instant.
  const pending = keyFile + '.new';
  fs.writeFileSync(pending, data.private_key + '\n', { mode: 0o600 });
  ownKey(pending);
  fs.renameSync(pending, keyFile);
  fs.writeFileSync(path.join(CLIENT_DIR, 'issuing-ca.crt'),
                   data.issuing_ca + '\n', { mode: 0o644 });
  say('issued the service its client certificate (CN=' + COMMON_NAME +
      ') into the shared volume.');
  log.debug("Leaving ensureClientCertificate().");
}

// ===========================================================================
// AND THEN PROVE IT, WITH THE CERTIFICATE IT JUST ISSUED.
//
// **THE POLICY IS A FILE AND A FILE IS A CLAIM.** `read-only.hcl` says this
// identity may read two paths and write nothing; whether OpenBao agrees is a
// different question, and one typo in a capability list is the difference
// between a service that cannot rotate its own key-encryption key and one that
// can. So the seeder logs in as the service, reads what the service reads, and
// tries the write the service must never be able to make — and REFUSES TO
// FINISH if the write is accepted.
//
// It is here rather than only in a test because of what it protects: a stack
// that came up with a writable identity would be a stack somebody deployed.
// A test that runs later reports it; this stops it.
// ===========================================================================
async function proveReadOnly() {
  log.debug("Entering proveReadOnly().");
  const cert = fs.readFileSync(path.join(CLIENT_DIR, 'client.crt'));
  const key = fs.readFileSync(path.join(CLIENT_DIR, 'client.key'));
  const login = await new Promise(function (resolve, reject) {
    const url = new URL(ADDR + '/v1/auth/cert/login');
    const payload = Buffer.from('{}');
    const req = https.request({
      method: 'POST', host: url.hostname, port: url.port || 443,
      path: url.pathname, ca: ca, cert: cert, key: key,
      headers: { 'Content-Type': 'application/json',
                 'Content-Length': payload.length }
    }, function (res) {
      let text = '';
      res.on('data', function (c) { text += c; });
      res.on('end', function () {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(text || '{}') });
        } catch (e) {
          log.debug("Caught in a callback in proveReadOnly(): " +
                    ((e && e.message) || e));
          resolve({ status: res.statusCode, body: { raw: text } });
        }
      });
    });
    req.on('error', reject);
    req.end(payload);
  });
  if (login.status !== 200 || !login.body.auth ||
      !login.body.auth.client_token) {
    refuse(login, 'the client certificate this seeder just issued cannot log ' +
                  'in to the store it was issued by');
  }
  const asService = login.body.auth.client_token;
  const policies = (login.body.auth.policies || []).join(', ');

  const read = await call('GET', '/v1/secret/data/' + SECRET_PATH, undefined,
                          asService);
  const data = (read.body && read.body.data && read.body.data.data) || {};
  if (read.status !== 200 || !data.kek || !data.databasePassword) {
    refuse(read, 'the service\'s own identity cannot read the two secrets it ' +
                 'is there to read');
  }

  // THE ONE THAT MATTERS. A 403 is the pass.
  const wrote = await call('POST', '/v1/secret/data/' + SECRET_PATH,
                           { data: { databasePassword: 'proof' } }, asService);
  if (wrote.status !== 403) {
    throw new Error('the service\'s identity was allowed to WRITE its own ' +
                    'secrets — OpenBao answered ' + wrote.status + ' where ' +
                    '403 was ' +
                    'expected. ' + POLICY_FILE + ' is meant to grant ' +
                    'read and nothing else, and this stack will not start ' +
                    'with an identity that can rotate the key its own data ' +
                    'is sealed under.');
  }
  // AND THAT THE POLICY IS NARROW AS WELL AS READ-ONLY: a read of somebody
  // else's path must be refused too, or "read" would mean the whole store.
  const elsewhere = await call('GET', '/v1/secret/data/somebody-else',
                               undefined, asService);
  if (elsewhere.status !== 403) {
    throw new Error('the service\'s identity could reach ' +
                    'secret/data/somebody-else (' + elsewhere.status + '). ' +
                    'The policy is meant to name two paths, not a prefix.');
  }
  // AND THE START-UP SECRETS ARE NOT ITS TO READ (#254): the identity a
  // running service holds must not open `/admin-api` as well.
  const startup = await call('GET', '/v1/secret/data/' + ADMIN_SECRET_PATH,
                             undefined, asService);
  if (startup.status !== 403) {
    throw new Error('the service\'s identity could read secret/' +
                    ADMIN_SECRET_PATH + ' (' + startup.status + '), the ' +
                    'start-up secrets it must read only through a start-up ' +
                    'token. ' + POLICY_FILE + ' names a path it must not.');
  }
  // THE TRANSIT KEY: used, and not changed (#391). A wrap and an unwrap with
  // associated data must work; a rotation, a configuration change and a read
  // of another key must be refused.
  const ad = Buffer.from('sts seed proof', 'utf8').toString('base64');
  const sealed = await call('POST', '/v1/transit/encrypt/' + TRANSIT_KEY,
    { plaintext: nodeCrypto.randomBytes(32).toString('base64'),
      associated_data: ad }, asService);
  const ct = sealed.body && sealed.body.data && sealed.body.data.ciphertext;
  const opened = ct ? await call('POST', '/v1/transit/decrypt/' + TRANSIT_KEY,
    { ciphertext: ct, associated_data: ad }, asService) : null;
  if (sealed.status !== 200 || !opened || opened.status !== 200) {
    refuse(opened || sealed, 'the service\'s identity cannot wrap and ' +
                             'unwrap with the Transit key ' + TRANSIT_KEY);
  }
  const rotated = await call('POST', '/v1/transit/keys/' + TRANSIT_KEY +
                             '/rotate', {}, asService);
  const configured = await call('POST', '/v1/transit/keys/' + TRANSIT_KEY +
                                '/config', { exportable: true }, asService);
  if (rotated.status !== 403 || configured.status !== 403) {
    throw new Error('the service\'s identity was allowed to rotate (' +
                    rotated.status + ') or reconfigure (' +
                    configured.status + ') the Transit key its data keys ' +
                    'are wrapped under, where 403 was expected for both. ' +
                    POLICY_FILE + ' grants its use and nothing else.');
  }
  say('proved it with the certificate itself: policies [' + policies + '], ' +
      'the two secrets readable, a write to them refused 403, no other ' +
      'path reachable (secret/' + ADMIN_SECRET_PATH + ' among them), and ' +
      'the Transit key ' + TRANSIT_KEY + ' usable but neither rotatable nor ' +
      'reconfigurable.');
  log.debug("Leaving proveReadOnly().");
}

async function main() {
  log.debug("Entering main().");
  if (fs.existsSync(CA_FILE)) {
    ca = fs.readFileSync(CA_FILE);
  } else {
    throw new Error('the listener certificate ' + CA_FILE + ' is not there, ' +
                    'so this seeder cannot verify the store it is about to ' +
                    'put secrets in. openbao/generate-tls.js is what mints ' +
                    'it, before the server starts.');
  }
  await waitForListener();
  let held = await rootToken();
  await waitForActive();
  if (held && held.kind === 'seeder' && !(await renewSeederToken(held.token))) {
    log.warn('the seeder token in ' + SEED_DIR + ' is no longer accepted by ' +
             'the store (it is renewed by every run and lapses after ' +
             SEEDER_PERIOD + ' without one). This run proves the client ' +
             'credential only and hands out no start-up token; set ' +
             'STS_BAO_TOKEN to an operator token to restore it.');
    held = null;
  }
  if (!held) {
    // A SECOND STACK WITH NO TOKEN (see the header). Nothing is re-declared;
    // what this stack needs is a client credential the store accepts, and that
    // can be proved without any token at all.
    const certFile = path.join(CLIENT_DIR, 'client.crt');
    if (!fs.existsSync(certFile) ||
        !fs.existsSync(path.join(CLIENT_DIR, 'client.key'))) {
      throw new Error('the secret store is already initialised, this stack ' +
                      'holds neither a root token nor a seeder token in ' +
                      SEED_DIR + ', STS_BAO_TOKEN is not set, and there is ' +
                      'no client certificate in ' + CLIENT_DIR +
                      ' to prove — ' +
                      'so this seeder can neither configure the store nor ' +
                      'show that this stack can read it. Either set ' +
                      'STS_BAO_TOKEN to an operator token for this store, or ' +
                      'put the client credential the store was seeded with ' +
                      '(client.crt, client.key, bao-ca.crt) in ' + CLIENT_DIR +
                      '. For a stack that has lost its own volume state, ' +
                      '`docker compose down --volumes` is the way back.');
    }
    fs.writeFileSync(path.join(CLIENT_DIR, 'bao-ca.crt'),
                     fs.readFileSync(CA_FILE), { mode: 0o644 });
    ownKey(path.join(CLIENT_DIR, 'client.key'));
    await proveReadOnly();
    const left = daysLeft(certFile);
    if (left !== null && left <= RENEW_WITHIN_DAYS) {
      log.warn('the client certificate in ' + CLIENT_DIR + ' expires in ' +
               Math.floor(left) + ' days, and this seeder holds no token to ' +
               'renew it. Run the seeder that holds one, or set ' +
               'STS_BAO_TOKEN.');
    }
    log.warn('no start-up token was written for ' + STARTUP_NODES.join(', ') +
             ': this run holds no token that can make one, so the service ' +
             'starts without the start-up secrets in secret/' +
             ADMIN_SECRET_PATH + '.');
    say('the secret store was initialised by another stack; nothing was ' +
        're-declared, and the client credential this stack holds was proved ' +
        'against it.');
    log.debug("Leaving main(). Proved only.");
    return;
  }
  const token = held.token;
  if (held.kind === 'seeder') {
    // DECLARES NOTHING (#254): the seeder token keeps the start-up secrets
    // as pinned, renews the certificate when due, proves the identity, and
    // hands out the start-up tokens.
    await ensureAdminSecrets(token);
    await ensureClientCertificate(token);
    await proveReadOnly();
    await issueStartupTokens(token);
    await issueOperatorToken(token);
    say('the secret store is ready: nothing re-declared (the seeder token ' +
        'cannot), the client credential proved, and a start-up token per ' +
        'node.');
    log.debug("Leaving main(). Seeder token.");
    return;
  }
  await ensureMount(token, 'secret', 'kv', { options: { version: '2' } });
  await ensureSecrets(token);
  await ensureAdminSecrets(token);
  await ensureTransitKey(token);
  const caPem = await ensurePki(token);
  await ensurePolicy(token);
  await ensureCertAuth(token, caPem);
  await ensureTokenRole(token);
  await ensureClientCertificate(token, caPem);
  await proveReadOnly();
  await issueStartupTokens(token);
  await issueOperatorToken(token);
  if (held.revoke) {
    await ensureSeederToken(token);
    await revokeRoot(held);
  }
  say('the secret store is ready: two secrets and the start-up secrets, one ' +
      'read-only identity, a client certificate the store itself issued, and ' +
      'a start-up token per node.');
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error((e && e.message) ? e.message : e);
  process.exit(1);
});
