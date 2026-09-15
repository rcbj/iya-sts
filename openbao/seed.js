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
//   * **THE DATABASE PASSWORD IS WRITTEN EVERY TIME**, because the database's
//     own copy comes from the same environment variable and the two have to
//     agree. If they ever disagree, the one in the environment is the one the
//     database was built with.
//   * **THE CLIENT CERTIFICATE IS ISSUED ONCE** and left in the shared volume.
//     Re-issuing on every start would be a new credential per restart for no
//     reason; the certificate authority stays inside the store either way.
//   * Everything else — mounts, roles, the policy, the trusted CA — is written
//     on every run, because those are declarations and re-declaring them is
//     free.
//
// ---------------------------------------------------------------------------
// THE ROOT TOKEN IS KEPT, AND THAT IS A DELIBERATE COST.
//
// `PUT /v1/sys/init` hands back a root token exactly once. This writes it into
// the store's own volume so that a later run can re-declare a policy or issue
// a replacement certificate — without it, a restarted stack could only be
// reconfigured by destroying the volume. **It is 0600 and it is in the volume
// the store's own data is in**, which is the same trade the static seal makes
// one file over: this arrangement protects the secrets from a reader of the
// DATABASE, not from somebody who already has the store's disk.
//
// A deployment that wants the real posture revokes it — `bao token revoke`,
// after configuring an auth method for its operators — and this seeder then
// reports that it cannot reconfigure, which is the correct answer rather than
// a surprise.
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
// so, and says that the client certificate's one-year lifetime is renewed
// only when a seeder runs (`ensureClientCertificate()`).
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
const WAIT_SECONDS = Number(process.env.STS_BAO_WAIT_SECONDS || 60);
// An operator's token for a store this stack did not initialise — see the
// header's section on several stacks. Never written anywhere by this script.
const OPERATOR_TOKEN = String(process.env.STS_BAO_TOKEN || '').trim();
// A client certificate this close to expiry is re-issued by a seeder that can.
const RENEW_WITHIN_DAYS = Number(process.env.STS_BAO_RENEW_WITHIN_DAYS || 30);

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
// than an error.
// ---------------------------------------------------------------------------
function call(method, route, body, token) {
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

// The token for a store that is ALREADY initialised: the root token this
// stack's own volume kept, an operator's `STS_BAO_TOKEN`, or null — which
// `main()` turns into proving the credential this stack already holds.
function tokenForInitialisedStore(tokenFile) {
  log.debug("Entering tokenForInitialisedStore().");
  if (fs.existsSync(tokenFile)) {
    say('the store is already initialised; reusing the root token from its ' +
        'own volume.');
    log.debug("Leaving tokenForInitialisedStore(). The kept root token.");
    return String(fs.readFileSync(tokenFile, 'utf8')).trim();
  }
  if (OPERATOR_TOKEN) {
    say('the store is already initialised and this stack holds no root ' +
        'token; using the operator token in STS_BAO_TOKEN.');
    log.debug("Leaving tokenForInitialisedStore(). The operator's token.");
    return OPERATOR_TOKEN;
  }
  log.debug("Leaving tokenForInitialisedStore(). None.");
  return null;
}

async function rootToken() {
  log.debug("Entering rootToken().");
  const tokenFile = path.join(SEED_DIR, 'root.token');
  const status = await call('GET', '/v1/sys/init');
  if (status.body && status.body.initialized) {
    log.debug("Leaving rootToken(). Already initialised.");
    return tokenForInitialisedStore(tokenFile);
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
      return tokenForInitialisedStore(tokenFile);
    }
    refuse(made, 'the secret store could not be initialised');
  }
  fs.mkdirSync(SEED_DIR, { recursive: true });
  fs.writeFileSync(tokenFile, made.body.root_token, { mode: 0o600 });
  fs.writeFileSync(path.join(SEED_DIR, 'recovery-keys.json'),
                   JSON.stringify(made.body.recovery_keys_b64 || [], null, 2),
                   { mode: 0o600 });
  say('initialised the store and kept its root token in the store\'s own ' +
      'volume. See this file\'s header for what that costs.');
  log.debug("Leaving rootToken().");
  return made.body.root_token;
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
async function readSecrets(token) {
  log.debug("Entering readSecrets().");
  const held = await call('GET', '/v1/secret/data/' + SECRET_PATH, undefined,
                          token);
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

async function writeSecrets(token, data, cas) {
  log.debug("Entering writeSecrets(). cas=" + cas);
  const at = '/v1/secret/data/' + SECRET_PATH;
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
                            { common_name: 'mock-sts secret store CA',
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

async function ensurePolicy(token) {
  log.debug("Entering ensurePolicy().");
  const policy = fs.readFileSync(POLICY_FILE, 'utf8');
  const wrote = await call('PUT', '/v1/sys/policies/acl/' + POLICY_NAME,
                           { policy: policy }, token);
  if (wrote.status !== 204 && wrote.status !== 200) {
    refuse(wrote, 'the read-only policy could not be written');
  }
  say('wrote the ' + POLICY_NAME + ' policy from ' + POLICY_FILE +
      ' — read on two paths and no write anywhere.');
  log.debug("Leaving ensurePolicy().");
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
                            { common_name: COMMON_NAME, ttl: '8760h' }, token);
  if (issued.status !== 200 || !issued.body || !issued.body.data) {
    refuse(issued, 'a client certificate could not be issued');
  }
  const data = issued.body.data;
  fs.writeFileSync(certFile, data.certificate + '\n', { mode: 0o644 });
  // 0644 ON A PRIVATE KEY, and it is said out loud rather than left to be
  // found: this volume is shared with one container in this stack and the
  // service in it runs as root. A deployment that wants the real posture
  // mounts its own credential instead of letting this seeder issue one — see
  // openbao/CLAUDE.md, where the line between this fixture and a deployment
  // is drawn.
  fs.writeFileSync(keyFile, data.private_key + '\n', { mode: 0o644 });
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
  say('proved it with the certificate itself: policies [' + policies + '], ' +
      'the two secrets readable, a write to them refused 403, and no other ' +
      'path reachable.');
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
  const token = await rootToken();
  await waitForActive();
  if (!token) {
    // A SECOND STACK WITH NO TOKEN (see the header). Nothing is re-declared;
    // what this stack needs is a client credential the store accepts, and that
    // can be proved without any token at all.
    const certFile = path.join(CLIENT_DIR, 'client.crt');
    if (!fs.existsSync(certFile) ||
        !fs.existsSync(path.join(CLIENT_DIR, 'client.key'))) {
      throw new Error('the secret store is already initialised, this stack ' +
                      'holds no root token in ' + SEED_DIR + ', ' +
                      'STS_BAO_TOKEN is not set, and there is no client ' +
                      'certificate in ' + CLIENT_DIR + ' to prove — so this ' +
                      'seeder can neither configure the store nor show that ' +
                      'this stack can read it. Either set STS_BAO_TOKEN to ' +
                      'an operator token for this store, or put the client ' +
                      'credential the store was seeded with (client.crt, ' +
                      'client.key, bao-ca.crt) in ' + CLIENT_DIR + '. For a ' +
                      'stack that has lost its own volume state, ' +
                      '`docker compose down --volumes` is the way back.');
    }
    fs.writeFileSync(path.join(CLIENT_DIR, 'bao-ca.crt'),
                     fs.readFileSync(CA_FILE), { mode: 0o644 });
    await proveReadOnly();
    const left = daysLeft(certFile);
    if (left !== null && left <= RENEW_WITHIN_DAYS) {
      log.warn('the client certificate in ' + CLIENT_DIR + ' expires in ' +
               Math.floor(left) + ' days, and this seeder holds no token to ' +
               'renew it. Run the seeder that holds one, or set ' +
               'STS_BAO_TOKEN.');
    }
    say('the secret store was initialised by another stack; nothing was ' +
        're-declared, and the client credential this stack holds was proved ' +
        'against it.');
    log.debug("Leaving main(). Proved only.");
    return;
  }
  await ensureMount(token, 'secret', 'kv', { options: { version: '2' } });
  await ensureSecrets(token);
  const caPem = await ensurePki(token);
  await ensurePolicy(token);
  await ensureCertAuth(token, caPem);
  await ensureClientCertificate(token, caPem);
  await proveReadOnly();
  say('the secret store is ready: two secrets, one read-only identity, and a ' +
      'client certificate the store itself issued.');
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error((e && e.message) ? e.message : e);
  process.exit(1);
});
