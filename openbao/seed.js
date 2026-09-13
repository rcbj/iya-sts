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
// ===========================================================================

const fs = require('fs');
const path = require('path');
const https = require('https');
const nodeCrypto = require('crypto');

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

let ca = null;

function say(what) {
  console.log('sts-bao-seed: ' + what);
}

// ---------------------------------------------------------------------------
// ONE REQUEST FUNCTION. It answers `{ status, body }` and NEVER throws for an
// HTTP status: every caller here has a status it is expecting and several have
// a 404 that means "not configured yet", which is the ordinary path rather
// than an error.
// ---------------------------------------------------------------------------
function call(method, route, body, token) {
  return new Promise(function (resolve, reject) {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
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
  const errors = (answer.body && answer.body.errors) || [];
  throw new Error(what + ' — OpenBao answered ' + answer.status +
                  (errors.length ? ': ' + errors.join('; ') : ''));
}

// The listener is up when it answers its own seal status. Waiting here rather
// than in compose's healthcheck as well, because this container may be started
// by a launcher that has no healthcheck to wait on.
async function waitForListener() {
  const until = Date.now() + WAIT_SECONDS * 1000;
  let last = '';
  while (Date.now() < until) {
    try {
      const answer = await call('GET', '/v1/sys/seal-status');
      if (answer.status === 200 && answer.body) {
        return answer.body;
      }
      last = 'status ' + answer.status;
    } catch (e) {
      last = e.message;
    }
    await new Promise(function (r) { setTimeout(r, 1000); });
  }
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
  const until = Date.now() + WAIT_SECONDS * 1000;
  let sealed = null;
  while (Date.now() < until) {
    const health = await call('GET', '/v1/sys/health');
    if (health.status === 200) {
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
  throw new Error('the secret store unsealed and did not become active ' +
                  'within ' + WAIT_SECONDS + ' seconds.');
}

async function rootToken() {
  const tokenFile = path.join(SEED_DIR, 'root.token');
  const status = await call('GET', '/v1/sys/init');
  if (status.body && status.body.initialized) {
    if (!fs.existsSync(tokenFile)) {
      throw new Error('the secret store is already initialised and there is ' +
                      'no root token in ' + tokenFile + ' — so this seeder ' +
                      'cannot configure it. That is the correct answer for a ' +
                      'store somebody else initialised; for a stack that has ' +
                      'lost its volume state, `docker compose down --volumes` ' +
                      'is the way back.');
    }
    say('the store is already initialised; reusing the root token from its ' +
        'own volume.');
    return String(fs.readFileSync(tokenFile, 'utf8')).trim();
  }
  // ONE RECOVERY SHARE. With an auto seal the shares are RECOVERY keys rather
  // than unseal keys — they exist to rekey or to recover, never to start the
  // store — and a quorum of five for a stack that unseals itself would be
  // ceremony with nothing on the other end of it.
  const made = await call('PUT', '/v1/sys/init',
                          { recovery_shares: 1, recovery_threshold: 1 });
  if (made.status !== 200 || !made.body || !made.body.root_token) {
    refuse(made, 'the secret store could not be initialised');
  }
  fs.mkdirSync(SEED_DIR, { recursive: true });
  fs.writeFileSync(tokenFile, made.body.root_token, { mode: 0o600 });
  fs.writeFileSync(path.join(SEED_DIR, 'recovery-keys.json'),
                   JSON.stringify(made.body.recovery_keys_b64 || [], null, 2),
                   { mode: 0o600 });
  say('initialised the store and kept its root token in the store\'s own ' +
      'volume. See this file\'s header for what that costs.');
  return made.body.root_token;
}

async function ensureMount(token, mount, type, options) {
  const mounts = await call('GET', '/v1/sys/mounts', undefined, token);
  if (mounts.status === 200 && mounts.body && mounts.body[mount + '/']) {
    return false;
  }
  const made = await call('POST', '/v1/sys/mounts/' + mount,
                          Object.assign({ type: type }, options || {}), token);
  if (made.status !== 204 && made.status !== 200) {
    refuse(made, 'the "' + mount + '" engine could not be enabled');
  }
  say('enabled the ' + type + ' engine at ' + mount + '/.');
  return true;
}

// Is this answer the kv engine asking to be come back to? The message is the
// only signal — the status is an ordinary 400 — so it is matched on the two
// words that cannot be anything else.
function upgrading(answer) {
  if (!answer || answer.status !== 400) {
    return false;
  }
  const said = JSON.stringify(answer.body || '');
  return /Upgrading from non-versioned/i.test(said);
}

async function ensureSecrets(token) {
  const at = '/v1/secret/data/' + SECRET_PATH;
  const held = await call('GET', at, undefined, token);
  const existing = (held.status === 200 && held.body && held.body.data &&
                    held.body.data.data) || {};
  // THE KEK IS KEPT IF IT IS THERE. See the header: replacing it destroys
  // everything this service has sealed.
  const kek = existing.kek ||
              nodeCrypto.randomBytes(32).toString('base64');
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
  // mistake into a ten-second pause followed by the same mistake.
  // ---------------------------------------------------------------------
  const body = { data: { kek: kek, databasePassword: DB_PASSWORD } };
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
  if (wrote.status !== 200 && wrote.status !== 204) {
    refuse(wrote, 'the secrets could not be written');
  }
  say(existing.kek
    ? 'the key-encryption key was already in the store and was left alone; ' +
      'the database password was refreshed from the environment.'
    : 'generated a key-encryption key and wrote it with the database ' +
      'password. It will never be replaced by this seeder.');
}

async function ensurePki(token) {
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
  return caPem;
}

async function ensurePolicy(token) {
  const policy = fs.readFileSync(POLICY_FILE, 'utf8');
  const wrote = await call('PUT', '/v1/sys/policies/acl/' + POLICY_NAME,
                           { policy: policy }, token);
  if (wrote.status !== 204 && wrote.status !== 200) {
    refuse(wrote, 'the read-only policy could not be written');
  }
  say('wrote the ' + POLICY_NAME + ' policy from ' + POLICY_FILE +
      ' — read on two paths and no write anywhere.');
}

async function ensureCertAuth(token, caPem) {
  const auths = await call('GET', '/v1/sys/auth', undefined, token);
  if (!(auths.status === 200 && auths.body && auths.body['cert/'])) {
    const made = await call('POST', '/v1/sys/auth/cert', { type: 'cert' },
                            token);
    if (made.status !== 204 && made.status !== 200) {
      refuse(made, 'the certificate auth method could not be enabled');
    }
    say('enabled the certificate auth method.');
  }
  // **THE TRUST IS THE STORE'S OWN CA AND THE NAME IS PINNED.** Trusting the
  // CA alone would admit every certificate it ever issues; `allowed_common_names`
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
}

async function ensureClientCertificate(token, caPem) {
  fs.mkdirSync(CLIENT_DIR, { recursive: true });
  const certFile = path.join(CLIENT_DIR, 'client.crt');
  const keyFile = path.join(CLIENT_DIR, 'client.key');
  const caOut = path.join(CLIENT_DIR, 'bao-ca.crt');
  // THE LISTENER'S certificate, which is what the service verifies the
  // CONNECTION against — a different question from who signed the client
  // certificate, and the two are different CAs here on purpose.
  fs.writeFileSync(caOut, fs.readFileSync(CA_FILE), { mode: 0o644 });
  if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
    say('the client certificate is already in the shared volume; it was not ' +
        're-issued.');
    return;
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
          resolve({ status: res.statusCode, body: { raw: text } });
        }
      });
    });
    req.on('error', reject);
    req.end(payload);
  });
  if (login.status !== 200 || !login.body.auth || !login.body.auth.client_token) {
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
                    'secrets — OpenBao answered ' + wrote.status + ' where 403 ' +
                    'was expected. ' + POLICY_FILE + ' is meant to grant read ' +
                    'and nothing else, and this stack will not start with an ' +
                    'identity that can rotate the key its own data is sealed ' +
                    'under.');
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
}

async function main() {
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
  await ensureMount(token, 'secret', 'kv', { options: { version: '2' } });
  await ensureSecrets(token);
  const caPem = await ensurePki(token);
  await ensurePolicy(token);
  await ensureCertAuth(token, caPem);
  await ensureClientCertificate(token, caPem);
  await proveReadOnly();
  say('the secret store is ready: two secrets, one read-only identity, and a ' +
      'client certificate the store itself issued.');
}

main().catch(function (e) {
  console.error('sts-bao-seed: ' + (e && e.message ? e.message : e));
  process.exit(1);
});
