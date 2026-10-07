// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: secret_destinations.js
// ===========================================================================
// SECRET PUSH DESTINATIONS (#221 P3): WHERE A SERVICE ACCOUNT'S ROTATED
// PASSWORD IS WRITTEN, AND THE WRITE.
//
// In process, in a throwaway realm, with every secrets manager FAKED: the
// three cloud SDKs through `secrets.setSdkLoader()`, Vault as a local HTTPS
// server whose CA and certificate are made here with openssl at test time
// (no key material is committed), and the file destination on a temporary
// directory. Held here:
//   A. a destination is an application entry declared for
//      secret-destination; add refuses a missing location, a plain http
//      address and a credential of the wrong shape (STS-SECDEST-0011),
//      naming members and never values;
//   B. the write credential is WRITE-ONLY: sealed-or-clear on the entry,
//      the withheld sentence in every view, absent from the register's view,
//      the API's answer, every audit row and every log line, and in
//      ldap_server.js's SECRET_ATTRIBUTES;
//   C. aws PutSecretValue with the destination's own keys and region, the
//      password or the JSON payload, a missing secret refused
//      (STS-SECDEST-0003);
//   D. gcp AddSecretVersion under the project, a missing secret refused;
//   E. azure: a secret with no versions is refused BEFORE setSecret, so a
//      push never creates one;
//   F. vault over verified TLS: a missing secret (0003), a write naming the
//      version it read (cas), a version written in between refused
//      (STS-SECDEST-0004), a wrong token refused (0005);
//   G. file: written in place in development, never created (0003), never
//      outside its directory (0007), and refused in product (0006, and not
//      offered there);
//   H. testPush writes a canary, and refuses a secret a service account's
//      rotation writes (STS-SECDEST-0010); push() never throws;
//   I. update keeps the credential when none is given; remove deletes the
//      entry; an unknown action and an unknown destination are refused.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');
const realms = require('../common/realms');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
// The directory: an application entry needs one.
require('../ldap/ldap_server');
const applications = require('../common/applications');
const secrets = require('../common/secrets');
const audit = require('../common/audit');
const destinations = require('../common/secret_destinations');
const destinationsApi = require('../mgmt-api/secret_destinations_api');

const log = require('bunyan').createLogger({ name: 'secret_destinations',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
// The credentials and passwords this test writes: none may appear in any
// answer, audit row or log line.
const AWS_SECRET_KEY = 'aws-secret-' + RUN + '-' +
  nodeCrypto.randomBytes(8).toString('hex');
const GCP_PRIVATE_KEY = 'gcp-private-' + RUN;
const AZURE_SECRET = 'azure-secret-' + RUN;
const VAULT_TOKEN = 'hvs.vault-token-' + RUN;
const PASSWORD = 'rotated-' + RUN + '-' +
  nodeCrypto.randomBytes(8).toString('hex');
const SECRETS_TO_HIDE = [AWS_SECRET_KEY, GCP_PRIVATE_KEY, AZURE_SECRET,
                         VAULT_TOKEN, PASSWORD];

const codeOf = function (x) {
  log.debug('Entering codeOf().');
  log.debug('Leaving codeOf().');
  return x && (x.code || errorCodes.codeOf(x));
};

// ---------------------------------------------------------------------------
// THE FAKE SDKs.
// ---------------------------------------------------------------------------
const aws = { secrets: { 'svc/backup': [] }, clients: [] };
const gcp = { secrets: { 'projects/p1/secrets/svc-backup': [] }, clients: [] };
const azure = { secrets: { 'svc-backup': ['v1'] }, sets: [], clients: [] };

function PutSecretValueCommand(input) {
  log.debug('Entering PutSecretValueCommand().');
  this.input = input;
  log.debug('Leaving PutSecretValueCommand().');
}
const fakeSdks = {
  '@aws-sdk/client-secrets-manager': {
    PutSecretValueCommand: PutSecretValueCommand,
    SecretsManagerClient: function (options) {
      log.debug('Entering SecretsManagerClient().');
      aws.clients.push(options);
      this.send = async function (command) {
        log.debug('Entering send().');
        const id = command.input.SecretId;
        if (!aws.secrets[id]) {
          log.debug('Leaving send(). Not found.');
          const e = new Error('Secrets Manager can\'t find the specified ' +
                              'secret.');
          e.name = 'ResourceNotFoundException';
          throw e;
        }
        aws.secrets[id].push(command.input.SecretString);
        log.debug('Leaving send().');
        return { VersionId: 'aws-v' + aws.secrets[id].length };
      };
      log.debug('Leaving SecretsManagerClient().');
    }
  },
  '@google-cloud/secret-manager': {
    SecretManagerServiceClient: function (options) {
      log.debug('Entering SecretManagerServiceClient().');
      gcp.clients.push(options);
      this.addSecretVersion = async function (request) {
        log.debug('Entering addSecretVersion().');
        if (!gcp.secrets[request.parent]) {
          log.debug('Leaving addSecretVersion(). Not found.');
          const e = new Error('5 NOT_FOUND: Secret not found');
          e.code = 5;
          throw e;
        }
        gcp.secrets[request.parent].push(
          Buffer.from(request.payload.data).toString('utf8'));
        log.debug('Leaving addSecretVersion().');
        return [{ name: request.parent + '/versions/' +
                        gcp.secrets[request.parent].length }];
      };
      log.debug('Leaving SecretManagerServiceClient().');
    }
  },
  '@azure/identity': {
    ClientSecretCredential: function (tenant, client, secret) {
      log.debug('Entering ClientSecretCredential().');
      azure.clients.push({ tenant: tenant, client: client, secret: secret });
      log.debug('Leaving ClientSecretCredential().');
    }
  },
  '@azure/keyvault-secrets': {
    SecretClient: function (url) {
      log.debug('Entering SecretClient().');
      this.url = url;
      this.listPropertiesOfSecretVersions = function (name) {
        log.debug('Entering listPropertiesOfSecretVersions().');
        const versions = azure.secrets[name] || [];
        log.debug('Leaving listPropertiesOfSecretVersions().');
        return (async function* () {
          for (const v of versions) {
            yield { version: v };
          }
        })();
      };
      this.setSecret = async function (name, value, options) {
        log.debug('Entering setSecret().');
        azure.sets.push({ name: name, value: value, options: options });
        azure.secrets[name] = (azure.secrets[name] || []).concat(
          ['v' + (azure.sets.length + 1)]);
        log.debug('Leaving setSecret().');
        return { properties: { version: 'az-v' + azure.sets.length } };
      };
      log.debug('Leaving SecretClient().');
    }
  }
};

// ---------------------------------------------------------------------------
// THE FAKE VAULT: a KV version 2 engine at /v1/secret over HTTPS.
// ---------------------------------------------------------------------------
function makeCertificates(dir) {
  log.debug('Entering makeCertificates().');
  const ossl = function (args) {
    const r = childProcess.spawnSync('openssl', args, { cwd: dir,
                                                       encoding: 'utf8' });
    if (r.status !== 0) {
      throw new Error('openssl ' + args[0] + ' failed: ' + r.stderr);
    }
  };
  ossl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
        'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out',
        'ca.crt', '-days', '2', '-subj', '/CN=sd test ca',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
  ossl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj',
        '/CN=localhost']);
  fs.writeFileSync(path.join(dir, 'ext.cnf'),
    'basicConstraints=critical,CA:FALSE\n' +
    'keyUsage=critical,digitalSignature\n' +
    'extendedKeyUsage=serverAuth\n' +
    'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  ossl(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey',
        'ca.key', '-CAcreateserial', '-out', 'leaf.crt', '-days', '2',
        '-extfile', 'ext.cnf']);
  log.debug('Leaving makeCertificates().');
  return { ca: fs.readFileSync(path.join(dir, 'ca.crt'), 'utf8'),
           key: fs.readFileSync(path.join(dir, 'leaf.key')),
           cert: fs.readFileSync(path.join(dir, 'leaf.crt')) };
}

const vault = { secrets: { 'svc/backup': { version: 3, data: {} } },
                requests: [], bumpAfterMetadata: false };

function startVault(material) {
  log.debug('Entering startVault().');
  const server = https.createServer({ key: material.key,
                                      cert: material.cert },
                                    function (req, res) {
    let raw = '';
    req.on('data', function (c) { raw += c; });
    req.on('end', function () {
      const answer = function (status, body) {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      vault.requests.push({ method: req.method, url: req.url,
                            token: req.headers['x-vault-token'],
                            body: raw ? JSON.parse(raw) : null });
      if (req.headers['x-vault-token'] !== VAULT_TOKEN) {
        answer(403, { errors: ['permission denied'] });
        return;
      }
      const meta = /^\/v1\/secret\/metadata\/(.+)$/.exec(req.url);
      const data = /^\/v1\/secret\/data\/(.+)$/.exec(req.url);
      if (meta && req.method === 'GET') {
        const held = vault.secrets[meta[1]];
        if (!held) {
          answer(404, { errors: [] });
          return;
        }
        const version = held.version;
        if (vault.bumpAfterMetadata) {
          held.version++;
        }
        answer(200, { data: { current_version: version } });
        return;
      }
      if (data && req.method === 'POST') {
        const held = vault.secrets[data[1]];
        const body = JSON.parse(raw);
        if (!held || body.options.cas !== held.version) {
          answer(400, { errors: ['check-and-set parameter did not match ' +
                                 'the current version'] });
          return;
        }
        held.version++;
        held.data = body.data;
        answer(200, { data: { version: held.version } });
        return;
      }
      answer(404, { errors: [] });
    });
  });
  log.debug('Leaving startVault().');
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

// ---------------------------------------------------------------------------
// WHAT IS WRITTEN TO STDOUT WHILE THE TEST RUNS: every log line, debug
// included, so the credential and the password can be looked for in them.
// ---------------------------------------------------------------------------
const captured = [];
let originalWrite = null;
function captureOutput() {
  log.debug('Entering captureOutput().');
  originalWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = function (chunk) {
    captured.push(String(chunk));
    return true;
  };
  log.debug('Leaving captureOutput().');
}
function releaseOutput() {
  log.debug('Entering releaseOutput().');
  if (originalWrite) {
    process.stdout.write = originalWrite;
    originalWrite = null;
  }
  log.debug('Leaving releaseOutput().');
}

async function act(body) {
  log.debug('Entering act(). ' + body.action);
  const out = await destinations.act(body, { actor: 'sd-test', via: 'test' });
  log.debug('Leaving act().');
  return out;
}

async function registerAndHide(t, base) {
  log.debug('Entering registerAndHide().');
  t.log.info('=== A. a destination is an application entry ===');
  const missing = await act({ action: 'add-destination',
                              identifier: 'aws-' + RUN, provider: 'aws' });
  t.equal(codeOf(missing), 'STS-SECDEST-0011',
          'A1. an aws destination with no region and no credential is ' +
          'refused');
  const badShape = await act({ action: 'add-destination',
                               identifier: 'aws-' + RUN, provider: 'aws',
                               region: 'us-east-1',
                               credential: JSON.stringify({
                                 accessKeyId: 'AKIA' + RUN }) });
  t.check(codeOf(badShape) === 'STS-SECDEST-0011' &&
          /secretAccessKey/.test(JSON.stringify(badShape)),
          'A2. a credential lacking secretAccessKey is refused, naming the ' +
          'member', JSON.stringify(badShape));
  const plain = await act({ action: 'add-destination',
                            identifier: 'vault-http-' + RUN,
                            provider: 'vault',
                            endpoint: 'http://127.0.0.1:8200',
                            credential: VAULT_TOKEN });
  t.check(codeOf(plain) === 'STS-SECDEST-0011' &&
          JSON.stringify(plain).indexOf(VAULT_TOKEN) < 0,
          'A3. a plain http Vault address is refused, and the refusal does ' +
          'not repeat the token', JSON.stringify(plain));

  const added = await act({ action: 'add-destination',
    identifier: 'aws-' + RUN, name: 'AWS ' + RUN, provider: 'aws',
    region: 'eu-west-1',
    credential: JSON.stringify({ accessKeyId: 'AKIA' + RUN,
                                 secretAccessKey: AWS_SECRET_KEY }) });
  t.check(added.ok && added.destination && added.destination.usable,
          'A4. an aws destination with its region and key is added and ' +
          'usable', JSON.stringify(added));
  const awsRow = destinations.get('aws-' + RUN);
  t.check(!!awsRow && /^cn=/i.test(awsRow.id) &&
          destinations.get(awsRow.id).identifier === 'aws-' + RUN,
          'A5. its id is the application entry\'s DN, and get() finds it ' +
          'by DN and by identifier', awsRow && awsRow.id);
  const view = applications.get('aws-' + RUN);
  t.check(destinations.isDestination(view) &&
          applications.declaredFamiliesOf(view)
            .indexOf('secret-destination') >= 0,
          'A6. the entry is declared for the secret-destination family');
  t.check(!destinations.isDestination(
            { fields: { appAllowedProtocol: ['oauth2'] } }),
          'A7. an application declared for anything else is not a ' +
          'destination');

  t.log.info('=== B. the write credential is write-only ===');
  const viewText = JSON.stringify(view);
  t.check(viewText.indexOf(AWS_SECRET_KEY) < 0 &&
          /withheld: a secret destination/.test(
            String(view.fields.secretDestCredential)) &&
          /withheld: a secret destination/.test(
            String([].concat(view.attributes.secretDestCredential)[0])),
          'B1. the application view carries the withheld sentence in ' +
          'fields and attributes, never the credential');
  t.check(JSON.stringify(destinations.view()).indexOf(AWS_SECRET_KEY) < 0 &&
          awsRow.credentialSet === true,
          'B2. the register\'s view says credentialSet and nothing more');
  t.check(applications.secretDestinationCredentialOf('aws-' + RUN)
            .indexOf(AWS_SECRET_KEY) >= 0,
          'B3. the one reader that pushes opens the credential');
  const routes = destinationsApi.ROUTES;
  const get = routes.filter(function (r) {
    return r.method === 'GET';
  })[0];
  let sent = '';
  const res = { status: function () { return res; },
                type: function () { return res; },
                set: function () { return res; },
                send: function (body) { sent = body; return res; } };
  get.handler({}, res);
  t.check(sent && JSON.parse(sent).destinations.length >= 1 &&
          sent.indexOf(AWS_SECRET_KEY) < 0,
          'B4. GET /admin-api/secret-destinations answers the register ' +
          'without the credential');
  const post = routes.filter(function (r) {
    return r.method === 'POST';
  })[0];
  t.check(post && post.mirrors === 'POST /admin/secret-destinations' &&
          post.actions.map(function (a) { return a.action; }).join(',') ===
            'add-destination,update-destination,remove-destination,' +
            'test-push',
          'B5. the action resource mirrors the page with its four acts');
  const ldapSource = fs.readFileSync(path.join(__dirname, '..', 'ldap',
                                               'ldap_server.js'), 'utf8');
  const list = ldapSource.slice(
    ldapSource.indexOf('const SECRET_ATTRIBUTES = ['),
    ldapSource.indexOf('];', ldapSource.indexOf('const SECRET_ATTRIBUTES')));
  t.check(list.indexOf("'secretdestcredential'") >= 0 &&
          applications.WITHHELD_FIELDS.indexOf('secretDestCredential') >= 0 &&
          applications.SEALED_FIELDS.indexOf('secretDestCredential') >= 0,
          'B6. the credential is sealed, withheld, and a directory secret');
  log.debug('Leaving registerAndHide().');
  return awsRow;
}

async function awsGcpAzure(t, awsRow) {
  log.debug('Entering awsGcpAzure().');
  t.log.info('=== C. aws ===');
  const value = { username: 'svc-backup', password: PASSWORD,
                  realm: realms.currentId(), rotatedAt: '2026-10-06T00:00Z' };
  const pushed = await destinations.push(awsRow.id, 'svc/backup', value);
  const client = aws.clients[aws.clients.length - 1];
  t.check(pushed.ok && pushed.version === 'aws-v1' &&
          aws.secrets['svc/backup'][0] === PASSWORD &&
          client.region === 'eu-west-1' &&
          client.credentials.secretAccessKey === AWS_SECRET_KEY,
          'C1. PutSecretValue writes the bare password with the ' +
          'destination\'s own key and region', JSON.stringify(pushed));
  const missing = await destinations.push(awsRow.id, 'svc/nobody', value);
  t.check(!missing.ok && missing.code === 'STS-SECDEST-0003' &&
          !aws.secrets['svc/nobody'],
          'C2. a secret that does not exist is refused and not created',
          JSON.stringify(missing));
  const changed = await act({ action: 'update-destination', id: awsRow.id,
                              payload: 'json' });
  t.check(changed.ok && changed.destination.payload === 'json' &&
          changed.destination.credentialSet,
          'C3. a change of payload keeps the credential set',
          JSON.stringify(changed));
  await destinations.push(awsRow.id, 'svc/backup', value);
  const json = JSON.parse(aws.secrets['svc/backup'][1]);
  t.check(json.username === 'svc-backup' && json.password === PASSWORD &&
          json.realm === value.realm && json.rotatedAt === value.rotatedAt &&
          Object.keys(json).length === 4,
          'C4. the json payload is {username, password, realm, rotatedAt}');

  t.log.info('=== D. gcp ===');
  const gAdd = await act({ action: 'add-destination',
    identifier: 'gcp-' + RUN, provider: 'gcp', project: 'p1',
    credential: JSON.stringify({ client_email: 'sts@p1.iam.example',
                                 private_key: GCP_PRIVATE_KEY }) });
  t.check(gAdd.ok, 'D1. a gcp destination is added', JSON.stringify(gAdd));
  const gPush = await destinations.push('gcp-' + RUN, 'svc-backup', value);
  t.check(gPush.ok && gPush.version === '1' &&
          gcp.secrets['projects/p1/secrets/svc-backup'][0] === PASSWORD &&
          gcp.clients[gcp.clients.length - 1].credentials.private_key ===
            GCP_PRIVATE_KEY,
          'D2. AddSecretVersion under the destination\'s project, with its ' +
          'service account', JSON.stringify(gPush));
  const gMissing = await destinations.push('gcp-' + RUN, 'nobody', value);
  t.equal(gMissing.code, 'STS-SECDEST-0003',
          'D3. a missing secret is refused');

  t.log.info('=== E. azure ===');
  const zAdd = await act({ action: 'add-destination',
    identifier: 'azure-' + RUN, provider: 'azure',
    endpoint: 'https://sd.vault.azure.example',
    credential: JSON.stringify({ tenantId: 't', clientId: 'c',
                                 clientSecret: AZURE_SECRET }) });
  t.check(zAdd.ok, 'E1. an azure destination is added', JSON.stringify(zAdd));
  const zPush = await destinations.push('azure-' + RUN, 'svc-backup', value);
  t.check(zPush.ok && azure.sets.length === 1 &&
          azure.sets[0].value === PASSWORD &&
          azure.clients[azure.clients.length - 1].secret === AZURE_SECRET,
          'E2. setSecret on a secret that has versions', JSON.stringify(zPush));
  const zMissing = await destinations.push('azure-' + RUN, 'nobody', value);
  t.check(zMissing.code === 'STS-SECDEST-0003' && azure.sets.length === 1,
          'E3. a secret with no versions is refused BEFORE setSecret, which ' +
          'would have created it');
  log.debug('Leaving awsGcpAzure().');
}

async function vaultPushes(t, material, port) {
  log.debug('Entering vaultPushes().');
  t.log.info('=== F. vault over verified TLS ===');
  const value = { username: 'svc-backup', password: PASSWORD,
                  realm: realms.currentId(), rotatedAt: '2026-10-06T00:00Z' };
  const added = await act({ action: 'add-destination',
    identifier: 'vault-' + RUN, provider: 'vault',
    endpoint: 'https://localhost:' + port, caCertificates: material.ca,
    credential: VAULT_TOKEN });
  t.check(added.ok && added.destination.usable,
          'F1. a vault destination with its CA is added',
          JSON.stringify(added));
  const missing = await destinations.push('vault-' + RUN, 'svc/nobody',
                                          value);
  t.equal(missing.code, 'STS-SECDEST-0003',
          'F2. a secret with no metadata is refused');
  const ok = await destinations.push('vault-' + RUN, 'svc/backup', value);
  const write = vault.requests.filter(function (r) {
    return r.method === 'POST';
  }).pop();
  t.check(ok.ok && ok.version === '4' && write.body.options.cas === 3 &&
          write.body.data.value === PASSWORD,
          'F3. the write names the version it read (cas 3) and puts the ' +
          'password in the value field', JSON.stringify(ok));
  vault.bumpAfterMetadata = true;
  const conflict = await destinations.push('vault-' + RUN, 'svc/backup',
                                           value);
  vault.bumpAfterMetadata = false;
  t.check(!conflict.ok && conflict.code === 'STS-SECDEST-0004' &&
          vault.secrets['svc/backup'].data.value === PASSWORD,
          'F4. a version written in between is a check-and-set conflict, ' +
          'and nothing is overwritten', JSON.stringify(conflict));
  await act({ action: 'update-destination', id: 'vault-' + RUN,
              credential: 'hvs.wrong' });
  const denied = await destinations.push('vault-' + RUN, 'svc/backup',
                                         value);
  t.check(!denied.ok && denied.code === 'STS-SECDEST-0005' &&
          JSON.stringify(denied).indexOf('hvs.wrong') < 0,
          'F5. a token the store refuses is STS-SECDEST-0005, without the ' +
          'token in the answer', JSON.stringify(denied));
  await act({ action: 'update-destination', id: 'vault-' + RUN,
              caCertificates: '' });
  await act({ action: 'update-destination', id: 'vault-' + RUN,
              credential: VAULT_TOKEN });
  const untrusted = await destinations.push('vault-' + RUN, 'svc/backup',
                                            value);
  t.check(!untrusted.ok && untrusted.code === 'STS-SECDEST-0005',
          'F6. without its CA the listener\'s certificate is not trusted, ' +
          'and nothing is sent', JSON.stringify(untrusted));
  log.debug('Leaving vaultPushes().');
}

async function fileAndTest(t, dir) {
  log.debug('Entering fileAndTest().');
  t.log.info('=== G. file, development only ===');
  fs.writeFileSync(path.join(dir, 'svc-backup'), 'old', { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'canary'), '', { mode: 0o600 });
  const added = await act({ action: 'add-destination',
    identifier: 'file-' + RUN, provider: 'file', directory: dir });
  t.check(added.ok && added.destination.usable,
          'G1. a file destination needs no credential in development',
          JSON.stringify(added));
  const value = { username: 'svc-backup', password: PASSWORD,
                  realm: realms.currentId(), rotatedAt: 'now' };
  const ok = await destinations.push('file-' + RUN, 'svc-backup', value);
  t.check(ok.ok && fs.readFileSync(path.join(dir, 'svc-backup'), 'utf8') ===
            PASSWORD,
          'G2. the password is written into the existing file');
  const none = await destinations.push('file-' + RUN, 'not-there', value);
  t.check(none.code === 'STS-SECDEST-0003' &&
          !fs.existsSync(path.join(dir, 'not-there')),
          'G3. a file that does not exist is refused, not created');
  const out = await destinations.push('file-' + RUN, '../escape', value);
  t.equal(out.code, 'STS-SECDEST-0007',
          'G4. a name that leaves the directory is refused');
  fs.symlinkSync(path.join(dir, 'svc-backup'), path.join(dir, 'link'));
  const link = await destinations.push('file-' + RUN, 'link', value);
  t.equal(link.code, 'STS-SECDEST-0007', 'G5. a link is not written');

  t.log.info('=== H. test push ===');
  const tested = await act({ action: 'test-push', id: 'file-' + RUN,
                             secretName: 'canary' });
  const canary = fs.readFileSync(path.join(dir, 'canary'), 'utf8');
  t.check(tested.ok && canary.length >= 40 && canary !== PASSWORD,
          'H1. a test push writes a random canary to the test secret',
          JSON.stringify(tested));
  const guarded = new destinations.SecretDestinations(Object.assign(
    destinations.SecretDestinations.defaultDeps(), {
      loadServiceAccounts: function () {
        return { secretNameInUse: function (id, name) {
          return name === 'svc-backup';
        } };
      } }));
  const refused = await guarded.testPush('file-' + RUN, 'svc-backup');
  t.check(!refused.ok && refused.code === 'STS-SECDEST-0010' &&
          fs.readFileSync(path.join(dir, 'svc-backup'), 'utf8') === PASSWORD,
          'H2. a test push to a service account\'s secret is refused and ' +
          'writes nothing', JSON.stringify(refused));
  const nowhere = await destinations.push('no-such-' + RUN, 'x', value);
  t.equal(nowhere.code, 'STS-SECDEST-0009',
          'H3. a push to no destination answers a refusal, never a throw');

  config.setOverride('global.mode', 'product');
  try {
    const product = await destinations.push('file-' + RUN, 'svc-backup',
                                            value);
    const row = destinations.get('file-' + RUN);
    const refusedAdd = await act({ action: 'add-destination',
      identifier: 'file2-' + RUN, provider: 'file', directory: dir });
    t.check(product.code === 'STS-SECDEST-0006' && !row.usable &&
            codeOf(refusedAdd) === 'STS-SECDEST-0006' &&
            destinations.view().providers.indexOf('file') < 0,
            'G6. in product a file destination is not usable, not offered, ' +
            'not added, and a push to it is refused',
            JSON.stringify(product));
  } finally {
    config.clearOverride('global.mode');
  }

  t.log.info('=== I. the register\'s acts ===');
  const unknown = await act({ action: 'rotate', id: 'file-' + RUN });
  t.equal(codeOf(unknown), 'STS-SECDEST-0012',
          'I1. an unknown action is refused');
  const noOne = await act({ action: 'remove-destination', id: 'nobody' });
  t.equal(codeOf(noOne), 'STS-SECDEST-0009',
          'I2. an unknown destination is refused');
  const gone = await act({ action: 'remove-destination', id: 'file-' + RUN });
  t.check(gone.ok && !destinations.get('file-' + RUN) &&
          !applications.get('file-' + RUN),
          'I3. remove deletes the application entry');
  log.debug('Leaving fileAndTest().');
}

async function run(t) {
  log.debug('Entering run().');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sd-'));
  const files = fs.mkdtempSync(path.join(os.tmpdir(), 'sd-files-'));
  const material = makeCertificates(dir);
  const server = await startVault(material);
  const realm = realms.create({ id: 'sd-' + RUN,
                                name: 'secret destinations ' + RUN }).realm;
  secrets.setSdkLoader(function (name) {
    if (fakeSdks[name]) {
      return fakeSdks[name];
    }
    throw new Error('Cannot find module ' + name);
  });
  const helpersLog = require('../common/helpers').log;
  const level = helpersLog.level();
  helpersLog.level('debug');
  captureOutput();
  try {
    await realms.run(realm, async function () {
      const awsRow = await registerAndHide(t);
      await awsGcpAzure(t, awsRow);
      await vaultPushes(t, material, server.address().port);
      await fileAndTest(t, files);
      const rows = JSON.stringify(audit.list());
      t.check(SECRETS_TO_HIDE.every(function (s) {
        return rows.indexOf(s) < 0;
      }) && /secret-destination\.push/.test(rows),
              'B7. the audit rows name the pushes and hold no credential or ' +
              'password');
    });
  } finally {
    releaseOutput();
    helpersLog.level(level);
    secrets.setSdkLoader(null);
    server.close();
    realms.remove(realm.id);
  }
  const output = captured.join('');
  // What the harness and the service said above debug is written out now,
  // as it would have been: the assertions' own lines among it.
  captured.forEach(function (line) {
    if (line.indexOf('"level":20,') < 0) {
      process.stdout.write(line);
    }
  });
  const leaked = SECRETS_TO_HIDE.filter(function (s) {
    return output.indexOf(s) >= 0;
  });
  t.check(captured.length > 100 && leaked.length === 0,
          'B8. no log line, debug included, holds a credential or a ' +
          'password (' + captured.length + ' lines read)',
          leaked.join(', '));
  log.debug('Leaving run().');
}

module.exports = {
  name: 'secret_destinations',
  describe: 'Secret push destinations (#221 P3), every store faked: ' +
            'application entries declared for secret-destination, the ' +
            'write-only credential, aws / gcp / azure / vault (cas) / file ' +
            'pushes that never create a secret, the test push and its ' +
            'guard, and the file destination refused in product',
  run: run
};
