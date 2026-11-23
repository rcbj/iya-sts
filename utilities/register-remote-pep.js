#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: utilities/register-remote-pep.js
// ---------------------------------------------------------------------------
// REGISTERS A NEW REMOTE XACML PEP WITH THE SERVICE, END TO END (rcbj,
// 2026-11-16: "I need a utility script, command, or documented process to
// register a new remote pep").
//
// Every step is a management API call an operator could make by hand, in
// the order docs/v1.2.0/remote-pep.md's *Registering a new remote PEP, step
// by step* gives them, and nothing here is a door of its own:
//
//   1. the PEP's entry, a person whose username is PEP_NAME
//      (POST /admin-api/users/create);
//   2. the entry in the remote PEPs group, `roles.remotePepGroup`
//      (POST /admin-api/groups/add-member);
//   3. the entry a service account with an owner: joining makes it one,
//      owned by the realm's Admin Write group, and where that group is
//      missing --owner names one (POST /admin-api/users/set-service-account);
//   4. its RFC 7523 assertion key, generated HERE and certified from a
//      PKCS #10 request (POST /admin-api/xacml/issue-pep-credential). The
//      private key is written to --out and never sent or printed;
//   5. with --cluster, its membership of a remote PEP cluster
//      (POST /admin-api/xacml/add-pep-cluster-member);
//   6. its HTTPS listener pair (POST /admin-api/xacml/issue-pep-certificate),
//      which the realm issues only to a PEP that has REGISTERED — so on the
//      first run it is planned (the environment names the two paths) and a
//      second run, after the container has started, issues it;
//   7. the container's environment (<out>/pep.env) and a compose service
//      (<out>/docker-compose.pep.yml). With --cluster that compose is the
//      whole cluster: every member recorded under the same parent directory,
//      one load balancer in front, published on 127.0.0.1 only, and the
//      companion container (hostname companion, upstream of /pep-app).
//      There is no TCP forwarder. A PEP_PDP_URL of https://localhost:<port>
//      is the service a browser opens; the compose points that name at the
//      sts container;
//   8. the companion's /pep-app on that cluster's reverse proxy: a
//      confidential client and one role on both read and write. A --cluster
//      run does this. --pep-app is the same switch, and it is refused
//      without --cluster. A run without a public https origin cannot save
//      a session route;
//   9. with --cluster, and not on --dry-run, `docker compose up -d` of that
//      file: the members, the load balancer and the companion. It does not
//      start or recreate the identity service. The tests image has no
//      Docker daemon, so the suite sets REGISTER_PEP_NO_START.
//
// **IT IS IDEMPOTENT, AND EACH STEP SAYS HOW.** A door that answers a repeat
// with a 400 is never asked twice: the entry and the cluster membership are
// read first and skipped when present. `groups/add-member` and
// `users/set-service-account` answer a repeat 200 with nothing changed, so
// they are simply called. `issue-pep-credential` ADDS a key every time it is
// called, so it is called only when the certificate in --out is not a valid
// key on the entry; the listener pair is issued only when --out holds none
// (`--reissue-https` replaces it). The companion path is saved only when
// that route is not already the one role's, and an application already in
// the registry keeps the client secret it has. `--dry-run` makes no write
// anywhere and says what each step would do.
//
// TLS: the service's certificate is verified. `--ca` (or
// NODE_EXTRA_CA_CERTS) names the anchor; `--insecure` turns verification
// off and says so on every run, and NODE_TLS_REJECT_UNAUTHORIZED=0 without
// it is refused rather than obeyed silently. Plain http:// is accepted only
// for a loopback address.
//
// It runs where the service's npm dependencies are: in the service image
// (`node utilities/register-remote-pep.js`, which .dockerignore lets in) or
// in a checkout after `npm ci`. The key and the request come from
// `pep-assertion-request.js` beside it. Its `log` is a console-backed
// logger of bunyan's shape, quiet unless REGISTER_PEP_DEBUG is set.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const childProcess = require('child_process');

const log = {
  debug: function (message) {
    if (process.env.REGISTER_PEP_DEBUG) {
      console.error(message);
    }
  }
};

const PEP_CLIENT_ID = 'sts-remote-pep';
const KEY_FILE = 'pep-assertion.key';
const CSR_FILE = 'pep-assertion.csr';
const CRT_FILE = 'pep-assertion.crt';
const SERVER_CRT = path.join('server', 'pep-server.crt');
const SERVER_KEY = path.join('server', 'pep-server.key');
const SERVICE_CA = 'service-ca.pem';
const ENV_FILE = 'pep.env';
const COMPOSE_FILE = 'docker-compose.pep.yml';
// The companion demonstration (--pep-app). One prefix covers every page
// companion/pep_app.js serves under /pep-app, including POST of an item.
const PEP_APP_SCOPES = ['openid', 'profile', 'email', 'offline_access'];
const PEP_APP_GRANTS = ['authorization_code', 'refresh_token'];
const PEP_APP_AUTH = ['client_secret_basic', 'client_secret_post'];
const PEP_APP_METHODS = ['GET', 'HEAD', 'POST'];
const PEP_APP_CALLBACK = '/.iya-pep/callback';
// What companion/pep_app.js's whoami page reads off the forwarded request.
const PEP_APP_HEADERS = [
  { name: 'X-Remote-User', claim: 'username' },
  { name: 'X-Iya-User', claim: 'sub' },
  { name: 'X-Iya-Email', claim: 'email' },
  { name: 'X-Iya-Name', claim: 'name' },
  { name: 'X-Iya-Groups', claim: 'groups' },
  { name: 'X-Iya-Auth', claim: 'mechanism' },
  { name: 'X-Iya-Amr', claim: 'amr' }
];

const USAGE = `Usage: register-remote-pep.js --url=URL --name=NAME --out=DIR [options]

Registers a remote XACML PEP: its directory entry, its membership of the
remote PEPs group, its RFC 7523 assertion key (generated here; only a
certificate request is sent), optionally its cluster membership and its
HTTPS listener pair, and writes the container's environment. Safe to run
again: what is already there is reported and skipped.

  --url URL          The service's base URL, https://sts.example.net:8081
  --realm ID         The trust realm the PEP pulls from (default: the
                     default realm)
  --name NAME        The PEP's username, which is its PEP_NAME
  --out DIR          Where the key, the certificates and the environment go
  --cluster NAME     Make it a member of this remote PEP cluster, register
                     /pep-app in front of the companion, and start the
                     containers: the members, one load balancer on
                     127.0.0.1 at a free port, and the companion. No TCP
                     forwarder. Put every member's --out in one directory
                     so one compose lists them all. Does not start the
                     identity service
  --create-cluster   Create --cluster, empty, when it does not exist
  --pep-app          Register /pep-app. Implied by --cluster. Refused
                     without it. Defaults: application pep-app, role
                     pep-app (read and write), path /pep-app, upstream
                     http://companion:9700, public base the load
                     balancer's origin (https://localhost:9543 when
                     that port is free)
  --app ID           That path's application (default pep-app)
  --role NAME        The one role that may read and write it (default
                     pep-app). Created empty; grant it to people yourself
  --path PATH        The path prefix (default /pep-app)
  --upstream URL     Where the proxy forwards it (default
                     http://companion:9700)
  --public-base URL  The https origin a browser reaches the proxy at
                     (default https://localhost:9543, or the free port
                     the cluster's load balancer took). The client's
                     redirect URI is this origin plus /.iya-pep/callback
  --key-alg ALG      ec-p256 (default) or rsa-2048
  --owner WHO        Who owns the entry as a service account: a group's cn,
                     a username or a DN; repeat or separate with commas.
                     Default: the realm's Admin Write group. --owner-group
                     is the same option.
  --group CN         The remote PEPs group (default: roles.remotePepGroup)
  --pdp-url URL      PEP_PDP_URL, the address the CONTAINER dials (default:
                     --url with the realm's prefix)
  --mount DIR        Where the container mounts --out (default /certs)
  --https-dns NAMES  Extra DNS names for the HTTPS listener certificate
  --https-ip ADDRS   Extra IP addresses for it
  --reissue-https    Issue the listener pair again, replacing the one in --out
  --new-key          Generate and certify a new assertion key even though
                     --out holds a valid one
  --revoke-previous  With the new key, revoke the entry's other keys
  --ca FILE          A PEM file of the CA that issued the service's
                     certificate; copied to --out for the PEP as PEP_TLS_CA
  --insecure         Do not verify the service's certificate (said loudly)
  --dry-run          Read only: say what each step would do, write nothing
  --help             This text

The management API token: STS_ADMIN_API_TOKEN (admin:read admin:write,
audienced to <url>/admin-api; a default-realm token works for every realm).
Or mint one with the client-credentials grant: --client ID (default
sts-api-client) and the secret in ADMIN_API_CLIENT_SECRET,
ADMIN_API_CLIENT_SECRET_FILE or --secret-file; --realm-client when the
client is the realm's own.

Exit status: 0 registered (or would be, with --dry-run), 1 a step failed,
2 usage.`;

// The options that take a value, by flag.
const VALUED = {
  '--url': 'url', '--realm': 'realm', '--name': 'name', '--out': 'out',
  '--cluster': 'cluster', '--key-alg': 'keyAlg', '--owner': 'owner',
  '--owner-group': 'owner', '--group': 'group', '--pdp-url': 'pdpUrl',
  '--mount': 'mount', '--https-dns': 'httpsDns', '--https-ip': 'httpsIp',
  '--ca': 'ca', '--client': 'client', '--secret-file': 'secretFile',
  '--app': 'app', '--role': 'role', '--path': 'path',
  '--upstream': 'upstream', '--public-base': 'publicBase'
};
const FLAGS = {
  '--create-cluster': 'createCluster', '--reissue-https': 'reissueHttps',
  '--new-key': 'newKey', '--revoke-previous': 'revokePrevious',
  '--insecure': 'insecure', '--dry-run': 'dryRun',
  '--realm-client': 'realmClient', '--pep-app': 'pepApp',
  '--help': 'help', '-h': 'help'
};
// The options that may be given more than once, gathered into a list.
const LISTS = ['owner', 'httpsDns', 'httpsIp'];

/**
 * Reads the command line: `--flag=value` and `--flag value` alike.
 *
 * @param argv - the arguments after the script's name
 * @returns the options, or `{ problem }`
 */
function parseArgs(argv) {
  log.debug("Entering parseArgs().");
  const out = { owner: [], httpsDns: [], httpsIp: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = String(argv[i]);
    const eq = arg.indexOf('=');
    const flag = eq > 0 ? arg.slice(0, eq) : arg;
    if (FLAGS[flag] && eq < 0) {
      out[FLAGS[flag]] = true;
      continue;
    }
    if (!VALUED[flag]) {
      log.debug("Leaving parseArgs(). Refused " + arg + ".");
      return { problem: 'Not understood: ' + arg };
    }
    let value = '';
    if (eq > 0) {
      value = arg.slice(eq + 1);
    } else if (i + 1 < argv.length) {
      value = String(argv[i + 1]);
      i = i + 1;
    } else {
      log.debug("Leaving parseArgs(). No value.");
      return { problem: flag + ' needs a value.' };
    }
    const key = VALUED[flag];
    if (LISTS.indexOf(key) >= 0) {
      value.split(',').map(function (one) {
        return one.trim();
      }).filter(Boolean).forEach(function (one) {
        out[key].push(one);
      });
    } else {
      out[key] = value;
    }
  }
  log.debug("Leaving parseArgs().");
  return out;
}

/**
 * A step that failed: which one, what the service said, what to do next.
 */
class StepError extends Error {
  /**
   * @param step - the step's title
   * @param said - what went wrong, the refusal's own words included
   * @param next - what the operator does about it
   */
  constructor(step, said, next) {
    super(step + ' failed: ' + said);
    log.debug("Entering StepError.constructor(). " + step);
    this.step = step;
    this.said = said;
    this.next = next || '';
    log.debug("Leaving StepError.constructor().");
  }
}

/**
 * The refusal's own words from an answer: `error_description`, `errors`,
 * `why` or `error`, whichever it carries, else the start of the body.
 *
 * @param answer - `{ status, body, text }`
 * @returns one line
 */
function refusalOf(answer) {
  log.debug("Entering refusalOf().");
  const body = (answer && answer.body) || {};
  const words = body.error_description ||
    (Array.isArray(body.errors) && body.errors.length
      ? body.errors.join(' ') : '') ||
    body.why || body.error ||
    String((answer && answer.text) || '').replace(/\s+/g, ' ').slice(0, 300);
  log.debug("Leaving refusalOf().");
  return 'HTTP ' + ((answer && answer.status) || 0) + ': ' + words;
}

/**
 * Makes one HTTP(S) request and reads a JSON answer where there is one.
 *
 * @param url - the URL
 * @param options - method, headers, body, and the TLS options
 * @returns a promise of `{ status, body, text }`
 */
function request(url, options) {
  log.debug("Entering request(). " + options.method + " " + url);
  const target = new URL(url);
  const client = target.protocol === 'http:' ? http : https;
  return new Promise(function (resolve, reject) {
    const bounded = Object.assign({ signal: AbortSignal.timeout(120000) },
                                  options);
    delete bounded.body;
    const req = client.request(target, bounded, function (res) {
      const chunks = [];
      res.on('data', function (chunk) {
        chunks.push(chunk);
      });
      res.on('end', function () {
        const text = Buffer.concat(chunks).toString('utf8');
        let body = null;
        try {
          body = JSON.parse(text);
        } catch (e) {
          // An HTML 404 (an unknown realm's prefix) is not JSON; the text
          // is what refusalOf() reports.
          log.debug("Caught in request(): " + ((e && e.message) || e));
          body = null;
        }
        log.debug("Leaving request(). " + res.statusCode);
        resolve({ status: res.statusCode, body: body, text: text });
      });
    });
    req.on('error', reject);
    req.end(options.body);
  });
}

/**
 * The management API's two verbs, on one token and one set of TLS options.
 *
 * @param api - the API's base, the realm's prefix included
 * @param token - the access token
 * @param tlsOptions - the TLS options
 * @returns `{ get(path), post(path, body) }`
 */
function apiClient(api, token, tlsOptions) {
  log.debug("Entering apiClient().");
  const headers = { authorization: 'Bearer ' + token };
  const failed = function (method, where, e) {
    log.debug("Entering failed(). " + where);
    log.debug("Leaving failed().");
    return { status: 0, body: null,
             text: method + ' ' + where + ' could not be sent: ' +
                   ((e && e.message) || e) };
  };
  log.debug("Leaving apiClient().");
  return {
    get: function (where) {
      log.debug("Entering get(). " + where);
      log.debug("Leaving get().");
      return request(api + where, Object.assign({ method: 'GET',
        headers: headers }, tlsOptions)).catch(function (e) {
        log.debug("Caught in get(): " + ((e && e.message) || e));
        return failed('GET', where, e);
      });
    },
    post: function (where, payload) {
      log.debug("Entering post(). " + where);
      const body = JSON.stringify(payload || {});
      log.debug("Leaving post().");
      return request(api + where, Object.assign({ method: 'POST', body: body,
        headers: Object.assign({ 'content-type': 'application/json',
          'content-length': Buffer.byteLength(body) }, headers) },
        tlsOptions)).catch(function (e) {
        log.debug("Caught in post(): " + ((e && e.message) || e));
        return failed('POST', where, e);
      });
    }
  };
}

/**
 * The TLS options every call carries, and the refusals of a configuration
 * that would turn verification off without saying so.
 *
 * @param opts - the options
 * @param target - the service's URL
 * @returns `{ options, caPem }` or `{ problem }`
 */
function tlsSetup(opts, target) {
  log.debug("Entering tlsSetup().");
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    log.debug("Leaving tlsSetup(). Not http(s).");
    return { problem: '--url must be an https:// URL.' };
  }
  if (target.protocol === 'http:' &&
      !/^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/i.test(target.hostname)) {
    log.debug("Leaving tlsSetup(). Plain HTTP off loopback.");
    return { problem: '--url is plain http:// to ' + target.hostname + '. ' +
             'The management API token would travel in the clear, so ' +
             'http:// is accepted only for a loopback address. Use the ' +
             'service\'s https:// URL.' };
  }
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' && !opts.insecure) {
    log.debug("Leaving tlsSetup(). Verification off by the environment.");
    return { problem: 'NODE_TLS_REJECT_UNAUTHORIZED=0 is set, which turns ' +
             'off verification of the service\'s certificate without a ' +
             'word. Unset it and name the service\'s CA with --ca (or ' +
             'NODE_EXTRA_CA_CERTS), or pass --insecure to do it knowingly.' };
  }
  const options = { rejectUnauthorized: !opts.insecure };
  let caPem = '';
  const caFile = opts.ca || process.env.NODE_EXTRA_CA_CERTS || '';
  if (caFile) {
    try {
      caPem = fs.readFileSync(caFile, 'utf8');
    } catch (e) {
      log.debug("Caught in tlsSetup(): " + ((e && e.message) || e));
      log.debug("Leaving tlsSetup(). The CA file.");
      return { problem: 'The CA file ' + caFile + ' could not be read: ' +
               ((e && e.message) || e) };
    }
    if (opts.ca) {
      // `ca` REPLACES node's own roots, so they are kept beside it: a
      // service with a publicly trusted certificate still verifies.
      options.ca = tls.rootCertificates.concat([caPem]);
    }
  }
  if (opts.insecure) {
    console.error('WARNING: --insecure: the service\'s certificate is NOT ' +
                  'verified on this run, and the management API token is ' +
                  'sent to whoever answers ' + target.host + '.');
  }
  log.debug("Leaving tlsSetup().");
  return { options: options, caPem: caPem };
}

/**
 * Finds the management API token: STS_ADMIN_API_TOKEN, or one minted with
 * the client-credentials grant.
 *
 * @param opts - the options
 * @param origin - the service's origin
 * @param prefix - the realm's prefix, '' for the default realm
 * @param tlsOptions - the TLS options
 * @returns a promise of the token
 */
async function findToken(opts, origin, prefix, tlsOptions) {
  log.debug("Entering findToken().");
  if (process.env.STS_ADMIN_API_TOKEN) {
    log.debug("Leaving findToken(). From the environment.");
    return process.env.STS_ADMIN_API_TOKEN;
  }
  const file = opts.secretFile || (process.env.ADMIN_API_CLIENT_SECRET ? ''
    : process.env.ADMIN_API_CLIENT_SECRET_FILE);
  let secret = '';
  try {
    secret = file ? fs.readFileSync(file, 'utf8').trim()
      : String(process.env.ADMIN_API_CLIENT_SECRET || '');
  } catch (e) {
    log.debug("Caught in findToken(): " + ((e && e.message) || e));
    throw new StepError('Getting a management API token',
      'the secret file ' + file + ' could not be read: ' +
      ((e && e.message) || e), 'Name a readable file.');
  }
  if (!secret) {
    log.debug("Leaving findToken(). Nothing to use.");
    throw new StepError('Getting a management API token',
      'there is no STS_ADMIN_API_TOKEN and no client secret',
      'Set STS_ADMIN_API_TOKEN to an admin:read admin:write token for ' +
      origin + '/admin-api, or ADMIN_API_CLIENT_SECRET(_FILE) for --client ' +
      '(docs/v1.2.0/management-api.md, Getting a token).');
  }
  const base = origin + (opts.realmClient ? prefix : '');
  const client = opts.client || 'sts-api-client';
  const form = new URLSearchParams({ grant_type: 'client_credentials',
    scope: 'admin:read admin:write', resource: base + '/admin-api' })
    .toString();
  const basic = Buffer.from(encodeURIComponent(client) + ':' +
                            encodeURIComponent(secret)).toString('base64');
  let answer = null;
  try {
    answer = await request(base + '/oauth2/token', Object.assign({
      method: 'POST', body: form,
      headers: { 'content-type': 'application/x-www-form-urlencoded',
                 authorization: 'Basic ' + basic,
                 'content-length': Buffer.byteLength(form) } }, tlsOptions));
  } catch (e) {
    log.debug("Caught in findToken(): " + ((e && e.message) || e));
    answer = { status: 0, body: null, text: String((e && e.message) || e) };
  }
  if (answer.status !== 200 || !answer.body || !answer.body.access_token) {
    log.debug("Leaving findToken(). Refused.");
    throw new StepError('Getting a management API token',
      'the token endpoint refused ' + client + ': ' + refusalOf(answer),
      'Check the client and its secret, and that it holds ADMIN_READ and ' +
      'ADMIN_WRITE (docs/v1.2.0/management-api.md, An application of your ' +
      'own).');
  }
  log.debug("Leaving findToken(). Minted.");
  return answer.body.access_token;
}

/**
 * Prints one step's outcome.
 *
 * @param step - the step's title
 * @param outcome - what happened, or would
 */
function report(step, outcome) {
  log.debug("Entering report().");
  console.log('* ' + step + ': ' + outcome);
  log.debug("Leaving report().");
}

/**
 * Writes a file, creating its directory; a private one at 0600.
 *
 * @param file - the path
 * @param text - the contents
 * @param secret - whether only the owner may read it
 */
function writeOut(file, text, secret) {
  log.debug("Entering writeOut(). " + file);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const mode = secret ? 0o600 : 0o644;
  fs.writeFileSync(file, text, { mode: mode });
  fs.chmodSync(file, mode);
  log.debug("Leaving writeOut().");
}

/**
 * Finds a setting's value anywhere in the configuration answer.
 *
 * @param node - the answer, or a part of it
 * @param key - the setting's key
 * @returns the value, or undefined
 */
function settingIn(node, key) {
  log.debug("Entering settingIn(). " + key);
  if (!node || typeof node !== 'object') {
    log.debug("Leaving settingIn(). Not here.");
    return undefined;
  }
  if (node.key === key && node.value !== undefined) {
    log.debug("Leaving settingIn(). Found.");
    return node.value;
  }
  const keys = Object.keys(node);
  for (let i = 0; i < keys.length; i++) {
    const found = settingIn(node[keys[i]], key);
    if (found !== undefined) {
      log.debug("Leaving settingIn(). Found below.");
      return found;
    }
  }
  log.debug("Leaving settingIn(). Not found.");
  return undefined;
}

/**
 * Reads one person's drill-down.
 *
 * @param api - the API client
 * @param name - the username
 * @returns a promise of `{ found, serviceAccount, jwtKeys, answer }`
 */
async function readEntry(api, name) {
  log.debug("Entering readEntry(). " + name);
  const answer = await api.get('/users?user=' + encodeURIComponent(name));
  if (answer.status !== 200 || !answer.body) {
    log.debug("Leaving readEntry(). Refused.");
    throw new StepError('Reading the PEP\'s entry', refusalOf(answer),
      'GET /admin-api/users?user=' + name + ' must answer; check the token ' +
      'and the realm.');
  }
  const body = answer.body;
  if (body.known && body.ldap === null) {
    log.debug("Leaving readEntry(). No directory.");
    throw new StepError('Reading the PEP\'s entry',
      'this service has no directory loaded', 'A remote PEP\'s identity is ' +
      'a directory entry; start the service with its directory.');
  }
  const pairs = (body.credentials && body.credentials.keyPairs) || [];
  const jwt = pairs.filter(function (one) {
    return one.purpose === 'jwt';
  })[0];
  log.debug("Leaving readEntry().");
  return { found: !!(body.known && body.ldap && body.ldap.found),
           serviceAccount: body.serviceAccount || null,
           jwtKeys: (jwt && jwt.keys) || [], answer: answer };
}

/**
 * A certificate serial number in the one form two of them are compared in.
 *
 * @param serial - hex, any case, perhaps with leading zeros or colons
 * @returns lower-case hex with no leading zeros
 */
function serialKey(serial) {
  log.debug("Entering serialKey().");
  const plain = String(serial || '').replace(/[^0-9a-f]/gi, '')
    .toLowerCase().replace(/^0+/, '');
  log.debug("Leaving serialKey().");
  return plain;
}

/**
 * What the assertion key files in --out hold: whether the certificate
 * belongs to the key, and its serial.
 *
 * @param out - the directory
 * @returns `{ key, csr, crt, serial, matches, notAfter }`
 */
function heldCredential(out) {
  log.debug("Entering heldCredential().");
  const read = function (name) {
    log.debug("Entering read(). " + name);
    const file = path.join(out, name);
    log.debug("Leaving read().");
    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  };
  const held = { key: read(KEY_FILE), csr: read(CSR_FILE),
                 crt: read(CRT_FILE), serial: '', matches: false,
                 notAfter: '' };
  if (held.key && held.crt) {
    try {
      const leaf = new crypto.X509Certificate(held.crt);
      const spki = function (keyObject) {
        log.debug("Entering spki().");
        log.debug("Leaving spki().");
        return keyObject.export({ type: 'spki', format: 'der' })
          .toString('base64');
      };
      held.matches = spki(leaf.publicKey) ===
        spki(crypto.createPublicKey(held.key));
      held.serial = leaf.serialNumber;
      held.notAfter = leaf.validTo;
    } catch (e) {
      log.debug("Caught in heldCredential(): " + ((e && e.message) || e));
      held.matches = false;
    }
  }
  log.debug("Leaving heldCredential().");
  return held;
}

/**
 * The preflight: the token works, the realm exists, and what the service
 * calls the two groups.
 *
 * @param api - the API client
 * @param opts - the options
 * @param where - a description of the target, for messages
 * @returns a promise of `{ peps, group, writeGroup, writeGroupExists }`
 */
async function preflight(api, opts, where) {
  log.debug("Entering preflight().");
  const step = 'Checking the token and the realm';
  const peps = await api.get('/xacml/peps?pep=' +
                             encodeURIComponent(opts.name));
  if (peps.status === 401 || peps.status === 403) {
    log.debug("Leaving preflight(). Token refused.");
    throw new StepError(step, refusalOf(peps), 'Give a management API ' +
      'token carrying admin:read and admin:write, audienced to ' +
      where.origin + '/admin-api (a default-realm token works under every ' +
      'realm\'s prefix): docs/v1.2.0/management-api.md, Getting a token.');
  }
  if (peps.status === 404) {
    log.debug("Leaving preflight(). No such realm.");
    throw new StepError(step, refusalOf(peps), (opts.realm
      ? 'There is no realm "' + opts.realm + '" at ' + where.origin +
        '. GET /admin-api/realms lists them.'
      : 'Check --url: nothing answers /admin-api there.'));
  }
  if (peps.status !== 200 || !peps.body) {
    log.debug("Leaving preflight(). Not answered.");
    throw new StepError(step, refusalOf(peps), 'Check --url, the ' +
      'service\'s certificate (--ca) and that the service is up.');
  }
  let group = opts.group || '';
  if (!group) {
    const config = await api.get('/config');
    group = String((config.body && settingIn(config.body,
      'roles.remotePepGroup')) || 'remote-peps');
  }
  const groups = await api.get('/groups?q=' + encodeURIComponent(group));
  if (groups.status !== 200 || !groups.body) {
    log.debug("Leaving preflight(). Groups unread.");
    throw new StepError(step, refusalOf(groups), 'GET /admin-api/groups ' +
      'must answer for this token.');
  }
  const named = function (list, cn) {
    log.debug("Entering named(). " + cn);
    log.debug("Leaving named().");
    return (list || []).some(function (row) {
      return String(row.cn || '').toLowerCase() === cn.toLowerCase();
    });
  };
  if (!named(groups.body.groups, group)) {
    log.debug("Leaving preflight(). No remote PEPs group.");
    throw new StepError(step, 'the realm has no group "' + group + '"',
      'Every realm seeds the group roles.remotePepGroup names. Name the ' +
      'right one with --group, or create it (POST ' +
      '/admin-api/groups/create).');
  }
  const writeGroup = String((groups.body.adminGroups &&
                             groups.body.adminGroups.write) || 'admin-write');
  const writers = await api.get('/groups?q=' +
                                encodeURIComponent(writeGroup));
  log.debug("Leaving preflight().");
  return { peps: peps.body, group: group, writeGroup: writeGroup,
           writeGroupExists: !!(writers.body &&
                                named(writers.body.groups, writeGroup)) };
}

/**
 * Steps 1 to 3: the entry, its membership and its service account.
 *
 * @param api - the API client
 * @param opts - the options
 * @param facts - what the preflight learned
 * @returns a promise of the entry as it now stands, or null on a dry run
 *   that would create it
 */
async function ensureIdentity(api, opts, facts) {
  log.debug("Entering ensureIdentity().");
  const owners = opts.owner.length ? opts.owner
    : (facts.writeGroupExists ? [facts.writeGroup] : []);
  let entry = await readEntry(api, opts.name);
  const step1 = '1. The entry ' + opts.name;
  if (entry.found) {
    report(step1, 'exists; skipped.');
  } else if (opts.dryRun) {
    report(step1, 'would be created' + (owners.length
      ? ', a service account owned by ' + owners.join(', ') : '') + '.');
  } else {
    const made = await api.post('/users/create', Object.assign({
      username: opts.name, invent: false, credential: 'none',
      attributes: { cn: opts.name, givenName: 'Remote', sn: 'Remote PEP',
                    displayName: opts.name,
                    description: 'remote XACML PEP ' + opts.name +
                                 ', registered by register-remote-pep.js' }
    }, owners.length ? { serviceAccount: true, owners: owners } : {}));
    if (made.status === 400 && made.body && made.body.existing) {
      // THE DIRECTORY HAS IT though the read above did not say so: the
      // create's refusal names the entry, which is the answer wanted.
      report(step1, 'exists (' + made.body.existing.dn + '); skipped.');
    } else if (made.status !== 200 || !made.body || !made.body.ok) {
      log.debug("Leaving ensureIdentity(). Create refused.");
      throw new StepError(step1, refusalOf(made), owners.length
        ? 'Check that the owner(s) ' + owners.join(', ') + ' exist in ' +
          'this realm, or name others with --owner.'
        : 'Name the entry\'s owner with --owner (a group or a person): ' +
          'created as a service account, it is held to no person\'s ' +
          'attribute policy.');
    } else {
      report(step1, 'created (' + made.body.dn + ', no password' +
        (owners.length ? ', a service account owned by ' +
          owners.join(', ') : '') + ').');
    }
  }
  const step2 = '2. Membership of ' + facts.group;
  if (opts.dryRun) {
    report(step2, 'would be ensured (add-member answers a member already ' +
                  'listed with nothing changed).');
  } else {
    const joined = await api.post('/groups/add-member',
                                  { group: facts.group, member: opts.name });
    if (joined.status !== 200 || !joined.body || !joined.body.ok) {
      log.debug("Leaving ensureIdentity(). Join refused.");
      throw new StepError(step2, refusalOf(joined), 'Add ' + opts.name +
        ' to ' + facts.group + ' on the console (Directory -> Groups) and ' +
        'run this again.');
    }
    report(step2, joined.body.changed ? 'added.' : 'already a member; ' +
           'skipped.');
  }
  const step3 = '3. Service account';
  entry = entry.found || !opts.dryRun ? await readEntry(api, opts.name)
    : entry;
  if (entry.serviceAccount) {
    report(step3, 'yes, owned by ' + (entry.serviceAccount.owners || [])
      .map(function (one) {
        return one.name || one.dn;
      }).join(', ') + '.');
    log.debug("Leaving ensureIdentity(). Already one.");
    return entry;
  }
  if (!owners.length) {
    if (opts.dryRun) {
      report(step3, 'NOBODY TO OWN IT: the realm has no "' +
        facts.writeGroup + '" group, so joining makes it a service account ' +
        'only where the realm has a bootstrap administrator ' +
        '(STS-SVCACCT-0051 otherwise). Pass --owner.');
      log.debug("Leaving ensureIdentity(). Dry run, no owner.");
      return entry;
    }
    log.debug("Leaving ensureIdentity(). No owner.");
    throw new StepError(step3, 'joining ' + facts.group + ' did not make ' +
      opts.name + ' a service account: the realm has no Admin Write group ' +
      '("' + facts.writeGroup + '") and no bootstrap administrator to own ' +
      'it, so the service left it unchanged and logged STS-SVCACCT-0051',
      'Run this again with --owner=<a group or person of this realm> ' +
      '(or create the "' + facts.writeGroup + '" group). Until then ' +
      'issue-pep-credential refuses it (STS-XACML-0299).');
  }
  if (opts.dryRun) {
    report(step3, 'would be made one, owned by ' + owners.join(', ') + '.');
    log.debug("Leaving ensureIdentity(). Dry run.");
    return entry;
  }
  const set = await api.post('/users/set-service-account',
    { user: opts.name, serviceAccount: true, owners: owners });
  if (set.status !== 200 || !set.body || !set.body.ok) {
    log.debug("Leaving ensureIdentity(). Not made one.");
    throw new StepError(step3, refusalOf(set), 'Check the owner(s) ' +
      owners.join(', ') + ', or make it one on the person\'s Service ' +
      'account tab.');
  }
  report(step3, 'made one, owned by ' + owners.join(', ') + '.');
  log.debug("Leaving ensureIdentity().");
  return readEntry(api, opts.name);
}

/**
 * Step 4: the assertion key, generated here and certified from its request.
 *
 * @param api - the API client
 * @param opts - the options
 * @param entry - the entry as it stands
 * @returns a promise of `{ kid, notAfter }` or null on a dry run
 */
async function ensureCredential(api, opts, entry) {
  log.debug("Entering ensureCredential().");
  const step = '4. The assertion key';
  const held = heldCredential(opts.out);
  const registered = function (serial) {
    log.debug("Entering registered().");
    const wanted = serialKey(serial);
    log.debug("Leaving registered().");
    return (entry.jwtKeys || []).filter(function (one) {
      return wanted && serialKey(one.serialHex) === wanted;
    })[0] || null;
  };
  const on = held.matches ? registered(held.serial) : null;
  if (on && on.state === 'valid' && !opts.newKey) {
    report(step, 'the key in ' + path.join(opts.out, KEY_FILE) + ' is ' +
           'registered and valid (kid ' + on.handle + ', until ' +
           (on.notAfter || held.notAfter) + '); skipped.');
    log.debug("Leaving ensureCredential(). Held.");
    return { kid: on.handle, notAfter: on.notAfter || held.notAfter };
  }
  if (on && !opts.newKey) {
    log.debug("Leaving ensureCredential(). Not valid.");
    throw new StepError(step, 'the key in ' + path.join(opts.out, KEY_FILE) +
      ' is registered on ' + opts.name + ' but ' + (on.state || 'not valid') +
      (on.reason ? ' (' + on.reason + ')' : ''),
      'Run again with --new-key to generate and certify a new one.');
  }
  const reuse = !opts.newKey && held.key && held.csr;
  if (opts.dryRun) {
    report(step, reuse
      ? 'would certify the request already in ' + opts.out + '.'
      : 'would generate a key (' + (opts.keyAlg || 'ec-p256') + ') in ' +
        opts.out + ' and certify its request.');
    log.debug("Leaving ensureCredential(). Dry run.");
    return null;
  }
  if (!opts.newKey && held.key && !held.csr) {
    log.debug("Leaving ensureCredential(). Key without a request.");
    throw new StepError(step, path.join(opts.out, KEY_FILE) + ' exists ' +
      'with no ' + CSR_FILE + ' beside it', 'Run again with --new-key; a ' +
      'private key this tool did not write is never overwritten silently.');
  }
  let made = null;
  // A NEW KEY IS STAGED BESIDE THE OLD ONE and moved into place only once
  // it is certified, so a refusal leaves a running PEP its working key.
  const stage = opts.newKey && held.key ? '.new' : '';
  if (reuse) {
    made = { privateKeyPem: held.key, csrPem: held.csr };
  } else {
    const requests = require('./pep-assertion-request.js');
    try {
      made = await requests.assertionRequest({
        keyAlg: opts.keyAlg || 'ec-p256', name: opts.name });
    } catch (e) {
      log.debug("Caught in ensureCredential(): " + ((e && e.message) || e));
      throw new StepError(step, 'the key could not be generated: ' +
        ((e && e.message) || e), 'Use --key-alg=ec-p256 or rsa-2048, and ' +
        'run where the service\'s npm dependencies are (the service image, ' +
        'or a checkout after npm ci).');
    }
    writeOut(path.join(opts.out, KEY_FILE + stage), made.privateKeyPem,
             true);
    writeOut(path.join(opts.out, CSR_FILE + stage), made.csrPem, false);
  }
  const answer = await api.post('/xacml/issue-pep-credential',
    Object.assign({ name: opts.name, csr: made.csrPem },
                  opts.revokePrevious ? { revokePrevious: true } : {}));
  if (answer.status !== 200 || !answer.body || !answer.body.ok) {
    log.debug("Leaving ensureCredential(). Refused.");
    throw new StepError(step, refusalOf(answer), 'The key and its request ' +
      'are in ' + opts.out + '; nothing was registered. Fix what the ' +
      'refusal names and run this again: it certifies the same request.');
  }
  if (stage) {
    fs.renameSync(path.join(opts.out, KEY_FILE + stage),
                  path.join(opts.out, KEY_FILE));
    fs.renameSync(path.join(opts.out, CSR_FILE + stage),
                  path.join(opts.out, CSR_FILE));
  }
  writeOut(path.join(opts.out, CRT_FILE),
           String(answer.body.fullChainPem || answer.body.certificatePem ||
                  ''), false);
  report(step, (reuse ? 'certified the request already in ' + opts.out
    : 'generated a key (' + made.keyAlg + ') and certified its request') +
    ' as ' + answer.body.urn + ' (kid ' + answer.body.kid + ', until ' +
    answer.body.notAfter + ')' + ((answer.body.revoked || []).length
      ? '; revoked ' + answer.body.revoked.join(', ') : '') +
    '. The private key was not sent.');
  log.debug("Leaving ensureCredential().");
  return { kid: answer.body.kid, notAfter: answer.body.notAfter };
}

/**
 * Step 5: the cluster membership.
 *
 * @param api - the API client
 * @param opts - the options
 * @returns a promise of the cluster's name, or ''
 */
async function ensureCluster(api, opts) {
  log.debug("Entering ensureCluster().");
  if (!opts.cluster) {
    log.debug("Leaving ensureCluster(). None asked.");
    return '';
  }
  const step = '5. Cluster ' + opts.cluster;
  const listed = await api.get('/xacml/pep-clusters');
  if (listed.status !== 200 || !listed.body) {
    log.debug("Leaving ensureCluster(). Unread.");
    throw new StepError(step, refusalOf(listed), 'GET ' +
      '/admin-api/xacml/pep-clusters must answer for this token.');
  }
  const clusters = listed.body.clusters || [];
  const holding = clusters.filter(function (one) {
    return (one.members || []).some(function (member) {
      return member.pep === opts.name;
    });
  })[0];
  if (holding && holding.name === opts.cluster) {
    report(step, 'already a member; skipped.');
    log.debug("Leaving ensureCluster(). A member.");
    return opts.cluster;
  }
  if (holding) {
    log.debug("Leaving ensureCluster(). Another cluster.");
    throw new StepError(step, opts.name + ' is a member of cluster "' +
      holding.name + '", and a PEP is a member of one cluster at most',
      'Remove it there first (POST /admin-api/xacml/' +
      'remove-pep-cluster-member), or leave out --cluster.');
  }
  const exists = clusters.some(function (one) {
    return one.name === opts.cluster;
  });
  if (!exists && !opts.createCluster) {
    log.debug("Leaving ensureCluster(). No such cluster.");
    throw new StepError(step, 'this realm has no cluster "' + opts.cluster +
      '"', 'Check the name (GET /admin-api/xacml/pep-clusters lists them), ' +
      'or pass --create-cluster to create it, empty.');
  }
  if (opts.dryRun) {
    report(step, (exists ? '' : 'would be created, empty, and ') +
           opts.name + ' would join it.');
    log.debug("Leaving ensureCluster(). Dry run.");
    return opts.cluster;
  }
  if (!exists) {
    const made = await api.post('/xacml/create-pep-cluster',
                                { cluster: opts.cluster });
    if (made.status !== 200 || !made.body || !made.body.ok) {
      log.debug("Leaving ensureCluster(). Not created.");
      throw new StepError(step, refusalOf(made), 'Create it on the ' +
        'console (XACML -> PEP clusters) and run this again.');
    }
  }
  const joined = await api.post('/xacml/add-pep-cluster-member',
                                { cluster: opts.cluster, pep: opts.name });
  if (joined.status !== 200 || !joined.body || !joined.body.ok) {
    log.debug("Leaving ensureCluster(). Not joined.");
    throw new StepError(step, refusalOf(joined), 'Add it on the cluster\'s ' +
      'Members tab, or with POST /admin-api/xacml/add-pep-cluster-member.');
  }
  report(step, (exists ? '' : 'created, empty; ') + 'joined. It pulls the ' +
         'cluster\'s configuration once it registers.');
  log.debug("Leaving ensureCluster().");
  return opts.cluster;
}

/**
 * The companion path's options, with the demonstration's defaults.
 *
 * @param opts - the options
 * @returns `{ app, role, path, upstream, publicBase, routeId }`
 */
function pepAppSpec(opts) {
  log.debug("Entering pepAppSpec().");
  const pathName = opts.path || '/pep-app';
  const routeId = pathName.replace(/^\/+|\/+$/g, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-') || 'pep-app';
  let publicBase = opts.publicBase || 'https://localhost:9543';
  try {
    publicBase = new URL(publicBase).origin;
  } catch (e) {
    // pepAppProblem() refuses a value that is not a URL; the raw text is
    // what that sentence quotes.
    log.debug("Caught in pepAppSpec(): " + ((e && e.message) || e));
  }
  const spec = {
    app: opts.app || 'pep-app',
    role: opts.role || 'pep-app',
    path: pathName,
    upstream: opts.upstream || 'http://companion:9700',
    publicBase: publicBase,
    routeId: routeId
  };
  log.debug("Leaving pepAppSpec().");
  return spec;
}

/**
 * What is wrong with --pep-app's options, or '' when they can be saved.
 *
 * @param opts - the options
 * @returns a sentence, or ''
 */
function pepAppProblem(opts) {
  log.debug("Entering pepAppProblem().");
  const spec = pepAppSpec(opts);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(spec.app)) {
    log.debug("Leaving pepAppProblem(). The application.");
    return '--app is the application\'s identifier: letters, digits, ".", ' +
      '"_" and "-", at most 64, starting with a letter or a digit.';
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,63}$/.test(spec.role)) {
    log.debug("Leaving pepAppProblem(). The role.");
    return '--role is a role name: up to 64 characters of letters, digits, ' +
      'and . _ : @ - or a space, starting with a letter or a digit.';
  }
  const dotted = spec.path.split('/').some(function (segment) {
    return segment === '.' || segment === '..';
  });
  if (spec.path.charAt(0) !== '/' || spec.path.length > 1024 ||
      spec.path.indexOf('//') >= 0 || /[%\\?#\s\u0000-\u001f\u007f]/.test(
        spec.path) || dotted || spec.path === '/.iya-pep' ||
      spec.path.indexOf('/.iya-pep/') === 0) {
    log.debug("Leaving pepAppProblem(). The path.");
    return '--path is an absolute path the proxy may forward (default ' +
      '/pep-app). It may not be /.iya-pep or under it, which the proxy ' +
      'keeps for its callback and sign-out.';
  }
  let base = null;
  try {
    base = new URL(opts.publicBase || 'https://localhost:9543');
  } catch (e) {
    log.debug("Caught in pepAppProblem(): " + ((e && e.message) || e));
    log.debug("Leaving pepAppProblem(). The public base.");
    return '--public-base is not a URL: ' +
      (opts.publicBase || 'https://localhost:9543');
  }
  if (base.protocol !== 'https:' || base.pathname !== '/' || base.search ||
      base.hash) {
    log.debug("Leaving pepAppProblem(). The public base is not an origin.");
    return '--public-base is the https origin a browser reaches the proxy ' +
      'at — scheme, host and port, no path (default ' +
      'https://localhost:9543). A session route\'s callback is ' +
      PEP_APP_CALLBACK + ' at that origin, and it is refused over http.';
  }
  let upstream = null;
  try {
    upstream = new URL(spec.upstream);
  } catch (e) {
    log.debug("Caught in pepAppProblem(): " + ((e && e.message) || e));
    log.debug("Leaving pepAppProblem(). The upstream.");
    return '--upstream is not a URL: ' + spec.upstream;
  }
  if ((upstream.protocol !== 'http:' && upstream.protocol !== 'https:') ||
      upstream.username || upstream.password || upstream.search ||
      upstream.hash) {
    log.debug("Leaving pepAppProblem(). The upstream's shape.");
    return '--upstream is an http or https URL with no user name, ' +
      'password, query or fragment (default http://companion:9700).';
  }
  log.debug("Leaving pepAppProblem().");
  return '';
}

/**
 * One attribute's values off an application reply. `attributes` is the
 * whole entry; `fields` is the editable subset.
 *
 * @param entry - the reply
 * @param attribute - the attribute's name
 * @returns the values, as strings
 */
function attributeValues(entry, attribute) {
  log.debug("Entering attributeValues(). " + attribute);
  const fields = (entry && (entry.attributes || entry.fields)) || {};
  const held = fields[attribute];
  let out = [];
  if (Array.isArray(held)) {
    out = held.map(String);
  } else if (held !== undefined && held !== null && held !== '') {
    out = [String(held)];
  }
  log.debug("Leaving attributeValues(). " + out.length);
  return out;
}

/**
 * Throws the step's refusal unless the answer succeeded.
 *
 * @param step - the step's title
 * @param answer - `{ status, body, text }`
 * @param next - what the operator does about a refusal
 */
function requireOk(step, answer, next) {
  log.debug("Entering requireOk().");
  if (!answer || answer.status !== 200 || !answer.body ||
      answer.body.ok === false) {
    log.debug("Leaving requireOk(). Refused.");
    throw new StepError(step, refusalOf(answer), next);
  }
  log.debug("Leaving requireOk().");
}

/**
 * Whether two lists of strings are the same, in order.
 *
 * @param left - one list
 * @param right - the other
 * @returns true when they are
 */
function sameStrings(left, right) {
  log.debug("Entering sameStrings().");
  const ok = Array.isArray(left) && Array.isArray(right) &&
    left.length === right.length && left.every(function (one, index) {
      return one === right[index];
    });
  log.debug("Leaving sameStrings(). " + ok);
  return ok;
}

/**
 * The route --pep-app saves: one prefix, the session mechanism, and one
 * role for both actions of the read-write model.
 *
 * @param spec - `pepAppSpec()`'s answer
 * @returns the route
 */
function pepAppRoute(spec) {
  log.debug("Entering pepAppRoute().");
  const route = {
    id: spec.routeId,
    path: spec.path,
    match: 'prefix',
    methods: PEP_APP_METHODS.slice(),
    mechanisms: ['session'],
    application: spec.app,
    authorization: {
      kind: 'simple',
      actionModel: 'read-write',
      roles: { read: [spec.role], write: [spec.role] }
    },
    identity: {
      mode: 'headers',
      headers: PEP_APP_HEADERS.map(function (one) {
        return { name: one.name, claim: one.claim };
      }),
      separator: ','
    },
    signals: true,
    multipleAccounts: false,
    forwardCredentials: false
  };
  log.debug("Leaving pepAppRoute().");
  return route;
}

/**
 * Whether the stored route is already the one this command would save.
 *
 * @param route - a route from the cluster's proxy document
 * @param spec - `pepAppSpec()`'s answer
 * @returns true when a second run should skip it
 */
function routeReady(route, spec) {
  log.debug("Entering routeReady().");
  const auth = (route && route.authorization) || {};
  const roles = auth.roles || {};
  const identity = (route && route.identity) || {};
  const headers = identity.headers || [];
  const headersOk = headers.length === PEP_APP_HEADERS.length &&
    PEP_APP_HEADERS.every(function (one, index) {
      return headers[index] && headers[index].name === one.name &&
        headers[index].claim === one.claim;
    });
  const ok = !!route && route.path === spec.path &&
    route.match === 'prefix' &&
    sameStrings(route.methods, PEP_APP_METHODS) &&
    sameStrings(route.mechanisms, ['session']) &&
    route.application === spec.app &&
    auth.kind === 'simple' && auth.actionModel === 'read-write' &&
    sameStrings(roles.read, [spec.role]) &&
    sameStrings(roles.write, [spec.role]) &&
    route.signals === true && route.multipleAccounts === false &&
    route.forwardCredentials === false &&
    identity.mode === 'headers' && identity.separator === ',' && headersOk;
  log.debug("Leaving routeReady(). " + ok);
  return ok;
}

/**
 * The redirect URIs the session route needs: the cluster's public base,
 * and any member that publishes an address of its own.
 *
 * @param spec - `pepAppSpec()`'s answer
 * @param cluster - the cluster's view, or null
 * @returns the callback URIs
 */
function callbacksFor(spec, cluster) {
  log.debug("Entering callbacksFor().");
  const list = [spec.publicBase + PEP_APP_CALLBACK];
  ((cluster && cluster.members) || []).forEach(function (member) {
    const own = member && member.publicBaseUrl;
    if (!own || own === spec.publicBase) {
      return;
    }
    const uri = String(own).replace(/\/+$/, '') + PEP_APP_CALLBACK;
    if (list.indexOf(uri) < 0) {
      list.push(uri);
    }
  });
  log.debug("Leaving callbacksFor().");
  return list;
}

/**
 * The role, created when the realm does not have it. A repeat is a skip:
 * create-role refuses a name that exists.
 *
 * @param api - the API client
 * @param step - the step's title
 * @param spec - `pepAppSpec()`'s answer
 * @param dryRun - whether to write nothing
 * @returns a promise of `created`, `exists` or `would`
 */
async function ensurePepRole(api, step, spec, dryRun) {
  log.debug("Entering ensurePepRole().");
  const listed = await api.get('/roles?role=' +
                                encodeURIComponent(spec.role));
  if (listed.status !== 200 || !listed.body) {
    log.debug("Leaving ensurePepRole(). Unread.");
    throw new StepError(step, refusalOf(listed), 'GET /admin-api/roles ' +
      'must answer for this token.');
  }
  if (listed.body.role && listed.body.role.found) {
    log.debug("Leaving ensurePepRole(). It exists.");
    return 'exists';
  }
  if (dryRun) {
    log.debug("Leaving ensurePepRole(). Dry run.");
    return 'would';
  }
  const made = await api.post('/roles/create-role', {
    role: spec.role,
    displayName: spec.role,
    description: 'May use ' + spec.app + ' through the remote PEP ' +
      '(read and write).'
  });
  requireOk(step, made, 'Create the role on the console (Directory -> ' +
    'Roles) and run this again. A simple route is refused until the role ' +
    'exists (STS-XACML-0266).');
  log.debug("Leaving ensurePepRole(). Created.");
  return 'created';
}

/**
 * The confidential client, created when it is not in the registry. An
 * existing one is given the callback, the code grant and the two secret
 * methods it lacks, and keeps the secret it already holds.
 *
 * @param api - the API client
 * @param step - the step's title
 * @param spec - `pepAppSpec()`'s answer
 * @param callbacks - the redirect URIs to register
 * @param dryRun - whether to write nothing
 * @returns a promise of `{ state, secret }`. `secret` is set only when one
 *   was generated on this run
 */
async function ensurePepApplication(api, step, spec, callbacks, dryRun) {
  log.debug("Entering ensurePepApplication().");
  const got = await api.get('/applications?application=' +
                             encodeURIComponent(spec.app));
  if (got.status !== 200 || !got.body) {
    log.debug("Leaving ensurePepApplication(). Unread.");
    throw new StepError(step, refusalOf(got), 'GET /admin-api/' +
      'applications must answer for this token.');
  }
  const next = 'Fix what the refusal names and run this again. The ' +
    'application is not forgotten, so a secret already issued is kept.';
  if (!got.body.found) {
    if (dryRun) {
      log.debug("Leaving ensurePepApplication(). Dry run.");
      return { state: 'would', secret: '' };
    }
    const secret = crypto.randomBytes(48).toString('base64')
      .replace(/[^A-Za-z0-9]/g, '').slice(0, 48);
    const made = await api.post('/applications/create', {
      identifier: spec.app,
      name: spec.app,
      protocols: ['oauth2', 'oidc'],
      fields: {
        oauthClientId: spec.app,
        oauthClientSecret: secret,
        oauthConfidential: 'TRUE',
        oauthTokenEndpointAuthMethod: PEP_APP_AUTH.slice(),
        oauthRedirectUri: callbacks.slice(),
        oauthGrantType: PEP_APP_GRANTS.slice(),
        oauthResponseType: ['code'],
        oauthAllowedScope: PEP_APP_SCOPES.slice()
      }
    });
    requireOk(step, made, next);
    await grantPepConsent(api, step, spec, []);
    log.debug("Leaving ensurePepApplication(). Created.");
    return { state: 'created', secret: secret };
  }
  if (dryRun) {
    log.debug("Leaving ensurePepApplication(). Dry run, it exists.");
    return { state: 'exists', secret: '' };
  }
  const have = function (attribute) {
    log.debug("Entering have(). " + attribute);
    log.debug("Leaving have().");
    return attributeValues(got.body, attribute);
  };
  const confidential = have('oauthConfidential').some(function (one) {
    return String(one).toUpperCase() === 'TRUE';
  });
  if (!confidential) {
    const set = await api.post('/applications/set', {
      application: spec.app, attribute: 'oauthConfidential', value: 'TRUE'
    });
    requireOk(step, set, next);
  }
  const missing = [
    ['oauthRedirectUri', callbacks],
    ['oauthGrantType', PEP_APP_GRANTS],
    ['oauthTokenEndpointAuthMethod', PEP_APP_AUTH],
    ['oauthResponseType', ['code']],
    ['oauthAllowedScope', PEP_APP_SCOPES]
  ];
  for (let i = 0; i < missing.length; i++) {
    const attribute = missing[i][0];
    const wanted = missing[i][1];
    const held = have(attribute);
    for (let j = 0; j < wanted.length; j++) {
      if (held.indexOf(wanted[j]) >= 0) {
        continue;
      }
      const added = await api.post('/applications/add', {
        application: spec.app, attribute: attribute, value: wanted[j]
      });
      requireOk(step, added, next);
    }
  }
  let secret = '';
  if (!have('oauthClientSecret').length) {
    const added = await api.post('/applications/add-secret', {
      application: spec.app, lifetimeDays: 0,
      description: 'remote PEP session client'
    });
    requireOk(step, added, next);
    secret = String((added.body && added.body.clientSecret) || '');
  }
  await grantPepConsent(api, step, spec, have('oauthGlobalConsent'));
  log.debug("Leaving ensurePepApplication().");
  return { state: secret ? 'secret' : 'exists', secret: secret };
}

/**
 * Global consent for the scopes the session route asks for, so a sign-in
 * does not stop on the consent screen. A scope already consented is kept.
 *
 * @param api - the API client
 * @param step - the step's title
 * @param spec - `pepAppSpec()`'s answer
 * @param consented - the scopes the application already consents globally
 * @returns a promise of nothing
 */
async function grantPepConsent(api, step, spec, consented) {
  log.debug("Entering grantPepConsent().");
  const held = consented || [];
  for (let k = 0; k < PEP_APP_SCOPES.length; k++) {
    if (held.indexOf(PEP_APP_SCOPES[k]) >= 0) {
      continue;
    }
    const grant = await api.post('/consent/grant-global-consent', {
      client: spec.app, scope: PEP_APP_SCOPES[k]
    });
    requireOk(step, grant, 'Grant it on the application\'s consent tab, ' +
      'or with POST /admin-api/consent/grant-global-consent, and run this ' +
      'again. Without it a sign-in stops on the consent screen.');
  }
  log.debug("Leaving grantPepConsent().");
}

/**
 * The cluster's proxy document, with this route on it and the public base
 * filled in. An existing document is kept: only this route, the upstream
 * and the public base change.
 *
 * @param api - the API client
 * @param step - the step's title
 * @param opts - the options
 * @param spec - `pepAppSpec()`'s answer
 * @param cluster - the cluster's view
 * @returns a promise of `added`, `updated` or `skipped`
 */
async function ensurePepRoute(api, step, opts, spec, cluster) {
  log.debug("Entering ensurePepRoute().");
  const proxy = cluster && cluster.proxy;
  const wanted = pepAppRoute(spec);
  const where = 'Save it on the cluster\'s Reverse proxy tab, or fix what ' +
    'the refusal names and run this again.';
  if (!proxy) {
    const made = await api.post('/xacml/set-pep-cluster-proxy', {
      cluster: opts.cluster,
      proxy: {
        upstream: spec.upstream,
        publicBaseUrl: spec.publicBase,
        routes: [wanted]
      }
    });
    requireOk(step, made, where);
    log.debug("Leaving ensurePepRoute(). Added.");
    return 'added';
  }
  const routes = proxy.routes || [];
  const existing = routes.filter(function (one) {
    return one.path === spec.path || one.id === wanted.id;
  })[0];
  const placed = proxy.publicBaseUrl === spec.publicBase &&
    proxy.upstream === spec.upstream && routeReady(existing, spec);
  if (placed) {
    log.debug("Leaving ensurePepRoute(). Already there.");
    return 'skipped';
  }
  if (existing) {
    wanted.id = existing.id;
  }
  if (proxy.publicBaseUrl === spec.publicBase &&
      proxy.upstream === spec.upstream) {
    const one = await api.post('/xacml/set-pep-cluster-route', {
      cluster: opts.cluster, route: wanted
    });
    requireOk(step, one, where);
    log.debug("Leaving ensurePepRoute(). " + (existing ? 'Updated.'
                                                        : 'Added.'));
    return existing ? 'updated' : 'added';
  }
  const kept = routes.filter(function (one) {
    return one !== existing;
  });
  kept.push(wanted);
  const replaced = await api.post('/xacml/set-pep-cluster-proxy', {
    cluster: opts.cluster,
    proxy: Object.assign({}, proxy, {
      upstream: spec.upstream,
      publicBaseUrl: spec.publicBase,
      routes: kept
    })
  });
  requireOk(step, replaced, where);
  log.debug("Leaving ensurePepRoute(). Replaced the document.");
  return existing ? 'updated' : 'added';
}

/**
 * Step 8: the companion container's path, on the cluster's shared proxy,
 * protected by one role. Asked only with --pep-app.
 *
 * @param api - the API client
 * @param opts - the options
 * @returns a promise of nothing
 */
async function ensurePepApp(api, opts) {
  log.debug("Entering ensurePepApp().");
  const spec = pepAppSpec(opts);
  const step = '8. The ' + spec.path + ' path';
  const listed = await api.get('/xacml/pep-clusters?cluster=' +
                                encodeURIComponent(opts.cluster));
  if (listed.status !== 200 || !listed.body) {
    log.debug("Leaving ensurePepApp(). Unread.");
    throw new StepError(step, refusalOf(listed), 'GET /admin-api/xacml/' +
      'pep-clusters must answer for this token.');
  }
  const cluster = (listed.body.clusters || []).filter(function (one) {
    return one.name === opts.cluster;
  })[0] || null;
  if (!opts.dryRun && !cluster) {
    log.debug("Leaving ensurePepApp(). No cluster.");
    throw new StepError(step, 'this realm has no cluster "' + opts.cluster +
      '"', 'Step 5 creates it. Pass --create-cluster, or check the name.');
  }
  if (cluster && cluster.proxyProblem) {
    log.debug("Leaving ensurePepApp(). The proxy does not validate.");
    throw new StepError(step, 'cluster "' + opts.cluster + '" holds a ' +
      'reverse-proxy document this service will not read: ' +
      cluster.proxyProblem, 'Correct it on the cluster\'s Reverse proxy ' +
      'tab, or clear it (POST /admin-api/xacml/clear-pep-proxy) and run ' +
      'this again. This command does not replace a document it cannot read.');
  }
  const callbacks = callbacksFor(spec, cluster);
  if (opts.dryRun) {
    const role = await ensurePepRole(api, step, spec, true);
    const app = await ensurePepApplication(api, step, spec, callbacks, true);
    const proxy = cluster && cluster.proxy;
    const existing = proxy && (proxy.routes || []).filter(function (one) {
      return one.path === spec.path;
    })[0];
    const ready = !!(proxy && proxy.publicBaseUrl === spec.publicBase &&
      proxy.upstream === spec.upstream && routeReady(existing, spec));
    const secretWords = app.state === 'exists' ? ''
      : ' A new client secret would be printed once.';
    report(step, ready
      ? 'already registered; would be skipped.' + secretWords
      : 'would ' + (role === 'exists' ? 'keep' : 'create') + ' role "' +
        spec.role + '", ' + (app.state === 'exists' ? 'keep' : 'create') +
        ' application "' + spec.app + '", and register ' + spec.path +
        ' on cluster "' + opts.cluster + '" to ' + spec.upstream + ' at ' +
        spec.publicBase + ', protected by that one role for read and write.' +
        secretWords);
    log.debug("Leaving ensurePepApp(). Dry run.");
    return;
  }
  const role = await ensurePepRole(api, step, spec, false);
  const app = await ensurePepApplication(api, step, spec, callbacks, false);
  const route = await ensurePepRoute(api, step, opts, spec, cluster);
  const parts = [];
  parts.push('role "' + spec.role + '" ' +
    (role === 'created' ? 'created' : 'already there'));
  if (app.state === 'created') {
    parts.push('application "' + spec.app + '" created');
  } else if (app.secret) {
    parts.push('application "' + spec.app + '" given a client secret');
  } else {
    parts.push('application "' + spec.app + '" already there');
  }
  if (route === 'skipped') {
    parts.push('route ' + spec.path + ' already protected by that role; ' +
               'skipped');
  } else {
    parts.push('route ' + spec.path + ' ' + route + ' on cluster "' +
      opts.cluster + '" (' + spec.upstream + ', ' + spec.publicBase +
      '), one role for read and write');
  }
  report(step, parts.join('; ') + '.');
  if (app.secret) {
    console.log('  Client secret for "' + spec.app + '" (shown once): ' +
                app.secret);
  }
  log.debug("Leaving ensurePepApp().");
}

/**
 * Step 6: the HTTPS listener pair, which needs the PEP registered.
 *
 * @param api - the API client
 * @param opts - the options
 * @param row - the PEP's register row, or null
 * @returns a promise of the state: `issued`, `held` or `waiting`
 */
async function ensureListener(api, opts, row) {
  log.debug("Entering ensureListener().");
  const step = '6. The HTTPS listener pair';
  const crt = path.join(opts.out, SERVER_CRT);
  const key = path.join(opts.out, SERVER_KEY);
  if (fs.existsSync(crt) && fs.existsSync(key) && !opts.reissueHttps) {
    report(step, 'already in ' + path.dirname(crt) + '; skipped ' +
           '(--reissue-https replaces it).');
    log.debug("Leaving ensureListener(). Held.");
    return 'held';
  }
  if (!row) {
    report(step, 'WAITING: the realm issues it only to a PEP that has ' +
      'registered. Start the container with this environment (it ' +
      'registers, then waits for the two files), and run this command ' +
      'again to issue the pair; the PEP picks it up without a restart.');
    log.debug("Leaving ensureListener(). Not registered.");
    return 'waiting';
  }
  if (opts.dryRun) {
    report(step, 'would be issued to the registered PEP.');
    log.debug("Leaving ensureListener(). Dry run.");
    return 'waiting';
  }
  const answer = await api.post('/xacml/issue-pep-certificate', {
    name: opts.name, dnsNames: opts.httpsDns, ipAddresses: opts.httpsIp });
  if (answer.status !== 200 || !answer.body || !answer.body.ok) {
    log.debug("Leaving ensureListener(). Refused.");
    throw new StepError(step, refusalOf(answer), 'Issue it on the PEP\'s ' +
      'Listener tab, or fix what the refusal names and run this again.');
  }
  writeOut(key, String(answer.body.privateKeyPem || ''), true);
  writeOut(crt, String(answer.body.fullChainPem || ''), false);
  writeOut(path.join(opts.out, 'service-root.pem'),
           String(answer.body.anchorPem || ''), false);
  report(step, 'issued (serial ' + answer.body.serialHex + ', names ' +
    (answer.body.dnsNames || []).concat(answer.body.ipAddresses || [])
      .join(', ') + ', until ' + answer.body.notAfter + ')' +
    (answer.body.replacedSerialHex ? '; the one it replaces is superseded'
      : '') + '. service-root.pem is what the PEP\'s clients trust.');
  log.debug("Leaving ensureListener().");
  return 'issued';
}

/**
 * The directory every member of one cluster shares: the parent of --out.
 * A second member is another directory beside this one.
 *
 * @param opts - the options
 * @returns the absolute directory
 */
function clusterDir(opts) {
  log.debug("Entering clusterDir().");
  const dir = path.dirname(path.resolve(opts.out));
  log.debug("Leaving clusterDir().");
  return dir;
}

/**
 * Where the cluster's saved port and member directories live.
 *
 * @param opts - the options
 * @returns the absolute path
 */
function clusterPlanPath(opts) {
  log.debug("Entering clusterPlanPath().");
  const safe = String(opts.cluster).replace(/[^A-Za-z0-9._-]/g, '_');
  const file = path.join(clusterDir(opts), 'pep-cluster-' + safe + '.json');
  log.debug("Leaving clusterPlanPath().");
  return file;
}

/**
 * The cluster compose, the balancer's configuration and the reach script,
 * all in the directory the members share.
 *
 * @param opts - the options
 * @param kind - `compose`, `haproxy` or `reach`
 * @returns the absolute path
 */
function clusterFile(opts, kind) {
  log.debug("Entering clusterFile(). " + kind);
  const name = kind === 'haproxy' ? 'pep-cluster-haproxy.cfg'
    : kind === 'reach' ? 'pep-cluster-reach-sts.sh'
      : kind === 'ca' ? 'pep-cluster-' + SERVICE_CA
        : 'docker-compose.pep-cluster.yml';
  const file = path.join(clusterDir(opts), name);
  log.debug("Leaving clusterFile().");
  return file;
}

/**
 * The port and the member directories recorded for this cluster, if a
 * previous run wrote them.
 *
 * @param opts - the options
 * @returns `{ hostPort, members }`
 */
function readClusterPlan(opts) {
  log.debug("Entering readClusterPlan().");
  const empty = { hostPort: 0, members: {} };
  const file = clusterPlanPath(opts);
  if (!fs.existsSync(file)) {
    log.debug("Leaving readClusterPlan(). None.");
    return empty;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    const members = parsed.members && typeof parsed.members === 'object'
      ? parsed.members : {};
    log.debug("Leaving readClusterPlan().");
    return { hostPort: Number(parsed.hostPort) || 0, members: members };
  } catch (e) {
    // A half-written plan is ignored: this run records the members again.
    log.debug("Caught in readClusterPlan(): " + ((e && e.message) || e));
    log.debug("Leaving readClusterPlan(). Unreadable.");
    return empty;
  }
}

/**
 * Whether 127.0.0.1:<port> can be bound. The listen is closed before the
 * answer, so the check does not hold the port.
 *
 * @param port - the port
 * @returns a promise of true when the bind succeeds
 */
function portIsFree(port) {
  log.debug("Entering portIsFree(). " + port);
  return new Promise(function (resolve) {
    const server = net.createServer();
    server.once('error', function () {
      log.debug("Leaving portIsFree(). Busy.");
      resolve(false);
    });
    server.listen({ host: '127.0.0.1', port: port, exclusive: true },
      function () {
        server.close(function () {
          log.debug("Leaving portIsFree(). Free.");
          resolve(true);
        });
      });
  });
}

/**
 * A free TCP port on 127.0.0.1. 9543 first, then 18443 upward.
 *
 * @param preferred - the port to try first
 * @returns a promise of the port, or 0 when none in the range is free
 */
async function chooseHostPort(preferred) {
  log.debug("Entering chooseHostPort().");
  const first = preferred || 9543;
  if (await portIsFree(first)) {
    log.debug("Leaving chooseHostPort(). " + first);
    return first;
  }
  let port = 18443;
  while (port <= 18543) {
    if (port !== first && await portIsFree(port)) {
      log.debug("Leaving chooseHostPort(). " + port);
      return port;
    }
    port = port + 1;
  }
  log.debug("Leaving chooseHostPort(). None.");
  return 0;
}

/**
 * The load balancer's host port, and the public origin a browser uses when
 * --pep-app did not name one. An origin the operator named wins. A port
 * saved for this cluster is reused, so a later member does not move it.
 *
 * @param opts - the options
 * @returns a promise of nothing
 */
async function prepareClusterPublish(opts) {
  log.debug("Entering prepareClusterPublish().");
  if (!opts.cluster) {
    log.debug("Leaving prepareClusterPublish(). Not a cluster.");
    return;
  }
  const plan = readClusterPlan(opts);
  let port = 0;
  if (opts.publicBase) {
    try {
      const url = new URL(opts.publicBase);
      port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
    } catch (e) {
      // pepAppProblem() reports a public base that is not a URL.
      log.debug("Caught in prepareClusterPublish(): " +
                ((e && e.message) || e));
      log.debug("Leaving prepareClusterPublish(). Bad public base.");
      return;
    }
  } else if (plan.hostPort) {
    port = plan.hostPort;
  } else {
    port = await chooseHostPort(9543);
  }
  if (!port) {
    log.debug("Leaving prepareClusterPublish(). No port.");
    throw new StepError('7. The container\'s environment',
      'no free TCP port on 127.0.0.1 for the load balancer ' +
      '(tried 9543 and 18443-18543)',
      'Stop what holds those ports, or pass --public-base ' +
      'https://localhost:<port> with a free port.');
  }
  opts.clusterHostPort = port;
  if (opts.pepApp && !opts.publicBase) {
    opts.publicBase = 'https://localhost:' + port;
  }
  log.debug("Leaving prepareClusterPublish(). " + port);
}

/**
 * The host of a PDP URL, or ''.
 *
 * @param pdpUrl - PEP_PDP_URL
 * @returns the hostname
 */
function pdpHost(pdpUrl) {
  log.debug("Entering pdpHost().");
  let host = '';
  try {
    host = new URL(pdpUrl).hostname;
  } catch (e) {
    log.debug("Caught in pdpHost(): " + ((e && e.message) || e));
    host = '';
  }
  log.debug("Leaving pdpHost().");
  return host;
}

/**
 * PEP_PDP_URL from a member's environment file.
 *
 * @param outDir - the member's --out
 * @param fallback - the URL when the file has none
 * @returns the URL
 */
function memberPdpUrl(outDir, fallback) {
  log.debug("Entering memberPdpUrl(). " + outDir);
  const file = path.join(outDir, ENV_FILE);
  if (!fs.existsSync(file)) {
    log.debug("Leaving memberPdpUrl(). No file.");
    return fallback;
  }
  const line = fs.readFileSync(file, 'utf8').split('\n').filter(
    function (one) {
      return one.indexOf('PEP_PDP_URL=') === 0;
    })[0];
  log.debug("Leaving memberPdpUrl().");
  return line ? line.slice('PEP_PDP_URL='.length) : fallback;
}

/**
 * A path relative to `fromDir`, with forward slashes, quoted for YAML.
 *
 * @param fromDir - the compose file's directory
 * @param target - the file or directory
 * @returns a quoted relative path
 */
function yamlPath(fromDir, target) {
  log.debug("Entering yamlPath().");
  let rel = path.relative(fromDir, target);
  if (!rel) {
    rel = '.';
  }
  rel = rel.split(path.sep).join('/');
  const quoted = '"' + rel.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  log.debug("Leaving yamlPath().");
  return quoted;
}

/**
 * A compose volume, the whole `source:target` quoted so the colon stays
 * inside one YAML string.
 *
 * @param fromDir - the compose file's directory
 * @param source - the host file or directory
 * @param target - the container path, including a `:ro` suffix
 * @returns a quoted volume
 */
function yamlVolume(fromDir, source, target) {
  log.debug("Entering yamlVolume().");
  let rel = path.relative(fromDir, source);
  if (!rel) {
    rel = '.';
  }
  rel = rel.split(path.sep).join('/');
  // A source that does not start with "." or "/" is a named volume.
  // "./pep-certs" is the bind mount of the directory beside the compose file.
  if (rel.charAt(0) !== '.' && !path.isAbsolute(rel)) {
    rel = './' + rel;
  }
  const spec = rel + ':' + target;
  const quoted = '"' + spec.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  log.debug("Leaving yamlVolume().");
  return quoted;
}

/**
 * The script that points the name localhost at the sts container. 127.0.0.1
 * stays the PEP, which is what its healthcheck dials.
 *
 * @returns the script
 */
function reachStsScript() {
  log.debug("Entering reachStsScript().");
  const text = [
    '#!/bin/sh',
    '# Points the name localhost at the sts container so PEP_PDP_URL',
    '# https://localhost:<port> is the service a browser opens, and the',
    '# issuer the service derives from the Host header stays that URL.',
    '# There is no TCP forwarder. 127.0.0.1 stays this container.',
    'set -e',
    'ip=$(getent ahostsv4 sts | head -n 1 | cut -d " " -f 1)',
    'if [ -z "$ip" ]; then',
    '  echo "sts has no address; refusing to start" >&2',
    '  exit 1',
    'fi',
    'grep -v localhost /etc/hosts > /tmp/hosts.new',
    'printf "%s localhost\\n" "$ip" >> /tmp/hosts.new',
    'cat /tmp/hosts.new > /etc/hosts',
    'exec xacml-pep',
    ''
  ].join('\n');
  log.debug("Leaving reachStsScript().");
  return text;
}

/**
 * HAProxy in front of the members. TLS passes through. The proxy listener
 * sticks to the source address; the decision API is round robin and is not
 * published on the host.
 *
 * @param names - the members' PEP names, in order
 * @returns the configuration
 */
function haproxyConfig(names) {
  log.debug("Entering haproxyConfig().");
  const lines = [
    '# Load balancer in front of this remote PEP cluster.',
    '# The host publishes 127.0.0.1 only, onto the proxy listener.',
    '# No TCP forwarder. PROXY protocol stays off.',
    'global',
    '  log stdout format raw local0 info',
    '  nbthread 2',
    '',
    'resolvers docker',
    '  nameserver dns 127.0.0.11:53',
    '  hold valid 5s',
    '',
    'defaults',
    '  mode tcp',
    '  log global',
    '  option tcplog',
    '  option dontlognull',
    '  balance roundrobin',
    '  timeout connect 5s',
    '  timeout client 30m',
    '  timeout server 30m',
    '  default-server check inter 2s fall 3 rise 2 resolvers docker ' +
      'init-addr last,libc,none',
    '',
    'listen proxy_https',
    '  bind :9543',
    '  balance source'
  ];
  names.forEach(function (name) {
    lines.push('  server ' + name + ' ' + name + ':9543');
  });
  lines.push('');
  lines.push('listen decision_https');
  lines.push('  bind :9443');
  names.forEach(function (name) {
    lines.push('  server ' + name + ' ' + name + ':9443');
  });
  lines.push('');
  log.debug("Leaving haproxyConfig().");
  return lines.join('\n');
}

/**
 * One compose file for the cluster, with paths relative to `baseDir`.
 *
 * @param baseDir - the directory the compose file is written in
 * @param opts - the options
 * @param plan - `{ hostPort, members, ca }`, each member's reach flag, and
 *   whether the cluster directory holds the service's CA
 * @returns the YAML
 */
function clusterComposeText(baseDir, opts, plan) {
  log.debug("Entering clusterComposeText().");
  const names = Object.keys(plan.members).sort();
  const lines = [
    '# Remote PEP cluster "' + opts.cluster + '".',
    '# The load balancer listens on 127.0.0.1:' + plan.hostPort +
      ' only, in front of the members.',
    '# The companion serves /pep-app on the cluster network.',
    '# No TCP forwarder. A member whose PEP_PDP_URL names localhost',
    '# points that name at the sts container before it starts.',
    '# This file does not define the identity service.',
    '# STS_NETWORK is the network that service is already on.',
    'services:'
  ];
  names.forEach(function (name) {
    const member = plan.members[name];
    lines.push('  ' + name + ':');
    lines.push('    image: ${XACML_PEP_IMAGE:-iyasec/iya-sts-xacml-pep}');
    lines.push('    container_name: ' + name);
    lines.push('    hostname: ' + name);
    lines.push('    restart: unless-stopped');
    lines.push('    env_file: ' +
      yamlPath(baseDir, path.join(member.out, ENV_FILE)));
    lines.push('    volumes:');
    lines.push('      - ' + yamlVolume(baseDir, member.out, '/certs:ro'));
    if (member.reach) {
      lines.push('      - ' + yamlVolume(baseDir, clusterFile(opts, 'reach'),
        '/usr/local/bin/pep-reach-sts.sh:ro'));
      lines.push('    entrypoint: ["/bin/sh", ' +
        '"/usr/local/bin/pep-reach-sts.sh"]');
    }
  });
  lines.push('  pep-lb:');
  lines.push('    image: ${PEP_LB_IMAGE:-ghcr.io/rcbj/iya-sts/mirror/' +
    'haproxy:3.2.23-alpine}');
  lines.push('    container_name: pep-lb-' + opts.cluster);
  lines.push('    hostname: pep-lb');
  lines.push('    restart: unless-stopped');
  lines.push('    ports:');
  lines.push('      - "127.0.0.1:' + plan.hostPort + ':9543"');
  lines.push('    volumes:');
  lines.push('      - ' + yamlVolume(baseDir, clusterFile(opts, 'haproxy'),
    '/usr/local/etc/haproxy/haproxy.cfg:ro'));
  lines.push('    depends_on:');
  names.forEach(function (name) {
    lines.push('      - ' + name);
  });
  lines.push('  companion:');
  lines.push('    image: ${STS_COMPANION_IMAGE:-iya-sts-companion}');
  lines.push('    container_name: companion-' + opts.cluster);
  lines.push('    hostname: companion');
  lines.push('    restart: unless-stopped');
  // NO HOST PORT (#1972). The companion is reached only as the upstream of
  // the members' reverse proxy, http://companion:9700 on this network, and
  // that route takes the person from identity HEADERS the proxy sets. A
  // port published on the host, even on 127.0.0.1, let any local process
  // send those headers straight to the companion and be whoever it named.
  // Nothing the registrar writes or starts dials it from the host.
  // THE SERVICE'S CERTIFICATE IS VERIFIED, against the anchor --ca gave
  // (copied beside this file), and never turned off: without --ca the
  // companion verifies against the roots in its image.
  if (plan.ca) {
    lines.push('    volumes:');
    lines.push('      - ' + yamlVolume(baseDir, clusterFile(opts, 'ca'),
      '/certs/' + SERVICE_CA + ':ro'));
  }
  lines.push('    environment:');
  lines.push('      COMPANION_PORT: "9700"');
  lines.push('      COMPANION_PUBLIC_URL: "http://127.0.0.1:9700"');
  lines.push('      COMPANION_STS_URL: "https://sts:8081"');
  lines.push('      COMPANION_STS_PUBLIC_URL: "https://localhost:8081"');
  lines.push('      COMPANION_KRB5_SERVICE_PORT: "off"');
  if (plan.ca) {
    lines.push('      COMPANION_STS_CA_FILE: "/certs/' + SERVICE_CA + '"');
  }
  lines.push('networks:');
  lines.push('  default:');
  lines.push('    name: ${STS_NETWORK:-iya-sts_default}');
  lines.push('    external: true');
  lines.push('');
  log.debug("Leaving clusterComposeText().");
  return lines.join('\n');
}

/**
 * The one-PEP compose, for a run that is not joining a cluster.
 *
 * @param opts - the options
 * @param mount - the container path of --out
 * @returns the YAML
 */
function singleComposeText(opts, mount) {
  log.debug("Entering singleComposeText().");
  const text = [
    '# ' + opts.name + ': docker compose -f ' + COMPOSE_FILE + ' up -d, ' +
      'run in this directory.',
    'services:',
    '  ' + opts.name + ':',
    '    image: ${XACML_PEP_IMAGE:-iyasec/iya-sts-xacml-pep}',
    '    container_name: ' + opts.name,
    '    hostname: ' + opts.name,
    '    env_file: ./' + ENV_FILE,
    '    volumes:',
    '      - ./:' + mount + ':ro',
    // On 127.0.0.1 only (#1972), as the cluster's load balancer is: a
    // listener another host must reach is published by editing this line.
    '    ports:',
    '      - "127.0.0.1:9444:9443"',
    '      - "127.0.0.1:9543:9543"',
    '    restart: unless-stopped',
    ''
  ].join('\n');
  log.debug("Leaving singleComposeText().");
  return text;
}

/**
 * Writes pep.env and the compose file. A cluster run writes the shared
 * balancer files as well, and rewrites every member's compose so a member
 * added later is in front of the same load balancer.
 *
 * @param opts - the options
 * @param where - `{ pdpUrl, caPem }`
 * @returns the environment lines
 */
function writeEnvironment(opts, where) {
  log.debug("Entering writeEnvironment().");
  const mount = (opts.mount || '/certs').replace(/\/+$/, '');
  const lines = [
    '# The remote PEP ' + opts.name + ', from register-remote-pep.js. ' +
    'Mount ' + path.resolve(opts.out) + ' at ' + mount + ', read-only.',
    'PEP_PDP_URL=' + where.pdpUrl,
    'PEP_NAME=' + opts.name,
    'PEP_CLIENT_ID=' + PEP_CLIENT_ID,
    'PEP_ASSERTION_KEY=' + mount + '/' + KEY_FILE,
    'PEP_HTTPS_CERT=' + mount + '/server/pep-server.crt',
    'PEP_HTTPS_KEY=' + mount + '/server/pep-server.key'
  ];
  if (where.caPem) {
    lines.push('PEP_TLS_CA=' + mount + '/' + SERVICE_CA);
  } else {
    lines.push('# No --ca was given: the PEP verifies the service against ' +
               'its own roots. Set PEP_TLS_CA to the anchor otherwise.');
  }
  lines.push('PEP_TLS_INSECURE=false');
  const text = lines.join('\n') + '\n';
  let compose = singleComposeText(opts, mount);
  let extra = '';
  if (opts.cluster) {
    const plan = readClusterPlan(opts);
    plan.hostPort = opts.clusterHostPort || plan.hostPort || 9543;
    plan.members[opts.name] = path.resolve(opts.out);
    const described = {};
    Object.keys(plan.members).sort().forEach(function (name) {
      const outDir = plan.members[name];
      const pdp = name === opts.name ? where.pdpUrl
        : memberPdpUrl(outDir, where.pdpUrl);
      described[name] = { out: outDir, reach: pdpHost(pdp) === 'localhost' };
    });
    const full = { hostPort: plan.hostPort, members: described,
                   ca: !!where.caPem ||
                       fs.existsSync(clusterFile(opts, 'ca')) };
    compose = clusterComposeText(path.resolve(opts.out), opts, full);
    extra = ' The cluster compose is ' + clusterFile(opts, 'compose') +
      ', load balancer 127.0.0.1:' + plan.hostPort + ' only.';
    if (!opts.dryRun) {
      writeOut(clusterPlanPath(opts), JSON.stringify({
        hostPort: plan.hostPort, members: plan.members
      }, null, 2) + '\n', false);
      writeOut(clusterFile(opts, 'haproxy'),
               haproxyConfig(Object.keys(described)), false);
      if (where.caPem) {
        writeOut(clusterFile(opts, 'ca'), where.caPem, false);
      }
      if (Object.keys(described).some(function (name) {
        return described[name].reach;
      })) {
        writeOut(clusterFile(opts, 'reach'), reachStsScript(), false);
      }
      writeOut(clusterFile(opts, 'compose'),
               clusterComposeText(clusterDir(opts), opts, full), false);
      Object.keys(described).forEach(function (name) {
        if (name === opts.name) {
          return;
        }
        writeOut(path.join(described[name].out, COMPOSE_FILE),
                 clusterComposeText(described[name].out, opts, full), false);
      });
    }
  }
  if (!opts.dryRun) {
    if (where.caPem) {
      writeOut(path.join(opts.out, SERVICE_CA), where.caPem, false);
    }
    writeOut(path.join(opts.out, ENV_FILE), text, false);
    writeOut(path.join(opts.out, COMPOSE_FILE), compose, false);
    fs.mkdirSync(path.join(opts.out, 'server'), { recursive: true });
  }
  report('7. The container\'s environment', opts.dryRun
    ? 'would be written to ' + path.join(opts.out, ENV_FILE) + ' and ' +
      path.join(opts.out, COMPOSE_FILE) + '.' + extra
    : 'written to ' + path.join(opts.out, ENV_FILE) + ' and ' +
      path.join(opts.out, COMPOSE_FILE) + '.' + extra);
  log.debug("Leaving writeEnvironment().");
  return lines;
}

/**
 * Starts the cluster compose: the members, the load balancer and the
 * companion. The identity service is not in that file, so this does not
 * recreate it.
 *
 * @param opts - the options
 * @returns nothing
 */
function startCluster(opts) {
  log.debug("Entering startCluster().");
  if (!opts.cluster) {
    log.debug("Leaving startCluster(). Not a cluster.");
    return;
  }
  const file = clusterFile(opts, 'compose');
  const command = 'docker compose -f ' + file +
    ' up -d --no-build --pull never';
  if (opts.dryRun) {
    report('9. The containers', 'would start with ' + command + '.');
    log.debug("Leaving startCluster(). Dry run.");
    return;
  }
  if (process.env.REGISTER_PEP_NO_START) {
    // The in-process suite has no Docker daemon. An operator does not set
    // this: a cluster run starts the containers.
    report('9. The containers', 'not started (REGISTER_PEP_NO_START). ' +
      command);
    log.debug("Leaving startCluster(). Skipped.");
    return;
  }
  const result = childProcess.spawnSync('docker',
    ['compose', '-f', file, 'up', '-d', '--no-build', '--pull', 'never'],
    { encoding: 'utf8' });
  if (result.error || result.status !== 0) {
    const said = (result.error && result.error.message) ||
      String(result.stderr || result.stdout || '').trim();
    log.debug("Leaving startCluster(). Compose failed.");
    throw new StepError('9. The containers',
      'docker compose up failed: ' + said,
      'The registration and the files are already written. Fix what ' +
      'Docker printed, then run: ' + command);
  }
  report('9. The containers', 'started from ' + file +
    ': the members, the load balancer on 127.0.0.1:' +
    opts.clusterHostPort + ', and the companion.');
  log.debug("Leaving startCluster().");
}

/**
 * Runs the command.
 *
 * @param argv - the arguments after the script's name
 * @returns a promise of the exit status
 */
async function main(argv) {
  log.debug("Entering main().");
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(USAGE);
    log.debug("Leaving main(). Help.");
    return 0;
  }
  const missing = ['url', 'name', 'out'].filter(function (one) {
    return !opts[one];
  });
  if (opts.problem || missing.length) {
    console.error((opts.problem || '--' + missing.join(', --') +
                   ' required.') + '\n\n' + USAGE);
    log.debug("Leaving main(). Usage.");
    return 2;
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(opts.name)) {
    console.error('--name must be a username: letters, digits, ".", "_" ' +
                  'and "-", at most 64, starting with a letter or digit.');
    log.debug("Leaving main(). A bad name.");
    return 2;
  }
  if (opts.keyAlg && ['ec-p256', 'rsa-2048'].indexOf(opts.keyAlg) < 0) {
    console.error('--key-alg must be ec-p256 or rsa-2048.');
    log.debug("Leaving main(). A bad key algorithm.");
    return 2;
  }
  if (opts.pepApp && !opts.cluster) {
    console.error('--pep-app registers one path on the cluster\'s shared ' +
      'reverse proxy, so it needs --cluster.');
    log.debug("Leaving main(). --pep-app without --cluster.");
    return 2;
  }
  if (opts.cluster) {
    opts.pepApp = true;
  }
  try {
    await prepareClusterPublish(opts);
  } catch (e) {
    // No registration yet: a missing port must not look like a half-done run.
    log.debug("Caught in main(): " + ((e && e.message) || e));
    if (e instanceof StepError) {
      console.error('\nFAILED at ' + e.step + ':\n  ' + e.said +
        (e.next ? '\nWhat to do: ' + e.next : ''));
      log.debug("Leaving main(). No load-balancer port.");
      return 1;
    }
    throw e;
  }
  if (opts.cluster && opts.publicBase && !opts.clusterHostPort &&
      !opts.pepApp) {
    console.error('--public-base is not a URL: ' + opts.publicBase);
    log.debug("Leaving main(). A bad public base.");
    return 2;
  }
  if (opts.pepApp) {
    const problem = pepAppProblem(opts);
    if (problem) {
      console.error(problem);
      log.debug("Leaving main(). The companion path.");
      return 2;
    }
  }
  let target = null;
  try {
    target = new URL(opts.url);
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    console.error('--url is not a URL: ' + opts.url);
    log.debug("Leaving main(). A bad URL.");
    return 2;
  }
  const tlsSet = tlsSetup(opts, target);
  if (tlsSet.problem) {
    console.error(tlsSet.problem);
    log.debug("Leaving main(). TLS.");
    return 2;
  }
  const origin = target.origin;
  const prefix = opts.realm ? '/realm/' + encodeURIComponent(opts.realm)
    : '';
  const pdpUrl = (opts.pdpUrl || (origin + prefix)).replace(/\/+$/, '');
  console.log('Registering remote PEP "' + opts.name + '" in ' +
              (opts.realm ? 'realm ' + opts.realm : 'the default realm') +
              ' at ' + origin + (opts.dryRun ? ' (DRY RUN: nothing is ' +
              'written)' : '') + '.');
  try {
    const token = await findToken(opts, origin, prefix, tlsSet.options);
    const api = apiClient(origin + prefix + '/admin-api', token,
                          tlsSet.options);
    const facts = await preflight(api, opts, { origin: origin });
    if (facts.peps.pepAuthentication &&
        facts.peps.pepAuthentication === 'certificate') {
      console.error('NOTE: this realm\'s xacml.pepAuthentication is ' +
        '`certificate`, which reads no token: this PEP\'s key is not ' +
        'accepted until it is `token` or `either`.');
    }
    if (!opts.dryRun) {
      fs.mkdirSync(opts.out, { recursive: true });
    }
    const entry = await ensureIdentity(api, opts, facts);
    await ensureCredential(api, opts, entry);
    await ensureCluster(api, opts);
    if (opts.pepApp) {
      await ensurePepApp(api, opts);
    }
    const row = facts.peps.found && (facts.peps.peps || [])[0]
      ? facts.peps.peps[0] : null;
    const listener = await ensureListener(api, opts, row);
    const lines = writeEnvironment(opts, { pdpUrl: pdpUrl,
                                           caPem: tlsSet.caPem });
    startCluster(opts);
    console.log('\nThe container\'s environment (' +
                path.join(opts.out, ENV_FILE) + '):\n');
    console.log(lines.filter(function (line) {
      return line.charAt(0) !== '#';
    }).map(function (line) {
      return '  ' + line;
    }).join('\n'));
    const dialHost = pdpHost(pdpUrl);
    if (opts.cluster && dialHost === 'localhost') {
      console.log('\nNOTE: PEP_PDP_URL names localhost. The compose ' +
        'points that name at the sts container before the PEP starts, ' +
        'so a browser is sent to ' + pdpUrl + '. There is no TCP ' +
        'forwarder. 127.0.0.1 stays the PEP.');
    } else if (dialHost === 'localhost' || dialHost === '127.0.0.1' ||
               dialHost === '::1') {
      console.log('\nNOTE: PEP_PDP_URL names ' + dialHost +
        ', which inside a container is the container itself. Pass ' +
        '--pdp-url with the address the container dials (on the compose ' +
        'network, https://sts:8081' + prefix + ').');
    }
    if (opts.cluster) {
      console.log('\nThe load balancer listens on 127.0.0.1:' +
        opts.clusterHostPort + ' only (the reverse proxy). The ' +
        'companion is http://companion:9700 on the cluster network ' +
        'only, not published on this host. The decision API is not ' +
        'published. There is no TCP forwarder.');
    } else {
      console.log('\nStart it:\n  docker run -d --name ' + opts.name +
        ' --hostname ' + opts.name + ' --env-file ' +
        path.join(opts.out, ENV_FILE) + ' \\\n    -v "' +
        path.resolve(opts.out) + ':' + (opts.mount || '/certs') + ':ro" ' +
        '-p 127.0.0.1:9444:9443 iyasec/iya-sts-xacml-pep\n' +
        'or: (cd ' + opts.out + ' && docker compose -f ' + COMPOSE_FILE +
        ' up -d)');
    }
    console.log('\nVerify: GET ' + origin + prefix + '/admin-api/xacml/' +
      'peps?pep=' + opts.name + ' lists it once it registers' +
      (row ? ' (it is registered now, last seen ' +
        (row.lastSeen || 'never') + ')' : '') +
      ', and the PEP\'s own GET / shows "credential" holding a token.' +
      (listener === 'waiting' && !opts.dryRun
        ? '\nThen run this same command again to issue its HTTPS ' +
          'listener pair.' : ''));
    if (opts.pepApp) {
      const spec = pepAppSpec(opts);
      console.log('\nCompanion path: ' + spec.publicBase + spec.path +
        ' on cluster "' + opts.cluster + '", protected by the one role "' +
        spec.role + '" (read and write). Grant that role to the people ' +
        'who may use it (POST /admin-api/roles/add-member).');
    }
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    if (e instanceof StepError) {
      console.error('\nFAILED at ' + e.step + ':\n  ' + e.said +
                    (e.next ? '\nWhat to do: ' + e.next : '') +
                    '\nThe steps before it stand; running this again ' +
                    'skips them.');
      log.debug("Leaving main(). A step failed.");
      return 1;
    }
    throw e;
  }
  log.debug("Leaving main().");
  return 0;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(function (status) {
    process.exitCode = status;
  }, function (e) {
    console.error('register-remote-pep: ' + ((e && e.stack) || e));
    process.exitCode = 1;
  });
}

module.exports = { main: main, parseArgs: parseArgs };
