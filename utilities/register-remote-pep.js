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
// the order docs/v1.1.0/remote-pep.md's *Registering a new remote PEP, step
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
//      (<out>/docker-compose.pep.yml), printed as well.
//
// **IT IS IDEMPOTENT, AND EACH STEP SAYS HOW.** A door that answers a repeat
// with a 400 is never asked twice: the entry and the cluster membership are
// read first and skipped when present. `groups/add-member` and
// `users/set-service-account` answer a repeat 200 with nothing changed, so
// they are simply called. `issue-pep-credential` ADDS a key every time it is
// called, so it is called only when the certificate in --out is not a valid
// key on the entry; the listener pair is issued only when --out holds none
// (`--reissue-https` replaces it). `--dry-run` makes no write anywhere and
// says what each step would do.
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
const tls = require('tls');
const crypto = require('crypto');

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
  --cluster NAME     Make it a member of this remote PEP cluster
  --create-cluster   Create --cluster, empty, when it does not exist
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
  '--ca': 'ca', '--client': 'client', '--secret-file': 'secretFile'
};
const FLAGS = {
  '--create-cluster': 'createCluster', '--reissue-https': 'reissueHttps',
  '--new-key': 'newKey', '--revoke-previous': 'revokePrevious',
  '--insecure': 'insecure', '--dry-run': 'dryRun',
  '--realm-client': 'realmClient', '--help': 'help', '-h': 'help'
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
      '(docs/v1.1.0/management-api.md, Getting a token).');
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
      'ADMIN_WRITE (docs/v1.1.0/management-api.md, An application of your ' +
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
      'realm\'s prefix): docs/v1.1.0/management-api.md, Getting a token.');
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
 * Step 7: the container's environment and a compose service.
 *
 * @param opts - the options
 * @param where - the target: `pdpUrl`, `caPem`
 * @returns the environment's lines
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
  const compose = [
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
    '    ports:',
    '      - "9444:9443"',
    '      - "9543:9543"',
    '    restart: unless-stopped',
    ''
  ].join('\n');
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
      path.join(opts.out, COMPOSE_FILE) + '.'
    : 'written to ' + path.join(opts.out, ENV_FILE) + ' and ' +
      path.join(opts.out, COMPOSE_FILE) + '.');
  log.debug("Leaving writeEnvironment().");
  return lines;
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
    const row = facts.peps.found && (facts.peps.peps || [])[0]
      ? facts.peps.peps[0] : null;
    const listener = await ensureListener(api, opts, row);
    const lines = writeEnvironment(opts, { pdpUrl: pdpUrl,
                                           caPem: tlsSet.caPem });
    console.log('\nThe container\'s environment (' +
                path.join(opts.out, ENV_FILE) + '):\n');
    console.log(lines.filter(function (line) {
      return line.charAt(0) !== '#';
    }).map(function (line) {
      return '  ' + line;
    }).join('\n'));
    if (/^(localhost|127\.|\[::1\])/.test(new URL(pdpUrl).hostname)) {
      console.log('\nNOTE: PEP_PDP_URL names ' + new URL(pdpUrl).host +
        ', which inside a container is the container itself. Pass ' +
        '--pdp-url with the address the container dials (on the compose ' +
        'network, https://sts:8081' + prefix + ').');
    }
    console.log('\nStart it:\n  docker run -d --name ' + opts.name +
      ' --hostname ' + opts.name + ' --env-file ' +
      path.join(opts.out, ENV_FILE) + ' \\\n    -v "' +
      path.resolve(opts.out) + ':' + (opts.mount || '/certs') + ':ro" ' +
      '-p 9444:9443 iyasec/iya-sts-xacml-pep\n' +
      'or: (cd ' + opts.out + ' && docker compose -f ' + COMPOSE_FILE +
      ' up -d)');
    console.log('\nVerify: GET ' + origin + prefix + '/admin-api/xacml/' +
      'peps?pep=' + opts.name + ' lists it once it registers' +
      (row ? ' (it is registered now, last seen ' +
        (row.lastSeen || 'never') + ')' : '') +
      ', and the PEP\'s own GET / shows "credential" holding a token.' +
      (listener === 'waiting' && !opts.dryRun
        ? '\nThen run this same command again to issue its HTTPS ' +
          'listener pair.' : ''));
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
