#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: config-dump.js
// ---------------------------------------------------------------------------
// THE COMMAND-LINE DOOR TO THE CONFIGURATION DUMP. It gets an access token
// with the client-credentials grant and saves `GET /admin-api/config-dump`,
// which the server has already masked. It masks nothing itself, so it cannot
// disagree with the console or the API about what is hidden.
//
// The client secret is read from the environment or a file and never from
// the command line, where `ps` would show it to everybody on the machine.
//
// It needs Node and nothing else. It runs outside the service, so it has no
// bunyan: `log` is a console-backed logger of the same shape, quiet unless
// CONFIG_DUMP_DEBUG is set.
// ---------------------------------------------------------------------------

const fs = require('fs');
const http = require('http');
const https = require('https');

const log = {
  debug: function (message) {
    if (process.env.CONFIG_DUMP_DEBUG) {
      console.error(message);
    }
  }
};

const USAGE = `Usage: config-dump.js --url <base URL> [options]

  --url URL          The service's base URL, https://sts.example.net
  --realm ID         One realm's effective parameters. Without it, the global
                     parameters and every realm's own values.
  --realm-client     The client belongs to --realm, not the default realm
  --client ID        The client_id (default sts-api-client)
  --secret-file F    A file holding the client secret. Otherwise
                     ADMIN_API_CLIENT_SECRET, or ADMIN_API_CLIENT_SECRET_FILE.
  --ca-file F        A PEM file of the CA to trust for this service
  --insecure         Do not verify the service's certificate
  --output F         Write here instead of standard output (mode 0600)
  --help             This text

Exit status: 0 saved, 1 failed, 2 usage.`;

/**
 * Reads the command line.
 *
 * @param argv - the arguments after the script's name
 * @returns the options, or `{ problem }`
 */
function parseArgs(argv) {
  log.debug("Entering parseArgs().");
  const valued = { '--url': 'url', '--realm': 'realm', '--client': 'client',
                   '--secret-file': 'secretFile', '--ca-file': 'caFile',
                   '--output': 'output' };
  const out = { client: 'sts-api-client' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      out.help = true;
    } else if (arg === '--insecure') {
      out.insecure = true;
    } else if (arg === '--realm-client') {
      out.realmClient = true;
    } else if (valued[arg] && i + 1 < argv.length) {
      out[valued[arg]] = argv[i + 1];
      i = i + 1;
    } else {
      log.debug("Leaving parseArgs(). Refused " + arg + ".");
      return { problem: 'Not understood: ' + arg };
    }
  }
  log.debug("Leaving parseArgs().");
  return out;
}

/**
 * Finds the client secret: the named file, the variable, the variable's file.
 *
 * @param opts - the options
 * @returns the secret, or an empty string
 */
function readSecret(opts) {
  log.debug("Entering readSecret().");
  const file = opts.secretFile || (process.env.ADMIN_API_CLIENT_SECRET ? '' :
    process.env.ADMIN_API_CLIENT_SECRET_FILE);
  const secret = file ? fs.readFileSync(file, 'utf8').trim()
    : String(process.env.ADMIN_API_CLIENT_SECRET || '');
  log.debug("Leaving readSecret().");
  return secret;
}

/**
 * Makes one HTTP(S) request.
 *
 * @param url - the URL
 * @param options - method, headers, body, and TLS options
 * @returns a promise of `{ status, body }`
 */
function request(url, options) {
  log.debug("Entering request(). " + url);
  const target = new URL(url);
  const client = target.protocol === 'http:' ? http : https;
  return new Promise(function (resolve, reject) {
    const bounded = Object.assign({ signal: AbortSignal.timeout(120000) },
                                  options);
    const req = client.request(target, bounded, function (res) {
      const chunks = [];
      res.on('data', function (chunk) {
        chunks.push(chunk);
      });
      res.on('end', function () {
        log.debug("Leaving request(). " + res.statusCode);
        resolve({ status: res.statusCode,
                  body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    req.end(options.body);
  });
}

/**
 * Gets an access token audienced to the management API.
 *
 * @param base - the base URL, with the realm's prefix when the client is
 *   the realm's, which is also what the audience is built from
 * @param opts - the options
 * @param secret - the client secret
 * @param tls - the TLS options
 * @returns a promise of the token
 */
async function getToken(base, opts, secret, tls) {
  log.debug("Entering getToken().");
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    resource: base + '/admin-api',
    scope: 'admin:read'
  }).toString();
  const basic = Buffer.from(encodeURIComponent(opts.client) + ':' +
                            encodeURIComponent(secret)).toString('base64');
  const answer = await request(base + '/oauth2/token', Object.assign({
    method: 'POST', body: body,
    headers: { 'content-type': 'application/x-www-form-urlencoded',
               authorization: 'Basic ' + basic,
               'content-length': Buffer.byteLength(body) }
  }, tls));
  if (answer.status !== 200) {
    log.debug("Leaving getToken(). Refused.");
    throw new Error('the token endpoint answered ' + answer.status + ': ' +
                    answer.body.slice(0, 300));
  }
  log.debug("Leaving getToken().");
  return JSON.parse(answer.body).access_token;
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
  if (opts.problem || !opts.url) {
    console.error((opts.problem || '--url is required.') + '\n\n' + USAGE);
    log.debug("Leaving main(). Usage.");
    return 2;
  }
  const secret = readSecret(opts);
  if (!secret) {
    console.error('No client secret: set ADMIN_API_CLIENT_SECRET or ' +
                  'ADMIN_API_CLIENT_SECRET_FILE, or pass --secret-file.');
    log.debug("Leaving main(). No secret.");
    return 2;
  }
  const tls = { rejectUnauthorized: !opts.insecure };
  if (opts.caFile) {
    tls.ca = fs.readFileSync(opts.caFile);
  }
  const origin = new URL(opts.url).origin;
  const base = origin + (opts.realm
    ? '/realm/' + encodeURIComponent(opts.realm) : '');
  // A service administrator's client is the default realm's, and its token
  // is believed under every realm's prefix.
  const token = await getToken(opts.realmClient ? base : origin, opts, secret,
                               tls);
  const answer = await request(base + '/admin-api/config-dump', Object.assign({
    method: 'GET', headers: { authorization: 'Bearer ' + token }
  }, tls));
  if (answer.status !== 200) {
    console.error('The service answered ' + answer.status + ': ' +
                  answer.body.slice(0, 300));
    log.debug("Leaving main(). Refused.");
    return 1;
  }
  if (opts.output) {
    fs.writeFileSync(opts.output, answer.body + '\n', { mode: 0o600 });
    const dump = JSON.parse(answer.body);
    console.error('Saved ' + dump.settingCount + ' parameters, ' +
                  dump.masking.maskedValues + ' value(s) masked, to ' +
                  opts.output + '.');
  } else {
    process.stdout.write(answer.body + '\n');
  }
  log.debug("Leaving main().");
  return 0;
}

main(process.argv.slice(2)).then(function (status) {
  process.exitCode = status;
}, function (e) {
  console.error('config-dump: ' + ((e && e.message) || e));
  process.exitCode = 1;
});
