#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/http-differential.js
// ===========================================================================
// THE SAME REQUESTS TO NODE AND TO RUST, AND EVERY ANSWER COMPARED (#444,
// rust/DESIGN.md section 10.2).
//
//   node tests/tools/http-differential.js --node <url> --rust <url>
//        [--admin-secret <s>] [--report <file>] [--only <substring>]
//
// Each case of the CORPUS below is sent to both bases with the SAME `Host`
// (the Node base's), so the two name the same origin, and the answers are
// compared: the status, every header but the VOLATILE ones (a date, the
// connection's own), and the body byte for byte. A body sent with a content
// coding is compared DECODED where the two codings' bytes differ — Node's
// zlib and the Rust brotli and deflate encoders need not agree on bytes for
// the same text — and then its `Content-Length` and `ETag`, which are
// computed over the compressed bytes, are said to be CODING-DEPENDENT
// rather than different.
//
// A difference on a path or header that a LATER PHASE owns is listed under
// `owned` with the owner (`OWNED` below) and does not fail the run: a route
// that phase has not ported, the `sts_session` cookie the sign-in service
// sets. Everything else is a failure, and the exit status says so.
//
// THE TWO PHASES. The default realm's corpus runs first, against a Node
// that has NO realm defined (a fresh container), because with one defined
// the console, the portal and the reports application ask a browser signed
// in nowhere which realm it means — the realm chooser, which needs the
// sign-on session and is owned with it. Then, with `--admin-secret`, the
// realm `diff` is created on Node through `/admin-api` (the Rust side
// defines it itself) and the realm corpus runs under `/realm/diff`. A Node
// that already holds realms has its default-realm shells listed as owned
// by the chooser, and says so.
//
// The tool needs nothing beyond node's own modules and bunyan.
// ===========================================================================

const http = require('http');
const https = require('https');
const zlib = require('zlib');
const fs = require('fs');
const log = require('bunyan').createLogger({ name: 'http-differential',
  level: process.env.LOG_LEVEL || 'info' });

// The headers that differ on every answer, whoever sends it.
const VOLATILE = ['date', 'connection', 'keep-alive', 'transfer-encoding'];

// What a later phase owns: a difference here is listed, not failed.
const OWNED = [
  { path: /^(\/realm\/diff)?\/(authn\/(login|select-idp|password-change|totp|webauthn|backup-code|password-factor|mfa-setup|email-[a-z-]+|wallet(\/wait)?|spnego|accounts)|oauth2\/consent|logout|gnap\/(interact|app|code|approve)(\/.*)?|federation|saml2|saml11|xacml|ssf|scim|spiffe|home-api(\/.*)?|realms|logo\.png)\/?(\?.*)?$/,
    owner: 'the family\'s phase (its route decides first: a pending ' +
           'sign-in, a consent, a session, a grant, its view)' },
  { path: /^\/gnap\/?$/, owner: 'GNAP (RFC 9635 section 9 discovery)' },
  { path: /^\/admin(-api)?\/risk\/upload\/?$/,
    owner: 'risk (the dataset upload reads its own body, #215)' },
  { path: /^(\/realm\/diff)?\/xacml\/description\.js/,
    owner: 'XACML (its client-certificate gate covers /xacml)' }
];

// What is different ON PURPOSE, and why: accepted, listed, never failed.
const ACCEPTED = [
  { status: 204, header: 'content-length', node: '0', rust: undefined,
    why: 'RFC 9110 section 8.6: a server MUST NOT send Content-Length in ' +
         'a 204; hyper drops it and Node sends "0" (a Node defect)' }
];
// Over HTTPS the cookie carries the `__Host-` prefix.
const OWNED_HEADERS = [
  { header: 'set-cookie', match: /^(__Host-)?sts_session=/,
    owner: 'the sign-in service (the session a page opens)' }
];

const say = function (text) {
  log.debug("Entering say().");
  process.stdout.write(text + '\n');
  log.debug("Leaving say().");
};

/**
 * Reads the command line.
 *
 * @returns the options
 */
function options() {
  log.debug("Entering options().");
  const out = { only: '' };
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 2) {
    out[argv[i].replace(/^--/, '').replace(/-([a-z])/g, function (w, c) {
      return c.toUpperCase();
    })] = argv[i + 1];
  }
  if (!out.node || !out.rust) {
    say('usage: http-differential.js --node <url> --rust <url> ' +
        '[--admin-secret <s>] [--report <file>] [--only <text>]');
    process.exitCode = 2;
  }
  log.debug("Leaving options().");
  return out;
}

/**
 * Sends one request and gathers its whole answer, undecoded.
 *
 * @param base - the base URL
 * @param host - the Host header both sides are sent
 * @param one - the case: method, path, headers, body
 * @returns `{ status, headers, body }`
 */
function send(base, host, one) {
  log.debug("Entering send().");
  const url = new URL(base);
  const mod = url.protocol === 'https:' ? https : http;
  const headers = Object.assign({ host: host }, one.headers || {});
  const body = one.body === undefined ? null
    : (Buffer.isBuffer(one.body) ? one.body : Buffer.from(one.body));
  if (body && headers['content-length'] === undefined) {
    headers['content-length'] = String(body.length);
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve) {
    const r = mod.request({ hostname: url.hostname, port: url.port,
      method: one.method || 'GET', path: one.path, headers: headers,
      rejectUnauthorized: false, agent: false }, function (res) {
      const chunks = [];
      res.on('data', function (c) {
        chunks.push(c);
      });
      res.on('end', function () {
        resolve({ status: res.statusCode, headers: res.headers,
                  body: Buffer.concat(chunks) });
      });
    });
    r.on('error', function (e) {
      log.debug("Caught in send(): " + ((e && e.message) || e));
      resolve({ status: 0, headers: {}, body: Buffer.from(String(e)) });
    });
    // A side that answers a body it will not read (a 413) may close the
    // socket while the rest is still being written; that is its answer,
    // already read above, and not an error of the run.
    r.on('socket', function (socket) {
      socket.on('error', function (e) {
        log.debug("Caught in send(): " + ((e && e.message) || e));
      });
    });
    if (body) {
      r.write(body);
    }
    r.end();
  });
}

/**
 * Decodes a body by its Content-Encoding, or answers it as it is.
 *
 * @param answer - an answer
 * @returns the decoded bytes
 */
function decoded(answer) {
  log.debug("Entering decoded().");
  const coding = String(answer.headers['content-encoding'] || '');
  let out = answer.body;
  try {
    if (coding === 'br') {
      out = zlib.brotliDecompressSync(answer.body);
    } else if (coding === 'gzip') {
      out = zlib.gunzipSync(answer.body);
    }
  } catch (e) {
    log.debug("Caught in decoded(): " + ((e && e.message) || e));
    out = Buffer.from('<undecodable ' + coding + ' body>');
  }
  log.debug("Leaving decoded().");
  return out;
}

/**
 * Who owns a difference on this path, or ''.
 *
 * @param path - the request's path
 * @param context - `{ nodeHasRealms }`
 * @returns the owner, or ''
 */
function ownerOf(path, context) {
  log.debug("Entering ownerOf().");
  const found = OWNED.filter(function (one) {
    return one.path.test(path);
  })[0];
  if (found) {
    log.debug("Leaving ownerOf().");
    return found.owner;
  }
  if (context.nodeHasRealms &&
      /^\/(admin|portal|report)(\/.*)?$/.test(path.split('?')[0])) {
    log.debug("Leaving ownerOf().");
    return 'the realm chooser (with the sign-on session; this Node ' +
           'already holds realms)';
  }
  log.debug("Leaving ownerOf().");
  return '';
}

/**
 * Compares two answers.
 *
 * @param a - Node's
 * @param b - Rust's
 * @returns `{ differences: [...], notes: [...] }`
 */
function compare(a, b) {
  log.debug("Entering compare().");
  const differences = [];
  const notes = [];
  if (a.status !== b.status) {
    differences.push({ what: 'status', node: a.status, rust: b.status });
  }
  const sameBytes = a.body.equals(b.body);
  const coded = !!a.headers['content-encoding'] &&
    a.headers['content-encoding'] === b.headers['content-encoding'];
  const codingDependent = coded && !sameBytes;
  const names = Object.keys(a.headers).concat(Object.keys(b.headers))
    .filter(function (n, i, all) {
      return all.indexOf(n) === i && VOLATILE.indexOf(n) < 0;
    }).sort();
  names.forEach(function (name) {
    const x = a.headers[name];
    const y = b.headers[name];
    const text = function (v) {
      return v === undefined ? undefined
        : (Array.isArray(v) ? v.join('\n') : String(v));
    };
    if (text(x) === text(y)) {
      return;
    }
    if (codingDependent && (name === 'content-length' || name === 'etag')) {
      notes.push(name + ' is coding-dependent (' +
                 a.headers['content-encoding'] + ')');
      return;
    }
    const accepted = ACCEPTED.filter(function (one) {
      return one.status === a.status && one.status === b.status &&
        one.header === name && one.node === text(x) && one.rust === text(y);
    })[0];
    if (accepted) {
      notes.push(name + ' accepted: ' + accepted.why);
      return;
    }
    const owned = OWNED_HEADERS.filter(function (one) {
      return one.header === name && (one.match.test(text(x) || '') ||
                                     one.match.test(text(y) || ''));
    })[0];
    differences.push({ what: 'header ' + name, node: text(x), rust: text(y),
                       owner: owned ? owned.owner : '' });
  });
  if (!sameBytes) {
    const x = coded ? decoded(a) : a.body;
    const y = coded ? decoded(b) : b.body;
    if (!x.equals(y)) {
      let at = 0;
      while (at < x.length && at < y.length && x[at] === y[at]) {
        at += 1;
      }
      differences.push({ what: 'body', at: at,
        node: x.slice(Math.max(0, at - 60), at + 120).toString('utf8'),
        rust: y.slice(Math.max(0, at - 60), at + 120).toString('utf8') });
    } else {
      notes.push('the body is the same text in different ' +
                 a.headers['content-encoding'] + ' bytes');
    }
  }
  log.debug("Leaving compare().");
  return { differences: differences, notes: notes };
}

// ---------------------------------------------------------------------------
// THE CORPUS. Each case: `{ name, method?, path, headers?, body?,
// etagFrom? }`. `etagFrom` sends `If-None-Match` with the ETag Node answered
// the named case with, the same value to both sides.
// ---------------------------------------------------------------------------

const BIG = Buffer.alloc(6 * 1024 * 1024, 0x61);
const ACCEPTS = [undefined, 'br', 'gzip', 'gzip, br;q=0', '*', 'br;q=0, gzip;q=0'];
const BUNDLES = ['/home.js', '/admin/console.js', '/portal/portal.js',
  '/report/report.js', '/authn/signin.js', '/oauth2/consent.js',
  '/logout/signout.js', '/gnap/interaction.js', '/federation/pages.js',
  '/saml2/description.js', '/saml11/description.js', '/xacml/description.js',
  '/ssf/description.js', '/scim/description.js', '/spiffe/description.js'];
const STYLES = ['/home.css', '/admin/console.css', '/portal/portal.css',
  '/report/report.css', '/logout/signout.css', '/web/card.css',
  '/web/footer.css', '/web/theme.css'];
const SHELLS = ['/', '/admin', '/admin/', '/admin/users', '/ADMIN/Users',
  '/admin/api-explorer', '/portal', '/portal/', '/portal/security',
  '/report', '/report/x/y'];
const TAGS = ['en', 'fr', 'fr-CA', 'es', 'es-ES', 'zh-Hans', 'zh-Hant',
  'zh-Hant-HK', 'fil', 'sv'];
const LANGUAGES = ['fr', 'fr-CA,fr;q=0.8', 'zh-TW', 'zh-HK', 'es-MX',
  'de, sv;q=0.5', 'tl', 'xx-YY', '*', 'en;q=0, fr;q=0'];

/**
 * The default realm's corpus.
 *
 * @param build - the build id Node's shells carry, for `?v=`
 * @returns the cases
 */
function defaultCorpus(build) {
  log.debug("Entering defaultCorpus().");
  const out = [];
  const add = function (one) {
    out.push(one);
  };
  SHELLS.forEach(function (p) {
    add({ name: 'shell ' + p, path: p });
    add({ name: 'shell HEAD ' + p, method: 'HEAD', path: p });
  });
  ['br', 'gzip'].forEach(function (c) {
    add({ name: 'console shell ' + c, path: '/admin',
          headers: { 'accept-encoding': c } });
  });
  add({ name: 'shell conditional', path: '/', etagFrom: 'shell /' });
  LANGUAGES.forEach(function (l) {
    add({ name: 'front door in ' + l, path: '/',
          headers: { 'accept-language': l } });
  });
  ['fr-CA', 'zh-tw', 'not a tag', 'sv-SE'].forEach(function (c) {
    add({ name: 'front door chosen ' + c, path: '/',
          headers: { cookie: 'sts_lang=' + encodeURIComponent(c) } });
  });
  add({ name: 'portal in fr', path: '/portal',
        headers: { 'accept-language': 'fr' } });
  ['post', 'put', 'patch', 'delete'].forEach(function (m) {
    ['/admin/x', '/portal', '/report/'].forEach(function (p) {
      add({ name: m + ' ' + p, method: m.toUpperCase(), path: p,
            body: m === 'delete' ? undefined : 'a=1',
            headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    });
  });
  BUNDLES.concat(STYLES).forEach(function (p) {
    ACCEPTS.forEach(function (c) {
      add({ name: 'file ' + p + ' ' + (c || 'identity'), path: p,
            headers: c ? { 'accept-encoding': c } : {} });
    });
  });
  add({ name: 'file HEAD /home.js', method: 'HEAD', path: '/home.js' });
  add({ name: 'file case /HOME.JS/', path: '/HOME.JS/' });
  add({ name: 'file conditional /home.js', path: '/home.js',
        etagFrom: 'file /home.js identity' });
  add({ name: 'card for this build', path: '/web/card.css?v=' + build });
  add({ name: 'card for another', path: '/web/card.css?v=other' });
  add({ name: 'card twice', path: '/web/card.css?v=' + build + '&v=x' });
  add({ name: 'footer for this build', path: '/web/footer.css?v=' + build });
  add({ name: 'theme with a digest', path: '/web/theme.css?v=0123' });
  add({ name: 'no logo', path: '/web/branding/logo' });
  add({ name: 'favicon', path: '/favicon.ico' });
  add({ name: 'catalog index', path: '/web/locales/catalogs.json' });
  add({ name: 'catalog index br', path: '/web/locales/catalogs.json',
        headers: { 'accept-encoding': 'br' } });
  add({ name: 'catalog index for this build',
        path: '/web/locales/catalogs.json?v=' + build });
  TAGS.forEach(function (t) {
    add({ name: 'footer words ' + t, path: '/web/locales/footer/' + t +
          '.json' });
    add({ name: 'authn words ' + t, path: '/web/locales/authn/' + t +
          '.json' });
    add({ name: 'console words ' + t, path: '/web/locales/console-all/' + t +
          '.json' });
  });
  add({ name: 'console words gzip', path: '/web/locales/console-all/fr.json',
        headers: { 'accept-encoding': 'gzip' } });
  add({ name: 'a namespace nobody has', path: '/web/locales/nope/en.json' });
  add({ name: 'a catalog nobody has', path: '/web/locales/footer/xx.json' });
  add({ name: 'not json', path: '/web/locales/footer/en.txt' });
  add({ name: 'a bad escape', path: '/web/locales/footer/%E0%A4.json' });
  add({ name: 'healthcheck', path: '/healthcheck' });
  add({ name: 'healthcheck HEAD', method: 'HEAD', path: '/healthcheck' });
  add({ name: 'healthcheck conditional', path: '/healthcheck',
        etagFrom: 'healthcheck' });
  add({ name: 'healthcheck no-cache', path: '/healthcheck',
        etagFrom: 'healthcheck', headers: { 'cache-control': 'no-cache' } });
  add({ name: 'healthcheck star', path: '/healthcheck',
        headers: { 'if-none-match': '*' } });
  // Unrouted, and the realm segment with an id nobody defined.
  ['/nope', '/nope?a=1', '/n%C3%A9', '/admin-api-nope', '/web/nope.css',
   '/realm/nope/x', '/realm/nope', '/healthcheck/x', '/%7Euser'
  ].forEach(function (p) {
    add({ name: 'unrouted ' + p, path: p });
  });
  add({ name: 'unrouted POST', method: 'POST', path: '/nope', body: 'x',
        headers: { 'content-type': 'text/plain' } });
  add({ name: 'unrouted DELETE', method: 'DELETE', path: '/healthcheck' });
  add({ name: 'unrouted HEAD', method: 'HEAD', path: '/nope' });
  // The validation guard.
  ['prototype=1', 'constructor=1', '__proto__=1', 'a=%0d', 'a=%09',
   'a%5B%5D=%01', 'a%5Bb%5D=%01', 'a=1&a=%01', 'a=%7f', 'a=%c2%85',
   '1=%01&prototype=1', 'hasOwnProperty=1'].forEach(function (q) {
    add({ name: 'guard ' + q, path: '/nope?' + q });
  });
  add({ name: 'guard on a route', path: '/web/card.css?prototype=1' });
  // CORS.
  const own = 'OWN';
  [['evil', 'https://evil.example'], ['own', own], ['null', 'null'],
   ['wildcard', '*'], ['path', 'https://a.example/x'],
   ['upper', 'HTTPS://EVIL.EXAMPLE']].forEach(function (o) {
    add({ name: 'preflight ' + o[0], method: 'OPTIONS', path: '/oauth2/token',
          headers: { origin: o[1], 'access-control-request-method': 'POST',
                     'access-control-request-headers': 'content-type, dpop' } });
    add({ name: 'cors ' + o[0], path: '/healthcheck',
          headers: { origin: o[1] } });
  });
  add({ name: 'preflight no origin', method: 'OPTIONS', path: '/x' });
  add({ name: 'preflight private network', method: 'OPTIONS', path: '/',
        headers: { origin: own,
                   'access-control-request-private-network': 'true' } });
  add({ name: 'cors navigation', path: '/',
        headers: { origin: 'https://evil.example',
                   'sec-fetch-mode': 'navigate' } });
  add({ name: 'cors on a shell', path: '/portal', headers: { origin: own } });
  add({ name: 'cors on a 404', path: '/nope', headers: { origin: own } });
  add({ name: 'cors client in body', method: 'POST', path: '/nope',
        body: 'client_id=nobody',
        headers: { origin: 'https://evil.example',
                   'content-type': 'application/x-www-form-urlencoded' } });
  add({ name: 'cors basic user', path: '/nope',
        headers: { origin: 'https://evil.example',
                   authorization: 'Basic ' +
                     Buffer.from('nobody:x').toString('base64') } });
  // The limits.
  add({ name: 'too large', method: 'POST', path: '/nope', body: BIG,
        headers: { 'content-type': 'text/plain' } });
  add({ name: 'too large raw', method: 'POST', path: '/nope', body: BIG,
        headers: { 'content-type': 'application/octet-stream' } });
  add({ name: 'too large inflated', method: 'POST', path: '/nope',
        body: zlib.gzipSync(BIG),
        headers: { 'content-type': 'text/plain', 'content-encoding': 'gzip' } });
  add({ name: 'unknown charset', method: 'POST', path: '/nope', body: 'x',
        headers: { 'content-type': 'text/plain; charset=koi9' } });
  add({ name: 'latin1', method: 'POST', path: '/nope', body: 'x',
        headers: { 'content-type': 'text/plain; charset=iso-8859-1' } });
  add({ name: 'gzip body', method: 'POST', path: '/nope',
        body: zlib.gzipSync('a=1'),
        headers: { 'content-type': 'text/plain', 'content-encoding': 'gzip' } });
  add({ name: 'broken br body', method: 'POST', path: '/nope', body: 'a=1',
        headers: { 'content-type': 'text/plain', 'content-encoding': 'br' } });
  add({ name: 'unknown coding', method: 'POST', path: '/nope', body: 'a=1',
        headers: { 'content-type': 'text/plain',
                   'content-encoding': 'compress' } });
  add({ name: 'streamed upload exempt', method: 'POST',
        path: '/admin/risk/upload', body: BIG,
        headers: { 'content-type': 'text/plain' } });
  // What later phases own: listed so the report shows where they stand.
  ['/authn/login', '/authn/totp', '/oauth2/consent', '/logout', '/federation',
   '/saml2', '/saml11', '/ssf', '/xacml', '/realms', '/home-api/front',
   '/authn/wallet', '/logo.png'].forEach(function (p) {
    add({ name: 'owned ' + p, path: p });
  });
  log.debug("Leaving defaultCorpus().");
  return out;
}

/**
 * The realm corpus, under `/realm/diff`.
 *
 * @returns the cases
 */
function realmCorpus() {
  log.debug("Entering realmCorpus().");
  const out = [];
  ['/', '/admin', '/admin/users', '/portal', '/report', '/home.js',
   '/web/card.css', '/web/theme.css', '/web/locales/footer/fr.json',
   '/nope', '/healthcheck', '/admin/console.css'].forEach(function (p) {
    out.push({ name: 'realm ' + p, path: '/realm/diff' + p });
  });
  out.push({ name: 'realm console br', path: '/realm/diff/admin',
             headers: { 'accept-encoding': 'br' } });
  out.push({ name: 'realm portal in fr', path: '/realm/diff/portal',
             headers: { 'accept-language': 'fr' } });
  out.push({ name: 'realm POST portal', method: 'POST',
             path: '/realm/diff/portal/x', body: 'a=1' });
  out.push({ name: 'realm guard', path: '/realm/diff/x?prototype=1' });
  out.push({ name: 'realm preflight', method: 'OPTIONS',
             path: '/realm/diff/oauth2/token',
             headers: { origin: 'OWN' } });
  log.debug("Leaving realmCorpus().");
  return out;
}

/**
 * Creates the realm `diff` on Node, unless it is there.
 *
 * @param base - Node's base
 * @param host - its Host
 * @param secret - `sts-api-client`'s secret
 * @returns whether the realm is there now
 */
async function ensureRealm(base, host, secret) {
  log.debug("Entering ensureRealm().");
  const form = 'grant_type=client_credentials&scope=' +
    encodeURIComponent('admin:read admin:write') + '&resource=' +
    encodeURIComponent(base.replace(/\/+$/, '') + '/admin-api');
  const token = await send(base, host, { method: 'POST', path: '/oauth2/token',
    body: form, headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' +
        Buffer.from('sts-api-client:' + secret).toString('base64') } });
  let access = '';
  try {
    access = JSON.parse(token.body.toString('utf8')).access_token || '';
  } catch (e) {
    log.debug("Caught in ensureRealm(): " + ((e && e.message) || e));
    access = '';
  }
  if (!access) {
    say('could not get a token from Node: ' + token.status);
    log.debug("Leaving ensureRealm(). No token.");
    return false;
  }
  const made = await send(base, host, { method: 'POST',
    path: '/admin-api/realms/create',
    body: JSON.stringify({ id: 'diff', domain: 'diff.example.net',
                           name: 'Differential' }),
    headers: { 'content-type': 'application/json',
               authorization: 'Bearer ' + access } });
  const ok = made.status === 200 || /already/i.test(made.body.toString());
  log.debug("Leaving ensureRealm(). " + made.status);
  return ok;
}

/**
 * Runs one corpus against both sides.
 *
 * @param opts - the options
 * @param host - the Host both are sent
 * @param corpus - the cases
 * @param context - `{ nodeHasRealms }`
 * @param report - the report to add to
 * @param nodeAnswers - Node's answers by case name, for `etagFrom`
 */
async function run(opts, host, corpus, context, report, nodeAnswers) {
  log.debug("Entering run().");
  const ownOrigin = new URL(opts.node).origin;
  for (const one of corpus) {
    if (opts.only && one.name.indexOf(opts.only) < 0) {
      continue;
    }
    const headers = Object.assign({}, one.headers || {});
    Object.keys(headers).forEach(function (k) {
      if (headers[k] === 'OWN') {
        headers[k] = ownOrigin;
      }
    });
    if (one.etagFrom && nodeAnswers[one.etagFrom]) {
      headers['if-none-match'] = nodeAnswers[one.etagFrom].headers.etag || '';
    }
    const asked = Object.assign({}, one, { headers: headers });
    const a = await send(opts.node, host, asked);
    const b = await send(opts.rust, host, asked);
    nodeAnswers[one.name] = a;
    const found = compare(a, b);
    report.cases += 1;
    const owner = ownerOf(one.path, context);
    const failing = found.differences.filter(function (d) {
      return !d.owner && !owner;
    });
    const owned = found.differences.filter(function (d) {
      return d.owner || owner;
    });
    if (owned.length) {
      report.owned.push({ name: one.name, path: one.path,
        owner: owner || owned.map(function (d) {
          return d.owner;
        }).join('; '), differences: owned });
    }
    if (failing.length) {
      report.failures.push({ name: one.name, method: one.method || 'GET',
                             path: one.path, differences: failing });
    } else {
      report.same += 1;
    }
    found.notes.forEach(function (n) {
      report.notes.push(one.name + ': ' + n);
    });
  }
  log.debug("Leaving run().");
}

/**
 * The tool.
 */
async function main() {
  log.debug("Entering main().");
  const opts = options();
  if (process.exitCode) {
    log.debug("Leaving main(). Usage.");
    return;
  }
  const host = new URL(opts.node).host;
  const report = { node: opts.node, rust: opts.rust, cases: 0, same: 0,
                   failures: [], owned: [], notes: [], phases: [] };
  const realms = await send(opts.node, host, { path: '/realms' });
  let nodeHasRealms = false;
  try {
    const body = JSON.parse(realms.body.toString('utf8'));
    nodeHasRealms = (body.realms || []).some(function (r) {
      return r && r.id && r.id !== 'default';
    });
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    nodeHasRealms = false;
  }
  const front = await send(opts.node, host, { path: '/' });
  const m = /data-sts-build="([^"]*)"/.exec(front.body.toString('utf8'));
  const build = m ? m[1] : '';
  const nodeAnswers = {};
  report.phases.push('default realm' + (nodeHasRealms
    ? ' (Node already holds realms: its chooser is owned)' : ''));
  await run(opts, host, defaultCorpus(build), { nodeHasRealms: nodeHasRealms },
            report, nodeAnswers);
  if (opts.adminSecret) {
    if (await ensureRealm(opts.node, host, opts.adminSecret)) {
      report.phases.push('realm diff');
      await run(opts, host, realmCorpus(), { nodeHasRealms: true }, report,
                nodeAnswers);
    } else {
      report.phases.push('realm diff: NOT RUN, the realm could not be made');
      report.failures.push({ name: 'realm setup', differences: [] });
    }
  }
  if (opts.report) {
    fs.writeFileSync(opts.report, JSON.stringify(report, null, 2) + '\n');
  }
  say('http-differential: ' + report.cases + ' cases, ' + report.same +
      ' the same, ' + report.failures.length + ' different, ' +
      report.owned.length + ' with differences later phases own (' +
      report.phases.join('; ') + ').');
  report.failures.forEach(function (f) {
    say('  DIFFERENT ' + f.name + ' (' + f.method + ' ' + f.path + ')');
    f.differences.forEach(function (d) {
      say('    ' + d.what + (d.at !== undefined ? ' at ' + d.at : '') +
          '\n      node: ' + JSON.stringify(d.node) +
          '\n      rust: ' + JSON.stringify(d.rust));
    });
  });
  process.exitCode = report.failures.length ? 1 : 0;
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.debug("Caught in main(): " + ((e && e.message) || e));
  say('http-differential: ' + ((e && e.stack) || e));
  process.exitCode = 2;
});
