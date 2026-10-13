// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/diagnostic_pages.js
// ===========================================================================
// THE DIAGNOSTIC PAGES OF #583 ARE GONE: THE TLS HALF (#597) AND THE SPNEGO
// HALF (#595).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   1. THE TLS PAGES ARE GONE: `/tls`, `/tls/forwarded`, `/tls/pages.js`,
//      `POST /tls/trust` and `POST /tls/trust/clear` answer as unrouted
//      paths in a development process (#597). What they showed is
//      Monitoring → TLS connection, a console page over
//      `/admin-api/tls-connection` (`tests/tls_connection_page.js`), and
//      the truststore's doors are `/admin-api/tls/trust`'s.
//   2. THE KERBEROS DEMONSTRATION IS GONE (#595): `/spnego`,
//      `/spnego/protected`, `/spnego/pages.js`, `/krb5/service` and
//      `/krb5/principals` answer as unrouted paths in a development
//      process too. The first four are the development companion's
//      (`tests/companion.js`); the database the last listed is
//      `GET /admin-api/kerberos/principals`'s. The RFC 4559 exchange the
//      SPNEGO pages answered is still the sign-in's, held byte for byte by
//      `tests/spnego_shell.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'diagnostic_pages',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.DP_ROOT;
  const OUT = process.env.DP_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const jar = {};
    const call = function (method, p, headers, body) {
      return new Promise(function (resolve, reject) {
        const h = Object.assign({}, headers || {});
        if (Object.keys(jar).length && !h.cookie) {
          h.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (h.cookie === '') {
          delete h.cookie;
        }
        const text = body === undefined ? '' : String(body);
        if (method !== 'GET') {
          h['content-length'] = Buffer.byteLength(text);
        }
        const req = http.request({ host: '127.0.0.1', port: port, path: p,
                                   method: method, headers: h },
          function (res) {
            let out = '';
            (res.headers['set-cookie'] || []).forEach(function (line) {
              const pair = line.split(';')[0];
              const eq = pair.indexOf('=');
              jar[pair.slice(0, eq)] = pair.slice(eq + 1);
            });
            res.on('data', function (c) {
              out += c;
            });
            res.on('end', function () {
              let json = null;
              try {
                json = JSON.parse(out);
              } catch (e) {
                json = null;
              }
              resolve({ status: res.statusCode, headers: res.headers,
                        text: out, json: json });
            });
          });
        req.on('error', reject);
        req.end(text);
      });
    };

    // --- 1. the TLS pages are gone (#597) -----------------------------------
    let r = null;
    for (const asked of [['GET', '/tls'], ['GET', '/tls/forwarded'],
                         ['GET', '/tls/pages.js'], ['POST', '/tls/trust'],
                         ['POST', '/tls/trust/clear']]) {
      r = await call(asked[0], asked[1], { 'content-type': 'text/plain' },
                     '');
      note(r.status === 404 &&
           new RegExp('Cannot ' + asked[0] + ' ' +
                      asked[1].replace(/\//g, '\\/')).test(r.text),
           '1. ' + asked.join(' ') + ' answers as an unrouted path in ' +
           'development', r.status + ' ' + r.text.slice(0, 120));
    }

    // --- 2. the Kerberos demonstration is gone (#595) ---------------------
    for (const asked of ['/spnego', '/spnego?format=json', '/spnego/protected',
                         '/spnego/pages.js', '/krb5/service',
                         '/krb5/principals']) {
      r = await call('GET', asked, { authorization: 'Negotiate YQ==' });
      const bare = asked.replace(/\?.*$/, '');
      note(r.status === 404 &&
           new RegExp('Cannot GET ' + bare.replace(/\//g, '\\/'))
             .test(r.text) &&
           !r.headers['www-authenticate'],
           '2. GET ' + asked + ' answers as an unrouted path in ' +
           'development, with no Negotiate challenge',
           r.status + ' ' + r.text.slice(0, 120));
    }

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'dp-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  DP_ROOT: ROOT, DP_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'diagnostic_pages',
  describe: 'the diagnostic pages of #583 are gone: the TLS pages and the ' +
            'truststore\'s open acts (#597), and the Kerberos demonstration ' +
            '— /spnego, /spnego/protected, /krb5/service, /krb5/principals ' +
            '(#595)',
  run: run
};
