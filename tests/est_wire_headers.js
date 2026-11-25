// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/est_wire_headers.js
// ===========================================================================
// WHAT AN EST ANSWER LOOKS LIKE ON THE WIRE (#2236).
//
// libest's estclient — Cisco's reference EST client, and
// tests/protocol/sts_est_libest.js's — reads AT MOST SIXTEEN header lines of
// an answer (`MAX_HEADERS` in `est_client_http.c`), and what follows the
// sixteenth it counts as the body. After #2164's `Reporting-Endpoints` and
// #2181's `Cross-Origin-Resource-Policy`, a dispatched product answer to
// `/cacerts` carried seventeen, and every one failed "Content Length (5470)
// and body length (5491) mismatch": 21 bytes, which is the seventeenth line
// (`Connection: close`) and two CRLFs. The declared length was right.
//
// The whole stack in a child process, over plain HTTP on 127.0.0.1, asked
// as libest asks (HTTP/1.1, `Connection: close`) on a raw socket so that
// every header line is counted as sent:
//
//   A. EACH ANSWER'S Content-Length IS THE NUMBER OF BYTES SENT after the
//      blank line — /cacerts, /csrattrs, and the refusals of /simpleenroll,
//      /simplereenroll and /serverkeygen with no credential, in the default
//      realm and through a label.
//   B. EACH ANSWER HAS AT MOST HEADER_BUDGET LINES: libest's sixteen less
//      the three a deployment adds to what this child sends —
//      `Strict-Transport-Security` (product, over TLS), the request pool's
//      pin cookie on an answer to a client with none (a dispatching front
//      process), and one spare. A new header on every response trips this
//      first, which is the point: it is then argued here, not found by an
//      enrollment client.
//   C. NO EST ANSWER CARRIES `Reporting-Endpoints` or an `ETag`: a
//      certificate body is not a page, and `no-store` has nothing to
//      validate.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'est_wire_headers',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.EW_ROOT;
  const OUT = process.env.EW_OUT;
  const http = require('http');
  const net = require('net');
  const findings = [];
  // libest's MAX_HEADERS, less HSTS, the pool's pin cookie and one spare.
  const HEADER_BUDGET = 16 - 3;
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    // The hierarchy /cacerts answers from, as est_handlers.js builds it.
    const pki = require(ROOT_DIR + '/common/pki');
    if (!pki.hasRoot()) {
      await pki.start({});
    }
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    // One request as libest writes it, and the raw bytes of the answer.
    const raw = function (method, p, body) {
      return new Promise(function (resolve) {
        const chunks = [];
        const socket = net.connect(port, '127.0.0.1', function () {
          const lines = [method + ' ' + p + ' HTTP/1.1',
                         'Host: 127.0.0.1:' + port,
                         'User-Agent: est_wire_headers',
                         'Accept: */*', 'Connection: close'];
          if (body !== undefined) {
            lines.push('Content-Type: application/pkcs10');
            lines.push('Content-Length: ' + Buffer.byteLength(body));
          }
          socket.write(lines.join('\r\n') + '\r\n\r\n' + (body || ''));
        });
        socket.on('data', function (c) {
          chunks.push(c);
        });
        socket.on('end', function () {
          resolve(Buffer.concat(chunks));
        });
        socket.on('error', function (e) {
          resolve(Buffer.from('error: ' + e.message));
        });
      });
    };
    const parse = function (bytes) {
      const at = bytes.indexOf('\r\n\r\n');
      if (at < 0) {
        return null;
      }
      const head = bytes.slice(0, at).toString('latin1').split('\r\n');
      const headers = {};
      head.slice(1).forEach(function (line) {
        const colon = line.indexOf(':');
        headers[line.slice(0, colon).trim().toLowerCase()] =
          line.slice(colon + 1).trim();
      });
      return { status: head[0], lines: head.length - 1, headers: headers,
               names: head.slice(1).map(function (line) {
                 return line.slice(0, line.indexOf(':'));
               }),
               bodyBytes: bytes.length - at - 4 };
    };

    const asks = [
      ['GET', '/.well-known/est/cacerts', undefined, '200'],
      ['GET', '/.well-known/est/csrattrs', undefined, ''],
      ['POST', '/.well-known/est/simpleenroll', 'MIIB', '401'],
      ['POST', '/.well-known/est/simplereenroll', 'MIIB', '401'],
      ['POST', '/.well-known/est/serverkeygen', 'MIIB', '401'],
      ['GET', '/.well-known/est/tls-server/cacerts', undefined, '200']
    ];
    for (const one of asks) {
      const got = parse(await raw(one[0], one[1], one[2]));
      if (!got) {
        note(false, one[0] + ' ' + one[1] + ' answers HTTP', 'no head');
        continue;
      }
      const what = one[0] + ' ' + one[1] + ' (' + got.status + ')';
      if (one[3]) {
        note(got.status.indexOf(' ' + one[3] + ' ') > 0,
             what + ' answers ' + one[3], got.status);
      }
      note(Number(got.headers['content-length']) === got.bodyBytes &&
           got.bodyBytes > 0,
           'A. ' + what + ': Content-Length is the bytes sent',
           got.headers['content-length'] + ' declared, ' + got.bodyBytes +
           ' sent');
      note(got.lines <= HEADER_BUDGET,
           'B. ' + what + ': at most ' + HEADER_BUDGET + ' header lines, ' +
           'so libest reads all of them in every mode',
           got.lines + ': ' + got.names.join(', '));
      note(!('reporting-endpoints' in got.headers) &&
           !('etag' in got.headers),
           'C. ' + what + ': no Reporting-Endpoints and no ETag',
           got.names.join(', '));
    }

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
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
  const out = path.join(os.tmpdir(), 'ew-' + process.pid + '-' + Date.now() +
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
                                  EW_ROOT: ROOT, EW_OUT: out }),
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
  name: 'est_wire_headers',
  describe: 'EST answers on the wire (#2236): Content-Length is the bytes ' +
            'sent, and the header lines fit libest\'s sixteen with room for ' +
            'HSTS and the pool\'s pin cookie',
  run: run
};
