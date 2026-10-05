// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/console_compression.js
//
// ---------------------------------------------------------------------------
// THE CONSOLE'S FILES ARE SENT COMPRESSED WHERE THE BROWSER TAKES IT
// (rcbj, 2026-10-05).
//
// `/admin/console.js`, `/admin/console.css` and the document every `/admin`
// path answers are sent brotli or gzip by the request's Accept-Encoding, with
// `Vary: Accept-Encoding` (`AdminConsole.sendConsoleFile()`); the script from
// the forms the image build wrote beside it. Held, in a CHILD PROCESS with
// the whole stack over real HTTP:
//
//   A. `AdminConsole.acceptedEncoding()` prefers brotli, then gzip, honours
//      `q=0` and `*`, and answers none for an empty header.
//   B. Each of the three files: brotli where asked, gzip where only gzip is,
//      plain where neither is — each decompressing to the plain bytes, each
//      carrying `Vary: Accept-Encoding`.
//   C. A realm's document, compressed, still loads the realm's own script:
//      the realm middleware's link rewrite runs before the bytes are packed.
//   D. Nothing else is compressed: an `/admin-api` answer is plain whatever
//      the request accepts (BREACH).
// ---------------------------------------------------------------------------

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'console_compression',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT_DIR = process.env.CC_ROOT;
  const OUT = process.env.CC_OUT;
  const http = require('http');
  const zlib = require('zlib');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function get(port, urlPath, encoding) {
    return new Promise(function (resolve, reject) {
      const headers = {};
      if (encoding !== null) {
        headers['accept-encoding'] = encoding;
      }
      http.get({ host: '127.0.0.1', port: port, path: urlPath,
                 headers: headers }, function (res) {
        const chunks = [];
        res.on('data', function (c) {
          chunks.push(c);
        });
        res.on('error', reject);
        res.on('end', function () {
          const raw = Buffer.concat(chunks);
          const coding = String(res.headers['content-encoding'] || '');
          let plain = raw;
          if (coding === 'br') {
            plain = zlib.brotliDecompressSync(raw);
          } else if (coding === 'gzip') {
            plain = zlib.gunzipSync(raw);
          }
          resolve({ status: res.statusCode, coding: coding,
                    vary: String(res.headers.vary || ''),
                    size: raw.length, plain: plain.toString('utf8') });
        });
      }).on('error', reject);
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const realms = require(ROOT_DIR + '/common/realms');
    const AdminConsole = require(ROOT_DIR + '/admin-ui/admin').AdminConsole;

    // --- A. the negotiation ---------------------------------------------
    const pick = AdminConsole.acceptedEncoding;
    note(pick('gzip, deflate, br') === 'br' && pick('gzip') === 'gzip' &&
         pick('br;q=0, gzip') === 'gzip' && pick('gzip;q=0') === '' &&
         pick('*') === 'br' && pick('*, br;q=0') === 'gzip' &&
         pick('') === '' && pick(undefined) === '' &&
         pick('identity') === '',
         'A1. brotli first, then gzip, q=0 refuses one, * offers both, and ' +
         'nothing asked is nothing sent');

    const server = http.createServer(app);
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;

    // --- B. each file, each encoding ------------------------------------
    for (const file of ['/admin/console.js', '/admin/console.css',
                        '/admin/users']) {
      const plain = await get(port, file, null);
      const br = await get(port, file, 'gzip, deflate, br');
      const gz = await get(port, file, 'gzip');
      note(plain.status === 200 && plain.coding === '' &&
           br.coding === 'br' && gz.coding === 'gzip' &&
           br.plain === plain.plain && gz.plain === plain.plain &&
           br.size < plain.size && gz.size < plain.size &&
           [plain, br, gz].every(function (one) {
             return /accept-encoding/i.test(one.vary);
           }),
           'B. ' + file + ' is brotli or gzip where asked, plain otherwise, ' +
           'the same bytes each way, with Vary: Accept-Encoding',
           plain.size + ' plain, ' + br.size + ' br, ' + gz.size + ' gzip');
    }

    // --- C. a realm's document ------------------------------------------
    const id = 'ccomp' + process.pid;
    realms.create({ id: id, name: 'Compression' });
    const prefix = realms.prefixOf(realms.get(id));
    const realmPlain = await get(port, prefix + '/admin/users', null);
    const realmBr = await get(port, prefix + '/admin/users', 'br');
    const wanted = 'src="' + prefix + '/admin/console.js"';
    note(realmBr.coding === 'br' && realmBr.plain.indexOf(wanted) >= 0 &&
         realmPlain.plain.indexOf(wanted) >= 0 &&
         realmBr.plain === realmPlain.plain,
         'C. a realm\'s document, compressed, loads the realm\'s own script ' +
         '— the link rewrite runs before the bytes are packed',
         wanted + ' in br: ' + (realmBr.plain.indexOf(wanted) >= 0));
    realms.remove(id);

    // --- D. nothing else ------------------------------------------------
    const apiAnswer = await get(port, '/admin-api/console', 'gzip, br');
    note(apiAnswer.coding === '',
         'D. an /admin-api answer is never compressed (BREACH)',
         apiAnswer.status + ' ' + apiAnswer.coding);

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: e && e.stack ? e.stack : String(e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'cc-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  CC_ROOT: ROOT, CC_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
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
  name: 'console_compression',
  describe: 'the console\'s script, stylesheet and document are sent brotli ' +
            'or gzip by Accept-Encoding with Vary, a realm\'s document keeps ' +
            'its realm links, and /admin-api answers are never compressed',
  run: run
};
