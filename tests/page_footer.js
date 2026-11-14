// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: page_footer.js
//
// ===========================================================================
// THE PAGE FOOTER ON EVERY HUMAN-FACING PAGE, AND ON NOTHING ELSE
// (rcbj, 2026-11-14).
//
// `common/web_footer.ts` is the markup and the stylesheet,
// `common/page_footer.ts` the server's half (the version from
// `common/version.js`, the year, the page's language), and two writers draw
// it: `common/shell_document.ts`, for every static surface's shell, and
// `common/error_page.ts`. Each runtime draws it again from the facts the
// shell's footer carries. What is held here:
//
//   A. Every shell a surface answers over HTTP — the front door, the
//      console, the portal, the reports application, the
//      federation pages and two description pages — carries EXACTLY ONE
//      footer: the three links and the two social links with their hrefs
//      exact, each `target="_blank" rel="noopener noreferrer"`, the two
//      icons by aria-label, the copyright with this year, the version and
//      its build line from `common/version.js`, and `/web/footer.css`
//      linked; and `/web/footer.css` is served.
//   B. As SOURCE, every shell writer but the RFC 4559 exchange's draws
//      through `ShellDocument.document()` without turning the footer off,
//      and only the two writers above (and the runtimes, through
//      `WebFooter`) draw one — so a specification's document (an auto-POST
//      form, the OP iframe, the fragment page) cannot grow one unnoticed.
//   C. A specification's document has none over HTTP: the OP iframe at
//      `/oauth2/check_session`.
//   D. The error page carries one, below its diagnostics, in its language.
//   E. French: the shell drawn for `Accept-Language: fr`, and the runtime's
//      redraw with the French catalog, carry the translated words;
//      `WebFooter.drawnIn()` draws nothing where the shell drew none.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'page_footer',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.PF_ROOT;
  const OUT = process.env.PF_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  const LINKS = [
    'https://rcbj.github.io/iya-sts/',
    'https://github.com/rcbj/iya-sts/issues',
    'https://github.com/rcbj/iya-sts',
    'https://www.linkedin.com/company/18811689/',
    'https://github.com/rcbj'
  ];

  function unescape(raw) {
    return String(raw).replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }

  function footersIn(text) {
    return String(text || '').match(/<footer class="sts-footer"[\s\S]*?<\/footer>/g) || [];
  }

  // What one footer must hold; answers the problems, none when right.
  function footerProblems(text, v) {
    const all = footersIn(text);
    if (all.length !== 1) {
      return ['footers: ' + all.length];
    }
    const f = all[0];
    const out = [];
    const hrefs = [];
    const re = /<a href="([^"]*)"([^>]*)>/g;
    let m = re.exec(f);
    while (m) {
      hrefs.push(unescape(m[1]));
      if (!/ target="_blank"/.test(m[2]) ||
          !/ rel="noopener noreferrer"/.test(m[2])) {
        out.push('link without target/rel: ' + m[1]);
      }
      m = re.exec(f);
    }
    if (JSON.stringify(hrefs) !== JSON.stringify(LINKS)) {
      out.push('hrefs: ' + JSON.stringify(hrefs));
    }
    ['LinkedIn', 'GitHub'].forEach(function (name) {
      if (f.indexOf('aria-label="' + name + '" title="' + name +
                    '"><svg') < 0) {
        out.push('no ' + name + ' icon');
      }
    });
    if ((f.match(/<svg /g) || []).length !== 2 ||
        (f.match(/fill="currentColor"/g) || []).length !== 2) {
      out.push('icons are not two inline svgs with fill="currentColor"');
    }
    const year = String(new Date().getUTCFullYear());
    if (f.indexOf('© 2026–' + year +
                  ' Iya CyberSecurity Solutions, LLC.') < 0) {
      out.push('copyright with ' + year);
    }
    if (f.indexOf('data-sts-footer-version="' + v.version + '"') < 0 ||
        unescape(f).indexOf('title="' + v.buildInfo + '"') < 0 ||
        f.indexOf(v.version + '</div></footer>') < 0) {
      out.push('version ' + v.version + ' and its build line');
    }
    return out;
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const version = require(ROOT_DIR + '/common/version');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');
    const WebFooter = require(ROOT_DIR + '/common/web_footer');
    const messages = require(ROOT_DIR + '/common/web_messages');
    const PageLocale = require(ROOT_DIR + '/common/page_locale');
    const ErrorPage = require(ROOT_DIR + '/common/error_page');
    const v = { version: String(version.load().version),
                buildInfo: version.buildInfo(version.load()) };

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const get = function (p, headers) {
      return screen.call({ port: port, jar: {}, method: 'GET', path: p,
                           headers: headers || {} });
    };

    // A. Every surface's shell.
    // /logout with no session is a 302 to sign in, so it is held as source
    // (B) with every other shell writer.
    const SHELLS = ['/', '/admin', '/portal', '/report',
                    '/federation', '/saml2', '/ssf'];
    for (const p of SHELLS) {
      const r = await get(p, { accept: 'text/html' });
      const problems = footerProblems(r.text, v);
      note(r.status === 200 && problems.length === 0,
           'A. ' + p + ' answers its shell with exactly one footer, the ' +
           'five links exact, the two icons, this year and the version',
           r.status + ' ' + problems.join('; '));
      note(r.text.indexOf('<link rel="stylesheet" href="/web/footer.css">') >
           0, 'A. ' + p + '\'s shell links /web/footer.css');
      const csp = String(r.headers['content-security-policy'] || '');
      note(/frame-ancestors 'none'/.test(csp) && /base-uri/.test(csp),
           'A. ' + p + '\'s policy still carries frame-ancestors and ' +
           'base-uri', csp);
    }
    const css = await get('/web/footer.css');
    note(css.status === 200 &&
         /^text\/css/.test(String(css.headers['content-type'])) &&
         css.text === WebFooter.CSS &&
         /max-width:500px/.test(css.text),
         'A. /web/footer.css is the footer\'s one rule set, stacking at ' +
         '500px', css.status);

    // C. A specification's document: the OP iframe.
    config.setOverride('oauth2.sessionManagement', 'true');
    const iframe = await get('/oauth2/check_session');
    note(iframe.status === 200 && /<html/i.test(iframe.text) &&
         footersIn(iframe.text).length === 0 &&
         iframe.text.indexOf('footer.css') < 0,
         'C. the OP iframe at /oauth2/check_session carries no footer',
         iframe.status);
    config.clearOverride('oauth2.sessionManagement');

    // D. The error page.
    const tEn = PageLocale.translatorFor({ headers: {} }, {});
    const page = ErrorPage.document({ t: tEn, chooser: '', status: 400,
      title: 'Refused', error: 'invalid_request', message: 'No.',
      diagnostics: [] }, 7, new Date());
    note(footerProblems(page, v).length === 0 &&
         page.indexOf('</section><footer class="sts-footer"') > 0 &&
         page.indexOf('.sts-footer{') > 0,
         'D. the error page carries one footer below its diagnostics, its ' +
         'rules in its own <style>', footerProblems(page, v).join('; '));
    const tFr = PageLocale.translatorFor({ headers:
      { 'accept-language': 'fr' } }, {});
    const pageFr = ErrorPage.document({ t: tFr, chooser: '', status: 400,
      title: 'Refusé', message: 'Non.', diagnostics: [] }, 0, new Date());
    note(/À propos<\/a>/.test(footersIn(pageFr)[0] || '') &&
         /Tous droits réservés/.test(pageFr),
         'D. the French error page\'s footer is in French');

    // E. French.
    const fr = await get('/', { accept: 'text/html',
                                'accept-language': 'fr' });
    const frFooter = footersIn(fr.text)[0] || '';
    note(/>À propos</.test(frFooter) &&
         /Tous droits réservés/.test(frFooter) &&
         />Version /.test(frFooter) &&
         /aria-label="Iya CyberSecurity Solutions sur les réseaux/
           .test(frFooter),
         'E. the shell drawn for Accept-Language: fr carries the French ' +
         'footer', frFooter.slice(0, 400));
    const catalogs = {};
    ['en', 'fr'].forEach(function (tag) {
      const own = JSON.parse(fs.readFileSync(ROOT_DIR +
        '/common/locales/footer/' + tag + '.json', 'utf8'));
      const flat = {};
      Object.keys(own).forEach(function (key) {
        flat['footer.' + key] = own[key];
      });
      catalogs[tag] = flat;
    });
    const t = messages.WebTranslator.fromData({ catalogs: catalogs,
      negotiated: { locale: 'fr', chain: ['fr', 'en'], catalog: 'fr',
                    direction: 'ltr', matched: true } });
    const attrs = { 'data-sts-footer-version': v.version,
                    'data-sts-footer-build': v.buildInfo,
                    'data-sts-footer-year': '2031' };
    const doc = { querySelector: function () {
      return { getAttribute: function (n) {
        return attrs[n];
      } };
    } };
    const redrawn = WebFooter.drawnIn(doc, t);
    note(/>Documentation</.test(redrawn) && />À propos</.test(redrawn) &&
         /© 2026–2031 /.test(redrawn) &&
         /Tous droits réservés/.test(redrawn) &&
         redrawn.indexOf('Version ' + v.version) > 0,
         'E. the runtime draws the shell\'s footer again in French, with ' +
         'the facts the shell carried', redrawn.slice(0, 300));
    note(WebFooter.drawnIn({ querySelector: function () {
      return null;
    } }, t) === '',
    'E. a runtime draws no footer where its shell drew none');

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * B: who draws a footer, read off the source.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {void}
 */
function sourceChecks(t) {
  log.debug("Entering sourceChecks().");
  const files = [];
  const skip = ['node_modules', 'tests', 'node-ldapjs', '.git', 'docs',
                'embedded', 'rust', 'deploy', '.claude', 'companion',
                'debugger'];
  const walk = function (dir) {
    log.debug("Entering walk(). " + dir);
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      if (skip.indexOf(entry.name) >= 0) {
        return;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (/\.ts$/.test(entry.name) && !/\.d\.ts$/.test(entry.name)) {
        files.push(full);
      }
    });
    log.debug("Leaving walk().");
  };
  walk(ROOT);
  const rel = function (f) {
    return path.relative(ROOT, f);
  };
  const server = files.filter(function (f) {
    return /require\('\.\.?\/(common\/)?page_footer'\)/
      .test(fs.readFileSync(f, 'utf8'));
  }).map(rel).sort();
  t.equal(JSON.stringify(server),
          JSON.stringify(['common/error_page.ts', 'common/shell_document.ts']),
          'B. only the shell writer and the error page draw the server\'s ' +
          'footer — no auto-POST form, OP iframe or fragment page does');
  const browser = files.filter(function (f) {
    return /require\('[^']*web_footer'\)/.test(fs.readFileSync(f, 'utf8'));
  }).map(rel).sort();
  t.equal(JSON.stringify(browser), JSON.stringify([
    'admin-ui/web_runtime.ts', 'common/error_page.ts',
    'common/page_footer.ts', 'common/public_assets.ts',
    'common/web_surface.ts', 'portal/web_portal_runtime.ts',
    'report/web_report_pages.ts']),
  'B. the footer\'s builder is read by the server\'s two writers, the ' +
  'stylesheet route and the four runtimes that put pages in place');
  const off = files.filter(function (f) {
    return /footer: false/.test(fs.readFileSync(f, 'utf8'));
  }).map(rel);
  t.equal(JSON.stringify(off), JSON.stringify(['kerberos/spnego_authn.ts']),
          'B. the RFC 4559 exchange\'s shell is the one drawn without a ' +
          'footer');
  const shells = files.filter(function (f) {
    return /ShellDocument\.document\(/.test(fs.readFileSync(f, 'utf8'));
  }).map(rel);
  t.check(shells.length >= 12,
          'B. every surface draws its shell through ShellDocument.document()',
          shells.join(', '));
  log.debug("Leaving sourceChecks().");
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  sourceChecks(t);
  const out = path.join(os.tmpdir(), 'pf-' + process.pid + '-' + Date.now() +
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
                                  PF_ROOT: ROOT, PF_OUT: out }),
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
  name: 'page_footer',
  describe: 'every static surface\'s shell and the error page carry one ' +
            'footer — the documentation, contact and about links, the ' +
            'LinkedIn and GitHub icons, the copyright and the version from ' +
            'common/version.js — in the page\'s language, and no ' +
            'specification\'s document carries one',
  run: run
};
