// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: static_surface_no_inline_style.js
//
// ---------------------------------------------------------------------------
// NO STATIC SURFACE DRAWS A `style=""` ATTRIBUTE (2026-11-10).
//
// #1621 took 'unsafe-inline' out of every shell's `style-src`
// (`common/shell_document.ts`), so a `style=""` a renderer still draws is
// refused by the browser: the page loses the look and the console logs a CSP
// violation for every element. The conversion swept `admin-ui/` and missed
// the families' own renderers that the console bundles — `xacml/web_xacml.ts`
// (forms, warnings, the policy tree's indent), `scim/web_scim.ts` and
// `logout/web_logout.ts` — and only the browser jobs saw it, as 583 and 336
// SEVERE messages in `sts_xacml_editor` and `sts_admin_console`.
//
//   A. The scanner refuses an attribute in either quoting and passes a
//      comment and a CSSOM assignment, so a scanner that stopped matching
//      fails here rather than passing.
//   B. No `web_*.ts` in the service draws one. A look is a class whose rule
//      is in the surface's stylesheet; `el.style.x = …` is the CSSOM, which
//      the policy does not govern.
//
// It reads a file with its comment lines removed, so a comment that says
// "no `style=""`" is not an attribute.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'static_surface_no_inline_style',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const SKIP = ['node_modules', 'tests', 'docs', 'node-ldapjs', 'rust', 'embedded',
              'types', '.git', '.claude', 'deploy', 'apidocs', 'debugger'];

// The attribute, with or without a backslash before its quote.
const ATTRIBUTE = /\bstyle\s*=\s*\\?["']/;

/**
 * Finds the `style=` attributes in one source, comments aside.
 *
 * @param text - the source
 * @returns the lines refused, trimmed
 */
function refusedIn(text) {
  log.debug('Entering refusedIn().');
  const out = [];
  let inBlock = false;
  text.split('\n').forEach(function (line) {
    const trimmed = line.trim();
    if (inBlock) {
      if (trimmed.indexOf('*/') >= 0) {
        inBlock = false;
      }
      return;
    }
    if (trimmed.indexOf('/*') === 0) {
      inBlock = trimmed.indexOf('*/') < 0;
      return;
    }
    if (trimmed.indexOf('//') === 0 || trimmed.indexOf('*') === 0) {
      return;
    }
    if (ATTRIBUTE.test(line)) {
      out.push(trimmed.slice(0, 120));
    }
  });
  log.debug('Leaving refusedIn(). ' + out.length);
  return out;
}

function renderers(dir, into) {
  log.debug('Entering renderers().');
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (one) {
    const full = path.join(dir, one.name);
    if (one.isDirectory()) {
      if (SKIP.indexOf(one.name) < 0) {
        renderers(full, into);
      }
    } else if (/^web_.*\.ts$/.test(one.name) && !/\.d\.ts$/.test(one.name)) {
      into.push(full);
    }
  });
  log.debug('Leaving renderers().');
  return into;
}

function run(t) {
  log.debug('Entering run().');
  t.equal(refusedIn("  '<form method=\"post\" style=\"display:inline\">' +\n")
    .length, 1, 'A1. an attribute in double quotes is refused');
  t.equal(refusedIn("  \"<td style='padding-left:1rem'>\" +\n").length, 1,
          'A2. and in single quotes');
  t.equal(refusedIn("  html += \"<b style=\\\"color:red\\\">\";\n").length, 1,
          'A3. and behind an escaped quote');
  t.equal(refusedIn("  // the policy allows no `style=\"\"` here\n" +
                    "  /* nor style=\"x\"\n   * style=\"y\" */\n" +
                    "  text.style.flex = '1';\n").length, 0,
          'A4. a comment and a CSSOM assignment are not');
  const files = renderers(ROOT, []);
  const refused = [];
  files.forEach(function (file) {
    refusedIn(fs.readFileSync(file, 'utf8')).forEach(function (one) {
      refused.push(path.relative(ROOT, file) + ': ' + one);
    });
  });
  t.check(files.length > 100,
          'B1. the scan reads the static surfaces\' renderers',
          String(files.length));
  t.check(refused.length === 0,
          'B2. no static surface renderer draws a style attribute, which ' +
          'every shell\'s style-src \'self\' refuses', refused.join('; '));
  log.debug('Leaving run().');
}

module.exports = {
  name: 'static_surface_no_inline_style',
  describe: 'no web_*.ts renderer draws a style="" attribute, which the ' +
            'shells\' style-src \'self\' refuses (#1621)',
  run: run
};
